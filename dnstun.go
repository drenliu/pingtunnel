package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// EDNS0 "local" option code in private use range: carries raw tunnel (MagicRequest / MagicResponse) payload.
const ednsLocalTunnel = 0x7e01

const defaultDNSPort = "1053"
const defaultDNSQName = "c.pingt.local"
const defaultDNSUpstreamPort = "53"
const dnsForwardTimeout = 5 * time.Second
const ednsUDPPayload = 4096
const dnsUDPSizeDefault = 1232
const dnsUDPSizeMin = 256
const dnsUDPSizeMax = 4096
const dnsProbeTimeout = 2 * time.Second

// dnsUDPSizeLadder: probe from large to small; first success is the negotiated size.
var dnsUDPSizeLadder = []uint16{4096, 2048, 1452, 1232, 1024, 768, 512, 400, 300, 256}

// addUDPDefaultPort returns "host:port" suitable for net.ResolveUDPAddr, defaulting the port.
func addUDPDefaultPort(hostport, defPort string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return defPort
	}
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	// no port: JoinHostPort handles domain names and bracketed v6
	return net.JoinHostPort(hostport, defPort)
}

func normQName(name string) string {
	n := strings.TrimSpace(name)
	if n == "" {
		n = defaultDNSQName
	}
	return dns.Fqdn(n)
}

// buildDNSRequest packs a single DNS query (type A) with EDNS0 tunnel payload in OPT.
func buildDNSRequest(id uint16, qname string, payload []byte) ([]byte, error) {
	return buildDNSRequestWithSize(id, qname, payload, dnsUDPSizeMax)
}

// buildDNSRequestWithSize sets EDNS UDP payload size and ensures the wire message fits.
func buildDNSRequestWithSize(id uint16, qname string, payload []byte, udpSize uint16) ([]byte, error) {
	udpSize = clampDNSUDPSize(udpSize)
	qn := normQName(qname)
	m := new(dns.Msg)
	m.Id = id
	m.RecursionDesired = true
	m.Question = []dns.Question{{
		Name:   qn,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}
	attachTunnelOPT(m, payload, udpSize)
	wire, err := m.Pack()
	if err != nil {
		return nil, err
	}
	if len(wire) > int(udpSize) {
		return nil, fmt.Errorf("DNS wire %d exceeds UDP payload size %d", len(wire), udpSize)
	}
	return wire, nil
}

// buildDNSResponse builds a DNS response matching the request with tunnel payload in OPT.
func buildDNSResponse(req *dns.Msg, payload []byte) ([]byte, error) {
	udpSize := extractEDNSUDPSize(req)
	if udpSize == 0 {
		udpSize = dnsUDPSizeDefault
	}
	return buildDNSResponseWithSize(req, payload, udpSize)
}

// buildDNSResponseWithSize caps the response to the negotiated EDNS UDP payload size.
func buildDNSResponseWithSize(req *dns.Msg, payload []byte, udpSize uint16) ([]byte, error) {
	if len(req.Question) < 1 {
		return nil, fmt.Errorf("no question")
	}
	udpSize = clampDNSUDPSize(udpSize)
	resp := new(dns.Msg)
	resp.SetReply(req)
	a := new(dns.A)
	a.Hdr = dns.RR_Header{
		Name:   req.Question[0].Name,
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    0,
	}
	a.A = net.IPv4(0, 0, 0, 0)
	resp.Answer = []dns.RR{a}
	attachTunnelOPT(resp, payload, udpSize)
	wire, err := resp.Pack()
	if err != nil {
		return nil, err
	}
	if len(wire) > int(udpSize) {
		return nil, fmt.Errorf("DNS wire %d exceeds UDP payload size %d", len(wire), udpSize)
	}
	return wire, nil
}

func attachTunnelOPT(m *dns.Msg, payload []byte, udpSize uint16) {
	udpSize = clampDNSUDPSize(udpSize)
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(udpSize)
	loc := new(dns.EDNS0_LOCAL)
	loc.Code = ednsLocalTunnel
	loc.Data = append([]byte(nil), payload...)
	opt.Option = []dns.EDNS0{loc}
	m.Extra = []dns.RR{opt}
}

func clampDNSUDPSize(udpSize uint16) uint16 {
	if udpSize < dnsUDPSizeMin {
		return dnsUDPSizeMin
	}
	if udpSize > dnsUDPSizeMax {
		return dnsUDPSizeMax
	}
	return udpSize
}

func extractEDNSUDPSize(m *dns.Msg) uint16 {
	for _, ex := range m.Extra {
		if opt, ok := ex.(*dns.OPT); ok {
			return opt.UDPSize()
		}
	}
	return 0
}

func templateDNSRequest(qname string) *dns.Msg {
	m := new(dns.Msg)
	m.Id = 1
	m.Question = []dns.Question{{
		Name:   normQName(qname),
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}
	return m
}

// maxTunnelPayloadForDNSRequest returns the largest CmdData payload in a DNS query.
func maxTunnelPayloadForDNSRequest(qname string, udpSize uint16) int {
	udpSize = clampDNSUDPSize(udpSize)
	qn := normQName(qname)
	lo, hi := 0, MaxPayloadSize
	for lo < hi {
		mid := (lo + hi + 1) / 2
		pkt := &TunnelPacket{Magic: MagicRequest, Cmd: CmdData, Data: make([]byte, mid)}
		raw, err := pkt.Encode()
		if err != nil {
			hi = mid - 1
			continue
		}
		if _, err := buildDNSRequestWithSize(1, qn, raw, udpSize); err == nil {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// maxTunnelPayloadForDNSResponse returns the largest CmdData payload in a DNS response.
// Responses include an A answer RR and are larger than requests for the same tunnel frame.
func maxTunnelPayloadForDNSResponse(qname string, udpSize uint16) int {
	udpSize = clampDNSUDPSize(udpSize)
	req := templateDNSRequest(qname)
	lo, hi := 0, MaxPayloadSize
	for lo < hi {
		mid := (lo + hi + 1) / 2
		pkt := &TunnelPacket{Magic: MagicResponse, Cmd: CmdData, Data: make([]byte, mid)}
		raw, err := pkt.Encode()
		if err != nil {
			hi = mid - 1
			continue
		}
		if _, err := buildDNSResponseWithSize(req, raw, udpSize); err == nil {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// dnsMaxDataChunk is the largest CmdData payload per DNS frame.
// forResponse: true when data is sent in DNS responses (server → client).
// Returns 0 when no CmdData payload fits (caller must not invent a larger floor —
// a previous floor of 64 produced frames that can never pack into the UDP budget).
func dnsMaxDataChunk(qname string, udpSize uint16, forResponse bool) int {
	var chunk int
	if forResponse {
		chunk = maxTunnelPayloadForDNSResponse(qname, udpSize)
	} else {
		chunk = maxTunnelPayloadForDNSRequest(qname, udpSize)
	}
	if chunk < 0 {
		return 0
	}
	if chunk > MaxPayloadSize {
		return MaxPayloadSize
	}
	return chunk
}

func extractEDNSTunnelPayload(m *dns.Msg) []byte {
	for _, ex := range m.Extra {
		if opt, ok := ex.(*dns.OPT); ok {
			for _, o := range opt.Option {
				if l, ok := o.(*dns.EDNS0_LOCAL); ok && l.Code == ednsLocalTunnel {
					return append([]byte(nil), l.Data...)
				}
			}
		}
	}
	return nil
}

// parseDNSResponse extracts wire tunnel data from a DNS response (ignores A answer).
func parseDNSResponse(buf []byte) (id uint16, payload []byte, err error) {
	m := new(dns.Msg)
	if ex := m.Unpack(buf); ex != nil {
		return 0, nil, ex
	}
	if !m.Response {
		return 0, nil, fmt.Errorf("not a response")
	}
	p := extractEDNSTunnelPayload(m)
	if len(p) == 0 {
		return 0, nil, fmt.Errorf("no tunnel option")
	}
	return m.Id, p, nil
}

func qnamesMatch(serverExpect, fromPacket string) bool {
	return normQName(serverExpect) == normQName(fromPacket)
}

// nextSmallerDNSUDPSize returns the next step down on the probe ladder, or 0 if at minimum.
func nextSmallerDNSUDPSize(cur uint16) uint16 {
	for i, sz := range dnsUDPSizeLadder {
		if sz == cur && i+1 < len(dnsUDPSizeLadder) {
			return dnsUDPSizeLadder[i+1]
		}
	}
	for _, sz := range dnsUDPSizeLadder {
		if sz < cur {
			return sz
		}
	}
	return 0
}

// parseServerTransports maps -transport (server) to (serveICMP, serveDNS).
// Empty, "both", and "all" mean listen on both ICMP and DNS UDP.
func parseServerTransports(s string) (serveICMP, serveDNS bool) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" || t == "both" || t == "all" {
		return true, true
	}
	if t == "ping" {
		return true, false
	}
	if t == "icmp" {
		return true, false
	}
	if t == "dns" {
		return false, true
	}
	// main rejects unknown; be conservative
	return true, true
}

// finalizeDNSServerAddr applies defaults for DNS when the server will listen on DNS.
func finalizeDNSServerAddr(serveDNS bool, dnsAddr, dnsName string) (addr, name string) {
	addr, name = strings.TrimSpace(dnsAddr), strings.TrimSpace(dnsName)
	if !serveDNS {
		return addr, name
	}
	if addr == "" {
		addr = ":" + defaultDNSPort
	}
	if name == "" {
		name = defaultDNSQName
	}
	return addr, name
}

// forwardDNSQuery relays a raw DNS request to upstream and writes the response back to clientAddr.
func forwardDNSQuery(upstream string, c net.PacketConn, req []byte, clientAddr net.Addr) {
	upstream = strings.TrimSpace(upstream)
	if upstream == "" || c == nil || len(req) < 12 || clientAddr == nil {
		return
	}
	target := addUDPDefaultPort(upstream, defaultDNSUpstreamPort)
	uaddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return
	}
	conn, err := net.DialUDP("udp", nil, uaddr)
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dnsForwardTimeout))
	if _, err := conn.Write(req); err != nil {
		return
	}
	resp := make([]byte, 65535)
	n, err := conn.Read(resp)
	if err != nil || n < 12 {
		return
	}
	_, _ = c.WriteTo(resp[:n], clientAddr)
}

func normalizeClientTransport(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return "icmp"
	}
	if t == "ping" {
		return "icmp"
	}
	return t
}
