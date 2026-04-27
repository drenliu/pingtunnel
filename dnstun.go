package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// EDNS0 "local" option code in private use range: carries raw tunnel (MagicRequest / MagicResponse) payload.
const ednsLocalTunnel = 0x7e01

const defaultDNSPort = "1053"
const defaultDNSQName = "c.pingt.local"
const ednsUDPPayload = 4096

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
	qn := normQName(qname)
	if msgLenEstimate(len(payload), len(qn)) > ednsUDPPayload-256 {
		return nil, fmt.Errorf("tunnel payload too large for DNS/UDP (try ICMP transport)")
	}
	m := new(dns.Msg)
	m.Id = id
	m.RecursionDesired = true
	m.Question = []dns.Question{{
		Name:   qn,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}
	attachTunnelOPT(m, payload)
	return m.Pack()
}

// buildDNSResponse builds a DNS response matching the request with tunnel payload in OPT.
func buildDNSResponse(req *dns.Msg, payload []byte) ([]byte, error) {
	if len(req.Question) < 1 {
		return nil, fmt.Errorf("no question")
	}
	if msgLenEstimate(len(payload), len(req.Question[0].Name)) > ednsUDPPayload-256 {
		return nil, fmt.Errorf("response too large for DNS/UDP")
	}
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
	attachTunnelOPT(resp, payload)
	return resp.Pack()
}

func attachTunnelOPT(m *dns.Msg, payload []byte) {
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(ednsUDPPayload)
	loc := new(dns.EDNS0_LOCAL)
	loc.Code = ednsLocalTunnel
	loc.Data = append([]byte(nil), payload...)
	opt.Option = []dns.EDNS0{loc}
	m.Extra = []dns.RR{opt}
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

// rough upper bound on wire size for conservative checks
func msgLenEstimate(tunnelLen, nameLen int) int {
	// 12 + question ~ name+4 + 300 for OPT+EDNS+labels
	return 12 + nameLen + 4 + 16 + tunnelLen
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
