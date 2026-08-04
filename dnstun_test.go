package main

import (
	"testing"

	"github.com/miekg/dns"
)

func TestAddUDPDefaultPort(t *testing.T) {
	tests := []struct {
		in, def, want string
	}{
		{"", "1053", "1053"},
		{"1.2.3.4", "1053", "1.2.3.4:1053"},
		{"1.2.3.4:99", "1053", "1.2.3.4:99"},
		{"example.com", "1053", "example.com:1053"},
	}
	for _, tc := range tests {
		if got := addUDPDefaultPort(tc.in, tc.def); got != tc.want {
			t.Errorf("addUDPDefaultPort(%q,%q)=%q want %q", tc.in, tc.def, got, tc.want)
		}
	}
}

func TestNormalizeClientTransport(t *testing.T) {
	if got := normalizeClientTransport(""); got != "icmp" {
		t.Errorf("empty -> %q", got)
	}
	if got := normalizeClientTransport("  PING "); got != "icmp" {
		t.Errorf("ping -> %q", got)
	}
	if got := normalizeClientTransport("DNS"); got != "dns" {
		t.Errorf("dns -> %q", got)
	}
}

func TestParseServerTransports(t *testing.T) {
	type row struct {
		in       string
		wantIcmp bool
		wantDNS  bool
	}
	rows := []row{
		{"", true, true},
		{"both", true, true},
		{"all", true, true},
		{"icmp", true, false},
		{"ping", true, false},
		{"dns", false, true},
	}
	for _, r := range rows {
		i, d := parseServerTransports(r.in)
		if i != r.wantIcmp || d != r.wantDNS {
			t.Errorf("parseServerTransports(%q)=(icmp:%v dns:%v) want icmp:%v dns:%v", r.in, i, d, r.wantIcmp, r.wantDNS)
		}
	}
}

func TestFinalizeDNSServerAddr(t *testing.T) {
	a, n := finalizeDNSServerAddr(false, "", "")
	if a != "" || n != "" {
		t.Fatalf("serveDNS false: got addr=%q name=%q", a, n)
	}
	a, n = finalizeDNSServerAddr(true, "", "")
	if a != ":"+defaultDNSPort || n != defaultDNSQName {
		t.Fatalf("defaults: addr=%q name=%q", a, n)
	}
	a, n = finalizeDNSServerAddr(true, ":9999", "x.example")
	if a != ":9999" || n != "x.example" {
		t.Fatalf("explicit: addr=%q name=%q", a, n)
	}
}

func TestQnamesMatch(t *testing.T) {
	if !qnamesMatch("c.pingt.local", "c.pingt.local.") {
		t.Fatal("FQDN vs non-FQDN should match")
	}
	if qnamesMatch("a.local", "b.local") {
		t.Fatal("different names should not match")
	}
}

func TestDNSRequestResponseTunnelRoundtrip(t *testing.T) {
	key := ComputeKeyHash("secret")
	reqPkt := &TunnelPacket{
		Magic:   MagicRequest,
		KeyHash: key,
		Cmd:     CmdSetup,
		Data:    []byte(":4455|192.168.1.1:22|tcp"),
	}
	payload, err := reqPkt.Encode()
	if err != nil {
		t.Fatal(err)
	}
	const id = 0x1234
	wire, err := buildDNSRequest(id, "t.example.local", payload)
	if err != nil {
		t.Fatal(err)
	}
	m := new(dns.Msg)
	if err := m.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if m.Id != id || m.Response {
		t.Fatalf("bad header id=%d response=%v", m.Id, m.Response)
	}
	got := extractEDNSTunnelPayload(m)
	if string(got) != string(payload) {
		t.Fatalf("payload mismatch len %d vs %d", len(got), len(payload))
	}

	respPayload, err := (&TunnelPacket{Magic: MagicResponse, KeyHash: key, Cmd: CmdSetupAck}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	respWire, err := buildDNSResponse(m, respPayload)
	if err != nil {
		t.Fatal(err)
	}
	gotID, gotRaw, err := parseDNSResponse(respWire)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != id {
		t.Fatalf("response id %d want %d", gotID, id)
	}
	dec, err := DecodeTunnelPacket(gotRaw)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Magic != MagicResponse || dec.Cmd != CmdSetupAck || dec.KeyHash != key {
		t.Fatalf("decoded %+v", dec)
	}
}

func TestMaxTunnelPayloadForDNSRequest(t *testing.T) {
	for _, udpSize := range []uint16{512, 1232, 4096} {
		n := maxTunnelPayloadForDNSRequest("c.pingt.local", udpSize)
		if n <= 0 {
			t.Fatalf("udpSize=%d max payload=%d", udpSize, n)
		}
		pkt := &TunnelPacket{Magic: MagicRequest, Cmd: CmdData, Data: make([]byte, n)}
		raw, err := pkt.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := buildDNSRequestWithSize(1, "c.pingt.local", raw, udpSize); err != nil {
			t.Fatalf("udpSize=%d n=%d: %v", udpSize, n, err)
		}
		if n < MaxPayloadSize {
			pkt.Data = make([]byte, n+1)
			raw, _ = pkt.Encode()
			if _, err := buildDNSRequestWithSize(1, "c.pingt.local", raw, udpSize); err == nil {
				t.Fatalf("udpSize=%d expected error for n+1=%d", udpSize, n+1)
			}
		}
	}
}

func TestMaxTunnelPayloadForDNSResponseSmallerThanRequest(t *testing.T) {
	reqN := maxTunnelPayloadForDNSRequest("c.pingt.local", 512)
	respN := maxTunnelPayloadForDNSResponse("c.pingt.local", 512)
	if respN <= 0 || reqN <= 0 {
		t.Fatalf("req=%d resp=%d", reqN, respN)
	}
	if respN >= reqN {
		t.Fatalf("response limit %d should be smaller than request limit %d at udp 512", respN, reqN)
	}
	pkt := &TunnelPacket{Magic: MagicResponse, Cmd: CmdData, Data: make([]byte, respN)}
	raw, err := pkt.Encode()
	if err != nil {
		t.Fatal(err)
	}
	req := templateDNSRequest("c.pingt.local")
	if _, err := buildDNSResponseWithSize(req, raw, 512); err != nil {
		t.Fatalf("respN=%d: %v", respN, err)
	}
}

func TestDNSMaxDataChunkNeverExceedsPackable(t *testing.T) {
	// Long QNAMEs at the minimum EDNS size used to force a floor of 64 even when
	// maxTunnelPayloadForDNSResponse was smaller, producing un-packable CmdData.
	names := []string{
		"c.pingt.local",
		"tunnel.very.long.subdomain.example.company.internal",
		"a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.com",
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.example.com",
	}
	for _, name := range names {
		for _, sz := range []uint16{256, 512, 1024, 1232} {
			for _, forResponse := range []bool{false, true} {
				chunk := dnsMaxDataChunk(name, sz, forResponse)
				max := maxTunnelPayloadForDNSRequest(name, sz)
				if forResponse {
					max = maxTunnelPayloadForDNSResponse(name, sz)
				}
				if chunk != max && !(chunk == MaxPayloadSize && max > MaxPayloadSize) {
					t.Fatalf("name=%q sz=%d forResponse=%v chunk=%d max=%d", name, sz, forResponse, chunk, max)
				}
				if chunk <= 0 {
					continue
				}
				magic := MagicRequest
				if forResponse {
					magic = MagicResponse
				}
				pkt := &TunnelPacket{Magic: magic, Cmd: CmdData, ConnID: 1, Seq: 1, Data: make([]byte, chunk)}
				raw, err := pkt.Encode()
				if err != nil {
					t.Fatalf("encode name=%q sz=%d: %v", name, sz, err)
				}
				if forResponse {
					if _, err := buildDNSResponseWithSize(templateDNSRequest(name), raw, sz); err != nil {
						t.Fatalf("response pack name=%q sz=%d chunk=%d: %v", name, sz, chunk, err)
					}
				} else if _, err := buildDNSRequestWithSize(1, name, raw, sz); err != nil {
					t.Fatalf("request pack name=%q sz=%d chunk=%d: %v", name, sz, chunk, err)
				}
			}
		}
	}
}

func TestExtractEDNSUDPSize(t *testing.T) {
	wire, err := buildDNSRequestWithSize(9, "c.pingt.local", []byte("x"), 1024)
	if err != nil {
		t.Fatal(err)
	}
	m := new(dns.Msg)
	if err := m.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if got := extractEDNSUDPSize(m); got != 1024 {
		t.Fatalf("got %d want 1024", got)
	}
}

func TestNextSmallerDNSUDPSize(t *testing.T) {
	if got := nextSmallerDNSUDPSize(4096); got != 2048 {
		t.Fatalf("4096 -> %d", got)
	}
	if got := nextSmallerDNSUDPSize(256); got != 0 {
		t.Fatalf("256 -> %d", got)
	}
}

func TestParseDNSResponseRejectsQuery(t *testing.T) {
	key := ComputeKeyHash("k")
	p, _ := (&TunnelPacket{Magic: MagicRequest, KeyHash: key, Cmd: CmdPing}).Encode()
	wire, err := buildDNSRequest(1, "q.test", p)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = parseDNSResponse(wire)
	if err == nil {
		t.Fatal("expected error when parsing query as response")
	}
}
