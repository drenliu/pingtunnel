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
