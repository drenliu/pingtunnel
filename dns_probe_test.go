package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type memUDPAddr struct {
	s string
}

func (a *memUDPAddr) Network() string { return "udp" }
func (a *memUDPAddr) String() string  { return a.s }

// Regression: DNS EDNS probes used to accept any tiny MagicResponse to a large
// padded request. That advertised oversized UDP payload sizes; server→client
// CmdData then failed to traverse the path / fit DNS answers, black-holing the
// tunnel after a "successful" negotiation.
func TestDNSPingEchoEnqueuedForProbe(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("probe-key", "t", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	from := &memUDPAddr{s: "198.51.100.10:5353"}
	pad := make([]byte, 200)
	for i := range pad {
		pad[i] = byte(i)
	}
	pkt := &TunnelPacket{
		KeyHash:  kc.Hash,
		ClientID: 0x11111111,
		Cmd:      CmdPing,
		Data:     pad,
	}
	s.handlePacket(pkt, from, "dns")

	routeKey := s.queueKeyForAddr(kc.Hash, 0x11111111, from)
	got := s.dequeueRoute(routeKey)
	if got == nil || got.Cmd != CmdPing {
		t.Fatalf("expected echoed CmdPing, got %#v", got)
	}
	if len(got.Data) != len(pad) {
		t.Fatalf("echo len=%d want %d", len(got.Data), len(pad))
	}
	for i := range pad {
		if got.Data[i] != pad[i] {
			t.Fatalf("echo mismatch at %d", i)
		}
	}
}

func TestDNSPingEchoSkippedOnICMP(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("probe-key-icmp", "t", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, false, "icmp", "", "", "")
	defer s.Close()

	from := &memUDPAddr{s: "198.51.100.11:0"}
	pkt := &TunnelPacket{
		KeyHash:  kc.Hash,
		ClientID: 0x22222222,
		Cmd:      CmdPing,
		Data:     make([]byte, 64),
	}
	s.handlePacket(pkt, from, "icmp")
	routeKey := s.queueKeyForAddr(kc.Hash, 0x22222222, from)
	got := s.dequeueRoute(routeKey)
	if got != nil && len(got.Data) != 0 {
		t.Fatalf("ICMP transport should not echo probe padding, got len=%d", len(got.Data))
	}
}

func TestDNSProbeRoundTripRejectsShortResponse(t *testing.T) {
	srvPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvPC.Close()
	cliPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cliPC.Close()

	key := ComputeKeyHash("probe-reject")
	clientID := uint32(0xabcdef01)
	qn := "c.pingt.local"
	udpSize := uint16(1232)
	dataLen := maxTunnelPayloadForDNSResponse(qn, udpSize)
	if dataLen < 64 {
		t.Fatalf("unexpected tiny response budget %d", dataLen)
	}

	// Responder: valid tunnel Ping with EMPTY data (legacy false-success reply).
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = srvPC.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := srvPC.ReadFrom(buf)
		if err != nil {
			errCh <- err
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(buf[:n]); err != nil {
			errCh <- err
			return
		}
		respPkt := &TunnelPacket{
			Magic:    MagicResponse,
			KeyHash:  key,
			ClientID: clientID,
			Cmd:      CmdPing,
		}
		raw, err := respPkt.Encode()
		if err != nil {
			errCh <- err
			return
		}
		wire, err := buildDNSResponseWithSize(req, raw, udpSize)
		if err != nil {
			errCh <- err
			return
		}
		_, err = srvPC.WriteTo(wire, addr)
		errCh <- err
	}()

	c := NewClient("", srvPC.LocalAddr().String(), "", "probe-reject", "tcp", "", "dns", qn)
	c.key = key
	c.clientID = clientID
	c.tunConn = cliPC
	c.tunPeer = srvPC.LocalAddr()

	if c.dnsProbeRoundTrip(normQName(qn), udpSize) {
		t.Fatal("probe succeeded on short Ping reply; oversized EDNS size would be accepted")
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("responder: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("responder did not finish")
	}
}

func TestDNSProbeRoundTripAcceptsEcho(t *testing.T) {
	srvPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srvPC.Close()
	cliPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cliPC.Close()

	key := ComputeKeyHash("probe-accept")
	clientID := uint32(0xabcdef02)
	qn := "c.pingt.local"
	udpSize := uint16(1232)
	dataLen := maxTunnelPayloadForDNSResponse(qn, udpSize)

	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 65535)
		_ = srvPC.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := srvPC.ReadFrom(buf)
		if err != nil {
			errCh <- err
			return
		}
		req := new(dns.Msg)
		if err := req.Unpack(buf[:n]); err != nil {
			errCh <- err
			return
		}
		payload := extractEDNSTunnelPayload(req)
		in, err := DecodeTunnelPacket(payload)
		if err != nil {
			errCh <- err
			return
		}
		if len(in.Data) != dataLen {
			errCh <- fmt.Errorf("unexpected probe pad length %d want %d", len(in.Data), dataLen)
			return
		}
		respPkt := &TunnelPacket{
			Magic:    MagicResponse,
			KeyHash:  key,
			ClientID: clientID,
			Cmd:      CmdPing,
			Data:     append([]byte(nil), in.Data...),
		}
		raw, err := respPkt.Encode()
		if err != nil {
			errCh <- err
			return
		}
		wire, err := buildDNSResponseWithSize(req, raw, udpSize)
		if err != nil {
			errCh <- err
			return
		}
		_, err = srvPC.WriteTo(wire, addr)
		errCh <- err
	}()

	c := NewClient("", srvPC.LocalAddr().String(), "", "probe-accept", "tcp", "", "dns", qn)
	c.key = key
	c.clientID = clientID
	c.tunConn = cliPC
	c.tunPeer = srvPC.LocalAddr()

	if !c.dnsProbeRoundTrip(normQName(qn), udpSize) {
		t.Fatal("probe should succeed when server echoes full probe payload")
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("responder: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("responder did not finish")
	}
}
