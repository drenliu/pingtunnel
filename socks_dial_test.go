package main

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func waitRouteCmd(s *Server, routeKey string, wantCmd uint8, timeout time.Duration) *TunnelPacket {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pkt := s.dequeueRoute(routeKey)
		if pkt != nil && pkt.Cmd != CmdPing {
			if wantCmd == 0 || pkt.Cmd == wantCmd {
				return pkt
			}
			// Unexpected non-ping; return it so the caller can assert.
			return pkt
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

// Regression: a retransmitted/duplicate CmdSocksDial used to enqueue CmdClose for an
// already-established ConnID, tearing down the live SOCKS relay under packet loss.
func TestSocksDialRetransmitKeepsLiveSession(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	acceptDone := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		acceptDone <- c
	}()

	mgr := NewManager("")
	kc, err := mgr.AddKey("socks-key", "t", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, true, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	from := &netUDPAddr{ip: "198.51.100.9", port: 5353}
	routeKey := s.queueKeyForAddr(kc.Hash, 0x22222222, from)
	if routeKey == "" {
		t.Fatal("empty route key")
	}

	connID := socksConnIDBase + 42
	dial := &TunnelPacket{
		KeyHash:  kc.Hash,
		ClientID: 0x22222222,
		ConnID:   connID,
		Data:     []byte(ln.Addr().String()),
	}

	s.handleSocksDial(dial, from)

	ack := waitRouteCmd(s, routeKey, CmdSocksDialAck, 3*time.Second)
	if ack == nil || ack.Cmd != CmdSocksDialAck || ack.ConnID != connID {
		t.Fatalf("expected CmdSocksDialAck for conn %d, got %#v", connID, ack)
	}

	var targetConn net.Conn
	select {
	case targetConn = <-acceptDone:
	case <-time.After(2 * time.Second):
		t.Fatal("target did not accept SOCKS dial")
	}
	defer targetConn.Close()

	s.mu.RLock()
	sc := s.connections[connID]
	s.mu.RUnlock()
	if sc == nil || sc.tcpConn == nil {
		t.Fatal("expected live SOCKS ServerConn after dial")
	}

	// Duplicate dial (ICMP/DNS retransmit) must re-ACK, not Close.
	s.handleSocksDial(dial, from)
	dup := waitRouteCmd(s, routeKey, CmdSocksDialAck, time.Second)
	if dup == nil || dup.Cmd != CmdSocksDialAck || dup.ConnID != connID {
		t.Fatalf("expected re-ACK on duplicate dial, got %#v", dup)
	}

	s.mu.RLock()
	got := s.connections[connID]
	s.mu.RUnlock()
	if got != sc {
		t.Fatal("duplicate CmdSocksDial replaced or removed the live session")
	}

	// Session must remain open; write server→target (avoid racing readTCP's Read).
	if atomic.LoadInt32(&sc.closed) != 0 {
		t.Fatal("live SOCKS session was closed after duplicate dial")
	}
	if _, err := sc.tcpConn.Write([]byte("pong")); err != nil {
		t.Fatalf("live session write after duplicate dial: %v", err)
	}
	buf := make([]byte, 4)
	_ = targetConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(targetConn, buf); err != nil {
		t.Fatalf("target read after duplicate dial: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("payload=%q", buf)
	}
}

func TestSocksDialDoesNotBlockTunnelLoop(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("socks-key2", "t", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, true, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	from := &netUDPAddr{ip: "198.51.100.10", port: 5354}
	routeKey := s.queueKeyForAddr(kc.Hash, 0x33333333, from)
	connID := socksConnIDBase + 99
	dial := &TunnelPacket{
		KeyHash:  kc.Hash,
		ClientID: 0x33333333,
		ConnID:   connID,
		// TEST-NET-1: typically blackholes; even if not, dial runs in a goroutine.
		Data: []byte("192.0.2.1:9"),
	}

	started := time.Now()
	s.handleSocksDial(dial, from)
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("handleSocksDial blocked for %v; dial must run asynchronously", elapsed)
	}

	// Give the goroutine a moment to mark socksDialing (or finish, on unusual networks).
	time.Sleep(20 * time.Millisecond)

	s.mu.RLock()
	_, dialing := s.socksDialing[connID]
	_, live := s.connections[connID]
	s.mu.RUnlock()

	if dialing {
		// Duplicate while DialTimeout is in flight must not enqueue Close.
		s.handleSocksDial(dial, from)
		time.Sleep(30 * time.Millisecond)
		if pkt := s.dequeueRoute(routeKey); pkt != nil && pkt.Cmd != CmdPing {
			t.Fatalf("unexpected packet while dial in flight: %#v", pkt)
		}
		return
	}
	if live {
		// Environment completed the dial unusually quickly; still require Ack not Close
		// on a duplicate, which is covered more thoroughly above.
		s.handleSocksDial(dial, from)
		dup := waitRouteCmd(s, routeKey, 0, time.Second)
		if dup == nil || dup.Cmd == CmdClose {
			t.Fatalf("duplicate dial must not Close live session, got %#v", dup)
		}
		return
	}
	// Dial may have already failed; ensure we didn't leave a stuck dialing mark.
	s.mu.RLock()
	_, still := s.socksDialing[connID]
	s.mu.RUnlock()
	if still {
		t.Fatal("socksDialing leaked after dial finished")
	}
	_ = routeKey
}
