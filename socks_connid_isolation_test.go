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
			return pkt
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

// Two SOCKS clients (same or different tunnel keys) both start ConnIDs at
// socksConnIDBase+1. The server used to key sessions by ConnID alone, so the
// second dial either tore down / rejected the first or overwrote it.
func TestSocksDialAllowsSameConnIDForDifferentClients(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	target := ln.Addr().String()

	acceptCh := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			acceptCh <- c
		}
	}()

	mgr := NewManager("")
	kc, err := mgr.AddKey("shared-socks-key", "t", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, true, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	connID := socksConnIDBase + 1
	fromA := &netUDPAddr{ip: "198.51.100.10", port: 10001}
	fromB := &netUDPAddr{ip: "198.51.100.11", port: 10002}
	clientA := uint32(0xaaaa0001)
	clientB := uint32(0xbbbb0002)
	routeA := s.queueKeyForAddr(kc.Hash, clientA, fromA)
	routeB := s.queueKeyForAddr(kc.Hash, clientB, fromB)

	s.handleSocksDial(&TunnelPacket{
		KeyHash:  kc.Hash,
		ClientID: clientA,
		ConnID:   connID,
		Data:     []byte(target),
	}, fromA)
	ackA := waitRouteCmd(s, routeA, CmdSocksDialAck, 2*time.Second)
	if ackA == nil || ackA.Cmd != CmdSocksDialAck || ackA.ConnID != connID {
		t.Fatalf("client A expected DialAck, got %#v", ackA)
	}

	s.handleSocksDial(&TunnelPacket{
		KeyHash:  kc.Hash,
		ClientID: clientB,
		ConnID:   connID,
		Data:     []byte(target),
	}, fromB)
	ackB := waitRouteCmd(s, routeB, CmdSocksDialAck, 2*time.Second)
	if ackB == nil || ackB.Cmd != CmdSocksDialAck || ackB.ConnID != connID {
		t.Fatalf("client B expected DialAck for same ConnID, got %#v (cross-client collision)", ackB)
	}

	keyA := makeConnMapKey(kc.Hash, clientA, connID)
	keyB := makeConnMapKey(kc.Hash, clientB, connID)
	s.mu.RLock()
	scA := s.connections[keyA]
	scB := s.connections[keyB]
	s.mu.RUnlock()
	if scA == nil || scB == nil {
		t.Fatalf("both SOCKS sessions must be present: A=%v B=%v", scA != nil, scB != nil)
	}
	if scA == scB {
		t.Fatal("distinct clients must not share one ServerConn")
	}

	// Closing A must not remove B's session (old map[uint32] delete did this).
	s.closeConn(scA)
	s.mu.RLock()
	_, aGone := s.connections[keyA]
	stillB := s.connections[keyB]
	s.mu.RUnlock()
	if aGone {
		t.Fatal("client A should be removed after close")
	}
	if stillB != scB {
		t.Fatal("closing client A removed or replaced client B's session")
	}
	if atomic.LoadInt32(&scB.closed) != 0 {
		t.Fatal("client B session was marked closed when A closed")
	}

	// Drain accepts so target side does not block on Close.
	deadline := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case c := <-acceptCh:
			go io.Copy(io.Discard, c)
			_ = c.Close()
		case <-deadline:
			t.Fatal("timed out waiting for target accepts")
		}
	}
	s.closeConn(scB)
}

func TestSocksDialCollisionAcrossDifferentKeys(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	target := ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				io.Copy(io.Discard, c)
				c.Close()
			}(c)
		}
	}()

	mgr := NewManager("")
	alice, err := mgr.AddKey("alice-key", "a", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := mgr.AddKey("bob-key", "b", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, true, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	connID := socksConnIDBase + 1
	fromA := &netUDPAddr{ip: "203.0.113.1", port: 20001}
	fromB := &netUDPAddr{ip: "203.0.113.2", port: 20002}
	routeA := s.queueKeyForAddr(alice.Hash, 1, fromA)
	routeB := s.queueKeyForAddr(bob.Hash, 1, fromB)

	s.handleSocksDial(&TunnelPacket{
		KeyHash: alice.Hash, ClientID: 1, ConnID: connID, Data: []byte(target),
	}, fromA)
	if pkt := waitRouteCmd(s, routeA, CmdSocksDialAck, 2*time.Second); pkt == nil || pkt.Cmd != CmdSocksDialAck {
		t.Fatalf("alice DialAck missing: %#v", pkt)
	}

	s.handleSocksDial(&TunnelPacket{
		KeyHash: bob.Hash, ClientID: 1, ConnID: connID, Data: []byte(target),
	}, fromB)
	if pkt := waitRouteCmd(s, routeB, CmdSocksDialAck, 2*time.Second); pkt == nil || pkt.Cmd != CmdSocksDialAck {
		t.Fatalf("bob DialAck missing (ConnID collision across keys): %#v", pkt)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connections[makeConnMapKey(alice.Hash, 1, connID)] == nil {
		t.Fatal("alice session missing")
	}
	if s.connections[makeConnMapKey(bob.Hash, 1, connID)] == nil {
		t.Fatal("bob session missing")
	}
}
