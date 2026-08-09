package main

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Cross-tenant ConnID confusion: handlers used to authorize only by ConnID +
// matchRoute(sc, from). With nonzero clientID, queue keys ignore source address,
// so matchRoute always succeeded — any other valid key could Close/Ack/inject.
func TestHandleCloseRejectsForeignKey(t *testing.T) {
	mgr := NewManager("")
	victimKey, err := mgr.AddKey("victim-key", "victim", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	attackerKey, err := mgr.AddKey("attacker-key", "attacker", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	from := &netUDPAddr{ip: "198.51.100.10", port: 9001}
	victimCID := uint32(0x0a0b0c0d)
	connID := uint32(42)
	routeKey := s.queueKeyForAddr(victimKey.Hash, victimCID, from)

	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	sc := &ServerConn{
		id:         connID,
		proto:      "tcp",
		tcpConn:    left,
		targetAddr: "127.0.0.1:9",
		keyHash:    victimKey.Hash,
		clientID:   victimCID,
		routeKey:   routeKey,
		ready:      make(chan struct{}),
	}
	sc.reliSend = NewReliableSend(connID, s.makeEnqueueRoute(routeKey))
	sc.reliRecv = NewReliableRecv(connID, func([]byte) error { return nil }, s.makeEnqueueRoute(routeKey))

	s.mu.Lock()
	s.connections[connID] = sc
	s.mu.Unlock()

	// Attacker uses a different valid key but the victim ConnID.
	s.handleClose(&TunnelPacket{
		KeyHash:  attackerKey.Hash,
		ClientID: victimCID,
		Cmd:      CmdClose,
		ConnID:   connID,
	}, from)

	s.mu.RLock()
	still := s.connections[connID]
	s.mu.RUnlock()
	if still != sc {
		t.Fatal("foreign key CmdClose removed victim connection")
	}
	if atomic.LoadInt32(&sc.closed) != 0 {
		t.Fatal("foreign key CmdClose marked victim connection closed")
	}

	// Legitimate owner can still close.
	s.handleClose(&TunnelPacket{
		KeyHash:  victimKey.Hash,
		ClientID: victimCID,
		Cmd:      CmdClose,
		ConnID:   connID,
	}, from)
	s.mu.RLock()
	_, ok := s.connections[connID]
	s.mu.RUnlock()
	if ok {
		t.Fatal("owner CmdClose should remove connection")
	}
	_ = right
}

func TestHandleDataRejectsForeignKey(t *testing.T) {
	mgr := NewManager("")
	victimKey, err := mgr.AddKey("victim-key-2", "victim", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	attackerKey, err := mgr.AddKey("attacker-key-2", "attacker", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	from := &netUDPAddr{ip: "198.51.100.11", port: 9002}
	victimCID := uint32(0x11223344)
	connID := uint32(77)
	routeKey := s.queueKeyForAddr(victimKey.Hash, victimCID, from)

	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	delivered := make(chan []byte, 1)
	sc := &ServerConn{
		id:         connID,
		proto:      "tcp",
		tcpConn:    left,
		targetAddr: "127.0.0.1:9",
		keyHash:    victimKey.Hash,
		clientID:   victimCID,
		routeKey:   routeKey,
		ready:      make(chan struct{}),
	}
	sc.reliSend = NewReliableSend(connID, s.makeEnqueueRoute(routeKey))
	sc.reliRecv = NewReliableRecv(connID,
		func(data []byte) error {
			cp := append([]byte(nil), data...)
			delivered <- cp
			return nil
		},
		s.makeEnqueueRoute(routeKey),
	)

	s.mu.Lock()
	s.connections[connID] = sc
	s.mu.Unlock()

	s.handleData(&TunnelPacket{
		KeyHash:  attackerKey.Hash,
		ClientID: victimCID,
		Cmd:      CmdData,
		ConnID:   connID,
		Seq:      1,
		Data:     []byte("pwned"),
	}, from)

	select {
	case got := <-delivered:
		t.Fatalf("foreign key injected data into victim stream: %q", got)
	case <-time.After(50 * time.Millisecond):
	}

	// Wrong clientID with correct key must also be rejected.
	s.handleData(&TunnelPacket{
		KeyHash:  victimKey.Hash,
		ClientID: victimCID + 1,
		Cmd:      CmdData,
		ConnID:   connID,
		Seq:      1,
		Data:     []byte("wrong-cid"),
	}, from)
	select {
	case got := <-delivered:
		t.Fatalf("wrong clientID injected data: %q", got)
	case <-time.After(50 * time.Millisecond):
	}

	s.handleData(&TunnelPacket{
		KeyHash:  victimKey.Hash,
		ClientID: victimCID,
		Cmd:      CmdData,
		ConnID:   connID,
		Seq:      1,
		Data:     []byte("ok"),
	}, from)
	select {
	case got := <-delivered:
		if string(got) != "ok" {
			t.Fatalf("got %q, want ok", got)
		}
	case <-time.After(time.Second):
		t.Fatal("owner data was not delivered")
	}

	// Drain pipe side so Close is quiet.
	go io.Copy(io.Discard, right)
}

func TestHandleDataAckRejectsForeignKey(t *testing.T) {
	mgr := NewManager("")
	victimKey, err := mgr.AddKey("victim-key-3", "victim", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	attackerKey, err := mgr.AddKey("attacker-key-3", "attacker", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	from := &netUDPAddr{ip: "198.51.100.12", port: 9003}
	victimCID := uint32(0x55667788)
	connID := uint32(88)
	routeKey := s.queueKeyForAddr(victimKey.Hash, victimCID, from)

	sc := &ServerConn{
		id:       connID,
		proto:    "tcp",
		keyHash:  victimKey.Hash,
		clientID: victimCID,
		routeKey: routeKey,
		ready:    make(chan struct{}),
	}
	sc.reliSend = NewReliableSend(connID, s.makeEnqueueRoute(routeKey))
	sc.reliRecv = NewReliableRecv(connID, func([]byte) error { return nil }, s.makeEnqueueRoute(routeKey))
	if !sc.reliSend.Send([]byte("inflight")) {
		t.Fatal("Send failed")
	}
	if sc.reliSend.PendingCount() != 1 {
		t.Fatalf("pending=%d", sc.reliSend.PendingCount())
	}

	s.mu.Lock()
	s.connections[connID] = sc
	s.mu.Unlock()

	s.handleDataAck(&TunnelPacket{
		KeyHash:  attackerKey.Hash,
		ClientID: victimCID,
		Cmd:      CmdDataAck,
		ConnID:   connID,
		Seq:      1,
	}, from)
	if sc.reliSend.PendingCount() != 1 {
		t.Fatal("foreign key cleared victim reliable ACK window (silent data loss)")
	}

	s.handleDataAck(&TunnelPacket{
		KeyHash:  victimKey.Hash,
		ClientID: victimCID,
		Cmd:      CmdDataAck,
		ConnID:   connID,
		Seq:      1,
	}, from)
	if sc.reliSend.PendingCount() != 0 {
		t.Fatal("owner ACK should clear pending")
	}
}
