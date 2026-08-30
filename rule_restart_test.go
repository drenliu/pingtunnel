package main

import (
	"sync/atomic"
	"testing"
)

func TestRestartListenersAfterRuleChangePreservesUnrelatedSessions(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("rule-restart-key", "t", "4455", "127.0.0.1:22", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.AddRule(kc.ID, "4456", "127.0.0.1:80", "tcp"); err != nil {
		t.Fatal(err)
	}

	s := NewServer(mgr, true, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	affectedKey := ListenerMapKey("tcp", "0.0.0.0:4455")
	otherKey := ListenerMapKey("tcp", "0.0.0.0:4456")

	affected := &ServerConn{
		id:           11,
		proto:        "tcp",
		listenMapKey: affectedKey,
		targetAddr:   "127.0.0.1:22",
		keyHash:      kc.Hash,
		clientID:     1,
		routeKey:     "route-a",
		ready:        make(chan struct{}),
		reliSend:     NewReliableSend(11, func(*TunnelPacket) {}),
		reliRecv:     NewReliableRecv(11, func([]byte) error { return nil }, func(*TunnelPacket) {}),
	}
	otherPF := &ServerConn{
		id:           12,
		proto:        "tcp",
		listenMapKey: otherKey,
		targetAddr:   "127.0.0.1:80",
		keyHash:      kc.Hash,
		clientID:     1,
		routeKey:     "route-b",
		ready:        make(chan struct{}),
		reliSend:     NewReliableSend(12, func(*TunnelPacket) {}),
		reliRecv:     NewReliableRecv(12, func([]byte) error { return nil }, func(*TunnelPacket) {}),
	}
	socks := &ServerConn{
		id:           socksConnIDBase + 1,
		proto:        "tcp",
		listenMapKey: "", // SOCKS dials are not bound to a forward rule listener
		targetAddr:   "example.com:443",
		keyHash:      kc.Hash,
		clientID:     1,
		routeKey:     "route-socks",
		ready:        make(chan struct{}),
		reliSend:     NewReliableSend(socksConnIDBase+1, func(*TunnelPacket) {}),
		reliRecv:     NewReliableRecv(socksConnIDBase+1, func([]byte) error { return nil }, func(*TunnelPacket) {}),
	}

	s.mu.Lock()
	s.connections[affected.id] = affected
	s.connections[otherPF.id] = otherPF
	s.connections[socks.id] = socks
	s.mu.Unlock()

	// Simulate editing only the :4455 rule (same map key for listen-only change of target).
	s.RestartListenersAfterRuleChange(kc.Hash, affectedKey, affectedKey)

	s.mu.RLock()
	_, affectedAlive := s.connections[affected.id]
	_, otherAlive := s.connections[otherPF.id]
	_, socksAlive := s.connections[socks.id]
	s.mu.RUnlock()

	if affectedAlive || atomic.LoadInt32(&affected.closed) == 0 {
		t.Fatal("session on edited listener should be closed")
	}
	if !otherAlive || atomic.LoadInt32(&otherPF.closed) != 0 {
		t.Fatal("unrelated port-forward session was torn down")
	}
	if !socksAlive || atomic.LoadInt32(&socks.closed) != 0 {
		t.Fatal("SOCKS session was torn down by an unrelated rule edit")
	}
}
