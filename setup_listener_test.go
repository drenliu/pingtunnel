package main

import (
	"net"
	"testing"
	"time"
)

func waitSetupCmd(s *Server, routeKey string, timeout time.Duration) *TunnelPacket {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pkt := s.dequeueRoute(routeKey)
		if pkt != nil && pkt.Cmd != CmdPing {
			return pkt
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// Regression: handleSetup used to CmdSetupAck whenever ListenerMapKey already had a
// listener, even if that listener belonged to a different tunnel key. The second
// client believed the tunnel was ready while accept() still routed to the first key.
func TestHandleSetupRejectsListenOwnedByOtherKey(t *testing.T) {
	listen := freeTCPAddr(t)
	mgr := NewManager("")
	kcA, err := mgr.AddKey("key-a", "a", listen, "127.0.0.1:9", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	kcB, err := mgr.AddKey("key-b", "b", listen, "127.0.0.1:10", "tcp")
	if err != nil {
		t.Fatal(err)
	}

	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	fromA := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 4001}
	fromB := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 4002}
	routeA := s.queueKeyForAddr(kcA.Hash, 0xaaaa0001, fromA)
	routeB := s.queueKeyForAddr(kcB.Hash, 0xbbbb0002, fromB)

	s.handleSetup(&TunnelPacket{
		KeyHash:  kcA.Hash,
		ClientID: 0xaaaa0001,
		Data:     []byte(listen + "|127.0.0.1:9|tcp"),
	}, fromA)

	ackA := waitSetupCmd(s, routeA, 2*time.Second)
	if ackA == nil || ackA.Cmd != CmdSetupAck {
		t.Fatalf("key A expected SetupAck, got %#v", ackA)
	}

	mapKey := ListenerMapKey("tcp", listen)
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.RLock()
		_, ok := s.listenersTCP[mapKey]
		bind := s.listenerBinds[mapKey]
		s.mu.RUnlock()
		if ok && bind != nil && bind.keyHash == kcA.Hash {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("key A listener did not register")
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.handleSetup(&TunnelPacket{
		KeyHash:  kcB.Hash,
		ClientID: 0xbbbb0002,
		Data:     []byte(listen + "|127.0.0.1:10|tcp"),
	}, fromB)

	ackB := waitSetupCmd(s, routeB, 500*time.Millisecond)
	if ackB != nil {
		t.Fatalf("key B must not receive SetupAck for another key's listen port, got cmd=%d", ackB.Cmd)
	}

	s.mu.RLock()
	bind := s.listenerBinds[mapKey]
	s.mu.RUnlock()
	if bind == nil || bind.keyHash != kcA.Hash || bind.targetAddr != "127.0.0.1:9" {
		t.Fatalf("listener bind mutated by rejected setup: %#v", bind)
	}
}

// Same key changing target must rebind so CmdConnect carries the new destination.
func TestHandleSetupRebindsTargetForSameKey(t *testing.T) {
	listen := freeTCPAddr(t)
	mgr := NewManager("")
	kc := &KeyConfig{
		ID:       "allow-all",
		Key:      "allow-key",
		AllowAll: true,
		Hash:     ComputeKeyHash("allow-key"),
	}
	mgr.mu.Lock()
	mgr.keys = []*KeyConfig{kc}
	mgr.byHash[kc.Hash] = kc
	mgr.mu.Unlock()

	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	from := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 3), Port: 4003}
	route := s.queueKeyForAddr(kc.Hash, 0xcccc0003, from)

	s.handleSetup(&TunnelPacket{
		KeyHash:  kc.Hash,
		ClientID: 0xcccc0003,
		Data:     []byte(listen + "|127.0.0.1:9|tcp"),
	}, from)
	if ack := waitSetupCmd(s, route, 2*time.Second); ack == nil || ack.Cmd != CmdSetupAck {
		t.Fatalf("first setup expected SetupAck, got %#v", ack)
	}

	s.handleSetup(&TunnelPacket{
		KeyHash:  kc.Hash,
		ClientID: 0xcccc0003,
		Data:     []byte(listen + "|127.0.0.1:11|tcp"),
	}, from)
	if ack := waitSetupCmd(s, route, 2*time.Second); ack == nil || ack.Cmd != CmdSetupAck {
		t.Fatalf("rebind setup expected SetupAck, got %#v", ack)
	}

	mapKey := ListenerMapKey("tcp", listen)
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.RLock()
		bind := s.listenerBinds[mapKey]
		s.mu.RUnlock()
		if bind != nil && bind.targetAddr == "127.0.0.1:11" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener did not rebind to new target, bind=%#v", bind)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAddRuleRejectsDuplicateListenMapKey(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("dup-listen", "t", "127.0.0.1:18081", "127.0.0.1:9", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	_, err = mgr.AddRule(kc.ID, "127.0.0.1:18081", "127.0.0.1:10", "tcp")
	if err == nil {
		t.Fatal("expected AddRule to reject second target on same listen address")
	}
}
