package main

import (
	"testing"
	"time"
)

func TestRegisterRuleTunnelClientStickyPerListen(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("shared-key", "shared", "0.0.0.0:2222", "127.0.0.1:22", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	mapKey := ListenerMapKey("tcp", "0.0.0.0:2222")
	fromA := &netUDPAddr{ip: "198.51.100.10", port: 5001}
	fromB := &netUDPAddr{ip: "198.51.100.11", port: 5002}
	clientA := uint32(0xa11a11a1)
	clientB := uint32(0xb22b22b2)

	if !s.registerRuleTunnelClient(kc.Hash, clientA, mapKey, fromA, "icmp") {
		t.Fatal("first client should own the listen route")
	}
	rkA, cid, ok := s.routeKeyForListener(kc.Hash, mapKey)
	if !ok || cid != clientA || rkA != s.queueKeyForAddr(kc.Hash, clientA, fromA) {
		t.Fatalf("route after A: ok=%v cid=%08x rk=%q", ok, cid, rkA)
	}

	// Second online client must not steal the accept route (periodic Setup used to overwrite).
	if s.registerRuleTunnelClient(kc.Hash, clientB, mapKey, fromB, "icmp") {
		t.Fatal("second client must not overwrite an online owner")
	}
	rk2, cid2, ok2 := s.routeKeyForListener(kc.Hash, mapKey)
	if !ok2 || cid2 != clientA || rk2 != rkA {
		t.Fatalf("route changed after rejected B: ok=%v cid=%08x rk=%q", ok2, cid2, rk2)
	}

	// Same client may refresh (addr/transport update).
	fromA2 := &netUDPAddr{ip: "198.51.100.10", port: 5003}
	if !s.registerRuleTunnelClient(kc.Hash, clientA, mapKey, fromA2, "dns") {
		t.Fatal("same clientID refresh should succeed")
	}
	rk3, cid3, ok3 := s.routeKeyForListener(kc.Hash, mapKey)
	wantRK := s.queueKeyForAddr(kc.Hash, clientA, fromA2)
	if !ok3 || cid3 != clientA || rk3 != wantRK {
		t.Fatalf("refresh route: ok=%v cid=%08x rk=%q want %q", ok3, cid3, rk3, wantRK)
	}
}

func TestRegisterRuleTunnelClientTakeoverWhenStale(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("shared-key", "shared", "0.0.0.0:2222", "127.0.0.1:22", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	mapKey := ListenerMapKey("tcp", "0.0.0.0:2222")
	fromA := &netUDPAddr{ip: "198.51.100.10", port: 5001}
	fromB := &netUDPAddr{ip: "198.51.100.11", port: 5002}
	clientA := uint32(0xa11a11a1)
	clientB := uint32(0xb22b22b2)

	if !s.registerRuleTunnelClient(kc.Hash, clientA, mapKey, fromA, "icmp") {
		t.Fatal("first register failed")
	}
	// Force stale lastSeen so B can take over after A goes offline.
	k := ruleTunnelMapKey(kc.Hash, mapKey)
	s.ruleTunnelMu.Lock()
	s.ruleTunnelClients[k].lastSeen = time.Now().Add(-icmpClientHeartbeatTTL - time.Second)
	s.ruleTunnelMu.Unlock()

	if !s.registerRuleTunnelClient(kc.Hash, clientB, mapKey, fromB, "icmp") {
		t.Fatal("stale owner should be replaceable")
	}
	_, cid, ok := s.routeKeyForListener(kc.Hash, mapKey)
	if !ok || cid != clientB {
		t.Fatalf("expected B to own route, ok=%v cid=%08x", ok, cid)
	}
}

func TestHandleSetupDoesNotAckWhenRouteOwned(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("shared-key", "shared", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	// allow_all so arbitrary listen/target in Setup is accepted
	kc.AllowAll = true
	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	fromA := &netUDPAddr{ip: "203.0.113.1", port: 4001}
	fromB := &netUDPAddr{ip: "203.0.113.2", port: 4002}
	clientA := uint32(0x11110001)
	clientB := uint32(0x22220002)
	payload := []byte("0.0.0.0:18080|127.0.0.1:22|tcp")

	s.handleSetup(&TunnelPacket{
		KeyHash:  kc.Hash,
		ClientID: clientA,
		Cmd:      CmdSetup,
		Data:     payload,
	}, fromA, "icmp")

	rkA := s.queueKeyForAddr(kc.Hash, clientA, fromA)
	ack := s.dequeueRoute(rkA)
	if ack == nil || ack.Cmd != CmdSetupAck {
		t.Fatalf("client A expected SetupAck, got %#v", ack)
	}

	s.handleSetup(&TunnelPacket{
		KeyHash:  kc.Hash,
		ClientID: clientB,
		Cmd:      CmdSetup,
		Data:     payload,
	}, fromB, "icmp")

	rkB := s.queueKeyForAddr(kc.Hash, clientB, fromB)
	pkt := s.dequeueRoute(rkB)
	if pkt != nil && pkt.Cmd == CmdSetupAck {
		t.Fatal("client B must not receive SetupAck while A still owns the listen route")
	}

	mapKey := ListenerMapKey("tcp", "0.0.0.0:18080")
	_, cid, ok := s.routeKeyForListener(kc.Hash, mapKey)
	if !ok || cid != clientA {
		t.Fatalf("A should remain owner, ok=%v cid=%08x", ok, cid)
	}
}

func TestSocksDynamicRegisterAllowsMultipleClients(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("socks-key", "s", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, true, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	fromA := &netUDPAddr{ip: "203.0.113.10", port: 6001}
	fromB := &netUDPAddr{ip: "203.0.113.11", port: 6002}
	if !s.registerRuleTunnelClient(kc.Hash, 1, "socks-dynamic", fromA, "icmp") {
		t.Fatal("socks A register failed")
	}
	if !s.registerRuleTunnelClient(kc.Hash, 2, "socks-dynamic", fromB, "dns") {
		t.Fatal("socks B register must succeed (multi-client dials use per-client queues)")
	}
}
