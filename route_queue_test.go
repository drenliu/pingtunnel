package main

import (
	"testing"
)

func TestQueueKeyForAddrBindsClientIDAndPeerIP(t *testing.T) {
	s := &Server{}
	h := ComputeKeyHash("shared-key")
	a1 := &netUDPAddr{ip: "203.0.113.10", port: 1111}
	a2 := &netUDPAddr{ip: "198.51.100.20", port: 2222}
	sameIPNewPort := &netUDPAddr{ip: "203.0.113.10", port: 9999}

	k1 := s.queueKeyForAddr(h, 0xAABBCCDD, a1)
	k2 := s.queueKeyForAddr(h, 0xAABBCCDD, a2)
	kSameIP := s.queueKeyForAddr(h, 0xAABBCCDD, sameIPNewPort)
	kOtherCID := s.queueKeyForAddr(h, 0x11223344, a1)

	if k1 == "" || k2 == "" {
		t.Fatal("empty route key")
	}
	if k1 == k2 {
		t.Fatalf("same ClientID from different IPs must not share a queue: %q", k1)
	}
	if k1 != kSameIP {
		t.Fatalf("UDP port change must keep IP-bound route key; got %q vs %q", k1, kSameIP)
	}
	if k1 == kOtherCID {
		t.Fatal("different ClientIDs on same IP must not share a queue")
	}
}

func TestDequeueDoesNotStealAcrossPeerIPs(t *testing.T) {
	s := NewServer(NewManager(""), false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	h := ComputeKeyHash("shared-key")
	cid := uint32(0xAABBCCDD)
	victim := &netUDPAddr{ip: "203.0.113.10", port: 1111}
	attacker := &netUDPAddr{ip: "198.51.100.20", port: 2222}

	secret := &TunnelPacket{Cmd: CmdData, ConnID: 42, Seq: 1, Data: []byte("victim-secret")}
	s.enqueueForAddr(h, cid, victim, secret)

	got := s.dequeueForAddr(h, cid, attacker)
	if got == nil || got.Cmd != CmdPing {
		t.Fatalf("attacker must not drain victim queue, got %#v", got)
	}

	victimGot := s.dequeueForAddr(h, cid, victim)
	if victimGot == nil || victimGot.Cmd != CmdData || string(victimGot.Data) != "victim-secret" {
		t.Fatalf("victim should still receive own frame, got %#v", victimGot)
	}
}

func TestMatchRouteRejectsDifferentPeerIP(t *testing.T) {
	s := &Server{}
	h := ComputeKeyHash("k")
	cid := uint32(7)
	from := &netUDPAddr{ip: "203.0.113.10", port: 1}
	other := &netUDPAddr{ip: "198.51.100.20", port: 2}
	sc := &ServerConn{
		keyHash:  h,
		clientID: cid,
		routeKey: s.queueKeyForAddr(h, cid, from),
	}
	if !s.matchRoute(sc, from) {
		t.Fatal("owner addr should match")
	}
	if s.matchRoute(sc, other) {
		t.Fatal("foreign addr must not match route")
	}
}
