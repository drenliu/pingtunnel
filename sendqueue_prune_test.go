package main

import (
	"testing"
	"time"
)

func TestPruneOrphanRouteStateRemovesUnusedQueues(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("prune-key", "t", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	from := &netUDPAddr{ip: "198.51.100.10", port: 5000}
	liveID := uint32(0x100)
	orphanID := uint32(0x200)

	s.enqueueForAddr(kc.Hash, liveID, from, &TunnelPacket{Cmd: CmdPing})
	s.enqueueForAddr(kc.Hash, orphanID, from, &TunnelPacket{Cmd: CmdPing})

	liveKey := s.queueKeyForAddr(kc.Hash, liveID, from)
	orphanKey := s.queueKeyForAddr(kc.Hash, orphanID, from)

	s.ruleTunnelMu.Lock()
	s.ruleTunnelClients[ruleTunnelMapKey(kc.Hash, "tcp/0.0.0.0:1")] = &ruleTunnelState{
		addr:     from,
		clientID: liveID,
		routeKey: liveKey,
		lastSeen: time.Now(),
	}
	s.ruleTunnelMu.Unlock()

	s.dnsRouteUDPSizeMu.Lock()
	s.dnsRouteUDPSize[liveKey] = 1232
	s.dnsRouteUDPSize[orphanKey] = 512
	s.dnsRouteUDPSizeMu.Unlock()

	s.pruneOrphanRouteState()

	s.sendQueuesMu.Lock()
	_, liveOK := s.sendQueues[liveKey]
	_, orphanOK := s.sendQueues[orphanKey]
	s.sendQueuesMu.Unlock()
	if !liveOK {
		t.Fatal("live route send queue was pruned")
	}
	if orphanOK {
		t.Fatal("orphan route send queue was not pruned")
	}

	s.dnsRouteUDPSizeMu.Lock()
	_, liveDNS := s.dnsRouteUDPSize[liveKey]
	_, orphanDNS := s.dnsRouteUDPSize[orphanKey]
	s.dnsRouteUDPSizeMu.Unlock()
	if !liveDNS {
		t.Fatal("live route dns UDP size was pruned")
	}
	if orphanDNS {
		t.Fatal("orphan route dns UDP size was not pruned")
	}
}

func TestEnqueueRouteCapsAndPrunesRotatingClientIDs(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("cap-key", "t", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	from := &netUDPAddr{ip: "203.0.113.50", port: 6000}

	// Pre-fill to the cap with tiny orphan channels (avoid allocating 4096-buffer each).
	s.sendQueuesMu.Lock()
	for i := 1; i <= maxSendQueues; i++ {
		rk := s.queueKeyForAddr(kc.Hash, uint32(i), from)
		s.sendQueues[rk] = make(chan *TunnelPacket, 1)
	}
	s.sendQueuesMu.Unlock()

	newID := uint32(maxSendQueues + 1)
	s.enqueueForAddr(kc.Hash, newID, from, &TunnelPacket{Cmd: CmdSetupAck})

	newKey := s.queueKeyForAddr(kc.Hash, newID, from)
	s.sendQueuesMu.Lock()
	n := len(s.sendQueues)
	_, ok := s.sendQueues[newKey]
	s.sendQueuesMu.Unlock()
	if n > maxSendQueues {
		t.Fatalf("send queues grew past cap: %d", n)
	}
	if !ok {
		t.Fatal("new ClientID route was not created after prune-at-cap")
	}
	if n != 1 {
		t.Fatalf("expected only the new route after orphan prune, got %d queues", n)
	}
}

func TestPruneOrphanRouteStateKeepsActiveConnectionRoute(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("conn-key", "t", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	from := &netUDPAddr{ip: "192.0.2.8", port: 7000}
	connID := uint32(0x42)
	routeKey := s.queueKeyForAddr(kc.Hash, connID, from)
	orphanKey := s.queueKeyForAddr(kc.Hash, 0x99, from)

	s.mu.Lock()
	s.connections[9] = &ServerConn{
		id:       9,
		keyHash:  kc.Hash,
		clientID: connID,
		routeKey: routeKey,
		ready:    make(chan struct{}),
		closed:   1,
	}
	s.mu.Unlock()

	s.sendQueuesMu.Lock()
	s.sendQueues[routeKey] = make(chan *TunnelPacket, 1)
	s.sendQueues[orphanKey] = make(chan *TunnelPacket, 1)
	s.sendQueuesMu.Unlock()

	s.pruneOrphanRouteState()

	s.sendQueuesMu.Lock()
	_, liveOK := s.sendQueues[routeKey]
	_, orphanOK := s.sendQueues[orphanKey]
	n := len(s.sendQueues)
	s.sendQueuesMu.Unlock()
	if !liveOK {
		t.Fatal("active connection routeKey was pruned")
	}
	if orphanOK {
		t.Fatal("orphan routeKey was not pruned")
	}
	if n != 1 {
		t.Fatalf("expected 1 live queue after prune, got %d", n)
	}
}

func TestDequeueRouteNilFromClosedChannel(t *testing.T) {
	s := NewServer(NewManager(""), false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	rk := "dead|cid:00000001"
	ch := make(chan *TunnelPacket)
	close(ch)
	s.sendQueuesMu.Lock()
	s.sendQueues[rk] = ch
	s.sendQueuesMu.Unlock()

	pkt := s.dequeueRoute(rk)
	if pkt == nil || pkt.Cmd != CmdPing {
		t.Fatalf("expected Ping fallback for nil recv, got %#v", pkt)
	}

	// Avoid double-close panic in Server.Close.
	s.sendQueuesMu.Lock()
	delete(s.sendQueues, rk)
	s.sendQueuesMu.Unlock()
}
