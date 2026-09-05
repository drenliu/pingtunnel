package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestReserveSocksConnIDSkipsPortForwardSpaceAfterWrap(t *testing.T) {
	c := NewClient("", "127.0.0.1", "", "k", "tcp", ":1080", "icmp", "")
	defer c.Close()

	// next Add yields 0xA0000000; +socksConnIDBase wraps to 0 (port-forward space).
	atomic.StoreUint32(&c.nextSocksConn, 0xA0000000-1)

	ch := make(chan bool, 1)
	id := c.reserveSocksConnID(ch)
	if id < socksConnIDBase {
		t.Fatalf("SOCKS ConnID %d fell into port-forward space", id)
	}
	c.socksMu.Lock()
	_, ok := c.socksWait[id]
	c.socksMu.Unlock()
	if !ok {
		t.Fatal("expected socksWait reservation")
	}
}

func TestReserveSocksConnIDSkipsLiveRelay(t *testing.T) {
	c := NewClient("", "127.0.0.1", "", "k", "tcp", ":1080", "icmp", "")
	defer c.Close()

	liveID := socksConnIDBase + 1
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	cc := &ClientConn{id: liveID, proto: "tcp", tcpConn: local}
	cc.reliSend = NewReliableSend(liveID, c.enqueue)
	cc.reliRecv = NewReliableRecv(liveID, func([]byte) error { return nil }, c.enqueue)
	c.mu.Lock()
	c.connections[liveID] = cc
	c.mu.Unlock()

	atomic.StoreUint32(&c.nextSocksConn, 0) // next id = socksConnIDBase+1 (live)

	ch := make(chan bool, 1)
	id := c.reserveSocksConnID(ch)
	if id == liveID {
		t.Fatal("reserved ConnID still held by a live relay")
	}
	if id < socksConnIDBase {
		t.Fatalf("SOCKS ConnID %d fell into port-forward space", id)
	}
}

// Regression: rejecting a SOCKS dial whose ConnID is in the port-forward space used to
// enqueue CmdClose. Dual-mode clients apply that Close to connections[ConnID] and tear
// down a live port-forward relay.
func TestLowIDSocksDialRejectionDoesNotClosePortForward(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("shared", "t", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, true, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	client := NewClient(":4455", "127.0.0.1", "127.0.0.1:22", "shared", "tcp", ":1080", "icmp", "")
	defer client.Close()

	pfID := uint32(7)
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	cc := &ClientConn{id: pfID, proto: "tcp", tcpConn: local}
	cc.reliSend = NewReliableSend(pfID, client.enqueue)
	cc.reliRecv = NewReliableRecv(pfID, func([]byte) error { return nil }, client.enqueue)
	client.mu.Lock()
	client.connections[pfID] = cc
	client.mu.Unlock()

	from := &netUDPAddr{ip: "203.0.113.9", port: 4242}
	s.handleSocksDial(&TunnelPacket{
		KeyHash:  kc.Hash,
		ClientID: client.clientID,
		ConnID:   pfID,
		Data:     []byte("example.com:80"),
	}, from)

	// Deliver whatever the server queued (should be nothing / Ping only).
	routeKey := s.queueKeyForAddr(kc.Hash, client.clientID, from)
	for i := 0; i < 3; i++ {
		pkt := s.dequeueRoute(routeKey)
		if pkt == nil || pkt.Cmd == CmdPing {
			continue
		}
		client.handlePacket(pkt)
	}

	client.mu.RLock()
	got := client.connections[pfID]
	client.mu.RUnlock()
	if got != cc {
		t.Fatal("port-forward session was torn down by low-ID SOCKS dial rejection")
	}
	if atomic.LoadInt32(&cc.silentClose) != 0 {
		t.Fatal("port-forward session was silently closed")
	}

	// Give any unexpected Close a moment; session must remain.
	time.Sleep(20 * time.Millisecond)
	client.mu.RLock()
	got = client.connections[pfID]
	client.mu.RUnlock()
	if got != cc {
		t.Fatal("port-forward session missing after rejection")
	}
}
