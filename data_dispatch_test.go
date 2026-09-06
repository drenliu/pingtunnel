package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// Stuck accept-side TCP peers used to block handleData on the ICMP/DNS read loop,
// freezing every tunnel client on that transport. dispatchData must return while
// the local Write is still blocked so control-plane packets keep flowing.
func TestDispatchDataDoesNotBlockControlPlane(t *testing.T) {
	srvSide, clientSide := net.Pipe()
	defer srvSide.Close()
	defer clientSide.Close()

	mgr := NewManager("")
	kc, err := mgr.AddKey("dispatch-key", "t", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	from := &netUDPAddr{ip: "198.51.100.7", port: 9}
	routeKey := s.queueKeyForAddr(kc.Hash, 0x42, from)
	sc := &ServerConn{
		id:       1,
		proto:    "tcp",
		tcpConn:  srvSide,
		keyHash:  kc.Hash,
		clientID: 0x42,
		routeKey: routeKey,
		ready:    make(chan struct{}),
	}
	sc.reliSend = NewReliableSend(1, func(*TunnelPacket) {})
	sc.reliRecv = NewReliableRecv(1, s.makeLocalDeliver(sc), func(*TunnelPacket) {})
	s.mu.Lock()
	s.connections[1] = sc
	s.mu.Unlock()

	payload := make([]byte, 64*1024)
	// Saturate the pipe so delivery Writes block inside handler goroutines.
	for i := 0; i < 8; i++ {
		s.dispatchData(&TunnelPacket{
			KeyHash:  kc.Hash,
			ClientID: 0x42,
			ConnID:   1,
			Seq:      uint32(i + 1),
			Data:     payload,
		}, from)
	}

	done := make(chan struct{})
	go func() {
		s.handleDataAck(&TunnelPacket{
			KeyHash:  kc.Hash,
			ClientID: 0x42,
			ConnID:   1,
			Seq:      1,
		}, from)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleDataAck blocked behind stuck CmdData TCP writes")
	}
}

func TestClientDispatchDataDoesNotBlockReceiver(t *testing.T) {
	local, peer := net.Pipe()
	defer local.Close()
	defer peer.Close()

	c := NewClient("", "127.0.0.1", "", "dispatch-client", "tcp", "", "icmp", "")
	defer c.Close()

	cc := &ClientConn{id: 9, proto: "tcp", tcpConn: local}
	cc.reliSend = NewReliableSend(9, c.enqueue)
	cc.reliRecv = NewReliableRecv(9, c.makeLocalDeliver(cc), c.enqueue)
	c.mu.Lock()
	c.connections[9] = cc
	c.mu.Unlock()

	payload := make([]byte, 64*1024)
	for i := 0; i < 8; i++ {
		c.dispatchData(&TunnelPacket{
			ConnID: 9,
			Seq:    uint32(i + 1),
			Data:   payload,
		})
	}

	var acked int32
	done := make(chan struct{})
	go func() {
		c.handleDataAck(&TunnelPacket{ConnID: 9, Seq: 1})
		atomic.StoreInt32(&acked, 1)
		close(done)
	}()

	select {
	case <-done:
		if atomic.LoadInt32(&acked) != 1 {
			t.Fatal("ack handler did not run")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client handleDataAck blocked behind stuck CmdData writes")
	}
}

func TestDispatchDataSaturatesWithoutBlockingCaller(t *testing.T) {
	mgr := NewManager("")
	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	// Fill the semaphore with goroutines that never finish.
	block := make(chan struct{})
	for i := 0; i < maxConcurrentDataHandlers; i++ {
		s.dataSem <- struct{}{}
		go func() {
			<-block
			<-s.dataSem
		}()
	}
	defer close(block)

	done := make(chan struct{})
	go func() {
		s.dispatchData(&TunnelPacket{ConnID: 1, Seq: 1, Data: []byte("x")}, &netUDPAddr{ip: "203.0.113.1", port: 1})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("dispatchData blocked when data handlers were saturated")
	}
}
