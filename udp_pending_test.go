package main

import (
	"testing"
)

func TestQueueUDPFromUserCapsPendingBeforeReady(t *testing.T) {
	s := NewServer(NewManager(""), false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	sc := &ServerConn{
		id:       1,
		proto:    "udp",
		keyHash:  ComputeKeyHash("udp-pending"),
		ready:    make(chan struct{}),
		reliSend: NewReliableSend(1, func(*TunnelPacket) {}),
		reliRecv: NewReliableRecv(1, func([]byte) error { return nil }, func(*TunnelPacket) {}),
	}

	pkt := make([]byte, 1024)
	for i := 0; i < maxUDPPendingDatagrams+32; i++ {
		sc.queueUDPFromUser(s, pkt)
	}

	sc.udpMu.Lock()
	n := len(sc.udpPending)
	bytes := sc.udpPendingBytes
	sc.udpMu.Unlock()

	if n != maxUDPPendingDatagrams {
		t.Fatalf("pending datagrams=%d, want capped at %d", n, maxUDPPendingDatagrams)
	}
	if bytes != maxUDPPendingDatagrams*len(pkt) {
		t.Fatalf("pending bytes=%d, want %d", bytes, maxUDPPendingDatagrams*len(pkt))
	}
}

func TestQueueUDPFromUserCapsPendingBytes(t *testing.T) {
	s := NewServer(NewManager(""), false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	sc := &ServerConn{
		id:       2,
		proto:    "udp",
		keyHash:  ComputeKeyHash("udp-pending-bytes"),
		ready:    make(chan struct{}),
		reliSend: NewReliableSend(2, func(*TunnelPacket) {}),
		reliRecv: NewReliableRecv(2, func([]byte) error { return nil }, func(*TunnelPacket) {}),
	}

	// Few huge datagrams should hit the byte cap before the count cap.
	big := make([]byte, 64<<10) // 64 KiB
	for i := 0; i < 8; i++ {
		sc.queueUDPFromUser(s, big)
	}

	sc.udpMu.Lock()
	n := len(sc.udpPending)
	bytes := sc.udpPendingBytes
	sc.udpMu.Unlock()

	if bytes > maxUDPPendingBytes {
		t.Fatalf("pending bytes=%d exceeds cap %d", bytes, maxUDPPendingBytes)
	}
	if n > maxUDPPendingDatagrams {
		t.Fatalf("pending datagrams=%d exceeds cap %d", n, maxUDPPendingDatagrams)
	}
	// 256 KiB / 64 KiB = 4 datagrams fit exactly.
	if n != 4 || bytes != maxUDPPendingBytes {
		t.Fatalf("got n=%d bytes=%d, want n=4 bytes=%d", n, bytes, maxUDPPendingBytes)
	}
}

func TestFlushUDPPendingClearsByteCounter(t *testing.T) {
	s := NewServer(NewManager(""), false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	var sent int
	sc := &ServerConn{
		id:      3,
		proto:   "udp",
		keyHash: ComputeKeyHash("udp-flush"),
		ready:   make(chan struct{}),
		reliSend: NewReliableSend(3, func(p *TunnelPacket) {
			if p.Cmd == CmdData {
				sent++
			}
		}),
		reliRecv: NewReliableRecv(3, func([]byte) error { return nil }, func(*TunnelPacket) {}),
	}

	sc.queueUDPFromUser(s, []byte("a"))
	sc.queueUDPFromUser(s, []byte("bb"))
	sc.flushUDPPending(s)

	sc.udpMu.Lock()
	n := len(sc.udpPending)
	bytes := sc.udpPendingBytes
	ready := sc.udpReady
	sc.udpMu.Unlock()

	if !ready || n != 0 || bytes != 0 {
		t.Fatalf("after flush ready=%v pending=%d bytes=%d", ready, n, bytes)
	}
	if sent != 2 {
		t.Fatalf("flushed sends=%d, want 2", sent)
	}
}
