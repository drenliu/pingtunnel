package main

import (
	"net"
	"testing"
	"time"
)

// Regression: ClientConn.readTarget used a MaxPayloadSize (1300) buffer for UDP.
// net.UDPConn.Read silently truncates oversized datagrams (n=len(buf), err=nil),
// so target→user UDP payloads larger than the tunnel MTU were corrupted.
func TestReadTargetDropsOversizedUDPWithoutTruncation(t *testing.T) {
	target, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	clientUDP, err := net.DialUDP("udp", nil, target.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()

	c := NewClient("", "127.0.0.1", "", "udp-key", "udp", "", "icmp", "")
	defer c.Close()

	cc := &ClientConn{id: 42, proto: "udp", tcpConn: clientUDP}
	cc.reliSend = NewReliableSend(42, c.enqueue)
	cc.reliRecv = NewReliableRecv(42, func([]byte) error { return nil }, c.enqueue)

	c.mu.Lock()
	c.connections[42] = cc
	c.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.readTarget(cc)
	}()

	// Larger than MaxPayloadSize; previously this was silently truncated to 1300.
	payload := make([]byte, MaxPayloadSize+700)
	payload[0] = 0xA5
	payload[len(payload)-1] = 0x5A
	if _, err := target.WriteTo(payload, clientUDP.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	// Give readTarget a moment to observe the datagram.
	deadline := time.Now().Add(2 * time.Second)
	sawDrop := false
	for time.Now().Before(deadline) {
		select {
		case pkt := <-c.sendQueue:
			if pkt.Cmd == CmdData {
				t.Fatalf("oversized UDP was forwarded (%d bytes); must drop, not truncate/send", len(pkt.Data))
			}
		default:
			time.Sleep(10 * time.Millisecond)
		}
		// Connection should still be alive (drop ≠ close).
		c.mu.RLock()
		_, ok := c.connections[42]
		c.mu.RUnlock()
		if ok {
			sawDrop = true
			break
		}
	}
	if !sawDrop {
		t.Fatal("expected session to remain open after dropping oversized UDP")
	}

	// A fitting datagram must still be forwarded intact.
	small := make([]byte, 64)
	small[0], small[63] = 1, 2
	if _, err := target.WriteTo(small, clientUDP.LocalAddr()); err != nil {
		t.Fatalf("small WriteTo: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case pkt := <-c.sendQueue:
			if pkt.Cmd != CmdData {
				continue
			}
			if len(pkt.Data) != len(small) || pkt.Data[0] != 1 || pkt.Data[63] != 2 {
				t.Fatalf("small UDP corrupted/truncated: len=%d data=%v", len(pkt.Data), pkt.Data[:min(8, len(pkt.Data))])
			}
			clientUDP.Close()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("readTarget did not exit after close")
			}
			return
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Fatal("timed out waiting for in-limit UDP datagram")
}

func TestQueueUDPFromUserDropsOversized(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("k", "t", "", "", "udp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, false, "icmp", "", "", "")
	defer s.Close()

	routeKey := s.queueKeyForAddr(kc.Hash, 0xabcd, &netUDPAddr{ip: "203.0.113.1", port: 9})
	sc := &ServerConn{
		id:       7,
		proto:    "udp",
		keyHash:  kc.Hash,
		clientID: 0xabcd,
		routeKey: routeKey,
		ready:    make(chan struct{}),
		udpReady: true,
	}
	sc.reliSend = NewReliableSend(7, s.makeEnqueueRoute(routeKey))
	sc.reliRecv = NewReliableRecv(7, func([]byte) error { return nil }, s.makeEnqueueRoute(routeKey))

	big := make([]byte, MaxPayloadSize+1)
	sc.queueUDPFromUser(s, big)
	if sc.reliSend.PendingCount() != 0 {
		t.Fatalf("oversized UDP was queued (%d pending)", sc.reliSend.PendingCount())
	}

	ok := make([]byte, 100)
	sc.queueUDPFromUser(s, ok)
	if sc.reliSend.PendingCount() != 1 {
		t.Fatalf("in-limit UDP should be queued, pending=%d", sc.reliSend.PendingCount())
	}
}
