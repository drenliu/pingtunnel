package main

import (
	"testing"
	"time"
)

// Regression: handleCloseCmd used to ignore pending dials. A CmdClose arriving
// while DialTimeout was in flight left pending set, so the dial could still
// install connections[ConnID] and send ConnectAck for a server session that was
// already gone (rule restart / connect teardown) — a ghost target session.
func TestHandleCloseCancelsInFlightConnectDial(t *testing.T) {
	// Blackhole documentation address: DialTimeout stays in flight until the 10s
	// dial deadline, giving CmdClose a wide race window.
	const blackhole = "203.0.113.1:59999"

	c := NewClient("", "127.0.0.1", blackhole, "close-during-dial", "tcp", "", "icmp", "")
	defer c.Close()

	done := make(chan struct{})
	go func() {
		c.handleConnect(&TunnelPacket{Cmd: CmdConnect, ConnID: 11, Data: []byte(blackhole)})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		c.mu.RLock()
		pending := c.pending[11]
		c.mu.RUnlock()
		if pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for pending dial")
		}
		time.Sleep(5 * time.Millisecond)
	}

	c.handleCloseCmd(&TunnelPacket{Cmd: CmdClose, ConnID: 11})

	c.mu.RLock()
	pendingAfterClose := c.pending[11]
	c.mu.RUnlock()
	if pendingAfterClose {
		t.Fatal("pending dial marker still set after CmdClose")
	}

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("handleConnect did not return after CmdClose during dial")
	}

	c.mu.RLock()
	_, exists := c.connections[11]
	pending := c.pending[11]
	c.mu.RUnlock()
	if exists {
		t.Fatal("ghost connection present after CmdClose during dial")
	}
	if pending {
		t.Fatal("pending flag still set after cancelled dial")
	}

	for {
		select {
		case pkt := <-c.sendQueue:
			if pkt.Cmd == CmdConnectAck && pkt.ConnID == 11 {
				t.Fatal("ConnectAck enqueued for cancelled dial")
			}
			if pkt.Cmd == CmdClose && pkt.ConnID == 11 {
				t.Fatal("CmdClose enqueued for cancelled dial (could kill reused ConnID)")
			}
		default:
			return
		}
	}
}
