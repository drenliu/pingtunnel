package main

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestHandleConnectAbortsAfterSessionReset verifies that an in-flight CmdConnect
// dial cancelled by resetTunnelSessions (server restart) does not reinstall a
// ghost session or send ConnectAck after the reset.
func TestHandleConnectAbortsAfterSessionReset(t *testing.T) {
	// Blackhole documentation address: DialTimeout stays in flight until the 10s dial
	// deadline, giving resetTunnelSessions a wide race window.
	const blackhole = "203.0.113.1:59999"

	c := NewClient("", "127.0.0.1", blackhole, "reset-e2e", "tcp", "", "icmp", "")
	defer c.Close()

	done := make(chan struct{})
	go func() {
		c.handleConnect(&TunnelPacket{Cmd: CmdConnect, ConnID: 7, Data: []byte(blackhole)})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		c.mu.RLock()
		pending := c.pending[7]
		c.mu.RUnlock()
		if pending {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for pending dial")
		}
		time.Sleep(5 * time.Millisecond)
	}

	genBefore := atomic.LoadUint32(&c.sessionGen)
	c.resetTunnelSessions()
	if atomic.LoadUint32(&c.sessionGen) == genBefore {
		t.Fatal("sessionGen was not bumped by resetTunnelSessions")
	}

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("handleConnect did not return after reset")
	}

	c.mu.RLock()
	_, exists := c.connections[7]
	pending := c.pending[7]
	c.mu.RUnlock()
	if exists {
		t.Fatal("ghost connection present after reset during dial")
	}
	if pending {
		t.Fatal("pending flag still set after cancelled dial")
	}

	for {
		select {
		case pkt := <-c.sendQueue:
			if pkt.Cmd == CmdConnectAck && pkt.ConnID == 7 {
				t.Fatal("ConnectAck enqueued for cancelled dial")
			}
			if pkt.Cmd == CmdClose && pkt.ConnID == 7 {
				t.Fatal("CmdClose enqueued for cancelled dial (could kill reused ConnID)")
			}
		default:
			return
		}
	}
}

// TestResetTunnelSessionsFailsSOCKSWaiters ensures in-flight SOCKS dials are nack'd on restart.
func TestResetTunnelSessionsFailsSOCKSWaiters(t *testing.T) {
	c := NewClient("", "127.0.0.1", "", "socks-reset", "tcp", ":0", "icmp", "")
	defer c.Close()

	ch := make(chan bool, 1)
	c.socksMu.Lock()
	c.socksWait[socksConnIDBase+1] = ch
	c.socksMu.Unlock()

	c.resetTunnelSessions()

	select {
	case ok := <-ch:
		if ok {
			t.Fatal("expected socks waiter to receive failure")
		}
	case <-time.After(time.Second):
		t.Fatal("socks waiter was not signaled")
	}

	c.socksMu.Lock()
	_, left := c.socksWait[socksConnIDBase+1]
	c.socksMu.Unlock()
	if left {
		t.Fatal("socks waiter entry not cleared")
	}
}
