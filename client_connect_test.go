package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestHandleConnectRetransmitKeepsLiveSession(t *testing.T) {
	c := NewClient("", "", "127.0.0.1:9", "k", "tcp", "", "icmp", "")
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	cc := &ClientConn{id: 42, proto: "tcp", tcpConn: local}
	cc.reliSend = NewReliableSend(42, c.enqueue)
	cc.reliRecv = NewReliableRecv(42, func([]byte) error { return nil }, c.enqueue)
	c.connections[42] = cc

	c.handleConnect(&TunnelPacket{Cmd: CmdConnect, ConnID: 42, Data: []byte("127.0.0.1:9")})

	c.mu.Lock()
	got := c.connections[42]
	c.mu.Unlock()
	if got != cc {
		t.Fatal("retransmitted CmdConnect replaced or removed the live session")
	}
	if atomic.LoadInt32(&cc.silentClose) != 0 {
		t.Fatal("live session was silently closed on CmdConnect retransmit")
	}

	select {
	case pkt := <-c.sendQueue:
		if pkt.Cmd != CmdConnectAck || pkt.ConnID != 42 {
			t.Fatalf("want ConnectAck conn=42, got cmd=%d conn=%d", pkt.Cmd, pkt.ConnID)
		}
	case <-time.After(time.Second):
		t.Fatal("expected ConnectAck for retransmitted CmdConnect")
	}
}

func TestHandleConnectPendingIgnoresRetransmit(t *testing.T) {
	c := NewClient("", "", "127.0.0.1:9", "k", "tcp", "", "icmp", "")
	c.pending[7] = true

	c.handleConnect(&TunnelPacket{Cmd: CmdConnect, ConnID: 7, Data: []byte("127.0.0.1:9")})

	c.mu.Lock()
	_, stillPending := c.pending[7]
	_, hasConn := c.connections[7]
	c.mu.Unlock()
	if !stillPending {
		t.Fatal("pending dial marker cleared by Connect retransmit")
	}
	if hasConn {
		t.Fatal("unexpected connection created while dial is pending")
	}
	select {
	case pkt := <-c.sendQueue:
		t.Fatalf("unexpected packet while dial pending: cmd=%d", pkt.Cmd)
	default:
	}
}
