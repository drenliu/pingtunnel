package main

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func waitNonPing(s *Server, routeKey string, timeout time.Duration) *TunnelPacket {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pkt := s.dequeueRoute(routeKey)
		if pkt != nil && pkt.Cmd != CmdPing {
			return pkt
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

// Regression: CmdSocksDialAck was enqueued once. Under ICMP/DNS loss the client
// never saw it, timed out, and left the server holding a live target TCP conn.
func TestSocksDialAckIsRetransmitted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	acceptDone := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		acceptDone <- c
	}()

	mgr := NewManager("")
	kc, err := mgr.AddKey("socks-ack-key", "t", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, true, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	from := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 11), Port: 5355}
	routeKey := s.queueKeyForAddr(kc.Hash, 0x11111111, from)
	if routeKey == "" {
		t.Fatal("empty route key")
	}

	connID := socksConnIDBase + 7
	s.handleSocksDial(&TunnelPacket{
		KeyHash:  kc.Hash,
		ClientID: 0x11111111,
		ConnID:   connID,
		Data:     []byte(ln.Addr().String()),
	}, from)

	first := waitNonPing(s, routeKey, 3*time.Second)
	if first == nil || first.Cmd != CmdSocksDialAck || first.ConnID != connID {
		t.Fatalf("expected first CmdSocksDialAck, got %#v", first)
	}

	var targetConn net.Conn
	select {
	case targetConn = <-acceptDone:
	case <-time.After(2 * time.Second):
		t.Fatal("target did not accept SOCKS dial")
	}
	defer targetConn.Close()

	// Simulate loss of the first ack: do not deliver it to the client.
	// A retry must appear within ~1s without any client retransmit.
	second := waitNonPing(s, routeKey, 2*time.Second)
	if second == nil || second.Cmd != CmdSocksDialAck || second.ConnID != connID {
		t.Fatalf("expected retransmitted CmdSocksDialAck, got %#v", second)
	}

	s.mu.RLock()
	sc := s.connections[connID]
	s.mu.RUnlock()
	if sc == nil || atomic.LoadInt32(&sc.closed) != 0 {
		t.Fatal("SOCKS session should still be live while acks retry")
	}
}

func TestSocksDialTimeoutSendsCmdClose(t *testing.T) {
	prev := socksDialWaitTimeout
	socksDialWaitTimeout = 80 * time.Millisecond
	defer func() { socksDialWaitTimeout = prev }()

	c := NewClient("", "127.0.0.1", "", "test-key", "tcp", ":0", "icmp", "")
	defer c.Close()

	gotClose := make(chan uint32, 1)
	go func() {
		for {
			select {
			case pkt := <-c.sendQueue:
				if pkt == nil {
					return
				}
				if pkt.Cmd == CmdClose {
					select {
					case gotClose <- pkt.ConnID:
					default:
					}
				}
				// Intentionally never send DialAck — client must time out.
			case <-c.done:
				return
			}
		}
	}()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c.serveSOCKSConn(serverConn)
	}()

	if _, err := clientConn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("greeting write: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}

	req := []byte{5, 1, 0, 3, byte(len("example.com"))}
	req = append(req, []byte("example.com")...)
	req = append(req, 0, 80)
	if _, err := clientConn.Write(req); err != nil {
		t.Fatalf("connect write: %v", err)
	}

	select {
	case id := <-gotClose:
		if id < socksConnIDBase {
			t.Fatalf("CmdClose ConnID %d not in SOCKS space", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected CmdClose after SOCKS dial wait timeout")
	}

	reply := make([]byte, 10)
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("SOCKS refused reply: %v", err)
	}
	if reply[1] != 5 {
		t.Fatalf("expected SOCKS connection refused (5), got %d", reply[1])
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveSOCKSConn did not finish after timeout")
	}
}
