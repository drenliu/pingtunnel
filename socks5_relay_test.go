package main

import (
	"io"
	"net"
	"testing"
	"time"
)

// Regression: serveSOCKSConn used to return after starting readTarget in a
// goroutine, so defer tc.Close() reset the SOCKS client immediately.
func TestServeSOCKSConnKeepsLocalConnOpenDuringRelay(t *testing.T) {
	c := NewClient("", "127.0.0.1", "", "test-key", "tcp", ":0", "icmp", "")
	defer c.Close()

	// Drain outbound tunnel packets and ACK SOCKS dials.
	go func() {
		for {
			select {
			case pkt := <-c.sendQueue:
				if pkt == nil {
					return
				}
				if pkt.Cmd == CmdSocksDial {
					c.handleSocksDialAck(&TunnelPacket{Cmd: CmdSocksDialAck, ConnID: pkt.ConnID})
				}
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

	// SOCKS5 greeting + CONNECT example.com:80
	if _, err := clientConn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("greeting write: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if buf[0] != 5 || buf[1] != 0 {
		t.Fatalf("unexpected greeting reply %#v", buf)
	}

	req := []byte{
		5, 1, 0, 3,
		byte(len("example.com")),
	}
	req = append(req, []byte("example.com")...)
	req = append(req, 0, 80)
	if _, err := clientConn.Write(req); err != nil {
		t.Fatalf("connect write: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if reply[1] != 0 {
		t.Fatalf("connect failed status=%d", reply[1])
	}

	payload := []byte("GET / HTTP/1.0\r\n\r\n")
	if _, err := clientConn.Write(payload); err != nil {
		t.Fatalf("payload write: %v", err)
	}

	// Local SOCKS conn must stay open long enough for the client payload to be
	// queued into the tunnel (previously it was reset within microseconds).
	deadline := time.Now().Add(2 * time.Second)
	for {
		c.mu.RLock()
		n := len(c.connections)
		c.mu.RUnlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SOCKS relay connection disappeared before payload could be read")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Give readTarget a moment to pull the bytes we wrote.
	time.Sleep(50 * time.Millisecond)

	select {
	case <-done:
		t.Fatal("serveSOCKSConn returned while SOCKS client was still open")
	default:
	}

	clientConn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveSOCKSConn did not finish after client close")
	}
}
