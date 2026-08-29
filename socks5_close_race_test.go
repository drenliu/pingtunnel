package main

import (
	"io"
	"net"
	"testing"
	"time"
)

// Regression: CmdClose after CmdSocksDialAck but before connections[connID] is
// installed used to be a no-op (wait already cleared, map empty). serveSOCKSConn
// then installed a ghost relay while the server session was already gone.
func TestSOCKSCloseAfterDialAckCancelsBeforeInstall(t *testing.T) {
	c := NewClient("", "127.0.0.1", "", "socks-close-race", "tcp", "", "icmp", "")
	defer c.Close()

	connID := socksConnIDBase + 42
	ch := make(chan bool, 1)
	c.socksMu.Lock()
	c.socksWait[connID] = ch
	c.socksMu.Unlock()

	// DialAck wakes the waiter; Close follows before relay install (server accepted
	// then immediately tore down — both frames often back-to-back on the wire).
	c.handleSocksDialAck(&TunnelPacket{Cmd: CmdSocksDialAck, ConnID: connID})
	c.handleCloseCmd(&TunnelPacket{Cmd: CmdClose, ConnID: connID})

	select {
	case ok := <-ch:
		if !ok {
			// Close nack won the channel race; still require cancel bit for the
			// DialAck-true path where the buffer was already consumed.
		}
	case <-time.After(time.Second):
		t.Fatal("waiter was not signaled")
	}

	c.socksMu.Lock()
	cancelled := c.socksCancel[connID]
	c.socksMu.Unlock()
	if !cancelled {
		t.Fatal("CmdClose must set socksCancel so install can abort")
	}

	// Mirror serveSOCKSConn install gate.
	c.socksMu.Lock()
	cancelled = c.socksCancel[connID]
	delete(c.socksCancel, connID)
	delete(c.socksWait, connID)
	c.socksMu.Unlock()
	if !cancelled {
		t.Fatal("install must observe cancel — otherwise a ghost session is created")
	}

	c.mu.RLock()
	_, exists := c.connections[connID]
	c.mu.RUnlock()
	if exists {
		t.Fatal("ghost SOCKS connection present after DialAck+Close race")
	}
}

func TestServeSOCKSConnRefusesWhenCloseRacesDialAck(t *testing.T) {
	c := NewClient("", "127.0.0.1", "", "socks-close-race-e2e", "tcp", "", "icmp", "")
	defer c.Close()

	go func() {
		for {
			select {
			case pkt := <-c.sendQueue:
				if pkt == nil {
					return
				}
				if pkt.Cmd == CmdSocksDial {
					// Ack then immediately Close — reproduces server accept+EOF.
					c.handleSocksDialAck(&TunnelPacket{Cmd: CmdSocksDialAck, ConnID: pkt.ConnID})
					c.handleCloseCmd(&TunnelPacket{Cmd: CmdClose, ConnID: pkt.ConnID})
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

	reply := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("connect reply: %v", err)
	}
	if reply[1] == 0 {
		t.Fatal("SOCKS connect succeeded; expected refusal after DialAck+Close race")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveSOCKSConn did not finish after refused dial")
	}

	c.mu.RLock()
	n := len(c.connections)
	c.mu.RUnlock()
	if n != 0 {
		t.Fatalf("ghost relay connections remain: %d", n)
	}
}
