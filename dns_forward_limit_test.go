package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type blockingPacketConn struct {
	writes int32
}

func (c *blockingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}
func (c *blockingPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	atomic.AddInt32(&c.writes, 1)
	return len(b), nil
}
func (c *blockingPacketConn) Close() error                       { return nil }
func (c *blockingPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *blockingPacketConn) SetDeadline(time.Time) error        { return nil }
func (c *blockingPacketConn) SetReadDeadline(time.Time) error    { return nil }
func (c *blockingPacketConn) SetWriteDeadline(time.Time) error   { return nil }

func TestStartDNSForwardCapsConcurrentGoroutines(t *testing.T) {
	mgr := NewManager("")
	s := NewServer(mgr, false, "dns", ":0", "c.pingt.local", "127.0.0.1:1")
	defer s.Close()

	// Replace semaphore with a tiny cap so the test stays fast.
	const capN = 4
	s.dnsForwardSem = make(chan struct{}, capN)

	// Stall forwards by pointing upstream at a black hole and using the real
	// forwardDNSQuery path (DialUDP + Read with deadline). Fill the semaphore
	// first so subsequent starts must be rejected without waiting.
	for i := 0; i < capN; i++ {
		s.dnsForwardSem <- struct{}{}
	}

	pc := &blockingPacketConn{}
	addr := &net.UDPAddr{IP: net.IP{203, 0, 113, 9}, Port: 5353}
	req := make([]byte, 12) // minimal DNS header size

	var started int
	for i := 0; i < 64; i++ {
		if s.startDNSForward(pc, req, addr) {
			started++
		}
	}
	if started != 0 {
		t.Fatalf("expected all forwards rejected while saturated, got %d started", started)
	}

	// Free one slot; exactly one new forward should be accepted.
	<-s.dnsForwardSem
	if !s.startDNSForward(pc, append([]byte(nil), req...), addr) {
		t.Fatal("expected forward to start after freeing a slot")
	}

	// Drain the intentional pre-fill so Close / GC stay clean; the one real
	// forward goroutine releases its slot when Dial/Read fails.
	for i := 0; i < capN-1; i++ {
		<-s.dnsForwardSem
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(s.dnsForwardSem) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("forward goroutine did not release semaphore (len=%d)", len(s.dnsForwardSem))
}

func TestStartDNSForwardNilOrEmptySkipped(t *testing.T) {
	s := NewServer(NewManager(""), false, "dns", ":0", "c.pingt.local", "")
	defer s.Close()
	pc := &blockingPacketConn{}
	addr := &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 53}
	if s.startDNSForward(pc, make([]byte, 12), addr) {
		t.Fatal("empty dnsUpstream should not start a forward")
	}
	s.dnsUpstream = "127.0.0.1:1"
	if s.startDNSForward(pc, make([]byte, 8), addr) {
		t.Fatal("short DNS payload should not start a forward")
	}
	if s.startDNSForward(nil, make([]byte, 12), addr) {
		t.Fatal("nil PacketConn should not start a forward")
	}
	if s.startDNSForward(pc, make([]byte, 12), nil) {
		t.Fatal("nil client addr should not start a forward")
	}
}

func TestStartDNSForwardRunsUnderCap(t *testing.T) {
	s := NewServer(NewManager(""), false, "dns", ":0", "c.pingt.local", "127.0.0.1:1")
	defer s.Close()
	s.dnsForwardSem = make(chan struct{}, 8)

	pc := &blockingPacketConn{}
	addr := &net.UDPAddr{IP: net.IP{198, 51, 100, 7}, Port: 5353}
	req := make([]byte, 12)

	const n = 8
	for i := 0; i < n; i++ {
		if !s.startDNSForward(pc, append([]byte(nil), req...), addr) {
			t.Fatalf("forward %d rejected under cap", i)
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(s.dnsForwardSem) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected semaphore drained after forwards finish, len=%d", len(s.dnsForwardSem))
}
