package main

import (
	"sync"
	"testing"
)

func TestGenBootEpochStaysBelowSocksSpace(t *testing.T) {
	for i := 0; i < 200; i++ {
		epoch := genBootEpoch()
		if epoch == 0 || epoch >= socksConnIDBase {
			t.Fatalf("boot epoch %d out of server ConnID space [1, %d)", epoch, socksConnIDBase)
		}
	}
}

func TestAllocConnIDNeverEntersSocksSpace(t *testing.T) {
	s := &Server{nextConnID: socksConnIDBase - 3}
	seen := map[uint32]bool{}
	for i := 0; i < 8; i++ {
		id := s.allocConnID()
		if id == 0 || id >= socksConnIDBase {
			t.Fatalf("allocConnID returned %d; must stay in [1, %d)", id, socksConnIDBase)
		}
		if seen[id] {
			t.Fatalf("duplicate ConnID %d while wrapping near socks boundary", id)
		}
		seen[id] = true
	}
}

func TestAllocConnIDConcurrentUnique(t *testing.T) {
	s := &Server{nextConnID: socksConnIDBase - 50}
	const n = 200
	ids := make([]uint32, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			ids[i] = s.allocConnID()
		}()
	}
	wg.Wait()

	seen := make(map[uint32]int, n)
	for _, id := range ids {
		if id == 0 || id >= socksConnIDBase {
			t.Fatalf("allocConnID returned %d; must stay in [1, %d)", id, socksConnIDBase)
		}
		seen[id]++
	}
	for id, count := range seen {
		if count != 1 {
			t.Fatalf("ConnID %d allocated %d times", id, count)
		}
	}
}

func TestSocksDialRejectsServerConnIDSpace(t *testing.T) {
	mgr := NewManager("")
	kc, err := mgr.AddKey("test-key", "t", "", "", "tcp")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(mgr, true, "dns", ":0", "c.pingt.local", "")
	defer s.Close()

	from := &netUDPAddr{ip: "203.0.113.9", port: 4242}
	routeKey := s.queueKeyForAddr(kc.Hash, 0x11111111, from)
	if routeKey == "" {
		t.Fatal("empty route key")
	}

	// Pre-create a server-assigned connection in the low ID space.
	serverConnID := uint32(7)
	sc := &ServerConn{
		id:       serverConnID,
		keyHash:  kc.Hash,
		clientID: 0x11111111,
		routeKey: routeKey,
		ready:    make(chan struct{}),
		closed:   1, // already closed marker so cleanup is quiet
	}
	s.mu.Lock()
	s.connections[sc.mapKey()] = sc
	s.mu.Unlock()

	s.handleSocksDial(&TunnelPacket{
		KeyHash:  kc.Hash,
		ClientID: 0x11111111,
		ConnID:   serverConnID,
		Data:     []byte("example.com:80"),
	}, from)

	// Low-ID SOCKS dial must be rejected without replacing the existing connection.
	s.mu.RLock()
	got := s.connections[sc.mapKey()]
	s.mu.RUnlock()
	if got != sc {
		t.Fatal("SOCKS dial with server-space ConnID overwrote an existing connection")
	}

	// A close response should be queued for the client.
	pkt := s.dequeueRoute(routeKey)
	if pkt == nil || pkt.Cmd != CmdClose || pkt.ConnID != serverConnID {
		t.Fatalf("expected CmdClose for rejected SOCKS dial, got %#v", pkt)
	}
}

func TestNewServerNextConnIDBelowSocksSpace(t *testing.T) {
	for i := 0; i < 50; i++ {
		s := NewServer(NewManager(""), false, "dns", ":0", "c.pingt.local", "")
		if s.nextConnID == 0 || s.nextConnID >= socksConnIDBase {
			s.Close()
			t.Fatalf("nextConnID %d not in server space", s.nextConnID)
		}
		if s.bootEpoch != s.nextConnID {
			s.Close()
			t.Fatalf("bootEpoch %d != nextConnID %d", s.bootEpoch, s.nextConnID)
		}
		id := s.allocConnID()
		if id == 0 || id >= socksConnIDBase {
			s.Close()
			t.Fatalf("first allocConnID %d out of range", id)
		}
		s.Close()
	}
}

// netUDPAddr is a tiny net.Addr for tests (avoids real sockets).
type netUDPAddr struct {
	ip   string
	port int
}

func (a *netUDPAddr) Network() string { return "udp" }
func (a *netUDPAddr) String() string  { return a.ip + ":" + itoaPort(a.port) }

func itoaPort(p int) string {
	if p == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for p > 0 {
		i--
		b[i] = byte('0' + p%10)
		p /= 10
	}
	return string(b[i:])
}
