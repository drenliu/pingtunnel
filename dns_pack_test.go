package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type dnsLoopPacketConn struct {
	readCh  chan packetFrom
	writeCh chan packetFrom
	closed  int32
}

type packetFrom struct {
	data []byte
	addr net.Addr
}

func (c *dnsLoopPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt, ok := <-c.readCh:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, pkt.data)
		return n, pkt.addr, nil
	case <-time.After(200 * time.Millisecond):
		return 0, nil, &net.DNSError{Err: "timeout", IsTimeout: true}
	}
}

func (c *dnsLoopPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if atomic.LoadInt32(&c.closed) != 0 {
		return 0, net.ErrClosed
	}
	cp := append([]byte(nil), p...)
	select {
	case c.writeCh <- packetFrom{data: cp, addr: addr}:
		return len(p), nil
	default:
		return 0, nil
	}
}

func (c *dnsLoopPacketConn) Close() error {
	if atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		close(c.readCh)
	}
	return nil
}
func (c *dnsLoopPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1053} }
func (c *dnsLoopPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *dnsLoopPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dnsLoopPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// TestDNSReadLoopRequeuesOversizedFrame ensures a dequeued frame that cannot be
// packed into the DNS response is put back on the send queue (not silently lost)
// and the DNS query still receives a Ping reply.
func TestDNSReadLoopRequeuesOversizedFrame(t *testing.T) {
	const qname = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example.com"
	const udpSize uint16 = 256

	mgr := NewManager("")
	kc := mgr.EnsureKey("dns-pack-test-key")

	srv := NewServer(mgr, false, "dns", "127.0.0.1:0", qname, "")
	defer srv.Close()

	pc := &dnsLoopPacketConn{
		readCh:  make(chan packetFrom, 2),
		writeCh: make(chan packetFrom, 2),
	}
	srv.tunDNS = pc
	go srv.dnsReadLoop(pc)

	clientID := uint32(0xabcd1234)
	clientAddr := &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 5300}
	routeKey := srv.queueKeyForAddr(kc.Hash, clientID, clientAddr)

	// Oversized CmdData relative to udpSize=256 + long QNAME (maxResp ~45).
	oversized := &TunnelPacket{
		Cmd:    CmdData,
		ConnID: 42,
		Seq:    7,
		Data:   make([]byte, 64),
	}
	srv.enqueueRoute(routeKey, oversized)

	pingReq := &TunnelPacket{
		Magic:    MagicRequest,
		KeyHash:  kc.Hash,
		ClientID: clientID,
		Cmd:      CmdPing,
	}
	payload, err := pingReq.Encode()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := buildDNSRequestWithSize(0x1111, qname, payload, udpSize)
	if err != nil {
		t.Fatal(err)
	}
	pc.readCh <- packetFrom{data: wire, addr: clientAddr}

	var got packetFrom
	select {
	case got = <-pc.writeCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for DNS response")
	}

	_, respRaw, err := parseDNSResponse(got.data)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeTunnelPacket(respRaw)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Cmd != CmdPing {
		t.Fatalf("expected Ping reply while oversized frame is deferred, got cmd=%d", dec.Cmd)
	}

	// The oversized frame must still be queued (not dropped after dequeue).
	recovered := srv.dequeueRoute(routeKey)
	if recovered == nil || recovered.Cmd != CmdData || recovered.ConnID != 42 || recovered.Seq != 7 {
		t.Fatalf("oversized frame was lost after pack failure: %+v", recovered)
	}
	if len(recovered.Data) != 64 {
		t.Fatalf("data len=%d want 64", len(recovered.Data))
	}
	if recovered.Flags&FlagMore != 0 {
		t.Fatal("requeued frame should clear FlagMore")
	}

	// Sanity: after the floor fix, a correctly sized chunk packs.
	chunk := dnsMaxDataChunk(qname, udpSize, true)
	if chunk <= 0 || chunk >= 64 {
		t.Fatalf("expected packable chunk < 64 for this QNAME/size, got %d", chunk)
	}
	okPkt := &TunnelPacket{Magic: MagicResponse, Cmd: CmdData, ConnID: 1, Seq: 1, Data: make([]byte, chunk)}
	raw, err := okPkt.Encode()
	if err != nil {
		t.Fatal(err)
	}
	req := new(dns.Msg)
	if err := req.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if _, err := buildDNSResponseWithSize(req, raw, udpSize); err != nil {
		t.Fatalf("correctly sized chunk should pack: %v", err)
	}
}
