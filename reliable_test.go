package main

import (
	"sync"
	"testing"
)

func TestReliableSendSendAndAck(t *testing.T) {
	var mu sync.Mutex
	var out []*TunnelPacket
	enq := func(p *TunnelPacket) {
		mu.Lock()
		out = append(out, p)
		mu.Unlock()
	}
	rs := NewReliableSend(7, enq)
	if !rs.Send([]byte("a")) || !rs.Send([]byte("b")) {
		t.Fatal("Send failed")
	}
	if rs.PendingCount() != 2 {
		t.Fatalf("pending %d", rs.PendingCount())
	}
	rs.Ack(1)
	rs.Ack(2)
	if rs.PendingCount() != 0 {
		t.Fatalf("after ack pending %d", rs.PendingCount())
	}
	mu.Lock()
	n := len(out)
	mu.Unlock()
	if n != 2 {
		t.Fatalf("enqueued %d packets", n)
	}
	rs.Close()
	if rs.Send([]byte("x")) {
		t.Fatal("Send after Close should fail")
	}
}

func TestReliableRecvInOrderDelivery(t *testing.T) {
	var delivered [][]byte
	var acks []*TunnelPacket
	deliver := func(b []byte) error {
		delivered = append(delivered, append([]byte(nil), b...))
		return nil
	}
	ack := func(p *TunnelPacket) { acks = append(acks, p) }
	rr := NewReliableRecv(3, deliver, ack)
	if err := rr.Receive(1, []byte("first")); err != nil {
		t.Fatal(err)
	}
	if len(delivered) != 1 || string(delivered[0]) != "first" {
		t.Fatalf("delivered=%v", delivered)
	}
	if len(acks) != 1 || acks[0].Seq != 1 {
		t.Fatalf("acks=%v", acks)
	}
}

func TestReliableRecvReorderThenFlush(t *testing.T) {
	var delivered [][]byte
	deliver := func(b []byte) error {
		delivered = append(delivered, append([]byte(nil), b...))
		return nil
	}
	ack := func(*TunnelPacket) {}
	rr := NewReliableRecv(9, deliver, ack)
	// out of order: 2 before 1
	if err := rr.Receive(2, []byte("two")); err != nil {
		t.Fatal(err)
	}
	if len(delivered) != 0 {
		t.Fatalf("should buffer, delivered=%v", delivered)
	}
	if err := rr.Receive(1, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if len(delivered) != 2 || string(delivered[0]) != "one" || string(delivered[1]) != "two" {
		t.Fatalf("delivered=%v", delivered)
	}
}

func TestReliableRecvDuplicateIgnored(t *testing.T) {
	var n int
	deliver := func([]byte) error {
		n++
		return nil
	}
	ack := func(*TunnelPacket) {}
	rr := NewReliableRecv(1, deliver, ack)
	if err := rr.Receive(1, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := rr.Receive(1, []byte("dup")); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("duplicate seq should not deliver again, n=%d", n)
	}
}

func TestReliableRecvRejectsGapBeyondSendWindow(t *testing.T) {
	var delivered int
	var acks int
	deliver := func([]byte) error {
		delivered++
		return nil
	}
	ack := func(*TunnelPacket) { acks++ }
	rr := NewReliableRecv(1, deliver, ack)

	// Honest max gap is maxUnacked-1 (e.g. seq 64 while waiting for 1).
	if err := rr.Receive(maxUnacked, []byte("edge")); err != nil {
		t.Fatalf("seq at window edge should buffer: %v", err)
	}
	if delivered != 0 || acks != 1 {
		t.Fatalf("delivered=%d acks=%d", delivered, acks)
	}
	if len(rr.buf) != 1 {
		t.Fatalf("buf len=%d", len(rr.buf))
	}

	// seq = nextSeq + maxUnacked is unreachable for a windowed sender.
	if err := rr.Receive(1+maxUnacked, []byte("too-far")); err == nil {
		t.Fatal("expected reorder window error")
	}
	if delivered != 0 {
		t.Fatalf("must not deliver after reject, delivered=%d", delivered)
	}
	if acks != 1 {
		t.Fatalf("rejected seq must not be ACKed, acks=%d", acks)
	}
	if len(rr.buf) != 1 {
		t.Fatalf("reject must not grow buf, len=%d", len(rr.buf))
	}
}

func TestReliableRecvAllowsFullHonestReorderWindow(t *testing.T) {
	deliver := func([]byte) error { return nil }
	ack := func(*TunnelPacket) {}
	rr := NewReliableRecv(3, deliver, ack)

	// Fill every in-window future seq while still missing nextSeq=1 (2..maxUnacked).
	for seq := uint32(2); seq <= maxUnacked; seq++ {
		if err := rr.Receive(seq, []byte{byte(seq)}); err != nil {
			t.Fatalf("seq %d within send window rejected: %v", seq, err)
		}
	}
	want := int(maxUnacked - 1)
	if len(rr.buf) != want {
		t.Fatalf("buf len=%d want %d", len(rr.buf), want)
	}

	// Duplicate of an already-buffered seq must still be accepted (dedup).
	if err := rr.Receive(2, []byte("dup")); err != nil {
		t.Fatalf("duplicate buffered seq should be ignored, not rejected: %v", err)
	}
	if len(rr.buf) != want {
		t.Fatalf("dedup changed buf len=%d", len(rr.buf))
	}

	// One past the window must fail without growing the buffer.
	if err := rr.Receive(1+maxUnacked, []byte("overflow")); err == nil {
		t.Fatal("expected reorder window error")
	}
	if len(rr.buf) != want {
		t.Fatalf("reject must not grow buf, len=%d", len(rr.buf))
	}
}
