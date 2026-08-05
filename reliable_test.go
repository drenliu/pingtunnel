package main

import (
	"sync"
	"testing"
	"time"
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

func TestReliableSendRetransmitExpireReturnsDead(t *testing.T) {
	rs := NewReliableSend(42, func(*TunnelPacket) {})
	if !rs.Send([]byte("lost")) {
		t.Fatal("Send failed")
	}
	rs.mu.Lock()
	for _, e := range rs.pending {
		e.retries = maxRetries
		e.sentAt = time.Now().Add(-retransmitTimeout - time.Millisecond)
	}
	rs.mu.Unlock()

	if !rs.Retransmit() {
		t.Fatal("expected dead=true after exceeding maxRetries")
	}
	if rs.PendingCount() != 0 {
		t.Fatalf("expired packet should be removed, pending=%d", rs.PendingCount())
	}
}

func TestReliableSendRetransmitLiveReturnsFalse(t *testing.T) {
	var n int
	rs := NewReliableSend(1, func(*TunnelPacket) { n++ })
	if !rs.Send([]byte("x")) {
		t.Fatal("Send failed")
	}
	rs.mu.Lock()
	for _, e := range rs.pending {
		e.sentAt = time.Now().Add(-retransmitTimeout - time.Millisecond)
	}
	rs.mu.Unlock()

	if rs.Retransmit() {
		t.Fatal("first retransmit should not expire")
	}
	if rs.PendingCount() != 1 {
		t.Fatalf("pending=%d", rs.PendingCount())
	}
	if n < 2 { // original Send + retransmit
		t.Fatalf("expected resend, enqueue count=%d", n)
	}
}
