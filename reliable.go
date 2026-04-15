package main

import (
	"sync"
	"time"
)

const (
	retransmitTimeout = 100 * time.Millisecond
	maxRetries        = 200
	maxUnacked        = 64
)

// ── sender side ──

type sendEntry struct {
	seq     uint32
	data    []byte
	sentAt  time.Time
	retries int
}

type ReliableSend struct {
	connID  uint32
	nextSeq uint32
	pending map[uint32]*sendEntry
	mu      sync.Mutex
	enqueue func(*TunnelPacket)
	closed  bool
}

func NewReliableSend(connID uint32, enqueue func(*TunnelPacket)) *ReliableSend {
	return &ReliableSend{
		connID:  connID,
		nextSeq: 1,
		pending: make(map[uint32]*sendEntry),
		enqueue: enqueue,
	}
}

// Send assigns a sequence number and enqueues the data packet.
// It blocks (polling) when the in-flight window is full.
func (rs *ReliableSend) Send(data []byte) bool {
	for {
		rs.mu.Lock()
		if rs.closed {
			rs.mu.Unlock()
			return false
		}
		if len(rs.pending) < maxUnacked {
			break
		}
		rs.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}

	seq := rs.nextSeq
	rs.nextSeq++
	rs.pending[seq] = &sendEntry{seq: seq, data: data, sentAt: time.Now()}
	rs.mu.Unlock()

	rs.enqueue(&TunnelPacket{Cmd: CmdData, ConnID: rs.connID, Seq: seq, Data: data})
	return true
}

func (rs *ReliableSend) Ack(seq uint32) {
	rs.mu.Lock()
	delete(rs.pending, seq)
	rs.mu.Unlock()
}

// Retransmit re-enqueues unacked packets that are older than the timeout.
func (rs *ReliableSend) Retransmit() {
	rs.mu.Lock()
	if rs.closed {
		rs.mu.Unlock()
		return
	}
	now := time.Now()
	var resend []*sendEntry
	var expired []uint32
	for seq, e := range rs.pending {
		if now.Sub(e.sentAt) > retransmitTimeout {
			e.retries++
			if e.retries > maxRetries {
				expired = append(expired, seq)
			} else {
				e.sentAt = now
				resend = append(resend, e)
			}
		}
	}
	for _, seq := range expired {
		delete(rs.pending, seq)
	}
	rs.mu.Unlock()

	for _, e := range resend {
		rs.enqueue(&TunnelPacket{Cmd: CmdData, ConnID: rs.connID, Seq: e.seq, Data: e.data})
	}
}

func (rs *ReliableSend) Close() {
	rs.mu.Lock()
	rs.closed = true
	rs.pending = nil
	rs.mu.Unlock()
}

func (rs *ReliableSend) PendingCount() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return len(rs.pending)
}

// ── receiver side ──

type ReliableRecv struct {
	connID  uint32
	nextSeq uint32
	buf     map[uint32][]byte
	mu      sync.Mutex
	deliver func([]byte) error
	ack     func(*TunnelPacket)
	closed  bool
}

func NewReliableRecv(connID uint32, deliver func([]byte) error, ack func(*TunnelPacket)) *ReliableRecv {
	return &ReliableRecv{
		connID:  connID,
		nextSeq: 1,
		buf:     make(map[uint32][]byte),
		deliver: deliver,
		ack:     ack,
	}
}

// Receive handles an incoming data packet: ACK, dedup, reorder, deliver.
func (rr *ReliableRecv) Receive(seq uint32, data []byte) error {
	rr.mu.Lock()
	if rr.closed {
		rr.mu.Unlock()
		return nil
	}

	rr.ack(&TunnelPacket{Cmd: CmdDataAck, ConnID: rr.connID, Seq: seq})

	if seq < rr.nextSeq {
		rr.mu.Unlock()
		return nil
	}
	if seq > rr.nextSeq {
		if _, ok := rr.buf[seq]; !ok {
			tmp := make([]byte, len(data))
			copy(tmp, data)
			rr.buf[seq] = tmp
		}
		rr.mu.Unlock()
		return nil
	}

	// seq == nextSeq — collect contiguous run for delivery.
	var batch [][]byte
	batch = append(batch, data)
	rr.nextSeq++
	for {
		if d, ok := rr.buf[rr.nextSeq]; ok {
			batch = append(batch, d)
			delete(rr.buf, rr.nextSeq)
			rr.nextSeq++
		} else {
			break
		}
	}
	rr.mu.Unlock()

	for _, d := range batch {
		if err := rr.deliver(d); err != nil {
			return err
		}
	}
	return nil
}

func (rr *ReliableRecv) Close() {
	rr.mu.Lock()
	rr.closed = true
	rr.buf = nil
	rr.mu.Unlock()
}
