package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Server struct {
	manager  *Manager
	icmpConn *icmp.PacketConn

	clientAddr net.Addr
	clientMu   sync.RWMutex

	listeners   map[string]net.Listener
	connections map[uint32]*ServerConn
	nextConnID  uint32

	sendQueue chan *TunnelPacket

	mu     sync.RWMutex
	closed int32
	done   chan struct{}

	stats struct {
		icmpIn     uint64
		icmpOut    uint64
		badKey     uint64
		retransmit uint64
	}
}

type ServerConn struct {
	id         uint32
	tcpConn    net.Conn
	targetAddr string
	keyHash    [16]byte
	closed     int32
	ready      chan struct{}
	readyOnce  sync.Once
	reliSend   *ReliableSend
	reliRecv   *ReliableRecv
}

func NewServer(mgr *Manager) *Server {
	return &Server{
		manager:     mgr,
		listeners:   make(map[string]net.Listener),
		connections: make(map[uint32]*ServerConn),
		sendQueue:   make(chan *TunnelPacket, 4096),
		done:        make(chan struct{}),
	}
}

func (s *Server) Close() {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return
	}
	close(s.done)
	if s.icmpConn != nil {
		s.icmpConn.Close()
	}
	s.mu.Lock()
	for _, l := range s.listeners {
		l.Close()
	}
	for _, sc := range s.connections {
		if atomic.CompareAndSwapInt32(&sc.closed, 0, 1) {
			sc.tcpConn.Close()
			sc.reliSend.Close()
			sc.reliRecv.Close()
		}
	}
	s.mu.Unlock()
}

func (s *Server) Run() error {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("ICMP listen failed (run as root): %w", err)
	}
	s.icmpConn = conn
	defer conn.Close()

	log.Println("[server] started, waiting for tunnel connections ...")

	s.manager.StartTrafficLoop(s.done)
	s.StartConfiguredListeners()
	go s.retransmitLoop()
	go s.statsLoop()

	buf := make([]byte, 65535)
	for atomic.LoadInt32(&s.closed) == 0 {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if atomic.LoadInt32(&s.closed) != 0 {
				return nil
			}
			log.Printf("[server] ICMP read: %v", err)
			continue
		}

		msg, err := icmp.ParseMessage(ProtocolICMP, buf[:n])
		if err != nil || msg.Type != ipv4.ICMPTypeEcho {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		pkt, err := DecodeTunnelPacket(echo.Data)
		if err != nil || pkt.Magic != MagicRequest {
			continue
		}

		if s.manager.ValidateKey(pkt.KeyHash) == nil {
			atomic.AddUint64(&s.stats.badKey, 1)
			continue
		}

		atomic.AddUint64(&s.stats.icmpIn, 1)

		s.clientMu.Lock()
		s.clientAddr = addr
		s.clientMu.Unlock()

		clientKeyHash := pkt.KeyHash
		s.handlePacket(pkt)

		var resp *TunnelPacket
		select {
		case resp = <-s.sendQueue:
			if len(s.sendQueue) > 0 {
				resp.Flags |= FlagMore
			}
		default:
			resp = &TunnelPacket{Cmd: CmdPing}
		}
		resp.Magic = MagicResponse
		resp.KeyHash = clientKeyHash

		respData, err := resp.Encode()
		if err != nil {
			continue
		}
		reply := &icmp.Message{
			Type: ipv4.ICMPTypeEchoReply,
			Code: 0,
			Body: &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: respData},
		}
		rb, err := reply.Marshal(nil)
		if err != nil {
			continue
		}
		conn.WriteTo(rb, addr)
		atomic.AddUint64(&s.stats.icmpOut, 1)
	}
	return nil
}

// --------------- packet handlers ---------------

func (s *Server) handlePacket(pkt *TunnelPacket) {
	switch pkt.Cmd {
	case CmdSetup:
		s.handleSetup(pkt)
	case CmdConnectAck:
		s.handleConnectAck(pkt)
	case CmdData:
		s.handleData(pkt)
	case CmdDataAck:
		s.handleDataAck(pkt)
	case CmdClose:
		s.handleClose(pkt)
	}
}

func (s *Server) handleSetup(pkt *TunnelPacket) {
	parts := bytes.SplitN(pkt.Data, []byte("|"), 2)
	if len(parts) != 2 {
		log.Println("[server] bad setup payload")
		return
	}
	listenAddr := normalizeListenAddr(string(parts[0]))
	targetAddr := normalizeTargetAddr(string(parts[1]))

	if !s.manager.IsRuleAllowed(pkt.KeyHash, listenAddr, targetAddr) {
		kc := s.manager.ValidateKey(pkt.KeyHash)
		keyInfo := "unknown"
		if kc != nil {
			keyInfo = kc.Name + " (key=" + kc.Key + ")"
		}
		log.Printf("[server] setup rejected: %s -> %s key=%s (not allowed)", listenAddr, targetAddr, keyInfo)
		return
	}

	s.mu.RLock()
	_, exists := s.listeners[listenAddr]
	s.mu.RUnlock()

	if !exists {
		go s.startTCPListener(listenAddr, targetAddr, pkt.KeyHash)
	}
	s.enqueue(&TunnelPacket{Cmd: CmdSetupAck})
	log.Printf("[server] tunnel setup: listen=%s target=%s", listenAddr, targetAddr)
}

func (s *Server) handleConnectAck(pkt *TunnelPacket) {
	s.mu.RLock()
	sc := s.connections[pkt.ConnID]
	s.mu.RUnlock()
	if sc != nil {
		sc.readyOnce.Do(func() { close(sc.ready) })
		log.Printf("[server] conn %d: client ready", pkt.ConnID)
	}
}

func (s *Server) handleData(pkt *TunnelPacket) {
	s.mu.RLock()
	sc := s.connections[pkt.ConnID]
	s.mu.RUnlock()
	if sc == nil || len(pkt.Data) == 0 {
		return
	}
	s.manager.RecordIn(sc.keyHash, len(pkt.Data))
	if err := sc.reliRecv.Receive(pkt.Seq, pkt.Data); err != nil {
		log.Printf("[server] conn %d recv err: %v", pkt.ConnID, err)
		s.closeConn(sc)
	}
}

func (s *Server) handleDataAck(pkt *TunnelPacket) {
	s.mu.RLock()
	sc := s.connections[pkt.ConnID]
	s.mu.RUnlock()
	if sc != nil {
		sc.reliSend.Ack(pkt.Seq)
	}
}

func (s *Server) handleClose(pkt *TunnelPacket) {
	s.mu.Lock()
	sc, ok := s.connections[pkt.ConnID]
	if ok {
		delete(s.connections, pkt.ConnID)
	}
	s.mu.Unlock()
	if ok && atomic.CompareAndSwapInt32(&sc.closed, 0, 1) {
		sc.tcpConn.Close()
		sc.reliSend.Close()
		sc.reliRecv.Close()
		sc.readyOnce.Do(func() { close(sc.ready) })
		log.Printf("[server] conn %d closed by client", pkt.ConnID)
	}
}

// --------------- auto-start ---------------

func (s *Server) StartConfiguredListeners() {
	keys := s.manager.GetKeys()
	for _, kc := range keys {
		for _, r := range kc.Rules {
			s.mu.RLock()
			_, exists := s.listeners[r.ListenAddr]
			s.mu.RUnlock()
			if !exists {
				go s.startTCPListener(r.ListenAddr, r.TargetAddr, kc.Hash)
			}
		}
	}
}

// --------------- TCP ---------------

func (s *Server) startTCPListener(listenAddr, targetAddr string, keyHash [16]byte) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Printf("[server] listen %s: %v", listenAddr, err)
		return
	}
	s.mu.Lock()
	s.listeners[listenAddr] = ln
	s.mu.Unlock()

	log.Printf("[server] TCP listening on %s", listenAddr)

	for atomic.LoadInt32(&s.closed) == 0 {
		tc, err := ln.Accept()
		if err != nil {
			if atomic.LoadInt32(&s.closed) != 0 {
				return
			}
			log.Printf("[server] accept: %v", err)
			continue
		}

		connID := atomic.AddUint32(&s.nextConnID, 1)
		sc := &ServerConn{
			id:         connID,
			tcpConn:    tc,
			targetAddr: targetAddr,
			keyHash:    keyHash,
			ready:      make(chan struct{}),
		}
		sc.reliSend = NewReliableSend(connID, s.enqueue)
		sc.reliRecv = NewReliableRecv(connID,
			func(data []byte) error { _, err := sc.tcpConn.Write(data); return err },
			s.enqueue,
		)

		s.mu.Lock()
		s.connections[connID] = sc
		s.mu.Unlock()

		log.Printf("[server] conn %d from %s", connID, tc.RemoteAddr())
		s.enqueue(&TunnelPacket{
			Cmd:    CmdConnect,
			ConnID: connID,
			Data:   []byte(targetAddr),
		})

		go s.waitReady(sc)
	}
}

func (s *Server) waitReady(sc *ServerConn) {
	retry := time.NewTicker(time.Second)
	defer retry.Stop()
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()

	for {
		select {
		case <-sc.ready:
			go s.readTCP(sc)
			return
		case <-retry.C:
			s.enqueue(&TunnelPacket{
				Cmd:    CmdConnect,
				ConnID: sc.id,
				Data:   []byte(sc.targetAddr),
			})
		case <-timeout.C:
			log.Printf("[server] conn %d: connect timeout", sc.id)
			s.closeConn(sc)
			return
		case <-s.done:
			return
		}
	}
}

func (s *Server) readTCP(sc *ServerConn) {
	defer s.closeConn(sc)
	buf := make([]byte, MaxPayloadSize)
	for atomic.LoadInt32(&sc.closed) == 0 {
		n, err := sc.tcpConn.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			s.manager.RecordOut(sc.keyHash, n)
			data := make([]byte, n)
			copy(data, buf[:n])
			if !sc.reliSend.Send(data) {
				return
			}
		}
	}
}

func (s *Server) closeConn(sc *ServerConn) {
	if !atomic.CompareAndSwapInt32(&sc.closed, 0, 1) {
		return
	}
	sc.tcpConn.Close()
	sc.reliSend.Close()
	sc.reliRecv.Close()
	sc.readyOnce.Do(func() { close(sc.ready) })

	s.mu.Lock()
	delete(s.connections, sc.id)
	s.mu.Unlock()

	s.enqueue(&TunnelPacket{Cmd: CmdClose, ConnID: sc.id})
	log.Printf("[server] conn %d closed", sc.id)
}

// --------------- connection info ---------------

type ConnInfo struct {
	ID         uint32 `json:"id"`
	ClientAddr string `json:"client_addr"`
	TargetAddr string `json:"target_addr"`
}

func (s *Server) GetConnsByKey() map[[16]byte][]ConnInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := make(map[[16]byte][]ConnInfo)
	for _, sc := range s.connections {
		ci := ConnInfo{
			ID:         sc.id,
			TargetAddr: sc.targetAddr,
		}
		if sc.tcpConn != nil {
			ci.ClientAddr = sc.tcpConn.RemoteAddr().String()
		}
		m[sc.keyHash] = append(m[sc.keyHash], ci)
	}
	return m
}

// --------------- background loops ---------------

func (s *Server) retransmitLoop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.RLock()
			for _, sc := range s.connections {
				sc.reliSend.Retransmit()
			}
			s.mu.RUnlock()
		case <-s.done:
			return
		}
	}
}

func (s *Server) statsLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			in := atomic.LoadUint64(&s.stats.icmpIn)
			out := atomic.LoadUint64(&s.stats.icmpOut)
			bad := atomic.LoadUint64(&s.stats.badKey)
			s.mu.RLock()
			conns := len(s.connections)
			s.mu.RUnlock()
			log.Printf("[server] stats: icmp_in=%d icmp_out=%d bad_key=%d conns=%d",
				in, out, bad, conns)
		case <-s.done:
			return
		}
	}
}

func (s *Server) enqueue(pkt *TunnelPacket) {
	select {
	case s.sendQueue <- pkt:
	default:
		log.Println("[server] send queue full, dropping")
	}
}
