package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpClientHeartbeatTTL: if no ICMP from a tunnel key for this long, treat client as offline.
const icmpClientHeartbeatTTL = 45 * time.Second

type Server struct {
	manager  *Manager
	icmpConn *icmp.PacketConn

	// socksDynamic: when true, accept CmdSocksDial / CmdSocksRegister from clients.
	socksDynamic bool

	// Per-tunnel-key outbound queue: ICMP replies must carry payloads for the same key
	// as the requesting client, so multiple clients with different keys do not cross-talk.
	sendQueues   map[[16]byte]chan *TunnelPacket
	sendQueuesMu sync.Mutex

	// ICMP tunnel client (source) per forwarding rule: key = hex(keyHash)|tcp/ or udp/ + listen.
	ruleTunnelClients map[string]*ruleTunnelState
	ruleTunnelMu      sync.Mutex

	listenersTCP map[string]net.Listener
	listenersUDP map[string]*net.UDPConn
	udpSessions  map[string]*ServerConn // key: listenAddr|remoteUDP
	connections  map[uint32]*ServerConn
	nextConnID   uint32

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
	proto      string // "tcp" or "udp"
	tcpConn    net.Conn
	udpSock    *net.UDPConn
	udpRemote  *net.UDPAddr
	udpSessKey string
	targetAddr string
	keyHash    [16]byte
	closed     int32
	ready      chan struct{}
	readyOnce  sync.Once
	reliSend   *ReliableSend
	reliRecv   *ReliableRecv

	udpMu      sync.Mutex
	udpReady   bool
	udpPending [][]byte

	idleMu    sync.Mutex
	idleTimer *time.Timer
}

type ruleTunnelState struct {
	addr     net.Addr
	lastSeen time.Time
}

func NewServer(mgr *Manager, socksDynamic bool) *Server {
	return &Server{
		manager:           mgr,
		socksDynamic:      socksDynamic,
		sendQueues:        make(map[[16]byte]chan *TunnelPacket),
		ruleTunnelClients: make(map[string]*ruleTunnelState),
		listenersTCP:      make(map[string]net.Listener),
		listenersUDP:      make(map[string]*net.UDPConn),
		udpSessions:       make(map[string]*ServerConn),
		connections:       make(map[uint32]*ServerConn),
		done:              make(chan struct{}),
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
	for _, l := range s.listenersTCP {
		l.Close()
	}
	for _, u := range s.listenersUDP {
		u.Close()
	}
	for _, sc := range s.connections {
		if atomic.CompareAndSwapInt32(&sc.closed, 0, 1) {
			if sc.tcpConn != nil {
				sc.tcpConn.Close()
			}
			sc.stopIdleTimer()
			sc.reliSend.Close()
			sc.reliRecv.Close()
		}
	}
	s.mu.Unlock()

	s.sendQueuesMu.Lock()
	for _, ch := range s.sendQueues {
		close(ch)
	}
	s.sendQueues = make(map[[16]byte]chan *TunnelPacket)
	s.sendQueuesMu.Unlock()
	s.ruleTunnelMu.Lock()
	s.ruleTunnelClients = make(map[string]*ruleTunnelState)
	s.ruleTunnelMu.Unlock()
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

		clientKeyHash := pkt.KeyHash
		s.handlePacket(pkt, addr)
		s.noteRuleTunnelICMP(clientKeyHash, addr)

		resp := s.dequeueForKey(clientKeyHash)
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

func (s *Server) handlePacket(pkt *TunnelPacket, from net.Addr) {
	switch pkt.Cmd {
	case CmdSetup:
		s.handleSetup(pkt, from)
	case CmdConnectAck:
		s.handleConnectAck(pkt)
	case CmdData:
		s.handleData(pkt)
	case CmdDataAck:
		s.handleDataAck(pkt)
	case CmdClose:
		s.handleClose(pkt)
	case CmdSocksDial:
		s.handleSocksDial(pkt)
	case CmdSocksRegister:
		s.handleSocksRegister(pkt, from)
	}
}

func (s *Server) handleSetup(pkt *TunnelPacket, from net.Addr) {
	parts := bytes.Split(pkt.Data, []byte("|"))
	if len(parts) < 2 {
		log.Println("[server] bad setup payload")
		return
	}
	listenAddr := normalizeListenAddr(string(parts[0]))
	targetAddr := normalizeTargetAddr(string(parts[1]))
	protocol := "tcp"
	if len(parts) >= 3 {
		protocol = normalizeProtocol(string(parts[2]))
	}

	if !s.manager.IsRuleAllowed(pkt.KeyHash, listenAddr, targetAddr, protocol) {
		kc := s.manager.ValidateKey(pkt.KeyHash)
		keyInfo := "unknown"
		if kc != nil {
			if kc.Name != "" {
				keyInfo = kc.Name + " (key=" + kc.Key + ")"
			} else {
				keyInfo = "key=" + kc.Key
			}
		}
		log.Printf("[server] setup rejected: %s -> %s (%s) key=%s (not allowed)", listenAddr, targetAddr, protocol, keyInfo)
		return
	}

	mapKey := ListenerMapKey(protocol, listenAddr)
	s.mu.RLock()
	exists := false
	if protocol == "udp" {
		_, exists = s.listenersUDP[mapKey]
	} else {
		_, exists = s.listenersTCP[mapKey]
	}
	s.mu.RUnlock()

	if !exists {
		if protocol == "udp" {
			go s.startUDPListener(listenAddr, targetAddr, pkt.KeyHash)
		} else {
			go s.startTCPListener(listenAddr, targetAddr, pkt.KeyHash)
		}
	}
	s.enqueueKey(pkt.KeyHash, &TunnelPacket{Cmd: CmdSetupAck})
	s.registerRuleTunnelClient(pkt.KeyHash, mapKey, from)
	log.Printf("[server] tunnel setup: listen=%s target=%s proto=%s", listenAddr, targetAddr, protocol)
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
		sc.stopIdleTimer()
		if sc.tcpConn != nil {
			sc.tcpConn.Close()
		}
		sc.reliSend.Close()
		sc.reliRecv.Close()
		sc.readyOnce.Do(func() { close(sc.ready) })
		if sc.udpSessKey != "" {
			s.mu.Lock()
			delete(s.udpSessions, sc.udpSessKey)
			s.mu.Unlock()
		}
		log.Printf("[server] conn %d closed by client", pkt.ConnID)
	}
}

func (s *Server) handleSocksRegister(pkt *TunnelPacket, from net.Addr) {
	if !s.socksDynamic {
		log.Printf("[server] SOCKS register rejected (socks-dynamic disabled)")
		s.enqueueKey(pkt.KeyHash, &TunnelPacket{Cmd: CmdSocksRegisterNack})
		return
	}
	s.enqueueKey(pkt.KeyHash, &TunnelPacket{Cmd: CmdSetupAck})
	s.registerRuleTunnelClient(pkt.KeyHash, "socks-dynamic", from)
	log.Printf("[server] SOCKS dynamic forwarding registered for tunnel key")
}

func (s *Server) handleSocksDial(pkt *TunnelPacket) {
	if !s.socksDynamic {
		log.Printf("[server] SOCKS dial conn %d rejected (socks-dynamic disabled)", pkt.ConnID)
		s.enqueueKey(pkt.KeyHash, &TunnelPacket{Cmd: CmdClose, ConnID: pkt.ConnID})
		return
	}
	if pkt.ConnID == 0 || len(pkt.Data) == 0 {
		return
	}
	target := normalizeSocksDialTarget(string(pkt.Data))
	if target == "" {
		s.enqueueKey(pkt.KeyHash, &TunnelPacket{Cmd: CmdClose, ConnID: pkt.ConnID})
		return
	}

	s.mu.Lock()
	if _, exists := s.connections[pkt.ConnID]; exists {
		s.mu.Unlock()
		s.enqueueKey(pkt.KeyHash, &TunnelPacket{Cmd: CmdClose, ConnID: pkt.ConnID})
		return
	}
	s.mu.Unlock()

	conn, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		log.Printf("[server] SOCKS dial %d %s: %v", pkt.ConnID, target, err)
		s.enqueueKey(pkt.KeyHash, &TunnelPacket{Cmd: CmdClose, ConnID: pkt.ConnID})
		return
	}

	connID := pkt.ConnID
	sc := &ServerConn{
		id:         connID,
		proto:      "tcp",
		tcpConn:    conn,
		targetAddr: target,
		keyHash:    pkt.KeyHash,
		ready:      make(chan struct{}),
	}
	enk := s.makeEnqueueKey(pkt.KeyHash)
	sc.reliSend = NewReliableSend(connID, enk)
	sc.reliRecv = NewReliableRecv(connID,
		func(data []byte) error { _, e := conn.Write(data); return e },
		enk,
	)

	s.mu.Lock()
	s.connections[connID] = sc
	s.mu.Unlock()

	sc.readyOnce.Do(func() { close(sc.ready) })
	s.enqueueKey(pkt.KeyHash, &TunnelPacket{Cmd: CmdSocksDialAck, ConnID: connID})
	log.Printf("[server] SOCKS conn %d -> %s", connID, target)

	go s.readTCP(sc)
}

// --------------- auto-start ---------------

func (s *Server) StartConfiguredListeners() {
	keys := s.manager.GetKeys()
	for _, kc := range keys {
		for _, r := range kc.Rules {
			mapKey := ListenerMapKey(r.Protocol, r.ListenAddr)
			s.mu.RLock()
			var exists bool
			if r.Protocol == "udp" {
				_, exists = s.listenersUDP[mapKey]
			} else {
				_, exists = s.listenersTCP[mapKey]
			}
			s.mu.RUnlock()
			if !exists {
				if r.Protocol == "udp" {
					go s.startUDPListener(r.ListenAddr, r.TargetAddr, kc.Hash)
				} else {
					go s.startTCPListener(r.ListenAddr, r.TargetAddr, kc.Hash)
				}
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
	mapKey := ListenerMapKey("tcp", listenAddr)
	s.mu.Lock()
	if _, exists := s.listenersTCP[mapKey]; exists {
		s.mu.Unlock()
		ln.Close()
		return
	}
	s.listenersTCP[mapKey] = ln
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
			proto:      "tcp",
			tcpConn:    tc,
			targetAddr: targetAddr,
			keyHash:    keyHash,
			ready:      make(chan struct{}),
		}
		enk := s.makeEnqueueKey(keyHash)
		sc.reliSend = NewReliableSend(connID, enk)
		sc.reliRecv = NewReliableRecv(connID,
			func(data []byte) error { _, err := sc.tcpConn.Write(data); return err },
			enk,
		)

		s.mu.Lock()
		s.connections[connID] = sc
		s.mu.Unlock()

		log.Printf("[server] conn %d from %s", connID, tc.RemoteAddr())
		s.enqueueKey(keyHash, &TunnelPacket{
			Cmd:    CmdConnect,
			ConnID: connID,
			Data:   []byte(targetAddr),
		})

		go s.waitReady(sc)
	}
}

func (s *Server) startUDPListener(listenAddr, targetAddr string, keyHash [16]byte) {
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		log.Printf("[server] UDP listen %s: %v", listenAddr, err)
		return
	}
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		log.Printf("[server] UDP listen %s: unexpected conn type", listenAddr)
		return
	}
	mapKey := ListenerMapKey("udp", listenAddr)
	s.mu.Lock()
	if _, exists := s.listenersUDP[mapKey]; exists {
		s.mu.Unlock()
		uc.Close()
		return
	}
	s.listenersUDP[mapKey] = uc
	s.mu.Unlock()

	log.Printf("[server] UDP listening on %s", listenAddr)

	s.udpReadLoop(uc, listenAddr, targetAddr, keyHash)

	s.mu.Lock()
	delete(s.listenersUDP, mapKey)
	s.mu.Unlock()
	uc.Close()
	log.Printf("[server] UDP listener stopped %s", listenAddr)
}

func (s *Server) udpReadLoop(uc *net.UDPConn, listenAddr, targetAddr string, keyHash [16]byte) {
	buf := make([]byte, 65535)
	for atomic.LoadInt32(&s.closed) == 0 {
		uc.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := uc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if atomic.LoadInt32(&s.closed) != 0 {
				return
			}
			log.Printf("[server] UDP read %s: %v", listenAddr, err)
			return
		}
		ra, ok := addr.(*net.UDPAddr)
		if !ok || n <= 0 {
			continue
		}
		sessKey := listenAddr + "|" + ra.String()

		s.mu.Lock()
		sc, exists := s.udpSessions[sessKey]
		if exists {
			s.mu.Unlock()
			data := make([]byte, n)
			copy(data, buf[:n])
			sc.queueUDPFromUser(s, data)
			continue
		}

		connID := atomic.AddUint32(&s.nextConnID, 1)
		sc = &ServerConn{
			id:         connID,
			proto:      "udp",
			udpSock:    uc,
			udpRemote:  ra,
			udpSessKey: sessKey,
			targetAddr: targetAddr,
			keyHash:    keyHash,
			ready:      make(chan struct{}),
		}
		enk := s.makeEnqueueKey(keyHash)
		sc.reliSend = NewReliableSend(connID, enk)
		sc.reliRecv = NewReliableRecv(connID,
			func(data []byte) error {
				_, werr := sc.udpSock.WriteTo(data, sc.udpRemote)
				if werr == nil {
					sc.resetUDPIdle(s)
				}
				return werr
			},
			enk,
		)
		s.udpSessions[sessKey] = sc
		s.connections[connID] = sc
		s.mu.Unlock()

		log.Printf("[server] UDP conn %d from %s", connID, ra.String())
		s.enqueueKey(keyHash, &TunnelPacket{
			Cmd:    CmdConnect,
			ConnID: connID,
			Data:   []byte(targetAddr),
		})
		go s.waitReady(sc)

		data := make([]byte, n)
		copy(data, buf[:n])
		sc.queueUDPFromUser(s, data)
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
			if sc.proto == "udp" {
				sc.flushUDPPending(s)
				return
			}
			go s.readTCP(sc)
			return
		case <-retry.C:
			s.enqueueKey(sc.keyHash, &TunnelPacket{
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
	sc.stopIdleTimer()
	if sc.tcpConn != nil {
		sc.tcpConn.Close()
	}
	sc.reliSend.Close()
	sc.reliRecv.Close()
	sc.readyOnce.Do(func() { close(sc.ready) })

	s.mu.Lock()
	delete(s.connections, sc.id)
	if sc.udpSessKey != "" {
		delete(s.udpSessions, sc.udpSessKey)
	}
	s.mu.Unlock()

	s.enqueueKey(sc.keyHash, &TunnelPacket{Cmd: CmdClose, ConnID: sc.id})
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
		} else if sc.udpRemote != nil {
			ci.ClientAddr = "udp:" + sc.udpRemote.String()
		}
		m[sc.keyHash] = append(m[sc.keyHash], ci)
	}
	return m
}

func ruleTunnelMapKey(keyHash [16]byte, listenerMapKey string) string {
	return hex.EncodeToString(keyHash[:]) + "|" + listenerMapKey
}

func (s *Server) registerRuleTunnelClient(keyHash [16]byte, listenerMapKey string, from net.Addr) {
	if from == nil {
		return
	}
	k := ruleTunnelMapKey(keyHash, listenerMapKey)
	s.ruleTunnelMu.Lock()
	s.ruleTunnelClients[k] = &ruleTunnelState{addr: from, lastSeen: time.Now()}
	s.ruleTunnelMu.Unlock()
}

func (s *Server) noteRuleTunnelICMP(keyHash [16]byte, from net.Addr) {
	if from == nil {
		return
	}
	prefix := hex.EncodeToString(keyHash[:]) + "|"
	now := time.Now()
	s.ruleTunnelMu.Lock()
	for mapKey, st := range s.ruleTunnelClients {
		if st == nil || st.addr == nil {
			continue
		}
		if !strings.HasPrefix(mapKey, prefix) {
			continue
		}
		if st.addr.String() == from.String() {
			st.lastSeen = now
		}
	}
	s.ruleTunnelMu.Unlock()
}

func (s *Server) ruleListenMapKey(r *ForwardRule) string {
	return ListenerMapKey(normalizeProtocol(r.Protocol), r.ListenAddr)
}

// IsRuleTunnelOnline is true when this rule's listen port has a tunnel client sending ICMP recently.
func (s *Server) IsRuleTunnelOnline(keyHash [16]byte, r *ForwardRule) bool {
	k := ruleTunnelMapKey(keyHash, s.ruleListenMapKey(r))
	s.ruleTunnelMu.Lock()
	st, ok := s.ruleTunnelClients[k]
	if !ok || st == nil || st.addr == nil {
		s.ruleTunnelMu.Unlock()
		return false
	}
	on := time.Since(st.lastSeen) <= icmpClientHeartbeatTTL
	s.ruleTunnelMu.Unlock()
	return on
}

// ICMPClientAddrForRule returns the ICMP source seen for this listen rule, or "" if offline.
func (s *Server) ICMPClientAddrForRule(keyHash [16]byte, r *ForwardRule) string {
	k := ruleTunnelMapKey(keyHash, s.ruleListenMapKey(r))
	s.ruleTunnelMu.Lock()
	st, ok := s.ruleTunnelClients[k]
	if !ok || st == nil || st.addr == nil || time.Since(st.lastSeen) > icmpClientHeartbeatTTL {
		s.ruleTunnelMu.Unlock()
		return ""
	}
	a := st.addr.String()
	s.ruleTunnelMu.Unlock()
	return a
}

func (s *Server) pruneStaleICMPPeers() {
	now := time.Now()
	s.ruleTunnelMu.Lock()
	for k, st := range s.ruleTunnelClients {
		if st == nil || now.Sub(st.lastSeen) > icmpClientHeartbeatTTL {
			delete(s.ruleTunnelClients, k)
		}
	}
	s.ruleTunnelMu.Unlock()
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

func (s *Server) makeEnqueueKey(keyHash [16]byte) func(*TunnelPacket) {
	return func(p *TunnelPacket) {
		s.enqueueKey(keyHash, p)
	}
}

func (s *Server) enqueueKey(keyHash [16]byte, pkt *TunnelPacket) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}
	s.sendQueuesMu.Lock()
	ch := s.sendQueues[keyHash]
	if ch == nil {
		ch = make(chan *TunnelPacket, 4096)
		s.sendQueues[keyHash] = ch
	}
	s.sendQueuesMu.Unlock()
	select {
	case ch <- pkt:
	default:
		log.Println("[server] send queue full for key, dropping")
	}
}

func (s *Server) dequeueForKey(keyHash [16]byte) *TunnelPacket {
	s.sendQueuesMu.Lock()
	ch := s.sendQueues[keyHash]
	s.sendQueuesMu.Unlock()
	if ch == nil {
		return &TunnelPacket{Cmd: CmdPing}
	}
	select {
	case resp := <-ch:
		if len(ch) > 0 {
			resp.Flags |= FlagMore
		}
		return resp
	default:
		return &TunnelPacket{Cmd: CmdPing}
	}
}

func (sc *ServerConn) queueUDPFromUser(s *Server, data []byte) {
	sc.udpMu.Lock()
	if sc.udpReady {
		sc.udpMu.Unlock()
		s.manager.RecordOut(sc.keyHash, len(data))
		sc.reliSend.Send(data)
		sc.resetUDPIdle(s)
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	sc.udpPending = append(sc.udpPending, cp)
	sc.udpMu.Unlock()
}

func (sc *ServerConn) flushUDPPending(s *Server) {
	sc.udpMu.Lock()
	sc.udpReady = true
	pending := sc.udpPending
	sc.udpPending = nil
	sc.udpMu.Unlock()
	for _, p := range pending {
		s.manager.RecordOut(sc.keyHash, len(p))
		sc.reliSend.Send(p)
	}
	sc.resetUDPIdle(s)
}

func (sc *ServerConn) resetUDPIdle(s *Server) {
	if sc.proto != "udp" {
		return
	}
	sc.idleMu.Lock()
	defer sc.idleMu.Unlock()
	if sc.idleTimer != nil {
		sc.idleTimer.Stop()
	}
	sc.idleTimer = time.AfterFunc(5*time.Minute, func() {
		log.Printf("[server] conn %d: UDP idle timeout", sc.id)
		s.closeConn(sc)
	})
}

func (sc *ServerConn) stopIdleTimer() {
	sc.idleMu.Lock()
	defer sc.idleMu.Unlock()
	if sc.idleTimer != nil {
		sc.idleTimer.Stop()
		sc.idleTimer = nil
	}
}
