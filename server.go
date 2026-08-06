package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// icmpClientHeartbeatTTL: if no ICMP from a tunnel key for this long, treat client as offline.
const icmpClientHeartbeatTTL = 45 * time.Second

type Server struct {
	manager *Manager
	// At most one of these may be nil. Both may be set when the server uses ICMP+DNS.
	tunICM      net.PacketConn
	tunDNS      net.PacketConn
	serveICMP   bool
	serveDNS    bool
	dnsAddr     string
	dnsQName    string
	dnsUpstream string // non-tunnel QNAME queries are forwarded here when set

	dnsRouteUDPSize   map[string]uint16 // routeKey -> client EDNS UDP payload size
	dnsRouteUDPSizeMu sync.Mutex

	// socksDynamic: when true, accept CmdSocksDial / CmdSocksRegister from clients.
	socksDynamic bool

	// Per-tunnel-endpoint outbound queue: key hash + tunnel peer address.
	// This prevents cross-talk when multiple clients share the same tunnel key.
	sendQueues   map[string]chan *TunnelPacket
	sendQueuesMu sync.Mutex

	// ICMP tunnel client (source) per forwarding rule: key = hex(keyHash)|tcp/ or udp/ + listen.
	ruleTunnelClients map[string]*ruleTunnelState
	ruleTunnelMu      sync.Mutex

	listenersTCP map[string]net.Listener
	listenersUDP map[string]*net.UDPConn
	udpSessions  map[string]*ServerConn // key: listenAddr|remoteUDP
	connections  map[uint32]*ServerConn
	nextConnID   uint32

	mu        sync.RWMutex
	closed    int32
	done      chan struct{}
	bootEpoch uint32 // changes each server process start; clients use it to detect restart

	stats struct {
		tunIn      uint64
		tunOut     uint64
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
	clientID   uint32
	routeKey   string
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
	clientID uint32
	routeKey string
	lastSeen time.Time
}

func NewServer(mgr *Manager, socksDynamic bool, transport, dnsAddr, dnsQName, dnsUpstream string) *Server {
	si, sd := parseServerTransports(transport)
	da, qn := finalizeDNSServerAddr(sd, dnsAddr, dnsQName)
	bootEpoch := genBootEpoch()
	return &Server{
		manager:           mgr,
		socksDynamic:      socksDynamic,
		serveICMP:         si,
		serveDNS:          sd,
		dnsAddr:           da,
		dnsQName:          qn,
		dnsUpstream:       strings.TrimSpace(dnsUpstream),
		dnsRouteUDPSize:   make(map[string]uint16),
		sendQueues:        make(map[string]chan *TunnelPacket),
		ruleTunnelClients: make(map[string]*ruleTunnelState),
		listenersTCP:      make(map[string]net.Listener),
		listenersUDP:      make(map[string]*net.UDPConn),
		udpSessions:       make(map[string]*ServerConn),
		connections:       make(map[uint32]*ServerConn),
		done:              make(chan struct{}),
		bootEpoch:         bootEpoch,
		nextConnID:        bootEpoch, // avoid connID reuse across restarts (stale CmdClose); kept < socksConnIDBase
	}
}

// allocConnID returns a ConnID in [1, socksConnIDBase). SOCKS dials use IDs >= socksConnIDBase;
// mixing the two spaces overwrites entries in Server.connections / Client.connections.
func (s *Server) allocConnID() uint32 {
	for {
		id := atomic.AddUint32(&s.nextConnID, 1)
		if id > 0 && id < socksConnIDBase {
			return id
		}
		// Wrap back into the server-assigned space below SOCKS IDs.
		atomic.CompareAndSwapUint32(&s.nextConnID, id, 0)
	}
}

func (s *Server) Close() {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return
	}
	Audit("server.shutdown", map[string]string{"result": "ok"})
	close(s.done)
	if s.tunICM != nil {
		s.tunICM.Close()
	}
	if s.tunDNS != nil {
		s.tunDNS.Close()
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
	s.sendQueues = make(map[string]chan *TunnelPacket)
	s.sendQueuesMu.Unlock()
	s.ruleTunnelMu.Lock()
	s.ruleTunnelClients = make(map[string]*ruleTunnelState)
	s.ruleTunnelMu.Unlock()
	s.dnsRouteUDPSizeMu.Lock()
	s.dnsRouteUDPSize = make(map[string]uint16)
	s.dnsRouteUDPSizeMu.Unlock()
}

func (s *Server) Run() error {
	s.manager.StartTrafficLoop(s.done)
	s.StartConfiguredListeners()
	go s.retransmitLoop()
	go s.statsLoop()

	var (
		ic  net.PacketConn
		udp net.PacketConn
	)
	if s.serveICMP {
		c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			if s.serveDNS {
				log.Printf("[server] ICMP not available (need root?): %v — only DNS or none", err)
			} else {
				return fmt.Errorf("ICMP listen (run as root): %w", err)
			}
		} else {
			ic = c
		}
	}
	if s.serveDNS {
		da := s.dnsAddr
		if strings.TrimSpace(da) == "" {
			da = ":" + defaultDNSPort
		}
		c, err := net.ListenPacket("udp", da)
		if err != nil {
			if ic != nil {
				log.Printf("[server] DNS/UDP listen %q: %v — running ICMP only", da, err)
			} else if !s.serveICMP {
				return fmt.Errorf("DNS/UDP listen %q: %w", da, err)
			} else {
				// both ICMP and DNS requested; ICMP is down and DNS bind failed
				return fmt.Errorf("neither transport: ICMP and DNS/UDP %q: %w", da, err)
			}
		} else {
			udp = c
		}
	}
	if ic == nil && udp == nil {
		return fmt.Errorf("no server transport available (check root for ICMP, -dns-addr for DNS)")
	}
	s.tunICM, s.tunDNS = ic, udp
	if ic != nil {
		log.Printf("[server] listening on ICMP echo (tunnel over ping, epoch=%08x)", s.bootEpoch)
	}
	if udp != nil {
		log.Printf("[server] listening on DNS/UDP %s (QNAME %s)", udp.LocalAddr().String(), normQName(s.dnsQName))
		if s.dnsUpstream != "" {
			log.Printf("[server] DNS transparent proxy: other names -> %s",
				addUDPDefaultPort(s.dnsUpstream, defaultDNSUpstreamPort))
		}
	}

	var wg sync.WaitGroup
	if ic != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.icmpReadLoop(ic)
		}()
	}
	if udp != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.dnsReadLoop(udp)
		}()
	}
	wg.Wait()
	return nil
}

func (s *Server) icmpReadLoop(c net.PacketConn) {
	buf := make([]byte, 65535)
	for atomic.LoadInt32(&s.closed) == 0 {
		c.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := c.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if atomic.LoadInt32(&s.closed) != 0 {
				return
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
			s.auditInvalidTunnelKey("icmp", pkt.KeyHash, pkt.ClientID, addr)
			continue
		}
		atomic.AddUint64(&s.stats.tunIn, 1)
		clientKeyHash := pkt.KeyHash
		clientID := pkt.ClientID
		s.handlePacket(pkt, addr)
		s.noteRuleTunnelICMP(clientKeyHash, clientID, addr)
		resp := s.dequeueForAddr(clientKeyHash, clientID, addr)
		resp.Magic = MagicResponse
		resp.KeyHash = clientKeyHash
		resp.ClientID = clientID
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
		_, _ = c.WriteTo(rb, addr)
		atomic.AddUint64(&s.stats.tunOut, 1)
	}
}

func (s *Server) dnsReadLoop(c net.PacketConn) {
	buf := make([]byte, 65535)
	for atomic.LoadInt32(&s.closed) == 0 {
		c.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := c.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if atomic.LoadInt32(&s.closed) != 0 {
				return
			}
			log.Printf("[server] DNS read: %v", err)
			continue
		}
		if n < 12 {
			continue
		}
		m := new(dns.Msg)
		if err := m.Unpack(buf[:n]); err != nil {
			continue
		}
		if m.Response || len(m.Question) < 1 {
			continue
		}
		if !qnamesMatch(s.dnsQName, m.Question[0].Name) {
			if s.dnsUpstream != "" {
				reqCopy := make([]byte, n)
				copy(reqCopy, buf[:n])
				go forwardDNSQuery(s.dnsUpstream, c, reqCopy, addr)
			}
			continue
		}
		raw := extractEDNSTunnelPayload(m)
		if len(raw) == 0 {
			continue
		}
		pkt, err := DecodeTunnelPacket(raw)
		if err != nil || pkt.Magic != MagicRequest {
			continue
		}
		if s.manager.ValidateKey(pkt.KeyHash) == nil {
			atomic.AddUint64(&s.stats.badKey, 1)
			s.auditInvalidTunnelKey("dns", pkt.KeyHash, pkt.ClientID, addr)
			continue
		}
		atomic.AddUint64(&s.stats.tunIn, 1)
		clientKeyHash := pkt.KeyHash
		clientID := pkt.ClientID
		routeKey := s.queueKeyForAddr(clientKeyHash, clientID, addr)
		udpSize := extractEDNSUDPSize(m)
		if udpSize == 0 {
			udpSize = s.dnsUDPSizeForRoute(routeKey)
		}
		if udpSize == 0 {
			udpSize = dnsUDPSizeDefault
		}
		s.setDNSRouteUDPSize(routeKey, udpSize)
		s.handlePacket(pkt, addr)
		s.noteRuleTunnelICMP(clientKeyHash, clientID, addr)
		resp := s.dequeueForAddr(clientKeyHash, clientID, addr)
		resp.Magic = MagicResponse
		resp.KeyHash = clientKeyHash
		resp.ClientID = clientID
		respData, err := resp.Encode()
		if err != nil {
			continue
		}
		dnsOut, err := buildDNSResponseWithSize(m, respData, udpSize)
		if err != nil {
			log.Printf("[server] DNS response: %v", err)
			continue
		}
		_, _ = c.WriteTo(dnsOut, addr)
		atomic.AddUint64(&s.stats.tunOut, 1)
	}
}

// --------------- packet handlers ---------------

func (s *Server) handlePacket(pkt *TunnelPacket, from net.Addr) {
	switch pkt.Cmd {
	case CmdSetup:
		s.handleSetup(pkt, from)
	case CmdConnectAck:
		s.handleConnectAck(pkt, from)
	case CmdData:
		s.handleData(pkt, from)
	case CmdDataAck:
		s.handleDataAck(pkt, from)
	case CmdClose:
		s.handleClose(pkt, from)
	case CmdSocksDial:
		s.handleSocksDial(pkt, from)
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
		Audit("tunnel.setup.rejected", mergeFields(auditKeyFields(s.manager, pkt.KeyHash), map[string]string{
			"listen_addr": listenAddr,
			"target_addr": targetAddr,
			"protocol":    protocol,
			"client_addr": addrString(from),
			"client_id":   fmt.Sprintf("%08x", pkt.ClientID),
			"result":      "denied",
			"detail":      "rule not allowed",
		}))
		log.Printf("[server] setup rejected: %s -> %s (%s) key=%s (not allowed)", listenAddr, targetAddr, protocol, keyAuditLabel(kc))
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
	_, _, wasOnline := s.routeKeyForListener(pkt.KeyHash, mapKey)
	s.enqueueForAddr(pkt.KeyHash, pkt.ClientID, from, &TunnelPacket{Cmd: CmdSetupAck, Data: s.setupAckPayload()})
	s.registerRuleTunnelClient(pkt.KeyHash, pkt.ClientID, mapKey, from)
	if !wasOnline {
		Audit("tunnel.client.online", mergeFields(auditKeyFields(s.manager, pkt.KeyHash), map[string]string{
			"listen_addr": listenAddr,
			"target_addr": targetAddr,
			"protocol":    protocol,
			"client_addr": addrString(from),
			"client_id":   fmt.Sprintf("%08x", pkt.ClientID),
			"result":      "ok",
		}))
		log.Printf("[server] tunnel setup: listen=%s target=%s proto=%s", listenAddr, targetAddr, protocol)
	}
}

func (s *Server) handleConnectAck(pkt *TunnelPacket, from net.Addr) {
	s.mu.RLock()
	sc := s.connections[pkt.ConnID]
	s.mu.RUnlock()
	if sc != nil && s.matchRoute(sc, from) {
		sc.readyOnce.Do(func() { close(sc.ready) })
		log.Printf("[server] conn %d: client ready", pkt.ConnID)
	}
}

func (s *Server) handleData(pkt *TunnelPacket, from net.Addr) {
	s.mu.RLock()
	sc := s.connections[pkt.ConnID]
	s.mu.RUnlock()
	if sc == nil || len(pkt.Data) == 0 || !s.matchRoute(sc, from) {
		return
	}
	s.manager.RecordIn(sc.keyHash, len(pkt.Data))
	if err := sc.reliRecv.Receive(pkt.Seq, pkt.Data); err != nil {
		log.Printf("[server] conn %d recv err: %v", pkt.ConnID, err)
		s.closeConn(sc)
	}
}

func (s *Server) handleDataAck(pkt *TunnelPacket, from net.Addr) {
	s.mu.RLock()
	sc := s.connections[pkt.ConnID]
	s.mu.RUnlock()
	if sc != nil && s.matchRoute(sc, from) {
		sc.reliSend.Ack(pkt.Seq)
	}
}

func (s *Server) handleClose(pkt *TunnelPacket, from net.Addr) {
	s.mu.Lock()
	sc, ok := s.connections[pkt.ConnID]
	if ok && !s.matchRoute(sc, from) {
		s.mu.Unlock()
		return
	}
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
		Audit("socks.register.rejected", mergeFields(auditKeyFields(s.manager, pkt.KeyHash), map[string]string{
			"client_addr": addrString(from),
			"client_id":   fmt.Sprintf("%08x", pkt.ClientID),
			"result":      "denied",
			"detail":      "socks-dynamic disabled",
		}))
		log.Printf("[server] SOCKS register rejected (socks-dynamic disabled)")
		s.enqueueForAddr(pkt.KeyHash, pkt.ClientID, from, &TunnelPacket{Cmd: CmdSocksRegisterNack})
		return
	}
	_, _, wasOnline := s.routeKeyForListener(pkt.KeyHash, "socks-dynamic")
	s.enqueueForAddr(pkt.KeyHash, pkt.ClientID, from, &TunnelPacket{Cmd: CmdSetupAck, Data: s.setupAckPayload()})
	s.registerRuleTunnelClient(pkt.KeyHash, pkt.ClientID, "socks-dynamic", from)
	if !wasOnline {
		log.Printf("[server] SOCKS dynamic forwarding registered for tunnel key")
	}
}

func (s *Server) setupAckPayload() []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, s.bootEpoch)
	return b
}

func (s *Server) handleSocksDial(pkt *TunnelPacket, from net.Addr) {
	if !s.socksDynamic {
		log.Printf("[server] SOCKS dial conn %d rejected (socks-dynamic disabled)", pkt.ConnID)
		s.enqueueForAddr(pkt.KeyHash, pkt.ClientID, from, &TunnelPacket{Cmd: CmdClose, ConnID: pkt.ConnID})
		return
	}
	if pkt.ConnID == 0 || len(pkt.Data) == 0 {
		return
	}
	routeKey := s.queueKeyForAddr(pkt.KeyHash, pkt.ClientID, from)
	if routeKey == "" {
		return
	}
	// SOCKS dial ConnIDs must use the high ID space; low IDs are server-assigned for port-forward.
	if pkt.ConnID < socksConnIDBase {
		log.Printf("[server] SOCKS dial conn %d rejected (ConnID below socks space)", pkt.ConnID)
		s.enqueueRoute(routeKey, &TunnelPacket{Cmd: CmdClose, ConnID: pkt.ConnID})
		return
	}
	target := normalizeSocksDialTarget(string(pkt.Data))
	if target == "" {
		s.enqueueRoute(routeKey, &TunnelPacket{Cmd: CmdClose, ConnID: pkt.ConnID})
		return
	}

	s.mu.Lock()
	if _, exists := s.connections[pkt.ConnID]; exists {
		s.mu.Unlock()
		s.enqueueRoute(routeKey, &TunnelPacket{Cmd: CmdClose, ConnID: pkt.ConnID})
		return
	}
	s.mu.Unlock()

	conn, err := net.DialTimeout("tcp", target, 15*time.Second)
	if err != nil {
		log.Printf("[server] SOCKS dial %d %s: %v", pkt.ConnID, target, err)
		s.enqueueRoute(routeKey, &TunnelPacket{Cmd: CmdClose, ConnID: pkt.ConnID})
		return
	}

	connID := pkt.ConnID
	sc := &ServerConn{
		id:         connID,
		proto:      "tcp",
		tcpConn:    conn,
		targetAddr: target,
		keyHash:    pkt.KeyHash,
		clientID:   pkt.ClientID,
		routeKey:   routeKey,
		ready:      make(chan struct{}),
	}
	enk := s.makeEnqueueRoute(routeKey)
	sc.reliSend = NewReliableSend(connID, enk)
	sc.reliRecv = NewReliableRecv(connID,
		func(data []byte) error { _, e := conn.Write(data); return e },
		enk,
	)

	s.mu.Lock()
	s.connections[connID] = sc
	s.mu.Unlock()

	sc.readyOnce.Do(func() { close(sc.ready) })
	s.enqueueRoute(routeKey, &TunnelPacket{Cmd: CmdSocksDialAck, ConnID: connID})
	log.Printf("[server] SOCKS conn %d -> %s (route=%s)", connID, target, routeKey)

	// DialAck is not covered by ReliableSend. Retransmit like waitReady's CmdConnect
	// retries so a single lost ICMP/DNS reply does not leave the client waiting until
	// timeout while this side already holds a live target connection.
	go s.retrySocksDialAck(sc)
	go s.readTCP(sc)
}

// retrySocksDialAck re-enqueues CmdSocksDialAck until the session closes or the
// client wait window elapses. Extra acks after the client has already succeeded
// are ignored (socksWait entry is gone).
func (s *Server) retrySocksDialAck(sc *ServerConn) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	timeout := time.NewTimer(socksDialAckRetryWindow)
	defer timeout.Stop()
	for {
		select {
		case <-ticker.C:
			if atomic.LoadInt32(&sc.closed) != 0 {
				return
			}
			s.enqueueRoute(sc.routeKey, &TunnelPacket{Cmd: CmdSocksDialAck, ConnID: sc.id})
		case <-timeout.C:
			return
		case <-s.done:
			return
		}
	}
}

// --------------- auto-start ---------------

// RestartListenersAfterKeyHashChange closes listeners and sessions for the given
// key ID's forwarding rules that used prevKeyHash, then re-binds from config.
func (s *Server) RestartListenersAfterKeyHashChange(prevKeyHash [16]byte, keyID string) {
	if atomic.LoadInt32(&s.closed) == 1 {
		return
	}
	var rules []*ForwardRule
	for _, kc := range s.manager.GetKeys() {
		if kc.ID == keyID {
			rules = kc.Rules
			break
		}
	}
	if rules == nil {
		rules = []*ForwardRule{}
	}
	seen := make(map[string]bool)
	var mapKeys []string
	for _, r := range rules {
		mk := ListenerMapKey(r.Protocol, r.ListenAddr)
		if !seen[mk] {
			seen[mk] = true
			mapKeys = append(mapKeys, mk)
		}
	}

	s.mu.Lock()
	for _, mk := range mapKeys {
		if ln, ok := s.listenersTCP[mk]; ok {
			ln.Close()
			delete(s.listenersTCP, mk)
		}
		if uc, ok := s.listenersUDP[mk]; ok {
			uc.Close()
			delete(s.listenersUDP, mk)
		}
	}
	var toClose []*ServerConn
	for _, sc := range s.connections {
		if sc.keyHash == prevKeyHash {
			toClose = append(toClose, sc)
		}
	}
	s.mu.Unlock()

	for _, sc := range toClose {
		s.closeConn(sc)
	}

	prefix := hex.EncodeToString(prevKeyHash[:]) + "|"
	s.sendQueuesMu.Lock()
	for k := range s.sendQueues {
		if strings.HasPrefix(k, prefix) {
			delete(s.sendQueues, k)
		}
	}
	s.sendQueuesMu.Unlock()
	s.clearDNSRouteUDPSizePrefix(prefix)

	s.ruleTunnelMu.Lock()
	for k := range s.ruleTunnelClients {
		if strings.HasPrefix(k, prefix) {
			delete(s.ruleTunnelClients, k)
		}
	}
	s.ruleTunnelMu.Unlock()

	log.Printf("[server] listeners restarted after tunnel key update (key id %s)", keyID)
	s.StartConfiguredListeners()
}

// RestartListenersAfterRuleChange closes listeners affected by a single rule update
// and re-binds configured listeners for the key.
func (s *Server) RestartListenersAfterRuleChange(keyHash [16]byte, oldMapKey, newMapKey string) {
	if atomic.LoadInt32(&s.closed) == 1 {
		return
	}
	affected := map[string]bool{}
	if strings.TrimSpace(oldMapKey) != "" {
		affected[oldMapKey] = true
	}
	if strings.TrimSpace(newMapKey) != "" {
		affected[newMapKey] = true
	}

	s.mu.Lock()
	for mk := range affected {
		if ln, ok := s.listenersTCP[mk]; ok {
			ln.Close()
			delete(s.listenersTCP, mk)
		}
		if uc, ok := s.listenersUDP[mk]; ok {
			uc.Close()
			delete(s.listenersUDP, mk)
		}
	}
	var toClose []*ServerConn
	for _, sc := range s.connections {
		if sc.keyHash == keyHash {
			toClose = append(toClose, sc)
		}
	}
	s.mu.Unlock()

	for _, sc := range toClose {
		s.closeConn(sc)
	}

	prefix := hex.EncodeToString(keyHash[:]) + "|"
	s.ruleTunnelMu.Lock()
	for k := range s.ruleTunnelClients {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		for mk := range affected {
			if strings.HasSuffix(k, "|"+mk) {
				delete(s.ruleTunnelClients, k)
				break
			}
		}
	}
	s.ruleTunnelMu.Unlock()

	s.StartConfiguredListeners()
}

func (s *Server) removeTCPListenerMapKey(mapKey string) {
	s.mu.Lock()
	delete(s.listenersTCP, mapKey)
	s.mu.Unlock()
}

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
				s.removeTCPListenerMapKey(mapKey)
				return
			}
			if errors.Is(err, net.ErrClosed) {
				s.removeTCPListenerMapKey(mapKey)
				return
			}
			log.Printf("[server] accept: %v", err)
			continue
		}

		connID := s.allocConnID()
		routeKey, clientID, ok := s.routeKeyForListener(keyHash, mapKey)
		if !ok {
			log.Printf("[server] conn %d: no active tunnel client for %s, rejecting %s", connID, listenAddr, tc.RemoteAddr())
			tc.Close()
			continue
		}
		sc := &ServerConn{
			id:         connID,
			proto:      "tcp",
			tcpConn:    tc,
			targetAddr: targetAddr,
			keyHash:    keyHash,
			clientID:   clientID,
			routeKey:   routeKey,
			ready:      make(chan struct{}),
		}
		enk := s.makeEnqueueRoute(routeKey)
		sc.reliSend = NewReliableSend(connID, enk)
		sc.reliRecv = NewReliableRecv(connID,
			func(data []byte) error { _, err := sc.tcpConn.Write(data); return err },
			enk,
		)

		s.mu.Lock()
		s.connections[connID] = sc
		s.mu.Unlock()

		log.Printf("[server] conn %d from %s (route=%s)", connID, tc.RemoteAddr(), routeKey)
		s.enqueueRoute(routeKey, &TunnelPacket{
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

		connID := s.allocConnID()
		mapKey := ListenerMapKey("udp", listenAddr)
		routeKey, clientID, ok := s.routeKeyForListener(keyHash, mapKey)
		if !ok {
			s.mu.Unlock()
			log.Printf("[server] UDP conn %d: no active tunnel client for %s, dropping %s", connID, listenAddr, ra.String())
			continue
		}
		sc = &ServerConn{
			id:         connID,
			proto:      "udp",
			udpSock:    uc,
			udpRemote:  ra,
			udpSessKey: sessKey,
			targetAddr: targetAddr,
			keyHash:    keyHash,
			clientID:   clientID,
			routeKey:   routeKey,
			ready:      make(chan struct{}),
		}
		enk := s.makeEnqueueRoute(routeKey)
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

		log.Printf("[server] UDP conn %d from %s (route=%s)", connID, ra.String(), routeKey)
		s.enqueueRoute(routeKey, &TunnelPacket{
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
			s.enqueueRoute(sc.routeKey, &TunnelPacket{
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
	chunk := MaxPayloadSize
	if s.serveDNS {
		udpSize := s.dnsUDPSizeForRoute(sc.routeKey)
		if udpSize == 0 {
			udpSize = dnsUDPSizeDefault
		}
		chunk = dnsMaxDataChunk(normQName(s.dnsQName), udpSize, true)
	}
	buf := make([]byte, chunk)
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

	s.enqueueRoute(sc.routeKey, &TunnelPacket{Cmd: CmdClose, ConnID: sc.id})
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

func (s *Server) registerRuleTunnelClient(keyHash [16]byte, clientID uint32, listenerMapKey string, from net.Addr) {
	if from == nil {
		return
	}
	k := ruleTunnelMapKey(keyHash, listenerMapKey)
	qk := s.queueKeyForAddr(keyHash, clientID, from)
	if qk == "" {
		return
	}
	s.ruleTunnelMu.Lock()
	s.ruleTunnelClients[k] = &ruleTunnelState{addr: from, clientID: clientID, routeKey: qk, lastSeen: time.Now()}
	s.ruleTunnelMu.Unlock()
}

func (s *Server) noteRuleTunnelICMP(keyHash [16]byte, clientID uint32, from net.Addr) {
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
		if st.clientID != 0 && clientID != 0 {
			if st.clientID != clientID {
				continue
			}
			st.lastSeen = now
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
			in := atomic.LoadUint64(&s.stats.tunIn)
			out := atomic.LoadUint64(&s.stats.tunOut)
			bad := atomic.LoadUint64(&s.stats.badKey)
			s.mu.RLock()
			conns := len(s.connections)
			s.mu.RUnlock()
			log.Printf("[server] stats: tun_in=%d tun_out=%d bad_key=%d conns=%d",
				in, out, bad, conns)
		case <-s.done:
			return
		}
	}
}

func (s *Server) makeEnqueueRoute(routeKey string) func(*TunnelPacket) {
	return func(p *TunnelPacket) {
		s.enqueueRoute(routeKey, p)
	}
}

func (s *Server) enqueueForAddr(keyHash [16]byte, clientID uint32, addr net.Addr, pkt *TunnelPacket) {
	s.enqueueRoute(s.queueKeyForAddr(keyHash, clientID, addr), pkt)
}

func (s *Server) enqueueRoute(routeKey string, pkt *TunnelPacket) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}
	if routeKey == "" {
		return
	}
	s.sendQueuesMu.Lock()
	ch := s.sendQueues[routeKey]
	if ch == nil {
		ch = make(chan *TunnelPacket, 4096)
		s.sendQueues[routeKey] = ch
	}
	s.sendQueuesMu.Unlock()
	select {
	case ch <- pkt:
	default:
		log.Printf("[server] send queue full for route %s, dropping", routeKey)
	}
}

func (s *Server) dequeueForAddr(keyHash [16]byte, clientID uint32, addr net.Addr) *TunnelPacket {
	return s.dequeueRoute(s.queueKeyForAddr(keyHash, clientID, addr))
}

func (s *Server) dequeueRoute(routeKey string) *TunnelPacket {
	if routeKey == "" {
		return &TunnelPacket{Cmd: CmdPing}
	}
	s.sendQueuesMu.Lock()
	ch := s.sendQueues[routeKey]
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

func (s *Server) setDNSRouteUDPSize(routeKey string, udpSize uint16) {
	if routeKey == "" {
		return
	}
	udpSize = clampDNSUDPSize(udpSize)
	s.dnsRouteUDPSizeMu.Lock()
	s.dnsRouteUDPSize[routeKey] = udpSize
	s.dnsRouteUDPSizeMu.Unlock()
}

func (s *Server) dnsUDPSizeForRoute(routeKey string) uint16 {
	if routeKey == "" {
		return 0
	}
	s.dnsRouteUDPSizeMu.Lock()
	sz := s.dnsRouteUDPSize[routeKey]
	s.dnsRouteUDPSizeMu.Unlock()
	return sz
}

func (s *Server) clearDNSRouteUDPSizePrefix(prefix string) {
	if prefix == "" {
		return
	}
	s.dnsRouteUDPSizeMu.Lock()
	for k := range s.dnsRouteUDPSize {
		if strings.HasPrefix(k, prefix) {
			delete(s.dnsRouteUDPSize, k)
		}
	}
	s.dnsRouteUDPSizeMu.Unlock()
}

func (s *Server) queueKeyForAddr(keyHash [16]byte, clientID uint32, addr net.Addr) string {
	prefix := hex.EncodeToString(keyHash[:]) + "|"
	if clientID != 0 {
		return prefix + fmt.Sprintf("cid:%08x", clientID)
	}
	if addr == nil {
		return ""
	}
	return prefix + "addr:" + addr.String()
}

func (s *Server) routeKeyForListener(keyHash [16]byte, listenerMapKey string) (string, uint32, bool) {
	k := ruleTunnelMapKey(keyHash, listenerMapKey)
	s.ruleTunnelMu.Lock()
	st, ok := s.ruleTunnelClients[k]
	if !ok || st == nil || st.addr == nil || time.Since(st.lastSeen) > icmpClientHeartbeatTTL {
		s.ruleTunnelMu.Unlock()
		return "", 0, false
	}
	qk := st.routeKey
	cid := st.clientID
	s.ruleTunnelMu.Unlock()
	if qk == "" {
		return "", 0, false
	}
	return qk, cid, true
}

func (s *Server) matchRoute(sc *ServerConn, from net.Addr) bool {
	if sc == nil || from == nil {
		return false
	}
	return sc.routeKey == s.queueKeyForAddr(sc.keyHash, sc.clientID, from)
}

func (s *Server) auditInvalidTunnelKey(transport string, hash [16]byte, clientID uint32, from net.Addr) {
	AuditRateLimited(
		transport+"|"+hashPrefix(hash)+"|"+addrString(from),
		"tunnel.key.invalid",
		mergeFields(auditKeyFields(s.manager, hash), map[string]string{
			"transport":   transport,
			"client_addr": addrString(from),
			"client_id":   fmt.Sprintf("%08x", clientID),
			"result":      "denied",
		}),
		10*time.Second,
	)
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
