package main

import (
	"crypto/rand"
	"encoding/binary"
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

// Re-send setup periodically so the server can rebuild in-memory tunnel routes
// after restart (ICMP and DNS transports).
const tunnelSetupRefreshInterval = 20 * time.Second

type Client struct {
	listenAddr string
	serverAddr string
	targetAddr string
	protocol   string
	socksAddr  string
	transport  string
	dnsQName   string
	key        [16]byte
	clientID   uint32

	// tunConn + tunPeer: ICMP echo or plain UDP to server (DNS transport)
	tunConn  net.PacketConn
	tunPeer  net.Addr
	serverIP net.Addr

	connections map[uint32]*ClientConn
	pending     map[uint32]bool
	sendQueue   chan *TunnelPacket

	socksListener net.Listener
	socksLnMu     sync.Mutex
	socksWait     map[uint32]chan bool
	socksMu       sync.Mutex
	nextSocksConn uint32

	tunSeq      uint32
	dnsUDPSize  uint32 // atomic: negotiated EDNS UDP payload size (DNS transport)
	serverEpoch uint32 // atomic: last seen server boot epoch (detect restart)
	mu          sync.RWMutex
	closed      int32
	done        chan struct{}
	setupDone   chan struct{}
	setupFail   chan struct{}
}

type ClientConn struct {
	id       uint32
	proto    string
	tcpConn  net.Conn // TCP stream or UDP datagram socket (implements net.Conn)
	reliSend *ReliableSend
	reliRecv *ReliableRecv

	silentClose int32 // atomic: skip CmdClose notify (server restart session reset)
	idleMu      sync.Mutex
	idleTimer   *time.Timer
}

func NewClient(listenAddr, serverAddr, targetAddr, key, protocol, socksAddr, transport, dnsName string) *Client {
	return &Client{
		listenAddr:  listenAddr,
		serverAddr:  serverAddr,
		targetAddr:  targetAddr,
		protocol:    normalizeProtocol(protocol),
		socksAddr:   strings.TrimSpace(socksAddr),
		transport:   normalizeClientTransport(transport),
		dnsQName:    strings.TrimSpace(dnsName),
		key:         ComputeKeyHash(key),
		clientID:    genClientID(),
		connections: make(map[uint32]*ClientConn),
		pending:     make(map[uint32]bool),
		socksWait:   make(map[uint32]chan bool),
		sendQueue:   make(chan *TunnelPacket, 4096),
		done:        make(chan struct{}),
		setupDone:   make(chan struct{}),
		setupFail:   make(chan struct{}),
	}
}

func (c *Client) Close() {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return
	}
	close(c.done)
	c.socksLnMu.Lock()
	if c.socksListener != nil {
		c.socksListener.Close()
	}
	c.socksLnMu.Unlock()
	if c.tunConn != nil {
		c.tunConn.Close()
	}
	c.mu.Lock()
	for _, cc := range c.connections {
		cc.stopIdleTimer()
		cc.tcpConn.Close()
		cc.reliSend.Close()
		cc.reliRecv.Close()
	}
	c.mu.Unlock()
}

func (c *Client) Run() error {
	if c.transport == "dns" {
		peer, err := net.ResolveUDPAddr("udp", addUDPDefaultPort(c.serverAddr, defaultDNSPort))
		if err != nil {
			return fmt.Errorf("resolve %s: %w", c.serverAddr, err)
		}
		if strings.TrimSpace(c.dnsQName) == "" {
			c.dnsQName = defaultDNSQName
		}
		conn, err := net.ListenPacket("udp", "0.0.0.0:0")
		if err != nil {
			return fmt.Errorf("DNS transport UDP listen: %w", err)
		}
		c.tunConn = conn
		c.tunPeer = peer
		defer conn.Close()
	} else {
		host := c.serverAddr
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		ip := net.ParseIP(host)
		if ip == nil {
			addrs, err := net.LookupHost(host)
			if err != nil {
				return fmt.Errorf("resolve %s: %w", c.serverAddr, err)
			}
			ip = net.ParseIP(addrs[0])
		}
		c.serverIP = &net.IPAddr{IP: ip}
		c.tunPeer = c.serverIP

		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return fmt.Errorf("ICMP listen failed (run as root): %w", err)
		}
		c.tunConn = conn
		defer conn.Close()
	}

	if c.transport == "dns" {
		atomic.StoreUint32(&c.dnsUDPSize, uint32(dnsUDPSizeLadder[0]))
		c.probeDNSPayloadSize()
	}
	go c.receiver()
	go c.sender()
	if c.wantPortForward() {
		go c.sendSetup()
	}
	if c.socksAddr != "" && !c.wantPortForward() {
		go c.sendSocksRegister()
	}
	go c.retransmitLoop()

	log.Printf("[client] connecting to server %s ...", c.serverAddr)

	select {
	case <-c.setupDone:
		if c.wantPortForward() {
			log.Printf("[client] tunnel ready: %s listens on %s, target %s (%s)",
				c.serverAddr, c.listenAddr, c.targetAddr, c.protocol)
		} else if c.socksAddr != "" {
			log.Printf("[client] tunnel ready: %s (SOCKS dynamic)", c.serverAddr)
		}
		if c.socksAddr != "" {
			go c.startSOCKS5(c.socksAddr)
		}
	case <-c.setupFail:
		return fmt.Errorf("server rejected SOCKS registration (start server with -socks-dynamic)")
	case <-time.After(30 * time.Second):
		return fmt.Errorf("setup timeout (check -key and server status)")
	case <-c.done:
		return nil
	}

	<-c.done
	return nil
}

func (c *Client) wantPortForward() bool {
	return strings.TrimSpace(c.listenAddr) != "" && strings.TrimSpace(c.targetAddr) != ""
}

func (c *Client) sendSetup() {
	if !c.wantPortForward() {
		return
	}
	data := fmt.Sprintf("%s|%s|%s", c.listenAddr, c.targetAddr, c.protocol)
	c.sendPeriodicCmd(CmdSetup, []byte(data), tunnelSetupRefreshInterval)
}

func (c *Client) sendSocksRegister() {
	c.sendPeriodicCmd(CmdSocksRegister, nil, tunnelSetupRefreshInterval)
}

func (c *Client) sendPeriodicCmd(cmd uint8, data []byte, refreshInterval time.Duration) {
	send := func() {
		pkt := &TunnelPacket{Cmd: cmd}
		if len(data) > 0 {
			pkt.Data = append([]byte(nil), data...)
		}
		c.enqueue(pkt)
	}
	send()
	// Retry quickly until the server acknowledges setup.
	for {
		select {
		case <-c.done:
			return
		case <-c.setupDone:
			goto refresh
		case <-c.setupFail:
			return
		case <-time.After(time.Second):
			send()
		}
	}
refresh:
	// Keep re-registering so the server can recover routes after restart.
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			send()
		}
	}
}

func (c *Client) sender() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	icmpID := int(c.key[0])<<8 | int(c.key[1])
	qn := c.dnsQName
	if strings.TrimSpace(qn) == "" {
		qn = defaultDNSQName
	}

	for atomic.LoadInt32(&c.closed) == 0 {
		var pkt *TunnelPacket

		select {
		case pkt = <-c.sendQueue:
		default:
			select {
			case pkt = <-c.sendQueue:
			case <-ticker.C:
				pkt = &TunnelPacket{Cmd: CmdPing}
			case <-c.done:
				return
			}
		}

		pkt.Magic = MagicRequest
		pkt.KeyHash = c.key
		pkt.ClientID = c.clientID

		payload, err := pkt.Encode()
		if err != nil {
			continue
		}
		seq := atomic.AddUint32(&c.tunSeq, 1)
		if c.transport == "dns" {
			id := uint16(seq)
			udpSize := c.dnsUDPSizeVal()
			dnsWire, e := buildDNSRequestWithSize(id, qn, payload, udpSize)
			if e != nil {
				if c.shrinkDNSUDPSize() {
					udpSize = c.dnsUDPSizeVal()
					dnsWire, e = buildDNSRequestWithSize(id, qn, payload, udpSize)
				}
			}
			if e != nil {
				log.Printf("[client] DNS request pack: %v", e)
				continue
			}
			_, e = c.tunConn.WriteTo(dnsWire, c.tunPeer)
			if e != nil {
				if atomic.LoadInt32(&c.closed) != 0 {
					return
				}
				log.Printf("[client] DNS write: %v", e)
			}
			continue
		}
		msg := &icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   icmpID,
				Seq:  int(seq & 0xFFFF),
				Data: payload,
			},
		}
		mb, err := msg.Marshal(nil)
		if err != nil {
			continue
		}
		_, _ = c.tunConn.WriteTo(mb, c.tunPeer)
	}
}

func (c *Client) receiver() {
	buf := make([]byte, 65535)
	for atomic.LoadInt32(&c.closed) == 0 {
		c.tunConn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := c.tunConn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if atomic.LoadInt32(&c.closed) != 0 {
				return
			}
			continue
		}
		if c.transport == "dns" {
			if n < 12 {
				continue
			}
			_, data, e := parseDNSResponse(buf[:n])
			if e != nil {
				continue
			}
			pkt, e := DecodeTunnelPacket(data)
			if e != nil || pkt.Magic != MagicResponse || pkt.KeyHash != c.key || pkt.ClientID != c.clientID {
				continue
			}
			c.handlePacket(pkt)
			if pkt.Flags&FlagMore != 0 {
				c.enqueue(&TunnelPacket{Cmd: CmdPing})
			}
			continue
		}
		msg, err := icmp.ParseMessage(ProtocolICMP, buf[:n])
		if err != nil || msg.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		pkt, err := DecodeTunnelPacket(echo.Data)
		if err != nil || pkt.Magic != MagicResponse || pkt.KeyHash != c.key || pkt.ClientID != c.clientID {
			continue
		}
		c.handlePacket(pkt)
		if pkt.Flags&FlagMore != 0 {
			c.enqueue(&TunnelPacket{Cmd: CmdPing})
		}
	}
}

// --------------- packet handlers ---------------

func (c *Client) handlePacket(pkt *TunnelPacket) {
	switch pkt.Cmd {
	case CmdSetupAck:
		c.noteServerEpoch(pkt.Data)
		select {
		case <-c.setupDone:
		default:
			close(c.setupDone)
		}
	case CmdConnect:
		go c.handleConnect(pkt)
	case CmdData:
		c.handleData(pkt)
	case CmdDataAck:
		c.handleDataAck(pkt)
	case CmdClose:
		c.handleCloseCmd(pkt)
	case CmdSocksDialAck:
		c.handleSocksDialAck(pkt)
	case CmdSocksRegisterNack:
		select {
		case <-c.setupFail:
		default:
			close(c.setupFail)
		}
	}
}

func (c *Client) handleSocksDialAck(pkt *TunnelPacket) {
	c.socksMu.Lock()
	ch := c.socksWait[pkt.ConnID]
	delete(c.socksWait, pkt.ConnID)
	c.socksMu.Unlock()
	if ch != nil {
		select {
		case ch <- true:
		default:
		}
	}
}

func (c *Client) handleConnect(pkt *TunnelPacket) {
	var stale *ClientConn
	c.mu.Lock()
	if cc, exists := c.connections[pkt.ConnID]; exists {
		delete(c.connections, pkt.ConnID)
		stale = cc
	}
	if c.pending[pkt.ConnID] {
		c.mu.Unlock()
		if stale != nil {
			c.closeClientConn(stale, true)
		}
		return
	}
	c.pending[pkt.ConnID] = true
	c.mu.Unlock()
	if stale != nil {
		c.closeClientConn(stale, true)
	}

	target := string(pkt.Data)
	if target == "" {
		target = c.targetAddr
	}

	log.Printf("[client] conn %d: dialing %s (%s)", pkt.ConnID, target, c.protocol)

	network := "tcp"
	if c.protocol == "udp" {
		network = "udp"
	}
	conn, err := net.DialTimeout(network, target, 10*time.Second)
	if err != nil {
		log.Printf("[client] conn %d: dial failed: %v", pkt.ConnID, err)
		c.mu.Lock()
		delete(c.pending, pkt.ConnID)
		c.mu.Unlock()
		c.enqueue(&TunnelPacket{Cmd: CmdClose, ConnID: pkt.ConnID})
		return
	}

	cc := &ClientConn{id: pkt.ConnID, proto: c.protocol, tcpConn: conn}
	cc.reliSend = NewReliableSend(pkt.ConnID, c.enqueue)
	cc.reliRecv = NewReliableRecv(pkt.ConnID,
		func(data []byte) error {
			_, werr := conn.Write(data)
			if werr == nil && c.protocol == "udp" {
				cc.resetUDPIdle(c)
			}
			return werr
		},
		c.enqueue,
	)

	c.mu.Lock()
	delete(c.pending, pkt.ConnID)
	c.connections[pkt.ConnID] = cc
	c.mu.Unlock()

	c.enqueue(&TunnelPacket{Cmd: CmdConnectAck, ConnID: pkt.ConnID})
	log.Printf("[client] conn %d: established to %s", pkt.ConnID, target)

	if c.protocol == "udp" {
		cc.resetUDPIdle(c)
	}
	go c.readTarget(cc)
}

func (c *Client) readTarget(cc *ClientConn) {
	defer func() {
		c.mu.Lock()
		delete(c.connections, cc.id)
		c.mu.Unlock()
		cc.stopIdleTimer()
		cc.tcpConn.Close()
		cc.reliSend.Close()
		cc.reliRecv.Close()
		if atomic.LoadInt32(&cc.silentClose) == 0 {
			c.enqueue(&TunnelPacket{Cmd: CmdClose, ConnID: cc.id})
			log.Printf("[client] conn %d: target closed", cc.id)
		}
	}()

	chunk := MaxPayloadSize
	if c.transport == "dns" {
		chunk = c.dnsMaxDataChunk()
	}
	buf := make([]byte, chunk)
	for {
		n, err := cc.tcpConn.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			if cc.proto == "udp" {
				cc.resetUDPIdle(c)
			}
			data := make([]byte, n)
			copy(data, buf[:n])
			if !cc.reliSend.Send(data) {
				return
			}
		}
	}
}

func (c *Client) handleData(pkt *TunnelPacket) {
	c.mu.RLock()
	cc := c.connections[pkt.ConnID]
	c.mu.RUnlock()
	if cc == nil || len(pkt.Data) == 0 {
		return
	}
	if err := cc.reliRecv.Receive(pkt.Seq, pkt.Data); err != nil {
		log.Printf("[client] conn %d: recv err: %v", pkt.ConnID, err)
		c.mu.Lock()
		delete(c.connections, pkt.ConnID)
		c.mu.Unlock()
		cc.stopIdleTimer()
		cc.tcpConn.Close()
		cc.reliSend.Close()
		cc.reliRecv.Close()
		c.enqueue(&TunnelPacket{Cmd: CmdClose, ConnID: pkt.ConnID})
	}
}

func (c *Client) handleDataAck(pkt *TunnelPacket) {
	c.mu.RLock()
	cc := c.connections[pkt.ConnID]
	c.mu.RUnlock()
	if cc != nil {
		cc.reliSend.Ack(pkt.Seq)
	}
}

func (c *Client) handleCloseCmd(pkt *TunnelPacket) {
	c.socksMu.Lock()
	if ch, wk := c.socksWait[pkt.ConnID]; wk {
		delete(c.socksWait, pkt.ConnID)
		c.socksMu.Unlock()
		select {
		case ch <- false:
		default:
		}
	} else {
		c.socksMu.Unlock()
	}

	c.mu.Lock()
	cc, ok := c.connections[pkt.ConnID]
	if ok {
		delete(c.connections, pkt.ConnID)
	}
	c.mu.Unlock()
	if ok {
		cc.stopIdleTimer()
		cc.tcpConn.Close()
		cc.reliSend.Close()
		cc.reliRecv.Close()
		log.Printf("[client] conn %d: closed by server", pkt.ConnID)
	}
}

func (cc *ClientConn) resetUDPIdle(c *Client) {
	if cc.proto != "udp" {
		return
	}
	cc.idleMu.Lock()
	defer cc.idleMu.Unlock()
	if cc.idleTimer != nil {
		cc.idleTimer.Stop()
	}
	cc.idleTimer = time.AfterFunc(5*time.Minute, func() {
		log.Printf("[client] conn %d: UDP idle timeout", cc.id)
		cc.tcpConn.Close()
	})
}

func (cc *ClientConn) stopIdleTimer() {
	cc.idleMu.Lock()
	defer cc.idleMu.Unlock()
	if cc.idleTimer != nil {
		cc.idleTimer.Stop()
		cc.idleTimer = nil
	}
}

func (c *Client) retransmitLoop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.mu.RLock()
			for _, cc := range c.connections {
				cc.reliSend.Retransmit()
			}
			c.mu.RUnlock()
		case <-c.done:
			return
		}
	}
}

func (c *Client) enqueue(pkt *TunnelPacket) {
	select {
	case c.sendQueue <- pkt:
	default:
		log.Println("[client] send queue full, dropping")
	}
}

func (c *Client) dnsUDPSizeVal() uint16 {
	v := atomic.LoadUint32(&c.dnsUDPSize)
	if v == 0 {
		return dnsUDPSizeDefault
	}
	return clampDNSUDPSize(uint16(v))
}

func (c *Client) dnsMaxDataChunk() int {
	qn := c.dnsQName
	if strings.TrimSpace(qn) == "" {
		qn = defaultDNSQName
	}
	return dnsMaxDataChunk(normQName(qn), c.dnsUDPSizeVal(), false)
}

func (c *Client) shrinkDNSUDPSize() bool {
	cur := c.dnsUDPSizeVal()
	next := nextSmallerDNSUDPSize(cur)
	if next == 0 || next == cur {
		return false
	}
	atomic.StoreUint32(&c.dnsUDPSize, uint32(next))
	log.Printf("[client] DNS UDP payload size reduced to %d", next)
	return true
}

func (c *Client) probeDNSPayloadSize() {
	qn := c.dnsQName
	if strings.TrimSpace(qn) == "" {
		qn = defaultDNSQName
	}
	qn = normQName(qn)

	for _, udpSize := range dnsUDPSizeLadder {
		if c.dnsProbeRoundTrip(qn, udpSize) {
			atomic.StoreUint32(&c.dnsUDPSize, uint32(udpSize))
			log.Printf("[client] DNS UDP payload size negotiated: %d (data chunk %d)",
				udpSize, dnsMaxDataChunk(qn, udpSize, false))
			_ = c.tunConn.SetReadDeadline(time.Time{})
			return
		}
	}
	atomic.StoreUint32(&c.dnsUDPSize, uint32(dnsUDPSizeMin))
	log.Printf("[client] DNS UDP payload size defaulted to %d", dnsUDPSizeMin)
	_ = c.tunConn.SetReadDeadline(time.Time{})
}

func (c *Client) dnsProbeRoundTrip(qname string, udpSize uint16) bool {
	if c.tunConn == nil || c.tunPeer == nil {
		return false
	}
	// Probe the response budget: server→client CmdData is packed into DNS answers,
	// which are larger than queries. Padding to the request max made tiny Ping
	// replies look like success even when a real response of this EDNS size cannot
	// fit the path (or even the DNS encoding overhead).
	dataLen := maxTunnelPayloadForDNSResponse(qname, udpSize)
	pkt := &TunnelPacket{
		Magic:    MagicRequest,
		KeyHash:  c.key,
		ClientID: c.clientID,
		Cmd:      CmdPing,
	}
	if dataLen > 0 {
		pkt.Data = make([]byte, dataLen)
	}
	raw, err := pkt.Encode()
	if err != nil {
		return false
	}
	const probeID = 0x7e7e
	wire, err := buildDNSRequestWithSize(probeID, qname, raw, udpSize)
	if err != nil {
		return false
	}
	_ = c.tunConn.SetReadDeadline(time.Now().Add(dnsProbeTimeout))
	if _, err := c.tunConn.WriteTo(wire, c.tunPeer); err != nil {
		return false
	}
	buf := make([]byte, 65535)
	for {
		n, _, err := c.tunConn.ReadFrom(buf)
		if err != nil {
			return false
		}
		if n < 12 {
			continue
		}
		id, payload, err := parseDNSResponse(buf[:n])
		if err != nil || id != probeID {
			continue
		}
		dec, err := DecodeTunnelPacket(payload)
		if err != nil || dec.Magic != MagicResponse || dec.KeyHash != c.key || dec.ClientID != c.clientID {
			continue
		}
		// Require an echoed payload of the probe size. A tiny default Ping reply
		// only proves the request got through — not that responses this large work.
		if len(dec.Data) < dataLen {
			return false
		}
		return true
	}
}

func (c *Client) noteServerEpoch(data []byte) {
	if len(data) < 4 {
		return
	}
	epoch := binary.BigEndian.Uint32(data[:4])
	prev := atomic.LoadUint32(&c.serverEpoch)
	if prev != 0 && epoch != prev {
		c.resetTunnelSessions()
		c.enqueueSetupRefresh()
		log.Printf("[client] server restarted (epoch %08x -> %08x), tunnel sessions cleared", prev, epoch)
	}
	atomic.StoreUint32(&c.serverEpoch, epoch)
}

func (c *Client) enqueueSetupRefresh() {
	if c.wantPortForward() {
		data := fmt.Sprintf("%s|%s|%s", c.listenAddr, c.targetAddr, c.protocol)
		c.enqueue(&TunnelPacket{Cmd: CmdSetup, Data: []byte(data)})
		return
	}
	if c.socksAddr != "" {
		c.enqueue(&TunnelPacket{Cmd: CmdSocksRegister})
	}
}

func (c *Client) resetTunnelSessions() {
	c.mu.Lock()
	var conns []*ClientConn
	for id, cc := range c.connections {
		conns = append(conns, cc)
		delete(c.connections, id)
	}
	c.pending = make(map[uint32]bool)
	c.mu.Unlock()
	for _, cc := range conns {
		c.closeClientConn(cc, true)
	}
}

func (c *Client) closeClientConn(cc *ClientConn, silent bool) {
	if silent {
		atomic.StoreInt32(&cc.silentClose, 1)
	}
	cc.stopIdleTimer()
	cc.tcpConn.Close()
	cc.reliSend.Close()
	cc.reliRecv.Close()
}

func genBootEpoch() uint32 {
	// Server-assigned ConnIDs must stay below socksConnIDBase so they never collide
	// with client-chosen SOCKS dial IDs (see allocConnID).
	id := genClientID() % socksConnIDBase
	if id == 0 {
		return 1
	}
	return id
}

func genClientID() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err == nil {
		id := binary.BigEndian.Uint32(b[:])
		if id != 0 {
			return id
		}
	}
	return uint32(time.Now().UnixNano())
}
