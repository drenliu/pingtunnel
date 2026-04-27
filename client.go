package main

import (
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

type Client struct {
	listenAddr string
	serverAddr string
	targetAddr string
	protocol   string
	socksAddr  string
	transport  string
	dnsQName   string
	key        [16]byte

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

	tunSeq    uint32
	mu        sync.RWMutex
	closed    int32
	done      chan struct{}
	setupDone chan struct{}
	setupFail chan struct{}
}

type ClientConn struct {
	id       uint32
	proto    string
	tcpConn  net.Conn // TCP stream or UDP datagram socket (implements net.Conn)
	reliSend *ReliableSend
	reliRecv *ReliableRecv

	idleMu    sync.Mutex
	idleTimer *time.Timer
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
	for i := 0; i < 30; i++ {
		select {
		case <-c.setupDone:
			return
		case <-c.done:
			return
		default:
		}
		c.enqueue(&TunnelPacket{Cmd: CmdSetup, Data: []byte(data)})
		time.Sleep(time.Second)
	}
}

func (c *Client) sendSocksRegister() {
	for i := 0; i < 30; i++ {
		select {
		case <-c.setupDone:
			return
		case <-c.done:
			return
		default:
		}
		c.enqueue(&TunnelPacket{Cmd: CmdSocksRegister})
		time.Sleep(time.Second)
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

		payload, err := pkt.Encode()
		if err != nil {
			continue
		}
		seq := atomic.AddUint32(&c.tunSeq, 1)
		if c.transport == "dns" {
			id := uint16(seq)
			dnsWire, e := buildDNSRequest(id, qn, payload)
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
			if e != nil || pkt.Magic != MagicResponse || pkt.KeyHash != c.key {
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
		if err != nil || pkt.Magic != MagicResponse || pkt.KeyHash != c.key {
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
	c.mu.Lock()
	if cc, exists := c.connections[pkt.ConnID]; exists {
		c.mu.Unlock()
		_ = cc
		c.enqueue(&TunnelPacket{Cmd: CmdConnectAck, ConnID: pkt.ConnID})
		return
	}
	if c.pending[pkt.ConnID] {
		c.mu.Unlock()
		return
	}
	c.pending[pkt.ConnID] = true
	c.mu.Unlock()

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
		c.enqueue(&TunnelPacket{Cmd: CmdClose, ConnID: cc.id})
		log.Printf("[client] conn %d: target closed", cc.id)
	}()

	buf := make([]byte, MaxPayloadSize)
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
