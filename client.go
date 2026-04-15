package main

import (
	"fmt"
	"log"
	"net"
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
	key        [16]byte

	icmpConn *icmp.PacketConn
	serverIP net.Addr

	connections map[uint32]*ClientConn
	pending     map[uint32]bool
	sendQueue   chan *TunnelPacket

	icmpSeq   uint32
	mu        sync.RWMutex
	closed    int32
	done      chan struct{}
	setupDone chan struct{}
}

type ClientConn struct {
	id       uint32
	tcpConn  net.Conn
	reliSend *ReliableSend
	reliRecv *ReliableRecv
}

func NewClient(listenAddr, serverAddr, targetAddr, key string) *Client {
	return &Client{
		listenAddr:  listenAddr,
		serverAddr:  serverAddr,
		targetAddr:  targetAddr,
		key:         ComputeKeyHash(key),
		connections: make(map[uint32]*ClientConn),
		pending:     make(map[uint32]bool),
		sendQueue:   make(chan *TunnelPacket, 4096),
		done:        make(chan struct{}),
		setupDone:   make(chan struct{}),
	}
}

func (c *Client) Close() {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return
	}
	close(c.done)
	if c.icmpConn != nil {
		c.icmpConn.Close()
	}
	c.mu.Lock()
	for _, cc := range c.connections {
		cc.tcpConn.Close()
		cc.reliSend.Close()
		cc.reliRecv.Close()
	}
	c.mu.Unlock()
}

func (c *Client) Run() error {
	ip := net.ParseIP(c.serverAddr)
	if ip == nil {
		addrs, err := net.LookupHost(c.serverAddr)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", c.serverAddr, err)
		}
		ip = net.ParseIP(addrs[0])
	}
	c.serverIP = &net.IPAddr{IP: ip}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("ICMP listen failed (run as root): %w", err)
	}
	c.icmpConn = conn
	defer conn.Close()

	go c.receiver()
	go c.sender()
	go c.sendSetup()
	go c.retransmitLoop()

	log.Printf("[client] connecting to server %s ...", c.serverAddr)

	select {
	case <-c.setupDone:
		log.Printf("[client] tunnel ready: %s listens on %s, target %s",
			c.serverAddr, c.listenAddr, c.targetAddr)
	case <-time.After(30 * time.Second):
		return fmt.Errorf("setup timeout (check -key and server status)")
	case <-c.done:
		return nil
	}

	<-c.done
	return nil
}

func (c *Client) sendSetup() {
	data := fmt.Sprintf("%s|%s", c.listenAddr, c.targetAddr)
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

func (c *Client) sender() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	icmpID := int(c.key[0])<<8 | int(c.key[1])

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
		seq := atomic.AddUint32(&c.icmpSeq, 1)
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
		c.icmpConn.WriteTo(mb, c.serverIP)
	}
}

func (c *Client) receiver() {
	buf := make([]byte, 65535)
	for atomic.LoadInt32(&c.closed) == 0 {
		c.icmpConn.SetReadDeadline(time.Now().Add(time.Second))
		n, _, err := c.icmpConn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if atomic.LoadInt32(&c.closed) != 0 {
				return
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

	log.Printf("[client] conn %d: dialing %s", pkt.ConnID, target)

	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("[client] conn %d: dial failed: %v", pkt.ConnID, err)
		c.mu.Lock()
		delete(c.pending, pkt.ConnID)
		c.mu.Unlock()
		c.enqueue(&TunnelPacket{Cmd: CmdClose, ConnID: pkt.ConnID})
		return
	}

	cc := &ClientConn{id: pkt.ConnID, tcpConn: conn}
	cc.reliSend = NewReliableSend(pkt.ConnID, c.enqueue)
	cc.reliRecv = NewReliableRecv(pkt.ConnID,
		func(data []byte) error {
			_, err := conn.Write(data)
			return err
		},
		c.enqueue,
	)

	c.mu.Lock()
	delete(c.pending, pkt.ConnID)
	c.connections[pkt.ConnID] = cc
	c.mu.Unlock()

	c.enqueue(&TunnelPacket{Cmd: CmdConnectAck, ConnID: pkt.ConnID})
	log.Printf("[client] conn %d: established to %s", pkt.ConnID, target)

	go c.readTarget(cc)
}

func (c *Client) readTarget(cc *ClientConn) {
	defer func() {
		c.mu.Lock()
		delete(c.connections, cc.id)
		c.mu.Unlock()
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
	c.mu.Lock()
	cc, ok := c.connections[pkt.ConnID]
	if ok {
		delete(c.connections, pkt.ConnID)
	}
	c.mu.Unlock()
	if ok {
		cc.tcpConn.Close()
		cc.reliSend.Close()
		cc.reliRecv.Close()
		log.Printf("[client] conn %d: closed by server", pkt.ConnID)
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
