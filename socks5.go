package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

func normalizeSocksDialTarget(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(s, "80")
}

// startSOCKS5 listens for SOCKS5 TCP CONNECT and tunnels via ICMP (CmdSocksDial).
func (c *Client) startSOCKS5(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[client] SOCKS listen %s: %v", addr, err)
		return
	}
	c.socksLnMu.Lock()
	c.socksListener = ln
	c.socksLnMu.Unlock()
	defer func() {
		ln.Close()
		c.socksLnMu.Lock()
		if c.socksListener == ln {
			c.socksListener = nil
		}
		c.socksLnMu.Unlock()
	}()
	log.Printf("[client] SOCKS5 listening on %s (dynamic forward)", addr)
	for atomic.LoadInt32(&c.closed) == 0 {
		tc, err := ln.Accept()
		if err != nil {
			if atomic.LoadInt32(&c.closed) != 0 {
				return
			}
			log.Printf("[client] SOCKS accept: %v", err)
			continue
		}
		go c.serveSOCKSConn(tc)
	}
}

func (c *Client) serveSOCKSConn(tc net.Conn) {
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(60 * time.Second))

	buf := make([]byte, 512)
	if _, err := io.ReadFull(tc, buf[:2]); err != nil {
		return
	}
	if buf[0] != 5 {
		return
	}
	nmeth := int(buf[1])
	if nmeth <= 0 || nmeth > 20 {
		return
	}
	if _, err := io.ReadFull(tc, buf[:nmeth]); err != nil {
		return
	}
	if _, err := tc.Write([]byte{5, 0}); err != nil { // no auth
		return
	}

	if _, err := io.ReadFull(tc, buf[:4]); err != nil {
		return
	}
	if buf[0] != 5 || buf[1] != 1 { // CONNECT only
		return
	}
	atyp := buf[3]
	var host string
	switch atyp {
	case 1: // IPv4
		if _, err := io.ReadFull(tc, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 3: // domain
		if _, err := io.ReadFull(tc, buf[:1]); err != nil {
			return
		}
		l := int(buf[0])
		if l <= 0 || l > 255 {
			return
		}
		if _, err := io.ReadFull(tc, buf[:l]); err != nil {
			return
		}
		host = string(buf[:l])
	case 4: // IPv6
		if _, err := io.ReadFull(tc, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		return
	}
	if _, err := io.ReadFull(tc, buf[:2]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(buf[:2])
	dialAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	ch := make(chan bool, 1)
	connID := atomic.AddUint32(&c.nextSocksConn, 1) + socksConnIDBase

	c.socksMu.Lock()
	c.socksWait[connID] = ch
	c.socksMu.Unlock()

	c.enqueue(&TunnelPacket{Cmd: CmdSocksDial, ConnID: connID, Data: []byte(dialAddr)})

	var ok bool
	select {
	case ok = <-ch:
	case <-time.After(25 * time.Second):
		c.socksMu.Lock()
		delete(c.socksWait, connID)
		c.socksMu.Unlock()
		ok = false
	case <-c.done:
		c.socksMu.Lock()
		delete(c.socksWait, connID)
		c.socksMu.Unlock()
		return
	}

	if !ok {
		_, _ = tc.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	if _, err := tc.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		c.enqueue(&TunnelPacket{Cmd: CmdClose, ConnID: connID})
		return
	}
	_ = tc.SetDeadline(time.Time{})

	cc := &ClientConn{id: connID, proto: "tcp", tcpConn: tc}
	cc.reliSend = NewReliableSend(connID, c.enqueue)
	cc.reliRecv = NewReliableRecv(connID,
		func(data []byte) error { _, werr := tc.Write(data); return werr },
		c.enqueue,
	)

	c.mu.Lock()
	c.connections[connID] = cc
	c.mu.Unlock()

	go c.readTarget(cc)
}

const socksConnIDBase uint32 = 0x60000000
