package main

import (
	"net"
	"testing"
)

func TestTunnelPeerMatchICMPIPOnly(t *testing.T) {
	server := &net.IPAddr{IP: net.ParseIP("203.0.113.10")}
	if !tunnelPeerMatch(server, &net.IPAddr{IP: net.ParseIP("203.0.113.10")}) {
		t.Fatal("same server IP should match")
	}
	if tunnelPeerMatch(server, &net.IPAddr{IP: net.ParseIP("198.51.100.20")}) {
		t.Fatal("foreign IP must not match (forged ICMP echo reply)")
	}
	if tunnelPeerMatch(server, nil) || tunnelPeerMatch(nil, server) {
		t.Fatal("nil addr must not match")
	}
}

func TestTunnelPeerMatchDNSRequiresIPAndPort(t *testing.T) {
	server := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1053}
	if !tunnelPeerMatch(server, &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 1053}) {
		t.Fatal("same UDP peer should match")
	}
	if tunnelPeerMatch(server, &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 5353}) {
		t.Fatal("same IP wrong port must not match")
	}
	if tunnelPeerMatch(server, &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 1053}) {
		t.Fatal("wrong IP must not match")
	}
}

func TestTunnelPeerMatchIPv4Mapped(t *testing.T) {
	server := &net.IPAddr{IP: net.ParseIP("203.0.113.10")}
	mapped := &net.IPAddr{IP: net.ParseIP("::ffff:203.0.113.10")}
	if !tunnelPeerMatch(server, mapped) {
		t.Fatal("IPv4-mapped form of the same address should match")
	}
}
