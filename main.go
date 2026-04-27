package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	typeFlag := flag.String("type", "", "server or client")
	key := flag.String("key", "", "server: web admin password / client: tunnel key")
	listen := flag.String("l", "", "listen address, e.g. :4455")
	server := flag.String("s", "", "server address, e.g. 120.46.204.235")
	target := flag.String("t", "", "target address, e.g. 192.168.33.1:22")
	protocol := flag.String("protocol", "tcp", "forwarding protocol: tcp or udp (client only)")
	webAddr := flag.String("web", ":8080", "web management listen address")
	socksDynamic := flag.Bool("socks-dynamic", false, "server: allow client SOCKS5 dynamic forwarding (-socks)")
	socks := flag.String("socks", "", "client: local SOCKS5 listen address, e.g. :1080")
	transport := flag.String("transport", "", "server: both|icmp|dns (default both). client: icmp|dns (default icmp).")
	dnsAddr := flag.String("dns-addr", ":1053", "server: UDP listen (DNS mode only, e.g. :1053)")
	dnsName := flag.String("dns-name", "c.pingt.local", "QNAME in DNS mode; must match on server and client")

	flag.Parse()

	if *typeFlag == "" {
		fmt.Println("pingtunnel - TCP/UDP port forwarding over ICMP or DNS (UDP)")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  Server:  pingtunnel -type server -key <admin_password> [-transport both|icmp|dns] ...")
		fmt.Println("  Client:  pingtunnel -type client -s <server> -key <tunnel_key> (-l -t | -socks) ... [-transport icmp|dns] ...")
		fmt.Println()
		fmt.Println("Server options:")
		fmt.Println("  -key    Web admin password (username: admin)")
		fmt.Println("  -web    Web management listen address (default :8080)")
		fmt.Println("  -socks-dynamic  Allow SOCKS5 dynamic port forwarding for clients using -socks")
		fmt.Println("  -transport  both (default) = ICMP + DNS. Or icmp only, dns only.")
		fmt.Println("  -dns-addr  UDP listen for DNS part (default :1053; used with both or dns)")
		fmt.Println("  -dns-name  QNAME in DNS (default c.pingt.local)")
		fmt.Println()
		fmt.Println("Client options:")
		fmt.Println("  -l      Local listen address")
		fmt.Println("  -s      Server: ICMP (default mode) = IP/hostname. DNS mode: host:port, default port 1053")
		fmt.Println("  -t      Target address to forward to")
		fmt.Println("  -key    Tunnel authentication key (configured on server via web)")
		fmt.Println("  -protocol  tcp (default) or udp; must match the server rule")
		fmt.Println("  -socks    Local SOCKS5 listen (ssh -D style); requires server -socks-dynamic")
		fmt.Println("  -transport, -dns-addr, -dns-name  Same meaning as server; use dns together")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  sudo pingtunnel -type server -key 123456")
		fmt.Println("  ./pingtunnel -type server -transport dns -key 123456 -dns-addr :1053   # DNS only")
		fmt.Println("  sudo pingtunnel -type client -l :4455 -s 120.46.204.235 -t 192.168.33.1:22 -key mykey")
		fmt.Println("  ./pingtunnel -type client -transport dns -s 120.46.204.235:1053 -l :4455 -t 192.168.33.1:22 -key mykey")
		fmt.Println()
		fmt.Println("Note: ICMP mode needs root. DNS transport uses UDP and usually does not require root (unless e.g. port 53).")
		os.Exit(0)
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	switch *typeFlag {
	case "server":
		if *key == "" {
			log.Fatal("server mode requires -key (web admin password, username: admin)")
		}

		mgr := NewManager("pingtunnel.json")
		if err := mgr.Load(); err != nil {
			log.Printf("[main] config load: %v (starting fresh)", err)
		}

		srvT := strings.ToLower(strings.TrimSpace(*transport))
		if srvT == "" {
			srvT = "both"
		}
		switch srvT {
		case "both", "all", "icmp", "ping", "dns":
		default:
			log.Fatalf("server: -transport must be both, icmp, or dns, got %q", *transport)
		}
		srv := NewServer(mgr, *socksDynamic, srvT, *dnsAddr, *dnsName)
		StartWeb(*webAddr, *key, mgr, srv)

		go func() {
			<-sigCh
			log.Println("shutting down ...")
			srv.Close()
			os.Exit(0)
		}()
		if err := srv.Run(); err != nil {
			log.Fatal(err)
		}

	case "client":
		listenTrim := strings.TrimSpace(*listen)
		targetTrim := strings.TrimSpace(*target)
		socksTrim := strings.TrimSpace(*socks)
		hasPF := listenTrim != "" && targetTrim != ""
		if *server == "" {
			log.Fatal("client mode requires -s")
		}
		if *key == "" {
			log.Fatal("client mode requires -key")
		}
		if (listenTrim != "") != (targetTrim != "") {
			log.Fatal("client -l and -t must both be set for port forwarding, or omit both when using -socks only")
		}
		if !hasPF && socksTrim == "" {
			log.Fatal("client mode requires (-l and -t) and/or -socks")
		}
		cliT := strings.ToLower(strings.TrimSpace(*transport))
		if cliT == "" {
			cliT = "icmp"
		}
		if cliT == "both" || cliT == "all" {
			log.Fatalf("client: -transport must be icmp or dns (not both)")
		}
		if cliT != "icmp" && cliT != "ping" && cliT != "dns" {
			log.Fatalf("client: -transport must be icmp or dns, got %q", *transport)
		}
		cli := NewClient(listenTrim, *server, targetTrim, *key, *protocol, socksTrim, cliT, *dnsName)
		go func() {
			<-sigCh
			log.Println("shutting down ...")
			cli.Close()
			os.Exit(0)
		}()
		if err := cli.Run(); err != nil {
			log.Fatal(err)
		}

	default:
		log.Fatalf("unknown -type %q (use server or client)", *typeFlag)
	}
}
