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

	flag.Parse()

	if *typeFlag == "" {
		fmt.Println("pingtunnel - TCP/UDP port forwarding over ICMP")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  Server:  pingtunnel -type server -key <admin_password> [-web :8080] [-socks-dynamic]")
		fmt.Println("  Client:  pingtunnel -type client -s <server_ip> -key <tunnel_key> (-l :port -t <target> | -socks :1080) [-protocol tcp|udp]")
		fmt.Println()
		fmt.Println("Server options:")
		fmt.Println("  -key    Web admin password (username: admin)")
		fmt.Println("  -web    Web management listen address (default :8080)")
		fmt.Println("  -socks-dynamic  Allow SOCKS5 dynamic port forwarding for clients using -socks")
		fmt.Println()
		fmt.Println("Client options:")
		fmt.Println("  -l      Local listen address")
		fmt.Println("  -s      Server ICMP address")
		fmt.Println("  -t      Target address to forward to")
		fmt.Println("  -key    Tunnel authentication key (configured on server via web)")
		fmt.Println("  -protocol  tcp (default) or udp; must match the server rule")
		fmt.Println("  -socks    Local SOCKS5 listen (ssh -D style); requires server -socks-dynamic")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  sudo pingtunnel -type server -key 123456")
		fmt.Println("  sudo pingtunnel -type server -key 123456 -web :9090")
		fmt.Println("  sudo pingtunnel -type client -l :4455 -s 120.46.204.235 -t 192.168.33.1:22 -key mykey")
		fmt.Println()
		fmt.Println("Note: requires root / sudo for raw ICMP sockets.")
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

		srv := NewServer(mgr, *socksDynamic)
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
		cli := NewClient(listenTrim, *server, targetTrim, *key, *protocol, socksTrim)
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
