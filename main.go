package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
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

	flag.Parse()

	if *typeFlag == "" {
		fmt.Println("pingtunnel - TCP/UDP port forwarding over ICMP")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  Server:  pingtunnel -type server -key <admin_password> [-web :8080]")
		fmt.Println("  Client:  pingtunnel -type client -l :4455 -s <server_ip> -t <target> -key <tunnel_key> [-protocol tcp|udp]")
		fmt.Println()
		fmt.Println("Server options:")
		fmt.Println("  -key    Web admin password (username: admin)")
		fmt.Println("  -web    Web management listen address (default :8080)")
		fmt.Println()
		fmt.Println("Client options:")
		fmt.Println("  -l      Local listen address")
		fmt.Println("  -s      Server ICMP address")
		fmt.Println("  -t      Target address to forward to")
		fmt.Println("  -key    Tunnel authentication key (configured on server via web)")
		fmt.Println("  -protocol  tcp (default) or udp; must match the server rule")
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

		srv := NewServer(mgr)
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
		if *server == "" || *target == "" || *listen == "" {
			log.Fatal("client mode requires -l, -s, and -t flags")
		}
		cli := NewClient(*listen, *server, *target, *key, *protocol)
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
