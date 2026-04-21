# PingTunnel

TCP and UDP port forwarding over the ICMP (Ping) protocol. Encapsulates TCP or UDP traffic inside ICMP Echo Request/Reply packets, enabling network access through firewalls that only allow Ping.

[中文文档](README_CN.md)

## Features

- **ICMP Tunneling** — TCP or UDP traffic wrapped in Ping packets, bypassing typical firewall restrictions on direct traffic
- **Reliable Transport** — Sequence numbers, ACKs, automatic retransmission, and out-of-order buffering for lossy networks
- **Web Management** — Built-in Web UI for managing tunnel keys and port forwarding rules
- **Authentication** — Web UI secured with admin login and session-based auth
- **Traffic Statistics** — Real-time speed and historical traffic totals, grouped by key
- **Connection Monitoring** — Live view of active TCP connections with client IPs
- **Persistent Config** — Keys, rules, and traffic data saved to `pingtunnel.json`
- **Auto Recovery** — Server automatically restores port listeners from config on restart

## Build

```bash
go build -o pingtunnel .
```

Cross-compile for Linux amd64:

```bash
GOOS=linux GOARCH=amd64 go build -o pingtunnel .
```

## Usage

> **Note:** Requires root privileges for raw ICMP sockets.

### Server

```bash
sudo ./pingtunnel -type server -key <admin_password>
```

| Flag | Description | Default |
|------|-------------|---------|
| `-key` | Web admin login password (username is `admin`) | Required |
| `-web` | Web management listen address | `:8080` |

After starting, open `http://<server_ip>:8080` in your browser and log in with `admin` / `<admin_password>`.

Use the Web UI to add tunnel keys and forwarding rules:

- **Key** — Authentication key used by clients to connect
- **Listen Address** — Port the server listens on (e.g. `4455` or `:4455`)
- **Target Address** — Destination the client forwards traffic to (e.g. `192.168.33.1:22`)
- **Protocol** — `TCP` (default) or `UDP`; TCP and UDP may use the same listen port as separate rules

### Client

```bash
sudo ./pingtunnel -type client -l <listen_addr> -s <server_ip> -t <target_addr> -key <tunnel_key> [-protocol tcp|udp]
```

| Flag | Description |
|------|-------------|
| `-l` | Local listen address (matches the server rule's Listen Address) |
| `-s` | Server ICMP address (server's public IP) |
| `-t` | Forward target address (matches the server rule's Target Address) |
| `-key` | Tunnel authentication key (configured on the server via Web UI) |
| `-protocol` | `tcp` (default) or `udp`; must match the rule’s protocol on the server |

## Example

### Scenario: SSH to an internal machine via ICMP tunnel

**1. Server (public IP: 120.120.120.120)**

```bash
sudo ./pingtunnel -type server -key admin123
```

Open `http://120.120.120.120:8080`, log in, and add a rule:
- Key: `office-ssh`
- Listen: `4455`
- Target: `192.168.33.1:22`

**2. Client (internal network machine)**

```bash
sudo ./pingtunnel -type client -l :4455 -s 120.46.204.235 -t 192.168.33.1:22 -key office-ssh
```

**3. Connect**

SSH to the server's forwarded port from any machine:

```bash
ssh user@120.46.204.235 -p 4455
```

Traffic path: `SSH Client → Server:4455 → ICMP Tunnel → Internal Client → 192.168.33.1:22`

## Project Structure

```
├── main.go          # CLI entry point and flag parsing
├── protocol.go      # ICMP tunnel protocol definition and encoding
├── server.go        # Server: ICMP listener, TCP/UDP forwarding
├── client.go        # Client: ICMP tunnel connection, TCP/UDP forwarding
├── reliable.go      # Reliable transport: seq numbers, ACK, retransmit, reordering
├── manager.go       # Key/rule management, traffic stats, config persistence
├── web.go           # Web HTTP server, API handlers, session auth
├── web.html         # Web management UI (embedded in binary)
└── pingtunnel.json  # Runtime config file (auto-generated)
```

## How It Works

```
┌─────────┐    ICMP Echo    ┌─────────┐     TCP      ┌────────┐
│  Server │ ◄────────────► │  Client │ ◄──────────► │ Target │
│  :4455  │  Request/Reply  │         │              │ :22    │
└─────────┘                 └─────────┘              └────────┘
     ▲
     │ TCP
     │
┌─────────┐
│SSH User │
└─────────┘
```

1. Client and server establish a tunnel via ICMP Echo Request/Reply
2. Server listens on a TCP port and accepts external connections
3. TCP data is encapsulated into ICMP packets and sent through the tunnel to the client
4. Client decapsulates the data and forwards it to the target address
5. Reliable transport layer ensures data integrity (ACK, retransmission, reordering)

## License

MIT
