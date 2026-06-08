# PingTunnel

TCP and UDP port forwarding over the **ICMP (Ping) protocol** or, alternatively, over **DNS** (UDP queries/responses with EDNS0, same tunnel framing as ICMP). ICMP mode targets environments that only allow ping; DNS mode is useful when only DNS-like UDP traffic to your server is allowed, and it usually does not require `root` (unless you bind a privileged port such as 53).

[中文文档](README_CN.md)

## Features

- **ICMP Tunneling** — TCP or UDP traffic wrapped in Ping packets, bypassing typical firewall restrictions on direct traffic
- **DNS Tunneling (optional)** — Same protocol over DNS-like UDP/EDNS0. The **server** can run **ICMP and DNS at the same time** (default `-transport both`). The **client** still picks **one** carrier: `-transport icmp` or `-transport dns`.
- **Reliable Transport** — Sequence numbers, ACKs, automatic retransmission, and out-of-order buffering for lossy networks
- **Web Management** — Built-in Web UI for managing tunnel keys and port forwarding rules
- **Key aliases** — Optional display name per key (`name` in `pingtunnel.json`); edit tunnel secret and alias from the UI
- **Authentication** — Web UI secured with admin login and session-based auth
- **Traffic Statistics** — Real-time speed and historical traffic totals, grouped by key
- **Connection Monitoring** — Live view of active TCP connections with client IPs
- **Persistent Config** — Keys, rules, and traffic data saved to `pingtunnel.json`
- **Auto Recovery** — Server restores port listeners from config on restart; clients periodically re-register so tunnel routes recover without a client restart (ICMP and DNS)
- **DNS Transparent Proxy** — Optional upstream DNS relay: queries for names other than `-dns-name` are forwarded to `-dns-upstream` (useful when binding `:53`)
- **Multi-Client Isolation** — Each client instance has a unique `clientID`; multiple clients with the same key and source IP are routed independently
- **SOCKS5 Dynamic Forwarding** — Optional local SOCKS5 proxy (`ssh -D` style); server can enable or disable it with `-socks-dynamic`

## Build

```bash
go build -o pingtunnel .
```

Cross-compile for Linux amd64:

```bash
GOOS=linux GOARCH=amd64 go build -o pingtunnel .
```

## Usage

> **Note:** The default **ICMP** mode requires `root` for raw ICMP sockets. **DNS** mode uses a normal UDP datagram socket and does not (unless you bind a privileged port such as 53).

### Server

**ICMP (default):**

```bash
sudo ./pingtunnel -type server -key <admin_password>
```

**ICMP + DNS (default, server listens on both; clients choose either to connect):**

```bash
./pingtunnel -type server -key <admin_password>
# same: -transport both
```

**DNS only** (e.g. no root on the host):

```bash
./pingtunnel -type server -key <admin_password> -transport dns -dns-addr :1053 -dns-name c.pingt.local
```

**DNS + transparent proxy** (listen on `:53`, tunnel on `c.pingt.local`, relay other names to upstream DNS):

```bash
sudo ./pingtunnel -type server -key <admin_password> -transport dns \
  -dns-addr :53 -dns-name c.pingt.local -dns-upstream 8.8.8.8
```

| Flag | Description | Default |
|------|-------------|---------|
| `-key` | Web admin login password (username is `admin`) | Required |
| `-web` | Web management listen address | `:8080` |
| `-web-server-ip` | Default `-s` host in Web UI copy-paste client commands (optional; see **Web UI** below) | *(empty)* |
| `-transport` | `both` (default): ICMP and DNS. Or `icmp` or `dns` only | `both` |
| `-dns-addr` | UDP port for the DNS part (when `both` or `dns`) | `:1053` |
| `-dns-name` | QNAME for DNS tunnel; must match **DNS** clients’ `-dns-name` | `c.pingt.local` |
| `-dns-upstream` | Upstream DNS for non-tunnel queries (transparent proxy on `-dns-addr`) | *(empty)* |
| `-socks-dynamic` | Allow clients to use `-socks` (SOCKS5 dynamic forwarding over the tunnel) | off |

After starting, open `http://<server_ip>:8080` in your browser and log in with `admin` / `<admin_password>`.

Use the Web UI to add tunnel keys and forwarding rules:

- **Key** — Authentication secret used by clients (`-key`); stored in config as `key`
- **Alias** (optional) — Display label only (`name` in `pingtunnel.json`); does not change authentication
- **Listen Address** — Port the server listens on (e.g. `4455` or `:4455`)
- **Target Address** — Destination the client forwards traffic to (e.g. `192.168.33.1:22`)
- **Protocol** — `TCP` (default) or `UDP`; TCP and UDP may use the same listen port as separate rules
- **Edit** — Per-key **Edit** updates alias and/or tunnel key. Changing the secret changes the key hash; the server restarts port-forward listeners for that key’s rules only (existing clients must use the new `-key`).
- **Edit Rule** — Per-rule **Edit Rule** updates listen address, target address, and protocol; the server rebinds affected listeners automatically.

**Client command templates (`-s` in the copied command):**

- If the server was started with **`-web-server-ip <host>`**, that value is used for `-s`.
- Otherwise the UI uses the **browser address bar host** (`window.location.host`: hostname and non-default port, e.g. `120.120.120.120:8080` when you open `http://120.120.120.120:8080/`). If the host is empty, the placeholder `<SERVER_IP>` is shown.
- **ICMP clients** usually need `-s` as the tunnel endpoint (public IP or DNS name), **without** the Web UI port. If you manage the server via `http://public-ip:8080`, set **`-web-server-ip public-ip`** (or a hostname) so copy-paste commands omit the `:8080` web port.

### Client

You need **either** fixed port forwarding **(`-l` and `-t` together)** **or** SOCKS dynamic forwarding **(`-socks`)**, or **both**. `-s` and `-key` are always required.

```bash
# Fixed forwarding only
sudo ./pingtunnel -type client -l <listen_addr> -s <server_ip> -t <target_addr> -key <tunnel_key> [-protocol tcp|udp]

# SOCKS dynamic forwarding only (server must use -socks-dynamic)
sudo ./pingtunnel -type client -s <server_ip> -key <tunnel_key> -socks <socks_listen_addr>

# Both fixed forwarding and SOCKS on the same tunnel
sudo ./pingtunnel -type client -l <listen_addr> -s <server_ip> -t <target_addr> -key <tunnel_key> -socks :1080
```

| Flag | Description |
|------|-------------|
| `-l` | Local listen address (matches the server rule's Listen Address); must be used together with `-t` when doing fixed forwarding |
| `-s` | Server ICMP address (server's public IP) |
| `-t` | Forward target address (matches the server rule's Target Address); must be used together with `-l` when doing fixed forwarding |
| `-key` | Tunnel authentication key (configured on the server via Web UI) |
| `-protocol` | `tcp` (default) or `udp`; must match the rule’s protocol on the server |
| `-socks` | Local SOCKS5 listen address (e.g. `:1080`), similar to `ssh -D`. No authentication; CONNECT only. Requires the server to be started with `-socks-dynamic`. |
| `-transport` | `icmp` (default) or `dns` (client uses **one**; server can offer **both**). |
| `-dns-name` | In DNS mode, the query name; must match the server (default `c.pingt.local`) |

**Client vs server** — A server with default `-transport both` accepts both ICMP clients and DNS clients at the same time. **DNS mode / `-s` on the client** — use `host:port` to reach the server’s UDP listener (e.g. `120.120.120.120:1053`); the port defaults to `1053` if omitted. ICMP mode uses `-s` as the target host or IP (optional `:port` is stripped and ignored for the ICMP path).

If the server does not enable `-socks-dynamic`, SOCKS-only clients receive an immediate error; combined-mode clients can still use fixed forwarding, but SOCKS dials will fail until the server enables it.

## Example

### Scenario: SSH to an internal machine via ICMP tunnel

**1. Server (public IP: 120.120.120.120)**

```bash
sudo ./pingtunnel -type server -key admin123
# optional: so Web UI copy-paste uses this host for -s (see Web UI section)
# sudo ./pingtunnel -type server -key admin123 -web-server-ip 120.120.120.120
```

Open `http://120.120.120.120:8080`, log in, and add a rule:
- Key: `office-ssh`
- Listen: `4455`
- Target: `192.168.33.1:22`

**2. Client (internal network machine)**

```bash
sudo ./pingtunnel -type client -l :4455 -s 120.120.120.120 -t 192.168.33.1:22 -key office-ssh
```

**3. Connect**

SSH to the server's forwarded port from any machine:

```bash
ssh user@120.120.120.120 -p 4455
```

Traffic path: `SSH Client → Server:4455 → ICMP Tunnel → Internal Client → 192.168.33.1:22`

### Scenario: SOCKS5 dynamic forwarding (like `ssh -D`)

**1. Server**

```bash
sudo ./pingtunnel -type server -key admin123 -socks-dynamic
```

**2. Client (runs a local SOCKS5 proxy; outbound TCP is dialed by the server)**

```bash
sudo ./pingtunnel -type client -s 120.120.120.120 -key office-ssh -socks :1080
```

**3. Use any SOCKS5-aware tool**

```bash
curl --socks5 127.0.0.1:1080 https://example.com
```

### Scenario: DNS transport with transparent proxy

Use this when the server can listen on UDP `:53` and you want normal DNS resolution plus the tunnel on the same port.

**1. Server**

```bash
sudo ./pingtunnel -type server -key admin123 -transport dns \
  -dns-addr :53 -dns-name c.pingt.local -dns-upstream 8.8.8.8
```

**2. Client** (no root required for DNS transport)

```bash
./pingtunnel -type client -transport dns -s 120.120.120.120:53 \
  -l :4455 -t 192.168.33.1:22 -key office-ssh -dns-name c.pingt.local
```

**3. Point DNS resolvers at the server**

Set a machine’s DNS to `120.120.120.120`. Ordinary lookups (e.g. `example.com`) go to `8.8.8.8` via `-dns-upstream`. The pingtunnel client still uses `c.pingt.local` for tunnel traffic.

### Server restart recovery

On restart, the server reloads `pingtunnel.json` and reopens configured listen ports. In-memory tunnel client routes are rebuilt when clients re-send `CmdSetup` (every ~20 seconds after the initial handshake). **Update both server and client binaries** for this behavior. No client restart is required after a server restart; allow up to ~20 seconds for routes to recover.

## Project Structure

```
├── main.go          # CLI entry point and flag parsing
├── protocol.go      # Tunnel frame definition and encoding
├── dnstun.go        # DNS/UDP+EDNS0 carrier (optional transport)
├── server.go        # Server: ICMP or DNS/UDP, TCP/UDP forwarding
├── client.go        # Client: tunnel to server, TCP/UDP forwarding
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
