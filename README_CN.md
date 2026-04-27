# PingTunnel

基于 **ICMP (Ping)** 或可选 **DNS（UDP 查询/响应 + EDNS0）** 的 **TCP 与 UDP** 端口转发工具。隧道内承载格式与原有 ICMP 模式相同；DNS 方式适用于只允许访问 DNS 式 UDP 的场景，且通常**不需要** root（除非使用 53 等特权端口）。

[English](README.md)

## 特性

- **ICMP 隧道** — TCP 或 UDP 流量封装在 Ping 包中，绕过对直连流量的常见防火墙限制
- **DNS 隧道（可选）** — 同样协议经 DNS 式 UDP/EDNS0 传输。服务端**可同时**开 ICMP 与 DNS（默认 `-transport both`）；**客户端**仍只选一种：`-transport icmp` 或 `-transport dns`。
- **可靠传输** — 序列号、ACK 确认、自动重传、乱序缓冲，适应高丢包环境
- **Web 管理** — 内置 Web UI，管理隧道密钥和端口转发规则
- **登录认证** — Web 管理界面使用 admin 账号 + 密码登录，Session 鉴权
- **流量统计** — 实时网速、历史流量汇总，按密钥分组统计
- **连接监控** — 实时显示活跃 TCP/UDP 会话及其客户端地址
- **配置持久化** — 密钥、规则、流量数据自动保存到 `pingtunnel.json`
- **自动恢复** — 服务器重启后自动根据配置文件恢复端口监听
- **SOCKS5 动态转发** — 可选本地 SOCKS5 代理（类似 `ssh -D`）；服务端通过 `-socks-dynamic` 控制是否允许

## 编译

```bash
go build -o pingtunnel .
```

交叉编译 Linux amd64：

```bash
GOOS=linux GOARCH=amd64 go build -o pingtunnel .
```

## 使用方法

> **注意：** 默认 **ICMP** 模式需要 root。选择 **DNS** 传输时使用普通 UDP，通常不需要 root（除非使用如 53 的特权端口）。

### 服务器端

**ICMP + DNS（默认，同时监听）：**

```bash
sudo ./pingtunnel -type server -key <管理密码>
# 与 `-transport both` 等价
```

**仅 DNS：**

```bash
./pingtunnel -type server -key <管理密码> -transport dns -dns-addr :1053 -dns-name c.pingt.local
```

参数说明：

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-key` | Web 管理登录密码（用户名固定为 `admin`） | 必填 |
| `-web` | Web 管理监听地址 | `:8080` |
| `-transport` | `both`（默认）同时开 ICMP+DNS，或只开 `icmp` / `dns` | `both` |
| `-dns-addr` | 含 DNS 时的 UDP 监听，如 `:1053` | `:1053` |
| `-dns-name` | 含 DNS 时 QNAME，与走 DNS 的客户端一致 | `c.pingt.local` |
| `-socks-dynamic` | 允许客户端使用 `-socks`（经隧道的 SOCKS5 动态转发） | 关闭 |

启动后打开浏览器访问 `http://<服务器IP>:8080`，使用 `admin` / `<管理密码>` 登录。

在 Web 界面中添加隧道密钥和端口转发规则：

- **Key** — 客户端连接使用的认证密钥
- **Listen Address** — 服务器端监听的端口（如 `4455` 或 `:4455`）
- **Target Address** — 客户端需要转发到的目标地址（如 `192.168.33.1:22`）
- **Protocol** — `TCP`（默认）或 `UDP`；同一监听端口可同时配置 TCP 与 UDP 两条独立规则

### 客户端

至少需要 **固定端口转发（`-l` 与 `-t` 同时指定）** 或 **SOCKS 动态转发（`-socks`）** 其一；`-s` 与 `-key` 始终必填。`-l` 与 `-t` 必须成对出现或同时省略。

```bash
# 仅固定转发
sudo ./pingtunnel -type client -l <监听地址> -s <服务器IP> -t <目标地址> -key <隧道密钥> [-protocol tcp|udp]

# 仅 SOCKS 动态转发（服务端须加 -socks-dynamic）
sudo ./pingtunnel -type client -s <服务器IP> -key <隧道密钥> -socks <socks监听地址>

# 固定转发与 SOCKS 共用一条隧道
sudo ./pingtunnel -type client -l <监听地址> -s <服务器IP> -t <目标地址> -key <隧道密钥> -socks :1080
```

参数说明：

| 参数 | 说明 |
|------|------|
| `-l` | 本地监听地址（与服务器端规则中的 Listen Address 一致）；做固定转发时须与 `-t` 同时使用 |
| `-s` | 服务器 ICMP 地址（服务器公网 IP） |
| `-t` | 转发目标地址（与服务器端规则中的 Target Address 一致）；做固定转发时须与 `-l` 同时使用 |
| `-key` | 隧道认证密钥（在服务器 Web 界面中配置的 Key） |
| `-protocol` | `tcp`（默认）或 `udp`，须与服务器端该条规则的协议一致 |
| `-socks` | 本地 SOCKS5 监听地址（如 `:1080`），行为类似 `ssh -D`。无认证，仅支持 CONNECT。服务端必须带 `-socks-dynamic` 才会允许。 |
| `-transport` | 客户端为 `icmp`（默认）或 `dns`（二选一；服务端可 `both` 同时支持两种入站方式）。 |
| `-dns-name` | DNS 模式下的 QNAME，须与走 DNS 的服务端一致（默认 `c.pingt.local`） |

**端与端** — 服务端为默认 `both` 时，可一部分客户端用 ICMP、一部分用 DNS。**DNS 下 `-s`：** `主机:端口` 指 UDP 监听，如 `120.120.120.120:1053`；未写端口则默认 `1053`。**ICMP 下 `-s`：** 写服务器 IP/主机名即可（有 `:端口` 会去掉端口再解析）。

若服务端未开启 `-socks-dynamic`，纯 `-socks` 模式会立即报错；若同时配置了 `-l`/`-t`，固定转发仍可用，但 SOCKS 拨号会失败，直至服务端开启该选项。

## 示例

### 场景：通过 ICMP 隧道 SSH 到内网机器

**1. 服务器端（公网 IP: 120.120.120.120）**

```bash
sudo ./pingtunnel -type server -key admin123
```

打开 `http://120.120.120.120:8080`，登录后添加：
- Key: `office-ssh`
- Listen: `4455`
- Target: `192.168.33.1:22`

**2. 客户端（内网机器）**

```bash
sudo ./pingtunnel -type client -l :4455 -s 120.120.120.120 -t 192.168.33.1:22 -key office-ssh
```

**3. 使用**

从任意机器 SSH 连接到服务器的 4455 端口：

```bash
ssh user@120.120.120.120 -p 4455
```

流量路径：`SSH 客户端 → 服务器:4455 → ICMP 隧道 → 内网客户端 → 192.168.33.1:22`

### 场景：SOCKS5 动态转发（类似 `ssh -D`）

**1. 服务器端**

```bash
sudo ./pingtunnel -type server -key admin123 -socks-dynamic
```

**2. 客户端（本机起 SOCKS5；出站 TCP 由服务器代拨）**

```bash
sudo ./pingtunnel -type client -s 120.120.120.120 -key office-ssh -socks :1080
```

**3. 使用支持 SOCKS5 的工具**

```bash
curl --socks5 127.0.0.1:1080 https://example.com
```

## 项目结构

```
├── main.go          # CLI 入口，参数解析
├── protocol.go      # 隧道帧协议定义与编解码
├── dnstun.go        # DNS/UDP+EDNS0 承载层（可选）
├── server.go        # 服务器：ICMP 或 DNS/UDP、TCP/UDP 转发
├── client.go        # 客户端：到服务器的隧道、TCP/UDP 转发
├── reliable.go      # 可靠传输层：序列号、ACK、重传、乱序缓冲
├── manager.go       # 密钥与规则管理、流量统计、配置持久化
├── web.go           # Web HTTP 服务、API、登录鉴权
├── web.html         # Web 管理界面（嵌入二进制）
└── pingtunnel.json  # 运行时配置文件（自动生成）
```

## 工作原理

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

1. 客户端与服务器通过 ICMP Echo Request/Reply 建立隧道
2. 服务器按规则监听 TCP 或 UDP 端口（TCP 为接受连接，UDP 为按对端地址区分会话）
3. 业务数据封装为 ICMP 数据包，通过隧道传输到客户端
4. 客户端解封装后转发到目标地址
5. 可靠传输层保证数据完整性（ACK、重传、乱序重组）

## 许可证

MIT
