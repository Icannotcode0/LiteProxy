# LiteProxy

A **lightweight**, **modular** proxy server written in Go, designed to deliver seamless SOCKS5 CONNECT tunneling—and nothing else… for now. 🛠️

---

## 🌟 Highlights

- **Minimalist Core**: Only the SOCKS5 CONNECT command is implemented, ensuring a small codebase and maximum focus.
- **Universal Relay**: High-performance, bidirectional traffic relay decoupled from protocol logic.
- **Go Idiomatic**: Leverages Go’s `net` library and channels for clean, maintainable code.
- **Future-Proof**: Architecture ready for SOCKS5 BIND, UDP ASSOCIATE, user authentication, and HTTP proxy extensions.

---

## 🚀 Features

| Status | Feature                           |
| ------ | --------------------------------- |
| ✅      | SOCKS5 CONNECT                    |
| ❌      | SOCKS5 BIND                       |
| ❌      | SOCKS5 UDP ASSOCIATE              |
| ❌      | Username/Password Authentication  |
| ❌      | HTTP(s) Proxy (CONNECT & Forward) |
| ❌      | Config File & CLI Enhancements    |
| ❌      | Advanced Logging & Metrics        |

*(✅ implemented, ❌ pending)*

---

## 🗂️ Project Layout

```plain
LiteProxy/
├── cmd/
│   └── liteproxy/                 # Application entrypoint
│       └── main.go                # CLI flags & server launcher
├── configs/                       # Configuration files
│   └── socks5-server-config.json  # SOCKS5 server JSON config
├── internal/                      # Core application packages
│   ├── common/
│   │   └── protocol.go            # SOCKS5 protocol constants & types
│   ├── config/
│   │   └── config.go              # Configuration loading logic
│   ├── listener/
│   │   └── listener.go            # Connection listener & accept loop
│   ├── protocols/                 # Protocol-specific handlers
│   │   ├── http/
│   │   │   └── server.go          # HTTP proxy scaffolding (WIP)
│   │   └── socks5/
│   │       ├── authentication/
│   │       │   └── auth.go        # SOCKS5 auth implementation
│   │       ├── request/
│   │       │   └── request.go     # Request parsing & reply logic
│   │       └── server.go          # SOCKS5 handshake & command loop
│   └── proxy/
│       └── proxy.go               # Universal bidirectional relay
├── pkg/                           # Reusable utility packages
│   ├── config/
│   │   └── config.go              # Application config helpers
│   ├── logger/
│   │   └── logger.go              # Logging utilities
│   └── socks5/
│       └── socks5.go              # High-level SOCKS5 client logic
├── go.mod                         # Go module definition
├── go.sum                         # Go module checksums
└── LICENSE                        # Project license
```

## ⚡ Quick Start

1. **Clone** the repo:
   ```bash
   git clone https://github.com/Icannotcode0/LiteProxy.git
   cd LiteProxy
   ```
2. **Build** the binary:
   ```bash
   go build -o liteproxy ./cmd/liteproxy
   ```
3. **Run** as a SOCKS5 CONNECT proxy (default):
   ```bash
   ./liteproxy -mode socks5 -bind 0.0.0.0:1080
   ```

---

## 🛠️ Usage Examples

- **Curl via SOCKS5**:
  ```bash
  curl -x socks5h://127.0.0.1:1080 https://example.com
  ```
- **Go client script**:
  ```bash
  go run client.go -proxy 127.0.0.1:1080 -query cat -output ./images
  ```

---

## 📌 Current Status

> **SOCKS5 CONNECT** proudly implemented and battle-tested. All other protocol methods (BIND, UDP ASSOCIATE), authentication schemes, and HTTP proxy features remain on the roadmap.

Pull requests and stars are welcome—let’s build this tiny titan together! ⭐

---

## 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

