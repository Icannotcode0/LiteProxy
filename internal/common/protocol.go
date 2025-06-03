package protocol

import "net"

// 常量定义，表示 SOCKS5 协议的各个部分
const (
	SOCKS5VER         = 0x05 // SOCKS5 Version
	CMD_CONNECT       = 0x01 // CONNECT Command
	CMD_BIND          = 0x02 // BIND Command
	CMD_UDP_ASSOCIATE = 0x03 // UDP ASSOCIATE
	ATYP_IPV4         = 0x01 // IPv4 Type Address
	ATYP_DOMAIN       = 0x03 // Domain Name Type Address
	ATYP_IPV6         = 0x04 // IPv6 Type Address
	STATUS_SUCCESS    = 0x00 // Successful Request
	STATUS_FAIL       = 0x01 // Failed Request
)

// auth opcodes
const (
	SOCKS5_NOAUTH = 0x00
	SOCKS5_GSSAPI = 0x01
	SOCKS5_UP     = 0x02
	SOCKS5_DENIED = 0xff
	AUTH_SUCCESS  = 0x00
	AUTH_FAILED   = 0xff
)

// Error Codes
const (
	STATUS_CMD_NOT_SUPPORTED  = 0x07
	STATUS_ATYP_NOT_SUPPORTED = 0x08
)

// Request Context Information

type RequestCtx struct {
	Version            uint8
	Command            uint8
	ATYP               uint8
	Addr               []byte
	Port               uint16
	ResolvedDstAddress net.Addr
	IsConnect          bool
}
