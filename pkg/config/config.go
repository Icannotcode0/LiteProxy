package config

import (
	"time"
)

type Socks5ServerConfig struct {
	Port         int64         `json:"port"`
	TLSEnable    bool          `json:"tls_enable"`
	ReadTimeOut  time.Duration `json:"read_timeout"`
	WriteTimeOut time.Duration `json:"write_timeout"`
	ServerTLSCrt string        `json:"tls_certs"`
	ServerTLSKey string        `json:"tls_key"`
	MaxConns     int64         `json:"max_connections"`
}
