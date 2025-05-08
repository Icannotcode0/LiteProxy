package socks5

import (
	"fmt"
	"net"
	"sync"
	"time"

	internalsocks5 "github.com/Icannotcode0/LiteProxy/internal/protocols/socks5"
	auth "github.com/Icannotcode0/LiteProxy/internal/protocols/socks5/authetication"
	config "github.com/Icannotcode0/LiteProxy/pkg/config"
	"github.com/sirupsen/logrus"
)

// interface for socks5 server
type Server interface {
	ListenAndServe() error
	ShutDown()
}

// generates a SOCKS5 server with simplest configuration
func ClassicSock5Server() *internalsocks5.Socks5Server {

	classicConfig := config.Socks5ServerConfig{

		Port:         1080,
		TLSEnable:    true,
		ReadTimeOut:  5 * time.Second,
		WriteTimeOut: 5 * time.Second,
		ServerTLSCrt: "server.crt",
		ServerTLSKey: "server.key",
		MaxConns:     100,
		AuthPriority: map[int]int{
			0x00: 300,
			0x01: 200,
			0x02: 200,
		},
		AuthMethods: []auth.Autheticator{auth.UserPassAuth{

			Vault: map[string]string{"tester": "password0", "admin": "password1", "mock_trial": "password2"},
		}, auth.NoAuthAccepted{}, auth.NoAuth{}},
	}

	classicListener, err := net.Listen("tcp", fmt.Sprintf("[::]:%d", 1080))

	if err != nil {
		logrus.Errorf("[LiteProxy] Cannot Initialize Listener: %v", err)
		return nil
	}

	return &internalsocks5.Socks5Server{Config: classicConfig, Listener: classicListener, ActiveConns: sync.Map{}}
}

func NewSocks5Server(cfg config.Socks5ServerConfig) (*internalsocks5.Socks5Server, error) {

	newServer, err := internalsocks5.NewSocks5Server(cfg)
	if err != nil {
		logrus.Errorf("[LiteProxy] Cannot Generate New Server Instance: %v", err)
		return &internalsocks5.Socks5Server{}, err
	}

	return newServer, nil
}
