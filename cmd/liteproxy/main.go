package main

import (
	//"github.com/Icannotcode0/LiteProxy/internal/config"
	"github.com/Icannotcode0/LiteProxy/internal/config"
	"github.com/Icannotcode0/LiteProxy/pkg/socks5"

	//socks5 "github.com/Icannotcode0/LiteProxy/pkg/socks5"

	"github.com/sirupsen/logrus"
)

func main() {

	//classicSocks5Server := socks5.ClassicSock5Server()

	serverConfig, err := config.LoadJSON("/Users/maxihan/Desktop/LiteProxy/configs/socks5-server-config.json")
	if err != nil {
		logrus.Errorf("[LiteProxy] Unable to Load JSON file: %v", err)
		return
	}

	newSocks5Server, err := socks5.NewSocks5Server(serverConfig)
	if err != nil {
		logrus.Fatalf("[LiteProxy] Cannot Initialize New SOCKS5 Server: %v", err)
	}

	if err := newSocks5Server.ListenAndServe(); err != nil {

		logrus.Fatalf("[LiteProxy] Critical Error in SOCKS5 Server: %v", err)
	}

}
