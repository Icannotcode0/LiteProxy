package main

import (
	//"github.com/Icannotcode0/LiteProxy/internal/config"
	"github.com/Icannotcode0/LiteProxy/internal/config"
	"github.com/Icannotcode0/LiteProxy/pkg/socks5"
	"time"

	//socks5 "github.com/Icannotcode0/LiteProxy/pkg/socks5"

	"github.com/sirupsen/logrus"
)

func newLogger() *logrus.Logger {
	logger := logrus.New() // create a new instance
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339Nano,
	})
	logger.SetLevel(logrus.InfoLevel)
	return logger
}

func main() {

	//classicSocks5Server := socks5.ClassicSock5Server()

	serverLogger := newLogger()

	serverConfig, err := config.LoadJSON("/Users/maxihan/LiteProxy/configs/socks5-server-config.json")
	if err != nil {
		serverLogger.Errorf("[LiteProxy] Unable to Load JSON file: %v", err)
		return
	}

	newSocks5Server, err := socks5.NewSocks5Server(serverConfig)
	if err != nil {
		serverLogger.Fatalf("[LiteProxy] Cannot Initialize New SOCKS5 Server: %v", err)
	}

	if err := newSocks5Server.ListenAndServe(); err != nil {

		serverLogger.Fatalf("[LiteProxy] Critical Error in SOCKS5 Server: %v", err)
	}

}
