package main

import (
	"log"

	socks5 "github.com/Icannotcode0/LiteProxy/pkg/socks5"
)

func main() {

	classicSocks5Server := socks5.ClassicSock5Server()

	if err := classicSocks5Server.ListenAndServe(); err != nil {

		log.Fatalf("[LiteProxy] Critical Error in SOCKS5 Server: %v", err)
	}

}
