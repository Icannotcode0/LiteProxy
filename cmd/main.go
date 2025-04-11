package main

import (
	"flag"
	"fmt"

	config "github.com/Icannotcode0/LiteProxy/pkg/liteproxy"
	"github.com/sirupsen/logrus"
)

func main() {

	fmt.Println()

	fmt.Printf("---------------------------------------- LiteProxy ----------------------------------------")
	fmt.Printf("\n")

	logrus.Info("[LiteProxy] Welcome to LiteProxy, a Compact and Secure Proxy Client/Server Tool")

	logrus.Info(`To begin with, please enter the name of the configuration file you have in this directory in the format of: 
	             
	            LiteProxy -config NAME_OF_CONFIG_FILE`)

	configFile := flag.String("config", "", "default configuration file")
	if *configFile != "" {

		config.LoadConfig(*configFile)
	} else {

		logrus.Errorf("[LiteProxy] Please Input the Name of the configuration file you are using")
	}
}
