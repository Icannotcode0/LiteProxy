package listener

import (
	"crypto/tls"
	"fmt"
	"net"
)

func GenerateListener(enableTLS bool, crt string, key string, port int64) (net.Listener, error) {
	if enableTLS {

		cert, err := tls.LoadX509KeyPair(crt, key)
		if err != nil {
			return nil, err
		}
		tlsConfig := tls.Config{

			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		tlsListener, err := tls.Listen("tcp", fmt.Sprintf("[::]:%d", port), &tlsConfig)
		if err != nil {
			return nil, err
		}

		return tlsListener, nil

	} else {

		listener, err := net.Listen("tcp", fmt.Sprintf("[::]:%d", port))
		if err != nil {
			return nil, err
		}

		return listener, nil
	}

}
