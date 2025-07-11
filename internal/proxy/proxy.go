package proxy

import (
	"errors"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"sync"
)

func RelyTraffic(dist net.Conn, client net.Conn) error {

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(dist, client); err != nil {
			if errors.Is(err, io.EOF) {
				logrus.Errorf("[LiteProxy] Server %s Connection Closed: EOF", dist.RemoteAddr().String())
			}
		}

	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(client, dist); err != nil {
			if errors.Is(err, io.EOF) {
				logrus.Errorf("[LiteProxy] Client %s Connection Closed: EOF", client.RemoteAddr().String())
			}
		}
	}()

	wg.Wait()
	dist.Close()
	client.Close()
	return nil
}
