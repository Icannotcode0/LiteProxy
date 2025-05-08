package internalsocks5

import (
	"errors"
	"net"
	"sync"

	protocol "github.com/Icannotcode0/LiteProxy/internal/common"
	listener "github.com/Icannotcode0/LiteProxy/internal/listener"
	auth "github.com/Icannotcode0/LiteProxy/internal/protocols/socks5/authetication"
	req "github.com/Icannotcode0/LiteProxy/internal/protocols/socks5/request"
	config "github.com/Icannotcode0/LiteProxy/pkg/config"

	"github.com/sirupsen/logrus"
)

type Socks5Server struct {
	Config      config.Socks5ServerConfig
	Listener    net.Listener
	ActiveConns sync.Map
	sem         chan struct{}
}

func NewSocks5Server(cfg config.Socks5ServerConfig) (*Socks5Server, error) {

	//generate a listener for the server
	Lisener, err := listener.GenerateListener(cfg.TLSEnable, cfg.ServerTLSCrt, cfg.ServerTLSKey, cfg.Port)
	if err != nil {
		logrus.Errorf("[LiteProxy] Cannot Initialize Listener: %v", err)
		return nil, err
	}
	// return the build server struct
	return &Socks5Server{Listener: Lisener, Config: cfg, ActiveConns: sync.Map{}}, nil

}

func (s *Socks5Server) ListenAndServe() error {

	//makes a buffered channel with the size of max connections of the server
	s.sem = make(chan struct{}, s.Config.MaxConns)

	logrus.Infof("[LiteProxy] SOCKS5 Server Starting With Port %d", s.Config.Port)

	// infinite loop, server always open
	for {

		clientConn, err := s.Listener.Accept()
		if err != nil {

			if errors.Is(err, net.ErrClosed) {
				logrus.Errorf("[LiteProxy] Listener Closed, Shutting Down Server...")
				return nil
			} else {
				logrus.Errorf("[LiteProxy] Cannot Establish Connection: %v", err)
				continue
			}
		}

		select {

		// manage all connections through a concurrency-save hashMap
		case s.sem <- struct{}{}:

			// relay the authetication configuration setup of the server to each request
			req := &req.Request{TcpConnect: clientConn, AuthContent: s.Config.AuthMethods, AuthPriority: s.Config.AuthPriority}
			_, loaded := s.ActiveConns.LoadOrStore(clientConn, req)
			if loaded {
				logrus.Errorf("[LiteProxy] Identical Connection From %v, Ending Connection...", clientConn.RemoteAddr().String())
				<-s.sem
				clientConn.Close()
			}

			go s.HandleConnections(req)

		default:

			logrus.Warnf("[LiteProxy] Connection Amount Limit Reached, Connection From %v Refused...", clientConn.RemoteAddr().String())
			clientConn.Close()
		}

	}
}

func (s *Socks5Server) HandleConnections(req *req.Request) {

	// clean-up function that is triggered at the end of each session or
	// an error return (shuts down the session when anything goes wrong according to the RFC file)
	defer func() {

		if req.TcpConnect != nil {
			req.TcpConnect.Close()
		}
		req.Bind.BindConnection.Close()
		s.ActiveConns.Delete(req.TcpConnect)
		<-s.sem
	}()

	methods, err := req.HandShake()
	if err != nil {
		logrus.Errorf("[LiteProxy] Failed to Negociate Authetication Methods with Client %s: %v", req.TcpConnect.RemoteAddr().String(), err)
	}

	chosenMethod, err := req.SelectAuthMethod(methods)
	logrus.Infof("[LiteProxy] Client %s Has Choose the Authetication Method, Method Code: %d", req.TcpConnect.RemoteAddr().String(), chosenMethod)

	if err != nil {

		logrus.Errorf("[LiteProxy] Authetication Negociation Failure: %v", err)
		var noAuth auth.NoAuthAccepted
		noAuth.AuthReply(req.TcpConnect, false)
		return
	}

	if chosenMethod == protocol.SOCKS5_UP {

		for i := range req.AuthContent {

			if _, ok := req.AuthContent[i].(auth.UserPassAuth); ok {
				pass, err := req.AuthContent[i].Autheticate(req.TcpConnect)
				if err != nil || !pass {

					logrus.Warnf("[LiteProxy] Client %s Failed to Autheticate Themselves, Ending Session...", req.TcpConnect.RemoteAddr().String())
					return
				} else {
					req.AuthContent[i].AuthReply(req.TcpConnect, true)
					break
				}
			}
		}
	} else if chosenMethod == protocol.SOCKS5_NOAUTH {
		var noauth auth.NoAuth
		noauth.AuthReply(req.TcpConnect, true)
	} else if chosenMethod == protocol.SOCKS5_DENIED {
		var denied auth.NoAuthAccepted
		denied.AuthReply(req.TcpConnect, false)
	}

	// authetication finished, parse out user's requests

	req.ParseRequest()

}
