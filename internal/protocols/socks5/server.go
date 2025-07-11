package internalsocks5

import (
	"errors"
	"fmt"
	protocol "github.com/Icannotcode0/LiteProxy/internal/common"
	listener "github.com/Icannotcode0/LiteProxy/internal/listener"
	auth "github.com/Icannotcode0/LiteProxy/internal/protocols/socks5/authetication"
	req "github.com/Icannotcode0/LiteProxy/internal/protocols/socks5/request"
	relay "github.com/Icannotcode0/LiteProxy/internal/proxy"
	config "github.com/Icannotcode0/LiteProxy/pkg/config"
	"github.com/sirupsen/logrus"
	"io"
	"net"
	"sync"
	"time"
)

type Socks5Server struct {
	Config      config.Socks5ServerConfig
	Listener    net.Listener
	ActiveConns sync.Map
	sem         chan struct{}
}

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

func NewSocks5Server(cfg config.Socks5ServerConfig) (*Socks5Server, error) {

	configLogger := newLogger()
	//generate a listener for the server
	Lisener, err := listener.GenerateListener(cfg.TLSEnable, cfg.ServerTLSCrt, cfg.ServerTLSKey, cfg.Port)
	if err != nil {
		configLogger.Errorf("[LiteProxy] Cannot Initialize Listener: %v", err)
		return nil, err
	}
	// return the build server struct
	return &Socks5Server{Listener: Lisener, Config: cfg, ActiveConns: sync.Map{}}, nil

}

func (s *Socks5Server) ListenAndServe() error {

	serverLogger := newLogger()
	//makes a buffered channel with the size of max connections of the server
	s.sem = make(chan struct{}, s.Config.MaxConns)
	serverLogger.Infof("[LiteProxy] SOCKS5 Server Starting With Port %d", s.Config.Port)

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
			go func() {

				if err := s.HandleConnections(req); err != nil {
					serverLogger.Errorf("[LiteProxy] Cannot HandleConnections: %v", err)
					return
				}
			}()

		default:
			logrus.Warnf("[LiteProxy] Connection Amount Limit Reached, Connection From %v Refused...", clientConn.RemoteAddr().String())
			clientConn.Close()
		}

	}
}

func (s *Socks5Server) HandleConnections(req *req.Request) error {

	// clean-up function that is triggered at the end of each session or
	// an error return (shuts down the session when anything goes wrong according to the RFC file)
	logrus.Infof("[LiteProxy] Client %s is Connected to the Server Via TCP Connection", req.TcpConnect.RemoteAddr().String())
	defer func() {

		if req.TcpConnect != nil {
			req.TcpConnect.Close()
		}
		if req.Bind.BindConnection != nil {
			req.Bind.BindConnection.Close()
		}
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
		return err
	}

	if chosenMethod == protocol.SOCKS5_UP {
		for i := range req.AuthContent {
			if _, ok := req.AuthContent[i].(auth.UserPassAuth); ok {
				pass, err := req.AuthContent[i].Autheticate(req.TcpConnect)
				if err != nil || !pass {

					logrus.Warnf("[LiteProxy] Client %s Failed to Autheticate Themselves, Ending Session...", req.TcpConnect.RemoteAddr().String())
					return err
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

	// cycle the TCP session with each client, terminate until client ends connections or an error occurs
	for {
		cmd, err := req.ParseRequest()
		if err != nil || cmd == -1 {
			logrus.Errorf("[LiteProxy] Unable to Process Request due to Error: %v", err)
			logrus.Errorf("[LiteProxy] Ending Session With Client %s...", req.TcpConnect.RemoteAddr().String())
			return err
		}

		logrus.Infof("[LiteProxy] Client Requested %d Command", cmd)
		// obtained all info regarding the target server and the type of request from client, log it now:
		logrus.Infof("[LiteProxy] Client Wishes to Connect to Address %s using Port %d", string(req.ConnectCtx.Addr), req.ConnectCtx.Port)

		// here begins the bidirectional traffic
		targetConn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", string(req.ConnectCtx.Addr), req.ConnectCtx.Port))
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				logrus.Errorf("[LiteProxy] Client %s Connection Closed", req.TcpConnect.RemoteAddr().String())
			} else if errors.Is(err, net.ErrWriteToConnected) {
				logrus.Errorf("[LiteProxy] Client %s Connection Failed", req.TcpConnect.RemoteAddr().String())
			}

			req.SendReply(0x04)
			return err
		}

		req.SendReply(0x00)

		if err := relay.RelyTraffic(targetConn, req.TcpConnect); err != nil {

			if errors.Is(err, net.ErrClosed) {
				logrus.Errorf("[LiteProxy] Client %s Connection Closed", req.TcpConnect.RemoteAddr().String())
			} else if errors.Is(err, net.ErrWriteToConnected) {
				logrus.Errorf("[LiteProxy] Client %s Connection Failed", req.TcpConnect.RemoteAddr().String())
			} else if errors.Is(err, io.EOF) {
				logrus.Errorf("[LiteProxy] Client %s Connection Closed: EOF", req.TcpConnect.RemoteAddr().String())
			}
			return err
		}
		continue
	}

	return nil
}
