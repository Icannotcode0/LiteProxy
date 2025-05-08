package request

import (
	"fmt"
	"io"
	"net"

	protocol "github.com/Icannotcode0/LiteProxy/internal/common"
	auth "github.com/Icannotcode0/LiteProxy/internal/protocols/socks5/authetication"
	"github.com/sirupsen/logrus"
)

type Request struct {
	TcpConnect   net.Conn
	Bind         UDPCtx
	DstAddress   net.Addr
	AuthContent  []auth.Autheticator
	AuthPriority map[int]int
	Ctx          protocol.RequestCtx
}

type UDPCtx struct {
	BindConnection net.UDPConn
	BindAddr       net.UDPAddr
}

func (r *Request) HandShake() ([]byte, error) {

	verbuff := make([]byte, 1)
	if _, err := io.ReadFull(r.TcpConnect, verbuff); err != nil {
		logrus.Errorf("[LiteProxy] Cannot Read Version Number of Client: %v", err)
		return nil, err
	}

	if verbuff[0] != protocol.SOCKS5VER {
		logrus.Errorf("[LiteProxy] Incorrect SOCKS version, Expected %d, Found %d, Ending Session...", protocol.SOCKS5VER, verbuff[0])
	}

	nmethodBuff := make([]byte, 1)

	if _, err := io.ReadFull(r.TcpConnect, nmethodBuff); err != nil {

		logrus.Errorf("[LiteProxy] Cannot Read NMethod Number From Client: %v", err)
		return nil, err
	}

	methodBuff := make([]byte, nmethodBuff[0])

	if _, err := io.ReadFull(r.TcpConnect, methodBuff); err != nil {
		logrus.Errorf("[LiteProxy] Cannot Read Authetication Methods Number From Client: %v", err)
		return nil, err
	}

	return methodBuff, nil
}

func (r *Request) SelectAuthMethod(clientMethods []byte) (int, error) {

	var currentPriority int
	verify := -1
	for i := range len(clientMethods) {

		if _, ok := r.AuthPriority[int(clientMethods[i])]; ok {

			if currentPriority < r.AuthPriority[int(clientMethods[i])] {

				verify = int(clientMethods[i])
				currentPriority = r.AuthPriority[int(clientMethods[i])]
			}
		}
	}

	if verify == -1 {

		return verify, fmt.Errorf("no authetication methods are accepted")
	}

	return verify, nil
}

func (r *Request) ParseRequest() {

	verbuff := make([]byte, 1)
	if _, err := io.ReadFull(r.TcpConnect, verbuff); err != nil || verbuff[0] != protocol.SOCKS5VER {
		logrus.Errorf("[LiteProxy] Failed to Read Version Number of User Request: %v", err)
		return
	}

	cmdbuff := make([]byte, 1)
	if _, err := io.ReadFull(r.TcpConnect, cmdbuff); err != nil || (cmdbuff[0] != protocol.CMD_CONNECT && !r.Ctx.IsConnect) {

		logrus.Errorf("[LiteProxy] Failed to Read Command or BIND Command Refused due to No Previous CONNECT Session")
		return
	}

	//**TODO: REQUEST HANDLE LOGIC NEEDS RECONFIGURE**
	rsvbuff := make([]byte, 1)
	if _, err := io.ReadFull(r.TcpConnect, rsvbuff); err != nil || rsvbuff[0] != 0x00 {

		logrus.Errorf("[LiteProxy] Failed to Read the Reserved Bit or Reserved Bit is Non-Zero")
		return
	}
	// save address resolving for later
	/*
	   addressType := make([]byte, 1)
	   if _, err := io.ReadFull(r.TcpConnect, addressType); err != nil {

	   		logrus.Errorf("[LiteProxy] Failed to Read the Adderss Type: %v", err)
	   		return
	   	}
	*/
}
