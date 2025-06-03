package request

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	protocol "github.com/Icannotcode0/LiteProxy/internal/common"
	auth "github.com/Icannotcode0/LiteProxy/internal/protocols/socks5/authetication"
	"github.com/sirupsen/logrus"
)

type Request struct {
	TcpConnect   net.Conn
	ConnectCtx   protocol.RequestCtx
	Bind         BindCtx
	AuthContent  []auth.Autheticator
	AuthPriority map[int]int
}

type BindCtx struct {
	BindConnection net.Conn
	BindAddr       net.Addr
	BindCtx        protocol.RequestCtx
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

func (r *Request) ParseRequest() (int, error) {

	verbuff := make([]byte, 1)
	if _, err := io.ReadFull(r.TcpConnect, verbuff); err != nil || verbuff[0] != protocol.SOCKS5VER {
		logrus.Errorf("[LiteProxy] Failed to Read Version Number of User Request: %v", err)
		return -1, err
	}
	logrus.Infof("Version Verified")

	cmdbuff := make([]byte, 1)
	if _, err := io.ReadFull(r.TcpConnect, cmdbuff); err != nil || (cmdbuff[0] != protocol.CMD_CONNECT && !r.ConnectCtx.IsConnect) {

		logrus.Errorf("[LiteProxy] Failed to Read Command or BIND Command Refused due to No Previous CONNECT Session")
		return -1, err
	}

	logrus.Infof("Cmd Code Verified: %v", cmdbuff[0])

	switch cmdbuff[0] {

	case protocol.CMD_CONNECT:

		if err := r.HandleConnect(); err != nil {
			return protocol.CMD_CONNECT, err
		}

	case protocol.CMD_BIND:

		r.HandleBind()

	case protocol.CMD_UDP_ASSOCIATE:

		r.HandleAssociate()
	default:

		logrus.Errorf("[LiteProxy] Unknown Command: %v, Ending Connection...", cmdbuff[0])
		return -1, fmt.Errorf("unkwon command code: %v", cmdbuff[0])

	}

	return 0, nil

}

func (r *Request) HandleConnect() error {

	rsvbuff := make([]byte, 1)
	if _, err := io.ReadFull(r.TcpConnect, rsvbuff); err != nil || rsvbuff[0] != 0x00 {

		logrus.Errorf("[LiteProxy] Failed to Read the Reserved Bit or Reserved Bit is Non-Zero")
		return fmt.Errorf("wrong reserve bit")
	}
	logrus.Infof("rsv verified")

	addressBuff := make([]byte, 1)
	if _, err := io.ReadFull(r.TcpConnect, addressBuff); err != nil || (addressBuff[0] != protocol.ATYP_DOMAIN && addressBuff[0] != protocol.ATYP_IPV4 && addressBuff[0] != protocol.ATYP_IPV6) {

		logrus.Errorf("[LiteProxy] Failed to Read Adress Type Bit or Invalid Address Type")

		if err == nil {
			return fmt.Errorf("invalid address type: %v", addressBuff[0])
		} else {
			return nil
		}
	}

	switch addressBuff[0] {

	case protocol.ATYP_IPV4:

		r.ConnectCtx.ATYP = protocol.ATYP_IPV4
		v4Buff := make([]byte, 4)
		if _, err := io.ReadFull(r.TcpConnect, v4Buff); err != nil {
			return err
		}
		r.ConnectCtx.Addr = v4Buff
		addr, err := net.ResolveIPAddr("ip4", string(v4Buff))
		if err != nil {
			return nil
		}
		r.ConnectCtx.ResolvedDstAddress = addr

		portBuff := make([]byte, 2)
		if _, err := io.ReadFull(r.TcpConnect, portBuff); err != nil {

			return err
		}
		r.ConnectCtx.Port = binary.BigEndian.Uint16(portBuff[:])

	case protocol.ATYP_IPV6:

		r.ConnectCtx.ATYP = protocol.ATYP_IPV6
		v6Buff := make([]byte, 16)
		if _, err := io.ReadFull(r.TcpConnect, v6Buff); err != nil {
			return err
		}
		r.ConnectCtx.Addr = v6Buff
		addr, err := net.ResolveIPAddr("ip6", string(v6Buff))
		if err != nil {
			return nil
		}
		r.ConnectCtx.ResolvedDstAddress = addr

		portBuff := make([]byte, 2)
		if _, err := io.ReadFull(r.TcpConnect, portBuff); err != nil {

			return err
		}
		r.ConnectCtx.Port = binary.BigEndian.Uint16(portBuff[:])

	case protocol.ATYP_DOMAIN:

		lenBuff := make([]byte, 1)
		if _, err := io.ReadFull(r.TcpConnect, lenBuff); err != nil {

			return err
		}
		domainBuff := make([]byte, lenBuff[0])
		if _, err := io.ReadFull(r.TcpConnect, domainBuff); err != nil {
			return err
		}

		r.ConnectCtx.Addr = domainBuff

		addr, err := net.ResolveIPAddr("ip", string(domainBuff))
		if err != nil {
			return nil
		}
		r.ConnectCtx.ResolvedDstAddress = addr

	}

	return nil
}

func (r *Request) HandleBind() error {

	return nil

}

func (r *Request) HandleAssociate() error {

	return nil

}
