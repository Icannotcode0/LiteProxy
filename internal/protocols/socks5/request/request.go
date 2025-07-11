package request

import (
	"encoding/binary"
	"fmt"
	protocol "github.com/Icannotcode0/LiteProxy/internal/common"
	auth "github.com/Icannotcode0/LiteProxy/internal/protocols/socks5/authetication"
	"github.com/sirupsen/logrus"
	"io"
	"net"
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

	rsvBuff := make([]byte, 1)
	if _, err := io.ReadFull(r.TcpConnect, rsvBuff); err != nil || rsvBuff[0] != 0x00 {
		logrus.Errorf("[LiteProxy] Failed to Read the RSV Byte or RSV Byte Non-Zero: %v", rsvBuff)
		return fmt.Errorf("wrong reserve bit")
	}
	logrus.Infof("[LiteProxy] RSV Byte Passed")

	addressBuf := make([]byte, 1)
	if _, err := io.ReadFull(r.TcpConnect, addressBuf); err != nil {
		logrus.Errorf("[LiteProxy] Cannot Read Adress Type: %v", err)
		return err
	}
	atyp := addressBuf[0]
	if atyp != protocol.ATYP_IPV4 && atyp != protocol.ATYP_IPV6 && atyp != protocol.ATYP_DOMAIN {
		logrus.Errorf("[LiteProxy] Unsupported Address Type: %v", atyp)
		return fmt.Errorf("invalid address type: %v", atyp)
	}

	r.ConnectCtx.ATYP = atyp

	switch atyp {
	case protocol.ATYP_IPV4:

		v4Buf := make([]byte, 4)
		if _, err := io.ReadFull(r.TcpConnect, v4Buf); err != nil {
			logrus.Errorf("[LiteProxy] Failed to Read IPv4 Address: %v", err)
			return err
		}

		r.ConnectCtx.Addr = v4Buf

		ip4 := net.IP(v4Buf)
		addr4 := &net.IPAddr{IP: ip4}
		r.ConnectCtx.ResolvedDstAddress = addr4

		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(r.TcpConnect, portBuf); err != nil {
			logrus.Errorf("[LiteProxy] Failed to Read IPv4 Port: %v", err)
			return err
		}
		r.ConnectCtx.Port = int(binary.BigEndian.Uint16(portBuf))
		logrus.Infof("[LiteProxy] Target IPv4: %s:%d", ip4.String(), r.ConnectCtx.Port)

	case protocol.ATYP_IPV6:

		v6Buf := make([]byte, 16)
		if _, err := io.ReadFull(r.TcpConnect, v6Buf); err != nil {
			logrus.Errorf("[LiteProxy] Failed to Read IPv6 Address: %v", err)
			return err
		}
		r.ConnectCtx.Addr = v6Buf

		ip6 := net.IP(v6Buf)
		addr6 := &net.IPAddr{IP: ip6}
		r.ConnectCtx.ResolvedDstAddress = addr6

		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(r.TcpConnect, portBuf); err != nil {
			logrus.Errorf("[LiteProxy] Failed to Read IPv6 Address: %v", err)
			return err
		}
		r.ConnectCtx.Port = int(binary.BigEndian.Uint16(portBuf))
		logrus.Infof("[LiteProxy] Target IPv6: [%s]:%d", ip6.String(), r.ConnectCtx.Port)

	case protocol.ATYP_DOMAIN:

		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r.TcpConnect, lenBuf); err != nil {
			logrus.Errorf("[LiteProxy] Failed to Read Domain Name Length: %v", err)
			return err
		}
		domainLen := int(lenBuf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(r.TcpConnect, domainBuf); err != nil {
			logrus.Errorf("[LiteProxy] Failed to Read Domain Name: %v", err)
			return err
		}
		r.ConnectCtx.Addr = domainBuf
		domainStr := string(domainBuf)

		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(r.TcpConnect, portBuf); err != nil {
			logrus.Errorf("[LiteProxy] Failed to Read Domain Name Port: %v", err)
			return err
		}
		r.ConnectCtx.Port = int(binary.BigEndian.Uint16(portBuf))
		addrResolved, err := net.ResolveIPAddr("ip", domainStr)

		if err != nil {
			logrus.Warnf("[LiteProxy] Failed to Resolve Domain Name: %s, Err: %v", domainStr, err)
			return err
		} else {
			r.ConnectCtx.ResolvedDstAddress = addrResolved
		}
		logrus.Infof("[LiteProxy] Target Domain: %s:%d", domainStr, r.ConnectCtx.Port)
	}

	return nil
}

func (r *Request) HandleBind() error {

	return nil

}

func (r *Request) HandleAssociate() error {

	return nil

}

func (r *Request) SendReply(errorCode byte) {

	errorPackage := []byte{
		protocol.SOCKS5VER, // 0x05
		errorCode,          // 0x04, host unreachable
		0x00,               // RSV
		byte(r.ConnectCtx.ATYP),
	}
	if r.ConnectCtx.ATYP == protocol.ATYP_DOMAIN {
		errorPackage = append(errorPackage, byte(len(r.ConnectCtx.Addr)))
	}
	errorPackage = append(errorPackage, r.ConnectCtx.Addr...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(r.ConnectCtx.Port))
	errorPackage = append(errorPackage, portBuf...)

	if _, err := r.TcpConnect.Write(errorPackage); err != nil {

		logrus.Errorf("[LiteProxy] Error writing error to client: %w", err)
	}
}
