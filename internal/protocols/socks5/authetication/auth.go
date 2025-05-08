package authetication

import (
	"fmt"
	"io"
	"net"

	"github.com/sirupsen/logrus"

	protocol "github.com/Icannotcode0/LiteProxy/internal/common"
)

type Autheticator interface {
	Autheticate(net.Conn) (bool, error)
	AuthReply(net.Conn, bool) (bool, error)
}

type UserPassAuth struct {
	Vault map[string]string `json:"user_passwords"`
}

func (u UserPassAuth) Autheticate(clientConn net.Conn) (bool, error) {

	// rfc 1929 implementation
	verbuff := make([]byte, 1)
	if _, err := io.ReadFull(clientConn, verbuff); err != nil {

		logrus.Errorf("[LiteProxy] Failed to Read Sub-Negociation: %v", err)
		return false, err
	}
	if verbuff[0] != protocol.SOCKS5VER {

		u.AuthReply(clientConn, false)
		return false, fmt.Errorf("wrong version number")
	}

	//read the username and password from the client based on the pLen and uLen params
	uLenBuff := make([]byte, 1)
	if _, err := io.ReadFull(clientConn, uLenBuff); err != nil {
		logrus.Errorf("[LiteProxy] Failed to Read Sub-Negociation: %v", err)
		return false, err
	}

	usernameBuff := make([]byte, uLenBuff[0])
	if _, err := io.ReadFull(clientConn, usernameBuff); err != nil {
		logrus.Errorf("[LiteProxy] Failed to Read Sub-Negociation: %v", err)
		return false, err
	}

	pLenBuff := make([]byte, 1)
	if _, err := io.ReadFull(clientConn, pLenBuff); err != nil {
		logrus.Errorf("[LiteProxy] Failed to Read Sub-Negociation: %v", err)
		return false, err
	}
	passwordBuff := make([]byte, pLenBuff[0])
	if _, err := io.ReadFull(clientConn, passwordBuff); err != nil {
		logrus.Errorf("[LiteProxy] Failed to Read Sub-Negociation: %v", err)
		return false, err
	}

	ok := false

	for username, password := range u.Vault {

		if username == string(usernameBuff) {

			if password == string(passwordBuff) {

				ok = true
				break
			}
		}
	}

	if !ok {

		logrus.Warnf("[LiteProxy] Client Failed to Autheticate, Wrong Username/Password")
		return false, fmt.Errorf("incorrect username/password")
	} else {

		return true, nil
	}

}

func (u UserPassAuth) AuthReply(clientConn net.Conn, status bool) (bool, error) {

	if status {

		successPackage := []byte{protocol.SOCKS5VER, protocol.AUTH_SUCCESS}
		if _, err := clientConn.Write(successPackage); err != nil {
			return false, err
		}
		return true, nil

	} else {
		successPackage := []byte{protocol.SOCKS5VER, protocol.AUTH_FAILED}
		if _, err := clientConn.Write(successPackage); err != nil {
			return false, err
		}
		return false, nil
	}

}

type NoAuthAccepted struct {
}

func (n NoAuthAccepted) Autheticate(clientConn net.Conn) (bool, error) {

	return true, nil

}

func (n NoAuthAccepted) AuthReply(clientConn net.Conn, status bool) (bool, error) {

	noAcceptedPackage := []byte{protocol.SOCKS5VER, protocol.SOCKS5_DENIED}
	if _, err := clientConn.Write(noAcceptedPackage); err != nil {

		logrus.Errorf("[LiteProxy] Cannot Send Respon to Client: %v", err)
		return false, err
	}
	logrus.Infof("[LiteProxy] Error Message to Client Sent, Ending Session with Client...")

	return true, nil
}

type NoAuth struct {
}

func (o NoAuth) Autheticate(clientConn net.Conn) (bool, error) {

	return true, nil

}

func (o NoAuth) AuthReply(clientConn net.Conn, status bool) (bool, error) {

	successPackage := []byte{protocol.SOCKS5VER, protocol.AUTH_SUCCESS}

	if _, err := clientConn.Write(successPackage); err != nil {
		return false, nil
	}

	return true, nil
}
