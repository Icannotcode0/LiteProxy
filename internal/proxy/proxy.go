package proxy

import (
	"net"
)

type TrafficRely interface {
	ServerClientRely(net.Addr, net.Addr) ([]byte, error)
	ServerTargetRely()
}

func ServerTargetRely(target net.Addr, user net.Addr)([]byte,error) {

}
