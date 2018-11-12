package enode

import "github.com/ethereum/go-ethereum/p2p/enr"

// Node代表了网络中的一个节点
type Node struct {
	r enr.Record
}
