package discover

import (
	"crypto/ecdsa"
	"errors"
	"github.com/EducationEKT/EKT/crypto"
	"github.com/ethereum/go-ethereum/common/math"
	"go_eth/p2p/enode"
	"math/big"
	"time"
)

// node 代表网络中的一个主机
// The fields of Node may not be modified.
type node struct {
	enode.Node
	addedAt time.Time // 节点添加到路由表的时间
}

type encPubkey [64]byte

func encodePubkey(key *ecdsa.PublicKey) encPubkey {
	var e encPubkey
	math.ReadBits(key.X, e[:len(e)/2])
	math.ReadBits(key.Y, e[len(e)/2:])
	return e
}

func decodePubkey(e encPubkey) (*ecdsa.PublicKey, error) {
	p := &ecdsa.PublicKey{Curve: crypto.S256(), X: new(big.Int), Y: new(big.Int)}
	half := len(e) / 2
	p.X.SetBytes(e[:half])
	p.Y.SetBytes(e[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return nil, errors.New("invalid secp256k1 curve point")
	}
	return p, nil
}

// TODO:本文件未完成
