package discover

import (
	"crypto/ecdsa"
	"errors"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/kardianos/govendor/migrate"
	"net"
	"sync"
	"time"
)

// Errors
var (
	errPacketToolSmall  = errors.New("too small")
	errBadHash          = errors.New("bad hash")
	errExpired          = errors.New("expired")
	errUnsolicitedReply = errors.New("unsolicited reply")
	errUnknownNode      = errors.New("unknown node")
	errTimeout          = errors.New("RPC timeout")
	errClockWarp        = errors.New("reply deadline too far in the future")
	errClosed           = errors.New("socket closed")
)

// Timeouts
const (
	respTimeout    = 500 * time.Millisecond
	expiration     = 20 * time.Second
	bondExpiration = 24 * time.Hour

	ntpFailureThreshold = 32               // 连接超时后检查NTP
	ntpWarningCooldown  = 10 * time.Minute // 重复NTP警告之前经过的最小时间
	driftThreshold      = 10 * time.Second // 允许的时间浮动
)

// RPC请求结构
type (
	ping struct {
		Version    uint
		From, To   rpcEndpoint
		Expiration uint64
		// 忽略其他字段(便于向前兼容)
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// pong是对ping的响应
	pong struct {
		// 这个字段应该与ping数据包的UDP地址镜像对应，这为发现外部地址提供了一种方法
		To rpcEndpoint

		ReplyTok   []byte // 包含了ping包的hash
		Expiration uint64 // 数据包失效的绝对时间戳
		// 忽略其他字段(便于向前兼容)
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// findnode 是对接近目标节点进行的查询
	findnode struct {
		Target     encPubkey
		Expiration uint64
		// 忽略其他字段(便于向前兼容)
		Rest []rlp.RawValue `rlp:"tail"`
	}
	// 回应findnode
	neighhbors struct {
		Nodes      []rpcNode
		Expiration uint64
		// 忽略其他字段(便于向前兼容)
		Rest []rlp.RawValue `rlp:"tail"`
	}

	rpcNode struct {
		IP  net.IP // 长度为4表示IPv4，16表示IPv6
		UDP uint16 // for discovery protocol
		TCP uint16 // for RLPx protocol
		ID  encPubkey
	}

	rpcEndpoint struct {
		IP  net.IP // 长度：4 --> IPv4  16 --> Ipv6
		UDP uint16 // for discovery protocol
		TCP uint16 // for RLPx protocol
	}
)

func makeEndpoint(addr *net.UDPAddr, tcpPort uint16) rpcEndpoint {
	ip := net.IP{}
	if ip4 := addr.IP.To4(); ip4 != nil {
		ip = ip4
	} else if ip6 := addr.IP.To16(); ip6 != nil {
		ip = ip6
	}
	return rpcEndpoint{IP: ip, UDP: uint16(addr.Port), TCP: tcpPort}
}

func (t *udp) nodeFromRPC(sender *net.UDPAddr, rn rpcNode) (*node, error) {
	if rn.UDP <= 1024 {
		return nil, errors.New("low port")
	}
	if err := netutil.CheckRelayIP(sender.IP, rn.IP); err != nil {
		return nil, err
	}
	if t.netrestrict != nil && !t.netrestrict.Contains(rn.IP) {
		return nil, errors.New("not contained in netrestrict whitelist")
	}
	key, err := decodePubkey(rn.ID)
	if err != nil {
		return nil, err
	}
	n := wrapNode(enode.NewV4(key, rn.IP, int(rn.TCP), int(rn.UDP)))
	err = n.ValidateComplete()
	return n, err
}

func nodeToRPC(n *node) rpcNode {
	var key ecdsa.PublicKey
	var ekey encPubkey
	if err := n.Load(*enode.Secp256k1(&key)); err == nil {
		ekey = encodePubkey(&key)
	}
	return rpcNode{ID: ekey, IP: n.IP(), UDP: uint16(n.UDP()), TCP: uint16(n.TCP())}
}

type packet interface {
	handle(t *udp, from *net.UDPAddr, fromKey encPubkey, mac []byte) error
	name() string
}

type conn interface {
	ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (n int, err error)
	Close() error
	LocalAddr() net.Addr
}

// udp实现了the discovery v4 UDP wire protocol
type udp struct {
	conn        conn
	netrestrict *netutil.Netlist
	priv        *ecdsa.PrivateKey
	loclNode    *enode.LocalNode
	db          *enode.DB
	tab         *Table
	wg          sync.WaitGroup

	addpending chan *pending
	gotreply   chan relpy
	closing    chan struct{}
}

// pending represents a pending reply

// 一些协议的实现希望发送不止一个响应包给findnode。通常，任何邻居包都不能与一个特定的findnode包相匹配

// 我们通过为每一个pending响应存储一个回调函数来处理这个问题。来自节点的包都被分配到该节点所有的回调函数
type pending struct {
	// 这些字段必须与响应中的字段相配
	from  enode.ID
	ptype byte

	// 请求必须完成的时间
	deadline time.Time

	// 当收到一个匹配的响应时调用callback。如果返回true
}
