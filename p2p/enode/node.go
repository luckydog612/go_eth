package enode

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"go_eth/p2p/enr"
	"math/bits"
	"math/rand"
	"net"
	"strings"
)

// Node代表了网络中的一个节点
type Node struct {
	r  enr.Record
	id ID
}

// New 包装了一个节点记录，记录必须是有效的
func New(validSchemes enr.IdentityScheme, r *enr.Record) (*Node, error) {
	if err := r.VerifySignature(validSchemes); err != nil {
		return nil, err
	}
	node := &Node{r: *r}
	if n := copy(node.id[:], validSchemes.NodeAddr(&node.r)); n != len(ID{}) {
		return nil, fmt.Errorf("invalid node ID length %d, need %d", n, len(ID{}))
	}
	return node, nil
}

// ID 返回节点的id
func (n *Node) ID() ID {
	return n.id
}

// Seq 返回序列号
func (n *Node) Seq() uint64 {
	return n.r.Seq()
}

// Incomplete 当节点没有IP地址时返回true
func (n *Node) Incomplete() bool {
	return n.IP() == nil
}

// Load 从记录中获取entry
func (n *Node) Load(k enr.Entry) error {
	return n.r.Load(k)
}

// 获取节点的IP地址
func (n *Node) IP() net.IP {
	var ip net.IP
	n.Load((*enr.IP)(&ip))
	return ip
}

// 获取节点的UDP端口
func (n *Node) UDP() int {
	var port enr.UDP
	n.Load(&port)
	return int(port)
}

// 获取TCP端口
func (n *Node) TCP() int {
	var port enr.TCP
	n.Load(&port)
	return int(port)
}

// 如果存在，Pubkey返回节点的secp256k1公钥
func (n *Node) Pubkey() *ecdsa.PublicKey {
	var key ecdsa.PublicKey
	if n.Load((*Secp256k1)(&key)) != nil {
		return nil
	}
	return &key
}

// Record 返回节点的记录。返回的值是一个副本并且有可能被调用者修改
func (n *Node) Record() *enr.Record {
	cpy := n.r
	return &cpy
}

// 验证节点是否有效且完整
func (n *Node) ValidateComplete() error {
	// 验证是否有IP地址
	if n.Incomplete() {
		return errors.New("incomplete node")
	}
	// 验证是否有UDP端口
	if n.UDP() == 0 {
		return errors.New("missing UDP port")
	}
	ip := n.IP()
	if ip.IsMulticast() || ip.IsUnspecified() {
		return errors.New("invalid IP (multicast/unspecified)")
	}
	// 验证节点的key（是否在曲线上）
	var key Secp256k1
	return n.Load(&key)
}

// Node的表示形式是一个URL
// 描述格式请参照ParseNode
func (n *Node) String() string {
	return n.v4URL()
}

// MarshalText implements encoding.TextMarshaler.
func (n *Node) MarshalText() ([]byte, error) {
	return []byte(n.v4URL()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (n *Node) UnmarshalText(text []byte) error {
	dec, err := ParseV4(string(text))
	if err == nil {
		*n = *dec
	}
	return err
}

// ID 是每个节点的唯一身份
type ID [32]byte

// Bytes 返回ID的字节切片表示
func (n ID) Butes() []byte {
	return n[:]
}

// ID 打印输出十六进制数
func (n ID) String() string {
	return fmt.Sprintf("%x", n[:])
}

// ID 的Go语法表示是对HexID的调用
func (n ID) GoString() string {
	return fmt.Sprintf("enode.HexID(\"%x\")", n[:])
}

// 为终端日志返回缩短的十六进制的字符串
func (n ID) TerminalString() string {
	return hex.EncodeToString(n[:8])
}

// MarshalText implements the encoding.TextMarshaler interface.
func (n ID) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(n[:])), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (n *ID) UnmarshalText(text []byte) error {
	id, err := parseID(string(text))
	if err != nil {
		return err
	}
	*n = id
	return nil
}

// HexID将十六进制字符串转为ID
// 字符串可能含有0x前缀
// 如果字符串不是有效的ID会引发panic
func HexID(in string) ID {
	id, err := parseID(in)
	if err != nil {
		panic(err)
	}
	return id
}

// 将字符串转化为ID
func parseID(in string) (ID, error) {
	var id ID
	b, err := hex.DecodeString(strings.TrimPrefix(in, "0x"))
	if err != nil {
		return id, err
	} else if len(b) != len(id) {
		return id, fmt.Errorf("wrong length, want %d hex chars", len(id)*2)
	}
	copy(id[:], b)
	return id, nil
}

// DistCmp 分别比较a到target和b到target的距离
// 返回值    情况
//   -1     a比较近
//    1     b比较近
//    0     距离相等
func DistCmp(target, a, b ID) int {
	for i := range target {
		da := a[i] ^ target[i]
		db := b[i] ^ target[i]
		if da > db {
			return 1
		} else if da < db {
			return -1
		}
	}
	return 0
}

// LogDist 返回a和b的对数距离 log2(a^b)
func LogDist(a, b ID) int {
	lz := 0
	for i := range a {
		x := a[i] ^ b[i]
		if x == 0 {
			lz += 8
		} else {
			// LeadingZeros8 计算x中前导零的位数 x==0时返回8
			lz += bits.LeadingZeros8(x)
			break
		}
	}
	return len(a)*8 - lz
}

// RandomID 返回一个类似logdist(a,b)==n随机的ID b
func RandomID(a ID, n int) (b ID) {
	if n == 0 {
		return a
	}
	// 在位置n处反转bit 填充随机bits的其余位
	b = a
	pos := len(a) - n/8 - 1
	bit := byte(0x01) << (byte(n%8) - 1)
	if bit == 0 {
		pos++
		bit = 0x80
	}
	b[pos] = a[pos]&^bit | ^a[pos]&bit // TODO: randomize end bits
	for i := pos + 1; i < len(a); i++ {
		b[i] = byte(rand.Intn(255))
	}
	return b
}
