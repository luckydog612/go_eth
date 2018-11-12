package enr

import (
	"fmt"
	"github.com/ethereum/go-ethereum/rlp"
	"io"
	"net"
)

// Entity 被已知的节点记录实体实现

// 为了定义包含节点记录的实体，创建一个新的Go类型
// 如果需要对值进行额外检查，该类型还需要实现rlp.Decoder
type Entity interface {
	// 获取记录对应的key
	ENRKey() string
}

type generic struct {
	key   string
	value interface{}
}

func (g generic) ENRKey() string {
	return g.key
}

func (g generic) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, g.value)
}

func (g generic) DecodeRLP(s *rlp.Stream) error {
	return s.Decode(g.value)
}

// WithEntry包含了一个key对应的所有value，它可用于设置和加载记录中的任意值
// 值v必须是rlp所支持的。如果WithEntry和Load一起使用，该值必须是指针类型
func WithEntry(k string, v interface{}) Entity {
	return &generic{key: k, value: v}
}

// TCP 是存储节点TCP端口的键“tcp"
type TCP uint16

func (v TCP) ENRKey() string {
	return "tcp"
}

// UDP 是存储节点UDP端口的键“udp”
type UDP uint16

func (v UDP) ENRKey() string {
	return "udp"
}

// ID 是存储身份格式名字的键“id”
type ID string

const IDv4 = ID("v4") //默认的id格式

func (v ID) ENRKey() string {
	return "id"
}

// IP 是存储节点IP地址的键“ip”
type IP net.IP

func (v IP) ENRKey() string {
	return "ip"
}

// EncodeRLP 实现了rlp.Encoder
func (v IP) EncodeRLP(w io.Writer) error {
	if ip4 := net.IP(v).To4(); ip4 != nil {
		return rlp.Encode(w, ip4)
	}
	return rlp.Encode(w, net.IP(v))
}

// DecodeRLP 实现了rlp.Decoder
func (v *IP) DecodeRLP(s *rlp.Stream) error {
	if err := s.Decode((*net.IP)(v)); err != nil {
		return err
	}
	if len(*v) != 4 && len(*v) != 16 {
		return fmt.Errorf("invalid IP address, want 4 or 16 bytes: %v", *v)
	}
	return nil
}

// KeyError 是与key相关的错误
type KeyError struct {
	Key string
	Err error
}

// Error 实现了error
func (err *KeyError) Error() string {
	if err.Err == errNotFound {
		return fmt.Sprintf("missing ENR key %q", err.Key)
	}
	return fmt.Sprintf("ENR key %q: %v", err.Key, err.Err)
}

func IsNotFound(err error) bool {
	kerr, ok := err.(*KeyError)
	return ok && kerr.Err == errNotFound
}
