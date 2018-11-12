package enr

import (
	"errors"
	"fmt"
)

// enr包支持"secp256k1-keccak"
// 节点记录的最大编码范围
const SizeLimit = 300

var (
	ErrInvalidSig     = errors.New("invalid signature on node record")
	errNotSorted      = errors.New("record key/value pairs are not sorted by key")
	errDuplicateKey   = errors.New("record contains duplicate key")
	errIncompletePair = errors.New("record contains incomplete k/v pair")
	errTooBig         = fmt.Errorf("record bigger than %d bytes", SizeLimit)
	errEncodeUnsigned = errors.New("can't encode unsigned record")
	errNotFound       = errors.New("no such key in record")
)

// IdentityScheme 可以验证记录签名以及得到节点地址
type IdentityScheme interface {
	Verify(r *Record, sig []byte) error
	NodeAddr(r *Record) []byte
}

// SchemeMap是一个已命名身份的注册表
type SchemeMap map[string]IdentityScheme

func (m SchemeMap) Verify(r *Record, sig []byte) error {
	s := m[r.IdentityScheme()]
	if s == nil {
		return ErrInvalidSig
	}
	return s.Verify(r, sig)
}

func (m SchemeMap) NodeAddr(r *Record) []byte {
	s := m[r.IdentityScheme()]
	if s == nil {
		return nil
	}
	return s.NodeAddr(r)
}

// Record代表了节点记录。零值是一个空记录
type Record struct {
	seq       uint64 // 序列号
	signature []byte // 签名
	raw       []byte // RLP 编码记录
	pairs     []pair // 所有key/value对的存储列表
}

// 获取序列号
func (r *Record) Seq() uint64 {
	return r.seq
}

// SetSeq更新记录的结果编号，这会使记录上的所有签名无效
// 一般情况下不建议调用SetSeq，因为设置任何已经签名的记录都会使序列号增加
func (r *Record) SetSeq(s uint64) {
	r.signature = nil
	r.raw = nil
	r.seq = s
}
