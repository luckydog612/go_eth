package enr

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/rlp"
	"io"
	"sort"
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

// 记录中的key/value对
type pair struct {
	k string
	v rlp.RawValue
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

// Load 检索一个key/value对的值。所给的Entity必须是一个指针类型，并且会更新记录里对应的值
// 返回的是KeyError包装的error，你可以使用IsNotFound函数从丢失的keys中区分解码errors

/*
  @Author
  查询记录中是否已经存在
*/
func (r *Record) Load(e Entity) error {
	i := sort.Search(len(r.pairs), func(i int) bool {
		return r.pairs[i].k >= e.ENRKey()
	})
	if i < len(r.pairs) && r.pairs[i].k == e.ENRKey() {
		if err := rlp.DecodeBytes(r.pairs[i].v, e); err != nil {
			return &KeyError{Key: e.ENRKey(), Err: err}
		}
		return nil
	}
	return &KeyError{Key: e.ENRKey(), Err: errNotFound}
}

// Set 添加或者更新记录中的Entity
// 如果value不能被编码会引发panic。如果该记录已经签名，Set方法会使序列号增大，并且废弃原来的序列号
func (r *Record) Set(e Entity) {
	blob, err := rlp.EncodeToBytes(e)
	if err != nil {
		panic(fmt.Errorf("enr: can't encode %s: %v", e.ENRKey(), err))
	}
	r.invalidate()

	pairs := make([]pair, len(r.pairs))
	copy(pairs, r.pairs)
	i := sort.Search(len(pairs), func(i int) bool {
		return pairs[i].k >= e.ENRKey()
	})
	switch {
	case i < len(pairs) && pairs[i].k == e.ENRKey():
		// 元素出现在r.pairs[i]
		pairs[i].v = blob
	case i < len(r.pairs):
		// 将元素插入到第i个下标
		el := pair{e.ENRKey(), blob}
		pairs = append(pairs, pair{})
		copy(pairs[i+1:], pairs[i:])
		pairs[i] = el
	default:
		// 元素放置在r.pairs的队尾
		pairs = append(pairs, pair{e.ENRKey(), blob})
	}
}

func (r *Record) invalidate() {
	if r.signature != nil {
		r.seq++
	}
	r.signature = nil
	r.raw = nil
}

// EncodeRLP 实现了rlp.Encoder。如果记录未签名将会编码失败
func (r *Record) EncodeRLP(w io.Writer) error {
	if r.signature == nil {
		return errEncodeUnsigned
	}
	_, err := w.Write(r.raw)
	return err
}

// DecodeRLP 实现了rlp.Decoder. Decoding验证签名
func (r *Record) DecodeRLP(s *rlp.Stream) error {
	dec, raw, err := decodeRecord(s)
	if err != nil {
		return err
	}
	*r = dec
	r.raw = raw
	return nil
}

func decodeRecord(s *rlp.Stream) (dec Record, raw []byte, err error) {
	raw, err = s.Raw()
	if err != nil {
		return dec, raw, err
	}
	if len(raw) > SizeLimit {
		return dec, raw, errTooBig
	}

	// 解码RLP容器
	s = rlp.NewStream(bytes.NewReader(raw), 0)
	if _, err := s.List(); err != nil {
		return dec, raw, err
	}
	if err = s.Decode(&dec.signature); err != nil {
		return dec, raw, err
	}
	if err = s.Decode(&dec.seq); err != nil {
		return dec, raw, err
	}
	// 记录剩余的部分包含已存储的k/v
	var prevkey string
	for i := 0; ; i++ {
		var kv pair
		if err := s.Decode(&kv.k); err != nil {
			if err == rlp.EOL {
				break
			}
			return dec, raw, err
		}
		if err := s.Decode(&kv.v); err != nil {
			if err == rlp.EOL {
				return dec, raw, errIncompletePair
			}
			return dec, raw, err
		}
		if i > 0 {
			if kv.k == prevkey {
				return dec, raw, errDuplicateKey
			}
			if kv.k < prevkey {
				return dec, raw, errNotSorted
			}
		}
		dec.pairs = append(dec.pairs, kv)
		prevkey = kv.k
	}
	return dec, raw, s.ListEnd()
}

// IdentityScheme 获取记录的身份标识
func (r *Record) IdentityScheme() string {
	var id ID
	r.Load(&id)
	return string(id)
}

// VerifySignature 检查记录是否使用给定的身份编号签名
func (r *Record) VerifySignature(s IdentityScheme) error {
	return s.Verify(r, r.signature)
}

// SetSig 设置记录的签名
// 如果已编码的记录的长度超过限制或者该签名无效，就会返回error
// 也可以通过使用一个空的scheme和签名来明确地删除签名
// 如果scheme或者签名两者其中有一个为空（不包括两者都为空）就会引发panic
func (r *Record) SetSig(s IdentityScheme, sig []byte) error {
	switch {
	// 阻止存储无效数据
	case s == nil && sig != nil:
		panic("ner: invalid call to SetSig with non-nil signature but nil scheme")
	case s != nil && sig == nil:
		panic("enr: invalid call to SetSig with nil signature but non-nil scheme")
		// 验证我们是否有scheme
	case s != nil:
		if err := s.Verify(r, sig); err != nil {
			return err
		}
		raw, err := r.encode(sig)
		if err != nil {
			return err
		}
		r.signature, r.raw = sig, raw
		// 否则重置
	default:
		r.signature, r.raw = nil, nil
	}
	return nil
}

// AppendElements 将序列号和其他项添加到所给的slice中
func (r *Record) AppendElements(list []interface{}) []interface{} {
	list = append(list, r.seq)
	for _, p := range r.pairs {
		list = append(list, p.k, p.v)
	}
	return list
}

func (r *Record) encode(sig []byte) (raw []byte, err error) {
	list := make([]interface{}, 1, 2*len(r.pairs)+1)
	list[0] = sig
	list = r.AppendElements(list)
	if raw, err = rlp.EncodeToBytes(list); err != nil {
		return nil, err
	}
	if len(raw) > SizeLimit {
		return nil, errTooBig
	}
	return raw, nil
}
