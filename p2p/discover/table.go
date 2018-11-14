package discover

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/netutil"
	"go_eth/p2p/enode"
	mrand "math/rand"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	alpha           = 3  // Kademlia concurrency factor
	bucketSize      = 16 // Kademlia 存储桶的大小
	maxReplacements = 10 // 每个桶更换清单的大小

	// 我们存储距离超过1/15的节点，因为我们不可能遇到更接近的节点
	hashBits          = len(common.Hash{}) * 8
	nBuckets          = hashBits / 15       // 桶的数量
	bucketMinDistance = hashBits - nBuckets // 记录最近的桶的距离

	// IP 地址限制
	bucketIPLimit, bucketSubnet = 2, 24 // at most 2 addresses from the same /24
	tableIPLimit, tableSubnet   = 10, 24

	maxFindnodeFailures = 5 // 超过此限制的节点将被丢弃
	refreshInterval     = 30 * time.Minute
	revalidateInterval  = 10 * time.Second
	copyNodesInterval   = 30 * time.Second
	seedMinTableTime    = 5 * time.Minute
	seedCount           = 30
	seedMaxAge          = 5 * 24 * time.Hour
)

type Table struct {
	mutex   sync.Mutex        // protects buckets, bucket content, nursery, rand
	buckets [nBuckets]*bucket // 已知节点的距离索引
	nursery []*node           // 引导节点
	rand    *mrand.Rand       // 随机源，定期重新生成
	ips     netutil.DistinctNetSet

	db         *enode.DB // 已知节点的数据库
	net        transport
	refreshReq chan chan struct{}
	initDone   chan struct{}
	closeReq   chan struct{}
	closed     chan struct{}

	nodeAddedHook func(*node) // for testing
}

// transport被UDPtransport实现
// 因为它是一个接口，因此我们不需要打开大量的UDP套接字且不生成私钥的情况下进行测试
type transport interface {
	self() *enode.Node
	ping(enode.ID, *net.UDPAddr) error
	findnode(toid enode.ID, addr *net.UDPAddr, target encPubkey) ([]*node, error)
	close()
}

// bucket包含了节点，按照活跃度排序
// 最近活跃的entry是所有entry(entries)中第一个元素
type bucket struct {
	entries      []*node // 实时entries，根据上次联系的时间排序
	replacements []*node // recently seen nodes to be used if revalidation fails
	ips          netutil.DistinctNetSet
}

func newTable(t transport, db *enode.DB, bootnodes []*enode.Node) (*Table, error) {
	tab := &Table{
		net:        t,
		db:         db,
		refreshReq: make(chan chan struct{}),
		initDone:   make(chan struct{}),
		closeReq:   make(chan struct{}),
		closed:     make(chan struct{}),
		rand:       mrand.New(mrand.NewSource(0)),
		ips:        netutil.DistinctNetSet{Subnet: tableSubnet, Limit: tableIPLimit},
	}
	if err := tab.setFallbackNodes(bootnodes); err != nil {
		return nil, err
	}
	for i := range tab.buckets {
		tab.buckets[i] = &bucket{
			ips: netutil.DistinctNetSet{Subnet: bucketSubnet, Limit: tableIPLimit},
		}
	}
	tab.seedRand()
	tab.loadSeedNodes()

	go tab.loop()
	return tab, nil
}

func (tab *Table) self() *enode.Node {
	return tab.net.self()
}

func (tab *Table) seedRand() {
	var b [8]byte
	crand.Read(b[:])

	tab.mutex.Lock()
	tab.rand.Seed(int64(binary.BigEndian.Uint64(b[:])))
	tab.mutex.Unlock()
}

// ReadRandomNodes 从路由表中获取随机的节点填充到所给的切片中
// 对于单个调用保证结果十唯一的，没有节点会出现第二次
func (tab *Table) ReadRandomNodes(buf []*enode.Node) (n int) {
	if !tab.isInitDone() {
		return 0
	}
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	// 寻找所有非空的桶存放在一个全新的切片中
	var buckets [][]*node
	for _, b := range &tab.buckets {
		if len(b.entries) > 0 {
			buckets = append(buckets, b.entries)
		}
	}
	if len(buckets) == 0 {
		return 0
	}
	// 重组buckets
	for i := len(buckets) - 1; i > 0; i-- {
		j := tab.rand.Intn(len(buckets))
		buckets[i], buckets[j] = buckets[j], buckets[i]
	}
	// 将每个桶的首部移进buf，移除空的buckets
	var i, j int
	for ; i < len(buf); i, j = i+1, (j+1)%len(buckets) {
		b := buckets[j]
		buf[i] = unwrapNode(b[0])
		buckets[j] = b[1:]
		if len(b) == 1 {
			buckets = append(buckets[:j], buckets[j+1:]...)
		}
		if len(buckets) == 0 {
			break
		}
	}
	return i + 1
}

// 终止网络监听，刷新节点数据库
func (tab *Table) Close() {
	if tab.net != nil {
		tab.net.close()
	}

	select {
	case <-tab.closed:
		// 已经关闭
	case tab.closeReq <- struct{}{}:
		<-tab.closed // 等待refreshLoop结束
	}
}

// setFallbackNodes设置初始联系点
// 如果路由表是空的且数据库中没有已知节点，这些节点将会被用于连接网络
func (tab *Table) setFallbackNodes(nodes []*enode.Node) error {
	for _, n := range nodes {
		if err := n.ValidateComplete(); err != nil {
			return fmt.Errorf("bad bootstrap node %q: %v", n, err)
		}
	}
	tab.nursery = wrapNodes(nodes)
	return nil
}

// isInitDone 路由表的种子初始化是否已经完成
func (tab *Table) isInitDone() bool {
	select {
	case <-tab.initDone:
		return true
	default:
		return false
	}
}

// Resolve 根据所给ID搜索特定的节点
// 如果找不到返回空
func (tab *Table) Resolve(n *enode.Node) *enode.Node {
	// 如果节点存在于本地路由表中，则不需要与网络交互
	hash := n.ID()
	tab.mutex.Lock()
	cl := tab.closest(hash, 1)
	tab.mutex.Unlock()
	if len(cl.entries) > 0 && cl.entries[0].ID() == hash {
		return unwrapNode(cl.entries[0])
	}
	// 否则，在网络中查找
	result := tab.lookup(encodePubkey(n.Pubkey()), true)
	for _, n := range result {
		if n.ID() == hash {
			return unwrapNode(n)
		}
	}
	return nil
}

// 在网络中寻找随机节点
func (tab *Table) LookupRandom() []*enode.Node {
	var target encPubkey
	crand.Read(target[:])
	return unwrapNodes(tab.lookup(target, true))
}

// 在网络中搜索与目标节点最接近的节点
// 在每次迭代中，都会查找到更接近于目标的节点。
// 目标节点不一定是真实存在的
func (tab *Table) lookup(targetKey encPubkey, refreshIfEmpty bool) []*node {
	var (
		target         = enode.ID(crypto.Keccak256Hash(targetKey[:]))
		asked          = make(map[enode.ID]bool)
		seen           = make(map[enode.ID]bool)
		reply          = make(chan []*node, alpha)
		pendingQueries = 0
		result         *nodesByDistance
	)
	// 如果我们查到了自己，就无需进一步查找
	// 在实际场景下，这种情况不易发生
	asked[tab.self().ID()] = true

	for {
		tab.mutex.Lock()
		// 生成初始化结果集
		result = tab.closest(target, bucketSize)
		tab.mutex.Unlock()
		if len(result.entries) > 0 || !refreshIfEmpty {
			break
		}
		// 结果集是空的，所有的节点将被废弃，然后刷新
		// 实际上我们要等刷新完成。 最早的一次查找将会遇到这种情况并且会运营引导逻辑
		<-tab.refresh()
		refreshIfEmpty = false
	}

	for {
		// 询问我们还没查找的最接近的节点
		for i := 0; i < len(result.entries) && pendingQueries < alpha; i++ {
			n := result.entries[i]
			if !asked[n.ID()] {
				asked[n.ID()] = true
				pendingQueries++
				go tab.findnode(n, targetKey, reply)
			}
		}
		if pendingQueries == 0 {
			// 已经询问完最接近的节点，停止查找
			break
		}
		// 等待下一次回应
		for _, n := range <-reply {
			if n != nil && !seen[n.ID()] {
				seen[n.ID()] = true
				result.push(n, bucketSize)
			}
		}
		pendingQueries--
	}
	return result.entries
}

func (tab *Table) findnode(n *node, targetKey encPubkey, reply chan<- []*node) {
	fails := tab.db.FindFails(n.ID())
	r, err := tab.net.findnode(n.ID(), n.addr(), targetKey)
	if err != nil || len(r) == 0 {
		fails++
		tab.db.UpdateFindFails(n.ID(), fails)
		log.Trace("Findnode failed", "id", n.ID(), "failcount", fails, "err", err)
		if fails >= maxFindnodeFailures {
			log.Trace("Too many findnode failures, dropping", "id", n.ID(), "failcount", fails)
			tab.delete(n)
		}
	} else if fails > 0 {
		tab.db.UpdateFindFails(n.ID(), fails-1)
	}

	// 尽可能多的记录更多的节点。一些节点可能已经不再活跃，我们将在再次验证时将这些节点删除
	for _, n := range r {
		tab.add(n)
	}
	reply <- r
}

func (tab *Table) refresh() <-chan struct{} {
	done := make(chan struct{})
	select {
	case tab.refreshReq <- done:
	case <-tab.closed:
		close(done)
	}
	return done

}

// 有规律的刷新，进行重新验证和关闭坐标
func (tab *Table) loop() {
	var (
		revalidate     = time.NewTimer(tab.nextRevalidateTime())
		refresh        = time.NewTicker(refreshInterval)
		copyNodes      = time.NewTicker(copyNodesInterval)
		refreshDone    = make(chan struct{})           // where doRefresh reports completion
		revalidateDone chan struct{}                   // where doRevalidate reports completion
		waiting        = []chan struct{}{tab.initDone} // holds waiting callers while doRefresh runs
	)
	defer refresh.Stop()
	defer revalidate.Stop()
	defer copyNodes.Stop()

	// 开始初始化刷新
	go tab.doRefresh(refreshDone)

loop:
	for {
		select {
		case <-refresh.C:
			tab.seedRand()
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				go tab.doRefresh(refreshDone)
			}
		case req := <-tab.refreshReq:
			waiting = append(waiting, req)
			if refreshDone == nil {
				refreshDone = make(chan struct{})
				go tab.doRefresh(refreshDone)
			}
		case <-refreshDone:
			for _, ch := range waiting {
				close(ch)
			}
			waiting, refreshDone = nil, nil
		case <-revalidate.C:
			revalidateDone = make(chan struct{})
			go tab.doRevalidate(revalidateDone)
		case <-revalidateDone:
			revalidate.Reset(tab.nextRevalidateTime())
			revalidateDone = nil
		case <-copyNodes.C:
			go tab.copyLiveNodes()
		case <-tab.closeReq:
			break loop
		}
	}
	if refreshDone != nil {
		<-refreshDone
	}
	for _, ch := range waiting {
		close(ch)
	}
	if revalidateDone != nil {
		<-revalidateDone
	}
	close(tab.closed)
}

// 循环搜索随机目标来保持桶处于满的状态
// 如果路由表为空，则插入种子节点(初始化引导或者丢弃有缺陷的节点)
func (tab *Table) doRefresh(done chan struct{}) {
	defer close(done)

	// 从数据库中获取节点并插入
	// 可能会产生以前看到过的仍然活跃的节点
	tab.loadSeedNodes()

	// 运行自查找以发现新的邻居节点
	// 如果我们拥有一个secp256k1身份，我们只能这样做
	var key ecdsa.PublicKey
	if err := tab.self().Load((*enode.Secp256k1)(&key)); err == nil {
		tab.lookup(encodePubkey(&key), false)
	}

	// Kademlia白皮书强调存储桶的刷新应该在最近最少使用的存储桶中执行查找
	// 我们不能固守这一点，因为findnode的目标是一个512位的值(不是散列大小)，
	// 并且不容易生成属于所选存储通的sha3原像
	// 我们使用随机目标做一些查找
	for i := 0; i < 3; i++ {
		var target encPubkey
		crand.Read(target[:])
		tab.lookup(target, false)
	}
}

func (tab *Table) loadSeedNodes() {
	seeds := wrapNodes(tab.db.QuerySeeds(seedCount, seedMaxAge))
	seeds = append(seeds, tab.nursery...)
	for i := range seeds {
		seed := seeds[i]
		age := log.Lazy{Fn: func() interface{} { return time.Since(tab.db.LastPingReceived(seed.ID())) }}
		log.Debug("Found seed node in database", "id", seed.ID(), "addr", seed.addr(), "age", age)
		tab.add(seed)
	}
}

// doRevalidate 检查随机存储桶里的最后一个节点是否仍然活跃
// 替换或删除不再活跃的节点
func (tab *Table) doRevalidate(done chan<- struct{}) {
	defer func() { done <- struct{}{} }()

	last, bi := tab.nodeToRevalidate()
	if last == nil {
		// 没有找到非空的存储桶
		return
	}

	// ping选中的节点并等待pong
	err := tab.net.ping(last.ID(), last.addr())

	tab.mutex.Lock()
	defer tab.mutex.Unlock()
	b := tab.buckets[bi]
	if err == nil {
		// 节点有响应，将该节点移至最前面
		log.Debug("Revalidate node", "b", bi, "id", last.ID())
		b.bump(last)
		return
	}

	// 如果没有收到回复，挑选一个节点将其替代，在没有替代节点的情况下将其删除
	if r := tab.replace(b, last); r != nil {
		log.Debug("Replaced dead node", "b", bi, "id", last.ID(), "ip", last.IP(), "r", r.ID(), "rip", r.IP())
	} else {
		log.Debug("Removed dead node", "b", bi, "id", last.ID(), "ip", last.IP())
	}
}

// nodeToRevalidate 返回一个随机的，非空的存储桶中的最后一个节点
func (tab *Table) nodeToRevalidate() (n *node, bi int) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	for _, bi = range tab.rand.Perm(len(tab.buckets)) {
		b := tab.buckets[bi]
		if len(b.entries) > 0 {
			last := b.entries[len(b.entries)-1]
			return last, bi
		}
	}
	return nil, 0
}

func (tab *Table) nextRevalidateTime() time.Duration {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	return time.Duration(tab.rand.Int63n(int64(revalidateInterval)))
}

// copyLiveNodes 将在路由表中的时间大于minTableTime的节点存储到数据库
func (tab *Table) copyLiveNodes() {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	now := time.Now()
	for _, b := range &tab.buckets {
		for _, n := range b.entries {
			if now.Sub(n.addedAt) >= seedMinTableTime {
				tab.db.UpdateNode(unwrapNode(n))
			}
		}
	}
}

// closest 返回路由表中与所给id最接近的节点。调用者必须拥有tab.mutex
func (tab *Table) closest(target enode.ID, nresults int) *nodesByDistance {
	// 这是找到最近节点的非常浪费但却非常正确的方式
	// 我相信基于树的存储桶将会使有效地实现更容易
	close := &nodesByDistance{target: target}
	for _, b := range &tab.buckets {
		for _, n := range b.entries {
			close.push(n, nresults)
		}
	}
	return close
}

func (tab *Table) len() (n int) {
	for _, b := range &tab.buckets {
		n += len(b.entries)
	}
	return n
}

// 获取所给节点ID哈希所对应的存储桶
func (tab *Table) bucket(id enode.ID) *bucket {
	d := enode.LogDist(tab.self().ID(), id)
	if d <= bucketMinDistance {
		return tab.buckets[0]
	}
	return tab.buckets[d-bucketMinDistance-1]
}

// add 尝试着添加所给节点到相应的存储桶内
// 如果存储桶有空间，那么会立即完成存储。否则，将会添加节点到没有响应ping数据包最近最活跃的节点
// 调用者必须拥有tab.mutex
func (tab *Table) add(n *node) {
	if n.ID() == tab.self().ID() {
		return
	}

	tab.mutex.Lock()
	defer tab.mutex.Unlock()
	b := tab.bucket(n.ID())
	if !tab.bumpOrAdd(b, n) {
		// 节点不在路由表中。将节点添加到替换列表
		tab.addReplacement(b, n)
	}
}

// 如果存储桶未满的话，stuff将添加路由表添加到赌赢的存储桶的最后
// 调用者必须有tab.mutex
func (tab *Table) stuff(nodes []*node) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	for _, n := range nodes {
		if n.ID() == tab.self().ID() {
			continue // 不添加自己
		}
		b := tab.bucket(n.ID())
		if len(b.entries) < bucketSize {
			tab.bumpOrAdd(b, n)
		}
	}
}

// delete 从节点路由表中移除一个entry 它用于肃清死亡的节点
func (tab *Table) delete(node *node) {
	tab.mutex.Lock()
	defer tab.mutex.Unlock()

	tab.deleteInBucket(tab.bucket(node.ID()), node)
}

func (tab *Table) addIP(b *bucket, ip net.IP) bool {
	if netutil.IsLAN(ip) {
		return true
	}
	if !tab.ips.Add(ip) {
		log.Debug("IP exceeds table limit", "ip", ip)
		return false
	}
	if !b.ips.Add(ip) {
		log.Debug("IP exceeds bucket limit", "ip", ip)
		tab.ips.Remove(ip)
		return false
	}
	return true
}

func (tab *Table) removeIP(b *bucket, ip net.IP) {
	if netutil.IsLAN(ip) {
		return
	}
	tab.ips.Remove(ip)
	b.ips.Remove(ip)
}

func (tab *Table) addReplacement(b *bucket, n *node) {
	for _, e := range b.replacements {
		if e.ID() == n.ID() {
			return // 已经存在列表中
		}
	}
	if !tab.addIP(b, n.IP()) {
		return
	}
	var removed *node
	b.replacements, removed = pushNode(b.replacements, n, maxReplacements)
	if removed != nil {
		tab.removeIP(b, removed.IP())
	}
}

// 如果节点在存储桶的最后一个entry中， replace 从替代列表中移除n 并且用'last'代替
// 如果'last'不在最后一个entry，这个节点将会被其他的节点代替或者变得活跃
func (tab *Table) replace(b *bucket, last *node) *node {
	if len(b.entries) == 0 || b.entries[len(b.entries)-1].ID() != last.ID() {
		// entry已经移动，不需要替换它
		return nil
	}
	// 仍然是最后一个entry
	if len(b.replacements) == 0 {
		tab.deleteInBucket(b, last)
		return nil
	}
	r := b.replacements[tab.rand.Intn(len(b.replacements))]
	b.replacements = deleteNode(b.replacements, r)
	b.entries[len(b.entries)-1] = r
	tab.removeIP(b, last.IP())
	return r
}

// 如果所给节点存在于列表中，bump 将该节点移动至存储桶entry列表最前面
func (b *bucket) bump(n *node) bool {
	for i := range b.entries {
		if b.entries[i].ID() == n.ID() {
			// 移动至最前面
			copy(b.entries[1:], b.entries[:i])
			b.entries[0] = n
			return true
		}
	}
	return false
}

// bumpOrAdd 将节点n移动到存储桶entry列表的最前面，如果列表未满的话，将其存储
// 如果n在存储桶里，返回true
func (tab *Table) bumpOrAdd(b *bucket, n *node) bool {
	if b.bump(n) {
		return true
	}
	if len(b.entries) >= bucketSize || !tab.addIP(b, n.IP()) {
		return false
	}
	b.entries, _ = pushNode(b.entries, n, bucketSize)
	b.replacements = deleteNode(b.replacements, n)
	n.addedAt = time.Now()
	if tab.nodeAddedHook != nil {
		tab.nodeAddedHook(n)
	}
	return true
}

func (tab *Table) deleteInBucket(b *bucket, n *node) {
	b.entries = deleteNode(b.entries, n)
	tab.removeIP(b, n.IP())
}

// pushNode 将节点n添加到列表前面，保持最大数量
func pushNode(list []*node, n *node, max int) ([]*node, *node) {
	if len(list) < max {
		list = append(list, nil)
	}
	removed := list[len(list)-1]
	copy(list[1:], list)
	list[0] = n
	return list, removed
}

func deleteNode(list []*node, n *node) []*node {
	for i := range list {
		if list[i].ID() == n.ID() {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// nodesByDistance 是一个节点列表，根据到目标的距离排序
type nodesByDistance struct {
	entries []*node
	target  enode.ID
}

// push 将所给节点添加到列表中，控制总数量在maxElems之下
func (h *nodesByDistance) push(n *node, maxElems int) {
	ix := sort.Search(len(h.entries), func(i int) bool {
		return enode.DistCmp(h.target, h.entries[i].ID(), n.ID()) > 0
	})
	if len(h.entries) < maxElems {
		h.entries = append(h.entries, n)
	}
	if ix == len(h.entries) {
		// 比拥有的所有节点都远
		// 如果有空间，节点会是最后一个元素
	} else {
		// 向下滑动现有的entries以腾出空间
		// 这会覆盖刚刚添加的entry
		copy(h.entries[ix+1:], h.entries[ix:])
		h.entries[ix] = n
	}
}
