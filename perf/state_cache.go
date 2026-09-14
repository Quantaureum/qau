// Quantaureum Node source, version 1.0.0.
package perf

import (
	"sync"
	"time"

	"github.com/quantaureum/qau/common"
	"github.com/quantaureum/qau/common/lru"
	"github.com/rs/zerolog/log"
)

type NodeType uint8

const (
	NodeTypeBranch NodeType = iota
	NodeTypeExtension
	NodeTypeLeaf
)

type TrieNode struct {
	Hash       common.Hash
	NodeType   NodeType
	Key        []byte
	Value      []byte
	Children   [16]common.Hash
	Dirty      bool
	LastAccess time.Time
}

type MerkleCache struct {
	mu         sync.RWMutex
	nodeCache  *lru.Cache[common.Hash, *TrieNode]
	proofCache *lru.Cache[common.Hash, [][]byte]
	dirtyNodes map[common.Hash]*TrieNode
	maxSize    int
	hits       uint64
	misses     uint64
}

func NewMerkleCache(maxSize int) *MerkleCache {
	return &MerkleCache{
		nodeCache:  lru.New[common.Hash, *TrieNode](maxSize),
		proofCache: lru.New[common.Hash, [][]byte](maxSize / 4),
		dirtyNodes: make(map[common.Hash]*TrieNode),
		maxSize:    maxSize,
	}
}

func (mc *MerkleCache) GetNode(hash common.Hash) (*TrieNode, bool) {
	mc.mu.RLock()
	node, ok := mc.nodeCache.Get(hash)
	mc.mu.RUnlock()

	if ok {
		mc.mu.Lock()
		mc.hits++
		node.LastAccess = time.Now()
		mc.mu.Unlock()
		return node, true
	}

	mc.mu.Lock()
	mc.misses++
	mc.mu.Unlock()
	return nil, false
}

func (mc *MerkleCache) PutNode(node *TrieNode) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.nodeCache.Put(node.Hash, node)
	if node.Dirty {
		mc.dirtyNodes[node.Hash] = node
	}
}

func (mc *MerkleCache) GetProof(rootHash common.Hash) ([][]byte, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	proof, ok := mc.proofCache.Get(rootHash)
	return proof, ok
}

func (mc *MerkleCache) PutProof(rootHash common.Hash, proof [][]byte) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.proofCache.Put(rootHash, proof)
}

func (mc *MerkleCache) Invalidate(hash common.Hash) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.nodeCache.Remove(hash)
	mc.proofCache.Remove(hash)
	delete(mc.dirtyNodes, hash)
}

func (mc *MerkleCache) FlushDirty() []*TrieNode {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	nodes := make([]*TrieNode, 0, len(mc.dirtyNodes))
	for _, node := range mc.dirtyNodes {
		node.Dirty = false
		nodes = append(nodes, node)
	}
	mc.dirtyNodes = make(map[common.Hash]*TrieNode)
	return nodes
}

func (mc *MerkleCache) Stats() (hits, misses uint64, dirtyCount int) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	return mc.hits, mc.misses, len(mc.dirtyNodes)
}

func (mc *MerkleCache) HitRate() float64 {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	total := mc.hits + mc.misses
	if total == 0 {
		return 0
	}
	return float64(mc.hits) / float64(total)
}

type ParallelStateAccess struct {
	mu           sync.RWMutex
	storage      map[common.Hash][]byte
	readLocks    map[common.Hash]*sync.RWMutex
	lockMu       sync.Mutex
	batchSize    int
	pendingBatch map[common.Hash][]byte
}

func NewParallelStateAccess() *ParallelStateAccess {
	return &ParallelStateAccess{
		storage:      make(map[common.Hash][]byte),
		readLocks:    make(map[common.Hash]*sync.RWMutex),
		batchSize:    256,
		pendingBatch: make(map[common.Hash][]byte),
	}
}

func (psa *ParallelStateAccess) getLock(key common.Hash) *sync.RWMutex {
	psa.lockMu.Lock()
	defer psa.lockMu.Unlock()

	if lock, exists := psa.readLocks[key]; exists && lock != nil {
		return lock
	}

	lock := &sync.RWMutex{}
	psa.readLocks[key] = lock
	return lock
}

func (psa *ParallelStateAccess) Read(key common.Hash) ([]byte, bool) {
	lock := psa.getLock(key)
	if lock == nil {
		return nil, false
	}
	lock.RLock()
	defer lock.RUnlock()

	psa.mu.RLock()
	defer psa.mu.RUnlock()

	val, ok := psa.storage[key]
	return val, ok
}

func (psa *ParallelStateAccess) Write(key common.Hash, value []byte) {
	lock := psa.getLock(key)
	if lock == nil {
		return
	}
	lock.Lock()
	defer lock.Unlock()

	psa.mu.Lock()
	defer psa.mu.Unlock()

	psa.storage[key] = value
}

func (psa *ParallelStateAccess) BatchRead(keys []common.Hash) map[common.Hash][]byte {
	result := make(map[common.Hash][]byte, len(keys))

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, key := range keys {
		wg.Add(1)
		go func(k common.Hash) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Error().Interface("panic", r).Msg("ParallelStateAccess BatchRead worker panic")
				}
			}()
			if val, ok := psa.Read(k); ok {
				mu.Lock()
				result[k] = val
				mu.Unlock()
			}
		}(key)
	}

	wg.Wait()
	return result
}

func (psa *ParallelStateAccess) BatchWrite(updates map[common.Hash][]byte) {
	// CRITICAL FIX: Use single mutex to protect entire batch, avoiding potential deadlock
	// from acquiring per-key locks while also holding the global mutex.
	psa.mu.Lock()
	defer psa.mu.Unlock()

	for key, value := range updates {
		psa.storage[key] = value
	}
}

func (psa *ParallelStateAccess) Snapshot() map[common.Hash][]byte {
	psa.mu.RLock()
	defer psa.mu.RUnlock()

	snapshot := make(map[common.Hash][]byte, len(psa.storage))
	for k, v := range psa.storage {
		val := make([]byte, len(v))
		copy(val, v)
		snapshot[k] = val
	}
	return snapshot
}

func (psa *ParallelStateAccess) Size() int {
	psa.mu.RLock()
	defer psa.mu.RUnlock()
	return len(psa.storage)
}
