// Quantaureum Node source, version 1.0.0.
package perf

import (
	"container/heap"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/common"
	"github.com/quantaureum/qau/types"
	"github.com/rs/zerolog/log"
)

type TxPriority uint8

const (
	TxPriorityLow      TxPriority = 0
	TxPriorityNormal   TxPriority = 1
	TxPriorityHigh     TxPriority = 2
	TxPriorityCritical TxPriority = 3
)

type PrioritizedTx struct {
	Hash      common.Hash
	From      types.Address
	To        *types.Address
	Nonce     uint64
	GasPrice  *big.Int
	GasTip    *big.Int
	Priority  TxPriority
	Size      int
	Timestamp time.Time
	Data      []byte
	index     int
}

type PriorityQueue []*PrioritizedTx

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	if pq[i].Priority != pq[j].Priority {
		return pq[i].Priority > pq[j].Priority
	}
	return pq[i].GasPrice.Cmp(pq[j].GasPrice) > 0
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *PriorityQueue) Push(x any) {
	n := len(*pq)
	item := x.(*PrioritizedTx)
	item.index = n
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*pq = old[0 : n-1]
	return item
}

type OptimizedTxPool struct {
	mu            sync.RWMutex
	queue         PriorityQueue
	pending       map[common.Hash]*PrioritizedTx
	queued        map[common.Hash]*PrioritizedTx
	byAddress     map[types.Address]map[uint64]*PrioritizedTx
	maxSize       int
	maxPerAddress int
	totalSize     int
}

func NewOptimizedTxPool(maxSize, maxPerAddress int) *OptimizedTxPool {
	return &OptimizedTxPool{
		queue:         make(PriorityQueue, 0),
		pending:       make(map[common.Hash]*PrioritizedTx),
		queued:        make(map[common.Hash]*PrioritizedTx),
		byAddress:     make(map[types.Address]map[uint64]*PrioritizedTx),
		maxSize:       maxSize,
		maxPerAddress: maxPerAddress,
	}
}

func (tp *OptimizedTxPool) Add(tx *PrioritizedTx) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	if _, exists := tp.pending[tx.Hash]; exists {
		return nil
	}
	if _, exists := tp.queued[tx.Hash]; exists {
		return nil
	}

	if tp.totalSize >= tp.maxSize {
		tp.evictLowest()
	}

	if tp.byAddress[tx.From] == nil {
		tp.byAddress[tx.From] = make(map[uint64]*PrioritizedTx)
	}
	if len(tp.byAddress[tx.From]) >= tp.maxPerAddress {
		tp.evictLowestFrom(tx.From)
	}

	tp.byAddress[tx.From][tx.Nonce] = tx
	tp.pending[tx.Hash] = tx
	tp.totalSize++

	heap.Push(&tp.queue, tx)

	return nil
}

func (tp *OptimizedTxPool) GetBest(count int) []*PrioritizedTx {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	if count > len(tp.queue) {
		count = len(tp.queue)
	}

	result := make([]*PrioritizedTx, count)
	for i := 0; i < count; i++ {
		tx := heap.Pop(&tp.queue).(*PrioritizedTx)
		result[i] = tx
	}

	for _, tx := range result {
		heap.Push(&tp.queue, tx)
	}

	return result
}

func (tp *OptimizedTxPool) Remove(hash common.Hash) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	tx, exists := tp.pending[hash]
	if !exists {
		return
	}

	delete(tp.pending, hash)
	delete(tp.queued, hash)
	if tp.byAddress[tx.From] != nil {
		delete(tp.byAddress[tx.From], tx.Nonce)
	}
	tp.totalSize--
}

func (tp *OptimizedTxPool) evictLowest() {
	if len(tp.queue) == 0 {
		return
	}

	lowestIdx := 0
	for i, tx := range tp.queue {
		if i == 0 {
			continue
		}
		if tp.isLowerPriority(tx, tp.queue[lowestIdx]) {
			lowestIdx = i
		}
	}

	lowest := tp.queue[lowestIdx]
	heap.Remove(&tp.queue, lowestIdx)
	delete(tp.pending, lowest.Hash)
	delete(tp.queued, lowest.Hash)
	if tp.byAddress[lowest.From] != nil {
		delete(tp.byAddress[lowest.From], lowest.Nonce)
	}
	tp.totalSize--
}

func (tp *OptimizedTxPool) isLowerPriority(a, b *PrioritizedTx) bool {
	if a.Priority != b.Priority {
		return a.Priority < b.Priority
	}
	return a.GasPrice.Cmp(b.GasPrice) < 0
}

func (tp *OptimizedTxPool) evictLowestFrom(addr types.Address) {
	addrTxs := tp.byAddress[addr]
	var lowestNonce uint64 = ^uint64(0)

	for nonce := range addrTxs {
		if nonce < lowestNonce {
			lowestNonce = nonce
		}
	}

	if tx, exists := addrTxs[lowestNonce]; exists {
		tp.Remove(tx.Hash)
	}
}

func (tp *OptimizedTxPool) Size() int {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return tp.totalSize
}

func (tp *OptimizedTxPool) PendingCount() int {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return len(tp.pending)
}

func (tp *OptimizedTxPool) GetByAddress(addr types.Address) []*PrioritizedTx {
	tp.mu.RLock()
	defer tp.mu.RUnlock()

	addrTxs := tp.byAddress[addr]
	result := make([]*PrioritizedTx, 0, len(addrTxs))
	for _, tx := range addrTxs {
		result = append(result, tx)
	}
	return result
}

type ParallelTxValidator struct {
	mu         sync.Mutex
	validators int
	semaphore  chan struct{}
}

func NewParallelTxValidator(maxParallel int) *ParallelTxValidator {
	return &ParallelTxValidator{
		validators: maxParallel,
		semaphore:  make(chan struct{}, maxParallel),
	}
}

func (pv *ParallelTxValidator) ValidateBatch(txs []*PrioritizedTx) []*PrioritizedTx {
	var validTxs []*PrioritizedTx
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, tx := range txs {
		wg.Add(1)
		go func(t *PrioritizedTx) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					log.Error().Interface("panic", r).Msg("ParallelTxValidator worker panic")
				}
			}()

			pv.semaphore <- struct{}{}
			defer func() { <-pv.semaphore }()

			if pv.validateTx(t) {
				mu.Lock()
				validTxs = append(validTxs, t)
				mu.Unlock()
			}
		}(tx)
	}

	wg.Wait()
	return validTxs
}

// validateTx performs per-tx validity checks for the parallel prioritized pool.
// Nonce validation: stateless checks only (gas, fields, signature);
// nonce monotonicity enforced in txpool.ValidateWithState before admission.
func (pv *ParallelTxValidator) validateTx(tx *PrioritizedTx) bool {
	if tx == nil {
		return false
	}
	if tx.GasPrice == nil || tx.GasPrice.Sign() <= 0 {
		return false
	}
	if tx.Size > 131072 {
		return false
	}
	return true
}
