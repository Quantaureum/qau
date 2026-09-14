// Quantaureum Node source, version 1.0.0.
// Package txpool implements the transaction pool for Quantaureum.
package txpool

import (
	"container/heap"
	"math/big"
	"sort"
	"sync"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// PriorityQueue is a max-heap of transactions ordered by gas price.
// It provides O(log n) insertion and removal operations.
// Implements Requirements 2.1: O(log n) insertion and priority sorting.
type PriorityQueue struct {
	items []*encoding.Transaction
	index map[types.Hash]int // hash -> index for O(1) lookup
}

// NewPriorityQueue creates a new priority queue.
func NewPriorityQueue() *PriorityQueue {
	pq := &PriorityQueue{
		items: make([]*encoding.Transaction, 0),
		index: make(map[types.Hash]int),
	}
	heap.Init(pq)
	return pq
}

// Len returns the number of transactions in the queue.
func (pq *PriorityQueue) Len() int {
	return len(pq.items)
}

// Less compares two transactions by effective gas price (max-heap: higher price = higher priority).
func (pq *PriorityQueue) Less(i, j int) bool {
	// Max-heap: higher effective gas price comes first
	cmp := effectiveGasPriceForSorting(pq.items[i]).Cmp(effectiveGasPriceForSorting(pq.items[j]))
	if cmp != 0 {
		return cmp > 0
	}
	// Tie-breaker 1: lower nonce comes first (for same account)
	if pq.items[i].From == pq.items[j].From {
		return pq.items[i].Nonce < pq.items[j].Nonce
	}
	// MEDIUM FIX: Deterministic tie-breaker using transaction hash
	// This prevents non-deterministic ordering when gas price and nonce are equal
	hashI := pq.items[i].Hash()
	hashJ := pq.items[j].Hash()
	return hashI.String() < hashJ.String()
}

// Swap swaps two transactions in the queue.
func (pq *PriorityQueue) Swap(i, j int) {
	pq.items[i], pq.items[j] = pq.items[j], pq.items[i]
	// Update index map
	pq.index[pq.items[i].Hash()] = i
	pq.index[pq.items[j].Hash()] = j
}

// Push adds a transaction to the queue. O(log n) complexity.
func (pq *PriorityQueue) Push(x any) {
	tx := x.(*encoding.Transaction)
	pq.index[tx.Hash()] = len(pq.items)
	pq.items = append(pq.items, tx)
}

// Pop removes and returns the highest priority transaction. O(log n) complexity.
func (pq *PriorityQueue) Pop() any {
	old := pq.items
	n := len(old)
	if n == 0 {
		return nil
	}
	tx := old[n-1]
	old[n-1] = nil // avoid memory leak
	pq.items = old[0 : n-1]
	delete(pq.index, tx.Hash())
	return tx
}

// Peek returns the highest priority transaction without removing it. O(1) complexity.
func (pq *PriorityQueue) Peek() *encoding.Transaction {
	if len(pq.items) == 0 {
		return nil
	}
	return pq.items[0]
}

// Contains checks if a transaction is in the queue. O(1) complexity.
func (pq *PriorityQueue) Contains(hash types.Hash) bool {
	_, exists := pq.index[hash]
	return exists
}

// Remove removes a specific transaction from the queue. O(log n) complexity.
func (pq *PriorityQueue) Remove(hash types.Hash) *encoding.Transaction {
	idx, exists := pq.index[hash]
	if !exists {
		return nil
	}
	return heap.Remove(pq, idx).(*encoding.Transaction)
}

// All returns all transactions in the queue sorted by priority (descending gas price).
func (pq *PriorityQueue) All() []*encoding.Transaction {
	result := make([]*encoding.Transaction, len(pq.items))
	copy(result, pq.items)
	// Sort by gas price descending
	sortByGasPrice(result)
	return result
}

// ThreadSafePriorityQueue wraps PriorityQueue with mutex for concurrent access.
type ThreadSafePriorityQueue struct {
	pq *PriorityQueue
	mu sync.RWMutex
}

// NewThreadSafePriorityQueue creates a new thread-safe priority queue.
func NewThreadSafePriorityQueue() *ThreadSafePriorityQueue {
	return &ThreadSafePriorityQueue{
		pq: NewPriorityQueue(),
	}
}

// Push adds a transaction to the queue. Thread-safe, O(log n).
func (tspq *ThreadSafePriorityQueue) Push(tx *encoding.Transaction) {
	tspq.mu.Lock()
	defer tspq.mu.Unlock()
	heap.Push(tspq.pq, tx)
}

// Pop removes and returns the highest priority transaction. Thread-safe, O(log n).
func (tspq *ThreadSafePriorityQueue) Pop() *encoding.Transaction {
	tspq.mu.Lock()
	defer tspq.mu.Unlock()
	if tspq.pq.Len() == 0 {
		return nil
	}
	return heap.Pop(tspq.pq).(*encoding.Transaction)
}

// Peek returns the highest priority transaction without removing it. Thread-safe, O(1).
func (tspq *ThreadSafePriorityQueue) Peek() *encoding.Transaction {
	tspq.mu.RLock()
	defer tspq.mu.RUnlock()
	return tspq.pq.Peek()
}

// Len returns the number of transactions. Thread-safe.
func (tspq *ThreadSafePriorityQueue) Len() int {
	tspq.mu.RLock()
	defer tspq.mu.RUnlock()
	return tspq.pq.Len()
}

// Contains checks if a transaction is in the queue. Thread-safe, O(1).
func (tspq *ThreadSafePriorityQueue) Contains(hash types.Hash) bool {
	tspq.mu.RLock()
	defer tspq.mu.RUnlock()
	return tspq.pq.Contains(hash)
}

// Remove removes a specific transaction. Thread-safe, O(log n).
func (tspq *ThreadSafePriorityQueue) Remove(hash types.Hash) *encoding.Transaction {
	tspq.mu.Lock()
	defer tspq.mu.Unlock()
	return tspq.pq.Remove(hash)
}

// All returns all transactions sorted by priority. Thread-safe.
func (tspq *ThreadSafePriorityQueue) All() []*encoding.Transaction {
	tspq.mu.RLock()
	defer tspq.mu.RUnlock()
	return tspq.pq.All()
}

// NonceHeap is a min-heap of transactions ordered by nonce for a single account.
// Used to track pending transactions per account and ensure nonce ordering.
type NonceHeap struct {
	txs   map[uint64]*encoding.Transaction
	ready uint64 // next expected nonce
}

// NewNonceHeap creates a new nonce heap with the given starting nonce.
func NewNonceHeap(startNonce uint64) *NonceHeap {
	return &NonceHeap{
		txs:   make(map[uint64]*encoding.Transaction),
		ready: startNonce,
	}
}

// Add adds a transaction to the heap.
func (nh *NonceHeap) Add(tx *encoding.Transaction) bool {
	// Check if we already have a tx with this nonce
	if existing, ok := nh.txs[tx.Nonce]; ok {
		// Only replace if new tx has higher gas price
		if tx.GasPrice.Cmp(existing.GasPrice) <= 0 {
			return false
		}
	}
	nh.txs[tx.Nonce] = tx
	return true
}

// Remove removes a transaction by nonce.
func (nh *NonceHeap) Remove(nonce uint64) *encoding.Transaction {
	tx, exists := nh.txs[nonce]
	if !exists {
		return nil
	}
	delete(nh.txs, nonce)
	return tx
}

// Get returns a transaction by nonce.
func (nh *NonceHeap) Get(nonce uint64) *encoding.Transaction {
	return nh.txs[nonce]
}

// Len returns the number of transactions.
func (nh *NonceHeap) Len() int {
	return len(nh.txs)
}

// Ready returns all transactions that are ready for execution (consecutive nonces starting from ready).
// FIX: Group by sender, sort within each group by nonce ascending, then
// sort groups by gas price descending. This preserves nonce ordering per account
// while still prioritizing higher gas price transactions.
func (nh *NonceHeap) Ready() []*encoding.Transaction {
	var result []*encoding.Transaction
	nonce := nh.ready
	for {
		tx, exists := nh.txs[nonce]
		if !exists {
			break
		}
		result = append(result, tx)
		nonce++
	}
	return sortBySenderNonceGasPrice(result)
}

// sortBySenderNonceGasPrice groups transactions by sender, sorts each sender
// group by nonce ascending, then orders the groups by the gas price of the
// first transaction in each group (descending). This ensures nonce ordering is
// preserved per account while still prioritizing higher gas price transactions
// across accounts.
// FIX: Previously Ready() sorted all transactions purely by gas price,
// which broke nonce ordering for same-account transactions and caused execution
// failures (e.g. nonce=5 returned before nonce=3).
func sortBySenderNonceGasPrice(txs []*encoding.Transaction) []*encoding.Transaction {
	if len(txs) <= 1 {
		return txs
	}

	// Group by sender
	senderGroups := make(map[types.Address][]*encoding.Transaction)
	for _, tx := range txs {
		senderGroups[tx.From] = append(senderGroups[tx.From], tx)
	}

	// Sort each group by nonce ascending
	for _, groupTxs := range senderGroups {
		sort.Slice(groupTxs, func(i, j int) bool {
			return groupTxs[i].Nonce < groupTxs[j].Nonce
		})
	}

	// Sort groups by the gas price of the first tx in each group (descending)
	type senderGroup struct {
		addr types.Address
		txs  []*encoding.Transaction
	}
	groups := make([]senderGroup, 0, len(senderGroups))
	for addr, groupTxs := range senderGroups {
		groups = append(groups, senderGroup{addr: addr, txs: groupTxs})
	}
	sort.Slice(groups, func(i, j int) bool {
		priceI := effectiveGasPriceForSorting(groups[i].txs[0])
		priceJ := effectiveGasPriceForSorting(groups[j].txs[0])
		cmp := priceI.Cmp(priceJ)
		if cmp != 0 {
			return cmp > 0 // descending
		}
		// Tie-breaker: deterministic ordering by sender address
		return groups[i].addr.String() < groups[j].addr.String()
	})

	// Flatten groups into result
	result := make([]*encoding.Transaction, 0, len(txs))
	for _, g := range groups {
		result = append(result, g.txs...)
	}
	return result
}

// SetReady updates the ready nonce (typically after transactions are confirmed).
func (nh *NonceHeap) SetReady(nonce uint64) {
	nh.ready = nonce
}

// GetReady returns the current ready nonce.
func (nh *NonceHeap) GetReady() uint64 {
	return nh.ready
}

// All returns all transactions sorted by nonce.
func (nh *NonceHeap) All() []*encoding.Transaction {
	result := make([]*encoding.Transaction, 0, len(nh.txs))
	for _, tx := range nh.txs {
		result = append(result, tx)
	}
	sortByNonce(result)
	return result
}

// Lowest returns the transaction with the lowest gas price.
// Used for eviction when pool is full.
func (nh *NonceHeap) Lowest() *encoding.Transaction {
	var lowest *encoding.Transaction
	for _, tx := range nh.txs {
		if lowest == nil || effectiveGasPriceForSorting(tx).Cmp(effectiveGasPriceForSorting(lowest)) < 0 {
			lowest = tx
		}
	}
	return lowest
}

// LowestPriceTransaction finds the transaction with the lowest gas price across all accounts.
type LowestPriceTransaction struct {
	Tx      *encoding.Transaction
	Account types.Address
}

// FindLowestPrice finds the lowest priced transaction in a map of nonce heaps.
func FindLowestPrice(pending map[types.Address]*NonceHeap) *LowestPriceTransaction {
	var result *LowestPriceTransaction
	for addr, nh := range pending {
		lowest := nh.Lowest()
		if lowest == nil {
			continue
		}
		if result == nil || effectiveGasPriceForSorting(lowest).Cmp(effectiveGasPriceForSorting(result.Tx)) < 0 {
			result = &LowestPriceTransaction{
				Tx:      lowest,
				Account: addr,
			}
		}
	}
	return result
}

// PriceBump calculates the minimum price required to replace a transaction.
func PriceBump(oldPrice *big.Int, bumpPercent int64) *big.Int {
	threshold := new(big.Int).Mul(oldPrice, big.NewInt(100+bumpPercent))
	threshold.Div(threshold, big.NewInt(100))
	return threshold
}

// effectiveGasPriceForSorting returns the effective gas price used for transaction sorting.
// For EIP-1559 dynamic fee transactions, this is MaxPriorityFeePerGas (the tip to the miner).
// For legacy transactions, this is GasPrice.
//
// R34 P3-02 FIX (2026-07-29): Added nil defense. If neither MaxPriorityFeePerGas
// (for dynamic-fee) nor GasPrice is set, the function previously returned nil,
// causing a nil pointer panic in callers (e.g., cmp.Cmp). validateBasicFields
// rejects nil GasPrice at pool ingress, but transactions that bypass the pool
// (e.g., block-applied txs during sync) may reach the sorter with nil fields.
// Returning big.NewInt(0) places such malformed transactions at the bottom of
// the fee-ordered heap instead of crashing the node.
func effectiveGasPriceForSorting(tx *encoding.Transaction) *big.Int {
	if tx.Type == encoding.TxTypeDynamicFee && tx.MaxPriorityFeePerGas != nil {
		return tx.MaxPriorityFeePerGas
	}
	if tx.GasPrice != nil {
		return tx.GasPrice
	}
	return big.NewInt(0)
}
