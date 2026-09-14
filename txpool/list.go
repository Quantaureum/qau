// Quantaureum Node source, version 1.0.0.
package txpool

import (
	"container/heap"
	"fmt"
	"math"
	"math/big"
	"sort"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// txList is a list of transactions from a single account, sorted by nonce.
type txList struct {
	txs map[uint64]*encoding.Transaction
}

// newTxList creates a new transaction list.
func newTxList() *txList {
	return &txList{
		txs: make(map[uint64]*encoding.Transaction),
	}
}

// minNonce returns the lowest nonce in the list, or 0 if empty.
func (l *txList) minNonce() uint64 {
	var min uint64
	first := true
	for n := range l.txs {
		if first || n < min {
			min = n
			first = false
		}
	}
	return min
}

// Add adds a transaction to the list.
// L14-014: Validate nonce gap to prevent memory exhaustion from transactions
// with excessively high nonces. Reject if nonce is more than MaxNonceGap
// ahead of the lowest pending nonce in the list (defense-in-depth).
//
// R25-038 (P3): Nonce gap tracking. txList is a map keyed by nonce; it tracks
// the full set of pending nonces for a sender so the pool can detect gaps
// (missing intermediate nonces) and promote the next executable transaction
// (minNonce) once a gap is filled. MaxNonceGap bounds how far ahead of the
// current minimum a new tx may be accepted, preventing a sender from pinning
// unbounded memory with far-future nonces. Gaps themselves are tolerated
// (out-of-order submission is allowed); only the maximum lookahead is rejected.
//
// R35-P2-TXPOOL-04 FIX (2026-07-29): The previous baseline was minNonce()
// (lowest pending nonce IN THE LIST). This baseline DRIFTS: once a low-nonce
// tx enters the list, it becomes the new min, allowing the next tx to be
// MaxNonceGap ahead of THAT — even if the low-nonce tx has already been
// included in a block and the state nonce has advanced far past it. A
// malicious sender could pin a low-nonce tx in the list (e.g. nonce 0 with
// insufficient balance) and then submit MaxNonceGap more txs ahead of the
// state nonce, bypassing the gap limit. Prefer AddWithStateNonce when the
// caller has access to the on-chain state nonce — it uses the STATE nonce
// (monotonically increasing, never regresses) as the baseline, which is the
// correct anchor for memory-exhaustion protection.
func (l *txList) Add(tx *encoding.Transaction) error {
	if len(l.txs) > 0 {
		min := l.minNonce()
		if tx.Nonce > min+MaxNonceGap {
			return fmt.Errorf("nonce %d exceeds gap limit: min pending %d + max gap %d", tx.Nonce, min, MaxNonceGap)
		}
	}
	l.txs[tx.Nonce] = tx
	return nil
}

// AddWithStateNonce adds a transaction, using the on-chain state nonce as the
// gap-limit baseline. This is the preferred method when the caller has access
// to the state DB — it closes the baseline-drift vulnerability described in
// R35-P2-TXPOOL-04 by anchoring the gap check to the monotonically-increasing
// state nonce rather than the list's minNonce() (which can be pinned low by
// a stale tx). Falls back to minNonce() when stateNonce is 0 and the list is
// non-empty (e.g. during genesis/stateless test scenarios).
func (l *txList) AddWithStateNonce(tx *encoding.Transaction, stateNonce uint64) error {
	baseline := stateNonce
	if baseline == 0 && len(l.txs) > 0 {
		// Stateless fallback: use list minNonce.
		baseline = l.minNonce()
	}
	if tx.Nonce > baseline+MaxNonceGap {
		return fmt.Errorf("nonce %d exceeds gap limit: state nonce %d + max gap %d", tx.Nonce, baseline, MaxNonceGap)
	}
	// Also enforce the list-relative gap as defense-in-depth: even with a
	// valid state nonce, a single list shouldn't have txs spanning more
	// than MaxNonceGap (otherwise a state-nonce regression across a fork
	// could leave a huge list orphaned in memory).
	if len(l.txs) > 0 {
		min := l.minNonce()
		if tx.Nonce > min+MaxNonceGap {
			return fmt.Errorf("nonce %d exceeds gap limit: min pending %d + max gap %d", tx.Nonce, min, MaxNonceGap)
		}
	}
	l.txs[tx.Nonce] = tx
	return nil
}

// Remove removes a transaction by nonce.
func (l *txList) Remove(nonce uint64) {
	delete(l.txs, nonce)
}

// Get returns a transaction by nonce.
func (l *txList) Get(nonce uint64) *encoding.Transaction {
	return l.txs[nonce]
}

// Len returns the number of transactions.
func (l *txList) Len() int {
	return len(l.txs)
}

// Ready returns transactions ready for execution starting from the given nonce.
// Transactions are returned in strict nonce order (required by EVM execution).
// CRITICAL FIX: Add nonce overflow check to prevent infinite loop when nonce reaches math.MaxUint64.
func (l *txList) Ready(startNonce uint64) []*encoding.Transaction {
	var ready []*encoding.Transaction

	nonce := startNonce
	for {
		if nonce == math.MaxUint64 {
			break // Prevent overflow
		}
		tx, exists := l.txs[nonce]
		if !exists {
			break
		}
		ready = append(ready, tx)
		nonce++
	}
	// audit-fix R40-H8: Removed gas price sort that destroyed nonce ordering.
	// EVM requires transactions from the same sender to execute in strict nonce
	// order. The loop above already collects transactions in ascending nonce order
	// (startNonce, startNonce+1, ...). Re-sorting by gas price here would break
	// that invariant, causing "nonce too high" execution failures. Gas price
	// prioritization belongs at a higher level (e.g., selecting between senders
	// in the block builder), NOT within a single sender's transaction list.

	return ready
}

// All returns all transactions sorted by nonce.
func (l *txList) All() []*encoding.Transaction {
	result := make([]*encoding.Transaction, 0, len(l.txs))
	for _, tx := range l.txs {
		result = append(result, tx)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Nonce < result[j].Nonce
	})
	return result
}

// txPriceHeap is a min-heap of transactions ordered by gas price.
type txPriceHeap struct {
	txs []*encoding.Transaction
}

func newTxPriceHeap() *txPriceHeap {
	h := &txPriceHeap{
		txs: make([]*encoding.Transaction, 0),
	}
	heap.Init(h)
	return h
}

func (h *txPriceHeap) Len() int {
	return len(h.txs)
}

func (h *txPriceHeap) Less(i, j int) bool {
	// Min-heap: lower effective price comes first (for eviction)
	return effectiveGasPriceForSorting(h.txs[i]).Cmp(effectiveGasPriceForSorting(h.txs[j])) < 0
}

func (h *txPriceHeap) Swap(i, j int) {
	h.txs[i], h.txs[j] = h.txs[j], h.txs[i]
}

func (h *txPriceHeap) Push(x any) {
	h.txs = append(h.txs, x.(*encoding.Transaction))
}

func (h *txPriceHeap) Pop() any {
	old := h.txs
	n := len(old)
	x := old[n-1]
	h.txs = old[0 : n-1]
	return x
}

func (h *txPriceHeap) Peek() *encoding.Transaction {
	if len(h.txs) == 0 {
		return nil
	}
	return h.txs[0]
}

// Remove removes a transaction by hash from the heap.
// This is an O(n) operation but it's called infrequently.
func (h *txPriceHeap) Remove(hash types.Hash) {
	for i, tx := range h.txs {
		if tx.Hash() == hash {
			// Remove the transaction and re-heapify
			heap.Remove(h, i)
			return
		}
	}
}

// sortByGasPrice sorts transactions by effective gas price in descending order.
func sortByGasPrice(txs []*encoding.Transaction) {
	sort.Slice(txs, func(i, j int) bool {
		return effectiveGasPriceForSorting(txs[i]).Cmp(effectiveGasPriceForSorting(txs[j])) > 0
	})
}

// sortByNonce sorts transactions by nonce in ascending order.
func sortByNonce(txs []*encoding.Transaction) {
	sort.Slice(txs, func(i, j int) bool {
		return txs[i].Nonce < txs[j].Nonce
	})
}

// TxByPrice implements sort.Interface for sorting by effective gas price.
type TxByPrice []*encoding.Transaction

func (s TxByPrice) Len() int { return len(s) }
func (s TxByPrice) Less(i, j int) bool {
	return effectiveGasPriceForSorting(s[i]).Cmp(effectiveGasPriceForSorting(s[j])) > 0
}
func (s TxByPrice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// TxByNonce implements sort.Interface for sorting by nonce.
type TxByNonce []*encoding.Transaction

func (s TxByNonce) Len() int           { return len(s) }
func (s TxByNonce) Less(i, j int) bool { return s[i].Nonce < s[j].Nonce }
func (s TxByNonce) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// Priority returns the priority of a transaction (higher is better).
func Priority(tx *encoding.Transaction) *big.Int {
	return effectiveGasPriceForSorting(tx)
}
