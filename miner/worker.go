// Quantaureum Node source, version 1.0.0.
// Package miner provides block building and mining functionality for the QAU blockchain.
package miner

import (
	"bytes"
	"errors"
	"math"
	"math/big"
	"sort"
	"sync"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// Worker errors
var (
	ErrNoTransactions     = errors.New("no transactions available")
	ErrGasLimitExceeded   = errors.New("gas limit exceeded")
	ErrInvalidParentBlock = errors.New("invalid parent block")
	ErrWorkerStopped      = errors.New("worker stopped")
)

// TxPool defines the interface for transaction pool operations.
type TxPool interface {
	// Pending returns all pending transactions sorted by gas price.
	Pending() []*encoding.Transaction
	// Remove removes a transaction from the pool.
	Remove(hash types.Hash)
	// Get returns a transaction by hash.
	Get(hash types.Hash) *encoding.Transaction
}

// StateReader defines the interface for reading blockchain state.
type StateReader interface {
	// GetNonce returns the nonce for an address.
	GetNonce(addr types.Address) uint64
	// GetBalance returns the balance for an address.
	GetBalance(addr types.Address) *big.Int
}

// Worker handles transaction selection and block building.
type Worker struct {
	mu sync.RWMutex

	txPool   TxPool
	state    StateReader
	gasLimit uint64

	// Pending transactions for current block
	pendingTxs []*encoding.Transaction
	pendingGas uint64

	// Configuration
	maxTxsPerBlock int
}

// WorkerConfig holds configuration for the Worker.
type WorkerConfig struct {
	GasLimit       uint64
	MaxTxsPerBlock int
}

// DefaultWorkerConfig returns default worker configuration.
func DefaultWorkerConfig() WorkerConfig {
	return WorkerConfig{
		GasLimit:       8000000, // 8M gas limit
		MaxTxsPerBlock: 1000,
	}
}

// NewWorker creates a new Worker instance.
func NewWorker(txPool TxPool, state StateReader, config WorkerConfig) *Worker {
	if config.GasLimit == 0 {
		config.GasLimit = DefaultWorkerConfig().GasLimit
	}
	if config.MaxTxsPerBlock == 0 {
		config.MaxTxsPerBlock = DefaultWorkerConfig().MaxTxsPerBlock
	}

	return &Worker{
		txPool:         txPool,
		state:          state,
		gasLimit:       config.GasLimit,
		maxTxsPerBlock: config.MaxTxsPerBlock,
		pendingTxs:     make([]*encoding.Transaction, 0),
	}
}

// SelectTransactions selects transactions from the pool for block inclusion.
// Transactions are grouped by sender and each sender's transactions are
// processed in ascending nonce order. Across senders, transactions are
// prioritized by gas price (highest first) with hash as tie-breaker.
//
// AUDIT (2026) ECON-04 FIX: Previously, transactions were sorted purely
// by gas price and wrong-nonce transactions were skipped without revisiting.
// This caused valid transactions to be missed when a higher-nonce transaction
// had a higher gas price than its preceding nonce (e.g., sender has
// tx[nonce=0,gp=100] and tx[nonce=1,gp=200]; the sort puts nonce=1 first,
// it gets skipped for wrong nonce, then nonce=0 is included but nonce=1 is
// never revisited). Now transactions are grouped by sender and processed in
// nonce order, ensuring:
//   - Per-sender nonce ordering is enforced by construction (not just filtering)
//   - No valid transactions are unnecessarily skipped
//   - Gas price prioritization is preserved across senders
func (w *Worker) SelectTransactions(gasLimit uint64) []*encoding.Transaction {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Get all pending transactions from pool
	allTxs := w.txPool.Pending()
	if len(allTxs) == 0 {
		return nil
	}

	// Group transactions by sender
	senderTxs := make(map[types.Address][]*encoding.Transaction)
	for _, tx := range allTxs {
		senderTxs[tx.From] = append(senderTxs[tx.From], tx)
	}

	// Sort each sender's transactions by nonce (ascending) so per-sender
	// nonce ordering is guaranteed by construction.
	for sender := range senderTxs {
		txs := senderTxs[sender]
		sort.Slice(txs, func(i, j int) bool {
			return txs[i].Nonce < txs[j].Nonce
		})
	}

	// Track per-sender state: current head index and expected next nonce.
	type senderState struct {
		txs       []*encoding.Transaction
		idx       int
		nextNonce uint64
	}
	states := make(map[types.Address]*senderState, len(senderTxs))
	for sender, txs := range senderTxs {
		states[sender] = &senderState{
			txs:       txs,
			idx:       0,
			nextNonce: w.state.GetNonce(sender),
		}
	}

	var selected []*encoding.Transaction
	var gasUsed uint64

	for {
		if len(selected) >= w.maxTxsPerBlock {
			break
		}

		// Find the best available transaction across all senders.
		// "Available" means: the sender's current head transaction has the
		// expected nonce and fits within the remaining gas limit.
		//
		// CONS-R14-001 (2026-07-21) FIX: Iterate senders in deterministic
		// (sorted address) order. Previously this iterated the `states` map
		// directly, relying on Go's randomized map iteration order. While
		// the hash tie-breaker below makes the final selection deterministic
		// regardless of iteration order (the min-hash tx always wins),
		// deterministic iteration makes the code obviously correct to
		// auditors and avoids any risk that a future change to the tie-breaker
		// logic could reintroduce non-determinism.
		sortedSenders := make([]types.Address, 0, len(states))
		for sender := range states {
			sortedSenders = append(sortedSenders, sender)
		}
		sort.Slice(sortedSenders, func(i, j int) bool {
			return bytes.Compare(sortedSenders[i][:], sortedSenders[j][:]) < 0
		})

		var bestTx *encoding.Transaction
		var bestSender types.Address
		var bestGasPrice *big.Int

		for _, sender := range sortedSenders {
			st := states[sender]
			// Skip senders with no more transactions
			if st.idx >= len(st.txs) {
				continue
			}
			tx := st.txs[st.idx]
			// Enforce nonce ordering: only include if nonce matches expected
			if tx.Nonce != st.nextNonce {
				continue
			}
			// audit-fix MEDIUM-4: overflow-safe gas check
			if gasUsed >= gasLimit || tx.GasLimit > gasLimit-gasUsed {
				continue
			}
			// Compare gas price (highest first), with hash tie-breaker
			gp := tx.GasPrice
			if gp == nil {
				gp = new(big.Int) // audit-fix R7-M1: guard nil GasPrice
			}
			if bestTx == nil {
				bestTx = tx
				bestSender = sender
				bestGasPrice = gp
				continue
			}
			cmp := gp.Cmp(bestGasPrice)
			if cmp > 0 {
				bestTx = tx
				bestSender = sender
				bestGasPrice = gp
			} else if cmp == 0 {
				// Tie-breaker: lower hash wins for determinism
				h := tx.Hash()
				bh := bestTx.Hash()
				for k := 0; k < len(h); k++ {
					if h[k] != bh[k] {
						if h[k] < bh[k] {
							bestTx = tx
							bestSender = sender
							bestGasPrice = gp
						}
						break
					}
				}
			}
		}

		if bestTx == nil {
			break // No more includable transactions
		}

		selected = append(selected, bestTx)
		gasUsed += bestTx.GasLimit
		st := states[bestSender]
		st.idx++
		st.nextNonce = bestTx.Nonce + 1
	}

	return selected
}

// CommitTransactions commits selected transactions to the pending block.
// Returns error if total gas exceeds the block gas limit.
// audit-fix H-4: overflow-safe gas accumulation.
func (w *Worker) CommitTransactions(txs []*encoding.Transaction) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var totalGas uint64
	for _, tx := range txs {
		// audit-fix H-4: check for uint64 overflow before adding
		if tx.GasLimit > w.gasLimit-totalGas {
			return ErrGasLimitExceeded
		}
		// CRITICAL: Add explicit overflow guard after pre-check
		if totalGas > math.MaxUint64-tx.GasLimit {
			return ErrGasLimitExceeded
		}
		totalGas += tx.GasLimit
	}

	// audit-fix H-4: overflow-safe pending gas check
	if totalGas > w.gasLimit-w.pendingGas {
		return ErrGasLimitExceeded
	}

	w.pendingTxs = append(w.pendingTxs, txs...)
	w.pendingGas += totalGas

	return nil
}

// PendingTransactions returns the currently pending transactions.
func (w *Worker) PendingTransactions() []*encoding.Transaction {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make([]*encoding.Transaction, len(w.pendingTxs))
	copy(result, w.pendingTxs)
	return result
}

// PendingGas returns the total gas of pending transactions.
func (w *Worker) PendingGas() uint64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.pendingGas
}

// Reset clears the pending transactions.
func (w *Worker) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.pendingTxs = make([]*encoding.Transaction, 0)
	w.pendingGas = 0
}

// SetGasLimit updates the gas limit for block building.
func (w *Worker) SetGasLimit(limit uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.gasLimit = limit
}

// GasLimit returns the current gas limit.
func (w *Worker) GasLimit() uint64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.gasLimit
}

// RemoveCommittedFromPool removes committed transactions from the pool.
func (w *Worker) RemoveCommittedFromPool() {
	w.mu.RLock()
	txs := make([]*encoding.Transaction, len(w.pendingTxs))
	copy(txs, w.pendingTxs)
	w.mu.RUnlock()

	for _, tx := range txs {
		w.txPool.Remove(tx.Hash())
	}
}
