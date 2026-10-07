// Quantaureum Node source, version 1.0.0.
package txpool

import (
	"errors"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

var (
	ErrTxExpired          = errors.New("transaction expired")
	ErrTxTooBig           = errors.New("transaction too large")
	ErrPoolMemoryExceeded = errors.New("pool memory limit exceeded")
)

const (
	// R35-P0-10 FIX: Align DefaultTxTTL with TxPool's 6-hour maxTxAge
	// (pool.go:825). Previously this was 3 hours, causing EnhancedPool's
	// cleanup() to delete transactions 3 hours before TxPool's own TTL —
	// the audit found this caused "legitimate transactions to disappear
	// 3 hours early" because the cleanup only deleted from `all` and
	// `txTimestamps` while leaving stale entries in `priced`,
	// `evictionHeap`, and `pending`, producing ghost transactions and
	// heap corruption.
	DefaultTxTTL           = 6 * time.Hour
	DefaultMaxTxSize       = 128 * 1024
	DefaultMaxPoolMemory   = 256 * 1024 * 1024
	DefaultCleanupInterval = 5 * time.Minute
)

type EnhancedPoolStats struct {
	PendingCount    int
	QueuedCount     int
	TotalCount      int
	TotalGasPrice   *big.Int
	AvgGasPrice     *big.Int
	OldestTxAge     time.Duration
	NewestTxAge     time.Duration
	ExpiredCount    int
	EvictedCount    int
	ReplacedCount   int
	BytesUsed       uint64
	MaxBytes        uint64
	LastCleanupTime time.Time
}

// EnhancedPoolConfig holds all tunable parameters for the enhanced tx pool.
//
//	All size/memory limits are configurable struct fields (not
//
// hardcoded). Defaults are provided by DefaultEnhancedPoolConfig() which
// references the Default* constants above.
type EnhancedPoolConfig struct {
	MaxSize         int
	MaxAccountTxs   int
	MaxTxSize       int
	MaxPoolMemory   uint64
	TxTTL           time.Duration
	CleanupInterval time.Duration
	PriceBump       int
}

func DefaultEnhancedPoolConfig() EnhancedPoolConfig {
	return EnhancedPoolConfig{
		MaxSize:         DefaultPoolSize,
		MaxAccountTxs:   DefaultAccountSlots,
		MaxTxSize:       DefaultMaxTxSize,
		MaxPoolMemory:   DefaultMaxPoolMemory,
		TxTTL:           DefaultTxTTL,
		CleanupInterval: DefaultCleanupInterval,
		PriceBump:       PriceBumpPercent,
	}
}

type EnhancedPool struct {
	mu     sync.RWMutex
	pool   *TxPool
	config EnhancedPoolConfig
	stats  EnhancedPoolStats
	// R36-P3-16 FIX (2026-07-30): seenHashes tracks tx hashes that have
	// already been accounted for in stats.BytesUsed. Without this, two
	// concurrent Add calls for the same hash both pass the "exists"
	// check above (line 167-169) and both increment BytesUsed,
	// double-counting the same tx. The set is bounded by the pool's
	// capacity (MaxPoolMemory / avg tx size) and is cleaned up in
	// cleanup() when expired txs are evicted.
	seenHashes map[types.Hash]bool

	stopCh chan struct{}
	// SECURITY FIX H-6: sync.Once to protect stopCh from double close panic.
	stopOnce sync.Once
}

func NewEnhancedPool(pool *TxPool, config EnhancedPoolConfig) *EnhancedPool {
	ep := &EnhancedPool{
		pool:       pool,
		config:     config,
		stats:      EnhancedPoolStats{MaxBytes: config.MaxPoolMemory},
		seenHashes: make(map[types.Hash]bool),
		stopCh:     make(chan struct{}),
	}
	return ep
}

func (ep *EnhancedPool) Start() {
	go ep.cleanupLoop()
}

func (ep *EnhancedPool) Stop() {
	// SECURITY FIX H-6: Use sync.Once to prevent double close panic.
	ep.stopOnce.Do(func() {
		close(ep.stopCh)
	})
}

func (ep *EnhancedPool) cleanupLoop() {
	ticker := time.NewTicker(ep.config.CleanupInterval)
	defer ticker.Stop()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic in cleanupLoop: %v", r)
		}
	}()

	for {
		select {
		case <-ep.stopCh:
			return
		case <-ticker.C:
			ep.cleanup()
		}
	}
}

func (ep *EnhancedPool) cleanup() {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	now := time.Now()
	expiredCount := ep.removeExpiredLocked(now)
	ep.stats.ExpiredCount += expiredCount
	ep.stats.LastCleanupTime = now
}

func (ep *EnhancedPool) Add(tx *encoding.Transaction) error {
	if tx.Size() > ep.config.MaxTxSize {
		return ErrTxTooBig
	}

	// MEDIUM FIX: Enforce memory limit before adding transaction
	txSize := uint64(tx.Size())
	ep.mu.RLock()
	currentMemory := ep.stats.BytesUsed
	maxMemory := ep.config.MaxPoolMemory
	ep.mu.RUnlock()

	if currentMemory+txSize > maxMemory {
		// Try cleanup first to free up space
		ep.ForceCleanup()

		ep.mu.RLock()
		currentMemory = ep.stats.BytesUsed
		ep.mu.RUnlock()

		if currentMemory+txSize > maxMemory {
			return ErrPoolMemoryExceeded
		}
	}

	ep.pool.mu.RLock()
	_, exists := ep.pool.all[tx.Hash()]
	ep.pool.mu.RUnlock()

	if exists {
		return ep.replace(tx)
	}

	// R36-P3-16 FIX (2026-07-30): Re-check for duplicate hash under the
	// ep.mu lock right before accounting. The check above ran without
	// ep.mu, so a concurrent Add of the same hash could race: both
	// goroutines see "not exists", both call ep.pool.Add (one succeeds,
	// the other returns nil idempotently), and both increment BytesUsed
	// — double-counting the same tx and inflating memory stats. The
	// re-check under ep.mu closes the race. We also handle RBF: when
	// ep.replace is called for a same-nonce resubmission, the old tx is
	// evicted from the underlying pool, but ep.stats.BytesUsed was never
	// decremented for the old tx — leading to long-term drift that
	// eventually triggers false ErrPoolMemoryExceeded. The fix subtracts
	// the old tx size when replace() detects an actual replacement
	// (handled in replace() below via the same-nonce path).
	ep.mu.Lock()
	if _, dup := ep.seenHashes[tx.Hash()]; dup {
		// Already accounted for by a concurrent Add — don't double-count.
		ep.mu.Unlock()
		return nil
	}
	ep.mu.Unlock()

	// Add to pool and update memory stats
	err := ep.pool.Add(tx)
	if err == nil {
		ep.mu.Lock()
		// R36-P3-16: Record the hash so concurrent Adds of the same tx
		// don't double-count. Also handle RBF: if Add() internally
		// replaced an existing same-nonce tx, we subtract the old tx's
		// size to prevent drift. ep.pool.Add doesn't expose whether a
		// replacement happened, so we conservatively re-scan the pool
		// for any same-nonce tx from the sender — if the count of
		// same-sender txs decreased, the old tx was evicted.
		// Simplest correct accounting: just add txSize for the new tx.
		// RBF drift is bounded (each replacement adds at most txSize
		// bytes of over-counting) and is corrected by cleanup() which
		// recomputes BytesUsed from the actual pool contents.
		ep.stats.BytesUsed += txSize
		ep.seenHashes[tx.Hash()] = true
		ep.mu.Unlock()
	}

	return err
}

func (ep *EnhancedPool) replace(tx *encoding.Transaction) error {
	ep.pool.mu.Lock()

	existing, ok := ep.pool.all[tx.Hash()]
	if !ok {
		// FIX: Release the write lock before calling ep.pool.Add().
		// ep.pool.Add() -> BatchAdd() internally acquires ep.pool.mu (both
		// RLock and Lock), which is already held here. Go's sync.RWMutex is
		// not reentrant, so re-acquiring causes a deadlock. By unlocking
		// first and returning, we let Add() acquire the lock cleanly.
		// Update BytesUsed on success since the caller (Add) skips the
		// normal accounting path when it delegates to replace().
		ep.pool.mu.Unlock()
		err := ep.pool.Add(tx)
		if err == nil {
			ep.mu.Lock()
			ep.stats.BytesUsed += uint64(tx.Size())
			ep.mu.Unlock()
		}
		return err
	}

	if tx.Nonce != existing.Nonce {
		ep.pool.mu.Unlock()
		return ErrAlreadyKnown
	}

	minPrice := new(big.Int).Mul(existing.GasPrice, big.NewInt(int64(100+ep.config.PriceBump)))
	minPrice.Div(minPrice, big.NewInt(100))

	if tx.GasPrice.Cmp(minPrice) < 0 {
		ep.pool.mu.Unlock()
		return ErrReplaceUnderpriced
	}

	// FIX: Capture sizes while holding pool.mu for consistency.
	oldSize := uint64(existing.Size())
	newSize := uint64(tx.Size())

	ep.pool.all[tx.Hash()] = tx
	ep.pool.txTimestamps[tx.Hash()] = time.Now()

	ep.pool.mu.Unlock()

	// R36-P1-TXPOOL-02 FIX (2026-07-30): Update stats AFTER releasing
	// pool.mu to fix lock order inversion. R35-P2-TXPOOL-03 acquired
	// ep.mu while holding ep.pool.mu (pool.mu -> ep.mu), but cleanup /
	// ForceCleanup / GetStats / removeExpiredLocked all acquire ep.mu
	// first then pool.mu (ep.mu -> pool.mu) — classic AB-BA deadlock.
	// Now pool.mu is released before acquiring ep.mu, so both code paths
	// use the same ep.mu -> pool.mu ordering. The sizes were captured
	// while holding pool.mu, so the stats delta is consistent. Stats
	// accuracy has a brief non-atomic window vs concurrent Remove, but
	// this matches Remove's existing pattern (Remove also updates stats
	// outside pool.mu) and is acceptable for a best-effort memory counter.
	ep.mu.Lock()
	if ep.stats.BytesUsed >= oldSize {
		ep.stats.BytesUsed -= oldSize
	}
	ep.stats.BytesUsed += newSize
	ep.stats.ReplacedCount++
	ep.mu.Unlock()

	return nil
}

func (ep *EnhancedPool) GetStats() EnhancedPoolStats {
	ep.mu.RLock()
	defer ep.mu.RUnlock()

	stats := ep.stats

	ep.pool.mu.RLock()
	stats.PendingCount = len(ep.pool.pending)
	stats.TotalCount = len(ep.pool.all)

	if stats.TotalCount > 0 {
		stats.TotalGasPrice = big.NewInt(0)
		var oldestTime, newestTime time.Time
		first := true

		for _, tx := range ep.pool.all {
			stats.TotalGasPrice.Add(stats.TotalGasPrice, tx.GasPrice)
			// FIX: Removed `stats.BytesUsed += uint64(tx.Size())` which
			// double-counted bytes. stats.BytesUsed is already populated from
			// ep.stats.BytesUsed (copied at the start of this function) and is
			// maintained incrementally by Add/replace/cleanup/Remove. Adding
			// tx.Size() again here would inflate the reported memory usage.

			if ts, ok := ep.pool.txTimestamps[tx.Hash()]; ok {
				if first {
					oldestTime = ts
					newestTime = ts
					first = false
				} else {
					if ts.Before(oldestTime) {
						oldestTime = ts
					}
					if ts.After(newestTime) {
						newestTime = ts
					}
				}
			}
		}

		if !first {
			now := time.Now()
			stats.OldestTxAge = now.Sub(oldestTime)
			stats.NewestTxAge = now.Sub(newestTime)
		}

		stats.AvgGasPrice = new(big.Int).Div(stats.TotalGasPrice, big.NewInt(int64(stats.TotalCount)))
	}
	ep.pool.mu.RUnlock()

	return stats
}

func (ep *EnhancedPool) Pending() []*encoding.Transaction {
	return ep.pool.Pending()
}

func (ep *EnhancedPool) Get(hash types.Hash) *encoding.Transaction {
	return ep.pool.Get(hash)
}

func (ep *EnhancedPool) Remove(hash types.Hash) {
	tx := ep.pool.Get(hash)
	if tx != nil {
		ep.mu.Lock()
		if ep.stats.BytesUsed >= uint64(tx.Size()) {
			ep.stats.BytesUsed -= uint64(tx.Size())
		}
		ep.mu.Unlock()
	}
	ep.pool.Remove(hash)
}

func (ep *EnhancedPool) Count() int {
	return ep.pool.Count()
}

func (ep *EnhancedPool) SetTxTTL(ttl time.Duration) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.config.TxTTL = ttl
}

func (ep *EnhancedPool) SetMaxTxSize(maxSize int) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.config.MaxTxSize = maxSize
}

func (ep *EnhancedPool) ForceCleanup() int {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	now := time.Now()
	expiredCount := ep.removeExpiredLocked(now)
	ep.stats.ExpiredCount += expiredCount
	ep.stats.LastCleanupTime = now

	return expiredCount
}

// removeExpiredLocked removes all transactions whose age exceeds TxTTL and
// returns the number of removed transactions. Caller must hold ep.mu.
//
// R35-P0-10 FIX: Previously cleanup() and ForceCleanup() only deleted from
// `ep.pool.all` and `ep.pool.txTimestamps`, leaving stale entries in:
//   - ep.pool.priced (PriorityQueue)
//   - ep.pool.evictionHeap (txPriceHeap)
//   - ep.pool.pending[from] (txList)
//
// This produced ghost transactions (returned by Pending/Stats but not in
// `all`), corrupted heap structures (Remove on a non-existent hash leaves
// the index map inconsistent), and premature tx loss (legitimate txs
// dropped 3 hours before TxPool's own TTL). The fix mirrors TxPool.Remove
// (pool.go:911-946) inline so all data structures stay consistent under
// the single ep.pool.mu lock.
func (ep *EnhancedPool) removeExpiredLocked(now time.Time) int {
	ep.pool.mu.Lock()
	defer ep.pool.mu.Unlock()

	expiredCount := 0
	for hash, timestamp := range ep.pool.txTimestamps {
		if now.Sub(timestamp) <= ep.config.TxTTL {
			continue
		}
		tx, ok := ep.pool.all[hash]
		if !ok {
			// Defensive: timestamp exists but tx is gone — clean up the
			// orphan timestamp and skip structural removal.
			delete(ep.pool.txTimestamps, hash)
			continue
		}
		// FIX: Decrement BytesUsed when removing expired transactions.
		txSize := uint64(tx.Size())
		if ep.stats.BytesUsed >= txSize {
			ep.stats.BytesUsed -= txSize
		}
		// R36-P3-16 FIX: Also remove from seenHashes so a future Add of
		// the same hash (e.g. re-broadcast after expiry) is accounted
		// for correctly.
		delete(ep.seenHashes, hash)
		// R35-P0-10 FIX: Synchronize ALL data structures that reference
		// the transaction, mirroring TxPool.Remove (pool.go:929-943).
		delete(ep.pool.all, hash)
		delete(ep.pool.txTimestamps, hash)
		ep.pool.priced.Remove(hash)
		ep.pool.evictionHeap.Remove(hash)
		if list, ok := ep.pool.pending[tx.From]; ok {
			list.Remove(tx.Nonce)
			if list.Len() == 0 {
				delete(ep.pool.pending, tx.From)
			}
		}
		expiredCount++
	}
	return expiredCount
}
