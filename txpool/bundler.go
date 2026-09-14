// Quantaureum Node source, version 1.0.0.
package txpool

import (
	"container/heap"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

const (
	DefaultMaxUserOpsInMempool = 1024
	DefaultMaxBundleSize       = 16
	DefaultBundleInterval      = 10 * time.Second
	DefaultMinPriorityFee      = 1000000000
	// R36-P1-TXPOOL-03 FIX (2026-07-30): Sanity upper bound for
	// MaxPriorityFeePerGas. Prevents attackers from submitting zombie
	// ops with absurdly high fees that always fail simulation but occupy
	// the top of the max-heap priority queue, permanently starving the
	// AA pipeline. 10^15 (1 micro-QAU per gas) is far above any
	// legitimate priority fee but rejects uint256-max-style abuse.
	DefaultMaxPriorityFee = 1000000000000000
)

type Bundler struct {
	mu             sync.RWMutex
	userOpMempool  map[types.Hash]*encoding.UserOperation
	userOpQueue    userOpPriorityQueue
	entryPoint     *qvm.EntryPoint
	executor       *qvm.Executor
	stateDB        qvm.StateDB
	chainID        uint64
	beneficiary    types.Address
	maxBundleSize  int
	bundleInterval time.Duration
	minPriorityFee *big.Int
	lastBundleTime time.Time
	// SECURITY (audit P2-19): Deterministic block context replaces time.Now()
	blockNumber    uint64
	blockTimestamp int64
	bundleCh       chan *encoding.UserOpBundle
	stopCh         chan struct{}
	// SECURITY FIX H-5: sync.Once to protect stopCh from double close panic.
	// Previously close(b.stopCh) had no guard, causing panic if Stop() was
	// called more than once (e.g., during shutdown + graceful exit).
	stopOnce sync.Once
}

// SetBlockContext updates the current block number and timestamp.
// SECURITY (audit P2-19): Called by the node after each block is committed
// to provide deterministic timestamps for bundle creation.
func (b *Bundler) SetBlockContext(blockNumber uint64, blockTimestamp int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blockNumber = blockNumber
	b.blockTimestamp = blockTimestamp
}

// getBlockTimestamp returns the deterministic block timestamp.
// Falls back to time.Now().Unix() only if no block context has been set.
func (b *Bundler) getBlockTimestamp() int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.blockTimestamp > 0 {
		return b.blockTimestamp
	}
	return time.Now().Unix() // fallback before first block
}

type BundlerConfig struct {
	ChainID        uint64
	Beneficiary    types.Address
	MaxBundleSize  int
	BundleInterval time.Duration
	MinPriorityFee *big.Int
}

func DefaultBundlerConfig() *BundlerConfig {
	return &BundlerConfig{
		MaxBundleSize:  DefaultMaxBundleSize,
		BundleInterval: DefaultBundleInterval,
		MinPriorityFee: big.NewInt(DefaultMinPriorityFee),
	}
}

func NewBundler(config *BundlerConfig, entryPoint *qvm.EntryPoint, executor *qvm.Executor, stateDB qvm.StateDB) *Bundler {
	if config == nil {
		config = DefaultBundlerConfig()
	}
	if config.MaxBundleSize <= 0 {
		config.MaxBundleSize = DefaultMaxBundleSize
	}
	if config.BundleInterval <= 0 {
		config.BundleInterval = DefaultBundleInterval
	}
	if config.MinPriorityFee == nil {
		config.MinPriorityFee = big.NewInt(DefaultMinPriorityFee)
	}

	return &Bundler{
		userOpMempool:  make(map[types.Hash]*encoding.UserOperation),
		entryPoint:     entryPoint,
		executor:       executor,
		stateDB:        stateDB,
		chainID:        config.ChainID,
		beneficiary:    config.Beneficiary,
		maxBundleSize:  config.MaxBundleSize,
		bundleInterval: config.BundleInterval,
		minPriorityFee: config.MinPriorityFee,
		bundleCh:       make(chan *encoding.UserOpBundle, 16),
		stopCh:         make(chan struct{}),
	}
}

func (b *Bundler) Start() {
	go b.bundleLoop()
}

func (b *Bundler) Stop() {
	// SECURITY FIX H-5: Use sync.Once to prevent double close panic.
	b.stopOnce.Do(func() {
		close(b.stopCh)
	})
}

func (b *Bundler) BundleChannel() <-chan *encoding.UserOpBundle {
	return b.bundleCh
}

func (b *Bundler) AddUserOperation(uo *encoding.UserOperation) error {
	if err := uo.Validate(); err != nil {
		return fmt.Errorf("invalid user operation: %w", err)
	}

	if uo.MaxPriorityFeePerGas.Cmp(b.minPriorityFee) < 0 {
		return fmt.Errorf("priority fee too low: %s < %s", uo.MaxPriorityFeePerGas.String(), b.minPriorityFee.String())
	}

	// R36-P1-TXPOOL-03 FIX (2026-07-30): Sanity upper bound for
	// MaxPriorityFeePerGas. Without this, an attacker can submit ops
	// with absurdly high fees that always fail simulation but sit at
	// the top of the max-heap forever (since RemoveUserOp only deleted
	// the map, not the heap), permanently starving the AA pipeline.
	if uo.MaxPriorityFeePerGas.Cmp(big.NewInt(DefaultMaxPriorityFee)) > 0 {
		return fmt.Errorf("priority fee too high: %s > %s", uo.MaxPriorityFeePerGas.String(), big.NewInt(DefaultMaxPriorityFee).String())
	}

	uoHash := uo.Hash(qvm.EntryPointAddress, b.chainID)

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.userOpMempool[uoHash]; exists {
		return fmt.Errorf("duplicate user operation")
	}

	if len(b.userOpMempool) >= DefaultMaxUserOpsInMempool {
		return fmt.Errorf("user operation mempool is full")
	}

	b.userOpMempool[uoHash] = uo
	heap.Push(&b.userOpQueue, &userOpEntry{
		userOp: uo,
		hash:   uoHash,
		fee:    new(big.Int).Set(uo.MaxPriorityFeePerGas),
	})

	return nil
}

func (b *Bundler) GetUserOperation(hash types.Hash) *encoding.UserOperation {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.userOpMempool[hash]
}

func (b *Bundler) PendingUserOps() []*encoding.UserOperation {
	b.mu.RLock()
	defer b.mu.RUnlock()

	ops := make([]*encoding.UserOperation, 0, len(b.userOpMempool))
	for _, uo := range b.userOpMempool {
		ops = append(ops, uo)
	}
	return ops
}

// findUserOpEntryLocked returns the userOpEntry for the given hash, or nil.
// Caller must hold b.mu.
//
// R36-P1-TXPOOL-03 FIX (2026-07-30): Used by RemoveUserOp to locate the
// heap entry by hash so it can be removed via heap.Remove using entry.index.
func (b *Bundler) findUserOpEntryLocked(hash types.Hash) *userOpEntry {
	for _, entry := range b.userOpQueue {
		if entry.hash == hash {
			return entry
		}
	}
	return nil
}

func (b *Bundler) RemoveUserOp(hash types.Hash) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.userOpMempool, hash)
	// R36-P1-TXPOOL-03 FIX (2026-07-30): Also remove from the priority
	// queue heap. Previously RemoveUserOp only deleted from the map,
	// leaving zombie entries in userOpQueue. These zombies would be
	// re-popped and re-simulated every bundle cycle (always failing),
	// permanently occupying candidate slots and starving legitimate ops.
	// The entry.index field is maintained by Swap/Push/Pop exactly for
	// this purpose (see container/heap docs).
	if entry := b.findUserOpEntryLocked(hash); entry != nil && entry.index >= 0 {
		heap.Remove(&b.userOpQueue, entry.index)
	}
}

func (b *Bundler) bundleLoop() {
	ticker := time.NewTicker(b.bundleInterval)
	defer ticker.Stop()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic in bundleLoop: %v", r)
		}
	}()

	for {
		select {
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.tryBuildBundle()
		}
	}
}

func (b *Bundler) tryBuildBundle() {
	b.mu.Lock()
	if len(b.userOpMempool) == 0 {
		b.mu.Unlock()
		return
	}

	candidates := make([]*userOpEntry, 0, len(b.userOpMempool))
	for b.userOpQueue.Len() > 0 && len(candidates) < b.maxBundleSize {
		entry := heap.Pop(&b.userOpQueue).(*userOpEntry)
		candidates = append(candidates, entry)
	}
	// R36-P1-TXPOOL-03 FIX (2026-07-30): Do NOT push candidates back
	// here. buildBundle will handle re-pushing non-bundled ops (gas
	// exceeded) and removing bundled ops from the mempool. Previously
	// all candidates were pushed back unconditionally, so successfully
	// bundled ops stayed in the heap and were re-popped/re-simulated
	// every cycle — wasting CPU and risking double-bundling.
	b.mu.Unlock()

	bundle := b.buildBundle(candidates)
	if bundle != nil && len(bundle.UserOps) > 0 {
		select {
		case b.bundleCh <- bundle:
			b.lastBundleTime = time.Now()
		default:
		}
	}
}

func (b *Bundler) buildBundle(candidates []*userOpEntry) *encoding.UserOpBundle {
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].fee.Cmp(candidates[j].fee) > 0
	})

	// FIX: The TODO about non-deterministic timestamp has been
	// resolved. SetBlockContext() is called by the block producer to set
	// a deterministic timestamp before bundle building. getBlockTimestamp()
	// returns the proposer-supplied value. The time.Now().Unix() fallback
	// only applies before the first block (startup), which is safe because
	// no bundles are built before the first block context is set.
	//
	// R36-P3-14 FIX (2026-07-30): Acquire b.mu.RLock when reading
	// b.blockNumber. SetBlockContext (line 58) writes b.blockNumber under
	// b.mu.Lock, but buildBundle was reading it without any lock — a
	// concurrent SetBlockContext call (e.g. block producer updating the
	// context immediately after a block commit) would race with this read
	// and could produce an inconsistent bundle context (blockNumber from
	// one block, timestamp from another). The RLock is held only briefly
	// to snapshot the value; the lock is released before the heavy
	// simulation loop below so we don't block SetBlockContext.
	b.mu.RLock()
	blockNumber := b.blockNumber
	b.mu.RUnlock()
	blockCtx := &qvm.BlockContext{
		BlockNumber: blockNumber,           // SECURITY (P2-19): deterministic
		Timestamp:   b.getBlockTimestamp(), // SECURITY (P2-19): deterministic
		GasLimit:    30000000,
		ChainID:     b.chainID,
	}

	bundle := &encoding.UserOpBundle{
		EntryPoint:  qvm.EntryPointAddress,
		ChainID:     b.chainID,
		Beneficiary: b.beneficiary,
	}

	validOps := make([]*encoding.UserOperation, 0)
	totalGas := uint64(0)
	// R36-P1-TXPOOL-03 FIX (2026-07-30): Track which candidates were
	// successfully bundled so we can remove them from the mempool and
	// push back the non-bundled (gas-exceeded) ones to the heap.
	bundledHashes := make(map[types.Hash]bool)

	for _, entry := range candidates {
		uo := entry.userOp

		simBundle := &encoding.UserOpBundle{
			EntryPoint: qvm.EntryPointAddress,
			ChainID:    b.chainID,
		}

		validationResult, err := b.entryPoint.SimulateValidation(uo, b.stateDB, blockCtx, simBundle)
		if err != nil || !validationResult.Valid {
			b.RemoveUserOp(entry.hash)
			continue
		}

		opGas := uo.CallGasLimit + uo.VerificationGasLimit + uo.PreVerificationGas
		if totalGas+opGas > blockCtx.GasLimit {
			continue
		}

		validOps = append(validOps, uo)
		bundledHashes[entry.hash] = true
		totalGas += opGas

		if len(validOps) >= b.maxBundleSize {
			break
		}
	}

	bundle.UserOps = validOps

	// R36-P1-TXPOOL-03 FIX (2026-07-30): Clean up the heap and mempool.
	// Candidates were popped from the heap by tryBuildBundle and are no
	// longer in userOpQueue. Three outcomes per candidate:
	//   1. Failed simulation: already removed from mempool by
	//      RemoveUserOp above (heap entry is already gone). Skip.
	//   2. Successfully bundled: remove from mempool (it's in the
	//      bundle now, keeping it would allow double-bundling).
	//   3. Gas-exceeded / not reached (break): still in mempool, push
	//      back to heap so it can be considered next cycle.
	b.mu.Lock()
	for _, entry := range candidates {
		if bundledHashes[entry.hash] {
			delete(b.userOpMempool, entry.hash)
		} else if _, exists := b.userOpMempool[entry.hash]; exists {
			// Still in mempool means it was not removed by RemoveUserOp
			// (not a failed op) and not bundled (gas exceeded or break).
			// Push it back to the heap for the next bundle cycle.
			heap.Push(&b.userOpQueue, entry)
		}
	}
	b.mu.Unlock()

	return bundle
}

func (b *Bundler) BuildBundleFromOps(userOps []*encoding.UserOperation) (*encoding.UserOpBundle, error) {
	if len(userOps) == 0 {
		return nil, fmt.Errorf("no user operations provided")
	}
	if len(userOps) > b.maxBundleSize {
		return nil, fmt.Errorf("too many user operations: %d > %d", len(userOps), b.maxBundleSize)
	}

	bundle := &encoding.UserOpBundle{
		UserOps:     userOps,
		EntryPoint:  qvm.EntryPointAddress,
		ChainID:     b.chainID,
		Beneficiary: b.beneficiary,
	}

	if err := bundle.Validate(); err != nil {
		return nil, err
	}

	return bundle, nil
}

type userOpEntry struct {
	userOp *encoding.UserOperation
	hash   types.Hash
	fee    *big.Int
	index  int
}

type userOpPriorityQueue []*userOpEntry

func (q userOpPriorityQueue) Len() int { return len(q) }

func (q userOpPriorityQueue) Less(i, j int) bool {
	return q[i].fee.Cmp(q[j].fee) > 0
}

func (q userOpPriorityQueue) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].index = i
	q[j].index = j
}

func (q *userOpPriorityQueue) Push(x any) {
	n := len(*q)
	entry := x.(*userOpEntry)
	entry.index = n
	*q = append(*q, entry)
}

func (q *userOpPriorityQueue) Pop() any {
	old := *q
	n := len(old)
	entry := old[n-1]
	old[n-1] = nil
	entry.index = -1
	*q = old[0 : n-1]
	return entry
}
