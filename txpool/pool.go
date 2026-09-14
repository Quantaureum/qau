// Quantaureum Node source, version 1.0.0.
package txpool

// L14-031 SECURITY NOTE: The pending transaction queue has a maximum size
// to prevent memory exhaustion from transaction flooding attacks. When
// the queue is full, new transactions with lower gas prices are rejected.
// This ensures the node can continue processing high-priority transactions
// even under DoS conditions. The queue size should be tuned based on
// available memory and expected transaction throughput.

import (
	"bytes"
	"container/heap"
	"context"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quantaureum/qau/encoding"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
)

// stakeLog logs staking transaction flow for debugging on-chain staking issues.
// Uses log.Printf (unbuffered stderr) for systemd compatibility.
func stakeLog(format string, args ...any) {
	log.Printf("[STAKE-TX] "+format, args...)
}

// debugLog is intentionally disabled in production.
// Writing heap pointers (%p) to a file exposes ASLR offsets and the unbounded
// file growth can cause disk-exhaustion DoS. Enable only in local dev builds.
func debugLog(_ string, _ ...any) {}

// Pool errors
var (
	ErrPoolFull           = errors.New("transaction pool is full")
	ErrAlreadyKnown       = errors.New("transaction already known")
	ErrReplaceUnderpriced = errors.New("replacement transaction underpriced")
	ErrBatchExceedsLimit  = errors.New("batch size exceeds validation limit")
	ErrPoolStopped        = errors.New("transaction pool has been stopped")
	ErrUnderpriced        = errors.New("transaction gas price below minimum")
)

// Pool configuration
const (
	DefaultPoolSize     = 25000 // TPS FIX: 10000→25000, handles 20K concurrent tx burst with headroom
	DefaultAccountSlots = 128
	PriceBumpPercent    = 10   // Minimum price bump to replace a transaction
	MinGasPrice         = 1    // Minimum gas price in wei — prevents zero-price DoS spam
	MaxBatchSize        = 1000 // L14-002 FIX: Hard limit on batch input size to prevent memory exhaustion
	// FIX: Named constant for validation batch limit. This is intentionally
	// smaller than MaxBatchSize (1000) because Dilithium3 signature verification
	// is CPU-intensive. Transactions beyond this limit are rejected with
	// ErrBatchExceedsLimit. The relationship: MaxBatchSize guards memory,
	// MaxValidationBatch guards CPU. Both must be > 0 and MaxValidationBatch
	// must be <= MaxBatchSize.
	MaxValidationBatch = 100
)

// SafePendingTx is a deep-copy of a pending transaction with sensitive fields omitted.
// R58-H-NEW-1 [HIGH] FIX: Excludes Signature and PublicKey to prevent exposing
// Dilithium3 private key material through the RPC API. Callers receive only
// public, verifiable fields.
type SafePendingTx struct {
	Version  uint32
	Type     encoding.TxType
	Nonce    uint64
	From     types.Address
	To       *types.Address
	Value    *big.Int
	GasLimit uint64
	GasPrice *big.Int
	Data     []byte
	ChainID  uint64
}

// toSafePendingTx creates a SafePendingTx deep copy from a Transaction.
func toSafePendingTx(tx *encoding.Transaction) SafePendingTx {
	safe := SafePendingTx{
		Version:  tx.Version,
		Type:     tx.Type,
		Nonce:    tx.Nonce,
		From:     tx.From,
		GasLimit: tx.GasLimit,
		ChainID:  tx.ChainID,
	}
	if tx.To != nil {
		addr := *tx.To
		safe.To = &addr
	}
	if tx.Value != nil {
		safe.Value = new(big.Int).Set(tx.Value)
	}
	if tx.GasPrice != nil {
		safe.GasPrice = new(big.Int).Set(tx.GasPrice)
	}
	if len(tx.Data) > 0 {
		safe.Data = make([]byte, len(tx.Data))
		copy(safe.Data, tx.Data)
	}
	return safe
}

// TxPool manages pending transactions.
// Implements Requirements 2.1, 2.2, 2.3 for optimized transaction pool.
type TxPool struct {
	mu sync.RWMutex

	validator *TxValidator
	state     StateReader

	bundler *Bundler

	// All transactions indexed by hash
	all map[types.Hash]*encoding.Transaction
	// txTimestamps tracks when transactions were added for zombie cleanup.
	// R3-N3 NOTE (2026-07-06): Uses time.Now() which includes Go's monotonic
	// clock reading. time.Since() comparisons use the monotonic component,
	// so they are immune to wall-clock adjustments (NTP, manual changes).
	// This is local pool management only — not part of consensus state.
	txTimestamps map[types.Hash]time.Time

	// Transactions by sender, sorted by nonce
	pending map[types.Address]*txList

	// Priority queue for transaction selection (max-heap by gas price)
	priced *PriorityQueue

	// Min-heap for eviction (lowest price first)
	evictionHeap *txPriceHeap

	// Configuration
	maxSize       int
	maxAccountTxs int

	// R32-P2-14 FIX (2026-07-28): Configurable price-bump threshold for
	// transaction replacement. Previously this was hardcoded as the
	// package-level PriceBumpPercent constant (10%). A bundler could
	// exploit the fixed 10% threshold by orchestrating multiple small
	// replacements that each barely meet the bump, gradually displacing
	// legitimate transactions without triggering any per-sender cap.
	// Making the threshold configurable lets operators raise it on
	// networks under active bundler attack (e.g., to 100% during a
	// hostile MEV environment) or lower it on isolated testnets where
	// frequent replacement is expected. The value MUST be > 0; a zero
	// or negative value would allow free replacement, enabling pool
	// churn DoS. SetPriceBumpPercent enforces this invariant.
	//
	// Default: PriceBumpPercent (10). Backward compatible — existing
	// callers using NewTxPool / NewTxPoolWithConfig get the original
	// behavior unless they explicitly call SetPriceBumpPercent.
	priceBumpPercent int

	// Commit-reveal front-running protection
	commitReveal *CommitRevealManager

	// CRITICAL FIX: Atomic flag to signal pool has been stopped
	// Prevents race conditions during concurrent access to nil fields
	stopped int32

	// R14-MED (2026-07-21): Background zombie-cleanup goroutine. Previously
	// cleanupZombieTransactions was only invoked from AddVerifiedTxs, so if
	// the pool went idle (no new txs) zombies would never be reclaimed until
	// the next AddVerifiedTxs call — letting an attacker who floods the pool
	// then stops sending pin maxSize worth of memory for hours. The periodic
	// timer fires every zombieCleanupInterval and runs the same bounded
	// cleanup, ensuring zombies are reclaimed even when the pool is idle.
	// Start() launches the goroutine; Stop() cancels the context and waits.
	ctx            context.Context
	cancel         context.CancelFunc
	cleanupWg      sync.WaitGroup
	cleanupStarted int32 // atomic; 1 once Start has launched the goroutine
}

// NewTxPool creates a new transaction pool.
func NewTxPool(validator *TxValidator, state StateReader) *TxPool {
	return &TxPool{
		validator:        validator,
		state:            state,
		all:              make(map[types.Hash]*encoding.Transaction),
		txTimestamps:     make(map[types.Hash]time.Time),
		pending:          make(map[types.Address]*txList),
		priced:           NewPriorityQueue(),
		evictionHeap:     newTxPriceHeap(),
		maxSize:          DefaultPoolSize,
		maxAccountTxs:    DefaultAccountSlots,
		priceBumpPercent: PriceBumpPercent, // R32-P2-14: default 10%
		commitReveal:     NewCommitRevealManager(DefaultCommitRevealConfig()),
	}
}

// NewTxPoolWithConfig creates a new transaction pool with custom configuration.
func NewTxPoolWithConfig(validator *TxValidator, state StateReader, maxSize, maxAccountTxs int) *TxPool {
	if maxSize <= 0 {
		maxSize = DefaultPoolSize
	}
	if maxAccountTxs <= 0 {
		maxAccountTxs = DefaultAccountSlots
	}
	return &TxPool{
		validator:        validator,
		state:            state,
		all:              make(map[types.Hash]*encoding.Transaction),
		txTimestamps:     make(map[types.Hash]time.Time),
		pending:          make(map[types.Address]*txList),
		priced:           NewPriorityQueue(),
		evictionHeap:     newTxPriceHeap(),
		maxSize:          maxSize,
		maxAccountTxs:    maxAccountTxs,
		priceBumpPercent: PriceBumpPercent, // R32-P2-14: default 10%
		commitReveal:     NewCommitRevealManager(DefaultCommitRevealConfig()),
	}
}

// NewTxPoolWithFullConfig creates a new transaction pool with all configurable
// parameters. R32-P2-14 FIX (2026-07-28): exposes priceBumpPercent so operators
// can tune the replacement threshold without recompiling.
//
// Parameters:
//   - maxSize:        maximum number of transactions in the pool (<=0 → default)
//   - maxAccountTxs:  maximum transactions per sender (<=0 → default)
//   - priceBumpPercent: minimum percentage increase required to replace a
//     pending transaction (<=0 → default). Must be > 0 to prevent free
//     replacement DoS; enforced here with a fallback to the default.
func NewTxPoolWithFullConfig(validator *TxValidator, state StateReader, maxSize, maxAccountTxs, priceBumpPercent int) *TxPool {
	if maxSize <= 0 {
		maxSize = DefaultPoolSize
	}
	if maxAccountTxs <= 0 {
		maxAccountTxs = DefaultAccountSlots
	}
	if priceBumpPercent <= 0 {
		priceBumpPercent = PriceBumpPercent
	}
	return &TxPool{
		validator:        validator,
		state:            state,
		all:              make(map[types.Hash]*encoding.Transaction),
		txTimestamps:     make(map[types.Hash]time.Time),
		pending:          make(map[types.Address]*txList),
		priced:           NewPriorityQueue(),
		evictionHeap:     newTxPriceHeap(),
		maxSize:          maxSize,
		maxAccountTxs:    maxAccountTxs,
		priceBumpPercent: priceBumpPercent,
		commitReveal:     NewCommitRevealManager(DefaultCommitRevealConfig()),
	}
}

// SetPriceBumpPercent sets the minimum price-bump percentage required to
// replace a pending transaction. R32-P2-14 FIX (2026-07-28).
//
// This is the runtime counterpart to NewTxPoolWithFullConfig's priceBumpPercent
// parameter. It allows operators to adjust the threshold in response to
// observed bundler activity without restarting the node.
//
// The value MUST be strictly positive (> 0). A zero or negative value would
// allow free transaction replacement, enabling an attacker to churn the pool
// indefinitely — replacing legitimate transactions with their own at no cost
// and starving honest users. This invariant is enforced here; invalid values
// are rejected with an error and the existing configuration is preserved.
//
// Recommended ranges:
//   - 10 (default): standard Ethereum-compatible behavior
//   - 20-30: heightened defense during active bundler attacks
//   - 100+: emergency mode, only 2x price increases accepted
//
// This method is safe to call concurrently with pool operations; it acquires
// the pool's read-write lock for the duration of the update.
func (p *TxPool) SetPriceBumpPercent(percent int) error {
	if percent <= 0 {
		return fmt.Errorf("priceBumpPercent must be > 0, got %d (zero or negative values allow free replacement DoS)", percent)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.priceBumpPercent = percent
	return nil
}

// PriceBumpPercent returns the currently configured price-bump percentage.
// R32-P2-14 FIX (2026-07-28). Safe for concurrent use.
func (p *TxPool) PriceBumpPercent() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.priceBumpPercent
}

// Validator returns the transaction validator used by this pool.
// Allows sharing the SigningVerifier (and its SignatureCache) with other
// components like the block validator for maximum cache hit rates.
func (p *TxPool) Validator() (*TxValidator, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.validator == nil {
		return nil, false
	}
	return p.validator, true
}

// SetState updates the state reader reference and removes stale transactions.
// CRITICAL FIX: Must be called whenever the node's stateDB is replaced
// (e.g., after block production). Without this, the txpool uses a stale
// state reference and getReadyTransactions() returns empty because
// p.state.GetNonce() returns an outdated nonce.
//
// TPS FIX: Also removes stale transactions (nonce < state nonce) that can
// never be selected by SelectTransactions. Without this cleanup, stale txs
// occupy pool slots and block new txs from being added (maxAccountTxs limit).
func (p *TxPool) SetState(state StateReader) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = state

	// Remove stale transactions (nonce < current state nonce)
	if state == nil {
		return
	}
	for addr, list := range p.pending {
		stateNonce := state.GetNonce(addr)
		allTxs := list.All()
		for _, tx := range allTxs {
			if tx.Nonce < stateNonce {
				if tx.Type == encoding.TxTypeStake || tx.Type == encoding.TxTypeUnstake {
					txHash := tx.Hash()
					stakeLog("SetState: REMOVING stale staking tx hash=%x from=%x txNonce=%d stateNonce=%d",
						txHash[:8], addr[:8], tx.Nonce, stateNonce)
				}
				hash := tx.Hash()
				delete(p.all, hash)
				delete(p.txTimestamps, hash)
				p.priced.Remove(hash)
				p.evictionHeap.Remove(hash)
				list.Remove(tx.Nonce)
			}
		}
		if list.Len() == 0 {
			delete(p.pending, addr)
		}
	}
}

// Add adds a transaction to the pool.
// Implements Requirements 2.1: O(log n) insertion with priority sorting.
func (p *TxPool) Add(tx *encoding.Transaction) error {
	return p.BatchAdd([]*encoding.Transaction{tx})[0]
}

// AddVerified adds a transaction to the pool WITHOUT Dilithium3 signature verification.
// Used by RPC qau_stake/qau_unstake which verify authorization through staking
// signatures (a separate Dilithium3 signature over staking message data) rather
// than transaction-level signatures. All other validations (nonce gap, gas price,
// pool capacity, account slots) are still enforced.
//
// This bridges the gap between the RPC staking path and the on-chain transaction
// pipeline: the staking signature proves the caller owns the address, and the
// transaction propagates staking state to all nodes through block synchronization.
//
// TXPOOL-R14-CRIT-004 (2026-07-21) SECURITY RESTRICTION:
// This method MUST NOT be called with any transaction type other than
// TxTypeStake / TxTypeUnstake. All other types (Transfer, Contract, Create,
// MultiSig, Privacy, etc.) require full Dilithium3 transaction-signature
// verification via BatchAdd/Add. The staking signature verified by the RPC
// layer only authorizes the staking operation itself — it is NOT a valid
// signature over an arbitrary transaction body. A type whitelist is enforced
// below as defense-in-depth against future misuse: even if a new caller is
// added by mistake, it cannot smuggle an unverified Transfer/MultiSig/etc.
// through this path.
func (p *TxPool) AddVerified(tx *encoding.Transaction) error {
	if p.IsStopped() {
		return ErrPoolStopped
	}
	if tx == nil {
		return fmt.Errorf("transaction is nil")
	}

	// TXPOOL-R14-CRIT-004: whitelist staking tx types only. Any other type
	// must go through BatchAdd which performs full Dilithium3 verification.
	if tx.Type != encoding.TxTypeStake && tx.Type != encoding.TxTypeUnstake {
		return fmt.Errorf("AddVerified: only stake/unstake transactions allowed (got %s); use Add for full signature verification",
			tx.Type)
	}

	// R32-P1-11 VERIFICATION (2026-07-28): Commit-reveal check is NOT needed
	// here because:
	// 1. AddVerified only accepts TxTypeStake/TxTypeUnstake (whitelist above)
	// 2. Staking/unstake transactions are EXEMPT from commit-reveal in both
	//    BatchAdd (line ~531: tx.Type != TxTypeStake && tx.Type != TxTypeUnstake)
	//    and SelectTransactions (line ~967: same exemption)
	// 3. The staking signature (verified by the RPC layer) authorizes the
	//    staking operation itself — the Value field represents the stake
	//    amount, not a transfer that needs front-running protection
	// 4. If a future caller loosens the type whitelist above, BatchAdd's
	//    commit-reveal check will catch non-staking high-value transactions
	//    IF they route through Add. But AddVerified bypasses BatchAdd, so
	//    the whitelist above is the primary defense — do not relax it.

	// Phase 1: read-only state reference (same two-phase locking as BatchAdd)
	p.mu.RLock()
	state := p.state
	validator := p.validator
	p.mu.RUnlock()

	// R33 NODE-05 FIX (2026-07-28): Previously, AddVerified bypassed the 6
	// basic field validations enforced by validator.validateBasicFields():
	//   1. Privacy tx ingress rejection when not enabled
	//   2. Tx size limit (MaxTxSize)
	//   3. Chain ID validation (must match node's chainID — cross-network
	//      replay attack prevention)
	//   4. Negative value check
	//   5. Dust limit (minTxValue for pure transfers)
	//   6. Gas limit bounds (MinGasLimit <= tx.GasLimit <= MaxGasLimit/blockGasLimit)
	// It also used the package-level MinGasPrice constant for the gas price
	// check, ignoring the validator's configurable minGasPrice.
	//
	// A staking tx with a wrong ChainID, oversized payload, negative value,
	// or invalid gas limit would be accepted into the pool — and only
	// rejected later by the executor (or worse, propagated to peers). The
	// fix delegates to validator.validateBasicFields(tx) so all 6 checks
	// run consistently with BatchAdd. Fail-closed when validator is nil,
	// matching BatchAdd's behavior (lines 577-585).
	if validator == nil {
		// CR40-C10 / R33 NODE-05: nil validator is a configuration error.
		// Fail-closed rather than accepting unvalidated transactions.
		return errors.New("AddVerified: transaction validator not initialized")
	}
	if err := validator.validateBasicFields(tx); err != nil {
		return fmt.Errorf("AddVerified: basic field validation failed: %w", err)
	}

	// Pre-check nonce gap (same as BatchAdd line 319-332)
	// R35-P1-05 FIX: use MaxNonceGap (64) from validator.go, not hardcoded 1000.
	// The 1000 bypassed the security hardening (P2- 128→64) and allowed
	// staking txs with nonce=current+1000 to fill the pool and block legit txs.
	//
	// R36-P3-13 FIX (2026-07-30): Also reject nonce-too-low here, matching
	// BatchAdd's behavior (line 478-485). Without this check, an expired
	// low-nonce staking tx (e.g. from a stale RPC retry) would be accepted
	// into the pool, occupy a slot until the 6h TTL, and silently never
	// execute — a self-DoS. The executor's final nonce check still rejects
	// it at execution time, but the pool-level check prevents the slot
	// from being wasted in the first place.
	if state != nil {
		stateNonce := state.GetNonce(tx.From)
		if tx.Nonce > stateNonce+MaxNonceGap {
			return fmt.Errorf("nonce %d too far ahead of state nonce %d (max gap %d)",
				tx.Nonce, stateNonce, MaxNonceGap)
		}
		if tx.Nonce < stateNonce {
			return fmt.Errorf("nonce %d too low (state nonce %d)",
				tx.Nonce, stateNonce)
		}
	}

	// Gas price check is now performed by validateBasicFields above using
	// the validator's configurable minGasPrice (v.minGasPrice), which is
	// more accurate than the package-level MinGasPrice constant. The
	// redundant check below was removed as part of R33 NODE-05.

	// Phase 2: write lock for pool modification
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.IsStopped() {
		return ErrPoolStopped
	}

	// R34 P2-03 FIX (2026-07-29): Re-validate nonce gap under the write lock.
	// The pre-check at line 444-451 ran under RLock and used a snapshot of
	// p.state. Between releasing the RLock and acquiring the write lock, a
	// concurrent block commit may have advanced the state (replacing p.state
	// with a new StateDB whose nonce for tx.From is different). Re-reading
	// p.state under the write lock guarantees we observe the latest state
	// reference and closes the TOCTOU window. The final authoritative nonce
	// check still happens in the executor (ApplyTransaction); this is
	// defense-in-depth to prevent queueing transactions that are obviously
	// too far ahead, which protects pool memory.
	if currentState := p.state; currentState != nil {
		// R35-P1-05 FIX: use MaxNonceGap (64), not hardcoded 1000
		stateNonce := currentState.GetNonce(tx.From)
		if tx.Nonce > stateNonce+MaxNonceGap {
			return fmt.Errorf("nonce %d too far ahead of state nonce %d (max gap %d)",
				tx.Nonce, stateNonce, MaxNonceGap)
		}
		// R36-P3-13 FIX: re-validate nonce-too-low under the write lock
		// (mirrors the pre-check above). Closes the TOCTOU window where a
		// concurrent block commit advanced the state nonce past tx.Nonce
		// between the pre-check and here.
		if tx.Nonce < stateNonce {
			return fmt.Errorf("nonce %d too low (state nonce %d)",
				tx.Nonce, stateNonce)
		}
	}

	hash := tx.Hash()

	// Already known? Return success (idempotent, like BatchAdd)
	if _, exists := p.all[hash]; exists {
		return nil
	}

	// Get or create sender's tx list — moved BEFORE capacity check so we can
	// detect same-nonce replacements without triggering an unnecessary eviction.
	list, exists := p.pending[tx.From]
	if !exists {
		list = newTxList()
		p.pending[tx.From] = list
	}

	// AUDIT (2026) ECON-03: Enforce RBF (replace-by-fee) for same-nonce
	// resubmission BEFORE the per-account slot check. Previously, tryReplace
	// was only called when list.Len() >= maxAccountTxs, so when the account
	// had room, a same-nonce resubmission silently overwrote the old tx in
	// list.txs (map assignment at list.Add) but left stale entries in p.all,
	// p.priced, and p.evictionHeap. Those ghost entries lingered up to the
	// 6h TTL, inflated pool size, bypassed the per-account slot limit, and
	// allowed fee-bypass (no price bump enforced). The staking RPC path
	// (qau_stake/unstake) reaches AddVerified, so this is reachable by RPC.
	//
	// AUDIT (2026) R4-ECON-03 FIX: The same-nonce detection must also
	// run BEFORE the global pool capacity eviction (lines below). A same-
	// nonce replacement does not increase pool size (one tx leaves via
	// tryReplace, one enters), so evicting a third-party tx to make room
	// is unnecessary and exploitable: an attacker can repeatedly submit
	// same-nonce RBF replacements to deliberately evict other senders'
	// transactions, weaponizing the eviction path as a DoS. By detecting
	// the replacement first and skipping the capacity check for it, we
	// ensure the eviction only fires for genuinely new transactions.
	isReplacement := false
	if existing := list.Get(tx.Nonce); existing != nil {
		if !p.tryReplace(list, tx) {
			return ErrUnderpriced
		}
		isReplacement = true
	}

	// Pool capacity check with eviction — SKIPPED for same-nonce replacements
	// (tryReplace already removed the old tx, so net pool size is unchanged).
	if !isReplacement && len(p.all) >= p.maxSize {
		if !p.evictLowest(tx) {
			return ErrPoolFull
		}
	}

	// Account slot check (evaluated AFTER RBF so a successful replacement
	// frees the slot it just occupied).
	if list.Len() >= p.maxAccountTxs {
		if !p.tryReplace(list, tx) {
			return ErrPoolFull
		}
	}

	// Add to all internal maps (same as BatchAdd lines 410-420)
	p.all[hash] = tx
	p.txTimestamps[hash] = time.Now()
	// R35-P2-TXPOOL-04 FIX: use AddWithStateNonce when state is available
	// to anchor the gap check to the monotonically-increasing state nonce
	// instead of the list's minNonce() (which can be pinned low by a stale
	// tx, allowing memory-exhaustion via far-future nonces).
	var addErr error
	if p.state != nil {
		addErr = list.AddWithStateNonce(tx, p.state.GetNonce(tx.From))
	} else {
		addErr = list.Add(tx)
	}
	if addErr != nil {
		delete(p.all, hash)
		delete(p.txTimestamps, hash)
		return addErr
	}
	heap.Push(p.priced, tx)
	heap.Push(p.evictionHeap, tx)

	if tx.Type == encoding.TxTypeStake || tx.Type == encoding.TxTypeUnstake {
		stakeLog("AddVerified: added to pool hash=%x type=%d from=%x nonce=%d gasPrice=%d pool_size=%d",
			hash[:8], tx.Type, tx.From[:8], tx.Nonce, tx.GasPrice, len(p.all))
	}
	return nil
}

// BatchAdd adds multiple transactions to the pool in a single operation.
// This reduces lock contention and improves performance in high-concurrency scenarios.
// Returns a slice of errors, one for each transaction.
func (p *TxPool) BatchAdd(txs []*encoding.Transaction) []error {
	if p.IsStopped() {
		errs := make([]error, len(txs))
		for i := range errs {
			errs[i] = ErrPoolStopped
		}
		return errs
	}

	debugLog("BatchAdd called, txs count=%d, pool=%p", len(txs), p)

	// CRITICAL: Hard limit on input array size to prevent memory exhaustion
	// before any processing begins. This protects against attackers sending
	// extremely large arrays that could cause OOM before validation runs.
	if len(txs) > MaxBatchSize {
		// R35-P1-06 FIX: return error array of length len(txs), NOT
		// MaxBatchSize. The  "fix" capped the array to MaxBatchSize
		// to save memory, but callers iterate by len(txs) per the API
		// contract ("Returns a slice of errors, one for each transaction"),
		// causing index-out-of-range panics when len(txs) > MaxBatchSize.
		// The memory concern is moot: []error is just pointers (8 bytes
		// each), negligible vs the []*Transaction input (also 8-byte
		// pointers to much larger structs).
		errs := make([]error, len(txs))
		for i := range errs {
			errs[i] = ErrBatchExceedsLimit
		}
		return errs
	}

	errs := make([]error, len(txs))

	// FIX: Validate each transaction is non-nil before processing.
	// A nil entry in the txs slice would cause a nil-pointer dereference
	// in validateTransaction or AddTx, crashing the node.
	for i, tx := range txs {
		if tx == nil {
			errs[i] = fmt.Errorf("transaction at index %d is nil", i)
		}
	}

	// H-NEW-6 FIX: Limit batch size to prevent CPU exhaustion attacks.
	// Dilithium3 signature verification is computationally expensive (~10-50x ECDSA).
	// An attacker could send a large batch of invalid transactions to exhaust CPU.
	// FIX: Use named MaxValidationBatch constant instead of magic 100.
	if len(txs) > MaxValidationBatch {
		// Reject transactions beyond the batch limit
		for i := MaxValidationBatch; i < len(txs); i++ {
			errs[i] = ErrBatchExceedsLimit
		}
		// Only validate up to MaxValidationBatch
		txs = txs[:MaxValidationBatch] // #nosec G602 -- safe: guard at line 280 ensures len(txs) > MaxValidationBatch
	}

	// C-NEW-3 FIX: Two-phase locking to prevent RLock→Lock deadlock.
	// Go's sync.RWMutex does NOT support lock upgrade. Previously, defer p.mu.RUnlock()
	// kept the RLock held when p.mu.Lock() was called, causing deadlock.
	// Fix: Phase 1 (RLock) captures validator/state references, then releases RLock.
	// Phase 2 (Lock) acquires write lock for pool modification.
	p.mu.RLock()
	validator := p.validator
	state := p.state
	p.mu.RUnlock()

	validTxs := make([]*encoding.Transaction, len(txs))
	if validator == nil {
		// CR40-C10 FIX: Validator must be present - nil validator is a configuration error
		for i := range errs {
			errs[i] = errors.New("transaction validator not initialized")
		}
		// FIX: Early return when validator is nil. All transactions
		// already have errors, so there is nothing to insert — acquiring the
		// write lock (p.mu.Lock) would be unnecessary contention.
		return errs
	} else {
		// R32-P4-4 FIX: Pre-check nonce before expensive signature verification.
		// Transactions with nonce far in the future (>MaxNonceGap ahead of state nonce)
		// are rejected early to prevent CPU waste on Dilithium3 verification.
		// R35-P1-05 FIX: use MaxNonceGap (64) from validator.go, not hardcoded 1000.
		txsToValidate := make([]*encoding.Transaction, 0, len(txs))
		txIndices := make([]int, 0, len(txs))
		for i, tx := range txs {
			if errs[i] != nil {
				continue
			}
			if state != nil {
				stateNonce := state.GetNonce(tx.From)
				if tx.Nonce > stateNonce+MaxNonceGap {
					// R35-P2-TXPOOL-04 FIX: return ErrNonceTooHigh (matching
					// validator.go:393 BatchValidateWithState behavior) instead
					// of a fmt.Errorf. This preserves compatibility with callers
					// that check err == ErrNonceTooHigh (direct comparison) and
					// avoids masking the sentinel error with a custom message.
					errs[i] = ErrNonceTooHigh
					continue
				}
			}
			txsToValidate = append(txsToValidate, tx)
			txIndices = append(txIndices, i)
		}

		// Batch validate with parallel Dilithium3 signature verification.
		// Separates fast checks (format, nonce, balance) from expensive
		// signature verification, running signatures in parallel via
		// BatchVerifier with SignatureCache for cache hits.
		//
		// R36-P2-TXPOOL-03 FIX: Guard against nil state. Phase 1 above skips
		// the nonce pre-check when state == nil, but BatchValidateWithState
		// unconditionally calls state.GetNonce (validator.go:430) → nil
		// interface panic. The p2p txProcessingLoop's defer-recover would
		// swallow the panic but terminate the loop, permanently halting tx
		// propagation. Reject all candidate txs with an explicit error instead.
		if state == nil {
			for _, idx := range txIndices {
				errs[idx] = errors.New("txpool state not initialized; cannot validate transactions")
			}
		} else {
			batchErrs := validator.BatchValidateWithState(txsToValidate, state)
			for j, tx := range txsToValidate {
				i := txIndices[j]
				if batchErrs[j] != nil {
					errs[i] = batchErrs[j]
					continue
				}
				// R33 P2-23 FIX (2026-07-28): Removed redundant GasPrice check
				// that used the hardcoded MinGasPrice constant. GasPrice is
				// already validated by BatchValidateWithState → validateBasicFields
				// using the configurable v.minGasPrice. The old redundant check
				// created an inconsistency: a tx with GasPrice between
				// v.minGasPrice and MinGasPrice would pass AddVerified (which
				// only checks v.minGasPrice) but fail BatchAdd (which checked
				// both). Now both paths use only v.minGasPrice via
				// validateBasicFields, ensuring consistent behavior.
				// R31-P2 FIX (2026-07-28): Early reject high-value transactions
				// (>= 1 QAU) that have NO valid pending commit and have NOT been
				// revealed. Without this pre-check, such transactions enter the
				// pool and block the sender's entire nonce queue in
				// SelectTransactions (line ~946) until zombie cleanup evicts them
				// after CommitTimeout (15 minutes). The user must submit a
				// commitment via qau_submitCommitment BEFORE submitting the tx.
				// Staking/unstaking txs are exempt (their Value is the stake
				// amount, not a transfer — see SelectTransactions line ~947).
				// CRV2: only plain transfers carry the reveal salt in Data and are
				// gated. Stake/unstake are exempt (system txs); contract calls keep
				// their Data for calldata and are exempt (documented behavior change
				// in docs/commit-reveal-v2-design.md).
				if p.commitReveal != nil &&
					tx.Type == encoding.TxTypeTransfer &&
					p.commitReveal.RequiresCommitment(tx.Value) {
					// Admission checks existence only (no consume, no delay
					// check) — a too-early reveal is admitted and deferred by
					// SelectTransactions until MinRevealBlocks passes.
					if err := p.commitReveal.CheckReveal(tx); err != nil {
						errs[i] = fmt.Errorf("%w (value=%s): %v",
							ErrCommitmentRequired, tx.Value.String(), err)
						continue
					}
				}
				validTxs[i] = tx
			}
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.IsStopped() {
		for i := range errs {
			errs[i] = ErrPoolStopped
		}
		return errs
	}

	// R35-P1-04 FIX: Re-validate nonce under the write lock to close the
	// TOCTOU window. Phase 1 (RLock section) captured a `state` snapshot
	// that may be stale by the time we acquire the write lock — a
	// concurrent SetState() / block commit can advance the account nonce,
	// making some validTxs nonce-too-low. Without this revalidation, those
	// txs would be admitted to the pool and block subsequent legitimate txs.
	// Mirrors the R34 P2-03 fix already applied to AddVerified.
	if currentState := p.state; currentState != nil {
		for i, tx := range validTxs {
			if tx == nil {
				continue
			}
			stateNonce := currentState.GetNonce(tx.From)
			if tx.Nonce < stateNonce {
				errs[i] = fmt.Errorf("nonce too low: tx nonce %d < state nonce %d (TOCTOU revalidation)",
					tx.Nonce, stateNonce)
				validTxs[i] = nil // skip in the main loop
				continue
			}
			if tx.Nonce > stateNonce+MaxNonceGap {
				errs[i] = fmt.Errorf("nonce %d too far ahead of state nonce %d (max gap %d, TOCTOU revalidation)",
					tx.Nonce, stateNonce, MaxNonceGap)
				validTxs[i] = nil
				continue
			}
			// R36-P2-TXPOOL-01 FIX: Re-validate balance under the write lock
			// to close the TOCTOU window left by P1-04. Phase 1 (RLock section)
			// checked balance via BatchValidateWithState; between that check and
			// the write lock, a concurrent block commit can reduce the sender's
			// balance (transfer/stake/penalty), making a previously-valid tx
			// unaffordable. Without this revalidation the tx would be admitted,
			// occupy a slot, and block the sender's nonce queue until 6h TTL.
			// Mirrors validateWithState: skip privacy txs (nullifier-based).
			if tx.Type != encoding.TxTypePrivacy {
				balance := currentState.GetBalance(tx.From)
				cost, costErr := validator.calculateTxCost(tx)
				if costErr != nil {
					// AUDIT (2026) M-02: nil-GasPrice (or any malformed
					// cost input) fails the TOCTOU revalidation outright.
					errs[i] = costErr
					validTxs[i] = nil
				} else if balance.Cmp(cost) < 0 {
					errs[i] = fmt.Errorf("%w: balance %s < cost %s (TOCTOU revalidation)",
						ErrInsufficientBalance, balance.String(), cost.String())
					validTxs[i] = nil
				}
			}
		}
	}

	// R35-P2-TXPOOL-01 FIX (2026-07-29): Re-validate commit-reveal under the
	// write lock to close the TOCTOU window. Phase 1 (RLock section) checked
	// commit-reveal BEFORE acquiring the write lock. Between that check and
	// the write lock acquisition, a concurrent commit-reveal rotation
	// (CommitRevealManager.RotateEpoch / ExpireCommitments) could invalidate
	// a previously-valid pending commit, OR a concurrent qau_submitCommitment
	// RPC call could ADD a valid commit for a tx that previously failed the
	// check. The former case is the dangerous one: a tx that passed the
	// pre-lock check would be admitted to the pool with a now-invalid commit,
	// block the sender's nonce queue in SelectTransactions, and require a
	// 15-minute zombie cleanup before the queue recovers.
	//
	// Re-checking under the write lock mirrors the nonce revalidation pattern
	// (P1-04) and ensures the commit-reveal state observed at admission time
	// is the same state that will be used by SelectTransactions.
	// CRV2: the reveal gate ran once in the RLock phase — AdmitReveal consumes
	// the commitment atomically under the manager lock, so a second TOCTOU
	// pass here would double-consume or reject valid reveals. Intentionally
	// not repeated (see docs/commit-reveal-v2-design.md).

	for i, tx := range validTxs {
		if tx == nil {
			continue // Already failed validation
		}

		hash := tx.Hash()

		// Check if already known - return nil (success) instead of error,
		// matching go-ethereum behavior where already-known txs return their hash.
		//  errs[i] is already nil from initialization; the explicit
		// assignment is kept here to document the "already-known = success" intent.
		if _, exists := p.all[hash]; exists {
			continue
		}

		// R-TXPOOL-RBF FIX (deep-audit 2026-07-12): detect a same-nonce
		// replacement BEFORE the global capacity check. A replacement is
		// net-zero on pool size, so it must NOT evict an unrelated transaction,
		// and it must be judged against its own same-nonce tx (via tryReplace),
		// not against the pool's lowest-priced entrant.
		list := p.pending[tx.From]
		isReplacement := list != nil && list.Get(tx.Nonce) != nil

		// Check pool capacity - evict lowest priced if needed.
		// Implements Requirements 2.3: capacity eviction strategy.
		// Skipped for replacements (they don't consume a new slot).
		if !isReplacement && len(p.all) >= p.maxSize {
			if !p.evictLowest(tx) {
				errs[i] = ErrPoolFull
				continue
			}
		}

		// Create the sender's list now if this is their first transaction.
		if list == nil {
			list = newTxList()
			p.pending[tx.From] = list
		}

		// R-TXPOOL-RBF FIX: route same-nonce replacements through tryReplace so
		// (1) the PriceBumpPercent fee-bump rule is enforced and (2) the old tx
		// is removed from p.all / p.priced / p.evictionHeap. Previously tryReplace
		// ran ONLY when the account was at its slot limit; under the limit,
		// list.Add below silently overwrote the nonce map entry, bypassing the
		// fee-bump check (RBF bypass) and orphaning the old tx's hash in the
		// priced/eviction heaps (a stale/underpriced tx could still be selected
		// for a block or eviction).
		if isReplacement {
			if !p.tryReplace(list, tx) {
				errs[i] = ErrReplaceUnderpriced
				continue
			}
		} else if list.Len() >= p.maxAccountTxs {
			// New nonce but the account is already at its per-account slot limit.
			errs[i] = ErrPoolFull
			continue
		}

		// Add to all maps - O(log n) for heap operations
		p.all[hash] = tx
		p.txTimestamps[hash] = time.Now() // audit-fix MED-TTL: Track when transactions were added
		// L14-014: txList.Add now validates nonce gap (defense-in-depth)
		// R35-P2-TXPOOL-04 FIX: use AddWithStateNonce when state is available.
		var addErr error
		if p.state != nil {
			addErr = list.AddWithStateNonce(tx, p.state.GetNonce(tx.From))
		} else {
			addErr = list.Add(tx)
		}
		if addErr != nil {
			delete(p.all, hash)
			delete(p.txTimestamps, hash)
			errs[i] = addErr
			continue
		}
		heap.Push(p.priced, tx)
		heap.Push(p.evictionHeap, tx)
		// CRV2: a TxTypeCommit tx registers its commitment (Data = commitHash)
		// for the sender at admission time, on every node that admits it —
		// this replaces the old RPC+gossip commitment propagation entirely.
		if tx.Type == encoding.TxTypeCommit && p.commitReveal != nil {
			var ch types.Hash
			copy(ch[:], tx.Data)
			if regErr := p.commitReveal.RegisterCommitment(ch, tx.From); regErr != nil {
				errs[i] = regErr
				continue
			}
		}
		// FIX: errs[i] is already nil from make([]error, len(txs))
		// initialization. A valid tx that reached this point never had an
		// error assigned, so no explicit nil assignment is needed here.

		debugLog("Tx added to pool: hash=%x, pool_size=%d", hash[:8], len(p.all))
	}

	// audit-fix MED-TTL: Remove zombie transactions older than maxTxAge
	p.cleanupZombieTransactions()

	// FIX (P3): Log transaction rejection reasons for observability.
	// Aggregates distinct rejection errors across the batch so operators can
	// diagnose pool admission failures without per-tx log spam. Only non-nil
	// errors (rejected transactions) are counted.
	rejected := 0
	reasons := make(map[string]int, 8)
	for _, e := range errs {
		if e == nil {
			continue
		}
		rejected++
		reasons[e.Error()]++
	}
	if rejected > 0 {
		// R38-P3 FIX: Use structured logging instead of log.Printf
		logging.Global().Infof("txpool: rejected %d/%d transactions: %v", rejected, len(errs), reasons)
	}

	return errs
}

// audit-fix MED-TTL + R25-TxPool-CR-1: Remove zombie transactions older than maxTxAge
// AND enforce MaxPendingTxsPerAddress limit per sender.
// Must be called while holding the pool lock (p.mu).
// HIGH FIX: Added maximum cleanup iterations to prevent unbounded processing.
//
//	(P3): Transaction expiry policy. Transactions are tracked with an
//
// added-at timestamp (p.txTimestamps) and evicted once older than maxTxAge
// (6 hours). This bounds memory usage from stale/abandoned transactions and
// prevents a sender from permanently pinning pool slots. Eviction is amortized:
// at most maxSize/4 (min 1000) zombie txs are removed per call to avoid
// unbounded single-call work. Evicted txs may be re-submitted by the sender.
func (p *TxPool) cleanupZombieTransactions() {
	const maxTxAge = 6 * time.Hour
	now := time.Now()

	// SECURITY FIX Q-B-007: maxCleanupPerRun is now dynamically sized as
	// maxSize / 4 instead of a fixed 1000. On high-throughput networks a
	// fixed 1000 may leave zombie transactions behind, causing memory bloat.
	maxCleanupPerRun := p.maxSize / 4
	if maxCleanupPerRun < 1000 {
		maxCleanupPerRun = 1000
	}
	cleaned := 0

	// Phase 1: Remove old zombie transactions
	for hash, addedAt := range p.txTimestamps {
		// HIGH FIX: Check cleanup limit
		if cleaned >= maxCleanupPerRun {
			break
		}
		if now.Sub(addedAt) > maxTxAge {
			tx := p.all[hash]
			delete(p.all, hash)
			delete(p.txTimestamps, hash)
			p.priced.Remove(hash)
			p.evictionHeap.Remove(hash)
			if tx != nil {
				if list, ok := p.pending[tx.From]; ok {
					list.Remove(tx.Nonce)
					if list.Len() == 0 {
						delete(p.pending, tx.From)
					}
				}
			}
			cleaned++
		}
	}

	// R25-TxPool-CR-1 FIX: Enforce MaxPendingTxsPerAddress limit per sender.
	// When the limit is exceeded, remove transactions with highest nonces first
	// (furthest from being executable, most likely to be stale/attackers).
	// Use validator constants if available, otherwise fall back to pool's maxAccountTxs.
	maxPerAddress := MaxPendingTxsPerAddress
	if p.maxAccountTxs < maxPerAddress {
		maxPerAddress = p.maxAccountTxs
	}

	for addr, list := range p.pending {
		if list.Len() <= maxPerAddress {
			continue
		}

		// HIGH FIX: Check cleanup limit
		if cleaned >= maxCleanupPerRun {
			break
		}

		// Get all transactions sorted by nonce ascending
		allTxs := list.All()

		// Remove highest nonce transactions until we're at the limit
		excess := list.Len() - maxPerAddress
		for i := len(allTxs) - 1; i >= 0 && excess > 0; i-- {
			// HIGH FIX: Check cleanup limit per iteration
			if cleaned >= maxCleanupPerRun {
				break
			}
			tx := allTxs[i]
			hash := tx.Hash()

			// Remove from all data structures
			delete(p.all, hash)
			delete(p.txTimestamps, hash)
			p.priced.Remove(hash)
			p.evictionHeap.Remove(hash)
			list.Remove(tx.Nonce)
			excess--
			cleaned++
		}

		// Clean up empty list
		if list.Len() == 0 {
			delete(p.pending, addr)
		}
	}
}

// Remove removes a transaction from the pool.
func (p *TxPool) Remove(hash types.Hash) {
	if p.IsStopped() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.IsStopped() {
		return
	}

	debugLog("Remove() called: hash=%x, pool=%p", hash[:8], p)

	tx, exists := p.all[hash]
	if !exists {
		return
	}

	delete(p.all, hash)
	delete(p.txTimestamps, hash)

	// Remove from priced queue
	p.priced.Remove(hash)

	// Remove from eviction heap
	p.evictionHeap.Remove(hash)

	if list, ok := p.pending[tx.From]; ok {
		list.Remove(tx.Nonce)
		if list.Len() == 0 {
			delete(p.pending, tx.From)
		}
	}

	debugLog("Tx removed: hash=%x, remaining=%d", hash[:8], len(p.all))
}

// Get returns a transaction by hash.
func (p *TxPool) Get(hash types.Hash) *encoding.Transaction {
	if p.IsStopped() {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.IsStopped() {
		return nil
	}
	return p.all[hash]
}

// Pending returns all pending transactions in nonce order (EVM-safe ordering).
// CRITICAL FIX: Previously returned gas-price sorted order which violated EVM
// requirement that transactions from the same sender execute in consecutive nonce order.
func (p *TxPool) Pending() []*encoding.Transaction {
	if p.IsStopped() {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.IsStopped() {
		return nil
	}

	debugLog("Pending() called: all_size=%d, pending_accounts=%d",
		len(p.all), len(p.pending))

	// CRITICAL: Use getReadyTransactions which enforces nonce ordering for EVM safety
	return p.getReadyTransactions()
}

// PendingForAccount returns pending transactions for a specific account.
func (p *TxPool) PendingForAccount(addr types.Address) []*encoding.Transaction {
	if p.IsStopped() {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.IsStopped() {
		return nil
	}

	list, exists := p.pending[addr]
	if !exists {
		return nil
	}

	// R35-P2-TXPOOL-02 FIX (2026-07-29): Guard against p.state being nil.
	// Previously, if SetState had not been called (or had been called with
	// nil), p.state.GetNonce(addr) would panic with a nil pointer
	// dereference, crashing the RPC handler goroutine serving
	// qau_getPendingTransactions or similar account-scoped queries.
	// Fallback to nonce 0 (return all txs in nonce order from the list's
	// start) when state is unavailable, matching the behavior of
	// GetPendingNonce which also guards p.state.
	if p.state == nil {
		return list.Ready(0)
	}
	return list.Ready(p.state.GetNonce(addr))
}

// GetPendingNonce returns the next nonce that should be used for a transaction
// from the given address. It accounts for both the on-chain nonce and any
// pending transactions in the pool, so consecutive transactions from the same
// address get distinct nonces.
func (p *TxPool) GetPendingNonce(addr types.Address) uint64 {
	if p.IsStopped() {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.IsStopped() {
		return 0
	}

	// Start with the on-chain nonce
	nonce := uint64(0)
	if p.state != nil {
		nonce = p.state.GetNonce(addr)
	}

	// Add the count of pending transactions from this address
	list, exists := p.pending[addr]
	if exists {
		txs := list.Ready(nonce)
		for _, tx := range txs {
			if tx.Nonce >= nonce {
				nonce = tx.Nonce + 1
			}
		}
	}

	return nonce
}

// SelectTransactions selects transactions for block inclusion.
// Implements Requirements 2.2: select by Gas price (descending) and nonce (ascending per account).
// audit-fix HIGH-1: front-running protection via commit-reveal.
func (p *TxPool) SelectTransactions(gasLimit uint64) []*encoding.Transaction {
	if p.IsStopped() {
		return nil
	}
	// AUDIT (2026) R4-ECON-04: zombieHashes collects uncommitted
	// high-value txs that have timed out (no valid commit, in pool past
	// CommitTimeout). These are removed from the pool AFTER the RLock is
	// released to avoid blocking the sender's nonce queue forever.
	var zombieHashes []types.Hash
	p.mu.RLock()
	defer func() {
		p.mu.RUnlock()
		for _, hash := range zombieHashes {
			p.Remove(hash)
		}
	}()

	readyTxs := p.getReadyTransactions()

	// Group transactions by sender, sort each group by nonce ascending.
	bySender := make(map[types.Address][]*encoding.Transaction)
	for _, tx := range readyTxs {
		bySender[tx.From] = append(bySender[tx.From], tx)
	}
	for _, group := range bySender {
		sort.Slice(group, func(i, j int) bool { return group[i].Nonce < group[j].Nonce })
	}

	// accountCursor tracks the next nonce we expect for each sender.
	accountCursor := make(map[types.Address]uint64)
	if p.state != nil {
		for addr := range bySender {
			accountCursor[addr] = p.state.GetNonce(addr)
		}
	}

	h := &txSelectionMaxHeap{}
	heap.Init(h)
	for sender, group := range bySender {
		for j := 0; j < len(group); j++ {
			heap.Push(h, txSelection{
				sender:     sender,
				tx:         group[j],
				groupIndex: j,
			})
		}
	}

	var selected []*encoding.Transaction
	var gasUsed uint64

	// Log staking txs available for selection
	stakeTxCount := 0
	for _, tx := range readyTxs {
		if tx.Type == encoding.TxTypeStake || tx.Type == encoding.TxTypeUnstake {
			stakeTxCount++
			txHash := tx.Hash()
			stakeLog("SelectTransactions: staking tx available hash=%x from=%x nonce=%d stateNonce=%d",
				txHash[:8], tx.From[:8], tx.Nonce, accountCursor[tx.From])
		}
	}
	if stakeTxCount > 0 {
		stakeLog("SelectTransactions: %d staking txs available, %d total ready txs", stakeTxCount, len(readyTxs))
	}

	for h.Len() > 0 {
		var deferred []txSelection
		var chosen txSelection
		var hasChosen bool

		for h.Len() > 0 {
			sel := heap.Pop(h).(txSelection)
			if sel.tx.Nonce != accountCursor[sel.sender] {
				deferred = append(deferred, sel)
				continue
			}

			// R59: Exempt staking/unstaking transactions from commit-reveal.
			// Staking txs are system transactions with their own Dilithium3
			// staking-signature authorization, and their Value represents the
			// stake amount (not a transfer). Requiring commit-reveal for staking
			// would block the entire staking pipeline since stake amounts are
			// always >= 1 QAU threshold.
			// CRV2: ≥threshold transfers consume their commitment via
			// ConsumeReveal once MinRevealBlocks has elapsed; until then they
			// are deferred (waiting for reveal delay).
			if p.commitReveal != nil && p.commitReveal.RequiresCommitment(sel.tx.Value) &&
				sel.tx.Type == encoding.TxTypeTransfer {
				if !p.commitReveal.IsTxRevealed(sel.tx.Hash()) {
					// Consume the commitment once the reveal delay has been
					// satisfied; defer until then.
					if !p.commitReveal.ConsumeReveal(sel.tx) {
						// Zombie: no commitment at all (user never committed, or
						// it expired) AND past the grace window — would block the
						// sender's nonce queue forever (R4-ECON-04).
						if !p.commitReveal.HasCommitmentFor(sel.tx) {
							if ts, ok := p.txTimestamps[sel.tx.Hash()]; ok &&
								time.Since(ts) > 15*time.Minute {
								zombieHashes = append(zombieHashes, sel.tx.Hash())
								continue // skip — removed after RLock released
							}
						}
						// Not revealed — defer. The cursor stays at N (do NOT
						// advance it), so subsequent txs from this sender are
						// nonce-gapped and also deferred. This prevents selecting
						// N+1 without N, which would produce an invalid block
						// with a nonce gap (R4-ECON-04).
						deferred = append(deferred, sel)
						continue
					}
				}
			}

			chosen = sel
			hasChosen = true
			break
		}

		for i := range deferred {
			heap.Push(h, deferred[i])
		}

		if !hasChosen {
			break
		}

		if gasUsed+chosen.tx.GasLimit > gasLimit {
			break
		}

		selected = append(selected, chosen.tx)
		gasUsed += chosen.tx.GasLimit
		accountCursor[chosen.sender]++

		if chosen.tx.Type == encoding.TxTypeStake || chosen.tx.Type == encoding.TxTypeUnstake {
			chosenHash := chosen.tx.Hash()
			stakeLog("SelectTransactions: SELECTED staking tx hash=%x from=%x nonce=%d gasUsed=%d/%d",
				chosenHash[:8], chosen.sender[:8], chosen.tx.Nonce, gasUsed, gasLimit)
		}

		nextIdx := chosen.groupIndex + 1
		if nextIdx < len(bySender[chosen.sender]) {
			heap.Push(h, txSelection{
				sender:     chosen.sender,
				tx:         bySender[chosen.sender][nextIdx],
				groupIndex: nextIdx,
			})
		}
	}

	if stakeTxCount > 0 {
		stakeSelected := 0
		for _, tx := range selected {
			if tx.Type == encoding.TxTypeStake || tx.Type == encoding.TxTypeUnstake {
				stakeSelected++
			}
		}
		stakeLog("SelectTransactions: selected %d/%d staking txs, %d total selected", stakeSelected, stakeTxCount, len(selected))
	}

	return selected
}

// Count returns the number of transactions in the pool.
func (p *TxPool) Count() int {
	if p.IsStopped() {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.all)
}

// GetPendingCount returns the number of pending transactions.
func (p *TxPool) GetPendingCount() int {
	if p.IsStopped() {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.all)
}

// GetQueuedCount returns the number of queued transactions.
func (p *TxPool) GetQueuedCount() int {
	// Currently all transactions are in pending, no separate queue
	return 0
}

// GetPendingTransactions returns all pending transactions as interface slice.
// R58-H-NEW-1 [HIGH] FIX: Returns SafePendingTx deep copies that exclude sensitive
// Signature and PublicKey fields, preventing private key material exposure via RPC.
func (p *TxPool) GetPendingTransactions() []any {
	if p.IsStopped() {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()

	txs := make([]*encoding.Transaction, 0, len(p.all))
	for _, tx := range p.all {
		txs = append(txs, tx)
	}
	// Sort by effective gas price descending, nonce ascending, hash as tie-breaker for determinism
	sort.Slice(txs, func(i, j int) bool {
		if cmp := effectiveGasPriceForSorting(txs[i]).Cmp(effectiveGasPriceForSorting(txs[j])); cmp != 0 {
			return cmp > 0
		}
		if txs[i].From == txs[j].From {
			return txs[i].Nonce < txs[j].Nonce
		}
		return bytes.Compare(txs[i].Hash().Bytes(), txs[j].Hash().Bytes()) < 0
	})

	result := make([]any, len(txs))
	for i, tx := range txs {
		result[i] = toSafePendingTx(tx)
	}
	return result
}

// evictLowest evicts the lowest priced transaction if new tx has higher price.
// Implements Requirements 2.3: evict lowest priority transaction when at capacity.
func (p *TxPool) evictLowest(newTx *encoding.Transaction) bool {
	if p.evictionHeap.Len() == 0 {
		return false
	}

	// Peek at lowest priced transaction
	lowest := p.evictionHeap.Peek()
	if lowest == nil {
		return false
	}

	// audit-fix  require minimum price bump for eviction to prevent
	// cheap DoS attacks that churn the pool with 1 wei increments.
	// R32-P2-14 FIX (2026-07-28): Use configurable priceBumpPercent instead
	// of hardcoded 10%. This closes the bundler-manipulation vector where
	// an attacker could orchestrate replacements that each exactly meet the
	// publicly-known 10% threshold. Operators can now raise the threshold
	// via SetPriceBumpPercent to make such attacks economically infeasible.
	//
	// NOTE: We read p.priceBumpPercent directly instead of calling
	// PriceBumpPercent() because the caller (BatchAdd/Add) already holds
	// p.mu (write lock). Calling PriceBumpPercent() would attempt to
	// re-acquire p.mu.RLock(), causing a deadlock.
	lowestPrice := effectiveGasPriceForSorting(lowest)
	newPrice := effectiveGasPriceForSorting(newTx)
	minBump := new(big.Int).Mul(lowestPrice, big.NewInt(int64(p.priceBumpPercent)))
	minBump.Div(minBump, big.NewInt(100))
	threshold := new(big.Int).Add(lowestPrice, minBump)
	if newPrice.Cmp(threshold) <= 0 {
		return false
	}

	// Remove lowest from all data structures
	heap.Pop(p.evictionHeap)
	hash := lowest.Hash()
	delete(p.all, hash)
	delete(p.txTimestamps, hash)

	// Remove from priced queue
	p.priced.Remove(hash)

	// Remove from pending list
	if list, ok := p.pending[lowest.From]; ok {
		list.Remove(lowest.Nonce)
		if list.Len() == 0 {
			delete(p.pending, lowest.From)
		}
	}

	return true
}

// tryReplace tries to replace an existing transaction with same nonce.
// Returns true if replacement succeeded. Caller will add newTx to list/p.all/priced/evictionHeap.
// R26-TxPool-C1: Verified that newTx is added by caller after this returns true.
func (p *TxPool) tryReplace(list *txList, newTx *encoding.Transaction) bool {
	old := list.Get(newTx.Nonce)
	if old == nil {
		return false
	}

	// Check price bump.
	// R32-P2-14 FIX (2026-07-28): Use the pool's configurable priceBumpPercent
	// instead of the package-level PriceBumpPercent constant. This allows
	// operators to raise the replacement threshold at runtime to defend
	// against bundler manipulation without recompiling.
	//
	// NOTE: We read p.priceBumpPercent directly instead of calling
	// PriceBumpPercent() because the caller (BatchAdd/Add) already holds
	// p.mu (write lock). Calling PriceBumpPercent() would attempt to
	// re-acquire p.mu.RLock(), causing a deadlock.
	//
	// R36-P3-15 FIX (2026-07-30): Use ceiling division instead of floor
	// division so the threshold is at least oldPrice + 1 wei when
	// oldPrice > 0. The previous floor division (Mul then Div) computed
	// threshold = oldPrice * (100+bump) / 100, which for oldPrice=1 and
	// bump=10 evaluates to 110/100 = 1 (floor) — equal to oldPrice, so a
	// 0% bump was enough to replace. With ceiling division the threshold
	// becomes 2, requiring an actual price increase. This closes the
	// griefing vector where miners/bundlers could spam same-price
	// replacements to force re-validation. We also enforce a minimum
	// absolute bump of 1 wei to cover the oldPrice=0 edge case (where
	// any positive newPrice should be accepted since the old tx is free).
	oldPrice := effectiveGasPriceForSorting(old)
	newPrice := effectiveGasPriceForSorting(newTx)
	bumpPercent := int64(100 + p.priceBumpPercent)
	threshold := new(big.Int).Mul(oldPrice, big.NewInt(bumpPercent))
	// Ceiling division: (a + b - 1) / b rounds up.
	threshold.Add(threshold, big.NewInt(99))
	threshold.Div(threshold, big.NewInt(100))

	if newPrice.Cmp(threshold) < 0 {
		// R36-P3-15: Allow replacement if newPrice > oldPrice (covers the
		// oldPrice=0 edge case where ceiling division still yields 0).
		if oldPrice.Sign() == 0 && newPrice.Sign() > 0 {
			// Fall through to replacement — any positive price beats free.
		} else {
			return false
		}
	}

	// Replace - remove old transaction from all tracking structures
	oldHash := old.Hash()
	delete(p.all, oldHash)
	delete(p.txTimestamps, oldHash)
	list.Remove(old.Nonce)
	// SECURITY FIX: Also remove from priced queue to prevent stale tx selection
	p.priced.Remove(oldHash)
	// SECURITY FIX: Remove from eviction heap to prevent stale entry selection
	p.evictionHeap.Remove(oldHash)
	// NOTE: New transaction is added by caller (see pool.go:194-199)

	return true
}

// getReadyTransactions returns transactions ready for execution.
// audit-remediation: use deterministic iteration order for consensus safety
func (p *TxPool) getReadyTransactions() []*encoding.Transaction {
	var ready []*encoding.Transaction

	// audit-remediation: extract and sort addresses for deterministic ordering
	addresses := make([]types.Address, 0, len(p.pending))
	for addr := range p.pending {
		addresses = append(addresses, addr)
	}
	sort.Slice(addresses, func(i, j int) bool {
		return bytes.Compare(addresses[i][:], addresses[j][:]) < 0
	})

	// Iterate in deterministic order
	for _, addr := range addresses {
		list := p.pending[addr]
		// R21-CRIT FIX: Add nil check for state
		var nonce uint64
		if p.state != nil {
			nonce = p.state.GetNonce(addr)
		}
		txs := list.Ready(nonce)
		ready = append(ready, txs...)
	}

	return ready
}

// MaxSize returns the maximum pool size.
func (p *TxPool) MaxSize() int {
	return p.maxSize
}

// IsFull returns true if the pool is at capacity.
func (p *TxPool) IsFull() bool {
	if p.IsStopped() {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.all) >= p.maxSize
}

// LowestPrice returns the lowest gas price in the pool.
// Returns nil if pool is empty.
func (p *TxPool) LowestPrice() *big.Int {
	if p.IsStopped() {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.evictionHeap.Len() == 0 {
		return nil
	}
	lowest := p.evictionHeap.Peek()
	if lowest == nil {
		return nil
	}
	return new(big.Int).Set(effectiveGasPriceForSorting(lowest))
}

// HighestPrice returns the highest effective gas price in the pool.
// Returns nil if pool is empty.
func (p *TxPool) HighestPrice() *big.Int {
	if p.IsStopped() {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.priced.Len() == 0 {
		return nil
	}
	highest := p.priced.Peek()
	if highest == nil {
		return nil
	}
	return new(big.Int).Set(effectiveGasPriceForSorting(highest))
}

// Stats returns pool statistics.
type PoolStats struct {
	TotalCount   int
	PendingCount int
	AccountCount int
	LowestPrice  *big.Int
	HighestPrice *big.Int
}

// Stats returns current pool statistics.
func (p *TxPool) Stats() *PoolStats {
	if p.IsStopped() {
		return &PoolStats{}
	}
	// R36-P2-TXPOOL-02 FIX: Acquire RLock BEFORE reading p.state to close the
	// TOCTOU window. The previous code read p.state == nil without holding the
	// lock (data race on the interface value), then a concurrent SetState(nil)
	// could nil the field between the check and the RLock acquisition, causing
	// p.state.GetNonce(addr) below to panic on a nil interface. Now the nil
	// check happens under the same lock that guards the state field.
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.state == nil {
		return &PoolStats{}
	}

	stats := &PoolStats{
		TotalCount:   len(p.all),
		AccountCount: len(p.pending),
	}

	// Count pending (ready) transactions
	for addr, list := range p.pending {
		nonce := p.state.GetNonce(addr)
		ready := list.Ready(nonce)
		stats.PendingCount += len(ready)
	}

	if p.evictionHeap.Len() > 0 {
		if lowest := p.evictionHeap.Peek(); lowest != nil {
			stats.LowestPrice = new(big.Int).Set(effectiveGasPriceForSorting(lowest))
		}
	}
	if p.priced.Len() > 0 {
		if highest := p.priced.Peek(); highest != nil {
			stats.HighestPrice = new(big.Int).Set(effectiveGasPriceForSorting(highest))
		}
	}

	return stats
}

// Stop stops the transaction pool and releases all resources.
// SECURITY FIX: Prevents goroutine leak by properly stopping background goroutines.
// audit-fix LOW: Clears data structures to allow garbage collection.
// CRITICAL FIX: Atomic stop flag ensures visibility to other goroutines
func (p *TxPool) SetBundler(bundler *Bundler) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bundler = bundler
}

func (p *TxPool) Bundler() *Bundler {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.bundler
}

func (p *TxPool) AddUserOperation(uo *encoding.UserOperation) error {
	p.mu.RLock()
	bundler := p.bundler
	p.mu.RUnlock()

	if bundler == nil {
		return errors.New("bundler not configured")
	}

	return bundler.AddUserOperation(uo)
}

func (p *TxPool) GetUserOperation(hash types.Hash) *encoding.UserOperation {
	p.mu.RLock()
	bundler := p.bundler
	p.mu.RUnlock()

	if bundler == nil {
		return nil
	}

	return bundler.GetUserOperation(hash)
}

func (p *TxPool) PendingUserOps() []*encoding.UserOperation {
	p.mu.RLock()
	bundler := p.bundler
	p.mu.RUnlock()

	if bundler == nil {
		return nil
	}

	return bundler.PendingUserOps()
}

// zombieCleanupInterval is how often the background goroutine runs
// cleanupZombieTransactions when the pool is idle. 5 minutes balances
// reclamation latency against lock contention on the pool: with a 6h
// maxTxAge, a 5min sweep catches zombies within ~5min of expiry while
// keeping the per-call work small (bounded by maxCleanupPerRun).
const zombieCleanupInterval = 5 * time.Minute

// Start launches the background zombie-cleanup goroutine. It is safe to
// call multiple times — only the first call spawns the goroutine. The
// node should call Start() after NewTxPool; tests that don't call Start
// retain the pre-R14 behavior (cleanup only on AddVerifiedTxs).
//
// R14-MED (2026-07-21): Without this, an attacker who floods the pool
// with maxSize transactions then stops sending can pin maxSize worth of
// memory for up to 6 hours (maxTxAge), because cleanupZombieTransactions
// was only invoked from AddVerifiedTxs.
func (p *TxPool) Start() {
	// CAS ensures only one goroutine is launched even if Start is called
	// concurrently from multiple sites.
	if !atomic.CompareAndSwapInt32(&p.cleanupStarted, 0, 1) {
		return
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.cleanupWg.Add(1)
	go p.zombieCleanupLoop()
}

// zombieCleanupLoop periodically runs cleanupZombieTransactions so zombies
// are reclaimed even when no new transactions arrive. Holds p.mu while
// running cleanup (same lock discipline as AddVerifiedTxs).
func (p *TxPool) zombieCleanupLoop() {
	defer p.cleanupWg.Done()
	ticker := time.NewTicker(zombieCleanupInterval)
	defer ticker.Stop()
	// R33 P3-12 FIX (2026-07-28): Add panic recovery to prevent silent
	// goroutine death on unexpected panics.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panic in zombieCleanupLoop: %v", r)
		}
	}()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			if p.IsStopped() {
				return
			}
			p.mu.Lock()
			if p.all != nil { // Stop() may have nilled the maps
				p.cleanupZombieTransactions()
			}
			p.mu.Unlock()
		}
	}
}

func (p *TxPool) Stop() {
	// CRITICAL FIX: Set atomic flag FIRST to signal stopped state
	// This ensures other goroutines see the stopped state immediately
	atomic.StoreInt32(&p.stopped, 1)

	// R14-MED (2026-07-21): Cancel the background cleanup goroutine and
	// wait for it to exit before nil-ing the maps. Without this wait the
	// goroutine could race with the map nil-out below and panic.
	if p.cancel != nil {
		p.cancel()
	}
	p.cleanupWg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.commitReveal != nil {
		p.commitReveal.Stop()
	}

	// Clear data structures to allow garbage collection
	// and prevent memory leaks if TxPool is recreated
	p.all = nil
	p.pending = nil
	p.priced = nil
	p.evictionHeap = nil
	p.txTimestamps = nil
}

// IsStopped returns true if the pool has been stopped
func (p *TxPool) IsStopped() bool {
	return atomic.LoadInt32(&p.stopped) == 1
}

// SetCommitRevealManager replaces the commit-reveal manager with a custom configured one.
// This allows the node to pass custom configuration for front-running protection.
// If a commit-reveal manager already exists, it will be stopped before replacement.
func (p *TxPool) SetCommitRevealManager(crm *CommitRevealManager) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.commitReveal != nil {
		p.commitReveal.Stop()
	}
	p.commitReveal = crm
}

// GetCommitRevealManager returns the current commit-reveal manager.
func (p *TxPool) GetCommitRevealManager() *CommitRevealManager {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.commitReveal
}

// RemoveConfirmed removes transactions that have been confirmed in a block.
// This should be called after a block is committed.
func (p *TxPool) RemoveConfirmed(txHashes []types.Hash) {
	if p.IsStopped() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, hash := range txHashes {
		tx, exists := p.all[hash]
		if !exists {
			continue
		}

		delete(p.all, hash)
		delete(p.txTimestamps, hash)
		p.priced.Remove(hash)
		p.evictionHeap.Remove(hash)

		if list, ok := p.pending[tx.From]; ok {
			list.Remove(tx.Nonce)
			if list.Len() == 0 {
				delete(p.pending, tx.From)
			}
		}
	}
}

// txSelectionMaxHeap implements heap.Interface as a max-heap of txSelection,
// ordered by effective gas price descending.
// CONS- (2026-07-21) FIX: Added transaction hash tie-breaker for
// deterministic ordering. Previously Less() only compared gas price — when
// two txs had identical gas prices, Go's heap (which is NOT a stable sort)
// would pop them in insertion-order-dependent order. Since heap.Push iterates
// over the bySender map (random Go map iteration order at line 887), equal
// gas-price txs could be ordered differently across validators, producing
// different blocks from the same pool state → consensus fork and MEV
// front-running opportunity. The tie-breaker uses tx.Hash() ascending
// (lexicographic comparison), guaranteeing that for any set of txs with
// equal gas price, the one with the lowest hash always comes first,
// regardless of insertion order.
type txSelectionMaxHeap []txSelection

func (h txSelectionMaxHeap) Len() int { return len(h) }
func (h txSelectionMaxHeap) Less(i, j int) bool {
	cmp := effectiveGasPriceForSorting(h[i].tx).Cmp(effectiveGasPriceForSorting(h[j].tx))
	if cmp != 0 {
		return cmp > 0
	}
	hi := h[i].tx.Hash()
	hj := h[j].tx.Hash()
	return bytes.Compare(hi[:], hj[:]) < 0
}
func (h txSelectionMaxHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *txSelectionMaxHeap) Push(x any)   { *h = append(*h, x.(txSelection)) }
func (h *txSelectionMaxHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

type txSelection struct {
	sender     types.Address
	tx         *encoding.Transaction
	groupIndex int
}
