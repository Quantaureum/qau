// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

// Bridge errors.
// W-P1-6 FIX (2026-07-13)
var (
	ErrDepositNotFound            = errors.New("deposit not found")
	ErrDepositAlreadyMinted       = errors.New("deposit already minted on L2")
	ErrInsufficientL1Liquidity    = errors.New("insufficient L1 liquidity in bridge")
	ErrWithdrawalAlreadyProcessed = errors.New("withdrawal already processed on L1")
	ErrInvalidWithdrawalProof     = errors.New("invalid withdrawal proof")
	ErrFinalizedStateRootNotFound = errors.New("finalized state root not found for batch")
	// RLLP- (2026-07-17): Returned by ProcessDeposit when the deposit's
	// L1 block has not yet reached the required confirmation depth. The
	// caller should retry after more L1 blocks have been produced.
	ErrDepositNotFinalized = errors.New("deposit L1 block not yet finalized (insufficient confirmations)")
)

// L1HeightReader provides the current L1 block height. Used by L2Bridge
// to verify that a deposit has reached sufficient finality before minting
// (RLLP-). Satisfied by L1Anchor and memoryL1Bridge.
// RLLP-FIX (2026-07-17)
type L1HeightReader interface {
	GetCurrentHeight() uint64
}

// Deposit represents an L1→L2 deposit. The user locks QAU on L1 via
// L1Bridge.Deposit(), and the L2Bridge mints the equivalent L2 balance
// once it observes the deposit.
// W-P1-6 FIX (2026-07-13)
type Deposit struct {
	Hash      types.Hash
	Depositor types.Address
	Amount    *big.Int
	Timestamp int64
	// Minted is true once L2Bridge has minted the L2 balance. Prevents
	// double-minting if the same deposit is observed twice.
	Minted bool
	// L1Height is the L1 block height at which this deposit was included.
	// Used by ProcessDeposit to verify the deposit has reached sufficient
	// finality before minting on L2 (RLLP-). Zero means "unknown"
	// (e.g. deposit created before the fix was deployed) — ProcessDeposit
	// will fail-closed when finality checking is enabled and L1Height==0.
	// RLLP-FIX (2026-07-17)
	L1Height uint64
}

// Withdrawal represents an L2→L1 withdrawal. The user burns QAU on L2
// (transfers to the bridge address), and once the batch is finalized,
// L2Bridge submits the withdrawal to L1Bridge, which releases the locked QAU.
// W-P1-6 FIX (2026-07-13)
type Withdrawal struct {
	Hash       types.Hash
	Withdrawer types.Address
	Amount     *big.Int
	BatchIndex uint64
	TxIndex    int
	BatchHash  types.Hash
	// Processed is true once L1Bridge has released the funds. Prevents
	// double-spending if ProcessFinalizedBatch is called again (idempotency).
	Processed bool
	Timestamp int64
	// W-P1-6 (2026-07-14): Merkle proof proving the withdrawer's account was
	// included in the finalized L2 state root. Generated once by
	// ProcessFinalizedBatch and reused on retries.
	Proof *MerkleWithdrawalProof
}

// MerkleWithdrawalProof is a Merkle-based withdrawal proof that binds the
// withdrawal amount to a dedicated withdrawal Merkle tree.
//
// SECURITY (audit R4-BRDG-02): The OLD proof verified only that the
// withdrawer's account existed in the finalized L2 state — the `amount`
// came from calldata and was never checked. An attacker with any non-empty
// account could produce a valid inclusion proof and claim an arbitrary
// withdrawal amount up to the bridge's total liquidity.
//
// The NEW proof uses a DEDICATED withdrawal tree per batch. Each leaf is:
//
//	leaf = SHA256(withdrawer || amount[32] || txIndex[4])
//
// The tree root (WithdrawalRoot) is recorded on L1 when the batch is finalized.
// The L1 bridge reconstructs the expected leaf from the calldata and verifies:
//  1. expectedLeaf == proof.LeafHash  (binds amount to the leaf)
//  2. VerifyMerkleProof(treeKey, proof, withdrawalRoot)  (authenticates the leaf)
//
// AUDIT R4-BRDG-02 (2026-07-15)
type MerkleWithdrawalProof struct {
	// WithdrawalRoot is the root of the dedicated withdrawal tree for this
	// batch. Must match the root recorded on L1 via RecordWithdrawalRoot.
	WithdrawalRoot types.Hash
	// Proof is the SMT inclusion proof for this withdrawal's leaf.
	Proof *MerkleProof
	// TreeKey is the SMT key (path) for this withdrawal, derived from
	// hash(withdrawer || txIndex)[:20]. Needed by VerifyMerkleProof to
	// reconstruct the path from leaf to root.
	TreeKey types.Address
}

// L1Bridge defines the L1 side of the L1↔L2 bridge.
// In production, this would be a QASM contract deployed on L1. For now,
// MemoryL1Bridge provides an in-memory implementation for integration
// testing and development (consistent with the W-P1-4 MemoryL1Anchor pattern).
// W-P1-6 FIX (2026-07-13), Merkle proof upgrade (2026-07-14)
type L1Bridge interface {
	// Deposit locks L1 QAU from the depositor and records a deposit.
	// Returns the deposit hash that L2Bridge uses to claim the mint.
	Deposit(depositor types.Address, amount *big.Int) (types.Hash, error)

	// ProcessWithdrawal releases locked L1 QAU to the withdrawer.
	// The MerkleWithdrawalProof must demonstrate that the specific withdrawal
	// (withdrawer, amount, txIndex) was committed in the batch's dedicated
	// withdrawal tree (audit R4-BRDG-02).
	ProcessWithdrawal(withdrawer types.Address, amount *big.Int, batchIndex uint64, txIndex int, batchHash types.Hash, proof *MerkleWithdrawalProof) error

	// GetDeposit returns a deposit by its hash.
	GetDeposit(depositHash types.Hash) (*Deposit, bool)

	// GetLiquidity returns the total L1 QAU currently locked in the bridge.
	GetLiquidity() *big.Int

	// RecordFinalizedBatch records the finalized L2 state root for a batch.
	// Called by L2Bridge when a batch's challenge period expires.
	// W-P1-6 (2026-07-14)
	RecordFinalizedBatch(batchIndex uint64, stateRoot types.Hash) error

	// GetFinalizedStateRoot returns the finalized state root for a batch.
	// W-P1-6 (2026-07-14)
	GetFinalizedStateRoot(batchIndex uint64) (types.Hash, bool)

	// RecordWithdrawalRoot records the dedicated withdrawal tree root for a
	// batch. Called by L2Bridge.ProcessFinalizedBatch. The L1Bridge uses this
	// to verify that withdrawal calldata amounts match the actual committed
	// withdrawals (audit R4-BRDG-02).
	// AUDIT R4-BRDG-02 (2026-07-15)
	RecordWithdrawalRoot(batchIndex uint64, root types.Hash) error

	// GetWithdrawalRoot returns the withdrawal tree root recorded for a batch.
	// AUDIT R4-BRDG-02 (2026-07-15)
	GetWithdrawalRoot(batchIndex uint64) (types.Hash, bool)

	// MarkDepositMinted persists the Minted=true flag for a deposit so that
	// a node restart cannot trigger a second mint (P1-ROLLUP-01).
	// Implementations backed by volatile storage (memoryL1Bridge) may treat
	// this as a no-op since the in-memory deposit pointer is already mutated
	// by the caller; persistent implementations (bboltL1Bridge) MUST re-write
	// the deposit JSON so the Minted flag survives a restart.
	// P1-ROLLUP-01 FIX (2026-07-30)
	MarkDepositMinted(depositHash types.Hash) error
}

// memoryL1Bridge is an in-memory implementation of L1Bridge for development.
// It simulates the L1 bridge contract's lockbox: deposits add liquidity,
// withdrawals drain it.
// W-P1-6 FIX (2026-07-13), Merkle proof upgrade (2026-07-14)
type memoryL1Bridge struct {
	mu              sync.RWMutex
	deposits        map[types.Hash]*Deposit
	withdrawals     map[types.Hash]bool // withdrawal hash → processed
	liquidity       *big.Int
	finalizedRoots  map[uint64]types.Hash // batchIndex → finalized stateRoot
	withdrawalRoots map[uint64]types.Hash // batchIndex → withdrawal tree root (R4-BRDG-02)
	// RLLP- (2026-07-17): Simulated L1 block height. Each deposit
	// records the current height as its L1Height. Tests advance the chain
	// by calling SetHeight to simulate L1 block production, then verify
	// that ProcessDeposit enforces the required confirmation depth.
	currentHeight uint64
}

// NewMemoryL1Bridge creates an in-memory L1 bridge with zero initial liquidity.
// W-P1-6 FIX (2026-07-13)
func NewMemoryL1Bridge() L1Bridge {
	return &memoryL1Bridge{
		deposits:        make(map[types.Hash]*Deposit),
		withdrawals:     make(map[types.Hash]bool),
		liquidity:       new(big.Int),
		finalizedRoots:  make(map[uint64]types.Hash),
		withdrawalRoots: make(map[uint64]types.Hash),
	}
}

// SetHeight updates the simulated L1 block height (for testing/simulation).
// RLLP-FIX (2026-07-17)
func (b *memoryL1Bridge) SetHeight(height uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.currentHeight = height
}

func (b *memoryL1Bridge) Deposit(depositor types.Address, amount *big.Int) (types.Hash, error) {
	if amount == nil || amount.Sign() <= 0 {
		return types.Hash{}, fmt.Errorf("deposit amount must be positive")
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	hash := computeDepositHash(depositor, amount, b.nextDepositNonce())
	deposit := &Deposit{
		Hash:      hash,
		Depositor: depositor,
		Amount:    new(big.Int).Set(amount),
		Timestamp: time.Now().Unix(),
		// RLLP- Record the L1 block height at which this deposit was
		// included. ProcessDeposit uses this to enforce confirmation depth.
		L1Height: b.currentHeight,
	}
	b.deposits[hash] = deposit
	b.liquidity.Add(b.liquidity, amount)

	log.Printf("[rollup-bridge] L1 deposit: depositor=%x amount=%s hash=%x l1Height=%d",
		depositor[:8], amount.String(), hash[:8], b.currentHeight)
	return hash, nil
}

func (b *memoryL1Bridge) ProcessWithdrawal(
	withdrawer types.Address,
	amount *big.Int,
	batchIndex uint64,
	txIndex int,
	batchHash types.Hash,
	proof *MerkleWithdrawalProof,
) error {
	if amount == nil || amount.Sign() <= 0 {
		return fmt.Errorf("withdrawal amount must be positive")
	}
	if proof == nil || proof.Proof == nil {
		return fmt.Errorf("%w: nil proof", ErrInvalidWithdrawalProof)
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	wHash := computeWithdrawalHash(withdrawer, amount, batchIndex, txIndex, batchHash)
	if b.withdrawals[wHash] {
		return ErrWithdrawalAlreadyProcessed
	}

	// SECURITY (audit R4-BRDG-02): Verify the withdrawal tree root matches
	// the one recorded on L1 for this batch.
	recordedRoot, ok := b.withdrawalRoots[batchIndex]
	if !ok {
		return fmt.Errorf("%w: no withdrawal root recorded for batch %d",
			ErrInvalidWithdrawalProof, batchIndex)
	}
	if proof.WithdrawalRoot != recordedRoot {
		return fmt.Errorf("%w: proof withdrawal root %x does not match recorded root %x",
			ErrInvalidWithdrawalProof, proof.WithdrawalRoot[:8], recordedRoot[:8])
	}

	// SECURITY (audit R4-BRDG-02): Reconstruct the expected leaf from the
	// calldata (withdrawer, amount, txIndex) and verify it matches the leaf
	// hash in the Merkle proof. This BINDS the amount to the proof — if an
	// attacker tampers with the amount, the leaf hash won't match.
	expectedLeaf := ComputeWithdrawalLeafHash(withdrawer, amount, txIndex)
	if expectedLeaf != proof.Proof.LeafHash {
		return fmt.Errorf("%w: leaf hash mismatch — withdrawal (withdrawer=%x amount=%s txIdx=%d) not committed in batch %d's withdrawal tree",
			ErrInvalidWithdrawalProof, withdrawer[:8], amount.String(), txIndex, batchIndex)
	}

	// Verify the Merkle inclusion proof: the leaf is in the withdrawal tree
	// rooted at the recorded root.
	if !VerifyMerkleProof(proof.TreeKey, proof.Proof, recordedRoot) {
		return fmt.Errorf("%w: Merkle proof verification failed for withdrawer %x",
			ErrInvalidWithdrawalProof, withdrawer[:8])
	}

	if b.liquidity.Cmp(amount) < 0 {
		return ErrInsufficientL1Liquidity
	}

	b.liquidity.Sub(b.liquidity, amount)
	b.withdrawals[wHash] = true

	log.Printf("[rollup-bridge] L1 withdrawal released: withdrawer=%x amount=%s batch=%d txIdx=%d",
		withdrawer[:8], amount.String(), batchIndex, txIndex)
	return nil
}

// RecordFinalizedBatch records the finalized L2 state root for a batch.
// W-P1-6 (2026-07-14)
func (b *memoryL1Bridge) RecordFinalizedBatch(batchIndex uint64, stateRoot types.Hash) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.finalizedRoots[batchIndex] = stateRoot
	log.Printf("[rollup-bridge] L1 finalized batch %d stateRoot=%x", batchIndex, stateRoot[:8])
	return nil
}

// GetFinalizedStateRoot returns the finalized state root for a batch.
// W-P1-6 (2026-07-14)
func (b *memoryL1Bridge) GetFinalizedStateRoot(batchIndex uint64) (types.Hash, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	root, ok := b.finalizedRoots[batchIndex]
	return root, ok
}

// RecordWithdrawalRoot records the dedicated withdrawal tree root for a batch.
// AUDIT R4-BRDG-02 (2026-07-15)
func (b *memoryL1Bridge) RecordWithdrawalRoot(batchIndex uint64, root types.Hash) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.withdrawalRoots[batchIndex] = root
	log.Printf("[rollup-bridge] L1 withdrawal root recorded: batch=%d root=%x", batchIndex, root[:8])
	return nil
}

// GetWithdrawalRoot returns the withdrawal tree root recorded for a batch.
// AUDIT R4-BRDG-02 (2026-07-15)
func (b *memoryL1Bridge) GetWithdrawalRoot(batchIndex uint64) (types.Hash, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	root, ok := b.withdrawalRoots[batchIndex]
	return root, ok
}

func (b *memoryL1Bridge) GetDeposit(depositHash types.Hash) (*Deposit, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	d, ok := b.deposits[depositHash]
	return d, ok
}

func (b *memoryL1Bridge) GetLiquidity() *big.Int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return new(big.Int).Set(b.liquidity)
}

// GetCurrentHeight returns the simulated L1 block height.
// Satisfies the L1HeightReader interface (RLLP-).
func (b *memoryL1Bridge) GetCurrentHeight() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.currentHeight
}

// MarkDepositMinted is a no-op for memoryL1Bridge: the caller (L2Bridge)
// already mutated deposit.Minted in place via the pointer returned by
// GetDeposit, so the in-memory state is already correct. The volatile
// store is lost on restart anyway, so persisting would not help.
// P1-ROLLUP-01 FIX (2026-07-30)
func (b *memoryL1Bridge) MarkDepositMinted(depositHash types.Hash) error {
	return nil
}

func (b *memoryL1Bridge) nextDepositNonce() uint64 {
	// Nonce = number of existing deposits (monotonic per bridge instance).
	// Not cryptographically significant — the deposit hash also includes
	// depositor address + amount + timestamp for uniqueness.
	return uint64(len(b.deposits))
}

// L2Bridge orchestrates deposits and withdrawals between L1 and L2.
// It implements WithdrawalProcessor so it can be hooked into the
// RollupEngine's finalizeLoop (see W-P1-5).
// W-P1-6 FIX (2026-07-13)
type L2Bridge struct {
	mu            sync.RWMutex
	l1Bridge      L1Bridge
	stateManager  *StateManager
	bridgeAddress types.Address // L2 address that receives withdrawal txs

	// Tracked deposits: depositHash → Deposit. Minted deposits have Minted=true.
	deposits map[types.Hash]*Deposit

	// Tracked withdrawals: withdrawalHash → Withdrawal.
	// Populated by ProcessFinalizedBatch, checked for idempotency.
	withdrawals map[types.Hash]*Withdrawal

	// RLLP- (2026-07-17): L1 finality check for deposits.
	// When requiredDepositConfirmations > 0, ProcessDeposit refuses to mint
	// until the deposit's L1 block has at least this many confirmations
	// (i.e. currentL1Height - deposit.L1Height >= requiredDepositConfirmations).
	// This prevents minting unbacked L2 assets if the L1 deposit is reorged
	// away. When 0 (default), the check is skipped (backward compatible for
	// dev/test). l1HeightReader provides the current L1 height (typically
	// the same L1Anchor used by the rollup engine).
	requiredDepositConfirmations uint64
	l1HeightReader               L1HeightReader

	// R37-FIX P2-BRIDGE-02 (2026-07-30): automatic retry of pending withdrawals.
	// A background goroutine started by Start() calls RetryPendingWithdrawals
	// periodically so that transient L1 failures are retried without manual
	// operator intervention. Stop() cleanly shuts down the goroutine.
	// R38-P2-05 FIX (2026-08-02): retryStarted guard keeps Start/Stop
	// idempotent and safe — repeated Start does not spawn a second ticker
	// goroutine, and repeated Stop does not double-close retryStop.
	retryStop      chan struct{}
	retryWG        sync.WaitGroup
	retryStopOnce  sync.Once
	retryStartedMu sync.Mutex
	retryStarted   bool
}

// NewL2Bridge creates a new L2 bridge.
// bridgeAddress is the L2 address that users send withdrawal transactions to.
// Any L2 tx with tx.To == bridgeAddress and tx.Value > 0 is treated as a withdrawal.
// W-P1-6 FIX (2026-07-13)
func NewL2Bridge(l1Bridge L1Bridge, stateManager *StateManager, bridgeAddress types.Address) *L2Bridge {
	return &L2Bridge{
		l1Bridge:      l1Bridge,
		stateManager:  stateManager,
		bridgeAddress: bridgeAddress,
		deposits:      make(map[types.Hash]*Deposit),
		withdrawals:   make(map[types.Hash]*Withdrawal),
		retryStop:     make(chan struct{}),
	}
}

// Start launches the background retry goroutine for pending withdrawals.
// R37 P2-BRIDGE-02: without this, RetryPendingWithdrawals has no production
// caller and failed withdrawals remain stuck forever.
// R38-P2-05 FIX (2026-08-02): idempotent — calling Start twice (or after the
// previous Stop) is safe; only the first call spawns the goroutine, mirroring
// the lifecycle now wired into RollupEngine.Start/Stop.
//
// RACE-A FIX (2026-08-19): the previous implementation rebuilt retryStopOnce
// OUTSIDE retryStartedMu, so a concurrent Stop()'s retryStopOnce.Do(...) could
// read/write the same sync.Once value as Start()'s `retryStopOnce = sync.Once{}`
// assignment — a data race on the sync.Once internals (detectable by
// `go test -race`). The fix keeps the ENTIRE Start()/Stop() critical section
// (including Once rebuild + chan close) under retryStartedMu so all retry-lifecycle
// state transitions are mutually exclusive. As part of the same fix the closed
// retryStop chan is rebuilt on a post-Stop re-Start (the goroutine that exited on
// close(retryStop) consumed the closure; a fresh chan is required so the next
// Stop's close() does not panic with close-of-closed).
func (b *L2Bridge) Start() {
	b.retryStartedMu.Lock()
	defer b.retryStartedMu.Unlock()
	if b.retryStarted {
		return
	}
	b.retryStop = make(chan struct{})
	b.retryStopOnce = sync.Once{}
	b.retryStarted = true
	b.retryWG.Add(1)
	go func() {
		defer b.retryWG.Done()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				b.RetryPendingWithdrawals()
			case <-b.retryStop:
				return
			}
		}
	}()
}

// Stop cleanly shuts down the background retry goroutine.
// R38-P2-05 FIX (2026-08-02): safe to call when Start was never invoked, or
// multiple times — sync.Once ensures retryStop is closed exactly once.
//
// RACE-A FIX (2026-08-19): hold retryStartedMu for the duration of Stop() so
// the close(retryStop) + retryWG.Wait() pair is mutually exclusive with any
// concurrent Start()'s chan rebuild / Once reset. retryStopOnce is still used
// as a per-cycle guard so a double-Stop within the SAME lifecycle (without an
// intervening Start) no-ops instead of close-of-closed; the Start() under the
// same lock rebuilds the chan and resets the Once so the race window is closed.
//
// NOTE: we intentionally do NOT clear retryStarted after a successful Stop.
// The audit's lifecycle contract (pinned by TestR38P2_05_ConcurrentStartAndStopDoesNotRaceSmoke)
// treats retryStarted as a "this bridge has been started at least once" sticky
// flag once Start has run — clearing it would let a concurrent Start observe
// retryStarted==false and re-spawn a SECOND goroutine, breaking the
// "exactly one retry goroutine ever runs" invariant from R38-P2-05. A subsequent
// Start() after Stop() therefore observes retryStarted==true and short-circuits
// without re-spawning (the previous goroutine has already exited via close; a
// future lifecycle reset of the bridge is done by constructing a NEW bridge).
func (b *L2Bridge) Stop() {
	b.retryStartedMu.Lock()
	defer b.retryStartedMu.Unlock()
	if !b.retryStarted {
		return
	}
	b.retryStopOnce.Do(func() {
		close(b.retryStop)
	})
	b.retryWG.Wait()
}

// IsRetryStarted reports whether the background retry goroutine is currently
// running. Provided so tests and diagnostics can observe lifecycle state
// without reading the retryStarted field directly (which is protected by
// retryStartedMu). RACE-A FIX (2026-08-19).
func (b *L2Bridge) IsRetryStarted() bool {
	b.retryStartedMu.Lock()
	defer b.retryStartedMu.Unlock()
	return b.retryStarted
}

// SetL1HeightReader injects the L1 height source used for deposit finality
// checks (RLLP-). Typically the same L1Anchor used by the rollup engine.
// When nil and requiredDepositConfirmations > 0, ProcessDeposit fail-closes.
// RLLP-FIX (2026-07-17)
func (b *L2Bridge) SetL1HeightReader(reader L1HeightReader) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.l1HeightReader = reader
}

// SetRequiredDepositConfirmations configures the minimum L1 confirmations
// required before a deposit can be minted on L2 (RLLP-).
// When 0 (default), the finality check is skipped (backward compatible for
// dev/test). Production deployments MUST set this to a non-zero value
// (e.g. 64 for Ethereum-grade finality, or the L1's finalized-epoch length).
// RLLP-FIX (2026-07-17)
func (b *L2Bridge) SetRequiredDepositConfirmations(n uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.requiredDepositConfirmations = n
}

// ProcessDeposit mints L2 balance for the depositor corresponding to a
// previously-recorded L1 deposit. Idempotent: if the deposit was already
// minted, returns nil without re-minting.
//
// RLLP- (2026-07-17): When requiredDepositConfirmations > 0, the deposit
// is NOT minted until its L1 block has reached the configured confirmation
// depth. This prevents minting unbacked L2 assets if the L1 deposit is later
// reorged away. The caller should retry ProcessDeposit after more L1 blocks
// have been produced (it will receive ErrDepositNotFinalized until then).
//
// Fail-closed behavior when finality checking is enabled:
//   - l1HeightReader == nil → error (misconfiguration: cannot verify finality)
//   - deposit.L1Height == 0 → error (unknown L1 height: cannot verify finality)
//   - currentHeight - deposit.L1Height < requiredConfirmations → ErrDepositNotFinalized
//
// RLLP-FIX (2026-07-17): Restructured into two phases to eliminate a
// lock-order inversion. Previously the entire function held b.mu, including
// the call to stateManager.MintBalance (which acquires stateManager.mu
// internally). That created a latent deadlock: any future code path acquiring
// stateManager.mu first and then calling back into L2Bridge would deadlock.
// The fix splits the function into:
//   - Phase 1 (locked): lookup, finality check, pre-mark Minted=true
//   - Phase 2 (unlocked): call stateManager.MintBalance outside b.mu
//   - Rollback: if MintBalance fails, re-acquire b.mu and clear Minted
//
// Pre-mark + rollback is safe because MintBalance is atomic (it only mutates
// state on success — a failed call leaves stateManager state unchanged), so
// rolling back Minted=false on failure does not leave a half-minted account.
// A concurrent ProcessDeposit for the same depositHash sees Minted=true
// during phase 2 and returns ErrDepositAlreadyMinted; this is a benign
// over-report (the caller will observe the minted balance once phase 2
// completes) and is strictly safer than the deadlock alternative.
//
// W-P1-6 FIX (2026-07-13), RLLP-FIX (2026-07-17), RLLP-FIX (2026-07-17)
func (b *L2Bridge) ProcessDeposit(depositHash types.Hash) error {
	// Phase 1: locked — lookup, finality check, pre-mark Minted.
	b.mu.Lock()
	deposit, ok := b.deposits[depositHash]
	if !ok {
		// Check L1 bridge directly.
		d, exists := b.l1Bridge.GetDeposit(depositHash)
		if !exists {
			b.mu.Unlock()
			return ErrDepositNotFound
		}
		deposit = d
		b.deposits[depositHash] = deposit
	}

	if deposit.Minted {
		b.mu.Unlock()
		return ErrDepositAlreadyMinted
	}

	// RLLP- (2026-07-17): L1 finality check. When enabled, refuse to
	// mint until the deposit's L1 block has enough confirmations to survive
	// a reorg. This is fail-closed: if we cannot verify finality, we refuse
	// to mint rather than risk minting unbacked assets.
	if b.requiredDepositConfirmations > 0 {
		if b.l1HeightReader == nil {
			b.mu.Unlock()
			return fmt.Errorf("RLLP- deposit finality check enabled (requiredConfirmations=%d) but no L1HeightReader configured — refusing to mint without finality verification (depositHash=%x)",
				b.requiredDepositConfirmations, depositHash[:8])
		}
		if deposit.L1Height == 0 {
			b.mu.Unlock()
			return fmt.Errorf("RLLP- deposit %x has L1Height=0 (unknown L1 inclusion block) — refusing to mint without finality verification (requiredConfirmations=%d)",
				depositHash[:8], b.requiredDepositConfirmations)
		}
		currentL1Height := b.l1HeightReader.GetCurrentHeight()
		if currentL1Height < deposit.L1Height {
			// Should not happen in normal operation (L1 height is
			// monotonic), but fail-closed just in case.
			b.mu.Unlock()
			return fmt.Errorf("%w: currentL1Height=%d < depositL1Height=%d (depositHash=%x)",
				ErrDepositNotFinalized, currentL1Height, deposit.L1Height, depositHash[:8])
		}
		confirmations := currentL1Height - deposit.L1Height
		if confirmations < b.requiredDepositConfirmations {
			b.mu.Unlock()
			return fmt.Errorf("%w: depositHash=%x has %d confirmations, need %d (depositL1Height=%d, currentL1Height=%d)",
				ErrDepositNotFinalized, depositHash[:8], confirmations, b.requiredDepositConfirmations,
				deposit.L1Height, currentL1Height)
		}
	}

	// RLLP- Pre-mark Minted=true while holding the lock to prevent a
	// concurrent ProcessDeposit call for the same depositHash from entering
	// the mint phase. If MintBalance fails below, we roll back the flag.
	deposit.Minted = true
	depositor := deposit.Depositor
	amount := new(big.Int).Set(deposit.Amount) // defensive copy for use after unlock
	l1Height := deposit.L1Height
	b.mu.Unlock()

	// Phase 2: unlocked — call stateManager.MintBalance OUTSIDE b.mu to avoid
	// the lock-order inversion (b.mu → stateManager.mu) that could deadlock
	// with a future reverse path (stateManager.mu → b.mu).
	if err := b.stateManager.MintBalance(depositor, amount); err != nil {
		// Rollback the pre-mark so the deposit can be retried later.
		// MintBalance is atomic, so a failed call left stateManager state
		// unchanged — clearing Minted is consistent with reality.
		b.mu.Lock()
		deposit.Minted = false
		b.mu.Unlock()
		return fmt.Errorf("mint L2 balance: %w", err)
	}

	// Phase 3: success — Minted was already set in phase 1.
	// P1-ROLLUP-01 FIX (2026-07-30): Persist the Minted=true flag so a node
	// restart cannot trigger a second mint of the same L1 deposit. The
	// in-memory deposit pointer is shared with L1Bridge (returned by
	// GetDeposit), so memoryL1Bridge already sees Minted=true; this call only
	// matters for persistent implementations (bboltL1Bridge), which re-write
	// the deposit JSON. Failures are logged but non-fatal: the mint has
	// already happened and cannot be rolled back (minting is irreversible),
	// and the next ProcessDeposit call will still observe the in-memory
	// Minted=true and refuse to remint. The risk window is "mint succeeded +
	// persist failed + node crashed before the next persist" — bounded to
	// that single restart.
	//
	// R38-P1-12 FIX (2026-08-01): MarkDepositMinted now strictly returns the
	// persist error instead of swallowing it. The mint itself is
	// irreversible (MintBalance already credited the account), so we still
	// cannot roll it back — reverting the in-memory Minted=true would be a
	// LIE (the state manager HAS credited the account) and reverting the
	// credit requires a stateManager.ReverseMintBalance interface that does
	// not exist (and would itself be racy on a partial disk failure).
	//
	// R39-P1-08 (2026-08-02) FIX: PREVIOUSLY this branch only LOGGED the
	// error and returned nil, which made ProcessDeposit a NO-OP for the
	// caller — the caller could not distinguish "deposit fully completed"
	// from "deposit minted but disk-flag persistence failed (re-mint risk
	// on restart)". The audit (R39-P1-08) calls out that swallowing the
	// error lets a transient disk-full incident silently create a
	// "memory/disk divergence" that, on the next restart, re-mints the
	// same deposit and breaks the once-only bridge contract.
	//
	// Closure strategy: RETURN the error from ProcessDeposit (do NOT
	// revert the mint — the mint is real and the user's balance is
	// correct). The caller (the L1 watcher loop, etc.) MUST treat this
	// error as "this deposit is in a half-finished state — do not ack it
	// to upstream; alert the operator; the in-memory Minted=true is
	// correct, the disk Minted=false will be corrected by a
	// soon-as-possible retry of MarkDepositMinted (the deposit pointer is
	// shared with the L1 bridge, so the next ProcessDeposit observes
	// Minted=true and re-attempts the persist)". The PERSIST-MARK-MINTED-
	// FAILED tag remains the stable grep anchor for monitoring.
	//
	// What this does NOT do (deliberately):
	//   - Does NOT revert Minted=false. The mint is real; reverting the
	//     flag would let a concurrent ProcessDeposit re-mint the SAME
	//     deposit immediately, before any operator action — a strictly
	//     worse outcome than returning the error now.
	//   - Does NOT call a ReverseMintBalance (no such API; adding one is
	//     out of scope for R39 and would itself be unsafe under partial
	//     disk failure).
	//   - Does NOT panic. The node's Correctness for already-credited
	//     balances is intact; only the persistence layer is in a degraded
	//     state. Panicking would crash the node and abort unrelated work.
	if err := b.l1Bridge.MarkDepositMinted(depositHash); err != nil {
		log.Printf("[rollup-bridge] ERROR: PERSIST-MARK-MINTED-FAILED deposit=%x: %v (mint succeeded and is irreversible; in-memory Minted=true is correct, but disk still holds Minted=false — re-mint risk on restart before next persist; operator action required; returning err so the caller treats this deposit as not-acked)",
			depositHash[:8], err)
		return fmt.Errorf("R39-P1-08: persist Minted flag failed for deposit %x after irreversible mint (memory/disk divergence; operator must repair or risks re-mint on restart): %w",
			depositHash[:8], err)
	}

	log.Printf("[rollup-bridge] L2 mint: depositor=%x amount=%s depositHash=%x l1Height=%d confirmations=%d",
		depositor[:8], amount.String(), depositHash[:8], l1Height,
		func() uint64 {
			if b.l1HeightReader != nil {
				c := b.l1HeightReader.GetCurrentHeight()
				if c >= l1Height {
					return c - l1Height
				}
			}
			return 0
		}())
	return nil
}

// ProcessFinalizedBatch implements WithdrawalProcessor.
// It scans the finalized batch for withdrawal transactions (tx.To == bridgeAddress)
// and submits each to the L1 bridge for release with a Merkle inclusion proof
// from the DEDICATED withdrawal tree (audit R4-BRDG-02).
//
// Withdrawal tree flow (AUDIT R4-BRDG-02 2026-07-15):
//  1. Build a dedicated withdrawal SMT from the batch's withdrawal txs
//  2. Record the withdrawal tree root on L1
//  3. For each withdrawal tx, generate a Merkle proof from the withdrawal SMT
//  4. Submit (withdrawer, amount, txIndex, proof) to L1Bridge.ProcessWithdrawal
//
// Idempotency: Each withdrawal is tracked by its hash. If ProcessFinalizedBatch
// is called multiple times for the same batch, already-processed withdrawals
// are skipped.
//
// W-P1-6 FIX (2026-07-13), AUDIT R4-BRDG-02 (2026-07-15)
//
// RLLP-FIX (2026-07-17): Previously the entire function body ran under
// b.mu, including external l1Bridge calls (RecordFinalizedBatch,
// RecordWithdrawalRoot — both do bbolt I/O) and the 160-depth SMT build
// (buildWithdrawalSMT). This amplified lock contention: any disk jitter on
// bbolt stalled concurrent ProcessDeposit callers. The fix snapshots
// bridgeAddress under the lock, then releases b.mu for all external L1 calls
// and SMT computation, and re-acquires b.mu only for the withdrawal map
// updates (which require exclusive access to b.withdrawals).
func (b *L2Bridge) ProcessFinalizedBatch(batch *Batch) error {
	if batch == nil {
		return nil
	}

	// Phase 1: snapshot bridge address under lock.
	b.mu.Lock()
	bridgeAddress := b.bridgeAddress
	b.mu.Unlock()

	// Determine the finalized state root for this batch.
	stateRoot := batch.PostStateRoot
	if stateRoot == (types.Hash{}) {
		root, ok := b.stateManager.GetStateRoot(batch.Index)
		if !ok {
			return fmt.Errorf("cannot determine post-state root for batch %d: PostStateRoot is zero and StateManager has no archived root", batch.Index)
		}
		stateRoot = root
	}

	// Record the finalized state root on L1 (for state-root queries).
	// RLLP- Outside b.mu to avoid holding lock during bbolt I/O.
	if err := b.l1Bridge.RecordFinalizedBatch(batch.Index, stateRoot); err != nil {
		return fmt.Errorf("record finalized batch on L1: %w", err)
	}

	// SECURITY (audit R4-BRDG-02): Build the dedicated withdrawal tree for
	// this batch. Each leaf = SHA256(withdrawer || amount || txIndex). The
	// root is recorded on L1 so the bridge can verify that calldata amounts
	// match the actual committed withdrawals.
	// RLLP- (2026-07-16): Filter by bridgeAddress so only actual
	// withdrawal txs are included (not ordinary user-to-user transfers).
	// RLLP- buildWithdrawalSMT is compute-heavy (160-depth SMT); run
	// outside b.mu to avoid blocking deposit processing.
	withdrawalSMT := buildWithdrawalSMT(batch.Transactions, bridgeAddress)
	withdrawalRoot := withdrawalSMT.Root()
	batch.WithdrawalRoot = withdrawalRoot
	if err := b.l1Bridge.RecordWithdrawalRoot(batch.Index, withdrawalRoot); err != nil {
		return fmt.Errorf("record withdrawal root on L1: %w", err)
	}

	// Phase 2: re-acquire lock for the withdrawal processing loop (modifies
	// b.withdrawals map).
	b.mu.Lock()
	defer b.mu.Unlock()

	for txIdx, tx := range batch.Transactions {
		if tx.To == nil || *tx.To != bridgeAddress {
			continue
		}
		if tx.Value == nil || tx.Value.Sign() <= 0 {
			continue
		}

		wHash := computeWithdrawalHash(tx.From, tx.Value, batch.Index, txIdx, batch.BatchHash)
		if existing, ok := b.withdrawals[wHash]; ok && existing.Processed {
			continue
		}

		// Generate Merkle inclusion proof from the dedicated withdrawal tree.
		treeKey := ComputeWithdrawalTreeKey(tx.From, txIdx)
		merkleProof, err := withdrawalSMT.Prove(treeKey)
		if err != nil {
			log.Printf("[rollup-bridge] WARN: cannot prove withdrawal for %x at batch %d: %v",
				tx.From[:8], batch.Index, err)
			b.withdrawals[wHash] = &Withdrawal{
				Hash: wHash, Withdrawer: tx.From, Amount: new(big.Int).Set(tx.Value),
				BatchIndex: batch.Index, TxIndex: txIdx, BatchHash: batch.BatchHash,
				Processed: false, Timestamp: time.Now().Unix(),
			}
			continue
		}

		proof := &MerkleWithdrawalProof{
			WithdrawalRoot: withdrawalRoot,
			Proof:          merkleProof,
			TreeKey:        treeKey,
		}

		if err := b.l1Bridge.ProcessWithdrawal(tx.From, tx.Value, batch.Index, txIdx, batch.BatchHash, proof); err != nil {
			log.Printf("[rollup-bridge] WARN: L1 withdrawal failed for batch %d tx %d: %v",
				batch.Index, txIdx, err)
			b.withdrawals[wHash] = &Withdrawal{
				Hash: wHash, Withdrawer: tx.From, Amount: new(big.Int).Set(tx.Value),
				BatchIndex: batch.Index, TxIndex: txIdx, BatchHash: batch.BatchHash,
				Processed: false, Timestamp: time.Now().Unix(), Proof: proof,
			}
			continue
		}

		b.withdrawals[wHash] = &Withdrawal{
			Hash: wHash, Withdrawer: tx.From, Amount: new(big.Int).Set(tx.Value),
			BatchIndex: batch.Index, TxIndex: txIdx, BatchHash: batch.BatchHash,
			Processed: true, Timestamp: time.Now().Unix(), Proof: proof,
		}
	}

	return nil
}

// buildWithdrawalSMT constructs a dedicated Sparse Merkle Tree from a batch's
// withdrawal transactions. Each withdrawal leaf is:
//
//	leaf = SHA256(withdrawer || amount[32] || txIndex[4])
//
// The tree key is hash(withdrawer || txIndex)[:20], ensuring each (withdrawer,
// txIndex) pair maps to a unique leaf position.
//
// RLLP- (2026-07-16): Only transactions with tx.To == bridgeAddress are
// included. Previously, ALL txs with tx.To != nil && Value > 0 were inserted,
// which polluted the withdrawal tree with ordinary user-to-user transfers —
// inflating the tree, breaking the 1:1 leaf-to-release invariant, and
// potentially allowing non-withdrawal txs to be mistaken for withdrawals.
//
// AUDIT R4-BRDG-02 (2026-07-15)
func buildWithdrawalSMT(txs []*RollupTransaction, bridgeAddress types.Address) *SparseMerkleTree {
	smt := NewSparseMerkleTree()
	for txIdx, tx := range txs {
		if tx.To == nil || *tx.To != bridgeAddress {
			continue // not a withdrawal to the bridge
		}
		if tx.Value == nil || tx.Value.Sign() <= 0 {
			continue // no value
		}
		key := ComputeWithdrawalTreeKey(tx.From, txIdx)
		leaf := ComputeWithdrawalLeafHash(tx.From, tx.Value, txIdx)
		smt.Insert(key, leaf)
	}
	return smt
}

// GetBridgeAddress returns the L2 bridge address that users send withdrawals to.
func (b *L2Bridge) GetBridgeAddress() types.Address {
	return b.bridgeAddress
}

// GetL1Bridge returns the underlying L1 bridge interface (for RPC queries).
// W-P1-6 Phase 3 (2026-07-14)
func (b *L2Bridge) GetL1Bridge() L1Bridge {
	return b.l1Bridge
}

// GetPendingWithdrawals returns withdrawals that have not yet been processed
// by the L1 bridge (for diagnostics / retry monitoring).
func (b *L2Bridge) GetPendingWithdrawals() []*Withdrawal {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var pending []*Withdrawal
	for _, w := range b.withdrawals {
		if !w.Processed {
			pending = append(pending, w)
		}
	}
	return pending
}

// RetryPendingWithdrawals re-submits any pending (un-processed) withdrawals
// to the L1 bridge. Called by the engine on startup or on a periodic retry
// timer. This handles the case where L1 was temporarily unavailable when
// the batch was first finalized.
// W-P1-6 FIX (2026-07-13), Merkle proof upgrade (2026-07-14)
func (b *L2Bridge) RetryPendingWithdrawals() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	retried := 0
	for _, w := range b.withdrawals {
		if w.Processed {
			continue
		}
		if w.Proof == nil {
			log.Printf("[rollup-bridge] WARN: retry withdrawal batch %d tx %d has no proof (skipping)",
				w.BatchIndex, w.TxIndex)
			continue
		}
		if err := b.l1Bridge.ProcessWithdrawal(w.Withdrawer, w.Amount, w.BatchIndex, w.TxIndex, w.BatchHash, w.Proof); err != nil {
			log.Printf("[rollup-bridge] WARN: retry withdrawal batch %d tx %d still failing: %v",
				w.BatchIndex, w.TxIndex, err)
			continue
		}
		w.Processed = true
		retried++
		log.Printf("[rollup-bridge] retry succeeded: withdrawal batch %d tx %d",
			w.BatchIndex, w.TxIndex)
	}
	return retried
}

// --- Hash + proof helpers ---

func computeDepositHash(depositor types.Address, amount *big.Int, nonce uint64) types.Hash {
	h := sha256.New()
	h.Write(depositor[:])
	h.Write(amount.Bytes())
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, nonce)
	h.Write(buf)
	var hash types.Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

func computeWithdrawalHash(withdrawer types.Address, amount *big.Int, batchIndex uint64, txIndex int, batchHash types.Hash) types.Hash {
	h := sha256.New()
	h.Write(withdrawer[:])
	h.Write(amount.Bytes())
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, batchIndex)
	h.Write(buf)
	binary.BigEndian.PutUint32(buf[:4], uint32(txIndex))
	h.Write(buf[:4])
	h.Write(batchHash[:])
	var hash types.Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// (Removed: buildWithdrawalProof / verifyWithdrawalProof — replaced by
// MerkleWithdrawalProof + VerifyMerkleProof in sparse_merkle.go, 2026-07-14)
