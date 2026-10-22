// Quantaureum Node source, version 1.0.0.
package txpool

import (
	"container/heap"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/metrics"
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

	// F-16 (2026-10-21): Admission fairness limits. UserOperation
	// signatures are only checked when the EntryPoint executes the sender's
	// validateUserOp, so without admission controls a caller can occupy all
	// 1024 mempool slots with operations that are guaranteed to fail later.
	// Cap pending operations per sender and rate-limit admissions so one
	// sender cannot monopolize the pool.
	//
	// R3-04 (2026-10-21): the admission rate limit is charged only for
	// operations that passed account validation. Charging it before validation
	// let anyone who knew a victim's sender address burn the victim's quota
	// with unsigned fake operations.
	//
	// R4-01 (2026-10-21): account validation now happens AT ADMISSION and the
	// per-sender cap rejects instead of evicting. R3-04's oldest-first eviction
	// assumed a third party's fake operations are always older than the
	// legitimate operation they displace — that is backwards: the attacker
	// submits last, so eviction deleted the victim's already-queued operations.
	// Because a `Sender` claim is meaningless until the sender account has
	// validated it, any per-sender policy keyed on an unauthenticated claim is
	// gameable; authenticating first is what makes the cap sound.
	DefaultMaxUserOpsPerSender       = 8
	DefaultUserOpAdmissionsPerWindow = 16
	DefaultUserOpAdmissionWindow     = time.Minute
	// Bound for per-sender rate-limit bookkeeping; distinct-sender floods
	// must not grow it without limit.
	DefaultMaxTrackedUserOpSenders = 4096
	// R4-01: global budget for the account-validation runs triggered by
	// submissions. Validation is now paid for at admission, so the work itself
	// must be bounded — otherwise replacing fake operations in the mempool with
	// synchronous simulations just moves the denial of service to the CPU.
	// 1024/window matches the whole mempool capacity per minute.
	DefaultUserOpValidationsPerWindow = 1024
	// R4-RES: per-sender sub-cap on admission-time validation runs. A single
	// sender must not be able to monopolize the global validation budget: even
	// a retry loop tops out at this many simulations per window, capping one
	// host's CPU share at 64/1024 of the global budget.
	DefaultUserOpValidationsPerSenderPerWindow = 64
)

// userOpSenderAdmissions is a fixed-window admission counter for one sender.
type userOpSenderAdmissions struct {
	windowStart time.Time
	count       int
}

// ExecutionGuard serializes top-level execution frames over one shared state
// object. R4-07 (2026-10-21 audit): the state used by the bundler is the node's
// live StateDB, whose snapshot stack and dirty journal are global to that
// instance; two frames must not be live at the same time. The guard is
// fail-fast by design — speculation must never queue behind, or delay,
// consensus block application.
type ExecutionGuard interface {
	TryBeginExecution() (func(), bool)
}

// ErrBundlerStateBusy is returned when the live state is already running another
// execution frame (a block being applied, or another simulation). The caller is
// expected to retry later; the operation is NOT dropped for a bad signature.
var ErrBundlerStateBusy = errors.New("bundler is busy: state execution frame unavailable")

// SetExecutionGuard wires the state execution guard described above. Called by
// the node during AA bundler construction; tests may leave it nil, in which
// case simulations still balance the snapshot stack but run without exclusivity.
func (b *Bundler) SetExecutionGuard(g ExecutionGuard) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.execGuard = g
}

// beginValidationFrame opens an exclusive execution frame and a simulation
// snapshot on the shared state, and returns the function that closes both. Every
// SimulateValidation call must run inside one: EntryPoint validation executes
// arbitrary account code that can revert sub-frames, and a reverted sub-frame
// restores the WHOLE dirty journal of the state it runs on.
func (b *Bundler) beginValidationFrame() (func(), error) {
	b.mu.RLock()
	guard := b.execGuard
	b.mu.RUnlock()

	if b.stateDB == nil {
		return nil, fmt.Errorf("bundler has no state database configured")
	}

	var release func()
	if guard != nil {
		var ok bool
		release, ok = guard.TryBeginExecution()
		if !ok {
			return nil, ErrBundlerStateBusy
		}
	}
	frame := b.stateDB.Snapshot()
	return func() {
		// Revert unconditionally: validation simulation must never persist the
		// state its account code touched, and this also pops the snapshots the
		// executor journalled for its own frames.
		b.stateDB.RevertToSnapshot(frame)
		if release != nil {
			release()
		}
	}, nil
}

type Bundler struct {
	mu            sync.RWMutex
	userOpMempool map[types.Hash]*userOpEntry
	userOpQueue   userOpPriorityQueue
	entryPoint    *qvm.EntryPoint
	executor      *qvm.Executor
	stateDB       qvm.StateDB
	// R4-07 (2026-10-21 audit): optional guard that makes a validation
	// simulation an exclusive execution frame on the shared state. Wired by the
	// node to the live StateDB (state.StateDB.TryBeginExecution). Simulations
	// snapshot and revert on the very same journal that consensus block
	// application is writing to, so running them concurrently used to rewind
	// in-flight block state.
	execGuard      ExecutionGuard
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
	// F-16: per-sender fixed-window counters for validated (simulation-passed)
	// admissions (guarded by mu).
	senderAdmissions map[types.Address]*userOpSenderAdmissions
	// R4-01: fixed-window budget for admission-time account validations
	// (guarded by mu).
	validationBudget *userOpSenderAdmissions
	// R4-RES: per-sender sub-cap of the validation budget above (guarded by
	// mu), so one sender cannot drain the global 1024-run window alone.
	senderValidationBudgets map[types.Address]*userOpSenderAdmissions
	// R4-01: optional admission validator injected by embedders/tests. When nil
	// the bundler validates through the EntryPoint below.
	admissionValidator func(*encoding.UserOperation) error
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
		userOpMempool:           make(map[types.Hash]*userOpEntry),
		entryPoint:              entryPoint,
		executor:                executor,
		stateDB:                 stateDB,
		chainID:                 config.ChainID,
		beneficiary:             config.Beneficiary,
		maxBundleSize:           config.MaxBundleSize,
		bundleInterval:          config.BundleInterval,
		minPriorityFee:          config.MinPriorityFee,
		bundleCh:                make(chan *encoding.UserOpBundle, 16),
		stopCh:                  make(chan struct{}),
		senderAdmissions:        make(map[types.Address]*userOpSenderAdmissions),
		senderValidationBudgets: make(map[types.Address]*userOpSenderAdmissions),
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

// SetUserOpAdmissionValidator installs a custom admission validator (R4-01).
// Embedders and tests use it to substitute the EntryPoint simulation; when nil
// the bundler falls back to SimulateValidation against the configured entry
// point. Passing a validator that accepts everything re-introduces the
// unauthenticated-admission problem R4-01 fixes, so production node startup
// must not call this.
func (b *Bundler) SetUserOpAdmissionValidator(v func(*encoding.UserOperation) error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.admissionValidator = v
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

	// Cheap pre-check so resubmitting an operation already in the pool does not
	// pay for another validation. Re-checked under the write lock below. The
	// write lock is required because the validation budget is charged here.
	b.mu.Lock()
	duplicate := false
	budgetErr := error(nil)
	if _, exists := b.userOpMempool[uoHash]; exists {
		duplicate = true
	} else {
		budgetErr = b.chargeValidationBudgetLocked(time.Now())
	}
	b.mu.Unlock()
	if duplicate {
		return fmt.Errorf("duplicate user operation")
	}
	if budgetErr != nil {
		return budgetErr
	}
	// R4-RES: charge the per-sender validation sub-cap before running the
	// simulation, so one sender cannot monopolize the global budget.
	b.mu.Lock()
	budgetErr = b.chargeSenderValidationBudgetLocked(uo.Sender, time.Now())
	b.mu.Unlock()
	if budgetErr != nil {
		return budgetErr
	}

	// R4-01: authenticate the sender claim before it can occupy a quota slot.
	// Runs outside b.mu: the simulation executes account code and must not hold
	// the mempool lock (same reason buildBundle releases it first).
	if err := b.validateUserOpForAdmission(uo); err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if _, exists := b.userOpMempool[uoHash]; exists {
		return fmt.Errorf("duplicate user operation")
	}

	// F-16: cap pending operations per sender before occupying a slot.
	// R4-01: reject at the cap. The sender claim is authenticated above, so the
	// cap can only be reached by the account owner itself — evicting an existing
	// operation here would only ever destroy legitimate work.
	pendingFromSender := 0
	for _, entry := range b.userOpMempool {
		if entry.userOp.Sender == uo.Sender {
			pendingFromSender++
		}
	}
	if pendingFromSender >= DefaultMaxUserOpsPerSender {
		return fmt.Errorf("sender %s already has %d pending user operations (max %d)",
			uo.Sender.ToHexAddress(), pendingFromSender, DefaultMaxUserOpsPerSender)
	}
	if len(b.userOpMempool) >= DefaultMaxUserOpsInMempool {
		return fmt.Errorf("user operation mempool is full")
	}

	// R3-04: the operation passed account validation, so charging the per-sender
	// admission rate here cannot be attributed to a third party's fake ops.
	if err := b.admitSenderLocked(uo.Sender, time.Now()); err != nil {
		return err
	}

	entry := &userOpEntry{
		userOp: uo,
		hash:   uoHash,
		fee:    new(big.Int).Set(uo.MaxPriorityFeePerGas),
	}
	b.userOpMempool[uoHash] = entry
	heap.Push(&b.userOpQueue, entry)

	return nil
}

// validateUserOpForAdmission runs the sender account's validateUserOp for a
// submitted operation (R4-01). A sender claim is only trustworthy once the
// account itself accepts it; ERC-4337 bundlers are required to reject
// operations that fail this check before putting them in the pool.
// Callers must NOT hold b.mu.
func (b *Bundler) validateUserOpForAdmission(uo *encoding.UserOperation) error {
	b.mu.RLock()
	custom := b.admissionValidator
	b.mu.RUnlock()
	if custom != nil {
		return custom(uo)
	}

	if b.entryPoint == nil || b.stateDB == nil {
		// Fail-closed: without an entry point there is no way to authenticate
		// the sender claim, so the operation cannot take a quota slot.
		return fmt.Errorf("cannot admit user operation: no entry point configured for validation")
	}

	b.mu.RLock()
	blockNumber := b.blockNumber
	b.mu.RUnlock()
	blockCtx := &qvm.BlockContext{
		BlockNumber: blockNumber,
		Timestamp:   b.getBlockTimestamp(),
		GasLimit:    30000000,
		ChainID:     b.chainID,
	}
	simBundle := &encoding.UserOpBundle{
		EntryPoint: qvm.EntryPointAddress,
		ChainID:    b.chainID,
	}

	// R4-07 (2026-10-21 audit): run the simulation inside an exclusive
	// execution frame. When the live state is busy (a block being applied, or
	// another simulation) the operation is refused rather than allowed to revert
	// shared state — admission stays fail-closed as in R4-01, so a busy frame
	// cannot smuggle an unvalidated operation into the pool.
	doneFrame, frameErr := b.beginValidationFrame()
	if frameErr != nil {
		return frameErr
	}
	defer doneFrame()

	result, err := b.entryPoint.SimulateValidation(uo, b.stateDB, blockCtx, simBundle)
	if err != nil {
		return fmt.Errorf("user operation validation failed: %w", err)
	}
	if !result.Valid {
		if result.ValidationError != nil {
			return fmt.Errorf("user operation validation failed: %w", result.ValidationError)
		}
		return fmt.Errorf("user operation validation failed")
	}
	return nil
}

// chargeValidationBudgetLocked bounds the global account-validation work
// admission can trigger in the current window (R4-01). Callers must hold b.mu.
func (b *Bundler) chargeValidationBudgetLocked(now time.Time) error {
	if b.validationBudget == nil || now.Sub(b.validationBudget.windowStart) >= DefaultUserOpAdmissionWindow {
		b.validationBudget = &userOpSenderAdmissions{windowStart: now}
	}
	if b.validationBudget.count >= DefaultUserOpValidationsPerWindow {
		return fmt.Errorf("user operation validation budget exceeded (%d per %s)",
			DefaultUserOpValidationsPerWindow, DefaultUserOpAdmissionWindow)
	}
	b.validationBudget.count++
	return nil
}

// chargeSenderValidationBudgetLocked applies the R4-RES per-sender sub-cap on
// admission-time validation runs: one sender can pay for at most
// DefaultUserOpValidationsPerSenderPerWindow simulations per admission window,
// capping a single host's share of the global budget at 1/16.
func (b *Bundler) chargeSenderValidationBudgetLocked(sender types.Address, now time.Time) error {
	if b.senderValidationBudgets == nil {
		b.senderValidationBudgets = make(map[types.Address]*userOpSenderAdmissions)
	}
	if len(b.senderValidationBudgets) >= DefaultMaxTrackedUserOpSenders {
		// Same eviction discipline as admitSenderLocked: clear expired
		// windows first, then evict the oldest so a distinct-sender flood
		// cannot lock new senders out permanently.
		for addr, st := range b.senderValidationBudgets {
			if now.Sub(st.windowStart) >= DefaultUserOpAdmissionWindow {
				delete(b.senderValidationBudgets, addr)
			}
		}
		if len(b.senderValidationBudgets) >= DefaultMaxTrackedUserOpSenders {
			var (
				oldestAddr  types.Address
				oldestStart time.Time
				haveOldest  bool
			)
			for addr, st := range b.senderValidationBudgets {
				if !haveOldest || st.windowStart.Before(oldestStart) {
					oldestAddr, oldestStart, haveOldest = addr, st.windowStart, true
				}
			}
			if haveOldest {
				delete(b.senderValidationBudgets, oldestAddr)
			}
		}
	}

	st, ok := b.senderValidationBudgets[sender]
	if !ok || now.Sub(st.windowStart) >= DefaultUserOpAdmissionWindow {
		st = &userOpSenderAdmissions{windowStart: now}
		b.senderValidationBudgets[sender] = st
	}
	if st.count >= DefaultUserOpValidationsPerSenderPerWindow {
		return fmt.Errorf("sender %s exceeded user operation validation budget (%d per %s)",
			sender.ToHexAddress(), DefaultUserOpValidationsPerSenderPerWindow, DefaultUserOpAdmissionWindow)
	}
	st.count++
	return nil
}

// admitSenderLocked applies the F-16 per-sender admission rate limit.
// R3-04/R4-01: callers must invoke this only for operations that passed
// account validation, so unauthenticated submissions cannot consume a
// sender's quota. Callers must hold b.mu.
func (b *Bundler) admitSenderLocked(sender types.Address, now time.Time) error {
	if b.senderAdmissions == nil {
		b.senderAdmissions = make(map[types.Address]*userOpSenderAdmissions)
	}
	if len(b.senderAdmissions) >= DefaultMaxTrackedUserOpSenders {
		for addr, st := range b.senderAdmissions {
			if now.Sub(st.windowStart) >= DefaultUserOpAdmissionWindow {
				delete(b.senderAdmissions, addr)
			}
		}
		if len(b.senderAdmissions) >= DefaultMaxTrackedUserOpSenders {
			// Every entry is still inside its window: evict the oldest so a
			// distinct-sender flood cannot lock new senders out permanently.
			var (
				oldestAddr  types.Address
				oldestStart time.Time
				haveOldest  bool
			)
			for addr, st := range b.senderAdmissions {
				if !haveOldest || st.windowStart.Before(oldestStart) {
					oldestAddr, oldestStart, haveOldest = addr, st.windowStart, true
				}
			}
			if haveOldest {
				delete(b.senderAdmissions, oldestAddr)
			}
		}
	}

	st, ok := b.senderAdmissions[sender]
	if !ok || now.Sub(st.windowStart) >= DefaultUserOpAdmissionWindow {
		st = &userOpSenderAdmissions{windowStart: now}
		b.senderAdmissions[sender] = st
	}
	if st.count >= DefaultUserOpAdmissionsPerWindow {
		return fmt.Errorf("sender %s exceeded user operation admission rate (%d per %s)",
			sender.ToHexAddress(), DefaultUserOpAdmissionsPerWindow, DefaultUserOpAdmissionWindow)
	}
	st.count++
	return nil
}

func (b *Bundler) GetUserOperation(hash types.Hash) *encoding.UserOperation {
	b.mu.RLock()
	defer b.mu.RUnlock()
	entry := b.userOpMempool[hash]
	if entry == nil {
		return nil
	}
	return entry.userOp
}

func (b *Bundler) PendingUserOps() []*encoding.UserOperation {
	b.mu.RLock()
	defer b.mu.RUnlock()

	ops := make([]*encoding.UserOperation, 0, len(b.userOpMempool))
	for _, entry := range b.userOpMempool {
		ops = append(ops, entry.userOp)
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
	b.removeUserOpLocked(hash)
}

// removeUserOpLocked removes an operation from both the mempool map and the
// priority queue. Callers must hold b.mu.
func (b *Bundler) removeUserOpLocked(hash types.Hash) {
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
		b.publishBundle(bundle)
	}
}

// publishBundle hands a built bundle to whoever consumes BundleChannel().
// Returns true when the bundle was handed off. Extracted from tryBuildBundle
// so the drop branch is reachable from a test without a full simulation stack
// (R5-05).
func (b *Bundler) publishBundle(bundle *encoding.UserOpBundle) bool {
	select {
	case b.bundleCh <- bundle:
		b.lastBundleTime = time.Now()
		return true
	default:
		// R5-05 (2026-10-21 fifth-round audit): this branch used to swallow the
		// bundle with no trace. Before the admission gates landed it was the
		// normal production outcome — node/node.go always constructs and starts a
		// Bundler, the public RPC could fill its mempool, and nothing ever read
		// BundleChannel() — so every bundle built here was thrown away silently.
		// Reaching this branch now means an internal caller filled the mempool
		// through the Bundler directly while no consumer is wired. Either way it
		// is visible from here on: one warning per bundler tick (this path runs on
		// DefaultBundleInterval, so it cannot spam) plus a /metrics counter.
		//
		// The drop is not benign: buildBundle already deleted the operations
		// that made it into the bundle from userOpMempool (it does that to
		// prevent double-bundling), and only the candidates it did not include
		// are pushed back on the heap. So the operations in this bundle are
		// gone for good — the sender holds no way to recover them except
		// resubmitting. That is the concrete reason admission is gated at the
		// pool and rpc boundaries rather than relying on this counter.
		log.Printf("AA bundle dropped: BundleChannel full or unread (capacity %d), discarding %d user operations", cap(b.bundleCh), len(bundle.UserOps))
		metrics.Global().AddAABundleDropped()
		return false
	}
}

// userOpGasBudget sums an operation's three gas fields without wrapping.
//
// R5-06 (2026-10-21 fifth-round audit): UserOperation.Validate() bounds only
// VerificationGasLimit, so CallGasLimit and PreVerificationGas are arbitrary
// uint64s from the wire. A uint64 sum of two of them can wrap to a value that
// passes any budget check (qvm/entrypoint.go had the same class fixed twice,
// in chargeFees and handleSingleOp), so the bundler budget arithmetic is done
// in big.Int.
func userOpGasBudget(uo *encoding.UserOperation) *big.Int {
	budget := new(big.Int).SetUint64(uo.CallGasLimit)
	budget.Add(budget, new(big.Int).SetUint64(uo.VerificationGasLimit))
	budget.Add(budget, new(big.Int).SetUint64(uo.PreVerificationGas))
	return budget
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
	// R5-06 (2026-10-21 fifth-round audit): the bundle gas budget is summed in
	// big.Int. The previous uint64 sum wrapped: Validate() caps only
	// VerificationGasLimit, so CallGasLimit and PreVerificationGas arrive
	// straight from the wire and two values near 2^63 wrapped opGas to a small
	// number — the same overflow class already fixed twice in
	// qvm/entrypoint.go (chargeFees, handleSingleOp).
	// The budget check also runs BEFORE the simulation now: an operation that
	// can never fit in a bundle must not be re-simulated every cycle.
	blockGasLimit := new(big.Int).SetUint64(blockCtx.GasLimit)
	totalGas := new(big.Int)
	// R36-P1-TXPOOL-03 FIX (2026-07-30): Track which candidates were
	// successfully bundled so we can remove them from the mempool and
	// push back the non-bundled (gas-exceeded) ones to the heap.
	bundledHashes := make(map[types.Hash]bool)

	for _, entry := range candidates {
		uo := entry.userOp

		opGas := userOpGasBudget(uo)
		if opGas.Cmp(blockGasLimit) > 0 || new(big.Int).Add(totalGas, opGas).Cmp(blockGasLimit) > 0 {
			continue
		}

		simBundle := &encoding.UserOpBundle{
			EntryPoint: qvm.EntryPointAddress,
			ChainID:    b.chainID,
		}

		// R4-07 (2026-10-21 audit): each candidate simulation needs the exclusive
		// execution frame of the live state. When the state is busy applying a
		// block the cycle stops early — the candidates that were not reached stay
		// in the mempool and the cleanup below pushes them back onto the heap.
		doneFrame, frameErr := b.beginValidationFrame()
		if frameErr != nil {
			break
		}

		validationResult, err := b.entryPoint.SimulateValidation(uo, b.stateDB, blockCtx, simBundle)
		doneFrame()
		if err != nil || !validationResult.Valid {
			b.RemoveUserOp(entry.hash)
			continue
		}

		// R4-01: the per-sender admission rate is charged in AddUserOperation,
		// where the operation was first authenticated. Re-simulating here only
		// guards against state changing between submission and bundling.

		validOps = append(validOps, uo)
		bundledHashes[entry.hash] = true
		totalGas.Add(totalGas, opGas)

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
