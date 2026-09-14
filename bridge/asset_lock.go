// Quantaureum Node source, version 1.0.0.
package bridge

import (
	"context"
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

type LockStatus uint8

const (
	LockStatusPending  LockStatus = 0
	LockStatusLocked   LockStatus = 1
	LockStatusMinted   LockStatus = 2
	LockStatusBurned   LockStatus = 3
	LockStatusUnlocked LockStatus = 4
	LockStatusFailed   LockStatus = 5
	// BRIDGE-R13-H02 (2026-07-21): Refunded status marks a Failed lock
	// whose stuck funds have been released back to the owner via
	// RefundFailedLock. Distinct from Unlocked (which is the success
	// path) so that operators can audit refund events separately.
	LockStatusRefunded LockStatus = 6
)

// defaultLockTimeout is the maximum time a lock may stay in a non-terminal
// status (Pending/Locked/Minted/Burned) before the timeout watcher
// auto-fails it. BRIDGE-R13-H02: 24 hours gives ample time for normal
// cross-chain finality (ConfirmationRequired blocks + observer latency)
// while preventing permanent fund-locking when an operator forgets to
// retry a stuck lock.
const defaultLockTimeout = 24 * time.Hour

type AssetLock struct {
	ID           string
	SourceChain  ChainID
	TargetChain  ChainID
	AssetType    AssetType
	TokenAddress types.Address
	TokenID      *big.Int
	Amount       *big.Int
	Owner        types.Address
	Recipient    types.Address
	Status       LockStatus
	LockTxHash   string
	MintTxHash   string
	BurnTxHash   string
	UnlockTxHash string
	CreatedAt    int64
	LockedAt     int64
	MintedAt     int64
	BurnedAt     int64
	UnlockedAt   int64
	// BRIDGE-R13-H02 (2026-07-21): Failure tracking fields.
	// FailedAt is set when the lock transitions to LockStatusFailed
	// (either via SubmitMessage error in Mint/Burn/Unlock, or via the
	// timeout watcher). Used by RefundFailedLock for audit trail.
	FailedAt int64
	// FailedReason records why the lock failed (e.g., "mint submit failed",
	// "timeout after 24h in Locked"). For diagnostics / audit log.
	FailedReason string
	// RefundedAt is set when RefundFailedLock successfully submits the
	// refund message. RefundTxHash tracks the refund message ID.
	RefundedAt   int64
	RefundTxHash string
	// BRIDGE-H06 (R30, 2026-07-27): BurnProof is required to refund a
	// lock whose last good status was Minted (i.e., FailedReason contains
	// "Minted"). Without a verified burn proof, refunding such a lock
	// would create a double-spend: the user keeps the wrapped asset on
	// the target chain AND gets the original asset back on the source
	// chain. Once attached, the proof is immutable — attempts to refund
	// with a DIFFERENT proof are rejected (no proof swapping).
	BurnProof *BurnProof
	// R41-BRIDGE-03 (2026-08-03): OwnerAuth binds the request to the
	// Owner of the lock. LockAsset REQUIRES a verifiable Dilithium-3
	// signature over the canonical lock message (see LockAsset for the
	// message construction) whose corresponding public key derives to
	// exactly `lock.Owner`. Without this field, any HTTP caller of the
	// bridge API could lock another account's assets by simply setting
	// `Owner` to the victim address. The bridge_api.createLock handler
	// must populate this from the request body before invoking LockAsset.
	OwnerAuth *OwnerAuth
}

// OwnerAuth is the Dilithium-3 authorization for an AssetLock request.
// It MUST be provided by every caller of LockAsset, and the public key
// it carries MUST derive `lock.Owner`. The signature covers the
// canonical message:
//
//	"QAU-Lock-V1" || uint64(sourceChain) || uint64(targetChain) ||
//	assetType(uint8) || tokenAddress([20]) || owner([20]) ||
//	recipient([20]) || amount(32-byte BE) || lockID(var) ||
//	int64(BE createdAt)
//
// The leading constant domain string prevents cross-protocol signature
// reuse; the remaining fields are all the LockAsset inputs that affect
// on-chain state. Amount is encoded as a left-padded 32-byte big-endian
// slice so that the signed message is byte-identical regardless of the
// caller's big.Int width.
type OwnerAuth struct {
	PublicKey []byte // Dilithium3 mode3, 1952 bytes
	Signature []byte // Dilithium3 mode3, 3293 bytes
}

// BurnProof records the on-chain evidence that the wrapped asset minted on
// the target chain has been irrevocably burned before the source-chain lock
// is refunded. Required for refunds of locks that reached Minted status.
//
// BRIDGE-H06 (R30, 2026-07-27): prevents double-spend where a user keeps
// the wrapped asset on the target chain AND gets the original asset back
// on the source chain.
//
// R35-P3-BRIDGE-7 / AUDIT-FULL C-6 (RESOLVED 2026-08-02): the former
// VERIFICATION GAP is closed. RefundFailedLockWithBurnProof DOES call the
// target-chain adapter's VerifyBurnTransaction with the full
// BurnVerificationRequest (fail-closed per R38-P1-11): bridge configured →
// adapter registered → verify returns no error → verify true. Adapters
// assert the burn tx exists, is finalized, targets the whitelisted
// wrapped-asset contract, and that calldata amount / beneficiary / epoch
// / validator match the proof fields below. A forged TxHash is rejected.
type BurnProof struct {
	// TxHash is the target-chain transaction hash that burned the wrapped
	// asset. Must be non-empty — without an on-chain burn there is no proof.
	TxHash string
	// ChainID is the chain on which the burn occurred. Must match
	// lock.TargetChain (the chain where the wrapped asset was minted).
	ChainID ChainID
	// Amount is the amount of wrapped asset that was burned. Must exactly
	// match lock.Amount — partial burns are NOT allowed because the entire
	// wrapped asset must be destroyed to prevent partial double-spend.
	Amount *big.Int

	// R38-P1-11 DEEP FIX (2026-08-02): Each field below is matched
	// against the calldata of the burn transaction by the target-chain
	// adapter. The surfaced BurnVerificationRequest (bridge.go) is
	// populated from these fields by RefundFailedLockWithBurnProof and
	// passed to adapter.VerifyBurnTransaction. The adapter then asserts
	// strong consistency between the BurnProof claims and the on-chain
	// calldata — a forged TxHash with mismatched calldata is rejected.

	// ValidatorAddr is the validator whose key was supposed to sign the
	// burn intent. The adapter compares this against either the sig-
	// recovered signer (ECDSA adapters) or the calldata beneficiary
	// (Dilithium3 adapters). Zero is allowed for adapter implementations
	// that do not bind to a specific validator (refund-only adapters),
	// in which case the adapter MUST still verify txHash + amount +
	// beneficiary.
	ValidatorAddr types.Address

	// FundingEpoch is the epoch the burn claims to fund. The adapter
	// compares this against the calldata fundingEpoch field. Zero is
	// allowed when the burn does not target a specific epoch (refund-only).
	FundingEpoch uint64

	// Signature is an optional Dilithium3 signature over
	// (txHash || validatorAddr || fundingEpoch || amount). The adapter
	// verifies it against the validator's known public key when non-empty.
	// Empty is allowed for adapter implementations that do not require a
	// burn-intent signature (the burn tx itself carries a signature from
	// the L1 sender).
	Signature []byte

	// Beneficiary is the L1 address that should receive the unwrapped
	// asset. The adapter compares this against the calldata beneficiary /
	// receipt log beneficiary. Zero is allowed for adapter implementations
	// that have no beneficiary concept — in that case the adapter MUST at
	// least match the L1 sender of the burn tx.
	Beneficiary types.Address
}

type AssetLockManager struct {
	mu            sync.RWMutex
	bridge        *QuantumBridge
	locks         map[string]*AssetLock
	locksByOwner  map[types.Address][]string
	locksByStatus map[LockStatus]map[string]bool
	stopped       int32 // audit-fix HIGH-NEW-2: prevents nil-panic after Stop()
	// R10-BR-005 FIX: Monotonic nonce counter for asset lock messages.
	nonceCounter uint64
	// AUDIT (2026 security review) BRDG-09: confirmation-watcher goroutine state
	watcherStop chan struct{}
	watcherWG   sync.WaitGroup
	watcherOn   bool
	// BRIDGE-R13-H02 (2026-07-21): timeout-watcher goroutine state.
	// Mirrors the confirmation-watcher pattern: started once, stopped
	// via Stop(). The watcher scans non-terminal locks and auto-fails
	// any that exceed lockTimeout in their current status.
	timeoutStop chan struct{}
	timeoutWG   sync.WaitGroup
	timeoutOn   bool
	lockTimeout time.Duration
	// BRIDGE-R15-CRIT-001 (2026-07-22): authorized operators for
	// RefundFailedLockAuthorized. When empty, fail-closed (all callers
	// rejected). The legacy RefundFailedLock (internal) skips this check
	// for backward compat with the timeout watcher and unit tests.
	authorizedOperators map[types.Address]bool
	// R35-P2-BRIDGE-01 FIX (2026-07-29): operatorAdmin is the governance/
	// multisig address authorized to call SetAuthorizedOperatorsAuthorized.
	// When zero (uninitialized), SetAuthorizedOperatorsAuthorized fails
	// closed — admin MUST be bootstrapped first via SetOperatorAdmin.
	// This mirrors the governanceAddress pattern in ethereum_adapter.go.
	operatorAdmin types.Address
}

// ErrUnauthorizedOperator is returned by RefundFailedLockAuthorized when
// the caller is not in the authorized operator set.
// BRIDGE-R15-CRIT-001 (2026-07-22): prevents unauthorized refunds.
var ErrUnauthorizedOperator = errors.New("unauthorized operator for refund")

// NewAssetLockManager creates a new AssetLockManager.
//
// R41-BRIDGE-07 (2026-08-03) FIX: the operator-admin trust root is now
// injected at construction via `initialAdmin`, NOT bootstrapped lazily via
// SetOperatorAdmin's "first caller wins" branch. The audit (R41-BRIDGE-07)
// flagged the prior fail-open bootstrap as unsafe: when operatorAdmin was
// zero, SetOperatorAdmin accepted ANY caller as the initializer, relying
// purely on a comment "RPC callers should never have a path to this
// method" — an implicit contract with no runtime enforcement. Worse,
// `SetOperatorAdmin` had ZERO production callers in the entire codebase,
// so in practice the trust root was never set, leaving
// `SetAuthorizedOperatorsAuthorized` permanently fail-closed and
// `qau_bridgeRefundFailedLock` returning "unauthorized" to every caller.
//
// The fix mirrors the project's existing fail-closed pattern
// (bridge/ethereum_adapter.go:SetGovernanceAddress uses a persisted
// initializerAddress; rpc/enforceAdminAuth defaults to fail-closed when
// the admin allowlist is empty):
//
//   - Pass `initialAdmin` from n.config.Bridge.OperatorAdminAddress at
//     node startup (see node/node.go initBridge).
//   - When `initialAdmin` is the zero address (config not provided), the
//     AssetLockManager stays fail-closed — exactly the same behavior as
//     today, but now explicit and auditable.
//   - When `initialAdmin` is non-zero, it is locked in as the trust root
//     at construction; subsequent SetOperatorAdmin calls must come from
//     that admin (rotate-only semantics).
//
// Tests that previously called NewAssetLockManager(bridge) should pass
// `types.Address{}` as `initialAdmin` to preserve the historical
// fail-closed test semantics — see bridge/*_test.go.
func NewAssetLockManager(bridge *QuantumBridge, initialAdmin types.Address) *AssetLockManager {
	return &AssetLockManager{
		bridge:              bridge,
		locks:               make(map[string]*AssetLock),
		locksByOwner:        make(map[types.Address][]string),
		locksByStatus:       make(map[LockStatus]map[string]bool),
		lockTimeout:         defaultLockTimeout,
		authorizedOperators: make(map[types.Address]bool),
		// R41-BRIDGE-07: trust root injected at construction (fail-closed
		// when zero). See the doc comment above for the rationale.
		operatorAdmin: initialAdmin,
	}
}

func (alm *AssetLockManager) IsStopped() bool {
	return atomic.LoadInt32(&alm.stopped) == 1
}

func (alm *AssetLockManager) Stop() {
	// BRDG-R42-CI-RACE: make Stop idempotent. The previous select-based
	// close-already-closed check on watcherStop/timeoutStop raced with a
	// concurrent Stop() call (and with an in-flight StartConfirmationWatcher
	// writing the same channel field under alm.mu). Under `-race` two Stop
	// goroutines could both observe the default branch and both call close(),
	// panicking on the second close (close of closed channel) — this was the
	// root cause of BRDG- flake.
	//
	// atomic.CompareAndSwapInt32 acts as a single gate: the first Stop call
	// wins and performs teardown; any subsequent Stop returns immediately.
	// This also eliminates the `<-alm.watcherStop: already closed` /
	// `default: close(...)` race because close() is now only ever invoked
	// from the winning caller and exactly once.
	if !atomic.CompareAndSwapInt32(&alm.stopped, 0, 1) {
		return
	}

	// Snapshot the stop channels and their WaitGroups under alm.mu so the
	// subsequent close() + Wait() do not race with StartConfirmationWatcher
	// / StartTimeoutWatcher assigning the same fields. We release the lock
	// BEFORE Wait() so a long-running watcher tick cannot block future
	// Starts on the same mutex (and so the watcher's own alm.mu.Lock() in
	// scanPendingLocks / scanStaleLocks cannot self-deadlock with us).
	alm.mu.Lock()
	watcherStop := alm.watcherStop
	timeoutStop := alm.timeoutStop
	alm.mu.Unlock()

	if watcherStop != nil {
		// BRDG-R42-CI-RACE: CompareAndSwap gate above already guarantees
		// we are the sole closer, so no need for the select dance.
		close(watcherStop)
		alm.watcherWG.Wait()
	}
	if timeoutStop != nil {
		close(timeoutStop)
		alm.timeoutWG.Wait()
	}

	alm.mu.Lock()
	defer alm.mu.Unlock()
	alm.locks = nil
	alm.locksByOwner = nil
	alm.locksByStatus = nil
	// BRDG-R42-CI-RACE: reset watcher/timeout bookkeeping so that, after
	// Stop, a subsequent Start is correctly rejected by the IsStopped()
	// fast-path at the top of StartConfirmationWatcher (rather than seeing
	// a stale watcherOn=true and misreporting "already running"). The CAS
	// gate already set stopped=1 so the IsStopped() check fires first; this
	// reset just keeps the struct internally consistent for any future
	// inspection (or hypothetical un-stop path).
	alm.watcherStop = nil
	alm.watcherOn = false
	alm.timeoutStop = nil
	alm.timeoutOn = false
}

// StartConfirmationWatcher launches a background goroutine that periodically
// scans pending asset locks and promotes them to Locked status once the
// source-chain lock transaction has sufficient confirmation depth.
//
// AUDIT (2026 security review) BRDG-09 FIX: ConfirmLock existed but had no production
// caller, so locks could remain Pending indefinitely — blocking MintAsset
// and leaving user assets stuck. This watcher bridges the gap by polling
// the source chain adapter for each pending lock's LockTxHash, fetching the
// block number at which it was included, and calling ConfirmLock to verify
// confirmation depth and promote the lock.
//
// The watcher polls every pollInterval. If the source adapter's RPC is
// unavailable or the transaction is not yet confirmed, the lock remains
// Pending and is retried on the next tick. Errors are logged but do not
// stop the watcher.
func (alm *AssetLockManager) StartConfirmationWatcher(ctx context.Context, pollInterval time.Duration) error {
	if alm.IsStopped() {
		return fmt.Errorf("asset lock manager has been stopped")
	}
	alm.mu.Lock()
	if alm.watcherOn {
		alm.mu.Unlock()
		return fmt.Errorf("confirmation watcher already running")
	}
	alm.watcherStop = make(chan struct{})
	alm.watcherOn = true
	// BRDG-R42-CI-RACE: wg.Add(1) MUST happen inside alm.mu so that a
	// concurrent Stop() that snapshots watcherStop under the same mutex
	// is guaranteed to see a matching Add (happen-before via the lock).
	// Previously Add ran AFTER Unlock, creating a window where Stop saw
	// watcherStop != nil but wg counter was still 0, so Wait() returned
	// immediately and the goroutine that started just after could then
	// drive the counter negative (panic: negative WaitGroup counter).
	alm.watcherWG.Add(1)
	alm.mu.Unlock()

	go alm.confirmationWatcherLoop(ctx, pollInterval)
	return nil
}

func (alm *AssetLockManager) confirmationWatcherLoop(ctx context.Context, pollInterval time.Duration) {
	defer alm.watcherWG.Done()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-alm.watcherStop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			alm.scanPendingLocks(ctx)
		}
	}
}

func (alm *AssetLockManager) scanPendingLocks(ctx context.Context) {
	if alm.IsStopped() {
		return
	}
	pendingLocks := alm.GetLocksByStatus(LockStatusPending)
	for _, lock := range pendingLocks {
		if lock.LockTxHash == "" {
			continue
		}
		adapter, exists := alm.bridge.adapters[lock.SourceChain]
		if !exists {
			continue
		}
		blockNum, err := adapter.GetTransactionBlockNumber(ctx, lock.LockTxHash)
		if err != nil {
			// Transaction not yet confirmed or RPC error — retry next tick.
			continue
		}
		if err := alm.ConfirmLock(ctx, lock.ID, blockNum); err != nil {
			// Insufficient confirmations or other error — retry next tick.
			continue
		}
	}
}

func (alm *AssetLockManager) LockAsset(ctx context.Context, lock *AssetLock) error {
	if alm.IsStopped() {
		return fmt.Errorf("asset lock manager has been stopped")
	}
	alm.mu.Lock()
	defer alm.mu.Unlock()

	// BRIDGE-R15-M (2026-07-22): Generate a cryptographically random lock
	// ID when the caller does not provide one. Predictable IDs (e.g.,
	// sequential counters) allowed attackers to pre-compute derived
	// message IDs ("<lockID>-mint", "<lockID>-burn") and front-run the
	// bridge. The generated ID has 128 bits of entropy (16 random bytes,
	// hex-encoded) prefixed with "lock-" for diagnostics. Caller-supplied
	// IDs are preserved unchanged (backward compatibility).
	if lock.ID == "" {
		var randBytes [16]byte
		if _, err := cryptoRand.Read(randBytes[:]); err != nil {
			return fmt.Errorf("failed to generate random lock ID: %w", err)
		}
		lock.ID = "lock-" + hex.EncodeToString(randBytes[:])
	}

	// R41-BRIDGE-02 (2026-08-03) FIX: Reject caller-supplied lock IDs whose
	// suffix collides with the derived message-ID namespace used by the
	// Mint / Burn / Unlock / Refund downstream flows (see asset_lock.go
	// lines 565, 653, 788 and the refund flow). Without this guard an
	// attacker (or a careless client) could supply lock.ID = "abc-mint"
	// and trigger two distinct messages converging on the same final
	// message ID "abc-mint-mint" / lock "abc" + its real mint would
	// produce "abc-mint", leading to either ID-collision rejection (DoS)
	// or, worse, message-store dedup ambiguity that masks a double-mint.
	// Generated IDs (line 336-342, 128-bit random) cannot accidentally end
	// in these suffixes in practice; the guard is for caller-supplied IDs.
	for _, reserved := range []string{"-mint", "-burn", "-unlock", "-refund"} {
		if strings.HasSuffix(lock.ID, reserved) {
			return fmt.Errorf("R41-BRIDGE-02: lock.ID %q ends with reserved suffix %q (used by %s message-ID derivation); rename to avoid collision", lock.ID, reserved, reserved[1:])
		}
	}

	if _, exists := alm.locks[lock.ID]; exists {
		return fmt.Errorf("lock already exists: %s", lock.ID)
	}

	lock.Status = LockStatusPending
	lock.CreatedAt = time.Now().Unix()

	// R41-BRIDGE-03 (2026-08-03) FIX: enforce caller authorization for
	// LockAsset. Without OwnerAuth any HTTP caller of bridge_api.createLock
	// could lock another account's assets by simply setting Owner = victim,
	// since LockAsset proceeds directly to adapter.SubmitMessage (the source-
	// chain broadcast path) and bypasses bridge.SubmitMessage entirely (see
	// the R41-BRIDGE-04 audit: Mint/Burn/Unlock were already switched to
	// bridge.SubmitMessage under BRIDGE-R10-CRIT-002, but LockAsset kept the
	// direct adapter path because lock txs are source-chain-side messages).
	// OwnerAuth closes the trust gap at the source-chain side by requiring a
	// Dilithium-3 signature over the canonical lock message from the Owner
	// key. The public key MUST derive `lock.Owner`. The domain string plus
	// amount/lockID/createdAt in the signed body prevents (a) cross-protocol
	// signature reuse, (b) amount tampering, (c) replacing lock.ID after the
	// user signed.
	if lock.OwnerAuth == nil {
		return errors.New("R41-BRIDGE-03: OwnerAuth is required for LockAsset (missing Dilithium3 signature over canonical lock message)")
	}
	if err := verifyLockOwnerAuth(lock); err != nil {
		return fmt.Errorf("R41-BRIDGE-03: %w", err)
	}

	adapter, exists := alm.bridge.adapters[lock.SourceChain]
	if !exists {
		return fmt.Errorf("no adapter for source chain %s", lock.SourceChain)
	}

	ownerAddr := lock.Owner.ToHexAddress()
	recipientAddr := lock.Recipient.ToHexAddress()
	assetType := string(lock.AssetType)
	amountStr := lock.Amount.String()
	assetID := lock.TokenAddress.ToHexAddress()

	msg := &BridgeMessage{
		ID:            lock.ID,
		SourceChain:   lock.SourceChain,
		TargetChain:   lock.TargetChain,
		SourceAddress: ownerAddr,
		TargetAddress: recipientAddr,
		AssetType:     AssetType(assetType),
		AssetID:       assetID,
		Amount:        amountStr,
		MessageType:   MessageTypeAssetTransfer,
		Status:        MessageStatusPending,
		Timestamp:     time.Now().Unix(),
		// R10-BR-005 FIX: Set a unique nonce to prevent replay-protection
		// collisions if this message enters the bridge processing pipeline.
		Nonce: atomic.AddUint64(&alm.nonceCounter, 1),
	}

	if err := alm.bridge.validateMessageFields(msg); err != nil {
		lock.Status = LockStatusFailed
		alm.locks[lock.ID] = lock
		return fmt.Errorf("message validation failed: %w", err)
	}

	txHash, err := adapter.SubmitMessage(ctx, msg)
	if err != nil {
		lock.Status = LockStatusFailed
		alm.locks[lock.ID] = lock
		return fmt.Errorf("failed to submit lock transaction: %w", err)
	}

	// AUDIT (2026 security review) BRDG-09: Do NOT mark as Locked based solely on
	// SubmitMessage returning a txHash. SubmitMessage only proves the
	// transaction was signed and broadcast — it does NOT prove on-chain
	// inclusion or finality. Previously, a forged txHash would immediately
	// mark the asset as Locked, allowing MintAsset to proceed without any
	// real source-chain lock. The lock now stays Pending until an external
	// observer calls ConfirmLock with the block number at which the lock
	// transaction was included, and the source adapter verifies sufficient
	// confirmation depth.
	lock.LockTxHash = txHash
	// Status remains LockStatusPending until ConfirmLock is called.

	alm.locks[lock.ID] = lock
	alm.locksByOwner[lock.Owner] = append(alm.locksByOwner[lock.Owner], lock.ID)
	if alm.locksByStatus[LockStatusPending] == nil {
		alm.locksByStatus[LockStatusPending] = make(map[string]bool)
	}
	alm.locksByStatus[LockStatusPending][lock.ID] = true

	// P3-3: structured log for asset lock submission.
	alm.bridge.logger.Info("asset lock submitted", map[string]any{
		"lockID":      lock.ID,
		"sourceChain": string(lock.SourceChain),
		"targetChain": string(lock.TargetChain),
		"owner":       lock.Owner.ToHexAddress(),
		"amount":      lock.Amount.String(),
		"txHash":      lock.LockTxHash,
	})

	return nil
}

// verifyLockOwnerAuth validates the OwnerAuth Dilithium-3 signature on an
// AssetLock request. It enforces three independent properties, ALL of which
// must hold for the lock to be accepted:
//
//  1. PublicKey length == Dilithium3PublicKeySize (1952 bytes) — checked
//     by crypto.PublicKeyFromBytes in constant time.
//  2. crypto.PublicKeyAddressFromBytes(OwnerAuth.PublicKey) == lock.Owner
//     — i.e. the authorization is signed by the same key that owns the
//     asset being locked. This is the binding that closes R41-BRIDGE-03.
//  3. crypto.Verify(PublicKey, canonicalMessage, OwnerAuth.Signature) is
//     true — i.e. the signature is actually over the canonical message
//     containing all of source/target/assetType/tokenAddress/owner/
//     recipient/amount. (lock.ID and lock.CreatedAt are NOT part of the
//     signed message because LockAsset sets them after the caller has
//     already prepared the authorization.)
//
// The canonical message uses a fixed domain prefix "QAU-Lock-V1" so the
// signed digest cannot be replayed against any other protocol surface.
//
// Fails closed: any error returns a descriptive error and LockAsset must
// abort. Constant-time comparison is used at the Dilithium3 boundary.
func verifyLockOwnerAuth(lock *AssetLock) error {
	if lock == nil || lock.OwnerAuth == nil {
		return errors.New("missing OwnerAuth")
	}
	pubKey, err := crypto.PublicKeyFromBytes(lock.OwnerAuth.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid OwnerAuth public key: %w", err)
	}
	derivedOwner := crypto.PublicKeyAddressFromBytes(lock.OwnerAuth.PublicKey)
	if derivedOwner != lock.Owner {
		return fmt.Errorf("OwnerAuth public key does not derive lock.Owner (got %x, want %x)", derivedOwner[:], lock.Owner[:])
	}
	if lock.Amount == nil || lock.Amount.Sign() <= 0 {
		return errors.New("lock amount must be a positive *big.Int")
	}
	msg, err := canonicalLockMessage(lock)
	if err != nil {
		return fmt.Errorf("canonical message: %w", err)
	}
	if !crypto.Verify(pubKey, msg, lock.OwnerAuth.Signature) {
		return errors.New("OwnerAuth signature does not verify under the canonical Dilithium3 message")
	}
	return nil
}

// canonicalLockMessage builds the deterministic byte sequence signed by the
// lock Owner's Dilithium3 key. See verifyLockOwnerAuth for the scheme.
//
// Only fields that the caller fully controls and that are NOT set by
// LockAsset itself are included. Specifically EXCLUDED:
//   - lock.ID: the server may overwrite an empty caller-supplied ID with a
//     128-bit random value (line 366-372), so it cannot be part of a
//     pre-signed message.
//   - lock.CreatedAt, lock.Status, lock.LockTxHash, etc.: set by LockAsset
//     after submission; not part of the signer's intent.
//   - lock.BurnProof, lock.RefundedAt: attached after mint/refund.
//
// String-typed fields (SourceChain, TargetChain, AssetType) are encoded
// as length-prefixed UTF-8 bytes (uint32 BE length + bytes) rather than
// being converted to numeric scalars, because ChainID and AssetType are
// `type X string` aliases and have no canonical numeric representation.
// The length-prefix prevents suffix-field merging when a caller supplies
// an empty or odd-length string.
func canonicalLockMessage(lock *AssetLock) ([]byte, error) {
	var buf []byte
	const domain = "QAU-Lock-V1"
	buf = append(buf, []byte(domain)...)

	// Append a length-prefixed string field to buf.
	appendLenStr := func(s string) {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
		buf = append(buf, lenBuf[:]...)
		buf = append(buf, []byte(s)...)
	}

	// sourceChain (string) and targetChain (string) — length-prefixed
	appendLenStr(string(lock.SourceChain))
	appendLenStr(string(lock.TargetChain))
	// assetType (string) — length-prefixed
	appendLenStr(string(lock.AssetType))

	// tokenAddress ([20]byte)
	buf = append(buf, lock.TokenAddress[:]...)
	// owner ([20]byte) and recipient ([20]byte)
	buf = append(buf, lock.Owner[:]...)
	buf = append(buf, lock.Recipient[:]...)

	// amount (32-byte BE, left-padded) — only positive amounts allowed.
	if lock.Amount == nil || lock.Amount.Sign() <= 0 {
		return nil, errors.New("lock amount must be positive")
	}
	if lock.Amount.BitLen() > 256 {
		return nil, errors.New("lock amount exceeds 256 bits")
	}
	amountBuf := make([]byte, 32)
	lock.Amount.FillBytes(amountBuf)
	buf = append(buf, amountBuf...)

	return buf, nil
}

// ConfirmLock marks a pending asset lock as confirmed (Locked) after the
// source-chain lock transaction has been verified to have sufficient
// confirmation depth. AUDIT (2026 security review) BRDG-09: Previously, LockAsset marked
// the lock as Locked immediately based solely on SubmitMessage returning a
// (potentially forged) txHash. ConfirmLock decouples submission from
// finality: the bridge event listener must call this method with the block
// number at which the lock transaction was included, and the source adapter
// verifies confirmation depth before the lock is promoted to Locked status.
// Only after ConfirmLock succeeds can MintAsset proceed.
func (alm *AssetLockManager) ConfirmLock(ctx context.Context, lockID string, blockNumber uint64) error {
	if alm.IsStopped() {
		return fmt.Errorf("asset lock manager has been stopped")
	}
	alm.mu.Lock()
	defer alm.mu.Unlock()

	lock, exists := alm.locks[lockID]
	if !exists {
		return fmt.Errorf("lock not found: %s", lockID)
	}
	if lock.Status != LockStatusPending {
		return fmt.Errorf("lock %s is not pending (status=%d); only pending locks can be confirmed", lockID, lock.Status)
	}

	adapter, exists := alm.bridge.adapters[lock.SourceChain]
	if !exists {
		return fmt.Errorf("no adapter for source chain %s", lock.SourceChain)
	}

	// BRDG-09: enforce source-chain confirmation depth before promoting.
	confirmed, err := adapter.HasSufficientConfirmations(ctx, blockNumber)
	if err != nil {
		return fmt.Errorf("failed to verify confirmations for lock %s: %w", lockID, err)
	}
	if !confirmed {
		return fmt.Errorf("lock %s has insufficient confirmations at block %d", lockID, blockNumber)
	}

	lock.Status = LockStatusLocked
	lock.LockedAt = time.Now().Unix()

	delete(alm.locksByStatus[LockStatusPending], lock.ID)
	if alm.locksByStatus[LockStatusLocked] == nil {
		alm.locksByStatus[LockStatusLocked] = make(map[string]bool)
	}
	alm.locksByStatus[LockStatusLocked][lock.ID] = true

	return nil
}

func (alm *AssetLockManager) MintAsset(ctx context.Context, lockID string) error {
	if alm.IsStopped() {
		return fmt.Errorf("asset lock manager has been stopped")
	}
	alm.mu.Lock()
	defer alm.mu.Unlock()

	lock, exists := alm.locks[lockID]
	if !exists {
		return fmt.Errorf("lock not found: %s", lockID)
	}

	if lock.Status != LockStatusLocked {
		return fmt.Errorf("invalid lock status for minting: %d", lock.Status)
	}

	// BRIDGE-R10-HIGH-002 (2026-07-19) FIX: Verify the Lock event Merkle
	// proof on the SOURCE chain before minting on the target chain.
	// Previously, MintAsset only checked lock.Status == Locked — but
	// Locked status is set by ConfirmLock, which only verifies the
	// source-chain lock transaction was included with sufficient
	// confirmations. It does NOT verify that the lock event itself was
	// attested to by a quorum of validators via a Merkle proof. An
	// attacker who controls a source-chain RPC endpoint could forge a
	// lock transaction + confirmation and then call MintAsset to mint
	// unbacked assets on the target chain.
	//
	// Defense in depth: fetch the Merkle proof for the lock event from
	// the source-chain adapter and verify it. The proof binds the lock
	// event to a committed Merkle root that has been attested to by the
	// validator quorum. If the source adapter cannot produce a valid
	// proof, minting is refused (fail-closed).
	//
	// NOTE: This requires lock.LockTxHash to be set (LockAsset populates
	// it from adapter.SubmitMessage's return value). If the lock was
	// created without going through LockAsset (e.g., test-only direct
	// map insertion), this check fails closed.
	if lock.LockTxHash == "" {
		return fmt.Errorf("mint refused: lock %s has no LockTxHash — cannot fetch Merkle proof (fail-closed)", lock.ID)
	}
	sourceAdapter, ok := alm.bridge.adapters[lock.SourceChain]
	if !ok {
		return fmt.Errorf("mint refused: lock %s has no source adapter for chain %s (fail-closed)", lock.ID, lock.SourceChain)
	}
	merkleProof, err := sourceAdapter.GetMessageProof(ctx, lock.ID)
	if err != nil {
		return fmt.Errorf("mint refused: failed to fetch Merkle proof for lock %s: %w", lock.ID, err)
	}
	if len(merkleProof) == 0 {
		return fmt.Errorf("mint refused: empty Merkle proof for lock %s (fail-closed)", lock.ID)
	}
	// Decode + verify the proof structurally. A proof that does not
	// verify indicates either the lock event was never committed to a
	// Merkle tree on the source chain, or the proof has been tampered
	// with — either way, minting is refused.
	decodedProof, err := DecodeMerkleProof(merkleProof)
	if err != nil {
		return fmt.Errorf("mint refused: invalid Merkle proof encoding for lock %s: %w", lock.ID, err)
	}
	if !VerifyMerkleProof(decodedProof) {
		return fmt.Errorf("mint refused: Merkle proof verification failed for lock %s (fail-closed)", lock.ID)
	}

	// BRIDGE-R10-CRIT-001 (2026-07-19) FIX: Previously this message omitted
	// Amount, SourceAddress, TargetAddress, AssetType, AssetID, Recipient
	// and went directly to adapter.SubmitMessage — BYPASSING
	// validateMessage / verifyQuantumSignature. A malicious relayer could
	// mint ANY amount to ANY address with NO signature. Now we populate
	// every fund-carrying field from the locked AssetLock and route through
	// alm.bridge.SubmitMessage, which runs validateMessage (structural
	// checks + verifyQuantumSignature). The bridge's trusted-validator-key
	// set must sign off before the mint transaction is submitted to the
	// target chain adapter.
	//
	// BRIDGE-R10-CRIT-002 (2026-07-19) FIX: Routing through
	// bridge.SubmitMessage ensures every message goes through the multi-sig
	// verification path. The previous direct adapter.SubmitMessage call was
	// the missing path that allowed unverified messages to execute.
	if lock.Amount == nil || lock.Amount.Sign() <= 0 {
		return fmt.Errorf("mint refused: lock %s has invalid amount", lock.ID)
	}
	if lock.Recipient == (types.Address{}) {
		return fmt.Errorf("mint refused: lock %s has zero recipient", lock.ID)
	}
	recipientAddr := lock.Recipient.ToHexAddress()
	ownerAddr := lock.Owner.ToHexAddress()
	assetID := lock.TokenAddress.ToHexAddress()
	assetType := string(lock.AssetType)
	amountStr := lock.Amount.String()

	msg := &BridgeMessage{
		ID:            lock.ID + "-mint",
		SourceChain:   lock.SourceChain,
		TargetChain:   lock.TargetChain,
		SourceAddress: ownerAddr,
		TargetAddress: recipientAddr,
		AssetType:     AssetType(assetType),
		AssetID:       assetID,
		Amount:        amountStr,
		MessageType:   MessageTypeAssetTransfer,
		Status:        MessageStatusPending,
		Timestamp:     time.Now().Unix(),
		// R10-BR-005: monotonic nonce to prevent replay-protection collisions.
		Nonce: atomic.AddUint64(&alm.nonceCounter, 1),
	}

	// BRIDGE-R10-CRIT-002: route through bridge.SubmitMessage so
	// validateMessage (including verifyQuantumSignature) is enforced.
	if err := alm.bridge.SubmitMessage(ctx, msg); err != nil {
		// BRIDGE-R13-H02: Mark the lock as Failed so RefundFailedLock
		// can release the stuck source-chain funds. Previously the lock
		// stayed in Locked status with no refund path — user funds were
		// permanently locked when mint submission failed.
		alm.markLockFailed(lock, fmt.Sprintf("mint submit failed: %v (was Locked)", err))
		return fmt.Errorf("failed to submit mint transaction: %w", err)
	}

	// adapter.SubmitMessage returns a txHash; bridge.SubmitMessage does
	// not return one (it stores the message). We retain the message ID
	// as the txHash for status tracking — this is consistent with how
	// LockAsset tracks LockTxHash when the source adapter returns one.
	lock.MintTxHash = msg.ID
	lock.Status = LockStatusMinted
	lock.MintedAt = time.Now().Unix()

	delete(alm.locksByStatus[LockStatusLocked], lock.ID)
	if alm.locksByStatus[LockStatusMinted] == nil {
		alm.locksByStatus[LockStatusMinted] = make(map[string]bool)
	}
	alm.locksByStatus[LockStatusMinted][lock.ID] = true

	// P3-3: structured log for asset mint.
	alm.bridge.logger.Info("asset minted", map[string]any{
		"lockID":      lock.ID,
		"sourceChain": string(lock.SourceChain),
		"targetChain": string(lock.TargetChain),
		"recipient":   lock.Recipient.ToHexAddress(),
		"amount":      lock.Amount.String(),
		"txHash":      lock.MintTxHash,
	})

	return nil
}

func (alm *AssetLockManager) BurnAsset(ctx context.Context, lockID string) error {
	if alm.IsStopped() {
		return fmt.Errorf("asset lock manager has been stopped")
	}
	alm.mu.Lock()
	defer alm.mu.Unlock()

	lock, exists := alm.locks[lockID]
	if !exists {
		return fmt.Errorf("lock not found: %s", lockID)
	}

	if lock.Status != LockStatusMinted {
		return fmt.Errorf("invalid lock status for burning: %d", lock.Status)
	}

	// BRIDGE-R10-CRIT-001/002 (2026-07-19) FIX: Same fix as MintAsset —
	// populate all fund-carrying fields and route through
	// bridge.SubmitMessage so verifyQuantumSignature is enforced. A burn
	// without these fields + signature could be forged to drain locked
	// assets on the source chain (the BurnAsset → UnlockAsset flow
	// releases the original locked funds on the source chain).
	if lock.Amount == nil || lock.Amount.Sign() <= 0 {
		return fmt.Errorf("burn refused: lock %s has invalid amount", lock.ID)
	}
	if lock.Owner == (types.Address{}) {
		return fmt.Errorf("burn refused: lock %s has zero owner", lock.ID)
	}
	ownerAddr := lock.Owner.ToHexAddress()
	recipientAddr := lock.Recipient.ToHexAddress()
	assetID := lock.TokenAddress.ToHexAddress()
	assetType := string(lock.AssetType)
	amountStr := lock.Amount.String()

	msg := &BridgeMessage{
		ID:            lock.ID + "-burn",
		SourceChain:   lock.TargetChain,
		TargetChain:   lock.SourceChain,
		SourceAddress: ownerAddr,
		TargetAddress: recipientAddr,
		AssetType:     AssetType(assetType),
		AssetID:       assetID,
		Amount:        amountStr,
		MessageType:   MessageTypeAssetTransfer,
		Status:        MessageStatusPending,
		Timestamp:     time.Now().Unix(),
		Nonce:         atomic.AddUint64(&alm.nonceCounter, 1),
	}

	if err := alm.bridge.SubmitMessage(ctx, msg); err != nil {
		// BRIDGE-R13-H02: Mark as Failed with Minted hint so RefundFailedLock
		// can warn about potential double-spend (wrapped asset still exists
		// on target chain). Operator must burn the wrapped asset out-of-band
		// before refunding the source-chain lock.
		alm.markLockFailed(lock, fmt.Sprintf("burn submit failed: %v (was Minted)", err))
		return fmt.Errorf("failed to submit burn transaction: %w", err)
	}

	lock.BurnTxHash = msg.ID
	lock.Status = LockStatusBurned
	lock.BurnedAt = time.Now().Unix()

	delete(alm.locksByStatus[LockStatusMinted], lock.ID)
	if alm.locksByStatus[LockStatusBurned] == nil {
		alm.locksByStatus[LockStatusBurned] = make(map[string]bool)
	}
	alm.locksByStatus[LockStatusBurned][lock.ID] = true

	// P3-3: structured log for asset burn.
	alm.bridge.logger.Info("asset burned", map[string]any{
		"lockID":      lock.ID,
		"sourceChain": string(lock.SourceChain),
		"targetChain": string(lock.TargetChain),
		"owner":       lock.Owner.ToHexAddress(),
		"amount":      lock.Amount.String(),
		"txHash":      lock.BurnTxHash,
	})

	return nil
}

func (alm *AssetLockManager) UnlockAsset(ctx context.Context, lockID string, burnBlockNumber uint64) error {
	if alm.IsStopped() {
		return fmt.Errorf("asset lock manager has been stopped")
	}
	alm.mu.Lock()
	defer alm.mu.Unlock()

	lock, exists := alm.locks[lockID]
	if !exists {
		return fmt.Errorf("lock not found: %s", lockID)
	}

	if lock.Status != LockStatusBurned {
		return fmt.Errorf("invalid lock status for unlocking: %d", lock.Status)
	}

	// BRIDGE-R10-HIGH-001 (2026-07-19) FIX: Verify Burn transaction
	// confirmation depth on the TARGET chain (where the burn happened)
	// before releasing the original locked funds on the source chain.
	// Previously, UnlockAsset only checked lock.Status == Burned and
	// immediately released funds — but BurnAsset only submits the burn
	// message to the bridge; the actual on-chain burn transaction may
	// still be pending or reorgable. A chain reorg on the target chain
	// could roll back the burn while the source-chain funds have already
	// been unlocked, resulting in a double-spend (funds released on
	// source AND still available on target).
	//
	// The caller (typically a relayer watching both chains) MUST supply
	// burnBlockNumber — the block on the TARGET chain at which the burn
	// transaction was included. The target-chain adapter verifies the
	// confirmation depth against its own current head. A value of 0
	// means "unknown" and is rejected to fail-closed.
	if burnBlockNumber == 0 {
		return fmt.Errorf("unlock refused: lock %s requires non-zero burnBlockNumber to verify burn confirmation depth", lock.ID)
	}
	targetAdapter, ok := alm.bridge.adapters[lock.TargetChain]
	if !ok {
		return fmt.Errorf("unlock refused: lock %s has no target adapter for chain %s (fail-closed)", lock.ID, lock.TargetChain)
	}
	burnConfirmed, err := targetAdapter.HasSufficientConfirmations(ctx, burnBlockNumber)
	if err != nil {
		return fmt.Errorf("unlock refused: failed to verify burn confirmations for lock %s: %w", lock.ID, err)
	}
	if !burnConfirmed {
		return fmt.Errorf("unlock refused: lock %s burn at block %d has insufficient confirmations on target chain %s", lock.ID, burnBlockNumber, lock.TargetChain)
	}

	// BRIDGE-R10-CRIT-001/002 (2026-07-19) FIX: Same fix as Mint/Burn —
	// populate all fund-carrying fields and route through
	// bridge.SubmitMessage so verifyQuantumSignature is enforced. The
	// unlock step is the most security-critical because it releases the
	// original locked funds on the source chain — a forged unlock with
	// no signature would let an attacker drain the bridge's locked
	// assets without any validator quorum.
	if lock.Amount == nil || lock.Amount.Sign() <= 0 {
		return fmt.Errorf("unlock refused: lock %s has invalid amount", lock.ID)
	}
	// R39-P2-05 (2026-08-02) FIX: enforce the same per-message max
	// transfer upper bound as the lock-side path (bridge.go:LockAssets).
	// Without this upper-bound check on the unlock path, a hypothetical
	// bug in LockAsset that lets lock.Amount exceed maxTransferAmount
	// (e.g., a refactor that drops the bridge.go:2525 upper-bound check)
	// would silently release / refund the inflated amount out of the
	// bridge's locked-asset reserve — the audit's R39-P2-05 finding.
	// We check at unlock-release time too so failure of any single
	// upstream check doesn't bypass the global upper bound.
	//
	// We use the shared maxTransferAmountStr constant so all three
	// paths (lock / unlock / refund-with-burn-proof) derive from one
	// source of truth.
	var r39P2_05Max big.Int
	r39P2_05Max.SetString(maxTransferAmountStr, 10)
	if lock.Amount.Cmp(&r39P2_05Max) > 0 {
		// DO NOT release the funds — the lock.amount exceeds the
		// protocol-wide upper bound. Fail-closed and refuse the
		// unlock; operator must investigate the upstream LockAsset
		// path that accepted this inflated amount.
		return fmt.Errorf("R39-P2-05: unlock refused: lock %s amount %s exceeds maximum allowed transfer limit %s (fail-closed; investigate upstream LockAsset path)", lock.ID, lock.Amount.String(), maxTransferAmountStr)
	}
	if lock.Owner == (types.Address{}) {
		return fmt.Errorf("unlock refused: lock %s has zero owner", lock.ID)
	}
	ownerAddr := lock.Owner.ToHexAddress()
	recipientAddr := lock.Recipient.ToHexAddress()
	assetID := lock.TokenAddress.ToHexAddress()
	assetType := string(lock.AssetType)
	amountStr := lock.Amount.String()

	msg := &BridgeMessage{
		ID:            lock.ID + "-unlock",
		SourceChain:   lock.TargetChain,
		TargetChain:   lock.SourceChain,
		SourceAddress: ownerAddr,
		TargetAddress: recipientAddr,
		AssetType:     AssetType(assetType),
		AssetID:       assetID,
		Amount:        amountStr,
		MessageType:   MessageTypeAssetTransfer,
		Status:        MessageStatusPending,
		Timestamp:     time.Now().Unix(),
		Nonce:         atomic.AddUint64(&alm.nonceCounter, 1),
	}

	if err := alm.bridge.SubmitMessage(ctx, msg); err != nil {
		// BRIDGE-R13-H02: Mark as Failed so RefundFailedLock can release
		// the source-chain funds. The user already burned their wrapped
		// assets on the target chain (BurnAsset succeeded) — refunding
		// the source-chain lock is the correct recovery path here (no
		// double-spend risk: target-chain assets are already burned).
		alm.markLockFailed(lock, fmt.Sprintf("unlock submit failed: %v (was Burned)", err))
		return fmt.Errorf("failed to submit unlock transaction: %w", err)
	}

	lock.UnlockTxHash = msg.ID
	lock.Status = LockStatusUnlocked
	lock.UnlockedAt = time.Now().Unix()

	delete(alm.locksByStatus[LockStatusBurned], lock.ID)
	if alm.locksByStatus[LockStatusUnlocked] == nil {
		alm.locksByStatus[LockStatusUnlocked] = make(map[string]bool)
	}
	alm.locksByStatus[LockStatusUnlocked][lock.ID] = true

	// P3-3: structured log for asset unlock.
	alm.bridge.logger.Info("asset unlocked", map[string]any{
		"lockID":      lock.ID,
		"sourceChain": string(lock.SourceChain),
		"targetChain": string(lock.TargetChain),
		"owner":       lock.Owner.ToHexAddress(),
		"amount":      lock.Amount.String(),
		"txHash":      lock.UnlockTxHash,
	})

	return nil
}

func (alm *AssetLockManager) GetLock(lockID string) (*AssetLock, bool) {
	if alm.IsStopped() {
		return nil, false
	}
	alm.mu.RLock()
	defer alm.mu.RUnlock()
	lock, exists := alm.locks[lockID]
	if !exists {
		return nil, false
	}
	copied := *lock
	if lock.Amount != nil {
		copied.Amount = new(big.Int).Set(lock.Amount)
	}
	if lock.TokenID != nil {
		copied.TokenID = new(big.Int).Set(lock.TokenID)
	}
	return &copied, true
}

func (alm *AssetLockManager) GetLocksByOwner(owner types.Address) []*AssetLock {
	if alm.IsStopped() {
		return nil
	}
	alm.mu.RLock()
	defer alm.mu.RUnlock()

	lockIDs := alm.locksByOwner[owner]
	locks := make([]*AssetLock, 0, len(lockIDs))
	for _, id := range lockIDs {
		if lock, exists := alm.locks[id]; exists {
			// R10-BR-003 FIX: Return deep copies, matching GetLock pattern.
			copied := *lock
			if lock.Amount != nil {
				copied.Amount = new(big.Int).Set(lock.Amount)
			}
			if lock.TokenID != nil {
				copied.TokenID = new(big.Int).Set(lock.TokenID)
			}
			locks = append(locks, &copied)
		}
	}
	return locks
}

func (alm *AssetLockManager) GetLocksByStatus(status LockStatus) []*AssetLock {
	if alm.IsStopped() {
		return nil
	}
	alm.mu.RLock()
	defer alm.mu.RUnlock()

	lockIDs := alm.locksByStatus[status]
	locks := make([]*AssetLock, 0, len(lockIDs))
	for id := range lockIDs {
		if lock, exists := alm.locks[id]; exists {
			// R10-BR-003 FIX: Return deep copies, matching GetLock pattern.
			copied := *lock
			if lock.Amount != nil {
				copied.Amount = new(big.Int).Set(lock.Amount)
			}
			if lock.TokenID != nil {
				copied.TokenID = new(big.Int).Set(lock.TokenID)
			}
			locks = append(locks, &copied)
		}
	}
	return locks
}

func GenerateLockID(sourceChain ChainID, owner types.Address, nonce uint64) string {
	h := sha256.New()
	h.Write([]byte(sourceChain))
	h.Write(owner[:])
	h.Write([]byte(fmt.Sprintf("%d", nonce)))
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// SetLockTimeout configures the maximum time a lock may stay in a non-terminal
// status before the timeout watcher auto-fails it.
//
// BRIDGE-R13-H02 (2026-07-21): Default is 24h (defaultLockTimeout). Callers
// may shorten this for testing or lengthen it for chains with very long
// finality (e.g., PoW chains with deep confirmation requirements). Setting
// to 0 disables the timeout watcher (NOT recommended for production).
//
// Must be called BEFORE StartTimeoutWatcher. Returns an error if the
// watcher is already running (to avoid races with the goroutine reading
// lockTimeout concurrently).
func (alm *AssetLockManager) SetLockTimeout(timeout time.Duration) error {
	if alm.IsStopped() {
		return fmt.Errorf("asset lock manager has been stopped")
	}
	alm.mu.Lock()
	defer alm.mu.Unlock()
	if alm.timeoutOn {
		return fmt.Errorf("cannot SetLockTimeout while timeout watcher is running")
	}
	alm.lockTimeout = timeout
	return nil
}

// StartTimeoutWatcher launches a background goroutine that periodically
// scans non-terminal locks (Pending/Locked/Minted/Burned) and auto-fails
// any that have been in their current status longer than lockTimeout.
//
// BRIDGE-R13-H02 (2026-07-21): Without this watcher, a lock could remain
// in Pending/Locked/Minted/Burned indefinitely if the operator forgets to
// retry it (e.g., bridge.SubmitMessage returned a transient error and was
// never retried). The user's funds would be permanently stuck.
//
// The watcher polls every pollInterval. If a lock is found to be stale,
// it transitions to LockStatusFailed with FailedReason="timeout after X
// in status Y". RefundFailedLock can then be called to release the funds.
//
// Returns an error if the watcher is already running or if lockTimeout
// is 0 (disabled).
func (alm *AssetLockManager) StartTimeoutWatcher(ctx context.Context, pollInterval time.Duration) error {
	if alm.IsStopped() {
		return fmt.Errorf("asset lock manager has been stopped")
	}
	alm.mu.Lock()
	if alm.timeoutOn {
		alm.mu.Unlock()
		return fmt.Errorf("timeout watcher already running")
	}
	if alm.lockTimeout == 0 {
		alm.mu.Unlock()
		return fmt.Errorf("lockTimeout is 0 (disabled); set a non-zero timeout via SetLockTimeout before starting")
	}
	alm.timeoutStop = make(chan struct{})
	alm.timeoutOn = true
	alm.mu.Unlock()

	alm.timeoutWG.Add(1)
	go alm.timeoutWatcherLoop(ctx, pollInterval)
	return nil
}

func (alm *AssetLockManager) timeoutWatcherLoop(ctx context.Context, pollInterval time.Duration) {
	defer alm.timeoutWG.Done()
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-alm.timeoutStop:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			alm.scanStaleLocks()
		}
	}
}

// scanStaleLocks iterates non-terminal lock statuses and fails any lock
// that has exceeded lockTimeout in its current status.
//
// The "current status timestamp" used for the timeout check is:
//   - Pending:   CreatedAt  (lock created but not yet confirmed)
//   - Locked:    LockedAt   (confirmed but not yet minted)
//   - Minted:    MintedAt   (minted but not yet burned)
//   - Burned:    BurnedAt   (burned but not yet unlocked)
//
// BRIDGE-R13-H02: transitions to Failed are logged for audit trail.
func (alm *AssetLockManager) scanStaleLocks() {
	if alm.IsStopped() {
		return
	}
	alm.mu.Lock()
	defer alm.mu.Unlock()

	if alm.lockTimeout == 0 {
		return
	}
	now := time.Now().Unix()
	timeoutSec := int64(alm.lockTimeout / time.Second)

	// Helper: returns the timestamp at which the lock entered its current
	// status, or 0 if the status has no meaningful entry timestamp.
	statusEntryTime := func(lock *AssetLock) int64 {
		switch lock.Status {
		case LockStatusPending:
			return lock.CreatedAt
		case LockStatusLocked:
			return lock.LockedAt
		case LockStatusMinted:
			return lock.MintedAt
		case LockStatusBurned:
			return lock.BurnedAt
		default:
			return 0
		}
	}

	staleStatuses := []LockStatus{
		LockStatusPending,
		LockStatusLocked,
		LockStatusMinted,
		LockStatusBurned,
	}
	for _, status := range staleStatuses {
		ids := alm.locksByStatus[status]
		for id := range ids {
			lock, exists := alm.locks[id]
			if !exists {
				continue
			}
			entryTime := statusEntryTime(lock)
			if entryTime == 0 {
				// No entry timestamp — skip (should not happen in normal
				// flow, but defensive against direct map manipulation).
				continue
			}
			if now-entryTime < timeoutSec {
				continue
			}

			// Stale: transition to Failed.
			oldStatus := lock.Status
			lock.Status = LockStatusFailed
			lock.FailedAt = now
			lock.FailedReason = fmt.Sprintf(
				"timeout after %s in status %d (entered at %d, now %d)",
				alm.lockTimeout, oldStatus, entryTime, now)

			delete(alm.locksByStatus[oldStatus], id)
			if alm.locksByStatus[LockStatusFailed] == nil {
				alm.locksByStatus[LockStatusFailed] = make(map[string]bool)
			}
			alm.locksByStatus[LockStatusFailed][id] = true

			if alm.bridge != nil && alm.bridge.logger != nil {
				alm.bridge.logger.Warn("asset lock auto-failed (timeout)", map[string]any{
					"lockID":       lock.ID,
					"oldStatus":    int(oldStatus),
					"failedReason": lock.FailedReason,
					"owner":        lock.Owner.ToHexAddress(),
					"amount":       lock.Amount.String(),
				})
			}
		}
	}
}

// markLockFailed transitions a lock to Failed status with the given reason.
// Caller MUST hold alm.mu. BRIDGE-R13-H02: extracted as a helper because
// MintAsset/BurnAsset/UnlockAsset all need the same failure transition.
func (alm *AssetLockManager) markLockFailed(lock *AssetLock, reason string) {
	oldStatus := lock.Status
	lock.Status = LockStatusFailed
	lock.FailedAt = time.Now().Unix()
	lock.FailedReason = reason

	delete(alm.locksByStatus[oldStatus], lock.ID)
	if alm.locksByStatus[LockStatusFailed] == nil {
		alm.locksByStatus[LockStatusFailed] = make(map[string]bool)
	}
	alm.locksByStatus[LockStatusFailed][lock.ID] = true

	if alm.bridge != nil && alm.bridge.logger != nil {
		alm.bridge.logger.Warn("asset lock marked failed", map[string]any{
			"lockID":       lock.ID,
			"oldStatus":    int(oldStatus),
			"failedReason": reason,
			"owner":        lock.Owner.ToHexAddress(),
			"amount":       lock.Amount.String(),
		})
	}
}

// RefundFailedLock releases the locked funds on the source chain back to
// the owner. It can ONLY be called on locks in LockStatusFailed.
//
// This is the legacy/internal entry point with NO authorization check.
// It is used by the timeout watcher and unit tests. External callers
// (RPC, governance) must use RefundFailedLockAuthorized instead.
//
// BRIDGE-R15-CRIT-001 (2026-07-22): renamed from RefundFailedLock to
// refundFailedLockLegacy. The exported RefundFailedLock is now a wrapper
// that delegates here for backward compatibility with existing callers.
//
// BRIDGE-R13-H02 (2026-07-21): Previously, when MintAsset/BurnAsset/
// UnlockAsset failed (bridge.SubmitMessage returned error), the lock
// remained in its current status with no path to release the stuck
// funds — user assets were permanently locked. The timeout watcher
// could also auto-fail a stale lock without any refund path.
//
// This method constructs a refund BridgeMessage routed through
// bridge.SubmitMessage (so validateMessage + verifyQuantumSignature are
// enforced — a forged refund would be rejected at the bridge level).
// On success, transitions the lock to LockStatusRefunded.
//
// Caller must have governance/operator authority — refunding a lock
// releases real funds. The caller is responsible for signature generation;
// this method only builds the message structure.
//
// Refund direction: from the source chain (where funds are locked) back
// to the owner. The source chain adapter must recognize this message as a
// release-lock instruction and unlock the originally locked funds.
//
// Note: For locks that failed at the Minted stage (BurnAsset failure),
// the user still holds wrapped assets on the target chain. Refunding the
// source-chain lock without burning the target-chain wrapped assets would
// be a double-spend — the bridge operator must handle this case
// out-of-band (e.g., manually burn the wrapped assets) before calling
// RefundFailedLock. This method logs a warning when refunding a lock that
// was in Minted status at failure time, but does NOT block the refund —
// the operator is responsible for ensuring no double-spend.
func (alm *AssetLockManager) refundFailedLockLegacy(ctx context.Context, lockID string) error {
	if alm.IsStopped() {
		return fmt.Errorf("asset lock manager has been stopped")
	}
	alm.mu.Lock()
	defer alm.mu.Unlock()

	lock, exists := alm.locks[lockID]
	if !exists {
		return fmt.Errorf("lock not found: %s", lockID)
	}
	if lock.Status != LockStatusFailed {
		return fmt.Errorf("lock %s is not failed (status=%d); only failed locks can be refunded", lockID, lock.Status)
	}
	if lock.Amount == nil || lock.Amount.Sign() <= 0 {
		return fmt.Errorf("refund refused: lock %s has invalid amount", lock.ID)
	}
	if lock.Owner == (types.Address{}) {
		return fmt.Errorf("refund refused: lock %s has zero owner", lock.ID)
	}

	// BRIDGE-H06 (R30, 2026-07-27) FIX: A lock whose last good status was
	// Minted (inferred from FailedReason containing "Minted") requires a
	// verified BurnProof before the refund may proceed. Without a burn
	// proof, refunding the source-chain lock would create a double-spend:
	// the user keeps the wrapped asset on the target chain AND gets the
	// original asset back on the source chain. The legacy/internal path
	// (timeout watcher, HandlePendingMessageEviction) does NOT supply a
	// burn proof, so it is fail-closed for Minted locks. Operators must
	// use RefundFailedLockWithBurnProof to supply the on-chain burn
	// evidence.
	if containsMintedHint(lock.FailedReason) && lock.BurnProof == nil {
		if alm.bridge != nil && alm.bridge.logger != nil {
			alm.bridge.logger.Warn("refund rejected: lock was in Minted status and no burn proof was supplied (BRIDGE-H06)", map[string]any{
				"lockID":       lock.ID,
				"failedReason": lock.FailedReason,
				"owner":        lock.Owner.ToHexAddress(),
				"amount":       lock.Amount.String(),
			})
		}
		return fmt.Errorf("refund refused: lock %s was in Minted status — burn proof is required to prevent double-spend (BRIDGE-H06)", lock.ID)
	}

	// ECON-R14-H03: build the refund message via a helper so the
	// message-construction logic is unit-testable independently of
	// bridge.SubmitMessage (which fails-closed in tests when no
	// trusted validator keys are configured).
	msg := alm.buildRefundMessage(lock)

	if err := alm.bridge.SubmitMessage(ctx, msg); err != nil {
		return fmt.Errorf("failed to submit refund transaction: %w", err)
	}

	lock.RefundTxHash = msg.ID
	lock.RefundedAt = time.Now().Unix()

	delete(alm.locksByStatus[LockStatusFailed], lock.ID)
	if alm.locksByStatus[LockStatusRefunded] == nil {
		alm.locksByStatus[LockStatusRefunded] = make(map[string]bool)
	}
	alm.locksByStatus[LockStatusRefunded][lock.ID] = true
	lock.Status = LockStatusRefunded

	if alm.bridge != nil && alm.bridge.logger != nil {
		alm.bridge.logger.Info("asset lock refunded", map[string]any{
			"lockID":       lock.ID,
			"sourceChain":  string(lock.SourceChain),
			"owner":        lock.Owner.ToHexAddress(),
			"amount":       lock.Amount.String(),
			"refundTxID":   lock.RefundTxHash,
			"failedReason": lock.FailedReason,
		})
	}

	return nil
}

// RefundFailedLock was an exported wrapper around refundFailedLockLegacy
// that performed NO authorization check. It has been REMOVED in R35-P0-13
// because any RPC caller could trigger an arbitrary lockID refund and the
// bridge internally signs the refund message with trustedValidatorKeys,
// enabling fund theft.
//
// Migration paths:
//   - External callers (RPC, governance) MUST use RefundFailedLockAuthorized,
//     which enforces the authorizedOperators whitelist and fails closed
//     when no operators are configured.
//   - Internal callers (timeout watcher) and same-package tests use the
//     unexported refundFailedLockLegacy directly.
//
// (Function body intentionally removed — see git history for the original
// implementation if needed for forensic analysis.)

// RefundFailedLockAuthorized is the external entry point for refund
// operations. It enforces caller authorization before delegating to
// refundFailedLockLegacy.
//
// BRIDGE-R15-CRIT-001 (2026-07-22): Previously RefundFailedLock had no
// caller authorization, so any RPC caller could trigger a refund on an
// arbitrary lockID. This method fail-closed when no operators are
// configured, and rejects callers not in the operator set.
func (alm *AssetLockManager) RefundFailedLockAuthorized(ctx context.Context, lockID string, caller types.Address) error {
	alm.mu.RLock()
	authorized := alm.authorizedOperators[caller]
	alm.mu.RUnlock()
	if !authorized {
		return ErrUnauthorizedOperator
	}
	return alm.refundFailedLockLegacy(ctx, lockID)
}

// SetOperatorAdmin rotates the operator admin AFTER the trust root has been
// injected at construction (see NewAssetLockManager initialAdmin).
//
// R41-BRIDGE-07 (2026-08-03) FIX: removed the prior "first caller wins"
// fail-open bootstrap. The previous behavior, when operatorAdmin was zero,
// accepted ANY caller as the initializer, relying purely on a comment
// "RPC callers should never have a path to this method" — an implicit
// contract with no runtime enforcement and zero audit trail. With the
// trust root now injected at construction, this method is rotate-only:
//
//   - If alm.operatorAdmin is zero (no trust root injected), this method
//     ALWAYS returns an error. The caller MUST fix the deployment by
//     providing OperatorAdminAddress in the node config (or, for tests,
//     set it via a dedicated test helper), not by silently becoming the
//     admin.
//   - If alm.operatorAdmin is non-zero, only the current admin can
//     rotate to a new admin. This preserves the post-bootstrap rotation
//     flow (e.g. after a multisig key rotation) without weakening the
//     initial-trust-root guarantee.
//
// Returns an error if the new admin address is zero (cannot unset admin).
func (alm *AssetLockManager) SetOperatorAdmin(caller, newAdmin types.Address) error {
	if newAdmin == (types.Address{}) {
		return fmt.Errorf("operator admin cannot be zero address")
	}
	alm.mu.Lock()
	defer alm.mu.Unlock()
	// R41-BRIDGE-07: fail-closed — the admin MUST be bootstrapped at
	// construction (NewAssetLockManager initialAdmin). There is NO runtime
	// bootstrap path; the prior "first caller wins" branch is removed because
	// it allowed any code with a *AssetLockManager reference to silently
	// become the operator admin (and from there inject arbitrary operators
	// via SetAuthorizedOperatorsAuthorized, enabling unauthorized refunds).
	if alm.operatorAdmin == (types.Address{}) {
		return fmt.Errorf("unauthorized: operator admin not bootstrapped at construction (configure bridge.operatorAdminAddress in the node config, or pass initialAdmin to NewAssetLockManager)")
	}
	if caller != alm.operatorAdmin {
		return fmt.Errorf("unauthorized: only current operator admin can rotate admin")
	}
	alm.operatorAdmin = newAdmin
	return nil
}

// GetOperatorAdmin returns the currently configured operator admin.
// Returns zero address when unconfigured (fail-closed state).
func (alm *AssetLockManager) GetOperatorAdmin() types.Address {
	alm.mu.RLock()
	defer alm.mu.RUnlock()
	return alm.operatorAdmin
}

// SetAuthorizedOperatorsAuthorized replaces the authorized operator set.
// The caller MUST be the configured operatorAdmin (governance/multisig).
// Fails closed when no admin is configured — admin MUST be bootstrapped
// first via SetOperatorAdmin.
//
// R35-P2-BRIDGE-01 FIX (2026-07-29): closes the unauthorized operator-set
// replacement vulnerability. The legacy unauthenticated SetAuthorizedOperators
// has been removed; this method is the sole public entry point.
//
// Duplicates in the operators slice are deduped via the map. Pass nil/empty
// to clear all operators (fail-closed for refunds).
func (alm *AssetLockManager) SetAuthorizedOperatorsAuthorized(caller types.Address, operators []types.Address) error {
	alm.mu.Lock()
	defer alm.mu.Unlock()
	if alm.operatorAdmin == (types.Address{}) {
		return fmt.Errorf("unauthorized: operator admin not configured (call SetOperatorAdmin first)")
	}
	if caller != alm.operatorAdmin {
		return fmt.Errorf("unauthorized: caller is not the operator admin")
	}
	alm.authorizedOperators = make(map[types.Address]bool, len(operators))
	for _, op := range operators {
		alm.authorizedOperators[op] = true
	}
	return nil
}

// setAuthorizedOperatorsForTest is an unexported helper that replaces the
// operator set WITHOUT authorization. It is intended ONLY for:
//   - Internal bridge initialization (before the admin is bootstrapped)
//   - Same-package unit tests that need to set up operator state without
//     the full admin bootstrap dance
//
// Production code MUST use SetAuthorizedOperatorsAuthorized instead.
func (alm *AssetLockManager) setAuthorizedOperatorsForTest(operators []types.Address) {
	alm.mu.Lock()
	defer alm.mu.Unlock()
	alm.authorizedOperators = make(map[types.Address]bool, len(operators))
	for _, op := range operators {
		alm.authorizedOperators[op] = true
	}
}

// IsAuthorizedOperator returns true if the address is in the authorized
// operator set. Returns false for everyone when unconfigured (fail-closed).
// BRIDGE-R15-CRIT-001 (2026-07-22).
func (alm *AssetLockManager) IsAuthorizedOperator(addr types.Address) bool {
	alm.mu.RLock()
	defer alm.mu.RUnlock()
	return alm.authorizedOperators[addr]
}

// RefundFailedLockWithBurnProof is the operator API for refunding a Failed
// lock that was in Minted status at failure time. The caller must be an
// authorized operator, and the burn proof must be structurally valid and
// match the lock (TargetChain and Amount). Once attached, the burn proof
// is immutable — retrying with the SAME proof is idempotent (succeeds /
// fails the same way), but retrying with a DIFFERENT proof is rejected
// (no proof swapping).
//
// BRIDGE-H06 (R30, 2026-07-27): prevents double-spend on Minted locks.
func (alm *AssetLockManager) RefundFailedLockWithBurnProof(ctx context.Context, lockID string, caller types.Address, proof *BurnProof) error {
	// 1. Authorization check (fail-closed when no operators configured).
	alm.mu.RLock()
	authorized := alm.authorizedOperators[caller]
	alm.mu.RUnlock()
	if !authorized {
		return ErrUnauthorizedOperator
	}

	// 2. Structural validation of the burn proof (before acquiring the
	//    write lock — these checks don't touch alm state).
	if proof == nil {
		return fmt.Errorf("burn proof is required for Minted-status lock refund (BRIDGE-H06)")
	}
	if proof.TxHash == "" {
		return fmt.Errorf("burn proof TxHash is required (BRIDGE-H06)")
	}
	if proof.Amount == nil || proof.Amount.Sign() <= 0 {
		return fmt.Errorf("burn proof amount must be positive (BRIDGE-H06)")
	}
	// R39-P2-05 (2026-08-02) FIX: enforce the per-message max transfer
	// upper bound on the refund-with-burn-proof path too. The audit's
	// finding observes that the unlock proof paths lacked amount range
	// upper-bound validation. Without this check, a compromised
	// operator who forges a burn proof with an inflated amount (within
	// the strict equality `proof.Amount == lock.Amount` check at line
	// ~1435 — the upper bound would have to come from upstream
	// LockAsset's behavior) could potentially refund an inflated
	// amount if the upstream lock path ever accepted amount >
	// maxTransferAmount. We check here too so failure of any single
	// upstream check doesn't bypass the global upper bound.
	var r39P2_05Max big.Int
	r39P2_05Max.SetString(maxTransferAmountStr, 10)
	if proof.Amount.Cmp(&r39P2_05Max) > 0 {
		return fmt.Errorf("R39-P2-05: burn proof amount %s exceeds maximum allowed transfer limit %s (fail-closed; investigate upstream LockAsset path that created this lock)", proof.Amount.String(), maxTransferAmountStr)
	}

	// 3. On-chain burn verification (R37 P2-BRIDGE-01). Before trusting the
	//    proof, ask the target-chain adapter to verify the TxHash is a real,
	//    finalized burn transaction. This prevents a compromised operator from
	//    forging a TxHash and double-spending (source-chain refund + target-
	//    chain wrapped asset still in circulation).
	alm.mu.RLock()
	bridge := alm.bridge
	alm.mu.RUnlock()
	// R38-P1-11 FIX (2026-08-01): fail-closed at every layer.
	// Previously, bridge==nil / adapter==nil / GetAdapter err all silently
	// skipped on-chain burn verification (fail-open), allowing a forged
	// TxHash to release the source-chain refund while the target-chain
	// wrapped asset stayed in circulation (double-spend). Now every layer
	// must succeed: bridge configured → adapter registered → verify no
	// error → verify true. Anything else rejects the refund.
	//
	// NOTE: This is the surgical fail-closed portion only. Full field-level
	// verification (burn calldata / Burn event / real token / beneficiary /
	// amount / finality) requires extending the ChainAdapter interface
	// signature and updating 5 mock adapters — a follow-up task.
	if bridge == nil {
		return fmt.Errorf("R38-P1-11: bridge not configured, cannot verify burn proof")
	}
	adapter, err := bridge.GetAdapter(proof.ChainID)
	if err != nil {
		return fmt.Errorf("R38-P1-11: no adapter registered for chain %s: %w", proof.ChainID, err)
	}
	if adapter == nil {
		return fmt.Errorf("R38-P1-11: adapter for chain %s is nil", proof.ChainID)
	}
	// R38-P1-11 DEEP FIX (2026-08-02): pass the full BurnVerificationRequest
	// so the adapter can perform field-level calldata verification instead
	// of only receipt-status + contract-whitelist match. Each field is
	// reproduced from BurnProof's struct so the request mirrors exactly
	// what the caller of RefundFailedLockWithBurnProof attested to.
	burnReq := &BurnVerificationRequest{
		TxHash:        proof.TxHash,
		ChainID:       proof.ChainID,
		Amount:        proof.Amount,
		ValidatorAddr: proof.ValidatorAddr,
		FundingEpoch:  proof.FundingEpoch,
		Signature:     proof.Signature,
		Beneficiary:   proof.Beneficiary,
	}
	verified, err := adapter.VerifyBurnTransaction(ctx, burnReq)
	if err != nil {
		return fmt.Errorf("R38-P1-11: burn verification error: %w", err)
	}
	if !verified {
		return fmt.Errorf("R38-P1-11: burn verification returned false (tx %s is not a valid burn)", proof.TxHash)
	}

	// 4. Acquire the write lock and validate the proof against the lock.
	alm.mu.Lock()
	// Re-check authorizedOperators under the write lock to avoid TOCTOU.
	if !alm.authorizedOperators[caller] {
		alm.mu.Unlock()
		return ErrUnauthorizedOperator
	}
	lock, exists := alm.locks[lockID]
	if !exists {
		alm.mu.Unlock()
		return fmt.Errorf("lock not found: %s", lockID)
	}
	if lock.Status != LockStatusFailed {
		alm.mu.Unlock()
		return fmt.Errorf("lock %s is not failed (status=%d); only failed locks can be refunded", lockID, lock.Status)
	}
	// Verify the burn proof's ChainID matches lock.TargetChain.
	if proof.ChainID != lock.TargetChain {
		alm.mu.Unlock()
		return fmt.Errorf("burn proof ChainID mismatch: proof=%s, lock.TargetChain=%s (BRIDGE-H06)", proof.ChainID, lock.TargetChain)
	}
	// Verify the burn proof's Amount matches lock.Amount exactly.
	if lock.Amount == nil || proof.Amount.Cmp(lock.Amount) != 0 {
		alm.mu.Unlock()
		return fmt.Errorf("burn proof amount mismatch: proof=%s, lock.Amount=%s (BRIDGE-H06)", proof.Amount.String(), lock.Amount.String())
	}
	// Idempotent retry: if a burn proof is already attached, the new
	// proof must match it EXACTLY. Any difference is rejected to prevent
	// proof swapping (e.g., replacing a real burn with a forged one).
	if lock.BurnProof != nil {
		if lock.BurnProof.TxHash != proof.TxHash ||
			lock.BurnProof.ChainID != proof.ChainID ||
			lock.BurnProof.Amount.Cmp(proof.Amount) != 0 {
			alm.mu.Unlock()
			return fmt.Errorf("burn proof mismatch: lock already has a different proof attached (BRIDGE-H06, no proof swapping)")
		}
		// Same proof — fall through to retry the refund. The lock is
		// still in Failed status (a previous attempt failed at
		// SubmitMessage), so we proceed.
	} else {
		// First valid proof — attach it to the lock as an audit trail.
		// The proof is stored as a deep copy to prevent the caller from
		// mutating it after attachment.
		lock.BurnProof = &BurnProof{
			TxHash:  proof.TxHash,
			ChainID: proof.ChainID,
			Amount:  new(big.Int).Set(proof.Amount),
		}
	}
	alm.mu.Unlock()

	// 4. Delegate to the legacy refund path. The burn proof is now
	//    attached, so the Minted-status check passes. We pass ctx
	//    through so the operator can cancel the operation.
	return alm.refundFailedLockLegacy(ctx, lockID)
}

// HandlePendingMessageEviction is the hook invoked by QuantumBridge's
// evictOldMessages when a PENDING BridgeMessage is evicted from memory
// due to age or capacity pressure. It marks the corresponding AssetLock
// (if any) as Failed so the timeout watcher / operator can later refund
// the stuck source-chain funds.
//
// BRIDGE-R15-CRIT-002 (2026-07-22): Previously, evicting a PENDING
// message silently dropped it from memory while the user's locked assets
// remained permanently stuck on the source chain — no refund path was
// triggered. This hook bridges the gap: the bridge registers it via
// SetPendingEvictionHook, and evictOldMessages invokes it before
// deleting the PENDING message. The hook is a no-op for non-existent
// locks (e.g., manual bridge messages without an associated lock) and
// for locks in non-Pending statuses (the timeout watcher handles those).
func (alm *AssetLockManager) HandlePendingMessageEviction(lockID string) {
	if alm.IsStopped() {
		return
	}
	alm.mu.Lock()
	defer alm.mu.Unlock()
	lock, exists := alm.locks[lockID]
	if !exists {
		// Not an asset-lock message — no-op (e.g., manual bridge message).
		return
	}
	if lock.Status != LockStatusPending {
		// Non-Pending lock — leave it alone. The timeout watcher is
		// responsible for auto-failing stale non-Pending locks.
		return
	}
	// Mark the lock as Failed with a clear reason for the audit trail.
	// The operator can then refund it via RefundFailedLockAuthorized
	// (or RefundFailedLockWithBurnProof if it had reached Minted).
	reason := fmt.Sprintf("pending message evicted from bridge memory at %s (was Pending)", time.Now().Format(time.RFC3339))
	alm.markLockFailed(lock, reason)
}

// buildRefundMessage constructs the BridgeMessage that RefundFailedLock
// submits to release locked funds back to the owner when a mint/burn/
// unlock step has permanently failed.
//
// ECON-R14-H03 (2026-07-21): extracted from RefundFailedLock so the
// message-construction logic is unit-testable independently of
// bridge.SubmitMessage (which fails-closed in tests when no trusted
// validator keys are configured).
//
// Three corrections vs. the pre-fix code:
//
//  1. SourceAddress: was lock.TokenAddress (token contract) with a
//     misleading "bridge holding address" comment. The source-chain
//     adapter resolves locked balances by owner address (matching
//     LockAsset and UnlockAsset, both of which use ownerAddr). Setting
//     it to the token contract meant no lock record matched → refund
//     failed on the source chain.
//
//  2. SourceChain/TargetChain: were BOTH set to lock.SourceChain,
//     which tripped validateMessageFields' "source and target chains
//     must be different" check (bridge.go:2046) BEFORE the message
//     ever reached the adapter. The existing
//     TestBRIDGE_R13H02_RefundFailedLockStaysFailedOnSubmitError
//     passed for the WRONG reason — it expected failure but the
//     failure was the chain check, not the signature check the test
//     comment claimed.
//
//  3. Routing: the refund must route FROM the target chain (where
//     the mint failure was observed) TO the source chain (where the
//     funds are locked and must be released). This mirrors the
//     UnlockAsset message (SourceChain=lock.TargetChain,
//     TargetChain=lock.SourceChain).
//
// TargetAddress is the owner (not the original recipient) because a
// refund returns the locked funds to the person who locked them; the
// recipient never received wrapped assets (mint failed).
//
// Signature consistency: SourceAddress is folded into the signed
// message hash (see hashLeafMessage / adapter signature at
// ethereum_adapter.go:1590). Using the same value as LockAsset/
// UnlockAsset keeps the signing canonical and lets the source-chain
// adapter verify the refund against the owner's original lock record.
func (alm *AssetLockManager) buildRefundMessage(lock *AssetLock) *BridgeMessage {
	ownerAddr := lock.Owner.ToHexAddress()
	return &BridgeMessage{
		ID:            lock.ID + "-refund",
		SourceChain:   lock.TargetChain, // failure observed on target chain
		TargetChain:   lock.SourceChain, // release funds on source chain
		SourceAddress: ownerAddr,        // ECON-R14-H03: owner, not token contract
		TargetAddress: ownerAddr,        // refund goes to owner, not recipient
		AssetType:     lock.AssetType,
		AssetID:       lock.TokenAddress.ToHexAddress(),
		Amount:        lock.Amount.String(),
		MessageType:   MessageTypeAssetTransfer,
		Status:        MessageStatusPending,
		Timestamp:     time.Now().Unix(),
		Nonce:         atomic.AddUint64(&alm.nonceCounter, 1),
	}
}

// containsMintedHint returns true if the failed reason string contains
// "Minted", indicating the lock was in Minted status when it failed.
// Used by RefundFailedLock to emit a double-spend warning.
func containsMintedHint(reason string) bool {
	for i := 0; i+6 <= len(reason); i++ {
		if reason[i:i+6] == "Minted" {
			return true
		}
	}
	return false
}
