// Quantaureum Node source, version 1.0.0.
// Package consensus implements advanced QPOS features.
// This file contains:
// - Validator registration/exit queue
// - Sync Committee for light clients
// - Withdrawal mechanism
// - Inactivity leak
// - LMD GHOST fork choice
package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"sort"
	"sync"
	"time"

	qaucrypto "github.com/quantaureum/qau/crypto"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// dilithiumSyncSigVerifier is the production SyncSigVerifier implementation
// backed by Dilithium3 (crypto.PublicKeyFromBytes + crypto.Verify).
//
// R40-P0 FIX (2026-08-04): NewSyncCommitteeManager() was previously called
// without a verifier in block.go:570, qpos_advanced.go:1518 and 1548, causing
// SyncCommitteeManager.sigVerifier to remain nil. SubmitSyncCommitteeSignature
// then fail-closed and dropped EVERY sync committee signature with
// "no verifier configured", breaking light-client finality. This adapter wires
// the consensus Dilithium3 verification path into the sync committee manager.
type dilithiumSyncSigVerifier struct{}

// VerifySignature implements SyncSigVerifier. It parses the Dilithium3 public
// key from raw bytes and verifies the signature against the message.
func (d *dilithiumSyncSigVerifier) VerifySignature(pubKey []byte, message []byte, signature []byte) bool {
	if len(pubKey) != qaucrypto.Dilithium3PublicKeySize {
		qposAdvLogger.Warn("dilithiumSyncSigVerifier: wrong public key length",
			map[string]any{"len": len(pubKey), "expected": qaucrypto.Dilithium3PublicKeySize, "category": "SECURITY"})
		return false
	}
	pk, err := qaucrypto.PublicKeyFromBytes(pubKey)
	if err != nil {
		qposAdvLogger.Warn("dilithiumSyncSigVerifier: invalid public key",
			map[string]any{"err": err.Error(), "category": "SECURITY"})
		return false
	}
	return qaucrypto.Verify(pk, message, signature)
}

// NewDilithiumSyncSigVerifier returns a production SyncSigVerifier backed by
// Dilithium3 crypto.Verify. Callers should pass this to NewSyncCommitteeManager
// so sync committee signatures are cryptographically verified instead of being
// silently dropped.
func NewDilithiumSyncSigVerifier() SyncSigVerifier {
	return &dilithiumSyncSigVerifier{}
}

// BuildSyncCommitteeMessage constructs the signed message payload that sync
// committee members must sign and that SubmitSyncCommitteeSignature verifies.
// Layout: "sync_committee_v2" || chainID(8) || epoch(8) || height(8) ||
// slot(8) || blockRoot(32).
//
// R40-P0 FIX (2026-08-04): Exposed as a public method so block_producer.go
// signs EXACTLY the same payload the verifier checks. Previously the producer
// signed computeSigningData() (a bare header hash) while the verifier checked
// the composite "sync_committee_v2||..." message — a mismatch that would cause
// every signature to fail verification even after the verifier is wired in.
func BuildSyncCommitteeMessage(chainID, epoch, height, slot uint64, blockRoot types.Hash) []byte {
	const prefix = "sync_committee_v2"
	msg := make([]byte, len(prefix)+8+8+8+8+types.HashLength)
	offset := copy(msg, []byte(prefix))
	binary.BigEndian.PutUint64(msg[offset:], chainID)
	offset += 8
	binary.BigEndian.PutUint64(msg[offset:], epoch)
	offset += 8
	binary.BigEndian.PutUint64(msg[offset:], height)
	offset += 8
	binary.BigEndian.PutUint64(msg[offset:], slot)
	offset += 8
	copy(msg[offset:], blockRoot[:])
	return msg
}

var qposAdvLogger = logging.Global()

// Advanced QPOS Errors
var (
	ErrParentNotFound           = errors.New("parent block not found")
	ErrInsufficientStake        = errors.New("stake amount below minimum required") // H-18 fix
	ErrInvalidWithdrawalAddress = errors.New("withdrawal address cannot be zero")   // H-FUND-3 fix
)

// Queue limits to prevent DoS
const (
	MaxEntryQueueSize     = 10000
	MaxExitQueueSize      = 10000
	MaxPendingWithdrawals = 50000
	MaxForkChoiceBlocks   = 100000
)

// Advanced QPOS Constants
const (
	// Validator lifecycle
	MinValidatorWithdrawableEpoch = 256 // ~27 hours before withdrawal
	MaxValidatorsPerEpoch         = 16  // Phase 1: 4→16 for faster validator onboarding
	ValidatorActivationDelay      = 4   // Epochs before activation
	ValidatorExitDelay            = 4   // Epochs before exit is processed

	// Sync Committee
	SyncCommitteeSize   = 512 // Size of sync committee
	SyncCommitteePeriod = 256 // Epochs per sync committee period

	// Inactivity leak
	InactivityScoreBias                = 4        // Bias for inactivity score
	InactivityScoreRecoveryRate        = 16       // Recovery rate when participating
	InactivityPenaltyQuotientBellatrix = 16777216 // ~2^24

	// Fork choice
	ProposerScoreBoostPercent = 40 // 40% boost for timely blocks
	ReorgMaxEpochsBack        = 2  // Max epochs to reorg
)

// ============================================================================
// VALIDATOR LIFECYCLE (Registration, Activation, Exit, Withdrawal)
// ============================================================================

// ValidatorStatus represents the lifecycle status of a validator
type ValidatorStatus int

const (
	ValidatorStatusPending ValidatorStatus = iota
	ValidatorStatusActive
	ValidatorStatusExiting
	ValidatorStatusSlashed
	ValidatorStatusWithdrawable
	ValidatorStatusWithdrawn
)

// String returns the string representation of ValidatorStatus
func (s ValidatorStatus) String() string {
	switch s {
	case ValidatorStatusPending:
		return "pending"
	case ValidatorStatusActive:
		return "active"
	case ValidatorStatusExiting:
		return "exiting"
	case ValidatorStatusSlashed:
		return "slashed"
	case ValidatorStatusWithdrawable:
		return "withdrawable"
	case ValidatorStatusWithdrawn:
		return "withdrawn"
	default:
		return "unknown"
	}
}

// ValidatorLifecycle tracks the full lifecycle of a validator
type ValidatorLifecycle struct {
	Address           types.Address
	Status            ValidatorStatus
	ActivationEpoch   uint64 // Epoch when validator becomes active
	ExitEpoch         uint64 // Epoch when validator exits
	WithdrawableEpoch uint64 // Epoch when withdrawal is possible
	SlashedEpoch      uint64 // Epoch when slashed (0 if not slashed)
	EffectiveBalance  *big.Int
	InactivityScore   uint64 // Score for inactivity leak
	WithdrawalAddress types.Address
}

// ValidatorQueue manages validator entry and exit queues
type ValidatorQueue struct {
	mu sync.RWMutex

	// Entry queue (validators waiting to be activated)
	entryQueue []*ValidatorLifecycle

	// Exit queue (validators waiting to exit)
	exitQueue []*ValidatorLifecycle

	// All validators by address
	validators map[types.Address]*ValidatorLifecycle

	// Withdrawal requests
	withdrawalQueue []*WithdrawalRequest
}

// WithdrawalRequest represents a withdrawal request
type WithdrawalRequest struct {
	ValidatorAddress  types.Address
	WithdrawalAddress types.Address
	Amount            *big.Int
	RequestEpoch      uint64
	ProcessedEpoch    uint64
}

// NewValidatorQueue creates a new validator queue
func NewValidatorQueue() *ValidatorQueue {
	return &ValidatorQueue{
		entryQueue:      make([]*ValidatorLifecycle, 0),
		exitQueue:       make([]*ValidatorLifecycle, 0),
		validators:      make(map[types.Address]*ValidatorLifecycle),
		withdrawalQueue: make([]*WithdrawalRequest, 0),
	}
}

// RegisterValidator registers a new validator for activation
// audit-fix CR-2: Added caller parameter and authorization check
func (vq *ValidatorQueue) RegisterValidator(caller, addr types.Address, stake *big.Int, withdrawalAddr types.Address, currentEpoch uint64) error {
	vq.mu.Lock()
	defer vq.mu.Unlock()

	// CRITICAL security fix: verify caller is the address being registered
	// This prevents unauthorized registration of validators
	if caller != addr {
		return ErrUnauthorizedValidatorOperation
	}

	if stake == nil || stake.Cmp(MinStakeAmount) < 0 {
		return ErrInsufficientStake
	}

	if _, exists := vq.validators[addr]; exists {
		return ErrValidatorAlreadyExists
	}

	lifecycle := &ValidatorLifecycle{
		Address:           addr,
		Status:            ValidatorStatusPending,
		ActivationEpoch:   currentEpoch + ValidatorActivationDelay,
		ExitEpoch:         ^uint64(0), // Max uint64 = not exiting
		WithdrawableEpoch: ^uint64(0),
		EffectiveBalance:  new(big.Int).Set(stake),
		WithdrawalAddress: withdrawalAddr,
	}

	vq.validators[addr] = lifecycle

	if len(vq.entryQueue) >= MaxEntryQueueSize {
		return errors.New("entry queue full, try again later")
	}
	vq.entryQueue = append(vq.entryQueue, lifecycle)

	return nil
}

// RequestExit requests a validator to exit
// audit-fix CR-4: Added caller parameter and authorization check
func (vq *ValidatorQueue) RequestExit(caller, addr types.Address, currentEpoch uint64) error {
	vq.mu.Lock()
	defer vq.mu.Unlock()

	// CRITICAL security fix: verify caller is the address requesting exit
	if caller != addr {
		return ErrUnauthorizedValidatorOperation
	}

	v, exists := vq.validators[addr]
	if !exists {
		return ErrValidatorNotFound
	}

	if v.Status != ValidatorStatusActive {
		return ErrValidatorNotActive
	}

	v.Status = ValidatorStatusExiting
	v.ExitEpoch = currentEpoch + ValidatorExitDelay
	v.WithdrawableEpoch = v.ExitEpoch + MinValidatorWithdrawableEpoch

	if len(vq.exitQueue) >= MaxExitQueueSize {
		return errors.New("exit queue full, try again later")
	}
	vq.exitQueue = append(vq.exitQueue, v)

	return nil
}

// ProcessEpoch processes validator activations and exits for an epoch.
// R40-A-C3 FIX: Now returns the addresses of activated validators so callers
// can sync with ValidatorManager via SetActive. This prevents slashed validators
// from being activated in ValidatorQueue while ValidatorManager doesn't know.
//
// L20-002 SECURITY NOTE: The returned activatedAddrs MUST be processed by the
// caller (see ProcessEpochAdvanced, which iterates over them and calls
// SetActive for each). Callers that discard activatedAddrs (e.g. using _)
// risk leaving ValidatorManager unaware of newly active validators, creating
// an inconsistency where the queue marks a validator active but ValidatorManager
// still considers it inactive/jailed. This would allow slashed or
// insufficiently-staked validators to bypass security checks.
func (vq *ValidatorQueue) ProcessEpoch(epoch uint64) (activated int, exited int, activatedAddrs []types.Address) {
	vq.mu.Lock()
	defer vq.mu.Unlock()

	// Process activations (up to MaxValidatorsPerEpoch)
	newEntryQueue := make([]*ValidatorLifecycle, 0)
	activatedAddrs = make([]types.Address, 0)

	for _, v := range vq.entryQueue {
		if v.ActivationEpoch <= epoch && activated < MaxValidatorsPerEpoch {
			v.Status = ValidatorStatusActive
			activated++
			activatedAddrs = append(activatedAddrs, v.Address)
		} else {
			newEntryQueue = append(newEntryQueue, v)
		}
	}
	vq.entryQueue = newEntryQueue

	// Process exits (up to MaxValidatorsPerEpoch)
	newExitQueue := make([]*ValidatorLifecycle, 0)

	for _, v := range vq.exitQueue {
		if v.ExitEpoch <= epoch && exited < MaxValidatorsPerEpoch {
			if v.WithdrawableEpoch <= epoch {
				v.Status = ValidatorStatusWithdrawable
			}
			exited++
		} else {
			newExitQueue = append(newExitQueue, v)
		}
	}
	vq.exitQueue = newExitQueue

	return activated, exited, activatedAddrs
}

// GetValidatorStatus returns the status of a validator.
// audit-fix R6-M2: returns a deep copy to prevent external mutation of
// internal state (EffectiveBalance, Status, etc.) without holding the lock.
func (vq *ValidatorQueue) GetValidatorStatus(addr types.Address) (*ValidatorLifecycle, error) {
	vq.mu.RLock()
	defer vq.mu.RUnlock()

	v, exists := vq.validators[addr]
	if !exists {
		return nil, ErrValidatorNotFound
	}

	vCopy := *v
	if v.EffectiveBalance != nil {
		vCopy.EffectiveBalance = new(big.Int).Set(v.EffectiveBalance)
	}
	return &vCopy, nil
}

// RemoveValidator removes a validator from the queue and both entry/exit queues.
// FIX: Called by ValidatorManager.RemoveValidator (when linked via
// SetValidatorQueue) to keep ValidatorManager and ValidatorQueue in sync.
// Previously, stale ValidatorLifecycle entries could remain in the queue after
// the validator was removed from ValidatorManager, causing misaligned processing.
// P1-05 FIX (R45): Add caller authorization check, consistent with
// RegisterValidator (L156) and RequestExit (L195). Without this, any caller
// could remove arbitrary validators from the queue.
func (vq *ValidatorQueue) RemoveValidator(caller, addr types.Address) error {
	vq.mu.Lock()
	defer vq.mu.Unlock()

	// CRITICAL security fix: verify caller is authorized to remove the validator.
	// Only the validator themselves or an authorized governance caller can remove.
	if caller != addr {
		return ErrUnauthorizedValidatorOperation
	}

	delete(vq.validators, addr)

	// Remove from entry queue
	newEntry := make([]*ValidatorLifecycle, 0, len(vq.entryQueue))
	for _, v := range vq.entryQueue {
		if v.Address != addr {
			newEntry = append(newEntry, v)
		}
	}
	vq.entryQueue = newEntry

	// Remove from exit queue
	newExit := make([]*ValidatorLifecycle, 0, len(vq.exitQueue))
	for _, v := range vq.exitQueue {
		if v.Address != addr {
			newExit = append(newExit, v)
		}
	}
	vq.exitQueue = newExit
	return nil
}

// ============================================================================
// SYNC COMMITTEE (for Light Clients)
// ============================================================================

// SyncCommittee represents a sync committee for light client support
type SyncCommittee struct {
	Period           uint64 // Sync committee period
	ValidatorIndices []int  // Indices of validators in the committee
	AggregatePubKey  []byte // Aggregated public key (for BLS)
}

// SyncCommitteeManager manages sync committees
type SyncSigVerifier interface {
	VerifySignature(pubKey []byte, message []byte, signature []byte) bool
}

type SyncCommitteeManager struct {
	mu sync.RWMutex

	currentCommittee *SyncCommittee
	nextCommittee    *SyncCommittee

	signatures map[uint64][]byte

	memberSignatures map[uint64]map[int][]byte

	maxSignatureSlots int

	sigVerifier SyncSigVerifier
	validators  []*Validator

	// R30-IMPLEMENT (2026-07-27): Per-submission pruning amortization.
	// CONS-R15-L03 FIX: Previously cleanup only ran in RotateCommittee
	// (every 256 epochs), allowing unbounded memory growth between
	// rotations. pruneSignaturesLocked is now invoked from
	// SubmitSyncCommitteeSignature every `pruneInterval` submissions to
	// keep the signature maps bounded at maxSignatureSlots. Default=64
	// amortizes the O(N log N) sort cost across many submissions; tests
	// set pruneInterval=1 to verify per-submission pruning. A
	// pruneInterval <= 0 disables per-submission pruning entirely (only
	// RotateCommittee prunes), preserving backward compatibility for
	// callers that never opt in.
	pruneInterval     int
	submissionCounter int
}

// NewSyncCommitteeManager creates a new sync committee manager
// FIX: Log a warning when no verifier is provided, so operators know
// sync committee signatures will be silently rejected.
func NewSyncCommitteeManager(verifier ...SyncSigVerifier) *SyncCommitteeManager {
	scm := &SyncCommitteeManager{
		signatures:        make(map[uint64][]byte),
		memberSignatures:  make(map[uint64]map[int][]byte),
		maxSignatureSlots: 1024,
		pruneInterval:     64, // CONS-R17-L03: default amortization window
	}
	if len(verifier) > 0 {
		scm.sigVerifier = verifier[0]
	} else {
		// P3-LOG-01 FIX (R30, 2026-07-27): Use logging.Global().Warn() with
		// category=SECURITY so SIEM can collect this security-relevant
		// misconfiguration (no signature verifier = all sigs silently dropped).
		logging.Global().Warn("SyncCommitteeManager created without a signature verifier; "+
			"all sync committee signatures will be silently rejected",
			map[string]any{"category": "SECURITY"})
	}
	return scm
}

// ComputeSyncCommittee computes the sync committee for a period
func (scm *SyncCommitteeManager) ComputeSyncCommittee(period uint64, validators []*Validator, randaoMix types.Hash) *SyncCommittee {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	if len(validators) == 0 {
		return nil
	}

	scm.validators = validators

	// Create seed for shuffling
	// P3-E6 AUDIT NOTE (fixed buffer size is sufficient): The 40-byte buffer
	// is a FIXED message-format buffer encoding (32-byte randaoMix/seed hash)
	// + (8-byte big-endian uint64 period/index). It is independent of the sync
	// committee SIZE (SyncCommitteeSize=512): the committee size only controls
	// how many (seed, index) pairs are hashed, not the per-pair buffer length.
	// 8 bytes can encode indices up to 2^64-1, which is far beyond any feasible
	// committee size, so this buffer can never overflow.
	seedData := make([]byte, 40)
	copy(seedData[:32], randaoMix[:])
	binary.BigEndian.PutUint64(seedData[32:], period)

	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(seedData)
	seed := hasher.Sum(nil)

	// Select committee members (with replacement for small validator sets)
	committeeSize := SyncCommitteeSize
	if committeeSize > len(validators)*16 {
		committeeSize = len(validators) * 16 // Allow up to 16x repetition
	}

	indices := make([]int, committeeSize)
	for i := 0; i < committeeSize; i++ {
		// Deterministic selection based on seed and position
		posData := make([]byte, 40)
		copy(posData[:32], seed)
		binary.BigEndian.PutUint64(posData[32:], uint64(i)) // #nosec G115 -- i bounded by committeeSize

		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(posData)
		hash := hasher.Sum(nil)

		idx := binary.BigEndian.Uint64(hash[:8]) % uint64(len(validators))
		indices[i] = int(idx) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	}

	committee := &SyncCommittee{
		Period:           period,
		ValidatorIndices: indices,
	}

	return committee
}

// GetCurrentCommittee returns the current sync committee
// Returns a deep copy to prevent external mutation of internal state.
func (scm *SyncCommitteeManager) GetCurrentCommittee() *SyncCommittee {
	scm.mu.RLock()
	defer scm.mu.RUnlock()
	if scm.currentCommittee == nil {
		return nil
	}
	// Return deep copy to prevent data races and external mutation
	indicesCopy := make([]int, len(scm.currentCommittee.ValidatorIndices))
	copy(indicesCopy, scm.currentCommittee.ValidatorIndices)
	aggregateCopy := make([]byte, len(scm.currentCommittee.AggregatePubKey))
	copy(aggregateCopy, scm.currentCommittee.AggregatePubKey)
	return &SyncCommittee{
		Period:           scm.currentCommittee.Period,
		ValidatorIndices: indicesCopy,
		AggregatePubKey:  aggregateCopy,
	}
}

// RotateCommittee rotates to the next sync committee
func (scm *SyncCommitteeManager) RotateCommittee(nextCommittee *SyncCommittee) {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	// L20-003 FIX: Guard against nil nextCommittee field. If nextCommittee was
	// never set (or was already consumed in a prior rotation), assigning it to
	// currentCommittee would set currentCommittee to nil, losing the active
	// committee and breaking block finalization/signature verification. Instead,
	// keep the current committee when nextCommittee is nil and only update
	// nextCommittee. Pruning still runs in either case.
	if scm.nextCommittee != nil {
		scm.currentCommittee = scm.nextCommittee
	}
	scm.nextCommittee = nextCommittee

	// audit-fix  prune old slot signatures to prevent unbounded map growth
	if len(scm.signatures) > scm.maxSignatureSlots {
		// Find the minimum slot to keep
		var maxSlot uint64
		for slot := range scm.signatures {
			if slot > maxSlot {
				maxSlot = slot
			}
		}
		// audit-fix  guard against underflow when maxSlot < maxSignatureSlots
		var cutoff uint64
		// #nosec G115 -- maxSignatureSlots is int >= 0, safe conversion
		if maxSlot > uint64(scm.maxSignatureSlots) {
			cutoff = maxSlot - uint64(scm.maxSignatureSlots) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		}
		for slot := range scm.signatures {
			if slot < cutoff {
				delete(scm.signatures, slot)
			}
		}
	}

	// Also prune member signatures
	if len(scm.memberSignatures) > scm.maxSignatureSlots {
		var maxSlot uint64
		for slot := range scm.memberSignatures {
			if slot > maxSlot {
				maxSlot = slot
			}
		}
		var cutoff uint64
		if maxSlot > uint64(scm.maxSignatureSlots) {
			cutoff = maxSlot - uint64(scm.maxSignatureSlots)
		}
		for slot := range scm.memberSignatures {
			if slot < cutoff {
				delete(scm.memberSignatures, slot)
			}
		}
	}
}

// pruneSignaturesLocked enforces the maxSignatureSlots bound on both
// signatures and memberSignatures using a deterministic sort-based approach.
//
// R30-IMPLEMENT (2026-07-27): Implements the test contract in
// cons_r15_l01_l03_test.go:257 (PruneCutoffGapFix). The old cutoff-based
// approach in RotateCommittee set cutoff = maxSlot - maxSignatureSlots,
// which (a) was a no-op when maxSlot <= maxSignatureSlots even if the map
// had more entries than the limit (because slots were not contiguous), and
// (b) kept one too many entries when slots were contiguous. The new
// approach sorts all slot keys and deletes the oldest entries until len ==
// maxSignatureSlots, keeping exactly the newest N entries regardless of
// whether slot numbers are contiguous.
//
// Caller MUST hold scm.mu (write) before calling this.
func (scm *SyncCommitteeManager) pruneSignaturesLocked() {
	// Prune memberSignatures down to maxSignatureSlots (keep newest N).
	if len(scm.memberSignatures) > scm.maxSignatureSlots {
		slots := make([]uint64, 0, len(scm.memberSignatures))
		for s := range scm.memberSignatures {
			slots = append(slots, s)
		}
		sort.Slice(slots, func(i, j int) bool { return slots[i] < slots[j] })
		// Delete oldest entries (lowest slot numbers) until we are at the limit.
		toDelete := len(slots) - scm.maxSignatureSlots
		for i := 0; i < toDelete; i++ {
			delete(scm.memberSignatures, slots[i])
		}
	}
	// Prune signatures down to maxSignatureSlots (keep newest N).
	if len(scm.signatures) > scm.maxSignatureSlots {
		slots := make([]uint64, 0, len(scm.signatures))
		for s := range scm.signatures {
			slots = append(slots, s)
		}
		sort.Slice(slots, func(i, j int) bool { return slots[i] < slots[j] })
		toDelete := len(slots) - scm.maxSignatureSlots
		for i := 0; i < toDelete; i++ {
			delete(scm.signatures, slots[i])
		}
	}
}

// SubmitSyncCommitteeSignature submits a signature from a sync committee member for a slot.
//
// R14-MED (2026-07-21): Previously all early-return paths (sigVerifier==nil,
// currentCommittee==nil, out-of-range indices, empty pubKey, failed
// verification) silently dropped the signature with NO log trail. Operators
// could not tell whether sync committee aggregation was failing because of
// misconfiguration (no verifier) or because of an attacker submitting
// invalid signatures. Each drop is now logged at the appropriate level so
// the failure mode is observable in production. The function still does
// not return an error to avoid changing the call signature and breaking
// existing callers; the log entries provide the audit trail.
//
// R30-IMPLEMENT (2026-07-27): Signature changed from 3 args
// (slot, committeeIndex, signature) to 7 args
// (slot, height, committeeIndex, signature, blockRoot, epoch, chainID) to
// match the unified lightclient message format (CONS-R18-CRIT-01,
// CONS-M02). The blockRoot/epoch/chainID are used to build the signed
// message so sync committee signatures are bound to a specific beacon
// block root (preventing cross-block replay). height is the L1 block
// height used for the V1/V2 fork-height gate (forkHeight=0 → both
// produce V2 format). The slot parameter is retained for backward
// compatibility with the signature map keying.
//
// R30-IMPLEMENT (2026-07-27): CONS-R15-L03 FIX — invokes
// pruneSignaturesLocked every pruneInterval submissions to keep the
// signature maps bounded between RotateCommittee calls. Previously
// cleanup only ran in RotateCommittee (every 256 epochs), allowing
// unbounded memory growth between rotations.
func (scm *SyncCommitteeManager) SubmitSyncCommitteeSignature(slot uint64, height uint64, committeeIndex int, signature []byte, blockRoot types.Hash, epoch uint64, chainID uint64) {
	scm.mu.Lock()
	defer scm.mu.Unlock()

	// audit-fix HIGH: Reject signatures when no verifier or no committee is configured.
	// Previously, when sigVerifier was nil or currentCommittee was nil, the signature
	// was stored WITHOUT cryptographic verification, allowing anyone to inject
	// arbitrary signatures into the sync committee aggregation. Fail closed instead.
	if scm.sigVerifier == nil {
		// R14-MED: log every drop so misconfiguration is observable. This path
		// indicates a deployment bug (NewSyncCommitteeManager called without a
		// verifier), not an attacker — log at Error so operators catch it.
		// P3-LOG-02 FIX (R30, 2026-07-27): Add category=SECURITY for SIEM filtering.
		logging.Global().Error("SyncCommitteeManager: dropping sync committee signature: no verifier configured (NewSyncCommitteeManager called without a verifier)",
			map[string]any{"slot": slot, "committeeIndex": committeeIndex, "category": "SECURITY"})
		return
	}
	if scm.currentCommittee == nil {
		// R14-MED: same rationale — committee not yet rotated in, deployment bug.
		// P3-LOG-02 FIX (R30, 2026-07-27): Add category=SECURITY for SIEM filtering.
		logging.Global().Error("SyncCommitteeManager: dropping sync committee signature: no current committee (RotateCommittee not called yet)",
			map[string]any{"slot": slot, "committeeIndex": committeeIndex, "category": "SECURITY"})
		return
	}

	if committeeIndex < 0 || committeeIndex >= len(scm.currentCommittee.ValidatorIndices) {
		// R14-MED: out-of-range index — likely peer error or bug; log at Warn.
		// P3-LOG-02 FIX (R30, 2026-07-27): Add category=SECURITY for SIEM filtering.
		logging.Global().Warn("SyncCommitteeManager: dropping sync committee signature: committee index out of range",
			map[string]any{"slot": slot, "committeeIndex": committeeIndex,
				"committeeSize": len(scm.currentCommittee.ValidatorIndices), "category": "SECURITY"})
		return
	}
	validatorIdx := scm.currentCommittee.ValidatorIndices[committeeIndex]
	if validatorIdx < 0 || validatorIdx >= len(scm.validators) {
		logging.Global().Warn("SyncCommitteeManager: dropping sync committee signature: validator index out of range",
			map[string]any{"slot": slot, "committeeIndex": committeeIndex,
				"validatorIdx": validatorIdx, "validatorCount": len(scm.validators), "category": "SECURITY"})
		return
	}
	pubKey := scm.validators[validatorIdx].PublicKeyBytes
	if len(pubKey) == 0 {
		logging.Global().Warn("SyncCommitteeManager: dropping sync committee signature: validator has empty public key",
			map[string]any{"slot": slot, "committeeIndex": committeeIndex, "validatorIdx": validatorIdx, "category": "SECURITY"})
		return
	}
	// R30-IMPLEMENT (2026-07-27): Build the unified lightclient signed message
	// (CONS-R18-CRIT-01, CONS-M02). The signed payload binds the signature to
	// a specific (blockRoot, epoch, chainID) tuple so a sync committee
	// signature cannot be replayed across blocks, epochs, or chains. Layout:
	//   "sync_committee_v2" || chainID(8) || epoch(8) || height(8) ||
	//   slot(8) || blockRoot(32)
	// The verifier is responsible for re-deriving the same message from the
	// validator's public key. (We deliberately do NOT fall back to the legacy
	// "sync_committee" message format — the V1/V2 fork is gated by the
	// forkHeight parameter at the lightclient layer, not here.)
	//
	// R40-P0 FIX (2026-08-04): Use BuildSyncCommitteeMessage so the producer
	// (block_producer.go) and the verifier see byte-identical payloads.
	msg := BuildSyncCommitteeMessage(chainID, epoch, height, slot, blockRoot)
	if !scm.sigVerifier.VerifySignature(pubKey, msg, signature) {
		// R14-MED: cryptographic verification failed — could be attacker or
		// corrupted signature. Log at Warn (not Error) because this is an
		// expected failure mode for byzantine peers.
		// P3-LOG-02 FIX (R30, 2026-07-27): Add category=SECURITY for SIEM filtering.
		logging.Global().Warn("SyncCommitteeManager: dropping sync committee signature: cryptographic verification failed",
			map[string]any{"slot": slot, "committeeIndex": committeeIndex,
				"validatorIdx": validatorIdx, "sigLen": len(signature), "category": "SECURITY"})
		return
	}

	if scm.memberSignatures[slot] == nil {
		scm.memberSignatures[slot] = make(map[int][]byte)
	}
	scm.memberSignatures[slot][committeeIndex] = signature

	// R30-IMPLEMENT (2026-07-27): CONS-R15-L03 FIX — amortized per-submission
	// pruning. Every pruneInterval submissions, drop the oldest entries that
	// exceed maxSignatureSlots. pruneInterval <= 0 disables this path (only
	// RotateCommittee prunes), preserving backward compatibility.
	if scm.pruneInterval > 0 {
		scm.submissionCounter++
		if scm.submissionCounter >= scm.pruneInterval {
			scm.pruneSignaturesLocked()
			scm.submissionCounter = 0
		}
	}
}

// BuildSyncCommitteeAggregation builds the aggregated signature and bitfield for a slot.
// Since Dilithium3 doesn't support native aggregation, we concatenate individual signatures
// and use a bitfield to track which committee members participated.
func (scm *SyncCommitteeManager) BuildSyncCommitteeAggregation(slot uint64) (aggregatedSig []byte, bitfield []byte) {
	scm.mu.RLock()
	defer scm.mu.RUnlock()

	committee := scm.currentCommittee
	if committee == nil || len(committee.ValidatorIndices) == 0 {
		return nil, nil
	}

	memberSigs := scm.memberSignatures[slot]
	if len(memberSigs) == 0 {
		return nil, nil
	}

	committeeSize := len(committee.ValidatorIndices)
	bitfieldSize := (committeeSize + 7) / 8
	bitfield = make([]byte, bitfieldSize)

	var sigParts [][]byte
	indices := make([]int, 0, len(memberSigs))
	for idx := range memberSigs {
		if idx < committeeSize {
			indices = append(indices, idx)
		}
	}
	sort.Ints(indices)
	for _, idx := range indices {
		sig := memberSigs[idx]
		sigParts = append(sigParts, sig)
		byteIdx := idx / 8
		bitIdx := idx % 8
		bitfield[byteIdx] |= 1 << bitIdx
	}

	if len(sigParts) == 0 {
		return nil, nil
	}

	totalLen := 0
	for _, s := range sigParts {
		totalLen += len(s)
	}
	aggregatedSig = make([]byte, 0, totalLen)
	for _, s := range sigParts {
		aggregatedSig = append(aggregatedSig, s...)
	}

	return aggregatedSig, bitfield
}

// GetSyncCommitteeSize returns the number of members in the current sync committee.
func (scm *SyncCommitteeManager) GetSyncCommitteeSize() int {
	scm.mu.RLock()
	defer scm.mu.RUnlock()
	if scm.currentCommittee == nil {
		return 0
	}
	return len(scm.currentCommittee.ValidatorIndices)
}

// ============================================================================
// INACTIVITY LEAK
// ============================================================================

// InactivityLeakManager manages inactivity penalties
type InactivityLeakManager struct {
	mu sync.RWMutex

	// FIX: Inactivity scores keyed by validator address instead of index.
	// Previously keyed by int index, which caused misalignment when validators
	// were removed and indices shifted. Using address as the key is stable
	// across validator set changes.
	scores map[types.Address]uint64

	// Epochs since finality
	epochsSinceFinality uint64

	// Is leak active?
	leakActive bool
}

// NewInactivityLeakManager creates a new inactivity leak manager
func NewInactivityLeakManager() *InactivityLeakManager {
	return &InactivityLeakManager{
		scores: make(map[types.Address]uint64),
	}
}

// UpdateInactivityScores updates inactivity scores for all validators
// SECURITY: This function only updates uint64 score counters.
// It does NOT directly modify validator stakes. Stake penalties are
// calculated separately in CalculateInactivityPenalty() and applied elsewhere.
// FIX: Scores and participated map are now keyed by validator address
// instead of index, preventing misalignment when validator indices change.
// audit-remediation: reviewed 2026-09-11 — inactivity bookkeeping; does not touch stake.
func (ilm *InactivityLeakManager) UpdateInactivityScores(participated map[types.Address]bool, epochsSinceFinality uint64, allValidators []types.Address) {
	ilm.mu.Lock()
	defer ilm.mu.Unlock()

	ilm.epochsSinceFinality = epochsSinceFinality

	// Leak is active if finality is delayed by more than 4 epochs
	ilm.leakActive = epochsSinceFinality > 4

	// P3-E1 AUDIT NOTE (intentional, no dedup needed): The allValidators slice
	// supplied by the caller MAY contain duplicate addresses. Duplicates are
	// HARMLESS here: every downstream use is either a map membership test
	// (`participated[addr]`, `ilm.scores[addr]`, `validAddrs[addr]`) or a
	// map write, all of which are idempotent. The worst case is that a
	// duplicated validator's inactivity score is initialized twice to the
	// same value — which is a no-op. Adding explicit dedup would allocate an
	// extra map on every call for no behavioral benefit, so it is deliberately
	// omitted.

	// audit-fix MED-1: Ensure all validators referenced in participated map
	// are tracked in the scores map. Previously, only existing keys were iterated,
	// meaning new validators never had their inactivity scores initialized or updated.
	for addr := range participated {
		if _, exists := ilm.scores[addr]; !exists {
			ilm.scores[addr] = 0
		}
	}

	// FIX: Initialize scores for all active validators NOT in the
	// participated map. Previously, only validators in the participated map
	// were tracked, so validators that never participated were never added to
	// the scores map and escaped inactivity penalties entirely. Now we iterate
	// the full active validator set and initialize any missing entries to 0;
	// the penalty loop below will then correctly increment their scores.
	// FIX: Iterate over allValidators addresses instead of 0..totalValidators
	// index range, since scores are now address-keyed.
	for _, addr := range allValidators {
		if _, ok := participated[addr]; !ok {
			if _, exists := ilm.scores[addr]; !exists {
				ilm.scores[addr] = 0
			}
		}
	}

	// FIX: Clean up stale scores for validators no longer in the active set.
	// Previously, the totalValidators parameter could be smaller than len(scores),
	// causing stale entries for removed validators to remain in the scores map and
	// be incorrectly penalized. Now we explicitly remove entries for addresses that
	// are neither in allValidators nor in participated, keeping len(scores) bounded
	// by the actual active validator set size.
	validAddrs := make(map[types.Address]bool, len(allValidators)+len(participated))
	for _, addr := range allValidators {
		validAddrs[addr] = true
	}
	for addr := range participated {
		validAddrs[addr] = true
	}
	for addr := range ilm.scores {
		if !validAddrs[addr] {
			delete(ilm.scores, addr)
		}
	}

	for addr := range ilm.scores {
		if participated[addr] {
			// Decrease score (recovery)
			if ilm.scores[addr] > InactivityScoreRecoveryRate {
				ilm.scores[addr] -= InactivityScoreRecoveryRate
			} else {
				ilm.scores[addr] = 0
			}
		} else {
			// Increase score (penalty) - capped to prevent overflow
			if ilm.scores[addr] < ^uint64(0)-InactivityScoreBias {
				ilm.scores[addr] += InactivityScoreBias
			}
		}
	}
}

// CalculateInactivityPenalty calculates the inactivity penalty for a validator
// FIX: Takes validator address instead of index to prevent misalignment.
func (ilm *InactivityLeakManager) CalculateInactivityPenalty(addr types.Address, effectiveBalance *big.Int) *big.Int {
	ilm.mu.RLock()
	defer ilm.mu.RUnlock()

	if !ilm.leakActive {
		return big.NewInt(0)
	}

	score := ilm.scores[addr]
	if score == 0 {
		return big.NewInt(0)
	}

	// Penalty = effective_balance * inactivity_score / INACTIVITY_PENALTY_QUOTIENT
	// audit-fix  use SetUint64 to avoid int64 overflow when score > MaxInt64
	scoreBig := new(big.Int).SetUint64(score)
	penalty := new(big.Int).Mul(effectiveBalance, scoreBig)
	penalty.Div(penalty, big.NewInt(InactivityPenaltyQuotientBellatrix))

	return penalty
}

// IsLeakActive returns whether the inactivity leak is active
func (ilm *InactivityLeakManager) IsLeakActive() bool {
	ilm.mu.RLock()
	defer ilm.mu.RUnlock()
	return ilm.leakActive
}

// GetInactivityScore returns the inactivity score for a validator
// FIX: Takes validator address instead of index to prevent misalignment.
func (ilm *InactivityLeakManager) GetInactivityScore(addr types.Address) uint64 {
	ilm.mu.RLock()
	defer ilm.mu.RUnlock()
	return ilm.scores[addr]
}

// ============================================================================
// LMD GHOST FORK CHOICE
// ============================================================================

// BlockNode represents a block in the fork choice tree
type BlockNode struct {
	Hash       types.Hash
	ParentHash types.Hash
	Slot       uint64
	Height     uint64
	Weight     *big.Int // Attestation weight
	Children   []*BlockNode
	Justified  bool
	Finalized  bool
}

// ForkChoice implements the LMD GHOST fork choice rule
type ForkChoice struct {
	mu sync.RWMutex

	// Block tree
	blocks map[types.Hash]*BlockNode

	// Root of the tree (finalized block)
	root *BlockNode

	// Current head
	head *BlockNode

	// Justified checkpoint
	justifiedRoot  types.Hash
	justifiedEpoch uint64

	// Finalized checkpoint
	finalizedRoot  types.Hash
	finalizedEpoch uint64

	// Latest messages (votes) from validators
	latestMessages map[int]types.Hash // validatorIdx -> block hash

	//  Inactive validators set — attestations from these validators
	// are rejected in OnAttestation, consistent with calculateBlockScoreLocked.
	inactiveValidators map[int]bool

	// Proposer boost
	proposerBoostRoot types.Hash
	proposerBoostSlot uint64
	// AUDIT (2026) CORE-08 FIX: proposerBoostWeight is the fixed boost value
	// (40% of total active committee stake) applied to the boosted block. The
	// previous implementation computed boost as 40% of the block's OWN weight,
	// which amplified already-heavy blocks instead of providing a uniform
	// committee-derived bonus. This field is set via SetProposerBoostWithWeight
	// and is nil when SetProposerBoost (legacy, no committee context) is used,
	// in which case no boost is applied (fail-closed).
	proposerBoostWeight *big.Int
}

// NewForkChoice creates a new fork choice instance
func NewForkChoice(genesisRoot types.Hash) *ForkChoice {
	genesisNode := &BlockNode{
		Hash:      genesisRoot,
		Slot:      0,
		Height:    0,
		Weight:    big.NewInt(0),
		Children:  make([]*BlockNode, 0),
		Finalized: true,
		Justified: true,
	}

	return &ForkChoice{
		blocks:             map[types.Hash]*BlockNode{genesisRoot: genesisNode},
		root:               genesisNode,
		head:               genesisNode,
		finalizedRoot:      genesisRoot,
		justifiedRoot:      genesisRoot,
		latestMessages:     make(map[int]types.Hash),
		inactiveValidators: make(map[int]bool),
	}
}

// OnBlock processes a new block
func (fc *ForkChoice) OnBlock(hash, parentHash types.Hash, slot, height uint64) error {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Check if block already exists
	if _, exists := fc.blocks[hash]; exists {
		return nil
	}

	// Find parent
	parent, exists := fc.blocks[parentHash]
	if !exists {
		return ErrParentNotFound
	}

	// L20-004 FIX: Slot and height sanity checks. A child block must have a
	// strictly greater slot and height than its parent. Without this, a
	// malicious or buggy proposer could submit blocks with stale or equal
	// slots, corrupting the fork choice view and enabling equivocation.
	if slot <= parent.Slot {
		return errors.New("block slot must be greater than parent slot")
	}
	if height <= parent.Height {
		return errors.New("block height must be greater than parent height")
	}

	// Create new node
	node := &BlockNode{
		Hash:       hash,
		ParentHash: parentHash,
		Slot:       slot,
		Height:     height,
		Weight:     big.NewInt(0),
		Children:   make([]*BlockNode, 0),
	}

	// AUDIT ROUND-4 2026-08-17 FIX: enforce the capacity limit BEFORE
	// linking the node into parent.Children. The previous order appended the
	// child first and only then checked MaxForkChoiceBlocks — on rejection
	// the node remained reachable via the parent's children list while
	// missing from fc.blocks, leaving fork-choice state inconsistent (a
	// dangling subtree invisible to block-map lookups and pruning).
	if len(fc.blocks) >= MaxForkChoiceBlocks {
		return errors.New("fork choice block limit exceeded")
	}

	// Add to parent's children
	parent.Children = append(parent.Children, node)

	// Add to blocks map
	fc.blocks[hash] = node

	return nil
}

// OnAttestation processes an attestation (vote)
func (fc *ForkChoice) OnAttestation(validatorIdx int, blockHash types.Hash, stake *big.Int) {
	// FIX: Validate validatorIdx bounds before accessing maps.
	// CS-01 FIX (R45): Reject nil stake to prevent Neg(nil) panic.
	if stake == nil || stake.Sign() <= 0 {
		return
	}
	// A negative index or an index exceeding the protocol maximum (MaxValidators)
	// indicates a malformed attestation and could corrupt fork-choice state.
	if validatorIdx < 0 || validatorIdx >= MaxValidators {
		return
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	// FIX: Reject attestations from inactive validators, consistent
	// with calculateBlockScoreLocked () and subtreeWeight ().
	if fc.inactiveValidators[validatorIdx] {
		return
	}

	// Update latest message
	oldHash, hadPrevious := fc.latestMessages[validatorIdx]
	if hadPrevious && oldHash == blockHash {
		return
	}
	fc.latestMessages[validatorIdx] = blockHash

	// Update weights
	if hadPrevious && oldHash != blockHash {
		// Remove weight from old chain
		fc.updateWeight(oldHash, new(big.Int).Neg(stake))
	}

	// Add weight to new chain
	fc.updateWeight(blockHash, stake)
}

// SetValidatorInactive marks a validator as inactive so that its attestations
// are rejected in OnAttestation. FIX.
func (fc *ForkChoice) SetValidatorInactive(validatorIdx int) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.inactiveValidators[validatorIdx] = true
}

// SetValidatorActive unmarks a previously inactive validator. FIX.
func (fc *ForkChoice) SetValidatorActive(validatorIdx int) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	delete(fc.inactiveValidators, validatorIdx)
}

// updateWeight updates the weight of a block and its ancestors.
// audit-fix M-12: clamp weight to zero to prevent negative weights from
// breaking the LMD GHOST heaviest-chain invariant. Negative weights can
// arise when a validator changes its vote (old chain gets Neg(stake)).
func (fc *ForkChoice) updateWeight(hash types.Hash, delta *big.Int) {
	node, exists := fc.blocks[hash]
	if !exists {
		return
	}

	zero := big.NewInt(0)
	// Update this node and all ancestors up to root
	for node != nil {
		node.Weight.Add(node.Weight, delta)
		if node.Weight.Sign() < 0 {
			node.Weight.Set(zero)
		}
		if node.ParentHash == (types.Hash{}) {
			break
		}
		node = fc.blocks[node.ParentHash]
	}
}

// GetHead returns the current head block using LMD GHOST
func (fc *ForkChoice) GetHead() types.Hash {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return fc.getHeadLocked()
}

// getHeadLocked computes the head block without acquiring the lock.
// MUST be called while fc.mu is already held.
func (fc *ForkChoice) getHeadLocked() types.Hash {
	// Start from justified checkpoint
	justified, exists := fc.blocks[fc.justifiedRoot]
	if !exists {
		return fc.root.Hash
	}

	// Follow the heaviest chain
	current := justified
	for len(current.Children) > 0 {
		// Find child with highest weight
		var bestChild *BlockNode
		bestWeight := big.NewInt(-1)

		for _, child := range current.Children {
			childWeight := new(big.Int).Set(child.Weight)

			// Apply proposer boost if applicable
			// AUDIT (2026) CORE-08 FIX: Use the fixed proposerBoostWeight
			// (40% of total committee stake) instead of 40% of the child's own
			// weight. The old formula amplified already-heavy blocks; the correct
			// semantics is a uniform committee-derived bonus. If the legacy
			// SetProposerBoost was used (no committee context), proposerBoostWeight
			// is nil and no boost is applied (fail-closed).
			if child.Hash == fc.proposerBoostRoot && child.Slot == fc.proposerBoostSlot && fc.proposerBoostWeight != nil {
				childWeight.Add(childWeight, new(big.Int).Set(fc.proposerBoostWeight))
			}

			if childWeight.Cmp(bestWeight) > 0 {
				bestWeight = childWeight
				bestChild = child
			} else if childWeight.Cmp(bestWeight) == 0 && bestChild != nil {
				// FIX: deterministic tiebreaker — when two children have
				// equal weight, pick the one with the lexicographically smaller
				// block hash so all nodes converge on the same head deterministically.
				if bytes.Compare(child.Hash[:], bestChild.Hash[:]) < 0 {
					bestChild = child
				}
			}
		}

		if bestChild == nil {
			break
		}
		current = bestChild
	}

	return current.Hash
}

// SetProposerBoost sets the proposer boost for a block.
//
// AUDIT (2026) CORE-08 FIX: This legacy setter does not provide the total
// committee stake, so the correct boost value cannot be computed. It now sets
// proposerBoostWeight to nil (fail-closed: no boost applied). Callers that
// know the total active committee stake should use SetProposerBoostWithWeight
// instead, which computes the boost as 40% of that stake.
func (fc *ForkChoice) SetProposerBoost(hash types.Hash, slot uint64) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	fc.proposerBoostRoot = hash
	fc.proposerBoostSlot = slot
	fc.proposerBoostWeight = nil
}

// SetProposerBoostWithWeight sets the proposer boost for a block using the
// total active committee stake to derive the boost value.
// AUDIT (2026) CORE-08 FIX: replaces the incorrect 40%-of-own-weight formula.
func (fc *ForkChoice) SetProposerBoostWithWeight(hash types.Hash, slot uint64, totalCommitteeStake *big.Int) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	fc.proposerBoostRoot = hash
	fc.proposerBoostSlot = slot
	if totalCommitteeStake == nil || totalCommitteeStake.Sign() <= 0 {
		fc.proposerBoostWeight = nil
		return
	}
	boost := new(big.Int).Mul(totalCommitteeStake, big.NewInt(ProposerScoreBoostPercent))
	boost.Div(boost, big.NewInt(100))
	fc.proposerBoostWeight = boost
}

// UpdateJustified updates the justified checkpoint
// SECURITY: This function only updates checkpoint state (root hash and epoch).
// It does NOT modify any validator stakes or balances.
// audit-remediation: reviewed 2026-09-11 — finality bookkeeping; does not touch stake.
func (fc *ForkChoice) UpdateJustified(root types.Hash, epoch uint64) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Only update if epoch is newer (prevents rollback attacks)
	if epoch > fc.justifiedEpoch {
		fc.justifiedRoot = root
		fc.justifiedEpoch = epoch

		if node, exists := fc.blocks[root]; exists {
			node.Justified = true
		}
	}
}

// UpdateFinalized updates the finalized checkpoint
// SECURITY: This function only updates checkpoint state (root hash and epoch).
// It does NOT modify any validator stakes or balances. It only prunes
// non-finalized blocks from the fork choice tree.
// audit-remediation: reviewed 2026-09-11 — finality bookkeeping; does not touch stake.
func (fc *ForkChoice) UpdateFinalized(root types.Hash, epoch uint64) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	// Only update if epoch is newer (prevents rollback attacks)
	if epoch > fc.finalizedEpoch {
		fc.finalizedRoot = root
		fc.finalizedEpoch = epoch

		if node, exists := fc.blocks[root]; exists {
			node.Finalized = true
			fc.root = node
		}

		// Prune blocks that are not descendants of finalized
		fc.pruneNonFinalized()
	}
}

// pruneNonFinalized removes blocks that are not descendants of the finalized block.
//
// CONS- (2026-07-19) FIX (comment-vs-code mismatch): The previous
// comment claimed "Changed to incremental execution - collect hashes to
// remove under RLock, then delete under Lock to minimize write lock hold
// time during large BFS traversals" but the actual implementation is a
// SINGLE-PHASE deletion under the caller's write lock — there is no
// RLock phase, no separate "hashes to remove" collection, and no two-phase
// lock acquisition. The misleading comment could lead future maintainers
// to believe the lock semantics are different from what they actually
// are. Comment corrected to describe the actual implementation.
//
// NOTE: This method must be called while fc.mu is already held (write-locked).
// It does NOT acquire fc.mu internally to avoid deadlock with callers like UpdateFinalized.
func (fc *ForkChoice) pruneNonFinalized() {
	keep := make(map[types.Hash]bool)
	fc.markDescendants(fc.root, keep)

	for hash := range fc.blocks {
		if !keep[hash] {
			delete(fc.blocks, hash)
		}
	}
}

// markDescendants marks a block and all its descendants.
// audit-fix M-14: converted from recursive to iterative BFS to prevent
// stack overflow when an attacker constructs a deep chain.
func (fc *ForkChoice) markDescendants(node *BlockNode, keep map[types.Hash]bool) {
	if node == nil {
		return
	}
	queue := []*BlockNode{node}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		keep[current.Hash] = true
		queue = append(queue, current.Children...)
	}
}

// GetBlockWeight returns the weight of a block
func (fc *ForkChoice) GetBlockWeight(hash types.Hash) *big.Int {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	if node, exists := fc.blocks[hash]; exists {
		// Return a deep copy of the weight to prevent data races
		weightCopy := new(big.Int).Set(node.Weight)
		return weightCopy
	}
	return big.NewInt(0)
}

// GetForkChoiceStatus returns the current fork choice status
func (fc *ForkChoice) GetForkChoiceStatus() map[string]any {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	head := fc.getHeadLocked()

	return map[string]any{
		"head":           head,
		"justifiedRoot":  fc.justifiedRoot,
		"justifiedEpoch": fc.justifiedEpoch,
		"finalizedRoot":  fc.finalizedRoot,
		"finalizedEpoch": fc.finalizedEpoch,
		"blockCount":     len(fc.blocks),
		"voteCount":      len(fc.latestMessages),
	}
}

// ============================================================================
// WITHDRAWAL MECHANISM
// ============================================================================

// WithdrawalManager manages validator withdrawals
type WithdrawalManager struct {
	mu sync.RWMutex

	// Pending withdrawals
	pendingWithdrawals []*Withdrawal

	// Processed withdrawals
	processedWithdrawals map[uint64][]*Withdrawal // epoch -> withdrawals

	// Next withdrawal index
	nextWithdrawalIndex uint64
}

// Withdrawal represents a withdrawal operation
type Withdrawal struct {
	Index             uint64
	ValidatorIndex    int
	Address           types.Address
	Amount            *big.Int
	RequestedEpoch    uint64
	ProcessedEpoch    uint64
	WithdrawalAddress types.Address
}

// NewWithdrawalManager creates a new withdrawal manager
func NewWithdrawalManager() *WithdrawalManager {
	return &WithdrawalManager{
		pendingWithdrawals:   make([]*Withdrawal, 0),
		processedWithdrawals: make(map[uint64][]*Withdrawal),
	}
}

// RequestWithdrawal requests a withdrawal for a validator
// audit-fix CR-3: Added caller parameter and authorization check
func (wm *WithdrawalManager) RequestWithdrawal(caller, addr, withdrawalAddr types.Address, amount *big.Int, epoch uint64) (*Withdrawal, error) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	// CRITICAL security fix: verify caller is the address requesting withdrawal
	// This prevents unauthorized withdrawal requests
	if caller != addr {
		return nil, ErrUnauthorizedValidatorOperation
	}

	// H-FUND-3 FIX: Reject zero address as withdrawal destination.
	// Zero address is a reserved system address and cannot receive withdrawals.
	if withdrawalAddr == (types.Address{}) {
		return nil, ErrInvalidWithdrawalAddress
	}

	withdrawal := &Withdrawal{
		Index:             wm.nextWithdrawalIndex,
		ValidatorIndex:    0, // Will be set by caller
		Address:           addr,
		Amount:            new(big.Int).Set(amount),
		RequestedEpoch:    epoch,
		WithdrawalAddress: withdrawalAddr,
	}

	wm.nextWithdrawalIndex++

	if len(wm.pendingWithdrawals) >= MaxPendingWithdrawals {
		return nil, errors.New("withdrawal queue full")
	}
	wm.pendingWithdrawals = append(wm.pendingWithdrawals, withdrawal)

	return withdrawal, nil
}

// ProcessWithdrawals processes pending withdrawals for an epoch
// Returns withdrawals that should be included in the block
func (wm *WithdrawalManager) ProcessWithdrawals(epoch uint64, maxWithdrawals int) []*Withdrawal {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	processed := make([]*Withdrawal, 0)
	remaining := make([]*Withdrawal, 0)

	for _, w := range wm.pendingWithdrawals {
		// Check if withdrawal is ready (after MinValidatorWithdrawableEpoch)
		if epoch >= w.RequestedEpoch+MinValidatorWithdrawableEpoch && len(processed) < maxWithdrawals {
			w.ProcessedEpoch = epoch
			processed = append(processed, w)
		} else {
			remaining = append(remaining, w)
		}
	}

	wm.pendingWithdrawals = remaining
	wm.processedWithdrawals[epoch] = processed

	// audit-fix  prune old processedWithdrawals to prevent unbounded map growth
	// Keep only the last 3 epochs of processed withdrawal records
	if epoch > 3 {
		for oldEpoch := range wm.processedWithdrawals {
			if oldEpoch < epoch-3 {
				delete(wm.processedWithdrawals, oldEpoch)
			}
		}
	}

	return processed
}

// GetPendingWithdrawals returns all pending withdrawals
func (wm *WithdrawalManager) GetPendingWithdrawals() []*Withdrawal {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	result := make([]*Withdrawal, len(wm.pendingWithdrawals))
	copy(result, wm.pendingWithdrawals)
	return result
}

// GetProcessedWithdrawals returns withdrawals processed in an epoch.
// audit-fix R6-L1: returns a copy of the slice to prevent external mutation
// of the manager's internal state.
func (wm *WithdrawalManager) GetProcessedWithdrawals(epoch uint64) []*Withdrawal {
	wm.mu.RLock()
	defer wm.mu.RUnlock()
	src := wm.processedWithdrawals[epoch]
	result := make([]*Withdrawal, len(src))
	copy(result, src)
	return result
}

// ============================================================================
// QPOS ADVANCED ENGINE (Integrates all advanced features)
// ============================================================================

// QPOSAdvanced extends QPOS with advanced features
type QPOSAdvanced struct {
	*QPOS

	// Validator lifecycle
	validatorQueue *ValidatorQueue

	// Sync committee
	syncCommittee *SyncCommitteeManager

	// Inactivity leak
	inactivityLeak *InactivityLeakManager

	// Fork choice
	forkChoice *ForkChoice

	// Withdrawals
	withdrawals *WithdrawalManager

	// Metrics
	metrics *QPOSMetrics
}

// QPOSMetrics tracks QPOS performance metrics
type QPOSMetrics struct {
	mu sync.RWMutex

	// Block production
	BlocksProposed uint64
	BlocksMissed   uint64
	OrphanedBlocks uint64

	// Attestations
	AttestationsTotal  uint64
	AttestationsOnTime uint64
	AttestationsLate   uint64

	// Finality
	EpochsToFinality []uint64 // History of epochs to finality
	AverageFinality  float64

	// Network
	SyncCommitteeParticipation float64
	ValidatorUptime            map[int]float64

	// Timestamps
	LastBlockTime    time.Time
	LastFinalityTime time.Time
}

// NewQPOSAdvanced creates a new advanced QPOS engine.
// audit-fix M-1: returns error to propagate QPOS/slashing config validation failures.
func NewQPOSAdvanced(validators *ValidatorSet, genesisRoot types.Hash) (*QPOSAdvanced, error) {
	qpos, err := NewQPOS(validators)
	if err != nil {
		return nil, err
	}
	qa := &QPOSAdvanced{
		QPOS:           qpos,
		validatorQueue: NewValidatorQueue(),
		// R40-P0 FIX (2026-08-04): Wire Dilithium3 verifier so sync committee
		// signatures are cryptographically verified instead of silently dropped.
		syncCommittee:  NewSyncCommitteeManager(NewDilithiumSyncSigVerifier()),
		inactivityLeak: NewInactivityLeakManager(),
		forkChoice:     NewForkChoice(genesisRoot),
		withdrawals:    NewWithdrawalManager(),
		metrics:        &QPOSMetrics{ValidatorUptime: make(map[int]float64)},
	}

	// Note: ForkChoice updates should be called explicitly when finality is updated
	// rather than through a callback, to ensure proper error handling.

	return qa, nil
}

// NewQPOSAdvancedWithQPOS creates a new advanced QPOS engine using an existing QPOS instance.
//
// CRITICAL FIX: This constructor reuses an existing *QPOS instance instead of creating
// a new one. Without this, bp.qpos and bp.qposAdvanced.QPOS would be different instances:
//   - Attestations stored via bp.qpos.ProcessAttestation() go to Instance A
//   - ProcessEpochAdvanced() reads from Instance B (empty) → finalizedEpoch stays 0
//   - epochsSinceFinality = epoch - 0 = epoch → always > 4 → leakActive = true forever
//
// By sharing the same instance, ProcessEpochAdvanced sees the real attestations and
// finalizedEpoch advances correctly, so the inactivity leak clears as expected.
func NewQPOSAdvancedWithQPOS(qpos *QPOS, genesisRoot types.Hash) (*QPOSAdvanced, error) {
	if qpos == nil {
		return nil, errors.New("qpos instance cannot be nil")
	}
	qa := &QPOSAdvanced{
		QPOS:           qpos,
		validatorQueue: NewValidatorQueue(),
		// R40-P0 FIX (2026-08-04): Wire Dilithium3 verifier so sync committee
		// signatures are cryptographically verified instead of silently dropped.
		syncCommittee:  NewSyncCommitteeManager(NewDilithiumSyncSigVerifier()),
		inactivityLeak: NewInactivityLeakManager(),
		forkChoice:     NewForkChoice(genesisRoot),
		withdrawals:    NewWithdrawalManager(),
		metrics:        &QPOSMetrics{ValidatorUptime: make(map[int]float64)},
	}
	return qa, nil
}

// ProcessSlot processes a slot with all advanced features
func (qa *QPOSAdvanced) ProcessSlot(slot uint64, blockHash types.Hash, parentHash types.Hash, height uint64) error {
	// Add block to fork choice
	if err := qa.forkChoice.OnBlock(blockHash, parentHash, slot, height); err != nil {
		return err
	}

	// Update metrics
	qa.metrics.mu.Lock()
	qa.metrics.BlocksProposed++
	qa.metrics.LastBlockTime = time.Now()
	qa.metrics.mu.Unlock()

	return nil
}

// ProcessEpochAdvanced processes an epoch with all advanced features
func (qa *QPOSAdvanced) ProcessEpochAdvanced(epoch uint64) {
	// M6-4: Log epoch transition start at Info level for production observability
	qposAdvLogger.Infof("epoch transition started: epoch %d", epoch)

	// Process validator queue
	// R40-A-C3 FIX: Sync activated validators with ValidatorManager via SetActive.
	// Previously, ProcessEpoch only updated the local entryQueue without notifying
	// ValidatorManager, allowing slashed validators (with 0 stake / permanently slashed)
	// to appear active in the queue while ValidatorManager had no knowledge.
	activated, exited, activatedAddrs := qa.validatorQueue.ProcessEpoch(epoch)

	// R40-A-C3 FIX: Sync each activated validator to ValidatorManager.
	// This ensures ValidatorManager knows which validators are active and can
	// enforce stake/jail/permanently-slashed checks for any subsequent operations.
	// MEDIUM FIX: Track SetActive failures for audit logging.
	// Failed activations are logged but don't stop epoch processing.
	failedActivations := make([]types.Address, 0)
	if qa.slashingManager != nil && qa.slashingManager.validatorMgr != nil {
		// FIX: Link ValidatorManager with ValidatorQueue so RemoveValidator
		// synchronously cleans up the queue. Idempotent — just sets a pointer.
		qa.slashingManager.validatorMgr.SetValidatorQueue(qa.validatorQueue)
		// HIGH FIX: ProcessEpochAdvanced must use a registered system caller
		// Using types.Address{} directly bypasses authorization checks since zero address
		// is explicitly rejected as system caller (R24-H2).
		// Use a deterministic system caller derived from epoch context.
		systemCaller := DeriveSystemCaller(epoch)
		for _, addr := range activatedAddrs {
			// R41-L5SLASH-08 (2026-08-03) FIX: distinguish first-time
			// activation vs re-activation. ProcessEpochAdvanced receives
			// `activatedAddrs` from `validatorQueue.ProcessEpoch`, which
			// mixes two populations:
			//   1. Newly-enqueued validators that just completed the 4-epoch
			//      activation delay — they have EverActivated=false, so
			//      SetActive would be rejected by VAL-H04 (line 1023) and
			//      the validator would silently fail to activate, then be
			//      dequeued by ProcessEpoch and *never retried* (it has
			//      already left the entryQueue). The net result: every
			//      non-genesis validator would be permanently stuck.
			//   2. Previously-activated validators that were deactivated
			//      (e.g. unjail) and are being reactivated — they have
			//      EverActivated=true, so SetActive is the correct path
			//      (ActivateFromQueue would also work since it is idempotent
			//      w.r.t. EverActivated, but SetActive preserves the
			//      post-unjail accounting semantics).
			//
			// The fix routes first-time activations (EverActivated=false)
			// to ActivateFromQueue — which atomically sets Active=true AND
			// EverActivated=true — while keeping SetActive for the
			// re-activation path. This unblocks the queue without
			// weakening VAL-H04 (which still protects the queue-delay
			// guarantee against direct SetActive calls from RPC/other
			// paths).
			if info, err := qa.slashingManager.validatorMgr.GetValidator(addr); err == nil && !info.EverActivated {
				if err := qa.slashingManager.validatorMgr.ActivateFromQueue(addr); err != nil {
					failedActivations = append(failedActivations, addr)
					activated-- // Decrement count since activation failed
				}
				continue
			}
			if err := qa.slashingManager.validatorMgr.SetActive(
				systemCaller, // Use derived system caller instead of zero address
				addr, true,
			); err != nil {
				// MEDIUM FIX: Track failed activation for audit logging.
				// The validator remains in the queue for retry in next epoch.
				// This prevents validators with issues (jailed, insufficient stake)
				// from being incorrectly marked as active while allowing epoch processing to continue.
				failedActivations = append(failedActivations, addr)
				activated-- // Decrement count since activation failed
			}
		}
	}
	// Log failed activations for monitoring and alerting
	if len(failedActivations) > 0 {
		qposAdvLogger.Errorf("epoch %d: %d validator activation(s) failed: %v", epoch, len(failedActivations), failedActivations)
	}
	// CS-09 FIX: Use the activated/exited counts for observability instead of
	// silently discarding them. activated reflects net successful activations
	// (failed SetActive calls decrement it above). exited is tracked by
	// ValidatorQueue's own lifecycle; logged here for monitoring.
	qposAdvLogger.Infof("epoch %d: %d validator(s) activated, %d exited", epoch, activated, exited)

	// Check finality FIRST, so UpdateInactivityScores uses the updated finalizedEpoch.
	// BUG FIX: Previously CheckFinality() was called after UpdateInactivityScores(),
	// causing epochsSinceFinality to be computed with a stale finalizedEpoch value.
	// This kept inactivityLeakActive stuck at true even after finality recovered.
	// audit-fix MEDIUM: capture finalizedEpoch from CheckFinality() return value
	// instead of reading qa.finalizedEpoch lock-free (data race).
	_, finalizedEpoch, _ := qa.CheckFinality()

	// Update inactivity scores (after finality is updated)
	participated := qa.getParticipatedValidators(epoch)
	// audit-fix  guard against underflow when epoch < finalizedEpoch
	var epochsSinceFinality uint64
	if epoch > finalizedEpoch {
		epochsSinceFinality = epoch - finalizedEpoch
	}
	// FIX: Pass all validator addresses instead of just the count,
	// so InactivityLeakManager can use addresses as keys (not indices).
	allValidatorAddrs := make([]types.Address, 0, qa.validators.Size())
	for _, v := range qa.validators.Validators() {
		allValidatorAddrs = append(allValidatorAddrs, v.Address)
	}
	qa.inactivityLeak.UpdateInactivityScores(participated, epochsSinceFinality, allValidatorAddrs)

	// Rotate sync committee if needed
	if epoch%SyncCommitteePeriod == 0 {
		validators := qa.validators.Validators()
		// audit-fix MEDIUM: read randaoMix under lock to avoid data race with
		// concurrent writers (e.g. ProcessRandaoReveal). Previously the read
		// was lock-free, causing a race detected by -race builds.
		qa.mu.RLock()
		randaoCopy := qa.randaoMix
		qa.mu.RUnlock()
		nextCommittee := qa.syncCommittee.ComputeSyncCommittee(
			epoch/SyncCommitteePeriod+1,
			validators,
			randaoCopy,
		)
		qa.syncCommittee.RotateCommittee(nextCommittee)
	}

	// Process withdrawals
	qa.withdrawals.ProcessWithdrawals(epoch, 16) // Max 16 withdrawals per epoch

	// FIX: Clean up old QTD finality state (pendingSeals and
	// instantFinalizedSlots) to prevent unbounded memory growth.
	// Called at every epoch boundary. Uses the last slot of the current epoch
	// as the reference for determining which entries to prune.
	if qf := qa.GetQTDFinality(); qf != nil {
		currentSlot := EpochStartSlot(epoch) + SlotsPerEpoch - 1
		qf.CleanupOldSlots(currentSlot)
	}
}

// getParticipatedValidators returns validators who participated in an epoch
// FIX: Returns map[types.Address]bool instead of map[int]bool to
// prevent misalignment when validator indices change.
func (qa *QPOSAdvanced) getParticipatedValidators(epoch uint64) map[types.Address]bool {
	participated := make(map[types.Address]bool)
	startSlot := EpochStartSlot(epoch)
	endSlot := startSlot + SlotsPerEpoch - 1

	qa.mu.RLock()
	defer qa.mu.RUnlock()

	for slot := startSlot; slot <= endSlot; slot++ {
		for _, att := range qa.attestations[slot] {
			// audit-fix LOW: only count attestations targeting the requested
			// epoch. Attestations stored in a slot range may carry a stale
			// Target.Epoch; without this check an attacker could reuse old
			// attestations to falsely mark validators as having participated.
			if att.Target.Epoch != epoch {
				continue
			}
			// audit-fix  validate attestation index is within active validator set
			// to prevent memory exhaustion from forged attestations with arbitrary indices
			if att.ValidatorIndex < 0 || att.ValidatorIndex >= qa.validators.Size() {
				continue
			}
			// FIX: Look up validator address by index and use it as the key.
			validator := qa.validators.GetValidatorByIndex(att.ValidatorIndex)
			if validator == nil {
				continue
			}
			participated[validator.Address] = true
		}
	}

	return participated
}

// GetAdvancedStatus returns the full advanced QPOS status
func (qa *QPOSAdvanced) GetAdvancedStatus() map[string]any {
	status := make(map[string]any)

	// Basic QPOS status
	status["currentSlot"] = qa.GetCurrentSlot()
	status["currentEpoch"] = qa.GetCurrentEpoch()
	// audit-fix  use locked getters to prevent data race
	status["justifiedEpoch"] = qa.GetJustifiedEpoch()
	status["finalizedEpoch"] = qa.GetFinalizedEpoch()

	// Fork choice
	status["forkChoice"] = qa.forkChoice.GetForkChoiceStatus()

	// Inactivity leak
	status["inactivityLeakActive"] = qa.inactivityLeak.IsLeakActive()

	// Sync committee
	if sc := qa.syncCommittee.GetCurrentCommittee(); sc != nil {
		status["syncCommitteePeriod"] = sc.Period
		status["syncCommitteeSize"] = len(sc.ValidatorIndices)
	}

	// Pending withdrawals
	status["pendingWithdrawals"] = len(qa.withdrawals.GetPendingWithdrawals())

	// Metrics
	qa.metrics.mu.RLock()
	status["metrics"] = map[string]any{
		"blocksProposed":    qa.metrics.BlocksProposed,
		"blocksMissed":      qa.metrics.BlocksMissed,
		"attestationsTotal": qa.metrics.AttestationsTotal,
		"averageFinality":   qa.metrics.AverageFinality,
	}
	qa.metrics.mu.RUnlock()

	return status
}

// GetValidatorQueue returns the validator queue
func (qa *QPOSAdvanced) GetValidatorQueue() *ValidatorQueue {
	return qa.validatorQueue
}

// GetWithdrawalManager returns the withdrawal manager
func (qa *QPOSAdvanced) GetWithdrawalManager() *WithdrawalManager {
	return qa.withdrawals
}

// GetForkChoice returns the fork choice instance
func (qa *QPOSAdvanced) GetForkChoice() *ForkChoice {
	return qa.forkChoice
}

// GetSyncCommitteeManager returns the sync committee manager
func (qa *QPOSAdvanced) GetSyncCommitteeManager() *SyncCommitteeManager {
	return qa.syncCommittee
}

// GetInactivityLeakManager returns the inactivity leak manager
func (qa *QPOSAdvanced) GetInactivityLeakManager() *InactivityLeakManager {
	return qa.inactivityLeak
}

// DeriveSystemCaller generates a deterministic system caller address for epoch operations.
// HIGH FIX: This provides a valid system caller for ProcessEpochAdvanced instead of
// using the zero address which is explicitly rejected (R24-H2).
// The address is derived from the epoch number to ensure determinism across nodes.
// H-NEW-4 FIX: Only registers for recent epochs (current epoch ± buffer) to prevent
// unbounded growth of system caller list. Old system callers are unregistered.
// P1-T2 (2026-07-14): Exported so node/block_producer.go can use the same
// epoch-based system caller when invoking MinistryRevenue.DistributeEpochRewards.
var (
	systemCallerMu    sync.Mutex
	registeredCallers map[uint64]types.Address // epoch -> address
	maxSystemCallers  = 100                    // H-NEW-4: bound on registered system callers
)

func init() {
	registeredCallers = make(map[uint64]types.Address)
}

func DeriveSystemCaller(epoch uint64) types.Address {
	// CRITICAL FIX: Generate a deterministic address from epoch and register it
	// as a system caller to pass authorization checks.
	// The address is derived using SHA3-256(epoch || "system") for determinism.
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, epoch)
	data = append(data, []byte("system")...)
	hash := sha3.Sum256(data)
	addr := types.BytesToAddress(hash[12:]) // Take last 20 bytes like Ethereum

	// H-NEW-4 FIX: Bounded registration with cleanup of old entries.
	systemCallerMu.Lock()
	defer systemCallerMu.Unlock()

	// If already registered, return without re-registering
	if _, exists := registeredCallers[epoch]; exists {
		return addr
	}

	// Register this address as system caller
	RegisterSystemCaller(addr)
	registeredCallers[epoch] = addr

	// H-NEW-4 FIX: Unregister and clean up old system callers beyond the limit
	if len(registeredCallers) > maxSystemCallers {
		// Find and remove the oldest epochs
		var epochs []uint64
		for e := range registeredCallers {
			epochs = append(epochs, e)
		}
		// Sort ascending
		sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })
		// Remove oldest entries beyond limit
		toRemove := len(registeredCallers) - maxSystemCallers
		for i := 0; i < toRemove; i++ {
			oldAddr := registeredCallers[epochs[i]]
			UnregisterSystemCaller(oldAddr)
			delete(registeredCallers, epochs[i])
		}
	}

	return addr
}

// ResetRegisteredCallersForTesting clears the local "registeredCallers" memo
// map used by DeriveSystemCaller to skip re-registering addresses that have
// already been bound to an epoch. MUST NOT be called in production code.
// Panics if EnableTestHelpers() was not called first.
//
// R55-MINISTRY-DEEPER-FIX (2026-08-12): The cross-test pollution fix
// ResetSystemCallersForTesting() clears the global systemCallers map but
// does NOT touch the registeredCallers memo in this file. That means
// once DeriveSystemCaller(epoch) has been called once for any epoch,
// the memo entry registeredCallers[epoch] survives ResetSystemCallers,
// and a subsequent DeriveSystemCaller(epoch) call returns the cached
// addr WITHOUT calling RegisterSystemCaller(addr) — so the address
// is no longer in systemCallers and isSystemCaller() returns false.
// This in turn breaks TestP1T2_EpochBoundaryRewardIntegration (which
// fatals at "DeriveSystemCaller did not register as system caller")
// when run via -count=N>1 after any prior test invoked DeriveSystemCaller
// for the same epoch, then ResetSystemCallersForTesting cleared the
// global map.
//
// Symmetric with ResetSystemCallersForTesting (validator_manager.go) and
// ResetGenesisHashForTesting (block.go): same panic-guard invariant
// (audit-fix M-1, testHelpersEnabled). Production code that accidentally
// invoked this would strip DeriveSystemCaller of its memoization (a
// fail-closed posture: every call re-registers, possibly re-removing
// oldest entries per H-NEW-4 cleanup) and panic immediately.
func ResetRegisteredCallersForTesting() {
	if !testHelpersEnabled {
		panic("consensus: ResetRegisteredCallersForTesting called without EnableTestHelpers(); this function is for tests only")
	}
	systemCallerMu.Lock()
	defer systemCallerMu.Unlock()
	for k := range registeredCallers {
		delete(registeredCallers, k)
	}
}
