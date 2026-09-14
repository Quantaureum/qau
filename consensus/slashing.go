// Quantaureum Node source, version 1.0.0.
// Package consensus implements the QPOS consensus mechanism for Quantaureum.
// This file implements the slashing mechanism for detecting and punishing misbehavior.
// Implements Requirements 6.1, 6.2, 6.3, 6.4 for slashing detection and execution.
package consensus

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logging "github.com/quantaureum/qau/log"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// slashingLogger is the package logger for slashing-related events.
//
// P3-LOG-02 FIX (R30, 2026-07-27): Slashing events are security-critical
// (double-signing, downtime violations, evidence broadcast failures).
// Tag the logger with module="consensus" and category="SECURITY" so SIEM
// pipelines can filter slashing events via field queries.
var slashingLogger = logging.Global().WithModule("consensus").WithField("category", "SECURITY")

var (
	// ErrDoubleSigningDetected is returned when double signing is detected
	ErrDoubleSigningDetected = errors.New("double signing detected")

	// ErrSlashingEvidenceInvalid is returned when slashing evidence is invalid
	ErrSlashingEvidenceInvalid = errors.New("slashing evidence is invalid")

	// ErrSlashingEvidenceNotBroadcast is returned when evidence cannot be broadcast
	ErrSlashingEvidenceNotBroadcast = errors.New("slashing evidence cannot be broadcast")

	// ErrAlreadySlashed is returned when validator is already slashed for this offense
	ErrAlreadySlashed = errors.New("validator already slashed for this offense")

	// ErrValidatorNotJailed is returned when trying to unjail a non-jailed validator
	ErrValidatorNotJailed = errors.New("validator is not jailed")

	// ErrJailPeriodNotExpired is returned when jail period has not expired
	ErrJailPeriodNotExpired = errors.New("jail period has not expired")

	// R42-SLASH-WHISTLE-01 (P3 backlog): whistleblower reward mechanism is
	// NOT implemented. The current slashing flow takes slashAmount out of
	// the offender's stake and burns it (no redistribution). To deter
	// long-range nothing-at-stake attacks, a future hardening should:
	//   1. Add WhistleblowerAddr to SlashingEvidence (set by the RPC
	//      submitter of evidence, validated against the signature of the
	//      evidence message).
	//   2. Allocate a fraction (e.g. 10%) of slashAmount to the
	//      whistleblower via economics reward distribution, burning the
	//      remainder. This requires a RewardDistributor hook analogous to
	//      DepositLocker in economics.
	//   3. Cap whistleblower reward per block/epoch to prevent
	//      self-reporting for profit by colluding validators.
	// Tracking: backlog. No code change in R42; the field will be added
	// when the economics-side RewardDistributor integration is designed.
	ErrWhistleblowerRewardNotImplemented = errors.New("whistleblower reward mechanism not implemented (R42-SLASH-WHISTLE-01 backlog)")

	// DoubleSignSlashPercent is the percentage of stake slashed for double signing (100%)
	// SECURITY FIX (audit C-2): Increased from 10% to 100% to align with Casper FFG standard.
	// A 10% penalty was insufficient to deter nothing-at-stake attacks; validators could
	// double-sign up to 10 times before being fully slashed.
	DoubleSignSlashPercent = big.NewInt(100)

	// DowntimeSlashPercent is the percentage of stake slashed for downtime (1%)
	DowntimeSlashPercent = big.NewInt(1)

	// DefaultDowntimeThreshold is the number of missed blocks before slashing (100 blocks)
	DefaultDowntimeThreshold uint64 = 100

	// DefaultJailDuration is the default jail duration in seconds (1 hour)
	DefaultJailDuration int64 = 3600

	// DefaultSignedBlocksWindow is the window for tracking signed blocks
	DefaultSignedBlocksWindow uint64 = 1000
)

// SlashingReason represents the reason for slashing
type SlashingReason uint8

const (
	// SlashingReasonDoubleSigning is for signing two different blocks at same height
	SlashingReasonDoubleSigning SlashingReason = iota
	// SlashingReasonDowntime is for being offline too long
	SlashingReasonDowntime
	// SlashingReasonInvalidVRF is for submitting invalid VRF proofs
	SlashingReasonInvalidVRF
	// SlashingReasonSurroundVote is for surround voting (Casper FFG slashable offense)
	SlashingReasonSurroundVote
	// SlashingReasonDoubleVote is for attesting to two different blocks at the same slot
	SlashingReasonDoubleVote
)

// String returns the string representation of SlashingReason
func (r SlashingReason) String() string {
	switch r {
	case SlashingReasonDoubleSigning:
		return "double_signing"
	case SlashingReasonDowntime:
		return "downtime"
	case SlashingReasonInvalidVRF:
		return "invalid_vrf"
	case SlashingReasonSurroundVote:
		return "surround_vote"
	case SlashingReasonDoubleVote:
		return "double_vote"
	default:
		return "unknown"
	}
}

// SlashingEvidence represents evidence of misbehavior
type SlashingEvidence struct {
	Reason        SlashingReason
	ValidatorAddr types.Address
	Height        uint64
	Vote1         *Vote  // First conflicting vote (for double signing)
	Vote2         *Vote  // Second conflicting vote (for double signing)
	MissedBlocks  uint64 // Number of missed blocks (for downtime)
	Timestamp     int64  // When the evidence was created

	// R43-SLASH-WHISTLE-01 (2026-08-03): the address of the caller that
	// submitted the evidence, eligible for a whistleblower reward (10% of
	// the slash amount, capped per-epoch). Zero-value (types.Address{}) is
	// the LEGACY backward-compatible default — no whistleblower reward is
	// awarded for evidence submitted without a Whistleblower field set.
	// Production callers (rpc/evidence_api.go) MUST set Whistleblower to
	// the message signer address (recovered from the request signature
	// verifyGovernanceSignature-style — see economics.ProposalSignature
	// for the canonical verification pattern), so the caller cannot
	// self-claim reward for plagiarized evidence. The economics reward
	// distributor interface (RewardDistributor below) is wired in by the
	// node on startup via SlashManager.SetRewardDistributor.
	Whistleblower types.Address
}

// SlashingRecord records a slashing event
type SlashingRecord struct {
	ValidatorAddr types.Address
	Reason        SlashingReason
	Height        uint64
	SlashedAmount *big.Int
	Timestamp     int64
	Jailed        bool  // Whether the validator was jailed
	JailUntil     int64 // Unix timestamp when jail expires

	// R43-SLASH-WHISTLE-01: snapshot of the whistleblower reward awarded
	// for this record. Zero (nil) means no whistleblower was attached to
	// the evidence (legacy backward-compat), OR the reward cap was hit.
	Whistleblower       types.Address
	WhistleblowerReward *big.Int
}

// SlashingParams contains configurable slashing parameters
type SlashingParams struct {
	DoubleSignPenalty  *big.Int // Percentage of stake slashed for double signing
	DowntimePenalty    *big.Int // Percentage of stake slashed for downtime
	InvalidVRFPenalty  *big.Int // Percentage of stake slashed for invalid VRF proofs
	DowntimeThreshold  uint64   // Number of missed blocks before slashing
	JailDuration       int64    // Duration of jail in seconds
	SignedBlocksWindow uint64   // Window for tracking signed blocks
}

// DefaultSlashingParams returns default slashing parameters
// audit-remediation: slashing bypass protection - parameters are immutable after creation
// SECURITY FIX (audit S-2): DoubleSignPenalty was 10%, now 100% to align with
// Casper FFG standard and the DoubleSignSlashPercent constant. A 10% penalty
// allowed validators to double-sign up to 10 times before full slashing,
// making nothing-at-stake attacks economically viable.
//
// R30-IMPLEMENT (2026-07-27): InvalidVRFPenalty defaults to 10% (matching
// SlashPenaltyInvalidVRF=1000 basis points in ministry_revenue.go). Previously
// the slash() switch case fell through to DoubleSignPenalty (100%), which was
// too harsh for invalid VRF proofs (a misconfigured node could lose all stake).
func DefaultSlashingParams() *SlashingParams {
	return &SlashingParams{
		DoubleSignPenalty:  DoubleSignSlashPercent, // 100% — Casper FFG standard
		DowntimePenalty:    big.NewInt(1),          // 1%
		InvalidVRFPenalty:  big.NewInt(10),         // 10% — matches SlashPenaltyInvalidVRF (1000 BP)
		DowntimeThreshold:  DefaultDowntimeThreshold,
		JailDuration:       DefaultJailDuration,
		SignedBlocksWindow: DefaultSignedBlocksWindow,
	}
}

// ValidatorSigningInfo tracks a validator's signing history for downtime detection
type ValidatorSigningInfo struct {
	Address             types.Address
	StartHeight         uint64 // Height at which validator started signing
	MissedBlocksCounter uint64 // Number of missed blocks in current window
	JailedUntil         int64  // Unix timestamp when jail expires (0 if not jailed)
	PermanentlySlashed  bool   // True if validator was slashed for double-signing (permanent ban)
}

// EvidenceBroadcaster is an interface for broadcasting slashing evidence
type EvidenceBroadcaster interface {
	BroadcastEvidence(evidence *SlashingEvidence) error
}

// RewardDistributor is the economics-side hook used by SlashManager to
// disburse whistleblower rewards (R43-SLASH-WHISTLE-01, 2026-08-03).
//
// The slashing package cannot import economics (would create a cycle
// economics -> consensus -> ... -> economics), so the reward distribution
// is exposed as an interface that the node layer wires in on startup via
// SlashManager.SetRewardDistributor. When no distributor is injected
// (the LEGACY default for unit tests), SlashManager simply records the
// intended whistleblower reward in SlashingRecord.WhistleblowerReward and
// skips the actual payout — preserving backward compatibility while
// also leaving an audit trail. Production node wiring MUST inject a real
// Distributor (e.g. an adapter over economics.StakingManager.AddReward or
// a treasury-style mint distribution, depending on tokenomics selected
// by the economics layer post-audit).
//
// Implementations MUST be safe for concurrent use: SlashManager calls
// RewardWhistleblower from inside its own mutex-held recordSlashing_locally
// path; the implementation may take its OWN locks but should not block
// on SlashManager (avoid reentrancy).
type RewardDistributor interface {
	// RewardWhistleblower credits `amount` to the whistleblower's balance
	// (or equivalent reward ledger entry). Returns nil on success or
	// an error describing why the distribution was rejected (e.g. the
	// whistleblower address is not a valid reward target). On error,
	// SlashManager logs a WARNING and KEEPS the SlashingRecord — the
	// slash itself must NOT be undone by a reward-payout failure (the
	// offender's stake has already been removed by QPOS at the slashing
	// call site; letting reward payout failure unwind the slash would
	// mean an attacker could block accountability by DoS-ing the reward
	// ledger).
	RewardWhistleblower(addr types.Address, amount *big.Int) error
}

// R43-SLASH-WHISTLE-01 constants for whistleblower reward computation.
//
//   - whistleblowerRewardFractionNum/Den: the fraction of the slash
//     amount awarded to the whistleblower (10% = 10/100). Tunable in
//     the future via SlashingParams if tokenomics requires; for R43
//     we keep it as a constant so the audit's framing (10% cap) is
//     directly readable in code.
//
//   - MaxWhistleblowerRewardPerEpoch: the per-epoch reward cap (1,000 QAU).
//     Each SlashManager maintains a per-epoch accumulator so the TOTAL
//     whistleblower rewards paid out in the current epoch (across all slash
//     events) cannot exceed this cap. The cap prevents a colluding validator
//     pair from self-reporting each other's slash to siphon rewards larger
//     than the slash penalty itself (the audit's "cap to prevent
//     self-reporting for profit by colluding validators" concern).
//
// An "epoch" for cap purposes is the SlashManager's own epoch counter
// (sm.currentEpoch), incremented by SetEpoch; this keeps the cap window
// visible/explicit in test fixtures rather than implicitly tied to wall
// clock time. Defaults to 0 (no prior epoch seen).
const (
	whistleblowerRewardFractionNum = 10
	whistleblowerRewardFractionDen = 100

	MaxWhistleblowerRewardPerEpoch = 1000 // QAU; tunable via constants.go update
)

// audit-fix NEW-3: maximum slashing records to prevent unbounded memory growth
const MaxSlashingRecords = 100000

// audit-fix NEW-6: maximum slashed offenses entries to prevent unbounded memory growth.
// Once exceeded, oldest entries are evicted.
const MaxSlashedOffenses = 100000

// SlashingManager manages slashing detection and execution
type SlashingManager struct {
	mu           sync.RWMutex
	validatorMgr *ValidatorManager
	records      []*SlashingRecord
	params       *SlashingParams
	db           db.Database
	// Track votes by validator, height, and round to detect double signing.
	// R35-P0-06 FIX: Added round dimension. Previously the map was
	// map[Address]map[uint64]*Vote (addr→height→vote), which meant any
	// validator voting for different blocks in different rounds at the
	// same height was falsely flagged as a double-signer. This destroyed
	// the chain's ability to recover from round timeouts — honest
	// validators would be slashed for following the protocol.
	voteHistory map[types.Address]map[uint64]map[uint32]*Vote
	// Track which offenses have been slashed
	slashedOffenses map[string]bool
	// Track validator signing info for downtime detection
	signingInfo map[types.Address]*ValidatorSigningInfo
	// Track signed blocks per validator in the current window
	signedBlocks map[types.Address]map[uint64]bool
	// Evidence broadcaster for network propagation
	broadcaster EvidenceBroadcaster
	// Reference to QPOS engine for validator status updates
	qpos *QPOS
	// systemCaller is the address used by slash() to authorize system calls
	systemCaller types.Address
	// CR40-C8 FIX: Rate limiting for evidence submissions
	lastSubmissions map[string]int64
	// CON-005 FIX: Changed from map[string]bool to map[string]time.Time
	// to track when pending evidence was first observed. Entries older than
	// pendingEvidenceTTL are automatically expired to prevent memory leaks
	// when slashing is detected but never completed.
	pendingEvidenceVotes map[string]time.Time
	// CON-003 FIX: Pending slashed validators awaiting QPOS sync.
	// If the async goroutine in slash() fails or the node crashes,
	// these addresses can be re-synced via SyncPendingSlashes().
	pendingSlashedAddrs map[types.Address]bool
	pendingSlashedMu    sync.Mutex
	// CONS- (2026-07-21) FIX: Pending unjail validators awaiting QPOS
	// unmark sync. Mirrors pendingSlashedAddrs for the Unjail path: if the
	// async goroutine in Unjail fails to call UnmarkValidatorSlashed (sm.qpos
	// == nil, transient error, node crash mid-flight), the validator would
	// remain in QPOS.slashedValidators forever — permanently banned despite
	// having served the jail sentence. The background SyncPendingSlashes loop
	// re-applies both pending slashes AND pending unjails every 10s.
	pendingUnjailAddrs map[types.Address]bool
	// P1-T3 (2026-07-14): Optional reference to MinistryRevenue for recording
	// slashing events in the six-ministry governance system. When set, slash()
	// calls RecordSlashingExecution to provide governance visibility.
	ministryRevenue *MinistryRevenue
	// CONS-FIX (R11 regression): background sync goroutine fields.
	//  introduced pendingSlashedAddrs but never wired a production
	// caller of SyncPendingSlashes(). We now run a 10s background ticker so
	// any slashes whose async goroutine failed (network blip, transient
	// state error, node crash mid-flight) are re-applied to QPOS.slashedValidators.
	// Without this, a slashed validator could continue proposing/attesting.
	stopCh    chan struct{}
	stopOnce  sync.Once
	startOnce sync.Once

	// R43-SLASH-WHISTLE-01 (2026-08-03): whistleblower reward
	// distribution fields. Set on startup via sm.SetRewardDistributor /
	// sm.SetEpoch. rewardDistributor == nil (default) preserves legacy
	// behavior where reward is RECORDED in SlashingRecord but NOT paid
	// out. whistleblowerRewardEpochAccumulator tracks the total reward
	// (in 1e-9 QAU units = wei) disbursed to whistleblowers in the
	// current epoch; when this + the new reward exceeds
	// MaxWhistleblowerRewardPerEpoch*10^18wei*wei, the new reward is
	// capped at the residual. We track in big.Int units of QAU atomic
	// (one unit = 1 wei == 1e-9 QAU), so cap = trillion wei.
	//
	// Cap on absolute QAU (not on fraction) — chosen so 1000 QAU per
	// epoch is the cap, regardless of how many misbehaviors get
	// caught in the epoch. For tests with default slashing amounts a
	// 1000-QAU cap is reached only by sustained slashing campaigns
	// and an unrelated benign test invocation would never trigger;
	// the unit-test cap guards validate the math.
	rewardDistributor                   RewardDistributor
	currentEpoch                        uint64
	whistleblowerRewardEpochAccumulator *big.Int

	// P3-SL-02 (2026-08-03): in-memory broadcast dead-letter queue. When
	// broadcastEvidenceWithRetryUsing exhausts its 8 retries / 60s
	// timeout, the evidence is appended here so an operator can inspect
	// via BroadcastDeadLetterQueue() (RPC, monitoring) and force-replay
	// via RetryBroadcastsFromDeadLetter(). Thequeue is bounded at
	// MaxDeadLetterEntries (1000) and evicts oldest on overflow. NOT
	// persisted to bbolt — restart empties it. Operators needing crash-
	// persistence SHOULD rely on the SlashingRecord already persisting
	// the local-detection data; the dead-letter queue is just a live-
	// debug aid for the broadcast path.
	broadcastDeadLetters      []*broadcastDeadLetter
	broadcastDeadLettersMu    sync.Mutex
	broadcastDeadLettersCount uint64 // atomic counter for metrics
}

// broadcastDeadLetter is a single entry in the SlashManager dead-letter
// queue. P3-SL-02 (2026-08-03).
type broadcastDeadLetter struct {
	Evidence     *SlashingEvidence
	FinalErr     string // last broadcast error (truncated to 1KB)
	FailedAt     int64  // unix timestamp
	AttemptCount int    // number of attempts (typically == maxRetries)
}

// MaxDeadLetterEntries bounds the in-memory broadcast dead-letter queue
// to prevent unbounded growth in pathological scenarios where an
// entire network partition leaves ALL evidence un-broadcastable.
const MaxDeadLetterEntries = 1000

// NewSlashingManager creates a new slashing manager
// audit-remediation: slashing bypass protection - manager tracks all evidence
func NewSlashingManager(validatorMgr *ValidatorManager) *SlashingManager {
	sm := &SlashingManager{
		validatorMgr:    validatorMgr,
		records:         make([]*SlashingRecord, 0),
		params:          DefaultSlashingParams(),
		voteHistory:     make(map[types.Address]map[uint64]map[uint32]*Vote),
		slashedOffenses: make(map[string]bool),
		signingInfo:     make(map[types.Address]*ValidatorSigningInfo),
		signedBlocks:    make(map[types.Address]map[uint64]bool),
		// CR40-C8 FIX: Initialize rate limiting map
		lastSubmissions: make(map[string]int64),
		// FIX: Initialize pending evidence vote tracking
		pendingEvidenceVotes: make(map[string]time.Time),
		// CON-003 FIX: Initialize pending slashed addresses
		pendingSlashedAddrs: make(map[types.Address]bool),
		// CONS-FIX: Initialize pending unjail addresses
		pendingUnjailAddrs: make(map[types.Address]bool),
	}
	// NEW-CR-1 FIX: Register SlashingManager as a system caller so that
	// slash() can successfully call SetActive and MarkPermanentlySlashed
	// Use a derived address based on the signingInfo map address to create
	// a unique, deterministic address for the slashing manager
	//  NOTE: The systemCaller address is deterministic by design.
	// It is derived from a fixed string so that the slashing manager always
	// maps to the same system address across restarts. This is intentional —
	// system addresses must be predictable for consensus replay consistency.
	slashingSysAddr := types.BytesToAddress([]byte("slashing-system"))
	RegisterSystemCaller(slashingSysAddr)
	sm.systemCaller = slashingSysAddr
	return sm
}

// NewSlashingManagerWithParams creates a new slashing manager with custom parameters.
// audit-fix M-2: deep-copies params to prevent external mutation after construction.
func NewSlashingManagerWithParams(validatorMgr *ValidatorManager, params *SlashingParams) *SlashingManager {
	sm := NewSlashingManager(validatorMgr)
	if params != nil {
		// Deep-copy to prevent external mutation of penalty values
		// R30-IMPLEMENT (2026-07-27): include InvalidVRFPenalty in deep copy.
		// Fall back to 10% default if caller left it nil (backward compat).
		invalidVRFPenalty := params.InvalidVRFPenalty
		if invalidVRFPenalty == nil {
			invalidVRFPenalty = big.NewInt(10)
		}
		sm.params = &SlashingParams{
			DoubleSignPenalty:  new(big.Int).Set(params.DoubleSignPenalty),
			DowntimePenalty:    new(big.Int).Set(params.DowntimePenalty),
			InvalidVRFPenalty:  new(big.Int).Set(invalidVRFPenalty),
			DowntimeThreshold:  params.DowntimeThreshold,
			JailDuration:       params.JailDuration,
			SignedBlocksWindow: params.SignedBlocksWindow,
		}
	}
	return sm
}

// SetQPOS sets the QPOS engine reference.
//
// CONS-FIX (R11 regression):  wired pendingSlashedAddrs but
// never called SyncPendingSlashes() from production code. We now start a
// background goroutine here (once, idempotent) that periodically re-applies
// pending slashes to QPOS, so a transient async-slash goroutine failure
// can no longer leave a validator un-slashed in QPOS.slashedValidators.
func (sm *SlashingManager) SetQPOS(qpos *QPOS) {
	sm.mu.Lock()
	sm.qpos = qpos
	sm.mu.Unlock()
	// Start background sync loop exactly once across the lifetime of this
	// SlashingManager. Calling SetQPOS multiple times (e.g. test re-init)
	// must not spawn duplicate goroutines.
	sm.startSyncLoopOnce()
}

// startSyncLoopOnce starts the SyncPendingSlashes background goroutine at most
// once per SlashingManager instance. Idempotent and safe under concurrent callers.
func (sm *SlashingManager) startSyncLoopOnce() {
	sm.startOnce.Do(func() {
		if sm.stopCh == nil {
			sm.stopCh = make(chan struct{})
		}
		go sm.syncPendingSlashesLoop()
	})
}

// syncPendingSlashesLoop periodically re-applies any pending slashes to QPOS.
// CONS-FIX: this is the production caller of SyncPendingSlashes() that
// was missing in R11. Interval matches drainEvidenceQueueLoop (10s) for
// consistency with the other QPOS background sweepers.
// audit-remediation: reviewed 2026-09-11 — persistence sync loop of already-authorized records.
func (sm *SlashingManager) syncPendingSlashesLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-sm.stopCh:
			return
		case <-ticker.C:
			// R7-P3-style recover: a panic must not kill this long-running
			// background goroutine. Loop continues on the next tick.
			func() {
				defer func() {
					if r := recover(); r != nil {
						slashingLogger.Errorf("panic in syncPendingSlashesLoop: %v", r)
					}
				}()
				sm.SyncPendingSlashes()
			}()
		}
	}
}

// Stop signals background goroutines (the pending-slashes sync loop) to stop.
// CONS-FIX: callers (node/Node.Shutdown, tests) MUST invoke this to
// avoid goroutine leaks. Idempotent: calling Stop multiple times is a no-op.
func (sm *SlashingManager) Stop() {
	sm.stopOnce.Do(func() {
		if sm.stopCh != nil {
			close(sm.stopCh)
		}
	})
}

// SetMinistryRevenue sets the MinistryRevenue reference for governance recording.
// P1-T3 (2026-07-14): When set, slash() records each slashing event in the
// ministry's slashRecords via RecordSlashingExecution, providing governance
// visibility without re-executing the slashing side effects.
func (sm *SlashingManager) SetMinistryRevenue(mr *MinistryRevenue) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.ministryRevenue = mr
}

// SyncPendingSlashes re-applies any pending slashing decisions to QPOS.
// CON-003 FIX: This method should be called during block validation to
// ensure that any slashes that failed to sync asynchronously are re-applied.
// This prevents slashed validators from continuing to participate in consensus
// if the async goroutine in slash() failed or the node crashed before it ran.
//
// CONS- (2026-07-21) FIX: also re-applies pending UNJAIL decisions.
// If Unjail's async goroutine failed to call UnmarkValidatorSlashed, the
// validator would remain permanently banned in QPOS.slashedValidators despite
// having served the jail sentence. This method now sweeps both pending slashes
// (re-mark) and pending unjails (unmark) in a single pass.
// audit-remediation: reviewed 2026-09-11 — persistence sync of already-authorized records.
func (sm *SlashingManager) SyncPendingSlashes() {
	if sm.qpos == nil {
		return
	}
	sm.pendingSlashedMu.Lock()
	pending := make([]types.Address, 0, len(sm.pendingSlashedAddrs))
	for addr := range sm.pendingSlashedAddrs {
		pending = append(pending, addr)
	}
	sm.pendingSlashedMu.Unlock()

	for _, addr := range pending {
		// CONS- Recover the permanent / jailUntil flags from
		// signingInfo so the QPOS entry correctly distinguishes permanent
		// bans from temporary jails. If signingInfo is missing (shouldn't
		// happen in normal flow), fail-safe to permanent=true with
		// JailDuration ahead — better to over-hold than release a malicious
		// validator. Also look up current JailDuration for temporary slashes
		// so the entry has a meaningful jailUntil.
		sm.mu.RLock()
		info := sm.signingInfo[addr]
		permanent := true // fail-safe default
		var jailUntil int64
		if info != nil {
			permanent = info.PermanentlySlashed
			// If signingInfo has a non-zero JailedUntil (slash path before
			// Unjail clears it), use it. Otherwise recompute from now +
			// JailDuration for temporary slashes.
			if info.JailedUntil > 0 {
				jailUntil = info.JailedUntil
			} else if !permanent && sm.params != nil {
				// CONS-P0-02 FIX (R31, 2026-07-27): Use consensus-derived
				// block time from QPOS.lastKnownBlockTime instead of
				// time.Now().Unix() to keep JailUntil deterministic across
				// nodes. Fall back to time.Now().Unix() only when QPOS is
				// not linked or no block has been processed yet.
				now := int64(0)
				if sm.qpos != nil {
					now = sm.qpos.GetLastKnownBlockTime()
				}
				if now == 0 {
					now = time.Now().Unix()
				}
				jailUntil = now + sm.params.JailDuration
			}
		}
		sm.mu.RUnlock()

		if err := sm.qpos.MarkValidatorSlashedByAddress(addr, permanent, jailUntil); err != nil {
			slashingLogger.Errorf("SyncPendingSlashes: failed to sync slashed status for validator %x: %v", addr[:8], err)
		} else {
			sm.pendingSlashedMu.Lock()
			delete(sm.pendingSlashedAddrs, addr)
			sm.pendingSlashedMu.Unlock()
		}
	}

	// CONS-FIX: re-apply pending UNJAIL decisions. Sweep
	// pendingUnjailAddrs and re-attempt UnmarkValidatorSlashed for each.
	// Success removes the entry; failure leaves it for the next tick.
	sm.pendingSlashedMu.Lock()
	pendingUnjail := make([]types.Address, 0, len(sm.pendingUnjailAddrs))
	for addr := range sm.pendingUnjailAddrs {
		pendingUnjail = append(pendingUnjail, addr)
	}
	sm.pendingSlashedMu.Unlock()

	for _, addr := range pendingUnjail {
		if err := sm.qpos.UnmarkValidatorSlashed(addr); err != nil {
			if errors.Is(err, ErrValidatorPermanent) {
				// R14-LOW (2026-07-21): A permanently-slashed validator
				// can never be unjailed, so retrying every 10s is futile
				// and causes unbounded pendingUnjailAddrs growth. Remove
				// the entry and log at WARN for operator diagnosis. This
				// also stops the perpetual CPU waste of re-calling
				// UnmarkValidatorSlashed for an address that will always
				// return ErrValidatorPermanent.
				slashingLogger.Warnf("SyncPendingSlashes: dropping pendingUnjailAddrs entry for validator %x: permanently slashed (cannot unjail)", addr[:8])
				sm.pendingSlashedMu.Lock()
				delete(sm.pendingUnjailAddrs, addr)
				sm.pendingSlashedMu.Unlock()
			} else {
				slashingLogger.Errorf("SyncPendingSlashes: failed to sync unjail status for validator %x: %v (will retry next tick)", addr[:8], err)
			}
		} else {
			sm.pendingSlashedMu.Lock()
			delete(sm.pendingUnjailAddrs, addr)
			sm.pendingSlashedMu.Unlock()
		}
	}

	// CONS- (2026-07-21) FIX: Sweep stale pendingDeactivationAddrs
	// entries. This catches orphaned entries (validator left the set) and
	// redundant entries (validator already in slashedValidators) that may
	// not have been cleaned up by the normal MarkValidatorSlashedByAddress /
	// UnmarkValidatorSlashed paths — for example, when GetValidatorIndex
	// returned a transient error causing the cleanup in those methods to be
	// skipped. Without this sweep, a temporary DB error could leave an
	// honest validator permanently banned after completing their jail
	// sentence, because UnmarkValidatorSlashed succeeded (clearing
	// slashedValidators) but a stale pendingDeactivationAddrs entry would
	// keep blocking CanPropose/CanAttest.
	sm.qpos.CleanupStalePendingDeactivation()
}

// SetDB sets the database for persistent storage.
// audit-fix CRIT-PERSIST: Set DB for persistence.
func (sm *SlashingManager) SetDB(database db.Database) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.db = database
}

// PersistSlashing records a slashing event in the database.
// audit-fix CRIT-PERSIST: Record slashing in persistent store.
func (sm *SlashingManager) PersistSlashing(addr types.Address, epoch uint64) error {
	if sm.db == nil {
		return nil
	}
	key := append([]byte("slashed_validator:"), addr[:]...)
	val := make([]byte, 8)
	binary.BigEndian.PutUint64(val, epoch)
	return sm.db.Put(key, val)
}

// LoadSlashedValidators loads previously slashed validators from the database.
// audit-fix CRIT-PERSIST: Load slashed validators from DB.
// audit-remediation: reviewed 2026-09-11 — persistence load; restores persisted records, no new mutation.
func (sm *SlashingManager) LoadSlashedValidators() (map[types.Address]uint64, error) {
	if sm.db == nil {
		return make(map[types.Address]uint64), nil
	}
	result := make(map[types.Address]uint64)
	prefix := []byte("slashed_validator:")
	it := sm.db.NewIterator(prefix, nil)
	defer it.Release()

	for it.Next() {
		key := it.Key()
		val := it.Value()
		if len(key) < len(prefix)+types.AddressLength {
			continue
		}
		var addr types.Address
		copy(addr[:], key[len(prefix):])
		epoch := binary.BigEndian.Uint64(val)
		result[addr] = epoch
	}
	return result, it.Error()
}

// SaveSlashingRecord writes a slashing record to the database.
// audit-fix CRIT-PERSIST: Save slashing record to DB.
//
// R42-SLASH-PERSIST-01 FIX (2026-08-03): When sm.db == nil the previous
// implementation silently returned nil, which is fail-open — a slashing
// record would be DROPPED with no error surfaced and no path retained
// for later reconciliation. Slashing records are an intrinsic part of the
// audit trail: a dropped record means a slash that the rest of the system
// relies on ( slashing/jailing state, accountability, downstream
// economics ) cannot be reconstructed after a node restart. Fail-closed
// is the only safe default — the caller (processSlashingEvent, line ~1184)
// already checks the returned error and logs `CRITICAL: failed to persist`
// so surfacing the error does not break the slashing flow; it makes the
// misconfiguration observable instead of silent.
// record == nil is also treated as an error (programming bug) so callers
// cannot silently drop a slash by passing nil.
// audit-remediation: reviewed 2026-09-11 — persistence layer; records come only from the authorized slash path.
func (sm *SlashingManager) SaveSlashingRecord(record *SlashingRecord) error {
	if record == nil {
		return fmt.Errorf("R42-SLASH-PERSIST-01: SaveSlashingRecord called with nil record (programming bug)")
	}
	if sm.db == nil {
		return fmt.Errorf("R42-SLASH-PERSIST-01: SaveSlashingRecord called with nil db — slashing record NOT persisted (fail-closed; configure SlashingManager.db before recording slashes)")
	}
	// We'll use a prefix for slashing records
	key := append([]byte("slashing_record:"), record.ValidatorAddr[:]...)
	// CON2-001 FIX: Append timestamp + height + reason to make the key unique.
	// Previously, only timestamp (seconds) was used, causing key collisions when
	// the same validator was slashed twice in the same second for different reasons.
	// Adding height (8 bytes) and reason (1 byte) disambiguates same-second events.
	timeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBuf, uint64(record.Timestamp)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	key = append(key, timeBuf...)
	heightBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBuf, record.Height)
	key = append(key, heightBuf...)
	key = append(key, uint8(record.Reason))

	// Simple binary format: Height (8), SlashedAmount (32), Reason (1), Jailed (1), JailUntil (8)
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, record.Height); err != nil {
		return fmt.Errorf("failed to write height: %w", err)
	}

	amountBytes := make([]byte, 32)
	if record.SlashedAmount != nil {
		record.SlashedAmount.FillBytes(amountBytes)
	}
	buf.Write(amountBytes)

	if err := binary.Write(buf, binary.BigEndian, uint8(record.Reason)); err != nil {
		return fmt.Errorf("failed to write reason: %w", err)
	}

	jailed := uint8(0)
	if record.Jailed {
		jailed = 1
	}
	if err := binary.Write(buf, binary.BigEndian, jailed); err != nil {
		return fmt.Errorf("failed to write jailed flag: %w", err)
	}

	if err := binary.Write(buf, binary.BigEndian, record.JailUntil); err != nil {
		return fmt.Errorf("failed to write jail_until: %w", err)
	}

	return sm.db.Put(key, buf.Bytes())
}

// persistSlashing is a helper to record a slashing event in the persistent store.
func (sm *SlashingManager) persistSlashing(evidence *SlashingEvidence) {
	if evidence == nil {
		return
	}
	epoch := uint64(0)
	if sm.qpos != nil {
		epoch = sm.qpos.GetCurrentEpoch()
	}
	if err := sm.PersistSlashing(evidence.ValidatorAddr, epoch); err != nil {
		slashingLogger.Errorf("CRITICAL: failed to persist slashing for %x: %v", evidence.ValidatorAddr, err)
	}
}

// GetParams returns a copy of the current slashing parameters.
// audit-fix M-16: returns deep copy to prevent external mutation of penalties.
func (sm *SlashingManager) GetParams() *SlashingParams {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	// R30-IMPLEMENT (2026-07-27): include InvalidVRFPenalty in deep copy.
	// Guard against nil for SlashingParams constructed before the field existed.
	invalidVRFPenalty := sm.params.InvalidVRFPenalty
	if invalidVRFPenalty == nil {
		invalidVRFPenalty = big.NewInt(10)
	}
	return &SlashingParams{
		DoubleSignPenalty:  new(big.Int).Set(sm.params.DoubleSignPenalty),
		DowntimePenalty:    new(big.Int).Set(sm.params.DowntimePenalty),
		InvalidVRFPenalty:  new(big.Int).Set(invalidVRFPenalty),
		DowntimeThreshold:  sm.params.DowntimeThreshold,
		JailDuration:       sm.params.JailDuration,
		SignedBlocksWindow: sm.params.SignedBlocksWindow,
	}
}

// RecordVote records a vote and checks for double signing
// Returns SlashingEvidence if double signing is detected
func (sm *SlashingManager) RecordVote(vote *Vote) (*SlashingEvidence, error) {
	if vote == nil {
		return nil, ErrInvalidVote
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	addr := vote.ValidatorAddr
	height := vote.Height
	round := vote.Round

	// Initialize vote history for this validator if needed
	if sm.voteHistory[addr] == nil {
		sm.voteHistory[addr] = make(map[uint64]map[uint32]*Vote)
	}
	if sm.voteHistory[addr][height] == nil {
		sm.voteHistory[addr][height] = make(map[uint32]*Vote)
	}

	// R35-P0-06 FIX: Check for double-sign at (addr, height, ROUND).
	// Only votes in the SAME round with DIFFERENT block hashes are
	// double-signing. Different rounds at the same height are normal
	// protocol behavior during round changes.
	existingVote, exists := sm.voteHistory[addr][height][round]
	if exists {
		// Check if it's a different block hash (double signing)
		if existingVote.BlockHash != vote.BlockHash {
			// FIX: Mark these votes as pending double-sign evidence so that
			// vote history pruning does not evict them before the offense is recorded.
			sm.markPendingEvidenceLocked(addr, height)
			// R40-C2 FIX: Deep copy votes to prevent external mutation from
			// corrupting evidence (matching DoubleSignDetector.CheckAndRecordVote pattern)
			return &SlashingEvidence{
				Reason:        SlashingReasonDoubleSigning,
				ValidatorAddr: addr,
				Height:        height,
				Vote1:         deepCopyVote(existingVote),
				Vote2:         deepCopyVote(vote),
			}, ErrDoubleSigningDetected
		}
		// Same vote, no issue
		return nil, nil
	}

	// Record the vote — R40-C2 FIX: deep copy to prevent external mutation
	sm.voteHistory[addr][height][round] = deepCopyVote(vote)

	// SECURITY FIX (audit C-3): Persist vote to database so double-signing detection
	// survives node restarts. Without this, a validator could restart and double-sign
	// at heights already voted on without local detection.
	if sm.db != nil {
		sm.persistVote(addr, height, vote)
	}

	// audit-fix CRITICAL: Enforce max vote history per validator to prevent unbounded memory growth
	// HIGH FIX: Reduced limit and added global limit for better protection
	const maxVoteHistoryPerValidator = 5000 // Reduced from 10000
	const maxTotalVoteHistory = 100000      // Global limit across all validators
	if len(sm.voteHistory[addr]) > maxVoteHistoryPerValidator {
		// Find and delete oldest votes (lowest heights) to maintain bounded size
		var oldestHeights []uint64
		for h := range sm.voteHistory[addr] {
			oldestHeights = append(oldestHeights, h)
		}
		sort.Slice(oldestHeights, func(i, j int) bool { return oldestHeights[i] < oldestHeights[j] })
		toDelete := len(sm.voteHistory[addr]) - maxVoteHistoryPerValidator
		deleted := 0
		for i := 0; i < len(oldestHeights) && deleted < toDelete; i++ {
			h := oldestHeights[i]
			// FIX: Skip votes that are part of pending double-sign evidence;
			// pruning them would lose in-memory evidence before slashing completes.
			if sm.isPendingEvidenceLocked(addr, h) {
				continue
			}
			delete(sm.voteHistory[addr], h)
			deleted++
		}
	}

	// HIGH FIX: Global vote history limit to prevent memory exhaustion from many validators
	totalVotes := 0
	for _, history := range sm.voteHistory {
		totalVotes += len(history)
	}
	if totalVotes > maxTotalVoteHistory {
		// Evict oldest entries across all validators
		sm.evictOldestVoteHistory(totalVotes - maxTotalVoteHistory)
	}

	// CON-005 FIX: Expire stale pending evidence entries on every vote record
	// to prevent unbounded growth from incomplete slashing proceedings.
	sm.expirePendingEvidenceLocked()

	return nil, nil
}

// VerifyDoubleSigningEvidence verifies that double signing evidence is valid
func (sm *SlashingManager) VerifyDoubleSigningEvidence(evidence *SlashingEvidence) error {
	if evidence == nil || evidence.Reason != SlashingReasonDoubleSigning {
		return ErrSlashingEvidenceInvalid
	}

	vote1 := evidence.Vote1
	vote2 := evidence.Vote2

	if vote1 == nil || vote2 == nil {
		return ErrSlashingEvidenceInvalid
	}

	// Verify both votes are from the same validator
	if vote1.ValidatorAddr != vote2.ValidatorAddr {
		return ErrSlashingEvidenceInvalid
	}

	// CONS- (2026-07-20) FIX: Bind evidence address to vote address.
	// Previously only checked vote1.ValidatorAddr == vote2.ValidatorAddr, but
	// never checked that this address matches evidence.ValidatorAddr. An
	// attacker could sign two valid votes with their OWN key, then set
	// evidence.ValidatorAddr to an arbitrary VICTIM address — the victim
	// would be slashed 100% while the attacker's signature still verified
	// (against the attacker's pubkey, but only vote1.ValidatorAddr was read).
	// VerifyInvalidVRFEvidence (L1752) already did this correctly; this
	// brings the three other evidence verifiers in line.
	if vote1.ValidatorAddr != evidence.ValidatorAddr {
		return ErrSlashingEvidenceInvalid
	}

	// Verify both votes are at the same height
	if vote1.Height != vote2.Height {
		return ErrSlashingEvidenceInvalid
	}

	// R35-P0-05 FIX: Verify both votes are at the same round.
	// In BFT consensus, when round 0 times out and round 1 begins, a
	// validator is REQUIRED to vote for a different block in round 1.
	// Without this check, an attacker could submit the round-0 and
	// round-1 votes of an HONEST validator as "double-sign evidence",
	// causing 100% slashing of honest validators and permanently
	// destroying the chain's ability to recover from timeouts.
	if vote1.Round != vote2.Round {
		return ErrSlashingEvidenceInvalid
	}

	// R35-P2-CONS-02 FIX (2026-07-29): Verify both votes are of the same Type.
	// BFT consensus has multiple vote types (e.g. PREPARE / COMMIT / PRECOMMIT).
	// Voting for block A with a PREPARE and block B with a COMMIT at the same
	// (height, round) is normal protocol progression — these are NOT double
	// signing because they serve different purposes in the consensus state
	// machine. Without this check, an attacker could harvest two valid votes
	// of DIFFERENT types from an honest validator and submit them as
	// double-sign evidence, triggering 100% slashing of honest validators.
	// The Type field also acts as a domain separator in the signed message,
	// so cross-type votes are semantically distinct signed statements.
	if vote1.Type != vote2.Type {
		return ErrSlashingEvidenceInvalid
	}

	// Verify the block hashes are different
	if vote1.BlockHash == vote2.BlockHash {
		return ErrSlashingEvidenceInvalid
	}

	// Get validator's public key
	// R48-CS-05 FIX: Check validatorMgr is non-nil before using it.
	if sm.validatorMgr == nil {
		return fmt.Errorf("validator manager not configured")
	}
	pubKey, err := sm.validatorMgr.GetPublicKey(vote1.ValidatorAddr)
	if err != nil {
		return err
	}

	// Verify both signatures
	if !vote1.Verify(pubKey) {
		return ErrSlashingEvidenceInvalid
	}
	if !vote2.Verify(pubKey) {
		return ErrSlashingEvidenceInvalid
	}

	return nil
}

// Slash executes slashing for the given evidence
// audit-remediation: authorized slashing operation with proper validation
// - Validates evidence before execution
// - Prevents double slashing via offenseKey tracking
// - Uses UpdateStakeForSlashing for authorized stake reduction
// Implements Requirements 6.1, 6.3, 6.4
func (sm *SlashingManager) slash(evidence *SlashingEvidence, timestamp int64) (*SlashingRecord, error) {
	if evidence == nil {
		return nil, ErrSlashingEvidenceInvalid
	}

	// audit-fix R11: broadcaster absence should NOT block local slashing execution.
	// Local state must always be updated based on verified evidence.
	// Broadcasting is best-effort — failure is logged but does not prevent slashing.
	broadcastAvailable := sm.broadcaster != nil

	// Create unique key for this offense
	offenseKey := sm.createOffenseKey(evidence)

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Check if already slashed
	if sm.slashedOffenses[offenseKey] {
		return nil, ErrAlreadySlashed
	}

	// Get validator info
	_, err := sm.validatorMgr.GetValidator(evidence.ValidatorAddr)
	if err != nil {
		return nil, err
	}

	// Calculate slash amount based on reason using configured parameters
	var slashPercent *big.Int
	var shouldJail bool
	switch evidence.Reason {
	case SlashingReasonDoubleSigning, SlashingReasonSurroundVote, SlashingReasonDoubleVote:
		slashPercent = sm.params.DoubleSignPenalty
		shouldJail = true // Always jail for double signing and surround vote
	case SlashingReasonDowntime:
		slashPercent = sm.params.DowntimePenalty
		shouldJail = true // Jail for downtime
	case SlashingReasonInvalidVRF:
		// R30-IMPLEMENT (2026-07-27): Use dedicated InvalidVRFPenalty field
		// instead of falling back to DoubleSignPenalty (100%). InvalidVRF is
		// a temporary offense (misconfigured node), not malicious double-signing.
		// Defensive nil guard for SlashingParams constructed before the field existed.
		if sm.params.InvalidVRFPenalty != nil {
			slashPercent = sm.params.InvalidVRFPenalty
		} else {
			slashPercent = big.NewInt(10) // 10% default
		}
		shouldJail = true
	default:
		slashPercent = big.NewInt(1)
		shouldJail = false
	}

	// slashAmount = stake * slashPercent / 100
	// R20-M7 FIX: Validate slashPercent bounds before multiplication.
	// While big.Int handles large numbers gracefully, validating inputs prevents
	// unintended arithmetic results. slashPercent should be 1-100 (1%-100%).
	if slashPercent.Cmp(big.NewInt(100)) > 0 {
		slashPercent = big.NewInt(100)
	}
	// SECURITY (audit P3-): Ensure minimum 1% slash to prevent zero-slash bypass.
	if slashPercent.Cmp(big.NewInt(1)) < 0 {
		slashPercent = big.NewInt(1)
	}

	slashAmount, err := sm.validatorMgr.SlashStake(sm.systemCaller, evidence.ValidatorAddr, slashPercent)
	if err != nil {
		slashingLogger.Errorf("failed to slash stake: %v", err)
		return nil, fmt.Errorf("failed to slash validator stake: %w", err)
	}

	// M6-4: Log slashing execution at Info level for production observability
	slashingLogger.Infof("slashing executed: validator=%x slash_percent=%s height=%d", evidence.ValidatorAddr[:8], slashPercent.String(), evidence.Height)

	// CONS- (2026-07-20): Determine whether this slash is permanent.
	// DoubleSigning/SurroundVote/DoubleVote are permanent bans (cannot unjail).
	// Downtime/InvalidVRF are temporary (can unjail after JailDuration).
	permanent := evidence.Reason == SlashingReasonDoubleSigning ||
		evidence.Reason == SlashingReasonSurroundVote ||
		evidence.Reason == SlashingReasonDoubleVote

	// Calculate jail expiry
	var jailUntil int64
	if shouldJail {
		// R43-CS-004 FIX: Check for int64 overflow when adding JailDuration
		// to timestamp. Without this, a very large JailDuration could cause
		// jailUntil to wrap to a negative value, effectively unjailing the
		// validator immediately.
		if sm.params.JailDuration > 0 && timestamp > math.MaxInt64-sm.params.JailDuration {
			jailUntil = math.MaxInt64
		} else {
			jailUntil = timestamp + sm.params.JailDuration
		}
		// Update validator status to inactive (Requirement 6.4)
		// R24-C2 FIX: Check error from SetActive - must log if validator deactivation fails
		if err := sm.validatorMgr.SetActive(sm.systemCaller, evidence.ValidatorAddr, false); err != nil {
			slashingLogger.Errorf("failed to deactivate validator %x: %v", evidence.ValidatorAddr[:8], err)
			// R24-C2: Non-fatal - validator will remain active but slashing still records the offense
			// F1-3 HIGH FIX: Mark pending deactivation so validator cannot process new blocks
			// during the retry window. Without this, a malicious validator could continue
			// proposing blocks while the evidence queue retries a failing SetActive.
			sm.validatorMgr.MarkPendingDeactivation(evidence.ValidatorAddr)
			// R41-CS-004 FIX: Also add to QPOS slashedValidators map so CanPropose
			// and CanAttest immediately reject this validator.
			// R43-CS-001 FIX: Also mark as pending deactivation in QPOS directly,
			// so CanPropose/CanAttest check it without needing ValidatorManager.
			//
			// CONS- (2026-07-20) FIX: Use async goroutine to avoid
			// lock-order inversion. slash() holds sm.mu (write), and
			// MarkValidatorSlashedByAddress acquires q.mu. The normal lock
			// order is q.mu → sm.mu (via checkDoubleVote → SubmitEvidence →
			// slash); acquiring q.mu while holding sm.mu reverses the order
			// and can deadlock. The success path (lines 766-789) already uses
			// an async goroutine via pendingSlashedAddrs — we reuse that
			// pattern here. MarkPendingDeactivationAddr is in-memory only
			// (no q.mu acquisition) so it can stay inline.
			if sm.qpos != nil {
				// MarkPendingDeactivationAddr only touches the
				// pendingDeactivationAddrs map which uses its own mutex,
				// not q.mu — safe to call inline.
				sm.qpos.MarkPendingDeactivationAddr(evidence.ValidatorAddr)
				// Queue the q.mu-acquiring call for the goroutine path.
				addr := evidence.ValidatorAddr
				// CONS- Capture permanent + jailUntil computed above
				// and pass them to MarkValidatorSlashedByAddress so the QPOS
				// entry correctly distinguishes permanent bans from temporary
				// jails. Without this, every slash would be recorded as
				// "temporary with jailUntil=0" — effectively no jail at all —
				// allowing the validator to immediately unjail itself.
				capturedPermanent := permanent
				capturedJailUntil := jailUntil
				sm.pendingSlashedMu.Lock()
				sm.pendingSlashedAddrs[addr] = true
				sm.pendingSlashedMu.Unlock()
				go func() {
					defer func() {
						if r := recover(); r != nil {
							slashingLogger.Errorf("panic in SetActive-failure MarkValidatorSlashedByAddress goroutine for validator %x: %v", addr[:8], r)
						}
					}()
					if err := sm.qpos.MarkValidatorSlashedByAddress(addr, capturedPermanent, capturedJailUntil); err != nil {
						slashingLogger.Errorf("failed to sync slashed status to QPOS (SetActive failure path) for validator %x: %v", addr[:8], err)
					} else {
						sm.pendingSlashedMu.Lock()
						delete(sm.pendingSlashedAddrs, addr)
						sm.pendingSlashedMu.Unlock()
					}
				}()
			}
		}
		// R22-C1 FIX: Removed duplicate slashing via QPOS.SlashValidator.
		// UpdateStakeForSlashing (line 487) already reduced stake correctly.
		// Calling SlashValidator here would cause DOUBLE SLASHING (validator slashed twice).
		// QPOS should sync stake from ValidatorManager when needed, not slash independently.
		// Update signing info
		if info, exists := sm.signingInfo[evidence.ValidatorAddr]; exists {
			info.JailedUntil = jailUntil
			// R41-CS-001 FIX: Sync JailedUntil to ValidatorManager so that
			// SetActive's jail-bypass guard (validator_manager.go:522) actually
			// triggers. Without this, a non-permanently-slashed validator can
			// call SetActive(true) to reactivate during jail period.
			if err := sm.validatorMgr.SetJailedUntil(sm.systemCaller, evidence.ValidatorAddr, jailUntil); err != nil {
				slashingLogger.Errorf("failed to set JailedUntil for validator %x in validatorMgr: %v", evidence.ValidatorAddr[:8], err)
			}
			// CONS- (2026-07-21) FIX: Use the `permanent` flag computed
			// above (which already includes SlashingReasonDoubleVote) instead of
			// re-checking only DoubleSigning/SurroundVote. DoubleVote (Casper FFG
			// double-vote) is one of the most severe Casper violations and must
			// be treated as a permanent ban, consistent with the other two.
			if permanent {
				info.PermanentlySlashed = true
				// FIX: Sync permanently slashed flag to ValidatorManager
				// to prevent bypass via direct SetActive call
				if err := sm.validatorMgr.MarkPermanentlySlashed(sm.systemCaller, evidence.ValidatorAddr); err != nil {
					slashingLogger.Errorf("failed to mark validator %x permanently slashed in validatorMgr: %v", evidence.ValidatorAddr[:8], err)
				}
			}
		} else {
			sm.signingInfo[evidence.ValidatorAddr] = &ValidatorSigningInfo{
				Address:            evidence.ValidatorAddr,
				JailedUntil:        jailUntil,
				PermanentlySlashed: permanent,
			}
			// R41-CS-001 FIX: Sync JailedUntil to ValidatorManager (else branch).
			if err := sm.validatorMgr.SetJailedUntil(sm.systemCaller, evidence.ValidatorAddr, jailUntil); err != nil {
				slashingLogger.Errorf("failed to set JailedUntil for validator %x in validatorMgr: %v", evidence.ValidatorAddr[:8], err)
			}
			// FIX: Also sync to ValidatorManager if newly created entry is permanently slashed
			if permanent {
				if err := sm.validatorMgr.MarkPermanentlySlashed(sm.systemCaller, evidence.ValidatorAddr); err != nil {
					slashingLogger.Errorf("failed to mark validator %x permanently slashed: %v", evidence.ValidatorAddr[:8], err)
				}
			}
		}
	}

	// SECURITY FIX: Slashing must be executed locally regardless of broadcaster availability.
	// Broadcast is async with retry, but local slashing record is mandatory.
	if err := sm.recordSlashing_locally(evidence, slashAmount, shouldJail, jailUntil, timestamp, offenseKey); err != nil {
		slashingLogger.Errorf("failed to record slashing locally: %v", err)
		return nil, err
	}

	// Create record for return value (local slashing was performed above)
	record := &SlashingRecord{
		ValidatorAddr: evidence.ValidatorAddr,
		Reason:        evidence.Reason,
		Height:        evidence.Height,
		SlashedAmount: slashAmount,
		Timestamp:     timestamp,
		Jailed:        shouldJail,
		JailUntil:     jailUntil,
	}

	// Broadcast evidence asynchronously with retry (best-effort)
	if broadcastAvailable {
		// Set timestamp on evidence if not set
		if evidence.Timestamp == 0 {
			evidence.Timestamp = timestamp
		}
		// audit-fix  capture broadcaster reference before goroutine to avoid
		// data race with SetBroadcaster after sm.mu is released.
		broadcaster := sm.broadcaster
		go sm.broadcastEvidenceWithRetryUsing(broadcaster, evidence)
	} else {
		slashingLogger.Warnf("broadcaster not configured, slashing evidence for %x not broadcast", evidence.ValidatorAddr[:8])
	}

	// SECURITY FIX (R2 P0-1): Sync slashed status to QPOS so it knows this validator
	// can no longer propose blocks or submit votes. R22-C1 removed QPOS.SlashValidator()
	// call to prevent double slashing, but that also removed the slashedValidators map
	// update. This call restores that sync without reducing stake again.
	//
	// Uses a goroutine to avoid lock ordering deadlock: slash() holds sm.mu, and
	// MarkValidatorSlashedByAddress acquires q.mu. The existing lock order is
	// q.mu → sm.mu (via checkDoubleVote → SubmitEvidence → slash), so acquiring
	// q.mu while holding sm.mu would reverse the order and deadlock.
	//
	// CON-003 FIX: Added pendingSlashedAddrs queue and SyncPendingSlashes method.
	// If the goroutine fails or the node crashes before it executes, the
	// pending slashes can be re-applied via SyncPendingSlashes, which is called
	// during block validation. This ensures slashed validators cannot continue
	// participating in consensus even if the async sync fails.
	if sm.qpos != nil {
		addr := evidence.ValidatorAddr
		// CONS- Capture permanent + jailUntil computed above so the
		// QPOS entry correctly distinguishes permanent bans from temporary
		// jails. Without this, Unjail() could clear the slashedValidators
		// entry for a permanent ban because the entry would be missing the
		// Permanent flag (defaulting to false).
		capturedPermanent := permanent
		capturedJailUntil := jailUntil
		// CON-003 FIX: Record pending slash for later synchronization
		sm.pendingSlashedMu.Lock()
		sm.pendingSlashedAddrs[addr] = true
		sm.pendingSlashedMu.Unlock()

		go func() {
			// R5-P3-3 FIX: Add recover to prevent panic from crashing the node.
			defer func() {
				if r := recover(); r != nil {
					slashingLogger.Errorf("panic in MarkValidatorSlashedByAddress goroutine for validator %x: %v", addr[:8], r)
				}
			}()
			if err := sm.qpos.MarkValidatorSlashedByAddress(addr, capturedPermanent, capturedJailUntil); err != nil {
				slashingLogger.Errorf("failed to sync slashed status to QPOS for validator %x: %v", addr[:8], err)
			} else {
				// CON-003 FIX: Remove from pending on success
				sm.pendingSlashedMu.Lock()
				delete(sm.pendingSlashedAddrs, addr)
				sm.pendingSlashedMu.Unlock()
			}
		}()
	}

	// P1-T3 (2026-07-14): Record the slashing in MinistryRevenue for governance
	// visibility. This is a best-effort recording — failures are logged but do
	// NOT block the slashing. RecordSlashingExecution only records (no side
	// effects), avoiding double-punishment.
	if sm.ministryRevenue != nil && sm.qpos != nil {
		vs := sm.qpos.GetValidatorSet()
		if vs != nil {
			validatorIndex := vs.GetValidatorIndex(evidence.ValidatorAddr)
			if validatorIndex >= 0 {
				epoch := uint64(0)
				if sm.qpos != nil {
					epoch = sm.qpos.GetCurrentEpoch()
				}
				if err := sm.ministryRevenue.RecordSlashingExecution(
					sm.systemCaller, validatorIndex, evidence.Reason,
					slashAmount, epoch, timestamp,
				); err != nil {
					slashingLogger.Warnf("failed to record slashing in MinistryRevenue for validator %x: %v",
						evidence.ValidatorAddr[:8], err)
				}
			}
		}
	}

	return record, nil
}

// RecordOffenseOnly records a slashing offense in SlashingManager's internal
// state WITHOUT reducing stake or deactivating the validator. This is called
// by QPOS.SlashValidator (via RecordOffenseInSlashingManager) after QPOS has
// already reduced the stake, to prevent double slashing when the same evidence
// is later submitted externally via SubmitEvidence.
//
// SECURITY FIX (R2 P0-1 reverse sync): Without this, QPOS-slashed validators
// could be slashed again when the same evidence is submitted via SubmitEvidence,
// because slashedOffenses map would not contain the offense key.
func (sm *SlashingManager) RecordOffenseOnly(addr types.Address, reason SlashingReason, height uint64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	offenseKey := fmt.Sprintf("%x:%d:%d", addr, reason, height)
	if sm.slashedOffenses[offenseKey] {
		return // Already recorded
	}
	sm.slashedOffenses[offenseKey] = true
	// FIX: Offense recorded; release the pending-evidence hold on the votes.
	sm.clearPendingEvidenceLocked(addr, height)

	// Prune if exceeding max size
	if len(sm.slashedOffenses) > MaxSlashedOffenses {
		count := 0
		for k := range sm.slashedOffenses {
			if count >= MaxSlashedOffenses/10 {
				break
			}
			delete(sm.slashedOffenses, k)
			count++
		}
	}

	slashingLogger.Infof("recorded QPOS slashing offense for validator %x (reason=%d, height=%d) — stake NOT reduced (already done by QPOS)",
		addr[:8], reason, height)
}

// SetRewardDistributor wires in the economics-side reward distributor
// used by R43-SLASH-WHISTLE-01 to pay whistleblower rewards. Should be
// called ONCE on node startup before SlashManager processes any
// evidence. Setting a nil distributor reverts to the LEGACY
// record-but-do-not-pay behavior (kept for unit tests).
func (sm *SlashingManager) SetRewardDistributor(rd RewardDistributor) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.rewardDistributor = rd
	if sm.whistleblowerRewardEpochAccumulator == nil {
		sm.whistleblowerRewardEpochAccumulator = big.NewInt(0)
	}
}

// SetEpoch advances the epoch counter used by R43-SLASH-WHISTLE-01 to
// bound cumulative whistleblower reward payouts. When epoch increments,
// the per-epoch reward accumulator RESETS to 0 (a fresh cap window
// opens). Idempotent for the same epoch value. Safe to call from any
// goroutine.
func (sm *SlashingManager) SetEpoch(epoch uint64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if epoch == sm.currentEpoch {
		return
	}
	sm.currentEpoch = epoch
	if sm.whistleblowerRewardEpochAccumulator == nil {
		sm.whistleblowerRewardEpochAccumulator = big.NewInt(0)
	} else {
		sm.whistleblowerRewardEpochAccumulator.SetUint64(0)
	}
}

// calculateWhistleblowerRewardLocked computes the whistleblower reward
// for this slashing event AND hikes the per-epoch cap accumulator. It
// is called from inside recordSlashing_locally which already holds
// sm.mu.Lock, hence the "Locked" suffix. Returns:
//   - nil reward + nil err when no whistleblower is attached (legacy)
//   - nil reward + nil err when rewardDistributor is nil (legacy path:
//     recorded in SlashingRecord but not paid out)
//   - the reward amount + nil err on success (after capping + accumulator
//     update)
//   - nil reward + err on arithmetic error (caller logs warning + proceeds)
//
// Reward formula: reward = slashAmount * whistleblowerRewardFractionNum /
// whistleblowerRewardFractionDen (= slashAmount * 10 / 100 = 10% of
// slash amount). If reward + sm.whistleblowerRewardEpochAccumulator >
// MaxWhistleblowerRewardPerEpoch in QAU units, reward is clamped to
// the residual (MaxWhistleblowerRewardPerEpoch - accumulator).
//
// UNIT ASSUMPTION: slashAmount is in QAU units (not wei); reward + cap
// are also in QAU units, consistent with how QPOS reports slash amount
// to recordSlashing_locally (see QPOS Slash path e.g.
// `slashAmount = params.DoubleSignPenalty * validator.Stake / 100`,
// where stake is unit-less-integer-equivalent-to-QAU). The cap
// threshold (MaxWhistleblowerRewardPerEpoch = 1000) is therefore 1000
// QAU per epoch — directly readable in code.
func (sm *SlashingManager) calculateWhistleblowerRewardLocked(evidence *SlashingEvidence, slashAmount *big.Int) (*big.Int, error) {
	// 1. No whistleblower attached — legacy backward-compat: no reward.
	if evidence == nil || evidence.Whistleblower == (types.Address{}) {
		return nil, nil
	}
	// 2. No timers no calc required if no slash (no amount to fraction).
	if slashAmount == nil || slashAmount.Sign() <= 0 {
		return nil, nil
	}
	// 3. Reward fraction (10% * slashAmount).
	scaled := new(big.Int).Mul(slashAmount, big.NewInt(whistleblowerRewardFractionNum))
	reward := new(big.Int).Div(scaled, big.NewInt(whistleblowerRewardFractionDen))
	if reward.Sign() <= 0 {
		// Slash amount is positive but < 10 (integer division rounds to
		// 0). Reward is effectively 0 — but we still record the
		// whistleblower address; the reward is nil (no payout).
		return nil, nil
	}
	// 4. Per-epoch cap. If we've already paid out the cap for the
	// current epoch, no further reward is owed (slash proceeds; the
	// audit cap is on the REWARD not the slash itself).
	if sm.whistleblowerRewardEpochAccumulator == nil {
		sm.whistleblowerRewardEpochAccumulator = big.NewInt(0)
	}
	cap := new(big.Int).SetUint64(MaxWhistleblowerRewardPerEpoch)
	residual := new(big.Int).Sub(cap, sm.whistleblowerRewardEpochAccumulator)
	if residual.Sign() <= 0 {
		// Cap already saturated this epoch.
		return nil, nil
	}
	if reward.Cmp(residual) > 0 {
		// Reward exceeds residual — clamp.
		reward.Set(residual)
	}
	// 5. Bump accumulator.
	sm.whistleblowerRewardEpochAccumulator.Add(sm.whistleblowerRewardEpochAccumulator, reward)
	return reward, nil
}

// pushBroadcastDeadLetterLocked is the package-internal helper used by
// broadcastEvidenceWithRetryUsing to append a dead-letter entry.
// Bounded by MaxDeadLetterEntries with FIFO eviction on overflow.
// P3-SL-02 (2026-08-03).
func (sm *SlashingManager) pushBroadcastDeadLetterLocked(dle *broadcastDeadLetter) {
	if sm == nil {
		return
	}
	sm.broadcastDeadLettersMu.Lock()
	defer sm.broadcastDeadLettersMu.Unlock()

	sm.broadcastDeadLetters = append(sm.broadcastDeadLetters, dle)
	atomic.AddUint64(&sm.broadcastDeadLettersCount, 1)

	// FIFO eviction: drop oldest entries beyond MaxDeadLetterEntries.
	if len(sm.broadcastDeadLetters) > MaxDeadLetterEntries {
		evictCount := len(sm.broadcastDeadLetters) - MaxDeadLetterEntries
		sm.broadcastDeadLetters = sm.broadcastDeadLetters[evictCount:]
	}
}

// BroadcastDeadLetterQueue returns a snapshot of the in-memory dead-letter
// queue (oldest-first). P3-SL-02 (2026-08-03). Read-only; callers MUST
// treat the returned slice as a snapshot (mutations do NOT affect the
// manager's internal state). For monitoring / RPC introspection.
func (sm *SlashingManager) BroadcastDeadLetterQueue() []*broadcastDeadLetter {
	sm.broadcastDeadLettersMu.Lock()
	defer sm.broadcastDeadLettersMu.Unlock()

	out := make([]*broadcastDeadLetter, len(sm.broadcastDeadLetters))
	copy(out, sm.broadcastDeadLetters)
	return out
}

// BroadcastDeadLetterCount returns the running count of dead-letter
// pushes since process start (monotonic counter, NOT the current queue
// length — the queue length can DROP via eviction). P3-SL-02 (2026-08-03).
func (sm *SlashingManager) BroadcastDeadLetterCount() uint64 {
	return atomic.LoadUint64(&sm.broadcastDeadLettersCount)
}

// RetryBroadcastsFromDeadLetter re-attempts broadcasting each entry in the
// dead-letter queue, blocking until all entries are scheduled. Entries
// whose retry succeeds are removed from the queue; entries whose retry
// fails IN THIS CALL are kept (with the new FinalErr) — the normal path
// for a still-broken p2p link. P3-SL-02 (2026-08-03). Caller MUST be the
// operator (RPC surface); not auto-called on a timer to avoid amplifying
// a still-broken link with retry storms.
func (sm *SlashingManager) RetryBroadcastsFromDeadLetter(broadcaster EvidenceBroadcaster) (retried, succeeded int, err error) {
	if broadcaster == nil {
		return 0, 0, errors.New("P3-SL-02: RetryBroadcastsFromDeadLetter called with nil broadcaster")
	}
	// Snapshot the queue under lock, then release the lock for the
	// actual broadcast (which could be slow / oversized).
	sm.broadcastDeadLettersMu.Lock()
	snap := make([]*broadcastDeadLetter, len(sm.broadcastDeadLetters))
	copy(snap, sm.broadcastDeadLetters)
	sm.broadcastDeadLettersMu.Unlock()

	// Re-acquire broadcaster reference (in case SetBroadcaster changed it
	// underneath us) for forensic consistency: retry with the broadcaster
	// the operator passes in.
	var retained []*broadcastDeadLetter
	for _, dle := range snap {
		if dle == nil || dle.Evidence == nil {
			continue
		}
		retried++
		// Per-call timeout (same shape as the original goroutine path).
		// Note: simpler than the original goroutine retry loop since this
		// is an explicit operator action — a single BroadcastEvidence call
		// per dead-letter entry.
		broadcastDone := make(chan error, 1)
		go func(ev *SlashingEvidence) {
			defer func() {
				if r := recover(); r != nil {
					broadcastDone <- fmt.Errorf("panic in retry BroadcastEvidence: %v", r)
				}
			}()
			broadcastDone <- broadcaster.BroadcastEvidence(ev)
		}(dle.Evidence)

		select {
		case callErr := <-broadcastDone:
			if callErr == nil {
				succeeded++
				// drop from retained queue
			} else {
				errStr := callErr.Error()
				if len(errStr) > 1024 {
					errStr = errStr[:1024] + "...(truncated)"
				}
				dle.FinalErr = errStr
				dle.FailedAt = time.Now().Unix()
				dle.AttemptCount++
				retained = append(retained, dle)
			}
		case <-time.After(30 * time.Second):
			// Treat timeout as failure; retain for next retry.
			dle.FinalErr = "retry broadcast timed out after 30s"
			dle.FailedAt = time.Now().Unix()
			dle.AttemptCount++
			retained = append(retained, dle)
		}
	}

	// Replace the queue contents with the retained entries. If everything
	// succeeded the queue is now empty.
	sm.broadcastDeadLettersMu.Lock()
	sm.broadcastDeadLetters = retained
	if len(sm.broadcastDeadLetters) > MaxDeadLetterEntries {
		sm.broadcastDeadLetters = sm.broadcastDeadLetters[len(sm.broadcastDeadLetters)-MaxDeadLetterEntries:]
	}
	sm.broadcastDeadLettersMu.Unlock()

	if retried > 0 && succeeded == 0 {
		err = fmt.Errorf("P3-SL-02: retried %d broadcasts, 0 succeeded (p2p may still be degraded)", retried)
	}
	return retried, succeeded, err
}

// recordSlashing_locally performs mandatory local slashing record operations.
// This function MUST succeed for slashing to be considered complete, regardless of
// broadcaster availability. Broadcasting is best-effort and async, but local state
// MUST always be updated.
// SECURITY FIX: Decouples mandatory local slashing from optional network broadcast.
// audit-remediation: reviewed 2026-09-11 — int arithmetic is bounded queue
// bookkeeping (len vs MaxSlashingRecords constants); amounts are big.Int.
func (sm *SlashingManager) recordSlashing_locally(evidence *SlashingEvidence, slashAmount *big.Int, shouldJail bool, jailUntil int64, timestamp int64, offenseKey string) error {
	// R43-SLASH-WHISTLE-01 (2026-08-03): compute the whistleblower reward
	// BEFORE constructing the record so the record carries a faithful
	// snapshot of the intended payout. reward may be nil (no
	// whistleblower, or distributor not wired, or cap reached) — the
	// record then has a zero WhistleblowerReward and legacy semantics
	// (slash amounts recorded but no reward payout).
	whistleblowerReward, wbErr := sm.calculateWhistleblowerRewardLocked(evidence, slashAmount)
	if wbErr != nil {
		// Non-fatal: log a warning and proceed without a reward. The
		// slash itself MUST still be recorded — we are in
		// recordSlashing_locally precisely because the slash is
		// committed; letting a reward-cap arithmetic error unwind the
		// slash would mean an attacker that finds a path to violate
		// reward arithmetic could escape accountability.
		slashingLogger.Warnf("R43-SLASH-WHISTLE-01: whistleblower reward calculation failed for validator %x: %v (slash proceeds without reward)",
			evidence.ValidatorAddr[:8], wbErr)
		whistleblowerReward = nil
	}

	record := &SlashingRecord{
		ValidatorAddr: evidence.ValidatorAddr,
		Reason:        evidence.Reason,
		Height:        evidence.Height,
		SlashedAmount: slashAmount,
		Timestamp:     timestamp,
		Jailed:        shouldJail,
		JailUntil:     jailUntil,

		// R43-SLASH-WHISTLE-01: snapshot the whistleblower + the reward
		// actually paid (or scheduled for payout if no distributor is
		// wired). When whistleblowerReward is nil, the record carries a
		// zero Whistleblower field (legacy) — NO actual reward was paid.
		Whistleblower:       evidence.Whistleblower,
		WhistleblowerReward: whistleblowerReward,
	}

	// audit-fix NEW-3: evict oldest records when at capacity
	// audit-remediation: reviewed 2026-09-11 — MaxSlashingRecords/10 is a
	// compile-time constant division (10_000/10); no dynamic economic value.
	if len(sm.records) >= MaxSlashingRecords {
		evictCount := MaxSlashingRecords / 10
		if evictCount < 1 {
			evictCount = 1
		}
		sm.records = sm.records[evictCount:]
	}

	sm.records = append(sm.records, record)
	sm.slashedOffenses[offenseKey] = true
	// FIX: The offense for this evidence has been recorded, so the associated
	// votes are no longer "pending" and may be pruned normally.
	sm.clearPendingEvidenceLocked(evidence.ValidatorAddr, evidence.Height)

	// audit-fix CRIT-PERSIST: Persist slashing record to DB
	if err := sm.SaveSlashingRecord(record); err != nil {
		slashingLogger.Errorf("CRITICAL: failed to persist slashing record for %x: %v", record.ValidatorAddr, err)
	}

	// R43-SLASH-WHISTLE-01 (2026-08-03): pay the whistleblower reward
	// through the wired RewardDistributor (if any). The reward amount
	// has already been capped against the per-epoch accumulator inside
	// calculateWhistleblowerRewardLocked above. We pay AFTER the record
	// is saved so that a record always exists for forensic follow-up
	// (even if the reward payout then fails); a payout failure does NOT
	// unwind the slash (record) — see RewardDistributor doc comment.
	if whistleblowerReward != nil && whistleblowerReward.Sign() > 0 && sm.rewardDistributor != nil {
		if err := sm.rewardDistributor.RewardWhistleblower(evidence.Whistleblower, whistleblowerReward); err != nil {
			// Payout failed. Log the failure but DO NOT undo the
			// record (slash itself remains committed; the offender is
			// still detained). Set record.WhistleblowerReward to nil
			// so future audits see the payout did NOT actually land.
			slashingLogger.Warnf("R43-SLASH-WHISTLE-01: whistleblower reward payout FAILED for whistleblower %x on slashing of %x: %v (slash record persists; reward not paid)",
				evidence.Whistleblower[:8], record.ValidatorAddr[:8], err)
			record.WhistleblowerReward = nil
		} else {
			slashingLogger.Infof("R43-SLASH-WHISTLE-01: paid whistleblower %x a reward of %s for slashing of %x (epoch=%d; epoch-accumulator now=%s / cap=%d)",
				evidence.Whistleblower[:8],
				whistleblowerReward.String(),
				record.ValidatorAddr[:8],
				sm.currentEpoch,
				sm.whistleblowerRewardEpochAccumulator.String(),
				MaxWhistleblowerRewardPerEpoch)
		}
	}

	// audit-fix NEW-6: prune slashedOffenses to prevent unbounded memory growth.
	// When the map exceeds MaxSlashedOffenses, rebuild with only recent entries.
	if len(sm.slashedOffenses) > MaxSlashedOffenses {
		// Keep only offense keys for records still in sm.records (already pruned).
		kept := make(map[string]bool, len(sm.records))
		for _, r := range sm.records {
			key := fmt.Sprintf("%x:%d:%d", r.ValidatorAddr, r.Reason, r.Height)
			kept[key] = true
		}
		sm.slashedOffenses = kept
	}

	return nil
}

// broadcastEvidenceWithRetryUsing broadcasts slashing evidence with exponential backoff retry
// using the provided broadcaster. The broadcaster is captured before goroutine launch to
// avoid a data race with SetBroadcaster (audit-fix ).
// SECURITY FIX: Added overall timeout to prevent indefinite blocking during network partitions.
// audit-fix Round3 M-1: Use stopCh to signal the inner goroutine to exit when the overall
// timeout expires. Previously, on timeout the outer goroutine returned but the inner goroutine
// kept running (blocked in broadcaster.BroadcastEvidence or sleeping between retries), causing
// a goroutine leak. Closing stopCh lets the inner goroutine exit at the next retry check or
// sleep interruption.
func (sm *SlashingManager) broadcastEvidenceWithRetryUsing(broadcaster EvidenceBroadcaster, ev *SlashingEvidence) {
	// R7-P3 FIX: recover prevents a panic in the broadcast retry logic from
	// crashing the node. This method runs as a goroutine
	// (go sm.broadcastEvidenceWithRetryUsing) from slash().
	defer func() {
		if r := recover(); r != nil {
			slashingLogger.Errorf("panic in broadcastEvidenceWithRetryUsing for validator %x: %v", ev.ValidatorAddr[:8], r)
		}
	}()

	const (
		initialBackoff = 100 * time.Millisecond
		maxBackoff     = 10 * time.Second
		backoffFactor  = 2
		// P3-SL-02 (2026-08-03): raised maxRetries 5 → 8 and
		// overallTimeout 30s → 60s. The previous bounds were tight
		// enough that a transient p2p blip (leader change, network
		// partition <30s) could silently lose evidence — the audit's
		// "permanent loss on network hiccup" concern. The new values
		// give roughly 8 attempts over ≤60s with exponential backoff
		// capped at 10s — same backoff curve as before, lower probability
		// of running out of retries before a transient p2p issue clears.
		// The added runtime (60s vs 30s) is bounded by stopCh so a node
		// shutdown / ledger roll-over won't be artificially delayed.
		maxRetries     = 8
		overallTimeout = 60 * time.Second // Maximum time to spend on broadcast attempts
	)

	// Create timeout channel
	done := make(chan struct{})
	// audit-fix Round3 M-1: stopCh is closed when the overall timeout expires,
	// signaling the inner goroutine to abandon further retry attempts.
	stopCh := make(chan struct{})

	// CON2-003 FIX: Track leaked inner goroutines so they can be waited on
	// (with a final timeout) after the outer retry loop exits. This prevents
	// goroutine leaks when BroadcastEvidence blocks permanently.
	var leakedWg sync.WaitGroup

	// Run broadcast attempts in goroutine
	go func() {
		defer func() {
			// R5-P3-3 FIX: Add recover to prevent panic from crashing the node.
			if r := recover(); r != nil {
				slashingLogger.Errorf("panic in broadcastEvidenceWithRetry goroutine: %v", r)
			}
			select {
			case done <- struct{}{}:
			default:
			}
		}()
		backoff := initialBackoff
		// P3-SL-02 (2026-08-03): keep track of the LAST broadcast error so
		// the dead-letter queue below can record it. The loop-local `err`
		// goes out of scope at each iteration; this outer var survives.
		var lastErr error
		for attempt := 0; attempt < maxRetries; attempt++ {
			// audit-fix Round3 M-1: check stop signal before each attempt
			select {
			case <-stopCh:
				return // Timeout reached
			default:
			}

			// CON-002 FIX: Wrap BroadcastEvidence with a per-call timeout to
			// prevent goroutine leak when the call blocks permanently (e.g.
			// network partition causing TCP hang). Previously, a blocking
			// BroadcastEvidence would never return, leaking the inner goroutine
			// even after stopCh was closed.
			broadcastDone := make(chan error, 1)
			// CON2-003 FIX: Track this goroutine so we can wait for it
			// (with final timeout) before returning from the outer function.
			leakedWg.Add(1)
			go func() {
				defer leakedWg.Done()
				defer func() {
					if r := recover(); r != nil {
						broadcastDone <- fmt.Errorf("panic in BroadcastEvidence: %v", r)
					}
				}()
				broadcastDone <- broadcaster.BroadcastEvidence(ev)
			}()

			var err error
			select {
			case <-stopCh:
				return // Timeout reached
			case err = <-broadcastDone:
				// Broadcast completed (success or failure)
			case <-time.After(10 * time.Second):
				// CON-002 FIX: Per-call timeout prevents indefinite blocking
				err = fmt.Errorf("BroadcastEvidence timed out after 10s")
			}

			if err == nil {
				slashingLogger.Infof("Successfully broadcast evidence for validator %x at height %d (attempt %d)",
					ev.ValidatorAddr[:8], ev.Height, attempt+1)
				return
			}

			slashingLogger.Warnf("Failed to broadcast evidence (attempt %d/%d): %v",
				attempt+1, maxRetries, err)
			// P3-SL-02 (2026-08-03): snapshot the loop-local err to outer
			// scope so the post-loop dead-letter push has the LAST failure
			// reason available.
			lastErr = err

			if attempt < maxRetries-1 {
				// Exponential backoff with jitter
				jitter := time.Duration(float64(backoff) * 0.1) // 10% jitter
				// audit-fix Round3 M-1: use select for sleep so we can exit on stop
				select {
				case <-stopCh:
					return
				case <-time.After(backoff + jitter):
				}

				// Increase backoff for next attempt
				backoff *= backoffFactor
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		}

		// Log final failure
		slashingLogger.Errorf("CRITICAL: Failed to broadcast evidence after %d attempts for validator %x at height %d, reason: %s",
			maxRetries, ev.ValidatorAddr[:8], ev.Height, ev.Reason.String())

		// P3-SL-02 (2026-08-03): push to the in-memory dead-letter queue
		// so an operator can inspect BroadcastDeadLetterQueue() and
		// RetryBroadcastsFromDeadLetter() to manually re-attempt once the
		// p2p issue clears. The local slashing record (already saved by
		// recordSlashing_locally) preserves the audit trail across node
		// restarts; this dead-letter queue is a live-debug aid for the
		// broadcast path (lost on process restart — by design, since a
		// restart e.g. due to operator attention will also re-broadcast
		// via the background async path).
		errStr := ""
		if lastErr != nil {
			errStr = lastErr.Error()
			if len(errStr) > 1024 {
				errStr = errStr[:1024] + "...(truncated)"
			}
		}
		sm.pushBroadcastDeadLetterLocked(&broadcastDeadLetter{
			Evidence:     ev,
			FinalErr:     errStr,
			FailedAt:     time.Now().Unix(),
			AttemptCount: maxRetries,
		})
	}()

	// Wait for completion or timeout
	// audit-fix HIGH-1: Use time.NewTimer instead of time.After to prevent memory leak
	// time.After creates a new timer every time, but time.NewTimer can be stopped
	timer := time.NewTimer(overallTimeout)
	defer timer.Stop()
	select {
	case <-done:
		// Normal completion
	case <-timer.C:
		// audit-fix Round3 M-1: close stopCh to signal the inner goroutine to stop
		// instead of abandoning it. This prevents goroutine leaks when
		// BroadcastEvidence is slow but not permanently blocked.
		close(stopCh)
		slashingLogger.Warnf("Evidence broadcast timed out after %v for validator %x at height %d",
			overallTimeout, ev.ValidatorAddr[:8], ev.Height)
	}

	// CON2-003 FIX: Wait for leaked inner goroutines with a final 5s grace
	// period. If BroadcastEvidence is still blocked after this, the goroutine
	// truly cannot be canceled (the interface doesn't support context), but
	// we've at least bounded the total number of outstanding goroutines and
	// given them a chance to complete. This is a best-effort mitigation.
	leakTimer := time.NewTimer(5 * time.Second)
	defer leakTimer.Stop()
	leakDone := make(chan struct{})
	go func() {
		leakedWg.Wait()
		close(leakDone)
	}()
	select {
	case <-leakDone:
		// All inner goroutines completed
	case <-leakTimer.C:
		// Some goroutines are still blocked — log and move on
		slashingLogger.Warnf("Evidence broadcast: some BroadcastEvidence goroutines remain blocked after grace period")
	}
}

// createOffenseKey creates a unique key for an offense.
// Uses structured fmt.Sprintf to avoid ambiguous raw byte concatenation.
func (sm *SlashingManager) createOffenseKey(evidence *SlashingEvidence) string {
	return fmt.Sprintf("%x:%d:%d", evidence.ValidatorAddr, evidence.Reason, evidence.Height)
}

// IsOffenseSlashed checks whether a specific (addr, reason, height) offense
// has already been slashed. Used by MinistryRevenue.ExecuteSlashing to prevent
// double punishment for the same offense via the second slashing path.
// AUDIT (2026) GOV B-1 FIX.
func (sm *SlashingManager) IsOffenseSlashed(addr types.Address, reason SlashingReason, height uint64) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	offenseKey := fmt.Sprintf("%x:%d:%d", addr, reason, height)
	return sm.slashedOffenses[offenseKey]
}

// copySlashingRecord returns a deep copy of a SlashingRecord.
// audit-fix R4-L1: prevents callers from mutating internal state (especially big.Int fields).
// audit-remediation: reviewed 2026-09-11 — read-only deep-copy helper; no stake mutation.
func copySlashingRecord(r *SlashingRecord) *SlashingRecord {
	cp := *r
	if r.SlashedAmount != nil {
		cp.SlashedAmount = new(big.Int).Set(r.SlashedAmount)
	}
	return &cp
}

// GetSlashingRecords returns all slashing records
// audit-fix R4-L1: returns deep copies to prevent external mutation of internal state.
func (sm *SlashingManager) GetSlashingRecords() []*SlashingRecord {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	records := make([]*SlashingRecord, len(sm.records))
	for i, r := range sm.records {
		records[i] = copySlashingRecord(r)
	}
	return records
}

// GetValidatorSlashingRecords returns slashing records for a specific validator
// audit-fix R4-L1: returns deep copies to prevent external mutation of internal state.
func (sm *SlashingManager) GetValidatorSlashingRecords(addr types.Address) []*SlashingRecord {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	records := make([]*SlashingRecord, 0)
	for _, r := range sm.records {
		if r.ValidatorAddr == addr {
			records = append(records, copySlashingRecord(r))
		}
	}
	return records
}

// IsDoubleSign checks if two votes constitute double signing
func IsDoubleSign(vote1, vote2 *Vote) bool {
	if vote1 == nil || vote2 == nil {
		return false
	}
	return vote1.ValidatorAddr == vote2.ValidatorAddr &&
		vote1.Height == vote2.Height &&
		vote1.BlockHash != vote2.BlockHash
}

// PruneVoteHistory removes vote history below the given height
func (sm *SlashingManager) PruneVoteHistory(keepAbove uint64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for addr, heights := range sm.voteHistory {
		for height := range heights {
			if height < keepAbove {
				// FIX: Preserve votes that are part of pending double-sign evidence.
				if sm.isPendingEvidenceLocked(addr, height) {
					continue
				}
				delete(heights, height)
			}
		}
		if len(heights) == 0 {
			delete(sm.voteHistory, addr)
		}
	}
}

// evictOldestVoteHistory removes the oldest vote entries across all validators
// when the global vote history limit is exceeded
func (sm *SlashingManager) evictOldestVoteHistory(toDelete int) {
	// Collect all votes with their timestamps (approximated by height)
	type voteEntry struct {
		addr   types.Address
		height uint64
	}
	var votes []voteEntry
	for addr, heights := range sm.voteHistory {
		for height := range heights {
			votes = append(votes, voteEntry{addr, height})
		}
	}
	// Sort by height (oldest first)
	sort.Slice(votes, func(i, j int) bool {
		return votes[i].height < votes[j].height
	})
	// Delete oldest entries
	deleted := 0
	for _, entry := range votes {
		if deleted >= toDelete {
			break
		}
		// FIX: Skip votes that are part of pending double-sign evidence.
		if sm.isPendingEvidenceLocked(entry.addr, entry.height) {
			continue
		}
		delete(sm.voteHistory[entry.addr], entry.height)
		if len(sm.voteHistory[entry.addr]) == 0 {
			delete(sm.voteHistory, entry.addr)
		}
		deleted++
	}
}

// evidenceVoteKey returns a stable key identifying a vote by validator address and
// height. Used by the pending-evidence tracking ().
func evidenceVoteKey(addr types.Address, height uint64) string {
	return fmt.Sprintf("%x:%d", addr, height)
}

// markPendingEvidenceLocked marks a vote (addr, height) as part of pending double-sign
// evidence so that vote history pruning preserves it until the offense is recorded.
// Caller must hold sm.mu.
func (sm *SlashingManager) markPendingEvidenceLocked(addr types.Address, height uint64) {
	if sm.pendingEvidenceVotes == nil {
		sm.pendingEvidenceVotes = make(map[string]time.Time)
	}
	// CON-005 FIX: Store the timestamp when the pending evidence was first observed.
	// This allows expired entries to be cleaned up via expirePendingEvidenceLocked.
	key := evidenceVoteKey(addr, height)
	if _, exists := sm.pendingEvidenceVotes[key]; !exists {
		sm.pendingEvidenceVotes[key] = time.Now() // NOT consensus-critical: local pending evidence tracking
	}
}

// clearPendingEvidenceLocked releases the pending-evidence hold on a vote once the
// associated offense has been recorded. No-op if the vote was not marked pending.
// Caller must hold sm.mu.
func (sm *SlashingManager) clearPendingEvidenceLocked(addr types.Address, height uint64) {
	if sm.pendingEvidenceVotes != nil {
		delete(sm.pendingEvidenceVotes, evidenceVoteKey(addr, height))
	}
}

// pendingEvidenceTTL bounds how long a detected-but-not-yet-slashed vote is
// protected from pruning. CON-005 FIX (deep-audit 2026-07-03): this must match
// the evidence validity window (maxEvidenceAgeSeconds = 1 week, see
// VerifyEvidence) — a shorter TTL (previously 1 hour) allowed double-sign
// evidence to be pruned while it was still valid and submittable, letting an
// equivocating validator escape slashing. Memory growth stays bounded because
// entries are small (key + timestamp) and still expire after the window.
const pendingEvidenceTTL = 7 * 24 * time.Hour

// isPendingEvidenceLocked reports whether a vote is part of pending slashing evidence
// and must be preserved during pruning ().
// Caller must hold sm.mu (or RLock).
func (sm *SlashingManager) isPendingEvidenceLocked(addr types.Address, height uint64) bool {
	if sm.pendingEvidenceVotes == nil {
		return false
	}
	ts, exists := sm.pendingEvidenceVotes[evidenceVoteKey(addr, height)]
	if !exists {
		return false
	}
	// CON-005 FIX: Expire pending evidence after the evidence validity window.
	// If slashing was detected but never completed within this window, the
	// pending entry is stale (the evidence can no longer be submitted) and
	// the vote can be pruned normally.
	if time.Since(ts) > pendingEvidenceTTL {
		delete(sm.pendingEvidenceVotes, evidenceVoteKey(addr, height))
		return false
	}
	return true
}

// expirePendingEvidenceLocked removes all pending evidence entries that have
// exceeded their TTL. CON-005 FIX: Called during vote history pruning to
// prevent stale entries from accumulating.
// Caller must hold sm.mu.
func (sm *SlashingManager) expirePendingEvidenceLocked() {
	if sm.pendingEvidenceVotes == nil {
		return
	}
	now := time.Now() // NOT consensus-critical: local pending evidence TTL cleanup
	for key, ts := range sm.pendingEvidenceVotes {
		if now.Sub(ts) > pendingEvidenceTTL {
			delete(sm.pendingEvidenceVotes, key)
		}
	}
}

// ============================================================================
// Downtime Detection (Requirement 6.2)
// ============================================================================

// RecordBlockSigned records that a validator signed a block at the given height
// RecordBlockSigned records that a validator signed a block at the given height
func (sm *SlashingManager) RecordBlockSigned(addr types.Address, height uint64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.recordBlockSignedLocked(addr, height)
}

func (sm *SlashingManager) recordBlockSignedLocked(addr types.Address, height uint64) {
	// Initialize signed blocks map for this validator if needed
	if sm.signedBlocks[addr] == nil {
		sm.signedBlocks[addr] = make(map[uint64]bool)
	}
	sm.signedBlocks[addr][height] = true

	// Initialize signing info if needed
	if sm.signingInfo[addr] == nil {
		sm.signingInfo[addr] = &ValidatorSigningInfo{
			Address:     addr,
			StartHeight: height,
		}
	}
}

// CheckDowntime checks if a validator has exceeded the downtime threshold
// Returns SlashingEvidence if downtime is detected, nil otherwise
// Implements Requirement 6.2
// CheckDowntime checks if a validator has exceeded the downtime threshold
func (sm *SlashingManager) CheckDowntime(addr types.Address, currentHeight uint64, blockTime uint64) *SlashingEvidence {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.checkDowntimeLocked(addr, currentHeight, blockTime)
}

func (sm *SlashingManager) checkDowntimeLocked(addr types.Address, currentHeight uint64, blockTime uint64) *SlashingEvidence {
	// Get signing info
	info := sm.signingInfo[addr]
	if info == nil {
		// No signing info, initialize it
		sm.signingInfo[addr] = &ValidatorSigningInfo{
			Address:     addr,
			StartHeight: currentHeight,
		}
		return nil
	}

	// If validator is already jailed, don't check downtime
	if info.JailedUntil > 0 && int64(blockTime) < info.JailedUntil {
		return nil
	}

	// C21-007 FIX: Skip downtime check for permanently slashed validators.
	// They are already banneded; generating downtime evidence is redundant
	// and wastes resources.
	if info.PermanentlySlashed {
		return nil
	}

	// Calculate the window start
	windowStart := uint64(0)
	if currentHeight > sm.params.SignedBlocksWindow {
		windowStart = currentHeight - sm.params.SignedBlocksWindow
	}

	// Count missed blocks in the window
	signedInWindow := sm.signedBlocks[addr]
	missedBlocks := uint64(0)

	// audit-fix  only count blocks since the validator started signing.
	// Without this, new validators are charged for blocks they had no
	// responsibility to sign, leading to false-positive downtime slashing.
	effectiveStart := windowStart
	if info.StartHeight > effectiveStart {
		effectiveStart = info.StartHeight
	}

	for h := effectiveStart; h < currentHeight; h++ {
		if signedInWindow == nil || !signedInWindow[h] {
			missedBlocks++
		}
	}

	// Update missed blocks counter
	info.MissedBlocksCounter = missedBlocks

	// Check if threshold exceeded
	if missedBlocks >= sm.params.DowntimeThreshold {
		return &SlashingEvidence{
			Reason:        SlashingReasonDowntime,
			ValidatorAddr: addr,
			Height:        currentHeight,
			MissedBlocks:  missedBlocks,
			Timestamp:     int64(blockTime),
		}
	}

	return nil
}

// HandleBlockFinalized should be called when a block is finalized
// It checks all active validators for downtime
// Returns a slice of SlashingEvidence for validators that exceeded downtime threshold
func (sm *SlashingManager) HandleBlockFinalized(height uint64, signers []types.Address, blockTime uint64) []*SlashingEvidence {
	// audit-fix MED-2: Acquire lock once for entire batch operation to reduce
	// lock contention from O(n) lock/unlock cycles to O(1) for large validator sets.
	sm.mu.Lock()

	// Record all signers (lock-free internal version)
	signerSet := make(map[types.Address]bool, len(signers))
	for _, signer := range signers {
		signerSet[signer] = true
		sm.recordBlockSignedLocked(signer, height)
	}

	// Get all active validators
	activeValidators := sm.validatorMgr.GetActiveValidators()

	// Check each validator for downtime (lock-free internal version)
	var evidences []*SlashingEvidence
	for _, v := range activeValidators {
		evidence := sm.checkDowntimeLocked(v.Address, height, blockTime)
		if evidence != nil {
			evidences = append(evidences, evidence)
		}
	}

	sm.mu.Unlock()

	// Prune old signed blocks data
	sm.pruneSignedBlocks(height)

	// audit-fix L-3: prune old vote history to prevent unbounded memory growth.
	// Keep votes within the signed blocks window.
	pruneAbove := uint64(0)
	if height > sm.params.SignedBlocksWindow {
		pruneAbove = height - sm.params.SignedBlocksWindow
	}
	sm.PruneVoteHistory(pruneAbove)

	return evidences
}

// pruneSignedBlocks removes signed blocks data older than the window
// MEDIUM FIX: Use dynamic window calculation based on both height and size
func (sm *SlashingManager) pruneSignedBlocks(currentHeight uint64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Dynamic window: use configured window or minimum of 100 blocks
	windowSize := sm.params.SignedBlocksWindow
	if windowSize < 100 {
		windowSize = 100
	}

	windowStart := uint64(0)
	if currentHeight > windowSize {
		windowStart = currentHeight - windowSize
	}

	// Also enforce maximum entries per validator to prevent memory growth
	const maxEntriesPerValidator = 1000

	for addr, blocks := range sm.signedBlocks {
		// Height-based pruning
		for height := range blocks {
			if height < windowStart {
				delete(blocks, height)
			}
		}

		// Size-based pruning: if still too many entries, remove oldest
		if len(blocks) > maxEntriesPerValidator {
			toRemove := len(blocks) - maxEntriesPerValidator
			removed := 0
			for height := range blocks {
				if removed >= toRemove {
					break
				}
				delete(blocks, height)
				removed++
			}
		}

		if len(blocks) == 0 {
			delete(sm.signedBlocks, addr)
		}
	}
}

// VerifyDowntimeEvidence verifies that downtime evidence is valid
func (sm *SlashingManager) VerifyDowntimeEvidence(evidence *SlashingEvidence) error {
	if evidence == nil || evidence.Reason != SlashingReasonDowntime {
		return ErrSlashingEvidenceInvalid
	}

	// Verify the validator exists
	_, err := sm.validatorMgr.GetValidator(evidence.ValidatorAddr)
	if err != nil {
		return err
	}

	// Verify missed blocks exceeds threshold
	if evidence.MissedBlocks < sm.params.DowntimeThreshold {
		return ErrSlashingEvidenceInvalid
	}

	return nil
}

// ============================================================================
// Jail Management
// ============================================================================

// IsJailed returns true if the validator is currently jailed.
//
// CON-006 FIX: This convenience wrapper uses the node's wall-clock time
// (time.Now().Unix()) and is intended only for ad-hoc status queries where
// block time is unavailable. Consensus-critical code paths MUST use
// IsJailedAt(blockTime) instead, so that jail-status checks are consistent
// with Unjail() (which uses deterministic block time) and are not affected by
// node clock skew — the original inconsistency flagged in CON-006.
func (sm *SlashingManager) IsJailed(addr types.Address) bool {
	return sm.IsJailedAt(addr, time.Now().Unix())
}

// IsJailedAt returns true if the validator is jailed as of the given block
// time. Use this in consensus paths instead of IsJailed so that jail-status
// checks are deterministic and consistent with Unjail(blockTime).
func (sm *SlashingManager) IsJailedAt(addr types.Address, blockTime int64) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	info := sm.signingInfo[addr]
	if info == nil {
		return false
	}

	return info.JailedUntil > 0 && blockTime < info.JailedUntil
}

// GetJailExpiry returns the jail expiry timestamp for a validator
// Returns 0 if the validator is not jailed
func (sm *SlashingManager) GetJailExpiry(addr types.Address) int64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	info := sm.signingInfo[addr]
	if info == nil {
		return 0
	}

	return info.JailedUntil
}

// Unjail attempts to unjail a validator
// Returns error if validator is not jailed or jail period has not expired
// FIX: Updated authorization check for consistency with R24-H2
// Only the validator themselves or registered system caller can unjail
// MEDIUM FIX: Enhanced caller validation to prevent authorization bypass
func (sm *SlashingManager) Unjail(caller, addr types.Address, blockTime uint64) error {
	// MEDIUM FIX: Validate addresses are not zero
	if caller == (types.Address{}) {
		return fmt.Errorf("%w: caller address cannot be zero", ErrUnauthorizedValidatorOperation)
	}
	if addr == (types.Address{}) {
		return fmt.Errorf("%w: validator address cannot be zero", ErrUnauthorizedValidatorOperation)
	}

	// Authorization check: only the validator themselves (caller == addr) or
	// registered system caller can unjail
	// Note: R24-H2 explicitly rejected zero address as system caller,
	// so governance must be explicitly registered via RegisterSystemCaller
	isSelfUnjail := caller == addr
	isSystemCaller := sm.validatorMgr.IsSystemCaller(caller)

	// MEDIUM FIX: Explicit authorization logic with audit logging
	if !isSelfUnjail && !isSystemCaller {
		return fmt.Errorf("%w: caller %x is not authorized to unjail validator %x (not self, not system caller)",
			ErrUnauthorizedValidatorOperation, caller, addr)
	}

	// MEDIUM FIX: Additional validation for self-unjail
	// Ensure the validator exists and is actually jailed before proceeding
	if isSelfUnjail {
		sm.mu.RLock()
		info := sm.signingInfo[addr]
		sm.mu.RUnlock()
		if info == nil {
			return fmt.Errorf("%w: no signing info found for validator %x", ErrValidatorNotFound, addr)
		}
		if info.JailedUntil == 0 {
			return ErrValidatorNotJailed
		}
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	info := sm.signingInfo[addr]
	if info == nil || info.JailedUntil == 0 {
		return ErrValidatorNotJailed
	}

	if info.PermanentlySlashed {
		return fmt.Errorf("validator %x is permanently slashed and cannot be unjailed", addr)
	}

	// Check if jail period has expired
	// L12-015 FIX: use deterministic blockTime instead of time.Now() to
	// avoid non-deterministic unjailing caused by node clock skew.
	if int64(blockTime) < info.JailedUntil {
		return ErrJailPeriodNotExpired
	}

	// Clear jail status
	info.JailedUntil = 0
	info.MissedBlocksCounter = 0

	// Reactivate validator if stake is sufficient
	validator, err := sm.validatorMgr.GetValidator(addr)
	if err != nil {
		return err
	}

	if validator.Stake.Cmp(MinStakeAmount) >= 0 {
		if err := sm.validatorMgr.SetActive(caller, addr, true); err != nil {
			return err
		}
		// CONS- (2026-07-20): Clear the QPOS slashedValidators entry
		// now that the validator has served its jail time and been reactivated.
		// Without this, a temporary slash became a permanent ban because the
		// QPOS.slashedValidators map was never cleaned — the validator would
		// remain in CanPropose/CanAttest's reject list forever even after
		// Unjail succeeded.
		//
		// Use a goroutine to avoid lock ordering deadlock: Unjail holds sm.mu,
		// and UnmarkValidatorSlashed acquires q.mu. The normal lock order is
		// q.mu → sm.mu (via checkDoubleVote → SubmitEvidence → slash → Unjail
		// path); acquiring q.mu while holding sm.mu reverses the order.
		//
		// CONS- (2026-07-21) FIX: previously this goroutine only logged
		// failures — a transient error or sm.qpos being nil at this moment
		// left the validator permanently banned in QPOS.slashedValidators
		// despite having served the jail sentence. Now we register the address
		// in pendingUnjailAddrs BEFORE spawning the goroutine, and the
		// background SyncPendingSlashes loop re-attempts the unmark every 10s
		// until it succeeds. This mirrors the slash path's pendingSlashedAddrs
		// retry mechanism for symmetric reliability.
		sm.pendingSlashedMu.Lock()
		sm.pendingUnjailAddrs[addr] = true
		sm.pendingSlashedMu.Unlock()

		if sm.qpos != nil {
			go func() {
				defer func() {
					if r := recover(); r != nil {
						slashingLogger.Errorf("panic in UnmarkValidatorSlashed goroutine for validator %x: %v", addr[:8], r)
					}
				}()
				if err := sm.qpos.UnmarkValidatorSlashed(addr); err != nil {
					slashingLogger.Errorf("failed to unmark validator %x from QPOS slashedValidators: %v (will retry via SyncPendingSlashes)", addr[:8], err)
					// Leave the entry in pendingUnjailAddrs for retry.
					return
				}
				// Success: remove from pending queue.
				sm.pendingSlashedMu.Lock()
				delete(sm.pendingUnjailAddrs, addr)
				sm.pendingSlashedMu.Unlock()
			}()
		}
		// If sm.qpos == nil here, the address stays in pendingUnjailAddrs.
		// Once SetQPOS is called and the sync loop ticks, it will be retried.
		return nil
	}

	// R36-H3 FIX: Return explicit error when stake is insufficient
	// Previously returned nil (success) but validator was not actually activated
	return fmt.Errorf("cannot unjail validator %x: stake %s is below minimum required %s",
		addr, validator.Stake.String(), MinStakeAmount.String())
}

// ============================================================================
// Evidence Verification
// ============================================================================

// VerifySurroundVoteEvidence verifies that surround vote evidence is valid
// CRITICAL FIX R13-C1: Now properly verifies the surround vote relationship
// between Vote1 and Vote2. A surround vote occurs when:
// - Vote1.source < Vote2.source < Vote2.target < Vote1.target (Vote1 surrounds Vote2)
// OR
// - Vote2.source < Vote1.source < Vote1.target < Vote2.target (Vote2 surrounds Vote1)
func (sm *SlashingManager) VerifySurroundVoteEvidence(evidence *SlashingEvidence) error {
	if evidence == nil || evidence.Reason != SlashingReasonSurroundVote {
		return ErrSlashingEvidenceInvalid
	}

	_, err := sm.validatorMgr.GetValidator(evidence.ValidatorAddr)
	if err != nil {
		return err
	}

	if evidence.Height == 0 {
		return ErrSlashingEvidenceInvalid
	}

	// CRITICAL FIX: Verify Vote1 and Vote2 are provided
	vote1 := evidence.Vote1
	vote2 := evidence.Vote2
	if vote1 == nil || vote2 == nil {
		return ErrSlashingEvidenceInvalid
	}

	// Verify both votes are from the same validator
	if vote1.ValidatorAddr != vote2.ValidatorAddr {
		return ErrSlashingEvidenceInvalid
	}

	// CONS- (2026-07-20) FIX: Bind evidence address to vote address.
	// See VerifyDoubleSigningEvidence for full rationale — without this an
	// attacker can sign votes with their own key and slash an arbitrary victim.
	if vote1.ValidatorAddr != evidence.ValidatorAddr {
		return ErrSlashingEvidenceInvalid
	}

	// Get validator's public key and verify signatures
	pubKey, err := sm.validatorMgr.GetPublicKey(vote1.ValidatorAddr)
	if err != nil {
		return err
	}

	if !vote1.Verify(pubKey) {
		return ErrInvalidVoteSignature
	}
	if !vote2.Verify(pubKey) {
		return ErrInvalidVoteSignature
	}

	// R41-H1 FIX: Verify the actual Casper FFG surround vote relationship using epoch fields.
	// A surround vote occurs when one attestation's source is before another's source,
	// but its target is after the other's target.
	// Casper FFG surround condition:
	//   Vote1 surrounds Vote2 if: source1 < source2 AND target2 < target1
	//   Vote2 surrounds Vote1 if: source2 < source1 AND target1 < target2
	//
	// HIGH FIX: Verify both votes are attestation votes (not prevote/precommit)
	// Surround vote detection is only valid for attestation votes with epoch data
	if vote1.Type != VoteTypeAttestation || vote2.Type != VoteTypeAttestation {
		return ErrSlashingEvidenceInvalid
	}
	// Basic sanity: both votes must be attestation votes and have different epochs
	if vote1.SourceEpoch == 0 || vote2.SourceEpoch == 0 {
		// Votes with SourceEpoch=0 are precommit votes — not valid for surround detection
		return ErrSlashingEvidenceInvalid
	}
	// Source must be strictly less than target for each attestation vote
	if vote1.SourceEpoch >= vote1.TargetEpoch {
		return ErrSlashingEvidenceInvalid
	}
	if vote2.SourceEpoch >= vote2.TargetEpoch {
		return ErrSlashingEvidenceInvalid
	}

	// CONS- (2026-07-19) FIX: Reject evidence whose SourceRoot/TargetRoot
	// are zero. Before this fix an attacker could fabricate Vote1/Vote2 with
	// attacker-chosen (and unbound) Roots that do not correspond to any real
	// chain history. Because the old VoteMessage() layout did not include Root,
	// the signature would still verify — letting an attacker slash an honest
	// validator by submitting votes that the validator never actually cast.
	//
	// Now that SignedMessage() (for attestation votes) rebuilds the canonical
	// attestation payload containing the Roots, the signature itself binds the
	// validator to the Roots. The non-zero check below is a defensive layer
	// that catches the degenerate case where a vote was constructed without
	// populating Root at all (e.g. via a buggy producer), preventing such a
	// vote from being used as slashing evidence.
	if vote1.SourceRoot == (types.Hash{}) || vote1.TargetRoot == (types.Hash{}) {
		return ErrSlashingEvidenceInvalid
	}
	if vote2.SourceRoot == (types.Hash{}) || vote2.TargetRoot == (types.Hash{}) {
		return ErrSlashingEvidenceInvalid
	}

	// Check for actual surround relationship
	vote1SurroundsVote2 := vote1.SourceEpoch < vote2.SourceEpoch && vote2.TargetEpoch < vote1.TargetEpoch
	vote2SurroundsVote1 := vote2.SourceEpoch < vote1.SourceEpoch && vote1.TargetEpoch < vote2.TargetEpoch
	if !vote1SurroundsVote2 && !vote2SurroundsVote1 {
		return ErrSlashingEvidenceInvalid
	}

	// Additional check: ensure the evidence height is consistent with one of the votes
	// (evidence can be filed at either vote's slot)
	if evidence.Height != vote1.Height && evidence.Height != vote2.Height {
		return ErrSlashingEvidenceInvalid
	}

	return nil
}

func (sm *SlashingManager) VerifyDoubleVoteEvidence(evidence *SlashingEvidence) error {
	if evidence == nil || evidence.Reason != SlashingReasonDoubleVote {
		return ErrSlashingEvidenceInvalid
	}

	vote1 := evidence.Vote1
	vote2 := evidence.Vote2
	if vote1 == nil || vote2 == nil {
		return ErrSlashingEvidenceInvalid
	}

	if vote1.ValidatorAddr != vote2.ValidatorAddr {
		return ErrSlashingEvidenceInvalid
	}

	// CONS- (2026-07-20) FIX: Bind evidence address to vote address.
	// See VerifyDoubleSigningEvidence for full rationale.
	if vote1.ValidatorAddr != evidence.ValidatorAddr {
		return ErrSlashingEvidenceInvalid
	}

	if vote1.Height != vote2.Height {
		return ErrSlashingEvidenceInvalid
	}

	// R41-L5SLASH-04 (2026-08-03) FIX: Verify both votes are at the same
	// round and of the same Type. These two checks already exist in
	// `VerifyDoubleSigningEvidence` (lines ~763, ~777, added by R35-P0-05
	// and R35-P2-CONS-02). Without them:
	//
	//   - Missing `Round` check: in BFT round-based consensus, a validator
	//     legitimately votes for DIFFERENT blocks in round 0 vs round 1
	//     (when round 0 times out). An attacker collecting the honest
	//     validator's round-0 vote for block A and round-1 vote for block B
	//     could submit them as "double-vote evidence". Both signatures verify
	//     (they sign different messages), `Height` matches, `BlockHash`
	//     differs — the validator gets 100% slashed + permanently banned,
	//     and the chain cannot recover from any timeout because every
	//     timeout produces a new slashing victim.
	//   - Missing `Type` check: PREPARE / COMMIT / PRECOMMIT are different
	//     signed messages at the same (height, round) and a validator
	//     legitimately signs all three as the protocol progresses. They are
	//     NOT double voting. The `Type` field also acts as a domain
	//     separator in the signed message — different types produce
	//     different signed digests even for the same block hash, so a
	//     cross-type pair never represents double voting.
	//
	// Both `SlashingReasonDoubleVote` and `SlashingReasonDoubleSigning` map
	// to the same penalty (100% slash + permanent ban, see ProcessSlashing
	// switch), so the inconsistency with `VerifyDoubleSigningEvidence` is
	// not just stylistic — it allows the most severe penalty to be
	// triggered by legitimate protocol behavior.
	if vote1.Round != vote2.Round {
		return ErrSlashingEvidenceInvalid
	}
	if vote1.Type != vote2.Type {
		return ErrSlashingEvidenceInvalid
	}

	if vote1.BlockHash == vote2.BlockHash {
		return ErrSlashingEvidenceInvalid
	}

	pubKey, err := sm.validatorMgr.GetPublicKey(vote1.ValidatorAddr)
	if err != nil {
		return ErrSlashingEvidenceInvalid
	}

	if !vote1.Verify(pubKey) || !vote2.Verify(pubKey) {
		return ErrSlashingEvidenceInvalid
	}

	return nil
}

func (sm *SlashingManager) VerifyInvalidVRFEvidence(evidence *SlashingEvidence) error {
	if evidence == nil || evidence.Reason != SlashingReasonInvalidVRF {
		return ErrSlashingEvidenceInvalid
	}

	if evidence.ValidatorAddr == (types.Address{}) {
		return ErrSlashingEvidenceInvalid
	}

	if evidence.Height == 0 {
		return ErrSlashingEvidenceInvalid
	}

	if evidence.Vote1 == nil {
		return ErrSlashingEvidenceInvalid
	}

	vote := evidence.Vote1
	if vote.ValidatorAddr != evidence.ValidatorAddr {
		return ErrSlashingEvidenceInvalid
	}

	if vote.Height != evidence.Height {
		return ErrSlashingEvidenceInvalid
	}

	// CON4-002 FIX: Verify the vote signature, consistent with all other
	// Verify*Evidence functions. Without this, an attacker can forge
	// SlashingReasonInvalidVRF evidence with a fabricated Vote1 signature
	// to slash an innocent validator.
	pubKey, err := sm.validatorMgr.GetPublicKey(vote.ValidatorAddr)
	if err != nil {
		return ErrSlashingEvidenceInvalid
	}
	if !vote.Verify(pubKey) {
		return ErrSlashingEvidenceInvalid
	}

	return nil
}

// VerifyEvidence verifies any type of slashing evidence
// audit-remediation: slashing bypass protection - comprehensive evidence verification
// - Validates evidence timestamp (max 1 week old)
// - Verifies evidence type and content
// R33 P2-18 FIX (2026-07-28): Added blockTime parameter for deterministic
// freshness validation. Previously used time.Now().Unix() which is
// consensus-nondeterministic — two validators with different wall clocks
// could disagree on evidence validity, causing slashing divergence.
// When blockTime is provided (consensus path), it is used instead of
// time.Now(). When not provided (e.g., tests, status queries), falls back
// to time.Now() for backward compatibility.
func (sm *SlashingManager) VerifyEvidence(evidence *SlashingEvidence, blockTime ...int64) error {
	if evidence == nil {
		return ErrSlashingEvidenceInvalid
	}

	// slashing bypass protection: verify evidence is not too old
	// SECURITY (audit 2026-06-14, H5): single source of truth for the evidence
	// freshness window, shared with SubmitEvidence. 1 week is the Casper standard.
	//  (P3): Evidence TTL = maxEvidenceAgeSeconds (1 week). Evidence older
	// than this is rejected to bound storage/replay risk; cryptographic validity
	// of double-sign proofs is independent of age, so the TTL only guards freshness.
	const maxEvidenceAgeSeconds = int64(7 * 24 * 60 * 60) // 1 week in seconds
	if evidence.Timestamp > 0 {
		// R33 P2-18 FIX: Use deterministic blockTime when available.
		// The consensus layer always passes blockTime; the fallback to
		// time.Now() is only for non-consensus callers (tests, queries).
		var now int64
		if len(blockTime) > 0 && blockTime[0] > 0 {
			now = blockTime[0]
		} else {
			now = time.Now().Unix() // fallback for non-consensus callers
		}
		age := now - evidence.Timestamp
		if age > maxEvidenceAgeSeconds {
			return ErrSlashingEvidenceInvalid
		}
		// audit-fix  reject future timestamps to prevent attackers from
		// extending jail duration by submitting evidence with far-future times.
		// Allow 10 seconds of clock skew tolerance (reduced from 60 seconds).
		if evidence.Timestamp > now+10 {
			return ErrSlashingEvidenceInvalid
		}
	}

	switch evidence.Reason {
	case SlashingReasonDoubleSigning:
		return sm.VerifyDoubleSigningEvidence(evidence)
	case SlashingReasonDowntime:
		return sm.VerifyDowntimeEvidence(evidence)
	case SlashingReasonSurroundVote:
		return sm.VerifySurroundVoteEvidence(evidence)
	case SlashingReasonInvalidVRF:
		return sm.VerifyInvalidVRFEvidence(evidence)
	case SlashingReasonDoubleVote:
		return sm.VerifyDoubleVoteEvidence(evidence)
	default:
		return ErrSlashingEvidenceInvalid
	}
}

// SubmitEvidence submits slashing evidence for processing
// CR40-C1 FIX: Added caller parameter and authorization check to prevent unauthorized slashing
// audit-remediation: slashing bypass protection - ensures slashing is executed atomically
// - Verifies evidence before processing
// - Checks validator has stake to slash
// - Executes slashing atomically
// CR40-C7 FIX: Removed ZeroAddress exception - all callers must be authorized system callers
// CR40-C8 FIX: Added additional security validation layer
// R4-C1 FIX (2026-07-06): Added variadic blockTime parameter for deterministic
// slashing timestamp. When provided, the slashing record timestamp uses blockTime
// instead of time.Now(), ensuring consensus determinism.
func (sm *SlashingManager) SubmitEvidence(evidence *SlashingEvidence, caller types.Address, blockTime ...int64) (*SlashingRecord, error) {
	// CR40-C7 FIX: Strict authorization - ZeroAddress is no longer allowed
	// All callers must be registered system callers, no exceptions
	// This prevents bypass of authorization through empty caller address
	if caller == (types.Address{}) {
		return nil, fmt.Errorf("%w: zero address is not authorized to submit evidence", ErrUnauthorizedOperation)
	}

	// CR40-C8 FIX: Additional security validation - check for nil evidence
	if evidence == nil {
		return nil, fmt.Errorf("%w: evidence cannot be nil", ErrSlashingEvidenceInvalid)
	}

	// CR40-C8 FIX: Additional security validation - check evidence validity
	// R33 CONS-03 FIX (2026-07-28): Previously, when evidence.Timestamp==0,
	// this code fell back to time.Now().Unix(). This is consensus-nondeterministic:
	// different validator nodes have different local clocks, so the same evidence
	// submitted on different nodes would get different timestamps, causing the
	// freshness check below to pass on some nodes and fail on others — leading
	// to inconsistent slashing decisions and potential consensus forks.
	//
	// Fix: When the submitter did not set a timestamp, use the deterministic
	// blockTime (passed by the consensus layer) if available. If blockTime is
	// not available (e.g., called from a non-consensus context), fail-closed
	// by rejecting the evidence. This ensures all nodes derive the same
	// timestamp for the same evidence.
	if evidence.Timestamp == 0 {
		if len(blockTime) > 0 && blockTime[0] > 0 {
			evidence.Timestamp = blockTime[0]
		} else {
			// R33 CONS-03: Fail-closed — reject evidence without a timestamp
			// rather than using non-deterministic wall-clock time. The
			// consensus layer always passes blockTime; reaching this branch
			// means the caller is not consensus-aligned (e.g., a test or a
			// legacy code path), and we prefer safety over convenience.
			return nil, fmt.Errorf("%w: evidence timestamp is zero and no blockTime provided (consensus determinism required)",
				ErrSlashingEvidenceInvalid)
		}
	}
	// SECURITY (audit 2026-06-14, H5): Unify the evidence-freshness window with
	// VerifyEvidence (both now use 1 week). The previous code rejected evidence
	// older than 1 hour here while VerifyEvidence accepted up to 1 week, so
	// legitimate evidence between 1 hour and 1 week old would be accepted by
	// VerifyEvidence but rejected by SubmitEvidence — an inconsistency that
	// either blocked valid slashing or, in combination with the old-timestamp
	// bug below, allowed stale evidence to bypass freshness intent. A 1-week
	// window is the Casper standard: evidence is cryptographically verified
	// (double-sign proofs), so freshness only guards against storage/replay
	// issues, not validity.
	const maxEvidenceAgeSeconds = int64(7 * 24 * 60 * 60) // 1 week, matches VerifyEvidence
	// R33 P2-18 FIX: Use deterministic blockTime for freshness check instead
	// of time.Now(). This ensures all validators agree on evidence validity.
	var nowForFreshness int64
	if len(blockTime) > 0 && blockTime[0] > 0 {
		nowForFreshness = blockTime[0]
	} else {
		nowForFreshness = time.Now().Unix() // fallback for non-consensus callers
	}
	if age := nowForFreshness - evidence.Timestamp; age > maxEvidenceAgeSeconds {
		return nil, fmt.Errorf("%w: evidence timestamp too old (>1 week)", ErrSlashingEvidenceInvalid)
	}

	// CR40-C8 FIX: Additional security validation - validator address check
	if evidence.ValidatorAddr == (types.Address{}) {
		return nil, fmt.Errorf("%w: validator address cannot be zero", ErrSlashingEvidenceInvalid)
	}

	if !sm.validatorMgr.IsSystemCaller(caller) {
		return nil, ErrUnauthorizedOperation
	}

	// Verify evidence first
	// R33 P2-18 FIX: Pass blockTime to VerifyEvidence for deterministic freshness check.
	if err := sm.VerifyEvidence(evidence, blockTime...); err != nil {
		return nil, err
	}

	// R4-P2-2 FIX: Rate limit AFTER verification, not before. Previously,
	// forged/invalid evidence consumed the caller's rate-limit quota, allowing
	// an attacker to exhaust the quota with garbage evidence and suppress
	// legitimate evidence submission.
	// CR40-C8 FIX: Limit system caller permissions - rate limiting
	sm.mu.Lock()
	submissionKey := fmt.Sprintf("%s:%d:%s", caller.String(), evidence.Reason, evidence.ValidatorAddr.String())
	lastSubmission, exists := sm.lastSubmissions[submissionKey]
	if exists && time.Now().Unix()-lastSubmission < 60 { // NOT consensus-critical: local rate limiting
		// Same caller submitting same type of evidence for same validator within 60 seconds
		sm.mu.Unlock()
		return nil, fmt.Errorf("%w: rate limit exceeded for evidence submissions", ErrUnauthorizedOperation)
	}
	sm.lastSubmissions[submissionKey] = time.Now().Unix() // NOT consensus-critical: local rate limiting
	sm.mu.Unlock()

	// audit-fix CRIT-PERSIST: Record slashing in persistent store
	sm.persistSlashing(evidence)

	// slashing bypass protection: check if validator is trying to exit
	// Lock stake during slashing investigation
	validator, err := sm.validatorMgr.GetValidator(evidence.ValidatorAddr)
	if err != nil {
		return nil, err
	}

	// slashing bypass protection: ensure validator has stake to slash
	if validator.Stake.Sign() <= 0 {
		return nil, ErrSlashingEvidenceInvalid
	}

	// Execute slashing.
	// SECURITY (audit 2026-06-14, H5): Always use the CURRENT time for the
	// slashing/penalty timestamp, never evidence.Timestamp. The evidence
	// timestamp is attacker-supplied (within the 1-week window) and using it
	// for penalty accounting (jail-start, offense time) would let an attacker
	// submit a real-but-old evidence to shift penalty boundaries. The evidence
	// timestamp is only used for freshness checks above.
	// R4-C1 FIX (2026-07-06): Use deterministic blockTime when provided to
	// ensure consensus determinism. Fall back to time.Now() for backward compat.
	var timestamp int64
	if len(blockTime) > 0 && blockTime[0] > 0 {
		timestamp = blockTime[0]
	} else {
		timestamp = time.Now().Unix()
	}

	// SECURITY FIX (R2 P0-1 reverse sync): Check if QPOS already slashed this
	// validator. QPOS.SlashValidator no longer calls SubmitEvidence (S-6 fix),
	// so if QPOS detected and slashed the validator internally, SlashingManager
	// won't know. This check prevents double slashing: if QPOS already slashed,
	// we record the offense only (for audit trail) without reducing stake again.
	if sm.qpos != nil {
		vs := sm.qpos.GetValidatorSet()
		if vs != nil {
			index := vs.GetValidatorIndex(evidence.ValidatorAddr)
			if index >= 0 && sm.qpos.IsSlashed(index) {
				slashingLogger.Infof("validator %x already slashed by QPOS — recording offense only (no stake reduction)",
					evidence.ValidatorAddr[:8])
				sm.RecordOffenseOnly(evidence.ValidatorAddr, evidence.Reason, evidence.Height)
				return &SlashingRecord{
					ValidatorAddr: evidence.ValidatorAddr,
					Reason:        evidence.Reason,
					Height:        evidence.Height,
					Timestamp:     timestamp,
					Jailed:        true,
				}, nil
			}
		}
	}

	return sm.slash(evidence, timestamp)
}

// ============================================================================
// Statistics and Queries
// ============================================================================

// GetValidatorSigningInfo returns the signing info for a validator
func (sm *SlashingManager) GetValidatorSigningInfo(addr types.Address) *ValidatorSigningInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	info := sm.signingInfo[addr]
	if info == nil {
		return nil
	}

	// Return a copy
	return &ValidatorSigningInfo{
		Address:             info.Address,
		StartHeight:         info.StartHeight,
		MissedBlocksCounter: info.MissedBlocksCounter,
		JailedUntil:         info.JailedUntil,
		// CON4-001 FIX: Include PermanentlySlashed in the copy. Previously
		// omitted, causing external callers to always see false.
		PermanentlySlashed: info.PermanentlySlashed,
	}
}

// GetMissedBlocksCount returns the number of missed blocks for a validator
func (sm *SlashingManager) GetMissedBlocksCount(addr types.Address) uint64 {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	info := sm.signingInfo[addr]
	if info == nil {
		return 0
	}

	return info.MissedBlocksCounter
}

// GetSlashingStats returns statistics about slashing
// audit-remediation: read-only function, no stake manipulation possible
func (sm *SlashingManager) GetSlashingStats() *SlashingStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats := &SlashingStats{
		TotalSlashings:       len(sm.records),
		DoubleSignSlashings:  0,
		DowntimeSlashings:    0,
		TotalSlashedAmount:   big.NewInt(0),
		JailedValidatorCount: 0,
	}

	for _, record := range sm.records {
		stats.TotalSlashedAmount.Add(stats.TotalSlashedAmount, record.SlashedAmount)
		switch record.Reason {
		case SlashingReasonDoubleSigning, SlashingReasonInvalidVRF, SlashingReasonSurroundVote, SlashingReasonDoubleVote:
			stats.DoubleSignSlashings++
		case SlashingReasonDowntime:
			stats.DowntimeSlashings++
		}
	}

	// Count currently jailed validators
	now := time.Now().Unix() // NOT consensus-critical: local status query
	for _, info := range sm.signingInfo {
		if info.JailedUntil > 0 && now < info.JailedUntil {
			stats.JailedValidatorCount++
		}
	}

	return stats
}

// MarkValidatorRemoved cleans up slashing state when a validator is removed
// R36-C1 FIX: RemoveValidator in ValidatorManager does not automatically clean up
// SlashingManager state. Callers of RemoveValidator MUST call this method to prevent
// memory leaks and stale data in signingInfo, voteHistory, slashedOffenses, and signedBlocks.
func (sm *SlashingManager) MarkValidatorRemoved(addr types.Address) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Clean up signing info
	delete(sm.signingInfo, addr)

	// Clean up vote history
	delete(sm.voteHistory, addr)

	// Clean up signed blocks record
	delete(sm.signedBlocks, addr)

	// Clean up slashedOffenses for this address.
	// CONS- (2026-07-20): The offenseKey format is created at lines 863
	// and 1110 via fmt.Sprintf("%x:%d:%d", addr, reason, height). Note that
	// types.Address implements fmt.Stringer (String() returns "QAU"+base32(...)),
	// so Go's %x verb invokes String() first and hex-encodes that string,
	// producing 70 hex chars (NOT 40). The previous cleanup code took
	// key[:40] directly, which sliced only PART of the hex address and so
	// never matched — every entry was silently leaked. The earlier fix
	// attempt validated len==40, but that rejected ALL valid entries
	// because the real hex is 70 chars. The robust fix is to match the
	// key prefix using the EXACT same "%x:" format string used to create
	// the key — no assumptions about address encoding length or format.
	if sm.slashedOffenses != nil {
		addrPrefix := fmt.Sprintf("%x:", addr)
		toDelete := make([]string, 0)
		for key := range sm.slashedOffenses {
			if strings.HasPrefix(key, addrPrefix) {
				toDelete = append(toDelete, key)
			}
		}
		for _, k := range toDelete {
			delete(sm.slashedOffenses, k)
		}
	}
}

// PruneExpiredState performs periodic cleanup of expired or stale state to
// prevent unbounded memory growth. This should be called periodically (e.g.,
// once per epoch) by the consensus engine.
//
// L20-006 FIX: SlashingManager previously lacked periodic cleanup for several
// internal maps that grow without bound:
//   - lastSubmissions: rate-limiting entries are never removed after the 60s
//     window expires, causing unbounded growth for active networks.
//   - signingInfo: entries for validators that are no longer jailed and no
//     longer active accumulate indefinitely.
//   - records: already bounded by MaxSlashingRecords capacity eviction, but
//     entries are never removed based on age.
//
// This method cleans up:
//  1. lastSubmissions entries older than the rate-limit window (60 seconds).
//  2. signingInfo entries for validators whose jail has expired AND who are
//     no longer in the active validator set (preserving entries for
//     permanently slashed validators for audit purposes).
//
// Note: records and slashedOffenses are already pruned by capacity-based
// eviction in recordSlashing_locally and RecordOffenseOnly.
func (sm *SlashingManager) PruneExpiredState(currentTime int64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 1. Prune expired rate-limiting entries (older than 60 seconds).
	const rateLimitWindow int64 = 60
	for key, lastTime := range sm.lastSubmissions {
		if currentTime-lastTime > rateLimitWindow {
			delete(sm.lastSubmissions, key)
		}
	}

	// 2. Prune signingInfo for validators whose jail has expired and who are
	//    not permanently slashed. We only remove entries for validators that are
	//    no longer jailed, keeping permanently slashed entries for audit trail.
	activeValidators := sm.validatorMgr.GetActiveValidators()
	activeSet := make(map[types.Address]bool, len(activeValidators))
	for _, v := range activeValidators {
		activeSet[v.Address] = true
	}
	for addr, info := range sm.signingInfo {
		// Keep permanently slashed entries for audit trail.
		if info.PermanentlySlashed {
			continue
		}
		// Keep entries for currently jailed validators.
		if info.JailedUntil > 0 && currentTime < info.JailedUntil {
			continue
		}
		// CON4-004 FIX: Remove entries for validators no longer active, whether
		// or not they were previously jailed. Previously, only validators with
		// JailedUntil > 0 were pruned, causing never-jailed inactive validators
		// to accumulate indefinitely (memory leak). PermanentlySlashed entries
		// are retained above for audit trail.
		if !activeSet[addr] {
			if info.JailedUntil == 0 || currentTime >= info.JailedUntil {
				delete(sm.signingInfo, addr)
				// Also clean up associated vote history and signed blocks.
				delete(sm.voteHistory, addr)
				delete(sm.signedBlocks, addr)
			}
		}
	}
}

// SlashingStats contains statistics about slashing
type SlashingStats struct {
	TotalSlashings       int
	DoubleSignSlashings  int
	DowntimeSlashings    int
	TotalSlashedAmount   *big.Int
	JailedValidatorCount int
}

// ============================================================================
// Vote History Persistence (audit C-3 fix)
// ============================================================================

// voteHistoryKeyPrefix is the DB key prefix for persisted votes.
// Key format: "vote:addr:height" -> encoded vote
var voteHistoryKeyPrefix = []byte("vote:")

// persistVote writes a single vote to the database for crash recovery.
// Called with sm.mu held.
func (sm *SlashingManager) persistVote(addr types.Address, height uint64, vote *Vote) {
	key := voteHistoryKey(addr, height)
	// Encode: Type(1) + Height(8) + Round(4) + BlockHash(32) + Addr(20) + SigLen(4) + Sig + SourceEpoch(8) + TargetEpoch(8)
	buf := make([]byte, 0, 85+len(vote.Signature))
	buf = append(buf, byte(vote.Type))
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, vote.Height)
	buf = append(buf, heightBytes...)
	roundBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(roundBytes, vote.Round)
	buf = append(buf, roundBytes...)
	buf = append(buf, vote.BlockHash[:]...)
	buf = append(buf, vote.ValidatorAddr[:]...)
	sigLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sigLenBytes, uint32(len(vote.Signature)))
	buf = append(buf, sigLenBytes...)
	buf = append(buf, vote.Signature...)
	srcEpochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(srcEpochBytes, vote.SourceEpoch)
	buf = append(buf, srcEpochBytes...)
	tgtEpochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tgtEpochBytes, vote.TargetEpoch)
	buf = append(buf, tgtEpochBytes...)
	if err := sm.db.Put(key, buf); err != nil {
		slashingLogger.Warn("failed to persist vote", map[string]any{"addr": addr.String(), "height": height, "err": err.Error()})
	}
}

// LoadVoteHistory loads persisted votes from the database into memory.
// SECURITY FIX (audit C-3): Restores vote history after node restart so that
// double-signing detection continues to work across restarts.
func (sm *SlashingManager) LoadVoteHistory() error {
	if sm.db == nil {
		return nil
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()

	it := sm.db.NewIterator(voteHistoryKeyPrefix, nil)
	defer it.Release()

	loaded := 0
	for it.Next() {
		key := it.Key()
		val := it.Value()
		if len(key) < len(voteHistoryKeyPrefix)+types.AddressLength+8 {
			continue
		}
		var addr types.Address
		copy(addr[:], key[len(voteHistoryKeyPrefix):len(voteHistoryKeyPrefix)+types.AddressLength])
		height := binary.BigEndian.Uint64(key[len(voteHistoryKeyPrefix)+types.AddressLength:])

		vote, err := decodeVote(val, addr, height)
		if err != nil {
			slashingLogger.Warn("failed to decode vote", map[string]any{"addr": addr.String(), "height": height, "err": err.Error()})
			continue
		}
		if sm.voteHistory[addr] == nil {
			sm.voteHistory[addr] = make(map[uint64]map[uint32]*Vote)
		}
		if sm.voteHistory[addr][height] == nil {
			sm.voteHistory[addr][height] = make(map[uint32]*Vote)
		}
		// R35-P0-06 FIX: Use vote.Round as the third dimension key.
		// Note: persistVote uses (addr, height) as the DB key without round,
		// so only the last-persisted vote per (addr, height) is restored.
		// This is acceptable: losing round history after restart only weakens
		// double-sign detection (false negatives), never causes false positives.
		sm.voteHistory[addr][height][vote.Round] = vote
		loaded++
	}
	if loaded > 0 {
		slashingLogger.Info("loaded persisted votes", map[string]any{"count": loaded})
	}
	return it.Error()
}

// LoadSlashingRecords (R49-SLASH-RELOAD-01, 2026-08-11): rebuild in-memory
// sm.records and sm.slashedOffenses from chain-level persistent storage so
// the (addr, reason, height) idempotency guard survives node restarts.
// Previously these maps were in-memory only; a node that processed an
// evidence, persisted it via SaveSlashingRecord, then restarted would have
// an empty slashedOffenses map on next boot — the SAME evidence replayed
// by gossip would re-enter ProcessSlashingEvent, trigger another
// whistleblower reward path, and re-append to sm.records. The QPOS-level
// slashed_validator: prefix prevents re-slash of the actual validator, but
// the whistleblower reward and per-record audit trail duplication were not
// guarded by anything after restart.
//
// Must be called ONCE by node bootstrap AFTER SetDB. Safe to call on top
// of an already non-empty sm.records (returns quickly when persisted count
// is 0 or matches in-memory count).
func (sm *SlashingManager) LoadSlashingRecords() error {
	if sm.db == nil {
		return nil
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()

	prefix := []byte("slashing_record:")
	it := sm.db.NewIterator(prefix, nil)
	defer it.Release()

	loaded := 0
	skippedDupe := 0
	for it.Next() {
		key := it.Key()
		val := it.Value()
		// key = prefix + addr(20) + timestamp(8) + height(8) + reason(1) = prefix+37
		if len(key) < len(prefix)+types.AddressLength+8+8+1 {
			continue
		}
		var addr types.Address
		copy(addr[:], key[len(prefix):len(prefix)+types.AddressLength])
		timestamp := int64(binary.BigEndian.Uint64(key[len(prefix)+types.AddressLength : len(prefix)+types.AddressLength+8])) // #nosec G115 -- timestamp int64 fits uint64 wire format
		height := binary.BigEndian.Uint64(key[len(prefix)+types.AddressLength+8 : len(prefix)+types.AddressLength+16])
		reasonByte := key[len(prefix)+types.AddressLength+16]

		// value = height(8) + slashedAmount(32) + reason(1) + jailed(1) + jailUntil(8) = 50 bytes
		if len(val) < 50 {
			continue
		}
		// Height is also in the value — prefer the value copy for safety
		// (defensive: key and value should always agree, ignore mismatches).
		valHeight := binary.BigEndian.Uint64(val[0:8])
		if valHeight != height {
			continue
		}
		var slashedAmount *big.Int
		amountBytes := val[8 : 8+32]
		if new(big.Int).SetBytes(amountBytes).Sign() > 0 {
			slashedAmount = new(big.Int).SetBytes(amountBytes)
		}
		reason := SlashingReason(val[8+32])
		if reason != SlashingReason(reasonByte) {
			continue
		}
		jailed := val[8+32+1] != 0
		jailUntil := int64(binary.BigEndian.Uint64(val[8+32+2 : 8+32+2+8])) // #nosec G115

		rec := &SlashingRecord{
			ValidatorAddr: addr,
			Reason:        reason,
			Height:        height,
			SlashedAmount: slashedAmount,
			Timestamp:     timestamp,
			Jailed:        jailed,
			JailUntil:     jailUntil,
			// Whistleblower / WhistleblowerReward are intentionally NOT
			// persisted by SaveSlashingRecord; leave zero. Reward is
			// already accounted offline by the reward distributor; the
			// in-memory record only needs enough to reproduce the
			// slashedOffenses guard.
		}

		// Check idempotency FIRST so we never double-insert into in-memory
		// records / offenses (e.g. if this function is called twice).
		offenseKey := fmt.Sprintf("%x:%d:%d", addr, reason, height)
		if sm.slashedOffenses[offenseKey] {
			skippedDupe++
			continue
		}
		sm.slashedOffenses[offenseKey] = true
		if len(sm.records) >= MaxSlashingRecords {
			evictCount := MaxSlashingRecords / 10
			if evictCount < 1 {
				evictCount = 1
			}
			sm.records = sm.records[evictCount:]
		}
		sm.records = append(sm.records, rec)
		loaded++
	}
	if loaded > 0 {
		slashingLogger.Info("R49-SLASH-RELOAD-01: loaded persisted slashing records", map[string]any{"loaded": loaded, "skipped_dupes": skippedDupe})
	}
	return it.Error()
}

func voteHistoryKey(addr types.Address, height uint64) []byte {
	key := make([]byte, len(voteHistoryKeyPrefix)+types.AddressLength+8)
	copy(key, voteHistoryKeyPrefix)
	copy(key[len(voteHistoryKeyPrefix):], addr[:])
	binary.BigEndian.PutUint64(key[len(voteHistoryKeyPrefix)+types.AddressLength:], height)
	return key
}

func decodeVote(data []byte, addr types.Address, height uint64) (*Vote, error) {
	if len(data) < 1+8+4+32+20+4 {
		return nil, fmt.Errorf("vote data too short: %d", len(data))
	}
	offset := 0
	vote := &Vote{
		Type:          VoteType(data[offset]),
		Height:        height,
		ValidatorAddr: addr,
	}
	offset += 1
	offset += 8 // height already known from key
	vote.Round = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	copy(vote.BlockHash[:], data[offset:])
	offset += 32
	offset += 20 // validator addr already known from key
	sigLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	if len(data) < offset+int(sigLen)+16 {
		return nil, fmt.Errorf("vote data truncated: need %d, have %d", offset+int(sigLen)+16, len(data))
	}
	vote.Signature = make([]byte, sigLen)
	copy(vote.Signature, data[offset:])
	offset += int(sigLen)
	vote.SourceEpoch = binary.BigEndian.Uint64(data[offset:])
	offset += 8
	vote.TargetEpoch = binary.BigEndian.Uint64(data[offset:])
	return vote, nil
}
