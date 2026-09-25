// Quantaureum Node source, version 1.0.0.
// Package consensus implements QPOS (Quantum-resistant Proof of Stake) consensus.
// QPOS is modeled after Ethereum's Gasper (Casper FFG + LMD GHOST) but uses
// post-quantum cryptography (Dilithium3) for all signatures.
//
// Key concepts:
// - Slot: 12 second time period, one block per slot
// - Epoch: 32 slots = 6.4 minutes, used for finality checkpoints
// - Proposer: Selected validator to create block for a slot
// - Attester: Validators who vote on blocks
// - Finality: Blocks become irreversible after 2 epochs of attestations
package consensus

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/types"
)

// QPOS Constants (matching Ethereum PoS)
const (
	SlotsPerEpoch   = 32                           // 32 slots per epoch
	SlotDuration    = 12 * time.Second             // 12 seconds per slot
	MaxClockDrift   = 5 * time.Second              // C21-005: Max allowed clock drift
	EpochDuration   = SlotsPerEpoch * SlotDuration // ~6.4 minutes
	MinAttestations = 3                            // Minimum attestations to consider block valid (audit-fix: raised from 2 to prevent small-network attacks)
	// L10-005: MinAttestations is the default for 6 validators (50% threshold).
	// For finality, 2/3 threshold is enforced via CheckpointManager.ComputeMinSignatures().
	// Use ComputeMinAttestations(validatorCount) for dynamic threshold.
	FinalityDelay       = 2   // Epochs before finality (2 epochs = ~13 minutes)
	TargetCommitteeSize = 128 // Target size for attestation committees

	// Reward/Penalty constants
	//
	// EM-2 (2026-08-31): issuance follows the Ethereum Altair structure. See
	// docs/economic-model.md for the derivation and economics/model for the
	// executable model that consensus/econ_model_parity_test.go pins this
	// implementation against.
	//
	// Calibration: F=31 targets ~4% staking APY at 4,000,000 QAU staked and
	// converges to ~3% as stake grows (APY is proportional to 1/sqrt(total)).
	// At the 36,000 QAU bootstrap level it yields ~42% APY, which is a
	// deliberate cold-start premium costing only 15,275 QAU/year (0.076% of
	// supply) and decaying automatically as stake grows.
	//
	// HISTORY — do not restore the previous values without reading this:
	// F used to be 2 with a comment claiming ~9.8% APR at 6 validators x
	// 30,000 QAU. That figure was only reachable under the pre-CONS-
	// semantics of one attester reward per SLOT. The dedup fix cut issuance by
	// SlotsPerEpoch (32x) without recalibrating F, leaving the real APY at
	// 1.94% and, at scale, effectively zero (0.031% at 3,000 validators).
	BaseRewardFactor = 31

	// BaseRewardsPerEpoch is the trailing divisor of the base-reward formula.
	//
	// Ethereum phase0 used BASE_REWARDS_PER_EPOCH = 4; Altair folded it into
	// the weight table and effectively uses 1. EM-2 follows Altair.
	//
	// This MUST stay a named constant. It was previously an unnamed literal 4
	// duplicated at two call sites in epoch.go, which made "change the divisor"
	// a change that is easy to apply to only one of them — and applying it to
	// one produces silently wrong issuance rather than a compile error.
	BaseRewardsPerEpoch = 1

	// ProposerWeight / WeightDenominator split epoch issuance between the
	// block proposer and the attesters, exactly as Altair's weight table does:
	// proposers take ProposerWeight/WeightDenominator (8/64 = 12.5%) of total
	// issuance and attesters receive the remainder (56/64 = 87.5%).
	//
	// Crucially the split carves the proposer share OUT of total issuance
	// rather than adding to it, so total issuance is independent of the
	// validator count.
	//
	// HISTORY: this replaces ProposerRewardQuotient = 8, which carried the
	// comment "Proposer gets 1/8 of attestation rewards" but had ZERO
	// references anywhere in the repository. Meanwhile the reward census paid
	// proposers one FULL base reward per proposed slot, i.e. 32/(N+32) of all
	// issuance — 84.2% at 6 validators, versus the intended 12.5%. Attesting,
	// which is what drives finality, was under-rewarded by 5.54x.
	//
	// WeightDenominator must divide 1e9 for the per-validator split to be
	// exact (see the zero-dust argument in economics/model.Attribution);
	// 64 does.
	ProposerWeight            = 8
	WeightDenominator         = 64
	MinSlashingPenalty        = 1000000  // Minimum slashing penalty (1 QAU)
	InactivityPenaltyQuotient = 67108864 // ~2^26, penalty for offline validators

	// Proposer boost (for fork choice)
	ProposerScoreBoost = 40 // 40% boost for timely block

	// audit-fix L-5: maximum shuffle cache entries to prevent unbounded memory growth
	MaxShuffleCacheSize = 5

	// Committee cache: max slots to cache committee results for
	MaxCommitteeCacheSize = 64

	// Memory limit constants to prevent unbounded growth
	MaxEvidenceQueue      = 10000  // Max slashing evidence queue entries
	MaxTrackedValidators  = 250000 // Max tracked validator indices in attestation map (raised for 200K+ validator support)
	MaxVoteHistoryEntries = 250000 // Max total vote history entries in finality tracker
	MaxValidators         = 250000 // L14-009: Maximum number of validators in the active validator set
	// P3-E8 AUDIT NOTE (two distinct MaxValidators limits — intentional):
	// This consensus.MaxValidators (250,000) is the THEORETICAL PROTOCOL
	// MAXIMUM — the largest validator set the consensus/attestation/finality
	// data structures are designed to handle (see MaxTrackedValidators/
	// MaxVoteHistoryEntries above). It is a protocol-level ceiling, NOT the
	// operational limit. The economics/staking.StakingConfig.MaxValidators
	// (default 100) is the CURRENT OPERATIONAL LIMIT enforced at stake
	// registration. The two are intentionally different: the protocol is
	// future-proofed for a much larger validator set, while the operational
	// limit is kept low for current network security and performance. Do NOT
	// "fix" the mismatch by making them equal.
)

// ComputeMinAttestations dynamically computes the minimum attestations needed
// for block validity based on validator count. Uses ceil(N/2) for majority
// threshold (block inclusion), while finality uses ceil(N*2/3) via checkpoints.
// L10-005 FIX: MinAttestations was hardcoded to 3, which is correct for 6 validators
// but should adapt to validator set changes.
// FIX: Enforce MinAttestations as a floor — for small validator sets
// (e.g., 4 validators → ceil(4/2)=2), the dynamic formula returns below the
// static minimum, reducing security margins. Clamp to MinAttestations.
// C3 FIX (2026-07-06): Log a warning when validatorCount <= 0 to surface
// invalid inputs instead of silently returning the default.
func ComputeMinAttestations(validatorCount int) int {
	if validatorCount <= 0 {
		// C3 FIX: Log warning for invalid input instead of silent degradation.
		// P3-LOG-01 FIX (R30, 2026-07-27): Use logging.Global().Warn() so SIEM
		// pipelines can collect this event via the global logger instance.
		logging.Global().Warn("ComputeMinAttestations called with non-positive validator count",
			map[string]any{"validatorCount": validatorCount})
		return MinAttestations
	}
	// ceil(N/2) for majority block inclusion
	min := (validatorCount + 1) / 2
	//  Enforce static minimum for security
	if min < MinAttestations {
		min = MinAttestations
	}
	return min
}

// QPOS Errors
var (
	ErrNotProposer          = errors.New("not the proposer for this slot")
	ErrSlotInPast           = errors.New("slot is in the past")
	ErrSlotTooFar           = errors.New("slot is too far in the future")
	ErrInvalidAttestation   = errors.New("invalid attestation")
	ErrDuplicateAttestation = errors.New("duplicate attestation")
	ErrNotInCommittee       = errors.New("validator not in committee for this slot")
	// R95-ATTEST-LOGLEVEL (2026-08-30): returned (wrapped) by
	// ReviewChamber.ProcessReviewAttestation when ThreeChambersCoordinator
	// .CanAttest refuses the attester. The overwhelmingly common cause is
	// structural and expected on EVERY slot: BlockProducer creates and
	// broadcasts an attestation for the slot it just proposed, and the slot
	// proposer may not also attest. Callers use errors.Is on this sentinel to
	// log the routine case at Debug while keeping every OTHER
	// ProcessReviewAttestation failure at Warn. Never classify by message text.
	ErrNotInReviewChamber = errors.New("validator not in Review Chamber for this slot")
	ErrDoubleVote         = errors.New("double vote detected (slashable offense)")
	ErrSurroundVote       = errors.New("surround vote detected (slashable offense)")
	ErrValidatorSlashed   = errors.New("validator has been slashed")
	// CONS- (2026-07-20): Returned by QPOS.UnmarkValidatorSlashed
	// when the caller attempts to unmark a permanently-slashed validator.
	// SlashingManager.Unjail() already rejects permanent slashes upstream,
	// but this is defense-in-depth in case a future caller forgets.
	ErrValidatorPermanent          = errors.New("validator is permanently slashed and cannot be unjailed")
	ErrThresholdSignerNotAvailable = errors.New("threshold signer not available for this operation")
	ErrGenesisTimeNotSet           = errors.New("genesis time not properly configured for production")
	ErrNetworkIDNotConfigured      = errors.New("attestation network ID not configured (must call SetAttestationNetworkID)")
	ErrGenesisHashMismatch         = errors.New("genesis block hash mismatch - node is on different network")
	ErrGenesisHashNotSet           = errors.New("genesis block hash not configured")
	ErrEmptyValidatorSet           = errors.New("validator set is empty") // L14-009: reject empty validator set during epoch transition
	// CONS- (2026-07-20): SlashValidator must reject unrecognized
	// reason strings. Previously, an unknown reason silently fell through
	// to SlashReasonUnknown, which is the default fallback in the penalty
	// calculator — a caller could trigger an unintended penalty calculation
	// path by passing an unrecognized string. Callers MUST pass one of the
	// known reason strings ("double_vote", "surround_vote", "inactivity",
	// "proposer_missed", "double_signing", "downtime", "invalid_vrf").
	ErrInvalidSlashReason = errors.New("invalid slash reason: must be one of double_vote, surround_vote, inactivity, proposer_missed, double_signing, downtime, invalid_vrf")
)

// genesisState holds all genesis configuration under a single mutex.
// SECURITY FIX Q-B-011: Previously genesisTime and genesisBlockHash each had
// independent mutexes, allowing atomicity violations when both were set together.
// Now a single genesisMu protects all genesis state.
type genesisState struct {
	mu         sync.RWMutex
	time       int64
	timeSet    bool
	timeFrozen bool
	hash       types.Hash
	hashSet    bool
	hashFrozen bool
}

var genesis = &genesisState{}

// GetGenesisTime returns the genesis timestamp.
func GetGenesisTime() int64 {
	genesis.mu.RLock()
	defer genesis.mu.RUnlock()
	return genesis.time
}

// IsGenesisTimeConfigured returns true if genesis time was explicitly set.
func IsGenesisTimeConfigured() bool {
	genesis.mu.RLock()
	defer genesis.mu.RUnlock()
	return genesis.timeSet
}

// ValidateGenesisTimeForProduction validates that genesis time is properly configured.
func ValidateGenesisTimeForProduction() error {
	genesis.mu.RLock()
	defer genesis.mu.RUnlock()

	if !genesis.timeSet {
		return ErrGenesisTimeNotSet
	}
	now := time.Now().Unix() // NOT consensus-critical: local genesis time validation
	oneYearAgo := now - 365*24*60*60
	oneYearAhead := now + 365*24*60*60
	if genesis.time < oneYearAgo || genesis.time > oneYearAhead {
		return errors.New("genesis time is outside reasonable range (within 1 year of current time)")
	}
	return nil
}

// SetGenesisTime sets the genesis timestamp.
func SetGenesisTime(t int64) error {
	genesis.mu.Lock()
	defer genesis.mu.Unlock()
	if genesis.timeFrozen {
		return nil
	}
	if t <= 0 {
		return fmt.Errorf("consensus: SetGenesisTime called with invalid timestamp %d (must be > 0)", t)
	}
	genesis.time = t
	genesis.timeSet = true
	return nil
}

// FreezeGenesisTime prevents further changes to genesis time.
func FreezeGenesisTime() {
	genesis.mu.Lock()
	defer genesis.mu.Unlock()
	genesis.timeFrozen = true
}

// GetGenesisBlockHash returns the genesis block hash.
func GetGenesisBlockHash() types.Hash {
	genesis.mu.RLock()
	defer genesis.mu.RUnlock()
	return genesis.hash
}

// SetGenesisBlockHash sets the genesis block hash.
func SetGenesisBlockHash(h types.Hash) error {
	genesis.mu.Lock()
	defer genesis.mu.Unlock()
	if genesis.hashFrozen {
		return errors.New("genesis block hash is frozen and cannot be changed")
	}
	genesis.hash = h
	genesis.hashSet = true
	return nil
}

// FreezeGenesisBlockHash prevents further changes to the genesis block hash.
func FreezeGenesisBlockHash() {
	genesis.mu.Lock()
	defer genesis.mu.Unlock()
	genesis.hashFrozen = true
}

// IsGenesisBlockHashConfigured returns true if genesis block hash was explicitly set.
func IsGenesisBlockHashConfigured() bool {
	genesis.mu.RLock()
	defer genesis.mu.RUnlock()
	return genesis.hashSet
}

// ValidateGenesisBlockHash validates that the provided hash matches the configured genesis hash.
func ValidateGenesisBlockHash(h types.Hash) error {
	genesis.mu.RLock()
	defer genesis.mu.RUnlock()
	if !genesis.hashSet {
		return ErrGenesisHashNotSet
	}
	if genesis.hash != h {
		return ErrGenesisHashMismatch
	}
	return nil
}

// LEGACY compatibility wrappers (will be removed after full migration)
// These keep the old variable names as pointers to the new struct fields.

// audit-fix C-5: CRITICAL - Key version tracking for safe key rotation
// QPOS implements the Quantum-resistant Proof of Stake consensus engine
type QPOS struct {
	mu sync.RWMutex

	// Validator set
	validators *ValidatorSet

	// Current state
	currentSlot  uint64
	currentEpoch uint64

	// RANDAO mix for randomness (accumulated from block proposers)
	randaoMix types.Hash

	randaoCommits map[uint64]map[int]types.Hash

	// Attestation pool
	attestations map[uint64][]*Attestation // slot -> attestations

	// Aggregated attestations (for efficient storage and transmission)
	aggregatedAttestations map[uint64]*AggregatedAttestation // slot -> aggregated

	// Slashing detection: track validator attestations for double-vote detection
	// DATA FLOW: This is the authoritative Attestation-level data source.
	// Written by: ProcessAttestation (direct), VotingManager.AddVote (sync).
	// Read by: checkDoubleVote, checkSurroundVote.
	validatorAttestations map[int]map[uint64]*Attestation // validatorIdx -> slot -> attestation

	// VotingManager for Vote-level tracking and DoubleSignDetector integration.
	// DATA FLOW: When ProcessAttestation accepts an attestation, it also notifies
	// VotingManager (converting attestation → vote) to keep voteSets and
	// DoubleSignDetector.voteHistory in sync with validatorAttestations.
	// When VotingManager.AddVote accepts a vote, it syncs back to validatorAttestations.
	votingManager *VotingManager

	// attestationCounter tracks attestations processed since the last finality
	// update. Used to throttle tryUpdateFinality (Fix 2) — finality only changes
	// when a 2/3 threshold is crossed, so checking every 8 attestations is
	// sufficient and avoids O(N×32) big.Int ops per attestation.
	attestationCounter uint64

	// Slashed validators
	//
	// CONS- (2026-07-20): Previously this was `map[int]uint64`
	// (validatorIdx -> epoch when slashed). The map had ONLY write paths
	// and NO delete/cleanup paths — once a validator was added it stayed
	// forever, even for temporary slashes (downtime, invalid VRF, etc.).
	// This turned every temporary slash into a permanent ban, allowing an
	// attacker to permanently eject competitor validators via trivial
	// offenses.
	//
	// Fix: the map now stores *SlashedEntry with Permanent and JailUntil
	// fields. SlashingManager.Unjail() clears the entry via
	// QPOS.UnmarkValidatorSlashed() after the jail period expires.
	// Permanent slashes (double_signing, surround_vote) cannot be unjailed.
	slashedValidators map[int]*SlashedEntry

	// P0-T2: Blacklist check callback — set by MinistryRegistry to allow
	// Defense ministry's blacklist to block proposers/attesters/sealers.
	//
	// P0-T5 (2026-07-14): The callback now accepts an optional blockTime
	// (Unix seconds) for deterministic expiry checks. QPOS passes the
	// slot-derived consensus time so all honest nodes agree on whether a
	// validator is blacklisted, preventing consensus divergence from
	// wall-clock differences.
	blacklistCheck func(int, ...int64) bool

	// P1-4 (2026-07-14): DA availability check callback. When set, QPOS
	// enforces DA availability at two points:
	//   1. CanPropose: check on the PARENT slot (slot-1).
	//      - DA-FIX (2026-07-17): In production mode (QAU_PRODUCTION=1),
	//        this is a HARD reject — proposing is refused when DA is
	//        unavailable. In non-production mode, it remains a soft check
	//        (warning + allow) for liveness during development.
	//   2. ThreeChambersFlow.FinalizeBlock: hard check on the CURRENT slot.
	//      If DA is unavailable, finalization is REFUSED — a block with
	//      unavailable blob data must not be finalized.
	// The callback receives the slot number and returns nil if DA is
	// available, or an error describing why it is not.
	daAvailabilityCheck func(slot uint64) error

	// R43-CS-001 FIX: Pending deactivation set (by address) for validators
	// that failed SetActive during slashing. CanPropose/CanAttest check this
	// set to prevent these validators from proposing/attesting.
	pendingDeactivationAddrs map[types.Address]bool

	// Finalized checkpoint
	finalizedEpoch uint64
	finalizedRoot  types.Hash

	// Justified checkpoint (1 epoch before finalized)
	justifiedEpoch uint64
	justifiedRoot  types.Hash

	// R107-FINALITY-PERSIST: optional durable checkpoint callback. The
	// consensus package stays storage-agnostic; node wiring persists the
	// current checkpoint and restores it before live attestation processing.
	finalityPersist        func(justifiedEpoch, finalizedEpoch uint64, justifiedRoot, finalizedRoot types.Hash) error
	finalityPersistPending bool

	// Epoch block roots for Casper FFG finality
	epochBlockRoots map[uint64]types.Hash // epoch -> block root

	// AUDIT (2026) GOV-05 FIX: Per-slot canonical block roots. The Review
	// Chamber previously looked up block roots by epoch, which meant every
	// slot within an epoch compared attestations against the SAME root. This
	// caused attestations for non-epoch-boundary slots to be misclassified
	// as "reject" whenever the slot's actual block differed from the epoch's
	// recorded root. Tracking per-slot roots lets the Review Chamber
	// classify each attestation against the correct canonical block.
	slotBlockRoots map[uint64]types.Hash // slot -> block root

	// AUDIT (2026) R4-CORE-01 FIX: Per-epoch VRF output accumulator.
	// XOR of all VRF outputs from proposers that produced canonical blocks
	// in a given epoch. Used as an additional entropy source for the proposer
	// shuffle seed in the NEXT epoch (epoch N's shuffle uses epoch N-1's
	// accumulator).
	//
	// WHY VRF (not RANDAO): VRF output is deterministic for a given
	// (privKey, seed) pair — a proposer CANNOT grind by choosing among
	// multiple outputs (unlike RANDAO reveals, which the proposer could
	// withhold). This satisfies the CORE- constraint (no last-proposer
	// grind) while adding genuine unpredictability (R4-CORE-01).
	//
	// SAFETY: Only accumulated for canonical-chain blocks (gated by
	// shouldSwitch in node.go), so all honest nodes agree on the contents.
	epochVRFAccumulator map[uint64]types.Hash // epoch -> XOR of VRF outputs

	// R58-VRF-PERSIST (2026-08-18): optional callback invoked (under q.mu)
	// whenever SetEpochVRFAccumulator commits an authoritative per-epoch
	// accumulator. node.go registers it to write the value to the block
	// store, so a restart recovers the deterministic proposer schedule even
	// if the R52 block replay is skipped or interrupted. Kept as a callback
	// (not a db handle) so the consensus package stays free of storage
	// dependencies; nil = persistence disabled (tests / standalone QPOS).
	vrfPersist func(epoch uint64, acc types.Hash)

	// R38-P1-08 DEEP FIX (2026-08-02): Per-block-hash idempotency set
	// recording which canonical block headers have already been replayed
	// into the incremental proposer snapshot reconstructor (ApplyBlockHeader).
	// Without this set, re-processing a canonical block during a re-sync or
	// reorg would XOR the VRF output a second time — flipping the accumulator
	// bit-by-bit and corrupting the shuffle seed for epochs ≥2 away. The set
	// is bounded to recent finalized-window entries; older entries are pruned
	// inside ApplyBlockHeader to keep memory growth linear with the live
	// finalized window, not the entire chain history.
	appliedBlockRoots map[types.Hash]struct{}

	// Shuffled validator indices per epoch (cached)
	shuffleCache map[uint64][]int

	// R102-WEIGHTED-PROPOSER: epoch-gated stake-weighted proposer election.
	// weightedProposerCutover defaults to MaxUint64 (feature OFF until
	// SetWeightedProposerCutover is called from node config). For epochs >=
	// the cutover, GetProposerForSlot selects per-slot via a deterministic
	// stake-weighted draw over the epoch's cumulative-weight table; below the
	// cutover the legacy uniform Fisher-Yates shuffle is used byte-for-byte.
	// The table cache follows the EXACT lifecycle of shuffleCache (same
	// invalidation points) so both regimes see identical validator-set views.
	weightedProposerCutover uint64
	weightedCumCache        map[uint64]*weightedEpochTable

	// R45-PoA-FIX (2026-08-12): epochs for which the deterministic
	// shuffle was computed under a COLD-START fallback (VRF accumulator
	// for epoch-2 was still zero when the shuffle was first requested,
	// i.e. this sealer restarted and has not yet replayed the canonical
	// chain far enough to repopulate epochVRFAccumulator[epoch-2]).
	//
	// Why this matters: when the accumulator is zero the seed falls back
	// to keccak256(epoch) alone. That is identical to other nodes ONLY
	// IF every node is cold (e.g. genesis bootstrap). The sealer-restart
	// case is the dangerous one — the restarting sealer is cold, but
	// the peers' accumulators are populated, so the seeds disagree →
	// the elected proposers disagree → chain fork. We surface this
	// disagreement by exposing IsProposerScheduleReadyForEpoch(epoch)
	// so the BlockProducer and BlockValidator can refuse to act until
	// the sealer has caught up.
	coldStartEpochs map[uint64]struct{}

	// Committee cache: slot → committee result (avoids repeated GetValidatorByIndex calls)
	committeeCache map[uint64][]*Validator

	// R88-F (2026-08-30): epoch of block 1 (the first non-genesis block),
	// mirrored from node.FirstBlockEpoch via SetFirstBlockEpoch. On a
	// high-genesis chain (static genesis file with an old genesisTime, the
	// devnet/rehearsal setup) the chain starts at a late epoch, so epochs
	// below it can never have on-chain VRF accumulators — Executive selection
	// for those epochs legitimately uses the zero hash on EVERY node
	// (identical selection, no divergence). Stored as atomics: read from
	// SelectExecutiveForEpoch while it holds tpc.mu and only q.mu.RLock on
	// the qpos side, so it must not take q.mu itself.
	firstBlockEpochKnown atomic.Bool
	firstBlockEpoch      atomic.Uint64

	// Reward tracking per epoch
	epochRewards map[uint64]*EpochRewards

	// Proposer boost tracking for fork choice
	proposerBoostRoot types.Hash
	proposerBoostSlot uint64
	// AUDIT (2026) CORE-08 FIX: fixed boost value (40% of total active
	// committee stake). Nil when the legacy SetProposerBoost setter is used
	// (fail-closed: no boost applied without committee context).
	proposerBoostWeight *big.Int

	// Security components
	authorizedCallers *AuthorizedCallers
	stakeChecker      *StakeConsistencyChecker
	slashingValidator *SlashingValidator
	slashingAuditLog  *SlashingAuditLog
	slashingManager   *SlashingManager // R17-C1 FIX: Added missing field for Surround Vote evidence submission

	syncCommitteeManager *SyncCommitteeManager
	// CRITICAL FIX: Evidence queue for when slashingManager is unavailable
	evidenceQueue []*SlashingEvidence
	// P1-2 FIX: stopCh signals the evidence queue drainer goroutine to stop.
	stopCh chan struct{}

	// Threshold signing for QTD-based multi-party block/vote signatures
	tssSigner ThresholdKeySigner

	// Three Chambers coordinator for power separation (Proposing/Review/Executive)
	chambers *ThreeChambersCoordinator

	// QTD instant finality engine (replaces Casper FFG when active)
	qtdFinality *QTDFinalityState

	// Investigation tracking: validators under investigation are not immediately slashed.
	// They are only slashed after InvestigationThreshold independent evidence submissions fail.
	investigationCounts map[types.Address]int // validatorAddr -> count of failed evidence submissions

	// audit-fix C-5: CRITICAL - Key version tracking for safe key rotation
	// During rotation windows, validators must check key versions to prevent
	// accepting blocks signed with revoked or not-yet-active keys.
	keyVersionMu         sync.RWMutex
	currentKeyVersion    uint64                     // Current active key version
	vkReg                *vkRegistry                // R131: validator session-key registry (lazy-init)
	keyVersionHistory    map[uint64]*KeyVersionInfo // version -> info
	keyVersionFrozen     bool                       // Prevent mutation after consensus starts
	keyVersionValidation bool                       // Set to false during rotation transitions

	// C21-005 FIX: Track last known block time for clock drift protection.
	// Updated when blocks are processed; used by GetCurrentSlot to clamp
	// wall-clock readings that are too far ahead of the network.
	// Uses atomic operations for lock-free reads (GetCurrentSlot is hot path).
	lastKnownBlockTime int64 // accessed via atomic.LoadInt64/StoreInt64

	// R30-IMPLEMENT (2026-07-27): SLASH-H2 — jailDuration is the jail
	// duration (seconds) applied to temporary slashes by QPOS.SlashValidator.
	// Propagated from SlashingManager.params.JailDuration via
	// SetSlashingManager so both slash paths (QPOS.SlashValidator and
	// SlashingManager.slashLocked) produce the same JailUntil for the same
	// offense. 0 means "use DefaultJailDuration" (backward-compatible
	// behavior for standalone QPOS instances without a SlashingManager).
	jailDuration int64
}

// InvestigationThreshold is the number of failed evidence submissions before a validator
// under investigation is actually marked as slashed. This prevents false positives from
// transient network errors or single evidence submission failures.
const InvestigationThreshold = 3

// AggregatedAttestation combines multiple attestations for the same target.
// Phase 3 optimization: When QTD threshold signing is active, AggregatedSignature
// contains a single 3293-byte GM-QTD aggregated signature instead of individual
// signatures. This reduces signature data from N×3293B to 1×3293B.
// Signatures [][]byte is retained as a fallback for backward compatibility
// when QTD threshold signing is not available.
type AggregatedAttestation struct {
	Slot                uint64
	BeaconBlockRoot     types.Hash
	Source              AttestationCheckpoint
	Target              AttestationCheckpoint
	AggregationBits     []byte   // Bitfield of participating validators
	AggregatedSignature []byte   // QTD threshold aggregated signature (3293 bytes, Phase 3)
	Signatures          [][]byte // Individual signatures (fallback when QTD not available)
	ValidatorCount      int      // Number of validators who attested
}

// EpochRewards tracks rewards and penalties for an epoch
type EpochRewards struct {
	Epoch              uint64
	ProposerRewards    map[int]*big.Int // validatorIdx -> reward
	AttesterRewards    map[int]*big.Int // validatorIdx -> reward
	Penalties          map[int]*big.Int // validatorIdx -> penalty
	SlashingPenalties  map[int]*big.Int // validatorIdx -> slashing penalty
	TotalRewards       *big.Int
	TotalPenalties     *big.Int
	ParticipatingStake *big.Int
	TotalStake         *big.Int
}

// deepCopy returns a deep copy of EpochRewards so callers cannot mutate internal state.
// audit-fix .
func (er *EpochRewards) deepCopy() *EpochRewards {
	result := &EpochRewards{
		Epoch:              er.Epoch,
		ProposerRewards:    make(map[int]*big.Int, len(er.ProposerRewards)),
		AttesterRewards:    make(map[int]*big.Int, len(er.AttesterRewards)),
		Penalties:          make(map[int]*big.Int, len(er.Penalties)),
		SlashingPenalties:  make(map[int]*big.Int, len(er.SlashingPenalties)),
		TotalRewards:       new(big.Int).Set(er.TotalRewards),
		TotalPenalties:     new(big.Int).Set(er.TotalPenalties),
		ParticipatingStake: new(big.Int).Set(er.ParticipatingStake),
		TotalStake:         new(big.Int).Set(er.TotalStake),
	}
	for k, v := range er.ProposerRewards {
		result.ProposerRewards[k] = new(big.Int).Set(v)
	}
	for k, v := range er.AttesterRewards {
		result.AttesterRewards[k] = new(big.Int).Set(v)
	}
	for k, v := range er.Penalties {
		result.Penalties[k] = new(big.Int).Set(v)
	}
	for k, v := range er.SlashingPenalties {
		result.SlashingPenalties[k] = new(big.Int).Set(v)
	}
	return result
}

// Attestation represents a validator's vote for a block
type Attestation struct {
	Slot            uint64                // Slot being attested
	BeaconBlockRoot types.Hash            // Block hash being voted for
	Source          AttestationCheckpoint // Last justified checkpoint
	Target          AttestationCheckpoint // Current epoch checkpoint
	ValidatorIndex  int                   // Index of attesting validator
	Signature       []byte                // Dilithium3 signature
	// F1-6 MEDIUM FIX: KeyVersion binds the attestation to a specific validator key.
	// After key rotation, attestations signed with old keys can be rejected by including
	// the key version in the signed data. Without this, an attacker with a compromised
	// retired key could forge attestations after the validator rotates to a new key.
	KeyVersion uint64
}

// AttestationCheckpoint represents a finality checkpoint for attestations
// (separate from the main Checkpoint type used for long-range attack protection)
type AttestationCheckpoint struct {
	Epoch uint64
	Root  types.Hash
}

// NewQPOS creates a new QPOS consensus engine.
// audit-fix M-1: returns error to propagate slashing config validation failures.
func NewQPOS(validators *ValidatorSet) (*QPOS, error) {
	sv, err := NewSlashingValidator(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create slashing validator: %w", err)
	}
	q := &QPOS{
		validators:              validators,
		attestations:            make(map[uint64][]*Attestation),
		aggregatedAttestations:  make(map[uint64]*AggregatedAttestation),
		validatorAttestations:   make(map[int]map[uint64]*Attestation),
		slashedValidators:       make(map[int]*SlashedEntry),
		shuffleCache:            make(map[uint64][]int),
		weightedProposerCutover: math.MaxUint64, // R102: opt-in via config
		weightedCumCache:        make(map[uint64]*weightedEpochTable),
		coldStartEpochs:         make(map[uint64]struct{}), // R45-PoA-FIX
		committeeCache:          make(map[uint64][]*Validator),
		epochRewards:            make(map[uint64]*EpochRewards),
		epochBlockRoots:         make(map[uint64]types.Hash),
		slotBlockRoots:          make(map[uint64]types.Hash),   // AUDIT (2026) GOV-05
		epochVRFAccumulator:     make(map[uint64]types.Hash),   // AUDIT (2026) R4-CORE-01
		appliedBlockRoots:       make(map[types.Hash]struct{}), // R38-P1-08 DEEP FIX
		randaoMix:               types.Hash{},
		authorizedCallers:       NewAuthorizedCallers(),
		stakeChecker:            NewStakeConsistencyChecker(),
		slashingValidator:       sv,
		slashingAuditLog:        NewSlashingAuditLog(),
		vkReg:                   newVKRegistry(), // R131
		evidenceQueue:           make([]*SlashingEvidence, 0),
		stopCh:                  make(chan struct{}),
		// R40-P0 FIX (2026-08-04): Wire the Dilithium3 verifier into the sync
		// committee manager. Without this, SubmitSyncCommitteeSignature
		// fail-closed and dropped every signature with "no verifier configured",
		// breaking light-client finality.
		syncCommitteeManager: NewSyncCommitteeManager(NewDilithiumSyncSigVerifier()),
	}
	// R33 P2-19 FIX (2026-07-28): Warn when the validator set is too small
	// for safe BFT consensus. With n=3 and a 2/3 threshold, only 2 votes
	// are needed to finalize — meaning a single Byzantine validator
	// colluding with one honest validator can finalize invalid blocks.
	// This is a known limitation of small validator sets, not a code bug.
	// The warning alerts operators that they should expand the validator
	// set for production safety. With n=4, the 2/3 threshold requires 3
	// votes, tolerating 1 Byzantine validator (the minimum for BFT safety).
	// n<=3 is allowed for dev/test networks but is risky for mainnet.
	if validators != nil {
		n := validators.ValidatorCount()
		if n < 4 {
			logging.Global().Warn("consensus: validator set size is below BFT-safe minimum",
				map[string]any{
					"validatorCount":  n,
					"minBFTSafe":      4,
					"votesToFinalize": (2*n + 2) / 3,
					"risk":            "single Byzantine validator can break consensus",
				})
		}
	}
	// P1-2 FIX: Start background evidence queue drainer. The drainer
	// periodically checks the evidence queue and submits pending evidence
	// to the slashing manager. Without this, evidence queued when
	// slashingManager is nil is never consumed (audit P1-2).
	go q.drainEvidenceQueueLoop()
	return q, nil
}

func (q *QPOS) SetChambersCoordinator(coordinator *ThreeChambersCoordinator) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.chambers = coordinator
}

func (q *QPOS) GetChambersCoordinator() *ThreeChambersCoordinator {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.chambers
}

func (q *QPOS) InitChambers() {
	// R5-P3-1 FIX: SetQTDSigner acquires qfs.mu. Calling it while holding
	// q.mu creates a lock order inversion with completeSealLocked (which
	// acquires qfs.mu then q.mu). To break the cycle, we capture the
	// pointers under q.mu, release the lock, then call SetQTDSigner
	// outside the critical section.
	var qtdFinality *QTDFinalityState
	var tssSigner ThresholdKeySigner
	func() {
		q.mu.Lock()
		defer q.mu.Unlock()
		if q.chambers == nil {
			q.chambers = NewThreeChambersCoordinator(q)
		}
		if q.qtdFinality == nil {
			q.qtdFinality = NewQTDFinalityState(q)
		}
		qtdFinality = q.qtdFinality
		tssSigner = q.tssSigner
	}()
	if qtdFinality != nil && tssSigner != nil {
		qtdFinality.SetQTDSigner(tssSigner)
	}
}

func (q *QPOS) HasChambers() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.chambers != nil
}

func (q *QPOS) CanPropose(validatorIndex int, slot uint64) bool {
	q.mu.RLock()
	chambers := q.chambers
	// audit-fix round 2 MEDIUM-3: Slashed validators must never propose,
	// even when chambers are not configured.
	if _, ok := q.slashedValidators[validatorIndex]; ok {
		q.mu.RUnlock()
		return false
	}
	// R43-CS-001 FIX: Check pending deactivation to prevent validators
	// awaiting deactivation from proposing blocks.
	if q.isPendingDeactivation(validatorIndex) {
		q.mu.RUnlock()
		return false
	}
	// P0-T2: Check Defense ministry blacklist.
	// P0-T5: Pass slot-derived consensus time for deterministic expiry check.
	if q.blacklistCheck != nil && q.blacklistCheck(validatorIndex, GetSlotStartTime(slot).Unix()) {
		q.mu.RUnlock()
		return false
	}
	daCheck := q.daAvailabilityCheck
	q.mu.RUnlock()

	// FIX (2026-07-17): CanPropose now hard-rejects blocks on DA gate failure.
	//
	// The earlier soft-check (warning + continue) favoured liveness but let
	// blocks committed while DA was unavailable reach the canonical chain.
	// FinalizeBlock does enforce a hard check, but a block that has already
	// been committed cannot be un-committed, so downstream txs and apps
	// that depended on those blocks would still be polluted.
	//
	// Fix strategy:
	//   - Production (QAU_PRODUCTION=1): CanPropose hard-rejects a parent
	//     slot whose DA is unavailable, blocking continued production while
	//     DA is down. Pairs with FinalizeBlock's check as a double gate.
	//   - Dev/test: keep the soft check (warning) so local development does
	//     not require the DA layer to be configured.
	isProduction := params.IsProductionEnv()

	if chambers == nil {
		// DA: hard-reject in production, soft-check in non-production (liveness priority).
		if daCheck != nil && slot > 0 {
			if err := daCheck(slot - 1); err != nil {
				if isProduction {
					// P3-LOG-01 FIX (R30, 2026-07-27): Use logging.Global().Warn() for SIEM collection.
					logging.Global().Warn("DA availability check failed for parent slot (PRODUCTION: hard reject)",
						map[string]any{"parentSlot": slot - 1, "currentSlot": slot, "error": err.Error()})
					return false
				}
				logging.Global().Warn("DA availability check failed for parent slot (non-blocking, liveness priority)",
					map[string]any{"parentSlot": slot - 1, "currentSlot": slot, "error": err.Error()})
			}
		}
		return true
	}
	// DA- chambers configured — same production hard reject / non-prod soft check.
	if daCheck != nil && slot > 0 {
		if err := daCheck(slot - 1); err != nil {
			if isProduction {
				logging.Global().Warn("DA availability check failed for parent slot (PRODUCTION: hard reject)",
					map[string]any{"parentSlot": slot - 1, "currentSlot": slot, "error": err.Error()})
				return false
			}
			logging.Global().Warn("DA availability check failed for parent slot (non-blocking, liveness priority)",
				map[string]any{"parentSlot": slot - 1, "currentSlot": slot, "error": err.Error()})
		}
	}
	return chambers.CanPropose(validatorIndex, slot)
}

func (q *QPOS) CanAttest(validatorIndex int, slot uint64) bool {
	q.mu.RLock()
	chambers := q.chambers
	// R42-CS-001 FIX: Slashed validators must never attest, consistent with
	// CanPropose. Previously, CanAttest completely omitted this check, allowing
	// slashed validators to continue submitting attestations that counted
	// toward finality weight, breaking Casper FFG safety.
	if _, ok := q.slashedValidators[validatorIndex]; ok {
		q.mu.RUnlock()
		return false
	}
	// R43-CS-001 FIX: Check pending deactivation to prevent validators
	// awaiting deactivation from attesting.
	if q.isPendingDeactivation(validatorIndex) {
		q.mu.RUnlock()
		return false
	}
	// P0-T2: Check Defense ministry blacklist.
	// P0-T5: Pass slot-derived consensus time for deterministic expiry check.
	if q.blacklistCheck != nil && q.blacklistCheck(validatorIndex, GetSlotStartTime(slot).Unix()) {
		q.mu.RUnlock()
		return false
	}
	q.mu.RUnlock()
	if chambers == nil {
		return true
	}
	return chambers.CanAttest(validatorIndex, slot)
}

func (q *QPOS) CanSeal(validatorIndex int, epoch uint64) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()

	// SECURITY (audit P2-): Slashed validators must not seal blocks.
	if q.slashedValidators != nil {
		if _, slashed := q.slashedValidators[validatorIndex]; slashed {
			return false
		}
	}

	// P0-T2: Check Defense ministry blacklist.
	// P0-T5: Pass epoch-derived consensus time for deterministic expiry check.
	if q.blacklistCheck != nil && q.blacklistCheck(validatorIndex, GetSlotStartTime(EpochStartSlot(epoch)).Unix()) {
		return false
	}

	chambers := q.chambers
	if chambers == nil {
		return true
	}
	return chambers.CanSeal(validatorIndex, epoch)
}
func (q *QPOS) GetQTDFinality() *QTDFinalityState {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.qtdFinality
}

func (q *QPOS) IsInstantFinalityEnabled() bool {
	q.mu.RLock()
	qf := q.qtdFinality
	q.mu.RUnlock()
	if qf == nil {
		return false
	}
	return qf.IsInstantFinality()
}

func (q *QPOS) RequestQTDFinalitySeal(slot uint64, blockHash types.Hash) error {
	q.mu.RLock()
	qf := q.qtdFinality
	q.mu.RUnlock()
	if qf == nil {
		return fmt.Errorf("QTD finality not initialized")
	}
	return qf.RequestSeal(slot, blockHash)
}

func (q *QPOS) IsSlotQTDFinalized(slot uint64) bool {
	q.mu.RLock()
	qf := q.qtdFinality
	q.mu.RUnlock()
	if qf == nil {
		return false
	}
	return qf.IsSlotFinalized(slot)
}

// SetThresholdSigner configures the QPOS engine to use threshold signing
// for block proposals and attestation votes. When nil (default), standard
// single-key Dilithium3 signing is used.
// P1-1: Also propagates the signer to QTDFinalityState so that QTD instant
// finality is activated when a threshold signer becomes available.
func (q *QPOS) SetThresholdSigner(signer ThresholdKeySigner) {
	q.mu.Lock()
	q.tssSigner = signer
	qfs := q.qtdFinality
	q.mu.Unlock()
	// P1-1: Propagate to QTD finality engine outside the lock to avoid
	// lock ordering issues (qfs.mu → qpos.mu would deadlock).
	if qfs != nil && signer != nil {
		qfs.SetQTDSigner(signer)
	}
}

// HasThresholdSigner returns true if a threshold signer is configured.
func (q *QPOS) HasThresholdSigner() bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.tssSigner != nil && q.tssSigner.IsThresholdMode()
}

// SetDAAvailabilityChecker registers a callback that checks whether a slot's
// blob data is sufficiently available in the DA layer. P1-4 (2026-07-14).
//
// When set, QPOS enforces DA availability at two points:
//  1. CanPropose: soft check on the parent slot (slot-1). If unavailable,
//     logs a warning but still allows proposing (liveness > strictness).
//  2. ThreeChambersFlow.FinalizeBlock: hard check on the current slot.
//     If unavailable, finalization is REFUSED.
//
// The callback should return nil if DA is available, or an error describing
// why it is not. When no checker is set (default), DA checks are skipped
// (DA layer not configured or node not participating in DA verification).
func (q *QPOS) SetDAAvailabilityChecker(checker func(slot uint64) error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.daAvailabilityCheck = checker
}

// CheckDAAvailability returns nil if the DA layer reports the slot's blob data
// as available, or an error if not. P1-4 (2026-07-14).
// R33 P2-21 FIX (2026-07-28): In production mode (QAU_PRODUCTION=1), fails
// closed when no checker is configured — DA verification must not be
// bypassed on mainnet. In dev/test mode, returns nil (available) for
// backward compatibility (DA verification is opt-in during development).
func (q *QPOS) CheckDAAvailability(slot uint64) error {
	q.mu.RLock()
	checker := q.daAvailabilityCheck
	q.mu.RUnlock()
	if checker == nil {
		// R33 P2-21: Fail-closed in production to prevent DA review bypass.
		if params.IsProductionEnv() {
			return fmt.Errorf("DA availability checker not configured (production mode requires DA verification)")
		}
		return nil
	}
	return checker(slot)
}

// GetGroupPublicKey returns the TSS group public key if a threshold signer is
// configured, or nil otherwise.
// P0-2 (2026-07-13): Used at epoch boundaries to complete the executive
// chamber DKG when a pre-established group key is available.
func (q *QPOS) GetGroupPublicKey() []byte {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.tssSigner == nil {
		return nil
	}
	return q.tssSigner.GroupPublicKey()
}

func (q *QPOS) SignBlock(validatorIndex int, data []byte) ([]byte, error) {
	if q.HasThresholdSigner() {
		return q.tssSigner.SignBlock(validatorIndex, data)
	}
	return nil, ErrThresholdSignerNotAvailable
}

// AggregatePartialSignatures combines collected partial signatures from
// multiple validators into a single threshold signature.
// FIX: This prevents completeSealLocked from falling back to a
// single signer, preserving the threshold security guarantee.
func (q *QPOS) AggregatePartialSignatures(sealers []int, partialSigs map[int][]byte, message []byte) ([]byte, error) {
	if q.HasThresholdSigner() {
		return q.tssSigner.AggregatePartialSignatures(sealers, partialSigs, message)
	}
	return nil, ErrThresholdSignerNotAvailable
}

// testHelpersEnabled must be set to true via EnableTestHelpers() before
// calling any test-only Reset*ForTesting functions. This prevents accidental
// use in production code, where such calls would corrupt consensus state.
// audit-fix M-1: runtime guard for test-only functions.
var testHelpersEnabled bool

// EnableTestHelpers enables test-only helper functions (Reset*ForTesting).
// MUST only be called from test code (e.g., TestMain or init in _test.go files).
func EnableTestHelpers() {
	testHelpersEnabled = true
}

// ResetGenesisTimeForTesting resets genesis time state for unit tests.
// MUST NOT be called in production code.
// audit-fix M-1: panics if EnableTestHelpers() was not called first.
//
// R8-OBS-4 (2026-07-18): The R8 audit suggested converting this panic to a
// returned error. However, this function is a test-only mutator with no
// return value, and the panic is an intentional fail-fast guard that
// prevents production misuse of test helpers. Converting to a returned
// error would require changing the signature to `ResetGenesisTimeForTesting()
// error` and updating all callers to check the error — adding complexity
// for no security benefit. The panic is the correct Go pattern for
// "function called in wrong context" violations: it fails immediately
// with a clear message rather than silently no-op'ing or propagating
// an error that callers might ignore.
//
// The guard is effective: EnableTestHelpers() is only called from _test.go
// files, so any production code that accidentally calls this function will
// panic at the call site with a message that clearly identifies the bug.
//
// R52-FROZEN-FIX-01 (2026-08-11): This function only resets the
// genesis TIME fields (time/timeSet/timeFrozen). It does NOT reset the
// genesis HASH fields. To reset those, call ResetGenesisHashForTesting
// (defined just below). Splitting the reset helpers maintains backward
// compatibility with the existing call sites that already use
// ResetGenesisTimeForTesting in their defer chain.
func ResetGenesisTimeForTesting() {
	if !testHelpersEnabled {
		panic("consensus: ResetGenesisTimeForTesting called without EnableTestHelpers(); this function is for tests only")
	}
	genesis.mu.Lock()
	defer genesis.mu.Unlock()
	genesis.time = 0
	genesis.timeSet = false
	genesis.timeFrozen = false
}

// ResetGenesisHashForTesting resets genesis HASH state (hash / hashSet /
// hashFrozen) for unit tests. MUST NOT be called in production code.
// Panics if EnableTestHelpers() was not called first.
//
// R52-FROZEN-FIX-01 (2026-08-11): TestGenesisBlockHash_Freeze previously
// left genesis.hashFrozen = true after running, which caused
// TestGenesisBlockHash to FAIL on the second invocation (and on any
// -count=N > 1 run that touched both tests in order) with the message
// "genesis block hash is frozen and cannot be changed". The new
// ResetGenesisHashForTesting allows tests that mutate the genesis hash
// state to defer-reset it, restoring test isolation.
func ResetGenesisHashForTesting() {
	if !testHelpersEnabled {
		panic("consensus: ResetGenesisHashForTesting called without EnableTestHelpers(); this function is for tests only")
	}
	genesis.mu.Lock()
	defer genesis.mu.Unlock()
	genesis.hash = types.Hash{}
	genesis.hashSet = false
	genesis.hashFrozen = false
}

// GetCurrentSlot returns the current slot based on wall clock time.
// SECURITY FIX Q-B-001: Returns 0 (no active slot) if genesis time is not set.
// This prevents consensus from operating with an uninitialized genesis time.
func (q *QPOS) GetCurrentSlot() uint64 {
	gt := GetGenesisTime()
	if gt == 0 {
		return 0
	}
	now := time.Now().Unix() // NOT consensus-critical: local slot scheduling (canonical slot from block header)
	if now < gt {
		return 0
	}
	// C21-005 FIX (R49, 2026-08-05): The R47 clamp (lastBlockTime + 17s)
	// was too aggressive — it permanently stalled the chain whenever no block
	// was produced within 17 seconds. Since SlotDuration = 12s, the slot
	// could only look ahead 1 slot. If the proposer missed its slot, the
	// chain was stuck forever.
	//
	// R49 FIX (2026-08-05): Remove the aggressive clamp entirely. Use raw
	// wall-clock time for slot computation, same as Ethereum's slot timing.
	// NTP drift protection is handled at block VALIDATION time (blocks with
	// timestamps too far in the future are rejected), not at slot COMPUTATION
	// time. This allows the produceLoop to advance through missed slots and
	// eventually reach a slot whose proposer is online.
	//
	// A warning is logged if the slot is more than 32 slots (~6.4 minutes)
	// ahead of the last block's slot, indicating possible clock drift or
	// network stall. No clamping is applied — the slot advances freely.
	lastBlockTime := atomic.LoadInt64(&q.lastKnownBlockTime)
	if lastBlockTime > 0 {
		lastBlockSlot := uint64((lastBlockTime - gt) / int64(SlotDuration.Seconds()))
		currentSlot := uint64((now - gt) / int64(SlotDuration.Seconds()))
		if currentSlot > lastBlockSlot+32 {
			logging.Global().Warn(fmt.Sprintf("GetCurrentSlot: wall-clock slot %d is %d slots ahead of last block slot %d (possible clock drift or network stall)",
				currentSlot, currentSlot-lastBlockSlot, lastBlockSlot))
		}
	}
	return uint64((now - gt) / int64(SlotDuration.Seconds())) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
}

// SetLastKnownBlockTime updates the last known block time for clock drift protection.
// C21-005 FIX: Called when a new block is processed to track network time.
// Uses atomic store for lock-free writes.
func (q *QPOS) SetLastKnownBlockTime(timestamp int64) {
	// R47-CS-06 FIX: Add retry limit to prevent infinite spin under
	// high contention. In practice this loop succeeds on the first try.
	for retries := 0; retries < 8; retries++ {
		old := atomic.LoadInt64(&q.lastKnownBlockTime)
		if timestamp <= old {
			return
		}
		if atomic.CompareAndSwapInt64(&q.lastKnownBlockTime, old, timestamp) {
			return
		}
	}
	// Log a warning if we exhausted retries (shouldn't happen in practice).
	// The timestamp update is best-effort; the next successful CAS will fix it.
}

// GetLastKnownBlockTime returns the consensus-derived block timestamp tracked
// from the most recently processed block. Returns 0 if no block has been
// processed yet (callers should fall back to time.Now().Unix() in that case).
//
// CONS-P0-02 FIX (R31, 2026-07-27): Used by SlashValidator and
// markValidatorForInvestigation as the deterministic time source for
// JailUntil computation, replacing time.Now().Unix() to prevent consensus
// divergence from node clock differences.
func (q *QPOS) GetLastKnownBlockTime() int64 {
	return atomic.LoadInt64(&q.lastKnownBlockTime)
}

// GetCurrentEpoch returns the current epoch
func (q *QPOS) GetCurrentEpoch() uint64 {
	return q.GetCurrentSlot() / SlotsPerEpoch
}

// SlotToEpoch converts a slot number to its epoch
func SlotToEpoch(slot uint64) uint64 {
	return slot / SlotsPerEpoch
}

// EpochStartSlot returns the first slot of an epoch
func EpochStartSlot(epoch uint64) uint64 {
	return epoch * SlotsPerEpoch
}

// GetSlotStartTime returns the start time of a slot
func GetSlotStartTime(slot uint64) time.Time {
	timestamp := GetGenesisTime() + int64(slot)*int64(SlotDuration.Seconds()) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	return time.Unix(timestamp, 0)
}
