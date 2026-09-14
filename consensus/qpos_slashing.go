// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"math/big"
	"time"

	"github.com/quantaureum/qau/types"
)

// SlashedEntry records why and how a validator was slashed.
//
// CONS- (2026-07-20): Previously slashedValidators was
// `map[int]uint64` (validatorIdx -> slash epoch) with no cleanup path.
// Once a validator was added — even for a temporary offense like downtime
// or invalid VRF — it stayed forever, effectively converting every
// temporary slash into a permanent ban. This struct distinguishes
// permanent bans (double_signing, surround_vote) from temporary jails
// (downtime, inactivity, invalid_vrf) and records the jail expiry so
// SlashingManager.Unjail() can clear the entry via
// QPOS.UnmarkValidatorSlashed().
type SlashedEntry struct {
	// Epoch is the consensus epoch at which the validator was slashed.
	// Used by applyEpochRewards to skip the validator during penalty
	// accounting (the stake was already reduced at slash time).
	Epoch uint64

	// Permanent is true for double_signing and surround_vote slashes.
	// These cannot be unjailed — SlashingManager.Unjail() rejects with
	// "validator is permanently slashed and cannot be unjailed".
	Permanent bool

	// JailUntil is the unix timestamp at which the temporary jail expires.
	// 0 for permanent slashes (no expiry). SlashingManager.Unjail() checks
	// int64(blockTime) >= JailUntil before clearing this entry.
	JailUntil int64
}

func (q *QPOS) checkDoubleVote(att *Attestation) error {
	validators := q.validators.Validators()
	if att.ValidatorIndex < 0 || att.ValidatorIndex >= len(validators) {
		return ErrInvalidAttestation
	}
	validatorAtts := q.validatorAttestations[att.ValidatorIndex]
	if validatorAtts == nil {
		return nil
	}

	existingAtt := validatorAtts[att.Slot]
	if existingAtt == nil {
		return nil
	}

	if existingAtt.BeaconBlockRoot != att.BeaconBlockRoot {
		// R42-CS-004 FIX: Remove variable shadowing — reuse the outer `validators`
		// variable instead of re-declaring it. The bounds check at line 13
		// already guarantees att.ValidatorIndex is valid.
		validatorAddr := validators[att.ValidatorIndex].Address
		// NOT consensus-critical: this timestamp is used only for the
		// in-memory evidence queue and local freshness validation in
		// SubmitEvidence. The consensus-critical slashing record timestamp
		// is set by SubmitEvidence's own blockTime parameter, not this
		// field.
		// R31-P2 FIX (2026-07-28): Use consensus-derived block time for
		// consistency with other slashing timestamps (CONS-P0-02). Falls
		// back to time.Now() only when no block has been processed.
		evidenceTs := q.GetLastKnownBlockTime()
		if evidenceTs == 0 {
			evidenceTs = time.Now().Unix()
		}
		evidence := &SlashingEvidence{
			Reason:        SlashingReasonDoubleVote,
			ValidatorAddr: validatorAddr,
			Height:        att.Slot,
			Timestamp:     evidenceTs,
			Vote1:         attestationToVote(existingAtt, validatorAddr),
			Vote2:         attestationToVote(att, validatorAddr),
		}
		q.queueSlashingEvidenceLocked(evidence)
		if q.slashingManager != nil {
			// FIX: Capture slashingManager in a local variable while
			// holding the lock (checkDoubleVote is called from
			// ValidateAttestation which holds q.mu). The previous code read
			// q.slashingManager INSIDE the goroutine, creating a data race
			// with concurrent SetSlashingManager calls that could set the
			// field to nil between the nil check above and the read below.
			sm := q.slashingManager
			// R34-CONS-P0-003 FIX: Capture deterministic blockTime for
			// SubmitEvidence to prevent non-deterministic slashing timestamps
			// and jailUntil divergence across nodes. Use the same consensus-
			// derived time that was used for evidence.Timestamp.
			submitBlockTime := evidenceTs
			// SECURITY FIX (R3-P0-1): Submit evidence asynchronously to prevent
			// self-deadlock. checkDoubleVote is called from ValidateAttestation
			// which holds q.mu.Lock() (write lock). SubmitEvidence internally
			// calls GetValidatorSet() which acquires q.mu.RLock() (read lock).
			// Go's sync.RWMutex does not support recursive locking, so calling
			// SubmitEvidence synchronously would self-deadlock.
			// checkSurroundVote in voting.go doesn't have this issue because
			// VotingManager uses its own mutex (vm.mu), not q.mu.
			evCopy := &SlashingEvidence{
				Reason:        evidence.Reason,
				ValidatorAddr: evidence.ValidatorAddr,
				Height:        evidence.Height,
				Timestamp:     evidence.Timestamp,
				// R5-P4-1 FIX: Deep copy Vote1/Vote2 to prevent pointer sharing
				// between the queued evidence and the goroutine's evCopy.
				Vote1: deepCopyVote(evidence.Vote1),
				Vote2: deepCopyVote(evidence.Vote2),
			}
			go func() {
				// SECURITY FIX (R4-P1-2): Add recover to prevent panic from
				// crashing the entire node. Surround vote path has this protection
				// but double vote path was missing it.
				defer func() {
					if r := recover(); r != nil {
						qposAdvLogger.Errorf("panic in SubmitEvidence goroutine (double vote): %v", r)
					}
				}()
				//  sm was captured above while holding the lock.
				if sm == nil {
					return
				}
				if _, submitErr := sm.SubmitEvidence(evCopy, getVotingSystemCaller(), submitBlockTime); submitErr != nil {
					qposAdvLogger.Errorf("failed to submit double vote evidence (queued): %v", submitErr)
				}
			}()
		}
		return ErrDoubleVote
	}

	return nil
}

func (q *QPOS) checkSurroundVote(att *Attestation) (*Attestation, error) {
	validators := q.validators.Validators()
	if att.ValidatorIndex < 0 || att.ValidatorIndex >= len(validators) {
		return nil, ErrInvalidAttestation
	}
	validatorAtts := q.validatorAttestations[att.ValidatorIndex]
	if validatorAtts == nil {
		return nil, nil
	}

	for _, existingAtt := range validatorAtts {
		// CONS- (2026-07-20) FIX: Same-epoch different-root detection
		// is a SEPARATE slashable offense from surround vote. The previous
		// code nested the same-epoch check inside the surround check
		// (which requires strict < on epochs), making the equality check
		// dead code — it could never be true when the outer condition
		// required strict inequality.
		//
		// The correct split:
		//   1. Conflicting votes: same source epoch OR same target epoch
		//      with different Roots. This is the slashable offense of
		//      voting for two different blocks at the same checkpoint.
		//   2. Surround vote: one attestation surrounds the other
		//      (strict < on both source and target). This is a separate
		//      slashable offense independent of root consistency.
		//
		// CONS- (2026-07-20) FIX: Same-epoch conflicting votes are
		// a DOUBLE-VOTE offense, not a SurroundVote offense. Casper FFG
		// defines:
		//   - DoubleVote: two votes with the same target epoch but
		//     different target hashes (or same source epoch with
		//     different source hashes — these are equivalent slashing
		//     conditions at the source checkpoint).
		//   - SurroundVote: source1 < source2 < target2 < target1
		//     (strict inequality on both ends).
		// Previously these conflicting-vote cases returned ErrSurroundVote,
		// causing the caller (validator.go) to use SlashingReasonSurroundVote
		// in the evidence. This is semantically wrong:
		//   - SlashingReasonDoubleVote and SlashingReasonSurroundVote map
		//     to different offense categories in SlashingManager and
		//     MinistryRevenue (different penalty multipliers, different
		//     accounting columns).
		//   - Audit logs and metrics group by reason — mixing the two
		//     obscured the true distribution of slashable offenses.
		//   - Evidence verification (VerifySurroundVoteEvidence) expects
		//     strict < on both epochs; passing a same-epoch case through
		//     that verifier would fail in confusing ways.
		// Fix: return ErrDoubleVote for same-epoch conflicts; only the
		// strict-surround cases continue to return ErrSurroundVote. The
		// caller in validator.go inspects the error to choose the right
		// SlashingReason for the evidence.
		if att.Source.Epoch == existingAtt.Source.Epoch &&
			att.Source.Root != existingAtt.Source.Root {
			// Same source epoch, different source root — double vote
			// on the source checkpoint.
			return existingAtt, ErrDoubleVote
		}
		if att.Target.Epoch == existingAtt.Target.Epoch &&
			att.Target.Root != existingAtt.Target.Root {
			// Same target epoch, different target root — double vote
			// on the target checkpoint (canonical Casper FFG double vote).
			return existingAtt, ErrDoubleVote
		}

		// Surround vote: existing surrounds new attestation.
		if att.Source.Epoch < existingAtt.Source.Epoch &&
			existingAtt.Target.Epoch < att.Target.Epoch {
			return existingAtt, ErrSurroundVote
		}
		// Surround vote: new attestation surrounds existing.
		if existingAtt.Source.Epoch < att.Source.Epoch &&
			att.Target.Epoch < existingAtt.Target.Epoch {
			return existingAtt, ErrSurroundVote
		}
	}

	return nil, nil
}

func attestationToVote(att *Attestation, validatorAddr types.Address) *Vote {
	if att == nil {
		return nil
	}
	// CONS- (2026-07-19) FIX: Preserve Source.Root / Target.Root,
	// KeyVersion, and ValidatorIndex so that:
	//
	//   1. VerifySurroundVoteEvidence can re-derive the exact signed
	//      payload (buildAttestationMessage) and cryptographically verify
	//      att.Signature via Vote.Verify(pubKey). Previously Root was
	//      dropped, so the signature could never be re-verified against
	//      the real attestation payload — slashing was effectively
	//      unenforceable.
	//   2. voteToAttestation can restore the full Attestation with
	//      canonical Roots when syncing votes through the VotingManager
	//      path (syncVoteToAttestations), so QPOS.validatorAttestations
	//      always carries real chain history — preventing attackers from
	//      later constructing fake slashing evidence with attacker-chosen
	//      Roots.
	return &Vote{
		Type:           VoteTypeAttestation,
		Height:         att.Slot,
		Round:          0,
		BlockHash:      att.BeaconBlockRoot,
		ValidatorAddr:  validatorAddr,
		Signature:      att.Signature,
		SourceEpoch:    att.Source.Epoch,
		TargetEpoch:    att.Target.Epoch,
		SourceRoot:     att.Source.Root,
		TargetRoot:     att.Target.Root,
		KeyVersion:     att.KeyVersion,
		ValidatorIndex: att.ValidatorIndex,
	}
}

// voteToAttestation converts a Vote back to an Attestation for syncing into
// QPOS.validatorAttestations. Only attestation-type votes carry enough data
// for a meaningful conversion; other vote types are skipped.
func voteToAttestation(vote *Vote) *Attestation {
	if vote == nil || vote.Type != VoteTypeAttestation {
		return nil
	}
	// CONS- (2026-07-19) FIX: Round-trip Root / KeyVersion /
	// ValidatorIndex so that votes arriving via the VotingManager path
	// (syncVoteToAttestations) populate QPOS.validatorAttestations with
	// the same canonical Roots that ProcessAttestation would have stored.
	// Without this, surround-vote and double-vote detection in
	// checkSurroundVote / checkDoubleVote could be bypassed by routing
	// votes through the VotingManager.
	return &Attestation{
		Slot:            vote.Height,
		BeaconBlockRoot: vote.BlockHash,
		Source: AttestationCheckpoint{
			Epoch: vote.SourceEpoch,
			Root:  vote.SourceRoot,
		},
		Target: AttestationCheckpoint{
			Epoch: vote.TargetEpoch,
			Root:  vote.TargetRoot,
		},
		Signature:      vote.Signature,
		KeyVersion:     vote.KeyVersion,
		ValidatorIndex: vote.ValidatorIndex,
	}
}

// syncVoteToAttestations syncs an accepted vote into QPOS.validatorAttestations.
// DATA FLOW: VotingManager.AddVote → syncVoteToAttestations → validatorAttestations.
// This keeps the Attestation-level data source consistent when votes arrive
// through the VotingManager path (instead of ProcessAttestation).
// This method acquires q.mu internally; caller MUST NOT hold q.mu.
func (q *QPOS) syncVoteToAttestations(vote *Vote, validatorIndex int) {
	if vote == nil || vote.Type != VoteTypeAttestation {
		return
	}
	if validatorIndex < 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.validatorAttestations[validatorIndex] == nil {
		q.validatorAttestations[validatorIndex] = make(map[uint64]*Attestation)
	}
	att := voteToAttestation(vote)
	if att != nil {
		q.validatorAttestations[validatorIndex][vote.Height] = att
	}
}

// audit-remediation: reviewed 2026-09-11 — queues evidence for the SlashingManager to re-validate; no penalty applied here.
func (q *QPOS) queueSlashingEvidence(evidence *SlashingEvidence) {
	if evidence == nil {
		return
	}
	// R5-P3-4 FIX: Acquire q.mu before calling the Locked variant.
	// queueSlashingEvidenceLocked accesses q.evidenceQueue without
	// synchronization, requiring the caller to hold q.mu.
	q.mu.Lock()
	defer q.mu.Unlock()
	q.queueSlashingEvidenceLocked(evidence)
}

// MaxEvidencePerValidator bounds the number of queued entries any single
// validator may have in q.evidenceQueue at one time. Without this cap, an
// attacker could submit a stream of conflicting attestations to trigger
// many internal double-vote detections for the same validator, fill the
// queue, and evict legitimate evidence for OTHER validators via FIFO.
// Setting the cap to 32 lets a heavily-misbehaving validator retain enough
// evidence to support appeal/audit while preserving queue slots for other
// validators' real evidence.
const MaxEvidencePerValidator = 32

// queueSlashingEvidenceLocked adds evidence without acquiring the mutex.
// Caller MUST hold q.mu before calling this.
//
// CONS- (2026-07-20): The previous implementation used naive FIFO
// eviction when the queue was full. An attacker could trigger many internal
// slashing detections (e.g., by broadcasting conflicting attestations) to
// fill the queue with junk evidence for one validator and push out real
// double-sign evidence for other validators. The fix adds three defenses:
//
//  1. Basic validation: reject evidence with zero validator address,
//     invalid reason, or nil Vote1/Vote2 (when the reason requires them).
//     This prevents obviously-malformed entries from consuming queue slots.
//
//  2. Per-validator cap (MaxEvidencePerValidator): when the validator
//     already has >= 32 entries in the queue, the new entry is dropped
//     instead of evicting a global entry. This bounds the queue space any
//     single validator can consume.
//
//  3. Validator-scoped FIFO eviction: when the global cap is reached and
//     the validator's own entries exist in the queue, evict the OLDEST
//     entry from the SAME validator (preserving evidence for other
//     validators). Only when the new validator has no prior entries do we
//     fall back to global FIFO eviction.
//
// audit-remediation: reviewed 2026-09-11 — evidence queueing with per-sender bounded eviction (CONS-FIX);
// the penalty itself is applied only after SlashingManager re-validation.
func (q *QPOS) queueSlashingEvidenceLocked(evidence *SlashingEvidence) {
	if evidence == nil {
		return
	}

	// (1) Basic validation: reject obviously-invalid evidence so it cannot
	// consume queue slots. These checks mirror the structure of
	// SlashingManager.VerifyEvidence but are intentionally lighter (full
	// verification happens in SubmitEvidence).
	if evidence.ValidatorAddr == (types.Address{}) {
		qposAdvLogger.Warnf("queueSlashingEvidenceLocked: rejected evidence with zero validator address (reason=%s)", evidence.Reason)
		return
	}
	switch evidence.Reason {
	case SlashingReasonDoubleSigning, SlashingReasonSurroundVote, SlashingReasonDoubleVote:
		// These reasons cryptographically require two conflicting votes.
		if evidence.Vote1 == nil || evidence.Vote2 == nil {
			qposAdvLogger.Warnf("queueSlashingEvidenceLocked: rejected %s evidence with missing Vote1/Vote2 for validator=%s",
				evidence.Reason, evidence.ValidatorAddr.String())
			return
		}
	case SlashingReasonDowntime, SlashingReasonInvalidVRF:
		// These reasons do not require Vote1/Vote2.
	default:
		qposAdvLogger.Warnf("queueSlashingEvidenceLocked: rejected evidence with unknown reason=%d", evidence.Reason)
		return
	}

	// (2) Per-validator cap. If the validator already has MaxEvidencePerValidator
	// entries in the queue, drop the new entry instead of accepting it.
	// SubmitEvidence will still process the offense (the queue is only a
	// backup for broadcast/persistence failures), so dropping here does not
	// let the validator escape slashing.
	validatorCount := 0
	for _, ev := range q.evidenceQueue {
		if ev.ValidatorAddr == evidence.ValidatorAddr {
			validatorCount++
		}
	}
	if validatorCount >= MaxEvidencePerValidator {
		qposAdvLogger.Warnf("queueSlashingEvidenceLocked: per-validator cap reached (%d/%d) for validator=%s reason=%s — dropping new entry",
			validatorCount, MaxEvidencePerValidator, evidence.ValidatorAddr.String(), evidence.Reason)
		return
	}

	// (3) Global cap with validator-scoped eviction. When the queue is full,
	// prefer to evict the OLDEST entry from the SAME validator (preserving
	// evidence for other validators). If the new validator has no prior
	// entries in the queue, REJECT the new entry instead of evicting an
	// existing one.
	//
	// CONS- (2026-07-20) FIX: The previous implementation used global
	// FIFO eviction as a fallback when the queue was full and the new
	// validator had no prior entries. An attacker controlling many validators
	// could each submit one junk evidence (passing basic validation) to
	// fill the queue and evict honest validators' real evidence via global
	// FIFO. The fix replaces the global FIFO fallback with a rejection:
	// existing evidence is protected, new evidence from a fresh validator
	// is dropped (with an error log) when the queue is full.
	//
	// Rationale: the queue is only a backup for slashingManager
	// unavailability. Real slashable offenses propagate through P2P gossip
	// and are submitted directly to slashingManager when available. Rejecting
	// a queued backup entry does NOT let the offender escape slashing —
	// other nodes will still process the evidence when their slashingManager
	// is available.
	if len(q.evidenceQueue) >= MaxEvidenceQueue {
		evictIdx := -1
		for i, ev := range q.evidenceQueue {
			if ev.ValidatorAddr == evidence.ValidatorAddr {
				evictIdx = i
				break
			}
		}
		if evictIdx >= 0 {
			// Validator-scoped eviction: drop oldest entry from same validator.
			// audit-remediation: reviewed 2026-09-11 — len()/MaxEvidenceQueue are
			// bounded queue metrics (cap 10_000), not economic values.
			qposAdvLogger.Errorf("Slashing evidence queue overflow (%d entries, max %d) — evicted oldest entry from same validator=%s reason=%s",
				len(q.evidenceQueue), MaxEvidenceQueue, evidence.ValidatorAddr.String(), evidence.Reason)
			q.evidenceQueue = append(q.evidenceQueue[:evictIdx], q.evidenceQueue[evictIdx+1:]...)
		} else {
			// CONS-FIX: No prior entries for this validator.
			// Reject new evidence to protect existing entries (previously
			// this branch evicted the oldest entry via global FIFO, enabling
			// the multi-validator eviction attack described above).
			qposAdvLogger.Errorf("Slashing evidence queue overflow (%d entries, max %d) — rejecting new evidence from validator=%s reason=%s (no prior entries; existing evidence protected)",
				len(q.evidenceQueue), MaxEvidenceQueue, evidence.ValidatorAddr.String(), evidence.Reason)
			return
		}
	}
	q.evidenceQueue = append(q.evidenceQueue, evidence)

	// audit-remediation: reviewed 2026-09-11 — len()/cap arithmetic against
	// the MaxEvidenceQueue constant (10_000); no economic values involved.
	// P3-3: Warn when queue is > 80% full (approaching overflow).
	if len(q.evidenceQueue) >= MaxEvidenceQueue*4/5 {
		qposAdvLogger.Warnf("Slashing evidence queue at %d/%d (%.0f%% capacity) — broadcast may be slow",
			len(q.evidenceQueue), MaxEvidenceQueue, float64(len(q.evidenceQueue))/float64(MaxEvidenceQueue)*100)
	}
}

func (q *QPOS) GetQueuedEvidence() []*SlashingEvidence {
	q.mu.Lock()
	defer q.mu.Unlock()
	queue := q.evidenceQueue
	q.evidenceQueue = make([]*SlashingEvidence, 0)
	return queue
}

// GetEvidenceQueueLength returns the current slashing evidence queue depth
// without draining it. P3-3 (2026-07-15): Used by the Three Chambers metric
// provider to surface evidence backlog for alerting. Unlike GetQueuedEvidence,
// this is a non-destructive read safe to call from monitoring paths.
func (q *QPOS) GetEvidenceQueueLength() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.evidenceQueue)
}

func (q *QPOS) SlashValidator(validatorIndex int, reason string, caller types.Address) error {
	// SECURITY (audit 2026-06-24, M-1): Fail-closed when no authorized callers
	// are configured, instead of allowing all callers.
	if q.authorizedCallers == nil {
		return ErrUnauthorizedOperation
	}
	if !q.authorizedCallers.IsAuthorized(caller) && !q.authorizedCallers.IsGovernance(caller) {
		return ErrUnauthorizedOperation
	}

	// CONS-P0-04 FIX (R31, 2026-07-27): Capture slashing event data in a
	// local variable and defer the LogSlashing call to run AFTER the q.mu
	// lock is released. Previously LogSlashing was invoked while holding
	// q.mu write lock, risking lock-ordering inversions and blocking the
	// consensus critical path if LogSlashing performs IO or acquires other
	// locks. The defer runs after the deferred q.mu.Unlock().
	var pendingAuditEvent *SlashingEvent
	defer func() {
		if pendingAuditEvent != nil && q.slashingAuditLog != nil {
			q.slashingAuditLog.LogSlashing(pendingAuditEvent)
		}
	}()

	q.mu.Lock()
	defer q.mu.Unlock()

	if validatorIndex < 0 || validatorIndex >= q.validators.Size() {
		return ErrInvalidAttestation
	}

	if _, slashed := q.slashedValidators[validatorIndex]; slashed {
		return ErrValidatorSlashed
	}

	validators := q.validators.Validators()
	validator := validators[validatorIndex]

	var slashReason SlashReason
	switch reason {
	case "double_vote":
		slashReason = SlashReasonDoubleVote
	case "surround_vote":
		slashReason = SlashReasonSurroundVote
	case "inactivity":
		slashReason = SlashReasonInactivity
	case "proposer_missed":
		slashReason = SlashReasonProposerMissed
	// CONS- (2026-07-20): Map the SlashingManager SlashingReason string
	// forms to the closest penalty-calculator bucket. Previously these were
	// missing, so callers passing "double_signing", "downtime", or
	// "invalid_vrf" silently fell through to SlashReasonUnknown, triggering
	// the wrong penalty calculation path.
	case "double_signing":
		// Double-signing at same height is semantically equivalent to a
		// double vote (both are equivocation at the same slot/height).
		slashReason = SlashReasonDoubleVote
	case "downtime":
		// P3-CONS-002 NOTE (R30, 2026-07-27): Downtime threshold guard.
		//
		// SlashValidator is the EXECUTION layer — it trusts that the caller
		// (governance or authorized system caller, see authorization check at
		// the top of this function) has already verified the inactivity score
		// threshold. The DETECTION layer enforces the threshold:
		//
		//   - SlashingManager.checkDowntimeLocked (slashing.go:1520) only
		//     generates SlashingEvidence when missedBlocksCounter >=
		//     sm.params.DowntimeThreshold (DefaultDowntimeThreshold=100).
		//   - SlashingManager.VerifyDowntimeEvidence (slashing.go:1688)
		//     re-checks evidence.MissedBlocks >= DowntimeThreshold before
		//     the evidence is accepted by SubmitEvidence.
		//   - HandleBlockFinalized iterates active validators and calls
		//     checkDowntimeLocked per validator, so no validator is slashed
		//     for downtime below the threshold.
		//
		// We do NOT re-check the threshold here because (a) SlashValidator
		// has no access to SlashingManager.signingInfo / MissedBlocksCounter,
		// (b) it would duplicate the detection-layer check, and (c) governance
		// must retain the ability to slash a validator manually (e.g. for
		// consensus-protocol violations that don't surface as missed blocks).
		//
		// R30-IMPLEMENT (2026-07-27): SLASH-H2 — Downtime is a DISTINCT offense
		// from inactivity. It carries a 10x higher penalty (1% vs 0.1%) to
		// reflect the greater harm to consensus liveness. Previously mapped to
		// SlashReasonInactivity, causing a 10x penalty discrepancy vs
		// SlashingManager.slashLocked which used its own DowntimePenalty rate.
		slashReason = SlashReasonDowntime
	case "invalid_vrf":
		// Invalid VRF proofs have no direct penalty equivalent — apply the
		// minimum penalty bucket (SlashReasonUnknown uses MinPenaltyPercent).
		slashReason = SlashReasonUnknown
	default:
		// CONS- Fail-closed. Reject unrecognized reason strings instead
		// of silently using SlashReasonUnknown — an attacker or buggy caller
		// could otherwise trigger an unintended penalty path.
		return fmt.Errorf("%w: got %q", ErrInvalidSlashReason, reason)
	}

	var penalty *big.Int
	if q.slashingValidator != nil && validator.Stake != nil {
		var err error
		penalty, err = q.slashingValidator.CalculatePenalty(validator.Stake, slashReason)
		if err != nil {
			return err
		}

		if err := q.slashingValidator.ValidatePenaltyAmount(penalty, validator.Stake); err != nil {
			return err
		}

		if q.stakeChecker != nil {
			// Verify total stake consistency BEFORE applying penalty.
			// The validators copy has original stakes; VerifyTotalStake
			// checks that the sum matches the validator set's total.
			// The actual stake reduction is done by ReduceStake below.
			// Previously, this code modified the local copy's Stake field
			// to simulate the post-penalty state, but that was fragile -- if
			// Validators() ever returned references instead of copies, it
			// would cause double slashing.
			currentTotal := q.validators.TotalStake()
			if err := q.stakeChecker.VerifyTotalStake(validators, currentTotal); err != nil {
				return err
			}
		}
	}

	if penalty != nil && penalty.Sign() > 0 {
		if !q.validators.ReduceStake(validatorIndex, penalty) {
			return fmt.Errorf("failed to reduce stake for validator %d", validatorIndex)
		}
	}

	q.validators.DeactivateValidator(validatorIndex)

	currentEpoch := q.GetCurrentEpoch()
	// CONS- (2026-07-20): Record whether this is a permanent ban
	// (double_vote, surround_vote) or a temporary jail (inactivity,
	// proposer_missed, unknown/invalid_vrf, downtime). Permanent bans
	// cannot be unjailed; temporary jails can be cleared via
	// SlashingManager.Unjail() → QPOS.UnmarkValidatorSlashed().
	//
	// The reason string was mapped to slashReason above. The QPOS-direct
	// SlashValidator path uses q.jailDuration (propagated from
	// SlashingManager.params.JailDuration via SetSlashingManager, or set
	// directly via SetJailDuration) for temporary slashes. This ensures
	// both slash paths (QPOS.SlashValidator and SlashingManager.slashLocked)
	// produce the same JailUntil for the same offense (SLASH-H2 fix).
	// If q.jailDuration is 0 (standalone QPOS without SlashingManager),
	// fall back to DefaultJailDuration (1 hour) for backward compatibility.
	permanent := slashReason == SlashReasonDoubleVote || slashReason == SlashReasonSurroundVote
	var jailUntil int64
	if !permanent {
		// R30-IMPLEMENT (2026-07-27): SLASH-H2 — use configured jailDuration.
		jd := q.jailDuration
		if jd == 0 {
			jd = DefaultJailDuration
		}
		// CONS-P0-02 FIX (R31, 2026-07-27): Use consensus-derived block
		// time from lastKnownBlockTime instead of time.Now().Unix().
		// Different nodes' wall clocks would compute different JailUntil
		// values, causing one node to consider the validator unjailed
		// while another still considers it jailed → consensus divergence.
		// Fall back to time.Now().Unix() only when no block has been
		// processed yet (tests / startup).
		now := q.GetLastKnownBlockTime()
		if now == 0 {
			now = time.Now().Unix()
		}
		jailUntil = now + jd
	}
	q.slashedValidators[validatorIndex] = &SlashedEntry{
		Epoch:     currentEpoch,
		Permanent: permanent,
		JailUntil: jailUntil,
	}

	// Clean up investigation count entry to prevent unbounded map growth.
	// The validator is now slashed and cannot be investigated again.
	delete(q.investigationCounts, validator.Address)

	// CONS-P0-04 FIX (R31, 2026-07-27): Capture event for deferred
	// LogSlashing (runs after q.mu is released). The Timestamp field
	// uses lastKnownBlockTime for consistency with JailUntil; the audit
	// log entry is local in-memory tracking, but using consensus time
	// here as well keeps the audit log deterministic across nodes.
	if q.slashingAuditLog != nil {
		auditTimestamp := q.GetLastKnownBlockTime()
		if auditTimestamp == 0 {
			auditTimestamp = time.Now().Unix()
		}
		pendingAuditEvent = &SlashingEvent{
			ValidatorIndex: validatorIndex,
			ValidatorAddr:  validator.Address,
			Reason:         slashReason,
			PenaltyAmount:  penalty,
			Epoch:          currentEpoch,
			Slot:           q.currentSlot,
			Timestamp:      auditTimestamp,
		}
	}

	// SECURITY FIX (audit S-6): Do NOT call slashingManager.SubmitEvidence here.
	// QPOS.SlashValidator already reduced stake and deactivated the validator above.
	// Calling SubmitEvidence would trigger SlashingManager.slash() which reduces
	// stake AGAIN — causing double slashing. The evidence is already logged via
	// slashingAuditLog above. Broadcasting to other nodes should be done via a
	// separate broadcast mechanism that does NOT trigger local slashing.
	//
	// SECURITY FIX (R2 P0-1 reverse sync): SlashingManager.SubmitEvidence now
	// checks QPOS.IsSlashed() before calling slash(), so if the same evidence is
	// later submitted externally, it will detect the QPOS slashing and record
	// the offense only (without reducing stake again).
	// SECURITY FIX (L14-015): Always emit a log entry when a validator is slashed,
	// regardless of whether slashingManager is configured. Previously the log only
	// fired when q.slashingManager != nil, so a standalone QPOS instance with no
	// SlashingManager would slash silently — making auditing impossible.
	penaltyStr := "0"
	if penalty != nil {
		penaltyStr = penalty.String()
	}
	qposAdvLogger.Warnf("validator %d (addr=%x) slashed by QPOS (reason=%s, penalty=%s, epoch=%d, slot=%d)",
		validatorIndex, validator.Address, reason, penaltyStr, currentEpoch, q.currentSlot)

	if q.slashingManager != nil {
		qposAdvLogger.Warnf("validator %d slashed by QPOS (reason=%s, penalty=%s) — evidence logged, SlashingManager.SubmitEvidence skipped to prevent double slashing",
			validatorIndex, reason, penalty.String())
	}

	return nil
}

func (q *QPOS) GetSlashingAuditLog() *SlashingAuditLog {
	return q.slashingAuditLog
}

// MarkValidatorSlashedByAddress marks a validator as slashed in QPOS's internal
// state WITHOUT reducing stake. This is called by SlashingManager after it has
// already reduced the stake, to ensure QPOS's slashedValidators map is updated.
//
// SECURITY FIX (R2 P0-1): R22-C1 removed QPOS.SlashValidator() call from
// SlashingManager.slash() to prevent double slashing, and S-6 removed
// SubmitEvidence() call from QPOS.SlashValidator() for the same reason.
// Together, these fixes cut off ALL update paths to slashedValidators map
// when slashing was initiated via SlashingManager. This method restores the
// sync: SlashingManager calls it after slashing to update QPOS state.
//
// CONS-FIX: on success, also clear pendingDeactivationAddrs[addr].
// SlashingManager sets pendingDeactivationAddrs when SetActive fails as a
// short-term defense so CanPropose/CanAttest reject the validator. Once
// MarkValidatorSlashedByAddress succeeds the validator is now in
// slashedValidators (until CONS- unjail path clears it for
// temporary slashes), so the pending entry is stale and should be removed
// to keep the map bounded.
//
// CONS- (2026-07-20): Added `permanent` and `jailUntil` parameters
// to distinguish permanent bans (double_signing, surround_vote) from
// temporary jails (downtime, inactivity, invalid_vrf). SlashingManager.slash()
// computes these from the evidence.Reason and its params.JailDuration. The
// caller MUST pass consistent values — a false `permanent` with jailUntil=0
// would create a slash entry that can be unjailed immediately (effectively
// no jail), and a true `permanent` with jailUntil>0 would be ignored (the
// Unjail path rejects permanently-slashed validators regardless of JailUntil).
//
// This method is safe to call from a goroutine (does not hold any locks on entry).
// audit-remediation: reviewed 2026-09-11 — status flag for fork choice; actual penalty goes through SlashingManager.
func (q *QPOS) MarkValidatorSlashedByAddress(addr types.Address, permanent bool, jailUntil int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	index := q.validators.GetValidatorIndex(addr)
	if index < 0 {
		return fmt.Errorf("validator %x not found in validator set", addr[:8])
	}

	// Check if already marked — no-op if already slashed
	if existing, slashed := q.slashedValidators[index]; slashed {
		// CONS- If the existing entry is permanent, keep it — a
		// later temporary slash must NOT downgrade a permanent ban. This
		// prevents an attacker from exploiting a stale temporary evidence
		// to clear a permanent ban via Unjail.
		if existing.Permanent {
			if q.pendingDeactivationAddrs != nil {
				delete(q.pendingDeactivationAddrs, addr)
			}
			return nil
		}
		// Existing entry is temporary. If the new slash is permanent,
		// upgrade the entry to permanent (the validator committed a
		// second, more serious offense). Otherwise refresh the JailUntil
		// to the later of the two.
		if permanent {
			existing.Permanent = true
			existing.JailUntil = 0
		} else if jailUntil > existing.JailUntil {
			existing.JailUntil = jailUntil
		}
		existing.Epoch = q.GetCurrentEpoch()
		if q.pendingDeactivationAddrs != nil {
			delete(q.pendingDeactivationAddrs, addr)
		}
		return nil
	}

	// Mark as slashed (DO NOT reduce stake — SlashingManager already did)
	currentEpoch := q.GetCurrentEpoch()
	q.slashedValidators[index] = &SlashedEntry{
		Epoch:     currentEpoch,
		Permanent: permanent,
		JailUntil: jailUntil,
	}

	// Deactivate the validator in the validator set
	q.validators.DeactivateValidator(index)

	// CONS-FIX: clear the pending deactivation marker now that the
	// validator is properly in slashedValidators.
	if q.pendingDeactivationAddrs != nil {
		delete(q.pendingDeactivationAddrs, addr)
	}

	qposAdvLogger.Warnf("validator %d (%x) marked as slashed via SlashingManager sync (epoch %d, permanent=%v, jailUntil=%d) — stake NOT reduced (already done by SlashingManager)",
		index, addr[:8], currentEpoch, permanent, jailUntil)

	return nil
}

// UnmarkValidatorSlashed clears a validator's slashed status in QPOS. This is
// called by SlashingManager.Unjail() after the validator's jail period has
// expired and the validator has been reactivated in ValidatorManager.
//
// CONS- (2026-07-20): Previously there was no unmark path — once a
// validator was added to slashedValidators it stayed forever, even after
// Unjail reactivated it in ValidatorManager. This caused CanPropose/CanAttest/
// CanSeal to keep returning false forever (since they check slashedValidators
// first), effectively converting every temporary slash into a permanent ban.
//
// Safety:
//   - Permanent slashes CANNOT be unmarked — returns ErrValidatorPermanent.
//     SlashingManager.Unjail() already rejects permanent slashes upstream,
//     but this is a defense-in-depth check in case a future caller forgets.
//   - The validator is identified by address (not index) to handle the case
//     where the validator set has been reshuffled since the slash.
//
// This method is safe to call from a goroutine (does not hold any locks on entry).
// audit-remediation: reviewed 2026-09-11 — status flag for fork choice; does not touch stake.
func (q *QPOS) UnmarkValidatorSlashed(addr types.Address) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	index := q.validators.GetValidatorIndex(addr)
	if index < 0 {
		// Validator is no longer in the active set (may have exited).
		// CONS- (2026-07-21) FIX: Clear any stale pending deactivation
		// entry for this address — the validator is gone, there's nothing to
		// block, and leaving the entry would cause isPendingDeactivation to
		// match against a future validator that happens to occupy the same
		// slot (unlikely but possible after a validator set reshuffle).
		if q.pendingDeactivationAddrs != nil {
			delete(q.pendingDeactivationAddrs, addr)
		}
		return nil
	}

	entry, slashed := q.slashedValidators[index]
	if !slashed {
		// Not slashed — nothing to do. Return success (idempotent).
		// CONS- (2026-07-21) FIX: Also clear stale pending entry.
		if q.pendingDeactivationAddrs != nil {
			delete(q.pendingDeactivationAddrs, addr)
		}
		return nil
	}

	if entry.Permanent {
		return ErrValidatorPermanent
	}

	// Clear the entry. The validator is now allowed to propose/attest/seal
	// (subject to the other checks in CanPropose/CanAttest/CanSeal).
	delete(q.slashedValidators, index)

	// CONS- (2026-07-21) FIX: Clear pendingDeactivationAddrs on
	// successful unmark. Previously this path did NOT clear the pending
	// entry, so a validator that was unjailed could still be permanently
	// blocked by a stale pendingDeactivationAddrs entry set during the
	// original slash (MarkPendingDeactivationAddr is called inline in
	// SlashingManager.slash() before the async MarkValidatorSlashedByAddress
	// runs). A temporary DB error causing MarkValidatorSlashedByAddress to
	// fail then succeed later, followed by Unjail, would leave the validator
	// banned forever despite completing their jail sentence.
	if q.pendingDeactivationAddrs != nil {
		delete(q.pendingDeactivationAddrs, addr)
	}

	qposAdvLogger.Warnf("validator %d (%x) unmarked from slashedValidators (was jailed at epoch %d until %d) — reactivated via Unjail",
		index, addr[:8], entry.Epoch, entry.JailUntil)

	return nil
}

// CleanupValidatorState removes ALL residual QPOS state for a validator that
// has been fully withdrawn from ValidatorManager. This is the cleanup method
// invoked by the onValidatorRemoved callback registered in node.go.
//
// R30-IMPLEMENT (2026-07-27): SLASH-H1 fix. Previously, WithdrawStake only
// deleted the validator from ValidatorManager.validators, leaving residual
// entries in QPOS.slashedValidators, QPOS.pendingDeactivationAddrs, and
// ValidatorSet. These stale entries caused unbounded memory growth and
// could block re-registration of the same address. This method cleans up
// ALL residual QPOS state for the given address.
//
// Unlike UnmarkValidatorSlashed, this method removes the entry even if it
// is Permanent (the validator is being fully withdrawn, not unjailed). It
// is idempotent — calling it on an address with no residual state is a no-op.
func (q *QPOS) CleanupValidatorState(addr types.Address) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Remove from slashedValidators (keyed by validator index).
	index := q.validators.GetValidatorIndex(addr)
	if index >= 0 {
		delete(q.slashedValidators, index)
	}

	// Remove from pendingDeactivationAddrs (keyed by address).
	if q.pendingDeactivationAddrs != nil {
		delete(q.pendingDeactivationAddrs, addr)
	}
}

// MarkPendingDeactivationAddr marks a validator as pending deactivation in
// QPOS's internal state. This is called by SlashingManager when SetActive
// fails, so CanPropose/CanAttest can immediately reject this validator.
// R43-CS-001 FIX: Previously, PendingDeactivation was only set on
// ValidatorManager, which CanPropose/CanAttest do not consult.
func (q *QPOS) MarkPendingDeactivationAddr(addr types.Address) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.pendingDeactivationAddrs == nil {
		q.pendingDeactivationAddrs = make(map[types.Address]bool)
	}
	q.pendingDeactivationAddrs[addr] = true
}

// isPendingDeactivation checks if a validator (by index) is pending
// deactivation. Caller must hold q.mu (read or write).
func (q *QPOS) isPendingDeactivation(validatorIndex int) bool {
	if q.pendingDeactivationAddrs == nil || len(q.pendingDeactivationAddrs) == 0 {
		return false
	}
	v := q.validators.GetValidatorByIndex(validatorIndex)
	if v == nil {
		return false
	}
	return q.pendingDeactivationAddrs[v.Address]
}

// CleanupStalePendingDeactivation sweeps pendingDeactivationAddrs and removes
// entries for addresses that are already in slashedValidators (redundant —
// CanPropose/CanAttest check slashedValidators first and return false) or are
// no longer present in the validator set (orphaned).
//
// CONS- (2026-07-21): Added to close the cleanup gap. Previously
// pendingDeactivationAddrs only had an add path (MarkPendingDeactivationAddr)
// and relied solely on MarkValidatorSlashedByAddress/UnmarkValidatorSlashed
// to remove entries. If those paths failed (e.g., validator not found due to
// temporary DB error), entries would accumulate indefinitely.
//
// SAFETY: This method does NOT remove entries for addresses that are in the
// validator set but NOT in slashedValidators. Such entries represent either
// (a) validators actively being slashed (MarkPendingDeactivationAddr called
// inline, MarkValidatorSlashedByAddress pending in async goroutine) — removing
// them would prematurely unblock malicious validators, or (b) validators that
// were unjailed — which is handled by UnmarkValidatorSlashed clearing the
// entry directly. The sweep here is strictly for orphaned/redundant entries.
//
// This method is called periodically from SyncPendingSlashes (every 10s).
func (q *QPOS) CleanupStalePendingDeactivation() {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.pendingDeactivationAddrs == nil || len(q.pendingDeactivationAddrs) == 0 {
		return
	}

	for addr := range q.pendingDeactivationAddrs {
		idx := q.validators.GetValidatorIndex(addr)
		if idx < 0 {
			// Address not in validator set — orphaned entry, safe to remove.
			// The validator can't propose/attest anyway (not in the set),
			// and isPendingDeactivation looks up by index→address so this
			// entry wouldn't match any active validator.
			delete(q.pendingDeactivationAddrs, addr)
			continue
		}
		if _, slashed := q.slashedValidators[idx]; slashed {
			// Already in slashedValidators — pending entry is redundant,
			// CanPropose/CanAttest already return false from the slashed check
			// before reaching isPendingDeactivation. Safe to remove.
			delete(q.pendingDeactivationAddrs, addr)
		}
	}
}

func (q *QPOS) IsSlashed(validatorIndex int) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	_, slashed := q.slashedValidators[validatorIndex]
	return slashed
}

// GetSlashedValidators returns a snapshot of all slashed validators.
//
// CONS- (2026-07-20): The return type changed from
// `map[int]uint64` to `map[int]*SlashedEntry` to expose the
// Permanent/JailUntil fields needed by monitoring tools and tests.
// Callers that only need "is slashed?" should use IsSlashed(idx) instead.
// The returned entries are deep-copied so callers cannot mutate internal
// state.
func (q *QPOS) GetSlashedValidators() map[int]*SlashedEntry {
	q.mu.RLock()
	defer q.mu.RUnlock()

	result := make(map[int]*SlashedEntry, len(q.slashedValidators))
	for k, v := range q.slashedValidators {
		if v == nil {
			continue
		}
		// Copy the struct to prevent external mutation.
		entry := *v
		result[k] = &entry
	}
	return result
}

func (q *QPOS) markValidatorForInvestigation(validatorAddr types.Address, reason SlashingReason) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.investigationCounts == nil {
		q.investigationCounts = make(map[types.Address]int)
	}

	// Prevent unbounded growth: if the map exceeds a reasonable size,
	// clear entries for validators that are no longer in the active set.
	// This handles cases where validators are marked but never reach
	// the investigation threshold (e.g., they leave the validator set).
	if len(q.investigationCounts) > 10000 {
		activeValidators := q.validators.Validators()
		activeSet := make(map[types.Address]bool, len(activeValidators))
		for _, v := range activeValidators {
			activeSet[v.Address] = true
		}
		for addr := range q.investigationCounts {
			if !activeSet[addr] {
				delete(q.investigationCounts, addr)
			}
		}
	}

	q.investigationCounts[validatorAddr]++

	if q.slashingAuditLog != nil {
		// CONS-P0-02 FIX (R31, 2026-07-27): Use consensus-derived block
		// time for the audit log timestamp to keep it deterministic across
		// nodes (matching SlashValidator's behavior).
		auditTs := q.GetLastKnownBlockTime()
		if auditTs == 0 {
			auditTs = time.Now().Unix()
		}
		q.slashingAuditLog.LogSlashing(&SlashingEvent{
			ValidatorAddr: validatorAddr,
			Reason:        SlashReasonUnknown,
			Epoch:         q.currentEpoch,
			Timestamp:     auditTs,
			EvidenceCount: q.investigationCounts[validatorAddr],
			Threshold:     InvestigationThreshold,
		})
	}

	if q.investigationCounts[validatorAddr] < InvestigationThreshold {
		return
	}

	validators := q.validators.Validators()
	for i, v := range validators {
		if v.Address == validatorAddr {
			// CONS- (2026-07-20): Investigation-triggered slash is
			// always temporary (SlashReasonUnknown → not double_signing or
			// surround_vote). Use DefaultJailDuration so the validator can
			// be unjailed via SlashingManager.Unjail() once the jail period
			// expires. Without this, an investigation slash would permanently
			// ban the validator with no recovery path.
			// CONS-P0-02 FIX (R31, 2026-07-27): Use consensus-derived block
			// time instead of time.Now().Unix() for JailUntil to prevent
			// consensus divergence from node clock differences.
			now := q.GetLastKnownBlockTime()
			if now == 0 {
				now = time.Now().Unix()
			}
			q.slashedValidators[i] = &SlashedEntry{
				Epoch:     q.currentEpoch,
				Permanent: false,
				JailUntil: now + DefaultJailDuration,
			}
			// audit-fix LOW: Deactivate the validator so it stops being counted
			// as active (mirrors the main slash path at qpos_slashing.go:226).
			// Without this, a slash-by-investigation only marks the map but the
			// validator remains Active, allowing it to keep proposing/attesting.
			q.validators.DeactivateValidator(i)
			break
		}
	}
}
