// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

type AttestationVerdict uint8

const (
	VerdictPending  AttestationVerdict = 0
	VerdictApproved AttestationVerdict = 1
	VerdictRejected AttestationVerdict = 2
	VerdictTimeout  AttestationVerdict = 3
)

func (v AttestationVerdict) String() string {
	switch v {
	case VerdictPending:
		return "Pending"
	case VerdictApproved:
		return "Approved"
	case VerdictRejected:
		return "Rejected"
	case VerdictTimeout:
		return "Timeout"
	default:
		return fmt.Sprintf("Unknown(%d)", v)
	}
}

type ReviewSlotResult struct {
	Slot          uint64
	CommitteeSize int
	ApproveCount  int
	RejectCount   int
	ApproveStake  *big.Int
	RejectStake   *big.Int
	TotalStake    *big.Int
	// AUDIT R4-GOV-01 (2026-07-15): The total stake of the FULL review
	// committee for this slot, computed once at slot-result creation time
	// (not accumulated from received attestations). This is the correct
	// denominator for the 2/3 supermajority threshold.
	//
	// Previously, evaluateVerdictLocked used TotalStake (accumulated from
	// received attestations) as the denominator. After the first attestation,
	// ApproveStake == TotalStake, so the 2/3 threshold was trivially met →
	// one-vote lock. Using CommitteeTotalStake forces the verdict to stay
	// Pending until attestations covering 2/3 of the COMMITTEE's stake arrive.
	CommitteeTotalStake *big.Int
	Verdict             AttestationVerdict
	VerdictTime         time.Time
	Attestations        []*Attestation
}

type ReviewChamber struct {
	mu sync.RWMutex

	qpos *QPOS

	slotResults map[uint64]*ReviewSlotResult

	attestationTimeout time.Duration
}

func NewReviewChamber(qpos *QPOS) *ReviewChamber {
	return &ReviewChamber{
		qpos:               qpos,
		slotResults:        make(map[uint64]*ReviewSlotResult),
		attestationTimeout: 6 * time.Second,
	}
}

func (mr *ReviewChamber) SetAttestationTimeout(timeout time.Duration) {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	mr.attestationTimeout = timeout
}

func (mr *ReviewChamber) GetAttestationTimeout() time.Duration {
	mr.mu.RLock()
	defer mr.mu.RUnlock()
	return mr.attestationTimeout
}

func (mr *ReviewChamber) ProcessReviewAttestation(att *Attestation) error {
	if att == nil {
		return ErrInvalidAttestation
	}

	if mr.qpos.HasChambers() && !mr.qpos.CanAttest(att.ValidatorIndex, att.Slot) {
		// R95-ATTEST-LOGLEVEL (2026-08-30): wrap the sentinel so receivers can
		// tell this expected-every-slot rejection (the slot proposer attesting
		// for its own block) apart from a genuine fault, and pick the log level
		// accordingly. See ErrNotInReviewChamber.
		return fmt.Errorf("validator %d cannot attest: %w for slot %d", att.ValidatorIndex, ErrNotInReviewChamber, att.Slot)
	}

	// GOV-R5-01 (2026-07-16): The attester must be a member of the slot's
	// review committee. CanAttest only verifies chamber membership (not in
	// Proposing/Executive province), NOT committee membership for the slot.
	// Without this check, a large-stake validator OUTSIDE the committee
	// could push ApproveStake past 2/3 of CommitteeTotalStake, single-
	// handedly locking the verdict (approve or reject) before 2/3 of the
	// actual committee has weighed in — defeating the BFT safety guarantee
	// that R4-GOV-01 established by fixing the denominator.
	//
	// IsInCommittee handles the small-validator-set case (n <= SlotsPerEpoch)
	// by returning true for all registered validators, so this check only
	// rejects when the validator set is large enough to have per-slot
	// committees and the attester is not in this slot's committee.
	if mr.qpos.validators != nil {
		validators := mr.qpos.validators.Validators()
		if att.ValidatorIndex >= 0 && att.ValidatorIndex < len(validators) {
			attesterAddr := validators[att.ValidatorIndex].Address
			if !mr.qpos.IsInCommittee(att.Slot, attesterAddr) {
				return fmt.Errorf("%w: validator %d (addr %x) not in review committee for slot %d",
					ErrNotInCommittee, att.ValidatorIndex, attesterAddr[:4], att.Slot)
			}
		}
	}

	// R52-FIX (2026-08-06): The attestation reaching this point has ALREADY
	// been validated and stored by QPOS.ProcessAttestation in the caller —
	// BlockProducer.tryAttest (block_producer.go:1449) or
	// Node.handleIncomingAttestation (node.go:7133). Both verify the
	// Dilithium3 signature, the canonical source root, and committee
	// membership, and record (validatorIndex, slot) -> block root.
	//
	// Previously this method called mr.qpos.ProcessAttestation(att) a SECOND
	// time, which had two critical faults on the live network:
	//   1. It re-wrote q.validatorAttestations and re-ran checkDoubleVote.
	//      When the same (validator, slot) was processed on the two paths
	//      with different block roots (a fork / propagation lag), the
	//      second write was misclassified as a slashable double vote → false
	//      slashing → validator stopped producing → no rewards.
	//   2. Because the caller had already stored the attestation, the second
	//      ProcessAttestation returned ErrDuplicateAttestation, ABORTING the
	//      review accounting before accumulateReviewVote merged the vote —
	//      the verdict stayed Pending forever, IsBlockApproved never returned
	//      true, QTD seal/finality stalled, and rewards were never issued.
	//
	// The fix: verify the signature only (defense-in-depth for any direct
	// caller) WITHOUT re-writing validatorAttestations, re-running double-vote
	// detection, or re-triggering finality. The attestation is a review vote —
	// the caller already performed the stateful consensus processing.
	if mr.qpos.validators == nil {
		return fmt.Errorf("review chamber: validator set not initialized")
	}
	validators := mr.qpos.validators.Validators()
	if att.ValidatorIndex < 0 || att.ValidatorIndex >= len(validators) {
		return fmt.Errorf("%w: validator index %d out of range [0, %d)", ErrInvalidAttestation, att.ValidatorIndex, len(validators))
	}
	if err := mr.qpos.verifyAttestationSignature(att, validators); err != nil {
		return err
	}

	mr.mu.Lock()
	defer mr.mu.Unlock()

	// R37-FIX P2-CONS-01 (2026-07-30): Prune old slot results at epoch
	// boundary to prevent unbounded memory growth. ProcessReviewAttestation
	// is called every slot, so we piggyback the cleanup on the first slot of
	// each epoch — the same pattern R36-P2-CONS-01 applied to
	// ThreeChambersFlow.cleanupOldSlotsLocked. Without this, slotResults
	// grows ~2.6M entries/year (one per slot, with ever-appending
	// Attestations) and CleanupSlot has no production caller.
	if att.Slot%uint64(SlotsPerEpoch) == 0 {
		mr.cleanupOldSlotsLocked(att.Slot)
	}

	result := mr.getOrCreateSlotResultLocked(att.Slot)
	result.Attestations = append(result.Attestations, att)

	if att.ValidatorIndex >= 0 && att.ValidatorIndex < len(validators) {
		v := validators[att.ValidatorIndex]
		if att.BeaconBlockRoot == mr.getExpectedBlockRoot(att.Slot) {
			result.ApproveCount++
			result.ApproveStake.Add(result.ApproveStake, v.Stake)
		} else {
			result.RejectCount++
			result.RejectStake.Add(result.RejectStake, v.Stake)
		}
		result.TotalStake.Add(result.TotalStake, v.Stake)
	}

	mr.evaluateVerdictLocked(result)

	return nil
}

// getExpectedBlockRoot returns the canonical block root that an attestation
// for the given slot should be voting on.
//
// AUDIT (2026) GOV-05 FIX: Previously this function looked up block roots
// by epoch (via SlotToEpoch), which meant every slot within an epoch compared
// attestations against the SAME root. This caused attestations for non-epoch-
// boundary slots to be misclassified as "reject" whenever the slot's actual
// block differed from the epoch's recorded root. Now we look up by slot first
// (the precise canonical block for that slot), and only fall back to the
// per-epoch root when no per-slot root has been recorded (e.g. during the
// transition before SetSlotBlockRoot is wired into block import).
func (mr *ReviewChamber) getExpectedBlockRoot(slot uint64) types.Hash {
	mr.qpos.mu.RLock()
	defer mr.qpos.mu.RUnlock()
	if root, ok := mr.qpos.slotBlockRoots[slot]; ok {
		return root
	}
	if root, ok := mr.qpos.epochBlockRoots[SlotToEpoch(slot)]; ok {
		return root
	}
	return types.Hash{}
}

func (mr *ReviewChamber) getOrCreateSlotResultLocked(slot uint64) *ReviewSlotResult {
	if result, ok := mr.slotResults[slot]; ok {
		return result
	}

	committeeSize := TargetCommitteeSize
	if mr.qpos.validators != nil {
		n := mr.qpos.validators.Size()
		if n < committeeSize {
			committeeSize = n
		}
	}

	// AUDIT R4-GOV-01 (2026-07-15): Compute the committee's TOTAL stake
	// (the denominator for the 2/3 supermajority threshold) from the full
	// committee membership, NOT from received attestations. This closes
	// the one-vote-lock vulnerability where the first attestation made
	// ApproveStake == TotalStake, trivially satisfying 2/3.
	//
	// GetCommitteeForSlot returns the deterministic committee for this
	// slot. We sum every member's stake once, at slot-result creation
	// time. evaluateVerdictLocked then compares ApproveStake/RejectStake
	// against 2/3 of THIS value, so the verdict stays Pending until
	// enough committee members have actually attested.
	committeeTotalStake := big.NewInt(0)
	if mr.qpos != nil {
		// LOCK ORDER: mr.mu → qpos.mu.
		// The caller (ProcessReviewAttestation) holds mr.mu while
		// GetCommitteeForSlot briefly acquires qpos.mu internally. This
		// establishes the mr.mu → qpos.mu ordering which MUST NOT be
		// reversed anywhere in the codebase (i.e. no path may hold
		// qpos.mu and then call into menxia_review while it tries to
		// acquire mr.mu — that would deadlock). qpos.mu is released as
		// soon as GetCommitteeForSlot returns, before any further mr
		// work, keeping the cross-module hold time minimal. If future
		// refactors introduce a qpos.mu → mr.mu path, this call must be
		// hoisted out of the mr.mu critical section (pre-fetch the
		// committee and pass it in).
		committee, err := mr.qpos.GetCommitteeForSlot(slot)
		if err == nil {
			for _, v := range committee {
				if v != nil && v.Stake != nil {
					committeeTotalStake.Add(committeeTotalStake, v.Stake)
				}
			}
			// Reflect the actual committee size (may differ from
			// TargetCommitteeSize when the validator set is small or
			// when getCommitteeForSlotLocked applies its own sizing).
			if len(committee) > 0 {
				committeeSize = len(committee)
			}
		}
	}

	result := &ReviewSlotResult{
		Slot:                slot,
		CommitteeSize:       committeeSize,
		ApproveStake:        big.NewInt(0),
		RejectStake:         big.NewInt(0),
		TotalStake:          big.NewInt(0),
		CommitteeTotalStake: committeeTotalStake,
		Verdict:             VerdictPending,
	}
	mr.slotResults[slot] = result
	return result
}

func (mr *ReviewChamber) evaluateVerdictLocked(result *ReviewSlotResult) {
	if result.Verdict != VerdictPending {
		return
	}

	// AUDIT R4-GOV-01 (2026-07-15): Use CommitteeTotalStake (the full
	// committee's stake, computed at slot-result creation time) as the
	// denominator for the 2/3 supermajority threshold — NOT the
	// accumulated TotalStake from received attestations.
	//
	// The old code used `result.TotalStake`, which only counts stake from
	// validators that have already attested. After the first attestation,
	// ApproveStake == TotalStake, so threshold = 2/3 * ApproveStake, which
	// is trivially satisfied → one-vote lock. This allowed a single
	// attester to lock the verdict (approve or reject) before 2/3 of the
	// committee had weighed in, causing:
	//   - A single malicious attester could approve an invalid block.
	//   - A single malicious attester could censor a valid block (reject).
	//   - Two honest nodes processing attestations in different orders
	//     could lock conflicting verdicts for the same slot.
	//
	// With CommitteeTotalStake as the denominator, the verdict stays
	// Pending until the approve (or reject) stake reaches 2/3 of the
	// COMMITTEE's total stake — the intended BFT safety property.
	denominator := result.CommitteeTotalStake
	if denominator == nil || denominator.Sign() <= 0 {
		// Committee not yet computed (e.g., GetCommitteeForSlot failed
		// at slot-result creation). Fall back to accumulated TotalStake
		// only if it is non-zero; otherwise stay Pending. This is a
		// degraded mode — the verdict cannot be safely locked without
		// knowing the committee's total stake. In practice this branch
		// is reached only when qpos is nil or has no validators, in
		// which case no attestations should arrive anyway.
		denominator = result.TotalStake
		if denominator.Sign() <= 0 {
			return
		}
	}

	// R38-P2-03 FIX (2026-08-02): The previous code computed
	// `threshold = floor(2*denominator/3)` and accepted when
	// `ApproveStake >= threshold`. Because `floor` rounds DOWN, a stake
	// strictly below the true 2/3 supermajority could lock the verdict —
	// e.g. denominator=10 → threshold=6, accept at 6 (which is 0.6, not
	// 0.666…). For BFT safety the supermajority must be STRICTLY AT LEAST
	// 2/3, i.e. `ApproveStake * 3 >= 2 * denominator`. This is the exact
	// integer comparison with no rounding loss and matches the audit
	// recommendation (cross-multiplication instead of floor).
	twoThirds := new(big.Int).Mul(big.NewInt(2), denominator)

	if new(big.Int).Mul(result.ApproveStake, big.NewInt(3)).Cmp(twoThirds) >= 0 {
		result.Verdict = VerdictApproved
		result.VerdictTime = time.Now() // NOT consensus-critical: local in-memory review record
		return
	}

	if new(big.Int).Mul(result.RejectStake, big.NewInt(3)).Cmp(twoThirds) >= 0 {
		result.Verdict = VerdictRejected
		result.VerdictTime = time.Now() // NOT consensus-critical: local in-memory review record
		return
	}

	// CS-01 FIX: Removed unreachable "neither side can reach threshold" branch.
	//
	// The original code computed maxPossibleApprove = TotalStake - RejectStake
	// (correct), but then tested `RejectStake + maxPossibleApprove < threshold`,
	// which simplifies to `TotalStake < threshold`. Since threshold is 2/3 of
	// TotalStake, TotalStake is always >= threshold, so the condition was
	// always false and the branch was dead code. The approve check also
	// double-counted ApproveStake.
	//
	// The branch is removed rather than "fixed" into an early-determination,
	// because the designed behavior (verified by TestReviewPendingWhenBelowThreshold)
	// is to keep the verdict Pending when neither side reaches the 2/3
	// threshold; CheckTimeout later transitions it to VerdictTimeout.
}

func (mr *ReviewChamber) CheckTimeout(slot uint64) {
	mr.mu.Lock()
	defer mr.mu.Unlock()

	result, ok := mr.slotResults[slot]
	if !ok || result.Verdict != VerdictPending {
		return
	}

	slotStart := GetSlotStartTime(slot)
	if time.Since(slotStart) > mr.attestationTimeout {
		result.Verdict = VerdictTimeout
		result.VerdictTime = time.Now() // NOT consensus-critical: local in-memory review record
	}
}

func (mr *ReviewChamber) GetSlotVerdict(slot uint64) AttestationVerdict {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	if result, ok := mr.slotResults[slot]; ok {
		return result.Verdict
	}
	return VerdictPending
}

func (mr *ReviewChamber) GetSlotResult(slot uint64) *ReviewSlotResult {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	if result, ok := mr.slotResults[slot]; ok {
		// AUDIT R4-GOV-01 (2026-07-15): CommitteeTotalStake may be nil for
		// slot results created before this field was added (e.g., by tests
		// that construct ReviewSlotResult directly). Guard against nil to
		// avoid a panic in big.Int.Set.
		var ctsCopy *big.Int
		if result.CommitteeTotalStake != nil {
			ctsCopy = new(big.Int).Set(result.CommitteeTotalStake)
		} else {
			ctsCopy = big.NewInt(0)
		}
		copy := &ReviewSlotResult{
			Slot:                result.Slot,
			CommitteeSize:       result.CommitteeSize,
			ApproveCount:        result.ApproveCount,
			RejectCount:         result.RejectCount,
			ApproveStake:        new(big.Int).Set(result.ApproveStake),
			RejectStake:         new(big.Int).Set(result.RejectStake),
			TotalStake:          new(big.Int).Set(result.TotalStake),
			CommitteeTotalStake: ctsCopy,
			Verdict:             result.Verdict,
			VerdictTime:         result.VerdictTime,
		}
		return copy
	}
	return nil
}

func (mr *ReviewChamber) IsBlockApproved(slot uint64) bool {
	return mr.GetSlotVerdict(slot) == VerdictApproved
}

// IsHashApproved checks whether a specific block hash is approved for the
// given slot. This extends IsBlockApproved with per-hash granularity:
// the slot must be approved (VerdictApproved) AND the hash must match the
// expected canonical block root for that slot.
//
// P0-T4 (2026-07-14): Previously, ArbitrateFork could not distinguish which
// competing block was the approved one — it only knew whether the slot was
// approved, not which hash was approved. This method provides the per-hash
// check needed for correct fork arbitration.
//
// Returns false if:
//   - the slot is not approved (verdict != VerdictApproved), OR
//   - the hash does not match the expected block root, OR
//   - the expected block root is zero (no canonical block recorded)
func (mr *ReviewChamber) IsHashApproved(slot uint64, hash types.Hash) bool {
	if mr.GetSlotVerdict(slot) != VerdictApproved {
		return false
	}
	expected := mr.getExpectedBlockRoot(slot)
	if expected == (types.Hash{}) {
		return false
	}
	return hash == expected
}

func (mr *ReviewChamber) IsBlockRejected(slot uint64) bool {
	verdict := mr.GetSlotVerdict(slot)
	return verdict == VerdictRejected || verdict == VerdictTimeout
}

func (mr *ReviewChamber) CleanupSlot(slot uint64) {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	delete(mr.slotResults, slot)
}

// reviewChamberCleanupRetainSlots is the number of slots of review history
// to retain before pruning. Three epochs (96 slots at 32 slots/epoch)
// comfortably covers the review/finality lifecycle plus finality lag, while
// bounding memory to a few hundred entries instead of growing ~2.6M/year.
// Sized identically to threeChambersCleanupRetainSlots (R36-P2-CONS-01).
const reviewChamberCleanupRetainSlots = 3 * SlotsPerEpoch

// cleanupOldSlotsLocked removes slot results older than
// (currentSlot - reviewChamberCleanupRetainSlots). Caller must hold mr.mu.
// R37-FIX P2-CONS-01 (2026-07-30).
func (mr *ReviewChamber) cleanupOldSlotsLocked(currentSlot uint64) {
	var cutoff uint64
	if currentSlot > reviewChamberCleanupRetainSlots {
		cutoff = currentSlot - reviewChamberCleanupRetainSlots
	} else {
		cutoff = 0
	}
	for slot := range mr.slotResults {
		if slot < cutoff {
			delete(mr.slotResults, slot)
		}
	}
}

func (mr *ReviewChamber) GetReviewStatus() map[string]any {
	mr.mu.RLock()
	defer mr.mu.RUnlock()

	pending := 0
	approved := 0
	rejected := 0
	timedOut := 0

	for _, result := range mr.slotResults {
		switch result.Verdict {
		case VerdictPending:
			pending++
		case VerdictApproved:
			approved++
		case VerdictRejected:
			rejected++
		case VerdictTimeout:
			timedOut++
		}
	}

	return map[string]any{
		"chamber":    ChamberReview.String(),
		"pending":    pending,
		"approved":   approved,
		"rejected":   rejected,
		"timedOut":   timedOut,
		"timeout":    mr.attestationTimeout.String(),
		"totalSlots": len(mr.slotResults),
	}
}
