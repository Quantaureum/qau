// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"sync"
	"time"

	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
)

var tpfLog = logging.Global()

type BlockPhase uint8

const (
	PhaseNone      BlockPhase = 0
	PhaseProposed  BlockPhase = 1
	PhaseReviewed  BlockPhase = 2
	PhaseSealed    BlockPhase = 3
	PhaseFinalized BlockPhase = 4
	PhaseRejected  BlockPhase = 5
)

func (p BlockPhase) String() string {
	switch p {
	case PhaseNone:
		return "None"
	case PhaseProposed:
		return "Proposed"
	case PhaseReviewed:
		return "Reviewed"
	case PhaseSealed:
		return "Sealed"
	case PhaseFinalized:
		return "Finalized"
	case PhaseRejected:
		return "Rejected"
	default:
		return fmt.Sprintf("Unknown(%d)", p)
	}
}

type BlockLifecycle struct {
	Slot      uint64
	BlockHash types.Hash
	Phase     BlockPhase

	Proposer   int
	ProposedAt time.Time

	ReviewVerdict AttestationVerdict
	ReviewedAt    time.Time

	Sealers  []int
	SealedAt time.Time

	FinalizedAt   time.Time
	FinalityDelay time.Duration
}

type ThreeChambersFlow struct {
	mu sync.RWMutex

	qpos        *QPOS
	coordinator *ThreeChambersCoordinator

	lifecycles map[uint64]*BlockLifecycle

	collusionAlerts []CollusionAlert
	maxAlerts       int
}

type CollusionAlert struct {
	Slot        uint64
	Type        string
	Description string
	Validators  []int
	DetectedAt  time.Time
}

func NewThreeChambersFlow(qpos *QPOS, coordinator *ThreeChambersCoordinator) *ThreeChambersFlow {
	return &ThreeChambersFlow{
		qpos:            qpos,
		coordinator:     coordinator,
		lifecycles:      make(map[uint64]*BlockLifecycle),
		collusionAlerts: make([]CollusionAlert, 0),
		maxAlerts:       1000,
	}
}

func (tpf *ThreeChambersFlow) ProposeBlock(slot uint64, blockHash types.Hash, proposerIndex int) error {
	tpf.mu.Lock()
	defer tpf.mu.Unlock()

	if _, exists := tpf.lifecycles[slot]; exists {
		return fmt.Errorf("block already exists for slot %d", slot)
	}

	if tpf.qpos.HasChambers() && !tpf.qpos.CanPropose(proposerIndex, slot) {
		return fmt.Errorf("validator %d cannot propose for slot %d: not in Proposing Chamber", proposerIndex, slot)
	}

	// R36-P2-CONS-01 FIX: Prune old lifecycle entries at epoch boundary to
	// prevent unbounded memory growth. ProposeBlock is called every slot,
	// so we piggyback the cleanup on the first slot of each epoch (when
	// slot % SlotsPerEpoch == 0). The retention window
	// (threeChambersCleanupRetainSlots) is sized to cover the review/seal/
	// finalize lifecycle plus a safety margin; older entries are stale.
	if slot%uint64(SlotsPerEpoch) == 0 {
		tpf.cleanupOldSlotsLocked(slot)
	}

	tpf.lifecycles[slot] = &BlockLifecycle{
		Slot:      slot,
		BlockHash: blockHash,
		Phase:     PhaseProposed,
		Proposer:  proposerIndex,
		// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
		ProposedAt: time.Unix(int64(slot), 0),
	}

	if tpf.coordinator != nil {
		if err := tpf.coordinator.AssignProposing(proposerIndex, slot); err != nil {
			tpfLog.Warnf("AssignProposing failed for proposer %d slot %d: %v", proposerIndex, slot, err)
		}
	}

	return nil
}

func (tpf *ThreeChambersFlow) ReviewBlock(slot uint64) error {
	tpf.mu.Lock()
	defer tpf.mu.Unlock()

	lifecycle, exists := tpf.lifecycles[slot]
	if !exists {
		return fmt.Errorf("no block proposed for slot %d", slot)
	}

	if lifecycle.Phase != PhaseProposed {
		return fmt.Errorf("block for slot %d is in phase %s, expected Proposed", slot, lifecycle.Phase)
	}

	review := tpf.coordinator.GetReviewChamber()
	if review == nil {
		return fmt.Errorf("review chamber not available")
	}

	verdict := review.GetSlotVerdict(slot)
	if verdict == VerdictApproved {
		lifecycle.Phase = PhaseReviewed
		lifecycle.ReviewVerdict = VerdictApproved
		// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
		lifecycle.ReviewedAt = time.Unix(int64(slot), 0)
		return nil
	}

	if verdict == VerdictRejected || verdict == VerdictTimeout {
		lifecycle.Phase = PhaseRejected
		lifecycle.ReviewVerdict = verdict
		// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
		lifecycle.ReviewedAt = time.Unix(int64(slot), 0)
		return nil
	}

	return fmt.Errorf("block for slot %d is still pending review (verdict: %s)", slot, verdict)
}

func (tpf *ThreeChambersFlow) SealBlock(slot uint64) error {
	tpf.mu.Lock()
	defer tpf.mu.Unlock()

	lifecycle, exists := tpf.lifecycles[slot]
	if !exists {
		return fmt.Errorf("no block proposed for slot %d", slot)
	}

	if lifecycle.Phase != PhaseReviewed {
		return fmt.Errorf("block for slot %d must be reviewed before sealing (current: %s)", slot, lifecycle.Phase)
	}

	if lifecycle.ReviewVerdict != VerdictApproved {
		return fmt.Errorf("executive refuses to seal: review chamber did not approve block for slot %d (verdict: %s)", slot, lifecycle.ReviewVerdict)
	}

	qfs := tpf.qpos.GetQTDFinality()
	if qfs == nil {
		return fmt.Errorf("QTD finality not initialized")
	}

	err := qfs.RequestSeal(slot, lifecycle.BlockHash)
	if err != nil {
		return fmt.Errorf("seal request failed: %w", err)
	}

	// FIX: Removed fake placeholder signature submission.
	// The previous code generated 32-byte placeholder signatures for ALL
	// executive members and submitted them via SubmitPartialSeal. These
	// placeholders passed the MinPartialSealSize=16 format check, allowing
	// a single node to forge the threshold signature and finalize blocks
	// without actual multi-party cooperation.
	//
	// Now SealBlock only requests the seal via qfs.RequestSeal(). The actual
	// partial seal signatures must be collected from executive members via
	// the P2P network. Each member independently computes and submits their
	// own partial seal through SubmitPartialSeal when they receive the seal
	// request. The block is not marked as sealed here — it transitions to
	// PhaseSealed only when completeSealLocked fires after enough partial
	// seals are collected.
	//
	// NOTE: lifecycle.Phase is NOT set to PhaseSealed here. It will be set
	// by the QTD finality callback when the threshold is reached.

	return nil
}

// CompleteSeal checks if the QTD finality has been completed for a slot and
// updates the lifecycle phase to PhaseSealed accordingly. This should be
// called after executive members have submitted their partial seals via
// QTDFinalityState.SubmitPartialSeal.
//
// FIX (companion): After removing fake placeholder
// signatures from SealBlock, this method provides the mechanism for the
// lifecycle to transition to PhaseSealed once real partial seals are
// collected and the QTD threshold is reached.
func (tpf *ThreeChambersFlow) CompleteSeal(slot uint64) error {
	tpf.mu.Lock()
	defer tpf.mu.Unlock()

	lifecycle, exists := tpf.lifecycles[slot]
	if !exists {
		return fmt.Errorf("no block proposed for slot %d", slot)
	}

	if lifecycle.Phase != PhaseReviewed {
		return fmt.Errorf("block for slot %d must be reviewed before completing seal (current: %s)", slot, lifecycle.Phase)
	}

	qfs := tpf.qpos.GetQTDFinality()
	if qfs == nil {
		return fmt.Errorf("QTD finality not initialized")
	}

	if !qfs.IsSlotFinalized(slot) {
		return fmt.Errorf("QTD finality not completed for slot %d", slot)
	}

	record := qfs.GetFinalityRecord(slot)
	if record != nil {
		lifecycle.Sealers = append([]int(nil), record.Sealers...)
		lifecycle.SealedAt = record.SealedAt
	}

	lifecycle.Phase = PhaseSealed

	return nil
}

func (tpf *ThreeChambersFlow) FinalizeBlock(slot uint64) error {
	tpf.mu.Lock()
	defer tpf.mu.Unlock()

	lifecycle, exists := tpf.lifecycles[slot]
	if !exists {
		return fmt.Errorf("no block proposed for slot %d", slot)
	}

	if lifecycle.Phase != PhaseSealed {
		return fmt.Errorf("block for slot %d must be sealed before finalizing (current: %s)", slot, lifecycle.Phase)
	}

	qfs := tpf.qpos.GetQTDFinality()
	if qfs == nil || !qfs.IsSlotFinalized(slot) {
		return fmt.Errorf("QTD finality not completed for slot %d", slot)
	}

	// P1-4 (2026-07-14): Hard DA availability check. Before finalizing a
	// block, verify that its blob data is sufficiently available in the DA
	// layer. A block with unavailable blob data MUST NOT be finalized —
	// finalization is the point of no return, and finalizing a block with
	// unavailable data would make it impossible for light clients and DA
	// sampling nodes to recover the data later.
	//
	// When no DA checker is configured (daAvailabilityCheck == nil), this
	// check is skipped — DA verification is opt-in (only nodes participating
	// in DA verification set the checker via SetDAAvailabilityChecker).
	if err := tpf.qpos.CheckDAAvailability(slot); err != nil {
		return fmt.Errorf("DA availability check failed for slot %d: %w", slot, err)
	}

	lifecycle.Phase = PhaseFinalized
	// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
	lifecycle.FinalizedAt = time.Unix(int64(slot), 0)
	lifecycle.FinalityDelay = lifecycle.FinalizedAt.Sub(lifecycle.ProposedAt)

	return nil
}

func (tpf *ThreeChambersFlow) GetLifecycle(slot uint64) *BlockLifecycle {
	tpf.mu.RLock()
	defer tpf.mu.RUnlock()
	if lc, ok := tpf.lifecycles[slot]; ok {
		copy := &BlockLifecycle{
			Slot:          lc.Slot,
			BlockHash:     lc.BlockHash,
			Phase:         lc.Phase,
			Proposer:      lc.Proposer,
			ProposedAt:    lc.ProposedAt,
			ReviewVerdict: lc.ReviewVerdict,
			ReviewedAt:    lc.ReviewedAt,
			Sealers:       append([]int(nil), lc.Sealers...),
			SealedAt:      lc.SealedAt,
			FinalizedAt:   lc.FinalizedAt,
			FinalityDelay: lc.FinalityDelay,
		}
		return copy
	}
	return nil
}

func (tpf *ThreeChambersFlow) DetectCollusion(slot uint64) *CollusionAlert {
	tpf.mu.Lock()
	defer tpf.mu.Unlock()

	lifecycle, exists := tpf.lifecycles[slot]
	if !exists {
		return nil
	}

	review := tpf.coordinator.GetReviewChamber()
	if review == nil {
		return nil
	}

	result := review.GetSlotResult(slot)
	if result == nil {
		return nil
	}

	if result.Verdict == VerdictApproved && result.RejectCount == 0 && result.CommitteeSize >= 5 {
		alert := CollusionAlert{
			Slot:        slot,
			Type:        "unanimous_approval",
			Description: fmt.Sprintf("Block for slot %d received unanimous approval from %d committee members - potential Proposing-Review collusion", slot, result.ApproveCount),
			Validators:  []int{lifecycle.Proposer},
			DetectedAt:  time.Now(), // NOT consensus-critical: local in-memory tracking only
		}
		tpf.addAlertLocked(alert)
		return &alert
	}

	return nil
}

func (tpf *ThreeChambersFlow) addAlertLocked(alert CollusionAlert) {
	if len(tpf.collusionAlerts) >= tpf.maxAlerts {
		tpf.collusionAlerts = tpf.collusionAlerts[1:]
	}
	tpf.collusionAlerts = append(tpf.collusionAlerts, alert)
}

func (tpf *ThreeChambersFlow) GetCollusionAlerts() []CollusionAlert {
	tpf.mu.RLock()
	defer tpf.mu.RUnlock()
	result := make([]CollusionAlert, len(tpf.collusionAlerts))
	copy(result, tpf.collusionAlerts)
	return result
}

func (tpf *ThreeChambersFlow) CleanupSlot(slot uint64) {
	tpf.mu.Lock()
	defer tpf.mu.Unlock()
	delete(tpf.lifecycles, slot)
}

// threeChambersCleanupRetainSlots is the number of slots of lifecycle
// history to retain before pruning. Three epochs (96 slots at 32
// slots/epoch) comfortably covers the Propose->Review->Seal->Finalize
// lifecycle plus finality lag, while bounding memory to a few hundred
// entries instead of growing ~2.6M/year.
const threeChambersCleanupRetainSlots = 3 * SlotsPerEpoch

// cleanupOldSlotsLocked removes lifecycle entries older than
// (currentSlot - threeChambersCleanupRetainSlots). Caller must hold
// tpf.mu. R36-P2-CONS-01 FIX.
func (tpf *ThreeChambersFlow) cleanupOldSlotsLocked(currentSlot uint64) {
	var cutoff uint64
	if currentSlot > threeChambersCleanupRetainSlots {
		cutoff = currentSlot - threeChambersCleanupRetainSlots
	} else {
		cutoff = 0
	}
	for slot := range tpf.lifecycles {
		if slot < cutoff {
			delete(tpf.lifecycles, slot)
		}
	}
}

func (tpf *ThreeChambersFlow) GetFlowStatus() map[string]any {
	tpf.mu.RLock()
	defer tpf.mu.RUnlock()

	phases := make(map[BlockPhase]int)
	for _, lc := range tpf.lifecycles {
		phases[lc.Phase]++
	}

	return map[string]any{
		"totalBlocks":     len(tpf.lifecycles),
		"proposed":        phases[PhaseProposed],
		"reviewed":        phases[PhaseReviewed],
		"sealed":          phases[PhaseSealed],
		"finalized":       phases[PhaseFinalized],
		"rejected":        phases[PhaseRejected],
		"collusionAlerts": len(tpf.collusionAlerts),
	}
}
