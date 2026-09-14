// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

type ChamberID uint8

const (
	ChamberNone      ChamberID = 0
	ChamberProposing ChamberID = 1
	ChamberReview    ChamberID = 2
	ChamberExecutive ChamberID = 3
)

func (p ChamberID) String() string {
	switch p {
	case ChamberNone:
		return "None"
	case ChamberProposing:
		return "Proposing Chamber"
	case ChamberReview:
		return "Review Chamber"
	case ChamberExecutive:
		return "Executive Chamber"
	default:
		return fmt.Sprintf("Unknown(%d)", p)
	}
}

type ChamberRole struct {
	Chamber    ChamberID
	Slot       uint64
	Epoch      uint64
	AssignedAt time.Time
}

type ChamberAssignment struct {
	mu    sync.RWMutex
	roles map[int]*ChamberRole
}

func NewChamberAssignment() *ChamberAssignment {
	return &ChamberAssignment{
		roles: make(map[int]*ChamberRole),
	}
}

func (pa *ChamberAssignment) Assign(validatorIndex int, chamber ChamberID, slot, epoch uint64) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	pa.roles[validatorIndex] = &ChamberRole{
		Chamber:    chamber,
		Slot:       slot,
		Epoch:      epoch,
		AssignedAt: time.Now(),
	}
}

func (pa *ChamberAssignment) GetChamber(validatorIndex int) ChamberID {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	if r, ok := pa.roles[validatorIndex]; ok {
		return r.Chamber
	}
	return ChamberNone
}

func (pa *ChamberAssignment) ClearSlot(slot uint64) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	for idx, r := range pa.roles {
		if r.Slot == slot {
			delete(pa.roles, idx)
		}
	}
}

func (pa *ChamberAssignment) ClearEpoch(epoch uint64) {
	pa.mu.Lock()
	defer pa.mu.Unlock()
	for idx, r := range pa.roles {
		if r.Epoch == epoch && r.Chamber == ChamberExecutive {
			delete(pa.roles, idx)
		}
	}
}

func (pa *ChamberAssignment) IsInChamber(validatorIndex int, chamber ChamberID) bool {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	if r, ok := pa.roles[validatorIndex]; ok {
		return r.Chamber == chamber
	}
	return false
}

// IsInChamberForSlot reports whether validatorIndex currently holds the given
// chamber role assigned to the exact slot. Proposing/Review are per-slot
// transient roles; this scopes the check so a stale role from a past slot no
// longer blocks decisions for a different slot.
//
// R53-FIX (2026-08-06): Previously only the unscoped IsInChamber existed, and
// ChamberAssignment.roles was never cleaned in production (AssignProposing
// runs every slot, roles accumulate). A validator who proposed ANY past slot
// ended up permanently flagged as "in Proposing", which forever blocked its
// CanAttest, CanSeal, and its eligibility for Executive selection on a
// 6-validator network (all 6 became ineligible → "not enough eligible
// validators: have 0, need 3" → no executive → no seal → no rewards).
func (pa *ChamberAssignment) IsInChamberForSlot(validatorIndex int, chamber ChamberID, slot uint64) bool {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	if r, ok := pa.roles[validatorIndex]; ok {
		return r.Chamber == chamber && r.Slot == slot
	}
	return false
}

// IsInChamberForEpoch reports whether validatorIndex currently holds the given
// chamber role assigned to the exact epoch. Executive is a per-epoch role;
// this scopes the check so an Executive role from a past epoch no longer
// blocks proposing/attesting in a later epoch (the Executive chamber is
// re-elected at every epoch boundary, so an ex-Executive member must be free
// to serve in the proposing/review chambers of subsequent epochs).
// R53-FIX (2026-08-06): same root-cause fix as IsInChamberForSlot.
func (pa *ChamberAssignment) IsInChamberForEpoch(validatorIndex int, chamber ChamberID, epoch uint64) bool {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	if r, ok := pa.roles[validatorIndex]; ok {
		return r.Chamber == chamber && r.Epoch == epoch
	}
	return false
}

func (pa *ChamberAssignment) GetValidatorsInChamber(chamber ChamberID) []int {
	pa.mu.RLock()
	defer pa.mu.RUnlock()
	result := make([]int, 0)
	for idx, r := range pa.roles {
		if r.Chamber == chamber {
			result = append(result, idx)
		}
	}
	return result
}

var (
	ErrCrossChamberConflict   = fmt.Errorf("validator cannot serve in multiple chambers simultaneously")
	ErrProposerPowerExceeded  = fmt.Errorf("proposer cannot also serve in Review or Executive Chamber")
	ErrReviewPowerExceeded    = fmt.Errorf("review member cannot also serve in Proposing or Executive Chamber")
	ErrExecutivePowerExceeded = fmt.Errorf("executive member cannot also serve in Proposing or Review Chamber")

	// R30-IMPLEMENT (2026-07-27): P2-ASSIGN-EXECUTIVE error variables.
	// AssignExecutive is a devnet/testnet helper for direct executive chamber
	// setup. In production (QAU_PRODUCTION=1 or requireDistributedDKG=true),
	// direct assignment is forbidden — production code MUST use
	// TransitionExecutiveForEpoch, which runs VRF-based stake-weighted random
	// selection (SelectExecutiveForEpoch) and enforces the
	// requireDistributedDKG production gate.
	ErrAssignExecutiveDisabledInProduction = fmt.Errorf("executive assignment disabled in production")
	// ErrExecutiveAlreadyAssigned is returned when AssignExecutive is called
	// for an epoch that already has executive members assigned. This prevents
	// a second direct call from silently overwriting legitimate VRF-selected
	// members with attacker-chosen ones.
	ErrExecutiveAlreadyAssigned = fmt.Errorf("executive already assigned for this epoch")

	// ErrExecutiveScheduleNotReady is returned by SelectExecutiveForEpoch when
	// the VRF accumulator for the epoch's randomness source (epoch-2) is not
	// yet populated locally (cold-start / restart / sync catch-up).
	//
	// R88-F (2026-08-30): mirrors R45-PoA-FIX for the shuffle. Previously a
	// node whose acc[epoch-2] was missing silently selected the Executive
	// Chamber with the ZERO hash as randomness and CACHED the result in
	// epochExecutive[epoch] — a node that later imported the canonical
	// accumulator kept the zero-hash-derived members for the rest of the
	// epoch (and, with the retain window, possibly longer). Because CanPropose
	// forbids Executive members from proposing, a divergent Executive set
	// makes the node's CanPropose/CanSeal decisions disagree with its peers
	// for that epoch — the same class of cross-node divergence R45 fixed for
	// the proposer shuffle. Fail-closed (do not select, do not cache) is safe:
	// a missing Executive assignment imposes NO proposing restriction (see
	// CanPropose), so the worst case is a slightly under-populated Executive
	// chamber for one epoch until the accumulator arrives and the next epoch
	// boundary re-selects.
	ErrExecutiveScheduleNotReady = fmt.Errorf("executive election randomness not ready (VRF accumulator for epoch-2 missing)")
)

type ThreeChambersCoordinator struct {
	mu sync.RWMutex

	qpos *QPOS

	assignment *ChamberAssignment

	executive *ExecutiveChamber

	review *ReviewChamber

	reviewSize int

	epochExecutive map[uint64][]int

	// GOV- (2026-07-17): Production gate for distributed DKG.
	// When true, SetDKGComplete refuses to activate the executive chamber
	// using a locally-preset group public key (the placeholder DKG path).
	// Only a group key produced by a real P2P distributed DKG round may
	// activate the executive chamber. This prevents mainnet from running
	// with a single-point preset key that defeats threshold trust.
	//
	// Default false (preserves devnet/testnet behavior where local preset
	// keys are acceptable for testing). Mainnet deployments MUST call
	// SetRequireDistributedDKG(true) before the first epoch transition.
	//
	// This is a code-level enforcement of the design disclosure in the
	// GOV- audit finding: the local DKG path is a placeholder, and
	// real P2P distributed DKG must be implemented and wired before
	// mainnet activation. Until P2P DKG is implemented, mainnet must
	// keep this flag true, which effectively disables executive chamber
	// activation (the network runs without executive-sealed blocks).
	requireDistributedDKG bool

	// GOV- (2026-07-17): Distributed DKG runner integration point.
	// When set AND requireDistributedDKG=true, TransitionExecutiveForEpoch
	// and CompleteDKGViaDistributedRunner use this runner to produce the
	// group public key via real P2P distributed DKG (multi-round Shamir
	// secret sharing across validator nodes), instead of accepting a
	// locally-preset key.
	//
	// When requireDistributedDKG=true but this runner is nil, the
	// executive chamber CANNOT be activated (fail-closed) — this is the
	// GOV- production gate. The runner is the GOV- closure: it
	// provides the integration point for wiring a real distributed DKG
	// implementation (e.g., wallet/tss/qtd.GenerateDKGDistributedSimulated
	// wrapped in a P2P transport — note: GenerateDKGDistributedSimulated is
	// a single-process simulation per TSS-; the runner must implement
	// the real multi-round protocol defined by qtd.DistributedDKGRunner in
	// dkg_runner.go). The runner is intentionally an interface so consensus
	// does NOT depend on wallet/tss (architecture: upper layers may not
	// depend on wallet; the implementation is injected by node/).
	//
	// Production mainnet deployments MUST inject a real runner before the
	// first epoch transition. Testnet/devnet may leave it nil to allow
	// the placeholder local DKG path (requireDistributedDKG=false).
	distributedDKGRunner DistributedDKGRunner

	// R93-DKG-LOGSPAM (2026-08-30): throttle state for the DKG timeout
	// warning. CheckDKGTimeout is called once per slot (every 12 s on
	// mainnet), so an executive chamber that can never activate emitted one
	// WARN per slot forever — 14,400 lines/day of a condition that is the
	// EXPECTED long-term state whenever requireDistributedDKG is true and no
	// distributedDKGRunner is wired (see those fields' docs). The warning is
	// still useful, so it is rate-limited rather than removed: at most one
	// line per `timeout` interval per epoch.
	dkgTimeoutWarnEpoch uint64
	dkgTimeoutWarnAt    time.Time
	dkgTimeoutWarnSeen  bool
}

// DistributedDKGRunner produces a group public key via real P2P distributed
// DKG. GOV- (2026-07-17): This is the integration point for closing the
// "executive DKG is a local preset placeholder" finding. Implementations must:
//
//   - Run multi-round Shamir secret sharing across the executive chamber's
//     validator nodes (no single party holds the full private key).
//   - Return the resulting group public key on success.
//   - Return an error if the DKG round fails (caller fail-closes: the
//     executive chamber remains in DKGRunning state).
//
// The threshold and total participant count are derived from the executive
// chamber's configuration. The epoch is provided for replay protection.
//
// Implementations live outside the consensus package (in node/) to respect
// the architecture discipline (consensus must not depend on wallet/tss).
type DistributedDKGRunner interface {
	// RunDistributedDKG executes a distributed DKG round for the given
	// epoch and participant count. Returns the group public key.
	RunDistributedDKG(epoch uint64, threshold, totalParticipants int) ([]byte, error)
}

func NewThreeChambersCoordinator(qpos *QPOS) *ThreeChambersCoordinator {
	return &ThreeChambersCoordinator{
		qpos:           qpos,
		assignment:     NewChamberAssignment(),
		executive:      NewExecutiveChamber(3, 2),
		review:         NewReviewChamber(qpos),
		reviewSize:     TargetCommitteeSize,
		epochExecutive: make(map[uint64][]int),
	}
}

// executiveSizeForValidatorCount returns the optimal number of executive
// chamber members for a given validator set size. For small validator sets,
// using too many executive members leaves too few validators in the Review
// Chamber to reach the 2/3 supermajority needed for finality.
//
// With n validators, 1 is the slot proposer (cannot attest), and the
// executive members also cannot attest. The remaining review members must
// be >= 2n/3 for finality, so:
//
//	executive <= n/3 - 1
//
// Examples:
//
//	n=6:  executive=1, review=4, 4/6=66%  ✅
//	n=9:  executive=2, review=6, 6/9=66%  ✅
//	n=12: executive=3, review=8, 8/12=66% ✅
//
// MinValidatorsForChambers is the smallest validator set for which the Three
// Chambers arithmetic closes.
//
// R85-CHAMBER-MINIMUM (2026-08-28): the Review Chamber needs >= 2n/3 attesting
// validators, while the slot proposer and all Executive members are excluded
// from attesting. executiveSizeForValidatorCount clamps the Executive to at
// least 1, so `executive <= n/3 - 1` first holds at n = 6. Below this the
// Review verdict can never reach its supermajority: attestations are rejected
// with "cannot attest: not in Review Chamber", and only the single Executive
// node advances justified/finalized while every other node reports
// justifiedEpoch = 0. Block production itself is unaffected.
const MinValidatorsForChambers = 6

func executiveSizeForValidatorCount(n int) int {
	if n <= 0 {
		return 1
	}
	// executive <= n/3 - 1, clamped to [1, 3]
	size := n/3 - 1
	if size < 1 {
		return 1
	}
	if size > 3 {
		return 3
	}
	return size
}

// epochExecutiveRetainEpochs is the number of recent epochs whose executive
// member lists are retained in epochExecutive. Older entries are pruned at
// each new epoch selection (the production epoch-boundary path), bounding
// memory growth. The window (~320 epochs) covers the QTD seal retention
// (qtdCleanupRetainSlots = 10000 slots ≈ 312 epochs at 32 slots/epoch), so
// CanSeal/GetExecutiveMembersForEpoch remain available for every epoch that
// may still hold a pending or finalized seal record.
// R37-P3-27 FIX (2026-07-31): CleanupEpoch previously had no production
// caller, so epochExecutive grew without bound.
const epochExecutiveRetainEpochs = 320

// SetRequireDistributedDKG enables the GOV- production gate.
// When enabled, SetDKGComplete refuses locally-preset group keys.
// Mainnet deployments MUST call this with true before the first epoch.
// Testnet/devnet may leave it false to allow the placeholder local DKG path.
func (tpc *ThreeChambersCoordinator) SetRequireDistributedDKG(required bool) {
	tpc.mu.Lock()
	defer tpc.mu.Unlock()
	tpc.requireDistributedDKG = required
}

// SetDistributedDKGRunner injects the GOV- distributed DKG runner.
// When set, TransitionExecutiveForEpoch uses this runner to produce the
// group public key via real P2P distributed DKG (instead of accepting a
// locally-preset key). The runner is the closure for the "executive DKG
// is a local preset placeholder" finding.
//
// Architecture: This method is called by node/ (the integration layer)
// which constructs a runner that wraps wallet/tss/qtd.GenerateDKGDistributedSimulated
// with a P2P transport. NOTE (TSS-): GenerateDKGDistributedSimulated is
// a single-process simulation; a real runner must implement the multi-round
// protocol defined by qtd.DistributedDKGRunner (dkg_runner.go). The consensus
// package itself does NOT depend on wallet/tss — it only depends on the
// DistributedDKGRunner interface.
//
// Mainnet deployments MUST inject a real runner before the first epoch
// transition (combined with SetRequireDistributedDKG(true)). Without a
// runner, requireDistributedDKG=true fail-closes the executive chamber.
func (tpc *ThreeChambersCoordinator) SetDistributedDKGRunner(runner DistributedDKGRunner) {
	tpc.mu.Lock()
	defer tpc.mu.Unlock()
	tpc.distributedDKGRunner = runner
}

// CompleteDKGViaDistributedRunner activates the executive chamber using a
// group public key produced by the injected DistributedDKGRunner. This is
// the GOV- closure path: when requireDistributedDKG=true, this is the
// ONLY way to activate the executive chamber (the local-preset path via
// TriggerDKG / TransitionExecutiveForEpoch's groupPublicKey parameter is
// refused by the GOV- gate).
//
// Returns true if the executive chamber was activated, false if:
//   - No DistributedDKGRunner is injected (caller must inject one first).
//   - The runner returned an error (DKG round failed; chamber stays in DKGRunning).
//   - The executive chamber is not in DKGRunning state (already active or
//     SetMembers has not been called yet for this epoch).
//
// Thread safety: Safe for concurrent use. The runner is called without
// holding tpc.mu (runners may take seconds/minutes for P2P rounds).
func (tpc *ThreeChambersCoordinator) CompleteDKGViaDistributedRunner(epoch uint64) bool {
	// Snapshot the runner and chamber config under the lock, then release
	// the lock before calling the runner (which may block on P2P rounds).
	tpc.mu.RLock()
	runner := tpc.distributedDKGRunner
	tpc.mu.RUnlock()

	if runner == nil {
		tpfLog.Warnf("GOV- CompleteDKGViaDistributedRunner refused — no DistributedDKGRunner injected; inject one via SetDistributedDKGRunner before mainnet activation")
		return false
	}

	executive := tpc.GetExecutiveChamber()
	if executive == nil {
		return false
	}

	// Already active — no need to run DKG.
	if executive.IsActive() {
		return true
	}

	// DKG not running — nothing to complete.
	if executive.State() != ExecutiveDKGRunning {
		return false
	}

	threshold := executive.Threshold()
	members := executive.Members()
	totalParticipants := len(members)
	if threshold <= 0 || totalParticipants <= 0 || threshold > totalParticipants {
		tpfLog.Warnf("GOV- invalid executive chamber config — threshold=%d, participants=%d",
			threshold, totalParticipants)
		return false
	}

	// Run the distributed DKG (may block for P2P rounds — do NOT hold tpc.mu).
	groupPubKey, err := runner.RunDistributedDKG(epoch, threshold, totalParticipants)
	if err != nil {
		tpfLog.Warnf("GOV- distributed DKG failed for epoch %d: %v (executive chamber remains in DKGRunning state)",
			epoch, err)
		return false
	}
	if len(groupPubKey) == 0 {
		tpfLog.Warnf("GOV- distributed DKG returned empty group public key for epoch %d", epoch)
		return false
	}

	// Activate the executive chamber with the distributed-DKG-produced key.
	// This bypasses the GOV- local-preset gate because the key was
	// produced by the injected runner (real distributed DKG), not a local
	// preset.
	if err := executive.SetDKGComplete(groupPubKey); err != nil {
		tpfLog.Warnf("GOV- distributed DKG returned malformed group public key for epoch %d: %v", epoch, err)
		return false
	}
	// Log a short prefix of the group key for correlation. Guard against
	// short keys (test runners may return short placeholders) to avoid
	// slice-bounds panic.
	keyPrefix := groupPubKey
	if len(keyPrefix) > 8 {
		keyPrefix = keyPrefix[:8]
	}
	tpfLog.Infof("GOV- executive chamber activated for epoch %d via distributed DKG (threshold=%d, participants=%d, groupPubKey=%x)",
		epoch, threshold, totalParticipants, keyPrefix)
	return true
}

func (tpc *ThreeChambersCoordinator) AssignProposing(validatorIndex int, slot uint64) error {
	tpc.mu.Lock()
	defer tpc.mu.Unlock()

	epoch := SlotToEpoch(slot)
	// R53-FIX (2026-08-06): scope the conflict check to the current epoch
	// (Executive) and current slot (Review). The unscoped IsInChamber wrongly
	// rejected a proposer carrying a stale Review role from a past slot.
	//
	// R93-CHAMBER-DEGRADED (2026-08-30): the Executive conflict is gated on
	// executiveRestrictionsActiveLocked() to stay consistent with CanPropose.
	// Without this, GetProposerForSlot would elect a DKG-pending executive
	// member (now permitted) and then fail to register the Proposing role,
	// logging "AssignProposing failed" every slot.
	if (tpc.executiveRestrictionsActiveLocked() &&
		tpc.assignment.IsInChamberForEpoch(validatorIndex, ChamberExecutive, epoch)) ||
		tpc.assignment.IsInChamberForSlot(validatorIndex, ChamberReview, slot) {
		currentChamber := tpc.assignment.GetChamber(validatorIndex)
		return fmt.Errorf("%w: validator %d is already in %s for slot %d epoch %d",
			ErrProposerPowerExceeded, validatorIndex, currentChamber, slot, epoch)
	}

	tpc.assignment.Assign(validatorIndex, ChamberProposing, slot, epoch)
	return nil
}

func (tpc *ThreeChambersCoordinator) AssignReview(validatorIndices []int, slot uint64) error {
	tpc.mu.Lock()
	defer tpc.mu.Unlock()

	epoch := SlotToEpoch(slot)
	for _, idx := range validatorIndices {
		// FIX: scope the conflict check (Executive per-epoch, Proposing
		// per-slot) so stale roles from past slots don't block the committee.
		if tpc.assignment.IsInChamberForEpoch(idx, ChamberExecutive, epoch) ||
			tpc.assignment.IsInChamberForSlot(idx, ChamberProposing, slot) {
			currentChamber := tpc.assignment.GetChamber(idx)
			return fmt.Errorf("%w: validator %d is already in %s for slot %d epoch %d",
				ErrReviewPowerExceeded, idx, currentChamber, slot, epoch)
		}
		tpc.assignment.Assign(idx, ChamberReview, slot, epoch)
	}
	return nil
}

func (tpc *ThreeChambersCoordinator) AssignExecutive(validatorIndices []int, epoch uint64) error {
	tpc.mu.Lock()
	defer tpc.mu.Unlock()

	// R30-IMPLEMENT (2026-07-27): P2-ASSIGN-EXECUTIVE production gate.
	// In production (QAU_PRODUCTION=1 or requireDistributedDKG=true), direct
	// Executive assignment is forbidden — production code MUST use
	// TransitionExecutiveForEpoch, which runs VRF-based stake-weighted random
	// selection (SelectExecutiveForEpoch) and enforces the
	// requireDistributedDKG production gate. This test/devnet-only helper
	// must fail-closed in production so an attacker cannot bypass VRF
	// selection by calling AssignExecutive directly.
	if tpc.requireDistributedDKG || params.IsProductionEnv() {
		return ErrAssignExecutiveDisabledInProduction
	}

	// R30-IMPLEMENT (2026-07-27): P2-ASSIGN-EXECUTIVE idempotency check.
	// A second direct call for the SAME epoch must fail — otherwise an
	// attacker could silently overwrite the legitimate VRF-selected members
	// mid-epoch. Different epochs are allowed (idempotency is per-epoch).
	if _, exists := tpc.epochExecutive[epoch]; exists {
		return fmt.Errorf("%w: epoch %d already has executive members", ErrExecutiveAlreadyAssigned, epoch)
	}

	for _, idx := range validatorIndices {
		// FIX: scope the conflict check to this epoch so a stale
		// Proposing/Review role from a past epoch does not block assignment.
		if tpc.assignment.IsInChamberForEpoch(idx, ChamberProposing, epoch) ||
			tpc.assignment.IsInChamberForEpoch(idx, ChamberReview, epoch) {
			currentChamber := tpc.assignment.GetChamber(idx)
			return fmt.Errorf("%w: validator %d is already in %s for epoch %d",
				ErrExecutivePowerExceeded, idx, currentChamber, epoch)
		}
		tpc.assignment.Assign(idx, ChamberExecutive, 0, epoch)
	}

	tpc.epochExecutive[epoch] = validatorIndices
	return nil
}

// executiveRestrictionsActiveLocked reports whether ChamberExecutive
// membership should carry its power-separation restrictions (its member may
// neither propose nor attest).
//
// R93-CHAMBER-DEGRADED (2026-08-30): the restrictions apply ONLY while the
// executive chamber is genuinely active (ExecutiveActive / ExecutiveSealing),
// i.e. once DKG has completed and the chamber can actually produce threshold
// seals. While DKG is pending the chamber performs no duty, so stripping its
// member's rights imposes the COST of power separation without its BENEFIT.
//
// The threshold is reachable at the minimum mainnet validator count:
// exactly 6 validators activate chambers, and
// executiveSizeForValidatorCount(6) == 1 assigns one validator to the
// Executive chamber. Mainnet also sets requireDistributedDKG=true, while the
// distributed DKG runner is still being integrated. In that state the chamber
// must not strip the member's proposing or attesting rights.
//
// Degrading to equal rights is the fail-safe direction: it restores exactly
// the behavior of epoch 0's cold-start round-robin, which is the path already
// verified in production. When a real distributed DKG runner is wired and the
// chamber activates, the restrictions resume automatically with no further
// code change.
//
// Caller must hold tpc.mu (RLock or Lock). tpc.executive is read directly
// rather than through GetExecutiveChamber() because that method takes
// tpc.mu.RLock itself, and recursive RLock deadlocks if a writer is queued.
// ExecutiveChamber.IsActive uses the chamber's own mutex, so no lock
// ordering issue arises.
func (tpc *ThreeChambersCoordinator) executiveRestrictionsActiveLocked() bool {
	return tpc.executive != nil && tpc.executive.IsActive()
}

func (tpc *ThreeChambersCoordinator) CanPropose(validatorIndex int, slot uint64) bool {
	tpc.mu.RLock()
	defer tpc.mu.RUnlock()

	epoch := SlotToEpoch(slot)
	// R53-FIX (2026-08-06): scope chamber checks to the current epoch
	// (Executive) and current slot (Review). The unscoped IsInChamber blocked
	// a validator from proposing forever once it had ever carried a stale
	// Executive/Review role, stalling block production on the live network.
	//
	// R93-CHAMBER-DEGRADED (2026-08-30): the Executive exclusion is gated on
	// executiveRestrictionsActiveLocked() — a chamber stuck in DKGRunning must
	// not strip its member's proposing right. The Review exclusion is NOT
	// gated: it is a per-slot role assigned by AssignReview and carries no
	// DKG precondition.
	if (tpc.executiveRestrictionsActiveLocked() &&
		tpc.assignment.IsInChamberForEpoch(validatorIndex, ChamberExecutive, epoch)) ||
		tpc.assignment.IsInChamberForSlot(validatorIndex, ChamberReview, slot) {
		return false
	}
	return true
}

func (tpc *ThreeChambersCoordinator) CanAttest(validatorIndex int, slot uint64) bool {
	tpc.mu.RLock()
	defer tpc.mu.RUnlock()

	epoch := SlotToEpoch(slot)
	// R53-FIX (2026-08-06): scope chamber checks to the current epoch
	// (Executive) and current slot (Proposing). The unscoped IsInChamber
	// permanently blocked attestations from any validator that had ever been
	// proposer, starving the Review Chamber and preventing block finality.
	//
	// R93-CHAMBER-DEGRADED (2026-08-30): the Executive exclusion is gated on
	// executiveRestrictionsActiveLocked(). With a DKG-pending chamber this was
	// rejecting the member's attestation on every slot
	// ("cannot attest: not in Review Chamber") while the chamber did no work.
	// The Proposing exclusion stays ungated — the slot's own proposer must
	// never attest for its own block.
	if (tpc.executiveRestrictionsActiveLocked() &&
		tpc.assignment.IsInChamberForEpoch(validatorIndex, ChamberExecutive, epoch)) ||
		tpc.assignment.IsInChamberForSlot(validatorIndex, ChamberProposing, slot) {
		return false
	}
	return true
}

// CanSeal reports whether validatorIndex is permitted to submit QTD partial
// seals for the given epoch.
//
// CHAMBER-H03 FIX (R30, 2026-07-27): Previously this method only checked
// tpc.assignment.IsInChamber against ChamberProposing/ChamberReview, ignoring
// the Epoch field. The ChamberAssignment.roles map is
// map[int]*ChamberRole (one role per validator, overwritten on each Assign),
// so it cannot represent "validator X is Executive for epoch N AND not
// Executive for epoch N+1". A validator assigned to Executive for epoch N
// would still pass CanSeal in epoch N+1 if the stale role hadn't been pruned
// yet, allowing an ex-Executive member to submit partial QTD seals in the
// wrong epoch.
//
// The fix uses the epochExecutive map (map[uint64][]int) which stores the
// exact Executive member list per epoch. CanSeal now requires the validator
// to be in epochExecutive[epoch]. When no assignment exists for the epoch,
// CanSeal fails closed (returns false) — this is the secure default during
// epoch transitions before the new Executive is elected.

// HasExecutiveAssignment returns true if an Executive assignment exists for
// the given epoch. This is used by test helpers (ExecuteFullFlow) to decide
// whether to assign Executive before sealing, without triggering the
// CHAMBER-H03 fail-closed gate. Production code should use CanSeal directly.
func (tpc *ThreeChambersCoordinator) HasExecutiveAssignment(epoch uint64) bool {
	tpc.mu.RLock()
	defer tpc.mu.RUnlock()
	_, ok := tpc.epochExecutive[epoch]
	return ok
}

// CanSeal fails closed (returns false) — this is the secure default during
// epoch transitions before the new Executive is elected.
func (tpc *ThreeChambersCoordinator) CanSeal(validatorIndex int, epoch uint64) bool {
	tpc.mu.RLock()
	defer tpc.mu.RUnlock()

	// CHAMBER-H03: Fail-closed when no Executive assignment exists for this
	// epoch. The Proposing/Review chamber check is kept as defense-in-depth —
	// a validator currently proposing/reviewing THIS epoch is also rejected.
	// FIX: scope it to this epoch so a stale role from a past epoch cannot
	// block a legitimately-elected Executive member from sealing.
	if tpc.assignment.IsInChamberForEpoch(validatorIndex, ChamberProposing, epoch) ||
		tpc.assignment.IsInChamberForEpoch(validatorIndex, ChamberReview, epoch) {
		return false
	}

	// CHAMBER-H03: Require explicit membership in epochExecutive[epoch].
	members, ok := tpc.epochExecutive[epoch]
	if !ok {
		// No assignment for this epoch → fail-closed.
		return false
	}
	for _, idx := range members {
		if idx == validatorIndex {
			return true
		}
	}
	return false
}

func (tpc *ThreeChambersCoordinator) GetExecutiveChamber() *ExecutiveChamber {
	tpc.mu.RLock()
	defer tpc.mu.RUnlock()
	return tpc.executive
}

func (tpc *ThreeChambersCoordinator) GetReviewChamber() *ReviewChamber {
	tpc.mu.RLock()
	defer tpc.mu.RUnlock()
	return tpc.review
}

func (tpc *ThreeChambersCoordinator) ProcessReviewAttestation(att *Attestation) error {
	tpc.mu.RLock()
	review := tpc.review
	tpc.mu.RUnlock()
	if review == nil {
		return fmt.Errorf("review chamber not initialized")
	}
	return review.ProcessReviewAttestation(att)
}

func (tpc *ThreeChambersCoordinator) IsBlockApproved(slot uint64) bool {
	tpc.mu.RLock()
	review := tpc.review
	tpc.mu.RUnlock()
	if review == nil {
		return false
	}
	return review.IsBlockApproved(slot)
}

func (tpc *ThreeChambersCoordinator) IsBlockRejected(slot uint64) bool {
	tpc.mu.RLock()
	review := tpc.review
	tpc.mu.RUnlock()
	if review == nil {
		return false
	}
	return review.IsBlockRejected(slot)
}

func (tpc *ThreeChambersCoordinator) GetExecutiveMembersForEpoch(epoch uint64) []int {
	tpc.mu.RLock()
	defer tpc.mu.RUnlock()
	if members, ok := tpc.epochExecutive[epoch]; ok {
		result := make([]int, len(members))
		copy(result, members)
		return result
	}
	return nil
}

func (tpc *ThreeChambersCoordinator) SelectExecutiveForEpoch(epoch uint64, validators *ValidatorSet) ([]int, error) {
	// LOCK ORDER: tpc.mu → qpos.mu (must not be reversed).
	// This function acquires tpc.mu (write) and then calls tpc.qpos.IsSlashed
	// and tpc.qpos.GetEpochVRFAccumulator, both of which acquire qpos.mu
	// (read) internally. No path in the codebase may acquire qpos.mu and
	// then call into ThreeChambersCoordinator while it tries to acquire
	// tpc.mu — that would deadlock. GOV- this ordering is the same
	// one established by getOrCreateSlotResultLocked in menxia_review.go
	// (mr.mu → qpos.mu), so cross-module lock-order discipline is
	// consistent. If a future refactor needs to break this ordering,
	// snapshot the slashed set out-of-lock (collect indices under tpc.mu,
	// release, then bulk-query IsSlashed) before re-acquiring tpc.mu to
	// write the result.
	tpc.mu.Lock()
	defer tpc.mu.Unlock()

	if existing, ok := tpc.epochExecutive[epoch]; ok {
		return existing, nil
	}

	// R88-F (2026-08-30): cold-start guard — mirrors R45-PoA-FIX for the
	// proposer shuffle. When epoch >= 2 the selection randomness comes from
	// the on-chain VRF accumulator of epoch-2. If that accumulator is not yet
	// populated locally (restarting sealer still replaying the chain, sync
	// catch-up, or a fragmented R53 rebuild), selecting now would silently use
	// the ZERO hash — a randomness source that exists nowhere in the canonical
	// chain — and the zero-hash-derived members would be cached in
	// epochExecutive[epoch] for the epoch, diverging from every peer that had
	// the accumulator (CanPropose forbids Executive members from proposing, so
	// a divergent Executive set silences different proposers on different
	// nodes). Fail-closed instead: return the sentinel WITHOUT caching, so the
	// selection is retried on a later epoch-boundary block once the
	// accumulator has been assigned by SetEpochVRFAccumulator.
	//
	// R80-style exemption: on a high-genesis chain (static genesis file with
	// an old genesisTime) the chain starts at a late epoch; for epochs whose
	// epoch-2 predates the first block, the accumulator CANNOT exist on-chain.
	// Every node — restarting or not — selects with the zero hash, so the
	// selection is identical everywhere and proceeding is safe (this mirrors
	// IsChainTooYoungForProposerSchedule on the shuffle path).
	//
	// Note the asymmetry with the shuffle path: the shuffle ALSO falls back to
	// keccak(epoch) under cold-start, but there the cold-start flag makes
	// producer/validator refuse to act on it (IsProposerScheduleReadyForSlot).
	// SelectExecutiveForEpoch has no such downstream guard — its output feeds
	// CanPropose directly — so the ONLY safe behavior for a genuinely missing
	// accumulator is fail-closed.
	if epoch >= 2 && tpc.qpos.GetEpochVRFAccumulator(epoch-2) == (types.Hash{}) {
		if !tpc.qpos.ChainStartsAfterEpoch(epoch - 2) {
			tpfLog.Warnf("SelectExecutiveForEpoch: refusing to select Executive for epoch %d — VRF accumulator for epoch %d not yet loaded (cold-start); will retry at the next epoch boundary (R88-F)",
				epoch, epoch-2)
			return nil, ErrExecutiveScheduleNotReady
		}
		// High-genesis exemption: acc[epoch-2] can never exist on this chain;
		// fall through and select with the zero hash (identical on every node).
	}

	n := validators.Size()

	// M4-FIX (2026-08-18): Use dynamic executive size based on validator
	// count. For small validator sets, the hardcoded size of 3 leaves too
	// few validators in the Review Chamber to reach 2/3 supermajority.
	// executiveSizeForValidatorCount computes the optimal size.
	executiveSize := executiveSizeForValidatorCount(n)
	if n < executiveSize {
		return nil, fmt.Errorf("not enough validators for Executive Chamber: have %d, need %d", n, executiveSize)
	}

	// AUDIT (2026) GOV-FIX: Replace top-K by (hash * stake) with
	// true proportional stake-weighted sampling without replacement. The
	// previous top-K approach was only correct for K=1 (single winner); for
	// K>1 it systematically over-represented high-stake validators.
	//
	// The sequential method selects K validators one at a time: at each step,
	// validator i is selected with probability stake_i / total_remaining_stake,
	// then removed from the pool. This gives exactly proportional inclusion
	// probabilities for all K.

	type eligibleVal struct {
		index int
		stake *big.Int
	}

	// Build eligible validator list (active, not slashed, positive stake,
	// not already in Proposing or Review chamber).
	eligible := make([]eligibleVal, 0, n)
	vList := validators.Validators()
	for i, v := range vList {
		if !v.Active {
			continue
		}
		// FIX (P2): slashedValidators is protected by qpos.mu, not tpc.mu.
		// Use the thread-safe IsSlashed() accessor which acquires qpos.mu.RLock()
		// internally. Lock order is tpc.mu -> qpos.mu (no reverse acquisition
		// exists), so this is deadlock-safe.
		if tpc.qpos.IsSlashed(i) {
			continue
		}
		if v.Stake == nil || v.Stake.Sign() <= 0 {
			continue
		}
		if tpc.assignment.IsInChamberForEpoch(i, ChamberProposing, epoch) ||
			tpc.assignment.IsInChamberForEpoch(i, ChamberReview, epoch) {
			continue
		}
		eligible = append(eligible, eligibleVal{index: i, stake: new(big.Int).Set(v.Stake)})
	}

	if len(eligible) < executiveSize {
		return nil, fmt.Errorf("not enough eligible validators for Executive Chamber: have %d, need %d", len(eligible), executiveSize)
	}

	selected := make([]int, 0, executiveSize)
	for round := 0; round < executiveSize && len(eligible) > 0; round++ {
		// Compute total stake of remaining validators.
		totalStake := big.NewInt(0)
		for _, ev := range eligible {
			totalStake.Add(totalStake, ev.stake)
		}
		if totalStake.Sign() <= 0 {
			break
		}

		// Generate deterministic randomness for this round from
		// (epoch, vrfAccumulator, round). All nodes derive the same
		// randomness because the VRF accumulator is carried on-chain in
		// every block header (blk.Header.VRFAccumulator) and is a
		// deterministic pure function of the verified canonical chain.
		//
		// CONSENSUS-DETERMINISM FIX (2026-08-08): Previously this used
		// `randaoMix` (q.randaoMix), a locally-XOR-accumulated value that
		// different nodes compute differently depending on their block
		// import/production path, restart history, and reorg count. This
		// caused different nodes to select different Executive Chamber
		// members at the same epoch boundary → CanPropose checks diverged
		// → proposers disagreed → chain fork. Replacing it with the
		// on-chain VRF accumulator (epoch-2, same delay as the shuffle
		// seed in computeDeterministicShuffleForEpoch) makes the selection
		// fully deterministic and path-independent.
		//
		// epoch-2 delay rationale (same as shuffle seed, CONS-R13-M03):
		// the last proposer of epoch N can grind epoch N's accumulator by
		// withholding a proposal. Delaying by 2 epochs gives the network
		// a full epoch of buffer to observe and react, making the grind
		// unprofitable. For epoch 0 and 1, epoch-2 underflows; we use the
		// zero hash (identical across all nodes — deterministic but low
		// entropy, acceptable because Executive selection at epoch 0/1
		// cannot activate without a DKG group key anyway).
		var randSource types.Hash
		if epoch >= 2 {
			randSource = tpc.qpos.GetEpochVRFAccumulator(epoch - 2)
		}
		roundData := make([]byte, 8+types.HashLength+8)
		binary.BigEndian.PutUint64(roundData[0:8], epoch)
		copy(roundData[8:40], randSource[:])
		binary.BigEndian.PutUint64(roundData[40:48], uint64(round))
		roundHash := sha3.Sum256(roundData)

		// Map hash to [0, totalStake). The 256-bit hash space is so much
		// larger than any realistic total stake that modulo bias is
		// negligible (bias < stake / 2^256).
		randVal := new(big.Int).SetBytes(roundHash[:])
		randVal.Mod(randVal, totalStake)

		// Walk through eligible validators to find the selected one:
		// the first validator where cumulative stake exceeds randVal.
		cumulative := big.NewInt(0)
		selectedIdx := 0
		for i, ev := range eligible {
			cumulative.Add(cumulative, ev.stake)
			if cumulative.Cmp(randVal) > 0 {
				selectedIdx = i
				break
			}
		}

		idx := eligible[selectedIdx].index
		selected = append(selected, idx)
		tpc.assignment.Assign(idx, ChamberExecutive, 0, epoch)

		// Remove selected validator from eligible pool (without replacement).
		eligible = append(eligible[:selectedIdx], eligible[selectedIdx+1:]...)
	}

	if len(selected) < executiveSize {
		return nil, fmt.Errorf("not enough eligible validators for Executive Chamber: selected %d, need %d", len(selected), executiveSize)
	}

	tpc.epochExecutive[epoch] = selected
	// R37-P3-27 FIX (2026-07-31): production cleanup caller — prune stale
	// epoch executive assignments at each epoch boundary selection.
	tpc.pruneEpochExecutiveLocked(epoch)
	return selected, nil
}

// TransitionExecutiveForEpoch selects executive chamber members for the new
// epoch and transitions the ExecutiveChamber state machine.
//
// P0-2 (2026-07-13): Wires SelectExecutiveForEpoch to the epoch boundary.
// Flow:
//  1. SelectExecutiveForEpoch — stake-weighted random selection
//  2. SetMembers — transitions ExecutiveChamber to ExecutiveDKGRunning
//  3. If groupPublicKey is provided (non-empty), SetDKGComplete — transitions
//     to ExecutiveActive immediately. This supports the "local DKG" path where
//     the group key is pre-established (genesis or prior DKG).
//
// Full P2P DKG rounds (multi-round Shamir secret sharing across validator nodes)
// are P1-9. This method provides the wiring so that when P1-9 is implemented,
// it remains: replace step 3 with a real P2P DKG flow.
//
// CONSENSUS-DETERMINISM FIX (2026-08-08): The randaoMix parameter has been
// removed. SelectExecutiveForEpoch now reads the on-chain VRF accumulator
// (epoch-2) directly from qpos, which is deterministic and path-independent.
// The previous randaoMix was a locally-accumulated value that diverged across
// nodes, causing Executive Chamber membership disagreements and chain forks.
func (tpc *ThreeChambersCoordinator) TransitionExecutiveForEpoch(epoch uint64, validators *ValidatorSet, groupPublicKey []byte) error {
	executive := tpc.GetExecutiveChamber()
	if executive == nil {
		return fmt.Errorf("executive chamber not initialized")
	}

	// Idempotency guard: skip if already active for this epoch.
	// Both block production and block import paths may call this at the same
	// epoch boundary; without this guard, SetMembers would reset the state
	// machine and potentially race with in-progress DKG.
	if executive.Epoch() == epoch && executive.IsActive() {
		return nil
	}

	members, err := tpc.SelectExecutiveForEpoch(epoch, validators)
	if err != nil {
		return fmt.Errorf("select executive for epoch %d: %w", epoch, err)
	}

	if err := executive.SetMembers(members, epoch); err != nil {
		return fmt.Errorf("set executive members for epoch %d: %w", epoch, err)
	}

	if len(groupPublicKey) > 0 {
		// GOV- (2026-07-17): Production gate. When requireDistributedDKG
		// is enabled (mainnet), refuse to activate the executive chamber
		// using a locally-preset group key. The local preset key is a
		// placeholder that defeats threshold trust (a single operator
		// controls the group key). Real P2P distributed DKG must produce
		// the group key before activation is allowed.
		tpc.mu.RLock()
		requireDistributed := tpc.requireDistributedDKG
		tpc.mu.RUnlock()
		if requireDistributed {
			tpfLog.Warnf("GOV- executive chamber for epoch %d NOT activated — requireDistributedDKG=true refuses local preset group key (placeholder DKG path); implement and wire P2P distributed DKG before mainnet activation",
				epoch)
		} else {
			if err := executive.SetDKGComplete(groupPublicKey); err != nil {
				tpfLog.Warnf("GOV- locally-preset group public key for epoch %d rejected: %v", epoch, err)
			} else {
				tpfLog.Infof("Executive chamber activated for epoch %d: %d members, threshold=%d",
					epoch, len(members), executive.Threshold())
			}
		}
	} else {
		// P1-9 (2026-07-14): DKG pending — the group public key is not yet
		// available. This happens when TSSManager has not generated key shares
		// (e.g., first startup without a pre-existing key file). The DKG will
		// be retried on the next epoch boundary via TriggerDKG, or when the
		// node's TSSManager completes key generation.
		tpfLog.Warnf("Executive chamber members selected for epoch %d: %d members (DKG pending — group public key not available, will retry)",
			epoch, len(members))
	}

	return nil
}

// TriggerDKG attempts to complete the DKG flow for the executive chamber using
// the provided group public key. P1-9 (2026-07-14): This is the "local DKG"
// completion path where the group key is pre-established (generated by the
// local TSSManager at startup or imported from a key file).
//
// GOV- (2026-07-17): This local-preset-key path is a PLACEHOLDER. Real
// P2P distributed DKG (multi-round Shamir secret sharing across validator
// nodes) is NOT yet implemented. When requireDistributedDKG=true (mainnet),
// this method refuses to activate the executive chamber, logging a warning
// instead. Testnet/devnet may leave the flag false to allow the placeholder.
//
// Returns true if DKG was completed (executive transitioned to Active),
// false if DKG is still pending or already complete.
func (tpc *ThreeChambersCoordinator) TriggerDKG(groupPublicKey []byte) bool {
	executive := tpc.GetExecutiveChamber()
	if executive == nil {
		return false
	}

	// Already active — no need to trigger DKG.
	if executive.IsActive() {
		return true
	}

	// GOV- (2026-07-17): Production gate — refuse local preset key.
	tpc.mu.RLock()
	requireDistributed := tpc.requireDistributedDKG
	tpc.mu.RUnlock()
	if requireDistributed {
		tpfLog.Warnf("GOV- TriggerDKG refused — requireDistributedDKG=true blocks local preset group key activation (placeholder DKG path); implement P2P distributed DKG before mainnet")
		return false
	}

	// DKG not running — nothing to trigger.
	if executive.State() != ExecutiveDKGRunning {
		return false
	}

	if len(groupPublicKey) == 0 {
		return false // Still no group key — DKG remains pending
	}

	if err := executive.SetDKGComplete(groupPublicKey); err != nil {
		tpfLog.Warnf("GOV- TriggerDKG rejected malformed group public key for epoch %d: %v",
			executive.Epoch(), err)
		return false
	}
	tpfLog.Infof("DKG completed via TriggerDKG: executive chamber activated for epoch %d",
		executive.Epoch())
	return true
}

// CheckDKGTimeout checks if the executive chamber's DKG has been running for
// longer than the timeout and logs a warning. P1-9 (2026-07-14): This provides
// observability for stuck DKG rounds without forcibly changing state (the DKG
// may still complete on a delayed P2P round).
//
// Returns true if DKG is timing out (running longer than timeout).
func (tpc *ThreeChambersCoordinator) CheckDKGTimeout(timeout time.Duration) bool {
	executive := tpc.GetExecutiveChamber()
	if executive == nil {
		return false
	}
	if executive.State() != ExecutiveDKGRunning {
		return false
	}
	// Read dkgStartTime directly. DKGDuration() is unsuitable here because it
	// computes dkgEndTime - dkgStartTime, which is negative when dkgEndTime is
	// zero (DKG still running).
	executive.mu.RLock()
	start := executive.dkgStartTime
	executive.mu.RUnlock()

	if start.IsZero() {
		return false
	}
	elapsed := time.Since(start)
	if elapsed <= timeout {
		return false
	}

	// R93-DKG-LOGSPAM (2026-08-30): rate-limit the warning (see the
	// dkgTimeoutWarn* field docs). The return value is NOT throttled — callers
	// that act on "is DKG timing out" keep seeing the true condition on every
	// call; only the log line is throttled.
	if tpc.shouldWarnDKGTimeout(executive.Epoch(), timeout) {
		tpc.mu.RLock()
		blockedByProductionGate := tpc.requireDistributedDKG && tpc.distributedDKGRunner == nil
		tpc.mu.RUnlock()

		if blockedByProductionGate {
			// This is a designed, permanent state — not an incident. Say so,
			// so operators do not chase it as a fault. Mainnet runs here until
			// a real P2P distributed DKG runner is implemented and injected.
			tpfLog.Warnf("DKG pending for %v (>%v) for epoch %d — executive chamber CANNOT activate: "+
				"requireDistributedDKG=true and no distributedDKGRunner is wired (GOV- production gate). "+
				"This is the expected state until real P2P distributed DKG is implemented; the network runs "+
				"without executive-sealed blocks and all validators keep equal proposing/attesting rights "+
				"(R93-CHAMBER-DEGRADED). Repeats at most once per %v.",
				elapsed, timeout, executive.Epoch(), timeout)
		} else {
			tpfLog.Warnf("DKG has been running for %v (timeout=%v) for epoch %d — executive chamber still pending. "+
				"Repeats at most once per %v.",
				elapsed, timeout, executive.Epoch(), timeout)
		}
	}
	return true
}

// shouldWarnDKGTimeout reports whether the DKG-timeout warning should be
// emitted now, allowing at most one line per `interval` per epoch. A new epoch
// always warns immediately so an epoch transition is never silent.
//
// R93-DKG-LOGSPAM (2026-08-30). Must NOT be called while holding tpc.mu — it
// takes the write lock itself.
func (tpc *ThreeChambersCoordinator) shouldWarnDKGTimeout(epoch uint64, interval time.Duration) bool {
	tpc.mu.Lock()
	defer tpc.mu.Unlock()

	now := time.Now()
	if !tpc.dkgTimeoutWarnSeen || tpc.dkgTimeoutWarnEpoch != epoch || now.Sub(tpc.dkgTimeoutWarnAt) >= interval {
		tpc.dkgTimeoutWarnSeen = true
		tpc.dkgTimeoutWarnEpoch = epoch
		tpc.dkgTimeoutWarnAt = now
		return true
	}
	return false
}

// GetDKGStatus returns the current DKG status for monitoring.
// P1-9 (2026-07-14): Used by RPC and logging to track DKG progress.
func (tpc *ThreeChambersCoordinator) GetDKGStatus() map[string]any {
	executive := tpc.GetExecutiveChamber()
	if executive == nil {
		return map[string]any{
			"available": false,
			"reason":    "executive chamber not initialized",
		}
	}

	executive.mu.RLock()
	defer executive.mu.RUnlock()

	status := map[string]any{
		"available":   true,
		"state":       executive.state.String(),
		"epoch":       executive.epoch,
		"members":     executive.members,
		"threshold":   executive.threshold,
		"hasGroupKey": executive.publicKey != nil,
	}

	if !executive.dkgStartTime.IsZero() {
		status["dkgStartTime"] = executive.dkgStartTime
		if executive.state == ExecutiveDKGRunning {
			status["dkgElapsed"] = time.Since(executive.dkgStartTime).String()
		} else if !executive.dkgEndTime.IsZero() {
			status["dkgDuration"] = executive.dkgEndTime.Sub(executive.dkgStartTime).String()
			status["dkgEndTime"] = executive.dkgEndTime
		}
	}

	return status
}

// CheckExecutiveHealth logs warnings/errors for executive chamber health issues.
// P3-2 (2026-07-14): Operational alerts for executive chamber problems.
//   - WARN: Executive Idle for > 2 epochs (expected to be active by now)
//   - ERROR: Seal failure rate > 50% (threshold signing may be broken)
//
// currentEpoch is passed in (rather than read from qpos) to avoid lock
// ordering issues — the caller already holds the slot tick context.
func (tpc *ThreeChambersCoordinator) CheckExecutiveHealth(currentEpoch uint64) {
	executive := tpc.GetExecutiveChamber()
	if executive == nil {
		return
	}

	executive.mu.RLock()
	state := executive.state
	execEpoch := executive.epoch
	sealCount := executive.sealCount
	sealFail := executive.sealFail
	executive.mu.RUnlock()

	// P3-2 Alert 1: Executive Idle > 2 epochs.
	if state == ExecutiveIdle && execEpoch > 0 && currentEpoch > execEpoch+2 {
		tpfLog.Warnf("Executive chamber has been Idle for %d epochs (selected at epoch %d, current epoch %d) — DKG may have failed or no members were assigned",
			currentEpoch-execEpoch, execEpoch, currentEpoch)
	}

	// P3-2 Alert 2: Seal failure rate > 50%.
	if sealCount+sealFail >= 4 { // Need enough samples for meaningful rate
		totalSeals := sealCount + sealFail
		failRate := float64(sealFail) / float64(totalSeals)
		if failRate > 0.5 {
			tpfLog.Errorf("Executive chamber seal failure rate %.1f%% (%d failed / %d total) — threshold signing may be broken",
				failRate*100, sealFail, totalSeals)
		}
	}
}

// EvidenceQueueLengthValue returns the current slashing evidence queue depth
// as a float64 for the Three Chambers metric provider. P3-3 (2026-07-15).
// Used by the "three_chambers_evidence_queue_backlog" alert rule — fires when
// queue length > 100 (early warning before the 10000 hard cap is reached).
//
// This is a non-destructive read (unlike GetQueuedEvidence which drains the
// queue). Safe to call from monitoring paths.
func (tpc *ThreeChambersCoordinator) EvidenceQueueLengthValue() float64 {
	if tpc == nil || tpc.qpos == nil {
		return 0
	}
	return float64(tpc.qpos.GetEvidenceQueueLength())
}

// DKGElapsedSecondsValue returns the number of seconds since the executive
// chamber's DKG started. P3-3 (2026-07-15). Used by the
// "three_chambers_dkg_stuck" alert rule — fires when elapsed > 1800 seconds
// (30 minutes) and DKG is still running (no progress).
//
// Returns 0 when DKG is not running (Idle, Active, or Sealing states), so the
// alert does not fire for healthy non-DKG states. Cold-start safe: returns 0
// when dkgStartTime is zero.
func (tpc *ThreeChambersCoordinator) DKGElapsedSecondsValue() float64 {
	if tpc == nil {
		return 0
	}
	executive := tpc.GetExecutiveChamber()
	if executive == nil {
		return 0
	}
	executive.mu.RLock()
	state := executive.state
	start := executive.dkgStartTime
	executive.mu.RUnlock()

	// Only report elapsed when DKG is actively running. In Idle/Active/Sealing
	// states, returning 0 ensures the alert does not fire.
	if state != ExecutiveDKGRunning {
		return 0
	}
	if start.IsZero() {
		return 0
	}
	return time.Since(start).Seconds()
}

func (tpc *ThreeChambersCoordinator) GetReviewCommittee(slot uint64) ([]*Validator, error) {
	return tpc.qpos.GetCommitteeForSlot(slot)
}

func (tpc *ThreeChambersCoordinator) GetChamberStatus() map[string]any {
	tpc.mu.RLock()
	defer tpc.mu.RUnlock()

	proposingMembers := tpc.assignment.GetValidatorsInChamber(ChamberProposing)
	reviewMembers := tpc.assignment.GetValidatorsInChamber(ChamberReview)
	executiveMembers := tpc.assignment.GetValidatorsInChamber(ChamberExecutive)

	return map[string]any{
		"proposing": map[string]any{
			"chamber": ChamberProposing.String(),
			"members": proposingMembers,
			"count":   len(proposingMembers),
		},
		"review": map[string]any{
			"chamber": ChamberReview.String(),
			"members": reviewMembers,
			"count":   len(reviewMembers),
		},
		"executive": map[string]any{
			"chamber": ChamberExecutive.String(),
			"members": executiveMembers,
			"count":   len(executiveMembers),
		},
	}
}

func (tpc *ThreeChambersCoordinator) CleanupSlot(slot uint64) {
	tpc.assignment.ClearSlot(slot)
}

func (tpc *ThreeChambersCoordinator) CleanupEpoch(epoch uint64) {
	tpc.assignment.ClearEpoch(epoch)
	tpc.mu.Lock()
	defer tpc.mu.Unlock()
	delete(tpc.epochExecutive, epoch)
}

// pruneEpochExecutiveLocked removes executive assignments older than the
// retention window (epochExecutiveRetainEpochs) relative to currentEpoch,
// mirroring CleanupEpoch's semantics (epochExecutive entry + executive
// chamber role assignment). Caller must hold tpc.mu.
// R37-P3-27 FIX (2026-07-31).
func (tpc *ThreeChambersCoordinator) pruneEpochExecutiveLocked(currentEpoch uint64) {
	if currentEpoch < epochExecutiveRetainEpochs {
		return
	}
	minEpoch := currentEpoch - epochExecutiveRetainEpochs + 1
	for e := range tpc.epochExecutive {
		if e < minEpoch {
			delete(tpc.epochExecutive, e)
			tpc.assignment.ClearEpoch(e)
		}
	}
}
