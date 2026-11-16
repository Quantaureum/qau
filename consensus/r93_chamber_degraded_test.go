// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
)

// R93-CHAMBER-DEGRADED regression test.
//
// With exactly 6 validators (== MinValidatorsForChambers) the Three
// Chambers subsystem activates and TransitionExecutiveForEpoch assigns one
// validator (executiveSizeForValidatorCount(6) == 1) to ChamberExecutive.
// Because mainnet sets requireDistributedDKG=true and real P2P distributed
// DKG is NOT implemented, the executive chamber never leaves
// ExecutiveDKGRunning — GetDKGStatus stays pending forever and the node logs
// "DKG has been running for 5m17s (timeout=5m0s) ... executive chamber still
// pending" every slot.
//
// R93 FIX (2026-08-30, election half superseded): the Executive restrictions
// in CanPropose / CanAttest / AssignProposing were gated on the chamber being
// genuinely active (ExecutiveActive or ExecutiveSealing), so a DKG-pending
// chamber degraded to equal rights for all validators.
//
// TSS-R3-B1-Wave-E (2026-11-16) SUPERSEDES the R93 degradation on the
// election path: gating the exclusion on ExecutiveChamber.IsActive() made it
// a per-node wall-clock predicate (the local DKG completion moment), which
// forked the devnet at epoch-boundary member slots. The exclusion now applies
// for the whole epoch once the member set has been selected, DKG complete or
// not (see executiveRestrictionsApplyLocked). The tests below assert the new
// deterministic contract; the DKG-timeout throttling half of R93 is unchanged
// and still covered.
func newDegradedTestCoordinator(t *testing.T) *ThreeChambersCoordinator {
	t.Helper()
	// A nil-QPOS coordinator is enough: the code paths under test only touch
	// tpc.assignment and tpc.executive, never tpc.qpos.
	return NewThreeChambersCoordinator(nil)
}

// activateExecutive drives the executive chamber to ExecutiveActive using a
// correctly-sized group public key, mimicking a completed DKG.
func activateExecutive(t *testing.T, tpc *ThreeChambersCoordinator) {
	t.Helper()
	groupKey := make([]byte, crypto.Dilithium3PublicKeySize)
	for i := range groupKey {
		groupKey[i] = byte(i % 251)
	}
	if err := tpc.executive.SetDKGComplete(groupKey); err != nil {
		t.Fatalf("SetDKGComplete: %v", err)
	}
	if !tpc.executive.IsActive() {
		t.Fatalf("executive chamber should be active after SetDKGComplete, state=%s",
			tpc.executive.State())
	}
}

// TestR93_DKGPendingExecutiveExcludedForWholeEpoch pins the
// TSS-R3-B1-Wave-E contract that superseded the R93 degradation: once the
// member set for the epoch has been selected, the member loses its proposing
// and attesting rights for the ENTIRE epoch even while the chamber is stuck
// in ExecutiveDKGRunning. Under the old R93 rule the rights depended on the
// local DKG completion moment, which diverged across nodes and forked the
// network at boundary member slots. Fails without the fix (rights were kept
// while DKG was pending).
func TestR93_DKGPendingExecutiveExcludedForWholeEpoch(t *testing.T) {
	tpc := newDegradedTestCoordinator(t)

	const execIdx = 2
	const slot = uint64(40)
	epoch := SlotToEpoch(slot)

	// Mirror TransitionExecutiveForEpoch's production behavior when the group
	// public key is unavailable: members are selected and assigned, but the
	// chamber stays in ExecutiveDKGRunning (SetDKGComplete is never reached).
	if err := tpc.executive.SetMembers([]int{execIdx}, epoch); err != nil {
		t.Fatalf("SetMembers: %v", err)
	}
	tpc.assignment.Assign(execIdx, ChamberExecutive, 0, epoch)

	if tpc.executive.State() != ExecutiveDKGRunning {
		t.Fatalf("precondition: executive state should be DKGRunning, got %s",
			tpc.executive.State())
	}
	if tpc.executive.IsActive() {
		t.Fatal("precondition: executive chamber must NOT be active while DKG is pending")
	}

	if tpc.CanPropose(execIdx, slot) {
		t.Errorf("CanPropose(%d, slot %d) = true; a selected executive member must be "+
			"excluded for the whole epoch regardless of the local DKG state "+
			"(TSS-R3-B1-Wave-E deterministic exclusion)", execIdx, slot)
	}
	if tpc.CanAttest(execIdx, slot) {
		t.Errorf("CanAttest(%d, slot %d) = true; a selected executive member must be "+
			"excluded for the whole epoch regardless of the local DKG state "+
			"(TSS-R3-B1-Wave-E deterministic exclusion)", execIdx, slot)
	}

	// A validator that holds no Executive role for this epoch keeps both
	// rights while DKG is pending — the exclusion must stay scoped to the
	// selected member set, not widen to the whole network.
	if !tpc.CanPropose(execIdx+1, slot) || !tpc.CanAttest(execIdx+1, slot) {
		t.Errorf("a non-member must keep its propose/attest rights while DKG is pending")
	}
}

// TestR93_ActiveExecutiveLosesProposeAndAttestRights pins the other half of
// the contract: once the chamber genuinely activates, power separation is
// enforced again. This must keep passing after the fix, so the fix cannot be
// "delete the check".
func TestR93_ActiveExecutiveLosesProposeAndAttestRights(t *testing.T) {
	tpc := newDegradedTestCoordinator(t)

	const execIdx = 2
	const slot = uint64(40)
	epoch := SlotToEpoch(slot)

	if err := tpc.executive.SetMembers([]int{execIdx}, epoch); err != nil {
		t.Fatalf("SetMembers: %v", err)
	}
	tpc.assignment.Assign(execIdx, ChamberExecutive, 0, epoch)
	activateExecutive(t, tpc)

	if tpc.CanPropose(execIdx, slot) {
		t.Errorf("CanPropose(%d, slot %d) = true while the executive chamber is ACTIVE; "+
			"power separation must be enforced once the chamber can seal", execIdx, slot)
	}
	if tpc.CanAttest(execIdx, slot) {
		t.Errorf("CanAttest(%d, slot %d) = true while the executive chamber is ACTIVE; "+
			"power separation must be enforced once the chamber can seal", execIdx, slot)
	}
}

// TestR93_AssignProposingRejectsDKGPendingExecutive pins the Wave E pairing
// of the two predicates: the proposer scan skips a member because CanPropose
// says false, so AssignProposing must refuse the same validator under the
// same DKG-pending state. If the two gates ever diverge, GetProposerForSlot
// would either elect a member it cannot register (an "AssignProposing
// failed" log every slot) or register a role for a validator other nodes
// excluded — an election divergence.
func TestR93_AssignProposingRejectsDKGPendingExecutive(t *testing.T) {
	tpc := newDegradedTestCoordinator(t)

	const execIdx = 2
	const slot = uint64(40)
	epoch := SlotToEpoch(slot)

	if err := tpc.executive.SetMembers([]int{execIdx}, epoch); err != nil {
		t.Fatalf("SetMembers: %v", err)
	}
	tpc.assignment.Assign(execIdx, ChamberExecutive, 0, epoch)

	if tpc.CanPropose(execIdx, slot) {
		t.Fatalf("precondition: CanPropose must already exclude the DKG-pending member")
	}
	if err := tpc.AssignProposing(execIdx, slot); err == nil {
		t.Errorf("AssignProposing(%d, slot %d) = nil; must be refused under the same "+
			"deterministic whole-epoch gate as CanPropose (TSS-R3-B1-Wave-E)",
			execIdx, slot)
	}
}

// TestR93_AssignProposingRejectsActiveExecutive is the paired negative case:
// an ACTIVE executive member must still be refused the proposing role.
func TestR93_AssignProposingRejectsActiveExecutive(t *testing.T) {
	tpc := newDegradedTestCoordinator(t)

	const execIdx = 2
	const slot = uint64(40)
	epoch := SlotToEpoch(slot)

	if err := tpc.executive.SetMembers([]int{execIdx}, epoch); err != nil {
		t.Fatalf("SetMembers: %v", err)
	}
	tpc.assignment.Assign(execIdx, ChamberExecutive, 0, epoch)
	activateExecutive(t, tpc)

	if err := tpc.AssignProposing(execIdx, slot); err == nil {
		t.Errorf("AssignProposing(%d, slot %d) = nil; an ACTIVE executive member must not "+
			"also hold the proposing role", execIdx, slot)
	}
}

// TestR93_NonExecutiveRightsUnchanged guards against the fix widening beyond
// the executive role: the per-slot Proposing and Review exclusions are
// independent of DKG state and must keep working.
func TestR93_NonExecutiveRightsUnchanged(t *testing.T) {
	tpc := newDegradedTestCoordinator(t)

	const slot = uint64(40)
	epoch := SlotToEpoch(slot)

	// The slot's proposer must not attest (unrelated to the executive chamber).
	tpc.assignment.Assign(4, ChamberProposing, slot, epoch)
	if tpc.CanAttest(4, slot) {
		t.Error("CanAttest(4) = true for the slot's own proposer; the Proposing " +
			"exclusion must be unaffected by the R93 fix")
	}

	// A Review-chamber member must not propose in that slot.
	tpc.assignment.Assign(5, ChamberReview, slot, epoch)
	if tpc.CanPropose(5, slot) {
		t.Error("CanPropose(5) = true for a Review member of the same slot; the Review " +
			"exclusion must be unaffected by the R93 fix")
	}
}

// TestR93_DKGTimeoutWarningIsThrottled covers the second half of the R93 fix:
// CheckDKGTimeout is invoked once per slot, so an executive chamber that never
// activates could produce one WARN line per slot indefinitely. Since that
// state is the designed long-term behavior
// whenever requireDistributedDKG=true and no runner is wired, the log is
// rate-limited to one line per timeout interval per epoch — while the RETURN
// VALUE stays truthful on every call so callers acting on the condition are
// unaffected.
//
// Fails without the fix: shouldWarnDKGTimeout does not exist / every call
// would be allowed to warn.
func TestR93_DKGTimeoutWarningIsThrottled(t *testing.T) {
	tpc := newDegradedTestCoordinator(t)

	const epoch = uint64(2)
	if err := tpc.executive.SetMembers([]int{2}, epoch); err != nil {
		t.Fatalf("SetMembers: %v", err)
	}
	// SetMembers puts the chamber in ExecutiveDKGRunning with dkgStartTime=now.
	// Backdate it so the timeout is already exceeded.
	tpc.executive.mu.Lock()
	tpc.executive.dkgStartTime = time.Now().Add(-30 * time.Minute)
	tpc.executive.mu.Unlock()

	const timeout = 5 * time.Minute

	// The condition itself must be reported on EVERY call — only the log line
	// is throttled.
	for i := range 5 {
		if !tpc.CheckDKGTimeout(timeout) {
			t.Fatalf("CheckDKGTimeout call %d = false; the timeout condition must be "+
				"reported truthfully on every call, only the log line is throttled", i)
		}
	}

	// First warning is allowed, subsequent ones inside the interval are not.
	tpc.dkgTimeoutWarnSeen = false
	if !tpc.shouldWarnDKGTimeout(epoch, timeout) {
		t.Error("shouldWarnDKGTimeout: first call for an epoch must be allowed to warn")
	}
	for i := range 10 {
		if tpc.shouldWarnDKGTimeout(epoch, timeout) {
			t.Fatalf("shouldWarnDKGTimeout: call %d within the interval must be throttled "+
				"(this is the per-slot warning spam R93 fixes)", i+2)
		}
	}

	// A NEW epoch must warn immediately — an epoch transition is never silent.
	if !tpc.shouldWarnDKGTimeout(epoch+1, timeout) {
		t.Error("shouldWarnDKGTimeout: a new epoch must be allowed to warn immediately")
	}

	// Interval elapsed → allowed again.
	tpc.dkgTimeoutWarnAt = time.Now().Add(-2 * timeout)
	if !tpc.shouldWarnDKGTimeout(epoch+1, timeout) {
		t.Error("shouldWarnDKGTimeout: must warn again once the interval has elapsed")
	}
}

// TestR93_ActiveChamberNeverReportsDKGTimeout guards the boundary: an ACTIVE
// chamber is not in ExecutiveDKGRunning, so no timeout is reported at all.
func TestR93_ActiveChamberNeverReportsDKGTimeout(t *testing.T) {
	tpc := newDegradedTestCoordinator(t)

	if err := tpc.executive.SetMembers([]int{2}, 2); err != nil {
		t.Fatalf("SetMembers: %v", err)
	}
	tpc.executive.mu.Lock()
	tpc.executive.dkgStartTime = time.Now().Add(-30 * time.Minute)
	tpc.executive.mu.Unlock()
	activateExecutive(t, tpc)

	if tpc.CheckDKGTimeout(5 * time.Minute) {
		t.Error("CheckDKGTimeout = true for an ACTIVE chamber; only ExecutiveDKGRunning " +
			"can time out")
	}
}
