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
// Yet CanPropose / CanAttest already deny that validator both rights for the
// whole epoch. The member can lose proposer rewards and the attestation path
// even while it is active and staked.
//
// ROOT CAUSE: the COST of the Three Chambers power separation (an Executive
// member may not propose or attest) was enforced while its BENEFIT (an
// activated executive chamber performing threshold sealing) was unreachable.
// A chamber that cannot perform its duty must not strip its member's rights.
//
// FIX: ChamberExecutive restrictions in CanPropose / CanAttest /
// AssignProposing apply only while the executive chamber is genuinely
// active (ExecutiveActive or ExecutiveSealing). While DKG is pending the
// network degrades to equal rights for all validators — the behavior that
// was verified working in epoch 0's cold-start round-robin.
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

// TestR93_DKGPendingExecutiveKeepsProposeAndAttestRights is the primary
// fails-without-fix test. Before the fix both assertions fail with
// "CanPropose=false" / "CanAttest=false".
func TestR93_DKGPendingExecutiveKeepsProposeAndAttestRights(t *testing.T) {
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

	if !tpc.CanPropose(execIdx, slot) {
		t.Errorf("CanPropose(%d, slot %d) = false; an executive member whose DKG never "+
			"completes must keep its proposing right (R93-CHAMBER-DEGRADED). "+
			"This must not happen while the chamber cannot seal.", execIdx, slot)
	}
	if !tpc.CanAttest(execIdx, slot) {
		t.Errorf("CanAttest(%d, slot %d) = false; an executive member whose DKG never "+
			"completes must keep its attesting right (R93-CHAMBER-DEGRADED). "+
			"This must not happen while the chamber cannot seal.", execIdx, slot)
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

// TestR93_AssignProposingSucceedsForDKGPendingExecutive covers the follow-on
// failure the fix would otherwise expose: once the executive member is elected
// again, GetProposerForSlot calls AssignProposing, whose conflict check also
// keys off ChamberExecutive membership. Without the same relaxation it returns
// ErrProposerPowerExceeded and every slot logs "AssignProposing failed".
func TestR93_AssignProposingSucceedsForDKGPendingExecutive(t *testing.T) {
	tpc := newDegradedTestCoordinator(t)

	const execIdx = 2
	const slot = uint64(40)
	epoch := SlotToEpoch(slot)

	if err := tpc.executive.SetMembers([]int{execIdx}, epoch); err != nil {
		t.Fatalf("SetMembers: %v", err)
	}
	tpc.assignment.Assign(execIdx, ChamberExecutive, 0, epoch)

	if err := tpc.AssignProposing(execIdx, slot); err != nil {
		t.Errorf("AssignProposing(%d, slot %d) = %v; must succeed while the executive "+
			"chamber's DKG is pending, otherwise the elected proposer is rejected every "+
			"slot (R93-CHAMBER-DEGRADED)", execIdx, slot, err)
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
