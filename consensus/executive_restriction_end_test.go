// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
)

// executiveRestrictionFixture builds a QPOS with chambers over n equal-stake
// validators and an ACTIVE executive chamber whose single member is execIdx.
func executiveRestrictionFixture(t *testing.T, n, execIdx int, slot uint64) (*QPOS, *ThreeChambersCoordinator) {
	t.Helper()
	qpos, err := NewQPOS(createTestValidatorSet(t, n))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.InitChambers()
	tpc := qpos.GetChambersCoordinator()
	if tpc == nil {
		t.Fatal("coordinator is nil")
	}
	epoch := SlotToEpoch(slot)
	if err := tpc.executive.SetMembers([]int{execIdx}, epoch); err != nil {
		t.Fatalf("SetMembers: %v", err)
	}
	tpc.assignment.Assign(execIdx, ChamberExecutive, 0, epoch)
	activateExecutive(t, tpc)
	return qpos, tpc
}

// asExecutiveOf records the executive role for the epoch, as the epoch
// transition does at every boundary. The role is per epoch and a validator holds
// one role record at a time, so each epoch under test needs its own assignment.
func asExecutiveOf(tpc *ThreeChambersCoordinator, execIdx int, epoch uint64) {
	tpc.assignment.Assign(execIdx, ChamberExecutive, 0, epoch)
}

// attestersFor counts the validators the chambers allow to attest in the slot.
func attestersFor(tpc *ThreeChambersCoordinator, n int, slot uint64) int {
	count := 0
	for index := 0; index < n; index++ {
		if tpc.CanAttest(index, slot) {
			count++
		}
	}
	return count
}

// The restriction is off by default: an active executive member keeps losing
// its rights until a network configures the end epoch, so upgrading a binary
// alone never changes who may propose or attest.
func TestExecutiveRestrictionEndEpochDefaultsToNever(t *testing.T) {
	const execIdx = 2
	const slot = uint64(40)
	qpos, tpc := executiveRestrictionFixture(t, 6, execIdx, slot)
	if got := qpos.GetExecutiveRestrictionEndEpoch(); got != 0 {
		t.Fatalf("default end epoch = %d, want 0 (never)", got)
	}
	for _, probe := range []uint64{slot, slot + 32*50, slot + 32*5000} {
		asExecutiveOf(tpc, execIdx, SlotToEpoch(probe))
		if tpc.CanPropose(execIdx, probe) || tpc.CanAttest(execIdx, probe) {
			t.Fatalf("slot %d: an active executive member has rights with no end epoch configured", probe)
		}
	}
}

// From the configured epoch on, the active executive member proposes and
// attests like every other validator; before it nothing changes. The per-slot
// proposer and reviewer exclusions are independent of the executive chamber
// and stay in force on both sides of the end epoch.
func TestExecutiveRestrictionEndEpochLiftsExactlyFromThatEpoch(t *testing.T) {
	const execIdx = 2
	const slot = uint64(40) // epoch 1
	qpos, tpc := executiveRestrictionFixture(t, 6, execIdx, slot)

	end := SlotToEpoch(slot) + 2 // epoch 3
	qpos.SetExecutiveRestrictionEndEpoch(end)
	if got := qpos.GetExecutiveRestrictionEndEpoch(); got != end {
		t.Fatalf("end epoch = %d, want %d", got, end)
	}
	lastBefore := EpochStartSlot(end) - 1
	first := EpochStartSlot(end)

	asExecutiveOf(tpc, execIdx, SlotToEpoch(lastBefore))
	if tpc.CanPropose(execIdx, lastBefore) || tpc.CanAttest(execIdx, lastBefore) {
		t.Fatalf("slot %d (epoch %d, before the end epoch): the executive member already has rights", lastBefore, SlotToEpoch(lastBefore))
	}
	if err := tpc.AssignProposing(execIdx, lastBefore); err == nil {
		t.Fatalf("AssignProposing(%d, slot %d) succeeded before the end epoch", execIdx, lastBefore)
	}
	asExecutiveOf(tpc, execIdx, SlotToEpoch(first))
	if !tpc.CanPropose(execIdx, first) || !tpc.CanAttest(execIdx, first) {
		t.Fatalf("slot %d (the end epoch): the executive member still lacks its rights", first)
	}
	if err := tpc.AssignProposing(execIdx, first); err != nil {
		t.Fatalf("AssignProposing(%d, slot %d) = %v; the executive member must be able to hold the proposing role from the end epoch", execIdx, first, err)
	}

	// The proposer of a slot never attests for its own block, on either side.
	const other = 4
	for _, probe := range []uint64{lastBefore, first + 1} {
		if err := tpc.AssignProposing(other, probe); err != nil {
			t.Fatalf("AssignProposing(%d, slot %d): %v", other, probe, err)
		}
		if tpc.CanAttest(other, probe) {
			t.Fatalf("slot %d: the slot's proposer may attest", probe)
		}
	}
	// A reviewer of a slot may not propose it.
	if err := tpc.AssignReview([]int{5}, first+2); err != nil {
		t.Fatalf("AssignReview: %v", err)
	}
	if tpc.CanPropose(5, first+2) {
		t.Fatal("a reviewer of the slot may propose it")
	}

	// The executive member can be named to a slot's review committee from the
	// end epoch on and not before; the conflict check follows the same epoch.
	asExecutiveOf(tpc, execIdx, SlotToEpoch(lastBefore))
	if err := tpc.AssignReview([]int{execIdx}, lastBefore); err == nil {
		t.Fatalf("AssignReview named the executive member to slot %d before the end epoch", lastBefore)
	}
	asExecutiveOf(tpc, execIdx, SlotToEpoch(first))
	if err := tpc.AssignReview([]int{execIdx}, first+3); err != nil {
		t.Fatalf("AssignReview(%d, slot %d) = %v; the executive conflict must end with the restriction", execIdx, first+3, err)
	}
}

// The reason the restriction ends: with it in force n-2 validators can attest
// (the proposer and the executive member cannot), which at the minimum chamber
// sizes is exactly the two-thirds the review verdict needs, so any one offline
// validator stops review approval and with it QTD sealing and Casper
// justification. Once it has ended n-1 can attest and one offline validator
// is tolerated.
func TestExecutiveRestrictionEndToleratesOneOfflineValidator(t *testing.T) {
	for _, n := range []int{6, 7} {
		const execIdx = 2
		const slot = uint64(40)
		qpos, tpc := executiveRestrictionFixture(t, n, execIdx, slot)
		// The slot's proposer is another validator.
		if err := tpc.AssignProposing(3, slot); err != nil {
			t.Fatal(err)
		}
		needed := func(attesting int) bool { return attesting*3 >= 2*n }

		withRestriction := attestersFor(tpc, n, slot)
		if withRestriction != n-2 {
			t.Fatalf("n=%d: %d validators may attest with the restriction in force, want n-2", n, withRestriction)
		}
		if !needed(withRestriction) {
			t.Fatalf("n=%d: even with every validator online the restricted quorum %d/%d is short", n, withRestriction, n)
		}
		if needed(withRestriction - 1) {
			t.Fatalf("n=%d: the restricted quorum tolerates an offline validator; the premise of the change is wrong", n)
		}

		qpos.SetExecutiveRestrictionEndEpoch(SlotToEpoch(slot))
		afterEnd := attestersFor(tpc, n, slot)
		if afterEnd != n-1 {
			t.Fatalf("n=%d: %d validators may attest after the end epoch, want n-1", n, afterEnd)
		}
		if !needed(afterEnd - 1) {
			t.Fatalf("n=%d: after the end epoch one offline validator still breaks the quorum (%d/%d)", n, afterEnd-1, n)
		}
		if needed(afterEnd - 2) {
			t.Fatalf("n=%d: two offline validators unexpectedly keep the quorum", n)
		}
	}
}
