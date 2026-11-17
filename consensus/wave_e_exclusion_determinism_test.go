// Quantaureum Node source, version 1.0.0.
//
// Wave E (PR 18): the executive exclusion is deterministic per target epoch;
// this file pins the two-state (DKG-pending vs complete) election-equivalence
// invariant and the epoch-6/9 boundary-plus-two-slot fork shape.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// TSS-R3-B1-Wave-E regression tests: deterministic executive exclusion.
//
// Root cause (audit-verified): ThreeChambersCoordinator.CanPropose /
// CanAttest gated the Executive exclusion on executiveRestrictionsApplyLocked,
// which required ExecutiveChamber.IsActive() — a per-node wall-clock state
// (the local DKG completion moment). Around an epoch boundary the member
// slots were therefore decided on local DKG progress: nodes whose DKG had
// completed skipped the member (proposer scan hands the slot to the next
// eligible validator) while nodes still in DKGRunning elected the member.
// Observed as devnet forks at the boundary+2 member slots (4v2 split).
//
// Fix: the exclusion is a deterministic pure function of the epoch-scoped
// Executive role written by SelectExecutiveForEpoch. The member set is
// excluded for the ENTIRE epoch it was selected for, decoupled from the local
// DKG state machine.

// waveExclusionFixture builds a QPOS over n equal-stake validators with
// chambers initialized and the on-chain epoch-2 VRF accumulator the
// production transition reads (SelectExecutiveForEpoch cold-start guard,
// R88-F). Every call returns an independent instance with byte-identical
// inputs, so two instances differ ONLY in the state a test applies afterwards.
func waveExclusionFixture(t *testing.T, n int, epoch uint64) (*QPOS, *ValidatorSet) {
	t.Helper()
	vs := createTestValidatorSet(t, n)
	qpos, err := NewQPOS(createTestValidatorSet(t, n))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.InitChambers()
	if epoch >= 2 {
		// Any fixed non-zero hash stands in for the on-chain accumulator; the
		// selection is a pure function of (epoch, accumulator, validator set).
		qpos.SetEpochVRFAccumulator(epoch-2, types.Hash{0xA1, 0xB2, 0xC3, 0xD4})
	}
	return qpos, vs
}

// waveGroupKey returns a deterministic correctly-sized Dilithium3 group
// public key for SetDKGComplete.
func waveGroupKey() []byte {
	groupKey := make([]byte, crypto.Dilithium3PublicKeySize)
	for i := range groupKey {
		groupKey[i] = byte(i % 251)
	}
	return groupKey
}

// TestWaveE_TwoStateElectionDeterminism is the core invariant of the fix:
// for the same (slot, on-chain state), proposer/attester eligibility is
// IDENTICAL whether the local DKG has completed or is still pending. Under
// the old IsActive()-gated rule the DKG-pending state elected the member
// where the DKG-complete state skipped it — the fork mechanism.
//
// Both states are produced through the production transition path
// (TransitionExecutiveForEpoch): an empty group key leaves the chamber in
// ExecutiveDKGRunning after member selection; a valid key activates it.
func TestWaveE_TwoStateElectionDeterminism(t *testing.T) {
	const n = 6
	const epoch = 6 // first devnet incident epoch

	pendingQPOS, vs := waveExclusionFixture(t, n, epoch)
	activeQPOS, _ := waveExclusionFixture(t, n, epoch)

	pendingTpc := pendingQPOS.GetChambersCoordinator()
	if err := pendingTpc.TransitionExecutiveForEpoch(epoch, vs, nil); err != nil {
		t.Fatalf("pending-state transition: %v", err)
	}
	pendingExec := pendingTpc.GetExecutiveChamber()
	if pendingExec.State() != ExecutiveDKGRunning || pendingExec.IsActive() {
		t.Fatalf("precondition: pending-state chamber must be DKGRunning/inactive, state=%s active=%v",
			pendingExec.State(), pendingExec.IsActive())
	}

	activeTpc := activeQPOS.GetChambersCoordinator()
	if err := activeTpc.TransitionExecutiveForEpoch(epoch, vs, waveGroupKey()); err != nil {
		t.Fatalf("active-state transition: %v", err)
	}
	activeExec := activeTpc.GetExecutiveChamber()
	if !activeExec.IsActive() {
		t.Fatalf("precondition: active-state chamber must be active, state=%s", activeExec.State())
	}

	// Deterministic selection: both states must hold the SAME member set.
	pendingMembers := pendingExec.Members()
	activeMembers := activeExec.Members()
	if len(pendingMembers) == 0 {
		t.Fatal("no executive members selected")
	}
	if len(pendingMembers) != len(activeMembers) {
		t.Fatalf("member set diverged across states: %v vs %v", pendingMembers, activeMembers)
	}
	for i := range pendingMembers {
		if pendingMembers[i] != activeMembers[i] {
			t.Fatalf("member set diverged across states: %v vs %v", pendingMembers, activeMembers)
		}
	}

	start := EpochStartSlot(epoch)
	for slot := start; slot < start+SlotsPerEpoch; slot++ {
		for idx := 0; idx < n; idx++ {
			if gotP, gotA := pendingQPOS.CanPropose(idx, slot), activeQPOS.CanPropose(idx, slot); gotP != gotA {
				t.Fatalf("slot %d validator %d: CanPropose diverged across DKG states (pending=%v active=%v)",
					slot, idx, gotP, gotA)
			}
			if gotP, gotA := pendingQPOS.CanAttest(idx, slot), activeQPOS.CanAttest(idx, slot); gotP != gotA {
				t.Fatalf("slot %d validator %d: CanAttest diverged across DKG states (pending=%v active=%v)",
					slot, idx, gotP, gotA)
			}
		}
	}

	// The semantic change vs R93, asserted explicitly: the member is excluded
	// in the DKG-PENDING state too, for the whole epoch.
	for _, m := range pendingMembers {
		for slot := start; slot < start+SlotsPerEpoch; slot++ {
			if pendingQPOS.CanPropose(m, slot) || pendingQPOS.CanAttest(m, slot) {
				t.Fatalf("slot %d: member %d keeps propose/attest rights while DKG is pending; "+
					"the exclusion must apply for the whole epoch from member selection", slot, m)
			}
		}
	}

	// Attester headcount is deterministic in both states: every non-member
	// can attest, no member can.
	for slot := start; slot < start+SlotsPerEpoch; slot++ {
		countP, countA := 0, 0
		for idx := 0; idx < n; idx++ {
			if pendingQPOS.CanAttest(idx, slot) {
				countP++
			}
			if activeQPOS.CanAttest(idx, slot) {
				countA++
			}
		}
		if countP != countA || countP != n-len(pendingMembers) {
			t.Fatalf("slot %d: attester count pending=%d active=%d, want %d",
				slot, countP, countA, n-len(pendingMembers))
		}
	}
}

// TestWaveE_BoundaryPlusTwoMemberSlotDeterministic mirrors the devnet fork
// shape: the executive member is scheduled at boundary+2 of an incident-like
// epoch. Pre-fix, nodes whose local DKG had completed elected the next
// eligible validator while nodes still in DKGRunning elected the member —
// the observed 4v2 split. Post-fix, both states must elect the SAME
// proposer through the real election path (GetProposerForSlot, including
// the scan that hands the member's slot over).
func TestWaveE_BoundaryPlusTwoMemberSlotDeterministic(t *testing.T) {
	const n = 6
	const epoch = 9 // second devnet incident epoch

	pendingQPOS, vs := waveExclusionFixture(t, n, epoch)
	activeQPOS, _ := waveExclusionFixture(t, n, epoch)

	pendingTpc := pendingQPOS.GetChambersCoordinator()
	if err := pendingTpc.TransitionExecutiveForEpoch(epoch, vs, nil); err != nil {
		t.Fatalf("pending-state transition: %v", err)
	}
	member := pendingTpc.GetExecutiveChamber().Members()[0]

	activeTpc := activeQPOS.GetChambersCoordinator()
	if err := activeTpc.TransitionExecutiveForEpoch(epoch, vs, waveGroupKey()); err != nil {
		t.Fatalf("active-state transition: %v", err)
	}
	if !activeTpc.GetExecutiveChamber().IsActive() {
		t.Fatal("precondition: active-state chamber must be active")
	}

	// Craft the epoch shuffle so the member sits exactly at boundary+2
	// (slotInEpoch == 2). Both instances get the identical permutation — a
	// stand-in for the deterministic on-chain shuffle every node computes.
	perm := make([]int, 0, n)
	for i := 0; i < n; i++ {
		if i != member {
			perm = append(perm, i)
		}
	}
	perm = append(perm[:2], append([]int{member}, perm[2:]...)...)
	pendingQPOS.mu.Lock()
	pendingQPOS.shuffleCache[epoch] = perm
	pendingQPOS.mu.Unlock()
	activeQPOS.mu.Lock()
	activeQPOS.shuffleCache[epoch] = perm
	activeQPOS.mu.Unlock()

	slot := EpochStartSlot(epoch) + 2
	pendingProp, errP := pendingQPOS.GetProposerForSlot(slot)
	activeProp, errA := activeQPOS.GetProposerForSlot(slot)
	if errP != nil || errA != nil {
		t.Fatalf("GetProposerForSlot(%d): pending err=%v, active err=%v", slot, errP, errA)
	}

	memberAddr := pendingQPOS.GetValidatorSet().GetValidatorByIndex(member).Address
	if pendingProp.Address == memberAddr {
		t.Fatalf("slot %d: the DKG-pending state still elected the executive member; "+
			"the exclusion must skip the member deterministically", slot)
	}
	if pendingProp.Address != activeProp.Address {
		t.Fatalf("slot %d: proposer diverged across DKG states (pending=%s active=%s) — "+
			"this is exactly the devnet fork shape", slot, pendingProp.Address, activeProp.Address)
	}
}

// TestWaveE_PreTransitionAndRestrictionEndEdges pins the remaining edge
// behavior of the deterministic gate: before the epoch's member set has been
// selected nobody is excluded (the role map holds no entry for that epoch),
// and the executive restriction end epoch still lifts the exclusion exactly
// as before.
func TestWaveE_PreTransitionAndRestrictionEndEdges(t *testing.T) {
	const n = 6
	const epoch = 3

	qpos, vs := waveExclusionFixture(t, n, epoch)
	tpc := qpos.GetChambersCoordinator()

	// Pre-transition: no selection for this epoch has run on this node, so
	// no validator is excluded — matching every peer that has not imported
	// the boundary block either (a node can only produce the epoch's first
	// block in that window, which no peer has seen either).
	start := EpochStartSlot(epoch)
	for slot := start; slot < start+3; slot++ {
		for idx := 0; idx < n; idx++ {
			if !qpos.CanPropose(idx, slot) {
				t.Fatalf("pre-transition slot %d: validator %d already excluded without a selected member set", slot, idx)
			}
		}
	}

	// Run the production transition; the member set is now excluded for the
	// whole epoch.
	if err := tpc.TransitionExecutiveForEpoch(epoch, vs, nil); err != nil {
		t.Fatalf("transition: %v", err)
	}
	member := tpc.GetExecutiveChamber().Members()[0]
	if qpos.CanPropose(member, start+SlotsPerEpoch-1) {
		t.Fatal("post-transition: member not excluded at the epoch's last slot")
	}

	// From the restriction end epoch the exclusion is lifted, unchanged.
	end := uint64(epoch + 1)
	qpos.SetExecutiveRestrictionEndEpoch(end)
	nextStart := EpochStartSlot(end)
	if !qpos.CanPropose(member, nextStart) {
		t.Fatal("restriction end epoch must lift the deterministic exclusion")
	}
}

// TestWaveE_ChambersDisabledNetworksUnchanged pins the zero-change guarantee:
// a network that never enabled chambers has no coordinator and no Executive
// roles, so neither the old nor the new exclusion can influence any election
// outcome. Every validator can propose in every slot and every slot elects a
// proposer exactly as before the fix.
func TestWaveE_ChambersDisabledNetworksUnchanged(t *testing.T) {
	qpos, err := NewQPOS(createTestValidatorSet(t, 6))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	if qpos.HasChambers() {
		t.Fatal("precondition: chambers must be disabled")
	}

	for slot := uint64(0); slot < SlotsPerEpoch*2; slot++ {
		for idx := 0; idx < 6; idx++ {
			if !qpos.CanPropose(idx, slot) {
				t.Fatalf("slot %d validator %d: chambers-disabled network must not exclude any proposer", slot, idx)
			}
		}
		if _, err := qpos.GetProposerForSlot(slot); err != nil {
			t.Fatalf("slot %d: GetProposerForSlot: %v", slot, err)
		}
	}
}
