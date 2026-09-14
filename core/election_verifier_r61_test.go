// Quantaureum Node source, version 1.0.0.
package core

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/types"
)

// R61-ELEC-DIVERGE-HEAL regression tests (2026-08-18) for QPOSElectionVerifier:
//   - A sealer whose local per-epoch VRF accumulator is polluted (non-zero but
//     wrong vs the canonical chain) would reject every canonical block at
//     that epoch forever. R61 heals: after the same (slot, epoch) is rejected
//     `healThreshold` times, VerifyProposer returns
//     ErrProposerScheduleNotReady so ValidateBlock trusts the canonical
//     ProposerAddr and lets ProcessBlock's SetEpochVRFAccumulator overwrite
//     the polluted local entry with the authoritative on-chain value.
//   - Already-healed epochs short-circuit to ErrProposerScheduleNotReady
//     without re-counting, so re-divergence at a later block of the SAME
//     epoch is repaired by the live SetEpochVRFAccumulator while the node
//     keeps importing canonical blocks.
//   - Switching to a different (slot, epoch) resets the counter, so only ONE
//     epoch is healed per divergence scene.

func TestR61_ElectionVerifier_PersistentRejectHealsToCanonicalTrust(t *testing.T) {
	q := r58NewTestQPOS(t)
	// Populate acc for epoch-1 (= epoch 3 − 2). Strict verification proceeds
	// but the local acc is the WRONG value vs the canonical chain — each
	// block at epoch 3 with the canonical ProposerAddr will mismatch locally.
	q.SetEpochVRFAccumulator(1, types.Hash{0x01})

	v := NewQPOSElectionVerifier(q)
	// Threshold 8 in prod; tests set 3 to exercise the heal deterministically.
	v.SetHealThreshold(3)

	// Compute the real QPOS-elected proposer for slot 96 epoch 3.
	expected, err := q.GetProposerForSlot(96)
	if err != nil || expected == nil {
		t.Fatalf("GetProposerForSlot: err=%v expected=%v", err, expected)
	}
	// `wrong` is the canonical ProposerAddr the chain actually carries; it
	// does NOT equal our local QPOS-elected expected.Address (the polluted
	// acc means local schedule differs).
	wrong := types.Address{0xEE}
	if wrong == expected.Address {
		wrong = types.Address{0xED}
	}

	// First two rejections produce "proposer mismatch" (the sealer still
	// trusts its local schedule). Verifier does NOT itself unwrap errors.*
	for i := 0; i < 2; i++ {
		err := v.VerifyProposer(wrong, 96, 3)
		if err == nil {
			t.Fatalf("rejection %d: expected mismatch error, got nil", i+1)
		}
		if errors.Is(err, ErrProposerScheduleNotReady) {
			t.Fatalf("rejection %d: prematurely healed", i+1)
		}
	}
	// Third rejection — count reaches the threshold, the heal fires and the
	// verifier returns ErrProposerScheduleNotReady so ValidateBlock trusts
	// the canonical ProposerAddr.
	healing := v.VerifyProposer(wrong, 96, 3)
	if !errors.Is(healing, ErrProposerScheduleNotReady) {
		t.Fatalf("threshold crossing: expected ErrProposerScheduleNotReady, got %v", healing)
	}
}

func TestR61_ElectionVerifier_AlreadyHealedEpochShortCircuits(t *testing.T) {
	q := r58NewTestQPOS(t)
	q.SetEpochVRFAccumulator(1, types.Hash{0x01})

	v := NewQPOSElectionVerifier(q)
	v.SetHealThreshold(1) // heal on first mismatch

	expected, _ := q.GetProposerForSlot(96)
	wrong := types.Address{0xEE}
	if wrong == expected.Address {
		wrong = types.Address{0xED}
	}

	// First mismatch => heal fires immediately (threshold=1).
	if err := v.VerifyProposer(wrong, 96, 3); !errors.Is(err, ErrProposerScheduleNotReady) {
		t.Fatalf("first mismatch: expected ErrProposerScheduleNotReady, got %v", err)
	}
	// Subsequent mismatches for the SAME epoch short-circuit to
	// ErrProposerScheduleNotReady without re-counting — the verifier has
	// already marked the epoch healed; subsequent blocks in this epoch are
	// repaired in flight by SetEpochVRFAccumulator. A DIFFERENT block in
	// the same epoch (different slot) must still heal immediately, not
	// count from scratch.
	for i := 0; i < 5; i++ {
		// Same epoch (3), different slots. Election for epoch 3 depends on
		// acc[1] — still the same (polluted) local value, so all of these
		// mismatch locally. Each call must return ErrProposerScheduleNotReady
		// (already-healed short-circuit).
		if err := v.VerifyProposer(wrong, 96+uint64(i), 3); !errors.Is(err, ErrProposerScheduleNotReady) {
			t.Fatalf("already-healed reuse %d: expected ErrProposerScheduleNotReady, got %v", i+1, err)
		}
	}
}

func TestR61_ElectionVerifier_NewEpochResetsCounter(t *testing.T) {
	q := r58NewTestQPOS(t)
	q.SetEpochVRFAccumulator(1, types.Hash{0x01}) // epoch 3 acc[1] present but wrong
	q.SetEpochVRFAccumulator(2, types.Hash{0x02}) // epoch 4 acc[2] present but wrong

	v := NewQPOSElectionVerifier(q)
	v.SetHealThreshold(3)

	expected3, _ := q.GetProposerForSlot(96)
	wrong3 := types.Address{0xEE}
	if wrong3 == expected3.Address {
		wrong3 = types.Address{0xED}
	}

	// Reject the epoch-3 block twice (below threshold), then switch to a
	// DIFFERENT (slot, epoch) pair (epoch 4). The counter must reset.
	for i := 0; i < 2; i++ {
		v.VerifyProposer(wrong3, 96, 3)
	}

	expected4, _ := q.GetProposerForSlot(128)
	wrong4 := types.Address{0xDD}
	if wrong4 == expected4.Address {
		wrong4 = types.Address{0xDC}
	}
	// First reject on the new epoch — this is rejection #1 for epoch 4 (not
	// #3, so it does NOT heal). Threshold=3, so healing must NOT fire here.
	err := v.VerifyProposer(wrong4, 128, 4)
	if errors.Is(err, ErrProposerScheduleNotReady) {
		t.Fatalf("new epoch first reject: should NOT have healed (counter reset), got %v", err)
	}
	// After 2 more rejections (=3 total for epoch 4), the heal fires.
	if err := v.VerifyProposer(wrong4, 128, 4); errors.Is(err, ErrProposerScheduleNotReady) {
		t.Fatalf("new epoch second reject: should NOT have healed yet, got %v", err)
	}
	healing := v.VerifyProposer(wrong4, 128, 4)
	if !errors.Is(healing, ErrProposerScheduleNotReady) {
		t.Fatalf("new epoch third reject: expected heal, got %v", healing)
	}
}

func TestR61_ElectionVerifier_SetHealThresholdRejectsZeroOrNegative(t *testing.T) {
	q := r58NewTestQPOS(t)
	v := NewQPOSElectionVerifier(q)
	// Default threshold
	if v.healThreshold != defaultHealThreshold {
		t.Fatalf("default threshold: got %d, want %d", v.healThreshold, defaultHealThreshold)
	}
	v.SetHealThreshold(0) // reset to default
	if v.healThreshold != defaultHealThreshold {
		t.Fatalf("after SetHealThreshold(0): got %d, want %d", v.healThreshold, defaultHealThreshold)
	}
	v.SetHealThreshold(-5) // negative also resets
	if v.healThreshold != defaultHealThreshold {
		t.Fatalf("after SetHealThreshold(-5): got %d, want %d", v.healThreshold, defaultHealThreshold)
	}
	v.SetHealThreshold(42)
	if v.healThreshold != 42 {
		t.Fatalf("after SetHealThreshold(42): got %d, want 42", v.healThreshold)
	}
}
