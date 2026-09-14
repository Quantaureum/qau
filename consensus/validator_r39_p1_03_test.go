// Quantaureum Node source, version 1.0.0.
// R39-P1-03 (2026-08-02) regression tests.
//
// R38-P1-09 only routed self-registration (MinistryPersonnel.RegisterValidator)
// through ValidatorManager.AddValidator, which has its own MaxValidators cap.
// The staking-tx-driven sync path (node.syncStakingFromBlock →
// qpos.AddStakingValidator → ValidatorSet.AddValidator) STILL bypassed any
// capacity check, so a malicious proposer could push the live consensus
// ValidatorSet past the protocol MaxValidators ceiling in a single block.
//
// R39-P1-03 adds: AddStakingValidator enforces consensus.MaxValidators at the
// single chokepoint via `validatorsCapExceeded(size)`, so EVERY entry path
// (sync, RPC adapter, genesis/restart rehydration, future callers) is held
// to the same invariant.
//
// These tests pin:
//
//	(a) the cap boundary (size == MaxValidators → exceeded; size == cap-1 → not)
//	(b) MaxValidators protocol stability (changing it silently invalidates the
//	    consensus data-structure sizing assumptions — MaxTrackedValidators,
//	    MaxVoteHistoryEntries, etc.).
//	(c) AddStakingValidator on a fresh small QPOS still accepts validators
//	    (regression guard: the cap check must not turn into an "always reject"
//	    bug).
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestR39_P1_03_ValidatorsCapExceeded pins the cap boundary. The cap is
// EXCLUSIVE: when the ValidatorSet already has MaxValidators entries, the
// next AddStakingValidator MUST be rejected; one below the cap leaves room
// for exactly one more.
func TestR39_P1_03_ValidatorsCapExceeded(t *testing.T) {
	if MaxValidators != 250000 {
		t.Fatalf("MaxValidators drift — protocol stability assumption broken: got %d, want 250000", MaxValidators)
	}
	if validatorsCapExceeded(int(MaxValidators)) {
		// expected: MaxValidators → exceeded (true). Re-assert explicitly.
	} else {
		t.Errorf("validatorsCapExceeded(MaxValidators) must be true (set is full): got false")
	}
	if validatorsCapExceeded(int(MaxValidators) - 1) {
		t.Errorf("validatorsCapExceeded(MaxValidators-1) must be false (room for one more): got true")
	}
	if validatorsCapExceeded(int(MaxValidators)+1) != true {
		t.Errorf("validatorsCapExceeded(MaxValidators+1) must be true")
	}
	if validatorsCapExceeded(0) {
		t.Errorf("validatorsCapExceeded(0) must be false")
	}
}

// TestR39_P1_03_AddStakingValidator_StillAcceptsUnderCap is the regression
// guard: the new cap check must not turn into an "always reject" bug that
// silently breaks all staking-tx sync. Construct a minimal QPOS with a small
// validator set and assert AddStakingValidator returns true under the cap.
func TestR39_P1_03_AddStakingValidator_StillAcceptsUnderCap(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	addr := types.Address{0x42}
	added := qpos.AddStakingValidator(addr, big.NewInt(1000))
	if !added {
		t.Fatal("AddStakingValidator MUST return true under the cap (regression guard)")
	}
	// Idempotency: re-adding the SAME address returns false (already in the
	// set) and must NOT be interpreted as a cap rejection.
	if qpos.AddStakingValidator(addr, big.NewInt(2000)) {
		t.Fatal("AddStakingValidator on an existing address returns false (updates stake, not added)")
	}
}
