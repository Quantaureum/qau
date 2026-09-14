// Quantaureum Node source, version 1.0.0.
package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
)

// R58-ELEC-TRUST regression tests (2026-08-18) for QPOSElectionVerifier:
//   - A non-producing node configured with SetTrustCanonicalProposer(true)
//     must NEVER reject a block on proposer mismatch — it returns
//     ErrProposerScheduleNotReady (geth post-merge model: the EL does not
//     re-derive the beacon proposer, it follows the canonical chain).
//   - A sealer (trustCanonical=false) with a populated epoch-2 accumulator
//     must still verify strictly: matching proposer passes, mismatch fails.

func r58NewTestQPOS(t *testing.T) *consensus.QPOS {
	t.Helper()
	vals := make([]*consensus.Validator, 4)
	for i := 0; i < 4; i++ {
		var addr types.Address
		addr[0] = byte(i + 1)
		vals[i] = &consensus.Validator{
			Address: addr,
			Stake:   big.NewInt(int64((i + 1) * 1000)),
			Active:  true,
		}
	}
	vs, err := consensus.NewValidatorSet(vals)
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	q, err := consensus.NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	return q
}

func TestR58_ElectionVerifier_TrustCanonicalSkipsVerification(t *testing.T) {
	q := r58NewTestQPOS(t)
	// Populate the epoch-2 accumulator so strict verification WOULD proceed —
	// a trusting verifier must ignore it and trust canonical anyway.
	q.SetEpochVRFAccumulator(1, types.Hash{0x01})

	v := NewQPOSElectionVerifier(q)
	v.SetTrustCanonicalProposer(true)

	// Slot 96 = epoch 3, needs acc[1] (present). Any proposer (even zero) must
	// be accepted as "trust canonical", i.e. never a hard mismatch error.
	if err := v.VerifyProposer(types.Address{}, 96, 3); !errors.Is(err, ErrProposerScheduleNotReady) {
		t.Fatalf("trusting verifier error = %v; want ErrProposerScheduleNotReady", err)
	}
}

func TestR58_ElectionVerifier_StrictVerifiesWhenAccumulatorPresent(t *testing.T) {
	q := r58NewTestQPOS(t)
	q.SetEpochVRFAccumulator(1, types.Hash{0x01})

	v := NewQPOSElectionVerifier(q)
	// Default trustCanonical = false → strict verification.

	expected, err := q.GetProposerForSlot(96)
	if err != nil {
		t.Fatalf("GetProposerForSlot: %v", err)
	}
	if expected == nil {
		t.Fatal("no expected proposer for slot 96")
	}
	// Matching proposer must pass.
	if err := v.VerifyProposer(expected.Address, 96, 3); err != nil {
		t.Fatalf("matching proposer rejected: %v", err)
	}
	// A wrong proposer must be rejected in strict mode.
	wrong := types.Address{0xFE}
	if wrong == expected.Address {
		wrong = types.Address{0xFD}
	}
	if err := v.VerifyProposer(wrong, 96, 3); err == nil {
		t.Fatal("strict verifier accepted a mismatching proposer")
	}
}

func TestR58_ElectionVerifier_StrictColdStartStillTrusts(t *testing.T) {
	q := r58NewTestQPOS(t)
	// Do NOT populate acc[epoch-2] → cold-start → trust canonical, even in
	// strict mode (this is the R45-PoA-FIX behavior kept intact).
	v := NewQPOSElectionVerifier(q)
	if err := v.VerifyProposer(types.Address{}, 96, 3); !errors.Is(err, ErrProposerScheduleNotReady) {
		t.Fatalf("cold-start strict verifier error = %v; want ErrProposerScheduleNotReady", err)
	}
}
