// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// r88fSetup builds a QPOS with chambers and n validators.
func r88fSetup(t *testing.T, n int) (*QPOS, *ThreeChambersCoordinator, *ValidatorSet) {
	t.Helper()
	vals := make([]*Validator, n)
	for i := 0; i < n; i++ {
		var addr [20]byte
		addr[0] = byte(i + 1)
		vals[i] = &Validator{
			Address:        types.Address(addr),
			Stake:          big.NewInt(1000),
			Active:         true,
			PublicKeyBytes: []byte{byte(i + 1)},
		}
	}
	vs, err := NewValidatorSet(vals)
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.InitChambers()
	coord := qpos.GetChambersCoordinator()
	if coord == nil {
		t.Fatal("GetChambersCoordinator returned nil")
	}
	return qpos, coord, vs
}

// TestR88F_SelectExecutive_ColdStartFailsClosed verifies the R88-F contract:
// on a NORMAL chain (first block at epoch 0/1, so the epoch-2 accumulator
// SHOULD exist on-chain), a node whose local acc[epoch-2] is not yet loaded
// (restarting sealer replaying the chain) must NOT select the Executive
// Chamber with the zero hash — it must return ErrExecutiveScheduleNotReady
// and must NOT cache anything.
//
// Fails without the R88-F fix: the old code silently selected zero-hash
// members and cached them in epochExecutive[epoch], so a restarting node's
// CanPropose (which forbids Executive members from proposing) diverged from
// its peers for the rest of the epoch.
func TestR88F_SelectExecutive_ColdStartFailsClosed(t *testing.T) {
	qpos, coord, vs := r88fSetup(t, 8)

	// Chain starts at epoch 1 (normal genesis-ish chain): acc[0] SHOULD
	// exist on-chain once epoch 0's blocks are imported.
	qpos.SetFirstBlockEpoch(1)

	const epoch = uint64(5) // needs acc[3]; not populated (cold-start)

	_, err := coord.SelectExecutiveForEpoch(epoch, vs)
	if !errors.Is(err, ErrExecutiveScheduleNotReady) {
		t.Fatalf("expected ErrExecutiveScheduleNotReady, got %v", err)
	}

	// Must NOT cache the failed selection: a later call after the
	// accumulator arrives must be able to select (see next test).
	coord.mu.RLock()
	_, cached := coord.epochExecutive[epoch]
	coord.mu.RUnlock()
	if cached {
		t.Fatal("cold-start selection was cached in epochExecutive — R88-F contract violation (poisoned cache)")
	}
}

// TestR88F_SelectExecutive_RecoversAfterAccumulatorArrives verifies the
// retry path: after SetEpochVRFAccumulator populates acc[epoch-2], the same
// epoch selects successfully (and the result is then cached).
func TestR88F_SelectExecutive_RecoversAfterAccumulatorArrives(t *testing.T) {
	qpos, coord, vs := r88fSetup(t, 8)
	qpos.SetFirstBlockEpoch(1)

	const epoch = uint64(5)

	// Cold-start refusal first.
	if _, err := coord.SelectExecutiveForEpoch(epoch, vs); !errors.Is(err, ErrExecutiveScheduleNotReady) {
		t.Fatalf("expected ErrExecutiveScheduleNotReady on cold-start, got %v", err)
	}

	// Accumulator arrives (canonical import path).
	qpos.SetEpochVRFAccumulator(epoch-2, types.Hash{0xAB})

	members, err := coord.SelectExecutiveForEpoch(epoch, vs)
	if err != nil {
		t.Fatalf("SelectExecutiveForEpoch after accumulator arrival: %v", err)
	}
	if len(members) == 0 {
		t.Fatal("expected non-empty executive selection")
	}

	// Determinism: same inputs → same members (cached).
	members2, err := coord.SelectExecutiveForEpoch(epoch, vs)
	if err != nil {
		t.Fatalf("SelectExecutiveForEpoch (2nd): %v", err)
	}
	if len(members) != len(members2) {
		t.Fatalf("cached selection changed length: %d vs %d", len(members), len(members2))
	}
	for i := range members {
		if members[i] != members2[i] {
			t.Fatalf("cached selection changed at %d: %d vs %d", i, members[i], members2[i])
		}
	}
}

// TestR88F_SelectExecutive_HighGenesisExemption verifies the R80-style
// exemption: on a high-genesis chain the epoch-2 accumulator CANNOT exist
// on-chain, so zero-hash selection is identical on every node and must
// proceed (fail-closing here would permanently disable the Executive
// chamber on every devnet/rehearsal chain).
func TestR88F_SelectExecutive_HighGenesisExemption(t *testing.T) {
	qpos, coord, vs := r88fSetup(t, 8)

	// Chain starts at epoch 557 (static genesis, old genesisTime): epochs
	// 557/558 select with the zero hash on every node.
	qpos.SetFirstBlockEpoch(557)

	for _, epoch := range []uint64{557, 558} {
		members, err := coord.SelectExecutiveForEpoch(epoch, vs)
		if err != nil {
			t.Fatalf("SelectExecutiveForEpoch(epoch=%d) under high-genesis exemption: %v", epoch, err)
		}
		if len(members) == 0 {
			t.Fatalf("epoch %d: expected non-empty selection", epoch)
		}
	}

	// epoch 559 needs acc[557] which CAN exist on-chain (epoch 557 blocks
	// are being produced) → a missing local acc[557] must still fail-closed.
	if _, err := coord.SelectExecutiveForEpoch(559, vs); !errors.Is(err, ErrExecutiveScheduleNotReady) {
		t.Fatalf("expected ErrExecutiveScheduleNotReady for epoch 559 with missing acc[557], got %v", err)
	}
}

// TestR88F_TransitionFailClosedNoDeadlock verifies that a cold-start
// TransitionExecutiveForEpoch failure leaves CanPropose permissive (no
// Executive assignment → no proposing restriction), so the fail-closed
// guard can never deadlock block production.
func TestR88F_TransitionFailClosedNoDeadlock(t *testing.T) {
	qpos, _, _ := r88fSetup(t, 8)
	qpos.SetFirstBlockEpoch(1)

	// No Executive assignment exists for the epoch → every non-slashed
	// validator can propose.
	slot := uint64(5*SlotsPerEpoch + 3)
	for i := 0; i < 8; i++ {
		if !qpos.CanPropose(i, slot) {
			t.Fatalf("validator %d blocked from proposing with no Executive assignment (deadlock regression)", i)
		}
	}
}
