// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// R58-VRF-PERSIST regression tests (2026-08-18) for the QPOS-side
// persistence hooks:
//   - SetVRFPersistCallback must fire on every authoritative
//     SetEpochVRFAccumulator commit (node.go → block store), so the durable
//     checkpoint always tracks the on-chain value.
//   - SetAllEpochVRFAccumulators must bulk-load persisted checkpoints at
//     startup WITHOUT re-firing the callback (those values just came from the
//     store; persisting them again would be a no-op write storm).

func TestR58_VRFPersist_CallbackFiresOnSet(t *testing.T) {
	vs, err := NewValidatorSet(createTestValidators(t, 4))
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	var gotEpoch uint64
	var gotAcc types.Hash
	calls := 0
	qpos.SetVRFPersistCallback(func(epoch uint64, acc types.Hash) {
		calls++
		gotEpoch, gotAcc = epoch, acc
	})

	wantAcc := types.Hash{0x42}
	qpos.SetEpochVRFAccumulator(777, wantAcc)
	if calls != 1 {
		t.Fatalf("callback calls = %d; want 1", calls)
	}
	if gotEpoch != 777 || gotAcc != wantAcc {
		t.Fatalf("callback got epoch=%d acc=%v; want epoch=777 acc=%v", gotEpoch, gotAcc, wantAcc)
	}
}

func TestR58_VRFPersist_BulkLoadSkipsCallback(t *testing.T) {
	vs, err := NewValidatorSet(createTestValidators(t, 4))
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	calls := 0
	qpos.SetVRFPersistCallback(func(epoch uint64, acc types.Hash) { calls++ })

	// Bulk-load from "the store" — must NOT re-persist via callback.
	qpos.SetAllEpochVRFAccumulators(map[uint64]types.Hash{
		10: {0x01},
		11: {0x02},
	})
	if calls != 0 {
		t.Fatalf("SetAllEpochVRFAccumulators fired persistence callback %d times; want 0", calls)
	}
	if got := qpos.GetEpochVRFAccumulator(10); got != (types.Hash{0x01}) {
		t.Fatalf("acc[10] = %v; want {0x01}", got)
	}
	if got := qpos.GetEpochVRFAccumulator(11); got != (types.Hash{0x02}) {
		t.Fatalf("acc[11] = %v; want {0x02}", got)
	}
}

func TestR58_VRFPersist_BulkLoadSkipsZeroHash(t *testing.T) {
	vs, err := NewValidatorSet(createTestValidators(t, 4))
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	// Zero-hash entries (stale/empty checkpoints) must be ignored on load.
	qpos.SetAllEpochVRFAccumulators(map[uint64]types.Hash{
		5:  {0x05},
		6:  {},
		20: {0x14},
	})
	if got := qpos.GetEpochVRFAccumulator(5); got != (types.Hash{0x05}) {
		t.Fatalf("acc[5] = %v; want {0x05}", got)
	}
	if got := qpos.GetEpochVRFAccumulator(6); got != (types.Hash{}) {
		t.Fatalf("acc[6] = %v; want zero (skipped)", got)
	}
	if got := qpos.GetEpochVRFAccumulator(20); got != (types.Hash{0x14}) {
		t.Fatalf("acc[20] = %v; want {0x14}", got)
	}
}
