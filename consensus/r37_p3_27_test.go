// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
)

// TestR37_P3_27_EpochExecutiveRetention verifies the R37-P3-27 fix:
// ThreeChambersCoordinator.epochExecutive no longer grows without bound.
// SelectExecutiveForEpoch (the production epoch-boundary path, invoked via
// TransitionExecutiveForEpoch) now prunes assignments older than
// epochExecutiveRetainEpochs, while recent epochs remain queryable via
// HasExecutiveAssignment / GetExecutiveMembersForEpoch / CanSeal.
func TestR37_P3_27_EpochExecutiveRetention(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil after InitChambers")
	}

	// Select executive members across more epochs than the retention window.
	const lastEpoch = uint64(2*epochExecutiveRetainEpochs + 50)

	// R88-F: high-genesis exemption — the retention test spans a synthetic
	// epoch range with no on-chain accumulators; exempt all of it.
	qpos.SetFirstBlockEpoch(lastEpoch + 10)

	for e := uint64(0); e <= lastEpoch; e++ {
		if _, err := coordinator.SelectExecutiveForEpoch(e, vs); err != nil {
			t.Fatalf("SelectExecutiveForEpoch(%d) failed: %v", e, err)
		}
	}

	coordinator.mu.RLock()
	size := len(coordinator.epochExecutive)
	coordinator.mu.RUnlock()
	if size > epochExecutiveRetainEpochs {
		t.Fatalf("epochExecutive size = %d, exceeds retention window %d (unbounded growth)",
			size, epochExecutiveRetainEpochs)
	}

	oldestRetained := lastEpoch - epochExecutiveRetainEpochs + 1

	// Epochs older than the window must have been pruned.
	for _, e := range []uint64{0, 1, oldestRetained - 1} {
		if coordinator.HasExecutiveAssignment(e) {
			t.Errorf("epochExecutive[%d] should have been pruned (outside retention window)", e)
		}
		if members := coordinator.GetExecutiveMembersForEpoch(e); members != nil {
			t.Errorf("GetExecutiveMembersForEpoch(%d) = %v, want nil (pruned)", e, members)
		}
	}

	// Epochs inside the window must retain their member lists.
	for _, e := range []uint64{oldestRetained, lastEpoch - 1, lastEpoch} {
		if !coordinator.HasExecutiveAssignment(e) {
			t.Fatalf("epochExecutive[%d] was pruned but is inside the retention window", e)
		}
		members := coordinator.GetExecutiveMembersForEpoch(e)
		if len(members) == 0 {
			t.Errorf("GetExecutiveMembersForEpoch(%d) returned empty list (inside retention window)", e)
		}
		// CanSeal must still work for retained epochs.
		if len(members) > 0 && !coordinator.CanSeal(members[0], e) {
			t.Errorf("CanSeal(%d, %d) = false, want true (member of retained epoch)", members[0], e)
		}
	}
}
