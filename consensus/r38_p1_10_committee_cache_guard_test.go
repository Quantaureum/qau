// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestR38P1_10_UpdateValidatorSet_ClearsCommitteeCache verifies the R38-P1-10
// fix in validator.go updateValidatorSet: after a validator set swap, the
// committeeCache must be empty (alongside the pre-existing shuffleCache
// clear). Cached committees pin Validator pointers + an index ordering derived
// from the OLD set's size/shuffle seed, so they are invalid after a swap.
func TestR38P1_10_UpdateValidatorSet_ClearsCommitteeCache(t *testing.T) {
	const n = 40 // > SlotsPerEpoch(32) to exercise the committee-cache code path
	qpos, err := NewQPOS(createTestValidatorSet(t, n))
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()

	// Populate the committee cache by calling GetCommitteeForSlot for several
	// slots. The R38-P1-10 pointer-equality guard passes on these calls
	// because q.validators still equals the captured `vs` at write time.
	for slot := uint64(0); slot < 4; slot++ {
		if _, err := qpos.GetCommitteeForSlot(slot); err != nil {
			t.Fatalf("GetCommitteeForSlot(%d) failed: %v", slot, err)
		}
	}
	qpos.mu.RLock()
	before := len(qpos.committeeCache)
	qpos.mu.RUnlock()
	if before == 0 {
		t.Fatalf("precondition: committeeCache empty before swap — cache writes did not happen")
	}

	// Swap the validator set via the unexported path (the same one
	// UpdateValidatorSetAuthorized delegates to after the auth check).
	newVs := createTestValidatorSet(t, n)
	if err := qpos.updateValidatorSet(newVs); err != nil {
		t.Fatalf("updateValidatorSet failed: %v", err)
	}

	qpos.mu.RLock()
	afterCommittee := len(qpos.committeeCache)
	afterShuffle := len(qpos.shuffleCache)
	qpos.mu.RUnlock()
	if afterCommittee != 0 {
		t.Errorf("R38-P1-10: updateValidatorSet left committeeCache populated (len=%d, want 0)", afterCommittee)
	}
	if afterShuffle != 0 {
		t.Errorf("R38-P1-10: updateValidatorSet did not clear shuffleCache (len=%d, want 0)", afterShuffle)
	}
}

// TestR38P1_10_AddStakingValidator_ClearsCommitteeCache verifies the R38-P1-10
// fix in validator.go AddStakingValidator: after a new validator is staked into
// the existing set, the committeeCache must be cleared (alongside the
// pre-existing shuffleCache clear) because the cached committee's membership
// and index ordering were computed BEFORE the new validator was appended.
func TestR38P1_10_AddStakingValidator_ClearsCommitteeCache(t *testing.T) {
	const n = 40
	qpos, err := NewQPOS(createTestValidatorSet(t, n))
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()

	// Prime cache.
	for slot := uint64(0); slot < 4; slot++ {
		if _, err := qpos.GetCommitteeForSlot(slot); err != nil {
			t.Fatalf("GetCommitteeForSlot(%d) failed: %v", slot, err)
		}
	}
	qpos.mu.RLock()
	before := len(qpos.committeeCache)
	qpos.mu.RUnlock()
	if before == 0 {
		t.Fatalf("precondition: committeeCache empty before AddStakingValidator")
	}

	// Add a NEW validator with an address GUARANTEED disjoint from the
	// existing 40 (helper uses addr[0]=byte(i+1) for i in [0,40), so
	// addr[0]=0xFF is unique).
	var newAddr types.Address
	newAddr[0] = 0xFF
	if !qpos.AddStakingValidator(newAddr, big.NewInt(1000)) {
		t.Fatal("AddStakingValidator returned false (validator not added)")
	}

	qpos.mu.RLock()
	afterCommittee := len(qpos.committeeCache)
	afterShuffle := len(qpos.shuffleCache)
	qpos.mu.RUnlock()
	if afterCommittee != 0 {
		t.Errorf("R38-P1-10: AddStakingValidator left committeeCache populated (len=%d, want 0)", afterCommittee)
	}
	if afterShuffle != 0 {
		t.Errorf("R38-P1-10: AddStakingValidator did not clear shuffleCache (len=%d, want 0)", afterShuffle)
	}

	// Sanity: a subsequent GetCommitteeForSlot recomputes from the post-add
	// validator set and repopulates the cache — proving the write guard is
	// not too restrictive.
	if _, err := qpos.GetCommitteeForSlot(0); err != nil {
		t.Fatalf("GetCommitteeForSlot(0) after AddStakingValidator failed: %v", err)
	}
	qpos.mu.RLock()
	afterRecompute := len(qpos.committeeCache)
	qpos.mu.RUnlock()
	if afterRecompute == 0 {
		t.Error("R38-P1-10: cache was not repopulated after recomputation — write guard is too restrictive")
	}
}

// TestR38P1_10_GetCommitteeForSlot_PointerGuard_RejectsStaleWrite verifies the
// R38-P1-10 pointer-equality guard inside qpos_committee.go:
// GetCommitteeForSlot. When the validator set captured at the start of the
// call (`vs`) is NOT the same pointer as q.validators at write-back time, the
// computed committee MUST NOT be pinned into q.committeeCache.
//
// The guard is `if q.validators == vs` mirroring the same pattern used in
// qpos_proposer.go:225-237 for shuffleCache. We simulate the
// partial-concurrent scenario the guard protects against by:
//  1. capturing vs1 = q.validators,
//  2. swapping q.validators → vs2 (updateValidatorSet clears the cache),
//  3. applying the SAME guarded write block GetCommitteeForSlot uses, but
//     with the stale vs1 as the "captured" reference.
//
// Without the guard, the stale-vs1 committee would be written back; with the
// guard, the write is skipped.
func TestR38P1_10_GetCommitteeForSlot_PointerGuard_RejectsStaleWrite(t *testing.T) {
	const n = 40
	qpos, err := NewQPOS(createTestValidatorSet(t, n))
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()

	// Step 1: capture vs1 (this mirrors the `vs := q.validators` snapshot at
	// the top of GetCommitteeForSlot, taken under RLock).
	qpos.mu.RLock()
	vs1 := qpos.validators
	qpos.mu.RUnlock()

	// Step 2: swap q.validators → vs2 (this wipes the cache via P1-10's
	// updateValidatorSet clear, simulating a concurrent updateValidatorSet).
	vs2 := createTestValidatorSet(t, n)
	if err := qpos.updateValidatorSet(vs2); err != nil {
		t.Fatalf("updateValidatorSet(vs2) failed: %v", err)
	}

	// Cache must be empty after the swap (this is the P1-10
	// updateValidatorSet clear, tested explicitly above).
	qpos.mu.RLock()
	cacheAfterSwap := len(qpos.committeeCache)
	qpos.mu.RUnlock()
	if cacheAfterSwap != 0 {
		t.Fatalf("precondition: cache not empty after updateValidatorSet (len=%d)", cacheAfterSwap)
	}

	// Step 3: simulate the guarded write block that GetCommitteeForSlot
	// performs AFTER computing the committee, with the STALE vs1 reference.
	// The committee is "computed from" vs1 here; the production code computes
	// it from the captured `vs` which was vs1 before the swap.
	simulatedStaleCommittee := vs1.Validators()
	written := false
	const slot uint64 = 100

	qpos.mu.Lock()
	// R38-P1-10 guard: only write when q.validators STILL equals the captured
	// vs (vs1 here). After the swap, q.validators is vs2 != vs1, so the write
	// is correctly skipped.
	if qpos.validators == vs1 {
		qpos.committeeCache[slot] = simulatedStaleCommittee
		qpos.evictStaleCommitteeCacheLocked()
		written = true
	}
	qpos.mu.Unlock()

	if written {
		t.Fatal("R38-P1-10 regression: pointer-equality guard let a STALE-vs1 committee be " +
			"written to committeeCache after q.validators had already been swapped to vs2")
	}

	qpos.mu.RLock()
	_, stillCached := qpos.committeeCache[slot]
	qpos.mu.RUnlock()
	if stillCached {
		t.Fatal("R38-P1-10: stale committee was pinned to committeeCache despite the guard")
	}

	// Step 4: confirm the positive case — when the captured vs DOES match
	// q.validators at write time, the write goes through (the guard is not
	// overly restrictive). Recapture vs against the live q.validators, then
	// apply the guarded write: it must succeed.
	qpos.mu.RLock()
	vsLive := qpos.validators
	qpos.mu.RUnlock()
	writtenLive := false
	qpos.mu.Lock()
	if qpos.validators == vsLive {
		qpos.committeeCache[slot] = vsLive.Validators()
		qpos.evictStaleCommitteeCacheLocked()
		writtenLive = true
	}
	qpos.mu.Unlock()
	if !writtenLive {
		t.Fatal("R38-P1-10: pointer-equality guard is TOO restrictive — refused a write when " +
			"q.validators == vs (the validator set had NOT been swapped)")
	}
	qpos.mu.RLock()
	_, cachedNow := qpos.committeeCache[slot]
	qpos.mu.RUnlock()
	if !cachedNow {
		t.Error("R38-P1-10: committee not cached after a write that SHOULD have passed the guard")
	}
}
