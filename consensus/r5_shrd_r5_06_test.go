// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestR5_SHRD_R5_06_RejectsDuplicateValidators verifies that
// AssignValidatorsToShards rejects an input list containing duplicate
// validator addresses. Without this check, a single entity could satisfy the
// count threshold by repeating its own address, achieving cheap committee
// takeover and BFT-threshold dilution.
func TestR5_SHRD_R5_06_RejectsDuplicateValidators(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	// Build a list with duplicates: 3 unique addresses each repeated 4 times = 12 entries
	// (>= shardCount*ShardMinValidators = 3*3 = 9), but only 3 unique entities.
	unique := generateShardAddrs(t, 3)
	allValidators := make([]types.Address, 0, 12)
	for _, v := range unique {
		for j := 0; j < 4; j++ {
			allValidators = append(allValidators, v)
		}
	}

	var seed types.Hash
	seed[0] = 0x42
	err := sm.AssignValidatorsToShards(allValidators, 3, seed)
	if err == nil {
		t.Fatal("SHRD-R5-06: expected error for duplicate validators, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("SHRD-R5-06: error should mention duplicate, got: %v", err)
	}

	// No shards should be created when validation fails (fail-closed, no partial state).
	if sm.GetShardCount() != 0 {
		t.Errorf("SHRD-R5-06: no shards should exist after rejection, got %d", sm.GetShardCount())
	}
}

// TestR5_SHRD_R5_06_RejectsZeroAddress verifies that AssignValidatorsToShards
// rejects an input list containing the zero address. The zero address is a
// sentinel for "unset" and must never be treated as a real validator.
func TestR5_SHRD_R5_06_RejectsZeroAddress(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	// 9 valid validators + 1 zero address. Total 10 >= 9.
	validators := generateShardAddrs(t, 9)
	var zero types.Address
	validators = append(validators, zero)

	var seed types.Hash
	seed[0] = 0x42
	err := sm.AssignValidatorsToShards(validators, 3, seed)
	if err == nil {
		t.Fatal("SHRD-R5-06: expected error for zero address, got nil")
	}
	if !strings.Contains(err.Error(), "zero") {
		t.Errorf("SHRD-R5-06: error should mention zero, got: %v", err)
	}

	if sm.GetShardCount() != 0 {
		t.Errorf("SHRD-R5-06: no shards should exist after rejection, got %d", sm.GetShardCount())
	}
}

// TestR5_SHRD_R5_06_RejectsInsufficientAfterDedup verifies that even when the
// raw count meets the threshold, dedup may reduce the effective count below
// shardCount*ShardMinValidators. In that case the assignment must be rejected.
//
// Scenario: 9 raw entries (passes initial count check for 3 shards), but only
// 2 unique addresses (fails post-dedup check: 2 < 9).
func TestR5_SHRD_R5_06_RejectsInsufficientAfterDedup(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	// 2 unique addresses repeated to reach 9 raw entries.
	unique := generateShardAddrs(t, 2)
	allValidators := make([]types.Address, 0, 9)
	for j := 0; j < 4; j++ {
		allValidators = append(allValidators, unique[0])
	}
	for j := 0; j < 5; j++ {
		allValidators = append(allValidators, unique[1])
	}
	// 9 raw entries: passes len check (9 >= 9), but only 2 unique.

	var seed types.Hash
	seed[0] = 0x42
	err := sm.AssignValidatorsToShards(allValidators, 3, seed)
	if err == nil {
		t.Fatal("SHRD-R5-06: expected error for insufficient validators after dedup, got nil")
	}
	// The duplicate check fires first (on the second occurrence), so the error
	// mentions "duplicate", not "insufficient after dedup". This is correct
	// fail-closed behavior — we reject as soon as we detect a problem.
	if !strings.Contains(err.Error(), "duplicate") && !strings.Contains(err.Error(), "insufficient") {
		t.Errorf("SHRD-R5-06: error should mention duplicate or insufficient, got: %v", err)
	}

	if sm.GetShardCount() != 0 {
		t.Errorf("SHRD-R5-06: no shards should exist after rejection, got %d", sm.GetShardCount())
	}
}

// TestR5_SHRD_R5_06_SucceedsWithUniqueNonZero verifies that a valid input
// (all unique, no zero addresses, count meets threshold) succeeds and
// distributes validators across shards. This is the happy path that must
// continue to work after the fix.
func TestR5_SHRD_R5_06_SucceedsWithUniqueNonZero(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	// 30 unique non-zero validators, 3 shards, 10 per shard.
	validators := generateShardAddrs(t, 30)
	var seed types.Hash
	seed[0] = 0x42

	if err := sm.AssignValidatorsToShards(validators, 3, seed); err != nil {
		t.Fatalf("SHRD-R5-06: valid input should succeed, got: %v", err)
	}

	if sm.GetShardCount() != 3 {
		t.Fatalf("SHRD-R5-06: expected 3 shards, got %d", sm.GetShardCount())
	}

	// Each shard must have at least ShardMinValidators.
	for i := 1; i <= 3; i++ {
		assignment, exists := sm.GetAssignment(uint64(i))
		if !exists {
			t.Fatalf("SHRD-R5-06: assignment for shard %d not found", i)
		}
		if len(assignment.Validators) < ShardMinValidators {
			t.Errorf("SHRD-R5-06: shard %d has %d validators, minimum is %d",
				i, len(assignment.Validators), ShardMinValidators)
		}
	}

	// All 30 validators must be assigned (no loss).
	totalAssigned := 0
	for i := 1; i <= 3; i++ {
		assignment, _ := sm.GetAssignment(uint64(i))
		totalAssigned += len(assignment.Validators)
	}
	if totalAssigned != 30 {
		t.Errorf("SHRD-R5-06: total assigned = %d, want 30", totalAssigned)
	}
}

// TestR5_SHRD_R5_06_NoPartialStateOnRejection verifies that when
// AssignValidatorsToShards rejects the input (due to duplicates), no shards
// or assignments are created. This is the fail-closed guarantee: either the
// entire assignment succeeds or no state is mutated.
func TestR5_SHRD_R5_06_NoPartialStateOnRejection(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	// First, create a valid assignment (2 shards, 6 validators).
	valid := generateShardAddrs(t, 6)
	var seed1 types.Hash
	seed1[0] = 0x01
	if err := sm.AssignValidatorsToShards(valid, 2, seed1); err != nil {
		t.Fatalf("first assignment failed: %v", err)
	}
	originalCount := sm.GetShardCount() // 2

	// Now attempt a second assignment with duplicates. Must be rejected.
	dup := make([]types.Address, 0, 6)
	for i := 0; i < 6; i++ {
		dup = append(dup, valid[0]) // all the same address
	}
	var seed2 types.Hash
	seed2[0] = 0x02
	err := sm.AssignValidatorsToShards(dup, 2, seed2)
	if err == nil {
		t.Fatal("SHRD-R5-06: expected rejection for all-duplicate input")
	}

	// State must be unchanged: still 2 shards with original validators.
	if sm.GetShardCount() != originalCount {
		t.Errorf("SHRD-R5-06: shard count changed after rejection: got %d, want %d",
			sm.GetShardCount(), originalCount)
	}
	for i := 1; i <= originalCount; i++ {
		assignment, exists := sm.GetAssignment(uint64(i))
		if !exists {
			t.Errorf("SHRD-R5-06: shard %d assignment lost after rejection", i)
			continue
		}
		if len(assignment.Validators) != 3 {
			t.Errorf("SHRD-R5-06: shard %d validator count changed after rejection: got %d, want 3",
				i, len(assignment.Validators))
		}
	}
}

// TestR5_SHRD_R5_06_EachShardMeetsMinimum verifies that after a successful
// assignment, every shard has at least ShardMinValidators. This exercises the
// post-distribution defensive check. Uses an uneven validator count to ensure
// the last shard (which absorbs the remainder) still meets the minimum.
func TestR5_SHRD_R5_06_EachShardMeetsMinimum(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	// 10 validators across 3 shards: floor(10/3)=3 per shard, last gets 4.
	// Each shard must have >= 3 (ShardMinValidators).
	validators := generateShardAddrs(t, 10)
	var seed types.Hash
	seed[0] = 0x42

	if err := sm.AssignValidatorsToShards(validators, 3, seed); err != nil {
		t.Fatalf("SHRD-R5-06: assignment failed: %v", err)
	}

	for i := 1; i <= 3; i++ {
		assignment, exists := sm.GetAssignment(uint64(i))
		if !exists {
			t.Fatalf("SHRD-R5-06: shard %d assignment not found", i)
		}
		if len(assignment.Validators) < ShardMinValidators {
			t.Errorf("SHRD-R5-06: shard %d has %d validators, minimum is %d",
				i, len(assignment.Validators), ShardMinValidators)
		}
	}
}

// TestR5_SHRD_R5_06_DuplicateDetectionIsDeterministic verifies that the
// dedup check catches duplicates regardless of their position in the input
// (first, middle, or last). This guards against off-by-one errors in the
// dedup loop.
func TestR5_SHRD_R5_06_DuplicateDetectionIsDeterministic(t *testing.T) {
	base := generateShardAddrs(t, 9)
	var seed types.Hash
	seed[0] = 0x42

	cases := []struct {
		name    string
		makeFn  func() []types.Address
		wantErr string
	}{
		{
			name: "duplicate at start",
			makeFn: func() []types.Address {
				v := append([]types.Address{base[0]}, base...) // base[0] twice at front
				return v
			},
			wantErr: "duplicate",
		},
		{
			name: "duplicate in middle",
			makeFn: func() []types.Address {
				v := make([]types.Address, 0, len(base)+1)
				v = append(v, base[:5]...)
				v = append(v, base[2]) // duplicate of base[2]
				v = append(v, base[5:]...)
				return v
			},
			wantErr: "duplicate",
		},
		{
			name: "duplicate at end",
			makeFn: func() []types.Address {
				v := append([]types.Address{}, base...)
				v = append(v, base[len(base)-1]) // duplicate of last
				return v
			},
			wantErr: "duplicate",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mc := &mockMainChain{}
			sm := NewShardManager(mc)
			err := sm.AssignValidatorsToShards(c.makeFn(), 3, seed)
			if err == nil {
				t.Fatalf("SHRD-R5-06: expected error containing %q, got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("SHRD-R5-06: error = %v, want substring %q", err, c.wantErr)
			}
		})
	}
}
