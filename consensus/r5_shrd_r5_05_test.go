// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestR5_SHRD_R5_05_AssignValidatorsCreatesInitializingShards verifies that
// AssignValidatorsToShards creates NEW shards in ShardStatusInitializing,
// NOT ShardStatusActive. Previously (pre-SHRD-R5-05) new shards were
// immediately set to Active, bypassing the Initialize→Activate prerequisite
// gate that CreateShard+ActivateShard enforce.
func TestR5_SHRD_R5_05_AssignValidatorsCreatesInitializingShards(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 30)
	var seed types.Hash
	seed[0] = 0x42

	if err := sm.AssignValidatorsToShards(validators, 3, seed); err != nil {
		t.Fatalf("AssignValidatorsToShards failed: %v", err)
	}

	for i := 1; i <= 3; i++ {
		chain, err := sm.GetShard(uint64(i))
		if err != nil {
			t.Fatalf("shard %d not found: %v", i, err)
		}
		if chain.Status() != ShardStatusInitializing {
			t.Errorf("SHRD-R5-05: shard %d status = %s, want Initializing", i, chain.Status())
		}
	}

	if sm.GetActiveShardCount() != 0 {
		t.Errorf("SHRD-R5-05: expected 0 active shards, got %d", sm.GetActiveShardCount())
	}
}

// TestR5_SHRD_R5_05_ReactivateRejectsMissingPubkeys verifies that
// ReactivateShard rejects a shard that has no registered validator public
// keys. Previously (pre-SHRD-R5-05) ReactivateShard skipped the pubkey
// and verifier checks that ActivateShard enforces.
func TestR5_SHRD_R5_05_ReactivateRejectsMissingPubkeys(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	// Create a shard via CreateShard (starts in Initializing).
	validators := generateShardAddrs(t, 3)
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard failed: %v", err)
	}

	// Deactivate it first (so ReactivateShard can be attempted).
	// ActivateShard will fail (no pubkeys), so manually set to Inactive
	// via DeactivateShard after temporarily meeting prerequisites.
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard failed: %v", err)
	}
	if err := sm.DeactivateShard(chain.ShardID()); err != nil {
		t.Fatalf("DeactivateShard failed: %v", err)
	}

	// Now clear the pubkeys to simulate a shard that lost its keys.
	chain.mu.Lock()
	chain.validatorPubKeys = make(map[types.Address][]byte)
	chain.mu.Unlock()

	// ReactivateShard must reject (no pubkeys).
	if err := sm.ReactivateShard(chain.ShardID()); err == nil {
		t.Fatal("SHRD-R5-05: ReactivateShard should reject shard with no pubkeys")
	}
}

// TestR5_SHRD_R5_05_ReactivateRejectsMissingVerifier verifies that
// ReactivateShard rejects a shard that has no election verifier.
func TestR5_SHRD_R5_05_ReactivateRejectsMissingVerifier(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 3)
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard failed: %v", err)
	}

	// Activate, then deactivate.
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard failed: %v", err)
	}
	if err := sm.DeactivateShard(chain.ShardID()); err != nil {
		t.Fatalf("DeactivateShard failed: %v", err)
	}

	// Clear the election verifier.
	chain.mu.Lock()
	chain.electionVerifier = nil
	chain.mu.Unlock()

	// ReactivateShard must reject (no verifier).
	if err := sm.ReactivateShard(chain.ShardID()); err == nil {
		t.Fatal("SHRD-R5-05: ReactivateShard should reject shard with no election verifier")
	}
}

// TestR5_SHRD_R5_05_ReactivateSucceedsWithPrereqs verifies that
// ReactivateShard succeeds when the prerequisites (pubkeys + verifier) are met.
func TestR5_SHRD_R5_05_ReactivateSucceedsWithPrereqs(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 3)
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard failed: %v", err)
	}

	// Set up prerequisites and activate.
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard failed: %v", err)
	}

	// Deactivate.
	if err := sm.DeactivateShard(chain.ShardID()); err != nil {
		t.Fatalf("DeactivateShard failed: %v", err)
	}

	// Reactivate — should succeed (prerequisites still in place).
	if err := sm.ReactivateShard(chain.ShardID()); err != nil {
		t.Fatalf("SHRD-R5-05: ReactivateShard should succeed with prerequisites met, got: %v", err)
	}

	if chain.Status() != ShardStatusActive {
		t.Errorf("SHRD-R5-05: after ReactivateShard, status = %s, want Active", chain.Status())
	}
}

// TestR5_SHRD_R5_05_ActivateShardNetworkAcceptsInitializing verifies that
// ActivateShardNetwork accepts shards in Initializing state (the new correct
// state after AssignValidatorsToShards). Previously it required Active status.
func TestR5_SHRD_R5_05_ActivateShardNetworkAcceptsInitializing(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 30)
	config := ShardActivationConfig{
		ShardCount:    3,
		MinValidators: ShardMinValidators,
		Validators:    validators,
		Seed:          types.Hash{0x01},
	}

	activated, perShard, err := sm.ActivateShardNetwork(config)
	if err != nil {
		t.Fatalf("SHRD-R5-05: ActivateShardNetwork should accept Initializing shards, got: %v", err)
	}
	if activated != 3 {
		t.Errorf("SHRD-R5-05: expected 3 activated shards, got %d", activated)
	}
	if len(perShard) != 3 {
		t.Errorf("SHRD-R5-05: expected 3 per-shard counts, got %d", len(perShard))
	}

	// All shards should be in Initializing state (not Active).
	for i := 1; i <= 3; i++ {
		chain, _ := sm.GetShard(uint64(i))
		if chain.Status() != ShardStatusInitializing {
			t.Errorf("SHRD-R5-05: shard %d status = %s, want Initializing", i, chain.Status())
		}
	}
}

// TestR5_SHRD_R5_05_ExistingActiveShardsStayActiveOnReassignment verifies
// that when AssignValidatorsToShards is called on EXISTING Active shards
// (epoch-boundary rotation), they remain Active. The SHRD-R5-05 fix only
// affects NEW shards — existing Active shards already passed activation.
func TestR5_SHRD_R5_05_ExistingActiveShardsStayActiveOnReassignment(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	// First assignment: creates 2 shards in Initializing.
	validators := generateShardAddrs(t, 10)
	seed1 := types.Hash{0x01}
	if err := sm.AssignValidatorsToShards(validators, 2, seed1); err != nil {
		t.Fatalf("first AssignValidatorsToShards failed: %v", err)
	}

	// Activate both shards (set up prerequisites first).
	for i := 1; i <= 2; i++ {
		chain, _ := sm.GetShard(uint64(i))
		vs := chain.Validators()
		setupShardValidators(chain, vs)
		if err := sm.ActivateShard(uint64(i)); err != nil {
			t.Fatalf("ActivateShard(%d) failed: %v", i, err)
		}
	}

	// Second assignment (epoch rotation): same shards, new validators.
	// These EXISTING shards should remain Active.
	validators2 := generateShardAddrs(t, 10)
	seed2 := types.Hash{0x02}
	if err := sm.AssignValidatorsToShards(validators2, 2, seed2); err != nil {
		t.Fatalf("second AssignValidatorsToShards failed: %v", err)
	}

	for i := 1; i <= 2; i++ {
		chain, _ := sm.GetShard(uint64(i))
		if chain.Status() != ShardStatusActive {
			t.Errorf("SHRD-R5-05: existing shard %d should remain Active after rotation, got %s", i, chain.Status())
		}
	}
}
