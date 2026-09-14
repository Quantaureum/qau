// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/qaudb/state"
)

// TestR5_SHRD_R5_07_ActivateRejectsNilStateDBInProdMode verifies that in
// production mode (requireRealStateRoot=true), ActivateShard rejects a shard
// that has no stateDB attached. Without this gate, a shard could go Active
// and produce blocks with placeholder state roots (content-derived hashes
// that don't commit to actual state transitions), which could then be
// committed to the main chain — defeating state-root integrity.
func TestR5_SHRD_R5_07_ActivateRejectsNilStateDBInProdMode(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)
	sm.SetRequireRealStateRoot(true)

	validators := generateShardAddrs(t, 3)
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard failed: %v", err)
	}

	// Verify the flag propagated to the shard.
	chain.mu.RLock()
	flag := chain.requireRealStateRoot
	chain.mu.RUnlock()
	if !flag {
		t.Fatal("SHRD-R5-07: requireRealStateRoot should propagate to new shards")
	}

	// Register pubkeys + verifier (so only the stateDB check fails).
	setupShardValidators(chain, validators)

	// ActivateShard must reject (no stateDB).
	err = sm.ActivateShard(chain.ShardID())
	if err == nil {
		t.Fatal("SHRD-R5-07: ActivateShard should reject nil stateDB in production mode")
	}
	if !errors.Is(err, ErrShardStateRootPlaceholder) {
		t.Errorf("SHRD-R5-07: error should wrap ErrShardStateRootPlaceholder, got: %v", err)
	}
}

// TestR5_SHRD_R5_07_ActivateSucceedsWithStateDBInProdMode verifies that in
// production mode, ActivateShard succeeds when a real stateDB is attached.
// This is the happy path that must continue to work.
func TestR5_SHRD_R5_07_ActivateSucceedsWithStateDBInProdMode(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)
	sm.SetRequireRealStateRoot(true)

	validators := generateShardAddrs(t, 3)
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard failed: %v", err)
	}

	setupShardValidators(chain, validators)

	// Attach a real stateDB with an account.
	sdb := state.NewStateDB()
	if err := sdb.AddBalance(validators[0], big.NewInt(1000)); err != nil {
		t.Fatalf("AddBalance failed: %v", err)
	}
	chain.SetStateDB(sdb)

	// ActivateShard must succeed (stateDB present).
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("SHRD-R5-07: ActivateShard should succeed with stateDB, got: %v", err)
	}

	if chain.Status() != ShardStatusActive {
		t.Errorf("SHRD-R5-07: expected Active status, got %s", chain.Status())
	}
}

// TestR5_SHRD_R5_07_CommitRejectsNilStateDBInProdMode verifies that
// CommitBlockToMainChain rejects placeholder state roots in production mode
// even if the shard somehow became Active (defense-in-depth).
func TestR5_SHRD_R5_07_CommitRejectsNilStateDBInProdMode(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 3)
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard failed: %v", err)
	}

	// Activate WITHOUT production mode (so it goes Active with placeholder root).
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard failed: %v", err)
	}

	// Propose + finalize a block (placeholder state root).
	block, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}
	if err := finalizeShardBlock(chain, block.Header.Height); err != nil {
		t.Fatalf("FinalizeBlock failed: %v", err)
	}

	// NOW enable production mode (simulating a mainnet upgrade mid-flight).
	chain.mu.Lock()
	chain.requireRealStateRoot = true
	chain.mu.Unlock()

	// CommitBlockToMainChain must reject (no stateDB).
	_, err = chain.CommitBlockToMainChain(block.Header.Height)
	if err == nil {
		t.Fatal("SHRD-R5-07: CommitBlockToMainChain should reject placeholder root in production mode")
	}
	if !errors.Is(err, ErrShardStateRootPlaceholder) {
		t.Errorf("SHRD-R5-07: error should wrap ErrShardStateRootPlaceholder, got: %v", err)
	}
}

// TestR5_SHRD_R5_07_CommitSucceedsWithStateDBInProdMode verifies that
// CommitBlockToMainChain succeeds in production mode when a real stateDB is
// attached (real state root, not placeholder).
func TestR5_SHRD_R5_07_CommitSucceedsWithStateDBInProdMode(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)
	sm.SetRequireRealStateRoot(true)

	validators := generateShardAddrs(t, 3)
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard failed: %v", err)
	}

	setupShardValidators(chain, validators)

	// Attach a real stateDB with an account.
	sdb := state.NewStateDB()
	if err := sdb.AddBalance(validators[0], big.NewInt(1000)); err != nil {
		t.Fatalf("AddBalance failed: %v", err)
	}
	chain.SetStateDB(sdb)

	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard failed: %v", err)
	}

	// Propose + finalize + commit.
	block, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}
	if err := finalizeShardBlock(chain, block.Header.Height); err != nil {
		t.Fatalf("FinalizeBlock failed: %v", err)
	}

	commitment, err := chain.CommitBlockToMainChain(block.Header.Height)
	if err != nil {
		t.Fatalf("SHRD-R5-07: CommitBlockToMainChain should succeed with stateDB, got: %v", err)
	}
	if commitment == nil {
		t.Fatal("SHRD-R5-07: commitment should not be nil")
	}
}

// TestR5_SHRD_R5_07_DefaultModeKeepsPlaceholderBehavior verifies that in
// default mode (requireRealStateRoot=false, i.e., testnet/devnet), the
// placeholder state root behavior is preserved. This ensures backward
// compatibility for tests and dev environments.
func TestR5_SHRD_R5_07_DefaultModeKeepsPlaceholderBehavior(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)
	// Note: NOT calling SetRequireRealStateRoot(true).

	validators := generateShardAddrs(t, 3)
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard failed: %v", err)
	}

	chain.mu.RLock()
	flag := chain.requireRealStateRoot
	chain.mu.RUnlock()
	if flag {
		t.Fatal("SHRD-R5-07: requireRealStateRoot should be false by default")
	}

	// Activate without stateDB should succeed in default mode.
	setupShardValidators(chain, validators)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("SHRD-R5-07: ActivateShard should succeed in default mode, got: %v", err)
	}

	// Propose + finalize + commit with placeholder root should succeed.
	block, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil)
	if err != nil {
		t.Fatalf("ProposeBlock failed: %v", err)
	}
	if err := finalizeShardBlock(chain, block.Header.Height); err != nil {
		t.Fatalf("FinalizeBlock failed: %v", err)
	}
	commitment, err := chain.CommitBlockToMainChain(block.Header.Height)
	if err != nil {
		t.Fatalf("SHRD-R5-07: CommitBlockToMainChain should succeed in default mode, got: %v", err)
	}
	if commitment == nil {
		t.Fatal("SHRD-R5-07: commitment should not be nil")
	}
}

// TestR5_SHRD_R5_07_SetRequireRealStateRootUpdatesExistingShards verifies that
// SetRequireRealStateRoot propagates to ALL existing shards, not just new ones.
// This is important for mainnet upgrades where shards already exist.
func TestR5_SHRD_R5_07_SetRequireRealStateRootUpdatesExistingShards(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	// Create 3 shards in default mode.
	for i := 0; i < 3; i++ {
		validators := generateShardAddrs(t, 3)
		if _, err := sm.CreateShard(validators); err != nil {
			t.Fatalf("CreateShard %d failed: %v", i, err)
		}
	}

	// Verify all shards start with flag=false.
	for i := uint64(1); i <= 3; i++ {
		chain, _ := sm.GetShard(i)
		chain.mu.RLock()
		if chain.requireRealStateRoot {
			t.Errorf("shard %d: expected flag=false before SetRequireRealStateRoot", i)
		}
		chain.mu.RUnlock()
	}

	// Enable production mode.
	sm.SetRequireRealStateRoot(true)

	// Verify all shards now have flag=true.
	for i := uint64(1); i <= 3; i++ {
		chain, _ := sm.GetShard(i)
		chain.mu.RLock()
		if !chain.requireRealStateRoot {
			t.Errorf("SHRD-R5-07: shard %d: expected flag=true after SetRequireRealStateRoot", i)
		}
		chain.mu.RUnlock()
	}
}

// TestR5_SHRD_R5_07_ReactivateRejectsNilStateDBInProdMode verifies that
// ReactivateShard also enforces the production gate (via the shared
// validateActivationPrereqsLocked helper). This closes the consistency
// defect where ReactivateShard could bypass the stateDB requirement.
func TestR5_SHRD_R5_07_ReactivateRejectsNilStateDBInProdMode(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)
	sm.SetRequireRealStateRoot(true)

	validators := generateShardAddrs(t, 3)
	chain, err := sm.CreateShard(validators)
	if err != nil {
		t.Fatalf("CreateShard failed: %v", err)
	}

	// Attach stateDB, register pubkeys+verifier, activate.
	setupShardValidators(chain, validators)
	sdb := state.NewStateDB()
	if err := sdb.AddBalance(validators[0], big.NewInt(1000)); err != nil {
		t.Fatalf("AddBalance failed: %v", err)
	}
	chain.SetStateDB(sdb)
	if err := sm.ActivateShard(chain.ShardID()); err != nil {
		t.Fatalf("ActivateShard failed: %v", err)
	}

	// Deactivate.
	if err := sm.DeactivateShard(chain.ShardID()); err != nil {
		t.Fatalf("DeactivateShard failed: %v", err)
	}

	// Remove stateDB (simulate loss of stateDB after restart in prod).
	chain.mu.Lock()
	chain.stateDB = nil
	chain.mu.Unlock()

	// ReactivateShard must reject (no stateDB in production mode).
	err = sm.ReactivateShard(chain.ShardID())
	if err == nil {
		t.Fatal("SHRD-R5-07: ReactivateShard should reject nil stateDB in production mode")
	}
	if !strings.Contains(err.Error(), "placeholder") {
		t.Errorf("SHRD-R5-07: error should mention placeholder, got: %v", err)
	}
}
