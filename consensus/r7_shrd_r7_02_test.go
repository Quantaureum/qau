// Quantaureum Node source, version 1.0.0.
package consensus

// SHRD-R7-02 (2026-07-17) regression tests.
//
// These tests verify that pruneOldBlocks preserves blocks that are still
// in flight (not yet finalized or not yet committed to the main chain).
// Before the fix, pruneOldBlocks deleted every block below the threshold
// regardless of state, which could cause FinalizeBlock and
// CommitBlockToMainChain to return ErrShardBlockNotFound for blocks that
// were still progressing through the pipeline.
//
// Attack/failure model covered:
//   - Finalization stall: an old block is still collecting attestations
//     when the pruning window slides past it. Pruning would make it
//     un-finalizable.
//   - Commit stall: a block is finalized but CommitBlockToMainChain has
//     not yet run. Pruning would make it un-committable.
//   - Happy path: blocks that are both finalized and committed are pruned
//     normally once they fall below the threshold.

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// r7_02_newActiveChain builds a fresh active shard chain with the given
// validators' Dilithium3 public keys registered. Mirrors r5_03_newActiveChain.
func r7_02_newActiveChain(t *testing.T, shardID uint64, validators []types.Address) *ShardChain {
	t.Helper()
	chain := NewShardChain(shardID, validators)
	chain.status = ShardStatusActive
	setupShardValidators(chain, validators)
	return chain
}

// r7_02_proposeFinalizeCommit is a test helper that proposes, finalizes,
// and commits a block at the next height. Returns the committed height.
func r7_02_proposeFinalizeCommit(t *testing.T, chain *ShardChain, proposer types.Address, txs [][]byte) uint64 {
	t.Helper()
	block, err := proposeShardBlock(chain, proposer, txs, nil)
	if err != nil {
		t.Fatalf("proposeShardBlock failed: %v", err)
	}
	height := block.Header.Height
	if err := finalizeShardBlock(chain, height); err != nil {
		t.Fatalf("finalizeShardBlock %d failed: %v", height, err)
	}
	if _, err := chain.CommitBlockToMainChain(height); err != nil {
		t.Fatalf("CommitBlockToMainChain %d failed: %v", height, err)
	}
	return height
}

// TestSHRD_R7_02_PruneFinalizedAndCommittedBlocks verifies that blocks
// which have been both finalized and committed are pruned normally once
// they fall below the threshold. This is the happy-path regression check.
func TestSHRD_R7_02_PruneFinalizedAndCommittedBlocks(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain := r7_02_newActiveChain(t, 1, validators)
	// Use a small window so pruning triggers after just a few blocks.
	chain.maxBlocks = 2

	// Produce 4 blocks, each finalized + committed. With maxBlocks=2,
	// after block 4 the threshold becomes 4-2=2, so block 1 (height=1)
	// should be pruned (h=1 < 2).
	r7_02_proposeFinalizeCommit(t, chain, validators[0], [][]byte{[]byte("tx1")})
	r7_02_proposeFinalizeCommit(t, chain, validators[0], [][]byte{[]byte("tx2")})
	r7_02_proposeFinalizeCommit(t, chain, validators[0], [][]byte{[]byte("tx3")})
	r7_02_proposeFinalizeCommit(t, chain, validators[0], [][]byte{[]byte("tx4")})

	// Block 1 should have been pruned (finalized + committed + below threshold).
	if _, exists := chain.blocks[1]; exists {
		t.Fatalf("block 1 should have been pruned (finalized+committed, below threshold)")
	}
	// Blocks 3 and 4 should still be present (within window: h >= 2).
	if _, exists := chain.blocks[3]; !exists {
		t.Fatalf("block 3 should still be present (within window)")
	}
	if _, exists := chain.blocks[4]; !exists {
		t.Fatalf("block 4 should still be present (latest)")
	}
}

// TestSHRD_R7_02_SkipUnfinalizedBlock verifies that a block which has NOT
// been finalized is preserved by pruneOldBlocks even when it falls below
// the threshold. Without the fix, FinalizeBlock would later return
// ErrShardBlockNotFound for this height.
func TestSHRD_R7_02_SkipUnfinalizedBlock(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain := r7_02_newActiveChain(t, 1, validators)
	chain.maxBlocks = 2

	// Block 1: propose only (NO finalize, NO commit) — left in flight.
	if _, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil); err != nil {
		t.Fatalf("proposeShardBlock 1 failed: %v", err)
	}
	// Blocks 2 and 3: full propose+finalize+commit. Producing block 3
	// triggers pruneOldBlocks with threshold=1.
	r7_02_proposeFinalizeCommit(t, chain, validators[0], [][]byte{[]byte("tx2")})
	r7_02_proposeFinalizeCommit(t, chain, validators[0], [][]byte{[]byte("tx3")})

	// Block 1 is below threshold (1 < 1 is false since threshold=1, but
	// the check is h < threshold). Actually threshold = latest - maxBlocks
	// = 3 - 2 = 1, so h < 1 means h == 0 only. We need a 4th block to push
	// threshold to 2 so block 1 (h=1) falls under pruning.
	r7_02_proposeFinalizeCommit(t, chain, validators[0], [][]byte{[]byte("tx4")})

	// Now threshold = 4 - 2 = 2, so block 1 (h=1 < 2) is a prune candidate.
	// But block 1 is NOT finalized — pruneOldBlocks must skip it.
	if _, exists := chain.blocks[1]; !exists {
		t.Fatalf("block 1 (unfinalized) must NOT be pruned — FinalizeBlock would later fail with ErrShardBlockNotFound")
	}

	// Sanity: block 1 can still be finalized (proves it was preserved correctly).
	if err := finalizeShardBlock(chain, 1); err != nil {
		t.Fatalf("finalizeShardBlock 1 should still succeed after pruning, got: %v", err)
	}
}

// TestSHRD_R7_02_SkipFinalizedButUncommittedBlock verifies that a block
// which has been finalized but NOT committed is preserved by pruneOldBlocks.
// Without the fix, CommitBlockToMainChain would later return
// ErrShardBlockNotFound for this height.
func TestSHRD_R7_02_SkipFinalizedButUncommittedBlock(t *testing.T) {
	validators := generateShardAddrs(t, 5)
	chain := r7_02_newActiveChain(t, 1, validators)
	chain.maxBlocks = 2

	// Block 1: propose + finalize (NO commit) — left pending commit.
	if _, err := proposeShardBlock(chain, validators[0], [][]byte{[]byte("tx1")}, nil); err != nil {
		t.Fatalf("proposeShardBlock 1 failed: %v", err)
	}
	if err := finalizeShardBlock(chain, 1); err != nil {
		t.Fatalf("finalizeShardBlock 1 failed: %v", err)
	}

	// Blocks 2, 3, 4: full propose+finalize+commit. Producing block 4
	// triggers pruneOldBlocks with threshold = 4 - 2 = 2, so block 1
	// (h=1 < 2) is a prune candidate.
	r7_02_proposeFinalizeCommit(t, chain, validators[0], [][]byte{[]byte("tx2")})
	r7_02_proposeFinalizeCommit(t, chain, validators[0], [][]byte{[]byte("tx3")})
	r7_02_proposeFinalizeCommit(t, chain, validators[0], [][]byte{[]byte("tx4")})

	// Block 1 is finalized but NOT committed — pruneOldBlocks must skip it.
	if _, exists := chain.blocks[1]; !exists {
		t.Fatalf("block 1 (finalized but uncommitted) must NOT be pruned — CommitBlockToMainChain would later fail with ErrShardBlockNotFound")
	}

	// Sanity: block 1 can still be committed (proves it was preserved correctly).
	if _, err := chain.CommitBlockToMainChain(1); err != nil {
		t.Fatalf("CommitBlockToMainChain 1 should still succeed after pruning, got: %v", err)
	}
}
