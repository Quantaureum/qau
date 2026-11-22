// Quantaureum Node source, version 1.0.0.
package node

// M4 hardening regression: header-stateRoot enforcement.
//
// The mainnet fleet incident was caused by blocks whose header stateRoot
// disagreed with the deterministic re-execution of their contents being
// accepted into the chain (the producers that stamped them had a divergent
// local state, and the consensus did not enforce the stateRoot). The
// enforcement makes the syncer REJECT such blocks once the network activates
// it, regardless of the rebuild/skip bypass.
//
// Covered here:
//   - activated: a block with a wrong header stateRoot is rejected even on the
//     rebuild/skip path; a block with the correct root passes;
//   - disabled (default): the historical lenient behavior is unchanged (the
//     mismatch is logged and the block is trusted, not rejected).

import (
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// m4e_fixture builds the 3-block chain (empty / dynamic-fee tx / empty) via
// the real producer and stores it. Returns the blocks and the ORIGINAL tip
// root so a tampered copy can be compared.
func m4e_fixture(t *testing.T, tamperTip bool) (*block.BlockStore, []*encoding.Block, types.Hash) {
	t.Helper()
	bs := block.NewBlockStore(db.NewMemDB())
	blocks := m4r_produce(t, bs, false)
	origTipRoot := blocks[2].Header.StateRoot
	if tamperTip {
		blocks[2].Header.StateRoot = types.Hash{0x99, 0x88, 0x77}
	}
	return bs, blocks, origTipRoot
}

// applyAll applies the blocks in order with the rebuild/skip flag set, and
// returns the error of the LAST application (the tampered tip).
func applyAll(t *testing.T, s *Syncer, blocks []*encoding.Block, skip bool) error {
	var lastErr error
	for _, blk := range blocks {
		lastErr = s.applyBlockInternal(blk, skip)
	}
	return lastErr
}

// TestM4Enforcement_DisabledKeepsLenientBehavior pins the default: with the
// activation height unset (0), a block whose header stateRoot is wrong is
// logged and trusted on the rebuild/skip path — byte-for-byte the historical
// behavior.
func TestM4Enforcement_DisabledKeepsLenientBehavior(t *testing.T) {
	bs, blocks, _ := m4e_fixture(t, true)

	s := m4r_newSyncer(t, bs)
	s.SetStateRootEnforcementHeight(0) // disabled
	if err := applyAll(t, s, blocks, true); err != nil {
		t.Fatalf("disabled: the lenient behavior must not reject the bad-root block: %v", err)
	}
}

// TestM4Enforcement_ActivatedRejectsBadRootBlock is the core regression: once
// activated, a block whose header stateRoot disagrees with the locally derived
// root is REJECTED even on the rebuild/skip path.
func TestM4Enforcement_ActivatedRejectsBadRootBlock(t *testing.T) {
	bs, blocks, _ := m4e_fixture(t, true)

	s := m4r_newSyncer(t, bs)
	s.SetStateRootEnforcementHeight(2) // enforce from height 2 (blocks 2 and 3)
	err := applyAll(t, s, blocks, true)
	if err == nil {
		t.Fatal("activated: the bad-root block was accepted on the rebuild/skip path — enforcement broken")
	}
}

// TestM4Enforcement_GoodRootBlockPasses proves the enforcement does not
// reject honest blocks: with the tip header restored to the correct root, the
// whole chain applies cleanly under enforcement.
func TestM4Enforcement_GoodRootBlockPasses(t *testing.T) {
	bs, blocks, origTipRoot := m4e_fixture(t, false)

	s := m4r_newSyncer(t, bs)
	s.SetStateRootEnforcementHeight(2)
	if err := applyAll(t, s, blocks, true); err != nil {
		t.Fatalf("activated: an honest chain must apply cleanly: %v", err)
	}
	if got := blocks[2].Header.StateRoot; got != origTipRoot {
		t.Fatalf("fixture broken: the tip root changed")
	}
}

// TestM4Enforcement_PreActivationHeightsUnaffected proves the gate is
// height-scoped: blocks BELOW the activation height keep the lenient
// behavior even when the enforcement is armed.
func TestM4Enforcement_PreActivationHeightsUnaffected(t *testing.T) {
	bs, blocks, _ := m4e_fixture(t, false)

	// Arm enforcement at height 3 and corrupt a PRE-activation block (height 2).
	blocks[1].Header.StateRoot = types.Hash{0x77}

	s := m4r_newSyncer(t, bs)
	s.SetStateRootEnforcementHeight(3)
	// Block 2 (height 2 < 3) carries a wrong root but is pre-activation: the
	// lenient behavior must persist for it. Block 3 (height 3 >= activation)
	// is honest and must pass under enforcement.
	if err := applyAll(t, s, blocks, true); err != nil {
		t.Fatalf("height-scoping broken: %v", err)
	}
}
