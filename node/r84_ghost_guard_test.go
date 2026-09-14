// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// R84-GHOST-DEADLOCK (2026-08-28)
//
// After accepting a fork and rolling back, `forkAccepted[h]` used to make the
// syncer drop EVERY later block whose parent did not match our block at height
// h. That is correct for a stale child of the branch we abandoned, but it also
// blocked the canonical chain we were re-syncing: a node that ended up with a
// different block at h (e.g. it produced one itself after sync tracking was
// reset) could never import the peers' chain again.
//
// The stale guard can deadlock re-sync because `clearForkAcceptedBelow` only
// clears heights strictly below the current one and the node can never get
// past the blocked height.
// ─────────────────────────────────────────────────────────────────────────────

func TestR84_GhostGuardDropsOnlyTheAbandonedBranch(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1333)

	const forkPoint = uint64(796)
	abandoned := types.Hash{0xaa, 0xbb}

	s.mu.Lock()
	s.forkAccepted[forkPoint] = true
	s.forkAbandonedHash[forkPoint] = abandoned
	s.mu.Unlock()

	// A child of the branch we abandoned is a genuine ghost: keep dropping it,
	// and keep the guard armed for the next one.
	if !s.isAbandonedBranchBlock(forkPoint, abandoned) {
		t.Fatal("a child of the abandoned branch must be treated as a ghost")
	}
	s.mu.RLock()
	stillArmed := s.forkAccepted[forkPoint]
	s.mu.RUnlock()
	if !stillArmed {
		t.Fatal("the ghost guard must stay armed while ghosts keep arriving")
	}

	// The canonical chain has a different parent at that height: it must be
	// allowed through, and the sticky guard must be cleared.
	canonicalParent := types.Hash{0xcc, 0xdd}
	if s.isAbandonedBranchBlock(forkPoint, canonicalParent) {
		t.Fatal("a block from a different branch must not be dropped as a ghost")
	}
	s.mu.RLock()
	armedAfter := s.forkAccepted[forkPoint]
	_, hashKept := s.forkAbandonedHash[forkPoint]
	s.mu.RUnlock()
	if armedAfter || hashKept {
		t.Fatalf("guard must be cleared after a foreign branch arrives (armed=%v hashKept=%v)",
			armedAfter, hashKept)
	}
}

func TestR84_UnknownAbandonedHashDisarmsAfterOneDrop(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1333)

	const forkPoint = uint64(42)
	s.mu.Lock()
	s.forkAccepted[forkPoint] = true // pre-R84 state: no abandoned hash recorded
	s.mu.Unlock()

	// Without a recorded hash we cannot classify the block, so the first one is
	// still dropped (old conservative behavior)...
	if !s.isAbandonedBranchBlock(forkPoint, types.Hash{0x01}) {
		t.Fatal("without a recorded abandoned hash the first block is dropped")
	}
	// ...but the flag is forgotten so a retry can make progress instead of
	// wedging the node forever.
	s.mu.RLock()
	armed := s.forkAccepted[forkPoint]
	s.mu.RUnlock()
	if armed {
		t.Fatal("guard must disarm after one drop when the abandoned hash is unknown")
	}
}

func TestR84_ClearForkAcceptedBelowAlsoClearsAbandonedHashes(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1333)

	s.mu.Lock()
	for _, h := range []uint64{10, 20, 30} {
		s.forkAccepted[h] = true
		s.forkAbandonedHash[h] = types.Hash{byte(h)}
	}
	s.clearForkAcceptedBelow(25)
	remainingAccepted := len(s.forkAccepted)
	remainingHashes := len(s.forkAbandonedHash)
	_, keptHash := s.forkAbandonedHash[30]
	s.mu.Unlock()

	if remainingAccepted != 1 || remainingHashes != 1 || !keptHash {
		t.Fatalf("expected only height 30 to survive: accepted=%d hashes=%d kept30=%v",
			remainingAccepted, remainingHashes, keptHash)
	}
}
