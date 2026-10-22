// Quantaureum Node source, version 1.0.0.
package node

// R10-01 (2026-10-21 tenth-round audit): boot-time state restoration must be
// accepted or rejected, not merely attempted.
//
// replayBlocksToRestoreState used to (a) skip any height it could not read as
// long as the misses were not ten in a row, and (b) print "State restored"
// without ever comparing the result to the chain head, while its single caller
// downgraded every error to a Warn. So a node could boot carrying a state built
// from an incomplete replay and nothing in the process knew it. The rest of the
// package already defines the invariant — the rebuild path refuses to validate
// unless the computed root equals the header root, and the persisted-state
// anchor only marks state verified on a match — this replay was the last site
// that got to skip the check.
//
// These tests pin the three ways restoration can fail short of verification and
// the one way it succeeds.

import (
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/types"
)

// r1001NewNode wires the minimum a replay touches: an in-memory state DB, a block
// store over its own in-memory DB, and a config for the block context.
//
// It then applies a genesis-style allocation. That is not decoration: this code
// represents the root of a state with no accounts as the zero hash, so an
// unfunded fixture would trip the "nothing verifiable" branch for a completely
// different reason than the one under test. Every real genesis funds accounts, so
// a funded state is the realistic shape for these assertions.
func r1001NewNode(t *testing.T) *Node {
	t.Helper()
	n := &Node{
		blockStore:   block.NewBlockStore(db.NewMemDB()),
		stateDB:      state.NewStateDB(db.NewMemDB()),
		config:       &Config{MaxGasLimit: 30000000},
		receiptCache: make(map[types.Hash]uint64),
	}
	n.stateDB.SetBalance(types.Address{0xaa}, big.NewInt(1_000_000_000))
	if _, err := n.stateDB.Commit(); err != nil {
		t.Fatalf("committing the genesis-style allocation: %v", err)
	}
	if n.stateDB.Root() == (types.Hash{}) {
		t.Fatal("precondition: a funded state must have a non-zero root")
	}
	return n
}

// r1001PutEmptyBlock stores a transactionless block at height, with Slot 0 so no
// epoch reward is derived and the replay exercises only the acceptance logic.
func r1001PutEmptyBlock(t *testing.T, n *Node, height uint64, stateRoot types.Hash) {
	t.Helper()
	blk := &encoding.Block{Header: &encoding.BlockHeader{
		Height:    height,
		Slot:      0,
		StateRoot: stateRoot,
		Timestamp: 1788110700 + int64(height)*12,
	}}
	if err := n.blockStore.PutBlockWithIndex(blk); err != nil {
		t.Fatalf("PutBlockWithIndex height=%d: %v", height, err)
	}
}

// r1001WantFail runs a replay expected to be rejected and returns the error
// text, asserting the node never records the state as verified.
func r1001WantFail(t *testing.T, n *Node, wantSubstring string) {
	t.Helper()
	err := n.replayBlocksToRestoreState()
	if err == nil {
		t.Fatalf("replay accepted a state it should have rejected (want error containing %q)", wantSubstring)
	}
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf("replay error = %q, want it to explain %q", err.Error(), wantSubstring)
	}
	if n.stateRestoreVerified {
		t.Fatalf("stateRestoreVerified = true after a rejected replay (%v)", err)
	}
}

// TestR10_01_IsolatedGapIsFatal: one unreadable height in the middle of the
// replay range must stop the replay. Before R10-01 the miss was skipped, the
// counter reset by the next success, and the run finished reporting the range
// size as if every block had been applied.
func TestR10_01_IsolatedGapIsFatal(t *testing.T) {
	n := r1001NewNode(t)
	r1001PutEmptyBlock(t, n, 1, types.Hash{0x11})
	r1001PutEmptyBlock(t, n, 3, types.Hash{0x33}) // height 2 is missing

	latest, err := n.blockStore.GetLatestHeight()
	if err != nil || latest != 3 {
		t.Fatalf("precondition: latest = %d (err %v), want 3", latest, err)
	}

	r1001WantFail(t, n, "unreadable")

	if n.stateRestoreVerifiedHeight != 0 {
		t.Fatalf("stateRestoreVerifiedHeight = %d, want 0", n.stateRestoreVerifiedHeight)
	}
}

// TestR10_01_RootMismatchIsRejected: a complete replay whose result does not
// match the tip header's StateRoot is not a restored state, no matter how many
// transactions executed.
func TestR10_01_RootMismatchIsRejected(t *testing.T) {
	n := r1001NewNode(t)
	for h := uint64(1); h <= 3; h++ {
		r1001PutEmptyBlock(t, n, h, types.Hash{0xde, 0xad, 0xbe, 0xef})
	}

	err := n.replayBlocksToRestoreState()
	if err == nil {
		t.Fatal("replay accepted a root that does not match the tip header")
	}
	if !strings.Contains(err.Error(), "NOT verified") {
		t.Fatalf("replay error = %q, want the mismatch to be spelled out", err.Error())
	}
	if n.stateRestoreVerified {
		t.Fatal("stateRestoreVerified = true on a root mismatch")
	}
}

// TestR10_01_TipWithoutStateRootCannotBeCleared: an absent (zero) header root is
// "unverifiable", not "verified". Treating it as a pass would let the cheapest
// possible fixture — blocks with no state root at all — satisfy the gate.
func TestR10_01_TipWithoutStateRootCannotBeCleared(t *testing.T) {
	n := r1001NewNode(t)
	for h := uint64(1); h <= 3; h++ {
		r1001PutEmptyBlock(t, n, h, types.Hash{})
	}

	r1001WantFail(t, n, "cannot be verified")
}

// TestR10_01_MatchingTipRootIsAccepted: the happy path, driven by the root the
// replay itself produces, so the assertion is about the comparison and not about
// a hard-coded hash.
func TestR10_01_MatchingTipRootIsAccepted(t *testing.T) {
	probe := r1001NewNode(t)
	for h := uint64(1); h <= 3; h++ {
		r1001PutEmptyBlock(t, probe, h, types.Hash{})
	}
	_ = probe.replayBlocksToRestoreState() // rejected on purpose: no header roots yet
	computed := probe.stateDB.Root()
	if computed == (types.Hash{}) {
		t.Fatal("precondition: the replayed root must be non-zero")
	}

	n := r1001NewNode(t)
	for h := uint64(1); h <= 3; h++ {
		r1001PutEmptyBlock(t, n, h, computed)
	}
	if err := n.replayBlocksToRestoreState(); err != nil {
		t.Fatalf("replay of a head-matching state returned %v", err)
	}
	if !n.stateRestoreVerified {
		t.Fatal("stateRestoreVerified = false after a verified replay")
	}
	if n.stateRestoreVerifiedHeight != 3 {
		t.Fatalf("stateRestoreVerifiedHeight = %d, want 3", n.stateRestoreVerifiedHeight)
	}
	if got := n.stateDB.Root(); got != computed {
		t.Fatalf("root drifted across the two runs: %x vs %x", got[:8], computed[:8])
	}
}

// TestR10_01_RestoredZeroRootIsNotAVerification: this codebase commits a state
// with no accounts to the zero hash. A chain head whose headers carry that same
// zero hash would therefore "match" a state the node never actually derived, so
// matching zeros must be rejected instead of cleared. This is the case the funded
// fixtures above deliberately avoid.
func TestR10_01_RestoredZeroRootIsNotAVerification(t *testing.T) {
	n := &Node{
		blockStore:   block.NewBlockStore(db.NewMemDB()),
		stateDB:      state.NewStateDB(db.NewMemDB()), // genesis-style allocation NOT applied
		config:       &Config{MaxGasLimit: 30000000},
		receiptCache: make(map[types.Hash]uint64),
	}
	if n.stateDB.Root() != (types.Hash{}) {
		t.Fatal("precondition: an unfunded state is expected to sit at the zero root")
	}
	for h := uint64(1); h <= 3; h++ {
		r1001PutEmptyBlock(t, n, h, types.Hash{})
	}

	r1001WantFail(t, n, "nothing verifiable")
}

// TestR10_01_ReplayWithoutBlocksStaysUnverified: nothing to replay is not proof
// of anything. The function has always returned nil here, which is correct for a
// genesis-only node, but the verified flag must stay off so no later reader can
// mistake "no blocks" for "state matched the head".
func TestR10_01_ReplayWithoutBlocksStaysUnverified(t *testing.T) {
	n := r1001NewNode(t)
	if err := n.replayBlocksToRestoreState(); err != nil {
		t.Fatalf("empty store should not error: %v", err)
	}
	if n.stateRestoreVerified {
		t.Fatal("a node with no blocks cannot have a head-verified state")
	}
}
