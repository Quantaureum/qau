// Quantaureum Node source, version 1.0.0.
package core

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
)

// R30 F8 (2026-10-30) — the justified/finalized checkpoint epochs in a block
// header used to be the last two unvalidated fields of the header. Every node
// adopts them into its QPOS state, where the adopted finalized epoch becomes
// the finality floor: the slot below which reorgs, store rollbacks and debug
// rollbacks are all refused. Because the ratchet only moves forward, a single
// header claiming FinalizedEpoch = 1<<40 would freeze the node's fork choice
// permanently, and the victim relays the poisoned value in its own headers.
//
// The fix binds both fields to the header's own epoch, the same class of rule
// R37-P1-CORE-01 applied to the epoch/slot pair. These tests pin the rejection
// of out-of-bounds claims and, just as important, that an honest header still
// passes.

// r30F8BuildHeader builds the (otherwise fully valid) child header of the fixed
// parent and stamps the checkpoint epochs under test.
func r30F8BuildHeader(bv *BlockValidator, parent *encoding.BlockHeader, justified, finalized uint64) *encoding.BlockHeader {
	h := makeValidChildHeader(parent, bv)
	h.JustifiedEpoch = justified
	h.FinalizedEpoch = finalized
	return h
}

func TestR30F8_HeaderFinalityCheckpointsAreBounded(t *testing.T) {
	bv := r39P1_04NewDevBV(t)
	parent := r39P1_04FixedParent()

	// Precondition: the child sits in epoch 0 (slot 1), so the only backed
	// claim is "nothing justified, nothing finalized".
	if child := r30F8BuildHeader(bv, parent, 0, 0); child.Epoch != 0 {
		t.Fatalf("precondition: child epoch = %d, want 0", child.Epoch)
	}

	// Honest header: no checkpoints yet. Must still pass every other rule.
	if err := bv.ValidateHeader(r30F8BuildHeader(bv, parent, 0, 0), parent); err != nil {
		t.Fatalf("honest header rejected: %v", err)
	}

	for _, tc := range []struct {
		name      string
		justified uint64
		finalized uint64
	}{
		{name: "justified one epoch ahead", justified: 1, finalized: 0},
		{name: "finalized one epoch ahead", justified: 0, finalized: 1},
		{name: "both far ahead", justified: 1 << 40, finalized: 1 << 40},
	} {
		err := bv.ValidateHeader(r30F8BuildHeader(bv, parent, tc.justified, tc.finalized), parent)
		if !errors.Is(err, ErrInvalidFinalityCheckpoint) {
			t.Errorf("%s: expected ErrInvalidFinalityCheckpoint, got %v", tc.name, err)
		}
	}
}

// TestR30F8_FinalityBoundAcceptsClaimsInsideTheHeaderEpoch pins the permissive
// half of the rule: a checkpoint may reference the block's own epoch (that is
// what a producer in the boundary epoch legitimately stamps), so the bound must
// be inclusive. Otherwise honest blocks on epoch boundaries would be rejected
// and the chain would halt.
func TestR30F8_FinalityBoundAcceptsClaimsInsideTheHeaderEpoch(t *testing.T) {
	for _, tc := range []struct {
		name      string
		justified uint64
		finalized uint64
		header    uint64
		want      bool
	}{
		{name: "genesis block carries nothing", header: 0, want: true},
		{name: "both at the header epoch", justified: 5, finalized: 5, header: 5, want: true},
		{name: "finalized behind justified", justified: 5, finalized: 4, header: 5, want: true},
		{name: "justified one past", justified: 6, finalized: 5, header: 5, want: false},
		{name: "finalized one past", justified: 5, finalized: 6, header: 5, want: false},
		{name: "overflowed claim", justified: ^uint64(0), finalized: ^uint64(0), header: 5, want: false},
	} {
		if got := consensus.HeaderFinalityCheckpointsValid(tc.justified, tc.finalized, tc.header); got != tc.want {
			t.Errorf("%s: HeaderFinalityCheckpointsValid(%d, %d, %d) = %v, want %v",
				tc.name, tc.justified, tc.finalized, tc.header, got, tc.want)
		}
	}
}
