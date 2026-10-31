// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// R30 (2026-10-30) — the fork choice now refuses to adopt a head whose fork
// point is at or below the local finality floor. That decision has to be made
// BEFORE the head is committed, i.e. without taking q.mu, so the range
// derivation and the conflict test were extracted as pure functions. These
// tests pin them independently of QPOS state.

func TestR30_FinalityFloorSlot(t *testing.T) {
	q, err := NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	if floor, ok := q.FinalityFloorSlot(); ok {
		t.Fatalf("a fresh QPOS reported a finality floor of %d", floor)
	}

	q.AdoptHeaderFinality(0, 3, types.Hash{0xA3})
	if got := q.GetFinalizedEpoch(); got != 3 {
		t.Fatalf("precondition: finalized epoch = %d, want 3", got)
	}
	floor, ok := q.FinalityFloorSlot()
	if !ok {
		t.Fatal("finality epoch 3 must expose a floor")
	}
	if want := uint64(3 * SlotsPerEpoch); floor != want {
		t.Fatalf("floor slot = %d, want %d", floor, want)
	}
}

func TestR30_ReanchorCleanRangeShapes(t *testing.T) {
	known := ReanchorBounds{AncestorSlot: 30, AncestorKnown: true, ReplacedHeadSlot: 40}

	tests := []struct {
		name     string
		roots    map[uint64]types.Hash
		bounds   ReanchorBounds
		wantOK   bool
		wantFrom uint64
		wantTo   uint64
	}{
		{
			name:   "linear extension has no abandoned range",
			bounds: ReanchorBounds{},
		},
		{
			name:     "pure rollback (empty roots) covers (ancestor, replaced head]",
			bounds:   known,
			wantOK:   true,
			wantFrom: 31,
			wantTo:   40,
		},
		{
			name:     "skipped boundary slots are part of the abandoned range",
			roots:    map[uint64]types.Hash{35: {0x35}, 40: {0x40}},
			bounds:   known,
			wantOK:   true,
			wantFrom: 31,
			wantTo:   40,
		},
		{
			name:     "unknown ancestor does not extend the lower bound",
			roots:    map[uint64]types.Hash{35: {0x35}},
			bounds:   ReanchorBounds{ReplacedHeadSlot: 40},
			wantOK:   true,
			wantFrom: 35,
			wantTo:   40,
		},
		{
			name:     "roots above the replaced head still bound the range",
			roots:    map[uint64]types.Hash{45: {0x45}},
			bounds:   known,
			wantOK:   true,
			wantFrom: 31,
			wantTo:   45,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			from, to, ok := ReanchorCleanRange(tc.roots, tc.bounds)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if from != tc.wantFrom || to != tc.wantTo {
				t.Fatalf("range = [%d,%d], want [%d,%d]", from, to, tc.wantFrom, tc.wantTo)
			}
		})
	}
}

func TestR30_ReanchorConflictsWithFinality(t *testing.T) {
	pureRollback := ReanchorBounds{AncestorSlot: 30, AncestorKnown: true, ReplacedHeadSlot: 40}

	// The rollback abandons slots 31..40. A floor of 32 means slot 32 (the
	// finalized epoch boundary) is inside the abandoned range → conflict.
	if !ReanchorConflictsWithFinality(nil, pureRollback, 32) {
		t.Fatal("abandoned range [31,40] must conflict with a finality floor of 32")
	}
	// The floor is the boundary slot itself, and the range starts at it.
	if !ReanchorConflictsWithFinality(nil, pureRollback, 31) {
		t.Fatal("abandoned range starting exactly at the floor must conflict")
	}
	// Floor below the abandoned range: history above finality may be reorged.
	if ReanchorConflictsWithFinality(nil, pureRollback, 30) {
		t.Fatal("abandoned range [31,40] must not conflict with a finality floor of 30")
	}
	// No abandoned range at all: nothing to refuse.
	if ReanchorConflictsWithFinality(nil, ReanchorBounds{}, 32) {
		t.Fatal("a linear extension must never conflict with finality")
	}
	// Bounds that cannot locate the ancestor must not invent a conflict from
	// the roots alone when the roots sit above the floor.
	if ReanchorConflictsWithFinality(map[uint64]types.Hash{40: {0x40}}, ReanchorBounds{ReplacedHeadSlot: 40}, 32) {
		t.Fatal("a re-anchor strictly above the floor must not conflict")
	}
}
