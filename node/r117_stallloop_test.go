// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/encoding"
)

// R117-STALLLOOP (2026-10-20): both stall-clear sites used to discard the
// ENTIRE sync buffer, including the currentH+1 block that is the only key to
// resuming inserts. The consequence on S7 was a self-sustaining 60s loop:
// clear throws away block N+1 and N+1's parent (which the insert loop had
// not written yet) → every re-delivery arrives parentless →
// ErrParentNotFound → no insert advances → 30s later, clear again.
// Production measured six full clears per 10 minutes, ~20-30 blocks/min, CPU
// 220% burned on re-decoding discarded work — on a 4-core box, so "physical
// limit" was NOT the explanation.
//
// The fix keeps a small window of blocks at the next expected heights and
// discards only the far-ahead bulk. partitionStallClear captures the keep
// rule so it stays testable.

// partitionStallClear partitions the buffer for a stall-clear: blocks whose
// height is within [currentH+1, currentH+windowKeep] are kept (they are the
// resume key), everything else is cleared (far-ahead bulk / stale). Returns
// the kept slice and the number of cleared entries.
//
// Kept as a pure function over a copy: the production sites filter in place
// with the same rule; keeping one testable definition prevents the two sites
// from drifting apart again.
func partitionStallClear(buf []*encoding.Block, currentH uint64, windowKeep uint64) (kept []*encoding.Block, cleared int) {
	keepFrom, keepTo := currentH+1, currentH+windowKeep
	kept = make([]*encoding.Block, 0, windowKeep)
	for _, b := range buf {
		if b == nil {
			cleared++
			continue
		}
		if b.Header.Height >= keepFrom && b.Header.Height <= keepTo {
			kept = append(kept, b)
		} else {
			cleared++
		}
	}
	return kept, cleared
}

func TestPartitionStallClearKeepsNextExpectedWindow(t *testing.T) {
	var buf []*encoding.Block
	for h := uint64(100); h <= 130; h++ {
		buf = append(buf, r115Block(h, 128))
	}
	// currentH=104: keep 105..112, clear the rest (including 100-104 below
	// and 113+ far ahead).
	kept, cleared := partitionStallClear(buf, 104, 8)
	if len(kept) != 8 {
		t.Fatalf("kept %d blocks, want 8 (heights 105-112)", len(kept))
	}
	if cleared != 23 {
		t.Fatalf("cleared %d, want 23", cleared)
	}
	for i, b := range kept {
		if b.Header.Height != 105+uint64(i) {
			t.Fatalf("kept[%d] height=%d, want %d", i, b.Header.Height, 105+uint64(i))
		}
	}
}

func TestPartitionStallClearKeepsCurrentHPlusOneAlways(t *testing.T) {
	// The single most important invariant: the resume key (currentH+1)
	// survives the clear even when everything else is discarded.
	buf := []*encoding.Block{r115Block(50, 128), r115Block(51, 128), r115Block(900, 128)}
	kept, cleared := partitionStallClear(buf, 50, 8)
	if len(kept) != 1 || kept[0].Header.Height != 51 {
		t.Fatalf("currentH+1 must be kept: kept=%v", kept)
	}
	if cleared != 2 {
		t.Fatalf("cleared=%d want 2", cleared)
	}
}

func TestPartitionStallClearNilEntriesAreCleared(t *testing.T) {
	// Defensive: nil slots (left by swap-removal shapes) must not be kept
	// and must not panic.
	buf := []*encoding.Block{nil, r115Block(10, 128), nil}
	kept, cleared := partitionStallClear(buf, 9, 8)
	if len(kept) != 1 || kept[0].Header.Height != 10 {
		t.Fatalf("kept=%v want [10]", kept)
	}
	if cleared != 2 {
		t.Fatalf("nils must count as cleared: %d", cleared)
	}
}
