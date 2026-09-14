// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// R86-SLOT-RACE (2026-08-28)
//
// Two consecutive proposers can produce blocks at the same height when the
// second has not yet imported the first one's block. Both can be the
// legitimately elected proposer for their own slot; propagation simply lost
// the race against the slot clock. waitForPreviousSlotBlock gives the previous
// slot's block a bounded grace period and must never turn that wait into a
// stall.
// ─────────────────────────────────────────────────────────────────────────────

func TestR86_GraceIsBoundedAndSkippedWhenNotApplicable(t *testing.T) {
	if previousSlotBlockGrace <= 0 || previousSlotBlockGrace > 6*time.Second {
		t.Fatalf("grace period %s is outside the sane range (0, 6s] — a longer wait "+
			"would eat into the slot time and hurt liveness", previousSlotBlockGrace)
	}

	bp := &BlockProducer{}

	// slot 0 and a nil node must return immediately, never panic: the guard runs
	// on the hot block-production path.
	done := make(chan struct{})
	go func() {
		defer close(done)
		bp.waitForPreviousSlotBlock(0)
		bp.waitForPreviousSlotBlock(42) // node == nil
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("waitForPreviousSlotBlock must return immediately when it cannot apply")
	}
}
