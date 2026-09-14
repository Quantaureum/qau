// Quantaureum Node source, version 1.0.0.
package node

import "testing"

// R87-M4-ROOTCAUSE regression tests.
//
// A cascading rollback can leave stateDB bookkeeping above the actual
// committed height. The baseline logic must replay every rolled-back block;
// moving only startHeight and stateVerifiedHeight forward skips those blocks
// and leaves the local state permanently divergent.

func TestR87M4_ComputeRebuildBaseline_ClampsToCommittedHeight(t *testing.T) {
	cases := []struct {
		name                      string
		fromHeight, verified, lch uint64
		hasHistory                bool
		want                      uint64
		note                      string
	}{
		{
			name:       "cascading rollback left stateDB behind",
			fromHeight: 37, verified: 37, lch: 29,
			hasHistory: true,
			want:       29,
			note:       "must replay 30..41, not 38..41",
		},
		{
			name:       "stateDB in sync with verified height",
			fromHeight: 37, verified: 37, lch: 37,
			hasHistory: true,
			want:       37,
		},
		{
			name:       "verified ahead of caller start: skip already-verified work",
			fromHeight: 10, verified: 37, lch: 37,
			hasHistory: true,
			want:       37,
		},
		{
			name:       "stateDB ahead of verified: R61 case, baseline stays verified",
			fromHeight: 10, verified: 20, lch: 40,
			hasHistory: true,
			want:       20,
			note:       "the caller rolls stateDB back to the verified baseline",
		},
		{
			name:       "fresh node",
			fromHeight: 0, verified: 0, lch: 0,
			hasHistory: true,
			want:       0,
		},
		{
			name:       "rollback all the way to genesis",
			fromHeight: 500, verified: 500, lch: 0,
			hasHistory: true,
			want:       0,
		},
		// R87-M4-RESTART (2026-08-29): beforeImages are in-memory only, so
		// after any restart hasHistory=false. A stateDB AHEAD of the baseline
		// can no longer be rolled back — replaying the range would re-execute
		// blocks already in the state (nonce rejections → gas failures → the
		// Skip forward to the committed height instead.
		{
			name:       "restart with state ahead of blockstore tip: skip forward",
			fromHeight: 46, verified: 46, lch: 54,
			hasHistory: false,
			want:       54,
			note:       "replaying already-committed blocks would double-apply their effects",
		},
		{
			name:       "restart with state behind tip: normal M4 clamp-down still applies",
			fromHeight: 46, verified: 46, lch: 29,
			hasHistory: false,
			want:       29,
			note:       "no history needed when clamping down — replay from 30",
		},
		{
			name:       "restart with state ahead but low verified: still skip forward",
			fromHeight: 10, verified: 20, lch: 54,
			hasHistory: false,
			want:       54,
		},
	}

	for _, c := range cases {
		got := computeRebuildBaseline(c.fromHeight, c.verified, c.lch, c.hasHistory)
		if got != c.want {
			t.Errorf("%s: computeRebuildBaseline(from=%d, verified=%d, lch=%d, hasHistory=%v) = %d, want %d %s",
				c.name, c.fromHeight, c.verified, c.lch, c.hasHistory, got, c.want, c.note)
		}
		// Invariant: the baseline may never exceed what the stateDB committed.
		if got > c.lch {
			t.Errorf("%s: baseline %d exceeds committed height %d — blocks %d..%d "+
				"would be skipped and their transactions lost from local state",
				c.name, got, c.lch, c.lch+1, got)
		}
	}
}

func TestR87M4_NoteStateRolledBackTo_LowersBookkeeping(t *testing.T) {
	s := &Syncer{startHeight: 37, stateVerifiedHeight: 37}

	s.noteStateRolledBackTo(30)

	if s.startHeight != 29 {
		t.Errorf("startHeight = %d, want 29 (post-rollback baseline)", s.startHeight)
	}
	if s.stateVerifiedHeight != 29 {
		t.Errorf("stateVerifiedHeight = %d, want 29. Leaving it at 37 makes "+
			"rebuildState resume at 38 and blocks 30..37 are never re-applied",
			s.stateVerifiedHeight)
	}
}

func TestR87M4_NoteStateRolledBackTo_NeverRaises(t *testing.T) {
	// A rollback to a height ABOVE the current bookkeeping must not inflate it;
	// that would claim state is verified further than it has been.
	s := &Syncer{startHeight: 10, stateVerifiedHeight: 12}
	s.noteStateRolledBackTo(100)

	if s.startHeight != 10 || s.stateVerifiedHeight != 12 {
		t.Errorf("bookkeeping must only move down: startHeight=%d stateVerifiedHeight=%d, want 10/12",
			s.startHeight, s.stateVerifiedHeight)
	}
}

func TestR87M4_NoteStateRolledBackTo_Genesis(t *testing.T) {
	s := &Syncer{startHeight: 5, stateVerifiedHeight: 5}
	s.noteStateRolledBackTo(0)

	if s.startHeight != 0 || s.stateVerifiedHeight != 0 {
		t.Errorf("rollback to genesis must zero the bookkeeping: startHeight=%d stateVerifiedHeight=%d",
			s.startHeight, s.stateVerifiedHeight)
	}
}

// TestR87M4_CascadingRollbackReplaysEveryDroppedBlock walks a cascading
// rollback sequence and asserts the replay range covers every rolled-back block.
func TestR87M4_CascadingRollbackReplaysEveryDroppedBlock(t *testing.T) {
	const (
		diskHeight = 37
		lastGood   = 29 // stateDB after the cascade rolled back 37..30
		syncedTo   = 41 // chain tip when the rebuild kicked off
	)

	s := &Syncer{startHeight: diskHeight, stateVerifiedHeight: diskHeight}
	for forkPoint := uint64(diskHeight); forkPoint >= 30; forkPoint-- {
		s.noteStateRolledBackTo(forkPoint)
	}

	baseline := computeRebuildBaseline(s.startHeight, s.stateVerifiedHeight, lastGood, true)
	replayFrom := baseline + 1

	if replayFrom != 30 {
		t.Fatalf("replay starts at block %d, want 30. Blocks %d..29 would keep "+
			"state that the fork rollback removed, or blocks 30..%d would be "+
			"skipped entirely (the observed defect: replay started at 38)",
			replayFrom, replayFrom, replayFrom-1)
	}
	for h := uint64(30); h <= syncedTo; h++ {
		if h < replayFrom {
			t.Errorf("block %d is inside the rolled-back range but outside the replay range [%d,%d]",
				h, replayFrom, syncedTo)
		}
	}
}
