// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"
)

// R115B-RESTART-REBUILD (2026-10-19): a node restarting mid full-sync boots
// with syncing=false while its verified height can be far behind the restored
// chain head. The old trigger armed only on the syncing→caught-up EDGE
// (shouldRebuildAfterSync requires wasSyncing), which already happened inside
// the previous process — so after a restart NOBODY ever launched the rebuild:
// the producer logged "state not verified yet (verified=0)" forever and the
// node never requested the remaining blocks. Production hit: S7 2026-10-19,
// reboot at head=220698, verified=0, wedged 11+ minutes until manual restart
// with the fix.
//
// The fix adds a rescue branch to checkSync's caught-up path: when not
// syncing, never was syncing this round, and no rebuild is running/pending,
// an unverified range above stateVerifiedHeight launches rebuildState
// directly. shouldRestartRebuild captures that decision so it stays testable
// without standing up a full Syncer loop.

// shouldRestartRebuild reports whether checkSync's caught-up path must launch
// a rebuild even though no syncing→caught-up transition happened in this
// process. It deliberately does NOT look at wasSyncing: the whole point of
// the rescue is the restart case where the transition belongs to a previous
// process.
//
// The condition mirrors shouldRebuildAfterSync's substantive question — "is
// there work?" — with two differences:
//   - rebuildRunning/rebuildPending must be 0 (a rebuild already covering the
//     range makes a second launch pointless; rebuildState would just mark
//     pending and exit),
//   - stateVerifiedHeight < currentHeight alone is sufficient even when the
//     in-memory unvalidated-marker map is empty: after a restart the durable
//     markers exist in the block store but countUnvalidatedInRangeLocked
//     counts only the in-memory set, so a marker-only check would
//     false-negative exactly in the case this branch exists for.
func TestShouldRestartRebuild_S7RestartCase(t *testing.T) {
	// The exact production signature: head restored to 220698, verified=0,
	// in-memory unvalidated markers empty (restart cleared them).
	if !shouldRestartRebuild(false, false, 220698, 0, 0) {
		t.Fatal("restart at head=220698 verified=0 must trigger a rebuild")
	}
}

func TestShouldRestartRebuild_NoWorkCases(t *testing.T) {
	cases := []struct {
		name             string
		running, pending bool
		cur, verified    uint64
		unvalidated      int
		want             bool
	}{
		{"rebuild already running", true, false, 100, 0, 50, false},
		{"rebuild pending", false, true, 100, 0, 50, false},
		{"genesis only", false, false, 0, 0, 0, false},
		{"verified through head", false, false, 100, 100, 0, false},
		{"verified ahead (rollback)", false, false, 100, 105, 0, false},
	}
	for _, c := range cases {
		if got := shouldRestartRebuild(c.running, c.pending, c.cur, c.verified, c.unvalidated); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestShouldRestartRebuild_MarkersEmptyButVerifiedBehind(t *testing.T) {
	// The durable-marker asymmetry: after restart the in-memory count is 0
	// but the verified height is behind. Height-aloneness must still fire.
	if !shouldRestartRebuild(false, false, 1000, 400, 0) {
		t.Fatal("verified=400 < head=1000 must trigger rebuild even with empty in-memory markers")
	}
}
