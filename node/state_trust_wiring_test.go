// Quantaureum Node source, version 1.0.0.
package node

import "testing"

// R87-STATE-TRUST wiring tests: the pure logic is covered by
// state_trust_test.go; these pin the Node/Syncer plumbing so a future
// refactor cannot silently disconnect the guard.

func TestR87Node_MismatchStreakDisablesTrust(t *testing.T) {
	n := &Node{stateTrust: newStateTrust()}
	n.stateTrust.streakLimit = 4

	if !n.IsStateTrusted() {
		t.Fatal("a fresh node must start trusted")
	}
	for i := 0; i < 3; i++ {
		n.recordStateRootMismatch(uint64(100 + i))
	}
	if !n.IsStateTrusted() {
		t.Fatal("3 mismatches with a limit of 4 must not disable trust")
	}
	n.recordStateRootMismatch(103)
	if n.IsStateTrusted() {
		t.Fatal("crossing the streak limit must disable trust")
	}
	if n.StateTrustDetail() == "" {
		t.Error("a broken node must expose a reason for operators")
	}
	if n.StateRootMismatchStreak() != 4 {
		t.Errorf("streak = %d, want 4", n.StateRootMismatchStreak())
	}

	// An agreeing root proves the drift was transient: soft break clears.
	n.recordStateRootMatch()
	if !n.IsStateTrusted() {
		t.Error("a matching root must clear a soft (streak-based) break")
	}
	if n.StateTrustDetail() != "" {
		t.Error("the reason must be cleared together with the soft break")
	}
}

func TestR87Node_FailedForkRollbackIsUnrecoverable(t *testing.T) {
	n := &Node{stateTrust: newStateTrust()}
	n.markStateTrustBroken("fork rollback to height 120 failed: history pruned")

	if n.IsStateTrusted() {
		t.Fatal("a failed fork rollback must disable trust")
	}
	for i := 0; i < 200; i++ {
		n.recordStateRootMatch()
	}
	if n.IsStateTrusted() {
		t.Fatal("matching roots must NOT re-enable trust after a failed rollback: " +
			"the abandoned branch's state changes are still in the account trie")
	}
}

func TestR87Node_NilSafeAccessors(t *testing.T) {
	// Tests and tools construct &Node{} directly; the guard must not panic and
	// must not accidentally report a healthy node as broken.
	n := &Node{}
	if !n.IsStateTrusted() {
		t.Error("a Node without a stateTrust must be treated as trusted")
	}
	n.recordStateRootMismatch(1)
	n.recordStateRootMatch()
	n.markStateTrustBroken("x")
	if n.StateTrustDetail() != "" || n.StateRootMismatchStreak() != 0 {
		t.Error("nil-stateTrust accessors must stay inert")
	}

	var nilNode *Node
	if !nilNode.IsStateTrusted() {
		t.Error("a nil Node must be treated as trusted")
	}
}

func TestR87Syncer_ReportsStateRootOutcomeToNode(t *testing.T) {
	s := &Syncer{}
	type call struct {
		height  uint64
		matched bool
	}
	var got []call
	s.SetOnStateRootResult(func(height uint64, matched bool) {
		got = append(got, call{height, matched})
	})

	s.reportStateRoot(7, false)
	s.reportStateRoot(8, true)

	want := []call{{7, false}, {8, true}}
	if len(got) != len(want) {
		t.Fatalf("got %d callbacks, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("callback %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	// No hook installed must not panic (unit tests build bare Syncers).
	bare := &Syncer{}
	bare.reportStateRoot(1, false)
}

func TestR87Producer_SkipsSlotWhenStateNotTrusted(t *testing.T) {
	n := &Node{stateTrust: newStateTrust()}
	bp := &BlockProducer{node: n}

	if bp.shouldSkipForStateTrust(1) {
		t.Fatal("a trusted node must keep producing")
	}

	n.markStateTrustBroken("fork rollback failed")
	if !bp.shouldSkipForStateTrust(1) {
		t.Fatal("R87: a node with untrusted state MUST NOT produce blocks — " +
			"producing is the only action that pushes local divergence onto peers")
	}
	// Slot 0 hits the log branch; must still skip.
	if !bp.shouldSkipForStateTrust(0) {
		t.Error("the gate must not depend on the log rate-limit branch")
	}

	// Nil-safety: tools construct bare producers.
	var nilBP *BlockProducer
	if nilBP.shouldSkipForStateTrust(1) {
		t.Error("a nil producer must not report a skip")
	}
	if (&BlockProducer{}).shouldSkipForStateTrust(1) {
		t.Error("a producer without a node must not report a skip")
	}
}
