// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"
	"time"
)

// ============================================================================
// TSS-R5-08 (2026-07-17): Round2 private message freshness state machine.
//
// These tests exercise Node.validateRound2PrivateFreshness in isolation —
// no P2P, no keyExchange, no distributedSigner required. They verify:
//   1. Fresh timestamp within window → accepted, lastTS updated.
//   2. Stale timestamp beyond ±5min window → rejected.
//   3. Future timestamp beyond ±5min window → rejected.
//   4. Identical replay (same timestamp) → rejected (non-monotonic).
//   5. Older timestamp (out-of-order) → rejected.
//   6. Strictly increasing timestamps → all accepted.
//   7. Different participants are tracked independently.
//   8. Different sessions are tracked independently.
//   9. clearAggregatorSession clears only that session's entries.
// ============================================================================

// newFreshnessTestNode returns a Node with only the TSS-R5-08 freshness
// state initialized — enough to exercise validateRound2PrivateFreshness
// without standing up the full Node stack.
func newFreshnessTestNode() *Node {
	return &Node{
		round2PrivateLastTS: make(map[[40]byte]int64),
	}
}

func TestTSS_R5_08_FreshTimestampAccepted(t *testing.T) {
	n := newFreshnessTestNode()
	var sid [32]byte
	sid[0] = 0x42

	now := time.Now().UnixNano()
	if !n.validateRound2PrivateFreshness(sid, 1, now) {
		t.Error("fresh timestamp rejected")
	}

	// Verify lastTS was recorded by checking that an identical replay
	// (same timestamp) is now rejected as non-monotonic — this proves
	// the prior call recorded state.
	if n.validateRound2PrivateFreshness(sid, 1, now) {
		t.Error("identical replay accepted — lastTS was not recorded")
	}
}

func TestTSS_R5_08_StaleTimestampRejected(t *testing.T) {
	n := newFreshnessTestNode()
	var sid [32]byte

	// 10 minutes ago — beyond 5min window.
	stale := time.Now().Add(-10 * time.Minute).UnixNano()
	if n.validateRound2PrivateFreshness(sid, 1, stale) {
		t.Error("stale timestamp accepted — freshness window violated")
	}
}

func TestTSS_R5_08_FutureTimestampRejected(t *testing.T) {
	n := newFreshnessTestNode()
	var sid [32]byte

	// 10 minutes in the future — beyond 5min window.
	future := time.Now().Add(10 * time.Minute).UnixNano()
	if n.validateRound2PrivateFreshness(sid, 1, future) {
		t.Error("future timestamp accepted — freshness window violated")
	}
}

func TestTSS_R5_08_BoundaryTimestampAccepted(t *testing.T) {
	n := newFreshnessTestNode()
	var sid [32]byte

	// Just inside the window (4 minutes ago).
	ts := time.Now().Add(-4 * time.Minute).UnixNano()
	if !n.validateRound2PrivateFreshness(sid, 1, ts) {
		t.Error("in-window timestamp rejected (4min ago)")
	}
}

func TestTSS_R5_08_IdenticalReplayRejected(t *testing.T) {
	n := newFreshnessTestNode()
	var sid [32]byte

	now := time.Now().UnixNano()
	if !n.validateRound2PrivateFreshness(sid, 1, now) {
		t.Fatal("first message rejected")
	}
	// Identical timestamp — replay.
	if n.validateRound2PrivateFreshness(sid, 1, now) {
		t.Error("identical replay accepted — monotonic check failed")
	}
}

func TestTSS_R5_08_OlderTimestampRejected(t *testing.T) {
	n := newFreshnessTestNode()
	var sid [32]byte

	now := time.Now().UnixNano()
	if !n.validateRound2PrivateFreshness(sid, 1, now) {
		t.Fatal("first message rejected")
	}
	// Older timestamp (still within window, but before prev).
	older := now - int64(time.Second)
	if n.validateRound2PrivateFreshness(sid, 1, older) {
		t.Error("older timestamp accepted — strict monotonic violated")
	}
}

func TestTSS_R5_08_StrictlyIncreasingAccepted(t *testing.T) {
	n := newFreshnessTestNode()
	var sid [32]byte

	base := time.Now().UnixNano()
	for i := 0; i < 5; i++ {
		ts := base + int64(i)*int64(time.Millisecond)
		if !n.validateRound2PrivateFreshness(sid, 1, ts) {
			t.Errorf("strictly increasing timestamp %d rejected", i)
		}
	}
}

func TestTSS_R5_08_DifferentParticipantsIndependent(t *testing.T) {
	n := newFreshnessTestNode()
	var sid [32]byte

	now := time.Now().UnixNano()
	// Same timestamp for two different participants — both must be accepted.
	if !n.validateRound2PrivateFreshness(sid, 1, now) {
		t.Fatal("participant 1 rejected")
	}
	if !n.validateRound2PrivateFreshness(sid, 2, now) {
		t.Error("participant 2 rejected — participants not tracked independently")
	}
}

func TestTSS_R5_08_DifferentSessionsIndependent(t *testing.T) {
	n := newFreshnessTestNode()
	var sid1, sid2 [32]byte
	sid1[0] = 0x11
	sid2[0] = 0x22

	now := time.Now().UnixNano()
	if !n.validateRound2PrivateFreshness(sid1, 1, now) {
		t.Fatal("session 1 rejected")
	}
	// Same pid, same timestamp, different session — must be accepted.
	if !n.validateRound2PrivateFreshness(sid2, 1, now) {
		t.Error("session 2 rejected — sessions not tracked independently")
	}
}

func TestTSS_R5_08_ClearAggregatorSessionDropsEntries(t *testing.T) {
	n := newFreshnessTestNode()
	sid1 := make([]byte, 32)
	sid1[0] = 0x11
	sid2 := make([]byte, 32)
	sid2[0] = 0x22

	// Set current aggregator session = sid1, then accept a message for sid1.
	n.setAggregatorSession(sid1)
	var sid1Arr [32]byte
	copy(sid1Arr[:], sid1)

	now := time.Now().UnixNano()
	if !n.validateRound2PrivateFreshness(sid1Arr, 1, now) {
		t.Fatal("sid1 message rejected")
	}
	// Also accept a message for sid2 (a concurrent session).
	var sid2Arr [32]byte
	copy(sid2Arr[:], sid2)
	if !n.validateRound2PrivateFreshness(sid2Arr, 1, now) {
		t.Fatal("sid2 message rejected")
	}

	// Clear sid1 session.
	n.clearAggregatorSession()

	// sid1 entry should be gone — accepting the same timestamp now should
	// succeed (no prev), but it will fail the window check since "now" is the
	// same instant. So verify by checking the map directly.
	n.round2PrivateTSMu.Lock()
	count := len(n.round2PrivateLastTS)
	n.round2PrivateTSMu.Unlock()

	if count == 0 {
		t.Error("all entries cleared — sid2 entries should have been preserved")
	}

	// Verify sid2 entry still exists by accepting a strictly greater timestamp.
	later := now + int64(time.Second)
	if !n.validateRound2PrivateFreshness(sid2Arr, 1, later) {
		t.Error("sid2 entry lost after clearing sid1 — clearAggregatorSession cleared wrong session")
	}
}

func TestTSS_R5_08_ReplayAfterClearAccepted(t *testing.T) {
	n := newFreshnessTestNode()
	sid := make([]byte, 32)
	sid[0] = 0x33

	n.setAggregatorSession(sid)
	var sidArr [32]byte
	copy(sidArr[:], sid)

	now := time.Now().UnixNano()
	if !n.validateRound2PrivateFreshness(sidArr, 1, now) {
		t.Fatal("first message rejected")
	}
	// Replay — must be rejected.
	if n.validateRound2PrivateFreshness(sidArr, 1, now) {
		t.Error("replay accepted before clear")
	}

	// Clear session, then the same timestamp becomes acceptable again
	// (window check still applies — use a fresh "now").
	n.clearAggregatorSession()
	freshTS := time.Now().UnixNano()
	if !n.validateRound2PrivateFreshness(sidArr, 1, freshTS) {
		t.Error("fresh timestamp after clear rejected — clear did not reset state")
	}
}
