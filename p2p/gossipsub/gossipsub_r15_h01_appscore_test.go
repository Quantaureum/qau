// Quantaureum Node source, version 1.0.0.
package gossipsub

// P2P-R15-H01 tests.
//
// Verifies the fix for the audit finding:
//   The GossipSub AppSpecificScore callback was unregistered → PeerScorer penalties did not affect GossipSub
//   mesh management, so malicious nodes could still propagate invalid messages
//
// Before the fix, GossipSub's mesh maintenance (pruneExcessPeers,
// handleGraft) consulted ONLY gs.scorer (the gossipsub package's own
// PeerScorer). The Host's application-layer PeerScorer — which tracks
// invalid blocks, votes, transactions — was exposed via
// MessageSender.GetPeerScore() but never consulted. A peer heavily
// penalized by the Host could still join and remain in the GossipSub
// mesh.
//
// After the fix, peerScore() combines the two scores by taking the
// minimum, so a peer penalized by EITHER scorer is excluded from the
// mesh. When the application-layer score is 0.0 (neutral / no opinion,
// e.g. test mocks), only the GossipSub score is used — preserving
// backward compatibility.

import (
	"math"
	"testing"
	"time"
)

// scoreAlmostEqual reports whether two peer scores are equal within the
// EMA blend + time-sensitive uptime float noise that GetScore introduces
// when called twice in quick succession (delta on the order of 1e-11).
func scoreAlmostEqual(a, b float64) bool {
	const eps = 1e-9
	return math.Abs(a-b) <= eps
}

// =============================================================================
// Unit tests for peerScore()
// =============================================================================

// TestP2P_R15_H01_PeerScore_NeutralAppScore_ReturnsGossipScore verifies
// that when the application-layer score is 0.0 (neutral / no opinion),
// peerScore returns the GossipSub scorer's score unchanged. This is the
// backward-compatibility path: test mocks whose GetPeerScore returns 0
// for all peers must see no behavior change.
func TestP2P_R15_H01_PeerScore_NeutralAppScore_ReturnsGossipScore(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	defer gs.Stop()

	// "peer1" has no app score set in mockSender → GetPeerScore returns 0.
	// Record one invalid message to give the peer a non-zero gossip score.
	gs.scorer.RecordInvalidMessage("peer1", TopicBlocks)

	gossipScore := gs.scorer.GetScore("peer1")
	if gossipScore == 0 {
		t.Fatal("expected non-zero gossip score after RecordInvalidMessage")
	}

	combined := gs.peerScore("peer1")
	if !scoreAlmostEqual(combined, gossipScore) {
		t.Errorf("expected peerScore=gossipScore=%f when appScore=0, got %f", gossipScore, combined)
	}
}

// TestP2P_R15_H01_PeerScore_NegativeAppScore_ReturnsMin verifies that
// when the application-layer score is negative (peer penalized by Host),
// peerScore returns the minimum of the two scores. This is the core fix:
// a peer penalized at the application layer is also excluded from the
// GossipSub mesh.
func TestP2P_R15_H01_PeerScore_NegativeAppScore_ReturnsMin(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	defer gs.Stop()

	// Give the peer a known gossip score (no penalties → fresh peer ≈ +40).
	gossipScore := gs.scorer.GetScore("peer1")

	// Set a very negative app score (Host penalized this peer for invalid blocks).
	sender.peerScores["peer1"] = -80.0

	combined := gs.peerScore("peer1")
	if combined != -80.0 {
		t.Errorf("expected peerScore=-80.0 (min of gossip=%f and app=-80), got %f", gossipScore, combined)
	}
}

// TestP2P_R15_H01_PeerScore_PositiveAppScore_GossipScoreWins verifies
// that when the application-layer score is positive but the GossipSub
// score is lower, peerScore returns the GossipSub score (the minimum).
func TestP2P_R15_H01_PeerScore_PositiveAppScore_GossipScoreWins(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	defer gs.Stop()

	// Give the peer a negative gossip score via invalid messages.
	gs.scorer.RecordInvalidMessage("peer1", TopicBlocks)
	gs.scorer.RecordInvalidMessage("peer1", TopicBlocks)
	gossipScore := gs.scorer.GetScore("peer1")

	// Set a positive app score.
	sender.peerScores["peer1"] = 50.0

	combined := gs.peerScore("peer1")
	if !scoreAlmostEqual(combined, gossipScore) {
		t.Errorf("expected peerScore=gossipScore=%f (min of gossip and app=50), got %f", gossipScore, combined)
	}
	if combined >= 50.0 {
		t.Errorf("expected peerScore < 50 (gossip score should be lower), got %f", combined)
	}
}

// TestP2P_R15_H01_PeerScore_NilSender_ReturnsGossipScore verifies the
// defensive path: if gs.sender is nil, peerScore returns the GossipSub
// score only.
func TestP2P_R15_H01_PeerScore_NilSender_ReturnsGossipScore(t *testing.T) {
	gs := NewGossipSub(nil, nil) // nil sender
	defer gs.Stop()

	gs.scorer.RecordInvalidMessage("peer1", TopicBlocks)
	gossipScore := gs.scorer.GetScore("peer1")

	combined := gs.peerScore("peer1")
	if !scoreAlmostEqual(combined, gossipScore) {
		t.Errorf("expected peerScore=gossipScore=%f when sender=nil, got %f", gossipScore, combined)
	}
}

// =============================================================================
// Integration test: handleGraft
// =============================================================================

// TestP2P_R15_H01_HandleGraft_RejectsPeerWithBadAppScore verifies that
// handleGraft rejects a peer whose GossipSub score is fine but whose
// application-layer score is below scoreGraylist. Before the fix, this
// peer would have been accepted into the mesh.
func TestP2P_R15_H01_HandleGraft_RejectsPeerWithBadAppScore(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	defer gs.Stop()

	// Join a topic so handleGraft has a topic to graft into.
	_, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// "badAppPeer" has no gossip-layer penalties → gossip score ≈ +40
	// (well above scoreGraylist=-50). Without the fix, handleGraft would
	// accept this peer.
	gossipScore := gs.scorer.GetScore("badAppPeer")
	if gossipScore < scoreGraylist {
		t.Fatalf("expected gossip score >= scoreGraylist for fresh peer, got %f", gossipScore)
	}

	// Set a very negative app score — Host penalized this peer for
	// sending invalid blocks.
	sender.peerScores["badAppPeer"] = -80.0

	// Clear any prior sent messages.
	sender.sentMessages = make(map[PeerID][][]byte)

	// Call handleGraft — should be rejected due to combined score < scoreGraylist.
	gs.handleGraft("badAppPeer", TopicBlocks)

	// Verify a PRUNE was sent (rejection).
	pruneSent := false
	if msgs, ok := sender.sentMessages["badAppPeer"]; ok && len(msgs) > 0 {
		pruneSent = true
	}
	if !pruneSent {
		t.Fatal("P2P-R15-H01 REGRESSION: handleGraft accepted a peer with appScore=-80 (below scoreGraylist) — expected PRUNE")
	}

	// Verify the peer was NOT added to the mesh.
	gs.topicsMu.RLock()
	topic := gs.topics[TopicBlocks]
	gs.topicsMu.RUnlock()
	if topic == nil {
		t.Fatal("topic not found")
	}
	topic.meshMu.RLock()
	_, inMesh := topic.mesh["badAppPeer"]
	topic.meshMu.RUnlock()
	if inMesh {
		t.Fatal("P2P-R15-H01 REGRESSION: badAppPeer was added to mesh despite appScore=-80")
	}
}

// TestP2P_R15_H01_HandleGraft_AcceptsPeerWithGoodAppScore is the control
// test: a peer with good app score and good gossip score IS accepted.
func TestP2P_R15_H01_HandleGraft_AcceptsPeerWithGoodAppScore(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	defer gs.Stop()

	_, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// "goodPeer" has a positive app score.
	sender.peerScores["goodPeer"] = 30.0

	sender.sentMessages = make(map[PeerID][][]byte)

	gs.handleGraft("goodPeer", TopicBlocks)

	// Verify NO PRUNE was sent (accepted).
	if msgs, ok := sender.sentMessages["goodPeer"]; ok && len(msgs) > 0 {
		t.Fatalf("expected no PRUNE for goodPeer, got %d messages", len(msgs))
	}

	// Verify the peer WAS added to the mesh.
	gs.topicsMu.RLock()
	topic := gs.topics[TopicBlocks]
	gs.topicsMu.RUnlock()
	topic.meshMu.RLock()
	_, inMesh := topic.mesh["goodPeer"]
	topic.meshMu.RUnlock()
	if !inMesh {
		t.Fatal("goodPeer was NOT added to mesh despite good scores")
	}
}

// =============================================================================
// Integration test: pruneExcessPeers
// =============================================================================

// TestP2P_R15_H01_PruneExcess_PrunesWorstCombinedScore verifies that
// pruneExcessPeers prunes the peer with the worst COMBINED score (min of
// gossip and app scores), not just the worst gossip score. Before the
// fix, a peer with a good gossip score but terrible app score would
// survive pruning.
func TestP2P_R15_H01_PruneExcess_PrunesWorstCombinedScore(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	defer gs.Stop()

	_, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	gs.topicsMu.RLock()
	topic := gs.topics[TopicBlocks]
	gs.topicsMu.RUnlock()

	// Set up 3 peers in the mesh with different score profiles:
	//
	//   peerA: gossip ≈ +40 (fresh), appScore = 0  → combined ≈ +40
	//          (neutral app score → backward compat → gossip only)
	//
	//   peerB: gossip ≈ +40 (fresh), appScore = -90 → combined = -90
	//          (Host penalized for invalid blocks → WORST combined)
	//
	//   peerC: gossip ≈ -20 (2 invalid msgs), appScore = +50 → combined = -20
	//          (gossip penalized but app is good)
	//
	// Without the fix, pruneExcessPeers would sort by gossip only:
	//   peerC (-20) < peerA (+40) = peerB (+40)
	//   → peerC would be pruned (worst gossip score).
	//
	// With the fix, pruneExcessPeers sorts by combined score:
	//   peerB (-90) < peerC (-20) < peerA (+40)
	//   → peerB is pruned (worst combined score).

	// Give peerC 2 invalid messages to lower its gossip score.
	gs.scorer.RecordInvalidMessage("peerC", TopicBlocks)
	gs.scorer.RecordInvalidMessage("peerC", TopicBlocks)

	// Set app scores.
	sender.peerScores["peerB"] = -90.0
	sender.peerScores["peerC"] = 50.0
	// peerA has no app score set → GetPeerScore returns 0 (neutral).

	// Add all 3 peers to the mesh.
	topic.meshMu.Lock()
	topic.mesh["peerA"] = nil
	topic.mesh["peerB"] = nil
	topic.mesh["peerC"] = nil
	topic.meshMu.Unlock()

	peers := []PeerID{"peerA", "peerB", "peerC"}

	// Verify our score assumptions.
	scoreA := gs.peerScore("peerA")
	scoreB := gs.peerScore("peerB")
	scoreC := gs.peerScore("peerC")
	if scoreB >= scoreC || scoreB >= scoreA {
		t.Fatalf("test setup error: peerB should have worst combined score; got A=%f B=%f C=%f", scoreA, scoreB, scoreC)
	}
	if scoreC >= scoreA {
		t.Fatalf("test setup error: peerC should have lower combined than peerA; got A=%f C=%f", scoreA, scoreC)
	}

	sender.sentMessages = make(map[PeerID][][]byte)

	// Prune 1 peer (the worst).
	gs.pruneExcessPeers(topic, peers, 1)

	// peerB MUST have been pruned (worst combined score).
	topic.meshMu.RLock()
	_, bInMesh := topic.mesh["peerB"]
	topic.meshMu.RUnlock()
	if bInMesh {
		t.Fatal("P2P-R15-H01 REGRESSION: peerB (worst combined score) was NOT pruned")
	}

	// peerA and peerC MUST still be in the mesh.
	topic.meshMu.RLock()
	_, aInMesh := topic.mesh["peerA"]
	_, cInMesh := topic.mesh["peerC"]
	topic.meshMu.RUnlock()
	if !aInMesh {
		t.Error("peerA should still be in mesh (best combined score)")
	}
	if !cInMesh {
		t.Error("peerC should still be in mesh (middle combined score)")
	}

	// Verify a PRUNE was sent to peerB.
	if msgs, ok := sender.sentMessages["peerB"]; !ok || len(msgs) == 0 {
		t.Error("expected PRUNE sent to peerB")
	}
}

// TestP2P_R15_H01_BackwardCompat_MockSenderZeroScores verifies that
// existing test infrastructure using mockSender (which returns 0 for
// all unknown peers) is unaffected by the fix. All peers should be
// scored by gossip score only, and handleGraft/pruneExcessPeers behave
// exactly as before.
func TestP2P_R15_H01_BackwardCompat_MockSenderZeroScores(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	defer gs.Stop()

	_, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// No app scores set → all peers have appScore=0 → peerScore returns
	// gossip score only (backward compat).
	peer1Score := gs.peerScore("peer1")
	gossip1 := gs.scorer.GetScore("peer1")
	if peer1Score != gossip1 {
		t.Errorf("backward compat: expected peerScore=gossipScore=%f, got %f", gossip1, peer1Score)
	}

	// Even after recording an invalid message (non-zero gossip score),
	// peerScore should still equal gossip score (appScore=0).
	gs.scorer.RecordInvalidMessage("peer1", TopicBlocks)
	gossip1 = gs.scorer.GetScore("peer1")
	peer1Score = gs.peerScore("peer1")
	if !scoreAlmostEqual(peer1Score, gossip1) {
		t.Errorf("backward compat after penalty: expected peerScore=gossipScore=%f, got %f", gossip1, peer1Score)
	}

	// handleGraft should accept a fresh peer (gossip score ≈ +40, above
	// scoreGraylist=-50).
	sender.sentMessages = make(map[PeerID][][]byte)
	gs.handleGraft("freshPeer", TopicBlocks)

	if msgs, ok := sender.sentMessages["freshPeer"]; ok && len(msgs) > 0 {
		t.Error("backward compat: fresh peer should be accepted (no PRUNE), but got messages")
	}

	gs.topicsMu.RLock()
	topic := gs.topics[TopicBlocks]
	gs.topicsMu.RUnlock()
	topic.meshMu.RLock()
	_, inMesh := topic.mesh["freshPeer"]
	topic.meshMu.RUnlock()
	if !inMesh {
		t.Error("backward compat: fresh peer should be in mesh")
	}
}

// =============================================================================
// Concurrency test
// =============================================================================

// TestP2P_R15_H01_PeerScore_ConcurrentAccess verifies that peerScore is
// safe for concurrent access from multiple goroutines (e.g., heartbeat
// loop + RPC handler calling handleGraft simultaneously).
func TestP2P_R15_H01_PeerScore_ConcurrentAccess(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	defer gs.Stop()

	// Set up peers with app scores.
	sender.peerScores["peer1"] = -60.0
	sender.peerScores["peer2"] = 30.0
	sender.peerScores["peer3"] = -10.0

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			gs.peerScore("peer1")
			gs.peerScore("peer2")
			gs.peerScore("peer3")
		}
		close(done)
	}()

	// Simultaneously record invalid messages (modifies scorer state).
	go func() {
		for i := 0; i < 100; i++ {
			gs.scorer.RecordInvalidMessage("peer1", TopicBlocks)
			gs.scorer.RecordDuplicate("peer2", TopicBlocks)
		}
	}()

	select {
	case <-done:
		// OK
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent peerScore access timed out")
	}
}
