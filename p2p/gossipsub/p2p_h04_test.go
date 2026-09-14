// Quantaureum Node source, version 1.0.0.
package gossipsub

import (
	"testing"
	"time"
)

// TestP2P_H04_IncrementMissingForward verifies the basic counter increment
// behavior of the missing-forward tracker.
//
// P2P-H04 FIX (R29, 2026-07-26): PeerScorer.IncrementMissingForward records
// that a mesh peer failed to forward a message that other mesh peers
// delivered. This is the raw data; ApplyMissingForwardPenalty applies the
// actual score penalty based on the deficit ratio.
func TestP2P_H04_IncrementMissingForward(t *testing.T) {
	ps := NewPeerScorer()
	peerID := PeerID("silent-peer")

	if count := ps.GetMissingForwardCount(peerID); count != 0 {
		t.Fatalf("initial missingForwardCount = %d, want 0", count)
	}

	ps.IncrementMissingForward(peerID)
	ps.IncrementMissingForward(peerID)
	ps.IncrementMissingForward(peerID)

	if count := ps.GetMissingForwardCount(peerID); count != 3 {
		t.Errorf("after 3 increments, missingForwardCount = %d, want 3", count)
	}
}

// TestP2P_H04_ApplyMissingForwardPenalty_RatioThreshold verifies that a peer
// is penalized only when its missing-forward ratio exceeds the threshold
// (missingForwardRatioThreshold = 0.8) AND the absolute count is at least
// missingForwardMinAbsolute (5).
func TestP2P_H04_ApplyMissingForwardPenalty_RatioThreshold(t *testing.T) {
	ps := NewPeerScorer()
	silentPeer := PeerID("silent-peer")
	goodPeer := PeerID("good-peer")

	// 10 total deliveries; silentPeer missed 9 (ratio 0.9 >= 0.8, count 9 >= 5).
	// goodPeer missed 2 (ratio 0.2 < 0.8).
	for i := 0; i < 9; i++ {
		ps.IncrementMissingForward(silentPeer)
	}
	for i := 0; i < 2; i++ {
		ps.IncrementMissingForward(goodPeer)
	}

	penaltyBefore := ps.GetPenalty(silentPeer)
	ps.ApplyMissingForwardPenalty(10) // 10 total deliveries
	penaltyAfter := ps.GetPenalty(silentPeer)

	if penaltyAfter >= penaltyBefore {
		t.Errorf("silentPeer penalty should decrease: before=%v after=%v",
			penaltyBefore, penaltyAfter)
	}
	if diff := penaltyBefore - penaltyAfter; diff < missingForwardPenalty-0.01 {
		t.Errorf("silentPeer penalty delta = %v, want >= %v (missingForwardPenalty)",
			diff, missingForwardPenalty)
	}

	// goodPeer should NOT be penalized (ratio 0.2 < 0.8).
	goodPenaltyBefore := ps.GetPenalty(goodPeer)
	// goodPeer was already penalized 0 times (no increments left after ApplyMissingForwardPenalty reset).
	// But we need to re-increment to test the ratio.
	for i := 0; i < 2; i++ {
		ps.IncrementMissingForward(goodPeer)
	}
	ps.ApplyMissingForwardPenalty(10)
	goodPenaltyAfter := ps.GetPenalty(goodPeer)
	if goodPenaltyAfter < goodPenaltyBefore {
		t.Errorf("goodPeer should NOT be penalized (ratio 0.2 < 0.8): before=%v after=%v",
			goodPenaltyBefore, goodPenaltyAfter)
	}
}

// TestP2P_H04_ApplyMissingForwardPenalty_MinAbsolute verifies that a peer
// is NOT penalized when its missing-forward count is below
// missingForwardMinAbsolute (3), even if the ratio exceeds the threshold.
// This avoids penalizing on tiny samples where the deficit is
// indistinguishable from propagation jitter.
//
// R33 FIX (2026-07-28): Updated test to match missingForwardMinAbsolute=3
// (was 5). The constant was intentionally lowered from 5 to 3 (see scorer.go
// line 110 comment) to detect deficits on smaller samples, but this test
// was not updated. With minAbsolute=3, we use 2 misses (below 3) to verify
// the floor is enforced.
func TestP2P_H04_ApplyMissingForwardPenalty_MinAbsolute(t *testing.T) {
	ps := NewPeerScorer()
	peer := PeerID("peer")

	// 2 misses out of 3 total (ratio 0.67 >= threshold 0.6, but count 2 < 3).
	for i := 0; i < 2; i++ {
		ps.IncrementMissingForward(peer)
	}

	penaltyBefore := ps.GetPenalty(peer)
	ps.ApplyMissingForwardPenalty(3)
	penaltyAfter := ps.GetPenalty(peer)

	if penaltyAfter < penaltyBefore {
		t.Errorf("peer with 2 misses (below minAbsolute 3) should NOT be penalized: before=%v after=%v",
			penaltyBefore, penaltyAfter)
	}
}

// TestP2P_H04_ApplyMissingForwardPenalty_ResetsCounter verifies that
// ApplyMissingForwardPenalty resets the missingForwards counter for all
// peers after evaluation, regardless of whether the penalty was applied.
func TestP2P_H04_ApplyMissingForwardPenalty_ResetsCounter(t *testing.T) {
	ps := NewPeerScorer()
	peer := PeerID("peer")

	// Add 10 misses (above threshold AND min absolute) so penalty applies.
	for i := 0; i < 10; i++ {
		ps.IncrementMissingForward(peer)
	}
	if count := ps.GetMissingForwardCount(peer); count != 10 {
		t.Fatalf("before Apply: count = %d, want 10", count)
	}

	ps.ApplyMissingForwardPenalty(10)

	if count := ps.GetMissingForwardCount(peer); count != 0 {
		t.Errorf("after Apply: count = %d, want 0 (counter should reset)", count)
	}
}

// TestP2P_H04_ApplyMissingForwardPenalty_ZeroDeliveries verifies that
// when totalWindowDeliveries is 0, no penalty is applied but counters
// are still reset.
func TestP2P_H04_ApplyMissingForwardPenalty_ZeroDeliveries(t *testing.T) {
	ps := NewPeerScorer()
	peer := PeerID("peer")

	for i := 0; i < 10; i++ {
		ps.IncrementMissingForward(peer)
	}

	penaltyBefore := ps.GetPenalty(peer)
	ps.ApplyMissingForwardPenalty(0) // no deliveries this window
	penaltyAfter := ps.GetPenalty(peer)

	if penaltyAfter < penaltyBefore {
		t.Errorf("with 0 total deliveries, no penalty should apply: before=%v after=%v",
			penaltyBefore, penaltyAfter)
	}
	if count := ps.GetMissingForwardCount(peer); count != 0 {
		t.Errorf("counter should still reset: count = %d, want 0", count)
	}
}

// TestP2P_H04_RecordMeshDelivery_TracksDeliveries verifies that
// recordMeshDelivery correctly tracks which peers delivered which messages.
// The first delivery of a message creates an entry; subsequent deliveries
// from other peers add to the entry.
//
// NOTE: Variable named 'topic' (not 't') to avoid shadowing the test
// framework's *testing.T parameter named 't'.
func TestP2P_H04_RecordMeshDelivery_TracksDeliveries(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	topic, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Deliver message 1 from peerA.
	msg1 := &Message{
		ID:    ComputeMessageID(TopicBlocks, []byte("payload1")),
		Topic: TopicBlocks,
		From:  PeerID("peerA"),
		Data:  []byte("payload1"),
	}
	gs.recordMeshDelivery(msg1)

	topic.deliveredMsgPeersMu.Lock()
	peers, ok := topic.deliveredMsgPeers[msg1.ID]
	topic.deliveredMsgPeersMu.Unlock()
	if !ok {
		t.Fatal("msg1 not tracked after first delivery")
	}
	if len(peers) != 1 {
		t.Errorf("msg1 should have 1 delivering peer, got %d", len(peers))
	}
	if _, exists := peers[PeerID("peerA")]; !exists {
		t.Error("peerA should be in delivering-peers set for msg1")
	}

	// Deliver the same message from peerB (duplicate delivery).
	msg1B := &Message{
		ID:    msg1.ID, // same ID
		Topic: TopicBlocks,
		From:  PeerID("peerB"),
		Data:  []byte("payload1"),
	}
	gs.recordMeshDelivery(msg1B)
	topic.deliveredMsgPeersMu.Lock()
	peers = topic.deliveredMsgPeers[msg1.ID]
	topic.deliveredMsgPeersMu.Unlock()
	if len(peers) != 2 {
		t.Errorf("msg1 should have 2 delivering peers after peerB, got %d", len(peers))
	}
	if _, exists := peers[PeerID("peerB")]; !exists {
		t.Error("peerB should be in delivering-peers set for msg1")
	}

	// Verify windowDeliveries was incremented exactly once (msg1 is one
	// distinct message).
	topic.deliveredMsgPeersMu.Lock()
	deliveries := topic.windowDeliveries
	topic.deliveredMsgPeersMu.Unlock()
	if deliveries != 1 {
		t.Errorf("windowDeliveries = %d, want 1 (one distinct message)", deliveries)
	}
}

// TestP2P_H04_EvaluateMissingForwards_ChargesSilentPeers verifies that
// evaluateMissingForwards charges mesh peers that did NOT deliver a message
// with a missing forward, and does NOT charge peers that did deliver.
func TestP2P_H04_EvaluateMissingForwards_ChargesSilentPeers(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	topic, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Manually add mesh peers: peerA, peerB, peerC.
	topic.meshMu.Lock()
	topic.mesh[PeerID("peerA")] = &peerState{id: PeerID("peerA")}
	topic.mesh[PeerID("peerB")] = &peerState{id: PeerID("peerB")}
	topic.mesh[PeerID("peerC")] = &peerState{id: PeerID("peerC")}
	topic.meshMu.Unlock()

	// Deliver 10 distinct messages from peerA only. peerB and peerC are
	// silent (they should be charged).
	for i := 0; i < 10; i++ {
		msg := &Message{
			ID:    ComputeMessageID(TopicBlocks, []byte{byte(i)}),
			Topic: TopicBlocks,
			From:  PeerID("peerA"),
			Data:  []byte{byte(i)},
		}
		gs.recordMeshDelivery(msg)
	}

	// Before evaluation, peerB and peerC should have 0 missing forwards.
	if c := gs.scorer.GetMissingForwardCount(PeerID("peerB")); c != 0 {
		t.Fatalf("peerB missingForwards before evaluation = %d, want 0", c)
	}

	totalDeliveries := gs.evaluateMissingForwards(topic)
	if totalDeliveries != 10 {
		t.Errorf("totalDeliveries = %d, want 10", totalDeliveries)
	}

	// peerB and peerC should each have 10 missing forwards.
	if c := gs.scorer.GetMissingForwardCount(PeerID("peerB")); c != 10 {
		t.Errorf("peerB missingForwards after evaluation = %d, want 10", c)
	}
	if c := gs.scorer.GetMissingForwardCount(PeerID("peerC")); c != 10 {
		t.Errorf("peerC missingForwards after evaluation = %d, want 10", c)
	}

	// peerA should have 0 missing forwards (it delivered all messages).
	if c := gs.scorer.GetMissingForwardCount(PeerID("peerA")); c != 0 {
		t.Errorf("peerA missingForwards after evaluation = %d, want 0 (it delivered all)", c)
	}
}

// TestP2P_H04_EvaluateMissingForwards_PartialDelivery verifies that a peer
// who delivered SOME but not ALL messages is charged only for the messages
// it missed (not all messages).
func TestP2P_H04_EvaluateMissingForwards_PartialDelivery(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	topic, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	topic.meshMu.Lock()
	topic.mesh[PeerID("peerA")] = &peerState{id: PeerID("peerA")}
	topic.mesh[PeerID("peerB")] = &peerState{id: PeerID("peerB")}
	topic.meshMu.Unlock()

	// Deliver 10 messages: peerA delivers all 10, peerB delivers only 5.
	for i := 0; i < 10; i++ {
		msgA := &Message{
			ID:    ComputeMessageID(TopicBlocks, []byte{byte(i)}),
			Topic: TopicBlocks,
			From:  PeerID("peerA"),
			Data:  []byte{byte(i)},
		}
		gs.recordMeshDelivery(msgA)
		if i < 5 {
			// peerB also delivers this message (duplicate delivery).
			msgB := &Message{
				ID:    msgA.ID, // same message ID
				Topic: TopicBlocks,
				From:  PeerID("peerB"),
				Data:  []byte{byte(i)},
			}
			gs.recordMeshDelivery(msgB)
		}
	}

	gs.evaluateMissingForwards(topic)

	// peerB missed 5 messages (the last 5).
	if c := gs.scorer.GetMissingForwardCount(PeerID("peerB")); c != 5 {
		t.Errorf("peerB missingForwards = %d, want 5 (partial delivery)", c)
	}
	// peerA missed 0 (it delivered all).
	if c := gs.scorer.GetMissingForwardCount(PeerID("peerA")); c != 0 {
		t.Errorf("peerA missingForwards = %d, want 0", c)
	}
}

// TestP2P_H04_PerformHeartbeat_AppliesPenaltyEndToEnd verifies the
// end-to-end flow: deliver messages from one peer only, run performHeartbeat
// repeatedly, and confirm that the silent peer's score drops AND it is
// eventually evicted from the mesh.
//
// NOTE: GetScore uses an EMA blend (scoreDecayRate=0.95) that smooths the
// stored score toward freshScore. A single penalty application does NOT
// immediately drop the stored score by the full penalty amount. Combined
// with the heartbeatTopic lowScorePeers eviction (which evicts peers with
// score in [scoreGraylist, scoreAcceptable) when replacements are available),
// the silent peer is evicted BEFORE its stored score reaches scoreGraylist.
// This is the desired behavior: the silent peer is identified (penalty
// applied) and evicted (mesh maintenance) without needing the stored score
// to fully converge.
func TestP2P_H04_PerformHeartbeat_AppliesPenaltyEndToEnd(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	topic, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Add peerA and peerB to mesh.
	topic.meshMu.Lock()
	topic.mesh[PeerID("peerA")] = &peerState{id: PeerID("peerA")}
	topic.mesh[PeerID("peerB")] = &peerState{id: PeerID("peerB")}
	topic.meshMu.Unlock()

	scoreBefore := gs.scorer.GetScore(PeerID("peerB"))

	// Run multiple silent windows. peerB never forwards; penalty
	// accumulates -45 per window. The heartbeat's lowScorePeers eviction
	// will evict peerB once its score drops below scoreAcceptable (0)
	// and replacement candidates are available (mockSender provides
	// peer1..peer10 as candidates).
	var scoreAfter float64
	peerBEvicted := false
	for w := 0; w < 40; w++ {
		// Deliver 10 distinct messages from peerA only. peerB is silent.
		for i := 0; i < 10; i++ {
			msg := &Message{
				ID:    ComputeMessageID(TopicBlocks, []byte{byte(i), byte(w)}),
				Topic: TopicBlocks,
				From:  PeerID("peerA"),
				Data:  []byte{byte(i), byte(w)},
			}
			gs.recordMeshDelivery(msg)
		}
		gs.performHeartbeat()

		scoreAfter = gs.scorer.GetScore(PeerID("peerB"))

		// Check if peerB has been evicted from mesh.
		topic.meshMu.RLock()
		_, inMesh := topic.mesh[PeerID("peerB")]
		meshSize := len(topic.mesh)
		meshPeers := make([]PeerID, 0, meshSize)
		for pid := range topic.mesh {
			meshPeers = append(meshPeers, pid)
		}
		topic.meshMu.RUnlock()
		if w < 3 || w%10 == 0 {
			t.Logf("WINDOW %d: score=%v, meshSize=%d, meshPeers=%v, gs.peers=%d",
				w, scoreAfter, meshSize, meshPeers, func() int {
					gs.peersMu.RLock()
					defer gs.peersMu.RUnlock()
					return len(gs.peers)
				}())
		}
		if !inMesh {
			peerBEvicted = true
			break
		}
	}

	// peerB's score should have dropped (penalty applied).
	if scoreAfter >= scoreBefore {
		t.Errorf("peerB score should drop after silent windows: before=%v after=%v",
			scoreBefore, scoreAfter)
	}

	// peerB should eventually be evicted from mesh (the goal of P2P-H04).
	if !peerBEvicted {
		t.Errorf("peerB was never evicted from mesh after 40 silent windows — "+
			"final score = %v. P2P-H04 penalty not strong enough to evict silent peer",
			scoreAfter)
	}
}

// TestP2P_H04_PerformHeartbeat_DoesNotPenalizeActivePeer verifies that
// a peer who delivers all messages is NOT penalized.
func TestP2P_H04_PerformHeartbeat_DoesNotPenalizeActivePeer(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	topic, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	topic.meshMu.Lock()
	topic.mesh[PeerID("peerA")] = &peerState{id: PeerID("peerA")}
	topic.meshMu.Unlock()

	// Deliver 10 messages from peerA.
	for i := 0; i < 10; i++ {
		msg := &Message{
			ID:    ComputeMessageID(TopicBlocks, []byte{byte(i)}),
			Topic: TopicBlocks,
			From:  PeerID("peerA"),
			Data:  []byte{byte(i)},
		}
		gs.recordMeshDelivery(msg)
	}

	scoreBefore := gs.scorer.GetScore(PeerID("peerA"))
	gs.performHeartbeat()
	scoreAfter := gs.scorer.GetScore(PeerID("peerA"))

	// peerA's score should not drop significantly (no missing-forward penalty).
	// Allow small fluctuations from EMA blending.
	if scoreAfter < scoreBefore-1.0 {
		t.Errorf("peerA score should NOT drop (delivered all messages): before=%v after=%v",
			scoreBefore, scoreAfter)
	}
}

// TestP2P_H04_CapEnforcement verifies that the deliveredMsgPeers map is
// bounded by windowMsgCap. When the cap is exceeded, the oldest entry is
// evicted.
func TestP2P_H04_CapEnforcement(t *testing.T) {
	sender := newMockSender()
	gs := NewGossipSub(nil, sender)
	gs.Start()
	defer gs.Stop()

	topic, err := gs.JoinTopic(TopicBlocks, func(msg *Message) {})
	if err != nil {
		t.Fatalf("JoinTopic failed: %v", err)
	}

	// Set a small cap for testing.
	topic.deliveredMsgPeersMu.Lock()
	topic.windowMsgCap = 5
	topic.deliveredMsgPeersMu.Unlock()

	// Deliver 10 messages; only the last 5 should remain in the map.
	for i := 0; i < 10; i++ {
		msg := &Message{
			ID:    ComputeMessageID(TopicBlocks, []byte{byte(i)}),
			Topic: TopicBlocks,
			From:  PeerID("peerA"),
			Data:  []byte{byte(i)},
		}
		gs.recordMeshDelivery(msg)
		// Small sleep to ensure timestamps differ for oldest-eviction logic.
		time.Sleep(1 * time.Millisecond)
	}

	topic.deliveredMsgPeersMu.Lock()
	count := len(topic.deliveredMsgPeers)
	cap := topic.windowMsgCap
	topic.deliveredMsgPeersMu.Unlock()

	if count > cap {
		t.Errorf("deliveredMsgPeers count = %d, want <= %d (cap not enforced)",
			count, cap)
	}
}
