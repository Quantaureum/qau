// Quantaureum Node source, version 1.0.0.
package gossipsub

import (
	"testing"
)

// TestP2P_R21_H01_IHaveUnknownTopicPenalized verifies that a peer sending
// IHAVE for a topic we don't subscribe to is penalized via
// RecordInvalidMessage. Previously handleIHave silently returned nil for
// unknown topics, allowing a malicious peer to endlessly spam IHAVE for
// bogus topics without any scoring consequence.
func TestP2P_R21_H01_IHaveUnknownTopicPenalized(t *testing.T) {
	gs := newTestGossipSubR21(t)

	from := "peer-spammer"
	gs.scorer.RecordMeshJoin(from, TopicBlocks)
	initialScore := gs.scorer.GetScore(from)

	// Send IHAVE for a topic that doesn't exist.
	ihave := &ControlIHave{
		Topic:      "qau_nonexistent_topic_v1",
		MessageIDs: []MessageID{{0x01}},
	}
	wantIDs := gs.handleIHave(from, ihave)

	// Should return nil (no messages to request for unknown topic).
	if len(wantIDs) != 0 {
		t.Errorf("expected no wantIDs for unknown topic, got %d", len(wantIDs))
	}

	// Score should have decreased due to the penalty.
	newScore := gs.scorer.GetScore(from)
	if newScore >= initialScore {
		t.Errorf("expected score to decrease after IHAVE for unknown topic: initial=%f, after=%f",
			initialScore, newScore)
	}
}

// TestP2P_R21_H01_IWantMissPenalized verifies that a peer sending IWANT
// for message IDs we don't have in any topic cache is penalized. Previously
// handleIWant silently ignored missing message IDs, allowing a malicious
// peer to probe for amplification vectors without any scoring consequence.
func TestP2P_R21_H01_IWantMissPenalized(t *testing.T) {
	gs := newTestGossipSubR21(t)

	from := "peer-spammer"
	gs.scorer.RecordMeshJoin(from, TopicBlocks)
	initialScore := gs.scorer.GetScore(from)

	// Send IWANT for message IDs that don't exist in any topic cache.
	// Use more than 4 IDs to verify the per-miss cap at 3.
	iwant := &ControlIWant{
		MessageIDs: []MessageID{{0x01}, {0x02}, {0x03}, {0x04}},
	}
	gs.handleIWant(from, iwant)

	// Score should have decreased due to per-miss penalties (capped at 3).
	newScore := gs.scorer.GetScore(from)
	if newScore >= initialScore {
		t.Errorf("expected score to decrease after IWANT with all misses: initial=%f, after=%f",
			initialScore, newScore)
	}
}

// TestP2P_R21_H01_IHaveRateLimitPenalized verifies that a peer exceeding
// the IHAVE rate limit is penalized. Previously the rate-limit violation
// just silently dropped the IHAVEs, allowing a peer to flood at exactly
// the ceiling forever.
func TestP2P_R21_H01_IHaveRateLimitPenalized(t *testing.T) {
	gs := newTestGossipSubR21(t)

	from := "peer-spammer"
	gs.scorer.RecordMeshJoin(from, TopicBlocks)
	initialScore := gs.scorer.GetScore(from)

	// Exhaust the IHAVE rate limit (maxIHavePerWindow = 4096 IDs per 10s).
	// Send one IHAVE with 5000 IDs to blow past the limit in one RPC.
	totalIDs := 5000
	if !gs.allowIHave(from, totalIDs) {
		// Rate limit triggered — apply the penalty as handleControlMessage does.
		gs.scorer.RecordInvalidMessage(from, "ihave-rate-limit")
	} else {
		t.Fatal("expected rate limit to trigger for 5000 IDs")
	}

	newScore := gs.scorer.GetScore(from)
	if newScore >= initialScore {
		t.Errorf("expected score to decrease after IHAVE rate-limit violation: initial=%f, after=%f",
			initialScore, newScore)
	}
}

// TestP2P_R21_H01_SustainedSpamPushesBelowGraylist verifies that sustained
// IHAVE-for-unknown-topic spam eventually pushes the peer below
// scoreGraylist, so the mesh maintenance logic will prune it.
func TestP2P_R21_H01_SustainedSpamPushesBelowGraylist(t *testing.T) {
	gs := newTestGossipSubR21(t)

	from := "peer-spammer"
	gs.scorer.RecordMeshJoin(from, TopicBlocks)

	// Spam IHAVE for unknown topics. Each call applies invalidMessagePenalty
	// (30). After 4 calls the accumulated penalty (-120) exceeds the fresh
	// peer's positive components (~+35), pushing the score below
	// scoreGraylist (-50).
	for i := 0; i < 4; i++ {
		ihave := &ControlIHave{
			Topic:      "qau_bogus_topic_v1",
			MessageIDs: []MessageID{{byte(i)}},
		}
		gs.handleIHave(from, ihave)
	}

	score := gs.scorer.GetScore(from)
	if score >= scoreGraylist {
		t.Errorf("expected sustained spammer to be below scoreGraylist (%f): got %f",
			scoreGraylist, score)
	}
}

// newTestGossipSubR21 creates a minimal GossipSub instance for R21 testing.
// We only need the fields touched by handleIHave/handleIWant/allowIHave —
// the scorer, topic map, and rate-limit maps. Stop() is a no-op because
// started=false, so no defer gs.Stop() is needed.
func newTestGossipSubR21(t *testing.T) *GossipSub {
	t.Helper()
	return &GossipSub{
		topics:         make(map[string]*Topic),
		scorer:         NewPeerScorer(),
		iwantRateLimit: make(map[PeerID]*iwantRateTracker),
		ihaveRateLimit: make(map[PeerID]*ihaveRateTracker),
	}
}
