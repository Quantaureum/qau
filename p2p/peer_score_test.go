// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"
	"time"
)

func TestPeerScorerOnConnect(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()

	ps.OnConnect("peer1", false)
	if ps.GetScore("peer1") != DefaultScore {
		t.Errorf("score after connect = %f, want %f", ps.GetScore("peer1"), DefaultScore)
	}
}

func TestPeerScorerOnConnectBootstrap(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()

	ps.OnConnect("bootstrap-peer", true)
	snap := ps.GetSnapshot("bootstrap-peer")
	if snap == nil {
		t.Fatal("snapshot should not be nil")
	}
	if snap.QualityScore != ScoreBootstrapNode {
		t.Errorf("bootstrap quality score = %f, want %f", snap.QualityScore, ScoreBootstrapNode)
	}
}

func TestPeerScorerOnDisconnect(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()

	ps.OnConnect("peer1", false)
	ps.OnDisconnect("peer1", true) // expected disconnect

	// Score should not change much for expected disconnect
	score := ps.GetScore("peer1")
	if score < DefaultScore-1 {
		t.Errorf("score after expected disconnect = %f, should be close to default", score)
	}

	ps.OnConnect("peer2", false)
	ps.OnDisconnect("peer2", false) // unexpected disconnect
	score2 := ps.GetScore("peer2")
	if score2 >= DefaultScore {
		t.Errorf("score after unexpected disconnect = %f, should be lower", score2)
	}
}

func TestPeerScorerRecordResponseTime(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()

	ps.OnConnect("peer1", false)
	ps.RecordResponseTime("peer1", 50*time.Millisecond) // fast response

	snap := ps.GetSnapshot("peer1")
	if snap == nil {
		t.Fatal("snapshot should not be nil")
	}
	if snap.ResponseScore <= 0 {
		t.Errorf("response score = %f, should be positive for fast response", snap.ResponseScore)
	}
}

func TestPeerScorerRecordValidBlock(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()

	ps.OnConnect("peer1", false)
	ps.RecordValidBlock("peer1")

	snap := ps.GetSnapshot("peer1")
	if snap == nil {
		t.Fatal("snapshot should not be nil")
	}
	if snap.QualityScore <= DefaultScore {
		t.Errorf("quality score = %f, should increase after valid block", snap.QualityScore)
	}
	if snap.MessageCount != 1 {
		t.Errorf("message count = %d, want 1", snap.MessageCount)
	}
}

func TestPeerScorerRecordInvalidBlock(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()

	ps.OnConnect("peer1", false)
	ps.RecordInvalidBlock("peer1")

	snap := ps.GetSnapshot("peer1")
	if snap == nil {
		t.Fatal("snapshot should not be nil")
	}
	if snap.QualityScore >= DefaultScore {
		t.Errorf("quality score = %f, should decrease after invalid block", snap.QualityScore)
	}
	if snap.InvalidCount != 1 {
		t.Errorf("invalid count = %d, want 1", snap.InvalidCount)
	}
}

func TestPeerScorerRecordValidTransaction(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()
	ps.OnConnect("peer1", false)
	ps.RecordValidTransaction("peer1")

	snap := ps.GetSnapshot("peer1")
	if snap.QualityScore <= DefaultScore {
		t.Errorf("quality score should increase after valid tx")
	}
}

func TestPeerScorerRecordInvalidTransaction(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()
	ps.OnConnect("peer1", false)
	ps.RecordInvalidTransaction("peer1")

	snap := ps.GetSnapshot("peer1")
	if snap.QualityScore >= DefaultScore {
		t.Errorf("quality score should decrease after invalid tx")
	}
}

func TestPeerScorerRecordValidVote(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()
	ps.OnConnect("peer1", false)
	ps.RecordValidVote("peer1")

	if ps.GetScore("peer1") <= DefaultScore {
		t.Errorf("score should increase after valid vote")
	}
}

func TestPeerScorerRecordInvalidVote(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()
	ps.OnConnect("peer1", false)
	ps.RecordInvalidVote("peer1")

	if ps.GetScore("peer1") >= DefaultScore {
		t.Errorf("score should decrease after invalid vote")
	}
}

func TestPeerScorerRecordValidAttestation(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()
	ps.OnConnect("peer1", false)
	ps.RecordValidAttestation("peer1")

	if ps.GetScore("peer1") <= DefaultScore {
		t.Errorf("score should increase after valid attestation")
	}
}

func TestPeerScorerRecordInvalidAttestation(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()
	ps.OnConnect("peer1", false)
	ps.RecordInvalidAttestation("peer1")

	if ps.GetScore("peer1") >= DefaultScore {
		t.Errorf("score should decrease after invalid attestation")
	}
}

func TestPeerScorerRecordProtocolViolation(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()
	ps.OnConnect("peer1", false)
	ps.RecordProtocolViolation("peer1")

	snap := ps.GetSnapshot("peer1")
	if snap.ProtocolScore >= 0 {
		t.Errorf("protocol score = %f, should be negative after violation", snap.ProtocolScore)
	}
}

func TestPeerScorerRecordTimeout(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()
	ps.OnConnect("peer1", false)
	ps.RecordTimeout("peer1")

	snap := ps.GetSnapshot("peer1")
	if snap.ProtocolScore >= 0 {
		t.Errorf("protocol score = %f, should be negative after timeout", snap.ProtocolScore)
	}
}

func TestPeerScorerRecordDiscoveryResponse(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()
	ps.OnConnect("peer1", false)
	ps.RecordDiscoveryResponse("peer1", 5)

	snap := ps.GetSnapshot("peer1")
	if snap.DiscoveryScore <= 0 {
		t.Errorf("discovery score = %f, should be positive", snap.DiscoveryScore)
	}
}

func TestPeerScorerIsBanned(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()
	ps.OnConnect("peer1", false)

	if ps.IsBanned("peer1") {
		t.Error("peer should not be banned initially")
	}

	// Record violations across multiple score dimensions to push total below -50
	// protocolScore: -30 * 0.20 = -6 per violation (clamped at -100 * 0.20 = -20)
	// qualityScore: -20 * 0.40 = -8 per invalid block (clamped at -100 * 0.40 = -40)
	// Need total <= -50
	for i := 0; i < 20; i++ {
		ps.RecordProtocolViolation("peer1")
		ps.RecordInvalidBlock("peer1")
		ps.RecordInvalidVote("peer1")
		ps.RecordTimeout("peer1")
	}

	if !ps.IsBanned("peer1") {
		score := ps.GetScore("peer1")
		t.Errorf("peer should be banned after many violations, score = %f", score)
	}
}

func TestPeerScorerGetTopPeers(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()

	ps.OnConnect("good-peer", false)
	ps.RecordValidBlock("good-peer")

	ps.OnConnect("bad-peer", false)
	ps.RecordInvalidBlock("bad-peer")

	ps.OnConnect("neutral-peer", false)

	top := ps.GetTopPeers(2)
	if len(top) != 2 {
		t.Fatalf("len(GetTopPeers) = %d, want 2", len(top))
	}
	// Good peer should be first
	if top[0] != "good-peer" {
		t.Errorf("top peer = %q, want %q", top[0], "good-peer")
	}
}

func TestPeerScorerGetWorstPeers(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()

	ps.OnConnect("good-peer", false)
	ps.RecordValidBlock("good-peer")

	ps.OnConnect("bad-peer", false)
	ps.RecordInvalidBlock("bad-peer")

	worst := ps.GetWorstPeers(1)
	if len(worst) != 1 {
		t.Fatalf("len(GetWorstPeers) = %d, want 1", len(worst))
	}
	if worst[0] != "bad-peer" {
		t.Errorf("worst peer = %q, want %q", worst[0], "bad-peer")
	}
}

func TestPeerScorerRemovePeer(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()
	ps.OnConnect("peer1", false)
	ps.RemovePeer("peer1")

	if ps.GetScore("peer1") != DefaultScore {
		t.Errorf("score after removal should be default, got %f", ps.GetScore("peer1"))
	}
}

func TestPeerScorerPeerCount(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()

	ps.OnConnect("peer1", false)
	ps.OnConnect("peer2", false)

	if ps.PeerCount() != 2 {
		t.Errorf("PeerCount = %d, want 2", ps.PeerCount())
	}
}

func TestPeerScorerCleanupStalePeers(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()

	ps.OnConnect("peer1", false)

	// With 1h stale threshold and minScoreForRetention very negative, nothing should be removed
	removed := ps.CleanupStalePeers(time.Hour, -200)
	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}

	// Re-establish peer1 in case case 1 left the map empty.
	ps.OnConnect("peer1", false)

	// With minScoreForRetention above the peer's score, peer should be removed
	// Default score is 0, so minScoreForRetention=1 means score 0 < 1
	removed = ps.CleanupStalePeers(time.Hour, 1)
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
}

func TestPeerScorerUnknownPeer(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()

	if ps.GetScore("unknown") != DefaultScore {
		t.Errorf("unknown peer score = %f, want %f", ps.GetScore("unknown"), DefaultScore)
	}
	if ps.GetSnapshot("unknown") != nil {
		t.Error("unknown peer snapshot should be nil")
	}
}

func TestPeerScorerGetOrCreate(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()

	entry := ps.GetOrCreate("new-peer")
	if entry == nil {
		t.Fatal("GetOrCreate should return entry")
	}
	if entry.peerID != "new-peer" {
		t.Errorf("entry.peerID = %q, want %q", entry.peerID, "new-peer")
	}

	// Second call should return same entry
	entry2 := ps.GetOrCreate("new-peer")
	if entry2 != entry {
		t.Error("GetOrCreate should return same entry for same peer")
	}
}

func TestClampScore(t *testing.T) {
	if clampScore(200) != MaxPeerScore {
		t.Errorf("clampScore(200) = %f, want %f", clampScore(200), MaxPeerScore)
	}
	if clampScore(-200) != MinPeerScore {
		t.Errorf("clampScore(-200) = %f, want %f", clampScore(-200), MinPeerScore)
	}
	if clampScore(50) != 50 {
		t.Errorf("clampScore(50) = %f, want 50", clampScore(50))
	}
}
