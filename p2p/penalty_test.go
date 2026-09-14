// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"
	"time"
)

func TestPenaltyWarning(t *testing.T) {
	pm := DefaultPenaltyConfig()
	bl := NewBlacklist()
	defer bl.Stop()
	pm.SetBlacklist(bl)
	defer pm.Stop()

	peerID := PeerID("test-peer-1")

	// 1-2 violations should remain at Warning level
	for i := 0; i < 3; i++ {
		level := pm.RecordViolation(peerID, ViolationBadMessage)
		if level != PenaltyWarning {
			t.Errorf("after %d bad_message violations, expected Warning, got %s", i+1, level)
		}
	}

	score := pm.GetScore(peerID)
	if score != 3 {
		t.Errorf("expected score 3, got %d", score)
	}

	// Should not be blacklisted at Warning level
	if bl.IsBlacklisted(peerID) {
		t.Error("peer should NOT be blacklisted at Warning level")
	}
}

func TestPenaltyTempBan(t *testing.T) {
	pm := DefaultPenaltyConfig()
	bl := NewBlacklist()
	defer bl.Stop()
	pm.SetBlacklist(bl)
	defer pm.Stop()

	peerID := PeerID("test-peer-2")

	// 10 bad_messages = score 10 → TempBan
	for i := 0; i < 10; i++ {
		pm.RecordViolation(peerID, ViolationBadMessage)
	}

	level := pm.GetLevel(peerID)
	if level != PenaltyTempBan {
		t.Errorf("expected TempBan, got %s", level)
	}

	if !bl.IsBlacklisted(peerID) {
		t.Error("peer should be blacklisted at TempBan level")
	}
}

func TestPenaltyLongBan(t *testing.T) {
	pm := DefaultPenaltyConfig()
	bl := NewBlacklist()
	defer bl.Stop()
	pm.SetBlacklist(bl)
	defer pm.Stop()

	peerID := PeerID("test-peer-3")

	// 30 bad_messages = score 30 → LongBan
	for i := 0; i < 30; i++ {
		pm.RecordViolation(peerID, ViolationBadMessage)
	}

	level := pm.GetLevel(peerID)
	if level != PenaltyLongBan {
		t.Errorf("expected LongBan, got %s", level)
	}
}

func TestPenaltyPermBan(t *testing.T) {
	pm := DefaultPenaltyConfig()
	bl := NewBlacklist()
	defer bl.Stop()
	pm.SetBlacklist(bl)
	defer pm.Stop()

	peerID := PeerID("test-peer-4")

	// 60 bad_messages = score 60 → PermBan
	for i := 0; i < 60; i++ {
		pm.RecordViolation(peerID, ViolationBadMessage)
	}

	level := pm.GetLevel(peerID)
	if level != PenaltyPermBan {
		t.Errorf("expected PermBan, got %s", level)
	}

	// Check reason
	reason := bl.GetReason(peerID)
	if reason == "" {
		t.Error("expected reason for permaban")
	}
}

func TestPenaltyWeightedViolations(t *testing.T) {
	pm := DefaultPenaltyConfig()
	bl := NewBlacklist()
	defer bl.Stop()
	pm.SetBlacklist(bl)
	defer pm.Stop()

	peerID := PeerID("test-peer-5")

	// 2 bad_blocks (weight 5 each) = 10 → TempBan
	pm.RecordViolation(peerID, ViolationBadBlock)
	pm.RecordViolation(peerID, ViolationBadBlock)

	level := pm.GetLevel(peerID)
	if level != PenaltyTempBan {
		t.Errorf("after 2 bad_blocks, expected TempBan, got %s", level)
	}
}

func TestPenaltyDecay(t *testing.T) {
	// Use a faster decay for testing
	pm := &PenaltyManager{
		entries:       make(map[PeerID]*penaltyEntry),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
		decayInterval: 100 * time.Millisecond,
		decayAmount:   5, // Decay 5 points per interval
	}
	bl := NewBlacklist()
	defer bl.Stop()
	pm.SetBlacklist(bl)
	pm.Start()
	defer pm.Stop()

	peerID := PeerID("test-decay-peer")

	// P3-P2P-02 FIX (R29, 2026-07-26): Use Warning-level violations
	// (score < 10) so decay applies. Banned peers (TempBan/LongBan/PermBan)
	// no longer have their scores decayed — see TestPenaltyDecay_BannedNoDecay.
	// 5 ViolationBadMessage (weight 1 each) = score 5 → Warning level
	for i := 0; i < 5; i++ {
		pm.RecordViolation(peerID, ViolationBadMessage)
	}

	if pm.GetLevel(peerID) != PenaltyWarning {
		t.Fatalf("expected Warning after violations, got %s", pm.GetLevel(peerID))
	}

	// Wait for decay (need 2*interval of no violations before decay kicks in)
	time.Sleep(500 * time.Millisecond)

	// After decay, score should have dropped below initial 5
	score := pm.GetScore(peerID)
	if score >= 5 {
		t.Errorf("expected score < 5 after decay, got %d", score)
	}
}

// TestPenaltyDecay_BannedNoDecay verifies the P3-P2P-02 security fix:
// peers at TempBan/LongBan/PermBan level do NOT have their scores decayed.
// This prevents an attacker from waiting out the ban period with their
// violation score being diluted, then continuing the attack cycle.
// Ban expiry is handled by the Blacklist's own TTL mechanism, not by
// penalty decay.
func TestPenaltyDecay_BannedNoDecay(t *testing.T) {
	pm := &PenaltyManager{
		entries:       make(map[PeerID]*penaltyEntry),
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
		decayInterval: 100 * time.Millisecond,
		decayAmount:   5,
	}
	bl := NewBlacklist()
	defer bl.Stop()
	pm.SetBlacklist(bl)
	pm.Start()
	defer pm.Stop()

	peerID := PeerID("test-banned-no-decay")

	// 10 ViolationBadMessage = score 10 → TempBan
	for i := 0; i < 10; i++ {
		pm.RecordViolation(peerID, ViolationBadMessage)
	}

	if pm.GetLevel(peerID) != PenaltyTempBan {
		t.Fatalf("expected TempBan after violations, got %s", pm.GetLevel(peerID))
	}

	// Wait long enough for decay to have run multiple times
	time.Sleep(500 * time.Millisecond)

	// P3-P2P-02: Banned peer's score must NOT decay — this is the security
	// property. If it decayed, an attacker could wait for score dilution
	// then resume violations without reaching PermBan.
	score := pm.GetScore(peerID)
	if score != 10 {
		t.Errorf("P3-P2P-02 REGRESSION: banned peer score decayed from 10 to %d — "+
			"banned peers must NOT have their scores decayed (security fix)", score)
	}
}

func TestPenaltyReset(t *testing.T) {
	pm := DefaultPenaltyConfig()
	bl := NewBlacklist()
	defer bl.Stop()
	pm.SetBlacklist(bl)
	defer pm.Stop()

	peerID := PeerID("test-reset-peer")

	// Build up violations to TempBan
	for i := 0; i < 10; i++ {
		pm.RecordViolation(peerID, ViolationBadMessage)
	}

	if pm.GetLevel(peerID) != PenaltyTempBan {
		t.Fatal("expected TempBan")
	}

	// Reset
	pm.Reset(peerID)

	if pm.GetLevel(peerID) != PenaltyWarning {
		t.Errorf("expected Warning after reset, got %s", pm.GetLevel(peerID))
	}

	if pm.GetScore(peerID) != 0 {
		t.Errorf("expected score 0 after reset, got %d", pm.GetScore(peerID))
	}

	if bl.IsBlacklisted(peerID) {
		t.Error("peer should NOT be blacklisted after reset")
	}
}

func TestPenaltyViolationTypes(t *testing.T) {
	pm := DefaultPenaltyConfig()
	defer pm.Stop()

	peerID := PeerID("test-types-peer")

	pm.RecordViolation(peerID, ViolationBadMessage)
	pm.RecordViolation(peerID, ViolationRateLimit)
	pm.RecordViolation(peerID, ViolationBadBlock)
	pm.RecordViolation(peerID, ViolationBadAttestation)
	pm.RecordViolation(peerID, ViolationDuplicate)
	pm.RecordViolation(peerID, ViolationTimeout)

	violations := pm.GetViolations(peerID)
	if len(violations) != 6 {
		t.Errorf("expected 6 violation types, got %d", len(violations))
	}

	expectedScore := ViolationWeight[ViolationBadMessage] +
		ViolationWeight[ViolationRateLimit] +
		ViolationWeight[ViolationBadBlock] +
		ViolationWeight[ViolationBadAttestation] +
		ViolationWeight[ViolationDuplicate] +
		ViolationWeight[ViolationTimeout]

	score := pm.GetScore(peerID)
	if score != expectedScore {
		t.Errorf("expected score %d, got %d", expectedScore, score)
	}
}

func TestPenaltyStats(t *testing.T) {
	pm := DefaultPenaltyConfig()
	bl := NewBlacklist()
	defer bl.Stop()
	pm.SetBlacklist(bl)
	defer pm.Stop()

	// Warning peer
	pm.RecordViolation("peer-warn", ViolationBadMessage)
	// TempBan peer
	for i := 0; i < 10; i++ {
		pm.RecordViolation("peer-temp", ViolationBadMessage)
	}
	// LongBan peer
	for i := 0; i < 30; i++ {
		pm.RecordViolation("peer-long", ViolationBadMessage)
	}
	// PermBan peer
	for i := 0; i < 60; i++ {
		pm.RecordViolation("peer-perm", ViolationBadMessage)
	}

	stats := pm.Stats()
	if stats["total_tracked"] != 4 {
		t.Errorf("expected 4 total, got %d", stats["total_tracked"])
	}
	if stats["warning"] != 1 {
		t.Errorf("expected 1 warning, got %d", stats["warning"])
	}
	if stats["temp_ban"] != 1 {
		t.Errorf("expected 1 temp_ban, got %d", stats["temp_ban"])
	}
	if stats["long_ban"] != 1 {
		t.Errorf("expected 1 long_ban, got %d", stats["long_ban"])
	}
	if stats["perm_ban"] != 1 {
		t.Errorf("expected 1 perm_ban, got %d", stats["perm_ban"])
	}
}

func TestPenaltyUnknownPeer(t *testing.T) {
	pm := DefaultPenaltyConfig()
	defer pm.Stop()

	unknown := PeerID("unknown-peer")

	if pm.GetLevel(unknown) != PenaltyWarning {
		t.Error("unknown peer should return Warning")
	}
	if pm.GetScore(unknown) != 0 {
		t.Error("unknown peer should return score 0")
	}
	if pm.GetViolations(unknown) != nil {
		t.Error("unknown peer should return nil violations")
	}
}
