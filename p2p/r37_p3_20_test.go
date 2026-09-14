// Quantaureum Node source, version 1.0.0.
// Package p2p — R37-P3-20 regression tests.
//
// R37-P3-20 (2026-07-31): PeerScorer.IsBanned compared the peer score
// against the hardcoded ScoreBanThreshold constant, silently ignoring the
// configurable banThreshold set via SetBanThreshold (R23-026). Operators
// tuning ban sensitivity at runtime saw no effect on ban decisions.
//
// The fix: IsBanned now uses GetBanThreshold() (configured value, defaulting
// to ScoreBanThreshold).
//
// These tests verify:
//  1. A runtime-configured threshold is honored by IsBanned.
//  2. The default behavior (ScoreBanThreshold) is preserved when no custom
//     threshold is set.
package p2p

import (
	"testing"
)

// TestR37_P3_20_IsBanned_UsesConfiguredThreshold verifies that IsBanned
// honors the threshold set via SetBanThreshold instead of the hardcoded
// ScoreBanThreshold constant.
func TestR37_P3_20_IsBanned_UsesConfiguredThreshold(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()

	ps.OnConnect("peer1", false)
	// Fresh peer score = DefaultScore (0.0). With the default threshold
	// (-50) the peer is not banned.
	if ps.IsBanned("peer1") {
		t.Fatal("fresh peer should not be banned under default threshold")
	}

	// Raise the threshold above the peer's current score: the peer must
	// now be considered banned. Before the fix, IsBanned still compared
	// against -50 and returned false here.
	ps.SetBanThreshold(10.0)
	if !ps.IsBanned("peer1") {
		t.Error("R37-P3-20 NOT FIXED: IsBanned ignored configured banThreshold=10 " +
			"(score 0 should be <= 10)")
	}

	// Lower it back below the score: the peer must no longer be banned.
	ps.SetBanThreshold(-100.0)
	if ps.IsBanned("peer1") {
		t.Error("R37-P3-20 NOT FIXED: IsBanned ignored configured banThreshold=-100 " +
			"(score 0 should be > -100)")
	}
}

// TestR37_P3_20_IsBanned_DefaultThresholdPreserved verifies that without a
// custom threshold, IsBanned still bans peers at or below ScoreBanThreshold.
func TestR37_P3_20_IsBanned_DefaultThresholdPreserved(t *testing.T) {
	ps := NewPeerScorer()
	defer ps.Stop()

	if ps.GetBanThreshold() != ScoreBanThreshold {
		t.Fatalf("default ban threshold = %f, want %f", ps.GetBanThreshold(), ScoreBanThreshold)
	}

	ps.OnConnect("bad-peer", false)
	// Drive the total score below ScoreBanThreshold (-50). The total is a
	// weighted sum of clamped components (quality weight 0.40, protocol
	// weight 0.20), so a single component cannot reach -50 alone:
	//   5 invalid blocks     -> quality  -100 (clamped) -> -40.0
	//   4 protocol violations -> protocol -100 (clamped) -> -20.0
	//   total = -60 <= -50.
	for i := 0; i < 5; i++ {
		ps.RecordInvalidBlock("bad-peer")
	}
	for i := 0; i < 4; i++ {
		ps.RecordProtocolViolation("bad-peer")
	}
	if !ps.IsBanned("bad-peer") {
		t.Errorf("peer with score %f should be banned under default threshold %f",
			ps.GetScore("bad-peer"), ScoreBanThreshold)
	}
}
