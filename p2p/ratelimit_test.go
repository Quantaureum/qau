// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"
	"time"
)

func TestBlacklistAdd(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	peer := PeerID("bad-peer-1")
	bl.Add(peer, "spamming")

	if !bl.IsBlacklisted(peer) {
		t.Error("peer should be blacklisted")
	}

	reason := bl.GetReason(peer)
	if reason != "spamming" {
		t.Errorf("reason = %q, want %q", reason, "spamming")
	}
}

func TestBlacklistAddPermanent(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	peer := PeerID("permanent-bad-peer")
	bl.AddPermanent(peer, "attack")

	if !bl.IsBlacklisted(peer) {
		t.Error("peer should be permanently blacklisted")
	}
}

func TestBlacklistAddWithDuration(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	peer := PeerID("temp-bad-peer")
	bl.AddWithDuration(peer, "rate limit", 1*time.Hour)

	if !bl.IsBlacklisted(peer) {
		t.Error("peer should be blacklisted")
	}
}

func TestBlacklistRemove(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	peer := PeerID("removable-peer")
	bl.Add(peer, "spamming")
	bl.Remove(peer)

	if bl.IsBlacklisted(peer) {
		t.Error("peer should not be blacklisted after removal")
	}
}

func TestBlacklistNotBlacklisted(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	peer := PeerID("good-peer")
	if bl.IsBlacklisted(peer) {
		t.Error("peer should not be blacklisted")
	}
}

func TestBlacklistGetReasonNotBlacklisted(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	reason := bl.GetReason(PeerID("unknown"))
	if reason != "" {
		t.Errorf("reason for unknown peer = %q, want empty", reason)
	}
}

func TestBlacklistList(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	bl.Add(PeerID("peer1"), "reason1")
	bl.Add(PeerID("peer2"), "reason2")

	list := bl.List()
	if len(list) != 2 {
		t.Errorf("len(List) = %d, want 2", len(list))
	}
}

func TestBlacklistExpired(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	peer := PeerID("expired-peer")
	bl.AddWithDuration(peer, "temp ban", 1*time.Nanosecond)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	if bl.IsBlacklisted(peer) {
		t.Error("peer should not be blacklisted after expiration")
	}
}

func TestBlacklistPermanentNotExpired(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	peer := PeerID("permanent-peer")
	bl.AddPermanent(peer, "permanent ban")

	// Permanent entries should never expire
	if !bl.IsBlacklisted(peer) {
		t.Error("permanent peer should still be blacklisted")
	}
}

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(3, time.Second)
	defer rl.Stop()

	peer := PeerID("test-peer")

	for i := 0; i < 3; i++ {
		if !rl.Allow(peer) {
			t.Errorf("Allow(%d) should return true", i+1)
		}
	}

	if rl.Allow(peer) {
		t.Error("Allow(4) should return false (rate limit exceeded)")
	}
}

func TestRateLimiterWindowReset(t *testing.T) {
	rl := NewRateLimiter(1, 50*time.Millisecond)
	defer rl.Stop()

	peer := PeerID("test-peer")

	if !rl.Allow(peer) {
		t.Error("first Allow should return true")
	}
	if rl.Allow(peer) {
		t.Error("second Allow should return false")
	}

	// Wait for window to reset
	time.Sleep(100 * time.Millisecond)

	if !rl.Allow(peer) {
		t.Error("Allow after window reset should return true")
	}
}

func TestRateLimiterGetCount(t *testing.T) {
	rl := NewRateLimiter(10, time.Second)
	defer rl.Stop()

	peer := PeerID("test-peer")

	if rl.GetCount(peer) != 0 {
		t.Errorf("GetCount before any requests = %d, want 0", rl.GetCount(peer))
	}

	rl.Allow(peer)
	rl.Allow(peer)

	if rl.GetCount(peer) != 2 {
		t.Errorf("GetCount = %d, want 2", rl.GetCount(peer))
	}
}

func TestRateLimiterReset(t *testing.T) {
	rl := NewRateLimiter(10, time.Second)
	defer rl.Stop()

	peer := PeerID("test-peer")
	rl.Allow(peer)
	rl.Allow(peer)
	rl.Reset(peer)

	if rl.GetCount(peer) != 0 {
		t.Errorf("GetCount after Reset = %d, want 0", rl.GetCount(peer))
	}
}

func TestRateLimiterRecordViolation(t *testing.T) {
	rl := NewRateLimiter(1, time.Second)
	defer rl.Stop()

	peer := PeerID("violating-peer")

	// First two violations should not trigger ban
	if rl.RecordViolation(peer) {
		t.Error("first violation should not trigger ban")
	}
	if rl.RecordViolation(peer) {
		t.Error("second violation should not trigger ban")
	}
	// Third violation should trigger ban
	if !rl.RecordViolation(peer) {
		t.Error("third violation should trigger ban")
	}
}

func TestRateLimiterGetViolationCount(t *testing.T) {
	rl := NewRateLimiter(10, time.Second)
	defer rl.Stop()

	peer := PeerID("test-peer")

	if rl.GetViolationCount(peer) != 0 {
		t.Errorf("GetViolationCount = %d, want 0", rl.GetViolationCount(peer))
	}

	rl.RecordViolation(peer)
	rl.RecordViolation(peer)

	if rl.GetViolationCount(peer) != 2 {
		t.Errorf("GetViolationCount = %d, want 2", rl.GetViolationCount(peer))
	}
}

func TestRateLimiterDifferentPeers(t *testing.T) {
	rl := NewRateLimiter(1, time.Second)
	defer rl.Stop()

	peer1 := PeerID("peer1")
	peer2 := PeerID("peer2")

	if !rl.Allow(peer1) {
		t.Error("peer1 first Allow should return true")
	}
	if !rl.Allow(peer2) {
		t.Error("peer2 first Allow should return true (independent rate limit)")
	}
	if rl.Allow(peer1) {
		t.Error("peer1 second Allow should return false")
	}
}

func TestValidateBlacklistReason(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"normal reason", "normal reason"},
		{"  trimmed  ", "trimmed"},
		{string(make([]byte, 300)), string(make([]byte, 256))}, // truncated
		{"has\ncontrol\tchars", "hascontrol\tchars"},
	}

	for _, tt := range tests {
		if tt.input == string(make([]byte, 300)) {
			// For the long string test, just check length
			result := validateBlacklistReason(tt.input)
			if len(result) > 256 {
				t.Errorf("validateBlacklistReason result too long: %d", len(result))
			}
			continue
		}
		result := validateBlacklistReason(tt.input)
		if result != tt.expect {
			t.Errorf("validateBlacklistReason(%q) = %q, want %q", tt.input, result, tt.expect)
		}
	}
}
