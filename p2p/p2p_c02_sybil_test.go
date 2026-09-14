// Quantaureum Node source, version 1.0.0.
// P2P-C-02 (R29) Sybil-resistance tests.
//
// These tests verify that the IP/subnet layer of the Blacklist correctly
// blocks attackers who rotate PeerIDs to bypass peer-only bans. The core
// invariant: after banning (peerID1, ip), a brand-new peerID2 from the
// SAME ip (or same /24 subnet) must also be rejected.
package p2p

import (
	"testing"
	"time"
)

// TestP2PC02_SybilResistance_SameIP verifies the core Sybil-defense
// invariant: banning peer1@ip also blocks peer2@ip even though peer2 was
// never seen before.
func TestP2PC02_SybilResistance_SameIP(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	attackerIP := "198.51.100.10:5678"
	peer1 := PeerID("sybil-attacker-peer-1")
	peer2 := PeerID("sybil-attacker-peer-2") // rotated PeerID, same IP

	// Ban peer1 with its IP.
	bl.AddPermanentWithIP(peer1, attackerIP, "sybil attack")

	// peer1 itself must be blocked.
	if !bl.IsBlacklisted(peer1) {
		t.Fatal("peer1 should be blacklisted (direct)")
	}

	// peer2 — a brand-new PeerID from the same IP — must ALSO be blocked.
	// This is the key Sybil-resistance check: rotating PeerIDs no longer
	// bypasses the ban.
	if !bl.IsBlacklistedWithIP(peer2, attackerIP) {
		t.Fatal("peer2 (rotated PeerID, same IP) should be blocked by IP layer — Sybil defense failed")
	}

	// A peer from a completely different IP must NOT be blocked.
	innocentPeer := PeerID("innocent-peer")
	innocentIP := "203.0.113.30:9999"
	if bl.IsBlacklistedWithIP(innocentPeer, innocentIP) {
		t.Fatal("innocent peer from different IP should NOT be blocked")
	}
}

// TestP2PC02_SybilResistance_SameSubnet verifies that banning peer1@ip
// also blocks peer2 from a different IP in the SAME /24 subnet.
func TestP2PC02_SybilResistance_SameSubnet(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	// Attacker at 10.0.0.5 — /24 subnet is 10.0.0.0/24.
	attackerIP1 := "10.0.0.5:1234"
	// Same /24, different last octet.
	attackerIP2 := "10.0.0.250:5678"

	peer1 := PeerID("subnet-attacker-1")
	peer2 := PeerID("subnet-attacker-2")

	bl.AddPermanentWithIP(peer1, attackerIP1, "subnet sweep")

	// peer2 from a different IP but same /24 must be blocked.
	if !bl.IsBlacklistedWithIP(peer2, attackerIP2) {
		t.Fatal("peer2 from same /24 subnet should be blocked — subnet defense failed")
	}

	// A peer from a different /24 must NOT be blocked.
	peer3 := PeerID("different-subnet-peer")
	differentIP := "10.0.1.5:1234"
	if bl.IsBlacklistedWithIP(peer3, differentIP) {
		t.Fatal("peer from different /24 subnet should NOT be blocked")
	}
}

// TestP2PC02_SybilResistance_IPv6_Subnet64 verifies that IPv6 addresses
// use /64 subnet blocking (RFC 6177 end-user allocation).
func TestP2PC02_SybilResistance_IPv6_Subnet64(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	// Two IPv6 addresses in the same /64 but different host suffix.
	attackerIP1 := "[2001:db8:abcd:1234::1]:1234"
	attackerIP2 := "[2001:db8:abcd:1234::ffff]:5678"

	peer1 := PeerID("v6-attacker-1")
	peer2 := PeerID("v6-attacker-2")

	bl.AddPermanentWithIP(peer1, attackerIP1, "v6 sybil")

	if !bl.IsBlacklistedWithIP(peer2, attackerIP2) {
		t.Fatal("peer2 from same /64 IPv6 subnet should be blocked")
	}

	// Different /64 must NOT be blocked.
	peer3 := PeerID("v6-different-subnet")
	differentV6 := "[2001:db8:abcd:9999::1]:1234"
	if bl.IsBlacklistedWithIP(peer3, differentV6) {
		t.Fatal("peer from different /64 IPv6 subnet should NOT be blocked")
	}
}

// TestP2PC02_EmptyIP_FallbackToPeerOnly verifies backward compatibility:
// when ip="" is passed, only the peer layer is checked (no IP/subnet).
func TestP2PC02_EmptyIP_FallbackToPeerOnly(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	peer1 := PeerID("legacy-peer")
	peer2 := PeerID("unrelated-peer")

	// Ban peer1 with empty IP — should only set the peer entry.
	bl.AddPermanentWithIP(peer1, "", "legacy ban")

	// peer1 is blocked.
	if !bl.IsBlacklisted(peer1) {
		t.Fatal("peer1 should be blocked")
	}
	// peer2 with empty IP is NOT blocked (no IP layer to catch it).
	if bl.IsBlacklistedWithIP(peer2, "") {
		t.Fatal("peer2 with empty IP should NOT be blocked — peer-only fallback")
	}
}

// TestP2PC02_TempBan_SybilResistance verifies that temporary bans
// (PenaltyTempBan / PenaltyLongBan) also trigger IP-layer blocking,
// not just permanent bans.
func TestP2PC02_TempBan_SybilResistance(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	attackerIP := "203.0.113.5:8888"
	peer1 := PeerID("temp-attacker-1")
	peer2 := PeerID("temp-attacker-2")

	// 1-hour ban with IP.
	bl.AddWithDurationWithIP(peer1, attackerIP, "rate limit abuse", 1*time.Hour)

	// peer2 from same IP must be blocked for the duration.
	if !bl.IsBlacklistedWithIP(peer2, attackerIP) {
		t.Fatal("peer2 from same IP should be blocked during temp ban")
	}
}

// TestP2PC02_PenaltyManager_IPAware verifies that PenaltyManager.RecordViolationWithIP
// escalates to an IP-aware ban when the threshold is reached.
func TestP2PC02_PenaltyManager_IPAware(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	pm := DefaultPenaltyConfig()
	pm.SetBlacklist(bl)
	defer pm.Stop()

	attackerIP := "198.51.100.1:7777"
	attackerPeer1 := PeerID("penalty-attacker-1")
	attackerPeer2 := PeerID("penalty-attacker-2")

	// ViolationRateLimit has weight 2; threshold for TempBan is 10.
	// 5 violations = 10 score → TempBan.
	for i := 0; i < 5; i++ {
		pm.RecordViolationWithIP(attackerPeer1, attackerIP, ViolationRateLimit)
	}

	// peer1 is now at TempBan level.
	if level := pm.GetLevel(attackerPeer1); level != PenaltyTempBan {
		t.Fatalf("peer1 level = %s, want %s", level, PenaltyTempBan)
	}

	// peer1 is blacklisted.
	if !bl.IsBlacklisted(attackerPeer1) {
		t.Fatal("peer1 should be blacklisted after escalation")
	}

	// A NEW peer from the same IP must ALSO be blocked — this is the
	// Sybil defense: the attacker cannot reset their penalty by rotating
	// to a new PeerID.
	if !bl.IsBlacklistedWithIP(attackerPeer2, attackerIP) {
		t.Fatal("peer2 (rotated PeerID, same IP) should be blocked after penalty escalation")
	}
}

// TestP2PC02_PenaltyManager_PermBan_IPAware verifies that PermBan level
// triggers a permanent IP-layer ban.
func TestP2PC02_PenaltyManager_PermBan_IPAware(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	pm := DefaultPenaltyConfig()
	pm.SetBlacklist(bl)
	defer pm.Stop()

	attackerIP := "203.0.113.99:5555"
	peer1 := PeerID("perm-attacker-1")
	peer2 := PeerID("perm-attacker-2")

	// ViolationBadBlock has weight 5; PermBan threshold is 60.
	// 12 violations = 60 score → PermBan.
	for i := 0; i < 12; i++ {
		pm.RecordViolationWithIP(peer1, attackerIP, ViolationBadBlock)
	}

	if level := pm.GetLevel(peer1); level != PenaltyPermBan {
		t.Fatalf("peer1 level = %s, want %s", level, PenaltyPermBan)
	}

	// peer2 from same IP is permanently blocked.
	if !bl.IsBlacklistedWithIP(peer2, attackerIP) {
		t.Fatal("peer2 from same IP should be permanently blocked after PermBan")
	}

	// Even after peer1 is manually Reset, the IP entry must persist
	// (Reset only clears the peer entry, not the IP/subnet entries).
	pm.Reset(peer1)
	if bl.IsBlacklisted(peer1) {
		t.Fatal("peer1 should be cleared after Reset")
	}
	// But peer2 from same IP is STILL blocked — IP layer is independent.
	if !bl.IsBlacklistedWithIP(peer2, attackerIP) {
		t.Fatal("peer2 from same IP should STILL be blocked after peer1 Reset — IP layer is independent")
	}
}

// TestP2PC02_RemoveWithIP clears all three layers.
func TestP2PC02_RemoveWithIP(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	peer1 := PeerID("remove-test-1")
	peer2 := PeerID("remove-test-2")
	ip := "192.0.2.1:1234"

	bl.AddPermanentWithIP(peer1, ip, "test")
	if !bl.IsBlacklistedWithIP(peer2, ip) {
		t.Fatal("peer2 should be blocked by IP before RemoveWithIP")
	}

	// RemoveWithIP clears peer + IP + subnet.
	bl.RemoveWithIP(peer1, ip)
	if bl.IsBlacklisted(peer1) {
		t.Fatal("peer1 should be cleared after RemoveWithIP")
	}
	if bl.IsBlacklistedWithIP(peer2, ip) {
		t.Fatal("peer2 should NOT be blocked after RemoveWithIP cleared IP layer")
	}
}

// TestP2PC02_BareIP_Input verifies that bare IPs (no port) are handled.
func TestP2PC02_BareIP_Input(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	peer1 := PeerID("bare-ip-1")
	peer2 := PeerID("bare-ip-2")

	// Ban with bare IP (no :port).
	bl.AddPermanentWithIP(peer1, "198.51.100.10", "bare ip test")

	if !bl.IsBlacklisted(peer1) {
		t.Fatal("peer1 should be blocked")
	}
	// peer2 with the bare IP must also be blocked.
	if !bl.IsBlacklistedWithIP(peer2, "198.51.100.10") {
		t.Fatal("peer2 with bare IP should be blocked")
	}
	// peer2 with host:port form of same IP must also be blocked.
	if !bl.IsBlacklistedWithIP(peer2, "198.51.100.10:9999") {
		t.Fatal("peer2 with host:port form should be blocked (IP normalization)")
	}
}

// TestP2PC02_IPNormalization verifies that the same IP in different
// string forms maps to the same blacklist entry.
func TestP2PC02_IPNormalization(t *testing.T) {
	bl := NewBlacklist()
	defer bl.Stop()

	peer1 := PeerID("norm-1")
	peer2 := PeerID("norm-2")

	// Ban with "198.51.100.10:5678".
	bl.AddPermanentWithIP(peer1, "198.51.100.10:5678", "norm test")

	// peer2 with "198.51.100.10:9999" (different port, same IP) must be blocked.
	if !bl.IsBlacklistedWithIP(peer2, "198.51.100.10:9999") {
		t.Fatal("peer2 with same IP different port should be blocked")
	}
	// peer2 with bare "198.51.100.10" must be blocked.
	if !bl.IsBlacklistedWithIP(peer2, "198.51.100.10") {
		t.Fatal("peer2 with bare IP should be blocked")
	}
}
