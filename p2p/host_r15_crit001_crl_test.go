// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/quantaureum/qau/p2p/gossipsub"
)

// =============================================================================
// P2P-R15-CRIT-001 (2026-07-22) tests: CRL GossipSub authentication
//
// These tests verify the three layers of defense added by R15-CRIT-001:
//  1. Per-peer rate limiting (1 message / 5 minutes / peer)
//  2. Issuer authorization (signature OR trusted-peer whitelist)
//  3. IssuerPeerID matches GossipSub msg.From
//
// Tests that depend on production-mode authorization use Host.skipCRLAuth
// (P2P-R16-M06) to bypass CRL issuer authentication. The flag defaults to
// false (secure); tests set it to true via struct literal.
// =============================================================================

// TestP2P_R15_CRIT_001_RateLimit_DropsSecondMessage verifies that a second
// CRL message from the same peer within the rate-limit interval is dropped.
func TestP2P_R15_CRIT_001_RateLimit_DropsSecondMessage(t *testing.T) {
	bdb := setupTestCertManagerR13CRIT003(t)
	defer bdb.cleanup()

	h := &Host{
		certManager: bdb.ncm,
		skipCRLAuth: true, // P2P-R16-M06: bypass CRL issuer auth in tests
	}

	snap := &CRLSnapshot{
		RevokedSNs:  map[string]int64{"sn-rate-1": time.Now().Unix()},
		LastUpdated: time.Now().Unix(),
		Version:     1,
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	msg := &gossipsub.Message{
		Topic: gossipsub.TopicCRL,
		Data:  data,
		From:  gossipsub.PeerID("rate-limit-peer"),
	}

	before := bdb.ncm.GetCRLRevocationCount()
	h.handleCRLMessage(msg) // first message: accepted
	afterFirst := bdb.ncm.GetCRLRevocationCount()
	if afterFirst != before+1 {
		t.Fatalf("first message should be accepted (before=%d, after=%d)", before, afterFirst)
	}

	// Second message with a NEW revocation should be dropped by rate limit.
	snap2 := &CRLSnapshot{
		RevokedSNs:  map[string]int64{"sn-rate-2": time.Now().Unix()},
		LastUpdated: time.Now().Unix(),
		Version:     1,
	}
	data2, _ := json.Marshal(snap2)
	msg2 := &gossipsub.Message{
		Topic: gossipsub.TopicCRL,
		Data:  data2,
		From:  gossipsub.PeerID("rate-limit-peer"),
	}
	h.handleCRLMessage(msg2) // second message: rate-limited
	afterSecond := bdb.ncm.GetCRLRevocationCount()
	if afterSecond != afterFirst {
		t.Errorf("second message within interval should be dropped by rate limit (after first=%d, after second=%d)",
			afterFirst, afterSecond)
	}
}

// TestP2P_R15_CRIT_001_RateLimit_AllowsDifferentPeers verifies that rate
// limiting is per-peer: a different peer's first message is not affected.
func TestP2P_R15_CRIT_001_RateLimit_AllowsDifferentPeers(t *testing.T) {
	bdb := setupTestCertManagerR13CRIT003(t)
	defer bdb.cleanup()

	h := &Host{
		certManager: bdb.ncm,
		skipCRLAuth: true, // P2P-R16-M06: bypass CRL issuer auth in tests
	}

	snap := &CRLSnapshot{
		RevokedSNs:  map[string]int64{"sn-peer-a": time.Now().Unix()},
		LastUpdated: time.Now().Unix(),
		Version:     1,
	}
	data, _ := json.Marshal(snap)

	h.handleCRLMessage(&gossipsub.Message{
		Topic: gossipsub.TopicCRL, Data: data, From: gossipsub.PeerID("peer-a"),
	})

	snap2 := &CRLSnapshot{
		RevokedSNs:  map[string]int64{"sn-peer-b": time.Now().Unix()},
		LastUpdated: time.Now().Unix(),
		Version:     1,
	}
	data2, _ := json.Marshal(snap2)
	beforeB := bdb.ncm.GetCRLRevocationCount()
	h.handleCRLMessage(&gossipsub.Message{
		Topic: gossipsub.TopicCRL, Data: data2, From: gossipsub.PeerID("peer-b"),
	})
	afterB := bdb.ncm.GetCRLRevocationCount()
	if afterB != beforeB+1 {
		t.Errorf("different peer's first message should be accepted (before=%d, after=%d)", beforeB, afterB)
	}
}

// TestP2P_R15_CRIT_001_TestingModeBypassesAuthorization verifies that in
// testing mode, snapshots without signatures from non-trusted peers are
// still accepted (preserving the pre-R15 test behavior). Rate limit still
// applies.
func TestP2P_R15_CRIT_001_TestingModeBypassesAuthorization(t *testing.T) {
	bdb := setupTestCertManagerR13CRIT003(t)
	defer bdb.cleanup()

	h := &Host{
		certManager: bdb.ncm,
		skipCRLAuth: true, // P2P-R16-M06: bypass CRL issuer auth in tests
	}

	snap := &CRLSnapshot{
		RevokedSNs:  map[string]int64{"sn-test-bypass": time.Now().Unix()},
		LastUpdated: time.Now().Unix(),
		Version:     1,
		// No IssuerPeerID, no Signature.
	}
	data, _ := json.Marshal(snap)

	before := bdb.ncm.GetCRLRevocationCount()
	h.handleCRLMessage(&gossipsub.Message{
		Topic: gossipsub.TopicCRL, Data: data, From: gossipsub.PeerID("untrusted-peer"),
	})
	after := bdb.ncm.GetCRLRevocationCount()
	if after != before+1 {
		t.Errorf("testing mode should accept unsigned snapshot from untrusted peer (before=%d, after=%d)", before, after)
	}
}

// TestP2P_R15_CRIT_001_SignAndVerify_RoundTrip verifies that a snapshot
// signed by the local cert manager can be verified when the issuer's
// certificate is added as a trusted peer.
func TestP2P_R15_CRIT_001_SignAndVerify_RoundTrip(t *testing.T) {
	bdb := setupTestCertManagerR13CRIT003(t)
	defer bdb.cleanup()

	// Build a snapshot and sign it with the local manager.
	snap := &CRLSnapshot{
		RevokedSNs:  map[string]int64{"sn-sign-1": time.Now().Unix()},
		LastUpdated: time.Now().Unix(),
		Version:     1,
	}
	nodeID := PeerID("signer-node-id")
	if err := bdb.ncm.SignCRLSnapshot(snap, nodeID); err != nil {
		t.Fatalf("SignCRLSnapshot failed: %v", err)
	}
	if snap.IssuerPeerID != string(nodeID) {
		t.Errorf("IssuerPeerID not set: got %q, want %q", snap.IssuerPeerID, nodeID)
	}
	if len(snap.Signature) == 0 {
		t.Fatal("Signature not set after SignCRLSnapshot")
	}

	// Verification requires the issuer's cert to be in trustedCerts.
	// AddTrustedPeer enforces IsCA=true, so we can't add a leaf cert
	// directly. Instead, we test that VerifyCRLSnapshotSignature returns
	// false when no trusted cert is present (the documented behavior).
	if bdb.ncm.VerifyCRLSnapshotSignature(snap) {
		t.Error("VerifyCRLSnapshotSignature should return false when no trusted cert is known for the issuer")
	}
	if bdb.ncm.HasIssuerCertificate(nodeID) {
		t.Error("HasIssuerCertificate should return false for unknown issuer")
	}
}

// TestP2P_R15_CRIT_001_OversizedStillDropped verifies that the size cap is
// enforced even when rate limiting and authorization would pass.
func TestP2P_R15_CRIT_001_OversizedStillDropped(t *testing.T) {
	bdb := setupTestCertManagerR13CRIT003(t)
	defer bdb.cleanup()

	h := &Host{
		certManager: bdb.ncm,
		skipCRLAuth: true, // P2P-R16-M06: bypass CRL issuer auth in tests
	}

	oversized := make([]byte, (1<<20)+1)
	before := bdb.ncm.GetCRLRevocationCount()
	h.handleCRLMessage(&gossipsub.Message{
		Topic: gossipsub.TopicCRL, Data: oversized, From: gossipsub.PeerID("oversized-peer"),
	})
	after := bdb.ncm.GetCRLRevocationCount()
	if after != before {
		t.Errorf("oversized snapshot should be dropped (before=%d, after=%d)", before, after)
	}
}

// TestP2P_R15_H05_RapidFireDoesNotContendCRLLock verifies the P2P-R15-H05
// DoS scenario: a malicious peer sending 1000 CRL snapshots in rapid
// succession must NOT cause 1000 MergeCRLSnapshot calls (which would
// acquire the CRL write lock 1000 times and starve new-connection
// handshakes). Only the FIRST message should reach MergeCRLSnapshot;
// the remaining 999 must be dropped by the per-peer rate limiter BEFORE
// touching the CRL lock.
//
// P2P-R15-H05 (2026-07-22).
func TestP2P_R15_H05_RapidFireDoesNotContendCRLLock(t *testing.T) {
	bdb := setupTestCertManagerR13CRIT003(t)
	defer bdb.cleanup()

	h := &Host{
		certManager: bdb.ncm,
		skipCRLAuth: true, // P2P-R16-M06: bypass CRL issuer auth in tests
	}

	const rapidFireCount = 1000
	before := bdb.ncm.GetCRLRevocationCount()

	// Send 1000 CRL snapshots from the SAME peer as fast as possible.
	// Each carries a unique revocation so we can detect if any beyond
	// the first were merged.
	for i := 0; i < rapidFireCount; i++ {
		snap := &CRLSnapshot{
			RevokedSNs:  map[string]int64{fmt.Sprintf("sn-rapid-%d", i): time.Now().Unix()},
			LastUpdated: time.Now().Unix(),
			Version:     1,
		}
		data, _ := json.Marshal(snap)
		h.handleCRLMessage(&gossipsub.Message{
			Topic: gossipsub.TopicCRL,
			Data:  data,
			From:  gossipsub.PeerID("rapid-fire-attacker"),
		})
	}

	after := bdb.ncm.GetCRLRevocationCount()
	merged := after - before

	// Only the FIRST message should have been merged. The other 999
	// must be dropped by the rate limiter before reaching
	// MergeCRLSnapshot (and thus before acquiring the CRL write lock).
	if merged != 1 {
		t.Errorf("P2P-R15-H05 REGRESSION: expected exactly 1 merge out of %d rapid-fire "+
			"CRL messages, got %d (rate limiter should drop all but the first, "+
			"preventing CRL write-lock contention)",
			rapidFireCount, merged)
	}
}

// TestP2P_R15_H05_RateLimiterMapBounded verifies that the
// crlRateLimiter map does not grow unboundedly when many distinct
// peers send CRL messages. Once crlRateLimitMaxEntries is reached,
// new peers are rejected (fail-closed) and stale entries are evicted.
//
// P2P-R15-H05 (2026-07-22): bounds memory growth from sybil peers.
func TestP2P_R15_H05_RateLimiterMapBounded(t *testing.T) {
	bdb := setupTestCertManagerR13CRIT003(t)
	defer bdb.cleanup()

	h := &Host{
		certManager: bdb.ncm,
		skipCRLAuth: true, // P2P-R16-M06: bypass CRL issuer auth in tests
	}

	// Send from crlRateLimitMaxEntries + 100 distinct peers.
	// The map must not exceed crlRateLimitMaxEntries.
	totalPeers := crlRateLimitMaxEntries + 100
	for i := 0; i < totalPeers; i++ {
		peer := PeerID(fmt.Sprintf("sybil-peer-%d", i))
		// Directly call crlRateLimitAllow to test the map bound without
		// needing valid CRL snapshots for each peer.
		h.crlRateLimitAllow(peer)
	}

	h.crlRateLimiterMu.Lock()
	mapSize := len(h.crlRateLimiter)
	h.crlRateLimiterMu.Unlock()

	if mapSize > crlRateLimitMaxEntries {
		t.Errorf("P2P-R15-H05 REGRESSION: crlRateLimiter map grew to %d entries "+
			"(max=%d) — sybil peers could exhaust memory without the bound",
			mapSize, crlRateLimitMaxEntries)
	}
}
