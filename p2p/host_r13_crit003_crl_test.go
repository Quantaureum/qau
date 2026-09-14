// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/quantaureum/qau/p2p/gossipsub"
)

// =============================================================================
// P2P-R13-CRIT-003 (2026-07-21, R12-H02 regression fix) tests:
// CRL snapshot propagation via GossipSub
//
// These tests verify that:
//  1. TopicCRL is in the allowed-topic whitelist
//  2. handleCRLMessage merges incoming snapshots into the local CRL
//  3. handleCRLMessage rejects oversized snapshots (>1MB)
//  4. handleCRLMessage drops malformed JSON
//  5. broadcastCRLSnapshot skips empty CRLs
//  6. crlBroadcastLoop exits on context cancel
// =============================================================================

// TestP2P_R13_CRIT_003_TopicCRLInWhitelist verifies that TopicCRL is in
// the GossipSub allowed-topic whitelist.
func TestP2P_R13_CRIT_003_TopicCRLInWhitelist(t *testing.T) {
	if !gossipsub.IsAllowedTopic(gossipsub.TopicCRL) {
		t.Errorf("TopicCRL %q is not in the allowed-topic whitelist", gossipsub.TopicCRL)
	}
}

// TestP2P_R13_CRIT_003_HandleCRLMessage_MergesSnapshot verifies that
// handleCRLMessage merges a valid CRL snapshot into the local CRL.
func TestP2P_R13_CRIT_003_HandleCRLMessage_MergesSnapshot(t *testing.T) {
	// Build a Host with a real certManager.
	bdb := setupTestCertManagerR13CRIT003(t)
	defer bdb.cleanup()

	h := &Host{
		certManager: bdb.ncm,
		skipCRLAuth: true, // P2P-R16-M06: bypass CRL issuer auth in tests
	}

	// Build a CRL snapshot with one revocation.
	snap := &CRLSnapshot{
		RevokedSNs:  map[string]int64{"12345": time.Now().Unix()},
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
		From:  gossipsub.PeerID("test-peer"),
	}

	before := bdb.ncm.GetCRLRevocationCount()
	h.handleCRLMessage(msg)
	after := bdb.ncm.GetCRLRevocationCount()

	if after != before+1 {
		t.Errorf("expected revocation count to increase by 1 (before=%d, after=%d)",
			before, after)
	}
}

// TestP2P_R13_CRIT_003_HandleCRLMessage_RejectsOversized verifies that
// handleCRLMessage drops snapshots larger than 1MB without merging.
func TestP2P_R13_CRIT_003_HandleCRLMessage_RejectsOversized(t *testing.T) {
	bdb := setupTestCertManagerR13CRIT003(t)
	defer bdb.cleanup()

	h := &Host{
		certManager: bdb.ncm,
		skipCRLAuth: true, // P2P-R16-M06: bypass CRL issuer auth in tests
	}

	// Build a snapshot >1MB.
	oversized := make([]byte, (1<<20)+1) // 1MB + 1 byte
	msg := &gossipsub.Message{
		Topic: gossipsub.TopicCRL,
		Data:  oversized,
		From:  gossipsub.PeerID("test-peer"),
	}

	before := bdb.ncm.GetCRLRevocationCount()
	h.handleCRLMessage(msg)
	after := bdb.ncm.GetCRLRevocationCount()

	if after != before {
		t.Errorf("oversized snapshot should be dropped, but count changed: before=%d, after=%d",
			before, after)
	}
}

// TestP2P_R13_CRIT_003_HandleCRLMessage_DropsMalformedJSON verifies
// that handleCRLMessage drops malformed JSON without error.
func TestP2P_R13_CRIT_003_HandleCRLMessage_DropsMalformedJSON(t *testing.T) {
	bdb := setupTestCertManagerR13CRIT003(t)
	defer bdb.cleanup()

	h := &Host{
		certManager: bdb.ncm,
		skipCRLAuth: true, // P2P-R16-M06: bypass CRL issuer auth in tests
	}

	msg := &gossipsub.Message{
		Topic: gossipsub.TopicCRL,
		Data:  []byte("this is not valid json"),
		From:  gossipsub.PeerID("test-peer"),
	}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("handleCRLMessage panicked on malformed JSON: %v", r)
		}
	}()
	before := bdb.ncm.GetCRLRevocationCount()
	h.handleCRLMessage(msg)
	after := bdb.ncm.GetCRLRevocationCount()

	if after != before {
		t.Errorf("malformed JSON should not change count: before=%d, after=%d",
			before, after)
	}
}

// TestP2P_R13_CRIT_003_BroadcastCRLSnapshot_SkipsEmptyCRL verifies that
// broadcastCRLSnapshot does nothing when the local CRL is empty.
func TestP2P_R13_CRIT_003_BroadcastCRLSnapshot_SkipsEmptyCRL(t *testing.T) {
	bdb := setupTestCertManagerR13CRIT003(t)
	defer bdb.cleanup()

	h := &Host{
		certManager:     bdb.ncm,
		skipCRLAuth:     true, // P2P-R16-M06: bypass CRL issuer auth in tests
		gossipSubRouter: nil,  // no router — function should early-return
	}

	// Empty CRL — should early-return without error.
	h.broadcastCRLSnapshot()
}

// TestP2P_R13_CRIT_003_CRLBroadcastLoop_ExitsOnCancel verifies that
// crlBroadcastLoop exits promptly when its context is canceled.
func TestP2P_R13_CRIT_003_CRLBroadcastLoop_ExitsOnCancel(t *testing.T) {
	bdb := setupTestCertManagerR13CRIT003(t)
	defer bdb.cleanup()

	h := &Host{
		certManager: bdb.ncm,
		skipCRLAuth: true, // P2P-R16-M06: bypass CRL issuer auth in tests
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	// Use the unexported crlBroadcastLoop. We can't easily override the
	// ticker interval (it's hardcoded to 5 minutes inside the loop),
	// so we rely on context cancellation to exit before the first ticker.
	// The startup broadcast call inside the loop is harmless: the CRL is
	// empty so broadcastCRLSnapshot is a no-op.
	go h.crlBroadcastLoop(ctx, done)

	cancel()
	select {
	case <-done:
		// Success.
	case <-time.After(2 * time.Second):
		t.Fatal("crlBroadcastLoop did not exit within 2s of context cancel")
	}
}

// =============================================================================
// Test helpers
// =============================================================================

// setupTestCertManagerR13CRIT003 creates a NodeCertificateManager in a
// temp directory for testing. Returns the manager and a cleanup function.
func setupTestCertManagerR13CRIT003(t *testing.T) struct {
	ncm     *NodeCertificateManager
	cleanup func()
} {
	t.Helper()
	dir := t.TempDir()
	certPath := dir + "/cert.pem"
	keyPath := dir + "/key.pem"
	// Use a self-signed cert with a known nodeID.
	nodeID := PeerID("test-node-id-for-r13-crit-003")
	ncm, err := NewNodeCertificateManager(certPath, keyPath, nodeID, nil, nil)
	if err != nil {
		t.Fatalf("NewNodeCertificateManager failed: %v", err)
	}
	return struct {
		ncm     *NodeCertificateManager
		cleanup func()
	}{
		ncm: ncm,
		cleanup: func() {
			ncm.Close() // P2P-R16-M08: stop CRL cleanup goroutine
			_ = ncm.SaveToFiles(certPath, keyPath)
		},
	}
}
