// Quantaureum Node source, version 1.0.0.
package core

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// =============================================================================
// P2-5: 3-Node Integration Test — ProcessBlobsForBlock → DAS Sampling → Aggregate Attestation
//
// This file tests the full DA (Data Availability) pipeline across a simulated
// 3-node network using mock P2P bridges. Each node has its own BlobStorage,
// DASClient, BlobNetworkManager, DAAttestationCollector, and DankshardingEngine.
//
// The mock P2P layer routes each node's peerGetter to the target node's
// BlobNetworkManager.ServeCellRequest, enabling cross-node cell fetching
// without a real P2P stack. Real Dilithium3 signatures are used throughout.
//
// Test coverage:
//   1. Happy path (3 nodes): all available → aggregate sufficient
//   2. One node fails (3 nodes): 2/3 = 0.6666 < 0.6667 → NOT sufficient
//   3. Two nodes fail (3 nodes): 1/3 → NOT sufficient
//   4. Concurrent attestations → no race/panic
//   5. Multiple blobs per block → sampling works
//   6. Multiple slots → independent attestations
//   7. Aggregate encoding round-trip
//   8. Sample cache reuse (BuildDAAttestation twice → Sample once)
//   9. Network partition → isolated node attests unavailable
//  10. Cross-node cell serving (explicit peer-to-peer fetch)
//  11. 4-node: 3/4 = 0.75 >= 0.6667 → sufficient (1 node fails)
//  12. 4-node: 2/4 = 0.5 < 0.6667 → NOT sufficient (2 nodes fail)
// =============================================================================

// testNode holds all per-node DA components for integration testing.
type testNode struct {
	index        int
	peerID       string
	storage      *encoding.BlobStorage
	dasClient    *encoding.DASClient
	netMgr       *encoding.BlobNetworkManager
	committeeMgr *consensus.DACommitteeManager
	collector    *consensus.DAAttestationCollector
	engine       *DankshardingEngine
	keypair      *crypto.KeyPair
	validator    *consensus.ValidatorInfo
}

// makeIntegrationValidators creates n validators with real Dilithium3 keypairs.
// The public key's last 20 bytes form the address (same convention as
// da_attestation_verifier_test.go).
func makeIntegrationValidators(t *testing.T, n int) ([]*consensus.ValidatorInfo, []*crypto.KeyPair) {
	t.Helper()
	validators := make([]*consensus.ValidatorInfo, n)
	keypairs := make([]*crypto.KeyPair, n)
	for i := 0; i < n; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair[%d] failed: %v", i, err)
		}
		keypairs[i] = kp
		pubBytes := kp.Public.Bytes()
		var addr types.Address
		copy(addr[:], pubBytes[len(pubBytes)-len(addr):])
		validators[i] = &consensus.ValidatorInfo{
			Address:   addr,
			PublicKey: kp.Public,
			Active:    true,
		}
	}
	return validators, keypairs
}

// newTestNode creates a fully wired test node with real Dilithium3 crypto.
// The committee manager is configured with Enabled=false (testnet mode) so
// all validators are accepted without committee membership checks. This
// focuses the test on the multi-node DAS sampling flow, not committee selection.
func newTestNode(t *testing.T, index int, validators []*consensus.ValidatorInfo, keypairs []*crypto.KeyPair) *testNode {
	t.Helper()

	storage := encoding.NewBlobStorage()

	// Fast DAS config for testing: 1 retry, 500ms timeout.
	dasConfig := encoding.DefaultDASConfig()
	dasConfig.MaxRetries = 1
	dasConfig.QueryTimeoutMs = 500
	// R40-P1-03 (2026-08-03): these integration tests exercise the
	// Danksharding NETWORK / ATTESTATION mechanics (sampling reachability,
	// aggregation thresholds, partition healing, reorg), NOT the
	// cryptographic authenticity of cell commitments — they do not wire
	// a real FRI data provider, so without `AllowHashStubFallback: true`
	// the R40-P1-03 hardening would reject every sampled cell and the
	// tests would collapse to "no sample ever succeeds". Opt into the
	// legacy permissive behavior explicitly here; production nodes MUST
	// leave this flag false so the strict FRI-or-reject enforcement
	// guards DAS cryptographic authenticity.
	dasConfig.AllowHashStubFallback = true
	dasClient := encoding.NewDASClient(dasConfig)

	netMgr := encoding.NewBlobNetworkManager(storage, dasClient)

	// Committee manager: disabled (testnet mode) so all validators are accepted.
	committeeMgr := consensus.NewDACommitteeManager(
		func() []*consensus.ValidatorInfo { return validators },
		func(epoch uint64) types.Hash { return types.Hash{} },
	)
	committeeMgr.SetConfig(consensus.DACommitteeConfig{Enabled: false, Size: len(validators)})

	// Real Dilithium3 signature verifier.
	verifier := consensus.NewDAAttestationVerifier(
		func() []*consensus.ValidatorInfo { return validators },
		committeeMgr,
	)

	collector := consensus.NewDAAttestationCollector()
	collector.SetCommitteeSize(len(validators))
	collector.SetAttestationVerifier(verifier)

	engine := NewDankshardingEngine(
		storage, dasClient, netMgr, committeeMgr, collector, nil, nil,
		DankshardingConfig{Enabled: true},
	)

	return &testNode{
		index:        index,
		peerID:       fmt.Sprintf("node%d", index),
		storage:      storage,
		dasClient:    dasClient,
		netMgr:       netMgr,
		committeeMgr: committeeMgr,
		collector:    collector,
		engine:       engine,
		keypair:      keypairs[index],
		validator:    validators[index],
	}
}

// wireMockP2P connects all nodes' BlobNetworkManagers via mock P2P.
// Each node's peerGetter routes to the target node's ServeCellRequest.
// Each node's peerList returns all OTHER nodes (not self).
//
// IMPORTANT: Must be called BEFORE engine.Start() because Start() wires
// the P2P bridge functions to the BlobNetworkManager.
func wireMockP2P(nodes []*testNode) {
	nodeByPeerID := make(map[string]*testNode)
	for _, n := range nodes {
		nodeByPeerID[n.peerID] = n
	}

	for _, n := range nodes {
		node := n // capture for closure
		peerGetter := func(peerID string, msgType uint8, data []byte) ([]byte, error) {
			target, ok := nodeByPeerID[peerID]
			if !ok {
				return nil, fmt.Errorf("unknown peer: %s", peerID)
			}
			return target.netMgr.ServeCellRequest(data)
		}
		peerList := func() []string {
			peers := make([]string, 0, len(nodes)-1)
			for _, other := range nodes {
				if other.peerID != node.peerID {
					peers = append(peers, other.peerID)
				}
			}
			return peers
		}
		node.engine.SetP2PBridge(peerGetter, peerList)
	}
}

// startAllNodes starts all engines (wires cellGetter + P2P to network manager).
func startAllNodes(t *testing.T, nodes []*testNode) {
	t.Helper()
	for _, node := range nodes {
		if err := node.engine.Start(); err != nil {
			t.Fatalf("node%d Start failed: %v", node.index, err)
		}
	}
}

// stopAllNodes shuts down all engines. Uses Shutdown() (not Stop()) to
// cancel DASClient sampling goroutines that would otherwise leak across
// tests and starve the scheduler under heavy parallel execution.
// PRE-FIX (2026-07-17).
func stopAllNodes(nodes []*testNode) {
	for _, node := range nodes {
		node.engine.Shutdown()
	}
}

// makeTestBlob creates a deterministic blob for testing.
func makeTestBlob(seed byte) encoding.Blob {
	var blob encoding.Blob
	for i := range blob {
		blob[i] = byte(i%256) ^ seed
	}
	return blob
}

// signAndSubmit signs the attestation with the node's private key and submits
// it to the specified collector. The attestation is modified in-place.
func signAndSubmit(t *testing.T, node *testNode, collector *consensus.DAAttestationCollector, att *encoding.DASAttestation) {
	t.Helper()
	hash := att.Hash()
	sig, err := crypto.Sign(node.keypair.Private, hash[:])
	if err != nil {
		t.Fatalf("node%d crypto.Sign failed: %v", node.index, err)
	}
	if len(sig) != crypto.Dilithium3SignatureSize {
		t.Fatalf("node%d signature size mismatch: got %d, want %d", node.index, len(sig), crypto.Dilithium3SignatureSize)
	}
	att.Signature = sig
	if err := collector.SubmitAttestation(att); err != nil {
		t.Fatalf("node%d SubmitAttestation failed: %v", node.index, err)
	}
}

// NOTE: commitmentsToHashes was removed in DA-R7-04 (2026-07-17).
// BuildAggregateAttestation now accepts []encoding.KZGCommitment directly,
// eliminating the 48→32 byte truncation that this helper performed.
// All callers pass `commitments` directly.

// processBlobsOnAllNodes has all nodes process the same blobs. In a real
// network, all nodes receive and store blobs from gossiped blocks.
//
// R37-P3-34 FIX (2026-07-31): ExtendBlobs2D costs ~2.3s per blob per call
// (O(n²) GF(2^16) Lagrange extension, see encoding benchmarks). Running the
// full ProcessBlobsForBlock on EVERY node multiplied that cost by the node
// count (3-8x per test, ~30 call sites), pushing the full core suite past
// the 10-minute package alarm on loaded machines — the alarm then killed
// whichever DA test happened to be running, making the suite unstable and
// masking regressions (R37 audit P3-34). ExtendBlobs2D is deterministic:
// every node derives the IDENTICAL matrix from the same blobs. So run the
// full production path on node 0 (still exercising ProcessBlobsForBlock)
// and replicate the resulting matrix into the other nodes' stores. Each
// node still serves cells from its own local storage; sampling, FRI, and
// attestation behavior are unchanged.
func processBlobsOnAllNodes(t *testing.T, nodes []*testNode, slot uint64, blobs []encoding.Blob) []encoding.KZGCommitment {
	t.Helper()
	matrix, commitments, err := nodes[0].engine.ProcessBlobsForBlock(slot, blobs)
	if err != nil {
		t.Fatalf("node%d ProcessBlobsForBlock failed: %v", nodes[0].index, err)
	}
	for _, node := range nodes[1:] {
		for i := range blobs {
			if err := node.storage.StoreMatrix(slot, i, *matrix, commitments); err != nil {
				t.Fatalf("node%d StoreMatrix failed: %v", node.index, err)
			}
		}
	}
	return commitments
}

// =============================================================================
// Test 1: Happy Path — All 3 nodes available → aggregate sufficient
// =============================================================================

func TestP2_5_ThreeNode_HappyPath(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 3)
	nodes := make([]*testNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x42)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Each node builds, signs, and submits its attestation to Node 0's collector.
	for _, node := range nodes {
		att, err := node.engine.BuildDAAttestation(1, 1, commitments, node.index)
		if err != nil {
			t.Fatalf("node%d BuildDAAttestation failed: %v", node.index, err)
		}
		if !att.Available {
			t.Errorf("node%d expected available=true, got false (confidence=%.4f)", node.index, att.Confidence)
		}
		signAndSubmit(t, node, nodes[0].collector, att)
	}

	// Build aggregate attestation.
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg == nil {
		t.Fatal("BuildAggregateAttestation returned nil")
	}
	if agg.AvailableCount != 3 {
		t.Errorf("expected AvailableCount=3, got %d", agg.AvailableCount)
	}
	if agg.TotalCount != 3 {
		t.Errorf("expected TotalCount=3, got %d", agg.TotalCount)
	}
	if !agg.IsSufficient() {
		t.Error("expected IsSufficient=true for 3/3 available")
	}
	if agg.ThresholdAggregated {
		t.Error("expected ThresholdAggregated=false (no QTD signer configured)")
	}
	if len(agg.Signatures) != 3 {
		t.Errorf("expected 3 signatures in transition mode, got %d", len(agg.Signatures))
	}
}

// =============================================================================
// Test 2: One node sampling fails → 2/3 NOT sufficient (2/3=0.6666 < 0.6667)
//
// The DA threshold is 0.6667 (strict >=). With 3 nodes, 2/3 = 0.6666... which
// is LESS than 0.6667, so the aggregate is NOT sufficient and
// BuildAggregateAttestation returns nil per P1-7. This test verifies:
//   - Node 2 attests unavailable (network partition)
//   - Nodes 0, 1 attest available
//   - 3 attestations collected (2 available + 1 unavailable)
//   - BuildAggregateAttestation returns nil (insufficient)
// =============================================================================

func TestP2_5_ThreeNode_OneNodeSamplingFails(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 3)
	nodes := make([]*testNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x55)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Simulate network partition for Node 2: override its peerGetter to always fail.
	nodes[2].netMgr.SetPeerGetter(func(peerID string, msgType uint8, data []byte) ([]byte, error) {
		return nil, errors.New("network partition")
	})

	// All nodes build attestations.
	availableCount := 0
	for _, node := range nodes {
		att, err := node.engine.BuildDAAttestation(1, 1, commitments, node.index)
		if err != nil {
			t.Fatalf("node%d BuildDAAttestation failed: %v", node.index, err)
		}
		// Node 2 should attest unavailable due to network partition.
		if node.index == 2 && att.Available {
			t.Errorf("node2 expected available=false (network partition), got true")
		}
		if att.Available {
			availableCount++
		}
		signAndSubmit(t, node, nodes[0].collector, att)
	}

	if availableCount != 2 {
		t.Errorf("expected 2 available attestations, got %d", availableCount)
	}

	// Verify 3 attestations were collected.
	atts := nodes[0].collector.GetAttestations(1)
	if len(atts) != 3 {
		t.Errorf("expected 3 attestations collected, got %d", len(atts))
	}

	// 2/3 = 0.6666... < 0.6667 (strict threshold) → NOT sufficient.
	// BuildAggregateAttestation returns nil per P1-7.
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg != nil {
		t.Errorf("expected nil aggregate (2/3 < 0.6667 not sufficient), got AvailableCount=%d TotalCount=%d",
			agg.AvailableCount, agg.TotalCount)
	}
}

// =============================================================================
// Test 3: Two nodes sampling fail → 1/3 not sufficient (< 0.6667)
// =============================================================================

func TestP2_5_ThreeNode_TwoNodesSamplingFail(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 3)
	nodes := make([]*testNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x77)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Simulate network partition for Nodes 1 and 2.
	for _, idx := range []int{1, 2} {
		nodes[idx].netMgr.SetPeerGetter(func(peerID string, msgType uint8, data []byte) ([]byte, error) {
			return nil, errors.New("network partition")
		})
	}

	// All nodes build attestations.
	availableCount := 0
	for _, node := range nodes {
		att, err := node.engine.BuildDAAttestation(1, 1, commitments, node.index)
		if err != nil {
			t.Fatalf("node%d BuildDAAttestation failed: %v", node.index, err)
		}
		if node.index != 0 && att.Available {
			t.Errorf("node%d expected available=false (network partition), got true", node.index)
		}
		if att.Available {
			availableCount++
		}
		signAndSubmit(t, node, nodes[0].collector, att)
	}

	if availableCount != 1 {
		t.Errorf("expected 1 available attestation, got %d", availableCount)
	}

	atts := nodes[0].collector.GetAttestations(1)
	if len(atts) != 3 {
		t.Errorf("expected 3 attestations collected, got %d", len(atts))
	}

	// 1/3 = 0.333 < 0.6667 → NOT sufficient → BuildAggregateAttestation returns nil.
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg != nil {
		t.Errorf("expected nil aggregate (1/3 < 0.6667 not sufficient), got AvailableCount=%d TotalCount=%d",
			agg.AvailableCount, agg.TotalCount)
	}
}

// =============================================================================
// Test 4: Concurrent attestations → no race/panic
// =============================================================================

func TestP2_5_ThreeNode_ConcurrentAttestations(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 3)
	nodes := make([]*testNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x88)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// All nodes build attestations concurrently and submit to Node 0's collector.
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []error

	for _, node := range nodes {
		wg.Add(1)
		go func(n *testNode) {
			defer wg.Done()
			att, err := n.engine.BuildDAAttestation(1, 1, commitments, n.index)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("node%d BuildDAAttestation: %w", n.index, err))
				mu.Unlock()
				return
			}
			hash := att.Hash()
			sig, err := crypto.Sign(n.keypair.Private, hash[:])
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("node%d Sign: %w", n.index, err))
				mu.Unlock()
				return
			}
			att.Signature = sig
			if err := nodes[0].collector.SubmitAttestation(att); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("node%d Submit: %w", n.index, err))
				mu.Unlock()
				return
			}
		}(node)
	}
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("concurrent attestation errors: %v", errs)
	}

	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg == nil {
		t.Fatal("BuildAggregateAttestation returned nil")
	}
	if agg.AvailableCount != 3 {
		t.Errorf("expected AvailableCount=3, got %d", agg.AvailableCount)
	}
	if !agg.IsSufficient() {
		t.Error("expected IsSufficient=true for 3/3 concurrent available")
	}
}

// =============================================================================
// Test 5: Multiple blobs per block → sampling works for all blobs
// =============================================================================

func TestP2_5_ThreeNode_MultipleBlobs(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 3)
	nodes := make([]*testNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	// 3 blobs per block
	blobs := []encoding.Blob{
		makeTestBlob(0x01),
		makeTestBlob(0x02),
		makeTestBlob(0x03),
	}
	commitments := processBlobsOnAllNodes(t, nodes, 1, blobs)

	if len(commitments) != 3 {
		t.Fatalf("expected 3 commitments, got %d", len(commitments))
	}

	// All nodes build attestations for the 3-blob block.
	for _, node := range nodes {
		att, err := node.engine.BuildDAAttestation(1, 3, commitments, node.index)
		if err != nil {
			t.Fatalf("node%d BuildDAAttestation failed: %v", node.index, err)
		}
		if !att.Available {
			t.Errorf("node%d expected available=true for 3 blobs, got false", node.index)
		}
		signAndSubmit(t, node, nodes[0].collector, att)
	}

	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg == nil {
		t.Fatal("BuildAggregateAttestation returned nil")
	}
	if !agg.IsSufficient() {
		t.Error("expected IsSufficient=true for 3/3 with multiple blobs")
	}
}

// =============================================================================
// Test 6: Multiple slots → independent attestations, no cross-slot contamination
// =============================================================================

func TestP2_5_ThreeNode_MultipleSlots(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 3)
	nodes := make([]*testNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	// Process blobs for slots 1, 2, 3
	for slot := uint64(1); slot <= 3; slot++ {
		blob := makeTestBlob(byte(slot))
		commitments := processBlobsOnAllNodes(t, nodes, slot, []encoding.Blob{blob})

		for _, node := range nodes {
			att, err := node.engine.BuildDAAttestation(slot, 1, commitments, node.index)
			if err != nil {
				t.Fatalf("node%d BuildDAAttestation slot %d failed: %v", node.index, slot, err)
			}
			if !att.Available {
				t.Errorf("node%d slot %d expected available=true, got false", node.index, slot)
			}
			if att.Slot != slot {
				t.Errorf("expected att.Slot=%d, got %d", slot, att.Slot)
			}
			signAndSubmit(t, node, nodes[0].collector, att)
		}

		agg := nodes[0].engine.BuildAggregateAttestation(slot, commitments)
		if agg == nil {
			t.Fatalf("slot %d: BuildAggregateAttestation returned nil", slot)
		}
		if agg.Slot != slot {
			t.Errorf("expected agg.Slot=%d, got %d", slot, agg.Slot)
		}
		if !agg.IsSufficient() {
			t.Errorf("slot %d: expected IsSufficient=true", slot)
		}
	}

	// Verify attestations for each slot are independent
	for slot := uint64(1); slot <= 3; slot++ {
		atts := nodes[0].collector.GetAttestations(slot)
		if len(atts) != 3 {
			t.Errorf("slot %d: expected 3 attestations, got %d", slot, len(atts))
		}
		for _, att := range atts {
			if att.Slot != slot {
				t.Errorf("slot %d: found attestation with wrong slot %d", slot, att.Slot)
			}
		}
	}
}

// =============================================================================
// Test 7: Aggregate encoding round-trip
// =============================================================================

func TestP2_5_ThreeNode_AggregateEncodingRoundTrip(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 3)
	nodes := make([]*testNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0xAA)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	for _, node := range nodes {
		att, err := node.engine.BuildDAAttestation(1, 1, commitments, node.index)
		if err != nil {
			t.Fatalf("node%d BuildDAAttestation failed: %v", node.index, err)
		}
		signAndSubmit(t, node, nodes[0].collector, att)
	}

	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg == nil {
		t.Fatal("BuildAggregateAttestation returned nil")
	}

	// Encode → Decode → verify fields match
	encoded := agg.Encode()
	if len(encoded) == 0 {
		t.Fatal("Encode() returned empty data")
	}

	decoded, err := encoding.DecodeDASAggregateAttestation(encoded)
	if err != nil {
		t.Fatalf("DecodeDASAggregateAttestation failed: %v", err)
	}

	if decoded.Slot != agg.Slot {
		t.Errorf("Slot mismatch: got %d, want %d", decoded.Slot, agg.Slot)
	}
	if decoded.AvailableCount != agg.AvailableCount {
		t.Errorf("AvailableCount mismatch: got %d, want %d", decoded.AvailableCount, agg.AvailableCount)
	}
	if decoded.TotalCount != agg.TotalCount {
		t.Errorf("TotalCount mismatch: got %d, want %d", decoded.TotalCount, agg.TotalCount)
	}
	if len(decoded.Signatures) != len(agg.Signatures) {
		t.Errorf("Signatures length mismatch: got %d, want %d", len(decoded.Signatures), len(agg.Signatures))
	}
	if decoded.ThresholdAggregated != agg.ThresholdAggregated {
		t.Errorf("ThresholdAggregated mismatch: got %v, want %v", decoded.ThresholdAggregated, agg.ThresholdAggregated)
	}
	if !decoded.IsSufficient() {
		t.Error("decoded aggregate should still be sufficient")
	}
}

// =============================================================================
// Test 8: Sample cache reuse — BuildDAAttestation twice → Sample called once
// =============================================================================

func TestP2_5_ThreeNode_SampleCacheReuse(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 3)
	nodes := make([]*testNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0xBB)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// First call triggers DAS sampling.
	att1, err := nodes[0].engine.BuildDAAttestation(1, 1, commitments, 0)
	if err != nil {
		t.Fatalf("first BuildDAAttestation failed: %v", err)
	}

	// Get sample stats after first call.
	session := nodes[0].dasClient.GetSession(1)
	if session == nil {
		t.Fatal("expected DAS session after BuildDAAttestation")
	}
	total1, success1 := session.GetSampleStats()
	if total1 == 0 {
		t.Error("expected TotalSamples > 0 after first BuildDAAttestation")
	}

	// Second call should return cached result (no new sampling).
	att2, err := nodes[0].engine.BuildDAAttestation(1, 1, commitments, 0)
	if err != nil {
		t.Fatalf("second BuildDAAttestation failed: %v", err)
	}

	total2, success2 := session.GetSampleStats()
	if total2 != total1 {
		t.Errorf("expected TotalSamples unchanged (cache reuse), got %d → %d", total1, total2)
	}
	if success2 != success1 {
		t.Errorf("expected SuccessSamples unchanged (cache reuse), got %d → %d", success1, success2)
	}

	// Both attestations should have the same Available/Confidence.
	if att1.Available != att2.Available {
		t.Errorf("Available mismatch: %v → %v", att1.Available, att2.Available)
	}
	if att1.Confidence != att2.Confidence {
		t.Errorf("Confidence mismatch: %f → %f", att1.Confidence, att2.Confidence)
	}
	if att1.SampleCount != att2.SampleCount {
		t.Errorf("SampleCount mismatch: %d → %d", att1.SampleCount, att2.SampleCount)
	}
}

// =============================================================================
// Test 9: Network partition — isolated node attests unavailable
// =============================================================================

func TestP2_5_ThreeNode_NetworkPartition(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 3)
	nodes := make([]*testNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0xCC)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Isolate Node 1: its peerGetter always fails AND its peerList returns empty.
	nodes[1].netMgr.SetPeerGetter(func(peerID string, msgType uint8, data []byte) ([]byte, error) {
		return nil, errors.New("network partition: no peers reachable")
	})
	nodes[1].netMgr.SetPeerList(func() []string { return nil })

	// Node 1 should fail to sample and attest unavailable.
	att1, err := nodes[1].engine.BuildDAAttestation(1, 1, commitments, 1)
	if err != nil {
		t.Fatalf("node1 BuildDAAttestation failed: %v", err)
	}
	if att1.Available {
		t.Error("node1 expected available=false (network partition), got true")
	}

	// Nodes 0 and 2 should still be able to sample.
	for _, idx := range []int{0, 2} {
		att, err := nodes[idx].engine.BuildDAAttestation(1, 1, commitments, idx)
		if err != nil {
			t.Fatalf("node%d BuildDAAttestation failed: %v", idx, err)
		}
		if !att.Available {
			t.Errorf("node%d expected available=true, got false", idx)
		}
	}

	// Submit all attestations to Node 0's collector.
	// att1 was built by node1, so sign with node1's keypair.
	signAndSubmit(t, nodes[1], nodes[0].collector, att1)
	// Rebuild for nodes 0 and 2 (their attestations were built above but not signed).
	// BuildDAAttestation returns cached result via sync.Once, so this is safe.
	att0, _ := nodes[0].engine.BuildDAAttestation(1, 1, commitments, 0)
	signAndSubmit(t, nodes[0], nodes[0].collector, att0)
	att2, _ := nodes[2].engine.BuildDAAttestation(1, 1, commitments, 2)
	signAndSubmit(t, nodes[2], nodes[0].collector, att2)

	// Verify 3 attestations collected (2 available + 1 unavailable).
	atts := nodes[0].collector.GetAttestations(1)
	if len(atts) != 3 {
		t.Errorf("expected 3 attestations collected, got %d", len(atts))
	}

	// 2/3 = 0.6666... < 0.6667 → NOT sufficient → BuildAggregateAttestation returns nil.
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg != nil {
		t.Errorf("expected nil aggregate (2/3 < 0.6667 not sufficient), got AvailableCount=%d TotalCount=%d",
			agg.AvailableCount, agg.TotalCount)
	}
}

// =============================================================================
// Test 10: Cross-node cell serving — explicit peer-to-peer fetch
// =============================================================================

func TestP2_5_ThreeNode_CrossNodeCellServing(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 3)
	nodes := make([]*testNode, 3)
	for i := 0; i < 3; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	// Only Node 0 processes and stores the blob.
	blob := makeTestBlob(0xDD)
	_, commitments, err := nodes[0].engine.ProcessBlobsForBlock(1, []encoding.Blob{blob})
	if err != nil {
		t.Fatalf("node0 ProcessBlobsForBlock failed: %v", err)
	}

	// Override Nodes 1 and 2 peerList to only include Node 0 (the only node
	// with the blob data). This avoids flakiness from random peer selection
	// picking Node 2 (which doesn't have the data).
	nodes[1].netMgr.SetPeerList(func() []string { return []string{"node0"} })
	nodes[2].netMgr.SetPeerList(func() []string { return []string{"node0"} })

	// Verify Node 1 can fetch cells from Node 0 via the mock P2P bridge.
	// Node 1's peerGetter routes to Node 0's ServeCellRequest (wired by wireMockP2P).
	resp, err := nodes[1].netMgr.RequestCell(1, 0, 0, 0)
	if err != nil {
		t.Fatalf("node1 RequestCell from node0 failed: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response from RequestCell")
	}
	if resp.Slot != 1 {
		t.Errorf("expected resp.Slot=1, got %d", resp.Slot)
	}
	if resp.BlobIndex != 0 {
		t.Errorf("expected resp.BlobIndex=0, got %d", resp.BlobIndex)
	}

	// Verify the cell proof is valid against the commitment.
	if len(commitments) > 0 {
		valid := encoding.VerifyCellProof(resp.Cell, commitments[0], resp.Proof, resp.CellRow, resp.CellCol)
		if !valid {
			t.Error("cell proof verification failed for cross-node fetched cell")
		}
	}

	// Verify Node 2 can also fetch cells from Node 0.
	resp2, err := nodes[2].netMgr.RequestCell(1, 0, 1, 1)
	if err != nil {
		t.Fatalf("node2 RequestCell from node0 failed: %v", err)
	}
	if resp2 == nil {
		t.Fatal("expected non-nil response from node2 RequestCell")
	}
	if resp2.Slot != 1 {
		t.Errorf("expected resp2.Slot=1, got %d", resp2.Slot)
	}
}

// =============================================================================
// Test 11: 4-Node network — 3/4 sufficient (0.75 >= 0.6667), 1 node fails
//
// With 3 nodes, 2/3 = 0.6666 < 0.6667 is NOT sufficient (Test 2). With 4
// nodes, 3/4 = 0.75 >= 0.6667 IS sufficient. This test demonstrates the
// threshold boundary: one node fails but the aggregate is still valid.
// =============================================================================

func TestP2_5_FourNode_ThreeOfFourSufficient(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0xEE)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Simulate network partition for Node 3.
	nodes[3].netMgr.SetPeerGetter(func(peerID string, msgType uint8, data []byte) ([]byte, error) {
		return nil, errors.New("network partition")
	})

	// All nodes build attestations.
	availableCount := 0
	for _, node := range nodes {
		att, err := node.engine.BuildDAAttestation(1, 1, commitments, node.index)
		if err != nil {
			t.Fatalf("node%d BuildDAAttestation failed: %v", node.index, err)
		}
		if node.index == 3 && att.Available {
			t.Errorf("node3 expected available=false (network partition), got true")
		}
		if att.Available {
			availableCount++
		}
		signAndSubmit(t, node, nodes[0].collector, att)
	}

	if availableCount != 3 {
		t.Errorf("expected 3 available attestations, got %d", availableCount)
	}

	// 3/4 = 0.75 >= 0.6667 → SUFFICIENT.
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg == nil {
		t.Fatal("expected non-nil aggregate (3/4 = 0.75 >= 0.6667 sufficient)")
	}
	if agg.AvailableCount != 3 {
		t.Errorf("expected AvailableCount=3, got %d", agg.AvailableCount)
	}
	if agg.TotalCount != 4 {
		t.Errorf("expected TotalCount=4, got %d", agg.TotalCount)
	}
	if !agg.IsSufficient() {
		t.Error("expected IsSufficient=true for 3/4 available (0.75 >= 0.6667)")
	}
	if len(agg.Signatures) != 4 {
		t.Errorf("expected 4 signatures in transition mode, got %d", len(agg.Signatures))
	}
}

// =============================================================================
// Test 12: 4-Node network — 2/4 NOT sufficient (0.5 < 0.6667), 2 nodes fail
// =============================================================================

func TestP2_5_FourNode_TwoOfFourNotSufficient(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0xFF)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Simulate network partition for Nodes 2 and 3.
	for _, idx := range []int{2, 3} {
		nodes[idx].netMgr.SetPeerGetter(func(peerID string, msgType uint8, data []byte) ([]byte, error) {
			return nil, errors.New("network partition")
		})
	}

	availableCount := 0
	for _, node := range nodes {
		att, err := node.engine.BuildDAAttestation(1, 1, commitments, node.index)
		if err != nil {
			t.Fatalf("node%d BuildDAAttestation failed: %v", node.index, err)
		}
		if att.Available {
			availableCount++
		}
		signAndSubmit(t, node, nodes[0].collector, att)
	}

	if availableCount != 2 {
		t.Errorf("expected 2 available attestations, got %d", availableCount)
	}

	// 2/4 = 0.5 < 0.6667 → NOT sufficient.
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg != nil {
		t.Errorf("expected nil aggregate (2/4 = 0.5 < 0.6667 not sufficient), got AvailableCount=%d TotalCount=%d",
			agg.AvailableCount, agg.TotalCount)
	}
}

// =============================================================================
// R7 P0-6 (DA-R7-01): FRI Integration Test — UseFRI=true calls FRIDACommitBlob
//
// This test verifies that when DankshardingConfig.UseFRI=true:
//  1. ProcessBlobsForBlock calls FRIDACommitBlob and caches FRIDABlobData
//  2. GetFRIBlobData returns the cached FRI data
//  3. VerifyBlockDAAvailability injects the FRI data provider into DASClient
//  4. DASClient.Sample uses friVerifyDASCell (FRI verification) for local cells
//
// The test uses a single node with locally-stored cells (no P2P), so all
// sampled cells are verified via the FRI path.
// =============================================================================

func TestR7_P0_6_FRIIntegration_ProcessBlobsAndSample(t *testing.T) {
	storage := encoding.NewBlobStorage()
	dasConfig := encoding.DefaultDASConfig()
	dasConfig.MaxRetries = 1
	dasConfig.QueryTimeoutMs = 500
	// R40-P1-03 (2026-08-03): UseFRI=true triggers the FRI COMMITMENT path
	// inside ProcessBlobsForBlock, but this test does NOT wire a real FRI
	// data provider on the SAMPLING side, so the sampling path still relies
	// on the hash-stub verification of cells. Opt into the legacy hash-
	// stub fallback explicitly; production DAS nodes MUST leave this flag
	// false so the strict FRI-or-reject enforcement guards crypto
	// authenticity. (See also: R40-P1-03 hardening rationale in
	// encoding/das.go.)
	dasConfig.AllowHashStubFallback = true
	dasClient := encoding.NewDASClient(dasConfig)
	netMgr := encoding.NewBlobNetworkManager(storage, dasClient)
	collector := consensus.NewDAAttestationCollector()

	// UseFRI=true: triggers FRI commitment path in ProcessBlobsForBlock.
	engine := NewDankshardingEngine(
		storage, dasClient, netMgr, nil, collector, nil, nil,
		DankshardingConfig{Enabled: true, UseFRI: true},
	)
	// CONS-R10-test-leak (2026-07-19) FIX: Register cleanup to Shutdown()
	// the engine at test exit. Previously this test leaked DASClient
	// sampling goroutines that accumulated across the suite and starved
	// the Go scheduler, causing later tests to time out at 604s.
	t.Cleanup(func() { engine.Shutdown() })

	// Wire local cell getter: cells come from local storage (no P2P).
	dasClient.SetCellGetter(func(slot uint64, blobIndex, row, col int) (*encoding.DASSampleResponse, error) {
		cell, _, err := storage.GetCell(slot, blobIndex, row, col)
		if err != nil {
			return nil, err
		}
		commitments := storage.GetCommitments(slot)
		var proof encoding.KZGProof
		if blobIndex < len(commitments) {
			p, ok := encoding.ComputeCellProof(*cell, row, col, commitments[blobIndex])
			if ok {
				proof = p
			}
		}
		return &encoding.DASSampleResponse{
			Slot:      slot,
			BlobIndex: blobIndex,
			CellRow:   row,
			CellCol:   col,
			Cell:      *cell,
			Proof:     proof,
		}, nil
	})

	blob := makeTestBlob(0x99)
	_, commitments, err := engine.ProcessBlobsForBlock(1, []encoding.Blob{blob})
	if err != nil {
		t.Fatalf("ProcessBlobsForBlock failed: %v", err)
	}
	if len(commitments) != 1 {
		t.Fatalf("expected 1 commitment, got %d", len(commitments))
	}

	// Verify FRI data was cached.
	friData := engine.GetFRIBlobData(1, 0)
	if friData == nil {
		t.Fatal("GetFRIBlobData returned nil — FRI data was not cached by ProcessBlobsForBlock")
	}
	if friData.Commitment == nil {
		t.Fatal("FRI data has nil commitment")
	}
	if friData.Commitment.DomainSize <= 0 {
		t.Errorf("FRI commitment has invalid DomainSize: %d", friData.Commitment.DomainSize)
	}

	// Verify FRI data can be used to verify a cell.
	cell, err := encoding.FRIDAGetCellValue(friData, 0)
	if err != nil {
		t.Fatalf("FRIDAGetCellValue failed: %v", err)
	}
	if !encoding.FRIDAVerifyCell(cell, friData.Commitment,
		mustGenCellProof(t, friData, 0), 0) {
		t.Error("FRIDAVerifyCell failed for locally-cached FRI data")
	}

	// VerifyBlockDAAvailability should inject FRI data provider and
	// sampling should succeed (cells are locally available).
	available, confidence, err := engine.VerifyBlockDAAvailability(1, 1, commitments)
	if err != nil {
		t.Fatalf("VerifyBlockDAAvailability failed: %v", err)
	}
	if !available {
		t.Errorf("expected available=true with FRI verification, got false (confidence=%.4f)", confidence)
	}
	if confidence <= 0 {
		t.Errorf("expected positive confidence, got %.4f", confidence)
	}
}

// mustGenCellProof is a test helper that generates a FRI cell proof or fails.
func mustGenCellProof(t *testing.T, blobData *encoding.FRIDABlobData, cellIndex int) *encoding.FRIDACellProof {
	t.Helper()
	proof, err := encoding.FRIDAGenerateCellProof(blobData, cellIndex)
	if err != nil {
		t.Fatalf("FRIDAGenerateCellProof failed: %v", err)
	}
	return proof
}

// TestR7_P0_6_FRIIntegration_UseFRIFalse_NoFRIData verifies that when
// UseFRI=false (default), ProcessBlobsForBlock does NOT cache FRI data
// and GetFRIBlobData returns nil.
func TestR7_P0_6_FRIIntegration_UseFRIFalse_NoFRIData(t *testing.T) {
	storage := encoding.NewBlobStorage()
	dasClient := encoding.NewDASClient(encoding.DefaultDASConfig())
	netMgr := encoding.NewBlobNetworkManager(storage, dasClient)
	collector := consensus.NewDAAttestationCollector()

	// UseFRI=false (default): legacy hash stub path.
	engine := NewDankshardingEngine(
		storage, dasClient, netMgr, nil, collector, nil, nil,
		DankshardingConfig{Enabled: true}, // UseFRI defaults to false
	)
	// CONS-R10-test-leak (2026-07-19) FIX: Register cleanup (see above).
	t.Cleanup(func() { engine.Shutdown() })

	blob := makeTestBlob(0x77)
	_, _, err := engine.ProcessBlobsForBlock(1, []encoding.Blob{blob})
	if err != nil {
		t.Fatalf("ProcessBlobsForBlock failed: %v", err)
	}

	// FRI data should NOT be cached.
	friData := engine.GetFRIBlobData(1, 0)
	if friData != nil {
		t.Error("GetFRIBlobData should return nil when UseFRI=false")
	}
}
