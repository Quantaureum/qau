// Quantaureum Node source, version 1.0.0.
package core

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/quantaureum/qau/encoding"
)

// =============================================================================
// P2-8: End-to-End Multi-Node Devnet Tests (4-8 nodes)
//
// This file extends P2-5's 3/4-node integration tests to larger networks
// (4, 6, 8 nodes) and adds scenarios for:
//   - Multi-slot sequential blob processing
//   - Block gating (VerifyBlockDAAvailability)
//   - Multiple blobs per block across multiple nodes
//   - Various fault ratios (1/4, 2/4, 2/8, 3/8, 3/6 offline)
//
// All helpers (testNode, makeIntegrationValidators, newTestNode, wireMockP2P,
// startAllNodes, stopAllNodes, makeTestBlob, signAndSubmit,
// commitmentsToHashes, processBlobsOnAllNodes) are defined in
// danksharding_integration_test.go (P2-5) and reused here.
//
// DoD: 4-8 node devnet verifying blob submission, DAS sampling, and block gating
// Note: The 7x24h stability requirement is operational (not testable in CI).
// These tests verify the functional correctness of the multi-node DA pipeline.
// =============================================================================

// simulateNetworkPartition breaks a node's peerGetter so it cannot fetch cells
// from other nodes. The node's Sample() will fail, causing its attestation to
// have Available=false. The node can still serve cells to others (its own
// ServeCellRequest is unaffected).
func simulateNetworkPartition(t *testing.T, node *testNode) {
	t.Helper()
	node.netMgr.SetPeerGetter(func(peerID string, msgType uint8, data []byte) ([]byte, error) {
		return nil, errors.New("network partition")
	})
}

// runFullDAPipeline is the shared end-to-end DA pipeline:
// 1. All nodes ProcessBlobsForBlock (store blobs + commitments)
// 2. Each node BuildDAAttestation (sample + build attestation)
// 3. Each node signs and submits attestation to collector
// 4. Build aggregate attestation
// Returns: (commitments, availableCount, aggregate)
func runFullDAPipeline(t *testing.T, nodes []*testNode, slot uint64, blobs []encoding.Blob) ([]encoding.KZGCommitment, int, *encoding.DASAggregateAttestation) {
	t.Helper()

	commitments := processBlobsOnAllNodes(t, nodes, slot, blobs)

	availableCount := 0
	for _, node := range nodes {
		att, err := node.engine.BuildDAAttestation(slot, len(blobs), commitments, node.index)
		if err != nil {
			t.Fatalf("node%d BuildDAAttestation failed: %v", node.index, err)
		}
		if att.Available {
			availableCount++
		}
		signAndSubmit(t, node, nodes[0].collector, att)
	}

	// DA-R7-04 (2026-07-17): BuildAggregateAttestation now takes
	// []encoding.KZGCommitment (48 bytes) directly — no more truncation
	// to []types.Hash (32 bytes).
	agg := nodes[0].engine.BuildAggregateAttestation(slot, commitments)
	return commitments, availableCount, agg
}

// =============================================================================
// 4-Node Devnet Tests
// =============================================================================

// TestP2_8_FourNode_AllOnline verifies the happy path: all 4 nodes online,
// all sample successfully, 4/4 aggregate is sufficient, block DA is available.
func TestP2_8_FourNode_AllOnline(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x41)
	commitments, availableCount, agg := runFullDAPipeline(t, nodes, 1, []encoding.Blob{blob})

	if availableCount != 4 {
		t.Errorf("expected 4 available, got %d", availableCount)
	}
	if agg == nil {
		t.Fatal("expected non-nil aggregate for 4/4 available")
	}
	if agg.AvailableCount != 4 || agg.TotalCount != 4 {
		t.Errorf("expected 4/4, got %d/%d", agg.AvailableCount, agg.TotalCount)
	}
	if !agg.IsSufficient() {
		t.Error("expected IsSufficient=true for 4/4")
	}

	// Block gating: VerifyBlockDAAvailability should return true.
	// Node 0 already cached the sampling result in BuildDAAttestation.
	avail, _, err := nodes[0].engine.VerifyBlockDAAvailability(1, 1, commitments)
	if err != nil {
		t.Fatalf("VerifyBlockDAAvailability failed: %v", err)
	}
	if !avail {
		t.Error("expected VerifyBlockDAAvailability=true when aggregate is sufficient")
	}
}

// TestP2_8_FourNode_OneOffline verifies 3/4 = 0.75 ≥ 0.6667 → sufficient.
// One node has a network partition; its sampling fails → Available=false.
func TestP2_8_FourNode_OneOffline(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x42)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Node 3 has a network partition.
	simulateNetworkPartition(t, nodes[3])

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

	if availableCount != 3 {
		t.Errorf("expected 3 available (node3 partitioned), got %d", availableCount)
	}

	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg == nil {
		t.Fatal("expected non-nil aggregate for 3/4 (0.75 ≥ 0.6667)")
	}
	if agg.AvailableCount != 3 || agg.TotalCount != 4 {
		t.Errorf("expected 3/4, got %d/%d", agg.AvailableCount, agg.TotalCount)
	}
	if !agg.IsSufficient() {
		t.Error("expected IsSufficient=true for 3/4=0.75")
	}
}

// TestP2_8_FourNode_TwoOffline verifies 2/4 = 0.5 < 0.6667 → NOT sufficient.
// BuildAggregateAttestation returns nil (fail-closed).
func TestP2_8_FourNode_TwoOffline(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x43)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Nodes 2 and 3 have network partitions.
	simulateNetworkPartition(t, nodes[2])
	simulateNetworkPartition(t, nodes[3])

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
		t.Errorf("expected 2 available, got %d", availableCount)
	}

	// 2/4 = 0.5 < 0.6667 → NOT sufficient → BuildAggregateAttestation returns nil.
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg != nil {
		t.Errorf("expected nil aggregate (2/4=0.5 < 0.6667), got %d/%d",
			agg.AvailableCount, agg.TotalCount)
	}
}

// =============================================================================
// 8-Node Devnet Tests
// =============================================================================

// TestP2_8_EightNode_AllOnline verifies 8/8 aggregate is sufficient.
func TestP2_8_EightNode_AllOnline(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 8)
	nodes := make([]*testNode, 8)
	for i := 0; i < 8; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x81)
	_, availableCount, agg := runFullDAPipeline(t, nodes, 1, []encoding.Blob{blob})

	if availableCount != 8 {
		t.Errorf("expected 8 available, got %d", availableCount)
	}
	if agg == nil {
		t.Fatal("expected non-nil aggregate for 8/8")
	}
	if agg.AvailableCount != 8 || agg.TotalCount != 8 {
		t.Errorf("expected 8/8, got %d/%d", agg.AvailableCount, agg.TotalCount)
	}
	if !agg.IsSufficient() {
		t.Error("expected IsSufficient=true for 8/8")
	}
}

// TestP2_8_EightNode_TwoOffline verifies 6/8 = 0.75 ≥ 0.6667 → sufficient.
func TestP2_8_EightNode_TwoOffline(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 8)
	nodes := make([]*testNode, 8)
	for i := 0; i < 8; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x82)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Nodes 6 and 7 have network partitions.
	simulateNetworkPartition(t, nodes[6])
	simulateNetworkPartition(t, nodes[7])

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

	if availableCount != 6 {
		t.Errorf("expected 6 available, got %d", availableCount)
	}

	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg == nil {
		t.Fatal("expected non-nil aggregate for 6/8 (0.75 ≥ 0.6667)")
	}
	if agg.AvailableCount != 6 || agg.TotalCount != 8 {
		t.Errorf("expected 6/8, got %d/%d", agg.AvailableCount, agg.TotalCount)
	}
	if !agg.IsSufficient() {
		t.Error("expected IsSufficient=true for 6/8=0.75")
	}
}

// TestP2_8_EightNode_ThreeOffline verifies 5/8 = 0.625 < 0.6667 → NOT sufficient.
func TestP2_8_EightNode_ThreeOffline(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 8)
	nodes := make([]*testNode, 8)
	for i := 0; i < 8; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x83)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Nodes 5, 6, 7 have network partitions.
	simulateNetworkPartition(t, nodes[5])
	simulateNetworkPartition(t, nodes[6])
	simulateNetworkPartition(t, nodes[7])

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

	if availableCount != 5 {
		t.Errorf("expected 5 available, got %d", availableCount)
	}

	// 5/8 = 0.625 < 0.6667 → NOT sufficient → nil aggregate.
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg != nil {
		t.Errorf("expected nil aggregate (5/8=0.625 < 0.6667), got %d/%d",
			agg.AvailableCount, agg.TotalCount)
	}
}

// =============================================================================
// 6-Node Devnet Tests
// =============================================================================

// TestP2_8_SixNode_ThreeOffline verifies 3/6 = 0.5 < 0.6667 → NOT sufficient.
// This is the "half offline" boundary case.
func TestP2_8_SixNode_ThreeOffline(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 6)
	nodes := make([]*testNode, 6)
	for i := 0; i < 6; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x61)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Nodes 3, 4, 5 have network partitions (half offline).
	simulateNetworkPartition(t, nodes[3])
	simulateNetworkPartition(t, nodes[4])
	simulateNetworkPartition(t, nodes[5])

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

	if availableCount != 3 {
		t.Errorf("expected 3 available, got %d", availableCount)
	}

	// 3/6 = 0.5 < 0.6667 → NOT sufficient.
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg != nil {
		t.Errorf("expected nil aggregate (3/6=0.5 < 0.6667), got %d/%d",
			agg.AvailableCount, agg.TotalCount)
	}
}

// =============================================================================
// Multi-Slot Sequential Tests
// =============================================================================

// TestP2_8_FourNode_MultipleSlots verifies that 4 nodes can process blobs
// across 5 consecutive slots, with each slot independently sampled and attested.
func TestP2_8_FourNode_MultipleSlots(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	for slot := uint64(1); slot <= 5; slot++ {
		blob := makeTestBlob(byte(slot))
		commitments, availableCount, agg := runFullDAPipeline(t, nodes, slot, []encoding.Blob{blob})

		if availableCount != 4 {
			t.Errorf("slot %d: expected 4 available, got %d", slot, availableCount)
		}
		if agg == nil {
			t.Fatalf("slot %d: expected non-nil aggregate", slot)
		}
		if agg.AvailableCount != 4 || agg.TotalCount != 4 {
			t.Errorf("slot %d: expected 4/4, got %d/%d", slot, agg.AvailableCount, agg.TotalCount)
		}
		if !agg.IsSufficient() {
			t.Errorf("slot %d: expected IsSufficient=true", slot)
		}

		// Verify slot isolation: each slot has its own attestations.
		atts := nodes[0].collector.GetAttestations(slot)
		if len(atts) != 4 {
			t.Errorf("slot %d: expected 4 attestations, got %d", slot, len(atts))
		}

		// Verify block gating per slot.
		avail, _, err := nodes[0].engine.VerifyBlockDAAvailability(slot, 1, commitments)
		if err != nil {
			t.Fatalf("slot %d: VerifyBlockDAAvailability failed: %v", slot, err)
		}
		if !avail {
			t.Errorf("slot %d: expected VerifyBlockDAAvailability=true", slot)
		}
	}
}

// =============================================================================
// Multiple Blobs Per Block Tests
// =============================================================================

// TestP2_8_FourNode_MultipleBlobsPerBlock verifies that 4 nodes can process
// 1, 3, and 6 blobs per block with full DA sampling and attestation.
func TestP2_8_FourNode_MultipleBlobsPerBlock(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blobCounts := []int{1, 3, 6}
	for idx, blobCount := range blobCounts {
		slot := uint64(idx + 1)
		blobs := make([]encoding.Blob, blobCount)
		for i := range blobs {
			blobs[i] = makeTestBlob(byte(slot*0x10 + uint64(i)))
		}

		commitments, availableCount, agg := runFullDAPipeline(t, nodes, slot, blobs)

		if availableCount != 4 {
			t.Errorf("blobCount=%d: expected 4 available, got %d", blobCount, availableCount)
		}
		if agg == nil {
			t.Fatalf("blobCount=%d: expected non-nil aggregate", blobCount)
		}
		if !agg.IsSufficient() {
			t.Errorf("blobCount=%d: expected IsSufficient=true", blobCount)
		}
		if len(commitments) != blobCount {
			t.Errorf("blobCount=%d: expected %d commitments, got %d", blobCount, blobCount, len(commitments))
		}

		// Verify block gating with multiple blobs.
		avail, _, err := nodes[0].engine.VerifyBlockDAAvailability(slot, blobCount, commitments)
		if err != nil {
			t.Fatalf("blobCount=%d: VerifyBlockDAAvailability failed: %v", blobCount, err)
		}
		if !avail {
			t.Errorf("blobCount=%d: expected VerifyBlockDAAvailability=true", blobCount)
		}
	}
}

// =============================================================================
// Block Gating Tests
// =============================================================================

// TestP2_8_BlockGating_SufficientReturnsTrue verifies that
// VerifyBlockDAAvailability returns true when the aggregate is sufficient.
func TestP2_8_BlockGating_SufficientReturnsTrue(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x91)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// All nodes sample and attest.
	for _, node := range nodes {
		att, err := node.engine.BuildDAAttestation(1, 1, commitments, node.index)
		if err != nil {
			t.Fatalf("node%d BuildDAAttestation failed: %v", node.index, err)
		}
		signAndSubmit(t, node, nodes[0].collector, att)
	}

	// Build aggregate — should be sufficient (4/4).
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg == nil || !agg.IsSufficient() {
		t.Fatal("expected sufficient aggregate")
	}

	// Block gating: all nodes should report DA available (cached sampling).
	for _, node := range nodes {
		avail, confidence, err := node.engine.VerifyBlockDAAvailability(1, 1, commitments)
		if err != nil {
			t.Errorf("node%d: VerifyBlockDAAvailability error: %v", node.index, err)
		}
		if !avail {
			t.Errorf("node%d: expected DA available=true, got false (confidence=%.4f)", node.index, confidence)
		}
	}
}

// TestP2_8_BlockGating_InsufficientReturnsFalse verifies that when the
// aggregate is NOT sufficient, the block should be gated as DA-unavailable.
// Note: VerifyBlockDAAvailability returns the node's OWN sampling result,
// not the aggregate. The block gating decision combines:
//   - Node's own sampling (VerifyBlockDAAvailability)
//   - Aggregate sufficiency (BuildAggregateAttestation != nil && IsSufficient)
//
// This test verifies the aggregate path returns nil when insufficient.
func TestP2_8_BlockGating_InsufficientReturnsFalse(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x92)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Nodes 2 and 3 have network partitions → 2/4 = 0.5 < 0.6667.
	simulateNetworkPartition(t, nodes[2])
	simulateNetworkPartition(t, nodes[3])

	for _, node := range nodes {
		att, err := node.engine.BuildDAAttestation(1, 1, commitments, node.index)
		if err != nil {
			t.Fatalf("node%d BuildDAAttestation failed: %v", node.index, err)
		}
		signAndSubmit(t, node, nodes[0].collector, att)
	}

	// Build aggregate — should return nil (2/4 insufficient).
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg != nil {
		t.Errorf("expected nil aggregate (2/4 insufficient), got %d/%d",
			agg.AvailableCount, agg.TotalCount)
	}

	// Block gating: nil aggregate means block should NOT be accepted.
	// A real block validator would check: agg != nil && agg.IsSufficient().
	blockDAValid := agg != nil && agg.IsSufficient()
	if blockDAValid {
		t.Error("expected blockDAValid=false when aggregate is nil")
	}
}

// =============================================================================
// Concurrent Attestation Submission Test
// =============================================================================

// TestP2_8_EightNode_ConcurrentAttestations verifies that 8 nodes can
// concurrently build and submit attestations without race conditions or panics.
// This tests the thread-safety of DAAttestationCollector under concurrent load.
func TestP2_8_EightNode_ConcurrentAttestations(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 8)
	nodes := make([]*testNode, 8)
	for i := 0; i < 8; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0xA1)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// All 8 nodes concurrently build and submit attestations.
	var wg sync.WaitGroup
	for _, node := range nodes {
		wg.Add(1)
		go func(n *testNode) {
			defer wg.Done()
			att, err := n.engine.BuildDAAttestation(1, 1, commitments, n.index)
			if err != nil {
				t.Errorf("node%d BuildDAAttestation failed: %v", n.index, err)
				return
			}
			signAndSubmit(t, n, nodes[0].collector, att)
		}(node)
	}
	wg.Wait()

	// Verify all 8 attestations were collected.
	atts := nodes[0].collector.GetAttestations(1)
	if len(atts) != 8 {
		t.Errorf("expected 8 attestations, got %d", len(atts))
	}

	// Build aggregate — should be sufficient (8/8).
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments)
	if agg == nil {
		t.Fatal("expected non-nil aggregate for 8/8")
	}
	if !agg.IsSufficient() {
		t.Error("expected IsSufficient=true for 8/8")
	}
}

// =============================================================================
// Network Topology: Star Topology Test
// =============================================================================

// TestP2_8_FourNode_StarTopology verifies DA sampling with a star topology:
// Node 0 is the hub; Nodes 1, 2, 3 can only reach Node 0 (not each other).
// All nodes can still sample because they all fetch cells from Node 0.
func TestP2_8_FourNode_StarTopology(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}

	// Star topology: Nodes 1, 2, 3 can only reach Node 0.
	// Node 0 can reach all others.
	nodeByPeerID := make(map[string]*testNode)
	for _, n := range nodes {
		nodeByPeerID[n.peerID] = n
	}

	for _, n := range nodes {
		node := n // capture
		peerGetter := func(peerID string, msgType uint8, data []byte) ([]byte, error) {
			target, ok := nodeByPeerID[peerID]
			if !ok {
				return nil, fmt.Errorf("unknown peer: %s", peerID)
			}
			return target.netMgr.ServeCellRequest(data)
		}

		var peerList func() []string
		if node.index == 0 {
			// Hub: can reach all spokes.
			peerList = func() []string {
				return []string{"node1", "node2", "node3"}
			}
		} else {
			// Spoke: can only reach hub.
			peerList = func() []string {
				return []string{"node0"}
			}
		}
		node.engine.SetP2PBridge(peerGetter, peerList)
	}

	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0xB1)
	_, availableCount, agg := runFullDAPipeline(t, nodes, 1, []encoding.Blob{blob})

	// All 4 nodes should be available: Nodes 1,2,3 fetch from Node 0,
	// Node 0 fetches from Nodes 1,2,3 (or itself via cache).
	if availableCount != 4 {
		t.Errorf("expected 4 available in star topology, got %d", availableCount)
	}
	if agg == nil {
		t.Fatal("expected non-nil aggregate for star topology 4/4")
	}
	if !agg.IsSufficient() {
		t.Error("expected IsSufficient=true for star topology 4/4")
	}
}
