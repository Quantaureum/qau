// Quantaureum Node source, version 1.0.0.
package core

import (
	"fmt"
	"sync"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
)

// =============================================================================
// P2-9: Fault Injection Tests — Network Partition, Node Crash, Malicious Attestation
//
// DoD: DA availability degrades correctly under network partition and self-heals after recovery
//
// Three test categories:
//   A. Network Partition + Self-Healing (core DoD)
//      - Partition degrades availability; healing restores it in subsequent slots
//      - sync.Once per-slot cache means self-healing is observed on NEW slots
//        (a slot's sampling result is immutable once computed)
//   B. Node Crash / Restart
//      - Node stops participating; aggregate degrades correctly
//      - Node "restarts" and participates in new slots
//   C. Malicious Attestation Rejection
//      - Forged signatures, tampered fields, out-of-range indices
//      - Fail-closed when verifier/committeeSize not configured
//
// All helpers (testNode, makeIntegrationValidators, newTestNode, wireMockP2P,
// startAllNodes, stopAllNodes, makeTestBlob, signAndSubmit,
// commitmentsToHashes, processBlobsOnAllNodes, simulateNetworkPartition,
// runFullDAPipeline) are defined in danksharding_integration_test.go (P2-5)
// and danksharding_e2e_test.go (P2-8).
// =============================================================================

// healNetworkPartition restores a node's peerGetter so it can fetch cells
// from other nodes again. This simulates network recovery after a partition.
// The routing logic mirrors wireMockP2P: route to target.netMgr.ServeCellRequest.
func healNetworkPartition(t *testing.T, nodes []*testNode, healedNode *testNode) {
	t.Helper()
	nodeByPeerID := make(map[string]*testNode)
	for _, n := range nodes {
		nodeByPeerID[n.peerID] = n
	}
	healedNode.netMgr.SetPeerGetter(func(peerID string, msgType uint8, data []byte) ([]byte, error) {
		target, ok := nodeByPeerID[peerID]
		if !ok {
			return nil, fmt.Errorf("unknown peer: %s", peerID)
		}
		return target.netMgr.ServeCellRequest(data)
	})
}

// makeManualAttestation creates a bare DASAttestation without sampling.
// Used for malicious attestation tests where we need full control over fields.
func makeManualAttestation(slot uint64, validatorIndex int, available bool) *encoding.DASAttestation {
	return &encoding.DASAttestation{
		Slot:           slot,
		Available:      available,
		Confidence:     1.0,
		ValidatorIndex: validatorIndex,
		SampleCount:    100,
		SuccessCount:   100,
	}
}

// signAttestation signs the attestation's Hash() with the given private key
// and sets att.Signature. Does NOT submit to a collector.
func signAttestation(t *testing.T, priv *crypto.PrivateKey, att *encoding.DASAttestation) {
	t.Helper()
	hash := att.Hash()
	sig, err := crypto.Sign(priv, hash[:])
	if err != nil {
		t.Fatalf("crypto.Sign failed: %v", err)
	}
	att.Signature = sig
}

// =============================================================================
// A. Network Partition + Self-Healing (Core DoD)
// =============================================================================

// TestP2_9_PartitionThenHeal_SingleNode verifies the core DoD:
// 1. Slot 1: Partition node 3 → 3/4 = 0.75 ≥ 0.6667 → sufficient (degraded but operational)
// 2. Heal node 3
// 3. Slot 2: All 4 online → 4/4 → sufficient (self-healed)
//
// Self-healing is observed on the NEW slot because sampleCache uses sync.Once
// per slot — slot 1's failed sampling result is immutable.
func TestP2_9_PartitionThenHeal_SingleNode(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob1 := makeTestBlob(0x11)
	blob2 := makeTestBlob(0x22)

	// --- Slot 1: Partition node 3 ---
	simulateNetworkPartition(t, nodes[3])

	commitments1, avail1, agg1 := runFullDAPipeline(t, nodes, 1, []encoding.Blob{blob1})

	if avail1 != 3 {
		t.Errorf("slot 1: expected 3 available (node 3 partitioned), got %d", avail1)
	}
	if agg1 == nil {
		t.Fatal("slot 1: expected non-nil aggregate (3/4 sufficient)")
	}
	if !agg1.IsSufficient() {
		t.Error("slot 1: expected IsSufficient=true for 3/4")
	}

	// --- Heal node 3 ---
	healNetworkPartition(t, nodes, nodes[3])

	// --- Slot 2: All online (self-healed) ---
	commitments2, avail2, agg2 := runFullDAPipeline(t, nodes, 2, []encoding.Blob{blob2})

	if avail2 != 4 {
		t.Errorf("slot 2: expected 4 available (healed), got %d", avail2)
	}
	if agg2 == nil {
		t.Fatal("slot 2: expected non-nil aggregate (4/4 sufficient)")
	}
	if agg2.AvailableCount != 4 {
		t.Errorf("slot 2: expected AvailableCount=4, got %d", agg2.AvailableCount)
	}
	if !agg2.IsSufficient() {
		t.Error("slot 2: expected IsSufficient=true for 4/4")
	}

	// Verify commitments are different across slots (different blobs).
	if commitments1[0] == commitments2[0] {
		t.Error("expected different commitments across slots")
	}
}

// TestP2_9_PartitionThenHeal_TwoNodes verifies self-healing after a severe
// partition that caused the aggregate to become insufficient:
// 1. Slot 1: Partition nodes 2,3 → 2/4 = 0.5 < 0.6667 → NOT sufficient (nil aggregate)
// 2. Heal nodes 2,3
// 3. Slot 2: All 4 online → 4/4 → sufficient (self-healed)
func TestP2_9_PartitionThenHeal_TwoNodes(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob1 := makeTestBlob(0x33)
	blob2 := makeTestBlob(0x44)

	// --- Slot 1: Partition nodes 2 and 3 ---
	simulateNetworkPartition(t, nodes[2])
	simulateNetworkPartition(t, nodes[3])

	_, avail1, agg1 := runFullDAPipeline(t, nodes, 1, []encoding.Blob{blob1})

	if avail1 != 2 {
		t.Errorf("slot 1: expected 2 available, got %d", avail1)
	}
	if agg1 != nil {
		t.Errorf("slot 1: expected nil aggregate (2/4 < 0.6667 not sufficient), got AvailableCount=%d", agg1.AvailableCount)
	}

	// --- Heal nodes 2 and 3 ---
	healNetworkPartition(t, nodes, nodes[2])
	healNetworkPartition(t, nodes, nodes[3])

	// --- Slot 2: All online (self-healed) ---
	_, avail2, agg2 := runFullDAPipeline(t, nodes, 2, []encoding.Blob{blob2})

	if avail2 != 4 {
		t.Errorf("slot 2: expected 4 available (healed), got %d", avail2)
	}
	if agg2 == nil {
		t.Fatal("slot 2: expected non-nil aggregate (4/4 sufficient after heal)")
	}
	if !agg2.IsSufficient() {
		t.Error("slot 2: expected IsSufficient=true for 4/4 after heal")
	}
}

// TestP2_9_PartitionAcrossMultipleSlots verifies a 3-slot sequence:
// 1. Slot 1: All online → 4/4 sufficient
// 2. Slot 2: Partition node 3 → 3/4 sufficient (degraded)
// 3. Slot 3: Heal node 3 → 4/4 sufficient (recovered)
//
// This tests that partition/heal events on one slot don't affect subsequent slots.
func TestP2_9_PartitionAcrossMultipleSlots(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	// --- Slot 1: All online ---
	blob1 := makeTestBlob(0x50)
	_, avail1, agg1 := runFullDAPipeline(t, nodes, 1, []encoding.Blob{blob1})
	if avail1 != 4 || agg1 == nil || !agg1.IsSufficient() {
		t.Fatalf("slot 1: expected 4/4 sufficient, got avail=%d agg=%v", avail1, agg1)
	}

	// --- Slot 2: Partition node 3 ---
	simulateNetworkPartition(t, nodes[3])
	blob2 := makeTestBlob(0x51)
	_, avail2, agg2 := runFullDAPipeline(t, nodes, 2, []encoding.Blob{blob2})
	if avail2 != 3 {
		t.Errorf("slot 2: expected 3 available, got %d", avail2)
	}
	if agg2 == nil || !agg2.IsSufficient() {
		t.Error("slot 2: expected 3/4 sufficient")
	}

	// --- Slot 3: Heal node 3 ---
	healNetworkPartition(t, nodes, nodes[3])
	blob3 := makeTestBlob(0x52)
	_, avail3, agg3 := runFullDAPipeline(t, nodes, 3, []encoding.Blob{blob3})
	if avail3 != 4 {
		t.Errorf("slot 3: expected 4 available (healed), got %d", avail3)
	}
	if agg3 == nil || !agg3.IsSufficient() {
		t.Error("slot 3: expected 4/4 sufficient after heal")
	}
}

// TestP2_9_PartitionThenHeal_EightNode verifies self-healing on a larger network:
// 1. Slot 1: Partition 3 of 8 nodes → 5/8 = 0.625 < 0.6667 → NOT sufficient
// 2. Heal all 3
// 3. Slot 2: All 8 online → 8/8 → sufficient
func TestP2_9_PartitionThenHeal_EightNode(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 8)
	nodes := make([]*testNode, 8)
	for i := 0; i < 8; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob1 := makeTestBlob(0x61)
	blob2 := makeTestBlob(0x62)

	// --- Slot 1: Partition nodes 5, 6, 7 ---
	for _, idx := range []int{5, 6, 7} {
		simulateNetworkPartition(t, nodes[idx])
	}

	_, avail1, agg1 := runFullDAPipeline(t, nodes, 1, []encoding.Blob{blob1})
	if avail1 != 5 {
		t.Errorf("slot 1: expected 5 available, got %d", avail1)
	}
	if agg1 != nil {
		t.Errorf("slot 1: expected nil aggregate (5/8 = 0.625 < 0.6667), got AvailableCount=%d", agg1.AvailableCount)
	}

	// --- Heal all 3 partitioned nodes ---
	for _, idx := range []int{5, 6, 7} {
		healNetworkPartition(t, nodes, nodes[idx])
	}

	// --- Slot 2: All 8 online ---
	_, avail2, agg2 := runFullDAPipeline(t, nodes, 2, []encoding.Blob{blob2})
	if avail2 != 8 {
		t.Errorf("slot 2: expected 8 available (healed), got %d", avail2)
	}
	if agg2 == nil || !agg2.IsSufficient() {
		t.Error("slot 2: expected 8/8 sufficient after heal")
	}
}

// TestP2_9_AsymmetricPartition verifies that a node which can reach some peers
// but not others can still sample successfully (as long as it can reach at
// least one node that has the cells).
//
// Topology: Node 0 can reach Node 1 only (not 2, 3).
// Node 1 has all cells stored. Node 0 fetches from Node 1 → sampling succeeds.
func TestP2_9_AsymmetricPartition(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x77)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Node 0: can only reach Node 1.
	nodes[0].netMgr.SetPeerGetter(func(peerID string, msgType uint8, data []byte) ([]byte, error) {
		if peerID == "node1" {
			return nodes[1].netMgr.ServeCellRequest(data)
		}
		return nil, fmt.Errorf("asymmetric partition: cannot reach %s", peerID)
	})
	nodes[0].netMgr.SetPeerList(func() []string {
		return []string{"node1"} // only Node 1 is reachable
	})

	// Node 0 builds attestation — should succeed because Node 1 has the cells.
	att, err := nodes[0].engine.BuildDAAttestation(1, 1, commitments, 0)
	if err != nil {
		t.Fatalf("node0 BuildDAAttestation failed: %v", err)
	}
	if !att.Available {
		t.Error("expected node0 available=true (can reach node1 which has cells)")
	}
}

// =============================================================================
// B. Node Crash / Restart
// =============================================================================

// TestP2_9_NodeCrashBeforeAttestation simulates a node crash: node 3's engine
// is stopped and it does not submit an attestation. The remaining 3/4 nodes
// produce a sufficient aggregate.
func TestP2_9_NodeCrashBeforeAttestation(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x88)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Node 3 "crashes" — stop its engine and skip its attestation.
	nodes[3].engine.Stop()

	// Only nodes 0, 1, 2 attest.
	availableCount := 0
	for _, node := range nodes[:3] {
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

	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments) // DA-R7-04: takes []KZGCommitment directly
	if agg == nil {
		t.Fatal("expected non-nil aggregate (3/4 sufficient)")
	}
	if agg.AvailableCount != 3 || agg.TotalCount != 3 {
		t.Errorf("expected 3/3 in aggregate, got %d/%d", agg.AvailableCount, agg.TotalCount)
	}
	if !agg.IsSufficient() {
		t.Error("expected IsSufficient=true for 3/3")
	}
}

// TestP2_9_HalfNodesCrash simulates 2 of 4 nodes crashing: only 2/4 attest.
// 2/4 = 0.5 < 0.6667 → NOT sufficient → aggregate is nil.
func TestP2_9_HalfNodesCrash(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0x99)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Nodes 2, 3 "crash" — stop engines and skip attestations.
	nodes[2].engine.Stop()
	nodes[3].engine.Stop()

	// Only nodes 0, 1 attest.
	availableCount := 0
	for _, node := range nodes[:2] {
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

	// DA-R5-07 (2026-07-17): Absolute attestation floor requires
	// TotalCount >= ceil(2/3 · CommitteeSize). With CommitteeSize=4, the
	// floor is ceil(8/3)=3. Only 2 attestations were collected (nodes 2,3
	// crashed), so 2 < 3 → IsSufficient()=false → BuildAggregateAttestation
	// returns nil. This is the CORRECT fail-closed behavior: a network where
	// half the committee is down cannot produce a sufficient DA aggregate,
	// even though the 2 collected attestations all agree (2/2 ratio).
	// The block proposer must wait for more attestations or skip DA for
	// this slot.
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments) // DA-R7-04: takes []KZGCommitment directly
	if agg != nil {
		t.Fatalf("expected nil aggregate: 2/4 committee < DA-R5-07 floor of 3, got non-nil (TotalCount=%d)", agg.TotalCount)
	}
}

// TestP2_9_NodeRestart_NewSlot simulates a node crashing in slot 1, then
// restarting and participating normally in slot 2.
func TestP2_9_NodeRestart_NewSlot(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	// --- Slot 1: Node 3 crashes, doesn't attest ---
	blob1 := makeTestBlob(0xa0)
	commitments1 := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob1})
	nodes[3].engine.Stop()

	avail1 := 0
	for _, node := range nodes[:3] {
		att, err := node.engine.BuildDAAttestation(1, 1, commitments1, node.index)
		if err != nil {
			t.Fatalf("node%d BuildDAAttestation failed: %v", node.index, err)
		}
		if att.Available {
			avail1++
		}
		signAndSubmit(t, node, nodes[0].collector, att)
	}
	if avail1 != 3 {
		t.Errorf("slot 1: expected 3 available, got %d", avail1)
	}

	// --- Slot 2: Node 3 "restarts" — participates again ---
	blob2 := makeTestBlob(0xa1)
	commitments2 := processBlobsOnAllNodes(t, nodes, 2, []encoding.Blob{blob2})

	avail2 := 0
	for _, node := range nodes {
		att, err := node.engine.BuildDAAttestation(2, 1, commitments2, node.index)
		if err != nil {
			t.Fatalf("node%d BuildDAAttestation failed: %v", node.index, err)
		}
		if att.Available {
			avail2++
		}
		signAndSubmit(t, node, nodes[0].collector, att)
	}
	if avail2 != 4 {
		t.Errorf("slot 2: expected 4 available (node 3 restarted), got %d", avail2)
	}
	// DA-R7-04 (2026-07-17): BuildAggregateAttestation takes []encoding.KZGCommitment.
	agg2 := nodes[0].engine.BuildAggregateAttestation(2, commitments2)
	if agg2 == nil || !agg2.IsSufficient() {
		t.Error("slot 2: expected 4/4 sufficient after restart")
	}
}

// =============================================================================
// C. Malicious Attestation Rejection
// =============================================================================

// TestP2_9_ForgedSignature_Rejected verifies that an attestation signed with
// the wrong private key (not matching the ValidatorIndex's public key) is
// rejected by SubmitAttestation.
func TestP2_9_ForgedSignature_Rejected(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	// Create attestation claiming to be from validator 0, but sign with
	// validator 1's private key (forged).
	att := makeManualAttestation(1, 0, true)
	signAttestation(t, keypairs[1].Private, att) // wrong key!

	err := nodes[0].collector.SubmitAttestation(att)
	if err == nil {
		t.Fatal("expected SubmitAttestation to reject forged signature")
	}
}

// TestP2_9_TamperedAvailableField_Rejected verifies that modifying the
// Available field AFTER signing invalidates the signature, causing
// SubmitAttestation to reject the attestation.
func TestP2_9_TamperedAvailableField_Rejected(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	// Build a valid attestation with Available=false, sign it, then flip
	// Available to true. The signature no longer matches the hash.
	att := makeManualAttestation(1, 0, false)
	signAttestation(t, keypairs[0].Private, att)
	att.Available = true // tamper after signing

	err := nodes[0].collector.SubmitAttestation(att)
	if err == nil {
		t.Fatal("expected SubmitAttestation to reject tampered attestation")
	}
}

// TestP2_9_OutOfRangeValidatorIndex_Rejected verifies that a ValidatorIndex
// outside [0, committeeSize) is rejected.
func TestP2_9_OutOfRangeValidatorIndex_Rejected(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	// ValidatorIndex=999 is way out of range.
	att := makeManualAttestation(1, 999, true)
	signAttestation(t, keypairs[0].Private, att) // signature won't even be checked

	err := nodes[0].collector.SubmitAttestation(att)
	if err == nil {
		t.Fatal("expected SubmitAttestation to reject out-of-range ValidatorIndex")
	}
}

// TestP2_9_NegativeValidatorIndex_Rejected verifies that a negative
// ValidatorIndex is rejected.
func TestP2_9_NegativeValidatorIndex_Rejected(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	att := makeManualAttestation(1, -1, true)
	att.Signature = []byte{0x01} // non-empty to pass signature presence check

	err := nodes[0].collector.SubmitAttestation(att)
	if err == nil {
		t.Fatal("expected SubmitAttestation to reject negative ValidatorIndex")
	}
}

// TestP2_9_EmptySignature_Rejected verifies that an attestation with an empty
// signature is rejected by the verifier.
func TestP2_9_EmptySignature_Rejected(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	att := makeManualAttestation(1, 0, true)
	att.Signature = nil // empty signature

	err := nodes[0].collector.SubmitAttestation(att)
	if err == nil {
		t.Fatal("expected SubmitAttestation to reject empty signature")
	}
}

// TestP2_9_CommitteeSizeNotConfigured_FailClosed verifies that a collector
// with committeeSize=0 (not configured) rejects ALL attestations (fail-closed).
func TestP2_9_CommitteeSizeNotConfigured_FailClosed(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	verifier := consensus.NewDAAttestationVerifier(
		func() []*consensus.ValidatorInfo { return validators },
		nil, // no committee manager
	)

	// Fresh collector with committeeSize=0 and verifier=nil.
	collector := consensus.NewDAAttestationCollector()
	// Deliberately do NOT call SetCommitteeSize or SetAttestationVerifier.

	att := makeManualAttestation(1, 0, true)
	signAttestation(t, keypairs[0].Private, att)

	err := collector.SubmitAttestation(att)
	if err == nil {
		t.Fatal("expected fail-closed rejection when committeeSize=0")
	}

	// Now set verifier but still leave committeeSize=0 → should still reject.
	collector.SetAttestationVerifier(verifier)
	err = collector.SubmitAttestation(att)
	if err == nil {
		t.Fatal("expected fail-closed rejection when committeeSize=0 (even with verifier)")
	}
}

// TestP2_9_VerifierNotConfigured_FailClosed verifies that a collector with
// verifier=nil (not configured) rejects ALL attestations (fail-closed), even
// when committeeSize is set.
func TestP2_9_VerifierNotConfigured_FailClosed(t *testing.T) {
	_, keypairs := makeIntegrationValidators(t, 4)

	// Fresh collector: set committeeSize but NOT verifier.
	collector := consensus.NewDAAttestationCollector()
	collector.SetCommitteeSize(4)
	// Deliberately do NOT call SetAttestationVerifier.

	att := makeManualAttestation(1, 0, true)
	signAttestation(t, keypairs[0].Private, att)

	err := collector.SubmitAttestation(att)
	if err == nil {
		t.Fatal("expected fail-closed rejection when verifier=nil")
	}
}

// TestP2_9_ReSubmitSameValidator_Overwrites verifies that re-submitting an
// attestation from the same validator overwrites the previous one (allowed).
// This is not malicious behavior — it's a legitimate update (e.g., the node
// re-sampled and got a different result).
func TestP2_9_ReSubmitSameValidator_Overwrites(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	// First submission: Available=false (e.g., sampling failed initially).
	att1 := makeManualAttestation(1, 0, false)
	signAttestation(t, keypairs[0].Private, att1)
	if err := nodes[0].collector.SubmitAttestation(att1); err != nil {
		t.Fatalf("first SubmitAttestation failed: %v", err)
	}

	// Second submission from same validator: Available=true (re-sampled).
	att2 := makeManualAttestation(1, 0, true)
	signAttestation(t, keypairs[0].Private, att2)
	if err := nodes[0].collector.SubmitAttestation(att2); err != nil {
		t.Fatalf("second SubmitAttestation failed: %v", err)
	}

	// Verify only 1 attestation exists for slot 1, and it's the latest (Available=true).
	atts := nodes[0].collector.GetAttestations(1)
	if len(atts) != 1 {
		t.Fatalf("expected 1 attestation (overwritten), got %d", len(atts))
	}
	if !atts[0].Available {
		t.Error("expected overwritten attestation to have Available=true")
	}
}

// TestP2_9_AggregateExcludesUnavailableFromCount verifies that attestations
// with Available=false are counted in TotalCount but NOT in AvailableCount.
// Uses 4 nodes with 1 partitioned (3/4 = 0.75 ≥ 0.6667 → sufficient) so the
// aggregate is non-nil and we can inspect the counts.
//
// P1-7 note: BuildAggregateAttestation returns nil when IsSufficient()=false,
// so we can only inspect counts when the aggregate is sufficient. The
// insufficient case (2/4 → nil) is covered by TestP2_9_PartitionThenHeal_TwoNodes.
func TestP2_9_AggregateExcludesUnavailableFromCount(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0xb0)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Partition node 3 only → 3/4 = 0.75 ≥ 0.6667 → sufficient.
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
		t.Errorf("expected 3 available, got %d", availableCount)
	}

	// All 4 nodes attested (3 available + 1 unavailable). The aggregate
	// should have AvailableCount=3, TotalCount=4.
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments) // DA-R7-04: takes []KZGCommitment directly
	if agg == nil {
		t.Fatal("expected non-nil aggregate (3/4 sufficient)")
	}
	if agg.AvailableCount != 3 {
		t.Errorf("expected AvailableCount=3, got %d", agg.AvailableCount)
	}
	if agg.TotalCount != 4 {
		t.Errorf("expected TotalCount=4 (all 4 attested), got %d", agg.TotalCount)
	}
	if !agg.IsSufficient() {
		t.Error("expected IsSufficient=true for 3/4")
	}

	// Verify the unavailable attestation is in the collected set.
	atts := nodes[0].collector.GetAttestations(1)
	unavailCount := 0
	for _, a := range atts {
		if !a.Available {
			unavailCount++
		}
	}
	if unavailCount != 1 {
		t.Errorf("expected 1 unavailable attestation collected, got %d", unavailCount)
	}
}

// TestP2_9_MaliciousAvailableInflation_Rejected verifies that an attacker
// cannot inflate the AvailableCount by submitting a forged attestation with
// Available=true and a valid ValidatorIndex but invalid signature.
// The verifier checks the signature over Hash() which includes Available,
// so flipping Available after signing (or signing with wrong key) is caught.
func TestP2_9_MaliciousAvailableInflation_Rejected(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0xc0)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Node 3 is partitioned → legitimately attests Available=false.
	simulateNetworkPartition(t, nodes[3])
	att3, err := nodes[3].engine.BuildDAAttestation(1, 1, commitments, 3)
	if err != nil {
		t.Fatalf("node3 BuildDAAttestation failed: %v", err)
	}
	if att3.Available {
		t.Fatal("expected node3 Available=false (partitioned)")
	}
	signAndSubmit(t, nodes[3], nodes[0].collector, att3)

	// Attacker intercepts node 3's attestation and flips Available to true,
	// but the signature is now invalid (hash changed). SubmitAttestation
	// should reject it.
	tampered := *att3 // copy
	tampered.Available = true
	// tampered.Signature is still the original (signed over Available=false).

	err = nodes[0].collector.SubmitAttestation(&tampered)
	if err == nil {
		t.Fatal("expected SubmitAttestation to reject tampered Available=true (signature mismatch)")
	}

	// Verify node 3's original attestation (Available=false) is still the
	// one stored — the tampered submission was rejected.
	atts := nodes[0].collector.GetAttestations(1)
	for _, a := range atts {
		if a.ValidatorIndex == 3 && a.Available {
			t.Error("node 3's stored attestation should have Available=false (tampered rejected)")
		}
	}
}

// TestP2_9_ConcurrentSubmission_NoRace verifies that concurrent
// SubmitAttestation calls from multiple goroutines don't cause races or
// panics. Run with -race flag.
func TestP2_9_ConcurrentSubmission_NoRace(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 8)
	nodes := make([]*testNode, 8)
	for i := 0; i < 8; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0xd0)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

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

	atts := nodes[0].collector.GetAttestations(1)
	if len(atts) != 8 {
		t.Errorf("expected 8 attestations, got %d", len(atts))
	}

	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments) // DA-R7-04: takes []KZGCommitment directly
	if agg == nil || !agg.IsSufficient() {
		t.Error("expected 8/8 sufficient aggregate")
	}
}

// TestP2_9_NetworkPartitionThenMaliciousSubmit verifies that during a network
// partition, an attacker cannot exploit the degraded state to inject forged
// attestations. The verifier still rejects invalid signatures even when the
// network is partitioned.
func TestP2_9_NetworkPartitionThenMaliciousSubmit(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	blob := makeTestBlob(0xe0)
	commitments := processBlobsOnAllNodes(t, nodes, 1, []encoding.Blob{blob})

	// Partition node 3.
	simulateNetworkPartition(t, nodes[3])

	// Legitimate nodes 0, 1, 2 attest.
	for _, node := range nodes[:3] {
		att, err := node.engine.BuildDAAttestation(1, 1, commitments, node.index)
		if err != nil {
			t.Fatalf("node%d BuildDAAttestation failed: %v", node.index, err)
		}
		signAndSubmit(t, node, nodes[0].collector, att)
	}

	// Attacker tries to inject a forged attestation claiming to be node 3
	// with Available=true (to make it 4/4 sufficient), signed with wrong key.
	forged := makeManualAttestation(1, 3, true)
	signAttestation(t, keypairs[0].Private, forged) // wrong key

	err := nodes[0].collector.SubmitAttestation(forged)
	if err == nil {
		t.Fatal("expected SubmitAttestation to reject forged attestation during partition")
	}

	// Aggregate should have 3/3 (only legitimate attestations).
	agg := nodes[0].engine.BuildAggregateAttestation(1, commitments) // DA-R7-04: takes []KZGCommitment directly
	if agg == nil {
		t.Fatal("expected non-nil aggregate (3 legitimate attestations)")
	}
	if agg.AvailableCount != 3 || agg.TotalCount != 3 {
		t.Errorf("expected 3/3, got %d/%d", agg.AvailableCount, agg.TotalCount)
	}
}

// TestP2_9_WrongSlotAttestation_Rejected verifies that an attestation for a
// different slot is not mixed into the current slot's aggregate. This is
// implicitly enforced by the collector's per-slot map structure.
//
// DA-R5-07 (2026-07-17): IsSufficient() requires TotalCount >= ceil(2/3 ·
// CommitteeSize). With CommitteeSize=4, the floor is 3. We submit 3
// attestations for slot 5 (validators 0,1,2) and 3 for slot 10 (validators
// 0,1,3) to meet the floor. The test verifies that slot 5's aggregate
// contains exactly the 3 slot-5 attestations and slot 10's contains exactly
// the 3 slot-10 attestations — no cross-slot mixing.
func TestP2_9_WrongSlotAttestation_Rejected(t *testing.T) {
	validators, keypairs := makeIntegrationValidators(t, 4)
	nodes := make([]*testNode, 4)
	for i := 0; i < 4; i++ {
		nodes[i] = newTestNode(t, i, validators, keypairs)
	}
	wireMockP2P(nodes)
	startAllNodes(t, nodes)
	defer stopAllNodes(nodes)

	// Submit 3 attestations for slot 5 (validators 0, 1, 2).
	for i := 0; i < 3; i++ {
		att := makeManualAttestation(5, i, true)
		signAttestation(t, keypairs[i].Private, att)
		if err := nodes[0].collector.SubmitAttestation(att); err != nil {
			t.Fatalf("SubmitAttestation for slot 5 validator %d failed: %v", i, err)
		}
	}

	// Submit 3 attestations for slot 10 (validators 0, 1, 3).
	for _, i := range []int{0, 1, 3} {
		att := makeManualAttestation(10, i, true)
		signAttestation(t, keypairs[i].Private, att)
		if err := nodes[0].collector.SubmitAttestation(att); err != nil {
			t.Fatalf("SubmitAttestation for slot 10 validator %d failed: %v", i, err)
		}
	}

	// Slot 5 aggregate should have exactly 3 attestations (validators 0,1,2).
	agg5 := nodes[0].engine.BuildAggregateAttestation(5, []encoding.KZGCommitment{{}}) // DA-R7-04: KZGCommitment
	if agg5 == nil {
		t.Fatal("expected non-nil aggregate for slot 5 (3/4 meets DA-R5-07 floor)")
	}
	if agg5.TotalCount != 3 {
		t.Errorf("slot 5: expected TotalCount=3, got %d", agg5.TotalCount)
	}

	// Slot 10 aggregate should have exactly 3 attestations (validators 0,1,3).
	agg10 := nodes[0].engine.BuildAggregateAttestation(10, []encoding.KZGCommitment{{}}) // DA-R7-04: KZGCommitment
	if agg10 == nil {
		t.Fatal("expected non-nil aggregate for slot 10 (3/4 meets DA-R5-07 floor)")
	}
	if agg10.TotalCount != 3 {
		t.Errorf("slot 10: expected TotalCount=3, got %d", agg10.TotalCount)
	}

	// Slot 99 should have no attestations → nil aggregate.
	agg99 := nodes[0].engine.BuildAggregateAttestation(99, []encoding.KZGCommitment{{}}) // DA-R7-04: KZGCommitment
	if agg99 != nil {
		t.Error("expected nil aggregate for slot 99 (no attestations)")
	}
}
