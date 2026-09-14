// Quantaureum Node source, version 1.0.0.
package bridge

import (
	"context"
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestBRDG_R5_05_NewMerkleTreeFromMessages_LeafBindsPayload verifies that the
// payload-bound Merkle tree constructor produces leaves that depend on the
// full message payload, not just the message ID.
//
// AUDIT (2026 security review) BRDG-R5-05 (Medium / LATENT):
// The legacy NewMerkleTree(msgIDs []string) produced leaves via
// hashLeaf([]byte(id)), so a Merkle membership proof attested only "this ID
// was committed" — not "this ID corresponds to this amount/recipient/data".
// Two distinct payloads sharing an ID would produce identical leaves,
// allowing proof reuse across payloads. NewMerkleTreeFromMessages fixes
// this by setting each leaf to hashLeafMessage(msg) = hashLeaf(computeMessageHash(msg)),
// which covers ID + chains + addresses + asset + amount + nonce + timestamp
// + execution-control fields.
//
// This test confirms: two messages with the SAME ID but DIFFERENT payload
// produce DIFFERENT leaf hashes (and therefore different roots), defeating
// payload substitution.
func TestBRDG_R5_05_NewMerkleTreeFromMessages_LeafBindsPayload(t *testing.T) {
	base := &BridgeMessage{
		ID:            "msg-1",
		SourceChain:   "quantaureum",
		TargetChain:   "ethereum",
		SourceAddress: "0xSrc",
		TargetAddress: "0xDst",
		AssetType:     "ERC20",
		AssetID:       "0xAsset",
		Amount:        "100",
		Nonce:         1,
		Timestamp:     1000,
		MessageType:   "transfer",
	}
	tampered := *base
	tampered.Amount = "999" // payload tampering — same ID, different amount

	leafBase := hashLeafMessage(base)
	leafTampered := hashLeafMessage(&tampered)

	if leafBase == leafTampered {
		t.Fatal("BRDG-R5-05: hashLeafMessage produced identical hashes for distinct payloads sharing an ID — payload substitution NOT defeated")
	}

	tree1, err := NewMerkleTreeFromMessages([]*BridgeMessage{base})
	if err != nil {
		t.Fatalf("NewMerkleTreeFromMessages(base): %v", err)
	}
	tree2, err := NewMerkleTreeFromMessages([]*BridgeMessage{&tampered})
	if err != nil {
		t.Fatalf("NewMerkleTreeFromMessages(tampered): %v", err)
	}
	if tree1.Root() == tree2.Root() {
		t.Fatal("BRDG-R5-05: trees with payloads differing only in Amount produced identical roots — payload binding failed")
	}
}

// TestBRDG_R5_05_NewMerkleTreeFromMessages_RejectsDuplicatePayloads verifies
// that two messages with the same payload (computeMessageHash collision)
// are rejected at construction. This preserves the CVE-2012-2459 defense:
// duplicate leaves enable duplicate-last root malleability and break proof
// generation for the second occurrence.
func TestBRDG_R5_05_NewMerkleTreeFromMessages_RejectsDuplicatePayloads(t *testing.T) {
	msg := &BridgeMessage{
		ID:            "msg-1",
		SourceChain:   "quantaureum",
		TargetChain:   "ethereum",
		SourceAddress: "0xSrc",
		TargetAddress: "0xDst",
		AssetType:     "ERC20",
		AssetID:       "0xAsset",
		Amount:        "100",
		Nonce:         1,
		Timestamp:     1000,
		MessageType:   "transfer",
	}
	// Identical payload (same nonce etc.) — should be rejected.
	dup := *msg

	_, err := NewMerkleTreeFromMessages([]*BridgeMessage{msg, &dup})
	if err == nil {
		t.Fatal("BRDG-R5-05: expected error for duplicate payloads, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate message payload") {
		t.Errorf("BRDG-R5-05: expected 'duplicate message payload' error, got: %v", err)
	}
}

// TestBRDG_R5_05_NewMerkleTreeFromMessages_AcceptsSameIDDifferentPayload
// verifies that two messages with the SAME ID but DIFFERENT payload are
// accepted (because their payload-bound leaves differ). This is the
// legitimate case the legacy constructor could not represent.
func TestBRDG_R5_05_NewMerkleTreeFromMessages_AcceptsSameIDDifferentPayload(t *testing.T) {
	msg1 := &BridgeMessage{
		ID:            "msg-shared",
		SourceChain:   "quantaureum",
		TargetChain:   "ethereum",
		SourceAddress: "0xSrc",
		TargetAddress: "0xDst",
		AssetType:     "ERC20",
		AssetID:       "0xAsset",
		Amount:        "100",
		Nonce:         1,
		Timestamp:     1000,
		MessageType:   "transfer",
	}
	msg2 := *msg1
	msg2.Amount = "200" // different payload, same ID

	tree, err := NewMerkleTreeFromMessages([]*BridgeMessage{msg1, &msg2})
	if err != nil {
		t.Fatalf("BRDG-R5-05: same-ID-different-payload should be accepted, got: %v", err)
	}
	var zero types.Hash
	if tree.Root() == zero {
		t.Error("BRDG-R5-05: 2-leaf tree root should not be zero")
	}
}

// TestBRDG_R5_05_NewMerkleTreeFromMessages_RejectsNilMessage verifies that
// nil messages are rejected at construction (defensive — a nil msg would
// panic in computeMessageHash).
func TestBRDG_R5_05_NewMerkleTreeFromMessages_RejectsNilMessage(t *testing.T) {
	_, err := NewMerkleTreeFromMessages([]*BridgeMessage{nil})
	if err == nil {
		t.Fatal("BRDG-R5-05: expected error for nil message, got nil")
	}
	if !strings.Contains(err.Error(), "nil") {
		t.Errorf("BRDG-R5-05: expected nil-message error, got: %v", err)
	}
}

// TestBRDG_R5_05_NewMerkleTreeFromMessages_EmptyAndSingleLeaf verifies the
// edge cases that must not be broken by the new constructor.
func TestBRDG_R5_05_NewMerkleTreeFromMessages_EmptyAndSingleLeaf(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		tree, err := NewMerkleTreeFromMessages(nil)
		if err != nil {
			t.Fatalf("empty input should not error: %v", err)
		}
		var zero types.Hash
		if tree.Root() != zero {
			t.Errorf("empty tree root should be zero hash, got %x", tree.Root())
		}
	})

	t.Run("single_leaf", func(t *testing.T) {
		msg := &BridgeMessage{ID: "only-msg", Amount: "1", Nonce: 1, Timestamp: 1}
		tree, err := NewMerkleTreeFromMessages([]*BridgeMessage{msg})
		if err != nil {
			t.Fatalf("single leaf should not error: %v", err)
		}
		var zero types.Hash
		if tree.Root() == zero {
			t.Error("single-leaf tree root should not be zero")
		}
	})
}

// TestBRDG_R5_05_NewMerkleTreeFromMessages_LegacyLeafDiffersFromPayloadLeaf
// verifies that the legacy hashLeaf([]byte(id)) leaf differs from the
// payload-bound hashLeafMessage(msg) leaf. This is the mathematical
// guarantee that the legacy constructor's leaves will be rejected by
// verifyMessageInclusion's new expectedLeaf check.
func TestBRDG_R5_05_NewMerkleTreeFromMessages_LegacyLeafDiffersFromPayloadLeaf(t *testing.T) {
	msg := &BridgeMessage{
		ID:            "msg-1",
		SourceChain:   "quantaureum",
		TargetChain:   "ethereum",
		SourceAddress: "0xSrc",
		TargetAddress: "0xDst",
		AssetType:     "ERC20",
		AssetID:       "0xAsset",
		Amount:        "100",
		Nonce:         1,
		Timestamp:     1000,
		MessageType:   "transfer",
	}
	legacyLeaf := hashLeaf([]byte(msg.ID))
	payloadLeaf := hashLeafMessage(msg)

	if legacyLeaf == payloadLeaf {
		t.Fatal("BRDG-R5-05: legacy ID-only leaf equals payload-bound leaf — verifyMessageInclusion cannot distinguish them, the fix is broken")
	}
}

// TestBRDG_R5_05_CommitMessagesByPayload_ProducesPayloadBoundTree verifies
// the end-to-end commit + proof + verify path on ExternalChainAdapter using
// the new payload-bound API.
func TestBRDG_R5_05_CommitMessagesByPayload_ProducesPayloadBoundTree(t *testing.T) {
	adapter := NewExternalChainAdapter("ethereum", "http://localhost:8546", "", 10, "0xInit").(*ExternalChainAdapter)
	if err := adapter.SetGovernanceAddress("0xGov", "0xInit"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}

	msg := &BridgeMessage{
		ID:            "msg-1",
		SourceChain:   "quantaureum",
		TargetChain:   "ethereum",
		SourceAddress: "0xSrc",
		TargetAddress: "0xDst",
		AssetType:     "ERC20",
		AssetID:       "0xAsset",
		Amount:        "100",
		Nonce:         1,
		Timestamp:     1000,
		MessageType:   "transfer",
	}

	root, err := adapter.CommitMessagesByPayload([]*BridgeMessage{msg}, "0xGov")
	if err != nil {
		t.Fatalf("CommitMessagesByPayload: %v", err)
	}
	if adapter.GetMerkleRoot() != root {
		t.Fatal("BRDG-R5-05: GetMerkleRoot mismatch after CommitMessagesByPayload")
	}

	// Verify the tree's leaf is the payload-bound hash (not the legacy ID hash).
	expectedLeaf := hashLeafMessage(msg)
	if len(adapter.messageTree.leaves) != 1 || adapter.messageTree.leaves[0] != expectedLeaf {
		t.Fatalf("BRDG-R5-05: tree leaf is not payload-bound. got=%v want=%v",
			adapter.messageTree.leaves, expectedLeaf)
	}

	// Generate a proof via the new API and confirm it matches the leaf.
	proofBytes, err := adapter.GetMessageProofByPayload(context.Background(), msg)
	if err != nil {
		t.Fatalf("GetMessageProofByPayload: %v", err)
	}
	proof, err := DecodeMerkleProof(proofBytes)
	if err != nil {
		t.Fatalf("DecodeMerkleProof: %v", err)
	}
	if proof.LeafHash != expectedLeaf {
		t.Fatalf("BRDG-R5-05: proof leaf hash does not match payload-bound leaf. got=%v want=%v",
			proof.LeafHash, expectedLeaf)
	}
}

// TestBRDG_R5_05_LegacyCommitMessages_ProducesIDOnlyLeaf verifies that the
// legacy CommitMessages([]string) overload still produces ID-only leaves
// (which verifyMessageInclusion will now REJECT). This test documents the
// deprecation: callers must migrate to CommitMessagesByPayload.
func TestBRDG_R5_05_LegacyCommitMessages_ProducesIDOnlyLeaf(t *testing.T) {
	adapter := NewExternalChainAdapter("ethereum", "http://localhost:8546", "", 10, "0xInit").(*ExternalChainAdapter)
	if err := adapter.SetGovernanceAddress("0xGov", "0xInit"); err != nil {
		t.Fatalf("SetGovernanceAddress: %v", err)
	}

	msgID := "msg-legacy"
	root, err := adapter.CommitMessages([]string{msgID}, "0xGov")
	if err != nil {
		t.Fatalf("CommitMessages (legacy): %v", err)
	}

	msg := &BridgeMessage{
		ID:            msgID,
		SourceChain:   "quantaureum",
		TargetChain:   "ethereum",
		SourceAddress: "0xSrc",
		TargetAddress: "0xDst",
		AssetType:     "ERC20",
		AssetID:       "0xAsset",
		Amount:        "100",
		Nonce:         1,
		Timestamp:     1000,
		MessageType:   "transfer",
	}

	// Tree leaf should be the legacy ID-only hash, NOT the payload-bound hash.
	legacyLeaf := hashLeaf([]byte(msgID))
	payloadLeaf := hashLeafMessage(msg)
	if adapter.messageTree.leaves[0] != legacyLeaf {
		t.Fatalf("BRDG-R5-05: legacy constructor should produce ID-only leaf. got=%v want=%v",
			adapter.messageTree.leaves[0], legacyLeaf)
	}
	if adapter.messageTree.leaves[0] == payloadLeaf {
		t.Fatal("BRDG-R5-05: legacy constructor unexpectedly produced a payload-bound leaf — deprecation contract broken")
	}
	_ = root // root exists, but verifyMessageInclusion would reject its proofs
}
