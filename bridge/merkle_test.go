// Quantaureum Node source, version 1.0.0.
package bridge

import (
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestR4DATA08_NewMerkleTree_RejectsDuplicateMsgIDs verifies that the bridge
// Merkle tree builder rejects duplicate message IDs at construction. This is
// the active defense against CVE-2012-2459 (duplicate-last malleability) for
// the bridge path, where message IDs are externally provided and are NOT
// protected by blockchain nonce uniqueness (unlike transaction hashes).
func TestR4DATA08_NewMerkleTree_RejectsDuplicateMsgIDs(t *testing.T) {
	msgIDs := []string{"msg-1", "msg-2", "msg-3", "msg-2"} // msg-2 duplicated

	_, err := NewMerkleTree(msgIDs)
	if err == nil {
		t.Fatal("expected error for duplicate message IDs, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate message ID") {
		t.Errorf("expected duplicate message ID error, got: %v", err)
	}
}

// TestR4DATA08_NewMerkleTree_AcceptsDistinctMsgIDs verifies that distinct
// message IDs are accepted (no false positives from the dedup check).
func TestR4DATA08_NewMerkleTree_AcceptsDistinctMsgIDs(t *testing.T) {
	msgIDs := []string{"msg-1", "msg-2", "msg-3", "msg-4"}

	tree, err := NewMerkleTree(msgIDs)
	if err != nil {
		t.Fatalf("distinct message IDs should be accepted, got error: %v", err)
	}
	if tree == nil {
		t.Fatal("NewMerkleTree returned nil tree for valid input")
	}
	var zero types.Hash
	if tree.Root() == zero {
		t.Error("4-leaf tree root should not be zero hash")
	}
}

// TestR4DATA08_NewMerkleTree_EmptyAndSingleLeaf verifies edge cases that must
// not be broken by the dedup check.
func TestR4DATA08_NewMerkleTree_EmptyAndSingleLeaf(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		tree, err := NewMerkleTree(nil)
		if err != nil {
			t.Fatalf("empty input should not error: %v", err)
		}
		var zero types.Hash
		if tree.Root() != zero {
			t.Errorf("empty tree root should be zero hash, got %x", tree.Root())
		}
	})

	t.Run("single_leaf", func(t *testing.T) {
		tree, err := NewMerkleTree([]string{"only-msg"})
		if err != nil {
			t.Fatalf("single leaf should not error: %v", err)
		}
		// Single leaf: root should be the leaf hash itself (see buildTree).
		var zero types.Hash
		if tree.Root() == zero {
			t.Error("single-leaf tree root should not be zero")
		}
	})
}
