// Quantaureum Node source, version 1.0.0.
package core

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestComputeReceiptRoot_EmptyReturnsNonZeroRoot pins the Ethereum-compatible
// behavior: an empty receipt set must yield the canonical non-zero empty trie
// root, NOT the zero hash. This is what lets a transaction-less block carry a
// valid ReceiptRoot so the R38-P1-08 zero-presence guard does not reject it
// during sync. Previously ComputeReceiptRoot([]) returned types.Hash{}, which
// made every empty block fail the sync fail-closed check and stall the chain.
func TestComputeReceiptRoot_EmptyReturnsNonZeroRoot(t *testing.T) {
	root := ComputeReceiptRoot(nil)
	if root == (types.Hash{}) {
		t.Fatal("ComputeReceiptRoot(nil) must return a non-zero root (Ethereum empty trie root), got zero hash")
	}
	want := types.Hash{
		0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6,
		0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
		0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0,
		0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
	}
	if root != want {
		t.Fatalf("ComputeReceiptRoot(nil) = %x, want canonical empty trie root %x", root, want)
	}
}

// TestComputeReceiptRoot_WithReceiptsDiffersFromEmpty ensures a block with
// receipts computes a different root than the empty root, so the empty-root
// constant never collides with a real receipt set.
func TestComputeReceiptRoot_WithReceiptsDiffersFromEmpty(t *testing.T) {
	empty := ComputeReceiptRoot(nil)
	withReceipts := ComputeReceiptRoot([]types.Hash{{0x01}})
	if withReceipts == (types.Hash{}) {
		t.Fatal("ComputeReceiptRoot with a receipt must be non-zero")
	}
	if withReceipts == empty {
		t.Fatal("ComputeReceiptRoot with a receipt must differ from the empty root")
	}
}
