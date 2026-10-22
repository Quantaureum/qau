// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// R6-05 (2026-10-21 sixth-round audit): eth_getProof used to run storage slots
// through StateDB.ProveStorage and attach the result as if it were the same kind
// of verified material the account path produces. It is not: committed storage
// never enters the Verkle state trie on this node (StateDB.Commit writes slots to
// BoltDB only, and every stateTrie.Put key is an account address), so
// ProveStorage can only ever answer with an EXCLUSION proof — proof that the slot
// is absent from the very structure the reported non-zero value is supposed to
// live in. The result-level Unverified flag did not reflect any of that, because
// it was computed from the account proof alone.
//
// These tests pin the honest labelling: storage entries are always marked
// unverified, and a response that carries storage invalidates itself at the top
// level so a caller that only checks one flag refuses it instead of trusting it.

func TestR6_05_GetProofMarksStorageEntriesUnverified(t *testing.T) {
	api := NewProofAPI(&r38P2_04DeepBlockReader{}, &r38P2_04DeepStateReader{})

	// Baseline: the account path is state-root-bound on this reader, so a
	// storage-free response keeps the R38-P2-04 guarantee (Unverified=false).
	res, err := api.GetProof("0x1234567890abcdef1234567890abcdef12345678", nil, "latest")
	if err != nil {
		t.Fatalf("GetProof without storage keys: %v", err)
	}
	if res.Unverified {
		t.Fatal("R38-P2-04 regression: a state-root-bound account proof must not be flagged unverified")
	}

	slot := "0x" + (&types.Hash{0x10, 0x20}).String()
	res, err = api.GetProof("0x1234567890abcdef1234567890abcdef12345678", []string{slot}, "latest")
	if err != nil {
		t.Fatalf("GetProof with a storage key: %v", err)
	}
	if len(res.StorageProof) != 1 {
		t.Fatalf("got %d storage entries, want 1", len(res.StorageProof))
	}
	if !res.StorageProof[0].Unverified {
		t.Fatal("a storage entry was labelled verified although no state-root-bound storage proof exists on this node")
	}
	if !res.Unverified {
		t.Fatal("GetProof returned Unverified=false for a response that contains storage — a caller checking only the top-level flag would trust a claim this node cannot prove")
	}
	if res.StorageProof[0].Key != slot {
		t.Fatalf("storage entry key = %q, want %q", res.StorageProof[0].Key, slot)
	}
}
