// Quantaureum Node source, version 1.0.0.
package trie

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// TestR37_P3_07_VerifyExclusionEvidence_StemLenBounds verifies that a
// negative (or oversized) ExtensionStemLen is rejected instead of causing
// a slice-bounds panic on stem[forkDepth:forkDepth+ExtensionStemLen].
func TestR37_P3_07_VerifyExclusionEvidence_StemLenBounds(t *testing.T) {
	key := make([]byte, VerkleKeySize)
	key[0] = 0x01

	ev := &ExclusionEvidence{
		Type:             ExclusionTypeExtensionMismatch,
		ExtensionStemLen: -1, // negative — must be rejected, not panic
		ExtensionChild:   types.Hash{0x09},
	}
	ev.ExtensionStem[0] = 0x02
	extHash := defaultHasher.HashExtension(ev.ExtensionStem, ev.ExtensionChild)

	proof := &VerkleProof{
		Key:               key,
		Path:              []types.Hash{extHash},
		ExclusionEvidence: ev,
	}
	if proof.verifyExclusion(extHash) {
		t.Fatal("negative ExtensionStemLen accepted")
	}

	// Oversized StemLen must also be rejected.
	ev.ExtensionStemLen = StemSize + 1
	if proof.verifyExclusion(extHash) {
		t.Fatal("oversized ExtensionStemLen accepted")
	}
}

// TestR37_P3_09_VerkleTree_PutGetDefensiveCopies verifies the bidirectional
// slice-aliasing fix: Put must copy key/value into the tree, and Get must
// return a copy the caller cannot use to mutate tree state.
func TestR37_P3_09_VerkleTree_PutGetDefensiveCopies(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	origKey := make([]byte, VerkleKeySize)
	origKey[0] = 0x11
	origKey[31] = 0x07
	key := append([]byte(nil), origKey...)
	val := []byte{0x01, 0x02, 0x03}

	if err := tree.Put(key, val); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Mutate the caller's slices after Put — tree state must be unaffected.
	key[0] = 0xFF
	val[0] = 0xFF

	got, err := tree.Get(origKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("tree state corrupted via caller slice: got %x", got)
	}

	// Mutate the returned slice — the tree must be unaffected on re-read.
	got[0] = 0xAA
	got2, err := tree.Get(origKey)
	if err != nil {
		t.Fatalf("Get #2: %v", err)
	}
	if !bytes.Equal(got2, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("tree state corrupted via returned slice: got %x", got2)
	}
}

// TestR37_P3_09_VerkleTree_SuffixValueDefensiveCopy verifies the defensive
// copy on the suffix-value path (same 31-byte stem, different suffix byte).
func TestR37_P3_09_VerkleTree_SuffixValueDefensiveCopy(t *testing.T) {
	tree := NewVerkleTree(MaxTreeDepth)

	// Two keys sharing the same 31-byte stem, differing in the suffix byte.
	keyA := make([]byte, VerkleKeySize)
	keyA[0] = 0x22
	keyA[31] = 0x01
	keyB := append([]byte(nil), keyA...)
	keyB[31] = 0x02

	valA := []byte{0x0A}
	valB := []byte{0x0B}
	if err := tree.Put(keyA, valA); err != nil {
		t.Fatalf("Put A: %v", err)
	}
	if err := tree.Put(keyB, valB); err != nil {
		t.Fatalf("Put B: %v", err)
	}
	// Mutate the caller's slice for the suffix entry.
	valB[0] = 0xFF

	got, err := tree.Get(keyB)
	if err != nil {
		t.Fatalf("Get B: %v", err)
	}
	if !bytes.Equal(got, []byte{0x0B}) {
		t.Fatalf("suffix value corrupted via caller slice: got %x", got)
	}
	got[0] = 0xEE
	got2, err := tree.Get(keyB)
	if err != nil {
		t.Fatalf("Get B #2: %v", err)
	}
	if !bytes.Equal(got2, []byte{0x0B}) {
		t.Fatalf("suffix value corrupted via returned slice: got %x", got2)
	}
}

// TestR37_P3_10_Import_TruncatedCodeKeySkipped verifies that a code key
// shorter than types.HashLength is skipped entirely — previously it was
// zero-padded into an arbitrary codeHash, allowing a crafted dump to
// overwrite legitimate contract code.
func TestR37_P3_10_Import_TruncatedCodeKeySkipped(t *testing.T) {
	state := NewVerkleStateDB()

	truncated := "code:" + string(make([]byte, 10))
	if err := state.Import(map[string][]byte{truncated: []byte("evil-code")}); err != nil {
		t.Fatalf("Import: %v", err)
	}
	if state.GetCodeCount() != 0 {
		t.Fatalf("truncated code key imported; codeDB size = %d", state.GetCodeCount())
	}
	var padded types.Hash // the zero-padded 10-byte key would map here
	if _, err := state.GetCode(padded); err == nil {
		t.Fatal("zero-padded codeHash unexpectedly present")
	}
}

// TestR37_P3_10_Deserialize_ReplaceNotMerge verifies that Deserialize
// replaces (not merges) state: stale entries from prior state must not
// survive the import.
func TestR37_P3_10_Deserialize_ReplaceNotMerge(t *testing.T) {
	src := NewVerkleStateDB()
	addr := types.Address{0x01}
	if err := src.SetAccount(addr, []byte("acct-data")); err != nil {
		t.Fatalf("SetAccount: %v", err)
	}
	data, err := src.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	dst := NewVerkleStateDB()
	staleAddr := types.Address{0x02}
	if err := dst.SetAccount(staleAddr, []byte("stale")); err != nil {
		t.Fatalf("SetAccount stale: %v", err)
	}
	dst.SetCode([]byte("stale-code"))

	if err := dst.Deserialize(data); err != nil {
		t.Fatalf("Deserialize: %v", err)
	}

	// Replace-style import: stale entries must be gone.
	if _, err := dst.GetAccount(staleAddr); err == nil {
		t.Fatal("stale account survived import (merge-style regression)")
	}
	if dst.GetCodeCount() != 0 {
		t.Fatalf("stale code survived import; codeDB size = %d", dst.GetCodeCount())
	}

	// The imported account must be present and intact.
	got, err := dst.GetAccount(addr)
	if err != nil {
		t.Fatalf("imported account missing: %v", err)
	}
	if string(got) != "acct-data" {
		t.Fatalf("imported account data = %q, want %q", got, "acct-data")
	}
}

// TestR37_P3_11_IPAProofFromBytes_TruncatedCommitment verifies that a
// proof whose trailing commitment is truncated returns an error instead of
// panicking on a slice-bounds violation.
func TestR37_P3_11_IPAProofFromBytes_TruncatedCommitment(t *testing.T) {
	const numRounds = 1
	base := 4 + numRounds*PedersenPointSize*2
	// Valid L/R section followed by a truncated trailing commitment
	// (one byte short).
	data := make([]byte, base+PedersenPointSize-1)
	binary.BigEndian.PutUint32(data[:4], uint32(numRounds))
	if _, err := IPAProofFromBytes(data); err == nil {
		t.Fatal("expected error for truncated commitment, got nil")
	}
}

// failBatch wraps a Batch and forces Write to fail, simulating an I/O
// error during VerkleTree.Flush.
type failBatch struct{ db.Batch }

func (failBatch) Write() error { return errors.New("injected write failure") }

// TestR37_P3_13_Commit_BestEffortFlushOnFailure verifies the cross-tree
// flush defense: Commit must surface the first flush failure AND still
// flush the remaining trees (best-effort convergence of on-disk state).
func TestR37_P3_13_Commit_BestEffortFlushOnFailure(t *testing.T) {
	state := NewVerkleStateDB()

	// Storage tree whose flush fails (injected I/O error).
	badMem := db.NewMemDB()
	bad := NewVerkleTree(MaxTreeDepth)
	bad.persistentDB = badMem
	bad.pendingBatch = failBatch{badMem.NewBatch()}

	// Storage tree whose flush succeeds and must still be flushed even
	// though the sibling tree failed.
	goodMem := db.NewMemDB()
	good := NewVerkleTree(MaxTreeDepth)
	good.persistentDB = goodMem
	good.pendingBatch = goodMem.NewBatch()
	if err := good.pendingBatch.Put([]byte("vnode:marker"), []byte("v")); err != nil {
		t.Fatalf("seed pending batch: %v", err)
	}

	state.storage["bad"] = bad
	state.storage["good"] = good

	if _, err := state.Commit(); err == nil {
		t.Fatal("Commit must surface the storage flush failure")
	} else if !strings.Contains(err.Error(), "storage tree bad") {
		t.Fatalf("Commit error = %v, want storage tree failure", err)
	}

	// Best-effort: the good tree's pending batch must have been written
	// despite the bad tree's failure.
	got, err := goodMem.Get([]byte("vnode:marker"))
	if err != nil || string(got) != "v" {
		t.Fatalf("good storage tree not flushed after sibling failure: got=%q err=%v", got, err)
	}
}
