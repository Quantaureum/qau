// Quantaureum Node source, version 1.0.0.
package lightclient

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/qaudb/trie"
	"github.com/quantaureum/qau/types"
)

// R6-04 (2026-10-21 sixth-round audit): the wire format carried Key, Value,
// Path and Siblings only, while VerkleProof.Verify also reads IsExclusion,
// ExtensionStems, StemHash, InclusionLeaf and ExclusionEvidence. A proof that
// verified on the prover's node therefore arrived at the light client in a shape
// that could not verify -- exactly what a serialized proof must never do. These
// tests pin full-fidelity round-tripping, and the fail-closed behaviour on
// anything the decoder cannot fully account for.

func u32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func TestR6_04_InclusionProofSurvivesTheWire(t *testing.T) {
	sdb, root := newProvedStateDB(t)
	addr := types.Address{0xa1, 0xb2}

	original, err := sdb.ProveAccount(addr)
	if err != nil {
		t.Fatalf("ProveAccount: %v", err)
	}
	if !trie.VerifyProof(root, original) {
		t.Fatal("fixture drift: the live trie no longer produces a verifiable inclusion proof")
	}
	if original.IsExclusion || len(original.InclusionLeaf) == 0 {
		t.Fatalf("fixture drift: expected an inclusion proof with leaf material (IsExclusion=%v leaf=%d bytes)",
			original.IsExclusion, len(original.InclusionLeaf))
	}

	encoded := marshalVerkleProof(original)
	if len(encoded) == 0 || encoded[0] != verkleProofWireVersion {
		t.Fatalf("encoded proof = %d bytes (version byte %v)", len(encoded), encoded[:1])
	}

	restored := unmarshalVerkleProof(encoded)
	if restored == nil {
		t.Fatal("unmarshalVerkleProof rejected a proof this node just produced")
	}
	if !bytes.Equal(restored.Key, original.Key) || !bytes.Equal(restored.Value, original.Value) {
		t.Fatal("key/value did not round-trip")
	}
	if restored.IsExclusion != original.IsExclusion || restored.StemHash != original.StemHash {
		t.Fatal("IsExclusion/StemHash were dropped by the codec")
	}
	if !bytes.Equal(restored.InclusionLeaf, original.InclusionLeaf) {
		t.Fatal("InclusionLeaf was dropped; a suffix-indexed leaf cannot be recomputed without it")
	}
	if len(restored.ExtensionStems) != len(original.ExtensionStems) {
		t.Fatalf("ExtensionStems = %d, want %d", len(restored.ExtensionStems), len(original.ExtensionStems))
	}
	for i := range original.ExtensionStems {
		if restored.ExtensionStems[i] != original.ExtensionStems[i] {
			t.Fatalf("ExtensionStems[%d] = %+v, want %+v", i, restored.ExtensionStems[i], original.ExtensionStems[i])
		}
	}

	// The invariant that matters to a light client: the verification outcome is
	// the same on both sides of the wire.
	if !trie.VerifyProof(root, restored) {
		t.Fatal("the deserialized proof does not verify against the root the original verified against")
	}
	if got := unmarshalVerkleProof(encoded); got == nil {
		t.Fatal("decoding is not deterministic")
	}
}

func TestR6_04_ExclusionProofSurvivesTheWire(t *testing.T) {
	sdb, root := newProvedStateDB(t)

	// An address that was never funded: the trie must answer with exclusion
	// evidence, and that evidence is precisely what the old codec threw away.
	original, err := sdb.ProveAccount(types.Address{0xde, 0xad, 0xbe, 0xef})
	if err != nil {
		t.Fatalf("ProveAccount: %v", err)
	}
	if !original.IsExclusion {
		t.Fatal("fixture drift: an absent account produced an inclusion proof")
	}
	if original.ExclusionEvidence == nil {
		t.Fatal("fixture drift: the trie produced an exclusion without evidence; the light client has nothing to check")
	}

	restored := unmarshalVerkleProof(marshalVerkleProof(original))
	if restored == nil {
		t.Fatal("unmarshalVerkleProof rejected a real exclusion proof")
	}
	if !restored.IsExclusion {
		t.Fatal("IsExclusion was lost across the wire")
	}
	if restored.ExclusionEvidence == nil {
		t.Fatal("ExclusionEvidence was dropped; the proof claims absence without the fork-point data that backs it")
	}
	if restored.ExclusionEvidence.Type != original.ExclusionEvidence.Type ||
		restored.ExclusionEvidence.ExtensionStem != original.ExclusionEvidence.ExtensionStem ||
		restored.ExclusionEvidence.ExtensionChild != original.ExclusionEvidence.ExtensionChild ||
		!bytes.Equal(restored.ExclusionEvidence.EncodedLeaf, original.ExclusionEvidence.EncodedLeaf) {
		t.Fatal("ExclusionEvidence did not round-trip field-for-field")
	}
	if !trie.VerifyProof(root, original) {
		t.Fatal("fixture drift: the trie's own exclusion proof does not verify against the live root")
	}
	if !trie.VerifyProof(root, restored) {
		t.Fatal("the exclusion proof stopped verifying after one encode/decode cycle")
	}
}

func TestR6_04_MalformedEncodingsDecodeToNil(t *testing.T) {
	sdb, _ := newProvedStateDB(t)
	original, err := sdb.ProveAccount(types.Address{0xa1, 0xb2})
	if err != nil {
		t.Fatalf("ProveAccount: %v", err)
	}
	encoded := marshalVerkleProof(original)

	// Any prefix of a valid encoding must be refused, not partially decoded: a
	// half-restored proof would still be handed to VerifyProof.
	for i := 0; i < len(encoded); i++ {
		if got := unmarshalVerkleProof(encoded[:i]); got != nil {
			t.Fatalf("a %d-byte prefix of a %d-byte encoding decoded into a %d-level proof", i, len(encoded), len(got.Path))
		}
	}

	// Trailing bytes mean the peers disagree about the format.
	trailing := append(append([]byte{}, encoded...), 0x00)
	if got := unmarshalVerkleProof(trailing); got != nil {
		t.Fatal("a proof with one trailing byte decoded")
	}

	// Version 1 (no version byte) carried proofs that could not be verified; it
	// must not be half-decoded into the new shape.
	v1 := append([]byte{0x01}, encoded[1:]...)
	if got := unmarshalVerkleProof(v1); got != nil {
		t.Fatal("a version-1 encoding was decoded")
	}
	if got := unmarshalVerkleProof(encoded[1:]); got != nil {
		t.Fatal("an untagged encoding was decoded")
	}
	if got := unmarshalVerkleProof(nil); got != nil {
		t.Fatal("a nil encoding was decoded")
	}

	// A leaf-length field beyond the trie's own proof budget must be refused
	// before the allocation happens.
	bloat := []byte{verkleProofWireVersion}
	bloat = append(bloat, u32(0)...)           // key length
	bloat = append(bloat, u32(0)...)           // value length
	bloat = append(bloat, u32(0)...)           // path count
	bloat = append(bloat, u32(0)...)           // siblings count
	bloat = append(bloat, u32(0)...)           // extension stem count
	bloat = append(bloat, 0)                   // isExclusion
	bloat = append(bloat, make([]byte, 32)...) // stem hash
	bloat = append(bloat, u32(uint32(trie.MaxProofTotalBytes)+1)...)
	bloat = append(bloat, []byte("x")...)
	if got := unmarshalVerkleProof(bloat); got != nil {
		t.Fatal("an oversized InclusionLeaf length prefix was accepted")
	}

	// IPA-backed proofs are refused by trie.VerkleProof.Verify (the verifier is a
	// stub), so the encoder must not ship them at all.
	withCommitments := *original
	withCommitments.Commitments = []types.Hash{{1}}
	if got := marshalVerkleProof(&withCommitments); got != nil {
		t.Fatal("marshalVerkleProof encoded a proof the verifier fails closed on")
	}
	if got := marshalVerkleProof(nil); got != nil {
		t.Fatal("marshalVerkleProof(nil) returned bytes")
	}
}

func TestR6_04_StateProofEnvelopeRoundTrips(t *testing.T) {
	sdb, root := newProvedStateDB(t)
	addr := types.Address{0xa1, 0xb2}
	prover := NewSPVProver(nil, sdb)

	proof, err := prover.GenerateStateProof(addr, nil)
	if err != nil {
		t.Fatalf("GenerateStateProof: %v", err)
	}
	encoded, err := MarshalStateProof(proof)
	if err != nil {
		t.Fatalf("MarshalStateProof: %v", err)
	}
	restored, err := UnmarshalStateProof(encoded)
	if err != nil {
		t.Fatalf("UnmarshalStateProof: %v", err)
	}
	if restored.Address != addr {
		t.Fatalf("Address = %x, want %x", restored.Address[:], addr[:])
	}
	if !VerifyStateProof(root, restored) {
		t.Fatal("a proof this node generated and serialized cannot be verified after one encode/decode cycle")
	}
	if restored.Account == nil || restored.Account.Balance.Cmp(proof.Account.Balance) != 0 {
		t.Fatalf("Account did not round-trip: %+v", restored.Account)
	}
}

// TestR6_04_PseudoProofEnvelopeIsRefusedAfterDecoding closes the loop with
// R6-02: even if a placeholder-shaped proof is smuggled into the envelope, the
// decoder must not turn it into something VerifyStateProof accepts.
func TestR6_04_PseudoProofEnvelopeIsRefusedAfterDecoding(t *testing.T) {
	sdb, root := newProvedStateDB(t)
	addr := types.Address{0xa1, 0xb2}
	_, legacy, err := sdb.GetAccountWithProof(addr)
	if err != nil {
		t.Fatalf("GetAccountWithProof: %v", err)
	}

	envelope := &StateProof{
		Address:       addr,
		Account:       &state.Account{Nonce: 7, Balance: big.NewInt(1)},
		AccountProof:  legacy,
		StorageProofs: map[types.Hash]*StorageProofEntry{},
	}
	encoded, err := MarshalStateProof(envelope)
	if err != nil {
		t.Fatalf("MarshalStateProof: %v", err)
	}
	if len(encoded) == 0 {
		t.Fatal("MarshalStateProof produced an empty envelope")
	}
	restored, err := UnmarshalStateProof(encoded)
	if err != nil {
		t.Fatalf("UnmarshalStateProof: %v", err)
	}
	// The placeholder has no Path at all, so it encodes as a path-less proof and
	// no root can accept it.
	if VerifyStateProof(root, restored) {
		t.Fatal("a placeholder proof (no path, no leaf) verified after a serialization round trip")
	}
	if VerifyStateProof(root, envelope) {
		t.Fatal("a placeholder proof verified in-process")
	}
}
