// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"bytes"
	"testing"

	"github.com/quantaureum/qau/types"
)

// DA-R5-04 (2026-07-16): Regression tests for the full-blob-commitment
// binding on DASAttestation. Previously Hash() only included
// BlobCommitment (commitments[0]), allowing attestation reuse across
// distinct commitment sets sharing [0]. These tests verify:
//
//   1. Two attestations differing only in BlobCommitments produce different hashes
//   2. The legacy BlobCommitment field alone is insufficient to differentiate
//   3. Encode/Decode round-trip preserves BlobCommitments
//   4. Legacy attestations (no trailing block) still decode (backward compat)
//   5. The commitment count cap is enforced on decode (OOM protection)
//   6. A tampered commitment (same [0], different [1..]) produces a different hash
//
// All tests are self-contained and do not touch disk or network.

// baseAttestationDA_R5_04 is a helper that builds a minimal attestation
// with the supplied BlobCommitments. BlobCommitment (legacy) is always
// set to commitments[0] (truncated to 32 bytes) when commitments is
// non-empty, mirroring BuildDAAttestation's behavior.
//
// DA-R7-04 (2026-07-17): commitments is now []KZGCommitment (48 bytes
// each). The legacy BlobCommitment field is populated from the first 32
// bytes of commitments[0].
func baseAttestationDA_R5_04(commitments []KZGCommitment) *DASAttestation {
	a := &DASAttestation{
		Slot:            42,
		Available:       true,
		Confidence:      0.9999,
		SampleCount:     75,
		SuccessCount:    75,
		ValidatorIndex:  3,
		Signature:       []byte{0xDE, 0xAD, 0xBE, 0xEF},
		BlobCommitments: commitments,
	}
	if len(commitments) > 0 {
		a.BlobCommitment = types.BytesToHash(commitments[0][:])
	}
	return a
}

// TestDA_R5_04_HashBindsFullCommitmentSet proves the core fix: two
// attestations with the same BlobCommitment (commitments[0]) but
// different BlobCommitments[1..] produce different hashes.
func TestDA_R5_04_HashBindsFullCommitmentSet(t *testing.T) {
	// Two distinct commitment sets sharing [0].
	setA := []KZGCommitment{{0x01}, {0x02}, {0x03}}
	setB := []KZGCommitment{{0x01}, {0x02}, {0x99}} // differs only at [2]

	attA := baseAttestationDA_R5_04(setA)
	attB := baseAttestationDA_R5_04(setB)

	// Sanity: legacy single-commitment field matches.
	if attA.BlobCommitment != attB.BlobCommitment {
		t.Fatalf("expected same legacy BlobCommitment, got %x vs %x",
			attA.BlobCommitment, attB.BlobCommitment)
	}

	hashA := attA.Hash()
	hashB := attB.Hash()

	if hashA == hashB {
		t.Fatalf("DA-R5-04: Hash() must differ when BlobCommitments[1..] differ, but both = %x", hashA)
	}
}

// TestDA_R5_04_HashUnaffectedBySignature confirms Hash() excludes the
// Signature field (otherwise the signature could not be computed over Hash()).
// This is a regression check: adding BlobCommitments to Hash() must not
// accidentally pull in the Signature field.
func TestDA_R5_04_HashUnaffectedBySignature(t *testing.T) {
	commitments := []KZGCommitment{{0x01}}
	att1 := baseAttestationDA_R5_04(commitments)
	att1.Signature = []byte{0x11}

	att2 := baseAttestationDA_R5_04(commitments)
	att2.Signature = []byte{0x22}

	if att1.Hash() != att2.Hash() {
		t.Fatalf("Hash() must not depend on Signature")
	}
}

// TestDA_R5_04_EncodeDecodeRoundTrip verifies the full commitment set
// survives Encode → Decode.
func TestDA_R5_04_EncodeDecodeRoundTrip(t *testing.T) {
	commitments := []KZGCommitment{
		{0x01, 0x02},
		{0x03, 0x04},
		{0x05, 0x06},
		{0x07, 0x08},
	}
	original := baseAttestationDA_R5_04(commitments)

	encoded := original.Encode()
	decoded, err := DecodeDASAttestation(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// Verify all original fields survived.
	if decoded.Slot != original.Slot {
		t.Errorf("Slot mismatch: %d != %d", decoded.Slot, original.Slot)
	}
	if decoded.BlobCommitment != original.BlobCommitment {
		t.Errorf("BlobCommitment mismatch: %x != %x", decoded.BlobCommitment, original.BlobCommitment)
	}
	if decoded.Available != original.Available {
		t.Errorf("Available mismatch")
	}
	if decoded.Confidence != original.Confidence {
		t.Errorf("Confidence mismatch: %v != %v", decoded.Confidence, original.Confidence)
	}
	if decoded.SampleCount != original.SampleCount {
		t.Errorf("SampleCount mismatch: %d != %d", decoded.SampleCount, original.SampleCount)
	}
	if decoded.SuccessCount != original.SuccessCount {
		t.Errorf("SuccessCount mismatch: %d != %d", decoded.SuccessCount, original.SuccessCount)
	}
	if decoded.ValidatorIndex != original.ValidatorIndex {
		t.Errorf("ValidatorIndex mismatch: %d != %d", decoded.ValidatorIndex, original.ValidatorIndex)
	}
	if !bytes.Equal(decoded.Signature, original.Signature) {
		t.Errorf("Signature mismatch: %x != %x", decoded.Signature, original.Signature)
	}

	// DA-R5-04: Verify the full BlobCommitments survived.
	if len(decoded.BlobCommitments) != len(original.BlobCommitments) {
		t.Fatalf("BlobCommitments length mismatch: %d != %d",
			len(decoded.BlobCommitments), len(original.BlobCommitments))
	}
	for i := range original.BlobCommitments {
		if decoded.BlobCommitments[i] != original.BlobCommitments[i] {
			t.Errorf("BlobCommitments[%d] mismatch: %x != %x",
				i, decoded.BlobCommitments[i], original.BlobCommitments[i])
		}
	}

	// Hash must match (Hash is deterministic given identical fields).
	if decoded.Hash() != original.Hash() {
		t.Fatalf("Hash mismatch after round-trip: %x != %x",
			decoded.Hash(), original.Hash())
	}
}

// TestDA_R5_04_LegacyAttestationDecodes verifies that an attestation
// encoded WITHOUT the trailing BlobCommitments block (i.e., an old
// binary's output) still decodes. BlobCommitments will be nil and
// Hash() will use length=0 prefix — this is the backward-compatibility
// path for attestations produced before DA-R5-04.
func TestDA_R5_04_LegacyAttestationDecodes(t *testing.T) {
	// Build a legacy-format attestation by hand: 61 fixed bytes + 4 sigLen
	// + signature. NO trailing BlobCommitments block.
	legacy := make([]byte, 0, 64)
	slot := make([]byte, 8)
	slot[7] = 7
	legacy = append(legacy, slot...)
	bc := make([]byte, 32)
	bc[0] = 0xAB
	legacy = append(legacy, bc...)
	legacy = append(legacy, 1) // available
	conf := make([]byte, 8)
	conf[7] = 100
	legacy = append(legacy, conf...)
	sc := make([]byte, 4)
	sc[3] = 50
	legacy = append(legacy, sc...)
	suc := make([]byte, 4)
	suc[3] = 50
	legacy = append(legacy, suc...)
	vi := make([]byte, 4)
	vi[3] = 1
	legacy = append(legacy, vi...)
	sigLen := make([]byte, 4)
	sigLen[3] = 0 // empty signature
	legacy = append(legacy, sigLen...)

	decoded, err := DecodeDASAttestation(legacy)
	if err != nil {
		t.Fatalf("legacy decode failed: %v", err)
	}
	if decoded.Slot != 7 {
		t.Errorf("Slot mismatch: %d", decoded.Slot)
	}
	if decoded.BlobCommitment[0] != 0xAB {
		t.Errorf("BlobCommitment mismatch: %x", decoded.BlobCommitment)
	}
	if decoded.BlobCommitments != nil {
		t.Errorf("legacy attestation must decode with BlobCommitments=nil, got %d entries",
			len(decoded.BlobCommitments))
	}
	// Hash must not panic and must be deterministic.
	h := decoded.Hash()
	if h == (types.Hash{}) {
		t.Errorf("Hash() returned zero for legacy attestation")
	}
}

// TestDA_R5_04_DecodeRejectsHugeCommitCount confirms the OOM guard fires
// when bcCount > maxBlobCommitmentsPerAttestation.
func TestDA_R5_04_DecodeRejectsHugeCommitCount(t *testing.T) {
	// Build a valid 61-byte + 4 sigLen(=0) frame, then append a 4-byte
	// bcCount = maxBlobCommitmentsPerAttestation + 1.
	data := make([]byte, 65)
	data[7] = 1     // slot
	data[40] = 1    // available
	data[48] = 0x99 // confidence
	data[52] = 50   // sampleCount
	data[56] = 50   // successCount
	data[60] = 1    // validatorIndex
	// data[61:65] = sigLen = 0 (zeros)
	// Append bcCount = maxBlobCommitmentsPerAttestation + 1.
	data = append(data, 0, 0, 0x04, 0x00) // 1024 = maxBlobCommitmentsPerAttestation; +1 = 1025
	data[len(data)-4] = 0
	data[len(data)-3] = 0
	data[len(data)-2] = 0x04
	data[len(data)-1] = 0x01 // 1025

	_, err := DecodeDASAttestation(data)
	if err == nil {
		t.Fatal("expected error for bcCount > max, got nil")
	}
}

// TestDA_R5_04_HashDifferentForDifferentCommitmentLengths proves the
// length prefix in Hash() prevents collisions between e.g. a 2-element
// set and a 3-element set.
func TestDA_R5_04_HashDifferentForDifferentCommitmentLengths(t *testing.T) {
	set2 := []KZGCommitment{{0x01}, {0x02}}
	set3 := []KZGCommitment{{0x01}, {0x02}, {0x03}}

	att2 := baseAttestationDA_R5_04(set2)
	att3 := baseAttestationDA_R5_04(set3)

	if att2.Hash() == att3.Hash() {
		t.Fatalf("Hash() must differ for commitment sets of different lengths")
	}
}

// TestDA_R5_04_EmptyCommitmentSetHash verifies that an attestation with
// BlobCommitments=nil (legacy or no-blob slot) still produces a stable
// hash. This must not panic on the nil slice.
func TestDA_R5_04_EmptyCommitmentSetHash(t *testing.T) {
	att := baseAttestationDA_R5_04(nil)
	// Must not panic.
	h := att.Hash()
	if h == (types.Hash{}) {
		// Zero hash is theoretically possible but extremely unlikely with
		// non-zero Slot/Confidence/etc.
		t.Errorf("Hash() returned zero for non-empty attestation")
	}
}

// TestDA_R5_04_HashDeterministicForSameCommitments confirms two
// attestations with identical fields produce identical hashes — the
// BlobCommitments binding must not introduce non-determinism.
func TestDA_R5_04_HashDeterministicForSameCommitments(t *testing.T) {
	commitments := []KZGCommitment{{0xAA}, {0xBB}, {0xCC}}
	a1 := baseAttestationDA_R5_04(commitments)
	a2 := baseAttestationDA_R5_04(commitments)

	if a1.Hash() != a2.Hash() {
		t.Fatalf("Hash() must be deterministic for identical inputs: %x vs %x",
			a1.Hash(), a2.Hash())
	}
}

// TestDA_R5_04_HashOrderDependent proves the commitment order matters.
// [A,B,C] and [A,C,B] must produce different hashes (no commutative
// surprise from the length-prefix + sequential-write construction).
func TestDA_R5_04_HashOrderDependent(t *testing.T) {
	set1 := []KZGCommitment{{0x01}, {0x02}, {0x03}}
	set2 := []KZGCommitment{{0x01}, {0x03}, {0x02}} // permuted

	a1 := baseAttestationDA_R5_04(set1)
	a2 := baseAttestationDA_R5_04(set2)

	if a1.Hash() == a2.Hash() {
		t.Fatalf("Hash() must be order-dependent: [1,2,3] and [1,3,2] produced the same hash")
	}
}

// TestDA_R5_04_EncodedSizeGrowsWithCommitments confirms the encoded size
// increases by 48 bytes per additional commitment (plus the 4-byte
// length prefix is constant). This guards against accidental removal
// of the BlobCommitments encoding block.
//
// DA-R7-04 (2026-07-17): Per-commitment size changed from 32 → 48 bytes.
func TestDA_R5_04_EncodedSizeGrowsWithCommitments(t *testing.T) {
	att0 := baseAttestationDA_R5_04(nil)
	att1 := baseAttestationDA_R5_04([]KZGCommitment{{0x01}})
	att2 := baseAttestationDA_R5_04([]KZGCommitment{{0x01}, {0x02}})

	s0 := len(att0.Encode())
	s1 := len(att1.Encode())
	s2 := len(att2.Encode())

	// att0 has no BlobCommitments trailing block → 4-byte length prefix
	// for bcCount=0 is still emitted.
	// att1 adds 48 bytes for the single commitment (DA-R7-04: KZGCommitment is 48 bytes).
	// att2 adds another 48 bytes.
	if s1-s0 != 48 {
		t.Errorf("expected +48 bytes for 1 commitment, got +%d", s1-s0)
	}
	if s2-s1 != 48 {
		t.Errorf("expected +48 bytes for the second commitment, got +%d", s2-s1)
	}
}
