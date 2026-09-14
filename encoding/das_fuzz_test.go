// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// dilithium3SigSize is the Dilithium3 signature size (3293 bytes).
// Defined here to avoid importing the crypto package into encoding tests.
const dilithium3SigSize = 3293

// =============================================================================
// P2-6: Fuzz Testing — DecodeDASAttestation / DecodeDASAggregateAttestation
//
// This file tests the resistance of the DA attestation decoders to malformed,
// adversarial, and random inputs. The decoders process untrusted network data
// from P2P peers, so they MUST NOT panic, allocate unbounded memory, or
// produce incorrect results on any input.
//
// Test coverage:
//   A. Go native fuzz tests (testing/fuzz):
//     1. FuzzDecodeDASAttestation — random bytes → no panic
//     2. FuzzDecodeDASAggregateAttestation — random bytes → no panic
//     3. FuzzDASAttestationRoundTrip — encode → decode → field equality
//     4. FuzzDASAggregateAttestationRoundTrip — encode → decode → field equality
//
//   B. Deterministic malformed-input tests:
//     5. Empty input → error
//     6. Too-short input (truncation at every byte boundary)
//     7. Huge sigLen (0xFFFFFFFF) → no OOM, graceful
//     8. Huge commitCount (0xFFFFFFFF) → rejected by cap
//     9. Huge bitsLen (0xFFFFFFFF) → rejected by cap
//    10. Huge sigCount (0xFFFFFFFF) → rejected by cap
//    11. Truncated signature data → partial decode, no panic
//    12. Truncated commitment data → partial decode, no panic
//    13. Edge values (slot=0, slot=MaxUint64, negative-looking uint32)
//    14. Valid input with max-length signature
//    15. Aggregate with max commitments (1024)
//    16. Aggregate with max signatures (4096)
//    17. Aggregate with max validator bits (8192)
// =============================================================================

// =============================================================================
// A. Go Native Fuzz Tests
// =============================================================================

// FuzzDecodeDASAttestation feeds random bytes to DecodeDASAttestation.
// The decoder MUST NOT panic on any input — it processes untrusted P2P data.
func FuzzDecodeDASAttestation(f *testing.F) {
	// Seed corpus: empty, too short, exactly minimum, valid, oversized.
	f.Add([]byte{})
	f.Add(make([]byte, 10))
	f.Add(make([]byte, 61)) // exact minimum
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 10000))

	// A valid attestation seed.
	valid := &DASAttestation{
		Slot:           1,
		Available:      true,
		Confidence:     0.9999,
		SampleCount:    75,
		SuccessCount:   75,
		ValidatorIndex: 0,
		Signature:      make([]byte, dilithium3SigSize),
	}
	f.Add(valid.Encode())

	f.Fuzz(func(t *testing.T, data []byte) {
		// The only invariant: no panic, no infinite allocation.
		att, err := DecodeDASAttestation(data)
		if err != nil {
			return // Error is acceptable; panic is not.
		}
		if att == nil {
			t.Error("DecodeDASAttestation returned nil, nil — should return nil error only with non-nil att or error")
		}
		// Verify no unbounded allocation: signature length ≤ len(data).
		if len(att.Signature) > len(data) {
			t.Errorf("signature length %d exceeds input length %d", len(att.Signature), len(data))
		}
	})
}

// FuzzDecodeDASAggregateAttestation feeds random bytes to the aggregate decoder.
func FuzzDecodeDASAggregateAttestation(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 5))
	f.Add(make([]byte, 20)) // exact minimum
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 100000))

	// A valid aggregate seed.
	valid := &DASAggregateAttestation{
		Slot:            1,
		BlobCommitments: []KZGCommitment{{}}, // DA-R7-04: 48-byte KZGCommitment
		AvailableCount:  2,
		TotalCount:      3,
		Signatures:      [][]byte{make([]byte, 32)},
		ValidatorBits:   []byte{0xFF},
	}
	f.Add(valid.Encode())

	f.Fuzz(func(t *testing.T, data []byte) {
		agg, err := DecodeDASAggregateAttestation(data)
		if err != nil {
			return
		}
		if agg == nil {
			t.Error("returned nil, nil")
		}
		// Verify caps are enforced.
		if len(agg.BlobCommitments) > maxBlobCommitmentsPerAttestation {
			t.Errorf("commitCount %d exceeds cap %d", len(agg.BlobCommitments), maxBlobCommitmentsPerAttestation)
		}
		if len(agg.ValidatorBits) > maxValidatorBitsLen {
			t.Errorf("bitsLen %d exceeds cap %d", len(agg.ValidatorBits), maxValidatorBitsLen)
		}
		if len(agg.Signatures) > maxSignaturesPerAttestation {
			t.Errorf("sigCount %d exceeds cap %d", len(agg.Signatures), maxSignaturesPerAttestation)
		}
		// Total signature bytes ≤ input length (no amplification).
		totalSigBytes := 0
		for _, sig := range agg.Signatures {
			totalSigBytes += len(sig)
		}
		if totalSigBytes > len(data) {
			t.Errorf("total signature bytes %d exceeds input %d", totalSigBytes, len(data))
		}
	})
}

// FuzzDASAttestationRoundTrip verifies encode → decode preserves all fields.
func FuzzDASAttestationRoundTrip(f *testing.F) {
	f.Add(uint64(0), uint32(0), uint32(0), int32(0), []byte{})
	f.Add(uint64(1), uint32(75), uint32(75), int32(0), make([]byte, dilithium3SigSize))
	f.Add(uint64(0xFFFFFFFFFFFFFFFF), uint32(0xFFFFFFFF), uint32(0xFFFFFFFF), int32(0x7FFFFFFF), make([]byte, 100))

	f.Fuzz(func(t *testing.T, slot uint64, sampleCount, successCount uint32, validatorIndex int32, sig []byte) {
		// Encode uses uint32(ValidatorIndex), so negative values don't round-trip.
		// Skip negative validatorIndex to avoid false positives.
		if validatorIndex < 0 {
			return
		}
		original := &DASAttestation{
			Slot:           slot,
			Available:      successCount > 0,
			Confidence:     0.9999,
			SampleCount:    int(sampleCount),
			SuccessCount:   int(successCount),
			ValidatorIndex: int(validatorIndex),
			Signature:      sig,
		}

		encoded := original.Encode()
		decoded, err := DecodeDASAttestation(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		if decoded.Slot != original.Slot {
			t.Errorf("Slot mismatch: %d != %d", decoded.Slot, original.Slot)
		}
		if decoded.Available != original.Available {
			t.Errorf("Available mismatch: %v != %v", decoded.Available, original.Available)
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
			t.Errorf("Signature mismatch: len %d != %d", len(decoded.Signature), len(original.Signature))
		}
	})
}

// FuzzDASAggregateAttestationRoundTrip verifies encode → decode preserves fields.
func FuzzDASAggregateAttestationRoundTrip(f *testing.F) {
	f.Add(uint64(0), uint32(0), uint32(0), uint32(0), uint32(0), uint8(0))
	f.Add(uint64(1), uint32(1), uint32(2), uint32(3), uint32(1), uint8(1))

	f.Fuzz(func(t *testing.T, slot uint64, availCount, totalCount, commitCount, sigCount uint32, threshold uint8) {
		// Cap to valid ranges to avoid cap-rejection.
		if commitCount > 10 {
			commitCount = 10
		}
		if sigCount > 10 {
			sigCount = 10
		}

		commitments := make([]KZGCommitment, commitCount) // DA-R7-04: 48-byte KZGCommitment
		for i := range commitments {
			commitments[i] = KZGCommitment{byte(i)}
		}
		sigs := make([][]byte, sigCount)
		for i := range sigs {
			sigs[i] = []byte{byte(i), byte(i + 1)}
		}

		original := &DASAggregateAttestation{
			Slot:                slot,
			BlobCommitments:     commitments,
			AvailableCount:      int(availCount),
			TotalCount:          int(totalCount),
			Signatures:          sigs,
			ValidatorBits:       []byte{0xFF, 0xAA},
			ThresholdAggregated: threshold%2 == 1,
		}

		encoded := original.Encode()
		decoded, err := DecodeDASAggregateAttestation(encoded)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}

		if decoded.Slot != original.Slot {
			t.Errorf("Slot mismatch: %d != %d", decoded.Slot, original.Slot)
		}
		if len(decoded.BlobCommitments) != len(original.BlobCommitments) {
			t.Errorf("BlobCommitments length mismatch: %d != %d", len(decoded.BlobCommitments), len(original.BlobCommitments))
		}
		if decoded.AvailableCount != original.AvailableCount {
			t.Errorf("AvailableCount mismatch: %d != %d", decoded.AvailableCount, original.AvailableCount)
		}
		if decoded.TotalCount != original.TotalCount {
			t.Errorf("TotalCount mismatch: %d != %d", decoded.TotalCount, original.TotalCount)
		}
		if len(decoded.Signatures) != len(original.Signatures) {
			t.Errorf("Signatures length mismatch: %d != %d", len(decoded.Signatures), len(original.Signatures))
		}
		if !bytes.Equal(decoded.ValidatorBits, original.ValidatorBits) {
			t.Errorf("ValidatorBits mismatch: %v != %v", decoded.ValidatorBits, original.ValidatorBits)
		}
		if decoded.ThresholdAggregated != original.ThresholdAggregated {
			t.Errorf("ThresholdAggregated mismatch: %v != %v", decoded.ThresholdAggregated, original.ThresholdAggregated)
		}
	})
}

// =============================================================================
// B. Deterministic Malformed-Input Tests
// =============================================================================

// TestP2_6_DecodeDASAttestation_EmptyInput verifies empty input is rejected.
func TestP2_6_DecodeDASAttestation_EmptyInput(t *testing.T) {
	_, err := DecodeDASAttestation([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}

// TestP2_6_DecodeDASAttestation_TooShort verifies truncation at every byte
// boundary from 0 to minDASAttestationSize-1 is rejected without panic.
func TestP2_6_DecodeDASAttestation_TooShort(t *testing.T) {
	const minSize = 61
	for length := 0; length < minSize; length++ {
		data := make([]byte, length)
		// Fill with non-zero to avoid accidental "valid" patterns.
		for i := range data {
			data[i] = 0xFF
		}
		_, err := DecodeDASAttestation(data)
		if err == nil {
			t.Errorf("length %d: expected error (too short), got nil", length)
		}
	}
}

// TestP2_6_DecodeDASAttestation_HugeSigLen verifies that a huge sigLen field
// does not cause OOM and is rejected as a malformed attestation.
//
// ENCODING-P0-02 FIX (R31, 2026-07-27): The decoder now rejects huge sigLen
// (exceeds maximum 16384) with an error instead of silently skipping the
// signature. This is a security fix — previously, an attacker could craft
// an attestation with sigLen=0xFFFFFFFF that bypassed signature verification
// (empty sig accepted as valid). Now the malformed input is rejected.
func TestP2_6_DecodeDASAttestation_HugeSigLen(t *testing.T) {
	// Build a valid 65-byte attestation (61 fixed + 4 sigLen) with sigLen=0xFFFFFFFF.
	data := make([]byte, 65)
	binary.BigEndian.PutUint64(data[0:8], 1) // slot
	// BlobCommitment [8:40] = zeros
	data[40] = 1                                        // available
	binary.BigEndian.PutUint64(data[41:49], 999900)     // confidence
	binary.BigEndian.PutUint32(data[49:53], 75)         // sampleCount
	binary.BigEndian.PutUint32(data[53:57], 75)         // successCount
	binary.BigEndian.PutUint32(data[57:61], 0)          // validatorIndex
	binary.BigEndian.PutUint32(data[61:65], 0xFFFFFFFF) // sigLen = huge

	// Must not panic, must not allocate 4GB.
	_, err := DecodeDASAttestation(data)
	if err == nil {
		t.Fatal("expected error for huge sigLen (exceeds maximum 16384), got nil")
	}
}

// TestP2_6_DecodeDASAttestation_ValidWithMaxSignature verifies a valid
// attestation with a large (but within-data) signature decodes correctly.
func TestP2_6_DecodeDASAttestation_ValidWithMaxSignature(t *testing.T) {
	sigSize := dilithium3SigSize // Dilithium3 signature size (3293)
	data := make([]byte, 61+4+sigSize)
	binary.BigEndian.PutUint64(data[0:8], 42)
	data[40] = 1
	binary.BigEndian.PutUint64(data[41:49], 999900)
	binary.BigEndian.PutUint32(data[49:53], 100)
	binary.BigEndian.PutUint32(data[53:57], 100)
	binary.BigEndian.PutUint32(data[57:61], 5)
	binary.BigEndian.PutUint32(data[61:65], uint32(sigSize))
	for i := 0; i < sigSize; i++ {
		data[65+i] = byte(i % 256)
	}

	att, err := DecodeDASAttestation(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if att.Slot != 42 {
		t.Errorf("Slot mismatch: %d", att.Slot)
	}
	if len(att.Signature) != sigSize {
		t.Errorf("signature length mismatch: %d != %d", len(att.Signature), sigSize)
	}
	if att.Signature[0] != 0 || att.Signature[1] != 1 {
		t.Error("signature content mismatch")
	}
}

// TestP2_6_DecodeDASAttestation_EdgeValues tests slot=0 and slot=MaxUint64.
func TestP2_6_DecodeDASAttestation_EdgeValues(t *testing.T) {
	for _, slot := range []uint64{0, 1, 0xFFFFFFFFFFFFFFFF} {
		att := &DASAttestation{
			Slot:           slot,
			Available:      true,
			Confidence:     1.0,
			SampleCount:    1,
			SuccessCount:   1,
			ValidatorIndex: 0,
		}
		encoded := att.Encode()
		decoded, err := DecodeDASAttestation(encoded)
		if err != nil {
			t.Fatalf("slot %d: decode failed: %v", slot, err)
		}
		if decoded.Slot != slot {
			t.Errorf("slot %d: round-trip mismatch %d", slot, decoded.Slot)
		}
	}
}

// TestP2_6_DecodeDASAttestation_TruncatedSignature verifies that a truncated
// signature (sigLen says 100 but only 50 bytes follow) is rejected.
//
// ENCODING-P0-02 FIX (R31, 2026-07-27): The decoder now rejects truncated
// signatures with an error instead of silently skipping. This prevents an
// attacker from crafting an attestation with sigLen=100 but only 50 bytes
// of signature data, which would be accepted with an empty signature
// (bypassing signature verification).
func TestP2_6_DecodeDASAttestation_TruncatedSignature(t *testing.T) {
	data := make([]byte, 61+4+50)                // 50 bytes of signature data
	binary.BigEndian.PutUint32(data[61:65], 100) // sigLen=100 but only 50 available

	_, err := DecodeDASAttestation(data)
	if err == nil {
		t.Fatal("expected error for truncated signature (sigLen=100 but only 50 bytes available), got nil")
	}
}

// TestP2_6_DecodeAggregate_EmptyInput verifies empty input is rejected.
func TestP2_6_DecodeAggregate_EmptyInput(t *testing.T) {
	_, err := DecodeDASAggregateAttestation([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}

// TestP2_6_DecodeAggregate_TooShort verifies truncation at every byte
// boundary from 0 to 19 is rejected without panic.
func TestP2_6_DecodeAggregate_TooShort(t *testing.T) {
	for length := 0; length < 20; length++ {
		data := make([]byte, length)
		for i := range data {
			data[i] = 0xFF
		}
		_, err := DecodeDASAggregateAttestation(data)
		if err == nil {
			t.Errorf("length %d: expected error (too short), got nil", length)
		}
	}
}

// TestP2_6_DecodeAggregate_HugeCommitCount verifies the cap rejects
// commitCount > maxBlobCommitmentsPerAttestation (1024).
func TestP2_6_DecodeAggregate_HugeCommitCount(t *testing.T) {
	data := make([]byte, 20)
	binary.BigEndian.PutUint64(data[0:8], 1)           // slot
	binary.BigEndian.PutUint32(data[8:12], 0xFFFFFFFF) // commitCount = huge

	_, err := DecodeDASAggregateAttestation(data)
	if err == nil {
		t.Error("expected error for huge commitCount")
	}
}

// TestP2_6_DecodeAggregate_HugeBitsLen verifies the cap rejects
// bitsLen > maxValidatorBitsLen (8192) when enough data is provided.
// Note: the cap check is inside the `offset+bitsLen <= len(data)` block,
// so if data is too short the bits are silently skipped (no OOM). To trigger
// the cap, we must provide enough data to match the claimed bitsLen.
func TestP2_6_DecodeAggregate_HugeBitsLen(t *testing.T) {
	// slot(8) + commitCount(4)=0 + availCount(4) + totalCount(4) + bitsLen(4)
	// + bitsLen bytes of data.
	hugeBitsLen := uint32(maxValidatorBitsLen + 1) // 8193
	data := make([]byte, 24+int(hugeBitsLen))
	binary.BigEndian.PutUint64(data[0:8], 1)
	binary.BigEndian.PutUint32(data[8:12], 0)  // commitCount=0
	binary.BigEndian.PutUint32(data[12:16], 1) // availCount
	binary.BigEndian.PutUint32(data[16:20], 2) // totalCount
	binary.BigEndian.PutUint32(data[20:24], hugeBitsLen)

	_, err := DecodeDASAggregateAttestation(data)
	if err == nil {
		t.Error("expected error for huge bitsLen (8193 > 8192 cap)")
	}
}

// TestP2_6_DecodeAggregate_HugeBitsLenShortData verifies that when bitsLen
// is huge but data is too short, the decoder rejects the input (no OOM).
//
// ENCODING-P0-03 FIX (R31, 2026-07-27): The decoder now rejects huge bitsLen
// (exceeds maximum 8192) with an error instead of silently skipping. This
// prevents an attacker from crafting an aggregate attestation with
// bitsLen=0xFFFFFFFF that bypasses validator-bits verification.
func TestP2_6_DecodeAggregate_HugeBitsLenShortData(t *testing.T) {
	data := make([]byte, 24)
	binary.BigEndian.PutUint64(data[0:8], 1)
	binary.BigEndian.PutUint32(data[8:12], 0)
	binary.BigEndian.PutUint32(data[12:16], 1)
	binary.BigEndian.PutUint32(data[16:20], 2)
	binary.BigEndian.PutUint32(data[20:24], 0xFFFFFFFF) // bitsLen = huge, but data too short

	_, err := DecodeDASAggregateAttestation(data)
	if err == nil {
		t.Fatal("expected error for huge bitsLen (exceeds maximum 8192), got nil")
	}
}

// TestP2_6_DecodeAggregate_HugeSigCount verifies the cap rejects
// sigCount > maxSignaturesPerAttestation (4096).
func TestP2_6_DecodeAggregate_HugeSigCount(t *testing.T) {
	// slot(8) + commitCount(4)=0 + availCount(4) + totalCount(4) + bitsLen(4)=0 + sigCount(4)
	data := make([]byte, 28)
	binary.BigEndian.PutUint64(data[0:8], 1)
	binary.BigEndian.PutUint32(data[8:12], 0)           // commitCount=0
	binary.BigEndian.PutUint32(data[12:16], 1)          // availCount
	binary.BigEndian.PutUint32(data[16:20], 2)          // totalCount
	binary.BigEndian.PutUint32(data[20:24], 0)          // bitsLen=0
	binary.BigEndian.PutUint32(data[24:28], 0xFFFFFFFF) // sigCount = huge

	_, err := DecodeDASAggregateAttestation(data)
	if err == nil {
		t.Error("expected error for huge sigCount")
	}
}

// TestP2_6_DecodeAggregate_HugeSigLenInLoop verifies that a huge sigLen
// inside the signature loop is rejected (no OOM).
//
// ENCODING-P0-03 FIX (R31, 2026-07-27): The decoder now rejects huge sigLen
// (exceeds maximum 16384) with an error instead of silently skipping. This
// prevents an attacker from crafting an aggregate attestation with a huge
// sigLen that bypasses signature verification.
func TestP2_6_DecodeAggregate_HugeSigLenInLoop(t *testing.T) {
	// slot(8) + commitCount(4)=0 + availCount(4) + totalCount(4) + bitsLen(4)=0
	// + sigCount(4)=1 + sigLen(4)=0xFFFFFFFF
	data := make([]byte, 32)
	binary.BigEndian.PutUint64(data[0:8], 1)
	binary.BigEndian.PutUint32(data[8:12], 0)
	binary.BigEndian.PutUint32(data[12:16], 1)
	binary.BigEndian.PutUint32(data[16:20], 2)
	binary.BigEndian.PutUint32(data[20:24], 0)
	binary.BigEndian.PutUint32(data[24:28], 1)          // sigCount=1
	binary.BigEndian.PutUint32(data[28:32], 0xFFFFFFFF) // sigLen = huge

	_, err := DecodeDASAggregateAttestation(data)
	if err == nil {
		t.Fatal("expected error for huge sigLen in loop (exceeds maximum 16384), got nil")
	}
}

// TestP2_6_DecodeAggregate_TruncatedCommitments verifies that truncated
// commitment data is rejected (commitCount=3 but only 1 commitment's worth of data).
//
// ENCODING-P0-03 FIX (R31, 2026-07-27): The decoder now rejects truncated
// commitment data with an error instead of silently returning a partial
// slice with zero-valued commitments. This prevents an attacker from
// crafting an aggregate attestation with commitCount=3 but only 1
// commitment's worth of data, where the 2 zero-valued commitments would
// be treated as valid (zeros are valid KZG commitments to zero blobs).
//
// DA-R7-04 (2026-07-17): Each commitment is now 48 bytes (KZGCommitment).
// The test provides 48 bytes (= 1 commitment) but declares commitCount=3.
func TestP2_6_DecodeAggregate_TruncatedCommitments(t *testing.T) {
	// slot(8) + commitCount(4)=3 but only 48 bytes of commitment data (1 commitment).
	data := make([]byte, 8+4+48)
	binary.BigEndian.PutUint64(data[0:8], 1)
	binary.BigEndian.PutUint32(data[8:12], 3) // commitCount=3, but only 1 fits

	_, err := DecodeDASAggregateAttestation(data)
	if err == nil {
		t.Fatal("expected error for truncated commitments (commitCount=3 but only 1 fits), got nil")
	}
}

// TestP2_6_DecodeAggregate_MaxCommitments verifies decoding with
// maxBlobCommitmentsPerAttestation (1024) commitments succeeds.
func TestP2_6_DecodeAggregate_MaxCommitments(t *testing.T) {
	commitCount := maxBlobCommitmentsPerAttestation // 1024
	agg := &DASAggregateAttestation{
		Slot:            1,
		BlobCommitments: make([]KZGCommitment, commitCount), // DA-R7-04: 48-byte each
		AvailableCount:  1,
		TotalCount:      1,
	}
	for i := range agg.BlobCommitments {
		agg.BlobCommitments[i] = KZGCommitment{byte(i % 256)}
	}

	encoded := agg.Encode()
	decoded, err := DecodeDASAggregateAttestation(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(decoded.BlobCommitments) != commitCount {
		t.Errorf("expected %d commitments, got %d", commitCount, len(decoded.BlobCommitments))
	}
}

// TestP2_6_DecodeAggregate_MaxSignatures verifies decoding with
// maxSignaturesPerAttestation (4096) signatures succeeds.
func TestP2_6_DecodeAggregate_MaxSignatures(t *testing.T) {
	sigCount := maxSignaturesPerAttestation // 4096
	sigs := make([][]byte, sigCount)
	for i := range sigs {
		sigs[i] = []byte{byte(i % 256), byte((i + 1) % 256)}
	}
	agg := &DASAggregateAttestation{
		Slot:           1,
		AvailableCount: 1,
		TotalCount:     1,
		Signatures:     sigs,
	}

	encoded := agg.Encode()
	decoded, err := DecodeDASAggregateAttestation(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(decoded.Signatures) != sigCount {
		t.Errorf("expected %d signatures, got %d", sigCount, len(decoded.Signatures))
	}
}

// TestP2_6_DecodeAggregate_MaxValidatorBits verifies decoding with
// maxValidatorBitsLen (8192) bytes of validator bits succeeds.
func TestP2_6_DecodeAggregate_MaxValidatorBits(t *testing.T) {
	bitsLen := maxValidatorBitsLen // 8192
	agg := &DASAggregateAttestation{
		Slot:           1,
		AvailableCount: 1,
		TotalCount:     1,
		ValidatorBits:  make([]byte, bitsLen),
	}
	for i := range agg.ValidatorBits {
		agg.ValidatorBits[i] = byte(i % 256)
	}

	encoded := agg.Encode()
	decoded, err := DecodeDASAggregateAttestation(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(decoded.ValidatorBits) != bitsLen {
		t.Errorf("expected %d validator bits, got %d", bitsLen, len(decoded.ValidatorBits))
	}
}

// TestP2_6_DecodeAggregate_OverCapCommitCount verifies commitCount exactly
// at cap+1 is rejected, and exactly at cap is accepted.
func TestP2_6_DecodeAggregate_OverCapCommitCount(t *testing.T) {
	// At cap (1024) — should succeed.
	agg := &DASAggregateAttestation{
		BlobCommitments: make([]KZGCommitment, maxBlobCommitmentsPerAttestation), // DA-R7-04: 48-byte each
	}
	encoded := agg.Encode()
	if _, err := DecodeDASAggregateAttestation(encoded); err != nil {
		t.Errorf("at cap %d: expected success, got %v", maxBlobCommitmentsPerAttestation, err)
	}

	// Over cap (1025) — manually craft because Encode won't produce it.
	data := make([]byte, 12)
	binary.BigEndian.PutUint64(data[0:8], 1)
	binary.BigEndian.PutUint32(data[8:12], maxBlobCommitmentsPerAttestation+1)
	if _, err := DecodeDASAggregateAttestation(data); err == nil {
		t.Errorf("over cap %d: expected error", maxBlobCommitmentsPerAttestation+1)
	}
}

// TestP2_6_DecodeDASAttestation_NoPanicOnRandomBytes feeds 1000 random
// byte slices of varying lengths to the decoder and verifies no panic.
func TestP2_6_DecodeDASAttestation_NoPanicOnRandomBytes(t *testing.T) {
	// Deterministic pseudo-random for reproducibility.
	seed := uint64(12345)
	for i := 0; i < 1000; i++ {
		seed = seed*6364136223846793005 + 1442695040888963407 // LCG
		length := int(seed % 200)
		data := make([]byte, length)
		for j := range data {
			seed = seed*6364136223846793005 + 1442695040888963407
			data[j] = byte(seed % 256)
		}
		// Must not panic.
		_, _ = DecodeDASAttestation(data)
		_, _ = DecodeDASAggregateAttestation(data)
	}
}

// TestP2_6_DecodeDASAttestation_AllZeros verifies all-zero input of
// various lengths doesn't panic and produces a valid (zero-valued) result.
func TestP2_6_DecodeDASAttestation_AllZeros(t *testing.T) {
	for _, length := range []int{0, 10, 61, 65, 100, 1000} {
		data := make([]byte, length)
		// Must not panic.
		att, err := DecodeDASAttestation(data)
		if length < 61 {
			if err == nil {
				t.Errorf("length %d: expected error (too short)", length)
			}
			continue
		}
		if err != nil {
			continue // Partial decode may return nil error.
		}
		if att == nil {
			t.Errorf("length %d: got nil att with nil error", length)
		}
	}
}
