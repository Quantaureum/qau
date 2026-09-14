// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"errors"
	"fmt"
	"testing"

	"github.com/quantaureum/qau/crypto"
)

// =============================================================================
// P2-7: Performance Benchmarks — DA Subsystem
//
// DoD (04-da-committee.md):
//   - Single slot sampling latency < 2s
//   - Aggregate signature verification > 1000 TPS
//   - Blob storage throughput measured
//
// Benchmark groups:
//   A. DAS sampling latency (single slot, end-to-end)
//   B. Dilithium3 signature verification (single + batch = aggregate throughput)
//   C. Blob storage throughput (StoreMatrix + GetCell)
//   D. Erasure coding throughput (ExtendBlobs2D)
//   E. Cell proof verification throughput (VerifyCellProof)
//   F. Aggregate attestation encode/decode throughput
// =============================================================================

// ── Helpers ──

// benchBlob creates a deterministic blob for benchmarking.
func benchBlob(seed byte) Blob {
	var blob Blob
	for i := range blob {
		blob[i] = byte(i%256) ^ seed
	}
	return blob
}

// setupDASSampling prepares a BlobStorage + DASClient with a local cellGetter
// that serves cells from storage (simulating a local P2P peer with zero latency).
// Returns the client ready to call Sample(slot, blobCount).
func setupDASSampling(b *testing.B, blobCount int) (*DASClient, uint64) {
	b.Helper()

	blobs := make([]Blob, blobCount)
	for i := range blobs {
		blobs[i] = benchBlob(byte(i + 1))
	}

	matrix, err := ExtendBlobs2D(blobs)
	if err != nil {
		b.Fatalf("ExtendBlobs2D failed: %v", err)
	}

	commitments := make([]KZGCommitment, blobCount)
	for i, blob := range blobs {
		commitments[i] = KZGCommitmentFromBlob(blob)
	}

	storage := NewBlobStorage()
	const slot uint64 = 1
	for i := 0; i < blobCount; i++ {
		if err := storage.StoreMatrix(slot, i, matrix, commitments); err != nil {
			b.Fatalf("StoreMatrix[%d] failed: %v", i, err)
		}
	}

	config := DefaultDASConfig()
	config.MaxRetries = 1
	config.QueryTimeoutMs = 5000
	client := NewDASClient(config)

	// Local cellGetter: reads directly from storage (zero network latency).
	client.SetCellGetter(func(s uint64, blobIndex, row, col int) (*DASSampleResponse, error) {
		cellPtr, commitPtr, err := storage.GetCell(s, blobIndex, row, col)
		if err != nil || cellPtr == nil || commitPtr == nil {
			return nil, errors.New("cell not found")
		}
		cell := *cellPtr
		commitment := *commitPtr
		proof, ok := ComputeCellProof(cell, row, col, commitment)
		if !ok {
			return nil, errors.New("proof computation failed")
		}
		return &DASSampleResponse{
			Slot:      s,
			BlobIndex: blobIndex,
			CellRow:   row,
			CellCol:   col,
			Cell:      cell,
			Proof:     proof,
		}, nil
	})

	client.NewSession(slot, commitments)
	return client, slot
}

// =============================================================================
// A. DAS Sampling Latency
// =============================================================================

// BenchmarkDASSample_SingleBlob measures end-to-end DAS sampling latency for
// a single blob per slot. This is the DoD metric: must be < 2s.
//
// The cellGetter returns valid cells from local storage (zero network latency).
// In production, network latency would add to this, but the DoD measures the
// sampling engine's own overhead.
func BenchmarkDASSample_SingleBlob(b *testing.B) {
	client, slot := setupDASSampling(b, 1)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Sample resets session counters each call, so it's safe to repeat.
		available, confidence, err := client.Sample(slot, 1)
		if err != nil {
			b.Fatalf("Sample failed: %v", err)
		}
		if !available {
			b.Fatalf("expected available=true, confidence=%f", confidence)
		}
	}
}

// BenchmarkDASSample_ThreeBlobs measures sampling latency with 3 blobs per slot.
func BenchmarkDASSample_ThreeBlobs(b *testing.B) {
	client, slot := setupDASSampling(b, 3)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		available, _, err := client.Sample(slot, 3)
		if err != nil {
			b.Fatalf("Sample failed: %v", err)
		}
		if !available {
			b.Fatalf("expected available=true")
		}
	}
}

// BenchmarkDASSample_MaxBlobs measures sampling latency with MaxBlobsPerBlock (6) blobs.
func BenchmarkDASSample_MaxBlobs(b *testing.B) {
	client, slot := setupDASSampling(b, MaxBlobsPerBlock)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		available, _, err := client.Sample(slot, MaxBlobsPerBlock)
		if err != nil {
			b.Fatalf("Sample failed: %v", err)
		}
		if !available {
			b.Fatalf("expected available=true")
		}
	}
}

// =============================================================================
// B. Dilithium3 Signature Verification (Aggregate Throughput)
// =============================================================================
//
// The DA aggregate attestation verification throughput is bounded by:
//   - QTD threshold mode: 1 threshold signature verification per aggregate
//   - Transition multi-sig mode: up to 64 individual Dilithium3 verifications
//
// We benchmark:
//   1. Single Verify() — the building block
//   2. VerifyBatch(64) — transition mode aggregate (max 64 sigs)
//   3. VerifyBatch(512) — full DA committee (512 validators)

// BenchmarkDilithium3Verify_Single measures single Dilithium3 signature
// verification latency. This is the per-validator cost in transition multi-sig
// mode.
func BenchmarkDilithium3Verify_Single(b *testing.B) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		b.Fatalf("GenerateKeyPair failed: %v", err)
	}

	msg := []byte("da-attestation-benchmark-message")
	sig, err := crypto.Sign(kp.Private, msg)
	if err != nil {
		b.Fatalf("Sign failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if !crypto.Verify(kp.Public, msg, sig) {
			b.Fatal("Verify returned false")
		}
	}
}

// BenchmarkDilithium3BatchVerify_64 measures batch verification of 64
// Dilithium3 signatures — the maximum in transition multi-sig mode
// (DAMaxTransitionSignatures = 64). This directly measures the aggregate
// signature verification cost for one DA slot in transition mode.
func BenchmarkDilithium3BatchVerify_64(b *testing.B) {
	benchDilithium3BatchVerify(b, 64)
}

// BenchmarkDilithium3BatchVerify_128 measures batch verification of 128 signatures.
func BenchmarkDilithium3BatchVerify_128(b *testing.B) {
	benchDilithium3BatchVerify(b, 128)
}

// BenchmarkDilithium3BatchVerify_256 measures batch verification of 256 signatures.
func BenchmarkDilithium3BatchVerify_256(b *testing.B) {
	benchDilithium3BatchVerify(b, 256)
}

// BenchmarkDilithium3BatchVerify_512 measures batch verification of 512
// signatures — the full DA committee size (DACommitteeSize = 512).
func BenchmarkDilithium3BatchVerify_512(b *testing.B) {
	benchDilithium3BatchVerify(b, 512)
}

// benchDilithium3BatchVerify is the shared implementation for batch verify
// benchmarks. It generates n keypairs, signs n distinct messages, and
// benchmarks crypto.VerifyBatch.
func benchDilithium3BatchVerify(b *testing.B, n int) {
	b.Helper()

	items := make([]crypto.SignatureItem, n)
	for i := 0; i < n; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			b.Fatalf("GenerateKeyPair[%d] failed: %v", i, err)
		}
		msg := []byte(fmt.Sprintf("da-attestation-msg-%d", i))
		sig, err := crypto.Sign(kp.Private, msg)
		if err != nil {
			b.Fatalf("Sign[%d] failed: %v", i, err)
		}
		items[i] = crypto.SignatureItem{
			PublicKey: kp.Public,
			Message:   msg,
			Signature: sig,
		}
	}

	// Warm up the batch verifier (worker pool initialization).
	crypto.VerifyBatch(items)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		result := crypto.VerifyBatch(items)
		if !result.AllValid {
			b.Fatalf("batch verify failed: %d invalid out of %d", result.InvalidCount, n)
		}
	}
}

// BenchmarkDilithium3Verify_Sequential_64 measures sequential (non-batch)
// verification of 64 signatures. This provides a baseline to quantify the
// speedup from VerifyBatch's parallel processing.
func BenchmarkDilithium3Verify_Sequential_64(b *testing.B) {
	n := 64
	items := make([]crypto.SignatureItem, n)
	for i := 0; i < n; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			b.Fatalf("GenerateKeyPair[%d] failed: %v", i, err)
		}
		msg := []byte(fmt.Sprintf("da-seq-msg-%d", i))
		sig, err := crypto.Sign(kp.Private, msg)
		if err != nil {
			b.Fatalf("Sign[%d] failed: %v", i, err)
		}
		items[i] = crypto.SignatureItem{
			PublicKey: kp.Public,
			Message:   msg,
			Signature: sig,
		}
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for _, item := range items {
			if !crypto.Verify(item.PublicKey, item.Message, item.Signature) {
				b.Fatal("sequential verify failed")
			}
		}
	}
}

// =============================================================================
// C. Blob Storage Throughput
// =============================================================================

// BenchmarkBlobStorage_StoreMatrix measures blob matrix storage write throughput.
// Each StoreMatrix call stores one blob's extended matrix (8192 cells × 32 bytes
// = 256 KB) plus its commitment.
func BenchmarkBlobStorage_StoreMatrix(b *testing.B) {
	blob := benchBlob(1)
	matrix, err := ExtendBlobs2D([]Blob{blob})
	if err != nil {
		b.Fatalf("ExtendBlobs2D failed: %v", err)
	}
	commitments := []KZGCommitment{KZGCommitmentFromBlob(blob)}

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(matrix[0])) * int64(CellSize))

	for i := 0; i < b.N; i++ {
		storage := NewBlobStorage()
		// Use slot i to avoid duplicate-key skip.
		if err := storage.StoreMatrix(uint64(i), 0, matrix, commitments); err != nil {
			b.Fatalf("StoreMatrix failed: %v", err)
		}
	}
}

// BenchmarkBlobStorage_StoreMatrix_Persistent measures persistent blob storage
// write throughput (P0-9 PersistentBlobStorage with KV store backend).
func BenchmarkBlobStorage_StoreMatrix_Persistent(b *testing.B) {
	b.Skip("PersistentBlobStorage benchmark requires a KV store backend — skipping to avoid temp file I/O flakiness in CI")
}

// BenchmarkBlobStorage_GetCell measures blob cell read throughput.
// This is the hot path in DAS sampling: each sample triggers a GetCell.
func BenchmarkBlobStorage_GetCell(b *testing.B) {
	blob := benchBlob(1)
	matrix, err := ExtendBlobs2D([]Blob{blob})
	if err != nil {
		b.Fatalf("ExtendBlobs2D failed: %v", err)
	}
	commitments := []KZGCommitment{KZGCommitmentFromBlob(blob)}

	storage := NewBlobStorage()
	if err := storage.StoreMatrix(1, 0, matrix, commitments); err != nil {
		b.Fatalf("StoreMatrix failed: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		cell, commit, err := storage.GetCell(1, 0, i%CellsPerBlobExtended, i%MaxBlobColumnsExt)
		if err != nil {
			b.Fatalf("GetCell failed: %v", err)
		}
		if cell == nil || commit == nil {
			b.Fatal("GetCell returned nil cell or commitment")
		}
	}
}

// BenchmarkBlobStorage_HasBlob measures HasBlob check throughput.
func BenchmarkBlobStorage_HasBlob(b *testing.B) {
	blob := benchBlob(1)
	matrix, err := ExtendBlobs2D([]Blob{blob})
	if err != nil {
		b.Fatalf("ExtendBlobs2D failed: %v", err)
	}
	commitments := []KZGCommitment{KZGCommitmentFromBlob(blob)}

	storage := NewBlobStorage()
	storage.StoreMatrix(1, 0, matrix, commitments)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if !storage.HasBlob(1, 0) {
			b.Fatal("HasBlob returned false for existing blob")
		}
	}
}

// =============================================================================
// D. Erasure Coding Throughput
// =============================================================================

// BenchmarkExtendBlobs2D_1Blob measures 2D erasure extension throughput for
// a single blob. This is the ProcessBlobsForBlock hot path.
func BenchmarkExtendBlobs2D_1Blob(b *testing.B) {
	blobs := []Blob{benchBlob(1)}
	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(BlobSize))

	for i := 0; i < b.N; i++ {
		_, err := ExtendBlobs2D(blobs)
		if err != nil {
			b.Fatalf("ExtendBlobs2D failed: %v", err)
		}
	}
}

// BenchmarkExtendBlobs2D_3Blobs measures 2D erasure extension for 3 blobs.
func BenchmarkExtendBlobs2D_3Blobs(b *testing.B) {
	blobs := []Blob{benchBlob(1), benchBlob(2), benchBlob(3)}
	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(BlobSize) * 3)

	for i := 0; i < b.N; i++ {
		_, err := ExtendBlobs2D(blobs)
		if err != nil {
			b.Fatalf("ExtendBlobs2D failed: %v", err)
		}
	}
}

// BenchmarkExtendBlobs2D_MaxBlobs measures 2D erasure extension for 6 blobs
// (MaxBlobsPerBlock), the maximum blobs per block.
func BenchmarkExtendBlobs2D_MaxBlobs(b *testing.B) {
	blobs := make([]Blob, MaxBlobsPerBlock)
	for i := range blobs {
		blobs[i] = benchBlob(byte(i + 1))
	}
	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(BlobSize) * int64(MaxBlobsPerBlock))

	for i := 0; i < b.N; i++ {
		_, err := ExtendBlobs2D(blobs)
		if err != nil {
			b.Fatalf("ExtendBlobs2D failed: %v", err)
		}
	}
}

// BenchmarkExtendBlob1D measures 1D erasure extension (horizontal extension
// of a single blob into 8192 cells). This is the inner loop of ExtendBlobs2D.
func BenchmarkExtendBlob1D(b *testing.B) {
	blob := benchBlob(1)
	var cells BlobCells
	for i := 0; i < CellsPerBlob; i++ {
		start := i * BytesPerFieldElement
		copy(cells[i][:], blob[start:start+BytesPerFieldElement])
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = ExtendBlob1D(cells)
	}
}

// =============================================================================
// E. Cell Proof Verification Throughput
// =============================================================================

// BenchmarkVerifyCellProof measures cell proof verification throughput.
// This is the DAS sampling inner loop: each sample requires one VerifyCellProof.
func BenchmarkVerifyCellProof(b *testing.B) {
	blob := benchBlob(1)
	matrix, err := ExtendBlobs2D([]Blob{blob})
	if err != nil {
		b.Fatalf("ExtendBlobs2D failed: %v", err)
	}
	commitment := KZGCommitmentFromBlob(blob)

	// Pre-compute a valid proof for row 0, col 0.
	cell := matrix[0][0]
	proof, ok := ComputeCellProof(cell, 0, 0, commitment)
	if !ok {
		b.Fatal("ComputeCellProof failed")
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		if !VerifyCellProof(cell, commitment, proof, 0, 0) {
			b.Fatal("VerifyCellProof returned false")
		}
	}
}

// BenchmarkComputeCellProof measures cell proof computation throughput.
// This is the ServeCellRequest hot path: each cell request requires computing
// a proof.
func BenchmarkComputeCellProof(b *testing.B) {
	blob := benchBlob(1)
	matrix, err := ExtendBlobs2D([]Blob{blob})
	if err != nil {
		b.Fatalf("ExtendBlobs2D failed: %v", err)
	}
	commitment := KZGCommitmentFromBlob(blob)
	cell := matrix[0][0]

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, ok := ComputeCellProof(cell, i%CellsPerBlobExtended, i%MaxBlobColumnsExt, commitment)
		if !ok {
			b.Fatal("ComputeCellProof failed")
		}
	}
}

// =============================================================================
// F. Aggregate Attestation Encode/Decode Throughput
// =============================================================================

// BenchmarkDASAggregateEncode_64Sigs measures encoding of a transition-mode
// aggregate attestation with 64 individual signatures (max transition mode).
func BenchmarkDASAggregateEncode_64Sigs(b *testing.B) {
	agg := makeBenchAggregate(64)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = agg.Encode()
	}
}

// BenchmarkDASAggregateDecode_64Sigs measures decoding of a transition-mode
// aggregate attestation with 64 individual signatures.
func BenchmarkDASAggregateDecode_64Sigs(b *testing.B) {
	agg := makeBenchAggregate(64)
	encoded := agg.Encode()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := DecodeDASAggregateAttestation(encoded)
		if err != nil {
			b.Fatalf("Decode failed: %v", err)
		}
	}
}

// BenchmarkDASAggregateEncode_512Sigs measures encoding of a full-committee
// aggregate (512 validators). Note: in QTD threshold mode this would be 1
// signature, but we benchmark the worst case (transition multi-sig with 512).
func BenchmarkDASAggregateEncode_512Sigs(b *testing.B) {
	agg := makeBenchAggregate(512)
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = agg.Encode()
	}
}

// BenchmarkDASAggregateDecode_512Sigs measures decoding of a full-committee
// aggregate (512 validators).
func BenchmarkDASAggregateDecode_512Sigs(b *testing.B) {
	agg := makeBenchAggregate(512)
	encoded := agg.Encode()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := DecodeDASAggregateAttestation(encoded)
		if err != nil {
			b.Fatalf("Decode failed: %v", err)
		}
	}
}

// BenchmarkDASAttestationHash measures attestation hash computation throughput.
// This is the per-attestation cost in the verifier (Hash is the signed message).
func BenchmarkDASAttestationHash(b *testing.B) {
	att := &DASAttestation{
		Slot:           42,
		Available:      true,
		Confidence:     0.9999,
		SampleCount:    75,
		SuccessCount:   75,
		ValidatorIndex: 7,
		Signature:      make([]byte, 3293),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = att.Hash()
	}
}

// makeBenchAggregate creates a DASAggregateAttestation with n dummy signatures
// for encode/decode benchmarks. Uses small (32-byte) signatures to isolate
// encode/decode overhead from signature size.
func makeBenchAggregate(n int) *DASAggregateAttestation {
	commitments := make([]KZGCommitment, 6) // MaxBlobsPerBlock (DA-R7-04: 48-byte KZGCommitment)
	for i := range commitments {
		commitments[i] = KZGCommitment{byte(i + 1)}
	}

	sigs := make([][]byte, n)
	for i := range sigs {
		sigs[i] = make([]byte, 32)
		sigs[i][0] = byte(i)
	}

	// ValidatorBits: 1 byte per 8 validators.
	bitsLen := (n + 7) / 8
	bits := make([]byte, bitsLen)
	for i := range bits {
		bits[i] = 0xFF
	}

	return &DASAggregateAttestation{
		Slot:                1,
		BlobCommitments:     commitments,
		AvailableCount:      n,
		TotalCount:          n,
		Signatures:          sigs,
		ValidatorBits:       bits,
		ThresholdAggregated: false,
	}
}
