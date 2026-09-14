// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestGF256Operations(t *testing.T) {
	t.Run("gfMul basic", func(t *testing.T) {
		if gfMul(0, 5) != 0 {
			t.Error("gfMul(0, 5) should be 0")
		}
		if gfMul(5, 0) != 0 {
			t.Error("gfMul(5, 0) should be 0")
		}
		if gfMul(1, 5) != 5 {
			t.Error("gfMul(1, 5) should be 5")
		}
		if gfMul(5, 1) != 5 {
			t.Error("gfMul(5, 1) should be 5")
		}
	})

	t.Run("gfMul commutativity", func(t *testing.T) {
		for a := byte(1); a < 255; a++ {
			for b := byte(1); b < 255; b++ {
				if gfMul(a, b) != gfMul(b, a) {
					t.Errorf("gfMul(%d, %d) != gfMul(%d, %d)", a, b, b, a)
					return
				}
			}
		}
	})

	t.Run("gfMul associativity", func(t *testing.T) {
		for a := byte(1); a < 100; a++ {
			for b := byte(1); b < 100; b++ {
				for c := byte(1); c < 100; c++ {
					ab := gfMul(a, b)
					bc := gfMul(b, c)
					if gfMul(ab, c) != gfMul(a, bc) {
						t.Errorf("gfMul not associative for %d,%d,%d", a, b, c)
						return
					}
				}
			}
		}
	})

	t.Run("gfDiv", func(t *testing.T) {
		for a := byte(1); a < 255; a++ {
			for b := byte(1); b < 255; b++ {
				q, err := gfDiv(a, b)
				if err != nil {
					t.Errorf("gfDiv(%d, %d) returned error: %v", a, b, err)
					return
				}
				if gfMul(q, b) != a {
					t.Errorf("gfDiv(%d, %d) = %d, but %d * %d != %d", a, b, q, q, b, a)
					return
				}
			}
		}
	})

	t.Run("gfInv", func(t *testing.T) {
		for a := byte(1); a < 255; a++ {
			inv, err := gfInv(a)
			if err != nil {
				t.Errorf("gfInv(%d) returned error: %v", a, err)
				return
			}
			if gfMul(a, inv) != 1 {
				t.Errorf("gfInv(%d) = %d, but %d * %d != 1", a, inv, a, inv)
				return
			}
		}
	})
}

func TestErasureCodingSmallScale(t *testing.T) {
	const testN = 16

	type testCells [testN]Cell
	type testCellsExtended [testN * 2]Cell

	extendSmall := func(cells testCells) testCellsExtended {
		var extended testCellsExtended
		copy(extended[:testN], cells[:])

		for i := 0; i < testN; i++ {
			var parity Cell
			base := byte(i + 1)
			power := byte(1)
			for j := 0; j < testN; j++ {
				for k := 0; k < CellSize; k++ {
					parity[k] ^= gfMul(cells[j][k], power)
				}
				power = gfMul(power, base)
			}
			extended[testN+i] = parity
		}
		return extended
	}

	recoverSmall := func(extended testCellsExtended, availableMask []bool) (testCells, error) {
		availableCount := 0
		allOriginalAvailable := true
		for i, avail := range availableMask {
			if avail {
				availableCount++
			}
			if i < testN && !avail {
				allOriginalAvailable = false
			}
		}
		if availableCount < testN {
			return testCells{}, ErrInsufficientCells
		}

		if allOriginalAvailable {
			var recovered testCells
			copy(recovered[:], extended[:testN])
			return recovered, nil
		}

		availableIndices := make([]int, 0, availableCount)
		for i, avail := range availableMask {
			if avail {
				availableIndices = append(availableIndices, i)
			}
		}

		var recovered testCells
		for byteIdx := 0; byteIdx < CellSize; byteIdx++ {
			values := make([]byte, availableCount)
			for i, idx := range availableIndices {
				values[i] = extended[idx][byteIdx]
			}

			solved, err := solveVandermonde(availableIndices, values, testN)
			if err != nil {
				return testCells{}, err
			}

			for i := 0; i < testN; i++ {
				recovered[i][byteIdx] = solved[i]
			}
		}
		return recovered, nil
	}

	t.Run("Extend produces non-zero parity", func(t *testing.T) {
		var cells testCells
		for i := 0; i < testN; i++ {
			for j := 0; j < CellSize; j++ {
				cells[i][j] = byte(i*7 + j*13 + 1)
			}
		}

		extended := extendSmall(cells)

		for i := 0; i < testN; i++ {
			if extended[i] != cells[i] {
				t.Errorf("original cell %d mismatch", i)
			}
		}

		allZero := true
		for i := testN; i < testN*2; i++ {
			for j := 0; j < CellSize; j++ {
				if extended[i][j] != 0 {
					allZero = false
					break
				}
			}
			if !allZero {
				break
			}
		}
		if allZero {
			t.Error("all parity cells are zero")
		}
	})

	t.Run("Recover all original available", func(t *testing.T) {
		var cells testCells
		for i := 0; i < testN; i++ {
			for j := 0; j < CellSize; j++ {
				cells[i][j] = byte(i*7 + j*13)
			}
		}

		extended := extendSmall(cells)

		availableMask := make([]bool, testN*2)
		for i := 0; i < testN; i++ {
			availableMask[i] = true
		}

		recovered, err := recoverSmall(extended, availableMask)
		if err != nil {
			t.Fatalf("recovery failed: %v", err)
		}

		for i := 0; i < testN; i++ {
			if recovered[i] != cells[i] {
				t.Errorf("recovered cell %d mismatch", i)
			}
		}
	})

	t.Run("Verify parity cell computation", func(t *testing.T) {
		var cells testCells
		for i := 0; i < testN; i++ {
			for j := 0; j < CellSize; j++ {
				cells[i][j] = byte(i*3 + j*7 + 1)
			}
		}

		extended := extendSmall(cells)

		for parityIdx := 0; parityIdx < testN; parityIdx++ {
			var expected Cell
			base := byte(parityIdx + 1)
			power := byte(1)
			for j := 0; j < testN; j++ {
				for k := 0; k < CellSize; k++ {
					expected[k] ^= gfMul(cells[j][k], power)
				}
				power = gfMul(power, base)
			}

			if extended[testN+parityIdx] != expected {
				t.Errorf("parity cell %d mismatch", parityIdx)
				break
			}
		}
	})

	t.Run("Recover insufficient cells", func(t *testing.T) {
		var cells testCells
		extended := extendSmall(cells)

		availableMask := make([]bool, testN*2)
		for i := 0; i < testN-1; i++ {
			availableMask[i] = true
		}

		_, err := recoverSmall(extended, availableMask)
		if err == nil {
			t.Error("expected error for insufficient cells")
		}
	})
}

var ErrInsufficientCells = errInsufficientCells{}

type errInsufficientCells struct{}

func (e errInsufficientCells) Error() string {
	return "insufficient cells"
}

func TestBlobCellConversion(t *testing.T) {
	t.Run("BlobToCells roundtrip", func(t *testing.T) {
		var blob Blob
		for i := 0; i < BlobSize; i++ {
			blob[i] = byte(i % 256)
		}

		cells := BlobToCells(blob)
		reconstructed := CellsToBlob(cells)

		if blob != reconstructed {
			t.Error("BlobToCells -> CellsToBlob roundtrip failed")
		}
	})

	t.Run("CellsToBlob partial", func(t *testing.T) {
		var cells BlobCells
		for i := 0; i < CellsPerBlob; i++ {
			for j := 0; j < CellSize; j++ {
				cells[i][j] = byte(i + j)
			}
		}

		blob := CellsToBlob(cells)
		for i := 0; i < BlobSize; i++ {
			expectedCell := i / CellSize
			expectedOffset := i % CellSize
			if blob[i] != byte(expectedCell+expectedOffset) {
				t.Errorf("byte %d mismatch: got %d, want %d", i, blob[i], byte(expectedCell+expectedOffset))
			}
		}
	})
}

func TestKZGCommitments(t *testing.T) {
	t.Run("ComputeKZGCommitmentsForMatrix", func(t *testing.T) {
		var matrix BlobMatrixExtended
		for col := 0; col < MaxBlobColumnsExt; col++ {
			for row := 0; row < CellsPerBlobExtended; row++ {
				for k := 0; k < CellSize; k++ {
					matrix[col][row][k] = byte(col*100 + row + k)
				}
			}
		}

		commitments := ComputeKZGCommitmentsForMatrix(matrix, 2)
		if len(commitments) != 2 {
			t.Errorf("expected 2 commitments, got %d", len(commitments))
		}

		for i := 0; i < 2; i++ {
			isZero := true
			for j := 0; j < 48; j++ {
				if commitments[i][j] != 0 {
					isZero = false
					break
				}
			}
			if isZero {
				t.Errorf("commitment %d is all zeros", i)
			}
		}
	})

	t.Run("VerifyCellProof", func(t *testing.T) {
		// Build a matrix with known data
		var matrix BlobMatrixExtended
		for row := 0; row < CellsPerBlobExtended; row++ {
			for k := 0; k < CellSize; k++ {
				matrix[0][row][k] = byte(row + k)
			}
		}

		commitments := ComputeKZGCommitmentsForMatrix(matrix, 1)
		cell := matrix[0][0]
		commitment := commitments[0]

		// Compute a valid proof
		proof, ok := ComputeCellProof(cell, 0, 0, commitment)
		if !ok {
			t.Fatal("ComputeCellProof failed")
		}

		// Valid proof should verify
		result := VerifyCellProof(cell, commitment, proof, 0, 0)
		if !result {
			t.Error("VerifyCellProof should return true for valid proof")
		}

		// Tampered proof should fail
		var tamperedProof KZGProof
		copy(tamperedProof[:], proof[:])
		tamperedProof[0] ^= 0xff
		if VerifyCellProof(cell, commitment, tamperedProof, 0, 0) {
			t.Error("VerifyCellProof should return false for tampered proof")
		}

		// Wrong position should fail
		if VerifyCellProof(cell, commitment, proof, 1, 0) {
			t.Error("VerifyCellProof should return false for wrong row")
		}
	})
}

func TestDASClient(t *testing.T) {
	t.Run("NewDASClient", func(t *testing.T) {
		config := DefaultDASConfig()
		client := NewDASClient(config)

		if client == nil {
			t.Fatal("NewDASClient returned nil")
		}
		if client.config.SamplesPerQuery != DASSamplesPerQuery {
			t.Errorf("expected SamplesPerQuery=%d, got %d", DASSamplesPerQuery, client.config.SamplesPerQuery)
		}
	})

	t.Run("NewSession", func(t *testing.T) {
		client := NewDASClient(DefaultDASConfig())

		var commitments []KZGCommitment
		session := client.NewSession(42, commitments)

		if session == nil {
			t.Fatal("NewSession returned nil")
		}
		if session.Slot != 42 {
			t.Errorf("expected slot 42, got %d", session.Slot)
		}
	})

	t.Run("GetSession", func(t *testing.T) {
		client := NewDASClient(DefaultDASConfig())

		var commitments []KZGCommitment
		client.NewSession(100, commitments)

		session := client.GetSession(100)
		if session == nil {
			t.Fatal("GetSession returned nil for existing session")
		}

		missing := client.GetSession(999)
		if missing != nil {
			t.Error("GetSession should return nil for missing session")
		}
	})

	t.Run("CleanupOldSessions", func(t *testing.T) {
		client := NewDASClient(DefaultDASConfig())
		// DA-R5-05 (2026-07-16): Use a small-but-valid retention config
		// instead of relying on the production default (which is now
		// 1024 slots). This keeps the test focused on GC behavior.
		client.SetRetentionConfig(DASRetentionConfig{
			BlobRetentionSlots:    8,
			SessionRetentionSlots: 4,
			AttestRetentionSlots:  2,
			ConfidenceDecaySlots:  1,
			MinConfidenceDecay:    0.5,
			GCTickerInterval:      60 * time.Second,
		})

		var commitments []KZGCommitment
		client.NewSession(50, commitments)
		client.NewSession(398, commitments)

		client.CleanupOldSessions(400)

		if client.GetSession(50) != nil {
			t.Error("old session should be cleaned up")
		}
		if client.GetSession(398) == nil {
			t.Error("current session should not be cleaned up")
		}
	})

	t.Run("calculateSamplesNeeded", func(t *testing.T) {
		client := NewDASClient(DefaultDASConfig())

		samples := client.calculateSamplesNeeded(1000)
		if samples < 30 {
			t.Errorf("expected at least 30 samples, got %d", samples)
		}
	})

	t.Run("computeConfidence", func(t *testing.T) {
		client := NewDASClient(DefaultDASConfig())

		if client.computeConfidence(0, 0) != 0 {
			t.Error("confidence for 0/0 should be 0")
		}
		if client.computeConfidence(100, 100) < 0.99 {
			t.Error("confidence for 100/100 should be >= 0.99")
		}
		if client.computeConfidence(50, 100) >= 0.99 {
			t.Error("confidence for 50/100 should be < 0.99")
		}
	})

	t.Run("randomInt", func(t *testing.T) {
		client := NewDASClient(DefaultDASConfig())

		for i := 0; i < 100; i++ {
			n := client.randomInt(10)
			if n < 0 || n >= 10 {
				t.Errorf("randomInt(10) = %d, out of range", n)
			}
		}

		if client.randomInt(0) != 0 {
			t.Error("randomInt(0) should be 0")
		}
		if client.randomInt(-1) != 0 {
			t.Error("randomInt(-1) should be 0")
		}
	})

	t.Run("generateSampleRequests", func(t *testing.T) {
		client := NewDASClient(DefaultDASConfig())

		requests := client.generateSampleRequests(1, 2, 5)
		if len(requests) != 5 {
			t.Errorf("expected 5 requests, got %d", len(requests))
		}

		for _, req := range requests {
			if req.Slot != 1 {
				t.Errorf("expected slot 1, got %d", req.Slot)
			}
			if req.BlobIndex < 0 || req.BlobIndex >= 2 {
				t.Errorf("blob index %d out of range", req.BlobIndex)
			}
		}
	})
}

func TestDASVerifier(t *testing.T) {
	t.Run("NewDASVerifier", func(t *testing.T) {
		verifier := NewDASVerifier(DefaultDASConfig())
		if verifier == nil {
			t.Fatal("NewDASVerifier returned nil")
		}
	})

	t.Run("VerifyDataAvailability empty", func(t *testing.T) {
		verifier := NewDASVerifier(DefaultDASConfig())

		available, confidence := verifier.VerifyDataAvailability(1, nil, nil)
		if available {
			t.Error("empty samples should not be available")
		}
		if confidence != 0 {
			t.Errorf("expected confidence 0, got %f", confidence)
		}
	})

	t.Run("VerifyDataAvailability all valid", func(t *testing.T) {
		verifier := NewDASVerifier(DefaultDASConfig())

		// Build a matrix with known data
		var matrix BlobMatrixExtended
		for row := 0; row < CellsPerBlobExtended; row++ {
			for k := 0; k < CellSize; k++ {
				matrix[0][row][k] = byte(row*10 + k)
			}
		}

		commitments := ComputeKZGCommitmentsForMatrix(matrix, 1)
		commitment := commitments[0]

		// DA-R5-06 (2026-07-17): Use 14 samples (minimum for binomial bound
		// 1 - 0.5^14 ≈ 0.99994 ≥ MinConfidence=0.9999). 10 samples would
		// yield 1 - 0.5^10 ≈ 0.999 < 0.9999 → not available, which is the
		// correct behavior under the new sample-count-aware bound.
		const sampleCount = 14
		samples := make([]DASSampleResponse, sampleCount)
		for i := 0; i < sampleCount; i++ {
			cell := matrix[0][i%CellsPerBlobExtended]
			proof, _ := ComputeCellProof(cell, i%CellsPerBlobExtended, 0, commitment)
			samples[i] = DASSampleResponse{
				Slot:      1,
				BlobIndex: 0,
				CellRow:   i % CellsPerBlobExtended,
				CellCol:   0,
				Cell:      cell,
				Proof:     proof,
			}
		}

		available, confidence := verifier.VerifyDataAvailability(1, commitments, samples)
		if !available {
			t.Error("all valid samples should be available")
		}
		if confidence < 0.99 {
			t.Errorf("confidence should be high, got %f", confidence)
		}
	})
}

func TestDASAttestation(t *testing.T) {
	t.Run("EncodeDecode roundtrip", func(t *testing.T) {
		original := &DASAttestation{
			Slot:           42,
			Available:      true,
			Confidence:     0.9999,
			SampleCount:    75,
			SuccessCount:   75,
			ValidatorIndex: 7,
			Signature:      []byte{1, 2, 3, 4},
		}

		encoded := original.Encode()
		decoded, err := DecodeDASAttestation(encoded)
		if err != nil {
			t.Fatalf("DecodeDASAttestation failed: %v", err)
		}

		if decoded.Slot != original.Slot {
			t.Errorf("slot mismatch: %d != %d", decoded.Slot, original.Slot)
		}
		if decoded.Available != original.Available {
			t.Errorf("available mismatch: %v != %v", decoded.Available, original.Available)
		}
		if decoded.ValidatorIndex != original.ValidatorIndex {
			t.Errorf("validator index mismatch: %d != %d", decoded.ValidatorIndex, original.ValidatorIndex)
		}
		if decoded.SampleCount != original.SampleCount {
			t.Errorf("sample count mismatch: %d != %d", decoded.SampleCount, original.SampleCount)
		}
	})

	t.Run("Hash", func(t *testing.T) {
		a1 := &DASAttestation{Slot: 1, Available: true, ValidatorIndex: 1}
		a2 := &DASAttestation{Slot: 1, Available: true, ValidatorIndex: 1}

		h1 := a1.Hash()
		h2 := a2.Hash()

		if h1 != h2 {
			t.Error("identical attestations should have same hash")
		}
	})

	t.Run("Decode short data", func(t *testing.T) {
		_, err := DecodeDASAttestation([]byte{1, 2, 3})
		if err == nil {
			t.Error("expected error for short data")
		}
	})
}

func TestDASAggregateAttestation(t *testing.T) {
	t.Run("IsSufficient", func(t *testing.T) {
		// DA-R5-07 (2026-07-17): IsSufficient now requires CommitteeSize > 0
		// (fail-closed) and TotalCount ≥ ceil(2/3 · CommitteeSize) as an
		// absolute floor, in addition to the ratio check. CommitteeSize=100
		// → required = ceil(200/3) = 67.
		a := &DASAggregateAttestation{
			AvailableCount: 70,
			TotalCount:     100,
			CommitteeSize:  100,
		}
		if !a.IsSufficient() {
			t.Error("70/100 with CommitteeSize=100 should be sufficient")
		}

		b := &DASAggregateAttestation{
			AvailableCount: 50,
			TotalCount:     100,
			CommitteeSize:  100,
		}
		if b.IsSufficient() {
			t.Error("50/100 with CommitteeSize=100 should not be sufficient (ratio < 0.6667)")
		}

		c := &DASAggregateAttestation{
			AvailableCount: 0,
			TotalCount:     0,
			CommitteeSize:  100,
		}
		if c.IsSufficient() {
			t.Error("0/0 should not be sufficient")
		}

		// DA-R5-07: CommitteeSize == 0 → fail-closed (cannot verify
		// sufficiency without knowing the expected committee size).
		d := &DASAggregateAttestation{
			AvailableCount: 70,
			TotalCount:     100,
			CommitteeSize:  0,
		}
		if d.IsSufficient() {
			t.Error("70/100 with CommitteeSize=0 should not be sufficient (fail-closed)")
		}

		// DA-R5-07: Small-sample attack prevention. Without the absolute
		// floor, 2/3≈0.667 passes the ratio check. With CommitteeSize=100,
		// required=67, so 3 total < 67 → not sufficient.
		e := &DASAggregateAttestation{
			AvailableCount: 2,
			TotalCount:     3,
			CommitteeSize:  100,
		}
		if e.IsSufficient() {
			t.Error("2/3 with CommitteeSize=100 should not be sufficient (below absolute floor 67)")
		}
	})

	t.Run("EncodeDecode roundtrip", func(t *testing.T) {
		original := &DASAggregateAttestation{
			Slot:           100,
			AvailableCount: 80,
			TotalCount:     100,
			ValidatorBits:  []byte{0xFF, 0x0F},
			Signatures:     [][]byte{{1, 2, 3}, {4, 5, 6}},
			CommitteeSize:  100,
		}

		encoded := original.Encode()
		decoded, err := DecodeDASAggregateAttestation(encoded)
		if err != nil {
			t.Fatalf("DecodeDASAggregateAttestation failed: %v", err)
		}

		if decoded.Slot != original.Slot {
			t.Errorf("slot mismatch: %d != %d", decoded.Slot, original.Slot)
		}
		if decoded.AvailableCount != original.AvailableCount {
			t.Errorf("available count mismatch: %d != %d", decoded.AvailableCount, original.AvailableCount)
		}
		if decoded.TotalCount != original.TotalCount {
			t.Errorf("total count mismatch: %d != %d", decoded.TotalCount, original.TotalCount)
		}
		// DA-R5-07: Verify CommitteeSize survives encode/decode roundtrip.
		if decoded.CommitteeSize != original.CommitteeSize {
			t.Errorf("committee size mismatch: %d != %d", decoded.CommitteeSize, original.CommitteeSize)
		}
	})

	t.Run("Decode short data", func(t *testing.T) {
		_, err := DecodeDASAggregateAttestation([]byte{1, 2})
		if err == nil {
			t.Error("expected error for short data")
		}
	})
}

func TestBlobStorage(t *testing.T) {
	t.Run("NewBlobStorage", func(t *testing.T) {
		storage := NewBlobStorage()
		if storage == nil {
			t.Fatal("NewBlobStorage returned nil")
		}
	})

	t.Run("StoreAndGet", func(t *testing.T) {
		storage := NewBlobStorage()

		var matrix BlobMatrixExtended
		for col := 0; col < MaxBlobColumnsExt; col++ {
			for row := 0; row < CellsPerBlobExtended; row++ {
				for k := 0; k < CellSize; k++ {
					matrix[col][row][k] = byte(col*100 + row + k)
				}
			}
		}

		var commitments []KZGCommitment
		err := storage.StoreMatrix(1, 0, matrix, commitments)
		if err != nil {
			t.Fatalf("StoreMatrix failed: %v", err)
		}

		if !storage.HasBlob(1, 0) {
			t.Error("HasBlob should return true after store")
		}
		if storage.HasBlob(1, 1) {
			t.Error("HasBlob should return false for unstored blob")
		}

		cell, _, err := storage.GetCell(1, 0, 0, 0)
		if err != nil {
			t.Fatalf("GetCell failed: %v", err)
		}
		if cell == nil {
			t.Fatal("GetCell returned nil cell")
		}

		for k := 0; k < CellSize; k++ {
			expected := byte(0*100 + 0 + k)
			if cell[k] != expected {
				t.Errorf("cell[%d] = %d, want %d", k, cell[k], expected)
			}
		}
	})

	t.Run("GetCell out of range", func(t *testing.T) {
		storage := NewBlobStorage()

		var matrix BlobMatrixExtended
		storage.StoreMatrix(1, 0, matrix, nil)

		_, _, err := storage.GetCell(1, 0, 0, MaxBlobColumnsExt)
		if err == nil {
			t.Error("expected error for out of range column")
		}

		_, _, err = storage.GetCell(1, 0, CellsPerBlobExtended, 0)
		if err == nil {
			t.Error("expected error for out of range row")
		}
	})

	t.Run("GetCell missing", func(t *testing.T) {
		storage := NewBlobStorage()

		_, _, err := storage.GetCell(999, 0, 0, 0)
		if err == nil {
			t.Error("expected error for missing blob")
		}
	})

	t.Run("GetBlobCount", func(t *testing.T) {
		storage := NewBlobStorage()

		var matrix BlobMatrixExtended
		storage.StoreMatrix(1, 0, matrix, nil)
		storage.StoreMatrix(1, 1, matrix, nil)
		storage.StoreMatrix(2, 0, matrix, nil)

		if storage.GetBlobCount(1) != 2 {
			t.Errorf("expected 2 blobs for slot 1, got %d", storage.GetBlobCount(1))
		}
		if storage.GetBlobCount(2) != 1 {
			t.Errorf("expected 1 blob for slot 2, got %d", storage.GetBlobCount(2))
		}
	})

	t.Run("GC", func(t *testing.T) {
		storage := NewBlobStorage()
		// DA-R5-05 (2026-07-16): Use a small-but-valid retention config
		// instead of relying on the production default (which is now
		// 2048 slots). This keeps the test focused on GC behavior.
		storage.SetRetentionConfig(DASRetentionConfig{
			BlobRetentionSlots:    8,
			SessionRetentionSlots: 4,
			AttestRetentionSlots:  2,
			ConfidenceDecaySlots:  1,
			MinConfidenceDecay:    0.5,
			GCTickerInterval:      60 * time.Second,
		})

		var matrix BlobMatrixExtended
		storage.StoreMatrix(10, 0, matrix, nil)
		storage.StoreMatrix(200, 0, matrix, nil)

		storage.GC(200)

		if storage.HasBlob(10, 0) {
			t.Error("old blob should be GC'd")
		}
		if !storage.HasBlob(200, 0) {
			t.Error("current blob should not be GC'd")
		}
	})

	t.Run("Stats", func(t *testing.T) {
		storage := NewBlobStorage()

		count, _ := storage.Stats()
		if count != 0 {
			t.Errorf("expected 0 entries, got %d", count)
		}

		var matrix BlobMatrixExtended
		storage.StoreMatrix(1, 0, matrix, nil)

		count, _ = storage.Stats()
		if count != 1 {
			t.Errorf("expected 1 entry, got %d", count)
		}
	})
}

func TestBlobNetworkEncoding(t *testing.T) {
	t.Run("encodeDecodeDASSampleRequest", func(t *testing.T) {
		req := DASSampleRequest{
			Slot:      42,
			BlobIndex: 1,
			CellRow:   10,
			CellCol:   5,
		}

		encoded := encodeDASSampleRequest(req)
		decoded, err := decodeDASSampleRequest(encoded)
		if err != nil {
			t.Fatalf("decodeDASSampleRequest failed: %v", err)
		}

		if decoded.Slot != req.Slot {
			t.Errorf("slot mismatch: %d != %d", decoded.Slot, req.Slot)
		}
		if decoded.BlobIndex != req.BlobIndex {
			t.Errorf("blob index mismatch: %d != %d", decoded.BlobIndex, req.BlobIndex)
		}
		if decoded.CellRow != req.CellRow {
			t.Errorf("cell row mismatch: %d != %d", decoded.CellRow, req.CellRow)
		}
		if decoded.CellCol != req.CellCol {
			t.Errorf("cell col mismatch: %d != %d", decoded.CellCol, req.CellCol)
		}
	})

	t.Run("decodeDASSampleRequest short", func(t *testing.T) {
		_, err := decodeDASSampleRequest([]byte{1, 2, 3})
		if err == nil {
			t.Error("expected error for short data")
		}
	})

	t.Run("encodeDecodeDASSampleResponse", func(t *testing.T) {
		resp := DASSampleResponse{
			Slot:      42,
			BlobIndex: 1,
			CellRow:   10,
			CellCol:   5,
		}
		for i := 0; i < CellSize; i++ {
			resp.Cell[i] = byte(i)
		}
		for i := 0; i < 48; i++ {
			resp.Proof[i] = byte(i + 100)
		}

		encoded := encodeDASSampleResponse(resp)
		decoded, err := decodeDASSampleResponse(encoded)
		if err != nil {
			t.Fatalf("decodeDASSampleResponse failed: %v", err)
		}

		if decoded.Slot != resp.Slot {
			t.Errorf("slot mismatch: %d != %d", decoded.Slot, resp.Slot)
		}
		if decoded.Cell != resp.Cell {
			t.Error("cell mismatch")
		}
		if decoded.Proof != resp.Proof {
			t.Error("proof mismatch")
		}
	})

	t.Run("decodeDASSampleResponse short", func(t *testing.T) {
		_, err := decodeDASSampleResponse([]byte{1, 2, 3})
		if err == nil {
			t.Error("expected error for short data")
		}
	})
}

func TestBlobNetworkManager(t *testing.T) {
	t.Run("NewBlobNetworkManager", func(t *testing.T) {
		storage := NewBlobStorage()
		client := NewDASClient(DefaultDASConfig())
		manager := NewBlobNetworkManager(storage, client)

		if manager == nil {
			t.Fatal("NewBlobNetworkManager returned nil")
		}
	})

	t.Run("RequestCell no network", func(t *testing.T) {
		storage := NewBlobStorage()
		client := NewDASClient(DefaultDASConfig())
		manager := NewBlobNetworkManager(storage, client)

		_, err := manager.RequestCell(1, 0, 0, 0)
		if err == nil {
			t.Error("expected error when network not configured")
		}
	})

	t.Run("ServeCellRequest missing", func(t *testing.T) {
		storage := NewBlobStorage()
		client := NewDASClient(DefaultDASConfig())
		manager := NewBlobNetworkManager(storage, client)

		req := DASSampleRequest{Slot: 999, BlobIndex: 0, CellRow: 0, CellCol: 0}
		_, err := manager.ServeCellRequest(encodeDASSampleRequest(req))
		if err == nil {
			t.Error("expected error for missing blob")
		}
	})

	t.Run("ServeCellRequest success", func(t *testing.T) {
		storage := NewBlobStorage()
		client := NewDASClient(DefaultDASConfig())
		manager := NewBlobNetworkManager(storage, client)

		var matrix BlobMatrixExtended
		storage.StoreMatrix(1, 0, matrix, nil)

		req := DASSampleRequest{Slot: 1, BlobIndex: 0, CellRow: 0, CellCol: 0}
		resp, err := manager.ServeCellRequest(encodeDASSampleRequest(req))
		if err != nil {
			t.Fatalf("ServeCellRequest failed: %v", err)
		}
		if len(resp) == 0 {
			t.Error("ServeCellRequest returned empty response")
		}
	})

	// DA-R7-09: randomPeerIndex MUST return an error when count <= 0, and
	// when RNG fails (rather than silently returning 0, which would always
	// select peer[0] and enable eclipse attacks). The happy path must
	// return an index in [0, count).
	t.Run("randomPeerIndex_DA_R7_09", func(t *testing.T) {
		storage := NewBlobStorage()
		client := NewDASClient(DefaultDASConfig())
		manager := NewBlobNetworkManager(storage, client)

		// count <= 0 must return an error (not 0).
		if _, err := manager.randomPeerIndex(0); err == nil {
			t.Error("DA-R7-09: randomPeerIndex(0) must return an error, not 0")
		}
		if _, err := manager.randomPeerIndex(-1); err == nil {
			t.Error("DA-R7-09: randomPeerIndex(-1) must return an error")
		}

		// Happy path: index must be in [0, count).
		const count = 10
		for i := 0; i < 100; i++ {
			idx, err := manager.randomPeerIndex(count)
			if err != nil {
				t.Fatalf("randomPeerIndex(%d) failed unexpectedly: %v", count, err)
			}
			if idx < 0 || idx >= count {
				t.Errorf("randomPeerIndex(%d) returned out-of-range index %d", count, idx)
			}
		}

		// Statistical check: with count=2 and enough iterations, BOTH
		// indices 0 and 1 must appear at least once. This catches a
		// regression where the function always returns 0 (the pre-DA-R7-09
		// failure mode).
		seen := make(map[int]bool)
		const iterations = 200
		for i := 0; i < iterations; i++ {
			idx, err := manager.randomPeerIndex(2)
			if err != nil {
				t.Fatalf("randomPeerIndex(2) failed: %v", err)
			}
			seen[idx] = true
		}
		if !seen[0] || !seen[1] {
			t.Errorf("DA-R7-09: randomPeerIndex(2) did not produce both indices over %d iterations (seen=%v); possible fixed-peer regression",
				iterations, seen)
		}
	})
}

func TestBlobGarbageCollector(t *testing.T) {
	t.Run("NewBlobGarbageCollector", func(t *testing.T) {
		storage := NewBlobStorage()
		gc := NewBlobGarbageCollector(storage, func() uint64 { return 100 })

		if gc == nil {
			t.Fatal("NewBlobGarbageCollector returned nil")
		}
	})

	t.Run("StartStop", func(t *testing.T) {
		storage := NewBlobStorage()
		gc := NewBlobGarbageCollector(storage, func() uint64 { return 100 })

		gc.Start()
		gc.Stop()
	})
}

func TestDASConfig(t *testing.T) {
	t.Run("DefaultDASConfig", func(t *testing.T) {
		config := DefaultDASConfig()
		if config.SamplesPerQuery != DASSamplesPerQuery {
			t.Errorf("expected SamplesPerQuery=%d, got %d", DASSamplesPerQuery, config.SamplesPerQuery)
		}
		if config.MinConfidence != DASMinConfidenceLevel {
			t.Errorf("expected MinConfidence=%f, got %f", DASMinConfidenceLevel, config.MinConfidence)
		}
	})

	t.Run("NewDASClient with zero config", func(t *testing.T) {
		client := NewDASClient(DASConfig{})
		if client.config.SamplesPerQuery <= 0 {
			t.Error("SamplesPerQuery should be positive")
		}
		if client.config.MinConfidence <= 0 {
			t.Error("MinConfidence should be positive")
		}
	})
}

func TestDASSampleRequestResponse(t *testing.T) {
	t.Run("DASSampleRequest fields", func(t *testing.T) {
		req := DASSampleRequest{
			Slot:      100,
			BlobIndex: 2,
			CellRow:   50,
			CellCol:   10,
		}

		if req.Slot != 100 {
			t.Errorf("slot mismatch")
		}
		if req.BlobIndex != 2 {
			t.Errorf("blob index mismatch")
		}
		if req.CellRow != 50 {
			t.Errorf("cell row mismatch")
		}
		if req.CellCol != 10 {
			t.Errorf("cell col mismatch")
		}
	})

	t.Run("DASSampleResponse fields", func(t *testing.T) {
		var cell Cell
		for i := 0; i < CellSize; i++ {
			cell[i] = byte(i)
		}

		var proof KZGProof
		for i := 0; i < 48; i++ {
			proof[i] = byte(i)
		}

		resp := DASSampleResponse{
			Slot:      200,
			BlobIndex: 3,
			CellRow:   60,
			CellCol:   15,
			Cell:      cell,
			Proof:     proof,
		}

		if resp.Slot != 200 {
			t.Errorf("slot mismatch")
		}
		if resp.Cell != cell {
			t.Error("cell mismatch")
		}
		if resp.Proof != proof {
			t.Error("proof mismatch")
		}
	})
}

func TestDASSession(t *testing.T) {
	t.Run("DASSession fields", func(t *testing.T) {
		session := &DASSession{
			Slot:           42,
			TotalSamples:   100,
			SuccessSamples: 95,
		}

		if session.Slot != 42 {
			t.Errorf("slot mismatch")
		}
		if session.TotalSamples != 100 {
			t.Errorf("total samples mismatch")
		}
		if session.SuccessSamples != 95 {
			t.Errorf("success samples mismatch")
		}
	})
}

func TestBlobStorageEdgeCases(t *testing.T) {
	t.Run("StoreMatrix duplicate", func(t *testing.T) {
		storage := NewBlobStorage()

		var matrix BlobMatrixExtended
		err := storage.StoreMatrix(1, 0, matrix, nil)
		if err != nil {
			t.Fatalf("first StoreMatrix failed: %v", err)
		}

		err = storage.StoreMatrix(1, 0, matrix, nil)
		if err != nil {
			t.Fatalf("duplicate StoreMatrix should not fail: %v", err)
		}
	})

	t.Run("GetCommitments", func(t *testing.T) {
		storage := NewBlobStorage()

		var matrix BlobMatrixExtended
		var commitments []KZGCommitment
		storage.StoreMatrix(1, 0, matrix, commitments)

		result := storage.GetCommitments(1)
		if result == nil {
			t.Log("GetCommitments returned nil (expected)")
		}

		empty := storage.GetCommitments(999)
		if empty != nil {
			t.Error("GetCommitments for missing slot should return nil")
		}
	})
}

func TestBlobStorageEviction(t *testing.T) {
	t.Run("evictOldest", func(t *testing.T) {
		storage := NewBlobStorage()
		storage.maxSize = 100

		var matrix BlobMatrixExtended
		storage.StoreMatrix(1, 0, matrix, nil)
		storage.StoreMatrix(2, 0, matrix, nil)

		count, _ := storage.Stats()
		if count < 1 {
			t.Error("should have at least 1 entry after eviction")
		}
	})

	// DA-R7-07: evictOldest MUST be deterministic when multiple entries share
	// the same StoredAt timestamp. Go's map iteration order is non-deterministic,
	// so without a tie-breaker different nodes could evict different blobs for
	// the same timestamp, causing storage state divergence. The fix uses the
	// entry key (lexicographically smallest) as a tie-breaker.
	t.Run("evictOldest_deterministicWithSameTimestamp_DA_R7_07", func(t *testing.T) {
		sameTime := time.Unix(1700000000, 0)
		keys := []string{"10:0", "2:0", "5:0", "1:0", "20:0"}
		// Run the eviction many times; each run rebuilds the same initial
		// state (same timestamps) and must evict the SAME key every time.
		// Without the tie-breaker, map iteration order would cause different
		// keys to be evicted across runs (non-determinism).
		var expectedEvicted string
		for run := 0; run < 50; run++ {
			storage := NewBlobStorage()
			storage.entries = make(map[string]*BlobStorageEntry, len(keys))
			for _, k := range keys {
				storage.entries[k] = &BlobStorageEntry{
					Slot:      1,
					BlobIndex: 0,
					StoredAt:  sameTime,
				}
			}
			storage.evictOldest()
			// Find which key was evicted this run.
			var evicted string
			seenEvicted := 0
			for _, k := range keys {
				if _, exists := storage.entries[k]; !exists {
					evicted = k
					seenEvicted++
				}
			}
			if seenEvicted != 1 {
				t.Fatalf("run %d: expected exactly 1 key evicted, got %d", run, seenEvicted)
			}
			if run == 0 {
				expectedEvicted = evicted
			} else if evicted != expectedEvicted {
				t.Errorf("run %d: non-deterministic eviction — got %q, want %q (DA-R7-07 tie-breaker regression)",
					run, evicted, expectedEvicted)
			}
		}
		if expectedEvicted == "" {
			t.Fatal("no key was evicted in the first run — test setup error")
		}
	})
}

func BenchmarkGFMul(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gfMul(byte(i%255+1), byte((i*7)%255+1))
	}
}

func BenchmarkBlobStorageGet(b *testing.B) {
	storage := NewBlobStorage()
	var matrix BlobMatrixExtended
	storage.StoreMatrix(1, 0, matrix, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		storage.GetCell(1, 0, 0, 0)
	}
}

func BenchmarkDASAttestationEncode(b *testing.B) {
	att := &DASAttestation{
		Slot:           42,
		Available:      true,
		Confidence:     0.9999,
		SampleCount:    75,
		SuccessCount:   75,
		ValidatorIndex: 7,
		Signature:      make([]byte, 96),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		att.Encode()
	}
}

func BenchmarkDASAttestationDecode(b *testing.B) {
	att := &DASAttestation{
		Slot:           42,
		Available:      true,
		Confidence:     0.9999,
		SampleCount:    75,
		SuccessCount:   75,
		ValidatorIndex: 7,
		Signature:      make([]byte, 96),
	}
	encoded := att.Encode()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DecodeDASAttestation(encoded)
	}
}

var _ = bytes.Buffer{}

// ── P1-9: DASClient.Sample timeout, backoff, and error statistics tests ──

// TestDASClient_Sample_TimeoutError verifies that when the cell getter always
// times out, the TimeoutErrors counter is incremented and sampling fails.
// P1-9 (2026-07-14).
func TestDASClient_Sample_TimeoutError(t *testing.T) {
	config := DefaultDASConfig()
	config.QueryTimeoutMs = 50 // 50ms per query timeout
	config.MaxRetries = 2      // limit retries to keep test fast
	client := NewDASClient(config)

	// Set a getter that blocks longer than the timeout.
	client.SetCellGetter(func(slot uint64, blobIndex, row, col int) (*DASSampleResponse, error) {
		time.Sleep(200 * time.Millisecond) // blocks longer than 50ms timeout
		return nil, nil
	})

	client.NewSession(1, []KZGCommitment{{1}})
	available, confidence, err := client.Sample(1, 1)

	// Sampling should fail (no successful samples).
	if available {
		t.Error("expected available=false when all queries time out")
	}
	if confidence > 0 {
		t.Errorf("expected confidence=0, got %f", confidence)
	}

	// Check error stats: TimeoutErrors should be > 0.
	session := client.GetSession(1)
	if session == nil {
		t.Fatal("session should exist after Sample")
	}
	netErrs, timeoutErrs, verifErrs := session.GetErrorStats()
	if timeoutErrs == 0 {
		t.Error("expected TimeoutErrors > 0 when all queries time out")
	}
	if netErrs != 0 {
		t.Errorf("expected NetworkErrors=0, got %d", netErrs)
	}
	if verifErrs != 0 {
		t.Errorf("expected VerificationErrors=0, got %d", verifErrs)
	}
	// err may be nil or "no samples collected" depending on timing.
	_ = err
}

// TestDASClient_Sample_NetworkError verifies that when the cell getter returns
// errors, the NetworkErrors counter is incremented. P1-9 (2026-07-14).
func TestDASClient_Sample_NetworkError(t *testing.T) {
	config := DefaultDASConfig()
	config.QueryTimeoutMs = 5000
	config.MaxRetries = 2
	client := NewDASClient(config)

	// Set a getter that always returns an error.
	client.SetCellGetter(func(slot uint64, blobIndex, row, col int) (*DASSampleResponse, error) {
		return nil, errors.New("peer unreachable")
	})

	client.NewSession(1, []KZGCommitment{{1}})
	available, _, _ := client.Sample(1, 1)

	if available {
		t.Error("expected available=false when all queries fail with network error")
	}

	session := client.GetSession(1)
	netErrs, timeoutErrs, _ := session.GetErrorStats()
	if netErrs == 0 {
		t.Error("expected NetworkErrors > 0 when getter returns errors")
	}
	if timeoutErrs != 0 {
		t.Errorf("expected TimeoutErrors=0, got %d", timeoutErrs)
	}
}

// TestDASClient_Sample_VerificationError verifies that when the cell getter
// returns responses with invalid proofs, the VerificationErrors counter is
// incremented. P1-9 (2026-07-14).
func TestDASClient_Sample_VerificationError(t *testing.T) {
	config := DefaultDASConfig()
	config.QueryTimeoutMs = 5000
	config.MaxRetries = 1 // single attempt to keep test fast
	client := NewDASClient(config)

	// Set a getter that returns a response with an invalid proof.
	client.SetCellGetter(func(slot uint64, blobIndex, row, col int) (*DASSampleResponse, error) {
		return &DASSampleResponse{
			Slot:      slot,
			BlobIndex: 0,
			CellRow:   row,
			CellCol:   col,
			Cell:      Cell{},         // empty cell
			Proof:     KZGProof{0xFF}, // invalid proof
		}, nil
	})

	client.NewSession(1, []KZGCommitment{{1}})
	available, _, _ := client.Sample(1, 1)

	if available {
		t.Error("expected available=false when all proofs fail verification")
	}

	session := client.GetSession(1)
	_, _, verifErrs := session.GetErrorStats()
	if verifErrs == 0 {
		t.Error("expected VerificationErrors > 0 when cell proofs fail")
	}
}

// TestDASClient_Sample_SuccessNoErrors verifies that when sampling succeeds,
// all error counters remain at zero. P1-9 (2026-07-14).
func TestDASClient_Sample_SuccessNoErrors(t *testing.T) {
	// Create a blob and store its matrix so the getter can return valid cells.
	blob := Blob{}
	for i := range blob {
		blob[i] = byte(i % 256)
	}
	matrix, err := ExtendBlobs2D([]Blob{blob})
	if err != nil {
		t.Fatalf("ExtendBlobs2D failed: %v", err)
	}
	commitment := KZGCommitmentFromBlob(blob)
	storage := NewBlobStorage()
	storage.StoreMatrix(1, 0, matrix, []KZGCommitment{commitment})

	config := DefaultDASConfig()
	config.MaxRetries = 1
	// R40-P1-03 (2026-08-03) regression: this unit test exercises the hash-
	// stub cell-verification path WITHOUT a FRI data provider (no
	// UseFRI commitment data is cached). After R40-P1-03 the DAS client
	// rejects samples in that configuration by default (the hash stub
	// only proves the cell hash matches the producer-supplied proof, NOT
	// that the cell is an evaluation of the committed polynomial). This
	// test specifically wants the success path through VerifyCellProof, so
	// it explicitly opts into the legacy permissive behavior via
	// `AllowHashStubFallback: true`. Production deployments MUST leave
	// this flag false.
	config.AllowHashStubFallback = true
	client := NewDASClient(config)

	// Set a getter that returns valid cells from storage.
	client.SetCellGetter(func(slot uint64, blobIndex, row, col int) (*DASSampleResponse, error) {
		cellPtr, commitPtr, err := storage.GetCell(slot, blobIndex, row, col)
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
			Slot:      slot,
			BlobIndex: blobIndex,
			CellRow:   row,
			CellCol:   col,
			Cell:      cell,
			Proof:     proof,
		}, nil
	})

	client.NewSession(1, []KZGCommitment{commitment})
	available, _, _ := client.Sample(1, 1)

	if !available {
		t.Error("expected available=true when sampling succeeds")
	}

	session := client.GetSession(1)
	netErrs, timeoutErrs, verifErrs := session.GetErrorStats()
	if netErrs != 0 || timeoutErrs != 0 || verifErrs != 0 {
		t.Errorf("expected all error counters=0, got net=%d timeout=%d verif=%d",
			netErrs, timeoutErrs, verifErrs)
	}
}

// TestDASSession_GetErrorStats verifies the GetErrorStats method returns
// the correct error classification counters. P1-9 (2026-07-14).
func TestDASSession_GetErrorStats(t *testing.T) {
	session := &DASSession{
		Slot:               1,
		NetworkErrors:      5,
		TimeoutErrors:      3,
		VerificationErrors: 2,
	}

	net, timeout, verif := session.GetErrorStats()
	if net != 5 {
		t.Errorf("expected NetworkErrors=5, got %d", net)
	}
	if timeout != 3 {
		t.Errorf("expected TimeoutErrors=3, got %d", timeout)
	}
	if verif != 2 {
		t.Errorf("expected VerificationErrors=2, got %d", verif)
	}
}

// TestDASClient_retryBackoff verifies that retryBackoff sleeps for the
// expected exponentially increasing duration. P1-9 (2026-07-14).
func TestDASClient_retryBackoff(t *testing.T) {
	client := NewDASClient(DefaultDASConfig())

	for retry := 0; retry < 3; retry++ {
		expected := time.Duration(DASRetryBackoffBaseMs<<retry) * time.Millisecond
		start := time.Now()
		client.retryBackoff(retry)
		elapsed := time.Since(start)

		// Allow 5ms tolerance for scheduler jitter.
		if elapsed < expected-5*time.Millisecond {
			t.Errorf("retry %d: backoff too short, expected %v, got %v", retry, expected, elapsed)
		}
		if elapsed > expected+50*time.Millisecond {
			t.Errorf("retry %d: backoff too long, expected %v, got %v", retry, expected, elapsed)
		}
	}
}
