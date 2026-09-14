// Quantaureum Node source, version 1.0.0.
// Package encoding - R32-P1-13 boundary check tests.
//
// These tests verify the boundary checks added in the R32-P1-13 fix for
// FRI proof verification. Each test crafts a malicious input that would
// have panicked or caused incorrect behavior before the fix, and asserts
// that the hardened function returns nil/false/error instead.
package encoding

import (
	"testing"
)

// TestR32_P1_13_GF64Generator_NoPanicOnOversizedK verifies that GF64Generator
// returns 0 (instead of panicking) when k > 32. Before R32-P1-13, this
// call panicked with "GF64Generator: k must be <= 32 for Goldilocks field".
func TestR32_P1_13_GF64Generator_NoPanicOnOversizedK(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GF64Generator(33) panicked: %v (should return 0)", r)
		}
	}()
	got := GF64Generator(33)
	if got != 0 {
		t.Errorf("GF64Generator(33) = %d, want 0 (invalid root of unity)", got)
	}
}

// TestR32_P1_13_GF64ReedSolomonExtend_RejectsNonPowerOf2 verifies that
// GF64ReedSolomonExtend returns nil for non-power-of-2 m. Before R32-P1-13,
// this produced a corrupt all-zero codeword (via GF64Generator returning 0).
func TestR32_P1_13_GF64ReedSolomonExtend_RejectsNonPowerOf2(t *testing.T) {
	coeffs := []GF64Element{1, 2, 3, 4}
	got := GF64ReedSolomonExtend(coeffs, 6) // 6 is not a power of 2
	if got != nil {
		t.Errorf("GF64ReedSolomonExtend(m=6) = %v, want nil", got)
	}
}

// TestR32_P1_13_GF64ReedSolomonExtend_RejectsMTooSmall verifies that
// GF64ReedSolomonExtend returns nil when m < len(coeffs).
func TestR32_P1_13_GF64ReedSolomonExtend_RejectsMTooSmall(t *testing.T) {
	coeffs := []GF64Element{1, 2, 3, 4, 5, 6, 7, 8}
	got := GF64ReedSolomonExtend(coeffs, 4) // m < len(coeffs)
	if got != nil {
		t.Errorf("GF64ReedSolomonExtend(m=4, len(coeffs)=8) = %v, want nil", got)
	}
}

// TestR32_P1_13_GF64EvaluateOnDomain_RejectsNonPowerOf2 verifies that
// GF64EvaluateOnDomain returns nil for non-power-of-2 domainSize.
func TestR32_P1_13_GF64EvaluateOnDomain_RejectsNonPowerOf2(t *testing.T) {
	coeffs := []GF64Element{1, 2, 3}
	got := GF64EvaluateOnDomain(coeffs, 5) // 5 is not a power of 2
	if got != nil {
		t.Errorf("GF64EvaluateOnDomain(domainSize=5) = %v, want nil", got)
	}
}

// TestR32_P1_13_friGenerateLayerDomain_ReturnsNilForZeroDomainSize
// verifies that friGenerateLayerDomain returns nil when domainSize <= 0.
func TestR32_P1_13_friGenerateLayerDomain_ReturnsNilForZeroDomainSize(t *testing.T) {
	got := friGenerateLayerDomain(0, 0)
	if got != nil {
		t.Errorf("friGenerateLayerDomain(0, 0) = %v, want nil", got)
	}
	got = friGenerateLayerDomain(0, -1)
	if got != nil {
		t.Errorf("friGenerateLayerDomain(0, -1) = %v, want nil", got)
	}
}

// TestR32_P1_13_friGenerateLayerDomain_ReturnsNilForNegativeLayer
// verifies that friGenerateLayerDomain returns nil when layerIdx < 0.
func TestR32_P1_13_friGenerateLayerDomain_ReturnsNilForNegativeLayer(t *testing.T) {
	got := friGenerateLayerDomain(-1, 16)
	if got != nil {
		t.Errorf("friGenerateLayerDomain(-1, 16) = %v, want nil", got)
	}
}

// TestR32_P1_13_friGenerateLayerDomain_ReturnsNilForLargeLayer
// verifies that friGenerateLayerDomain returns nil when layerIdx >= 64
// (which would cause `1 << layerIdx` to overflow).
func TestR32_P1_13_friGenerateLayerDomain_ReturnsNilForLargeLayer(t *testing.T) {
	got := friGenerateLayerDomain(64, 16)
	if got != nil {
		t.Errorf("friGenerateLayerDomain(64, 16) = %v, want nil", got)
	}
}

// TestR32_P1_13_friFold_ReturnsNilForMismatchedLengths verifies that
// friFold returns nil when len(c) != 2*len(domain). Before R32-P1-13,
// this caused an index-out-of-range panic.
func TestR32_P1_13_friFold_ReturnsNilForMismatchedLengths(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("friFold panicked on mismatched lengths: %v", r)
		}
	}()
	c := []GF64Element{1, 2, 3, 4}
	// R37 FIX (2026-07-31): domain length must be < len(c)/2 = 2 to trigger
	// the mismatch guard. Previously [1,2,3] (len=3) was NOT < 2.
	domain := []GF64Element{1} // len(domain)=1 < len(c)/2=2
	got := friFold(c, domain, GF64Element(5))
	if got != nil {
		t.Errorf("friFold with mismatched lengths = %v, want nil", got)
	}
}

// TestR32_P1_13_friFold_ReturnsNilForTooSmallCodeword verifies that
// friFold returns nil when len(c) < 2.
func TestR32_P1_13_friFold_ReturnsNilForTooSmallCodeword(t *testing.T) {
	got := friFold([]GF64Element{1}, []GF64Element{1}, GF64Element(5))
	if got != nil {
		t.Errorf("friFold(len(c)=1) = %v, want nil", got)
	}
}

// TestR32_P1_13_FRIProve_ReturnsNilForInvalidQueryIndex verifies that
// FRIProve returns nil when a query index is out of range for layer 0.
// Before R32-P1-13, this panicked with index-out-of-range.
func TestR32_P1_13_FRIProve_ReturnsNilForInvalidQueryIndex(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FRIProve panicked on invalid query index: %v", r)
		}
	}()
	// Create a minimal valid layer setup (4-element codeword).
	codeword := []GF64Element{1, 2, 3, 4}
	layers := []*friLayer{
		{values: codeword, domain: friGenerateLayerDomain(0, 4), merkleTree: friBuildMerkleTree(codeword)},
		{values: []GF64Element{5, 6}, domain: friGenerateLayerDomain(1, 4), merkleTree: friBuildMerkleTree([]GF64Element{5, 6})},
	}
	cfg := FRIConfig{DomainSize: 4, CodeRate: 1, NumQueries: 1, FinalLayerSize: 2}
	got := FRIProve(layers, []int{99}, cfg) // 99 is out of range
	if got != nil {
		t.Errorf("FRIProve(queryIdx=99) = %v, want nil", got)
	}
}

// TestR32_P1_13_FRIVerify_RejectsInsufficientLayerRoots verifies that
// FRIVerify returns false when len(LayerRoots) < NumLayers+1. Before
// R32-P1-13, this panicked when accessing LayerRoots[i] in the Fiat-Shamir
// recomputation loop.
func TestR32_P1_13_FRIVerify_RejectsInsufficientLayerRoots(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FRIVerify panicked on insufficient LayerRoots: %v", r)
		}
	}()
	commitment := &FRICommitment{
		LayerRoots:  make([][32]byte, 1), // only 1 root, but NumLayers=3
		FinalValues: []GF64Element{1, 2, 3, 4},
		NumLayers:   3,
		DomainSize:  16,
	}
	proof := &FRIProof{Queries: []FRIQueryProof{{Layers: []friLayerProof{{}, {}, {}}}}}
	cfg := FRIConfig{DomainSize: 16, CodeRate: 4, NumQueries: 1, FinalLayerSize: 4}
	got := FRIVerify(commitment, proof, []int{0}, cfg)
	if got {
		t.Errorf("FRIVerify with insufficient LayerRoots returned true, want false")
	}
}

// TestR32_P1_13_FRIVerify_RejectsNonPowerOf2DomainSize verifies that
// FRIVerify returns false when DomainSize is not a power of 2.
func TestR32_P1_13_FRIVerify_RejectsNonPowerOf2DomainSize(t *testing.T) {
	commitment := &FRICommitment{
		LayerRoots:  make([][32]byte, 4),
		FinalValues: []GF64Element{1, 2, 3, 4},
		NumLayers:   3,
		DomainSize:  15, // not a power of 2
	}
	proof := &FRIProof{Queries: []FRIQueryProof{{Layers: []friLayerProof{{}, {}, {}}}}}
	cfg := FRIConfig{DomainSize: 15, CodeRate: 4, NumQueries: 1, FinalLayerSize: 4}
	got := FRIVerify(commitment, proof, []int{0}, cfg)
	if got {
		t.Errorf("FRIVerify with non-power-of-2 DomainSize returned true, want false")
	}
}

// TestR32_P1_13_FRIVerifyOpeningProof_RejectsEmptyLayerRoots verifies
// that FRIVerifyOpeningProof returns false when LayerRoots is empty.
// Before R32-P1-13, this panicked on `commitment.LayerRoots[0]` access.
func TestR32_P1_13_FRIVerifyOpeningProof_RejectsEmptyLayerRoots(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FRIVerifyOpeningProof panicked on empty LayerRoots: %v", r)
		}
	}()
	commitment := &FRICommitment{
		LayerRoots:  nil, // empty!
		FinalValues: []GF64Element{1, 2, 3, 4},
		NumLayers:   1,
		DomainSize:  4,
	}
	proof := &FRIOpeningProof{
		CellValue:    1,
		CellIndex:    0,
		MerkleProof:  [][]byte{},
		FRIProof:     &FRIProof{Queries: []FRIQueryProof{{Layers: []friLayerProof{{}}}}},
		QueryIndices: []int{0},
	}
	cfg := FRIConfig{DomainSize: 4, CodeRate: 4, NumQueries: 1, FinalLayerSize: 4}
	got := FRIVerifyOpeningProof(commitment, proof, cfg)
	if got {
		t.Errorf("FRIVerifyOpeningProof with empty LayerRoots returned true, want false")
	}
}

// TestR32_P1_13_FRIDEEPVerify_RejectsNegativeXiIdx verifies that
// FRIDEEPVerify returns false when XiIdx < 0.
func TestR32_P1_13_FRIDEEPVerify_RejectsNegativeXiIdx(t *testing.T) {
	// Build a minimal DEEP proof with XiIdx = -1.
	root := [32]byte{1, 2, 3}
	commitment := &FRICommitment{
		LayerRoots:  [][32]byte{root, root},
		FinalValues: []GF64Element{1, 2, 3, 4},
		NumLayers:   1,
		DomainSize:  4,
	}
	qCommitment := &FRICommitment{
		LayerRoots:  [][32]byte{root, root},
		FinalValues: []GF64Element{1, 2, 3, 4},
		NumLayers:   1,
		DomainSize:  4,
	}
	proof := &FRIDEEPProof{
		Z:           1,
		Y:           2,
		QCommitment: qCommitment,
		FCommitment: commitment,
		XiIdx:       -1, // negative!
		Xi:          1,
		FAtXi:       1,
		QAtXi:       1,
		FCellProof:  &FRIOpeningProof{CellValue: 1, CellIndex: 0, FRIProof: &FRIProof{Queries: []FRIQueryProof{{Layers: []friLayerProof{{}}}}}, QueryIndices: []int{0}},
		QCellProof:  &FRIOpeningProof{CellValue: 1, CellIndex: 0, FRIProof: &FRIProof{Queries: []FRIQueryProof{{Layers: []friLayerProof{{}}}}}, QueryIndices: []int{0}},
	}
	cfg := FRIConfig{DomainSize: 4, CodeRate: 4, NumQueries: 1, FinalLayerSize: 4}
	got := FRIDEEPVerify(proof, cfg)
	if got {
		t.Errorf("FRIDEEPVerify with XiIdx=-1 returned true, want false")
	}
}

// TestR32_P1_13_DecodeFRIDACommitment_RejectsHugeNumRoots verifies that
// DecodeFRIDACommitment returns an error when numRoots exceeds
// MaxFRIDALayerRoots. Before R32-P1-13, this caused a multi-GB allocation
// that OOM-killed the node.
func TestR32_P1_13_DecodeFRIDACommitment_RejectsHugeNumRoots(t *testing.T) {
	// Craft a serialized commitment with numRoots = 2^31 - 1.
	data := make([]byte, 24)
	// NumLayers=1, DomainSize=4, CodeRate=4, NumQueries=1, FinalLayerSize=4
	data[3] = 1  // NumLayers
	data[7] = 4  // DomainSize
	data[11] = 4 // CodeRate
	data[15] = 1 // NumQueries
	data[19] = 4 // FinalLayerSize
	// numRoots = 0x7FFFFFFF (2^31 - 1)
	data[20] = 0x7F
	data[21] = 0xFF
	data[22] = 0xFF
	data[23] = 0xFF
	_, err := DecodeFRIDACommitment(data)
	if err == nil {
		t.Errorf("DecodeFRIDACommitment with numRoots=2^31-1 returned nil error, want error")
	}
}

// TestR32_P1_13_DecodeFRIDACommitment_RejectsHugeNumFinal verifies that
// DecodeFRIDACommitment returns an error when numFinal exceeds
// MaxFRIDAFinalValues. Before R32-P1-13, this caused a multi-GB allocation.
func TestR32_P1_13_DecodeFRIDACommitment_RejectsHugeNumFinal(t *testing.T) {
	// Craft a serialized commitment with valid numRoots but huge numFinal.
	// Header: 6 uint32s = 24 bytes
	// + 1 root * 32 bytes = 32 bytes
	// + 1 uint32 for numFinal count = 4 bytes
	// Total = 60 bytes
	data := make([]byte, 60)
	// NumLayers=1
	data[3] = 1
	// DomainSize=4
	data[7] = 4
	// CodeRate=4
	data[11] = 4
	// NumQueries=1
	data[15] = 1
	// FinalLayerSize=4
	data[19] = 4
	// numRoots=1
	data[23] = 1
	// (32 bytes of root data, already zero)
	// numFinal = 0x7FFFFFFF (2^31 - 1) at offset 24+32 = 56
	data[56] = 0x7F
	data[57] = 0xFF
	data[58] = 0xFF
	data[59] = 0xFF
	_, err := DecodeFRIDACommitment(data)
	if err == nil {
		t.Errorf("DecodeFRIDACommitment with numFinal=2^31-1 returned nil error, want error")
	}
}

// TestR32_P1_13_FRIDAVerifyCell_RejectsInvalidCommitment verifies that
// FRIDAVerifyCell returns false for various invalid commitment structures.
func TestR32_P1_13_FRIDAVerifyCell_RejectsInvalidCommitment(t *testing.T) {
	cell := Cell{}

	// Empty LayerRoots.
	c := &FRIDACommitment{
		LayerRoots:     nil,
		FinalValues:    []GF64Element{1},
		NumLayers:      1,
		DomainSize:     4,
		CodeRate:       4,
		NumQueries:     1,
		FinalLayerSize: 4,
	}
	p := &FRIDACellProof{Opening: &FRIOpeningProof{CellValue: 0, CellIndex: 0, FRIProof: &FRIProof{Queries: []FRIQueryProof{{}}}, QueryIndices: []int{0}}}
	if FRIDAVerifyCell(cell, c, p, 0) {
		t.Errorf("FRIDAVerifyCell with empty LayerRoots returned true, want false")
	}

	// NumLayers <= 0.
	c2 := &FRIDACommitment{
		LayerRoots:     [][32]byte{{1}},
		FinalValues:    []GF64Element{1},
		NumLayers:      0, // invalid
		DomainSize:     4,
		CodeRate:       4,
		NumQueries:     1,
		FinalLayerSize: 4,
	}
	if FRIDAVerifyCell(cell, c2, p, 0) {
		t.Errorf("FRIDAVerifyCell with NumLayers=0 returned true, want false")
	}

	// CodeRate <= 0.
	c3 := &FRIDACommitment{
		LayerRoots:     [][32]byte{{1}},
		FinalValues:    []GF64Element{1},
		NumLayers:      1,
		DomainSize:     4,
		CodeRate:       0, // invalid
		NumQueries:     1,
		FinalLayerSize: 4,
	}
	if FRIDAVerifyCell(cell, c3, p, 0) {
		t.Errorf("FRIDAVerifyCell with CodeRate=0 returned true, want false")
	}
}

// TestR32_P1_13_verifyMerkleProof_RejectsInvalidInputs verifies that
// verifyMerkleProof returns false for invalid leafIndex/leafCount/proof.
func TestR32_P1_13_verifyMerkleProof_RejectsInvalidInputs(t *testing.T) {
	root := [32]byte{1, 2, 3}
	leaf := [32]byte{4, 5, 6}

	// leafCount <= 0.
	if verifyMerkleProof(root, leaf, 0, 0, nil) {
		t.Errorf("verifyMerkleProof(leafCount=0) returned true, want false")
	}

	// leafIndex < 0.
	if verifyMerkleProof(root, leaf, -1, 4, nil) {
		t.Errorf("verifyMerkleProof(leafIndex=-1) returned true, want false")
	}

	// leafIndex >= leafCount.
	if verifyMerkleProof(root, leaf, 4, 4, nil) {
		t.Errorf("verifyMerkleProof(leafIndex>=leafCount) returned true, want false")
	}

	// Proof length exceeds maxMerkleProofLen.
	hugeProof := make([][]byte, maxMerkleProofLen+1)
	for i := range hugeProof {
		hugeProof[i] = make([]byte, 32)
	}
	if verifyMerkleProof(root, leaf, 0, 4, hugeProof) {
		t.Errorf("verifyMerkleProof(len(proof)>max) returned true, want false")
	}

	// Sibling with wrong length.
	badProof := [][]byte{make([]byte, 16)} // should be 32 bytes
	if verifyMerkleProof(root, leaf, 0, 4, badProof) {
		t.Errorf("verifyMerkleProof(sibling len=16) returned true, want false")
	}
}

// TestR32_P1_13_verifyMerkleProofGetRoot_RejectsInvalidInputs verifies
// that verifyMerkleProofGetRoot returns false for invalid inputs. Before
// R32-P1-13, this function had NO validation at all.
func TestR32_P1_13_verifyMerkleProofGetRoot_RejectsInvalidInputs(t *testing.T) {
	leaf := [32]byte{4, 5, 6}
	var out [32]byte

	// leafCount <= 0.
	if verifyMerkleProofGetRoot(leaf, 0, 0, nil, &out) {
		t.Errorf("verifyMerkleProofGetRoot(leafCount=0) returned true, want false")
	}

	// leafIndex < 0.
	if verifyMerkleProofGetRoot(leaf, -1, 4, nil, &out) {
		t.Errorf("verifyMerkleProofGetRoot(leafIndex=-1) returned true, want false")
	}

	// leafIndex >= leafCount.
	if verifyMerkleProofGetRoot(leaf, 4, 4, nil, &out) {
		t.Errorf("verifyMerkleProofGetRoot(leafIndex>=leafCount) returned true, want false")
	}

	// Proof too long.
	hugeProof := make([][]byte, maxMerkleProofLen+1)
	for i := range hugeProof {
		hugeProof[i] = make([]byte, 32)
	}
	if verifyMerkleProofGetRoot(leaf, 0, 4, hugeProof, &out) {
		t.Errorf("verifyMerkleProofGetRoot(len(proof)>max) returned true, want false")
	}
}

// TestR32_P1_13_GF64FromBytes_ShortInputNoPanic verifies that GF64FromBytes
// handles short input (len < 8) without panicking. The missing high bytes
// are treated as zero (documented behavior after R32-P1-13).
func TestR32_P1_13_GF64FromBytes_ShortInputNoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("GF64FromBytes panicked on short input: %v", r)
		}
	}()
	// Empty input should return 0.
	if got := GF64FromBytes(nil); got != 0 {
		t.Errorf("GF64FromBytes(nil) = %d, want 0", got)
	}
	// 1-byte input should return that byte value.
	if got := GF64FromBytes([]byte{42}); got != 42 {
		t.Errorf("GF64FromBytes([42]) = %d, want 42", got)
	}
	// 7-byte input should return the 7-byte value (high byte = 0).
	short := []byte{1, 2, 3, 4, 5, 6, 7}
	got := GF64FromBytes(short)
	expected := GF64Element(0x07060504030201)
	if got != expected {
		t.Errorf("GF64FromBytes(7 bytes) = %d, want %d", got, expected)
	}
}

// TestR32_P1_13_FRICommit_ReturnsNilForInvalidConfig verifies that
// FRICommit returns (nil, nil) instead of panicking when the codeword
// length doesn't match cfg.DomainSize. Before R32-P1-13, this panicked.
func TestR32_P1_13_FRICommit_ReturnsNilForInvalidConfig(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FRICommit panicked on invalid config: %v", r)
		}
	}()
	// Codeword length doesn't match DomainSize.
	codeword := []GF64Element{1, 2, 3} // len=3
	cfg := FRIConfig{DomainSize: 4, CodeRate: 4, NumQueries: 1, FinalLayerSize: 4}
	gotC, gotL := FRICommit(codeword, cfg)
	if gotC != nil || gotL != nil {
		t.Errorf("FRICommit(codeword len mismatch) = (%v, %v), want (nil, nil)", gotC, gotL)
	}
}

// TestR32_P1_13_FRICommit_ReturnsNilForNonPowerOf2DomainSize verifies
// that FRICommit returns (nil, nil) when DomainSize is not a power of 2.
func TestR32_P1_13_FRICommit_ReturnsNilForNonPowerOf2DomainSize(t *testing.T) {
	codeword := []GF64Element{1, 2, 3, 4, 5, 6} // len=6
	cfg := FRIConfig{DomainSize: 6, CodeRate: 4, NumQueries: 1, FinalLayerSize: 4}
	gotC, gotL := FRICommit(codeword, cfg)
	if gotC != nil || gotL != nil {
		t.Errorf("FRICommit(non-power-of-2 DomainSize) = (%v, %v), want (nil, nil)", gotC, gotL)
	}
}
