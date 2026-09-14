// Quantaureum Node source, version 1.0.0.
// Package encoding - R37-P3-15 regression tests.
//
// R36-P2-ENC-01 capped DomainSize at 2^31 only inside DecodeFRIDACommitment,
// but commitments can reach FRIDAVerifyCell / FRIVerify without passing
// through the decoder. A DomainSize of 2^32 passes the power-of-2 checks in
// both verifiers, then FRIGenerateQueryIndices casts it to uint32, wrapping
// to 0 and causing a divide-by-zero panic. The R37-P3-15 fix rejects
// DomainSize > MaxFRIDADomainSize in both verification paths.
package encoding

import (
	"testing"
)

// TestR37_P3_15_FRIDAVerifyCell_RejectsOversizedDomainSize verifies that
// FRIDAVerifyCell returns false (instead of panicking) for a commitment with
// DomainSize = 2^32. Before R37-P3-15, this panicked inside
// FRIGenerateQueryIndices with an integer-divide-by-zero.
func TestR37_P3_15_FRIDAVerifyCell_RejectsOversizedDomainSize(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FRIDAVerifyCell panicked on DomainSize=2^32: %v (should return false)", r)
		}
	}()
	commitment := &FRIDACommitment{
		LayerRoots:     [][32]byte{{1}, {2}},
		FinalValues:    []GF64Element{1},
		NumLayers:      1,
		DomainSize:     1 << 32, // power of 2, passes the structural check
		CodeRate:       4,
		NumQueries:     1,
		FinalLayerSize: 4,
	}
	proof := &FRIDACellProof{
		Opening: &FRIOpeningProof{
			CellValue:    0,
			CellIndex:    0,
			FRIProof:     &FRIProof{Queries: []FRIQueryProof{{Layers: []friLayerProof{{}}}}},
			QueryIndices: []int{0},
		},
	}
	var cell Cell
	if FRIDAVerifyCell(cell, commitment, proof, 0) {
		t.Errorf("FRIDAVerifyCell with DomainSize=2^32 returned true, want false")
	}
}

// TestR37_P3_15_FRIVerify_RejectsOversizedDomainSize verifies that FRIVerify
// returns false for a commitment with DomainSize = 2^32.
func TestR37_P3_15_FRIVerify_RejectsOversizedDomainSize(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FRIVerify panicked on DomainSize=2^32: %v (should return false)", r)
		}
	}()
	commitment := &FRICommitment{
		LayerRoots:  [][32]byte{{1}, {2}},
		FinalValues: []GF64Element{1},
		NumLayers:   1,
		DomainSize:  1 << 32, // power of 2, passes the structural check
	}
	proof := &FRIProof{Queries: []FRIQueryProof{{Layers: []friLayerProof{{}}}}}
	cfg := FRIConfig{DomainSize: 1 << 32, CodeRate: 4, NumQueries: 1, FinalLayerSize: 4}
	if FRIVerify(commitment, proof, []int{0}, cfg) {
		t.Errorf("FRIVerify with DomainSize=2^32 returned true, want false")
	}
}

// TestR37_P3_15_FRIGenerateQueryIndices_AcceptsMaxDomainSize verifies the
// boundary: DomainSize == MaxFRIDADomainSize (2^31) must remain usable —
// uint32(2^31) does not wrap to 0, so index generation must not panic and
// must return in-range indices.
func TestR37_P3_15_FRIGenerateQueryIndices_AcceptsMaxDomainSize(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("FRIGenerateQueryIndices panicked on DomainSize=2^31: %v", r)
		}
	}()
	commitment := &FRICommitment{
		LayerRoots:  [][32]byte{{1}, {2}},
		FinalValues: []GF64Element{1},
		NumLayers:   1,
		DomainSize:  MaxFRIDADomainSize,
	}
	indices := FRIGenerateQueryIndices(commitment, 4)
	if len(indices) != 4 {
		t.Fatalf("FRIGenerateQueryIndices returned %d indices, want 4", len(indices))
	}
	for i, idx := range indices {
		if idx < 0 || idx >= MaxFRIDADomainSize {
			t.Errorf("indices[%d] = %d, out of range [0, %d)", i, idx, MaxFRIDADomainSize)
		}
	}
}
