// Quantaureum Node source, version 1.0.0.
// Package encoding - R37-P3-14 regression tests.
//
// DecodeFRIDACommitment previously did not bound NumQueries: an attacker
// could supply NumQueries = 2^32-1, which (a) wraps to a negative int on
// 32-bit builds and (b) is far beyond any legitimate FRI configuration,
// enabling oversized allocations downstream. The R37-P3-14 fix caps it at
// MaxFRIDANumQueries (4096).
package encoding

import (
	"testing"
)

// r37BuildFRIDACommitmentBytes builds a minimal serialized FRIDACommitment
// with the given NumQueries. Layout: 6 uint32 header (NumLayers, DomainSize,
// CodeRate, NumQueries, FinalLayerSize, numRoots) + numRoots*32 + uint32
// numFinal + numFinal*8.
func r37BuildFRIDACommitmentBytes(numQueries uint32) []byte {
	data := make([]byte, 24+32+4+8)
	put := func(off int, v uint32) {
		data[off] = byte(v >> 24)
		data[off+1] = byte(v >> 16)
		data[off+2] = byte(v >> 8)
		data[off+3] = byte(v)
	}
	put(0, 1)           // NumLayers
	put(4, 4)           // DomainSize
	put(8, 4)           // CodeRate
	put(12, numQueries) // NumQueries
	put(16, 4)          // FinalLayerSize
	put(20, 1)          // numRoots
	put(24+32+0, 1)     // numFinal (after the single 32-byte root)
	return data
}

// TestR37_P3_14_DecodeFRIDACommitment_RejectsHugeNumQueries verifies that
// DecodeFRIDACommitment rejects NumQueries = 2^32-1. Before R37-P3-14 this
// value was accepted, risking negative-int wraparound on 32-bit builds and
// oversized allocations.
func TestR37_P3_14_DecodeFRIDACommitment_RejectsHugeNumQueries(t *testing.T) {
	data := r37BuildFRIDACommitmentBytes(0xFFFFFFFF)
	_, err := DecodeFRIDACommitment(data)
	if err == nil {
		t.Errorf("DecodeFRIDACommitment with NumQueries=2^32-1 returned nil error, want error")
	}
}

// TestR37_P3_14_DecodeFRIDACommitment_RejectsNumQueriesAboveMax verifies
// that NumQueries just above the cap is rejected.
func TestR37_P3_14_DecodeFRIDACommitment_RejectsNumQueriesAboveMax(t *testing.T) {
	data := r37BuildFRIDACommitmentBytes(MaxFRIDANumQueries + 1)
	_, err := DecodeFRIDACommitment(data)
	if err == nil {
		t.Errorf("DecodeFRIDACommitment with NumQueries=MaxFRIDANumQueries+1 returned nil error, want error")
	}
}

// TestR37_P3_14_DecodeFRIDACommitment_AcceptsNumQueriesAtMax verifies the
// boundary: NumQueries == MaxFRIDANumQueries must still decode successfully.
func TestR37_P3_14_DecodeFRIDACommitment_AcceptsNumQueriesAtMax(t *testing.T) {
	data := r37BuildFRIDACommitmentBytes(MaxFRIDANumQueries)
	c, err := DecodeFRIDACommitment(data)
	if err != nil {
		t.Fatalf("DecodeFRIDACommitment with NumQueries=MaxFRIDANumQueries returned error: %v", err)
	}
	if c.NumQueries != MaxFRIDANumQueries {
		t.Errorf("NumQueries = %d, want %d", c.NumQueries, MaxFRIDANumQueries)
	}
}

// TestR37_P3_14_DecodeFRIDACommitment_AcceptsLegitNumQueries verifies that a
// typical production value (80 queries) still decodes successfully.
func TestR37_P3_14_DecodeFRIDACommitment_AcceptsLegitNumQueries(t *testing.T) {
	data := r37BuildFRIDACommitmentBytes(80)
	c, err := DecodeFRIDACommitment(data)
	if err != nil {
		t.Fatalf("DecodeFRIDACommitment with NumQueries=80 returned error: %v", err)
	}
	if c.NumQueries != 80 {
		t.Errorf("NumQueries = %d, want 80", c.NumQueries)
	}
}
