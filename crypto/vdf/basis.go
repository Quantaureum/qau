// Quantaureum Node source, version 1.0.0.
package vdf

import "math/rand"

// Fixed structural parameters of the Papercraft conductor-24 ring, mirrored
// from the reference implementation's custom_ring/static_generated_24.rs.
// The basis matrices map between the 8-coefficient Φ_24 representation and a
// 4-coefficient "native" representation; their q-1 entries depend on the
// active modulus, so they are constructed per-q rather than hardcoded.

// NativeDegree is the dimension of the native (twisted) representation.
const NativeDegree = 4

// LogQBits is the number of radix-2 decomposition chunks per native
// coefficient. The reference implementation used 62, which silently drops
// bit 62 for native coefficients in [2^62, q) (q slightly exceeds 2^62),
// truncating the sequential function and opening a grinding vector. We use
// 63 so every coefficient in [0, q) decomposes exactly — with q < 2^63,
// bits 0..62 cover the full range.
const LogQBits = 63

// ModuleSize is the number of ring elements per state vector (MODULE_SIZE).
const ModuleSize = 14

// BasisFor returns the native→Φ24 basis matrix (8×4) for modulus q.
func BasisFor(q uint64) [Phi][NativeDegree]uint64 {
	return [Phi][NativeDegree]uint64{
		{q - 1, 0, 0, 0},
		{0, 0, 0, 1},
		{0, 0, 0, 0},
		{0, q - 1, 0, 0},
		{0, 0, 0, 0},
		{0, 0, 0, q - 1},
		{0, 0, q - 1, 0},
		{0, 0, 0, 0},
	}
}

// InvBasisFor returns the Φ24→native basis matrix (4×8) for modulus q.
func InvBasisFor(q uint64) [NativeDegree][Phi]uint64 {
	return [NativeDegree][Phi]uint64{
		{q - 1, 0, 0, 0, 0, 0, 0, 0},
		{0, 0, 0, q - 1, 0, 0, 0, 0},
		{0, 0, q - 1, 0, 0, 0, q - 1, 0},
		{0, 0, 0, 0, 0, q - 1, 0, 0},
	}
}

// ToNative maps a Φ24-representation element to its 4 native coefficients
// via INV_BASIS.
func ToNative(e Element, q uint64) [NativeDegree]uint64 {
	inv := InvBasisFor(q)
	var out [NativeDegree]uint64
	for i := 0; i < NativeDegree; i++ {
		var acc uint64
		for j := 0; j < Phi; j++ {
			acc = AddMod(acc, MulMod(inv[i][j], e[j], q), q)
		}
		out[i] = acc
	}
	return out
}

// FromNative maps 4 native coefficients back to the Φ24 representation
// via BASIS.
func FromNative(n [NativeDegree]uint64, q uint64) Element {
	b := BasisFor(q)
	var out Element
	for i := 0; i < Phi; i++ {
		var acc uint64
		for j := 0; j < NativeDegree; j++ {
			acc = AddMod(acc, MulMod(b[i][j], n[j], q), q)
		}
		out[i] = acc
	}
	return out
}

// RandomNative returns a deterministic pseudo-random native vector for tests
// and benchmarks; production callers derive inputs from beacon randomness.
func RandomNative(r *rand.Rand, q uint64) [NativeDegree]uint64 {
	var n [NativeDegree]uint64
	for i := range n {
		n[i] = r.Uint64() % q
	}
	return n
}
