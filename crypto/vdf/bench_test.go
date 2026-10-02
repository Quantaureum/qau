// Quantaureum Node source, version 1.0.0.
package vdf

import (
	"math/rand"
	"testing"
)

func BenchmarkElementMul(b *testing.B) {
	q := QBC
	r := rand.New(rand.NewSource(7))
	a := randElement(r, q)
	c := randElement(r, q)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a = a.Mul(c, q)
	}
}

func BenchmarkMulMod(b *testing.B) {
	q := QBC
	a := rand.Uint64() % q
	c := rand.Uint64() % q
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a = MulMod(a, c, q)
	}
}

// BenchmarkMatVecStepMont measures the Montgomery hot path used by
// ExecuteVDF (A pre-converted, per-step w conversion included).
func BenchmarkMatVecStepMont(b *testing.B) {
	q := QBC
	red := NewReducer(q)
	r := rand.New(rand.NewSource(14))
	a := randomMatrix(r, q, ModuleSize)
	aM := make(Matrix, len(a))
	for i, row := range a {
		aM[i] = montVec(row, red)
	}
	w := make([]Element, ModuleSize*LogQBits)
	for i := range w {
		w[i] = randomSubringElement(r, q)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matVecMont(aM, montVec(w, red), red)
	}
}

// BenchmarkExecuteVDFShort runs a tiny full evaluation end to end.
func BenchmarkExecuteVDFShort(b *testing.B) {
	q := QBC
	r := rand.New(rand.NewSource(15))
	y := make(StateVector, ModuleSize)
	for i := range y {
		y[i] = randomSubringElement(r, q)
	}
	a := randomMatrix(r, q, ModuleSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExecuteVDF(y, a, 1, 4, q)
	}
}
