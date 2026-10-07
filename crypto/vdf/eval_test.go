// Quantaureum Node source, version 1.0.0.
package vdf

import (
	"math/rand"
	"testing"
)

// randomSubringElement samples a native vector over the full coefficient
// range [0, q); with LogQBits = 63 the decompose/reconstruct round trip is
// exact for every value.
func randomSubringElement(r *rand.Rand, q uint64) Element {
	var n [NativeDegree]uint64
	for i := range n {
		n[i] = r.Uint64() % q
	}
	return FromNative(n, q)
}

func randomMatrix(r *rand.Rand, q uint64, rows int) Matrix {
	m := make(Matrix, rows)
	for i := range m {
		m[i] = make([]Element, ModuleSize*LogQBits)
		for j := range m[i] {
			m[i][j] = randomSubringElement(r, q)
		}
	}
	return m
}

func TestDecomposeReconstructRoundTrip(t *testing.T) {
	q := QBC
	r := rand.New(rand.NewSource(10))
	for i := 0; i < 20; i++ {
		e := randomSubringElement(r, q)
		chunks := Decompose(e, q)
		// Every chunk must be binary in the native representation.
		for _, c := range chunks {
			n := ToNative(c, q)
			for _, v := range n {
				if v != 0 && v != 1 {
					t.Fatalf("non-binary chunk coefficient %d", v)
				}
			}
		}
		back := ReconstructVector(chunks[:], q)
		if len(back) != 1 {
			t.Fatalf("reconstruct length = %d, want 1", len(back))
		}
		if !back[0].Equal(e) {
			t.Fatalf("round-trip mismatch on iteration %d", i)
		}
	}
}

// TestExecuteVDFSelfConsistent mirrors the reference test_vdf invariants:
//
//	G·w[0] = y,  G·w[i] + A·w[i-1] = 0 for 0 < i < time,  A·w[time-1] = output.
func TestExecuteVDFSelfConsistent(t *testing.T) {
	q := QBC
	time, rep := 8, 2
	r := rand.New(rand.NewSource(11))

	y := make(StateVector, ModuleSize)
	for i := range y {
		y[i] = randomSubringElement(r, q)
	}
	a := randomMatrix(r, q, ModuleSize)

	out := ExecuteVDF(y, a, rep, time, q)

	if len(out.Witness) != WitnessLen(time) {
		t.Fatalf("witness length = %d, want %d", len(out.Witness), WitnessLen(time))
	}

	w := func(step int) []Element {
		lo := step * ModuleSize * LogQBits
		return out.Witness[lo : lo+ModuleSize*LogQBits]
	}

	if !ReconstructVector(w(0), q)[0].Equal(y[0]) {
		t.Fatal("G·w[0] != y[0]")
	}
	for i := 0; i < ModuleSize; i++ {
		if !ReconstructVector(w(0), q)[i].Equal(y[i]) {
			t.Fatalf("G·w[0] != y at element %d", i)
		}
	}

	zero := Element{}
	for step := 1; step < time-1; step++ {
		gw := ReconstructVector(w(step), q)
		aw := MatVec(a, w(step-1), q)
		for i := 0; i < ModuleSize; i++ {
			if !gw[i].Add(aw[i], q).Equal(zero) {
				t.Fatalf("G·w[%d] + A·w[%d] != 0 at element %d", step, step-1, i)
			}
		}
	}

	final := MatVec(a, w(time-1), q)
	for i := 0; i < ModuleSize; i++ {
		if !final[i].Equal(out.OutputImage[i]) {
			t.Fatalf("A·w[time-1] != output at element %d", i)
		}
	}

	if len(out.Intermediates) != rep-1 {
		t.Fatalf("intermediates = %d, want %d (states after step 1..time-2 sampled every %d)",
			len(out.Intermediates), rep-1, time/rep)
	}
}

func BenchmarkMatVecStep(b *testing.B) {
	q := QBC
	r := rand.New(rand.NewSource(12))
	a := randomMatrix(r, q, ModuleSize)
	w := make([]Element, ModuleSize*LogQBits)
	for i := range w {
		w[i] = randomSubringElement(r, q)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = MatVec(a, w, q)
	}
}
