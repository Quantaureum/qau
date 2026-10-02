// Quantaureum Node source, version 1.0.0.
package vdf

import (
	"math/rand"
	"runtime"
	"testing"

	"golang.org/x/crypto/sha3"
)

// TestMatVecMontParallelEquivalence verifies that the row-partitioned
// parallel matvec is bit-identical to the serial path for every worker
// count. This is the core invariant the distributed prover relies on:
// disjoint row ownership must merge deterministically.
func TestMatVecMontParallelEquivalence(t *testing.T) {
	q := QBC
	red := NewReducer(q)
	r := rand.New(rand.NewSource(21))
	a := randomMatrix(r, q, ModuleSize)
	aM := montVecRows(a, red)
	w := make([]Element, ModuleSize*LogQBits)
	for i := range w {
		w[i] = randomSubringElement(r, q)
	}
	wM := montVec(w, red)

	want := matVecMont(aM, wM, red)
	for _, workers := range []int{1, 2, 3, 4, 7, 8, 16} {
		got := MatVecMontParallel(aM, wM, red, workers)
		for i := range got {
			if !got[i].Equal(want[i]) {
				t.Fatalf("workers=%d: row %d differs from serial result", workers, i)
			}
		}
	}
}

// TestExecuteVDFParallelEquivalence runs the full evaluation with parallel
// matvec and compares the final image and witness hash against the serial
// execution.
func TestExecuteVDFParallelEquivalence(t *testing.T) {
	q := QBC
	time := 6
	r := rand.New(rand.NewSource(22))
	y := make(StateVector, ModuleSize)
	for i := range y {
		y[i] = randomSubringElement(r, q)
	}
	a := randomMatrix(r, q, ModuleSize)

	serial := ExecuteVDF(y, a, 1, time, q)
	par := ExecuteVDFParallel(y, a, 1, time, q, 4)

	for i := range serial.OutputImage {
		if !serial.OutputImage[i].Equal(par.OutputImage[i]) {
			t.Fatalf("output element %d differs", i)
		}
	}
	if len(serial.Witness) != len(par.Witness) {
		t.Fatalf("witness length %d != %d", len(par.Witness), len(serial.Witness))
	}
	for i := range serial.Witness {
		if !serial.Witness[i].Equal(par.Witness[i]) {
			t.Fatalf("witness element %d differs", i)
		}
	}
}

// montVecRows converts a plain matrix to Montgomery form row by row.
func montVecRows(a Matrix, red *Reducer) Matrix {
	out := make(Matrix, len(a))
	for i, row := range a {
		out[i] = montVec(row, red)
	}
	return out
}

// BenchmarkMatVecMontParallel measures row-partitioned scaling of the
// Montgomery matvec, the pattern underlying cross-machine proof sharding.
func BenchmarkMatVecMontParallel(b *testing.B) {
	q := QBC
	red := NewReducer(q)
	r := rand.New(rand.NewSource(23))
	a := randomMatrix(r, q, ModuleSize)
	aM := montVecRows(a, red)
	w := make([]Element, ModuleSize*LogQBits)
	for i := range w {
		w[i] = randomSubringElement(r, q)
	}
	wM := montVec(w, red)

	workers := runtime.NumCPU()
	if workers > 14 {
		workers = 14 // one per matrix row
	}
	for _, n := range []int{1, 2, 4, workers} {
		b.Run("workers="+itoa(n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = MatVecMontParallel(aM, wM, red, n)
			}
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestExecuteVDFLightEquivalence checks that the streaming light variant
// produces the same output image and the same witness hash as ExecuteVDF.
func TestExecuteVDFLightEquivalence(t *testing.T) {
	q := QBC
	time := 6
	r := rand.New(rand.NewSource(24))
	y := make(StateVector, ModuleSize)
	for i := range y {
		y[i] = randomSubringElement(r, q)
	}
	a := randomMatrix(r, q, ModuleSize)

	full := ExecuteVDF(y, a, 1, time, q)
	image, whash, err := ExecuteVDFLight(y, a, time, q, 4)
	if err != nil {
		t.Fatal(err)
	}
	for i := range full.OutputImage {
		if !full.OutputImage[i].Equal(image[i]) {
			t.Fatalf("light output element %d differs", i)
		}
	}
	ref := sha3.New256()
	for _, e := range full.Witness {
		var buf [8]byte
		for _, c := range e {
			v := c
			for k := 0; k < 8; k++ {
				buf[k] = byte(v >> (8 * uint(k)))
				v >>= 8
			}
			ref.Write(buf[:])
		}
	}
	var want [32]byte
	ref.Sum(want[:0])
	if whash != want {
		t.Fatal("light witness hash differs from full witness hash")
	}
}
