// Quantaureum Node source, version 1.0.0.
package vdf

import (
	"fmt"
	"sync"

	"golang.org/x/crypto/sha3"
)

// Matrix is the sequential-function matrix A: ModuleSize rows of
// ModuleSize*LogQBits ring elements, matching the reference layout.
type Matrix [][]Element

// StateVector is a vector of ModuleSize ring elements.
type StateVector = []Element

// Decompose returns the radix-2 decomposition of a ring element: the element
// is mapped to its native coefficients, each split LSB-first into LogQBits
// binary chunks, and every chunk is mapped back through BASIS. This is the
// G^-1 operator of the construction.
//
// Known reference edge case (documented, replicated bit-exactly): a native
// coefficient >= 2^LogQBits loses its top bit, because q slightly exceeds
// 2^62. The stage-2 specification must either bound coefficients below 2^62
// or widen the chunk count.
func Decompose(e Element, q uint64) [LogQBits]Element {
	native := ToNative(e, q)
	basis := BasisFor(q)
	var chunks [LogQBits]Element
	for k := 0; k < NativeDegree; k++ {
		val := native[k]
		for c := 0; c < LogQBits; c++ {
			if val&1 == 1 {
				chunks[c][k] = 1
			}
			val >>= 1
		}
	}
	for c := 0; c < LogQBits; c++ {
		// chunks[c] currently holds native (degree-4) bit values; map to Φ24.
		var acc Element
		for i := 0; i < Phi; i++ {
			var s uint64
			for j := 0; j < NativeDegree; j++ {
				s = AddMod(s, MulMod(basis[i][j], chunks[c][j], q), q)
			}
			acc[i] = s
		}
		chunks[c] = acc
	}
	return chunks
}

// DecomposeVector flattens Decompose over a state vector, producing
// len(v)*LogQBits elements in the reference's element-major order.
func DecomposeVector(v StateVector, q uint64) []Element {
	out := make([]Element, 0, len(v)*LogQBits)
	for _, e := range v {
		chunks := Decompose(e, q)
		out = append(out, chunks[:]...)
	}
	return out
}

// ReconstructVector applies the gadget reconstruction G·w: element i of the
// output is Σ_b 2^b · w[i*LogQBits+b]. It is the inverse of DecomposeVector
// on the subring (up to the documented 62-bit edge case).
func ReconstructVector(w []Element, q uint64) StateVector {
	if len(w)%LogQBits != 0 {
		panic("vdf: witness length not a multiple of LogQBits")
	}
	out := make(StateVector, len(w)/LogQBits)
	for i := range out {
		var acc Element
		base := i * LogQBits
		for b := 0; b < LogQBits; b++ {
			f := uint64(1) << uint(b)
			for k := 0; k < Phi; k++ {
				acc[k] = AddMod(acc[k], MulMod(f, w[base+b][k], q), q)
			}
		}
		out[i] = acc
	}
	return out
}

// MatVec returns A·w over the ring.
func MatVec(a Matrix, w []Element, q uint64) StateVector {
	out := make(StateVector, len(a))
	for i, row := range a {
		var acc Element
		for j := range row {
			acc = acc.Add(row[j].Mul(w[j], q), q)
		}
		out[i] = acc
	}
	return out
}

// montElement converts an element into Montgomery form coefficient-wise.
func montElement(e Element, red *Reducer) Element {
	var out Element
	for i, c := range e {
		if c != 0 {
			out[i] = red.ToMont(c)
		}
	}
	return out
}

// MatVecMontParallel is MatVec over Montgomery-form operands, with rows
// partitioned across `workers` goroutines. Row sets are disjoint, so no
// synchronization is needed and the merge is bit-exact by construction —
// the same partition pattern the distributed prover uses across machines
// (each machine owns a row range and returns exactly those rows).
func MatVecMontParallel(aM Matrix, wM []Element, red *Reducer, workers int) StateVector {
	if workers <= 1 || len(aM) <= 1 {
		return matVecMont(aM, wM, red)
	}
	out := make(StateVector, len(aM))
	chunk := (len(aM) + workers - 1) / workers
	var wg sync.WaitGroup
	for wk := 0; wk*chunk < len(aM); wk++ {
		lo := wk * chunk
		hi := lo + chunk
		if hi > len(aM) {
			hi = len(aM)
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				var acc Element
				for j := range aM[i] {
					acc = acc.Add(red.MulElement(aM[i][j], wM[j]), red.Q)
				}
				out[i] = acc
			}
		}(lo, hi)
	}
	wg.Wait()
	return out
}

// NegVector returns -v element-wise.
func NegVector(v StateVector, q uint64) StateVector {
	out := make(StateVector, len(v))
	for i, e := range v {
		out[i] = e.Neg(q)
	}
	return out
}

// VDFOutput mirrors the reference VDFOutputMat: the flat binary witness of
// every step, the final image A·w_last, and the intermediate states sampled
// every time/rep steps.
type VDFOutput struct {
	Witness       []Element
	OutputImage   StateVector
	Intermediates []StateVector
}

// ExecuteVDF runs the sequential function x_{i+1} = -(A · G^-1(x_i)) for
// `time` steps, recording the G^-1 image of every state as the witness.
// rep must divide time; intermediate states are captured every time/rep
// steps. This mirrors the reference execute_vdf step for step.
//
// The matrix A is converted to Montgomery form once; each step runs the
// matvec entirely in the Montgomery domain and only the 14-element state is
// converted back for the bit decomposition.
func ExecuteVDF(y StateVector, a Matrix, rep, time int, q uint64) *VDFOutput {
	if time%rep != 0 {
		panic("vdf: time not divisible by rep")
	}
	intermediateEvery := time / rep
	red := NewReducer(q)

	am := make(Matrix, len(a))
	for i, row := range a {
		am[i] = make([]Element, len(row))
		for j, e := range row {
			am[i][j] = montElement(e, red)
		}
	}

	var witness []Element
	witness = append(witness, DecomposeVector(y, q)...)

	rem := y
	current := DecomposeVector(y, q)
	currentM := montVec(current, red)
	intermediates := make([]StateVector, 0, rep)
	for i := 0; i < time-1; i++ {
		if i%intermediateEvery == 0 && i != 0 {
			intermediates = append(intermediates, rem)
		}
		rem = NegVector(fromMontVec(matVecMont(am, currentM, red), red), q)
		current = DecomposeVector(rem, q)
		currentM = montVec(current, red)
		witness = append(witness, current...)
	}
	output := fromMontVec(matVecMont(am, currentM, red), red)

	return &VDFOutput{
		Witness:       witness,
		OutputImage:   output,
		Intermediates: intermediates,
	}
}

// ExecuteVDFLight runs the same sequential evaluation as ExecuteVDF but
// never retains the witness: each step's decomposition is hashed into a
// running SHA3-256 state and discarded. Memory stays at O(matrix + one
// step) instead of O(time), which is what re-evaluating validators need
// (they compare the output image, not the witness). Returns the final
// image and the streaming witness hash (identical to hashing the flat
// witness that ExecuteVDF would return).
//
// rep/intermediates semantics of ExecuteVDF do not apply here: light mode
// records no intermediate states.
func ExecuteVDFLight(y StateVector, a Matrix, time int, q uint64, workers int) (StateVector, [32]byte, error) {
	if time < 1 {
		return nil, [32]byte{}, fmt.Errorf("vdf: time must be >= 1")
	}
	red := NewReducer(q)

	am := make(Matrix, len(a))
	for i, row := range a {
		am[i] = make([]Element, len(row))
		for j, e := range row {
			am[i][j] = montElement(e, red)
		}
	}

	h := sha3.New256()
	writeStep := func(elements []Element) {
		for _, e := range elements {
			for _, c := range e {
				var buf [8]byte
				v := c
				for k := 0; k < 8; k++ {
					buf[k] = byte(v >> (8 * uint(k)))
					v >>= 8
				}
				h.Write(buf[:])
			}
		}
	}

	current := DecomposeVector(y, q)
	currentM := montVec(current, red)
	writeStep(current)

	for i := 0; i < time-1; i++ {
		remM := MatVecMontParallel(am, currentM, red, workers)
		rem := fromMontVec(remM, red)
		rem = NegVector(rem, q)
		current = DecomposeVector(rem, q)
		currentM = montVec(current, red)
		writeStep(current)
	}
	output := fromMontVec(matVecMont(am, currentM, red), red)

	var witnessHash [32]byte
	h.Sum(witnessHash[:0])
	return output, witnessHash, nil
}

// montVec converts a state vector into Montgomery form.
func montVec(v StateVector, red *Reducer) []Element {
	out := make([]Element, len(v))
	for i, e := range v {
		out[i] = montElement(e, red)
	}
	return out
}

// fromMontVec converts a Montgomery vector back to plain residues.
func fromMontVec(v []Element, red *Reducer) []Element {
	out := make([]Element, len(v))
	for i, e := range v {
		for k, c := range e {
			if c != 0 {
				out[i][k] = red.FromMont(c)
			}
		}
	}
	return out
}

// matVecMont returns A·w for Montgomery-form operands, result in Montgomery
// form.
func matVecMont(a Matrix, w []Element, red *Reducer) StateVector {
	out := make(StateVector, len(a))
	for i, row := range a {
		var acc Element
		for j := range row {
			acc = acc.Add(red.MulElement(row[j], w[j]), red.Q)
		}
		out[i] = acc
	}
	return out
}

// WitnessLen returns the flat witness length for a given time parameter.
func WitnessLen(time int) int { return time * ModuleSize * LogQBits }
