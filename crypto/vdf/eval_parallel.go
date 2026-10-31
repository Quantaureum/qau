// Quantaureum Node source, version 1.0.0.
package vdf

import "errors"

// ErrVDFCanceled is returned by ExecuteVDFParallelStop when the caller's
// stop channel closed before the evaluation finished.
var ErrVDFCanceled = errors.New("vdf: evaluation canceled")

// ExecuteVDFParallel is ExecuteVDF with the per-step matvec partitioned
// across `workers` goroutines (bit-identical output; see
// TestExecuteVDFParallelEquivalence). workers <= 1 falls back to the serial
// path.
func ExecuteVDFParallel(y StateVector, a Matrix, rep, time int, q uint64, workers int) *VDFOutput {
	out, err := ExecuteVDFParallelStop(nil, y, a, rep, time, q, workers)
	if err != nil {
		// Unreachable: a nil stop channel can never fire.
		panic("vdf: unexpected cancellation with a nil stop channel")
	}
	return out
}

// ExecuteVDFParallelStop is ExecuteVDFParallel with a cancellation hook
// (R24, 2026-10-30).
//
// The witness buffer grows by one full state vector per timestep, so an
// evaluation that is left running after its caller gave up (the beacon
// timeout path) keeps consuming memory until it finishes. The stop channel
// lets the abandoned evaluator exit early: it is checked every 64 timesteps
// (a negligible overhead), the partially grown buffers become collectable,
// and the caller observes ErrVDFCanceled. A nil channel never fires —
// that form is bit-identical to ExecuteVDFParallel.
func ExecuteVDFParallelStop(stop <-chan struct{}, y StateVector, a Matrix, rep, time int, q uint64, workers int) (*VDFOutput, error) {
	if time%rep != 0 {
		panic("vdf: time not divisible by rep")
	}
	intermediateEvery := time / rep
	red := NewReducer(q)

	am := make(Matrix, len(a))
	for i, row := range a {
		am[i] = montVec(row, red)
	}

	canceled := func(i int) bool {
		if stop == nil || i%64 != 0 {
			return false
		}
		select {
		case <-stop:
			return true
		default:
			return false
		}
	}

	var witness []Element
	witness = append(witness, DecomposeVector(y, q)...)

	rem := y
	current := DecomposeVector(y, q)
	currentM := montVec(current, red)
	intermediates := make([]StateVector, 0, rep)
	for i := 0; i < time-1; i++ {
		if canceled(i) {
			return nil, ErrVDFCanceled
		}
		if i%intermediateEvery == 0 && i != 0 {
			intermediates = append(intermediates, rem)
		}
		rem = NegVector(fromMontVec(MatVecMontParallel(am, currentM, red, workers), red), q)
		current = DecomposeVector(rem, q)
		currentM = montVec(current, red)
		witness = append(witness, current...)
	}
	if stop != nil {
		select {
		case <-stop:
			return nil, ErrVDFCanceled
		default:
		}
	}
	output := fromMontVec(MatVecMontParallel(am, currentM, red, workers), red)

	return &VDFOutput{
		Witness:       witness,
		OutputImage:   output,
		Intermediates: intermediates,
	}, nil
}
