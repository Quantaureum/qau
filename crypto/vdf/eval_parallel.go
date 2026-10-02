// Quantaureum Node source, version 1.0.0.
package vdf

// ExecuteVDFParallel is ExecuteVDF with the per-step matvec partitioned
// across `workers` goroutines (bit-identical output; see
// TestExecuteVDFParallelEquivalence). workers <= 1 falls back to the serial
// path.
func ExecuteVDFParallel(y StateVector, a Matrix, rep, time int, q uint64, workers int) *VDFOutput {
	if time%rep != 0 {
		panic("vdf: time not divisible by rep")
	}
	intermediateEvery := time / rep
	red := NewReducer(q)

	am := make(Matrix, len(a))
	for i, row := range a {
		am[i] = montVec(row, red)
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
		rem = NegVector(fromMontVec(MatVecMontParallel(am, currentM, red, workers), red), q)
		current = DecomposeVector(rem, q)
		currentM = montVec(current, red)
		witness = append(witness, current...)
	}
	output := fromMontVec(MatVecMontParallel(am, currentM, red, workers), red)

	return &VDFOutput{
		Witness:       witness,
		OutputImage:   output,
		Intermediates: intermediates,
	}
}
