// Quantaureum Node source, version 1.0.0.
//go:build race

package consensus

// raceEnabled reports that the test binary was built with the race detector.
// Wall-clock latency budgets cannot be asserted under the detector (its
// instrumentation slows execution 5-20x), so budget-guarded tests consult
// this flag and skip instead (see TestLargeScale_*Latency).
const raceEnabled = true
