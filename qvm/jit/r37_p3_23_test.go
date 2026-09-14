// Quantaureum Node source, version 1.0.0.
package jit

import (
	"testing"
	"time"
)

// R37-P3-23 regression tests: PrecompileQueue.Stop() must be idempotent —
// calling it more than once must not panic (previously double-close of
// stopCh panicked).

func TestR37_P3_23_StopIdempotentAfterStart(t *testing.T) {
	q := NewPrecompileQueue(NewJITCompiler(16), 16)
	q.Start(time.Millisecond)
	q.Stop()
	q.Stop() // must not panic
}

func TestR37_P3_23_StopIdempotentWithoutStart(t *testing.T) {
	q := NewPrecompileQueue(NewJITCompiler(16), 16)
	q.Stop()
	q.Stop() // must not panic
}
