// Quantaureum Node source, version 1.0.0.
package jit

import (
	"crypto/sha256"
	"sync"
	"testing"
	"time"
)

// R37-P3-22 regression tests: PrecompileQueue precompiled/skipped counters
// must be race-free between the worker goroutine (processOne) and callers
// of Stats().

func TestR37_P3_22_StatsCountersAccurate(t *testing.T) {
	q := NewPrecompileQueue(NewJITCompiler(128), 128)
	code := []byte{0x00} // STOP — compiles successfully
	// The compilation cache is keyed by sha256(code) (see Compile).
	codeHash := sha256.Sum256(code)

	// Enqueue and process the entry.
	q.Enqueue(codeHash, code, 0)
	q.processOne()
	precompiled, skipped, queueLen := q.Stats()
	if precompiled != 1 {
		t.Fatalf("precompiled = %d, want 1", precompiled)
	}
	if skipped != 0 {
		t.Fatalf("skipped = %d, want 0", skipped)
	}
	if queueLen != 0 {
		t.Fatalf("queueLen = %d, want 0", queueLen)
	}

	// Re-enqueue the same code hash — now cached, must count as skipped.
	q.Enqueue(codeHash, code, 0)
	_, skipped, queueLen = q.Stats()
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	if queueLen != 0 {
		t.Fatalf("queueLen = %d, want 0 (cached entries must not be queued)", queueLen)
	}
}

// TestR37_P3_22_StatsCountersNoDataRace exercises concurrent
// Enqueue/worker/Stats access. Run with -race to detect regressions.
func TestR37_P3_22_StatsCountersNoDataRace(t *testing.T) {
	q := NewPrecompileQueue(NewJITCompiler(64), 64)
	q.Start(time.Millisecond)
	code := []byte{0x00}

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				var h [32]byte
				h[0] = byte(g)
				h[1] = byte(i)
				q.Enqueue(h, code, i)
				_, _, _ = q.Stats()
			}
		}(g)
	}
	wg.Wait()

	// Drain the queue deterministically (the ticker may not have fired
	// during the fast enqueue loops above).
	for q.Size() > 0 {
		q.processOne()
	}
	q.Stop()

	precompiled, skipped, _ := q.Stats()
	if precompiled+skipped == 0 {
		t.Fatal("expected some entries to be precompiled or skipped")
	}
}
