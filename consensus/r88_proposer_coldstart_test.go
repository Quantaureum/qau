// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"testing"
)

// r88ValidatorSet builds a ValidatorSet with n active validators.
func r88ValidatorSet(t *testing.T, n int) *ValidatorSet {
	t.Helper()
	vals := make([]*Validator, n)
	for i := 0; i < n; i++ {
		var addr [20]byte
		addr[0] = byte(i + 1)
		vals[i] = &Validator{
			Address: addr,
			Stake:   big.NewInt(1000),
			Active:  true,
		}
	}
	vs, err := NewValidatorSet(vals)
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	return vs
}

// TestGetProposerForSlot_ColdStartMarksGuard_R88 verifies that the FIRST
// GetProposerForSlot computation for a cold-start epoch (epochVRFAccumulator
// [epoch-2] missing) marks coldStartEpochs[epoch], so that the R45-PoA-FIX
// guard (IsProposerScheduleReadyForSlot) refuses to act on the fallback
// shuffle for SUBSEQUENT calls.
//
// R88-B regression contract: before R88-B the marking happened inside
// computeDeterministicShuffleForEpoch (under q.mu.RLock — a data race);
// after R88-B the marking is performed by the caller under the write lock.
// This test pins the OBSERVABLE behavior: the flag must still be set after
// the first computation.
func TestGetProposerForSlot_ColdStartMarksGuard_R88(t *testing.T) {
	vs := r88ValidatorSet(t, 3)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	const epoch = uint64(5) // >= 2, acc[3] never set → cold-start
	slot := epoch * SlotsPerEpoch

	// Before any computation the epoch is NOT marked (the guard would pass —
	// this is the known TOCTOU: the flag is only set by the FIRST
	// computation, see R45-ACC-LOOKUP-FIX).
	if !qpos.IsProposerScheduleReadyForEpoch(epoch) {
		t.Fatalf("epoch %d marked cold-start before first computation (unexpected)", epoch)
	}

	p1, err := qpos.GetProposerForSlot(slot)
	if err != nil {
		t.Fatalf("GetProposerForSlot(slot=%d): %v", slot, err)
	}
	if p1 == nil {
		t.Fatal("GetProposerForSlot returned nil proposer")
	}

	// After the first computation the epoch MUST be marked cold-start,
	// so the guard refuses to act on the fallback shuffle.
	if qpos.IsProposerScheduleReadyForEpoch(epoch) {
		t.Fatalf("epoch %d must be marked cold-start after first computation (R45-PoA-FIX guard broken)", epoch)
	}
	if qpos.IsProposerScheduleReadyForSlot(slot) {
		t.Fatalf("slot %d (epoch %d) must not be schedule-ready after cold-start computation", slot, epoch)
	}

	// Determinism: repeated calls return the same proposer.
	p2, err := qpos.GetProposerForSlot(slot)
	if err != nil {
		t.Fatalf("GetProposerForSlot (2nd): %v", err)
	}
	if p1.Address != p2.Address {
		t.Fatalf("proposer changed between calls: %x vs %x", p1.Address[:4], p2.Address[:4])
	}

	// Warm path sanity: once the accumulator is populated and the caches
	// cleared, the epoch must no longer be cold-start-marked.
	qpos.mu.Lock()
	qpos.epochVRFAccumulator[epoch-2] = [32]byte{0xAA}
	delete(qpos.coldStartEpochs, epoch)
	for k := range qpos.shuffleCache {
		delete(qpos.shuffleCache, k)
	}
	qpos.mu.Unlock()

	p3, err := qpos.GetProposerForSlot(slot)
	if err != nil {
		t.Fatalf("GetProposerForSlot (warm): %v", err)
	}
	_ = p3
	if !qpos.IsProposerScheduleReadyForEpoch(epoch) {
		t.Fatalf("epoch %d should be schedule-ready once acc[%d] is populated", epoch, epoch-2)
	}
}

// TestGetProposerForSlot_ConcurrentColdStartNoRace_R88 exercises concurrent
// proposer lookups for a COLD epoch (accumulator missing). Before R88-B the
// coldStartEpochs map was written inside computeDeterministicShuffleForEpoch
// under q.mu.RLock — two goroutines computing the same cold epoch concurrently
// performed concurrent map writes (runtime fatal under -race / map corruption
// in production). After R88-B the marking happens under the write lock and
// this test must be race-clean.
//
// Run with: go test -race -run TestGetProposerForSlot_ConcurrentColdStartNoRace_R88 ./consensus/
func TestGetProposerForSlot_ConcurrentColdStartNoRace_R88(t *testing.T) {
	vs := r88ValidatorSet(t, 3)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	const epoch = uint64(7) // acc[5] never set → cold-start
	const goroutines = 16

	// Each goroutine repeatedly looks up proposers for slots across the
	// cold epoch (cache-miss storms + cache-hit reads interleaved).
	start := make(chan struct{})
	var wg sync.WaitGroup
	proposers := make([][]byte, goroutines) // first answer per goroutine for slot0
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			<-start
			for i := 0; i < 50; i++ {
				slot := epoch*SlotsPerEpoch + uint64(i%int(SlotsPerEpoch))
				p, err := qpos.GetProposerForSlot(slot)
				if err != nil {
					t.Errorf("goroutine %d: GetProposerForSlot(slot=%d): %v", g, slot, err)
					return
				}
				if p == nil {
					t.Errorf("goroutine %d: nil proposer for slot %d", g, slot)
					return
				}
				if i == 0 && slot == epoch*SlotsPerEpoch {
					cp := make([]byte, len(p.Address))
					copy(cp, p.Address[:])
					proposers[g] = cp
				}
			}
		}(g)
	}
	close(start)
	wg.Wait()

	// All goroutines must agree on the proposer for the same slot.
	for g := 1; g < goroutines; g++ {
		if proposers[g] == nil || proposers[0] == nil {
			t.Fatalf("goroutine %d did not record proposer", g)
		}
		if string(proposers[g]) != string(proposers[0]) {
			t.Fatalf("goroutine %d proposer %x != goroutine 0 proposer %x (non-deterministic shuffle)",
				g, proposers[g][:4], proposers[0][:4])
		}
	}

	// The cold-start flag must be marked after the concurrent storm.
	if qpos.IsProposerScheduleReadyForEpoch(epoch) {
		t.Fatalf("epoch %d must be cold-start-marked after concurrent computations", epoch)
	}
}

// TestR88Diag_ShuffleSeedLoggedOnColdMiss verifies the QAU_R88_DIAG probe
// fires on the first (cache-miss) computation of a cold epoch and emits the
// seed inputs (epoch, n, accPresent, acc prefix) — the data needed to diff
// accumulator values across nodes for the R88-C follow-up.
func TestR88Diag_ShuffleSeedLoggedOnColdMiss(t *testing.T) {
	vs := r88ValidatorSet(t, 3)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	var buf []byte
	sink := log.Writer()
	log.SetOutput(&testLogWriter{&buf})
	defer log.SetOutput(sink)

	r88DiagEnabled.Store(true)
	defer r88DiagEnabled.Store(false)

	// Use a FUTURE epoch (beyond wall-clock current) so the shuffle-cache
	// eviction (evictStaleShuffleCacheLocked deletes epochs ≤ current+(-5))
	// does not evict it — that would turn every lookup into a cache-miss.
	epoch := currentEpochUnlocked() + 100 // cold: acc[epoch-2] never set
	if _, err := qpos.GetProposerForSlot(epoch * SlotsPerEpoch); err != nil {
		t.Fatalf("GetProposerForSlot: %v", err)
	}

	out := string(buf)
	wantEpoch := fmt.Sprintf("[R88DIAG] shuffle-seed epoch=%d", epoch)
	if !strings.Contains(out, wantEpoch) {
		t.Fatalf("expected %q in log, got: %q", wantEpoch, out)
	}
	if !strings.Contains(out, "accPresent=false") {
		t.Fatalf("expected accPresent=false for cold epoch, got: %q", out)
	}
	// Second call hits the cache — no duplicate log line.
	if _, err := qpos.GetProposerForSlot(epoch*SlotsPerEpoch + 1); err != nil {
		t.Fatalf("GetProposerForSlot (2nd): %v", err)
	}
	if got := strings.Count(string(buf), fmt.Sprintf("shuffle-seed epoch=%d", epoch)); got != 1 {
		t.Fatalf("expected exactly one shuffle-seed line per epoch, got %d: %q", got, string(buf))
	}
}

type testLogWriter struct{ b *[]byte }

func (w *testLogWriter) Write(p []byte) (int, error) {
	*w.b = append(*w.b, p...)
	return len(p), nil
}
