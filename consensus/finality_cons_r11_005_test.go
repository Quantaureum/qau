// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestCONS_R11005_SetBroadcastEvidenceSynchronizesAccess verifies that
// SetBroadcastEvidence is the synchronized setter for the broadcastEvidence
// field, and that broadcastEvidenceWithRetry correctly reads the field
// under ft.mu.RLock().
//
// CONS-R11-005 (2026-07-20): Previously, broadcastEvidenceWithRetry read
// ft.broadcastEvidence directly without holding ft.mu, which was a data
// race when FinalizeBlock launched a goroutine that called the method
// while another goroutine could be writing the field. The fix adds
// SetBroadcastEvidence (which takes ft.mu.Lock()) and modifies
// broadcastEvidenceWithRetry to take ft.mu.RLock() when reading the field.
func TestCONS_R11005_SetBroadcastEvidenceSynchronizesAccess(t *testing.T) {
	ft := NewFinalityTracker(NewValidatorManager())

	// Initially, broadcastEvidence is nil — method should return nil immediately.
	if err := ft.broadcastEvidenceWithRetry(&SlashingEvidence{}); err != nil {
		t.Errorf("expected nil error when broadcastEvidence is nil, got: %v", err)
	}

	// Set a broadcast function via the synchronized setter.
	called := make(chan struct{}, 1)
	ft.SetBroadcastEvidence(func(e *SlashingEvidence) {
		called <- struct{}{}
	})

	// Call broadcastEvidenceWithRetry — should invoke the broadcast function.
	// Use a short timeout to avoid hanging if the function is never called.
	go func() {
		_ = ft.broadcastEvidenceWithRetry(&SlashingEvidence{})
	}()

	select {
	case <-called:
		// Success — broadcast function was invoked.
	case <-time.After(6 * time.Second):
		t.Fatal("broadcast function was not invoked within timeout")
	}

	// Reset to nil — subsequent calls should return nil immediately.
	ft.SetBroadcastEvidence(nil)
	if err := ft.broadcastEvidenceWithRetry(&SlashingEvidence{}); err != nil {
		t.Errorf("expected nil error after SetBroadcastEvidence(nil), got: %v", err)
	}
}

// TestCONS_R11005_ConcurrentSetAndBroadcastNoRace verifies that concurrent
// SetBroadcastEvidence and broadcastEvidenceWithRetry calls do not trigger
// a data race. This test is meaningful under `go test -race`.
//
// CONS-R11-005 (2026-07-20): The previous implementation read
// ft.broadcastEvidence directly in broadcastEvidenceWithRetry (and in the
// inner retry goroutines) without synchronization. Under `-race`, this test
// would detect the data race. With the fix (RLock + captured local var),
// the test should be race-free.
func TestCONS_R11005_ConcurrentSetAndBroadcastNoRace(t *testing.T) {
	ft := NewFinalityTracker(NewValidatorManager())

	// Counter for how many times the broadcast function was invoked.
	var callCount int32

	// Set an initial broadcast function.
	ft.SetBroadcastEvidence(func(e *SlashingEvidence) {
		atomic.AddInt32(&callCount, 1)
	})

	// Launch a writer goroutine that repeatedly swaps the broadcast function.
	stopCh := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			ft.SetBroadcastEvidence(func(e *SlashingEvidence) {
				atomic.AddInt32(&callCount, 1)
			})
		}
	}()

	// Launch reader goroutines that repeatedly call broadcastEvidenceWithRetry.
	// Each call reads ft.broadcastEvidence (under RLock after the fix) and
	// may spawn inner retry goroutines that also read the field (via the
	// captured local variable after the fix).
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = ft.broadcastEvidenceWithRetry(&SlashingEvidence{
					ValidatorAddr: types.BytesToAddress([]byte("race-test-----------")),
					Height:        uint64(j),
				})
			}
		}()
	}

	// Let the race run for a short period.
	time.Sleep(200 * time.Millisecond)
	close(stopCh)
	wg.Wait()

	// No assertion needed — the test passes if no data race is detected
	// by `go test -race`. The call count just ensures the broadcast
	// function was actually invoked at least once.
	if atomic.LoadInt32(&callCount) == 0 {
		t.Error("broadcast function was never invoked during concurrent test")
	}
}
