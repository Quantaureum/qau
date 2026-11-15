// Quantaureum Node source, version 1.0.0.
package consensus

// Concurrency regression for the stardust anchor write (TSS-R3-B-1
// follow-up, 2026-11-15). PopulateStardustFields runs on the block
// PRODUCTION goroutine; anchor adoption (ObserveAnchoredGroupKey) runs on
// block-import goroutines. The custody-table read inside the anchor write
// used the unlocked getGroupPublicKeyForEpoch wrapper (whose contract is
// "caller must hold qfs.mu") and raced the import-side map writes — a
// concurrent map read/write is a fatal runtime error, i.e. a production
// panic. The fix routes the read through GroupPublicKeyForEpoch, the same
// lookup under qfs.mu.RLock.
//
// The stress below reproduces the exact production shape — ONE production
// goroutine calling PopulateStardustFields against SEVERAL import goroutines
// adopting anchors — and asserts survival plus functional sanity.
//
// LIMITATION (honest scoping): the Go race detector is unavailable in this
// build environment (-race needs cgo/gcc, absent on this host), so the
// runtime's concurrent-map detector is the only in-process witness and its
// triggering is probabilistic under load. The stress maximizes the
// collision window (shared sliding epoch window, continuous same-key map
// writes) but CANNOT prove absence of the race; it proves the fixed code is
// stable under contention and fails loudly (fatal) if the unlock reappears
// and the detector fires. The lock discipline itself is enforced by
// construction: the read goes through GroupPublicKeyForEpoch, whose body
// takes qfs.mu.RLock — see the LOCKING comment at stardust_block.go.

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
)

// TestQTD_StardustAnchor_PopulateImportConcurrency drives the production
// shape: one PopulateStardustFields caller (the producer), several
// ObserveAnchoredGroupKey callers (import-side adoption), all hammering a
// shared sliding epoch window so custody reads and writes collide.
func TestQTD_StardustAnchor_PopulateImportConcurrency(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.InitChambers()
	qfs := qpos.GetQTDFinality()
	if qfs == nil {
		t.Fatal("no QTD finality engine")
	}
	// A signer turns IsInstantFinality on, which is what engages the anchor
	// write path inside PopulateStardustFields (finalityType is set by
	// setQTDSignerLocked). Its key is the only key the R19-F02
	// first-establishment rule lets the import side adopt.
	anchorKey := testExportGroupKey(0xAC)
	qfs.SetQTDSignerForEpoch(&epochKeySigner{groupKey: anchorKey}, 1)

	// The shared sliding window: writers advance head, readers cover the
	// last few epochs — the same epochs the reader looks up, so custody map
	// reads and writes collide on the same keys.
	var head uint64 = 1
	var anchoredReads uint64
	var headersWithAnchor uint64

	deadline := time.Now().Add(3 * time.Second)
	var wg sync.WaitGroup

	// Import-side adoption writers: same-key continuation at fresh epochs —
	// every call is a custody-table write under qfs.mu.
	for w := 0; w < 6; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				epoch := atomic.AddUint64(&head, 1)
				qfs.ObserveAnchoredGroupKey(epoch, anchorKey, nil)
			}
		}()
	}

	// The single production goroutine: boundary headers only (the anchor
	// path engages at EpochStartSlot), sweeping the window the writers just
	// covered.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for time.Now().Before(deadline) {
			epoch := atomic.LoadUint64(&head)
			if epoch < 2 {
				continue
			}
			target := epoch - 1 - uint64(time.Now().UnixNano()%3)
			if target < 1 {
				target = 1
			}
			header := &encoding.BlockHeader{Epoch: target, Slot: EpochStartSlot(target)}
			if err := PopulateStardustFields(header, qpos); err != nil {
				t.Errorf("PopulateStardustFields: %v", err)
				return
			}
			if len(header.QTDGroupKey) > 0 {
				atomic.AddUint64(&headersWithAnchor, 1)
			}
			if got := qfs.GroupPublicKeyForEpoch(target); len(got) > 0 {
				atomic.AddUint64(&anchoredReads, 1)
			}
		}
	}()

	wg.Wait()

	// Survival is the primary assertion (a concurrent map read/write is a
	// fatal runtime error that fails the whole test binary). Functional
	// sanity: the custody actually served anchored keys and the anchor
	// actually reached headers — proves the stress exercised the fixed read
	// path rather than spinning on empty lookups.
	if atomic.LoadUint64(&anchoredReads) == 0 {
		t.Fatal("the stress never exercised a served custody read — coverage was empty")
	}
	if atomic.LoadUint64(&headersWithAnchor) == 0 {
		t.Fatal("the stress never produced an anchored header — the anchor write path was never engaged")
	}
	if got := qfs.GroupPublicKeyForEpoch(1); !bytes.Equal(got, anchorKey) {
		t.Fatalf("post-stress custody lookup at epoch 1 = %d bytes, want the anchor key", len(got))
	}
}
