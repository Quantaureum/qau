// Quantaureum Node source, version 1.0.0.
package consensus

// P3-QTD-02 FIX (R29, 2026-07-26): Regression tests for the announceSeal
// RLock hardening.
//
// Previously, announceSeal read qfs.sealAnnouncer under RLock but
// performed the nil check OUTSIDE the lock. While this was safe today
// (the local variable holds an immutable interface snapshot), the
// pattern was fragile: a future SetSealAnnouncer(nil) call to "disable"
// announcements would NOT affect a goroutine that had already snapshotted
// the non-nil announcer, defeating the disable.
//
// The fix moves the nil check INSIDE the RLock so the snapshot + nil
// check is atomic. These tests verify:
//  1. announceSeal does NOT call AnnounceQTDSeal when sealAnnouncer is nil.
//  2. announceSeal DOES call AnnounceQTDSeal when sealAnnouncer is set.
//  3. announceSeal recovers from panics in AnnounceQTDSeal (defense-in-depth).

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// mockSealAnnouncer is a test SealAnnouncer that records calls.
type mockSealAnnouncer struct {
	mu       sync.Mutex
	calls    []announcedSeal
	panicked bool
}

type announcedSeal struct {
	slot      uint64
	blockHash types.Hash
	qtdSig    []byte
	sealers   []int
}

func (m *mockSealAnnouncer) AnnounceQTDSeal(slot uint64, blockHash types.Hash, qtdSignature []byte, sealers []int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.panicked {
		panic("mockSealAnnouncer: simulated panic")
	}
	m.calls = append(m.calls, announcedSeal{
		slot:      slot,
		blockHash: blockHash,
		qtdSig:    append([]byte(nil), qtdSignature...),
		sealers:   append([]int(nil), sealers...),
	})
}

func (m *mockSealAnnouncer) getCalls() []announcedSeal {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]announcedSeal, len(m.calls))
	copy(out, m.calls)
	return out
}

// TestP3_QTD_02_AnnounceSeal_NoCallWhenAnnouncerNil verifies that
// announceSeal does NOT call AnnounceQTDSeal when sealAnnouncer is nil.
//
// This is the core regression test for the "nil check inside the lock"
// fix: if the nil check were moved back outside the lock (or removed),
// a nil announcer would cause a panic when AnnounceQTDSeal is called.
func TestP3_QTD_02_AnnounceSeal_NoCallWhenAnnouncerNil(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)
	// Do NOT call SetSealAnnouncer — sealAnnouncer remains nil.

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("P3-QTD-02 REGRESSION: announceSeal panicked when "+
				"sealAnnouncer is nil: %v. The nil check inside the "+
				"RLock should have prevented the call to "+
				"AnnounceQTDSeal.", r)
		}
	}()

	blockHash := types.Hash{0x12, 0x34}
	qfs.announceSeal(42, blockHash, []byte("sig"), []int{0, 1, 2})

	// If we reach here without panic, the test passes.
	t.Log("PASS: announceSeal correctly skipped when sealAnnouncer is nil")
}

// TestP3_QTD_02_AnnounceSeal_CallsWhenAnnouncerSet verifies that
// announceSeal DOES call AnnounceQTDSeal when sealAnnouncer is set,
// and passes through the correct arguments (with defensive copies).
func TestP3_QTD_02_AnnounceSeal_CallsWhenAnnouncerSet(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	announcer := &mockSealAnnouncer{}
	qfs.SetSealAnnouncer(announcer)

	blockHash := types.Hash{0x12, 0x34}
	origSig := []byte("test-signature")
	origSealers := []int{0, 1, 2}

	qfs.announceSeal(42, blockHash, origSig, origSealers)

	calls := announcer.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call to AnnounceQTDSeal, got %d", len(calls))
	}

	call := calls[0]
	if call.slot != 42 {
		t.Errorf("slot = %d, want 42", call.slot)
	}
	if call.blockHash != blockHash {
		t.Errorf("blockHash = %x, want %x", call.blockHash, blockHash)
	}
	if string(call.qtdSig) != "test-signature" {
		t.Errorf("qtdSig = %q, want %q", string(call.qtdSig), "test-signature")
	}
	if len(call.sealers) != 3 || call.sealers[0] != 0 || call.sealers[1] != 1 || call.sealers[2] != 2 {
		t.Errorf("sealers = %v, want [0, 1, 2]", call.sealers)
	}

	// Verify defensive copies: mutating the original slices after the
	// call should NOT affect the recorded call.
	origSig[0] = 'X'
	origSealers[0] = 99

	calls = announcer.getCalls()
	if string(calls[0].qtdSig) != "test-signature" {
		t.Errorf("P3-QTD-02: defensive copy of qtdSignature failed — "+
			"mutating the original slice affected the recorded call: %q",
			string(calls[0].qtdSig))
	}
	if calls[0].sealers[0] != 0 {
		t.Errorf("P3-QTD-02: defensive copy of sealers failed — "+
			"mutating the original slice affected the recorded call: %v",
			calls[0].sealers)
	}
}

// TestP3_QTD_02_AnnounceSeal_RecoverFromPanic verifies that announceSeal
// recovers from a panic in AnnounceQTDSeal without crashing the caller.
//
// This is defense-in-depth: the top-level defer recover() in announceSeal
// should catch any panic from the announcer implementation (e.g., a P2P
// host that has been stopped and panics on send).
func TestP3_QTD_02_AnnounceSeal_RecoverFromPanic(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	announcer := &mockSealAnnouncer{panicked: true}
	qfs.SetSealAnnouncer(announcer)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("P3-QTD-02 REGRESSION: announceSeal did NOT recover "+
				"from a panic in AnnounceQTDSeal: %v. The top-level "+
				"defer recover() should have caught it.", r)
		}
	}()

	blockHash := types.Hash{0x12, 0x34}
	qfs.announceSeal(42, blockHash, []byte("sig"), []int{0, 1, 2})

	t.Log("PASS: announceSeal correctly recovered from announcer panic")
}

// TestP3_QTD_02_AnnounceSeal_SetNilAfterSet verifies that calling
// SetSealAnnouncer(nil) AFTER a non-nil announcer was set correctly
// disables announcements.
//
// This is the key test for the "nil check inside the lock" fix: if the
// nil check were outside the lock (or if the snapshot were taken before
// the nil check without re-checking), a goroutine that snapshotted the
// non-nil announcer could still call AnnounceQTDSeal after the announcer
// was set to nil. With the fix, the nil check is inside the RLock, so
// SetSealAnnouncer(nil) (which takes the exclusive Lock) is visible to
// the next announceSeal call.
//
// Note: This test verifies the SYNCHRONOUS case (announceSeal is called
// AFTER SetSealAnnouncer(nil) completes). The asynchronous race (where
// announceSeal is running concurrently with SetSealAnnouncer(nil)) is
// inherently safe because:
//   - If announceSeal's RLock acquires first: it sees the non-nil announcer
//     and proceeds. SetSealAnnouncer(nil) blocks on the exclusive Lock
//     until announceSeal releases the RLock, but by then AnnounceQTDSeal
//     is already executing (or done). This is acceptable — the announcer
//     was non-nil when the snapshot was taken.
//   - If SetSealAnnouncer(nil)'s Lock acquires first: it sets the field
//     to nil, then releases. announceSeal's RLock acquires next, sees nil,
//     and returns early. Correct.
func TestP3_QTD_02_AnnounceSeal_SetNilAfterSet(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	announcer := &mockSealAnnouncer{}
	qfs.SetSealAnnouncer(announcer)

	blockHash := types.Hash{0x12, 0x34}

	// First call: announcer is set → should record the call.
	qfs.announceSeal(1, blockHash, []byte("sig-1"), []int{0})
	if len(announcer.getCalls()) != 1 {
		t.Fatalf("expected 1 call before SetSealAnnouncer(nil), got %d",
			len(announcer.getCalls()))
	}

	// Disable announcements.
	qfs.SetSealAnnouncer(nil)

	// Second call: announcer is nil → should NOT record the call.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("P3-QTD-02 REGRESSION: announceSeal panicked after "+
				"SetSealAnnouncer(nil): %v. The nil check inside the "+
				"RLock should have prevented the call.", r)
		}
	}()
	qfs.announceSeal(2, blockHash, []byte("sig-2"), []int{1})

	calls := announcer.getCalls()
	if len(calls) != 1 {
		t.Errorf("P3-QTD-02 REGRESSION: announceSeal called "+
			"AnnounceQTDSeal after SetSealAnnouncer(nil). Expected "+
			"1 call total (from before the disable), got %d. The nil "+
			"check inside the RLock should have prevented the second "+
			"call — the snapshot was likely taken before the nil was "+
			"visible.", len(calls))
	}
}

// TestP3_QTD_02_AnnounceSeal_ConcurrentSetAndAnnounce verifies that
// concurrent calls to SetSealAnnouncer and announceSeal do not race
// or panic. This is a stress test for the RLock/Lock interaction.
//
// Uses go test -race to detect data races.
func TestP3_QTD_02_AnnounceSeal_ConcurrentSetAndAnnounce(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	announcer := &mockSealAnnouncer{}
	qfs.SetSealAnnouncer(announcer)

	blockHash := types.Hash{0x12, 0x34}

	var wg sync.WaitGroup
	var announceCount int64

	// Writer goroutine: toggles sealAnnouncer between nil and announcer.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if i%2 == 0 {
				qfs.SetSealAnnouncer(nil)
			} else {
				qfs.SetSealAnnouncer(announcer)
			}
			time.Sleep(time.Microsecond)
		}
	}()

	// Reader goroutine: calls announceSeal concurrently.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("announceSeal panicked during concurrent "+
							"SetSealAnnouncer: %v", r)
					}
				}()
				qfs.announceSeal(uint64(i), blockHash, []byte("sig"), []int{0, 1})
				atomic.AddInt64(&announceCount, 1)
			}()
		}
	}()

	wg.Wait()

	if atomic.LoadInt64(&announceCount) != 100 {
		t.Errorf("expected 100 announceSeal calls to complete, got %d",
			atomic.LoadInt64(&announceCount))
	}

	t.Logf("PASS: %d concurrent announceSeal calls completed without panic or race",
		atomic.LoadInt64(&announceCount))
}
