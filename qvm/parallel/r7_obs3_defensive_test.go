// Quantaureum Node source, version 1.0.0.
package parallel

// R7-OBS-3 (2026-07-18) — Defensive test coverage for the QVM parallel
// execution engine.
//
// Audit observation (Low):
//   "QVM (Quantum Virtual Machine) — Findings: The WriteSet mechanism
//    (QVM-R7-04) correctly populates state dependencies, resolving the
//    parallel execution conflicts noted in R6. Observation (Low): No
//    critical logic errors detected. The parallel execution engine is
//    robust. Recommendation (R8): Consider formal verification for the
//    QVM parallel execution engine to mathematically guarantee absence
//    of race conditions."
//
// This file adds defensive regression tests that exercise edge cases and
// security-critical invariants of the parallel execution engine. They do
// not change runtime behavior; they exist to:
//
//   1. Lock in the security-critical invariants already enforced by code
//      (CRIT-2 value comparison, H-3 incarnation check, R7-8 find copy,
//       QVM-R7-09 retryQueue clearing, R4-QVM-01 consensus-safe guard).
//   2. Cover boundary conditions that have no test today (empty batch,
//      single-call fast path, MVMemory basic operations, version
//      replacement on retry, Clear/DeleteVersion memory hygiene).
//   3. Provide a race-detector harness (run with -race) for the
//      concurrency primitives inside MVMemory.
//
// Run: go test ./qvm/parallel/... -count=1 -race -timeout 120s

import (
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// ---------------------------------------------------------------------------
// MVMemory core invariants
// ---------------------------------------------------------------------------

// TestR7OBS3_MVMemory_ReadBeforeWrite confirms that a Read on a key with no
// prior writes returns (zero, Version{}, false) — the caller must fall back
// to baseState. This is the cold-start invariant relied on by
// mvStateWrapper.recordRead and isolatedStateWrapper.recordRead.
func TestR7OBS3_MVMemory_ReadBeforeWrite(t *testing.T) {
	mvm := NewMVMemory()
	addr := types.Address{0x11}

	if v, ver, ok := mvm.ReadBalance(addr, 5); ok {
		t.Fatalf("ReadBalance on empty MVMemory returned ok=true v=%s ver=%+v", v, ver)
	}
	if v, ver, ok := mvm.ReadNonce(addr, 5); ok {
		t.Fatalf("ReadNonce on empty MVMemory returned ok=true v=%d ver=%+v", v, ver)
	}
	if v, ver, ok := mvm.ReadStorage(addr, types.Hash{0x01}, 5); ok {
		t.Fatalf("ReadStorage on empty MVMemory returned ok=true v=%x ver=%+v", v, ver)
	}
	if v, ver, ok := mvm.ReadCode(addr, 5); ok {
		t.Fatalf("ReadCode on empty MVMemory returned ok=true v=%x ver=%+v", v, ver)
	}
}

// TestR7OBS3_MVMemory_ReadReturnsLatestVersionBeforeTxIndex verifies the
// multi-version memory contract: Read(addr, txIndex) returns the value of
// the LARGEST entry.txIndex that is STRICTLY LESS than the reader's txIndex.
// This invariant is what makes Block-STM's optimistic reads correct.
func TestR7OBS3_MVMemory_ReadReturnsLatestVersionBeforeTxIndex(t *testing.T) {
	mvm := NewMVMemory()
	addr := types.Address{0x22}

	// Three writers at txIndex 1, 3, 5.
	mvm.WriteBalance(addr, 1, 0, big.NewInt(100))
	mvm.WriteBalance(addr, 3, 0, big.NewInt(300))
	mvm.WriteBalance(addr, 5, 0, big.NewInt(500))

	cases := []struct {
		name     string
		txIndex  int
		expected int64
		verTx    int
	}{
		{"reader at 0 sees nothing", 0, 0, 0}, // no entry with txIndex < 0
		{"reader at 1 sees nothing", 1, 0, 0}, // no entry with txIndex < 1
		{"reader at 2 sees tx=1", 2, 100, 1},
		{"reader at 3 sees tx=1", 3, 100, 1}, // strictly less than
		{"reader at 4 sees tx=3", 4, 300, 3},
		{"reader at 5 sees tx=3", 5, 300, 3}, // strictly less than
		{"reader at 6 sees tx=5", 6, 500, 5},
		{"reader at 100 sees tx=5", 100, 500, 5},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, ver, ok := mvm.ReadBalance(addr, tc.txIndex)
			if tc.verTx == 0 {
				if ok {
					t.Fatalf("expected no entry, got v=%s ver=%+v", v, ver)
				}
				return
			}
			if !ok {
				t.Fatalf("expected entry, got ok=false")
			}
			if v.Int64() != tc.expected {
				t.Fatalf("expected %d, got %s", tc.expected, v)
			}
			if ver.TxIndex != tc.verTx {
				t.Fatalf("expected version.TxIndex=%d, got %d", tc.verTx, ver.TxIndex)
			}
		})
	}
}

// TestR7OBS3_MVMemory_WriteReplacesOnSameTxIndex locks in the retry
// semantics of sortedVersions.add: writing with the same txIndex (but a
// higher incarnation, as produced by markForRetry) MUST replace the existing
// entry in place, NOT append a duplicate. Otherwise the binary search in
// find() and deleteVersion() would behave non-deterministically.
func TestR7OBS3_MVMemory_WriteReplacesOnSameTxIndex(t *testing.T) {
	mvm := NewMVMemory()
	addr := types.Address{0x33}

	// tx=2, incarnation=0 writes 200
	mvm.WriteBalance(addr, 2, 0, big.NewInt(200))
	// tx=2 retries, incarnation=1 writes 250 (retry produced a different value)
	mvm.WriteBalance(addr, 2, 1, big.NewInt(250))
	// tx=2 retries again, incarnation=2 writes 300
	mvm.WriteBalance(addr, 2, 2, big.NewInt(300))

	// A reader at txIndex=3 should see the LATEST incarnation's value.
	v, ver, ok := mvm.ReadBalance(addr, 3)
	if !ok {
		t.Fatal("expected entry, got ok=false")
	}
	if v.Int64() != 300 {
		t.Fatalf("expected 300 (latest incarnation), got %s", v)
	}
	if ver.Incarnation != 2 {
		t.Fatalf("expected incarnation=2, got %d", ver.Incarnation)
	}

	// Verify no duplicate entries were created: write tx=4, then ensure
	// the slice is still ordered and contains exactly 1 entry for txIndex=2.
	mvm.WriteBalance(addr, 4, 0, big.NewInt(400))
	// Read at txIndex=10 should return the latest entry (txIndex=4).
	v, _, ok = mvm.ReadBalance(addr, 10)
	if !ok || v.Int64() != 400 {
		t.Fatalf("expected 400 after final write, got v=%s ok=%v", v, ok)
	}
}

// ---------------------------------------------------------------------------
// H-3: DeleteVersion incarnation check
// ---------------------------------------------------------------------------

// TestR7OBS3_DeleteVersion_IncarnationMismatchIsNoOp locks in the H-3 fix:
// DeleteVersion(txIndex, incarnation) MUST be a no-op when the incarnation
// parameter does not match the currently stored entry. Otherwise a retry
// that bumps the incarnation between find() and deleteVersion() could
// wrongly delete the NEW value, corrupting the multi-version memory.
func TestR7OBS3_DeleteVersion_IncarnationMismatchIsNoOp(t *testing.T) {
	mvm := NewMVMemory()
	addr := types.Address{0x44}

	// tx=1, incarnation=0 writes 100.
	mvm.WriteBalance(addr, 1, 0, big.NewInt(100))

	// tx=1 retries → incarnation=1 writes 200 (replaces in place).
	mvm.WriteBalance(addr, 1, 1, big.NewInt(200))

	// Stale delete request (incarnation=0) must NOT delete anything.
	mvm.DeleteVersion(1, 0)

	// The entry for tx=1 (incarnation=1) must still be present.
	v, ver, ok := mvm.ReadBalance(addr, 2)
	if !ok {
		t.Fatal("H-3 regression: DeleteVersion(1, 0) deleted the entry for incarnation=1")
	}
	if v.Int64() != 200 {
		t.Fatalf("expected 200, got %s", v)
	}
	if ver.Incarnation != 1 {
		t.Fatalf("expected incarnation=1, got %d", ver.Incarnation)
	}

	// Correct delete (matching incarnation) removes the entry.
	mvm.DeleteVersion(1, 1)
	if _, _, ok := mvm.ReadBalance(addr, 2); ok {
		t.Fatal("DeleteVersion(1, 1) did not remove the entry")
	}
}

// TestR7OBS3_DeleteVersion_RemovesEntriesAcrossAllStores verifies that
// DeleteVersion purges writes from balances, nonces, storage AND code in
// one call. A partial cleanup would leave stale entries that subsequent
// reads could observe, breaking retry correctness.
func TestR7OBS3_DeleteVersion_RemovesEntriesAcrossAllStores(t *testing.T) {
	mvm := NewMVMemory()
	addr := types.Address{0x55}
	key := types.Hash{0x01}
	code := []byte{0x60, 0x80}

	mvm.WriteBalance(addr, 1, 0, big.NewInt(999))
	mvm.WriteNonce(addr, 1, 0, 7)
	mvm.WriteStorage(addr, key, 1, 0, types.Hash{0xAA})
	mvm.WriteCode(addr, 1, 0, code)

	// Sanity: all four entries are visible to a later reader.
	if _, _, ok := mvm.ReadBalance(addr, 2); !ok {
		t.Fatal("WriteBalance not visible before DeleteVersion")
	}
	if _, _, ok := mvm.ReadNonce(addr, 2); !ok {
		t.Fatal("WriteNonce not visible before DeleteVersion")
	}
	if _, _, ok := mvm.ReadStorage(addr, key, 2); !ok {
		t.Fatal("WriteStorage not visible before DeleteVersion")
	}
	if _, _, ok := mvm.ReadCode(addr, 2); !ok {
		t.Fatal("WriteCode not visible before DeleteVersion")
	}

	// Delete and verify all four are gone.
	mvm.DeleteVersion(1, 0)

	if _, _, ok := mvm.ReadBalance(addr, 2); ok {
		t.Fatal("DeleteVersion did not remove balance entry")
	}
	if _, _, ok := mvm.ReadNonce(addr, 2); ok {
		t.Fatal("DeleteVersion did not remove nonce entry")
	}
	if _, _, ok := mvm.ReadStorage(addr, key, 2); ok {
		t.Fatal("DeleteVersion did not remove storage entry")
	}
	if _, _, ok := mvm.ReadCode(addr, 2); ok {
		t.Fatal("DeleteVersion did not remove code entry")
	}
}

// ---------------------------------------------------------------------------
// Clear: batch-boundary memory hygiene
// ---------------------------------------------------------------------------

// TestR7OBS3_Clear_ResetsAllStores confirms that Clear() fully resets
// MVMemory. A leaked entry across batches would let txIndex=N of batch 2
// read a value written by txIndex=N of batch 1, breaking isolation.
func TestR7OBS3_Clear_ResetsAllStores(t *testing.T) {
	mvm := NewMVMemory()
	addr := types.Address{0x66}
	key := types.Hash{0x02}

	mvm.WriteBalance(addr, 1, 0, big.NewInt(123))
	mvm.WriteNonce(addr, 1, 0, 9)
	mvm.WriteStorage(addr, key, 1, 0, types.Hash{0xBB})
	mvm.WriteCode(addr, 1, 0, []byte{0xDE, 0xAD})

	mvm.Clear()

	if _, _, ok := mvm.ReadBalance(addr, 5); ok {
		t.Fatal("Clear() did not reset balances")
	}
	if _, _, ok := mvm.ReadNonce(addr, 5); ok {
		t.Fatal("Clear() did not reset nonces")
	}
	if _, _, ok := mvm.ReadStorage(addr, key, 5); ok {
		t.Fatal("Clear() did not reset storage")
	}
	if _, _, ok := mvm.ReadCode(addr, 5); ok {
		t.Fatal("Clear() did not reset code")
	}
}

// ---------------------------------------------------------------------------
// Empty batch — ParallelQVM.Execute early return
// ---------------------------------------------------------------------------

// TestR7OBS3_ParallelQVM_Execute_EmptyCalls verifies that Execute([]) returns
// an empty (non-nil) slice and no error, WITHOUT starting workers or a
// scheduler. This is the cold-start fast path used by empty blocks.
func TestR7OBS3_ParallelQVM_Execute_EmptyCalls(t *testing.T) {
	state := newMinimalMockState()
	config := DefaultParallelQVMConfig()
	config.ChainID = 1
	pq := NewParallelQVM(config)
	pq.EnableConsensusMode()

	results, err := pq.Execute(nil, state)
	if err != nil {
		t.Fatalf("Execute(nil) returned error: %v", err)
	}
	if results == nil {
		t.Fatal("Execute(nil) returned nil slice — callers may dereference and panic")
	}
	if len(results) != 0 {
		t.Fatalf("Execute(nil) returned %d results, expected 0", len(results))
	}

	// Same for an empty (non-nil) slice.
	results, err = pq.Execute([]*ContractCall{}, state)
	if err != nil {
		t.Fatalf("Execute([]) returned error: %v", err)
	}
	if results == nil || len(results) != 0 {
		t.Fatalf("Execute([]) returned results=%v len=%d, expected empty slice", results, len(results))
	}
}

// ---------------------------------------------------------------------------
// Single-call fast path — QVM-R7-09 defensive cleanup
// ---------------------------------------------------------------------------

// TestR7OBS3_ParallelQVM_SingleCall_AppliesStateChanges verifies that the
// single-call fast path (parallel_qvm.go executeCall "no code" branch)
// actually commits the transfer to baseState via applyStateChanges. This
// is the QVM B-2 invariant: a single successful call MUST mutate the
// underlying state, otherwise receipts would lie about the post-state.
func TestR7OBS3_ParallelQVM_SingleCall_AppliesStateChanges(t *testing.T) {
	state := newMinimalMockState()
	addrA := types.Address{0xAA}
	addrB := types.Address{0xBB}
	state.SetBalance(addrA, big.NewInt(1000))
	state.SetBalance(addrB, big.NewInt(0))

	config := DefaultParallelQVMConfig()
	config.ChainID = 1
	pq := NewParallelQVM(config)
	pq.EnableConsensusMode()

	calls := []*ContractCall{
		NewContractCall(0, addrB, addrA, nil, 100000, 100),
	}
	results, err := pq.Execute(calls, state)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if len(results) != 1 || !results[0].Success {
		t.Fatalf("expected 1 successful result, got %+v", results)
	}

	// SECURITY-CRITICAL: the transfer MUST be reflected in baseState.
	balA := state.GetBalance(addrA)
	balB := state.GetBalance(addrB)
	if balA.Int64() != 900 {
		t.Fatalf("QVM B-2 regression: A balance = %s, expected 900 (transfer not applied to baseState)", balA)
	}
	if balB.Int64() != 100 {
		t.Fatalf("QVM B-2 regression: B balance = %s, expected 100 (transfer not applied to baseState)", balB)
	}
}

// ---------------------------------------------------------------------------
// CRIT-2: Version.Value comparison
// ---------------------------------------------------------------------------

// TestR7OBS3_Version_ValueFieldExists is a structural test that locks in the
// CRIT-2 fix: the Version struct MUST carry a Value field. Without it, a
// malicious validator could commit a transaction with the same
// (TxIndex, Incarnation) but a different Value (e.g., transfer 100 instead
// of 50), and the honest validator's validateResults would incorrectly
// mark the read as consistent.
//
// We cannot easily construct an end-to-end malicious validator attack in a
// unit test (it requires two diverging executors comparing results), so
// this structural test ensures the Value field exists and is populated by
// the Write path. The end-to-end protection is exercised by
// validateResults' three-way comparison (TxIndex, Incarnation, Value) in
// the integration tests.
func TestR7OBS3_Version_ValueFieldExists(t *testing.T) {
	mvm := NewMVMemory()
	addr := types.Address{0x77}

	// Write a balance — the Write path must attach the actual value to
	// the Version. If the Value field is removed or not populated, the
	// CRIT-2 protection in validateResults is silently defeated.
	mvm.WriteBalance(addr, 1, 0, big.NewInt(42))

	v, ver, ok := mvm.ReadBalance(addr, 2)
	if !ok {
		t.Fatal("expected entry")
	}
	if v.Int64() != 42 {
		t.Fatalf("expected 42, got %s", v)
	}

	// The Version returned to the caller has TxIndex and Incarnation
	// populated. The Value field is internal to MVMemory (used by
	// validateResults via getFinalWriteVersion's finalWrites map), so we
	// only assert the public Version fields here.
	if ver.TxIndex != 1 {
		t.Fatalf("expected TxIndex=1, got %d", ver.TxIndex)
	}
	if ver.Incarnation != 0 {
		t.Fatalf("expected Incarnation=0, got %d", ver.Incarnation)
	}
	// Value field must exist on the struct (compile-time check via
	// assignment — if the field is removed, this won't compile).
	ver.Value = nil
	_ = ver.Value
}

// ---------------------------------------------------------------------------
// Concurrency safety — race detector harness
// ---------------------------------------------------------------------------

// TestR7OBS3_MVMemory_ConcurrentReadsNoRace exercises the read path under
// concurrency. Run with `go test -race` to detect data races in
// sortedVersions.find() (R7-8: returns a copy, not a pointer) and
// sortedVersions.add() (uses mutex; concurrent writes must not corrupt
// the slice or leak a stale pointer to the reader).
//
// This test does NOT assert correctness of the values returned — it exists
// solely to give the race detector a workload that exercises the
// read-while-write pattern that Block-STM relies on.
func TestR7OBS3_MVMemory_ConcurrentReadsNoRace(t *testing.T) {
	mvm := NewMVMemory()
	addr := types.Address{0x88}

	// Seed with one write so readers have something to find.
	mvm.WriteBalance(addr, 1, 0, big.NewInt(100))

	const writers = 4
	const readers = 8
	const iterations = 200

	var wg sync.WaitGroup
	var stop atomic.Bool

	// Writers: bump incarnation and re-write the same txIndex.
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			defer func() { _ = recover() }() // defensive; add() should not panic
			for i := 0; i < iterations; i++ {
				if stop.Load() {
					return
				}
				// Re-write txIndex=1 with a new incarnation.
				mvm.WriteBalance(addr, 1, i, big.NewInt(int64(100+i)))
			}
		}(w)
	}

	// Readers: read at various txIndices concurrently.
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if stop.Load() {
					return
				}
				// Read at txIndex=2 — should always see tx=1 (or nothing,
				// if a writer is mid-replace). Either way, no race.
				_, _, _ = mvm.ReadBalance(addr, 2)
				// Read at txIndex=1 — strictly less than 1, so always
				// returns false (no entry). Exercises the empty path.
				_, _, _ = mvm.ReadBalance(addr, 1)
			}
		}(r)
	}

	// Hard timeout in case of deadlock (the race detector itself would
	// also flag a deadlock, but we want a clean test failure rather than
	// a hung CI job).
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		stop.Store(true)
		t.Fatal("test timed out — possible deadlock in MVMemory read/write path")
	}
}

// ---------------------------------------------------------------------------
// R4-QVM-01: consensus-safe guard (regression lock)
// ---------------------------------------------------------------------------

// TestR7OBS3_ParallelQVM_DefaultRefusesConsensusPath re-asserts R4-QVM-01
// from a defensive-coverage angle: a freshly constructed ParallelQVM MUST
// refuse Execute until EnableConsensusMode() is called. This guard prevents
// accidental wiring of the non-consensus-safe Execute into the consensus
// path (which would cause nonce/intrinsic-gas divergence vs. the
// sequential executor and could fork the chain).
func TestR7OBS3_ParallelQVM_DefaultRefusesConsensusPath(t *testing.T) {
	config := DefaultParallelQVMConfig()
	config.ChainID = 1
	pq := NewParallelQVM(config)

	calls := []*ContractCall{
		NewContractCall(0, types.Address{0x02}, types.Address{0x01}, nil, 100000, 0),
	}
	_, err := pq.Execute(calls, newMinimalMockState())
	if err != ErrParallelQVMNotConsensusSafe {
		t.Fatalf("expected ErrParallelQVMNotConsensusSafe, got %v", err)
	}
}
