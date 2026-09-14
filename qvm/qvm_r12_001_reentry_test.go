// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"testing"
)

// TestQVM_R12001_DecrementReentryCount_Basic verifies that DecrementReentryCount
// decrements the counter for the given address.
//
// QVM-R12-001 (2026-07-20): Previously there was no DecrementReentryCount method,
// so once an address was re-entered up to MaxReentriesPerAddress times, the
// counter stayed saturated forever within the transaction, permanently DoS'ing
// the address.
func TestQVM_R12001_DecrementReentryCount_Basic(t *testing.T) {
	env := &Environment{
		ctx: &ExecutionContext{
			Code: []byte{byte(STOP)},
			Gas:  1000000,
		},
	}

	addr := Address{0xAA}

	// Increment 5 times.
	for i := 0; i < 5; i++ {
		if !env.IncrementReentryCount(addr) {
			t.Fatalf("increment #%d should be allowed", i+1)
		}
	}

	// Decrement 3 times — counter should go from 5 to 2.
	env.DecrementReentryCount(addr)
	env.DecrementReentryCount(addr)
	env.DecrementReentryCount(addr)

	// Verify counter allows 8 more increments (10 - 2 = 8).
	for i := 0; i < 8; i++ {
		if !env.IncrementReentryCount(addr) {
			t.Fatalf("after 3 decrements, increment #%d should be allowed (count was 2, limit 10)", i+1)
		}
	}

	// 11th total increment (count would become 11) should be blocked.
	if env.IncrementReentryCount(addr) {
		t.Error("increment beyond limit should be blocked after decrements restored capacity")
	}
}

// TestQVM_R12001_DecrementReentryCount_ToZero verifies that decrementing back
// to zero clears the entry from the map (keeps the map clean).
func TestQVM_R12001_DecrementReentryCount_ToZero(t *testing.T) {
	env := &Environment{
		ctx: &ExecutionContext{
			Code: []byte{byte(STOP)},
			Gas:  1000000,
		},
	}

	addr := Address{0xBB}

	// Increment once, then decrement once — counter should be 0.
	env.IncrementReentryCount(addr)
	env.DecrementReentryCount(addr)

	// Verify the entry is gone from the map.
	root := env
	for root.parentEnv != nil {
		root = root.parentEnv
	}
	if count, exists := root.reentryCounts[addr]; exists {
		t.Errorf("after decrement to zero, entry should be deleted from map, but exists with count=%d", count)
	}

	// Verify a subsequent Increment works fresh.
	if !env.IncrementReentryCount(addr) {
		t.Error("increment after decrement-to-zero should succeed")
	}
}

// TestQVM_R12001_DecrementReentryCount_ClampsAtZero verifies that calling
// DecrementReentryCount without a matching Increment (defensive case) does
// NOT cause the counter to go negative.
func TestQVM_R12001_DecrementReentryCount_ClampsAtZero(t *testing.T) {
	env := &Environment{
		ctx: &ExecutionContext{
			Code: []byte{byte(STOP)},
			Gas:  1000000,
		},
	}

	addr := Address{0xCC}

	// Decrement without prior increment — should not panic or go negative.
	env.DecrementReentryCount(addr)
	env.DecrementReentryCount(addr)
	env.DecrementReentryCount(addr)

	// Verify counter is still 0 (or absent from map).
	root := env
	for root.parentEnv != nil {
		root = root.parentEnv
	}
	if count, exists := root.reentryCounts[addr]; exists && count != 0 {
		t.Errorf("counter should be 0 or absent after decrements without increments, got count=%d", count)
	}

	// Subsequent increment should work.
	if !env.IncrementReentryCount(addr) {
		t.Error("increment should succeed after defensive decrements")
	}
}

// TestQVM_R12001_IncrementReentryCount_CheckBeforeIncrement verifies that
// when the counter is at the limit, IncrementReentryCount returns false
// WITHOUT incrementing (so the counter doesn't permanently saturate).
//
// QVM-R12-001 (2026-07-20): Previously the method ALWAYS incremented first
// then checked `<= MaxReentriesPerAddress`. When the check failed, the
// counter had already been pushed to limit+1, permanently saturating it.
func TestQVM_R12001_IncrementReentryCount_CheckBeforeIncrement(t *testing.T) {
	env := &Environment{
		ctx: &ExecutionContext{
			Code: []byte{byte(STOP)},
			Gas:  1000000,
		},
	}

	addr := Address{0xDD}

	// Fill to the limit.
	for i := 0; i < MaxReentriesPerAddress; i++ {
		if !env.IncrementReentryCount(addr) {
			t.Fatalf("increment #%d should be allowed", i+1)
		}
	}

	// Verify at-limit increment returns false WITHOUT incrementing.
	if env.IncrementReentryCount(addr) {
		t.Fatal("increment at limit should be blocked")
	}

	// Verify counter is STILL at MaxReentriesPerAddress (not MaxReentriesPerAddress+1).
	root := env
	for root.parentEnv != nil {
		root = root.parentEnv
	}
	if count := root.reentryCounts[addr]; count != MaxReentriesPerAddress {
		t.Errorf("counter should be %d after blocked increment, got %d", MaxReentriesPerAddress, count)
	}

	// After one decrement, the next increment should succeed.
	env.DecrementReentryCount(addr)
	if !env.IncrementReentryCount(addr) {
		t.Error("increment should succeed after one decrement freed up capacity")
	}
}

// TestQVM_R12001_DecrementReentryCount_NilMap verifies that calling
// DecrementReentryCount on a fresh environment (no map initialized) is safe.
func TestQVM_R12001_DecrementReentryCount_NilMap(t *testing.T) {
	env := &Environment{
		ctx: &ExecutionContext{
			Code: []byte{byte(STOP)},
			Gas:  1000000,
		},
	}

	addr := Address{0xEE}

	// Should not panic even though reentryCounts is nil.
	env.DecrementReentryCount(addr)
}

// TestQVM_R12001_DecrementReentryCount_TraversesToRoot verifies that
// DecrementReentryCount traverses to the root environment (same as
// IncrementReentryCount) so the shared counter is updated correctly.
func TestQVM_R12001_DecrementReentryCount_TraversesToRoot(t *testing.T) {
	root := &Environment{
		ctx: &ExecutionContext{
			Code: []byte{byte(STOP)},
			Gas:  1000000,
		},
	}

	// Child environment shares the root's reentryCounts via parentEnv.
	child := &Environment{
		ctx:       root.ctx,
		parentEnv: root,
	}

	addr := Address{0xFF}

	// Increment from child — counter goes to root's map.
	if !child.IncrementReentryCount(addr) {
		t.Fatal("first increment from child should succeed")
	}

	// Decrement from child — should also go to root's map.
	child.DecrementReentryCount(addr)

	// Verify counter is 0 in the root map.
	if count, exists := root.reentryCounts[addr]; exists && count != 0 {
		t.Errorf("after decrement from child, root counter should be 0, got %d", count)
	}

	// Verify counter allows MaxReentriesPerAddress increments from child.
	for i := 0; i < MaxReentriesPerAddress; i++ {
		if !child.IncrementReentryCount(addr) {
			t.Fatalf("increment #%d from child should be allowed after decrement", i+1)
		}
	}
}
