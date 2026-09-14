// Quantaureum Node source, version 1.0.0.
// Package node — tests for NODE-R12-H01 (QTD seal concurrency + per-peer rate limit).
//
// Audit finding (R12 HIGH-14): BroadcastQTDSealRequest / BroadcastQTDPartialSeal
// had no concurrency or per-peer rate limiting. Dilithium3 aggregate signing is
// CPU-expensive, so:
//
//	(a) Outbound: requestQTDSeal spawns a goroutine per call
//	    (computeAndCompleteQTDSeal). Without a bound, a burst of slots could
//	    spawn unbounded goroutines and exhaust CPU.
//	(b) Inbound: a malicious peer could spam MsgTypeQTDSealRequest /
//	    MsgTypeQTDPartialSeal messages, each triggering expensive Dilithium3
//	    verification in qfs.SubmitPartialSeal.
//
// Fix: counting semaphore (cap=MaxConcurrentQTDSeals=3) on outbound; sliding-
// window per-peer rate limit (qtdSealPerPeerMax=20 per qtdSealPerPeerWindow=10s)
// on inbound.
package node

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/p2p"
)

// newNodeBare constructs a Node without running NewNode, mimicking the
// pattern used by many existing tests in this package (e.g.
// bridge_config_test.go). NODE-R12-H01 added qtdSealSem/qtdPeerRate fields
// that are lazily initialized via ensureQTDSealLimiter so this pattern
// continues to work.
func newNodeBare() *Node {
	return &Node{}
}

// ---------------------------------------------------------------------------
// Semaphore (outbound) tests
// ---------------------------------------------------------------------------

func TestNODE_R12H01_AcquireAndRelease(t *testing.T) {
	n := newNodeBare()
	if got := n.GetQTDSealSemaphoreFill(); got != 0 {
		t.Fatalf("initial fill = %d, want 0", got)
	}
	if !n.acquireQTDSealSlot() {
		t.Fatal("acquireQTDSealSlot returned false on empty semaphore")
	}
	if got := n.GetQTDSealSemaphoreFill(); got != 1 {
		t.Fatalf("after acquire, fill = %d, want 1", got)
	}
	n.releaseQTDSealSlot()
	if got := n.GetQTDSealSemaphoreFill(); got != 0 {
		t.Fatalf("after release, fill = %d, want 0", got)
	}
}

func TestNODE_R12H01_LazyInitFromBareNode(t *testing.T) {
	// Tests constructed via &Node{} (without NewNode) must still work —
	// ensureQTDSealLimiter lazily initializes the semaphore and rate map.
	n := newNodeBare()
	if n.qtdSealSem != nil || n.qtdPeerRate != nil {
		t.Fatal("bare Node should start with nil limiter fields")
	}
	if !n.acquireQTDSealSlot() {
		t.Fatal("acquireQTDSealSlot should succeed after lazy init")
	}
	if n.qtdSealSem == nil {
		t.Fatal("qtdSealSem not initialized after acquire")
	}
	if got := n.GetQTDSealSemaphoreFill(); got != 1 {
		t.Fatalf("fill after lazy init + acquire = %d, want 1", got)
	}
	n.releaseQTDSealSlot()

	// Rate limiter should also lazy-init.
	if n.allowQTDSealFromPeer(p2p.PeerID("peer-A")) != true {
		t.Fatal("allowQTDSealFromPeer should return true under limit")
	}
	if n.qtdPeerRate == nil {
		t.Fatal("qtdPeerRate not initialized after allowQTDSealFromPeer")
	}
}

func TestNODE_R12H01_SemaphoreBoundedConcurrency(t *testing.T) {
	// Verify that at most MaxConcurrentQTDSeals goroutines may hold a slot
	// concurrently. Spawn MaxConcurrentQTDSeals holders; the next acquirer
	// should time out and return false.
	n := newNodeBare()

	// Hold all slots.
	for i := 0; i < MaxConcurrentQTDSeals; i++ {
		if !n.acquireQTDSealSlot() {
			t.Fatalf("acquire %d failed (should succeed, semaphore not yet full)", i)
		}
	}
	if got := n.GetQTDSealSemaphoreFill(); got != MaxConcurrentQTDSeals {
		t.Fatalf("fill = %d, want %d", got, MaxConcurrentQTDSeals)
	}

	// Next acquire should time out (qtdSealAcquireTimeout=2s — too long for
	// a unit test, so we use a separate goroutine to validate non-blocking).
	done := make(chan bool, 1)
	start := time.Now()
	go func() {
		done <- n.acquireQTDSealSlot()
	}()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("acquire succeeded on full semaphore (should have timed out)")
		}
		elapsed := time.Since(start)
		if elapsed < qtdSealAcquireTimeout-100*time.Millisecond {
			t.Errorf("acquire returned too fast: %v (want ~%v)", elapsed, qtdSealAcquireTimeout)
		}
		if elapsed > qtdSealAcquireTimeout+500*time.Millisecond {
			t.Errorf("acquire returned too slow: %v (want ~%v)", elapsed, qtdSealAcquireTimeout)
		}
	case <-time.After(qtdSealAcquireTimeout + 2*time.Second):
		t.Fatal("acquire did not return within expected timeout window")
	}

	// Release one slot; next acquire should now succeed.
	n.releaseQTDSealSlot()
	if !n.acquireQTDSealSlot() {
		t.Fatal("acquire failed after one release (should succeed)")
	}

	// Clean up all remaining slots. We currently hold MaxConcurrentQTDSeals
	// slots (3 initial + 1 just-acquired − 1 released = 3 held).
	for i := 0; i < MaxConcurrentQTDSeals; i++ {
		n.releaseQTDSealSlot()
	}
	if got := n.GetQTDSealSemaphoreFill(); got != 0 {
		t.Fatalf("final fill = %d, want 0", got)
	}
}

func TestNODE_R12H01_AcquireTimeoutExitsQuicklyWhenFull(t *testing.T) {
	// Sanity check: when semaphore is full, acquire blocks for at least
	// qtdSealAcquireTimeout (not zero, not instant). This documents the
	// behavior so future refactors don't accidentally reduce the timeout
	// to zero (which would make the semaphore a no-op).
	n := newNodeBare()
	for i := 0; i < MaxConcurrentQTDSeals; i++ {
		n.acquireQTDSealSlot()
	}
	defer func() {
		for i := 0; i < MaxConcurrentQTDSeals; i++ {
			n.releaseQTDSealSlot()
		}
	}()

	start := time.Now()
	ok := n.acquireQTDSealSlot()
	elapsed := time.Since(start)

	if ok {
		t.Fatal("acquire should have failed on full semaphore")
	}
	if elapsed < qtdSealAcquireTimeout-100*time.Millisecond {
		t.Errorf("acquire returned too fast: %v (want ~%v)", elapsed, qtdSealAcquireTimeout)
	}
}

func TestNODE_R12H01_ReleaseWithoutAcquireLogsButDoesNotPanic(t *testing.T) {
	// releaseQTDSealSlot called without matching acquire should not panic
	// (it logs a warning). This protects against double-release bugs.
	n := newNodeBare()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("releaseQTDSealSlot panicked on underflow: %v", r)
		}
	}()
	n.releaseQTDSealSlot() // should not panic
}

func TestNODE_R12H01_RepeatedAcquireReleaseCycle(t *testing.T) {
	// Stress the acquire/release path to catch any leaks or counter drift.
	n := newNodeBare()
	const iterations = 1000
	for i := 0; i < iterations; i++ {
		if !n.acquireQTDSealSlot() {
			t.Fatalf("iteration %d: acquire failed", i)
		}
		n.releaseQTDSealSlot()
	}
	if got := n.GetQTDSealSemaphoreFill(); got != 0 {
		t.Fatalf("after %d cycles, fill = %d, want 0", iterations, got)
	}
}

// ---------------------------------------------------------------------------
// Per-peer rate limit (inbound) tests
// ---------------------------------------------------------------------------

func TestNODE_R12H01_AllowUnderLimit(t *testing.T) {
	n := newNodeBare()
	peer := p2p.PeerID("peer-under-limit")
	for i := 0; i < qtdSealPerPeerMax; i++ {
		if !n.allowQTDSealFromPeer(peer) {
			t.Fatalf("peer rejected at message %d (limit=%d)", i, qtdSealPerPeerMax)
		}
	}
}

func TestNODE_R12H01_BlockOverLimit(t *testing.T) {
	n := newNodeBare()
	peer := p2p.PeerID("peer-over-limit")
	// Fill up the limit.
	for i := 0; i < qtdSealPerPeerMax; i++ {
		if !n.allowQTDSealFromPeer(peer) {
			t.Fatalf("peer rejected at message %d (limit=%d)", i, qtdSealPerPeerMax)
		}
	}
	// The next message should be rejected.
	if n.allowQTDSealFromPeer(peer) {
		t.Fatal("peer allowed over limit (should be rejected)")
	}
	// Subsequent messages should also be rejected within the same window.
	if n.allowQTDSealFromPeer(peer) {
		t.Fatal("peer allowed again after first rejection (should remain blocked in window)")
	}
}

func TestNODE_R12H01_WindowReset(t *testing.T) {
	// Use a custom-tunable test by directly manipulating windowStart.
	// We can't shorten qtdSealPerPeerWindow without changing production
	// constants, so we directly mutate the rate-info struct to simulate
	// window expiry.
	n := newNodeBare()
	peer := p2p.PeerID("peer-window-reset")

	// Fill the limit.
	for i := 0; i < qtdSealPerPeerMax; i++ {
		if !n.allowQTDSealFromPeer(peer) {
			t.Fatalf("peer rejected at message %d", i)
		}
	}
	// Over-limit now.
	if n.allowQTDSealFromPeer(peer) {
		t.Fatal("peer should be over limit")
	}

	// Force the window to look expired by backdating windowStart.
	n.qtdPeerRtMu.Lock()
	if info, ok := n.qtdPeerRate[peer]; ok {
		info.windowStart = time.Now().Add(-(qtdSealPerPeerWindow + time.Second))
	} else {
		t.Fatal("peer rate info missing")
	}
	n.qtdPeerRtMu.Unlock()

	// After window expiry, peer should be allowed again (counter resets).
	if !n.allowQTDSealFromPeer(peer) {
		t.Fatal("peer should be allowed after window reset")
	}
}

func TestNODE_R12H01_PerPeerIsolation(t *testing.T) {
	// Each peer should have its own rate-limit counter. Peer A maxing out
	// should not affect peer B.
	n := newNodeBare()
	peerA := p2p.PeerID("peer-A")
	peerB := p2p.PeerID("peer-B")

	// Burn through peer A's quota.
	for i := 0; i < qtdSealPerPeerMax; i++ {
		if !n.allowQTDSealFromPeer(peerA) {
			t.Fatalf("peer A rejected at message %d", i)
		}
	}
	if n.allowQTDSealFromPeer(peerA) {
		t.Fatal("peer A should be over limit")
	}

	// Peer B should still be allowed.
	for i := 0; i < qtdSealPerPeerMax; i++ {
		if !n.allowQTDSealFromPeer(peerB) {
			t.Fatalf("peer B rejected at message %d (peers should be isolated)", i)
		}
	}
	// Now peer B is also over limit.
	if n.allowQTDSealFromPeer(peerB) {
		t.Fatal("peer B should be over limit after burning quota")
	}

	if got := n.GetQTDPeerRateCount(); got != 2 {
		t.Errorf("GetQTDPeerRateCount = %d, want 2", got)
	}
}

func TestNODE_R12H01_RequestAndPartialShareCounter(t *testing.T) {
	// Both handleQTDSealRequest and handleQTDPartialSeal call
	// allowQTDSealFromPeer. They share the same per-peer counter (per the
	// audit fix design), so a peer sending 10 requests + 10 partials
	// (total 20) should be at the limit.
	n := newNodeBare()
	peer := p2p.PeerID("peer-mixed")

	// 10 of each — total 20 = qtdSealPerPeerMax.
	for i := 0; i < 10; i++ {
		if !n.allowQTDSealFromPeer(peer) {
			t.Fatalf("rejected at message %d (mixed sequence)", i)
		}
		if !n.allowQTDSealFromPeer(peer) {
			t.Fatalf("rejected at message %d (mixed sequence)", i+10)
		}
	}
	// 21st message (regardless of type) should be rejected.
	if n.allowQTDSealFromPeer(peer) {
		t.Fatal("peer should be at limit after 20 mixed messages")
	}
}

func TestNODE_R12H01_GetPeerRateCountGrowsWithNewPeers(t *testing.T) {
	n := newNodeBare()
	if got := n.GetQTDPeerRateCount(); got != 0 {
		t.Fatalf("initial peer rate count = %d, want 0", got)
	}
	for i := 0; i < 5; i++ {
		peer := p2p.PeerID("peer-" + string(rune('A'+i)))
		n.allowQTDSealFromPeer(peer)
	}
	if got := n.GetQTDPeerRateCount(); got != 5 {
		t.Errorf("after 5 unique peers, count = %d, want 5", got)
	}
}

// ---------------------------------------------------------------------------
// Concurrency stress test (verifies thread-safety)
// ---------------------------------------------------------------------------

func TestNODE_R12H01_ConcurrentRateLimitIsThreadSafe(t *testing.T) {
	// Many goroutines hitting allowQTDSealFromPeer concurrently. The
	// counter must not race (qtdPeerRtMu guards it). Without the lock,
	// `go test -race` would flag a data race here.
	n := newNodeBare()
	peer := p2p.PeerID("peer-stress")
	const goroutines = 50
	const callsPerGoroutine = 4 // total = 200, well above qtdSealPerPeerMax=20

	var wg sync.WaitGroup
	var allowed int64
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for c := 0; c < callsPerGoroutine; c++ {
				if n.allowQTDSealFromPeer(peer) {
					atomic.AddInt64(&allowed, 1)
				}
			}
		}()
	}
	wg.Wait()

	// Total allowed should equal exactly qtdSealPerPeerMax (20). Any other
	// value indicates a race that allowed over-limit messages through or
	// under-counted legitimate ones.
	if allowed != int64(qtdSealPerPeerMax) {
		t.Errorf("allowed = %d, want exactly %d (race in rate limiter?)", allowed, qtdSealPerPeerMax)
	}
}

func TestNODE_R12H01_ConcurrentAcquireReleaseThreadSafe(t *testing.T) {
	// Concurrent acquire/release on the semaphore — verifies the buffered
	// channel + mutex pattern is race-free.
	n := newNodeBare()
	const goroutines = 20
	const cyclesPerGoroutine = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for c := 0; c < cyclesPerGoroutine; c++ {
				if n.acquireQTDSealSlot() {
					// Simulate brief work.
					n.releaseQTDSealSlot()
				}
			}
		}()
	}
	wg.Wait()

	// After all goroutines finish, the semaphore should be empty.
	if got := n.GetQTDSealSemaphoreFill(); got != 0 {
		t.Errorf("after concurrent test, fill = %d, want 0 (leak)", got)
	}
}

// ---------------------------------------------------------------------------
// End-to-end: computeAndCompleteQTDSeal exits cleanly when semaphore is full
// ---------------------------------------------------------------------------

func TestNODE_R12H01_ComputeAndCompleteQTDSealExitsWhenSemaphoreFull(t *testing.T) {
	// Without a fully-wired blockProducer, computeAndCompleteQTDSeal
	// would return early on `n.blockProducer == nil` AFTER acquiring the
	// slot. We verify that:
	//   1. When the semaphore is full, the goroutine exits early WITHOUT
	//      blocking for the full qtdSealAcquireTimeout in the fast path
	//      (it should still wait the timeout — that's the contract — but
	//      it should NOT crash, NOT block forever, and NOT leave the
	//      semaphore in an inconsistent state).
	//   2. After the early exit, the semaphore is still full (the
	//      exited goroutine did not acquire a slot).
	n := newNodeBare()

	// Fill the semaphore manually.
	for i := 0; i < MaxConcurrentQTDSeals; i++ {
		if !n.acquireQTDSealSlot() {
			t.Fatalf("manual acquire %d failed", i)
		}
	}
	defer func() {
		for i := 0; i < MaxConcurrentQTDSeals; i++ {
			n.releaseQTDSealSlot()
		}
	}()

	// Call computeAndCompleteQTDSeal — it should fail to acquire and exit.
	start := time.Now()
	n.computeAndCompleteQTDSeal(999, [32]byte{0x42})
	elapsed := time.Since(start)

	// Should have waited ~qtdSealAcquireTimeout before giving up.
	if elapsed < qtdSealAcquireTimeout-200*time.Millisecond {
		t.Errorf("computeAndCompleteQTDSeal returned too fast: %v (want ~%v)", elapsed, qtdSealAcquireTimeout)
	}
	if elapsed > qtdSealAcquireTimeout+2*time.Second {
		t.Errorf("computeAndCompleteQTDSeal returned too slow: %v (want ~%v)", elapsed, qtdSealAcquireTimeout)
	}

	// Semaphore should still be full (the goroutine did not acquire).
	if got := n.GetQTDSealSemaphoreFill(); got != MaxConcurrentQTDSeals {
		t.Errorf("semaphore fill after blocked call = %d, want %d (slot leaked)", got, MaxConcurrentQTDSeals)
	}
}

func TestNODE_R12H01_ComputeAndCompleteQTDSealReleasesSlotOnEarlyReturn(t *testing.T) {
	// When the semaphore IS available but n.blockProducer is nil,
	// computeAndCompleteQTDSeal must still release the slot on early
	// return (the deferred release must fire).
	n := newNodeBare()

	if got := n.GetQTDSealSemaphoreFill(); got != 0 {
		t.Fatalf("initial fill = %d, want 0", got)
	}

	// Call with no blockProducer — should acquire, hit the early return,
	// and release via defer.
	n.computeAndCompleteQTDSeal(42, [32]byte{0x01})

	if got := n.GetQTDSealSemaphoreFill(); got != 0 {
		t.Errorf("after early-return call, fill = %d, want 0 (slot not released)", got)
	}
}

// ---------------------------------------------------------------------------
// Constants sanity check
// ---------------------------------------------------------------------------

func TestNODE_R12H01_ConstantsAreSane(t *testing.T) {
	// Document the production values so future changes are intentional.
	if MaxConcurrentQTDSeals != 3 {
		t.Errorf("MaxConcurrentQTDSeals = %d, want 3", MaxConcurrentQTDSeals)
	}
	if qtdSealAcquireTimeout != 2*time.Second {
		t.Errorf("qtdSealAcquireTimeout = %v, want 2s", qtdSealAcquireTimeout)
	}
	if qtdSealPerPeerWindow != 10*time.Second {
		t.Errorf("qtdSealPerPeerWindow = %v, want 10s", qtdSealPerPeerWindow)
	}
	if qtdSealPerPeerMax != 20 {
		t.Errorf("qtdSealPerPeerMax = %d, want 20", qtdSealPerPeerMax)
	}
}
