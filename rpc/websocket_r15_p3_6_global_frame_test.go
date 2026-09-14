// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestP3_6_GlobalFrameLimiter_AllowsBurst verifies the global limiter seeds
// the bucket full (burst) on first call, allowing a short burst to pass.
func TestP3_6_GlobalFrameLimiter_AllowsBurst(t *testing.T) {
	var g wsGlobalFrameLimiter
	const rate = 100
	const burst = 50

	// First 50 calls (the burst budget) should all pass.
	for i := 0; i < burst; i++ {
		if !g.allow(rate, burst) {
			t.Fatalf("call %d (within burst budget) was rejected", i)
		}
	}

	// The 51st call should be rejected — bucket is empty, no time elapsed.
	if g.allow(rate, burst) {
		t.Fatal("call beyond burst budget was accepted; expected rejection")
	}
}

// TestP3_6_GlobalFrameLimiter_RefillsOverTime verifies tokens accrue at the
// configured rate after the bucket is drained.
func TestP3_6_GlobalFrameLimiter_RefillsOverTime(t *testing.T) {
	var g wsGlobalFrameLimiter
	const rate = 1000 // 1000 tokens/sec → 1 token/ms
	const burst = 10

	// Drain the bucket.
	for i := 0; i < burst; i++ {
		if !g.allow(rate, burst) {
			t.Fatalf("initial call %d rejected", i)
		}
	}

	// Sleep ~5ms → should accrue ~5 tokens.
	time.Sleep(6 * time.Millisecond)

	// Should be able to make a few more calls now.
	allowed := 0
	for i := 0; i < burst; i++ {
		if g.allow(rate, burst) {
			allowed++
		} else {
			break
		}
	}
	if allowed == 0 {
		t.Fatal("expected at least 1 token to accrue after sleeping 6ms at rate=1000/s")
	}
}

// TestP3_6_GlobalFrameLimiter_DisabledWhenZero verifies that rate=0 or burst=0
// disables the limiter (accepts all frames).
func TestP3_6_GlobalFrameLimiter_DisabledWhenZero(t *testing.T) {
	var g wsGlobalFrameLimiter
	for i := 0; i < 1000; i++ {
		if !g.allow(0, 100) {
			t.Fatal("rate=0 should disable limiter")
		}
		if !g.allow(100, 0) {
			t.Fatal("burst=0 should disable limiter")
		}
	}
}

// TestP3_6_GlobalFrameLimiter_ConcurrentSafety verifies the CAS loop is safe
// under concurrent access from many goroutines — no panics, no data races,
// total accepted count is bounded by the bucket math.
func TestP3_6_GlobalFrameLimiter_ConcurrentSafety(t *testing.T) {
	var g wsGlobalFrameLimiter
	const rate = 10000
	const burst = 100
	const goroutines = 50
	const callsPerGoroutine = 100

	var accepted atomic.Int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < callsPerGoroutine; j++ {
				if g.allow(rate, burst) {
					accepted.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	total := int(accepted.Load())
	// Upper bound: burst + rate * (test duration in seconds). The test
	// typically runs in <100ms, so well under 2000. We use a generous
	// upper bound of burst + rate to avoid flakiness.
	upperBound := burst + rate
	if total > upperBound {
		t.Fatalf("accepted %d frames, but upper bound is %d (burst=%d + rate=%d)",
			total, upperBound, burst, rate)
	}
	// Lower bound: at least the burst budget should be accepted.
	if total < burst {
		t.Fatalf("only accepted %d frames, expected at least burst=%d", total, burst)
	}
}

// TestP3_6_SetGlobalFrameRateLimit verifies the setter updates the config.
func TestP3_6_SetGlobalFrameRateLimit(t *testing.T) {
	ws := NewWebSocketServer(nil)
	if ws.globalFramesPerSec != wsDefaultGlobalFramesPerSec {
		t.Fatalf("default globalFramesPerSec = %d, want %d",
			ws.globalFramesPerSec, wsDefaultGlobalFramesPerSec)
	}
	if ws.globalMaxBurst != wsDefaultGlobalMaxBurst {
		t.Fatalf("default globalMaxBurst = %d, want %d",
			ws.globalMaxBurst, wsDefaultGlobalMaxBurst)
	}

	ws.SetGlobalFrameRateLimit(50000, 100000)
	if ws.globalFramesPerSec != 50000 {
		t.Fatalf("globalFramesPerSec = %d, want 50000", ws.globalFramesPerSec)
	}
	if ws.globalMaxBurst != 100000 {
		t.Fatalf("globalMaxBurst = %d, want 100000", ws.globalMaxBurst)
	}

	// Zero/negative values should be ignored.
	ws.SetGlobalFrameRateLimit(0, 100)
	if ws.globalFramesPerSec != 50000 {
		t.Fatalf("zero rate should not change config; got %d, want 50000",
			ws.globalFramesPerSec)
	}
	ws.SetGlobalFrameRateLimit(100, 0)
	if ws.globalMaxBurst != 100000 {
		t.Fatalf("zero burst should not change config; got %d, want 100000",
			ws.globalMaxBurst)
	}
}
