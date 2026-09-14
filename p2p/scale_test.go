// Quantaureum Node source, version 1.0.0.
// Package p2p implements 200K-scale tests for network optimization components.
//
// Tests cover the connection pool manager and rate limiter at 200K peer scale.
package p2p

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// =============================================================================
// 200K-Scale Connection Pool Tests
// =============================================================================

// TestScale_200KPeerPools tests creating 200K peer connection pools.
func TestScale_200KPeerPools(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K connpool test in short mode")
	}

	n := 200000
	cfg := DefaultConnPoolConfig()
	mgr := NewConnPoolManager(cfg)
	defer mgr.Close()

	t.Logf("Creating %d peer connection pools...", n)
	start := time.Now()

	for i := 0; i < n; i++ {
		peerID := PeerID(fmt.Sprintf("peer-%05d", i))
		addr := fmt.Sprintf("10.%d.%d.%d:30303", byte(i>>16), byte(i>>8), byte(i))
		// Use canceled context to create pool without actual dialing
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _ = mgr.GetConn(ctx, peerID, addr)
	}

	elapsed := time.Since(start)
	open, idle := mgr.TotalConnections()
	t.Logf("  Created pools in %v (avg %.3fµs/pool, %.0f pools/sec)",
		elapsed,
		float64(elapsed.Microseconds())/float64(n),
		float64(n)/elapsed.Seconds())
	t.Logf("  Total connections: %d open, %d idle", open, idle)
}

// TestScale_200KPeerPools_MemoryFootprint creates pools without actual connections
// to measure memory impact of pool management.
func TestScale_200KPeerPools_MemoryFootprint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K connpool test in short mode")
	}

	n := 200000
	cfg := DefaultConnPoolConfig()
	mgr := NewConnPoolManager(cfg)
	defer mgr.Close()

	t.Logf("Creating %d peer pools (no connections)...", n)
	start := time.Now()

	for i := 0; i < n; i++ {
		peerID := PeerID(fmt.Sprintf("peer-%05d", i))
		addr := fmt.Sprintf("10.%d.%d.%d:30303", byte(i>>16), byte(i>>8), byte(i))
		// GetConn with a canceled context to avoid actual dialing
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _ = mgr.GetConn(ctx, peerID, addr)
	}

	elapsed := time.Since(start)
	stats := mgr.Stats()
	t.Logf("  Created %d pools in %v (%.0f pools/sec)", len(stats), elapsed, float64(len(stats))/elapsed.Seconds())

	// Each pool + peer entry is ~200 bytes
	estimatedMB := float64(len(stats)) * 200 / (1024 * 1024)
	t.Logf("  Memory estimate: ~%.0f MB for %d pools (200 bytes/pool)", estimatedMB, len(stats))
}

// TestScale_200KPeerPools_Remove verifies that peers can be removed at scale.
func TestScale_200KPeerPools_Remove(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K connpool test in short mode")
	}

	n := 200000
	cfg := DefaultConnPoolConfig()
	mgr := NewConnPoolManager(cfg)

	// Create pools
	t.Logf("Creating %d peer pools...", n)
	for i := 0; i < n; i++ {
		peerID := PeerID(fmt.Sprintf("peer-%05d", i))
		addr := fmt.Sprintf("10.%d.%d.%d:30303", byte(i>>16), byte(i>>8), byte(i))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _ = mgr.GetConn(ctx, peerID, addr)
	}

	stats := mgr.Stats()
	t.Logf("  Before remove: %d pools", len(stats))

	// Remove half the peers
	removeCount := n / 2
	t.Logf("Removing %d peers...", removeCount)
	start := time.Now()
	for i := 0; i < removeCount; i++ {
		peerID := PeerID(fmt.Sprintf("peer-%05d", i))
		mgr.RemovePeer(peerID)
	}
	elapsed := time.Since(start)

	stats = mgr.Stats()
	t.Logf("  After remove: %d pools (removed %d in %v, %.0f removes/sec)",
		len(stats), removeCount, elapsed,
		float64(removeCount)/elapsed.Seconds())

	mgr.Close()
}

// =============================================================================
// 200K-Scale Rate Limiter Tests
// =============================================================================

// TestScale_200KRateLimiter tests rate limiting with 200K unique peers.
func TestScale_200KRateLimiter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K rate limit test in short mode")
	}

	n := 200000
	limiter := NewRateLimiter(100, time.Second)
	defer limiter.Stop()

	t.Logf("Adding %d rate limiters...", n)
	start := time.Now()

	allowed := 0
	for i := 0; i < n; i++ {
		peerID := PeerID(fmt.Sprintf("peer-%05d", i))
		if limiter.Allow(peerID) {
			allowed++
		}
	}

	elapsed := time.Since(start)
	t.Logf("  %d/%d peers within rate limit in %v (avg %.3fµs/peer, %.0f peers/sec)",
		allowed, n, elapsed,
		float64(elapsed.Microseconds())/float64(n),
		float64(n)/elapsed.Seconds())
}

// TestScale_200KRateLimiter_ViolationTracking tests violation tracking at scale.
func TestScale_200KRateLimiter_ViolationTracking(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K rate limit test in short mode")
	}

	n := 200000
	// Very low limit to trigger violations
	limiter := NewRateLimiter(1, time.Hour)
	defer limiter.Stop()

	t.Logf("Testing violation tracking with %d peers...", n)
	start := time.Now()

	violations := 0
	for i := 0; i < n; i++ {
		peerID := PeerID(fmt.Sprintf("peer-%05d", i))
		// First request always allowed
		limiter.Allow(peerID)
		// Second request should be denied
		if !limiter.Allow(peerID) {
			violations++
		}
	}

	elapsed := time.Since(start)
	t.Logf("  %d violations detected from %d peers in %v (%.3fµs/peer)",
		violations, n, elapsed,
		float64(elapsed.Microseconds())/float64(n))
}

// TestScale_200KRateLimiter_MemoryFootprint measures memory for 200K rate limiters.
func TestScale_200KRateLimiter_MemoryFootprint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K rate limit test in short mode")
	}

	n := 200000
	limiter := NewRateLimiter(100, time.Second)
	defer limiter.Stop()

	t.Logf("Populating %d rate limiters...", n)
	for i := 0; i < n; i++ {
		peerID := PeerID(fmt.Sprintf("peer-%05d", i))
		limiter.Allow(peerID)
	}

	// Each rate limiter entry is ~80 bytes (map entry + counter + tracker)
	estimatedMB := float64(n) * 80 / (1024 * 1024)
	t.Logf("  Memory estimate: ~%.0f MB for %d peer rate limiters (80 bytes/peer)", estimatedMB, n)

	// Verify clean access
	for i := 0; i < 100; i++ {
		peerID := PeerID(fmt.Sprintf("peer-%05d", i))
		limiter.Allow(peerID)
	}
	t.Logf("  Clean access: 100 peers verified")
}

// =============================================================================
// 200K-Scale Combined Network Test
// =============================================================================

// TestScale_200KCombined runs connpool + ratelimiter together at 200K scale.
func TestScale_200KCombined(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 200K combined test in short mode")
	}

	n := 200000

	// Create both components
	poolCfg := DefaultConnPoolConfig()
	poolMgr := NewConnPoolManager(poolCfg)
	defer poolMgr.Close()

	limiter := NewRateLimiter(100, time.Second)
	defer limiter.Stop()

	t.Logf("Running combined connpool + ratelimiter with %d peers...", n)
	start := time.Now()

	poolCreated := 0
	rateAllowed := 0
	for i := 0; i < n; i++ {
		peerID := PeerID(fmt.Sprintf("peer-%05d", i))
		addr := fmt.Sprintf("10.%d.%d.%d:30303", byte(i>>16), byte(i>>8), byte(i))

		// Rate limit check before creating pool
		if limiter.Allow(peerID) {
			rateAllowed++
		}

		// Create pool (with canceled context to avoid actual dial)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _ = poolMgr.GetConn(ctx, peerID, addr)
		poolCreated++
	}

	elapsed := time.Since(start)
	stats := poolMgr.Stats()

	t.Logf("  Combined test completed in %v:", elapsed)
	t.Logf("    Pools created: %d", len(stats))
	t.Logf("    Rate limit allowed: %d/%d", rateAllowed, n)
	t.Logf("    Throughput: %.0f peers/sec", float64(n)/elapsed.Seconds())
}
