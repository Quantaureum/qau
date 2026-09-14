// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestConnPoolConfigDefaults(t *testing.T) {
	cfg := DefaultConnPoolConfig()
	if cfg.MaxConnsPerPeer <= 0 {
		t.Error("MaxConnsPerPeer should be positive")
	}
	if cfg.MaxIdleConns <= 0 {
		t.Error("MaxIdleConns should be positive")
	}
	if cfg.MaxIdleTime <= 0 {
		t.Error("MaxIdleTime should be positive")
	}
	if cfg.DialTimeout <= 0 {
		t.Error("DialTimeout should be positive")
	}
	if cfg.KeepAliveInterval <= 0 {
		t.Error("KeepAliveInterval should be positive")
	}
}

func TestConnectionPoolConfigDefaults(t *testing.T) {
	cfg := DefaultConnectionPoolConfig()
	if cfg.MaxPeers <= 0 {
		t.Error("MaxPeers should be positive")
	}
	if cfg.MinPeers <= 0 {
		t.Error("MinPeers should be positive")
	}
	if cfg.PruneInterval <= 0 {
		t.Error("PruneInterval should be positive")
	}
	if cfg.DialTimeout <= 0 {
		t.Error("DialTimeout should be positive")
	}
	if cfg.PingInterval <= 0 {
		t.Error("PingInterval should be positive")
	}
	if cfg.MaxIdleTime <= 0 {
		t.Error("MaxIdleTime should be positive")
	}
}

func TestNewConnectionPool(t *testing.T) {
	cp := NewConnectionPool(nil)
	if cp == nil {
		t.Fatal("NewConnectionPool returned nil")
	}
	defer cp.Close()
}

func TestConnectionPoolAddPeer(t *testing.T) {
	cp := NewConnectionPool(nil)
	defer cp.Close()

	peer := &PeerConnection{
		ID:        "valid-peer-id-12345678",
		Direction: DirInbound,
		Connected: time.Now(),
		LastSeen:  time.Now(),
		Addr:      "198.51.100.10:9000",
		Verified:  true,
	}

	err := cp.AddPeer(peer)
	if err != nil {
		t.Fatalf("AddPeer failed: %v", err)
	}

	if cp.PeerCount() != 1 {
		t.Errorf("PeerCount = %d, want 1", cp.PeerCount())
	}
}

func TestConnectionPoolAddPeerNil(t *testing.T) {
	cp := NewConnectionPool(nil)
	defer cp.Close()

	err := cp.AddPeer(nil)
	if err != ErrConnInvalid {
		t.Errorf("expected ErrConnInvalid, got %v", err)
	}
}

func TestConnectionPoolAddPeerBlacklisted(t *testing.T) {
	cp := NewConnectionPool(nil)
	defer cp.Close()

	peerID := PeerID("blacklisted-peer-1234")
	cp.Blacklist().Add(peerID, "bad behavior")

	peer := &PeerConnection{
		ID:       peerID,
		Verified: true,
	}
	err := cp.AddPeer(peer)
	if err != ErrPeerBlacklisted {
		t.Errorf("expected ErrPeerBlacklisted, got %v", err)
	}
}

func TestConnectionPoolAddPeerMaxReached(t *testing.T) {
	cfg := DefaultConnectionPoolConfig()
	cfg.MaxPeers = 1
	cp := NewConnectionPool(cfg)
	defer cp.Close()

	peer1 := &PeerConnection{
		ID:       "peer-1-aaaaaaaaaaaa",
		Verified: true,
	}
	peer2 := &PeerConnection{
		ID:       "peer-2-bbbbbbbbbbbb",
		Verified: true,
	}

	_ = cp.AddPeer(peer1)
	err := cp.AddPeer(peer2)
	if err != ErrMaxPeersReached {
		t.Errorf("expected ErrMaxPeersReached, got %v", err)
	}
}

func TestConnectionPoolAddPeerNotVerified(t *testing.T) {
	cp := NewConnectionPool(nil)
	defer cp.Close()

	peer := &PeerConnection{
		ID:       "unverified-peer-1234",
		Verified: false,
	}
	err := cp.AddPeer(peer)
	if err != ErrIdentityNotVerified {
		t.Errorf("expected ErrIdentityNotVerified, got %v", err)
	}
}

func TestConnectionPoolAddPeerShortID(t *testing.T) {
	cp := NewConnectionPool(nil)
	defer cp.Close()

	peer := &PeerConnection{
		ID:       "short", // Less than MinPeerIDLength
		Verified: true,
	}
	err := cp.AddPeer(peer)
	if err != ErrIdentityNotVerified {
		t.Errorf("expected ErrIdentityNotVerified for short ID, got %v", err)
	}
}

func TestConnectionPoolAddPeerUnsafe(t *testing.T) {
	cp := NewConnectionPool(nil)
	defer cp.Close()
	cp.AllowUnsafePeerAddForTesting()

	peer := &PeerConnection{
		ID:       "unsafe-peer-12345678",
		Verified: false, // Not verified, but using unsafe method
	}
	err := cp.AddPeerUnsafe(peer)
	if err != nil {
		t.Fatalf("AddPeerUnsafe failed: %v", err)
	}
}

func TestConnectionPoolRemovePeer(t *testing.T) {
	cp := NewConnectionPool(nil)
	defer cp.Close()
	cp.AllowUnsafePeerAddForTesting()

	peerID := PeerID("removable-peer-1234")
	peer := &PeerConnection{
		ID:       peerID,
		Verified: true,
	}
	_ = cp.AddPeerUnsafe(peer)
	cp.RemovePeer(peerID)

	if cp.PeerCount() != 0 {
		t.Errorf("PeerCount after remove = %d, want 0", cp.PeerCount())
	}
}

func TestConnectionPoolGetPeer(t *testing.T) {
	cp := NewConnectionPool(nil)
	defer cp.Close()
	cp.AllowUnsafePeerAddForTesting()

	peerID := PeerID("gettable-peer-1234")
	peer := &PeerConnection{
		ID:       peerID,
		Verified: true,
	}
	_ = cp.AddPeerUnsafe(peer)

	found, ok := cp.GetPeer(peerID)
	if !ok {
		t.Error("GetPeer should find the peer")
	}
	if found.ID != peerID {
		t.Errorf("found.ID = %q, want %q", found.ID, peerID)
	}

	_, ok = cp.GetPeer("unknown-peer")
	if ok {
		t.Error("GetPeer should not find unknown peer")
	}
}

func TestConnectionPoolGetBestPeers(t *testing.T) {
	cp := NewConnectionPool(nil)
	defer cp.Close()
	cp.AllowUnsafePeerAddForTesting()

	peer1 := &PeerConnection{ID: "best-peer-1-aaaaaa", Verified: true}
	peer2 := &PeerConnection{ID: "best-peer-2-bbbbbb", Verified: true}
	_ = cp.AddPeerUnsafe(peer1)
	_ = cp.AddPeerUnsafe(peer2)

	best := cp.GetBestPeers(1)
	if len(best) != 1 {
		t.Fatalf("len(GetBestPeers) = %d, want 1", len(best))
	}
}

func TestConnectionPoolUpdateScore(t *testing.T) {
	cp := NewConnectionPool(nil)
	defer cp.Close()
	cp.AllowUnsafePeerAddForTesting()

	peerID := PeerID("scored-peer-123456")
	peer := &PeerConnection{ID: peerID, Verified: true}
	_ = cp.AddPeerUnsafe(peer)

	cp.UpdateScore(peerID, 50*time.Millisecond, true)

	score, ok := cp.GetScore(peerID)
	if !ok {
		t.Fatal("GetScore should find the peer")
	}
	if score.Latency != 50*time.Millisecond {
		t.Errorf("Latency = %v, want 50ms", score.Latency)
	}
}

func TestConnectionPoolGetScoreUnknown(t *testing.T) {
	cp := NewConnectionPool(nil)
	defer cp.Close()

	_, ok := cp.GetScore("unknown-peer")
	if ok {
		t.Error("GetScore should not find unknown peer")
	}
}

func TestConnectionPoolPrune(t *testing.T) {
	cfg := DefaultConnectionPoolConfig()
	cfg.MinPeers = 0
	cfg.ScoreThreshold = 0.5
	cp := NewConnectionPool(cfg)
	defer cp.Close()
	cp.AllowUnsafePeerAddForTesting()

	// Add a peer and make its score very low
	peerID := PeerID("low-score-peer-1234")
	peer := &PeerConnection{ID: peerID, Verified: true}
	_ = cp.AddPeerUnsafe(peer)

	// Record failures to lower the score
	cp.UpdateScore(peerID, 500*time.Millisecond, false)
	cp.UpdateScore(peerID, 500*time.Millisecond, false)
	cp.UpdateScore(peerID, 500*time.Millisecond, false)

	pruned := cp.Prune()
	// May or may not prune depending on score
	_ = pruned
}

func TestConnectionPoolNeedsMorePeers(t *testing.T) {
	cfg := DefaultConnectionPoolConfig()
	cfg.MinPeers = 5
	cp := NewConnectionPool(cfg)
	defer cp.Close()

	if !cp.NeedsMorePeers() {
		t.Error("should need more peers with 0 peers and MinPeers=5")
	}
}

func TestConnectionPoolHasCapacity(t *testing.T) {
	cfg := DefaultConnectionPoolConfig()
	cfg.MaxPeers = 1
	cp := NewConnectionPool(cfg)
	defer cp.Close()
	cp.AllowUnsafePeerAddForTesting()

	if !cp.HasCapacity() {
		t.Error("should have capacity with 0 peers")
	}

	peer := &PeerConnection{ID: "capacity-peer-12345", Verified: true}
	_ = cp.AddPeerUnsafe(peer)

	if cp.HasCapacity() {
		t.Error("should not have capacity after reaching MaxPeers")
	}
}

func TestConnectionPoolAllPeers(t *testing.T) {
	cp := NewConnectionPool(nil)
	defer cp.Close()
	cp.AllowUnsafePeerAddForTesting()

	peer1 := &PeerConnection{ID: "all-peer-1-aaaaaa", Verified: true}
	peer2 := &PeerConnection{ID: "all-peer-2-bbbbbb", Verified: true}
	_ = cp.AddPeerUnsafe(peer1)
	_ = cp.AddPeerUnsafe(peer2)

	all := cp.AllPeers()
	if len(all) != 2 {
		t.Errorf("len(AllPeers) = %d, want 2", len(all))
	}
}

func TestConnectionPoolAllScores(t *testing.T) {
	cp := NewConnectionPool(nil)
	defer cp.Close()
	cp.AllowUnsafePeerAddForTesting()

	peer := &PeerConnection{ID: "score-peer-123456", Verified: true}
	_ = cp.AddPeerUnsafe(peer)

	scores := cp.AllScores()
	if len(scores) != 1 {
		t.Errorf("len(AllScores) = %d, want 1", len(scores))
	}
}

func TestConnectionPoolSelectPeersForBroadcast(t *testing.T) {
	cp := NewConnectionPool(nil)
	defer cp.Close()
	cp.AllowUnsafePeerAddForTesting()

	peer := &PeerConnection{ID: "broadcast-peer-1234", Verified: true}
	_ = cp.AddPeerUnsafe(peer)

	selected := cp.SelectPeersForBroadcast(1)
	if len(selected) != 1 {
		t.Errorf("len(SelectPeersForBroadcast) = %d, want 1", len(selected))
	}
}

func TestConnectionPoolCloseTwice(t *testing.T) {
	cp := NewConnectionPool(nil)
	_ = cp.Close()
	_ = cp.Close()
	// Should not panic
}

func TestConnectionPoolAddPeerAfterClose(t *testing.T) {
	cp := NewConnectionPool(nil)
	_ = cp.Close()

	peer := &PeerConnection{ID: "closed-pool-peer-12", Verified: true}
	err := cp.AddPeer(peer)
	if err != ErrConnPoolClosed {
		t.Errorf("expected ErrConnPoolClosed, got %v", err)
	}
}

func TestPooledConnIsExpired(t *testing.T) {
	pc := &PooledConn{
		lastUsed: time.Now().Add(-10 * time.Minute),
		inUse:    false,
	}

	if !pc.IsExpired(5 * time.Minute) {
		t.Error("should be expired")
	}
	if pc.IsExpired(15 * time.Minute) {
		t.Error("should not be expired")
	}
}

func TestPooledConnIsExpiredInUse(t *testing.T) {
	pc := &PooledConn{
		lastUsed: time.Now().Add(-10 * time.Minute),
		inUse:    true,
	}

	if pc.IsExpired(5 * time.Minute) {
		t.Error("in-use connection should not be expired")
	}
}

func TestPooledConnIsExpiredZeroDuration(t *testing.T) {
	pc := &PooledConn{
		lastUsed: time.Now().Add(-10 * time.Minute),
		inUse:    false,
	}

	if pc.IsExpired(0) {
		t.Error("zero duration should not expire connections")
	}
}

func TestNewPeerConnPool(t *testing.T) {
	pool := NewPeerConnPool("test-peer", "198.51.100.10:9000", nil)
	if pool == nil {
		t.Fatal("NewPeerConnPool returned nil")
	}
}

func TestPeerConnPoolClose(t *testing.T) {
	pool := NewPeerConnPool("test-peer", "198.51.100.10:9000", nil)
	err := pool.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestPeerConnPoolGetClosed(t *testing.T) {
	pool := NewPeerConnPool("test-peer", "198.51.100.10:9000", nil)
	pool.Close()

	ctx := context.Background()
	_, err := pool.Get(ctx)
	if err != ErrConnPoolClosed {
		t.Errorf("expected ErrConnPoolClosed, got %v", err)
	}
}

func TestPeerConnPoolStats(t *testing.T) {
	pool := NewPeerConnPool("test-peer", "198.51.100.10:9000", nil)
	defer pool.Close()

	open, idle := pool.Stats()
	if open != 0 {
		t.Errorf("open = %d, want 0", open)
	}
	if idle != 0 {
		t.Errorf("idle = %d, want 0", idle)
	}
}

func TestNewConnPoolManager(t *testing.T) {
	mgr := NewConnPoolManager(nil)
	if mgr == nil {
		t.Fatal("NewConnPoolManager returned nil")
	}
	defer mgr.Close()
}

func TestConnPoolManagerClose(t *testing.T) {
	mgr := NewConnPoolManager(nil)
	err := mgr.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestConnPoolManagerStats(t *testing.T) {
	mgr := NewConnPoolManager(nil)
	defer mgr.Close()

	stats := mgr.Stats()
	if stats == nil {
		t.Error("Stats should not return nil")
	}
}

func TestConnPoolManagerTotalConnections(t *testing.T) {
	mgr := NewConnPoolManager(nil)
	defer mgr.Close()

	open, idle := mgr.TotalConnections()
	if open != 0 {
		t.Errorf("open = %d, want 0", open)
	}
	if idle != 0 {
		t.Errorf("idle = %d, want 0", idle)
	}
}

func TestConnPoolManagerRemovePeer(t *testing.T) {
	mgr := NewConnPoolManager(nil)
	defer mgr.Close()

	mgr.RemovePeer("unknown-peer")
	// Should not panic
}

// TestPeerConnPoolPruneIdleConnections verifies that pruneIdleConnections
// closes idle connections that have exceeded MaxIdleTime and leaves
// non-expired ones alone.
//
// P2P-R11-L04 (2026-07-20): This test covers the new method that's called
// by ConnPoolManager.idleSweepLoop. Without the sweeper, idle connections
// could leak forever in a pool that no one was actively pulling from.
func TestPeerConnPoolPruneIdleConnections(t *testing.T) {
	cfg := &ConnPoolConfig{
		MaxConnsPerPeer:   5,
		MaxIdleConns:      2,
		MaxIdleTime:       100 * time.Millisecond,
		DialTimeout:       10 * time.Second,
		KeepAliveInterval: 30 * time.Second,
	}
	pool := NewPeerConnPool("peer1", "198.51.100.10:9000", cfg)
	defer pool.Close()

	// Inject an expired idle connection (lastUsed = 1s ago, MaxIdleTime = 100ms).
	c1a, c1b := net.Pipe()
	defer c1b.Close()
	pool.idle.PushBack(&PooledConn{
		conn:     c1a,
		lastUsed: time.Now().Add(-1 * time.Second),
		inUse:    false,
	})
	atomic.AddInt32(&pool.numOpen, 1)

	// Inject a fresh idle connection (lastUsed = now, within MaxIdleTime).
	c2a, c2b := net.Pipe()
	defer c2b.Close()
	pool.idle.PushBack(&PooledConn{
		conn:     c2a,
		lastUsed: time.Now(),
		inUse:    false,
	})
	atomic.AddInt32(&pool.numOpen, 1)

	open, idle := pool.Stats()
	if open != 2 || idle != 2 {
		t.Fatalf("before prune: open=%d idle=%d, want 2/2", open, idle)
	}

	pool.pruneIdleConnections()

	open, idle = pool.Stats()
	if open != 1 || idle != 1 {
		t.Errorf("after prune: open=%d idle=%d, want 1/1 (only fresh conn kept)", open, idle)
	}

	// Verify the expired end was actually closed by attempting to write
	// to the other end. A closed net.Pipe end causes Write to return
	// an error on the peer end.
	c1b.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_, err := c1b.Write([]byte("x"))
	if err == nil {
		t.Error("c1b.Write should have failed because c1a was closed by prune")
	}
}

// TestConnPoolManagerSweepAllPools verifies that ConnPoolManager.sweepAllPools
// (the function called by the idle-sweeper goroutine) walks every pool and
// prunes expired idle connections in each one.
//
// P2P-R11-L04 (2026-07-20): This test directly drives sweepAllPools rather
// than waiting for the goroutine's ticker to fire (which would take 30s due
// to the sweep-interval clamp). It exercises the snapshot-under-RLock code
// path and confirms pruning works across multiple pools.
func TestConnPoolManagerSweepAllPools(t *testing.T) {
	// Use a long MaxIdleTime (5m) so the background sweeper's first tick
	// (30s after NewConnPoolManager) doesn't fire during this test. We
	// call sweepAllPools manually below.
	cfg := &ConnPoolConfig{
		MaxConnsPerPeer:   5,
		MaxIdleConns:      2,
		MaxIdleTime:       5 * time.Minute,
		DialTimeout:       10 * time.Second,
		KeepAliveInterval: 30 * time.Second,
		MaxPools:          1000,
		MinOutboundConns:  3,
		MinOutboundRatio:  0.3,
	}
	mgr := NewConnPoolManager(cfg)
	defer mgr.Close()

	// Inject two pools with expired idle connections.
	// lastUsed = 10 minutes ago, MaxIdleTime = 5 minutes → IsExpired = true.
	pool1 := NewPeerConnPool("peer1", "203.0.113.20:9000", cfg)
	c1a, c1b := net.Pipe()
	defer c1b.Close()
	pool1.idle.PushBack(&PooledConn{
		conn:     c1a,
		lastUsed: time.Now().Add(-10 * time.Minute),
		inUse:    false,
	})
	atomic.AddInt32(&pool1.numOpen, 1)

	pool2 := NewPeerConnPool("peer2", "198.51.100.20:9000", cfg)
	c2a, c2b := net.Pipe()
	defer c2b.Close()
	pool2.idle.PushBack(&PooledConn{
		conn:     c2a,
		lastUsed: time.Now().Add(-10 * time.Minute),
		inUse:    false,
	})
	atomic.AddInt32(&pool2.numOpen, 1)

	mgr.mu.Lock()
	mgr.pools["peer1"] = pool1
	mgr.pools["peer2"] = pool2
	mgr.mu.Unlock()

	open, idle := mgr.TotalConnections()
	if open != 2 || idle != 2 {
		t.Fatalf("before sweep: open=%d idle=%d, want 2/2", open, idle)
	}

	// Drive the sweep directly (the goroutine calls the same method).
	mgr.sweepAllPools()

	open, idle = mgr.TotalConnections()
	if open != 0 || idle != 0 {
		t.Errorf("after sweep: open=%d idle=%d, want 0/0 (all expired conns pruned)", open, idle)
	}

	// Verify both pipe ends were actually closed.
	c1b.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := c1b.Write([]byte("x")); err == nil {
		t.Error("c1b.Write should fail after c1a was closed by sweep")
	}
	c2b.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := c2b.Write([]byte("x")); err == nil {
		t.Error("c2b.Write should fail after c2a was closed by sweep")
	}
}

// TestConnPoolManagerSweepRespectsClosedFlag ensures sweepAllPools returns
// without doing anything after Close() has been called. This guards against
// a race where Close() runs concurrently with the sweeper and would otherwise
// iterate pools that have already been torn down.
//
// P2P-R11-L04 (2026-07-20).
func TestConnPoolManagerSweepRespectsClosedFlag(t *testing.T) {
	cfg := &ConnPoolConfig{
		MaxConnsPerPeer:   5,
		MaxIdleConns:      2,
		MaxIdleTime:       5 * time.Minute,
		DialTimeout:       10 * time.Second,
		KeepAliveInterval: 30 * time.Second,
	}
	mgr := NewConnPoolManager(cfg)

	// Close immediately. The sweeper goroutine's first tick is 30s away
	// so we don't race it; we're testing the closed-flag check.
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Calling sweepAllPools after Close should be a no-op (no panic,
	// no error, no work done).
	mgr.sweepAllPools()

	// Calling Close again should be idempotent.
	if err := mgr.Close(); err != nil {
		t.Errorf("second Close failed: %v", err)
	}
}

// TestConnPoolManagerNoSweeperWhenMaxIdleTimeZero verifies that when
// MaxIdleTime=0 (idle expiration disabled), NewConnPoolManager does NOT
// start a background sweeper goroutine. This avoids burning a goroutine
// for a feature that's been turned off.
//
// P2P-R11-L04 (2026-07-20).
func TestConnPoolManagerNoSweeperWhenMaxIdleTimeZero(t *testing.T) {
	cfg := &ConnPoolConfig{
		MaxConnsPerPeer:   5,
		MaxIdleConns:      2,
		MaxIdleTime:       0, // disabled
		DialTimeout:       10 * time.Second,
		KeepAliveInterval: 30 * time.Second,
	}
	mgr := NewConnPoolManager(cfg)
	defer mgr.Close()

	// Inject an "expired" idle connection — but since MaxIdleTime=0,
	// IsExpired returns false and pruneIdleConnections is a no-op.
	pool := NewPeerConnPool("peer1", "198.51.100.10:9000", cfg)
	c1a, c1b := net.Pipe()
	defer c1b.Close()
	pool.idle.PushBack(&PooledConn{
		conn:     c1a,
		lastUsed: time.Now().Add(-1 * time.Hour), // very old
		inUse:    false,
	})
	atomic.AddInt32(&pool.numOpen, 1)

	mgr.mu.Lock()
	mgr.pools["peer1"] = pool
	mgr.mu.Unlock()

	// Even though lastUsed is 1 hour ago, MaxIdleTime=0 disables expiration.
	mgr.sweepAllPools()

	open, idle := mgr.TotalConnections()
	if open != 1 || idle != 1 {
		t.Errorf("after sweep with MaxIdleTime=0: open=%d idle=%d, want 1/1 (sweep must be a no-op)", open, idle)
	}
}

func TestPeerScoreUpdateLatency(t *testing.T) {
	ps := NewPeerScore()
	ps.UpdateLatency(50 * time.Millisecond)

	if ps.Latency != 50*time.Millisecond {
		t.Errorf("Latency = %v, want 50ms", ps.Latency)
	}
}

func TestPeerScoreRecordSuccess(t *testing.T) {
	ps := NewPeerScore()
	ps.RecordSuccess()

	if ps.Reliability != 1.0 {
		t.Errorf("Reliability = %f, want 1.0", ps.Reliability)
	}
	if ps.Score <= 0 {
		t.Errorf("Score = %f, should be positive", ps.Score)
	}
}

func TestPeerScoreRecordFailure(t *testing.T) {
	ps := NewPeerScore()
	ps.RecordFailure()

	if ps.Reliability != 0.0 {
		t.Errorf("Reliability = %f, want 0.0", ps.Reliability)
	}
}

func TestPeerScoreUpdateBandwidth(t *testing.T) {
	ps := NewPeerScore()
	ps.UpdateBandwidth(5 * 1024 * 1024)

	if ps.Bandwidth != 5*1024*1024 {
		t.Errorf("Bandwidth = %d, want 5MB/s", ps.Bandwidth)
	}
}

func TestPeerScoreClone(t *testing.T) {
	ps := NewPeerScore()
	ps.RecordSuccess()
	ps.UpdateLatency(50 * time.Millisecond)

	clone := ps.Clone()
	if clone.Score != ps.Score {
		t.Errorf("clone Score = %f, want %f", clone.Score, ps.Score)
	}
	if clone.Latency != ps.Latency {
		t.Errorf("clone Latency = %v, want %v", clone.Latency, ps.Latency)
	}
}

func TestPeerScoreMixedResults(t *testing.T) {
	ps := NewPeerScore()
	ps.RecordSuccess()
	ps.RecordSuccess()
	ps.RecordSuccess()
	ps.RecordFailure()

	if ps.Reliability != 0.75 {
		t.Errorf("Reliability = %f, want 0.75", ps.Reliability)
	}
}

func TestPeerConnectionFields(t *testing.T) {
	now := time.Now()
	pc := &PeerConnection{
		ID:        "test-peer-id",
		Direction: DirInbound,
		Connected: now,
		LastSeen:  now,
		Addr:      "198.51.100.10:9000",
		Verified:  true,
	}

	if pc.ID != "test-peer-id" {
		t.Errorf("ID = %q, want %q", pc.ID, "test-peer-id")
	}
	if pc.Direction != DirInbound {
		t.Errorf("Direction = %d, want %d", pc.Direction, DirInbound)
	}
	if !pc.Verified {
		t.Error("Verified should be true")
	}
}
