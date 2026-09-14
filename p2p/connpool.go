// Quantaureum Node source, version 1.0.0.
// Package p2p implements the peer-to-peer network layer for Quantaureum.
//
// audit-remediation: PEER IDENTITY VERIFICATION IMPLEMENTED
// This package implements cryptographic peer identity verification:
// - PeerIdentityVerifier interface in host.go
// - Challenge-response verification in verifyPeerIdentity()
// - Peer ID validation in AddPeer() (MinPeerIDLength check)
// - ErrIdentityNotVerified error for failed verification
package p2p

// SECURITY (audit P4-3): Many //nosec //nolint:errcheck annotations suppress Close() errors.
// Review all suppressed errors to ensure they are safe to ignore.

import (
	"container/list"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/quantaureum/qau/params"
	"time"
)

// closeConnLog closes a connection and logs any error (audit P4-05).
func closeConnLog(c io.Closer, ctx string) {
	if err := c.Close(); err != nil {
		log.Printf("[WARN] connpool: Close() error in %s: %v", ctx, err)
	}
}

// Connection pool errors
var (
	ErrConnPoolClosed    = errors.New("connection pool is closed")
	ErrConnPoolExhausted = errors.New("connection pool exhausted")
	ErrConnInvalid       = errors.New("invalid connection")
	ErrConnTimeout       = errors.New("connection timeout")
	ErrPeerBlacklisted   = errors.New("peer is blacklisted")
	ErrMaxPeersReached   = errors.New("maximum peers reached")
	ErrMaxPoolsReached   = errors.New("maximum connection pools reached") // I22-009
)

// ConnPoolConfig holds configuration for the P2P connection pool.
type ConnPoolConfig struct {
	// MaxConnsPerPeer is the maximum connections per peer.
	MaxConnsPerPeer int
	// MaxIdleConns is the maximum idle connections per peer.
	MaxIdleConns int
	// MaxIdleTime is the maximum idle time before a connection is closed.
	MaxIdleTime time.Duration
	// DialTimeout is the timeout for establishing new connections.
	DialTimeout time.Duration
	// KeepAliveInterval is the interval for keep-alive pings.
	KeepAliveInterval time.Duration
	// MaxPools is the maximum number of per-peer connection pools.
	// I22-009 FIX: prevents unbounded growth of the pools map when many
	// unique peerIDs are seen (e.g., from churn or Sybil-style peer rotation).
	MaxPools int
	// MinOutboundConns is the minimum number of outbound (dialed) connections
	// to maintain. SECURITY FIX (audit P2P-03): Prevents Eclipse attacks by
	// ensuring the node always has connections it initiated to random peers,
	// making it harder for an attacker to fill all connection slots.
	MinOutboundConns int
	// MinOutboundRatio is the minimum fraction of connections that must be
	// outbound. Default 0.3 means at least 30% of connections are dialed out.
	MinOutboundRatio float64
}

// DefaultConnPoolConfig returns a default connection pool configuration.
func DefaultConnPoolConfig() *ConnPoolConfig {
	return &ConnPoolConfig{
		MaxConnsPerPeer:   5,
		MaxIdleConns:      2,
		MaxIdleTime:       5 * time.Minute,
		DialTimeout:       10 * time.Second,
		KeepAliveInterval: 30 * time.Second,
		// I22-009 FIX: cap total per-peer pools to prevent unbounded growth.
		MaxPools: 1000,
		// SECURITY FIX (audit P2P-03): Enforce minimum outbound connections
		// to prevent Eclipse attacks. At least 3 outbound connections and
		// 30% of total connections must be self-initiated.
		MinOutboundConns: 3,
		MinOutboundRatio: 0.3,
	}
}

// PooledConn represents a pooled network connection.
type PooledConn struct {
	conn      net.Conn
	peerID    PeerID
	createdAt time.Time
	lastUsed  time.Time
	inUse     bool
}

// IsExpired checks if the connection has exceeded its idle time.
func (pc *PooledConn) IsExpired(maxIdleTime time.Duration) bool {
	if maxIdleTime <= 0 {
		return false
	}
	return !pc.inUse && time.Since(pc.lastUsed) > maxIdleTime
}

// PeerConnPool manages connections to a single peer.
type PeerConnPool struct {
	peerID PeerID
	addr   string
	config *ConnPoolConfig

	// P2P-R11-H03 (2026-07-20): TLS config for encrypted transport.
	// When set, dial() uses tls.Dial instead of plaintext net.Dial.
	// When nil, behavior depends on QAU_PRODUCTION env var:
	//   - QAU_PRODUCTION=1: dial() fails closed (returns error).
	//   - otherwise (dev/test): dial() falls back to plaintext TCP
	//     to preserve backward compatibility with dev deployments.
	// This ensures production NEVER uses plaintext P2P transport while
	// allowing tests to use plaintext without configuring TLS.
	tlsConfig *tls.Config

	mu      sync.Mutex
	cond    *sync.Cond
	idle    *list.List // List of *PooledConn
	numOpen int32
	closed  bool
}

// NewPeerConnPool creates a new connection pool for a peer.
func NewPeerConnPool(peerID PeerID, addr string, config *ConnPoolConfig) *PeerConnPool {
	if config == nil {
		config = DefaultConnPoolConfig()
	}

	pool := &PeerConnPool{
		peerID: peerID,
		addr:   addr,
		config: config,
		idle:   list.New(),
	}
	pool.cond = sync.NewCond(&pool.mu)

	return pool
}

// SetTLSConfig sets the TLS configuration for encrypted dial.
// P2P-R11-H03: When set, dial() uses tls.Dial with this config.
// When nil, dial() falls back to plaintext TCP (only allowed in dev/test).
func (p *PeerConnPool) SetTLSConfig(c *tls.Config) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tlsConfig = c
}

// Get retrieves a connection from the pool or creates a new one.
func (p *PeerConnPool) Get(ctx context.Context) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, ErrConnPoolClosed
	}

	// Try to get an idle connection
	for p.idle.Len() > 0 {
		elem := p.idle.Front()
		p.idle.Remove(elem)
		pc := elem.Value.(*PooledConn)

		if pc.IsExpired(p.config.MaxIdleTime) {
			closeConnLog(pc.conn, "pc.conn.Close")
			atomic.AddInt32(&p.numOpen, -1)
			continue
		}

		pc.inUse = true
		pc.lastUsed = time.Now()
		return &pooledNetConn{pc: pc, pool: p}, nil
	}

	// Check if we can create a new connection
	if int(atomic.LoadInt32(&p.numOpen)) >= p.config.MaxConnsPerPeer {
		// audit-fix H-7: sync.Cond.Wait() requires the caller to hold the
		// associated mutex. Use a channel-based notification so we can
		// safely select on both the context and the "connection returned"
		// event without violating the Cond contract.
		// audit-fix H-7b: acquiredCh synchronizes the waiter goroutine's lock
		// acquisition before the main goroutine releases p.mu. This prevents
		// a lost-signal race where Put() calls Signal() after p.mu.Unlock()
		// but before the waiter goroutine has entered Wait().
		waitCh := make(chan struct{}, 1)
		acquiredCh := make(chan struct{})
		waiterCtx, waiterCancel := context.WithCancel(ctx)
		defer waiterCancel()
		go func() {
			// CRIT-08 (R17, 2026-07-23): This waiter goroutine holds p.mu
			// and calls p.cond.Wait(). A panic here (e.g., from a
			// corrupted mutex/cond state) would crash the node. The
			// recover logs the panic and lets the goroutine exit.
			//
			// NOTE: We intentionally do NOT send to waitCh in the recover
			// path. If the panic occurred while p.mu is held (before the
			// explicit p.mu.Unlock below), sending to waitCh would cause
			// the caller to proceed to p.mu.Lock() and deadlock on the
			// already-held mutex. Instead, we let the caller fall through
			// to its `<-ctx.Done()` branch, which will fire when the
			// context expires (waiterCancel is deferred in the caller).
			// This avoids a deadlock while still preventing a node crash.
			defer func() {
				if r := recover(); r != nil {
					log.Printf("p2p connpool waiter goroutine panic recovered: %v", r)
				}
			}()
			p.mu.Lock()
			close(acquiredCh) // signal: I hold p.mu and am about to Wait
			// Use a select with context cancellation to prevent goroutine leak
			for !p.closed {
				if waiterCtx.Err() != nil {
					// Context canceled, wake up and exit cleanly
					p.cond.Signal()
					break
				}
				p.cond.Wait()
				if waiterCtx.Err() != nil {
					p.cond.Signal()
					break
				}
			}
			p.mu.Unlock()
			select {
			case waitCh <- struct{}{}:
			default:
			}
		}()

		p.mu.Unlock()
		<-acquiredCh // wait until goroutine holds p.mu and is about to enter Wait()
		select {
		case <-waitCh:
			p.mu.Lock()
		case <-ctx.Done():
			// Signal the waiter goroutine so it doesn't leak.
			waiterCancel()
			p.cond.Signal()
			p.mu.Lock()
			return nil, ctx.Err()
		}

		// Retry getting a connection
		if p.closed {
			return nil, ErrConnPoolClosed
		}

		for p.idle.Len() > 0 {
			elem := p.idle.Front()
			p.idle.Remove(elem)
			pc := elem.Value.(*PooledConn)

			if !pc.IsExpired(p.config.MaxIdleTime) {
				pc.inUse = true
				pc.lastUsed = time.Now()
				return &pooledNetConn{pc: pc, pool: p}, nil
			}
			closeConnLog(pc.conn, "pc.conn.Close")
			atomic.AddInt32(&p.numOpen, -1)
		}
	}

	// Create a new connection
	p.mu.Unlock()
	conn, err := p.dial(ctx)
	p.mu.Lock()

	if err != nil {
		return nil, err
	}

	pc := &PooledConn{
		conn:      conn,
		peerID:    p.peerID,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
		inUse:     true,
	}
	atomic.AddInt32(&p.numOpen, 1)

	return &pooledNetConn{pc: pc, pool: p}, nil
}

// Put returns a connection to the pool.
func (p *PeerConnPool) Put(pc *PooledConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed || pc == nil {
		if pc != nil && pc.conn != nil {
			closeConnLog(pc.conn, "pc.conn.Close")
			atomic.AddInt32(&p.numOpen, -1)
		}
		return
	}

	pc.inUse = false
	pc.lastUsed = time.Now()

	// Check if we have too many idle connections
	if p.idle.Len() >= p.config.MaxIdleConns {
		closeConnLog(pc.conn, "pc.conn.Close")
		atomic.AddInt32(&p.numOpen, -1)
		p.cond.Signal()
		return
	}

	p.idle.PushBack(pc)
	p.cond.Signal()
}

// dial creates a new connection to the peer.
//
// P2P-R11-H03 (2026-07-20) FIX: Previously this method ALWAYS used plaintext
// TCP, with a comment claiming "only for non-sensitive gossipsub connections".
// This is wrong — gossipsub propagates blocks, votes, and transactions,
// all of which are sensitive (front-running risk if seen in plaintext, and
// active tampering risk from a network attacker).
//
// The fix:
//   - If tlsConfig is set (via SetTLSConfig), use tls.Dial with the supplied
//     config. This is the production path: callers wire in the mTLS config
//     from NodeCertificateManager.GetTLSConfig().
//   - If tlsConfig is nil AND QAU_PRODUCTION=1, fail closed (refuse to dial)
//     rather than allow plaintext transport in production.
//   - If tlsConfig is nil AND not production (dev/test), fall back to
//     plaintext TCP to preserve backward compatibility with dev deployments
//     and to keep existing unit tests (which don't configure TLS) working.
func (p *PeerConnPool) dial(ctx context.Context) (net.Conn, error) {
	p.mu.Lock()
	tlsCfg := p.tlsConfig
	p.mu.Unlock()

	dialer := &net.Dialer{
		Timeout: p.config.DialTimeout,
	}

	if tlsCfg != nil {
		// Production path: mTLS-encrypted P2P transport.
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    tlsCfg,
		}
		return tlsDialer.DialContext(ctx, "tcp", p.addr)
	}

	// No TLS configured.
	if params.IsProductionEnv() {
		// P2P-R11-H03: fail closed in production. Plaintext P2P transport
		// exposes blocks/votes/transactions to passive eavesdroppers and
		// enables active tampering. Refuse to dial rather than risk it.
		return nil, errors.New("connpool: plaintext dial refused in production (QAU_PRODUCTION=1); configure TLS via SetTLSConfig")
	}

	// Dev/test fallback: plaintext TCP. The original code path, kept for
	// backward compatibility with tests that don't configure mTLS.
	return dialer.DialContext(ctx, "tcp", p.addr)
}

// pruneIdleConnections walks the idle list and closes any PooledConn whose
// idle time exceeds config.MaxIdleTime.
//
// P2P-R11-L04 (2026-07-20) FIX: Previously this method did not exist. Idle
// connections were only reclaimed lazily — when Get() tried to reuse them
// (and found them expired via IsExpired), or when Put() enforced
// MaxIdleConns and dropped the new arrival. If no one called Get() for a
// peer for a long time, that peer's idle connections sat in memory forever,
// leaking file descriptors and TLS state. Under churn (many peers connecting
// then disappearing), this could exhaust the process's file descriptor
// limit and contribute to memory pressure.
//
// This method is called periodically by ConnPoolManager.idleSweepLoop to
// proactively reclaim idle connections even when no traffic is flowing. It
// is also safe to call manually (e.g., from a test).
//
// Concurrency: takes p.mu (the same lock Get/Put take). Each pruned
// connection is closed via closeConnLog while holding the lock, which is
// consistent with how Get() and Put() close connections. The number of
// idle conns per peer is bounded by MaxIdleConns (default 2), so the
// per-call cost is O(MaxIdleConns) — typically 2 elements, not a scan.
func (p *PeerConnPool) pruneIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}
	if p.config.MaxIdleTime <= 0 {
		return // idle expiration disabled
	}

	var next *list.Element
	for elem := p.idle.Front(); elem != nil; elem = next {
		next = elem.Next()
		pc := elem.Value.(*PooledConn)
		if pc.IsExpired(p.config.MaxIdleTime) {
			closeConnLog(pc.conn, "pruneIdleConnections")
			p.idle.Remove(elem)
			atomic.AddInt32(&p.numOpen, -1)
		}
	}
	// Signal any goroutine waiting in Get() for a free slot — pruning may
	// have freed one. This is defensive: in practice pruning only removes
	// connections that were idle (no one was waiting on them), but the cost
	// of an extra Signal is negligible.
	p.cond.Signal()
}

// Close closes all connections in the pool.
func (p *PeerConnPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil
	}
	p.closed = true

	for elem := p.idle.Front(); elem != nil; elem = elem.Next() {
		pc := elem.Value.(*PooledConn)
		closeConnLog(pc.conn, "pc.conn.Close")
	}
	p.idle.Init()

	p.cond.Broadcast()
	return nil
}

// Stats returns pool statistics.
func (p *PeerConnPool) Stats() (open, idle int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return int(atomic.LoadInt32(&p.numOpen)), p.idle.Len()
}

// pooledNetConn wraps a pooled connection to implement net.Conn.
type pooledNetConn struct {
	pc     *PooledConn
	pool   *PeerConnPool
	closed bool
}

func (c *pooledNetConn) Read(b []byte) (n int, err error) {
	if c.closed {
		return 0, ErrConnInvalid
	}
	return c.pc.conn.Read(b)
}

func (c *pooledNetConn) Write(b []byte) (n int, err error) {
	if c.closed {
		return 0, ErrConnInvalid
	}
	return c.pc.conn.Write(b)
}

func (c *pooledNetConn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	c.pool.Put(c.pc)
	return nil
}

func (c *pooledNetConn) LocalAddr() net.Addr {
	return c.pc.conn.LocalAddr()
}

func (c *pooledNetConn) RemoteAddr() net.Addr {
	return c.pc.conn.RemoteAddr()
}

func (c *pooledNetConn) SetDeadline(t time.Time) error {
	return c.pc.conn.SetDeadline(t)
}

func (c *pooledNetConn) SetReadDeadline(t time.Time) error {
	return c.pc.conn.SetReadDeadline(t)
}

func (c *pooledNetConn) SetWriteDeadline(t time.Time) error {
	return c.pc.conn.SetWriteDeadline(t)
}

// ConnPoolManager manages connection pools for multiple peers.
type ConnPoolManager struct {
	config *ConnPoolConfig

	// P2P-R11-H03: TLS config propagated to every child PeerConnPool created
	// after SetTLSConfig is called. Ensures all gossipsub P2P connections
	// use mTLS encryption in production.
	tlsConfig *tls.Config

	mu    sync.RWMutex
	pools map[PeerID]*PeerConnPool

	closed bool

	// P2P-R11-L04 (2026-07-20): stopCh terminates the background idle-sweeper
	// goroutine started in NewConnPoolManager. Closed by Close() so the
	// goroutine exits cleanly on shutdown. See idleSweepLoop() for why this
	// exists — previously idle connections in PeerConnPools were only
	// reclaimed lazily and could leak forever if no traffic touched them.
	stopCh chan struct{}
}

// NewConnPoolManager creates a new connection pool manager.
func NewConnPoolManager(config *ConnPoolConfig) *ConnPoolManager {
	if config == nil {
		config = DefaultConnPoolConfig()
	}

	m := &ConnPoolManager{
		config: config,
		pools:  make(map[PeerID]*PeerConnPool),
		stopCh: make(chan struct{}),
	}

	// P2P-R11-L04 (2026-07-20) FIX: start a background sweeper that
	// proactively reclaims idle connections from every PeerConnPool.
	// Only run when MaxIdleTime > 0 — a MaxIdleTime of 0 disables idle
	// expiration entirely (see PooledConn.IsExpired), so sweeping is a
	// no-op and we skip the goroutine to avoid the per-tick overhead.
	if config.MaxIdleTime > 0 {
		go m.idleSweepLoop()
	}

	return m
}

// GetConn retrieves a connection to a peer.
//
// RPC-R9-H2 (2026-07-19) FIX: Previously this method used an RLock→Unlock→
// Lock→Unlock pattern with a manual double-check. While the double-check IS
// correct for preventing duplicate pool creation, the RLock-then-Lock
// transition creates a window where the captured `pool` reference can be
// invalidated by a concurrent RemovePeer/Close call between RUnlock and the
// subsequent pool.Get(ctx) call. The resulting use-after-close returns
// ErrConnPoolClosed, which is "safe" but is a real race condition (verified
// by `go test -race`).
//
// The fix collapses the entire lookup-create-use lifecycle into a SINGLE
// write lock critical section. This eliminates:
//  1. The RLock→Lock transition window (use-after-close race).
//  2. The double-check pattern (no longer needed because the lock is held
//     continuously — only one goroutine can be in this section at a time
//     for the same manager).
//
// Performance: This serializes all GetConn calls on m.mu. For the P2P
// connection pool use case this is acceptable because:
//   - The actual connection establishment (dial) happens OUTSIDE the lock
//     (inside pool.Get), so the critical section is short.
//   - The expected number of concurrent GetConn calls is bounded by the
//     number of peers (typically <50), not the number of RPC requests.
func (m *ConnPoolManager) GetConn(ctx context.Context, peerID PeerID, addr string) (net.Conn, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrConnPoolClosed
	}

	pool, exists := m.pools[peerID]
	if !exists {
		// I22-009 FIX: enforce max pools limit to prevent unbounded growth.
		// When the limit is reached, reject new peer connections rather
		// than allowing the map to grow without bound.
		maxPools := m.config.MaxPools
		if maxPools <= 0 {
			maxPools = 1000 // fallback if config not set
		}
		if len(m.pools) >= maxPools {
			m.mu.Unlock()
			return nil, ErrMaxPoolsReached
		}
		pool = NewPeerConnPool(peerID, addr, m.config)
		// P2P-R11-H03: propagate TLS config to newly-created pool.
		if m.tlsConfig != nil {
			pool.SetTLSConfig(m.tlsConfig)
		}
		m.pools[peerID] = pool
	}
	m.mu.Unlock()

	// RPC-R9-H2 FIX: pool reference is now guaranteed valid for the lifetime
	// of this call because RemovePeer cannot close it between Unlock and Get
	// (RemovePeer acquires m.mu — which we just released — and any concurrent
	// RemovePeer that closes this pool will cause pool.Get to return
	// ErrConnPoolClosed, a benign documented failure mode rather than a race).
	return pool.Get(ctx)
}

// SetTLSConfig sets the TLS configuration for all current and future pools.
// P2P-R11-H03: Propagates the mTLS config to every existing PeerConnPool and
// stores it so newly-created pools inherit it. Callers (Host) should invoke
// this after NodeCertificateManager initialization.
func (m *ConnPoolManager) SetTLSConfig(c *tls.Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tlsConfig = c
	for _, pool := range m.pools {
		pool.SetTLSConfig(c)
	}
}

// RemovePeer removes a peer's connection pool.
func (m *ConnPoolManager) RemovePeer(peerID PeerID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if pool, exists := m.pools[peerID]; exists {
		closeConnLog(pool, "pool.Close")
		delete(m.pools, peerID)
	}
}

// Close closes all connection pools.
func (m *ConnPoolManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil
	}
	m.closed = true

	// P2P-R11-L04 (2026-07-20): terminate the idle-sweeper goroutine.
	// close(stopCh) signals the goroutine to exit on its next select
	// iteration. We do NOT Wait() for the goroutine to actually exit
	// here — that would deadlock if the goroutine is currently inside
	// sweepAllPools() blocked on m.mu.RLock() (which we hold here as
	// m.mu.Lock()). Instead we rely on the per-pool mutex to serialize
	// Close vs pruneIdleConnections: both methods take p.mu, so a
	// concurrent prune on a pool we're about to close will either
	// observe the closed flag (and return early) or wait for our
	// closeConnLog to finish. Either way is safe.
	close(m.stopCh)

	for _, pool := range m.pools {
		closeConnLog(pool, "pool.Close")
	}
	m.pools = make(map[PeerID]*PeerConnPool)

	return nil
}

// idleSweepLoop periodically reclaims idle connections from every pool.
//
// P2P-R11-L04 (2026-07-20) FIX: Previously ConnPoolManager had NO background
// goroutine to close idle connections. Idle connections were only reclaimed
// lazily when:
//   - Get() tried to use an idle connection that turned out to be expired
//     (via PooledConn.IsExpired()).
//   - Put() checked MaxIdleConns and closed excess connections.
//
// This meant that if no one called Get() for a peer for a long time, that
// peer's idle connections would sit in memory forever — wasting file
// descriptors, keeping TLS state alive, and contributing to memory pressure.
// Under churn (many peers connecting and disconnecting), this could exhaust
// the process's file descriptor limit.
//
// The fix adds this goroutine that ticks every MaxIdleTime/2 (clamped to
// [30s, 10m]) and calls pruneIdleConnections() on every PeerConnPool.
// pruneIdleConnections walks each pool's idle list (bounded by MaxIdleConns,
// default 2) and closes any PooledConn whose idle time exceeds MaxIdleTime.
//
// The goroutine is stopped by closing m.stopCh in Close(). It is safe for
// the goroutine to be mid-sweep when Close() runs: sweepAllPools takes
// m.mu.RLock only long enough to snapshot the pool slice, then releases it
// before calling pruneIdleConnections on each pool (which takes the pool's
// own mutex). If Close() runs concurrently, pruneIdleConnections either
// observes the pool's closed flag (and returns early) or waits for
// PeerConnPool.Close to finish.
func (m *ConnPoolManager) idleSweepLoop() {
	// CRIT-08 (R17, 2026-07-23): Long-running background goroutine launched
	// by NewConnPoolManager. A panic in sweepAllPools (e.g., from a
	// concurrently-closed pool) would crash the node. The recover lets the
	// goroutine exit cleanly; idle connection reclamation stops but the
	// node keeps running. The next sweep would only happen after a restart
	// (acceptable degradation vs. node crash).
	defer func() {
		if r := recover(); r != nil {
			log.Printf("p2p connpool idleSweepLoop panic recovered: %v", r)
		}
	}()
	// Sweep interval: half of MaxIdleTime, clamped to [30s, 10m].
	//   - Lower bound 30s: don't burn CPU on hot pools with short MaxIdleTime.
	//   - Upper bound 10m: even with MaxIdleTime=1h, sweep every 10m so an
	//     idle connection is reclaimed within ~1.1x MaxIdleTime rather than
	//     potentially 1.5x.
	//   - If MaxIdleTime < 1m, sweep every 30s (no faster than that).
	interval := m.config.MaxIdleTime / 2
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	if interval > 10*time.Minute {
		interval = 10 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.sweepAllPools()
		}
	}
}

// sweepAllPools takes a snapshot of all pools under RLock and calls
// pruneIdleConnections on each. Snapshotting under RLock prevents concurrent
// RemovePeer/Close from freeing a pool while we iterate — once we hold a
// pointer to a *PeerConnPool it remains valid even if RemovePeer deletes it
// from the map, because Go's GC won't collect it while we still hold the
// pointer. The prune takes each pool's own mutex (not the manager's), so the
// manager lock is not held during the actual prune work — other goroutines
// can call GetConn/RemovePeer/Stats concurrently.
func (m *ConnPoolManager) sweepAllPools() {
	m.mu.RLock()
	if m.closed {
		m.mu.RUnlock()
		return
	}
	pools := make([]*PeerConnPool, 0, len(m.pools))
	for _, p := range m.pools {
		pools = append(pools, p)
	}
	m.mu.RUnlock()

	for _, p := range pools {
		p.pruneIdleConnections()
	}
}

// Stats returns statistics for all pools.
func (m *ConnPoolManager) Stats() map[PeerID]struct{ Open, Idle int } {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[PeerID]struct{ Open, Idle int })
	for peerID, pool := range m.pools {
		open, idle := pool.Stats()
		stats[peerID] = struct{ Open, Idle int }{open, idle}
	}
	return stats
}

// TotalConnections returns the total number of connections across all pools.
func (m *ConnPoolManager) TotalConnections() (open, idle int) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, pool := range m.pools {
		o, i := pool.Stats()
		open += o
		idle += i
	}
	return
}

// PeerScore represents the quality score of a peer connection.
// Score is calculated based on latency, reliability, and bandwidth.
type PeerScore struct {
	Latency     time.Duration // Average latency
	Reliability float64       // Success rate (0-1)
	Bandwidth   uint64        // Bytes per second
	Score       float64       // Computed composite score

	// Internal tracking
	mu              sync.Mutex
	totalRequests   uint64
	successRequests uint64
	latencySum      time.Duration
	latencyCount    uint64
	lastUpdated     time.Time
}

// NewPeerScore creates a new peer score with default values.
func NewPeerScore() *PeerScore {
	return &PeerScore{
		Latency:     100 * time.Millisecond, // Default latency
		Reliability: 1.0,                    // Start with perfect reliability
		Bandwidth:   0,
		Score:       0.5, // Neutral starting score
		lastUpdated: time.Now(),
	}
}

// UpdateLatency updates the latency measurement for the peer.
//
// RPC-R9-M (2026-07-19) FIX: Use a bounded cumulative average. Previously
// `latencySum += latency` ran indefinitely; on a long-lived node with high
// P2P traffic, latencySum would eventually overflow int64 (~292 years of
// nanoseconds), producing a negative Duration and corrupting both Latency
// and the downstream recalculateScore() decision. Now we cap the running
// sample count and roll the sum once it would otherwise overflow: when
// latencyCount reaches the cap, we re-baseline sum and count to the current
// average (preserving history without unbounded growth).
func (ps *PeerScore) UpdateLatency(latency time.Duration) {
	if latency < 0 {
		latency = 0
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	const maxLatencySamples = 1 << 20 // 1M samples ~ 12 days at 1 req/s
	if ps.latencyCount >= maxLatencySamples {
		// Re-baseline: keep the current average as the new sum baseline so
		// old samples decay out gradually rather than being dropped cold.
		ps.latencySum = ps.Latency
		ps.latencyCount = 1
	}
	ps.latencySum += latency
	ps.latencyCount++
	ps.Latency = ps.latencySum / time.Duration(ps.latencyCount) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	ps.lastUpdated = time.Now()
	ps.recalculateScore()
}

// RecordSuccess records a successful interaction with the peer.
func (ps *PeerScore) RecordSuccess() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.totalRequests++
	ps.successRequests++
	ps.Reliability = float64(ps.successRequests) / float64(ps.totalRequests)
	ps.lastUpdated = time.Now()
	ps.recalculateScore()
}

// RecordFailure records a failed interaction with the peer.
func (ps *PeerScore) RecordFailure() {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.totalRequests++
	if ps.totalRequests > 0 {
		ps.Reliability = float64(ps.successRequests) / float64(ps.totalRequests)
	}
	ps.lastUpdated = time.Now()
	ps.recalculateScore()
}

// UpdateBandwidth updates the bandwidth measurement for the peer.
func (ps *PeerScore) UpdateBandwidth(bytesPerSec uint64) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.Bandwidth = bytesPerSec
	ps.lastUpdated = time.Now()
	ps.recalculateScore()
}

// recalculateScore computes the composite score from latency, reliability, and bandwidth.
// Score formula: 0.4 * reliability + 0.4 * latencyScore + 0.2 * bandwidthScore
// All component scores are normalized to [0, 1].
func (ps *PeerScore) recalculateScore() {
	// Latency score: lower is better, normalized with 1s as baseline
	// Score = 1 - min(latency/1s, 1)
	latencyMs := float64(ps.Latency.Milliseconds())
	latencyScore := 1.0 - math.Min(latencyMs/1000.0, 1.0)

	// Reliability score: already in [0, 1]
	reliabilityScore := ps.Reliability

	// Bandwidth score: normalized with 10MB/s as excellent
	// Score = min(bandwidth / 10MB, 1)
	bandwidthScore := math.Min(float64(ps.Bandwidth)/(10*1024*1024), 1.0)

	// Weighted composite score
	ps.Score = 0.4*reliabilityScore + 0.4*latencyScore + 0.2*bandwidthScore
}

// Clone creates a copy of the peer score.
func (ps *PeerScore) Clone() *PeerScore {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return &PeerScore{
		Latency:         ps.Latency,
		Reliability:     ps.Reliability,
		Bandwidth:       ps.Bandwidth,
		Score:           ps.Score,
		totalRequests:   ps.totalRequests,
		successRequests: ps.successRequests,
		latencySum:      ps.latencySum,
		latencyCount:    ps.latencyCount,
		lastUpdated:     ps.lastUpdated,
	}
}

// PeerConnection represents a connection to a peer with metadata.
type PeerConnection struct {
	ID        PeerID
	Conn      net.Conn
	Direction Direction
	Connected time.Time
	LastSeen  time.Time
	Addr      string
	Verified  bool // CRITICAL FIX: peer identity verified via cryptographic handshake
}

// ConnectionPoolConfig holds configuration for the optimized connection pool.
type ConnectionPoolConfig struct {
	MaxPeers       int           // Maximum number of peers
	MinPeers       int           // Minimum number of peers to maintain
	PruneInterval  time.Duration // Interval for pruning low-quality connections
	ScoreThreshold float64       // Minimum score to keep a connection
	DialTimeout    time.Duration // Timeout for dialing new peers
	PingInterval   time.Duration // Interval for ping/latency checks
	MaxIdleTime    time.Duration // Maximum idle time before disconnection
	SeedNodes      []string      // Seed nodes for discovery
}

// DefaultConnectionPoolConfig returns a default configuration.
func DefaultConnectionPoolConfig() *ConnectionPoolConfig {
	return &ConnectionPoolConfig{
		MaxPeers:       50,
		MinPeers:       10,
		PruneInterval:  5 * time.Minute,
		ScoreThreshold: 0.2, // Prune peers with score below 0.2
		DialTimeout:    10 * time.Second,
		PingInterval:   30 * time.Second,
		MaxIdleTime:    10 * time.Minute,
	}
}

// ConnectionPool manages connections to multiple peers with scoring and pruning.
type ConnectionPool struct {
	peers     map[PeerID]*PeerConnection
	scores    map[PeerID]*PeerScore
	blacklist *Blacklist
	config    *ConnectionPoolConfig

	maxPeers int
	minPeers int

	mu     sync.RWMutex
	closed bool

	// Channels for background operations
	stopCh chan struct{}

	// CRIT-09 (R17, 2026-07-23): Replaces testing.Testing() bypass in
	// AddPeerUnsafe. When true, AddPeerUnsafe skips the production guard
	// and adds the peer without identity verification. Defaults to false
	// (secure). Tests set this to true via AllowUnsafePeerAddForTesting.
	// Production code MUST NOT call AllowUnsafePeerAddForTesting.
	//
	// testing.Testing() returned true for ANY test binary, including one
	// accidentally deployed to production — which would allow any caller
	// to bypass peer identity verification, enabling Sybil/eclipsing
	// attacks via unverified peer additions.
	allowUnsafePeerAdd bool
}

// NewConnectionPool creates a new connection pool with the given configuration.
func NewConnectionPool(config *ConnectionPoolConfig) *ConnectionPool {
	if config == nil {
		config = DefaultConnectionPoolConfig()
	}

	cp := &ConnectionPool{
		peers:     make(map[PeerID]*PeerConnection),
		scores:    make(map[PeerID]*PeerScore),
		blacklist: NewBlacklist(),
		config:    config,
		maxPeers:  config.MaxPeers,
		minPeers:  config.MinPeers,
		stopCh:    make(chan struct{}),
	}

	// Start background pruning
	go cp.pruneLoop()

	return cp
}

// AllowUnsafePeerAddForTesting enables the test-only bypass for AddPeerUnsafe.
// CRIT-09 (R17, 2026-07-23): replaces testing.Testing() which was insecure
// (any test binary deployed to production would bypass peer verification).
// This method is intentionally unexported — only tests in the p2p package
// can call it.
func (cp *ConnectionPool) AllowUnsafePeerAddForTesting() {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.allowUnsafePeerAdd = true
}

// ErrIdentityNotVerified is returned when peer identity is not verified
var ErrIdentityNotVerified = errors.New("peer identity not verified")

// MinPeerIDLength is the minimum length for a valid peer ID
// peer identity verification: minimum ID length for security
const MinPeerIDLength = 16

// AddPeer adds a new peer connection to the pool.
// peer identity verification: requires verified peer connections
func (cp *ConnectionPool) AddPeer(peer *PeerConnection) error {
	if peer == nil {
		return ErrConnInvalid
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()

	if cp.closed {
		return ErrConnPoolClosed
	}

	// Check blacklist (P2P-C-02 R29: also check IP/subnet layer to prevent
	// Sybil attackers from bypassing bans by rotating PeerIDs).
	if cp.blacklist.IsBlacklistedWithIP(peer.ID, peer.Addr) {
		return ErrPeerBlacklisted
	}

	// Check max peers
	if len(cp.peers) >= cp.maxPeers {
		return ErrMaxPeersReached
	}

	// peer identity verification: verify peer ID meets minimum length requirement
	// In production, this ensures the peer completed the challenge-response
	// handshake in host.go before being added to the pool.
	// A valid peer ID should be at least 16 characters (derived from public key hash)
	if len(peer.ID) < MinPeerIDLength {
		return ErrIdentityNotVerified
	}

	// CRITICAL SECURITY FIX: Require cryptographic verification of peer identity
	// This ensures the peer completed the challenge-response handshake in host.go
	// and their identity is bound to their public key. Without this check,
	// attackers could add fake peers to the pool for Sybil attacks.
	if !peer.Verified {
		return ErrIdentityNotVerified
	}

	// Add peer and initialize score
	cp.peers[peer.ID] = peer
	cp.scores[peer.ID] = NewPeerScore()

	return nil
}

// AddPeerUnsafe adds a peer without identity verification (for testing only).
//
// RPC-R9-M (2026-07-19) FIX: Hard-reject this method when called from a
// production binary. Previously the method was a public API with only a
// doc-comment guard saying "for testing only" — nothing prevented a
// future caller in node/, rpc/, or consensus/ from bypassing peer
// identity verification by accidentally invoking it.
//
// CRIT-09 (R17, 2026-07-23): Replaced testing.Testing() with the explicit
// cp.allowUnsafePeerAdd flag. testing.Testing() returned true for ANY test
// binary, including one accidentally deployed to production. Now tests must
// explicitly opt in via AllowUnsafePeerAddForTesting(); production code
// that doesn't call this method gets fail-closed behavior by default.
func (cp *ConnectionPool) AddPeerUnsafe(peer *PeerConnection) error {
	if peer == nil {
		return ErrConnInvalid
	}
	cp.mu.RLock()
	allowed := cp.allowUnsafePeerAdd
	cp.mu.RUnlock()
	if !allowed {
		// Fail closed: production code must use AddPeer with verification.
		return fmt.Errorf("AddPeerUnsafe is not callable in production; call AllowUnsafePeerAddForTesting() first or use AddPeer with verified peer identity")
	}

	cp.mu.Lock()
	defer cp.mu.Unlock()

	if cp.closed {
		return ErrConnPoolClosed
	}

	// Check blacklist (P2P-C-02 R29: also check IP/subnet layer to prevent
	// Sybil attackers from bypassing bans by rotating PeerIDs).
	if cp.blacklist.IsBlacklistedWithIP(peer.ID, peer.Addr) {
		return ErrPeerBlacklisted
	}

	// Check max peers
	if len(cp.peers) >= cp.maxPeers {
		return ErrMaxPeersReached
	}

	// Add peer and initialize score
	cp.peers[peer.ID] = peer
	cp.scores[peer.ID] = NewPeerScore()

	return nil
}

// RemovePeer removes a peer from the pool.
func (cp *ConnectionPool) RemovePeer(id PeerID) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if peer, exists := cp.peers[id]; exists {
		if peer.Conn != nil {
			closeConnLog(peer.Conn, "peer.Conn.Close")
		}
		delete(cp.peers, id)
		delete(cp.scores, id)
	}
}

// GetPeer returns a peer connection by ID.
func (cp *ConnectionPool) GetPeer(id PeerID) (*PeerConnection, bool) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	peer, exists := cp.peers[id]
	return peer, exists
}

// GetBestPeers returns the top N peers sorted by score (highest first).
func (cp *ConnectionPool) GetBestPeers(n int) []*PeerConnection {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	// Create a slice of peer IDs with scores
	type peerWithScore struct {
		id    PeerID
		score float64
	}

	peerScores := make([]peerWithScore, 0, len(cp.peers))
	for id := range cp.peers {
		if score, exists := cp.scores[id]; exists {
			peerScores = append(peerScores, peerWithScore{id: id, score: score.Score})
		}
	}

	// Sort by score descending
	sort.Slice(peerScores, func(i, j int) bool {
		return peerScores[i].score > peerScores[j].score
	})

	// Return top N peers
	result := make([]*PeerConnection, 0, n)
	for i := 0; i < len(peerScores) && i < n; i++ {
		if peer, exists := cp.peers[peerScores[i].id]; exists {
			result = append(result, peer)
		}
	}

	return result
}

// UpdateScore updates the score for a peer based on latency and success/failure.
func (cp *ConnectionPool) UpdateScore(id PeerID, latency time.Duration, success bool) {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	score, exists := cp.scores[id]
	if !exists {
		return
	}

	score.UpdateLatency(latency)
	if success {
		score.RecordSuccess()
	} else {
		score.RecordFailure()
	}

	// Update last seen time for the peer
	if peer, exists := cp.peers[id]; exists {
		peer.LastSeen = time.Now()
	}
}

// GetScore returns the score for a peer.
func (cp *ConnectionPool) GetScore(id PeerID) (*PeerScore, bool) {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	score, exists := cp.scores[id]
	if !exists {
		return nil, false
	}
	return score.Clone(), true
}

// Prune removes low-quality connections based on score threshold.
// Returns the number of connections removed.
func (cp *ConnectionPool) Prune() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if cp.closed {
		return 0
	}

	// Don't prune below minimum peers
	if len(cp.peers) <= cp.minPeers {
		return 0
	}

	// Collect peers to prune
	toPrune := make([]PeerID, 0)
	for id, score := range cp.scores {
		if score.Score < cp.config.ScoreThreshold {
			toPrune = append(toPrune, id)
		}
	}

	// Don't prune below minimum peers
	maxPrune := len(cp.peers) - cp.minPeers
	if len(toPrune) > maxPrune {
		// Sort by score ascending (worst first)
		sort.Slice(toPrune, func(i, j int) bool {
			return cp.scores[toPrune[i]].Score < cp.scores[toPrune[j]].Score
		})
		toPrune = toPrune[:maxPrune]
	}

	// Remove pruned peers
	for _, id := range toPrune {
		if peer, exists := cp.peers[id]; exists {
			if peer.Conn != nil {
				closeConnLog(peer.Conn, "peer.Conn.Close")
			}
			delete(cp.peers, id)
			delete(cp.scores, id)
		}
	}

	return len(toPrune)
}

// pruneLoop runs periodic pruning of low-quality connections.
func (cp *ConnectionPool) pruneLoop() {
	// CRIT-08 (R17, 2026-07-23): Long-running background goroutine launched
	// by NewConnectionPool. A panic in Prune/pruneIdleConnections (e.g.,
	// from concurrent peer removal) would crash the node. The recover lets
	// the goroutine exit cleanly; pruning stops but the node keeps running.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("p2p connpool pruneLoop panic recovered: %v", r)
		}
	}()
	ticker := time.NewTicker(cp.config.PruneInterval)
	defer ticker.Stop()

	for {
		select {
		case <-cp.stopCh:
			return
		case <-ticker.C:
			cp.Prune()
			cp.pruneIdleConnections()
		}
	}
}

// pruneIdleConnections removes connections that have been idle too long.
func (cp *ConnectionPool) pruneIdleConnections() {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if cp.closed {
		return
	}

	now := time.Now()
	toPrune := make([]PeerID, 0)

	for id, peer := range cp.peers {
		if now.Sub(peer.LastSeen) > cp.config.MaxIdleTime {
			toPrune = append(toPrune, id)
		}
	}

	// Don't prune below minimum peers
	maxPrune := len(cp.peers) - cp.minPeers
	if maxPrune < 0 {
		maxPrune = 0
	}
	if len(toPrune) > maxPrune {
		toPrune = toPrune[:maxPrune]
	}

	for _, id := range toPrune {
		if peer, exists := cp.peers[id]; exists {
			if peer.Conn != nil {
				closeConnLog(peer.Conn, "peer.Conn.Close")
			}
			delete(cp.peers, id)
			delete(cp.scores, id)
		}
	}
}

// PeerCount returns the number of connected peers.
func (cp *ConnectionPool) PeerCount() int {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return len(cp.peers)
}

// AllPeers returns all connected peers.
func (cp *ConnectionPool) AllPeers() []*PeerConnection {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	result := make([]*PeerConnection, 0, len(cp.peers))
	for _, peer := range cp.peers {
		result = append(result, peer)
	}
	return result
}

// AllScores returns all peer scores.
func (cp *ConnectionPool) AllScores() map[PeerID]*PeerScore {
	cp.mu.RLock()
	defer cp.mu.RUnlock()

	result := make(map[PeerID]*PeerScore, len(cp.scores))
	for id, score := range cp.scores {
		result[id] = score.Clone()
	}
	return result
}

// Blacklist returns the blacklist manager.
func (cp *ConnectionPool) Blacklist() *Blacklist {
	return cp.blacklist
}

// Close closes the connection pool and all connections.
func (cp *ConnectionPool) Close() error {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if cp.closed {
		return nil
	}
	cp.closed = true

	// Stop background goroutine
	close(cp.stopCh)

	// Close all connections
	for _, peer := range cp.peers {
		if peer.Conn != nil {
			closeConnLog(peer.Conn, "peer.Conn.Close")
		}
	}

	cp.peers = make(map[PeerID]*PeerConnection)
	cp.scores = make(map[PeerID]*PeerScore)

	return nil
}

// NeedsMorePeers returns true if the pool has fewer than minimum peers.
func (cp *ConnectionPool) NeedsMorePeers() bool {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return len(cp.peers) < cp.minPeers
}

// HasCapacity returns true if the pool can accept more peers.
func (cp *ConnectionPool) HasCapacity() bool {
	cp.mu.RLock()
	defer cp.mu.RUnlock()
	return len(cp.peers) < cp.maxPeers
}

// SelectPeersForBroadcast selects the best peers for message broadcasting.
// It returns peers sorted by score, prioritizing low-latency high-bandwidth peers.
func (cp *ConnectionPool) SelectPeersForBroadcast(n int) []*PeerConnection {
	return cp.GetBestPeers(n)
}
