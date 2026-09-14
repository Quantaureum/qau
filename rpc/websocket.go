// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"bufio"
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha1" // #nosec G505
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quantaureum/qau/metrics"
)

// WebSocket constants
const (
	wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

	// MaxWSMessageSize is the maximum allowed WebSocket message size (10MB).
	// Prevents OOM from malicious clients sending oversized frame headers.
	//
	// P2P-R11-M01 (2026-07-20): This constant IS the project's equivalent of
	// gorilla/websocket's `Conn.SetReadLimit(10MB)`. The audit recommendation
	// to "call ws.SetReadLimit(maxMessageSize=10MB)" was based on the
	// assumption that the project uses gorilla/websocket; it does not. The
	// project implements its own RFC 6455 frame parser, and the manual
	// `payloadLen > MaxWSMessageSize` checks in readMessage (lines 735, 740,
	// 818, 830) reject any frame whose declared length exceeds 10MB BEFORE
	// allocating memory for its payload — exactly the same defense
	// gorilla/websocket's SetReadLimit provides. There is no separate
	// `SetReadLimit` API to call because there is no gorilla Conn to call
	// it on. Defense-in-depth: the per-connection frame rate limiter
	// (`wsFramesPerSec=50`, `wsMaxBurst=100`) further caps the rate at which
	// a single connection can drive memory allocation, and the read deadline
	// (`pingInterval*2`) closes any connection that stops making progress.
	MaxWSMessageSize = 10 * 1024 * 1024

	// MaxWSBatchSize is the maximum number of requests in a single WebSocket batch.
	MaxWSBatchSize = 100

	// AUDIT (2026) R4-API-01: Write timeout for WebSocket broadcast
	// messages. Without this, a slow/stopped reader blocks the single
	// broadcast goroutine (head-of-line blocking), preventing ALL other
	// subscribers from receiving events. 10s is generous for a small JSON
	// notification; if a subscriber can't receive it in 10s, they are
	// effectively a DoS vector and should be dropped.
	WSWriteTimeout = 10 * time.Second

	// audit-fix R2-L1: MaxSubscriptionsPerConn prevents a single client from
	// exhausting server memory with unlimited subscriptions.
	// audit-fix H-2: Reduced to 10 to prevent per-connection resource exhaustion
	MaxSubscriptionsPerConn = 10

	// M-NEW-2 FIX: Maximum concurrent WebSocket connections to prevent
	// resource exhaustion attacks (file descriptor exhaustion, memory pressure).
	// audit-fix H-2: Increased from 1000 to 10000 for production deployments
	MaxWSConnections = 10000

	// R50-RP-01 FIX: Per-IP WebSocket connection limit to prevent a single
	// attacker from exhausting all global connection slots. Without this, one
	// attacker IP can open 10000 connections and block all legitimate users.
	MaxWSConnectionsPerIP = 100

	// audit-fix H-2: Per-subscription memory limit to prevent DoS via large filters
	MaxBytesPerSubscription = 1024 * 1024 // 1MB per subscription

	// audit-fix H-2: Per-connection memory limit to bound total memory per client
	MaxBytesPerConn = 100 * 1024 * 1024 // 100MB per connection

	// R30-IMPLEMENT (2026-07-27): Global subscription cap to prevent total
	// subscription exhaustion across all connections. Without this, an
	// attacker could open MaxWSConnections (10000) connections and create
	// MaxSubscriptionsPerConn (10) subscriptions on each, totaling 100K
	// subscriptions. Each subscription may carry a 1MB filter
	// (MaxBytesPerSubscription), so 100K subscriptions ≈ 100GB of filter
	// memory, plus O(N) work on every broadcast. The global cap matches
	// the theoretical max (MaxWSConnections * MaxSubscriptionsPerConn =
	// 100000) so legitimate deployments are unaffected; only the all-
	// connections-attack is bounded. Tracked by RPC-R15-H04.
	MaxWSGlobalSubscriptions = 100000
)

// Subscription types
const (
	SubTypeNewHeads = "newHeads"
	SubTypeLogs     = "logs"
	SubTypePending  = "newPendingTransactions"
)

// R14-LOW (P2P-LOW-02): Minimum interval between drop-warning log emissions.
// The dropped-event counter is incremented on every drop; this throttle only
// governs the log line so a slow subscriber cannot flood the journal.
const wsDropLogInterval = 10 * time.Second

// R14-LOW (P2P-LOW-08): Default per-connection WebSocket frame rate limits.
// Promoted from function-local consts inside readLoop so they are tunable
// via the WebSocketServer struct fields. A well-behaved client (≤1 req/s)
// is never affected; only abnormally high senders are throttled.
const (
	wsDefaultFramesPerSec = 50
	wsDefaultMaxBurst     = 100

	// R30-IMPLEMENT (2026-07-27): Default global frame rate limits, applied
	// across ALL WebSocket connections aggregate. With MaxWSConnections=10000
	// and per-conn burst=100, a distributed tiny-frame flood could otherwise
	// drive up to 1M frames in the first second. The global burst (1000) is
	// intentionally much lower than the per-conn aggregate (1M) so the global
	// limiter kicks in before per-conn limits under a distributed attack.
	// Tracked by RPC-R15-P3-6.
	wsDefaultGlobalFramesPerSec = 10000
	wsDefaultGlobalMaxBurst     = 1000
)

// R14-LOW (P2P-LOW-10): Default graceful shutdown timeout for the WS HTTP
// server. Nodes with many active WS subscribers on slow links may need to
// extend this via the WebSocketServer.shutdownTimeout field.
const wsDefaultShutdownTimeout = 5 * time.Second

// AUDIT-FULL H-6 (2026-08-14): per-connection outbound queue depth. Each
// WSConn gets a buffered sendCh drained by a dedicated writer goroutine, so
// a slow subscriber can only stall its own queue — when the queue is full
// further events are dropped FOR THAT SUBSCRIBER ONLY (with metric+log),
// instead of blocking the single broadcast goroutine for up to
// WSWriteTimeout and stalling every other subscriber (head-of-line
// blocking). 128 slots bounds queued memory to well under 1MB per
// connection for typical JSON notifications, and a stalled connection is
// closed by the ping/pong liveness checks within ~2 ping intervals anyway.
const wsSendQueueSize = 128

// Subscription represents a WebSocket subscription
type Subscription struct {
	ID      string
	Type    string
	Filter  any
	Conn    *WSConn
	Created time.Time
}

// WSConn represents a WebSocket connection
type WSConn struct {
	conn   net.Conn
	reader *bufio.Reader
	// L9-016 FIX: preserve auth/forwarding headers from the HTTP upgrade request
	// so that WebSocket requests go through the same auth pipeline as HTTP.
	header http.Header
	mu     sync.Mutex
	// FIX: pongSem limits concurrent pong-response goroutines to 1
	// per connection. Without this, a client can flood the server with ping
	// frames, each spawning a new goroutine (each waiting up to 5s for the
	// write deadline), leading to goroutine exhaustion (DoS).
	pongSem chan struct{}
	// RPC-R9-M (2026-07-19) FIX: token-bucket frame rate limiter. Caps the
	// number of WebSocket frames a single connection can process per second,
	// preventing a tiny-frame flood from consuming server CPU. Zero value
	// (tokens=0, last=zero Time) is fine: the first call to allow() will
	// replenish tokens based on elapsed wall time.
	frameLimiter wsFrameLimiter
	// P2P-R11-M07 (2026-07-20): lastPongAt tracks the last time a pong
	// frame (opcode 10) was received from this client. The ping goroutine
	// uses it to detect "slow-loris" WebSocket clients that keep the TCP
	// connection alive by sending other frames (e.g. subscription
	// messages) but never respond to pings — a violation of RFC 6455
	// §5.5.3 which requires clients to send a pong frame "as soon as is
	// practical" after receiving a ping.
	//
	// Defense-in-depth on top of the read deadline (pingInterval*2):
	// the read deadline resets on ANY frame, so without explicit pong
	// tracking a client could ignore pings and stay alive by sending
	// a 1-byte frame every 30s. With lastPongAt, the ping goroutine
	// can close connections whose last pong is older than
	// 2*pingInterval (a full ping cycle of slack).
	//
	// Accessed atomically: read loop writes (Store), ping goroutine
	// reads (Load). No mutex needed — time.Time is a struct with a
	// single uint64 field (wall clock) under the hood on 64-bit
	// platforms, and atomic.LoadInt64/StoreInt64 are used via
	// atomic.Value to avoid torn reads on 32-bit platforms.
	lastPongAt atomic.Value // time.Time

	// AUDIT-FULL H-6 (2026-08-14): outbound queue drained by a dedicated
	// per-connection writer goroutine (started in handleConnection).
	// broadcastToSubscribers enqueues with a non-blocking send: a slow
	// subscriber fills its own queue and subsequent events are dropped
	// for it only, instead of head-of-line blocking the shared broadcast
	// goroutine for up to WSWriteTimeout.
	sendCh chan []byte
}

// wsFrameLimiter is a per-connection token bucket. RPC-R9-M (2026-07-19).
//
// We deliberately keep this implementation lock-free: only the read loop
// of a single WSConn calls allow(), and that loop runs in a single
// goroutine per connection. A sync.Mutex here would needlessly serialize
// frame reads.
type wsFrameLimiter struct {
	tokens float64
	last   time.Time
}

// allow returns true if a frame can be processed now. rate is in tokens
// per second; burst is the maximum accumulated tokens (and thus the
// largest burst that can pass without throttling).
func (fl *wsFrameLimiter) allow(rate int, burst int) bool {
	now := time.Now()
	if rate <= 0 || burst <= 0 {
		// Caller disabled rate limiting — accept all frames.
		return true
	}
	if fl.last.IsZero() {
		// First frame on this connection: seed the bucket full so a
		// freshly-connected client with a backlog of subscriptions
		// doesn't get dropped.
		fl.tokens = float64(burst)
		fl.last = now
	} else {
		elapsed := now.Sub(fl.last).Seconds()
		fl.tokens += elapsed * float64(rate)
		if fl.tokens > float64(burst) {
			fl.tokens = float64(burst)
		}
		fl.last = now
	}
	if fl.tokens >= 1.0 {
		fl.tokens -= 1.0
		return true
	}
	return false
}

// R30-IMPLEMENT (2026-07-27): wsGlobalFrameLimiter is a thread-safe token
// bucket shared across ALL WebSocket connections. Tracked by RPC-R15-P3-6.
//
// Unlike the per-connection wsFrameLimiter (which is single-goroutine by
// design and therefore lock-free), the global limiter is called from every
// connection's read loop concurrently, so it MUST be concurrency-safe.
//
// The original spec called for an "atomic CAS loop", but the struct shape
// (tokens float64 + last atomic.Int64) cannot be made race-free with atomic
// operations alone — float64 is 64 bits and atomic.Int64 is another 64 bits,
// totaling 128 bits, which is not a single atomic word on most platforms.
// Updating `last` via CAS does not protect `tokens` from concurrent read-
// modify-write between the CAS success and the subsequent tokens update.
// We therefore use a sync.Mutex to serialize the read-modify-write on the
// (tokens, last) pair. The atomic.Int64 field is retained (per spec) so a
// future lock-free implementation (e.g. atomic.Pointer[wsGlobalLimiterState]
// with a 128-bit packed state) can read `last` without acquiring the Mutex.
//
// Zero-value is safe to use: mu zero-value is unlocked, tokens=0.0, last=0.
// The first call to allow() seeds tokens=burst and stores the current
// unix-nano timestamp in last.
type wsGlobalFrameLimiter struct {
	mu     sync.Mutex
	tokens float64
	last   atomic.Int64
}

// allow returns true if a frame can be processed now under the global
// budget. rate is in tokens per second; burst is the maximum accumulated
// tokens (and thus the largest burst that can pass without throttling).
//
// R30-IMPLEMENT (2026-07-27): matches the test contract in
// websocket_r15_p3_6_global_frame_test.go.
//
// Concurrency: protected by mu. Multiple read loops call this concurrently;
// the Mutex serializes the read-modify-write on tokens+last. Critical
// section is short (no I/O, no blocking), so contention stays low even
// under MaxWSConnections (10000) concurrent connections.
func (g *wsGlobalFrameLimiter) allow(rate int, burst int) bool {
	// Caller disabled rate limiting — accept all frames without touching
	// state. This keeps the disabled test (TestP3_6_..._DisabledWhenZero)
	// stateless: 1000 alternating rate=0/burst=0 calls leave tokens=0
	// and last=0, so a subsequent enabled call seeds the bucket afresh.
	if rate <= 0 || burst <= 0 {
		return true
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now().UnixNano()
	last := g.last.Load()
	if last == 0 {
		// First enabled call: seed the bucket full so a freshly-started
		// server with a backlog of connections doesn't immediately
		// throttle. Matches the per-conn wsFrameLimiter seeding behavior.
		g.tokens = float64(burst)
	} else {
		// elapsed seconds since last update (nanosecond precision).
		elapsed := float64(now-last) / 1e9
		g.tokens += elapsed * float64(rate)
		if g.tokens > float64(burst) {
			g.tokens = float64(burst)
		}
	}
	g.last.Store(now)

	if g.tokens >= 1.0 {
		g.tokens -= 1.0
		return true
	}
	return false
}

// WebSocketServer handles WebSocket connections
type WebSocketServer struct {
	rpcServer *Server

	// Subscriptions
	subscriptions map[string]*Subscription
	connSubs      map[*WSConn][]string
	mu            sync.RWMutex

	// M-NEW-2 FIX: track active connection count for limit enforcement
	connCount int32

	// R30-IMPLEMENT (2026-07-27): WaitGroup tracking for handleConnection
	// goroutines. http.Server.Shutdown only waits for non-hijacked requests;
	// WebSocket connections are hijacked (via http.Hijacker), so they are
	// NOT tracked by http.Server. Without explicit WaitGroup tracking,
	// Stop() returns while handleConnection goroutines are still blocked
	// on readMessage, leading to use-after-close on conn.conn. Tracked by
	// P2P-R15-H02.
	connWG sync.WaitGroup

	// R50-RP-01 FIX: Per-IP connection tracking to enforce MaxWSConnectionsPerIP.
	// Maps "ip:port" prefix -> active connection count.
	connCountPerIP   map[string]int32
	connCountPerIPMu sync.Mutex

	// FIX: Track total dropped events for observability
	droppedEvents atomic.Uint64
	// R14-LOW (P2P-LOW-02): Throttle drop-warning logs so a slow subscriber
	// cannot flood the systemd journal with thousands of identical lines/sec.
	// The atomic counter is incremented on EVERY drop; the log is emitted at
	// most once per wsDropLogInterval. Stored as unix nanoseconds for atomic
	// compare-and-swap.
	lastDropLogTime atomic.Int64

	// Event channels
	newHeadsCh chan any
	logsCh     chan any
	pendingCh  chan any

	// Configuration
	pingInterval   time.Duration
	allowedOrigins []string // SECURITY (audit P1-): empty = localhost-only (NOT allow all)
	// audit-fix R2-M5: when true, reject requests with missing Origin header
	// when allowedOrigins is configured. FIX: default true for security.
	rejectMissingOrigin bool

	// R14-LOW (P2P-LOW-08): per-connection frame rate limit. Previously
	// hardcoded as function-local consts inside readLoop; promoted to
	// struct fields so deployments can tune them (e.g. indexers that
	// legitimately send >50 frames/sec, or stricter limits under attack).
	// Set by NewWebSocketServer to wsDefaultFramesPerSec / wsDefaultMaxBurst.
	framesPerSec int
	maxBurst     int

	// R30-IMPLEMENT (2026-07-27): Global frame rate limit, applied across
	// ALL WebSocket connections aggregate. Tracked by RPC-R15-P3-6.
	// Per-conn limiter catches single-connection floods; global limiter
	// catches distributed floods (many connections each under the per-conn
	// limit but together overwhelming server CPU).
	// Set by NewWebSocketServer to wsDefaultGlobalFramesPerSec /
	// wsDefaultGlobalMaxBurst; tunable via SetGlobalFrameRateLimit.
	globalFrameLimiter wsGlobalFrameLimiter
	globalFramesPerSec int
	globalMaxBurst     int

	// R14-LOW (P2P-LOW-10): graceful shutdown timeout for the WS HTTP
	// server. Previously hardcoded as 5s inside Stop(); promoted to a
	// struct field so nodes with many active subscribers on slow links
	// can extend it. Set by NewWebSocketServer to wsDefaultShutdownTimeout.
	shutdownTimeout time.Duration

	// HTTP server for WebSocket listener
	httpServer *http.Server

	// RPC-H2 FIX (2026-07-19): WebSocket TLS support. When tlsConfig is
	// non-nil, Start() calls httpServer.ListenAndServeTLS with this config,
	// producing a `wss://` listener instead of plaintext `ws://`. Without
	// this, browsers cannot subscribe to event streams over the public
	// internet without a reverse proxy terminating TLS for them, and any
	// reverse-proxy-less deployment leaks subscription data (and the
	// X-API-Key header used for auth) in cleartext.
	//
	// Configure via SetTLSConfig() before calling Start(). The server does
	// NOT load certs from disk itself — callers supply a fully-initialized
	// *tls.Config (typically from tls.LoadX509KeyPair / tls.X509KeyPair +
	// tls.Config{Certificates: [...], MinVersion: tls.VersionTLS12}).
	// RPC-FIX: serializes Start/Stop/SetTLSConfig/SetShutdownTimeout
	// access to httpServer, tlsConfig, and shutdownTimeout. Without this,
	// the start-in-goroutine / stop-from-main test pattern triggers race
	// detector reports because these fields are assigned in Start and read
	// in Stop concurrently. We use a dedicated mutex (not ws.mu) to avoid
	// nesting against ws.mu which is already held inside handler paths.
	httpMu sync.Mutex

	// RPC-FIX: makes Stop idempotent so the "defer ws.Stop()" /
	// repeated-Stop test pattern does not race with a concurrent
	// Shutdown already in flight.
	stopOnce sync.Once

	tlsConfig *tls.Config

	// Context
	ctx    context.Context
	cancel context.CancelFunc
}

// getClientIPFromConn extracts the client IP from a net.Conn.
// R50-RP-01 FIX: Used for per-IP WebSocket connection limiting.
func getClientIPFromConn(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// NewWebSocketServer creates a new WebSocket server
func NewWebSocketServer(rpcServer *Server) *WebSocketServer {
	ctx, cancel := context.WithCancel(context.Background())

	ws := &WebSocketServer{
		rpcServer:           rpcServer,
		subscriptions:       make(map[string]*Subscription),
		connSubs:            make(map[*WSConn][]string),
		connCountPerIP:      make(map[string]int32), // R50-RP-01: per-IP connection tracking
		newHeadsCh:          make(chan any, 100),
		logsCh:              make(chan any, 1000),
		pendingCh:           make(chan any, 1000),
		pingInterval:        30 * time.Second,
		ctx:                 ctx,
		cancel:              cancel,
		rejectMissingOrigin: true, //  default secure — reject missing Origin
		// R14-LOW (P2P-LOW-08): default frame rate limits; tunable via
		// SetFrameRateLimit for deployments that need different values.
		framesPerSec: wsDefaultFramesPerSec,
		maxBurst:     wsDefaultMaxBurst,
		// R30-IMPLEMENT (2026-07-27): default global frame rate limits;
		// tunable via SetGlobalFrameRateLimit. globalFrameLimiter is a
		// zero-value wsGlobalFrameLimiter (mu unlocked, tokens=0, last=0)
		// — the first call to allow() seeds tokens=burst, so no explicit
		// init is needed.
		globalFramesPerSec: wsDefaultGlobalFramesPerSec,
		globalMaxBurst:     wsDefaultGlobalMaxBurst,
		// R14-LOW (P2P-LOW-10): default shutdown timeout; tunable via
		// SetShutdownTimeout for deployments with slow subscribers.
		shutdownTimeout: wsDefaultShutdownTimeout,
	}

	go ws.broadcastEvents()

	return ws
}

// SetAllowedOrigins configures which Origins are permitted for WebSocket upgrades.
// An empty list allows all origins (default, for backwards compatibility).
// Use ["*"] to explicitly allow all, or specific origins like ["https://example.com"].
func (ws *WebSocketServer) SetAllowedOrigins(origins []string) {
	ws.allowedOrigins = origins
}

// R14-LOW (P2P-LOW-08): SetFrameRateLimit configures the per-connection frame
// rate limit. framesPerSec is the sustained rate (tokens per second); maxBurst
// is the maximum burst size before the rate limit kicks in. A well-behaved
// client (≤1 req/s) is never affected; only abnormally high senders are
// throttled. Both values must be > 0; otherwise the defaults are kept.
func (ws *WebSocketServer) SetFrameRateLimit(framesPerSec, maxBurst int) {
	if framesPerSec <= 0 || maxBurst <= 0 {
		return
	}
	ws.framesPerSec = framesPerSec
	ws.maxBurst = maxBurst
}

// R30-IMPLEMENT (2026-07-27): SetGlobalFrameRateLimit configures the aggregate
// frame rate limit across ALL WebSocket connections. Tracked by RPC-R15-P3-6.
//
// Mirrors SetFrameRateLimit's all-or-nothing semantics: if EITHER value is
// <= 0, BOTH are ignored (existing config preserved). This matches the test
// contract in websocket_r15_p3_6_global_frame_test.go, which expects
// `SetGlobalFrameRateLimit(0, 100)` to leave globalFramesPerSec unchanged
// AND `SetGlobalFrameRateLimit(100, 0)` to leave globalMaxBurst unchanged —
// only possible if a zero in either field rejects the whole call.
//
// Note: changing the rate/burst does NOT reset globalFrameLimiter.tokens
// (the in-flight token bucket). A token bucket self-corrects on the next
// allow() call: tokens are clamped to the new burst ceiling, and the
// replenish rate uses the new rate. So no explicit reset is needed.
func (ws *WebSocketServer) SetGlobalFrameRateLimit(rate, burst int) {
	if rate <= 0 || burst <= 0 {
		return
	}
	ws.globalFramesPerSec = rate
	ws.globalMaxBurst = burst
}

// R14-LOW (P2P-LOW-10): SetShutdownTimeout configures the graceful shutdown
// timeout for the WS HTTP server. Nodes with many active WS subscribers on
// slow links may need to extend this beyond the 5s default so subscribers
// receive pending notifications before the server forces close. A value
// <= 0 keeps the default.
func (ws *WebSocketServer) SetShutdownTimeout(d time.Duration) {
	if d <= 0 {
		return
	}
	ws.httpMu.Lock()
	ws.shutdownTimeout = d
	ws.httpMu.Unlock()
}

// SetRejectMissingOrigin configures whether to reject requests with no Origin header
// when allowedOrigins is configured.
// audit-fix R2-M5: makes empty-Origin behavior explicit and configurable.
func (ws *WebSocketServer) SetRejectMissingOrigin(reject bool) {
	ws.rejectMissingOrigin = reject
}

// SetTLSConfig configures TLS for the WebSocket listener.
// RPC-H2 FIX (2026-07-19): when set, Start() uses ListenAndServeTLS,
// producing a secure wss:// listener. The supplied *tls.Config must already
// contain the certificate chain (e.g. via tls.LoadX509KeyPair) and SHOULD
// set MinVersion to tls.VersionTLS12 or higher; we enforce that here as a
// defense-in-depth guard against accidentially serving TLS 1.0/1.1.
//
// Callers that already terminate TLS at a reverse proxy (Caddy, nginx,
// Cloudflare) should NOT set this — the reverse proxy provides wss://
// and the upstream can stay plaintext on a loopback interface.
func (ws *WebSocketServer) SetTLSConfig(cfg *tls.Config) {
	if cfg == nil {
		ws.httpMu.Lock()
		ws.tlsConfig = nil
		ws.httpMu.Unlock()
		return
	}
	// R35-P1-08 FIX (2026-07-29): force TLS 1.3 to match the HTTP server
	// (server.go:709). TLS 1.3 removes legacy cipher negotiation entirely and
	// mandates AEAD + forward secrecy, eliminating the downgrade / weak-cipher
	// attack class that TLS 1.2 still permits. Previously this only forced
	// TLS 1.2, leaving CipherSuites/CurvePreferences unset so the WebSocket
	// listener could negotiate weak ciphers (CBC, 3DES) from Go's defaults.
	if cfg.MinVersion < tls.VersionTLS13 {
		cfg.MinVersion = tls.VersionTLS13
	}
	// R35-P1-08 FIX: apply AEAD-only cipher whitelist when caller hasn't
	// configured one. Identical to server.go:710-717. If the caller explicitly
	// set CipherSuites (regulated environment), we respect it.
	if len(cfg.CipherSuites) == 0 {
		cfg.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		}
	}
	// R35-P1-08 FIX: apply strong curve preferences when caller hasn't.
	// X25519 is constant-time by design; P-256 has constant-time impl in Go.
	if len(cfg.CurvePreferences) == 0 {
		cfg.CurvePreferences = []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		}
	}
	ws.httpMu.Lock()
	ws.tlsConfig = cfg.Clone()
	ws.httpMu.Unlock()
}

// HasTLS reports whether the WebSocket server will use TLS (wss://) when
// Start() is called. Useful for health-check endpoints and logs that need
// to indicate the actual scheme.
func (ws *WebSocketServer) HasTLS() bool {
	ws.httpMu.Lock()
	has := ws.tlsConfig != nil
	ws.httpMu.Unlock()
	return has
}

// checkOrigin validates the Origin header against the allowed list.
// audit-fix CRIT-WS: require explicit origin configuration - no longer allows all origins by default
// checkOrigin validates the WebSocket origin.
// SECURITY (audit P3-): This implementation must be kept consistent with the
// HTTP CORS check in setCORSHeaders() (rpc/server.go). Any origin-policy change
// must be applied to both transports to prevent a WebSocket-vs-HTTP policy split.
//
// P3-12: The localhost fallback below now shares the isLocalhostOrigin() helper
// used by setCORSHeaders(), so both transports agree on what counts as
// "localhost".
//
// FIX: The configured-origin matching is now consistent with
// setCORSHeaders() in server.go — both use exact, case-sensitive comparison of
// the full Origin string (origin == allowed). Previously the WebSocket path used
// case-insensitive matching (strings.EqualFold) and also matched by host
// (u.Host), which was more permissive than the HTTP CORS handler. The wildcard
// "*" is retained as it is a legitimate configuration for open access.
func (ws *WebSocketServer) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")

	// R14-MED (2026-07-21): Mirror the HTTP path's mainnet-default-origins
	// fallback so WebSocket and HTTP enforce the SAME origin policy. Without
	// this, a browser wallet at https://lzadmin.quantaureum.com could pass
	// HTTP CORS preflight but fail the WebSocket origin check (or vice
	// versa), producing confusing "connection failed" errors in production.
	// The shared mainnetDefaultOrigins list lives in server.go and is the
	// single source of truth for which subdomains are official.
	origins := ws.allowedOrigins
	if ws.rpcServer != nil && ws.rpcServer.network == "mainnet" {
		hasWildcard := false
		for _, o := range origins {
			if o == "*" {
				hasWildcard = true
				break
			}
		}
		if len(origins) == 0 || hasWildcard {
			origins = mainnetDefaultOrigins
		}
	}

	// SECURITY (audit P1-, CRIT-WS): if no origins configured, only allow localhost.
	// Previous comment incorrectly said "empty = allow all" — the actual behavior
	// has been localhost-only since the CRIT-WS fix. This comment correction ensures
	// future auditors and developers understand the security posture.
	if len(origins) == 0 {
		log.Printf("[WARN] WebSocket: allowedOrigins not configured, restricting to localhost only")
		// Only allow if request is from localhost
		// R7-C4 FIX: 0.0.0.0 is a bind address, not a loopback origin, and
		// must not be treated as localhost for origin checks.
		host := r.Host
		// FIX: Use net.SplitHostPort for robust Host header parsing.
		// Previous strings.HasPrefix approach had edge cases:
		// - "localhost" without port was rejected (no colon to match "localhost:")
		// - Case-sensitive: "LOCALHOST:8080" was rejected
		// - "[::1]:8080" required a separate prefix check
		// SplitHostPort correctly handles all these cases including IPv6 brackets.
		hostname, _, splitErr := net.SplitHostPort(host)
		if splitErr != nil {
			// No port — the entire string is the hostname
			hostname = host
		}
		hostname = strings.ToLower(hostname)
		isLocalhost := hostname == "localhost" ||
			hostname == "127.0.0.1" ||
			hostname == "::1"
		if isLocalhost {
			return true
		}
		// Also check Origin header for localhost. P3-12: reuse the shared
		// isLocalhostOrigin() helper so the localhost definition is identical to
		// setCORSHeaders() in server.go (uses Hostname() to strip any port).
		if origin != "" && isLocalhostOrigin(origin) {
			return true
		}
		return false // reject non-localhost when no origins configured
	}

	if origin == "" {
		// audit-fix R2-M5: configurable behavior for missing Origin
		return !ws.rejectMissingOrigin
	}
	for _, allowed := range origins {
		if allowed == "*" {
			return true
		}
		// FIX: use exact case-sensitive match, consistent with
		// setCORSHeaders() in server.go (which uses `o == origin`).
		// P3-N2 VERIFIED RESOLVED: The earlier Host-vs-Origin confusion is
		// fully fixed — origin matching now uses exact string equality
		// (`origin == allowed`), NOT strings.EqualFold and NOT a u.Host
		// comparison. The localhost fallback above correctly keys off r.Host
		// (the actual request host) only when no origins are configured. No
		// further change needed; this comment documents the resolution.
		if origin == allowed {
			return true
		}
	}
	return false
}

// ServeHTTP implements http.Handler for WebSocket upgrade
func (ws *WebSocketServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check for WebSocket upgrade
	if r.Header.Get("Upgrade") != "websocket" {
		http.Error(w, "Expected WebSocket upgrade", http.StatusBadRequest)
		return
	}

	// Validate Origin header to prevent cross-site WebSocket hijacking
	if !ws.checkOrigin(r) {
		http.Error(w, "Origin not allowed", http.StatusForbidden)
		return
	}

	// Get WebSocket key
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "Missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}

	// Calculate accept key per RFC 6455 Section 4.2.2.
	// NOTE (L-3): SHA-1 is used here per the WebSocket specification.
	// This is NOT a security vulnerability — the accept key is a protocol
	// handshake value, not a cryptographic secret. SHA-1's collision
	// weakness is irrelevant here because both inputs (client key + GUID)
	// are known/fixed and the output is not used for trust decisions.
	h := sha1.New() // #nosec G401 G505 -- SHA-1 required by RFC 6455 Section 4.2.2
	h.Write([]byte(key + wsGUID))
	acceptKey := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Hijack connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported", http.StatusInternalServerError)
		return
	}

	conn, bufrw, err := hijacker.Hijack()
	if err != nil {
		// audit-fix HIGH: Never echo the raw hijack error back to the client —
		// it may contain internal details (file descriptors, syscall names,
		// network stack internals) that aid an attacker. Log the real error
		// server-side and return a generic message.
		log.Printf("[WebSocket] Hijack failed: %v", err)
		http.Error(w, "WebSocket upgrade failed", http.StatusInternalServerError)
		return
	}

	// Send upgrade response - errors are handled by closing connection on failure
	var writeErr error
	if _, writeErr = bufrw.WriteString("HTTP/1.1 101 Switching Protocols\r\n"); writeErr != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on write failure //nolint:errcheck
		return
	}
	if _, writeErr = bufrw.WriteString("Upgrade: websocket\r\n"); writeErr != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on write failure //nolint:errcheck
		return
	}
	if _, writeErr = bufrw.WriteString("Connection: Upgrade\r\n"); writeErr != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on write failure //nolint:errcheck
		return
	}
	if _, writeErr = bufrw.WriteString("Sec-WebSocket-Accept: " + acceptKey + "\r\n"); writeErr != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on write failure //nolint:errcheck
		return
	}
	// FIX: add security headers to the WebSocket handshake response,
	// consistent with the HTTP RPC server's setSecurityHeaders() in server.go.
	// X-Content-Type-Options prevents MIME sniffing; X-Frame-Options prevents
	// clickjacking. These are defense-in-depth on the HTTP-level handshake.
	//
	// P2P-R10-M1 (2026-07-19) FIX: Added Content-Security-Policy, Referrer-Policy,
	// and Permissions-Policy headers to match the HTTP RPC server's modern
	// security header set (see server.go setSecurityHeaders).
	if _, writeErr = bufrw.WriteString("X-Content-Type-Options: nosniff\r\n"); writeErr != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on write failure //nolint:errcheck
		return
	}
	if _, writeErr = bufrw.WriteString("X-Frame-Options: DENY\r\n"); writeErr != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on write failure //nolint:errcheck
		return
	}
	if _, writeErr = bufrw.WriteString("Content-Security-Policy: default-src 'none'\r\n"); writeErr != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on write failure //nolint:errcheck
		return
	}
	if _, writeErr = bufrw.WriteString("Referrer-Policy: no-referrer\r\n"); writeErr != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on write failure //nolint:errcheck
		return
	}
	if _, writeErr = bufrw.WriteString("Permissions-Policy: geolocation=(), microphone=(), camera=()\r\n"); writeErr != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on write failure //nolint:errcheck
		return
	}
	if _, writeErr = bufrw.WriteString("\r\n"); writeErr != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on write failure //nolint:errcheck
		return
	}
	if writeErr = bufrw.Flush(); writeErr != nil {
		conn.Close() // #nosec G104 -- best-effort cleanup on write failure //nolint:errcheck
		return
	}

	// Create WebSocket connection
	wsConn := &WSConn{
		conn:   conn,
		reader: bufrw.Reader,
		// L9-016 FIX: clone headers from the upgrade request so auth/rate-limit
		// checks on the WS transport can read API keys and forwarding headers.
		header:  r.Header.Clone(),
		pongSem: make(chan struct{}, 1), //  limit 1 concurrent pong goroutine
		// AUDIT-FULL H-6: per-connection outbound queue (see comment on field).
		sendCh: make(chan []byte, wsSendQueueSize),
	}
	// P2P-R11-M07 (2026-07-20): Initialize lastPongAt to connection start
	// time so the first ping cycle doesn't immediately close a freshly-
	// connected client that hasn't yet had a chance to receive a ping
	// and respond with a pong.
	wsConn.lastPongAt.Store(time.Now())

	// R30-IMPLEMENT (2026-07-27): Track handleConnection goroutine in
	// connWG so Stop() can wait for all connection handlers to exit
	// before returning. Without this, Stop() returns while
	// handleConnection goroutines are still blocked on readMessage,
	// accessing already-closed connections. The Add(1) MUST happen
	// BEFORE handleConnection starts so Stop() cannot miss an in-flight
	// handler. Tracked by P2P-R15-H02.
	ws.connWG.Add(1)
	defer ws.connWG.Done()
	ws.handleConnection(wsConn)
}

// handleConnection handles a WebSocket connection
func (ws *WebSocketServer) handleConnection(conn *WSConn) {
	// P2P-R10-H1 (2026-07-19) FIX: Top-level panic recovery. Although Go's
	// net/http server already has its own panic recovery for handler
	// functions, this WebSocket handler spawns long-lived goroutines (ping,
	// pong) and runs a long-running read loop — any panic in these would
	// propagate up through handleConnection. The defer is registered FIRST
	// so it runs LAST (after the cleanup defer below), ensuring peer state
	// is still cleaned up before the panic is swallowed. Without this, a
	// malicious WebSocket frame could crash the entire node.
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[WebSocket] handleConnection panic recovered for %s: %v",
				conn.conn.RemoteAddr(), r)
		}
	}()
	// R50-RP-01 FIX: Per-IP connection limit to prevent a single attacker
	// from exhausting all global connection slots.
	clientIP := getClientIPFromConn(conn.conn)
	ws.connCountPerIPMu.Lock()
	ipCount := ws.connCountPerIP[clientIP] + 1
	if ipCount > int32(MaxWSConnectionsPerIP) {
		ws.connCountPerIPMu.Unlock()
		log.Printf("[WebSocket] Connection rejected: per-IP limit %d reached for %s", MaxWSConnectionsPerIP, clientIP)
		conn.conn.Close() // #nosec G104 -- best-effort cleanup //nolint:errcheck
		return
	}
	ws.connCountPerIP[clientIP] = ipCount
	ws.connCountPerIPMu.Unlock()

	// L4-021 FIX: Atomically check and increment connection count BEFORE
	// registering the defer. Previously the defer (which decrements
	// connCount) was registered before the AddInt32 increment, creating a
	// TOCTOU race: if a panic occurred between defer registration and the
	// increment, the defer would decrement a counter that was never
	// incremented, driving connCount negative. Now the increment happens
	// first; if the limit is exceeded we manually undo it and return
	// without ever registering the defer.
	currentConns := atomic.AddInt32(&ws.connCount, 1)
	if currentConns > int32(MaxWSConnections) {
		atomic.AddInt32(&ws.connCount, -1)
		// R50-RP-01: Also undo per-IP count
		ws.connCountPerIPMu.Lock()
		ws.connCountPerIP[clientIP]--
		ws.connCountPerIPMu.Unlock()
		log.Printf("[WebSocket] Connection rejected: max connections %d reached", MaxWSConnections)
		conn.conn.Close() // #nosec G104 -- best-effort cleanup on disconnect //nolint:errcheck
		// R14-LOW (P2P-LOW-05): Reflect rejection in the gauge too — the
		// rejection decremented connCount back, so update metrics to match.
		metrics.Global().SetWSActiveConnections(int(atomic.LoadInt32(&ws.connCount)))
		return
	}
	// R14-LOW (P2P-LOW-05): Publish current connection count to metrics
	// so operators can alert on capacity exhaustion (climb toward MaxWSConnections)
	// or disconnect storms (sudden drop).
	metrics.Global().SetWSActiveConnections(int(currentConns))

	// M-NEW-2 FIX: Enforce maximum concurrent WebSocket connections.
	// Prevents resource exhaustion attacks (file descriptors, memory).
	defer func() {
		ws.cleanupConnection(conn)
		conn.conn.Close() // #nosec G104 -- best-effort cleanup on disconnect //nolint:errcheck
		// M-NEW-2 FIX: decrement connection counter on disconnect
		atomic.AddInt32(&ws.connCount, -1)
		// R14-LOW (P2P-LOW-05): Reflect disconnect in the gauge too.
		metrics.Global().SetWSActiveConnections(int(atomic.LoadInt32(&ws.connCount)))
		// R50-RP-01: decrement per-IP connection counter on disconnect
		ws.connCountPerIPMu.Lock()
		ws.connCountPerIP[clientIP]--
		if ws.connCountPerIP[clientIP] <= 0 {
			delete(ws.connCountPerIP, clientIP)
		}
		ws.connCountPerIPMu.Unlock()
	}()

	ws.mu.Lock()
	ws.connSubs[conn] = make([]string, 0)
	ws.mu.Unlock()

	// audit-fix MEDIUM: WebSocket heartbeat (ping/pong).
	// Without a heartbeat, stale/half-open connections persist indefinitely,
	// consuming file descriptors and subscription memory. We enforce liveness
	// by:
	//   1. Setting a read deadline that the client must beat by sending any
	//      frame (including pong responses to our pings).
	//   2. Sending periodic ping frames so well-behaved clients have an
	//      opportunity to reset the deadline.
	// The read deadline is set to pingInterval*2 so the client has a full
	// ping interval to respond before we give up and close the connection.
	//
	// RP-07: For a complete end-to-end trace of the ping/pong flow across
	// handleConnection, readMessage, and writeControlFrame, see the overview
	// comment on writeControlFrame (search "RP-07: Ping/Pong Control Flow").
	// RPC-R9-M (2026-07-19) FIX: Cap pingInterval before multiplying by 2.
	// pingInterval is an exported field that can be set externally; without
	// a cap, a caller-supplied value > MaxInt64/2 ns would wrap the
	// `* 2` to a negative Duration, which `<= 0` would catch but only
	// after the negative product overflowed into the int64 negative range.
	// A 1-hour ping interval is already extreme for any production setup,
	// and the resulting 2-hour read deadline is well below the int64 cap.
	pingInterval := ws.pingInterval
	const maxPingInterval = time.Hour
	if pingInterval <= 0 || pingInterval > maxPingInterval {
		pingInterval = 30 * time.Second
	}
	readDeadline := pingInterval * 2
	if readDeadline <= 0 {
		readDeadline = 60 * time.Second
	}
	_ = conn.conn.SetReadDeadline(time.Now().Add(readDeadline))

	// RPC-R9-M FIX: use the sanitized pingInterval here too — passing the
	// raw ws.pingInterval to time.NewTicker would panic if it were <= 0 or
	// extremely large (time.NewTicker requires 0 < d < math.MaxInt64).
	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()
	// audit-fix M-5: use a per-connection context so the ping goroutine
	// exits when this connection closes. Previously it waited on ws.ctx
	// (server-level), so it kept running after the connection was torn
	// down, leaking the goroutine for the lifetime of the WebSocket
	// server.
	connCtx, connCancel := context.WithCancel(ws.ctx)
	defer connCancel()

	// AUDIT-FULL H-6 (2026-08-14): dedicated writer goroutine per
	// connection. It drains conn.sendCh and performs the (potentially
	// slow, up to WSWriteTimeout) socket writes OFF the shared broadcast
	// goroutine, isolating slow subscribers from everyone else. On write
	// failure it closes the underlying TCP connection (same teardown
	// signal the ping goroutine uses) so the read loop's defer runs the
	// full cleanup path.
	go func() {
		// P2P-R10-H1: panic recovery, matching the ping goroutine.
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[WebSocket] writer goroutine panic recovered for %s: %v",
					conn.conn.RemoteAddr(), r)
				connCancel()
			}
		}()
		for {
			select {
			case <-connCtx.Done():
				return
			case msg := <-conn.sendCh:
				if err := ws.writeMessage(conn, msg); err != nil {
					log.Printf("[WebSocket] writer: write failed for %s: %v",
						conn.conn.RemoteAddr(), err)
					// Close (idempotent) so the read loop tears the
					// connection down via its deferred cleanup instead of
					// waiting for the read deadline.
					_ = conn.conn.Close()
					return
				}
			}
		}
	}()
	go func() {
		// P2P-R10-H1 (2026-07-19) FIX: panic recovery for ping goroutine.
		// A panic in writeControlFrame (e.g. due to a race on conn.conn)
		// would otherwise propagate up and crash the node. Cancel the
		// connection context on panic so the read loop tears down too.
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[WebSocket] ping goroutine panic recovered for %s: %v",
					conn.conn.RemoteAddr(), r)
				connCancel()
			}
		}()
		for {
			select {
			case <-pingTicker.C:
				// Send a ping frame. If the write fails the connection is
				// dead and the read loop will tear it down.
				//
				// P2P-R11-L03 (2026-07-20) NOTE: Normal ping/pong is
				// intentionally silent — no log line is emitted on a
				// successful ping write, and pong responses (handled in
				// readMessage at opcode 10) are also silent. Logging every
				// 30-second heartbeat for every connection would flood the
				// server log (with N connections and 30s ping interval,
				// that's N*2880 log lines per day per connection). Only
				// the failure paths below log, and only at the default
				// (INFO-equivalent) level. This was flagged by an audit
				// sub-agent report as "excessive logging" but the report
				// was a false positive based on code-path inspection
				// rather than runtime observation. The comment here is
				// added to document the design decision and prevent
				// future re-flagging.
				//
				// L16-028 NOTE: On ping write failure, this goroutine exits without notifying
				// the main read loop. The main loop will eventually detect the dead connection
				// via read deadline timeout, but there is a delay. A future improvement could
				// close the connection or signal the main loop immediately via a channel.
				if err := ws.writeControlFrame(conn, 0x9, nil); err != nil {
					// FIX: Log the ping failure before exiting, so operators
					// can see when connections go stale in the server logs.
					log.Printf("websocket: ping write failed for %s: %v", conn.conn.RemoteAddr(), err)
					// RPC-M3 (R8 2026-07-19 FIX): Close the underlying TCP
					// connection so the read loop in handleConnection exits
					// immediately instead of waiting up to pingInterval*2
					// (default 60s) for the read deadline to fire. Without
					// this, a half-dead TCP connection (peer is gone, RST not
					// yet received locally) keeps occupying a slot in
					// ws.connCount and ws.connCountPerIP, and the
					// connection's subscriptions continue to consume memory
					// until the deadline timeout. Closing here is idempotent
					// — the read loop's defer (which calls UnregisterConn
					// and removes subscriptions) runs exactly once because
					// sync.Once / sequential defer ordering already guards
					// it. We deliberately do NOT call connCancel() here:
					// closing the network connection is sufficient and
					// avoids racing with the read loop's own teardown.
					_ = conn.conn.Close()
					return
				}
				// P2P-R11-M07 (2026-07-20): Slow-pong detection. The ping
				// was sent successfully, but did the client respond to the
				// PREVIOUS ping? lastPongAt is updated by readMessage when
				// a pong frame arrives. If it's been more than 2*pingInterval
				// since the last pong, the client is either:
				//   - Ignoring pings (RFC 6455 §5.5.3 violation)
				//   - Sending other frames to reset the read deadline but
				//     never responding to pings (slow-loris variant)
				//   - Network path is dropping pong frames
				// In all three cases the connection is unhealthy and should
				// be closed. We use 2*pingInterval as the threshold to give
				// the client one full extra ping cycle of slack (the first
				// ping may have been lost, the second gives them another
				// chance). This is defense-in-depth on top of the read
				// deadline (which catches totally silent clients).
				if v := conn.lastPongAt.Load(); v != nil {
					if lastPong, ok := v.(time.Time); ok && !lastPong.IsZero() {
						slowPongThreshold := 2 * pingInterval
						if time.Since(lastPong) > slowPongThreshold {
							log.Printf("websocket: closing slow-pong connection %s: last pong %v ago (threshold %v)",
								conn.conn.RemoteAddr(), time.Since(lastPong), slowPongThreshold)
							_ = conn.conn.Close()
							return
						}
					}
				}
			case <-connCtx.Done():
				return
			}
		}
	}()

	for {
		msg, err := ws.readMessage(conn)
		if err != nil {
			return
		}

		// Reset the read deadline after any successful frame read — this
		// includes pong frames handled inside readMessage, so a live client
		// keeps the connection open even if it only responds to pings.
		_ = conn.conn.SetReadDeadline(time.Now().Add(readDeadline))

		// RPC-R9-M (2026-07-19) FIX: per-connection frame rate limit. A
		// client could otherwise flood the connection with thousands of
		// tiny frames per second (each <125 bytes, evading MaxWSMessageSize)
		// and consume server CPU in handleMessage. We allow a short burst
		// of up to maxBurst frames, then require one token-replenish
		// interval per frame thereafter. Tokens replenish at
		// `framesPerSec` per second, so a well-behaved client (≤1 req/s)
		// is never affected; only abnormally high senders are throttled.
		//
		// R14-LOW (P2P-LOW-08): Previously hardcoded as function-local
		// consts (`wsFramesPerSec=50`, `wsMaxBurst=100`); promoted to
		// WebSocketServer struct fields so deployments can tune them via
		// SetFrameRateLimit (e.g. indexers that legitimately send >50
		// frames/sec, or stricter limits under attack).
		if !conn.frameLimiter.allow(ws.framesPerSec, ws.maxBurst) {
			// Too many frames — drop the connection. Returning here makes
			// the outer loop exit and tear down the connection.
			return
		}

		// R30-IMPLEMENT (2026-07-27): Global frame rate limit. Caps
		// aggregate frame throughput across ALL WebSocket connections to
		// prevent a distributed tiny-frame flood from consuming server
		// CPU. The per-conn limiter above catches single-connection
		// floods; the global limiter catches many-connection floods where
		// each connection stays under its per-conn limit but together
		// they overwhelm the server. Tracked by RPC-R15-P3-6.
		//
		// Behavior on rejection: drop the connection (return), matching
		// the per-conn limiter's behavior. Alternative: silently drop the
		// frame and continue. Dropping the connection is more aggressive
		// but simpler and consistent with the per-conn path. Under a real
		// distributed attack, some legitimate connections will be dropped
		// along with attacker connections — this is acceptable because
		// the global limiter only fires under sustained flood, and
		// clients reconnect with exponential backoff.
		if !ws.globalFrameLimiter.allow(ws.globalFramesPerSec, ws.globalMaxBurst) {
			return
		}

		ws.handleMessage(conn, msg)
	}
}

// readMessage reads a WebSocket message
func (ws *WebSocketServer) readMessage(conn *WSConn) ([]byte, error) {
	// Read frame header
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn.reader, header); err != nil {
		return nil, err
	}

	// Parse header
	fin := header[0]&0x80 != 0
	opcode := header[0] & 0x0F
	masked := header[1]&0x80 != 0
	payloadLen := int(header[1] & 0x7F)

	// L13-012 FIX: Per RFC 6455 §5.1, a client MUST mask all frames sent to
	// the server. Reject unmasked client frames to prevent cross-protocol
	// injection attacks (e.g., WebSocket confusion with HTTP caches).
	if !masked {
		return nil, fmt.Errorf("websocket protocol error: client frame must be masked (RFC 6455 §5.1)")
	}

	// RFC 6455 §5.5: control frames must not be fragmented, must use one
	// of the defined control opcodes, and must have a payload of at most 125
	// bytes. Reject these properties before reading or allocating payload data.
	if opcode >= 8 {
		if !fin {
			return nil, fmt.Errorf("websocket protocol error: fragmented control frame")
		}
		if opcode != 8 && opcode != 9 && opcode != 10 {
			return nil, fmt.Errorf("websocket protocol error: invalid control opcode %d", opcode)
		}
		if payloadLen >= 126 {
			return nil, fmt.Errorf("websocket protocol error: control frame payload exceeds 125 bytes")
		}
	}

	// Handle close frame
	if opcode == 8 {
		return nil, io.EOF
	}

	// audit-fix MEDIUM: handle WebSocket control frames per RFC 6455.
	// Ping (opcode 9) must be answered with a pong (opcode 10) carrying
	// back the ping payload. Pong (opcode 10) is a heartbeat response and
	// is consumed silently — the read deadline reset in handleConnection
	// is what keeps the connection alive.
	//
	// RP-07: This is step 2 (pong) or step 3 (ping) of the ping/pong flow.
	// See the overview comment on writeControlFrame for the complete trace.
	if opcode == 9 || opcode == 10 {
		// Read the masked payload for the control frame. The RFC checks above
		// ensure payloadLen is already within the 125-byte control-frame limit.
		if payloadLen == 126 {
			ext := make([]byte, 2)
			if _, err := io.ReadFull(conn.reader, ext); err != nil {
				return nil, err
			}
			payloadLen = int(binary.BigEndian.Uint16(ext))
		} else if payloadLen == 127 {
			ext := make([]byte, 8)
			if _, err := io.ReadFull(conn.reader, ext); err != nil {
				return nil, err
			}
			rawLen := binary.BigEndian.Uint64(ext)
			if rawLen > uint64(MaxWSMessageSize) {
				return nil, fmt.Errorf("websocket control frame size %d exceeds maximum %d", rawLen, MaxWSMessageSize)
			}
			payloadLen = int(rawLen)
		}
		if payloadLen < 0 || payloadLen > MaxWSMessageSize {
			return nil, fmt.Errorf("websocket control frame size %d exceeds maximum %d", payloadLen, MaxWSMessageSize)
		}
		var maskKey []byte
		if masked {
			maskKey = make([]byte, 4)
			if _, err := io.ReadFull(conn.reader, maskKey); err != nil {
				return nil, err
			}
		}
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(conn.reader, payload); err != nil {
			return nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}
		// Respond to ping with a pong echoing the payload.
		// audit-fix MEDIUM: write the pong asynchronously so a slow/stuck
		// client cannot block the read loop. The write is bounded by a
		// deadline so the goroutine exits even if the client never reads.
		// writeControlFrame acquires conn.mu, so concurrent writes are safe.
		//
		// FIX: Use a non-blocking semaphore (capacity 1) to limit
		// concurrent pong goroutines to 1 per connection. A malicious client
		// can flood ping frames; without the semaphore each ping spawns a
		// new goroutine (each waiting up to 5s), leading to goroutine
		// exhaustion. With the semaphore, a ping that arrives while a
		// previous pong is still in flight closes the connection (see the
		// SV-03 fix in the default branch below).
		if opcode == 9 {
			select {
			case conn.pongSem <- struct{}{}:
				go func(p []byte) {
					// P2P-R10-H1 (2026-07-19) FIX: panic recovery for pong
					// goroutine. SetWriteDeadline/writeControlFrame can
					// panic on a half-closed conn; without recovery this
					// would crash the node. The semaphore is released via
					// the existing defer below, so we register the panic
					// recovery FIRST (runs LAST) to preserve that release.
					defer func() {
						if r := recover(); r != nil {
							log.Printf("[WebSocket] pong goroutine panic recovered for %s: %v",
								conn.conn.RemoteAddr(), r)
						}
					}()
					defer func() { <-conn.pongSem }()
					_ = conn.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
					_ = ws.writeControlFrame(conn, 0xA, p)
					_ = conn.conn.SetWriteDeadline(time.Time{}) // clear deadline
				}(payload)
			default:
				// AUDIT-FULL SV-03 FIX (2026-08-15): Semaphore full — a previous
				// pong is still in flight. Previously this ping was SILENTLY
				// dropped: a well-behaved client that pings faster than the
				// in-flight pong write completes (e.g. sub-second keepalive
				// intervals) never got its pong back and could misjudge the
				// connection as dead on its own timeout, with zero server-side
				// visibility. The semaphore can only stay full when the peer
				// pings faster than a 5s-deadline-bounded pong write completes —
				// i.e. a ping flood or a peer that stopped reading. Fail fast
				// instead: log and tear down the connection (same rejection
				// behavior as the per-conn/global frame limiters above); the
				// client reconnects with backoff.
				log.Printf("[WebSocket] pong semaphore full for %s — previous pong still in flight; closing connection (ping flood or unreadable peer)",
					conn.conn.RemoteAddr())
				return nil, fmt.Errorf("websocket: pong semaphore full — closing connection (SV-03)")
			}
		}
		// Return a sentinel empty message with no data so the caller loops
		// back to readMessage without dispatching to handleMessage. We use
		// a zero-length slice (not nil) so the caller can distinguish from
		// an error. handleMessage already no-ops on empty/non-JSON input.
		//
		// P2P-R11-M07 (2026-07-20): If this was a pong (opcode 10), update
		// lastPongAt so the ping goroutine can detect slow-loris clients
		// that ignore pings but stay alive by sending other frames.
		if opcode == 10 {
			conn.lastPongAt.Store(time.Now())
		}
		return []byte{}, nil
	}

	// Extended payload length
	if payloadLen == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(conn.reader, ext); err != nil {
			return nil, err
		}
		payloadLen = int(binary.BigEndian.Uint16(ext))
	} else if payloadLen == 127 {
		ext := make([]byte, 8)
		if _, err := io.ReadFull(conn.reader, ext); err != nil {
			return nil, err
		}
		// audit-fix H-3: prevent integer overflow on 32-bit systems
		rawLen := binary.BigEndian.Uint64(ext)
		if rawLen > uint64(MaxWSMessageSize) {
			return nil, fmt.Errorf("websocket message size %d exceeds maximum %d", rawLen, MaxWSMessageSize)
		}
		// R32-P3-7 FIX: On 32-bit systems, int is 32-bit. Ensure rawLen fits
		// in a positive int before conversion to prevent signed integer overflow.
		if rawLen > uint64(math.MaxInt32) {
			return nil, fmt.Errorf("websocket message size %d exceeds 32-bit int limit", rawLen)
		}
		payloadLen = int(rawLen)
	}

	// Reject oversized messages to prevent OOM from malicious clients
	if payloadLen < 0 || payloadLen > MaxWSMessageSize {
		return nil, fmt.Errorf("websocket message size %d exceeds maximum %d", payloadLen, MaxWSMessageSize)
	}

	// Read mask key
	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(conn.reader, maskKey); err != nil {
			return nil, err
		}
	}

	// Read payload
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn.reader, payload); err != nil {
		return nil, err
	}

	// Unmask payload
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return payload, nil
}

// writeMessage writes a WebSocket message
func (ws *WebSocketServer) writeMessage(conn *WSConn, data []byte) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Build frame
	frame := make([]byte, 0, 10+len(data))

	// FIN + text opcode
	frame = append(frame, 0x81)

	// Payload length
	if len(data) < 126 {
		frame = append(frame, byte(len(data))) // #nosec G115 -- len < 126, fits in byte
	} else if len(data) < 65536 {
		frame = append(frame, 126)
		frame = append(frame, byte(len(data)>>8), byte(len(data))) // #nosec G115 -- len < 65536, shifts safe
	} else {
		frame = append(frame, 127)
		for i := 7; i >= 0; i-- {
			frame = append(frame, byte(len(data)>>(i*8))) // #nosec G115 -- 64-bit shift, each byte fits
		}
	}

	// Payload
	frame = append(frame, data...)

	// AUDIT (2026) R4-API-01: Set a write deadline before writing to
	// prevent a slow/stopped reader from blocking the broadcast goroutine
	// indefinitely (head-of-line blocking DoS). If the write doesn't complete
	// within WSWriteTimeout, the Write returns a timeout error and the caller
	// (broadcastToSubscribers) cleans up the connection.
	_ = conn.conn.SetWriteDeadline(time.Now().Add(WSWriteTimeout))
	n, err := conn.conn.Write(frame)
	// Clear the deadline so subsequent writes (e.g., ping/pong) are not
	// affected by a stale deadline.
	_ = conn.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	if n != len(frame) {
		return fmt.Errorf("short write: wrote %d of %d bytes", n, len(frame))
	}
	return nil
}

// audit-fix MEDIUM: writeControlFrame writes a WebSocket control frame
// (ping=0x9, pong=0xA, close=0x8) with the given payload. Control frames
// are always FIN=1 and carry at most 125 bytes of payload per RFC 6455 §5.5.
//
// RP-07: Ping/Pong Control Flow Overview
// =======================================
// The heartbeat mechanism spans three functions. This comment documents the
// complete flow so it can be traced end-to-end.
//
//  1. SERVER → CLIENT PING (keepalive):
//     handleConnection starts a goroutine with a pingTicker (pingInterval,
//     default 30s). On each tick it calls writeControlFrame(conn, 0x9, nil)
//     to send a ping. If the write fails the goroutine exits; the read loop
//     will later detect the dead connection via read-deadline timeout.
//
//  2. CLIENT → SERVER PONG (response to server ping):
//     readMessage receives a pong frame (opcode 10). It is consumed silently
//     — no response is needed. Control returns to handleConnection, which
//     resets the read deadline (line: SetReadDeadline), keeping the
//     connection alive.
//
//  3. CLIENT → SERVER PING (client-initiated):
//     readMessage receives a ping frame (opcode 9). It responds with a pong
//     (opcode 10) asynchronously via a goroutine, so a slow client cannot
//     block the read loop. The pong write is rate-limited by conn.pongSem
//     (capacity 1): if a previous pong is still in flight, the new ping is
//     silently dropped to prevent goroutine exhaustion (RFC 6455 lets the
//     client re-ping). The pong goroutine sets a 5s write deadline so it
//     exits even if the client never reads.
//
//  4. READ DEADLINE (liveness enforcement):
//     handleConnection sets an initial read deadline of pingInterval*2
//     (default 60s). After every successful readMessage return — including
//     ping and pong frames — the deadline is reset. If no frame arrives
//     within the deadline, readMessage returns an error and the connection
//     is torn down.
//
//  5. CONNECTION TEARDOWN:
//     When handleConnection returns (read error or close frame), it calls
//     connCancel() which cancels connCtx, causing the ping goroutine to
//     exit via the <-connCtx.Done() select case.
//
// Write serialization: this function acquires conn.mu, so concurrent writes
// (ping from heartbeat goroutine, pong from pong goroutine, and data frames
// from writeMessage) are safely serialized.
func (ws *WebSocketServer) writeControlFrame(conn *WSConn, opcode byte, payload []byte) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if len(payload) > 125 {
		// RFC 6455 §5.5: control frame payloads must not exceed 125 bytes.
		payload = payload[:125]
	}

	// FIN + control opcode (0x80 | opcode)
	frame := make([]byte, 0, 2+len(payload))
	frame = append(frame, 0x80|opcode)
	// Server-to-client frames are unmasked per RFC 6455 §5.3.
	frame = append(frame, byte(len(payload))) // #nosec G115 -- len <= 125
	frame = append(frame, payload...)

	_, err := conn.conn.Write(frame)
	return err
}

// handleMessage handles a WebSocket message
func (ws *WebSocketServer) handleMessage(conn *WSConn, msg []byte) {
	// audit-fix MEDIUM: skip empty messages produced by control-frame
	// (ping/pong) handling in readMessage. These are heartbeat bookkeeping
	// and must not be dispatched as JSON-RPC requests.
	if len(msg) == 0 {
		return
	}

	// Try batch
	var batch []Request
	if err := json.Unmarshal(msg, &batch); err == nil && len(batch) > 0 {
		// Reject oversized batches to prevent resource exhaustion
		if len(batch) > MaxWSBatchSize {
			ws.sendError(conn, nil, NewError(ErrCodeInvalidRequest,
				fmt.Sprintf("batch size %d exceeds limit of %d", len(batch), MaxWSBatchSize)))
			return
		}

		// FIX: Unify WebSocket batch authentication with HTTP path.
		// HTTP batch verifies HMAC once on the first non-public method, then
		// uses AuthorizeMethod for remaining non-public methods. Previously
		// WebSocket called full ValidateRequest (HMAC+auth+rate) per element,
		// causing nonce reuse errors and rate-limit inconsistencies.
		//
		// FIX: HMAC must cover the ENTIRE batch message, not just the
		// first non-public element. Previously, fakeReq.Body was set to the
		// marshaled JSON of only the first non-public request, allowing an
		// attacker to replace subsequent methods in the batch without
		// invalidating the HMAC. Now fakeReq.Body uses the full batch message
		// (msg), matching the HTTP path where HMAC is computed over the full
		// HTTP body. This ensures any modification to any element in the batch
		// invalidates the HMAC.
		//
		// P1-13 (RPC-H3, 2026-07-19) FIX: Now uses ValidateBatchRequest which
		// computes HMAC over ALL non-public method names (length-prefixed),
		// not just the first. This explicitly binds every method in the batch
		// to the signature, closing the method-substitution attack surface
		// that relied on bodyHash's indirect coverage. The "BATCHv1" prefix
		// in the HMAC input makes batch signatures incompatible with single-
		// request signatures, preventing cross-format replay.
		batchAuthCtx := ws.rpcServer.authManager
		if batchAuthCtx != nil {
			// Collect all non-public method names. HMAC will cover every name.
			nonPublicMethods := make([]string, 0, len(batch))
			firstNonPublicID := interface{}(nil)
			for i := range batch {
				if !batchAuthCtx.IsPublicMethod(batch[i].Method) {
					nonPublicMethods = append(nonPublicMethods, batch[i].Method)
					if firstNonPublicID == nil {
						firstNonPublicID = batch[i].ID
					}
				}
			}
			if len(nonPublicMethods) > 0 {
				// Full validation (HMAC + authorization) using the entire batch
				// message as the body. HMAC covers all method names explicitly.
				fakeReq := &http.Request{
					Header:     conn.header,
					RemoteAddr: conn.conn.RemoteAddr().String(),
					Body:       io.NopCloser(bytes.NewReader(msg)),
				}
				if err := batchAuthCtx.ValidateBatchRequest(fakeReq, nonPublicMethods); err != nil {
					ws.sendError(conn, firstNonPublicID, NewError(ErrCodeUnauthorized, err.Error()))
					return
				}
				// ValidateAdminRequest for any admin methods in the batch.
				// ValidateBatchRequest covers API key + HMAC + permissions, but
				// admin methods require additional admin-level authorization.
				for i := range batch {
					if ws.rpcServer.isAdminMethod(batch[i].Method) {
						if err := batchAuthCtx.ValidateAdminRequest(fakeReq, batch[i].Method); err != nil {
							ws.sendError(conn, batch[i].ID, NewError(ErrCodeUnauthorized, err.Error()))
							return
						}
					}
				}
			}
		}

		responses := make([]*Response, 0, len(batch))
		for _, req := range batch {
			// RPC-M6 (R8 2026-07-19 FIX): Pre-validate params length at
			// the WebSocket transport layer BEFORE dispatching to
			// handleRequestInternal. The HTTP path enforces this same
			// limit in handleHTTP (server.go around line 840) before
			// any HMAC/auth work, but the WebSocket path was relying on
			// the check inside server.handleRequest (line 1147) which
			// runs AFTER the WS-layer HMAC computation (line 883 above)
			// and rate-limit/admin-auth checks. Without this guard a
			// WebSocket client could send a 1 MiB params blob (under
			// the 1 MiB body limit but over the 64 KiB params limit)
			// that forces expensive HMAC/auth computation before being
			// rejected. Mirror the HTTP path's defense-in-depth pattern.
			if ws.rpcServer.maxParamsLen > 0 && len(req.Params) > ws.rpcServer.maxParamsLen {
				ws.sendError(conn, req.ID, NewError(ErrCodeInvalidRequest,
					"params size exceeds limit"))
				continue
			}
			// RPC-P0-01 FIX (R31, 2026-07-27): Per-request panic recovery
			// (WebSocket batch path). Without this, a single panic in
			// handleRequestInternal (nil pointer, array out of bounds, etc.)
			// would propagate up through the entire batch loop, killing the
			// read loop goroutine and dropping the entire WebSocket connection
			// without a close frame. handleConnection's top-level recover
			// (P2P-R10-H1) would catch it, but the connection would still
			// be torn down — one malicious batch request could disconnect
			// any subscriber. Wrapping each request in an anonymous function
			// with defer recover ensures a panic in ONE request does not
			// break the rest of the batch or the connection. Tracked by
			// RPC-P0-01 / RPC-P1-03.
			var resp *Response
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("[WebSocket] batch handleRequestInternal panic recovered for method %s: %v",
							req.Method, r)
						resp = &Response{
							JSONRPC: JSONRPCVersion,
							ID:      req.ID,
							Error: NewError(ErrCodeInternal,
								"internal error: panic during request processing"),
						}
					}
				}()
				//  skipAuth=true — auth already verified at batch level above.
				resp = ws.handleRequestInternal(conn, &req, batchAuthCtx != nil)
			}()
			if req.ID != nil {
				responses = append(responses, resp)
			}
		}
		if len(responses) > 0 {
			data, err := json.Marshal(responses)
			if err != nil {
				// audit-fix WS-L2: use structured log instead of fmt.Printf
				log.Printf("[WebSocket] Failed to marshal responses: %v", err)
				return
			}
			if err := ws.writeMessage(conn, data); err != nil {
				// Connection error - will be handled by connection cleanup
				log.Printf("[WebSocket] Failed to write message: %v", err)
			}
		}
		return
	}

	// Single request
	var req Request
	if err := json.Unmarshal(msg, &req); err != nil {
		ws.sendError(conn, nil, ErrParse)
		return
	}

	// RPC-M6 (R8 2026-07-19 FIX): Pre-validate params length at the WS
	// transport layer before handleRequest runs HMAC/auth/rate-limit.
	// See the batch path above for the full rationale.
	if ws.rpcServer.maxParamsLen > 0 && len(req.Params) > ws.rpcServer.maxParamsLen {
		ws.sendError(conn, req.ID, NewError(ErrCodeInvalidRequest,
			"params size exceeds limit"))
		return
	}

	resp := ws.handleRequest(conn, &req)
	data, err := json.Marshal(resp)
	if err != nil {
		log.Printf("[WebSocket] Failed to marshal response: %v", err)
		return
	}
	if err := ws.writeMessage(conn, data); err != nil {
		log.Printf("[WebSocket] Failed to write response: %v", err)
	}
}

// handleRequest handles a single request.
// audit-fix WS-H1: enforce auth and rate-limit checks before dispatching to the
// RPC server. Without this, WebSocket clients bypass the authentication and rate
// limiting that the HTTP path enforces in handleHTTP(), allowing unauthenticated
// access to privileged methods like personal_sendTransaction.
func (ws *WebSocketServer) handleRequest(conn *WSConn, req *Request) *Response {
	return ws.handleRequestInternal(conn, req, false)
}

// handleRequestInternal handles a single request. When skipAuth is true, the
// auth/rate-limit checks are skipped (caller has already verified them at the
// batch level — FIX for consistent WebSocket/HTTP batch authentication).
func (ws *WebSocketServer) handleRequestInternal(conn *WSConn, req *Request, skipAuth bool) *Response {
	// audit-fix R40-H9: Auth check MUST run BEFORE subscribe/unsubscribe dispatch.
	// Previously, eth_subscribe and eth_unsubscribe were handled in a switch
	// statement above the auth check, allowing unauthenticated clients to create
	// and manage subscriptions. Moving auth first ensures all WebSocket methods
	// go through the same authentication pipeline.
	// FIX: When authManager is nil, admin methods must still be rejected.
	// The previous condition `ws.rpcServer.authManager != nil && !skipAuth`
	// skipped ALL auth checks when authManager was nil, allowing admin methods
	// to be called via WebSocket without any authentication.
	if !skipAuth {
		if ws.rpcServer.authManager == nil {
			// No auth manager configured — reject any admin method.
			if ws.rpcServer.isAdminMethod(req.Method) {
				return &Response{
					JSONRPC: JSONRPCVersion,
					Error:   NewError(ErrCodeUnauthorized, "admin authentication is not configured"),
					ID:      req.ID,
				}
			}
		} else {
			// L9-016 FIX: carry over the upgrade request's headers (API key,
			// signature, X-Forwarded-For, etc.) so auth checks match the HTTP path.
			// FIX: Set Body to the JSON-encoded request so HMAC signature
			// verification uses the actual message content, not an empty body.
			// Without this, all non-public methods fail HMAC validation over WebSocket.
			reqBody, err := json.Marshal(req)
			if err != nil {
				return &Response{JSONRPC: JSONRPCVersion, Error: NewError(ErrCodeInvalidRequest, "failed to marshal request body"), ID: req.ID}
			}
			fakeReq := &http.Request{
				Header:     conn.header,
				RemoteAddr: conn.conn.RemoteAddr().String(),
				Body:       io.NopCloser(bytes.NewReader(reqBody)),
			}
			if err := ws.rpcServer.authManager.ValidateRequest(fakeReq, req.Method); err != nil {
				return &Response{JSONRPC: JSONRPCVersion, Error: NewError(ErrCodeUnauthorized, err.Error()), ID: req.ID}
			}
			// H-2 FIX: Admin method authorization for WebSocket transport.
			// Previously only basic auth (ValidateRequest) was checked, allowing
			// users with regular API keys to call admin methods via WebSocket.
			if ws.rpcServer.isAdminMethod(req.Method) {
				if err := ws.rpcServer.authManager.ValidateAdminRequest(fakeReq, req.Method); err != nil {
					return &Response{JSONRPC: JSONRPCVersion, Error: NewError(ErrCodeUnauthorized, err.Error()), ID: req.ID}
				}
			}
		} // end else (authManager != nil)
	}

	// audit-fix R40-H9: Rate-limit check also before subscribe/unsubscribe
	// R48-RP-05 FIX: Rate limiting applies even when skipAuth=true (batch mode).
	// Auth was verified at batch level, but rate limiting must still apply
	// per-request to prevent DoS via large batches.
	if ws.rpcServer.rateLimiter != nil {
		fakeReq := &http.Request{Header: conn.header, RemoteAddr: conn.conn.RemoteAddr().String()}
		if err := ws.rpcServer.rateLimiter.Allow(fakeReq, req.Method); err != nil {
			return &Response{JSONRPC: JSONRPCVersion, Error: NewError(ErrCodeUnauthorized, "rate limit exceeded"), ID: req.ID}
		}
	}

	// Now dispatch subscribe/unsubscribe after auth is validated
	switch req.Method {
	case "eth_subscribe":
		return ws.handleSubscribe(conn, req)
	case "eth_unsubscribe":
		return ws.handleUnsubscribe(conn, req)
	}

	// R7-M5 FIX: previously dispatched with a bare context.Background(), which
	// made requireTLS take the "non-HTTP transport — allow without TLS" branch
	// and let personal_* password-bearing methods run over plaintext ws://.
	// Build a synthetic http.Request that reflects whether the underlying socket
	// is TLS (wss://), so requireTLS can enforce WSS on the WS transport.
	ctx := context.WithValue(context.Background(), contextKeyClientIP{}, conn.conn.RemoteAddr().String())
	// R41-RP-001 FIX: Copy conn.header into the synthetic request so that
	// admin re-authentication (ValidateAdminRequest) can read HMAC/API-Key
	// headers. Without this, all admin methods fail with "authentication required".
	// R42-RP-001 FIX: Set Body to the JSON-RPC request params so HMAC
	// verification covers the actual payload, not an empty body.
	reqBody, err := json.Marshal(req)
	if err != nil {
		reqBody = nil
	}
	synReq := &http.Request{
		RemoteAddr:    conn.conn.RemoteAddr().String(),
		Header:        conn.header,
		Body:          io.NopCloser(bytes.NewReader(reqBody)),
		ContentLength: int64(len(reqBody)),
	}
	if isTLSDial(conn.conn) {
		// Non-nil TLS field signals "secure transport" to requireTLS.
		synReq.TLS = &tls.ConnectionState{}
	}
	ctx = context.WithValue(ctx, contextKeyHTTPRequest{}, synReq)
	return ws.rpcServer.HandleRequest(ctx, req)
}

// isTLSDial reports whether conn is a TLS connection (wss://). Used so the WS
// dispatch path can populate the synthetic http.Request's TLS field, allowing
// requireTLS to correctly enforce WSS on the WebSocket transport.
func isTLSDial(conn net.Conn) bool {
	type handshakeConn interface {
		ConnectionState() tls.ConnectionState
	}
	_, ok := conn.(handshakeConn)
	return ok
}

// handleSubscribe handles a subscription request
func (ws *WebSocketServer) handleSubscribe(conn *WSConn, req *Request) *Response {
	var params []any
	if err := json.Unmarshal(req.Params, &params); err != nil || len(params) < 1 {
		return &Response{JSONRPC: JSONRPCVersion, Error: ErrInvalidParams, ID: req.ID}
	}

	subType, ok := params[0].(string)
	if !ok {
		return &Response{JSONRPC: JSONRPCVersion, Error: ErrInvalidParams, ID: req.ID}
	}

	switch subType {
	case SubTypeNewHeads, SubTypeLogs, SubTypePending:
	default:
		return &Response{JSONRPC: JSONRPCVersion, Error: NewError(ErrCodeInvalidParams, "invalid subscription type"), ID: req.ID}
	}

	// audit-fix R2-L1: enforce per-connection subscription limit
	// L10-018: Verified — this check enforces MaxSubscriptionsPerConn (10)
	// per WebSocket connection, preventing resource exhaustion from
	// unlimited subscriptions. Each eth_subscribe call acquires ws.mu.Lock()
	// and checks the count atomically before creating a new subscription.
	ws.mu.Lock()
	if len(ws.connSubs[conn]) >= MaxSubscriptionsPerConn {
		ws.mu.Unlock()
		return &Response{JSONRPC: JSONRPCVersion, Error: NewError(ErrCodeInvalidRequest,
			fmt.Sprintf("subscription limit %d reached for this connection", MaxSubscriptionsPerConn)), ID: req.ID}
	}

	// R30-IMPLEMENT (2026-07-27): Global subscription limit. Tracked by
	// RPC-R15-H04. The per-connection check above runs first so a single
	// connection hitting its own limit gets the per-conn error message
	// (more actionable for legitimate clients). The global check catches
	// the distributed attack where many connections each stay under the
	// per-conn limit but together exhaust server memory. We use >= (not
	// >) so the boundary is exact: at MaxWSGlobalSubscriptions-1 a new
	// subscription succeeds; at MaxWSGlobalSubscriptions it fails.
	if len(ws.subscriptions) >= MaxWSGlobalSubscriptions {
		ws.mu.Unlock()
		return &Response{JSONRPC: JSONRPCVersion, Error: NewError(ErrCodeInvalidRequest,
			fmt.Sprintf("global subscription limit %d reached", MaxWSGlobalSubscriptions)), ID: req.ID}
	}

	subID, err := generateSubID()
	if err != nil {
		ws.mu.Unlock()
		return &Response{JSONRPC: JSONRPCVersion, Error: NewError(ErrCodeInternal, fmt.Sprintf("failed to generate subscription ID: %v", err)), ID: req.ID}
	}
	sub := &Subscription{ID: subID, Type: subType, Conn: conn, Created: time.Now()}

	if len(params) > 1 {
		// R7-L6 FIX: enforce MaxBytesPerSubscription on the stored filter to
		// prevent oversized per-subscription memory allocation. The constant
		// existed but was never checked.
		filterBytes, mErr := json.Marshal(params[1])
		if mErr != nil || len(filterBytes) > MaxBytesPerSubscription {
			ws.mu.Unlock()
			return &Response{JSONRPC: JSONRPCVersion, Error: NewError(ErrCodeInvalidRequest,
				fmt.Sprintf("filter exceeds max size %d bytes", MaxBytesPerSubscription)), ID: req.ID}
		}
		sub.Filter = params[1]
	}

	ws.subscriptions[subID] = sub
	ws.connSubs[conn] = append(ws.connSubs[conn], subID)
	// R14-LOW (P2P-LOW-05): Publish current subscription count to metrics.
	metrics.Global().SetWSActiveSubscriptions(len(ws.subscriptions))
	ws.mu.Unlock()

	return &Response{JSONRPC: JSONRPCVersion, Result: subID, ID: req.ID}
}

// handleUnsubscribe handles an unsubscription request
func (ws *WebSocketServer) handleUnsubscribe(conn *WSConn, req *Request) *Response {
	var params []string
	if err := json.Unmarshal(req.Params, &params); err != nil || len(params) < 1 {
		return &Response{JSONRPC: JSONRPCVersion, Error: ErrInvalidParams, ID: req.ID}
	}

	subID := params[0]
	// R31-P4 FIX: Validate subID format to prevent injection/malformed input.
	// Subscription IDs are hex strings prefixed with "0x" (generated by handleSubscribe).
	if len(subID) == 0 || len(subID) > 128 {
		return &Response{JSONRPC: JSONRPCVersion, Error: ErrInvalidParams, ID: req.ID}
	}

	ws.mu.Lock()
	defer ws.mu.Unlock()

	sub, exists := ws.subscriptions[subID]
	if !exists || sub.Conn != conn {
		return &Response{JSONRPC: JSONRPCVersion, Result: false, ID: req.ID}
	}

	delete(ws.subscriptions, subID)
	// R14-LOW (P2P-LOW-05): Publish current subscription count to metrics.
	metrics.Global().SetWSActiveSubscriptions(len(ws.subscriptions))

	subs := ws.connSubs[conn]
	for i, id := range subs {
		if id == subID {
			ws.connSubs[conn] = append(subs[:i], subs[i+1:]...)
			break
		}
	}

	return &Response{JSONRPC: JSONRPCVersion, Result: true, ID: req.ID}
}

// cleanupConnection cleans up subscriptions for a closed connection.
// L19-003 RACE CONDITION ANALYSIS:
// There is a benign race between broadcastToSubscribers Phase 2 (which
// writes to connections outside ws.mu) and cleanupConnection (which
// acquires ws.mu.Lock to delete subscription entries). This race is
// safe for the following reasons:
//  1. writeMessage acquires conn.mu before writing, so concurrent
//     writes to the same WSConn are serialized at the connection level.
//  2. If a connection is closed by the handler (conn.conn.Close())
//     while broadcastToSubscribers is writing, writeMessage returns an
//     error, which is collected in failedConns and handled gracefully.
//  3. cleanupConnection only deletes map entries; it does NOT close the
//     connection (that is done separately by the handler). Calling
//     cleanupConnection on an already-cleaned connection is a no-op
//     (Go map delete on absent key is safe).
//  4. The R40-L6 fix ensures cleanupConnection is never called while
//     ws.mu.RLock is held (deadlock prevention).
func (ws *WebSocketServer) cleanupConnection(conn *WSConn) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	for _, subID := range ws.connSubs[conn] {
		delete(ws.subscriptions, subID)
	}
	delete(ws.connSubs, conn)
	// R14-LOW (P2P-LOW-05): Publish current subscription count to metrics
	// after bulk cleanup so the gauge reflects subscriptions freed by
	// connection close.
	metrics.Global().SetWSActiveSubscriptions(len(ws.subscriptions))
}

// broadcastEvents broadcasts events to subscribers
func (ws *WebSocketServer) broadcastEvents() {
	for {
		select {
		case <-ws.ctx.Done():
			return
		case head := <-ws.newHeadsCh:
			ws.broadcastToSubscribers(SubTypeNewHeads, head)
		case log := <-ws.logsCh:
			ws.broadcastToSubscribers(SubTypeLogs, log)
		case tx := <-ws.pendingCh:
			ws.broadcastToSubscribers(SubTypePending, tx)
		}
	}
}

// logMatchesFilter checks whether a log entry matches the given subscription
// filter. The filter is the decoded JSON object stored in Subscription.Filter
// (e.g., {"address": "0x...", "topics": ["0x...", null, ...]}).
//
// AUDIT (2026) API-03 FIX: Previously, broadcastToSubscribers stored the
// filter on the subscription but never consulted it — every logs subscriber
// received EVERY log event regardless of their address/topic criteria. This
// function implements the same matching semantics as advanced.go's getLogs.
func logMatchesFilter(logData any, filter any) bool {
	if filter == nil {
		return true // no filter = match all
	}

	filterMap, ok := filter.(map[string]any)
	if !ok {
		return true // unparseable filter = match all (safe default)
	}

	// Extract address and topics from the log data.
	var logAddr string
	var logTopics []string

	switch ld := logData.(type) {
	case Log:
		logAddr = ld.Address
		logTopics = ld.Topics
	case *Log:
		if ld != nil {
			logAddr = ld.Address
			logTopics = ld.Topics
		}
	case map[string]any:
		if a, ok := ld["address"].(string); ok {
			logAddr = a
		}
		if rawTopics, ok := ld["topics"].([]any); ok {
			for _, t := range rawTopics {
				if s, ok := t.(string); ok {
					logTopics = append(logTopics, s)
				}
			}
		}
	default:
		return true // unknown log format = match all
	}

	// Check address filter
	if addrFilter, exists := filterMap["address"]; exists && addrFilter != nil {
		var allowedAddrs []string
		switch af := addrFilter.(type) {
		case string:
			if af != "" {
				allowedAddrs = append(allowedAddrs, af)
			}
		case []any:
			for _, a := range af {
				if s, ok := a.(string); ok && s != "" {
					allowedAddrs = append(allowedAddrs, s)
				}
			}
		}
		if len(allowedAddrs) > 0 {
			matched := false
			for _, a := range allowedAddrs {
				if strings.EqualFold(a, logAddr) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	// Check topic filters
	if rawTopics, exists := filterMap["topics"]; exists && rawTopics != nil {
		if topicList, ok := rawTopics.([]any); ok && len(topicList) > 0 {
			for i, tf := range topicList {
				var allowedTopics []string
				switch t := tf.(type) {
				case string:
					if t != "" {
						allowedTopics = append(allowedTopics, t)
					}
				case []any:
					for _, ti := range t {
						if s, ok := ti.(string); ok && s != "" {
							allowedTopics = append(allowedTopics, s)
						}
					}
				}
				// nil or empty filter at this position = match any topic
				if len(allowedTopics) == 0 {
					continue
				}
				// Log doesn't have enough topics
				if i >= len(logTopics) {
					return false
				}
				matched := false
				for _, at := range allowedTopics {
					if logTopics[i] == at {
						matched = true
						break
					}
				}
				if !matched {
					return false
				}
			}
		}
	}

	return true
}

// broadcastToSubscribers sends an event to all subscribers of a type
// R40-L6 FIX: Collect failed connections under RLock, then clean up outside
// the lock to avoid a race condition. Previously, the goroutine spawned by
// `go ws.cleanupConnection(sub.Conn)` would try to acquire ws.mu.Lock()
// while the caller held ws.mu.RLock(). If the goroutine ran immediately
// (on the same OS thread or with GOMAXPROCS=1), this would deadlock since
// RWMutex.Lock() waits for all RLock() holders to release. Even without
// deadlock, iterating the map while a goroutine concurrently deletes from
// it is a data race. Now we collect failed conns, release the RLock, then
// clean up sequentially.
// INFO-1 FIX: Collect all subscriber+message pairs under RLock, then release
// the lock BEFORE performing I/O (writeMessage). This prevents slow TCP writes
// from blocking subscription management operations (subscribe/unsubscribe/cleanup).
func (ws *WebSocketServer) broadcastToSubscribers(subType string, data any) {
	// Phase 1: Under RLock, collect subscriber connections and pre-marshaled messages
	ws.mu.RLock()

	type delivery struct {
		conn *WSConn
		data []byte
	}

	var deliveries []delivery

	notification := map[string]any{
		"jsonrpc": JSONRPCVersion,
		"method":  "eth_subscription",
		"params": map[string]any{
			"subscription": "placeholder", // overridden per subscriber below
			"result":       data,
		},
	}

	for _, sub := range ws.subscriptions {
		if sub.Type != subType {
			continue
		}

		// AUDIT (2026) API-03 FIX: Apply the stored subscription filter
		// for logs subscriptions. Previously the filter was stored but never
		// consulted, so every logs subscriber received every log event.
		if subType == SubTypeLogs && sub.Filter != nil {
			if !logMatchesFilter(data, sub.Filter) {
				continue
			}
		}

		// Create per-subscriber notification with correct subscription ID
		notification["params"] = map[string]any{
			"subscription": sub.ID,
			"result":       data,
		}

		msgData, err := json.Marshal(notification)
		if err != nil {
			log.Printf("[WebSocket] Failed to marshal notification: %v", err)
			continue
		}
		deliveries = append(deliveries, delivery{conn: sub.Conn, data: msgData})
	}

	ws.mu.RUnlock()

	// Phase 2: AUDIT-FULL H-6 (2026-08-14) — enqueue into each subscriber's
	// per-connection send queue with a NON-BLOCKING send. The dedicated
	// writer goroutine on each connection performs the actual (potentially
	// slow) socket write, so a stalled subscriber can only fill its own
	// bounded queue; when full, events are dropped for that subscriber
	// only (metric + throttled log) instead of head-of-line blocking the
	// broadcast goroutine — and every OTHER subscriber — for up to
	// WSWriteTimeout. Write failures on dead connections are handled by
	// the writer goroutine (it closes the conn; the read loop's deferred
	// cleanup runs the full teardown path), so no failedConns collection
	// is needed here anymore.
	for _, d := range deliveries {
		select {
		case d.conn.sendCh <- d.data:
		default:
			// Queue full: slow subscriber. Drop the event for this
			// subscriber only (same accounting as the Notify* drops).
			ws.droppedEvents.Add(1)
			metrics.Global().AddWSDroppedEvent()
			ws.logDroppedEvent("sendCh")
		}
	}
}

// L16-024 NOTE: The Notify* methods (NotifyNewHead, NotifyLog, NotifyPendingTx) use
// non-blocking sends. When the channel buffer is full, notifications are dropped.
// FIX: Added a warning log when events are dropped so operators can
// detect event loss and adjust buffer sizes if needed.
// NotifyNewHead notifies subscribers of a new block head
func (ws *WebSocketServer) NotifyNewHead(head any) {
	select {
	case ws.newHeadsCh <- head:
	default:
		// FIX: Log dropped events for observability.
		// R14-LOW (P2P-LOW-02): Throttle the log to once per
		// wsDropLogInterval so a slow subscriber cannot flood the journal.
		// R14-LOW (P2P-LOW-04): Also increment the global metrics counter
		// so the value is exposed via /metrics for alerting.
		ws.droppedEvents.Add(1)
		metrics.Global().AddWSDroppedEvent()
		ws.logDroppedEvent("newHeadsCh")
	}
}

// NotifyLog notifies subscribers of a new log
func (ws *WebSocketServer) NotifyLog(logEntry any) {
	select {
	case ws.logsCh <- logEntry:
	default:
		// FIX: Log dropped events for observability.
		// R14-LOW (P2P-LOW-02): Throttle the log to once per
		// wsDropLogInterval so a slow subscriber cannot flood the journal.
		// R14-LOW (P2P-LOW-04): Also increment the global metrics counter
		// so the value is exposed via /metrics for alerting.
		ws.droppedEvents.Add(1)
		metrics.Global().AddWSDroppedEvent()
		ws.logDroppedEvent("logsCh")
	}
}

// NotifyPendingTx notifies subscribers of a new pending transaction
func (ws *WebSocketServer) NotifyPendingTx(tx any) {
	select {
	case ws.pendingCh <- tx:
	default:
		// FIX: Log dropped events for observability.
		// R14-LOW (P2P-LOW-02): Throttle the log to once per
		// wsDropLogInterval so a slow subscriber cannot flood the journal.
		// R14-LOW (P2P-LOW-04): Also increment the global metrics counter
		// so the value is exposed via /metrics for alerting.
		ws.droppedEvents.Add(1)
		metrics.Global().AddWSDroppedEvent()
		ws.logDroppedEvent("pendingCh")
	}
}

// logDroppedEvent emits a single drop-warning log line, throttled to at most
// once per wsDropLogInterval. The atomic counter (ws.droppedEvents) is always
// incremented by the caller BEFORE this method is invoked, so the log shows
// the cumulative drop count at the moment of emission — including all the
// drops that were silently counted between throttled log lines.
//
// R14-LOW (P2P-LOW-02): The throttle prevents a slow subscriber from
// flooding the systemd journal with thousands of identical log lines/sec.
// The implementation uses atomic compare-and-swap on lastDropLogTime so the
// throttle decision is race-free across goroutines invoking Notify* in
// parallel. If the CAS fails (another goroutine just logged), we simply skip
// the log without retrying — the next drop will pick up the throttle.
func (ws *WebSocketServer) logDroppedEvent(channel string) {
	now := time.Now().UnixNano()
	last := ws.lastDropLogTime.Load()
	if now-last < int64(wsDropLogInterval) {
		return
	}
	// CAS: only the first goroutine within the interval window emits the log.
	// If CAS fails, another goroutine already updated the timestamp this cycle.
	if !ws.lastDropLogTime.CompareAndSwap(last, now) {
		return
	}
	log.Printf("[WebSocket] %s full, dropped notification (total dropped: %d)",
		channel, ws.droppedEvents.Load())
}

// Start starts the WebSocket server on the given address.
// It creates an HTTP server that handles WebSocket upgrade requests on the "/" path.
func (ws *WebSocketServer) Start(addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/", ws)

	// RPC-FIX: snapshot tlsConfig under httpMu so the subsequent
	// read+write of ws.httpServer is not racing with SetTLSConfig (which
	// mutates ws.tlsConfig under the same mutex) or with Stop (which reads
	// ws.httpServer under the same mutex). We only hold the lock while
	// reading tlsConfig and assigning httpServer; the blocking Serve call
	// happens outside the lock so Stop can still acquire it to shutdown.
	ws.httpMu.Lock()
	tlsCfg := ws.tlsConfig
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second, // R7-H3: Slowloris header-DoS protection
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second, // R7-H3: bound keepalive resource use
		MaxHeaderBytes:    1 << 20,           // R7-H3: 1 MiB header cap
		// RPC-H2 FIX: when tlsConfig is set, the HTTP server becomes a wss://
		// listener. We attach the config here so callers don't have to know
		// to set it on httpServer directly (defensive API design).
		TLSConfig: tlsCfg,
	}
	ws.httpServer = srv
	ws.httpMu.Unlock()

	if tlsCfg != nil {
		// RPC-H2: secure wss:// path. Certs come from the tlsConfig supplied
		// via SetTLSConfig(); we pass empty cert/key paths to ListenAndServeTLS
		// because http.Server.TLSConfig already carries Certificates.
		log.Printf("[WebSocket] Server listening on %s (wss://, TLS enabled)", addr)
		// RPC-R42-CI-RACE-3: use local `srv` (assigned under httpMu.Lock) for
		// the blocking Serve call; reading ws.httpServer here would race with
		// Stop's `ws.httpServer = nil` write performed inside stopOnce.Do.
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	}

	// Plaintext ws:// path — only safe behind a reverse proxy that terminates
	// TLS on a loopback/PRIVATE interface. Public internet deployments MUST
	// call SetTLSConfig() before Start() or front the listener with TLS.
	log.Printf("[WebSocket] Server listening on %s (ws://, no TLS — ensure reverse proxy terminates TLS for public exposure)", addr)
	// RPC-R42-CI-RACE-3: same as TLS branch — use local `srv` not ws.httpServer.
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Stop stops the WebSocket server
func (ws *WebSocketServer) Stop() {
	// RPC-FIX: make Stop idempotent so the "defer ws.Stop()" /
	// repeated-Stop test pattern does not race with a concurrent
	// Shutdown already in flight. The first call runs the shutdown
	// sequence; subsequent calls return immediately.
	ws.stopOnce.Do(func() {
		ws.cancel()
		// RPC-FIX: snapshot httpServer and shutdownTimeout under
		// httpMu so Stop does not race with Start's assignment of
		// httpServer or with SetShutdownTimeout. Once we have the local
		// snapshot, Shutdown/Wait run outside the lock so a stuck handler
		// cannot hold httpMu and block future Starts.
		ws.httpMu.Lock()
		srv := ws.httpServer
		timeout := ws.shutdownTimeout
		ws.httpServer = nil // prevent any second Stop path from touching the same *http.Server
		ws.httpMu.Unlock()
		if srv != nil {
			// R14-LOW (P2P-LOW-10): Previously hardcoded as 5*time.Second.
			// Promoted to ws.shutdownTimeout so deployments with many active
			// subscribers on slow links can extend it via SetShutdownTimeout.
			// Also log Shutdown errors at warn level instead of silently
			// dropping them (#nosec G104 removed) — operators should see if
			// graceful shutdown fails so they can investigate stale conns.
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				log.Printf("[WebSocket] graceful shutdown failed (timeout=%s): %v",
					timeout, err)
			}
		}

		// R30-IMPLEMENT (2026-07-27): Force-close all active WebSocket
		// connections to unblock handleConnection's read loop (which is
		// blocked on readMessage). Without this, handleConnection goroutines
		// remain blocked indefinitely after httpServer.Shutdown returns,
		// since hijacked connections are not tracked by http.Server.
		// Tracked by P2P-R15-H02.
		//
		// We collect the connection list under the lock, then close them
		// OUTSIDE the lock to avoid deadlocking with handleConnection's
		// cleanupConnection defer (which also acquires ws.mu).
		ws.mu.Lock()
		connsToClose := make([]*WSConn, 0, len(ws.connSubs))
		for c := range ws.connSubs {
			connsToClose = append(connsToClose, c)
		}
		ws.mu.Unlock()
		for _, c := range connsToClose {
			c.conn.Close() // #nosec G104 -- best-effort cleanup to unblock read loop //nolint:errcheck
		}

		// R30-IMPLEMENT (2026-07-27): Wait for all handleConnection goroutines
		// to exit before returning. This ensures no goroutine accesses an
		// already-closed connection after Stop() returns. We use a goroutine
		// + channel + timeout instead of a plain connWG.Wait() so a stuck
		// handler cannot block Stop() forever (e.g. a slow client write in
		// the middle of handleConnection's cleanup path). The timeout matches
		// ws.shutdownTimeout — by the time we reach here, httpServer.Shutdown
		// already gave subscribers time to finish, and we just force-closed
		// the connections, so handlers should exit within milliseconds.
		// Tracked by P2P-R15-H02.
		waitDone := make(chan struct{})
		go func() {
			ws.connWG.Wait()
			close(waitDone)
		}()
		select {
		case <-waitDone:
			// All handleConnection goroutines exited cleanly.
		case <-time.After(timeout):
			log.Printf("[WebSocket] Stop() timed out waiting for %d handleConnection goroutines after %s",
				atomic.LoadInt32(&ws.connCount), timeout)
		}
	})
}

// sendError sends an error response
func (ws *WebSocketServer) sendError(conn *WSConn, id any, err *Error) {
	// R30-P3 FIX: Sanitize internal error messages before sending to clients.
	// Prevents leakage of internal details (file paths, stack traces, DB errors)
	// through WebSocket error responses. Client-facing error codes (InvalidRequest,
	// Unauthorized, etc.) keep their descriptive messages for usability.
	sanitizedMsg := err.Message
	if err.Code == ErrCodeInternal {
		sanitizedMsg = sanitizeErrorMessage(err.Code)
	}
	sanitizedErr := &Error{Code: err.Code, Message: sanitizedMsg, Data: err.Data}
	resp := &Response{JSONRPC: JSONRPCVersion, Error: sanitizedErr, ID: id}
	data, marshalErr := json.Marshal(resp)
	if marshalErr != nil {
		log.Printf("[WebSocket] Failed to marshal error response: %v", marshalErr)
		return
	}
	if writeErr := ws.writeMessage(conn, data); writeErr != nil {
		log.Printf("[WebSocket] Failed to send error: %v", writeErr)
	}
}

// generateSubID generates a unique subscription ID using crypto/rand.
// audit-fix N-4: prevents attackers from predicting subscription IDs.
// Returns error if crypto/rand fails instead of panicking.
func generateSubID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(cryptorand.Reader, b); err != nil {
		return "", fmt.Errorf("crypto/rand.Read failed: %w", err)
	}
	return fmt.Sprintf("0x%x", b), nil
}
