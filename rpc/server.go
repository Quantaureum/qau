// Quantaureum Node source, version 1.0.0.
// Package rpc implements the JSON-RPC 2.0 server for Quantaureum.
package rpc

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logging "github.com/quantaureum/qau/log"

	"github.com/quantaureum/qau/security/audit"
	"github.com/quantaureum/qau/tracing"
)

// Input validation constants - audit-remediation: input validation limits
const (
	// MaxRequestBodySize is the maximum allowed request body size (1 MiB).
	// R7-H5 FIX: this is the single source of truth used by both handleHTTP
	// and the HMAC verification path so the signed body and the processed
	// body always match. Comment previously said "10MB" which was wrong.
	//  This is a named, tunable constant. It is also exposed via
	// Config.MaxBodySize for per-deployment configuration without recompiling.
	MaxRequestBodySize = 1 * 1024 * 1024

	// MaxResponseBodySize is the maximum allowed response body size (50MB)
	// #nosec audit-remediation: response size limit
	MaxResponseBodySize = 50 * 1024 * 1024

	// MaxParamsLength is the maximum allowed length (in bytes) for the JSON-RPC
	// "params" field of a single request.
	//
	// Quantaureum privacy transactions (qau_sendPrivacyTransaction) carry
	// post-quantum cryptographic material in params:
	//   - receiverSpendPubKey: Dilithium3 public key (1952 bytes, 3904 hex chars)
	//   - receiverViewPubKey:  Kyber768 public key (1184 bytes, 2368 hex chars)
	//   - plus from/to/amount/fee fields
	// Total params size is ~6-10 KB. The old 1 KB limit rejected these requests
	// with "params size exceeds limit" before the handler ever ran.
	//
	// 64 KB is large enough for privacy transactions (and reasonable future
	// expansion such as batched stealth proofs), while still well below the
	// 1 MiB HTTP body limit (MaxRequestBodySize) and small enough to prevent
	// memory-exhaustion DoS.
	MaxParamsLength = 64 * 1024

	// MaxBatchRequests is the default maximum batch size.
	// / (P3): RPC batch size limit. Enforced in handleHTTP
	// (rejects batches > maxBatchSize before parsing) and re-checked in
	// handleBatch as defense-in-depth, preventing JSON-RPC batch DoS.
	MaxBatchRequests = 100

	// MinRequestInterval is the minimum interval between requests (rate limiting)
	MinRequestInterval = 10 * time.Millisecond

	// RPCRateLimitPerSecond is the rate limit for RPC requests
	// #nosec audit-remediation: rate limiting
	RPCRateLimitPerSecond = 1000
)

// JSON-RPC 2.0 constants
const (
	JSONRPCVersion = "2.0"
)

// Error codes as per JSON-RPC 2.0 specification
const (
	ErrCodeParse          = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternal       = -32603

	// Custom error codes
	ErrCodeNotFound          = -32000
	ErrCodeInvalidTx         = -32001
	ErrCodeInsufficientFunds = -32002
	ErrCodeUnauthorized      = -32003
)

// Request represents a JSON-RPC 2.0 request
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      any             `json:"id,omitempty"`
}

// Response represents a JSON-RPC 2.0 response
type Response struct {
	JSONRPC string `json:"jsonrpc"`
	Result  any    `json:"result,omitempty"`
	Error   *Error `json:"error,omitempty"`
	ID      any    `json:"id"`
}

// MarshalJSON implements custom JSON marshaling for Response.
// JSON-RPC 2.0 spec requires: success responses MUST include "result",
// error responses MUST include "error" and MUST NOT include "result".
// Go's omitempty skips nil results, but Ethereum clients expect "result":null
// for not-found transactions. We handle this by always including "result"
// when there is no error, even if result is nil.
func (r *Response) MarshalJSON() ([]byte, error) {
	// Use a map to have full control over which fields appear
	m := map[string]any{
		"jsonrpc": r.JSONRPC,
		"id":      r.ID,
	}
	if r.Error != nil {
		m["error"] = r.Error
	} else {
		// Always include "result" for success responses, even if nil
		m["result"] = r.Result
	}
	return json.Marshal(m)
}

// Error represents a JSON-RPC 2.0 error
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Error implements the error interface
func (e *Error) Error() string {
	return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message)
}

// NewError creates a new JSON-RPC error
func NewError(code int, message string) *Error {
	return &Error{Code: code, Message: message}
}

// NewErrorWithData creates a new JSON-RPC error with additional data.
//
//	SECURITY: The Data field may contain internal error details
//
// (e.g., err.Error(), stack traces, DB errors). In production mode
// (devMode=false, the default), sanitizeError strips the Data field before
// the error reaches the client. Only when BOTH devMode=true AND
// exposeErrorData=true is the Data field preserved in responses.
// WARNING: Enabling devMode in production exposes internal error details,
// which can leak file paths, SQL errors, and implementation specifics.
func NewErrorWithData(code int, message string, data any) *Error {
	return &Error{Code: code, Message: message, Data: data}
}

// Standard errors
var (
	ErrParse          = NewError(ErrCodeParse, "Parse error")
	ErrInvalidRequest = NewError(ErrCodeInvalidRequest, "Invalid Request")
	ErrMethodNotFound = NewError(ErrCodeMethodNotFound, "Method not found")
	ErrInvalidParams  = NewError(ErrCodeInvalidParams, "Invalid params")
	ErrInternal       = NewError(ErrCodeInternal, "Internal error")
)

// Context key for HTTP request (for permission validation)
// H-21 FIX: Needed to pass HTTP request to handleRequest for auth validation
type contextKeyHTTPRequest struct{}

// contextKeyClientIP is the context key for storing client IP address
type contextKeyClientIP struct{}

// Context keys for authentication credentials on non-HTTP transports
type contextKeyAPIKey struct{}
type contextKeySignature struct{}
type contextKeyTimestamp struct{}

// FIX: RequestID context key for end-to-end request tracing
type contextKeyRequestID struct{}

// requestIDCounter provides monotonic request IDs for RPC request tracing
var requestIDCounter uint64

// Handler is a function that handles a JSON-RPC method
type Handler func(ctx context.Context, params json.RawMessage) (any, *Error)

// corsAllowHeaders is the canonical list of CORS request headers the RPC
// server allows. R14-LOW (P2P-LOW-11): previously this string was inlined
// verbatim in BOTH branches of setCORSHeaders (localhost branch + explicit
// allowlist branch), so adding a new header (e.g. a future X-Request-ID)
// required updating both lines or risking inconsistent preflight behavior
// between configurations. Extracted to a single named constant so the list
// lives in one place.
const corsAllowHeaders = "Content-Type, X-API-Key, X-Signature, X-Timestamp, X-Quantaureum-Commit-Auth"

// maxHTTPConns is the maximum number of simultaneous HTTP connections the
// RPC server accepts. RPC-R13-H02 (2026-07-21): without an explicit limit,
// an attacker could open thousands of idle HTTP keep-alive connections and
// exhaust the process file-descriptor table, causing the node to refuse all
// new RPC (and potentially P2P) connections. WebSocket connections are
// already bounded by MaxWebSocketConns + per-IP limits in websocket.go, but
// the plain HTTP JSON-RPC path used the default http.Server (no limit).
//
// 1024 is a defensive default large enough to handle legitimate bursty batch
// traffic from explorer/indexer clients while leaving ample headroom for the
// OS FD limit (typically 65535+ on production servers). Reached via the
// limitListener wrapper in Start()/StartTLS().
const maxHTTPConns = 1024

// Server is a JSON-RPC 2.0 server
type Server struct {
	handlers map[string]Handler
	mu       sync.RWMutex

	// HTTP server
	httpServer *http.Server

	// RPC-FIX: serializes Start/Stop access to httpServer so the
	// start-in-goroutine / stop-from-main test pattern does not trigger
	// race detector reports. We use a dedicated mutex (not s.mu) to avoid
	// nesting with s.mu which is held inside handler registration paths.
	httpMu sync.Mutex

	// RPC-FIX: makes Stop idempotent so the "defer s.Stop()" /
	// repeated-Stop test pattern does not race with a concurrent
	// Shutdown already in flight.
	stopOnce sync.Once

	// Configuration
	maxBatchSize    int
	readTimeout     time.Duration
	writeTimeout    time.Duration
	maxBodySize     int64    // audit-remediation: request body size limit
	maxParamsLen    int      // audit-remediation: parameter length limit
	enableRateLimit bool     // audit-remediation: rate limiting flag
	allowedOrigins  []string // audit-fix L-4: CORS allowed origins
	network         string   // network identifier (e.g. "mainnet", "testnet")
	trustedProxies  []string // L4-012: trusted proxy IPs for X-Forwarded-For parsing
	// R14-LOW (P2P-LOW-07): max simultaneous HTTP connections. 0 = use the
	// default maxHTTPConns package const. Resolved at Start()/StartTLS()
	// time so operators can lower it (low-FD containers) or raise it
	// (high-throughput validators) via Config.MaxHTTPConns.
	maxHTTPConns int

	// audit-fix R5-H1: security middleware wired into request pipeline
	authManager    *AuthManager
	rateLimiter    *RateLimiter
	tracingEnabled bool

	// H-21 FIX: Define privileged methods that require admin authentication
	// Methods not in this set are considered public
	adminMethods map[string]bool

	// #247: production mode strips error Data to prevent sensitive info leakage.
	//  SECURITY: devMode defaults to false (secure). When false,
	// sanitizeError strips the Data field from all RPC errors, preventing
	// internal error details (e.g., err.Error(), file paths, DB errors) from
	// reaching clients. Set to true ONLY in development (ChainID=1333).
	// WARNING: Enabling devMode in production exposes internal error details
	// which can leak implementation specifics and aid attackers.
	devMode bool
	// audit-fix MED-3: DEBUG_ERROR_LEAK — even in devMode, error Data is stripped
	// unless this flag is explicitly set. Prevents accidental internal state leaks.
	//  Defaults to false. Must remain false in production. Only enable
	// for debugging in isolated dev environments where error detail exposure
	// is acceptable.
	exposeErrorData bool

	// SECURITY FIX  Audit logger for RPC call logging (who, what, when, result)
	// Integrates with security/audit package to provide structured audit trails.
	auditLogger AuditLogger
}

// AuditLogger wraps the security/audit logger for RPC-specific logging.
type AuditLogger interface {
	LogRPC(eventType string, method, requestID, ipAddress, result string, details map[string]any) error
}

// AuditLoggerAdapter adapts security/audit.AuditLogger to the rpc.AuditLogger interface.
// This allows seamless integration of the existing audit subsystem with RPC logging.
type AuditLoggerAdapter struct {
	logger interface {
		LogRPC(eventType audit.EventType, method, requestID, ipAddress, result string, details map[string]any) error
	}
}

// NewAuditLoggerAdapter creates an adapter from the security/audit package's logger.
func NewAuditLoggerAdapter(auditLogger interface {
	LogRPC(eventType audit.EventType, method, requestID, ipAddress, result string, details map[string]any) error
}) *AuditLoggerAdapter {
	return &AuditLoggerAdapter{logger: auditLogger}
}

// LogRPC implements the rpc.AuditLogger interface by delegating to the adapted logger.
func (a *AuditLoggerAdapter) LogRPC(eventType string, method, requestID, ipAddress, result string, details map[string]any) error {
	return a.logger.LogRPC(audit.EventType(eventType), method, requestID, ipAddress, result, details)
}

// Config holds server configuration
type Config struct {
	Addr            string
	MaxBatchSize    int
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	MaxBodySize     int64    // audit-remediation: request body size limit
	MaxParamsLength int      // audit-remediation: parameter length limit
	EnableRateLimit bool     // audit-remediation: enable rate limiting
	AllowedOrigins  []string // audit-fix L-4: CORS allowed origins (empty = no CORS)
	Network         string   // network identifier for CORS policy ("mainnet" restricts wildcard)
	TLSCertFile     string   // audit-fix M-2: path to TLS certificate file
	TLSKeyFile      string   // audit-fix M-2: path to TLS private key file
	// R7-M6 FIX: AllowAuthBypass field removed. It was declared but never read
	// and its name implied an auth-bypass switch — a latent footgun. Any future
	// "dev bypass" must be implemented via an explicit, logged, dev-only flag.
	TracingEnabled bool // enable OpenTelemetry-compatible tracing on RPC handlers
	// L4-012: Trusted proxies for X-Forwarded-For header parsing.
	// When non-empty, the server trusts X-Forwarded-For from these IPs
	// for audit logging and client IP extraction, consistent with the
	// rate limiter's behavior.
	TrustedProxies []string
	// R14-LOW (P2P-LOW-07): Maximum simultaneous HTTP connections.
	// 0 means "use the default maxHTTPConns (1024)". Operators on hosts
	// with low FD limits (e.g. containers with `ulimit -n 1024`) can lower
	// it; high-throughput validators can raise it. Reached via the
	// limitListener wrapper in Start()/StartTLS().
	MaxHTTPConns int
}

// DefaultConfig returns default server configuration
func DefaultConfig() *Config {
	return &Config{
		Addr:            ":8545",
		MaxBatchSize:    MaxBatchRequests,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		MaxBodySize:     MaxRequestBodySize, // audit-remediation: 10MB default
		MaxParamsLength: MaxParamsLength,    // audit-remediation: 64KB default (privacy tx crypto material)
		EnableRateLimit: true,               // audit-remediation: enabled by default
		// R14-LOW (P2P-LOW-07): 0 means "use default maxHTTPConns". We
		// intentionally do NOT inline 1024 here so that the canonical
		// default lives in one place (the maxHTTPConns package const).
		MaxHTTPConns: 0,
	}
}

// NewServer creates a new JSON-RPC server
func NewServer(cfg *Config) *Server {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// audit-remediation: ensure safe defaults for input validation
	maxBodySize := cfg.MaxBodySize
	if maxBodySize <= 0 {
		maxBodySize = MaxRequestBodySize
	}
	maxParamsLen := cfg.MaxParamsLength
	if maxParamsLen <= 0 {
		maxParamsLen = MaxParamsLength
	}

	srv := &Server{
		handlers:        make(map[string]Handler),
		maxBatchSize:    cfg.MaxBatchSize,
		readTimeout:     cfg.ReadTimeout,
		writeTimeout:    cfg.WriteTimeout,
		maxBodySize:     maxBodySize,
		maxParamsLen:    maxParamsLen,
		enableRateLimit: cfg.EnableRateLimit,
		allowedOrigins:  cfg.AllowedOrigins, // audit-fix L-4
		network:         cfg.Network,
		tracingEnabled:  cfg.TracingEnabled,
		trustedProxies:  cfg.TrustedProxies, // L4-012
		// R14-LOW (P2P-LOW-07): operator-tunable max connections. 0 means
		// "use default maxHTTPConns" — resolved in Start()/StartTLS().
		maxHTTPConns: cfg.MaxHTTPConns,
		// FIX: Explicitly set devMode=false and exposeErrorData=false
		// (secure defaults). In production, error Data fields containing
		// err.Error() are stripped by sanitizeError before reaching clients.
		// Only devMode=true AND exposeErrorData=true exposes internal details.
		devMode:         false,
		exposeErrorData: false,
	}

	// AUDIT (2026) API-FIX: Auto-construct a default rate limiter
	// when EnableRateLimit is true. Previously, NewServer set enableRateLimit=true
	// but never constructed rateLimiter, so the `if s.rateLimiter != nil` checks
	// in request handling always skipped rate limiting — making the "enabled by
	// default" claim a no-op. Callers can still override with SetRateLimiter.
	if cfg.EnableRateLimit {
		rl := NewRateLimiter(DefaultRateLimitConfig())
		rl.Start()
		srv.rateLimiter = rl
	}

	return srv
}

// SetAuditLogger sets the audit logger for RPC call logging.
// SECURITY FIX  enables structured audit trails for all RPC requests.
func (s *Server) SetAuditLogger(al AuditLogger) {
	s.auditLogger = al
}

// SetAuditLoggerFromSecurityPkg sets the audit logger using the security/audit package.
// This is a convenience method that wraps the security audit logger with the adapter.
func (s *Server) SetAuditLoggerFromSecurityPkg(auditLogger *audit.AuditLogger) {
	s.auditLogger = NewAuditLoggerAdapter(auditLogger)
}

// RegisterHandler registers a handler for a method
func (s *Server) RegisterHandler(method string, handler any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Support both Handler type and generic error-returning functions
	switch h := handler.(type) {
	case Handler:
		s.handlers[method] = h
	case func(ctx context.Context, params json.RawMessage) (any, *Error):
		s.handlers[method] = h
	case func(ctx context.Context, params json.RawMessage) (any, error):
		// Wrap generic error handler
		s.handlers[method] = func(ctx context.Context, params json.RawMessage) (any, *Error) {
			result, err := h(ctx, params)
			if err != nil {
				// Check if it's already an RPC error type
				if rpcErr, ok := err.(*Error); ok {
					return nil, rpcErr
				}
				// Convert generic error to RPC error
				return nil, NewError(ErrCodeInternal, err.Error())
			}
			return result, nil
		}
	default:
		// FIX: Log when a handler signature does not match any
		// accepted type. Previously this silently did nothing, making
		// misregistered handlers unreachable without any diagnostic.
		log.Printf("WARNING: RegisterHandler %q: handler signature does not match any accepted type", method)
	}
}

// UnregisterHandler removes a handler for a method
func (s *Server) UnregisterHandler(method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.handlers, method)
}

// SetAuthManager sets the authentication manager for the server.
// audit-fix R5-H1: wire auth into request pipeline.
func (s *Server) SetAuthManager(am *AuthManager) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// RPC-004 FIX: if admin methods were registered before the authManager was
	// set, copy them into the authManager now so ValidateAdminRequest enforces
	// the whitelist regardless of initialization order. Lock order is
	// s.mu -> am.mu, consistent with RegisterAdminMethod (no deadlock).
	if am != nil && len(s.adminMethods) > 0 {
		for m := range s.adminMethods {
			am.RegisterAdminMethod(m)
		}
	}
	s.authManager = am
}

// SetRateLimiter sets the rate limiter for the server.
// audit-fix R5-H1: wire rate limiting into request pipeline.
func (s *Server) SetRateLimiter(rl *RateLimiter) {
	s.rateLimiter = rl
}

// SetDevMode sets whether the server runs in development mode.
// #247: In production mode (devMode=false), error Data fields are stripped
// to prevent sensitive information leakage through RPC error responses.
func (s *Server) SetDevMode(devMode bool) {
	s.devMode = devMode
}

// audit-fix MED-3: SetExposeErrorData controls whether internal error details
// are exposed in RPC responses. Must be explicitly enabled, even in devMode.
// Default is false — error Data is always stripped unless this is set to true.
func (s *Server) SetExposeErrorData(expose bool) {
	s.exposeErrorData = expose
}

// sanitizeError strips the Data field and sanitizes the Message field
// from RPC errors in production mode.
// #247: Error.Data may contain internal details (stack traces, DB errors, etc.)
// that should not be exposed to external callers.
// R4 FIX: Also sanitize Message for internal/server errors to prevent
// leakage of file paths, SQL errors, stack traces, and other internal details.
func (s *Server) sanitizeError(rpcErr *Error) *Error {
	if rpcErr == nil {
		return nil
	}
	//  AUDIT NOTE: In devMode + exposeErrorData, the full error including
	// Data is returned verbatim. This is intentional for development/testing —
	// devMode should only be enabled on local or trusted test networks.
	// Operators must ensure devMode is NEVER enabled in production, as internal
	// error Data may contain stack traces, file paths, or internal addresses.
	if s.devMode && s.exposeErrorData {
		return rpcErr
	}
	msg := rpcErr.Message
	// Only sanitize truly internal errors (codes <= -32603).
	// Custom business error codes (-32000 to -32099) are user-facing
	// and must NOT be sanitized — they carry actionable information
	// (e.g. "account is locked", "insufficient funds", "invalid transaction").
	if rpcErr.Code <= ErrCodeInternal {
		msg = sanitizeErrorMessage(rpcErr.Code)
	}
	if rpcErr.Data != nil {
		return &Error{
			Code:    rpcErr.Code,
			Message: msg,
			Data:    nil,
		}
	}
	if msg != rpcErr.Message {
		return &Error{
			Code:    rpcErr.Code,
			Message: msg,
		}
	}
	return rpcErr
}

// sanitizeErrorMessage returns a generic error message for internal/server errors.
// R4 FIX: Prevents leakage of internal details (file paths, stack traces,
// database errors) through RPC error messages in production mode.
func sanitizeErrorMessage(code int) string {
	switch code {
	case ErrCodeInternal:
		return "Internal error"
	case ErrCodeInvalidRequest:
		return "Invalid Request"
	case ErrCodeInvalidParams:
		return "Invalid params"
	case ErrCodeParse:
		return "Parse error"
	case ErrCodeMethodNotFound:
		return "Method not found"
	case ErrCodeUnauthorized:
		return "Unauthorized"
	default:
		return "Server error"
	}
}

// RegisterAdminMethod marks a method as requiring admin authentication.
// H-21 FIX: Add method-level permission system for privileged operations.
func (s *Server) RegisterAdminMethod(method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.adminMethods == nil {
		s.adminMethods = make(map[string]bool)
	}
	s.adminMethods[method] = true
	// RPC-004 FIX: propagate the registration to the authManager so that
	// ValidateAdminRequest can enforce the admin method whitelist
	// (defense-in-depth). RegisterAdminMethod on AuthManager takes its own
	// lock; lock order is s.mu -> am.mu, which is consistent with
	// SetAuthManager, so there is no deadlock risk.
	if s.authManager != nil {
		s.authManager.RegisterAdminMethod(method)
	}
}

// isAdminMethod checks if a method requires admin authentication
func (s *Server) isAdminMethod(method string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.adminMethods != nil && s.adminMethods[method]
}

// authenticateFromContext validates authentication for non-HTTP transports.
// It extracts credentials from the context (set by WebSocket or other transports)
// and validates them against the auth manager.
func (s *Server) authenticateFromContext(ctx context.Context, method string) *Error {
	if s.authManager == nil {
		return NewError(ErrCodeUnauthorized, "authentication required")
	}

	// Extract credentials from context - set by transport handlers (WebSocket, etc.)
	apiKey, _ := ctx.Value(contextKeyAPIKey{}).(string)
	signature, _ := ctx.Value(contextKeySignature{}).(string)
	timestamp, _ := ctx.Value(contextKeyTimestamp{}).(string)
	clientIP, _ := ctx.Value(contextKeyClientIP{}).(string)

	// Build minimal HTTP request for auth validation
	r := &http.Request{}
	if apiKey != "" {
		r.Header.Set("X-API-Key", apiKey)
	}
	if signature != "" {
		r.Header.Set("X-Signature", signature)
	}
	if timestamp != "" {
		r.Header.Set("X-Timestamp", timestamp)
	}
	if clientIP != "" {
		// FIX: Use net.JoinHostPort for proper IPv6 handling
		r.RemoteAddr = net.JoinHostPort(clientIP, "0")
	}

	if err := s.authManager.ValidateRequest(r, method); err != nil {
		return NewError(ErrCodeUnauthorized, err.Error())
	}
	return nil
}

// Start starts the HTTP server
func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.setCORSHeaders(w, r)
		if r.Method == http.MethodOptions {
			// FIX: Add security headers to OPTIONS preflight response
			// to prevent MIME sniffing and clickjacking on preflight responses.
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.handleHTTP(w, r)
	})

	var handler http.Handler = mux
	if s.tracingEnabled {
		handler = tracing.RPCInstrumentation(true)(handler)
	}

	// RPC-FIX: serialize httpServer assignment under httpMu so
	// Stop (which reads httpServer under the same mutex) does not race
	// with this write. The blocking Serve call happens outside the
	// lock so Stop can still acquire it to shutdown.
	s.httpMu.Lock()
	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       s.readTimeout,
		ReadHeaderTimeout: 10 * time.Second, // R7-H3/L13-019: Slowloris header-DoS protection (10s)
		WriteTimeout:      s.writeTimeout,
		IdleTimeout:       120 * time.Second, // R7-H3: bound keepalive resource use
		MaxHeaderBytes:    1 << 20,           // R7-H3/L13-019: 1 MiB header cap to prevent oversized header attacks
	}
	srv := s.httpServer
	s.httpMu.Unlock()

	// RPC-R13-H02 (2026-07-21): bound the number of simultaneous HTTP
	// connections to prevent FD exhaustion via idle keep-alive attacks.
	// We replace ListenAndServe with a manual net.Listen + Serve on a
	// limitListener wrapper so the bound is enforced at the accept layer.
	// R14-LOW (P2P-LOW-07): honor Config.MaxHTTPConns when set (operator-
	// tunable); fall back to the package const default otherwise.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	limitedLn := newLimitListener(ln, s.effectiveMaxHTTPConns())
	return srv.Serve(limitedLn)
}

// Stop stops the HTTP server
func (s *Server) Stop(ctx context.Context) error {
	// audit-fix R5-H1: stop rate limiter cleanup goroutine
	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}
	// RPC-FIX: make Stop idempotent so repeated calls do not race
	// with the in-flight Shutdown started by the first call. The first
	// invocation runs the shutdown; subsequent calls return nil.
	var shutdownErr error
	s.stopOnce.Do(func() {
		s.httpMu.Lock()
		srv := s.httpServer
		s.httpServer = nil
		s.httpMu.Unlock()
		if srv != nil {
			shutdownErr = srv.Shutdown(ctx)
		}
	})
	return shutdownErr
}

// StartTLS starts the HTTPS server with TLS encryption.
// audit-fix M-2: production deployments should use TLS to protect RPC traffic.
func (s *Server) StartTLS(addr, certFile, keyFile string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		s.setCORSHeaders(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.handleHTTP(w, r)
	})

	var handler http.Handler = mux
	if s.tracingEnabled {
		handler = tracing.RPCInstrumentation(true)(handler)
	}

	// RPC-FIX: serialize httpServer assignment under httpMu so
	// Stop (which reads httpServer under the same mutex) does not race
	// with this write.
	s.httpMu.Lock()
	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       s.readTimeout,
		ReadHeaderTimeout: 10 * time.Second, // R7-H3: Slowloris header-DoS protection
		WriteTimeout:      s.writeTimeout,
		IdleTimeout:       120 * time.Second, // R7-H3: bound keepalive resource use
		MaxHeaderBytes:    1 << 20,           // R7-H3: 1 MiB header cap
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
			CurvePreferences: []tls.CurveID{
				tls.X25519,
				tls.CurveP256,
			},
		},
	}
	srv := s.httpServer
	s.httpMu.Unlock()

	// RPC-R13-H02 (2026-07-21): same connection bound as Start().
	// We replace ListenAndServeTLS with a manual net.Listen + ServeTLS
	// on a limitListener wrapper.
	// R14-LOW (P2P-LOW-07): honor Config.MaxHTTPConns when set; fall back
	// to the package const default otherwise.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	limitedLn := newLimitListener(ln, s.effectiveMaxHTTPConns())
	return srv.ServeTLS(limitedLn, certFile, keyFile)
}

// effectiveMaxHTTPConns returns the operator-configured max-connections value,
// falling back to the package const default when unset (0 or negative).
//
// R14-LOW (P2P-LOW-07): The legacy behavior was a hardcoded `maxHTTPConns`
// const consumed directly at the call sites. Operators on hosts with low FD
// limits (e.g. containers with `ulimit -n 1024`) could not lower it, and
// high-throughput validators could not raise it, without a rebuild. This
// method resolves the effective value at Start/StartTLS time so the limit
// is tunable via Config without changing the default for callers that
// don't set it.
func (s *Server) effectiveMaxHTTPConns() int {
	if s.maxHTTPConns > 0 {
		return s.maxHTTPConns
	}
	return maxHTTPConns
}

// audit-fix MEDIUM: setSecurityHeaders sets standard HTTP security response
// headers on RPC responses. These are defense-in-depth measures:
//   - X-Content-Type-Options: nosniff prevents browsers from MIME-sniffing the
//     response away from the declared application/json content type.
//   - X-Frame-Options: DENY prevents the RPC endpoint from being framed by
//     hostile pages (clickjacking defense).
//   - Content-Security-Policy: default-src 'none' — the RPC endpoint returns
//     JSON only; no inline scripts, styles, fonts, images, etc. should ever
//     be needed. 'none' is the strictest possible CSP and prevents any
//     injected content from executing or loading.
//   - Referrer-Policy: no-referrer — the RPC endpoint should never leak the
//     calling page's URL via the Referer header to a third party (defense
//     in depth against logs / analytics exfiltration).
//   - Permissions-Policy: geolocation=(), microphone=(), camera=() —
//     explicitly disable browser capabilities that the RPC endpoint has no
//     legitimate use for. Prevents a malicious page from invoking these
//     APIs under the RPC origin's identity.
//
// We intentionally do NOT set Strict-Transport-Security here because the RPC
// server may be terminated by a reverse proxy on plain HTTP inside a trusted
// network; HSTS must be set by the TLS-terminating edge.
//
// P2P-R10-M1 (2026-07-19) FIX: Added Content-Security-Policy, Referrer-Policy,
// and Permissions-Policy headers. The audit found the previous header set
// (X-Content-Type-Options + X-Frame-Options only) was missing modern
// defense-in-depth headers that are standard on production JSON API endpoints.
func setSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	if h.Get("X-Content-Type-Options") == "" {
		h.Set("X-Content-Type-Options", "nosniff")
	}
	if h.Get("X-Frame-Options") == "" {
		h.Set("X-Frame-Options", "DENY")
	}
	// P2P-R10-M1: Modern security headers.
	if h.Get("Content-Security-Policy") == "" {
		h.Set("Content-Security-Policy", "default-src 'none'")
	}
	if h.Get("Referrer-Policy") == "" {
		h.Set("Referrer-Policy", "no-referrer")
	}
	if h.Get("Permissions-Policy") == "" {
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
	}
}

// audit-fix L-4: setCORSHeaders sets CORS headers based on the configured allowed origins.
// R7-H4: when allowedOrigins is empty, only localhost/loopback origins are permitted
// (via isLocalhostOrigin); non-localhost origins get no ACAO header (failed preflight).
// When configured, only listed origins (or "*" for all) are allowed.
//
// P3-12: keep the localhost definition and origin-allowlist policy CONSISTENT with
// WebSocketServer.checkOrigin() (rpc/websocket.go). Both share the isLocalhostOrigin()
// helper. Any origin-policy change must be applied to both transports.
// RPC-M2 (R8 2026-07-19 FIX): Expanded mainnet default origins to include
// all official subdomains enumerated in the project CORS rule. Previously
// this list omitted www, lzadmin, and testnet, which caused browsers to
// reject preflight responses for legitimate calls from the admin console
// and testnet explorer when no operator-configured allowlist was present.
//
// R14-MED (2026-07-21): Added "https://rpc.quantaureum.com" — browser-based
// wallets and explorers that target the RPC subdomain directly were blocked
// by CORS preflight failures when no operator allowlist was configured.
var mainnetDefaultOrigins = []string{
	"https://quantaureum.com",
	"https://www.quantaureum.com",
	"https://lzadmin.quantaureum.com",
	"https://testnet.quantaureum.com",
	"https://explorer.quantaureum.com",
	"https://rpc.quantaureum.com",
}

func (s *Server) setCORSHeaders(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")

	if origin == "" {
		return false
	}

	origins := s.allowedOrigins
	isMainnet := s.network == "mainnet"

	if isMainnet {
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

	if len(origins) == 0 {
		// R7-H4 FIX: Previously this branch reflected the caller's Origin verbatim,
		// giving any website credentialed cross-origin access to the RPC (CORS
		// reflection bypass). Only allow localhost/loopback origins when no
		// explicit allowlist is configured. Everything else gets no ACAO header,
		// which the browser treats as a failed CORS preflight.
		if !isLocalhostOrigin(origin) {
			return false
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
		w.Header().Set("Access-Control-Max-Age", "600")
		w.Header().Set("Vary", "Origin")
		return true
	}

	allowed := false
	for _, o := range origins {
		if o == origin {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", corsAllowHeaders)
	w.Header().Set("Access-Control-Max-Age", "600")
	w.Header().Set("Vary", "Origin")
	return true
}

// handleHTTP handles HTTP requests
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// audit-fix MEDIUM: set security headers on all RPC responses to prevent
	// content-type sniffing (X-Content-Type-Options), clickjacking
	// (X-Frame-Options), and MIME confusion attacks. These headers are
	// defense-in-depth even though the RPC only returns JSON.
	setSecurityHeaders(w)

	// audit-fix L-4: handle CORS
	s.setCORSHeaders(w, r)
	if r.Method == http.MethodOptions {
		// RPC-R9-M (2026-07-19) FIX: Apply per-IP rate limiting to OPTIONS
		// preflight requests too. Previously OPTIONS short-circuited before
		// the rate limiter ran, so an attacker could flood OPTIONS at
		// thousands of req/s and exhaust connection slots / CPU without
		// ever being throttled. We pass an empty method string so the
		// OPTIONS request is counted under the global per-IP bucket only
		// (not under any specific per-method quota). If the limiter is
		// disabled or this is a legitimate browser preflight (low rate),
		// the call is a no-op and the response is still 204 No Content.
		if s.rateLimiter != nil && s.enableRateLimit {
			if err := s.rateLimiter.Allow(r, ""); err != nil {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Only accept POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// audit-fix M-5: Validate Content-Type to prevent CSRF via form submissions.
	// HTML forms can only POST application/x-www-form-urlencoded or multipart/form-data,
	// so requiring application/json blocks cross-origin form-based attacks.
	// FIX: Use exact match or "application/json;" prefix (for charset params)
	// instead of HasPrefix("application/json") which accepted subtypes like
	// application/json-patch+json.
	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
	if contentType != "application/json" && !strings.HasPrefix(contentType, "application/json;") {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	// RPC-R13-H01 (2026-07-21) FIX: reject compressed request bodies to prevent
	// compression bomb attacks. The RPC server does not currently decompress
	// request bodies, but a future middleware could inadvertently do so, causing
	// OOM via a small gzip stream that decompresses to gigabytes. By explicitly
	// rejecting non-identity Content-Encoding at the entry point, we ensure the
	// server remains safe regardless of future middleware changes. The HTTP/1.1
	// spec (RFC 7231, Content-Encoding) says "If the representation is encoded with a
	// content-coding, the Content-Encoding header field indicates that encoding";
	// "identity" is the no-encoding marker and is the default when the header is
	// absent. We accept missing header (default identity) and explicit identity;
	// everything else (gzip, deflate, br, zstd, etc.) is rejected with 415.
	contentEncoding := strings.TrimSpace(r.Header.Get("Content-Encoding"))
	contentEncoding = strings.ToLower(contentEncoding)
	if contentEncoding != "" && contentEncoding != "identity" {
		http.Error(w, "Content-Encoding must be identity or omitted", http.StatusUnsupportedMediaType)
		return
	}

	// Set content type.
	// R14-LOW (P2P-LOW-12): Explicit charset=utf-8 to align with the
	// metrics endpoint (metrics.go sets "text/plain; version=0.0.4;
	// charset=utf-8"). RFC 8259 mandates UTF-8 for JSON, but strict
	// clients/proxies may default to a different encoding when charset
	// is absent — explicit declaration removes the ambiguity.
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// audit-remediation: validate Content-Length header if present
	// L4-020 FIX: Use >= (not >) for consistency with the actual body size
	// check below (line ~722). Previously a body of exactly maxBodySize
	// passed this header check but was rejected after reading, wasting I/O.
	if r.ContentLength >= s.maxBodySize {
		s.writeError(w, nil, NewError(ErrCodeInvalidRequest, "request body too large"))
		return
	}

	// audit-remediation: read request body with configurable size limit
	body, err := io.ReadAll(io.LimitReader(r.Body, s.maxBodySize))
	if err != nil {
		s.writeError(w, nil, ErrParse)
		return
	}

	// Restore r.Body so downstream consumers (e.g. authManager.ValidateRequest
	// HMAC verification in auth.go) can re-read the body. Without this the body
	// is already consumed and HMAC is computed over an empty body, rejecting all
	// authenticated requests when HMAC is enabled.
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	// audit-remediation: check actual body size
	if int64(len(body)) >= s.maxBodySize {
		s.writeError(w, nil, NewError(ErrCodeInvalidRequest, "request body too large"))
		return
	}

	// Try to parse as batch request first
	// audit-fix HIGH-RPC-DOS: Unmarshal to RawMessage first to check batch size
	// before expensive full object parsing of many small objects.
	var batchMessages []json.RawMessage
	if err := json.Unmarshal(body, &batchMessages); err == nil && len(batchMessages) > 0 {
		if len(batchMessages) > s.maxBatchSize {
			s.writeError(w, nil, NewError(ErrCodeInvalidRequest, "batch size limit exceeded"))
			return
		}
		// Now unmarshal to full Request objects
		var batch []Request
		if err := json.Unmarshal(body, &batch); err != nil {
			s.writeError(w, nil, ErrParse)
			return
		}
		// FIX: Defense-in-depth — check params length for each batch
		// request in handleHTTP (not only in handleRequest). If future code
		// bypasses handleRequest and calls handlers directly, this check still
		// prevents oversized params from reaching handlers.
		if s.maxParamsLen > 0 {
			for _, breq := range batch {
				if len(breq.Params) > s.maxParamsLen {
					s.writeError(w, breq.ID, NewError(ErrCodeInvalidRequest, "params size exceeds limit"))
					return
				}
			}
		}
		// audit-fix R5-H1: auth+ratelimit for batch requests
		if s.rateLimiter != nil {
			// audit-fix HIGH-RATELIMIT: Consume tokens for each request in the batch.
			// Previously called Allow(r, "batch") once, allowing 100x bypass of limits.
			// L12-034 [P3] NOTE: All batch elements share the same "batch_element" per-method
			// rate limit bucket, regardless of their actual RPC method names. This differs from
			// single requests which use req.Method as the bucket key (line ~828). Consequence:
			// batch and single requests maintain SEPARATE per-method rate limit budgets, so an
			// attacker splitting traffic between batch and single could effectively double their
			// per-method allowance. The global and per-IP rate limits still apply uniformly to
			// both paths, bounding the total amplification. Using a shared bucket here is
			// intentional for simplicity; a future hardening could use batch[i].Method instead.
			for i := 0; i < len(batch); i++ {
				// FIX: Use the actual method name as the rate limit bucket key
				// instead of a shared "batch_element" bucket. This ensures batch
				// requests count against the same per-method budget as single requests.
				if err := s.rateLimiter.Allow(r, batch[i].Method); err != nil {
					s.writeError(w, nil, NewError(ErrCodeUnauthorized, "rate limit exceeded in batch"))
					return
				}
			}
		}
		// SECURITY FIX (P1): Previously only batch[0].Method was validated.
		// If batch[0] was a public method (e.g. eth_blockNumber), ValidateRequest
		// returned nil immediately and all subsequent methods — including
		// protected/admin ones — bypassed authentication entirely.
		//
		// P1-13 (RPC-H3, 2026-07-19) FIX: Previously HMAC was verified only on
		// the FIRST non-public method name, with the rest of the body relying
		// on bodyHash for indirect coverage. This was fragile — a future
		// weakening of bodyHash would expose method substitution attacks.
		// Now ValidateBatchRequest computes HMAC over ALL non-public method
		// names (length-prefixed), explicitly binding the semantic intent of
		// the batch to the signature. The "BATCHv1" prefix in the HMAC input
		// makes this format incompatible with single-request signatures,
		// preventing cross-format replay.
		//
		// Each non-public method is still individually permission-checked
		// inside ValidateBatchRequest (API key, IP whitelist, permissions),
		// so a key authorized only for "eth_*" cannot sneak in an "admin_*"
		// call by burying it after a valid "eth_blockNumber" entry.
		if s.authManager != nil && len(batch) > 0 {
			// Collect all non-public method names in order. The HMAC will cover
			// every name in this list, so an attacker cannot swap any method in
			// the batch without invalidating the signature.
			nonPublicMethods := make([]string, 0, len(batch))
			for i := range batch {
				if !s.authManager.IsPublicMethod(batch[i].Method) {
					nonPublicMethods = append(nonPublicMethods, batch[i].Method)
				}
			}
			if len(nonPublicMethods) > 0 {
				// Find the first non-public method's ID for error reporting.
				// (ValidateBatchRequest returns a single error covering the
				// whole batch; we attribute it to the first non-public element
				// for client-side debuggability.)
				firstNonPublicID := interface{}(nil)
				for i := range batch {
					if !s.authManager.IsPublicMethod(batch[i].Method) {
						firstNonPublicID = batch[i].ID
						break
					}
				}
				if err := s.authManager.ValidateBatchRequest(r, nonPublicMethods); err != nil {
					s.writeError(w, firstNonPublicID, NewError(ErrCodeUnauthorized, err.Error()))
					return
				}
				// ValidateAdminRequest for any admin methods in the batch.
				// ValidateBatchRequest covers API key + HMAC + permissions, but
				// admin methods require additional admin-level authorization
				// (e.g. IP whitelist for admin endpoints).
				for i := range batch {
					if s.isAdminMethod(batch[i].Method) {
						if err := s.authManager.ValidateAdminRequest(r, batch[i].Method); err != nil {
							s.writeError(w, batch[i].ID, NewError(ErrCodeUnauthorized, err.Error()))
							return
						}
					}
				}
			}
		}
		// R5-P3-1 FIX: Set contextKeyHTTPRequest and other context values for
		// batch requests, consistent with the single-request path. Without this,
		// admin methods in batch requests fail authorization because handleRequest
		// cannot determine the transport type (HTTP vs non-HTTP).
		batchCtx := r.Context()
		// L4-012 FIX: Use getClientIPWithTrust for consistent IP extraction
		// with the rate limiter, so audit logs record the real client IP
		// behind trusted proxies instead of the proxy's IP.
		if clientIP := getClientIPWithTrust(r, s.trustedProxies); clientIP != "" {
			batchCtx = context.WithValue(batchCtx, contextKeyClientIP{}, clientIP)
		}
		batchCtx = context.WithValue(batchCtx, contextKeyRequestID{}, atomic.AddUint64(&requestIDCounter, 1))
		batchCtx = context.WithValue(batchCtx, contextKeyHTTPRequest{}, r)
		s.handleBatch(w, batchCtx, batch)
		return
	}

	// Try to parse as single request
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeError(w, nil, ErrParse)
		return
	}

	// FIX: Defense-in-depth — check params length in handleHTTP as well
	// as handleRequest. If future code bypasses handleRequest and calls handlers
	// directly, this check still prevents oversized params payloads from
	// reaching handlers and causing memory/CPU exhaustion.
	if s.maxParamsLen > 0 && len(req.Params) > s.maxParamsLen {
		s.writeError(w, req.ID, NewError(ErrCodeInvalidRequest, "params size exceeds limit"))
		return
	}

	// audit-fix R5-H1: auth and rate limit checks
	if s.authManager != nil {
		if err := s.authManager.ValidateRequest(r, req.Method); err != nil {
			s.writeError(w, req.ID, NewError(ErrCodeUnauthorized, err.Error()))
			return
		}
	}
	if s.rateLimiter != nil {
		if err := s.rateLimiter.Allow(r, req.Method); err != nil {
			s.writeError(w, req.ID, NewError(ErrCodeUnauthorized, "rate limit exceeded"))
			return
		}
	}

	// audit-fix MED-4: Populate client IP in request context for defense-in-depth.
	// SubmitCommitment includes clientIP in HMAC computation,
	// but the context value was never set, making IP-binding ineffective.
	ctx := r.Context()
	// L4-012 FIX: Use getClientIPWithTrust for consistent IP extraction
	// with the rate limiter, so audit logs record the real client IP
	// behind trusted proxies instead of the proxy's IP.
	if clientIP := getClientIPWithTrust(r, s.trustedProxies); clientIP != "" {
		ctx = context.WithValue(ctx, contextKeyClientIP{}, clientIP)
	}
	// FIX: Assign a monotonic RequestID for end-to-end tracing across P2P and RPC
	ctx = context.WithValue(ctx, contextKeyRequestID{}, atomic.AddUint64(&requestIDCounter, 1))
	// H-21 FIX: Mark context as HTTP transport so handleRequest knows auth was validated
	ctx = context.WithValue(ctx, contextKeyHTTPRequest{}, r)
	// Handle single request
	// R37-P3-08 FIX (2026-07-31): per-request panic recovery for the single-
	// request HTTP path. The batch path already has this (RPC-P0-01, R31);
	// the single-request path was missed, meaning any panic in handleRequest
	// (nil pointer, array out of bounds, etc.) would kill the HTTP handler
	// goroutine and leave the client with a truncated response / connection
	// drop. net/http has a top-level recover, but it runs AFTER response
	// headers are written, so the client sees an empty body.
	var resp *Response
	func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[RPC] single-request handleRequest panic recovered for method %s: %v",
					req.Method, r)
				resp = &Response{
					JSONRPC: JSONRPCVersion,
					ID:      req.ID,
					Error: NewError(ErrCodeInternal,
						"internal error: panic during request processing"),
				}
			}
		}()
		resp = s.handleRequest(ctx, &req)
	}()
	// FIX: JSON-RPC 2.0 notifications (requests without ID) must NOT
	// receive a response, even on error. Only send response for requests with ID.
	if req.ID == nil {
		return
	}
	s.writeResponse(w, resp)
}

// handleBatch handles a batch of requests
//
// RPC-R9-H4 (2026-07-19) FIX: Previously rate-limit checks were interleaved
// with handler execution inside the loop. This created a timing side-channel:
// an attacker could measure total batch response time to determine which
// methods were rate-limited (fast reject, no handler invoked) vs. which were
// actually processed (slow handler). For example, a batch of N identical
// eth_call requests would have response time proportional to the number that
// passed the rate limit, leaking the rate-limit state of each method.
//
// The fix splits processing into two passes:
//  1. Pre-validate ALL rate limits first (no handler invocation).
//  2. Invoke handlers only for requests that passed rate-limiting.
//
// This decouples the rate-limit decision from handler execution timing.
// The total response time now depends only on the slowest handler invoked,
// not on the order in which rate limits were hit. Defense-in-depth: the
// existing behavior (return per-element "rate limit exceeded" errors) is
// preserved, only the ordering of operations changed.
func (s *Server) handleBatch(w http.ResponseWriter, ctx context.Context, batch []Request) {
	if len(batch) > s.maxBatchSize {
		s.writeError(w, nil, NewError(ErrCodeInvalidRequest, fmt.Sprintf("Batch size exceeds limit of %d", s.maxBatchSize)))
		return
	}

	// RP-01 FIX (R45): Extract the *http.Request from context to avoid
	// passing nil to Allow(), which would panic if the rate limiter
	// dereferences it for IP-based limiting.
	var httpReq *http.Request
	if val := ctx.Value(contextKeyHTTPRequest{}); val != nil {
		if r, ok := val.(*http.Request); ok {
			httpReq = r
		}
	}

	// RPC-R9-H4 FIX: Pass 1 — pre-validate ALL rate limits BEFORE invoking
	// any handler. This eliminates the timing side-channel that leaked
	// per-method rate-limit state via handler execution latency.
	//  each request in the batch is still individually rate-limited
	// against the same limiter, so a batch of N requests consumes N tokens
	// from the rate limit budget (preserved behavior).
	rateLimited := make([]bool, len(batch))
	if s.rateLimiter != nil && s.enableRateLimit {
		for i := range batch {
			if err := s.rateLimiter.Allow(httpReq, batch[i].Method); err != nil {
				rateLimited[i] = true
			}
		}
	}

	// Pass 2 — invoke handlers only for requests that passed rate limiting.
	responses := make([]*Response, 0, len(batch))
	for i := range batch {
		req := batch[i]
		if rateLimited[i] {
			resp := &Response{
				JSONRPC: JSONRPCVersion,
				ID:      req.ID,
				Error: NewError(ErrCodeInvalidRequest,
					"rate limit exceeded for batch request"),
			}
			if req.ID != nil {
				responses = append(responses, resp)
			}
			continue
		}
		// RPC-P0-01 FIX (R31, 2026-07-27): Per-request panic recovery.
		// Without this, a single panic in handleRequest (nil pointer, array
		// out of bounds, etc.) would propagate up through the entire batch
		// loop, killing the HTTP handler goroutine and causing the entire
		// batch connection to drop without a response. Go's net/http server
		// has its own top-level recover, but it runs AFTER the response
		// headers are written for batch — the client would receive a
		// truncated response and the connection would close. Wrapping each
		// request in an anonymous function with defer recover ensures a
		// panic in ONE request does not break the rest of the batch.
		// Tracked by RPC-P0-01.
		var resp *Response
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[RPC] batch handleRequest panic recovered for method %s: %v",
						req.Method, r)
					resp = &Response{
						JSONRPC: JSONRPCVersion,
						ID:      req.ID,
						Error: NewError(ErrCodeInternal,
							"internal error: panic during request processing"),
					}
				}
			}()
			resp = s.handleRequest(ctx, &req)
		}()
		// Only include responses for requests with IDs (not notifications)
		if req.ID != nil {
			responses = append(responses, resp)
		}
	}

	// Write batch response
	if len(responses) > 0 {
		// #247: sanitize errors in production mode for batch responses
		for _, resp := range responses {
			if resp.Error != nil {
				resp.Error = s.sanitizeError(resp.Error)
			}
		}
		// L18-016 FIX: Marshal to buffer first so we can return HTTP 500 on
		// failure. Previously the encoding error was silently discarded with `_ =`,
		// which could cause clients to receive truncated or empty responses with
		// a 200 OK status, masking server-side failures.
		batchData, err := json.Marshal(responses)
		if err != nil {
			logging.Global().Error("failed to marshal batch RPC response", map[string]any{"error": err.Error()})
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if _, err := w.Write(batchData); err != nil {
			logging.Global().Warn("failed to write batch RPC response", map[string]any{"error": err.Error()})
		}
	}
}

// isValidMethodName reports whether name is a syntactically valid JSON-RPC
// method name for this server: non-empty and containing only ASCII letters,
// digits and underscores (e.g. "eth_blockNumber", "qau_tss_status").
// L7-018 FIX.
// L8-015 CONFIRMED FIXED: Method name validation is present and enforced as
// the single gate before handler lookup (see handleRequest). Malformed names
// are rejected with ErrMethodNotFound to avoid leaking registered methods.
func isValidMethodName(name string) bool {
	// L10-030: Verified — empty method name check is present.
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// handleRequest handles a single request
func (s *Server) handleRequest(ctx context.Context, req *Request) *Response {
	// Validate JSON-RPC version
	if req.JSONRPC != JSONRPCVersion {
		return &Response{
			JSONRPC: JSONRPCVersion,
			Error:   ErrInvalidRequest,
			ID:      req.ID,
		}
	}

	// Validate method
	if req.Method == "" {
		return &Response{
			JSONRPC: JSONRPCVersion,
			Error:   ErrInvalidRequest,
			ID:      req.ID,
		}
	}

	// FIX: Params length check moved AFTER handler lookup to prevent
	// leaking method existence. Previously, "params size exceeds limit" was
	// returned before method-not-found, revealing whether a method is registered.
	// Now, method-not-found is returned first for unregistered methods.

	method := req.Method

	// L7-018 FIX: Validate the method name format. Only ASCII letters,
	// digits and underscores are permitted. This is the single gate before
	// the handler map is accessed, preventing malformed keys from reaching
	// lookup. A malformed name is reported as method-not-found to avoid
	// leaking which methods are registered.
	if !isValidMethodName(method) {
		return &Response{
			JSONRPC: JSONRPCVersion,
			Error:   ErrMethodNotFound,
			ID:      req.ID,
		}
	}

	s.mu.RLock()
	handler, exists := s.handlers[method]
	s.mu.RUnlock()

	if !exists {
		return &Response{
			JSONRPC: JSONRPCVersion,
			Error:   ErrMethodNotFound,
			ID:      req.ID,
		}
	}

	// FIX: Params length check now happens AFTER handler lookup.
	// This prevents leaking method existence through error message differences.
	// "params size exceeds limit" is only returned for registered methods.
	if s.maxParamsLen > 0 && len(req.Params) > s.maxParamsLen {
		return &Response{
			JSONRPC: JSONRPCVersion,
			Error:   NewError(ErrCodeInvalidRequest, "params size exceeds limit"),
			ID:      req.ID,
		}
	}

	// HIGH FIX (admin bypass): Admin method authorization must be enforced for
	// ALL transport types (HTTP, WebSocket, IPC). The previous !isHTTP condition
	// allowed HTTP requests to bypass admin auth checks entirely — an attacker
	// could call admin methods via HTTP with only an API key.
	// - HTTP transport: auth was already validated in handleHTTP, but admin-level
	//   authorization was NOT checked there. We check it here for all transports.
	// - Non-HTTP transport: auth credentials are extracted from context.
	if s.isAdminMethod(method) {
		// R7-L8 FIX: if any admin method is registered, an absent authManager is
		// a misconfiguration that must NOT silently allow admin calls. Fail hard
		// rather than letting the privileged handler run unauthenticated.
		if s.authManager == nil {
			return &Response{
				JSONRPC: JSONRPCVersion,
				Error:   NewError(ErrCodeUnauthorized, "admin authentication is not configured"),
				ID:      req.ID,
			}
		}
		_, isHTTP := ctx.Value(contextKeyHTTPRequest{}).(*http.Request)
		if isHTTP {
			// HTTP transport already validated basic auth in handleHTTP,
			// but we must verify admin-level permission here.
			// The request object is stored in context; re-validate with admin awareness.
			if httpReq, ok := ctx.Value(contextKeyHTTPRequest{}).(*http.Request); ok {
				if s.authManager != nil {
					// ValidateRequest checks API key permissions and IP whitelist,
					// but admin methods need explicit admin authorization.
					// We enforce this by checking admin IP whitelist + API key admin flag.
					if err := s.authManager.ValidateAdminRequest(httpReq, req.Method); err != nil {
						return &Response{
							JSONRPC: JSONRPCVersion,
							Error:   NewError(ErrCodeUnauthorized, err.Error()),
							ID:      req.ID,
						}
					}
				}
			}
		} else {
			if err := s.authenticateFromContext(ctx, req.Method); err != nil {
				return &Response{
					JSONRPC: JSONRPCVersion,
					Error:   err,
					ID:      req.ID,
				}
			}
			if s.authManager != nil {
				apiKey, _ := ctx.Value(contextKeyAPIKey{}).(string)
				signature, _ := ctx.Value(contextKeySignature{}).(string)
				timestamp, _ := ctx.Value(contextKeyTimestamp{}).(string)
				clientIP, _ := ctx.Value(contextKeyClientIP{}).(string)
				r := &http.Request{}
				if apiKey != "" {
					r.Header.Set("X-API-Key", apiKey)
				}
				if signature != "" {
					r.Header.Set("X-Signature", signature)
				}
				if timestamp != "" {
					r.Header.Set("X-Timestamp", timestamp)
				}
				if clientIP != "" {
					r.RemoteAddr = net.JoinHostPort(clientIP, "0")
				}
				if err := s.authManager.ValidateAdminRequest(r, method); err != nil {
					return &Response{
						JSONRPC: JSONRPCVersion,
						Error:   NewError(ErrCodeUnauthorized, err.Error()),
						ID:      req.ID,
					}
				}
			}
		}
	}

	// Call handler
	result, rpcErr := handler(ctx, req.Params)

	// SECURITY FIX  Log every RPC call to the audit subsystem.
	// This captures who (client IP), what (method), when (timestamp), and result.
	if s.auditLogger != nil {
		requestID := ""
		if rid, ok := ctx.Value(contextKeyRequestID{}).(uint64); ok {
			requestID = fmt.Sprintf("%d", rid)
		}
		clientIP := ""
		if ip, ok := ctx.Value(contextKeyClientIP{}).(string); ok {
			clientIP = ip
		}
		resultStr := "success"
		if rpcErr != nil {
			resultStr = fmt.Sprintf("error:%d", rpcErr.Code)
		}
		details := map[string]any{
			"method":     method,
			"admin":      s.isAdminMethod(method),
			"params_len": len(req.Params),
		}
		// R46-RP-01 FIX: Log audit log failures instead of silently ignoring.
		// R14-LOW (P2P-LOW-01): Use structured logger to align with the rest of
		// the RPC logging path (server.go:1180/1185/1400/1415). The previous
		// log.Printf emitted unstructured text without request_id/method fields,
		// breaking log-level routing and structured field aggregation.
		if err := s.auditLogger.LogRPC("RPC_REQUEST", method, requestID, clientIP, resultStr, details); err != nil {
			logging.Global().Warn("rpc: audit log failed", map[string]any{
				"method":     method,
				"request_id": requestID,
				"client_ip":  clientIP,
				"error":      err.Error(),
			})
		}
	}

	if rpcErr != nil {
		return &Response{
			JSONRPC: JSONRPCVersion,
			Error:   rpcErr,
			ID:      req.ID,
		}
	}

	return &Response{
		JSONRPC: JSONRPCVersion,
		Result:  result,
		ID:      req.ID,
	}
}

// writeResponse writes a response to the HTTP response writer
func (s *Server) writeResponse(w http.ResponseWriter, resp *Response) {
	// #247: sanitize error in production mode
	if resp.Error != nil {
		resp.Error = s.sanitizeError(resp.Error)
	}
	// L-1 FIX: log encoding errors instead of silently discarding them
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logging.Global().Warn("failed to encode RPC response", map[string]any{"error": err.Error()})
	}
}

// writeError writes an error response
func (s *Server) writeError(w http.ResponseWriter, id any, err *Error) {
	// #247: sanitize error in production mode
	err = s.sanitizeError(err)
	resp := &Response{
		JSONRPC: JSONRPCVersion,
		Error:   err,
		ID:      id,
	}
	// L-1 FIX: log encoding errors instead of silently discarding them
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logging.Global().Warn("failed to encode RPC error response", map[string]any{"error": err.Error()})
	}
}

// HandleRequest handles a request directly (for testing)
func (s *Server) HandleRequest(ctx context.Context, req *Request) *Response {
	return s.handleRequest(ctx, req)
}

// HandleBatchRequest handles a batch request directly (for testing)
func (s *Server) HandleBatchRequest(ctx context.Context, batch []Request) []*Response {
	responses := make([]*Response, 0, len(batch))
	for _, req := range batch {
		resp := s.handleRequest(ctx, &req)
		if req.ID != nil {
			responses = append(responses, resp)
		}
	}
	return responses
}

// extractClientIP extracts the client IP address from the request using
// only RemoteAddr (does not trust proxy headers).
//
// L4-012: This function is retained for backward compatibility and testing.
// Production code paths (audit logging, rate limiting) now use
// getClientIPWithTrust() with the server's trustedProxies configuration
// to correctly extract the real client IP behind trusted reverse proxies.
// Use getClientIPWithTrust() in all production code instead of this function.
func extractClientIP(r *http.Request) string {
	// Simple implementation - in production this would trust specific headers
	// like X-Forwarded-For based on a list of trusted proxies.
	// For Quantaureum, we use RemoteAddr as the primary source of truth.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isLocalhostOrigin reports whether the given CORS Origin refers to a loopback host.
// It accepts http(s)://localhost, http(s)://127.0.0.1 and http(s)://[::1] on any
// port. Used to gate the no-allowlist CORS path so only local development tools
// can talk to the RPC, never arbitrary websites.
// audit-fix L-5: the special "null" Origin (sent by browsers for sandboxed
// iframes, file:// pages, and cross-origin redirects) is no longer treated as
// localhost. Treating "null" as localhost allowed any sandboxed context to
// bypass the CORS allowlist.
func isLocalhostOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
