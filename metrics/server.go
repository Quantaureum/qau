// Quantaureum Node source, version 1.0.0.
// Package metrics provides Prometheus metrics for Quantaureum node monitoring.
// #nosec audit-remediation: implements rate limiting, size limits, response limits
package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Security constants for metrics server
// #nosec audit-remediation: HTTP security limits
const (
	// MaxMetricsRequestSize is the maximum request size (64KB)
	MaxMetricsRequestSize = 64 * 1024

	// MaxMetricsResponseSize is the maximum response size (10MB)
	MaxMetricsResponseSize = 10 * 1024 * 1024

	// MetricsRateLimitPerSecond is the rate limit for metrics requests
	MetricsRateLimitPerSecond = 100
)

// ServerConfig holds metrics server configuration
type ServerConfig struct {
	Addr            string        // Address to listen on (e.g., ":9090")
	Path            string        // Metrics endpoint path (default: "/metrics")
	ReadTimeout     time.Duration // HTTP read timeout
	WriteTimeout    time.Duration // HTTP write timeout
	UpdateInterval  time.Duration // System metrics update interval
	AlertInterval   time.Duration // Alert check interval
	EnableAlerts    bool          // Enable alert checking
	MaxRequestSize  int64         // Maximum request size (audit-remediation)
	MaxResponseSize int64         // Maximum response size (audit-remediation)
	// SECURITY FIX: TrustedProxies is a list of trusted proxy IPs that can set X-Forwarded-For
	// If empty, X-Forwarded-For header is NOT trusted (use RemoteAddr directly)
	TrustedProxies []string // List of trusted proxy IPs/CIDR for X-Forwarded-For
}

// DefaultServerConfig returns default server configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Addr:           ":9090",
		Path:           "/metrics",
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		UpdateInterval: 15 * time.Second,
		AlertInterval:  30 * time.Second,
		EnableAlerts:   true,
	}
}

// Server is a metrics HTTP server
type Server struct {
	config      *ServerConfig
	metrics     *Metrics
	server      *http.Server
	stopCh      chan struct{}
	rateLimiter *metricsRateLimiter // audit-fix P2P-AMP-RATE: rate limiting per client
}

// metricsRateLimiter implements rate limiting per client IP
type metricsRateLimiter struct {
	mu       sync.Mutex
	counters map[string]*rateLimitCounter
	limit    int64
	window   time.Duration
}

type rateLimitCounter struct {
	count     int64
	windowEnd time.Time
}

// audit-fix P2P-AMP-RATE: rate limiter implementation
func newMetricsRateLimiter(limit int64, window time.Duration) *metricsRateLimiter {
	return &metricsRateLimiter{
		counters: make(map[string]*rateLimitCounter),
		limit:    limit,
		window:   window,
	}
}

func (rl *metricsRateLimiter) allow(clientID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	counter, exists := rl.counters[clientID]
	if !exists || counter.windowEnd.Before(now) {
		rl.counters[clientID] = &rateLimitCounter{
			count:     1,
			windowEnd: now.Add(rl.window),
		}
		return true
	}
	if counter.count >= rl.limit {
		return false
	}
	counter.count++
	return true
}

// getClientIP extracts client IP from request
// SECURITY FIX: Only trust X-Forwarded-For if the direct connection is from a trusted proxy
func (s *Server) getClientIP(r *http.Request) string {
	// Get the direct connection IP first
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	// If no trusted proxies configured, return direct IP
	if len(s.config.TrustedProxies) == 0 {
		return remoteIP
	}

	// Check if the direct connection is from a trusted proxy
	isTrustedProxy := false
	for _, trusted := range s.config.TrustedProxies {
		if strings.Contains(trusted, "/") {
			// CIDR notation
			_, network, err := net.ParseCIDR(trusted)
			if err == nil {
				ip := net.ParseIP(remoteIP)
				if ip != nil && network.Contains(ip) {
					isTrustedProxy = true
					break
				}
			}
		} else if remoteIP == trusted {
			isTrustedProxy = true
			break
		}
	}

	// Only trust X-Forwarded-For if connection is from trusted proxy
	if isTrustedProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first (client) IP in the list
			parts := strings.Split(xff, ",")
			clientIP := strings.TrimSpace(parts[0])
			if net.ParseIP(clientIP) != nil {
				return clientIP
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if net.ParseIP(xri) != nil {
				return xri
			}
		}
	}

	return remoteIP
}

// NewServer creates a new metrics server
func NewServer(cfg *ServerConfig, m *Metrics) *Server {
	if cfg == nil {
		cfg = DefaultServerConfig()
	}
	if m == nil {
		m = Global()
	}
	if cfg.Path == "" {
		cfg.Path = "/metrics"
	}

	return &Server{
		config:      cfg,
		metrics:     m,
		stopCh:      make(chan struct{}),
		rateLimiter: newMetricsRateLimiter(MetricsRateLimitPerSecond, time.Second),
	}
}

// Start starts the metrics server
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Native Prometheus metrics endpoint (promhttp.Handler, serving all metrics registered by NodeMetrics)
	// audit fix (CRITICAL): the original endpoint had no authentication; anyone could read sensitive node metrics. Bearer token auth is now required.
	mux.Handle("/metrics/prometheus", s.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.metrics.validateMetricsToken(r) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		promhttp.Handler().ServeHTTP(w, r)
	})))

	// Custom Prometheus-format metrics endpoint (legacy-compatible; requires Bearer token auth)
	mux.Handle(s.config.Path, s.rateLimitMiddleware(s.metrics.PrometheusHandler()))

	// Health check endpoint with rate limiting
	mux.HandleFunc("/health", s.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// audit-fix LOW: health is read-only, reject non-GET methods.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// audit-fix MEDIUM: security headers on metrics responses
		setMetricsSecurityHeaders(w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// R31-P3 FIX (P3-3, 2026-07-28): The /health endpoint is publicly
		// accessible (needed for k8s/lb probes). Previously it exposed
		// precise uptime_seconds to anyone, allowing attackers to:
		//   1. Pinpoint exact node restart times
		//   2. Time attacks to coincide with restart windows
		//   3. Fingerprint node software/versions by uptime patterns
		// Now we return only the coarse "healthy" status publicly, and
		// gate the precise uptime behind the same Bearer token used by
		// /metrics/prometheus. Unauthenticated probes still get a usable
		// 200/503 response — k8s/lb probes only need the status code.
		if s.metrics.validateMetricsToken(r) {
			fmt.Fprintf(w, `{"status":"healthy","uptime_seconds":%.2f}`, s.metrics.Uptime().Seconds())
		} else {
			fmt.Fprintf(w, `{"status":"healthy"}`)
		}
	})).ServeHTTP)

	// Ready check endpoint with rate limiting
	mux.HandleFunc("/ready", s.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// audit-fix LOW: ready is read-only, reject non-GET methods.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// audit-fix MEDIUM: security headers on metrics responses
		setMetricsSecurityHeaders(w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ready"}`)
	})).ServeHTTP)

	// Alerts endpoint (Requirements 17.3)
	mux.HandleFunc("/alerts", s.alertsHandler)

	// Snapshot endpoint for JSON metrics
	mux.HandleFunc("/snapshot", s.snapshotHandler)

	s.server = &http.Server{
		Addr:              s.config.Addr,
		Handler:           mux,
		ReadTimeout:       s.config.ReadTimeout,
		ReadHeaderTimeout: 10 * time.Second, // audit-fix MEDIUM: Slowloris header-DoS protection
		WriteTimeout:      s.config.WriteTimeout,
		IdleTimeout:       120 * time.Second, // audit-fix MEDIUM: bound keepalive resource use
		MaxHeaderBytes:    1 << 20,           // audit-fix MEDIUM: 1 MiB header cap
	}

	// Start background metrics updater
	go s.updateLoop()

	// Start alert checker if enabled
	if s.config.EnableAlerts {
		go s.alertLoop()
	}

	// Start HTTP server
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// SECURITY FIX: Log startup errors instead of silently ignoring them
			log.Printf("[ERROR] Metrics server failed to start: %v", err)
		}
	}()

	return nil
}

// alertsHandler handles the /alerts endpoint
// audit-fix P2P-AMP-RATE: rate limiting added
// audit-fix P2P-AMP-SIZE: size limit on response
// audit-fix H-3: require Bearer token auth, same as /metrics/prometheus
func (s *Server) alertsHandler(w http.ResponseWriter, r *http.Request) {
	// audit-fix H-3: authenticate before serving alerts
	if !s.metrics.validateMetricsToken(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// audit-fix LOW: restrict to GET only — these endpoints are read-only and
	// accepting POST/PUT/DELETE has no semantic meaning and widens the attack
	// surface (e.g. for CSRF-style probes).
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limiting check
	clientIP := s.getClientIP(r)
	if !s.rateLimiter.allow(clientIP) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// audit-fix MEDIUM: security headers on metrics responses
	setMetricsSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")

	am := s.metrics.AlertManager()
	if am == nil {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"alerts":[]}`)
		return
	}

	alerts := am.GetAlerts(100)
	response := struct {
		Alerts []*Alert `json:"alerts"`
		Count  int      `json:"count"`
	}{
		Alerts: alerts,
		Count:  len(alerts),
	}

	// Use size-limited writer to prevent response amplification attacks
	w.WriteHeader(http.StatusOK)
	limitedW := &limitedResponseWriter{w: w, limit: MaxMetricsResponseSize}
	if err := json.NewEncoder(limitedW).Encode(response); err != nil {
		// Response truncated due to size limit
		return
	}
}

// snapshotHandler handles the /snapshot endpoint
// audit-fix P2P-AMP-RATE: rate limiting added
// audit-fix P2P-AMP-SIZE: size limit on response
// audit-fix H-3: require Bearer token auth, same as /metrics/prometheus
func (s *Server) snapshotHandler(w http.ResponseWriter, r *http.Request) {
	// audit-fix H-3: authenticate before serving snapshot
	if !s.metrics.validateMetricsToken(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// audit-fix LOW: restrict to GET only — snapshot is a read-only operation.
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Rate limiting check
	clientIP := s.getClientIP(r)
	if !s.rateLimiter.allow(clientIP) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// audit-fix MEDIUM: security headers on metrics responses
	setMetricsSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	snapshot := s.metrics.Snapshot()

	// Use size-limited writer to prevent response amplification attacks
	w.WriteHeader(http.StatusOK)
	limitedW := &limitedResponseWriter{w: w, limit: MaxMetricsResponseSize}
	if err := json.NewEncoder(limitedW).Encode(snapshot); err != nil {
		// Response truncated due to size limit
		return
	}
}

// limitedResponseWriter wraps http.ResponseWriter to enforce size limits
// audit-fix P2P-AMP-SIZE: prevent response amplification attacks
type limitedResponseWriter struct {
	w      http.ResponseWriter
	size   int64
	limit  int64
	mu     sync.Mutex
	closed bool
}

var errResponseClosed = errors.New("response write after close")

func (lr *limitedResponseWriter) Write(p []byte) (n int, err error) {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	if lr.closed {
		return 0, errResponseClosed
	}
	newSize := lr.size + int64(len(p))
	if newSize > lr.limit {
		// Write only what fits within the limit
		available := lr.limit - lr.size
		if available > 0 {
			n, err = lr.w.Write(p[:available])
			lr.size = lr.limit
		}
		lr.closed = true
		return n, errors.New("response size limit exceeded")
	}
	n, err = lr.w.Write(p)
	lr.size += int64(n)
	return n, err
}

func (lr *limitedResponseWriter) WriteHeader(statusCode int) {
	lr.mu.Lock()
	defer lr.mu.Unlock()
	if !lr.closed {
		lr.w.WriteHeader(statusCode)
	}
}

func (lr *limitedResponseWriter) Header() http.Header {
	return lr.w.Header()
}

// rateLimitMiddleware wraps an http.Handler with rate limiting
// audit-fix ROUND4-H2: add rate limiting to /metrics endpoint
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := s.getClientIP(r)
		if !s.rateLimiter.allow(clientIP) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// audit-fix MEDIUM: setMetricsSecurityHeaders sets standard HTTP security
// response headers on metrics endpoint responses. Prevents content-type
// sniffing and clickjacking on monitoring endpoints that may be exposed to
// untrusted networks (e.g. scrape targets reachable from outside the node).
func setMetricsSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	if h.Get("X-Content-Type-Options") == "" {
		h.Set("X-Content-Type-Options", "nosniff")
	}
	if h.Get("X-Frame-Options") == "" {
		h.Set("X-Frame-Options", "DENY")
	}
}

// alertLoop periodically checks alert rules
func (s *Server) alertLoop() {
	ticker := time.NewTicker(s.config.AlertInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.metrics.CheckAlerts()
		}
	}
}

// Stop stops the metrics server
func (s *Server) Stop(ctx context.Context) error {
	close(s.stopCh)
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

// updateLoop periodically updates system metrics
func (s *Server) updateLoop() {
	ticker := time.NewTicker(s.config.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.metrics.UpdateSystemMetrics()
		}
	}
}

// Metrics returns the metrics instance
func (s *Server) Metrics() *Metrics {
	return s.metrics
}
