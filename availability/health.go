// Quantaureum Node source, version 1.0.0.
// Package ha provides high availability components for Quantaureum nodes.
package ha

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// HealthStatus represents the health status of a component
type HealthStatus string

const (
	// StatusHealthy indicates the component is healthy
	StatusHealthy HealthStatus = "healthy"
	// StatusUnhealthy indicates the component is unhealthy
	StatusUnhealthy HealthStatus = "unhealthy"
	// StatusDegraded indicates the component is degraded but functional
	StatusDegraded HealthStatus = "degraded"
)

// ComponentHealth represents the health of a single component
type ComponentHealth struct {
	Name    string            `json:"name"`
	Status  HealthStatus      `json:"status"`
	Message string            `json:"message,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

// HealthResponse represents the overall health response
type HealthResponse struct {
	Status     HealthStatus      `json:"status"`
	Timestamp  time.Time         `json:"timestamp"`
	Version    string            `json:"version,omitempty"`
	Components []ComponentHealth `json:"components,omitempty"`
}

// ReadinessResponse represents the readiness response
type ReadinessResponse struct {
	Ready     bool             `json:"ready"`
	Timestamp time.Time        `json:"timestamp"`
	Checks    []ReadinessCheck `json:"checks,omitempty"`
}

// ReadinessCheck represents a single readiness check
type ReadinessCheck struct {
	Name   string `json:"name"`
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`
}

// HealthChecker is a function that checks the health of a component
type HealthChecker func(ctx context.Context) ComponentHealth

// ReadinessChecker is a function that checks if a component is ready
type ReadinessChecker func(ctx context.Context) ReadinessCheck

// HealthServer provides health and readiness endpoints
type HealthServer struct {
	server            *http.Server
	healthCheckers    []HealthChecker
	readinessCheckers []ReadinessChecker
	mu                sync.RWMutex
	version           string
	ready             atomic.Bool
	shutdownHandler   *ShutdownHandler
}

// HealthServerConfig holds configuration for the health server
type HealthServerConfig struct {
	Addr            string
	Version         string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownHandler *ShutdownHandler
}

// DefaultHealthServerConfig returns the default health server configuration
func DefaultHealthServerConfig() *HealthServerConfig {
	return &HealthServerConfig{
		Addr:         ":8080",
		Version:      "1.0.0",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
}

// NewHealthServer creates a new health server
func NewHealthServer(cfg *HealthServerConfig) *HealthServer {
	if cfg == nil {
		cfg = DefaultHealthServerConfig()
	}

	hs := &HealthServer{
		healthCheckers:    make([]HealthChecker, 0),
		readinessCheckers: make([]ReadinessChecker, 0),
		version:           cfg.Version,
		shutdownHandler:   cfg.ShutdownHandler,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", hs.handleHealth)
	mux.HandleFunc("/healthz", hs.handleHealth) // Kubernetes alias
	mux.HandleFunc("/ready", hs.handleReady)
	mux.HandleFunc("/readyz", hs.handleReady) // Kubernetes alias
	mux.HandleFunc("/live", hs.handleLive)
	mux.HandleFunc("/livez", hs.handleLive) // Kubernetes alias

	hs.server = &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: 10 * time.Second, // audit-fix MEDIUM: Slowloris header-DoS protection
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       120 * time.Second, // audit-fix MEDIUM: bound keepalive resource use
		MaxHeaderBytes:    1 << 20,           // audit-fix MEDIUM: 1 MiB header cap
	}

	return hs
}

// RegisterHealthChecker registers a health checker
func (hs *HealthServer) RegisterHealthChecker(checker HealthChecker) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.healthCheckers = append(hs.healthCheckers, checker)
}

// RegisterReadinessChecker registers a readiness checker
func (hs *HealthServer) RegisterReadinessChecker(checker ReadinessChecker) {
	hs.mu.Lock()
	defer hs.mu.Unlock()
	hs.readinessCheckers = append(hs.readinessCheckers, checker)
}

// SetReady sets the ready state
func (hs *HealthServer) SetReady(ready bool) {
	hs.ready.Store(ready)
}

// IsReady returns the current ready state
func (hs *HealthServer) IsReady() bool {
	return hs.ready.Load()
}

// Start starts the health server
func (hs *HealthServer) Start() error {
	return hs.server.ListenAndServe()
}

// Stop stops the health server
func (hs *HealthServer) Stop(ctx context.Context) error {
	return hs.server.Shutdown(ctx)
}

// handleHealth handles the /health endpoint
func (hs *HealthServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	// audit-fix LOW: health endpoints are read-only probes; reject non-GET/HEAD
	// methods to avoid widening the attack surface (e.g. CSRF-style probes).
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	hs.mu.RLock()
	checkers := make([]HealthChecker, len(hs.healthCheckers))
	copy(checkers, hs.healthCheckers)
	hs.mu.RUnlock()

	components := make([]ComponentHealth, 0, len(checkers))
	overallStatus := StatusHealthy

	for _, checker := range checkers {
		health := checker(ctx)
		components = append(components, health)

		// Determine overall status
		if health.Status == StatusUnhealthy {
			overallStatus = StatusUnhealthy
		} else if health.Status == StatusDegraded && overallStatus != StatusUnhealthy {
			overallStatus = StatusDegraded
		}
	}

	// Check if shutting down
	if hs.shutdownHandler != nil && hs.shutdownHandler.IsShuttingDown() {
		overallStatus = StatusUnhealthy
	}

	response := HealthResponse{
		Status:     overallStatus,
		Timestamp:  time.Now().UTC(),
		Version:    hs.version,
		Components: components,
	}

	w.Header().Set("Content-Type", "application/json")
	if overallStatus == StatusUnhealthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else if overallStatus == StatusDegraded {
		w.WriteHeader(http.StatusOK) // Still return 200 for degraded
	} else {
		w.WriteHeader(http.StatusOK)
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("ERROR: failed to encode health response: %v", err)
	}
}

// handleReady handles the /ready endpoint
func (hs *HealthServer) handleReady(w http.ResponseWriter, r *http.Request) {
	// audit-fix LOW: readiness endpoints are read-only probes; reject non-GET/HEAD.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Check if shutting down - not ready during shutdown
	if hs.shutdownHandler != nil && hs.shutdownHandler.IsShuttingDown() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		if err := json.NewEncoder(w).Encode(ReadinessResponse{
			Ready:     false,
			Timestamp: time.Now().UTC(),
			Checks: []ReadinessCheck{
				{Name: "shutdown", Ready: false, Reason: "node is shutting down"},
			},
		}); err != nil {
			log.Printf("ERROR: failed to encode shutdown readiness response: %v", err)
		}
		return
	}

	hs.mu.RLock()
	checkers := make([]ReadinessChecker, len(hs.readinessCheckers))
	copy(checkers, hs.readinessCheckers)
	hs.mu.RUnlock()

	checks := make([]ReadinessCheck, 0, len(checkers))
	allReady := hs.ready.Load()

	for _, checker := range checkers {
		check := checker(ctx)
		checks = append(checks, check)
		if !check.Ready {
			allReady = false
		}
	}

	response := ReadinessResponse{
		Ready:     allReady,
		Timestamp: time.Now().UTC(),
		Checks:    checks,
	}

	w.Header().Set("Content-Type", "application/json")
	if allReady {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("ERROR: failed to encode readiness response: %v", err)
	}
}

// handleLive handles the /live endpoint (liveness probe)
func (hs *HealthServer) handleLive(w http.ResponseWriter, r *http.Request) {
	// audit-fix LOW: liveness endpoints are read-only probes; reject non-GET/HEAD.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Liveness check is simple - if we can respond, we're alive
	// Only return unhealthy if we're completely stopped
	if hs.shutdownHandler != nil && hs.shutdownHandler.IsStopped() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"alive":     true,
		"timestamp": time.Now().UTC(),
	}); err != nil {
		log.Printf("ERROR: failed to encode liveness response: %v", err)
	}
}
