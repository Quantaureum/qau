// Quantaureum Node source, version 1.0.0.
// Package ha provides high availability components for Quantaureum nodes.
package ha

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ShutdownState represents the current shutdown state
type ShutdownState int32

const (
	// StateRunning indicates the system is running normally
	StateRunning ShutdownState = iota
	// StateShuttingDown indicates shutdown has been initiated
	StateShuttingDown
	// StateStopped indicates the system has stopped
	StateStopped
)

// ShutdownHandler manages graceful shutdown of the node
type ShutdownHandler struct {
	state        atomic.Int32
	shutdownCh   chan struct{}
	doneCh       chan struct{}
	timeout      time.Duration
	hooks        []ShutdownHook
	hooksMu      sync.RWMutex
	signalCh     chan os.Signal
	onShutdown   func()
	shutdownOnce sync.Once
}

// ShutdownHook represents a function to be called during shutdown
type ShutdownHook struct {
	Name     string
	Priority int // Lower priority runs first
	Fn       func(ctx context.Context) error
}

// ShutdownConfig holds configuration for the shutdown handler
type ShutdownConfig struct {
	// Timeout is the maximum time to wait for graceful shutdown
	Timeout time.Duration
	// Signals are the OS signals to listen for
	Signals []os.Signal
}

// DefaultShutdownConfig returns the default shutdown configuration
func DefaultShutdownConfig() *ShutdownConfig {
	return &ShutdownConfig{
		Timeout: 30 * time.Second,
		Signals: []os.Signal{syscall.SIGINT, syscall.SIGTERM},
	}
}

func init() {
	// Ignore signals that should not cause shutdown
	// SIGHUP: terminal closed (e.g., in WSL)
	// SIGPIPE: broken pipe
	signal.Ignore(syscall.SIGHUP)
	signal.Ignore(syscall.SIGPIPE)
}

// NewShutdownHandler creates a new shutdown handler
func NewShutdownHandler(cfg *ShutdownConfig) *ShutdownHandler {
	if cfg == nil {
		cfg = DefaultShutdownConfig()
	}

	// Use default signals if none specified
	signals := cfg.Signals
	if len(signals) == 0 {
		signals = []os.Signal{syscall.SIGINT, syscall.SIGTERM}
	}

	// Ensure these signals are ignored (must be done before Notify)
	signal.Ignore(syscall.SIGHUP)
	signal.Ignore(syscall.SIGPIPE)

	h := &ShutdownHandler{
		shutdownCh: make(chan struct{}),
		doneCh:     make(chan struct{}),
		timeout:    cfg.Timeout,
		signalCh:   make(chan os.Signal, 1),
		hooks:      make([]ShutdownHook, 0),
	}
	h.state.Store(int32(StateRunning))

	// Register signal handlers - only for SIGINT and SIGTERM
	signal.Notify(h.signalCh, signals...)

	return h
}

// RegisterHook registers a shutdown hook
func (h *ShutdownHandler) RegisterHook(hook ShutdownHook) {
	h.hooksMu.Lock()
	defer h.hooksMu.Unlock()

	// Insert in priority order (lower priority first)
	inserted := false
	for i, existing := range h.hooks {
		if hook.Priority < existing.Priority {
			h.hooks = append(h.hooks[:i], append([]ShutdownHook{hook}, h.hooks[i:]...)...)
			inserted = true
			break
		}
	}
	if !inserted {
		h.hooks = append(h.hooks, hook)
	}
}

// SetOnShutdown sets a callback to be called when shutdown is initiated
func (h *ShutdownHandler) SetOnShutdown(fn func()) {
	h.onShutdown = fn
}

// Start starts listening for shutdown signals
func (h *ShutdownHandler) Start() {
	go h.listenForSignals()
}

// listenForSignals listens for OS signals and initiates shutdown
func (h *ShutdownHandler) listenForSignals() {
	select {
	case sig := <-h.signalCh:
		// Log the signal for debugging
		os.Stderr.WriteString("Received signal: " + sig.String() + "\n") // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
		h.Shutdown()
	case <-h.shutdownCh:
		// Shutdown was initiated programmatically
	}
}

// Shutdown initiates graceful shutdown
func (h *ShutdownHandler) Shutdown() {
	h.shutdownOnce.Do(func() {
		h.state.Store(int32(StateShuttingDown))
		close(h.shutdownCh)

		// Call shutdown callback if set
		if h.onShutdown != nil {
			h.onShutdown()
		}

		// Execute shutdown hooks with timeout
		ctx, cancel := context.WithTimeout(context.Background(), h.timeout)
		defer cancel()

		h.executeHooks(ctx)

		h.state.Store(int32(StateStopped))
		close(h.doneCh)
	})
}

// executeHooks executes all registered shutdown hooks
func (h *ShutdownHandler) executeHooks(ctx context.Context) {
	h.hooksMu.RLock()
	hooks := make([]ShutdownHook, len(h.hooks))
	copy(hooks, h.hooks)
	h.hooksMu.RUnlock()

	for _, hook := range hooks {
		select {
		case <-ctx.Done():
			// Timeout reached, stop executing hooks
			return
		default:
			// Execute hook with individual timeout
			hookCtx, cancel := context.WithTimeout(ctx, h.timeout/time.Duration(len(hooks)+1))
			// FIX: Log the error instead of silently ignoring it.
			// Previously _ = hook.Fn(hookCtx) discarded the error, making it
			// impossible to diagnose shutdown hook failures.
			if err := hook.Fn(hookCtx); err != nil {
				log.Printf("[shutdown] hook %q failed: %v", hook.Name, err)
			}
			cancel()
		}
	}
}

// Wait blocks until shutdown is complete
func (h *ShutdownHandler) Wait() {
	<-h.doneCh
}

// WaitForSignal blocks until a shutdown signal is received
func (h *ShutdownHandler) WaitForSignal() {
	<-h.shutdownCh
}

// ShutdownCh returns a channel that is closed when shutdown is initiated
func (h *ShutdownHandler) ShutdownCh() <-chan struct{} {
	return h.shutdownCh
}

// DoneCh returns a channel that is closed when shutdown is complete
func (h *ShutdownHandler) DoneCh() <-chan struct{} {
	return h.doneCh
}

// State returns the current shutdown state
func (h *ShutdownHandler) State() ShutdownState {
	return ShutdownState(h.state.Load())
}

// IsShuttingDown returns true if shutdown has been initiated
func (h *ShutdownHandler) IsShuttingDown() bool {
	return h.State() >= StateShuttingDown
}

// IsStopped returns true if shutdown is complete
func (h *ShutdownHandler) IsStopped() bool {
	return h.State() == StateStopped
}

// Stop stops the shutdown handler and cleans up resources
func (h *ShutdownHandler) Stop() {
	signal.Stop(h.signalCh)
	close(h.signalCh)
}
