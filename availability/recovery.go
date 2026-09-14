// Quantaureum Node source, version 1.0.0.
// Package ha provides high availability components for Quantaureum nodes.
package ha

import (
	"context"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// Recovery errors
var (
	ErrSubsystemNotFound   = errors.New("subsystem not found")
	ErrSubsystemNotRunning = errors.New("subsystem not running")
	ErrRecoveryFailed      = errors.New("recovery failed")
	ErrMaxRetriesExceeded  = errors.New("maximum retries exceeded")
)

// SubsystemState represents the state of a subsystem
type SubsystemState int32

const (
	// SubsystemStopped indicates the subsystem is stopped
	SubsystemStopped SubsystemState = iota
	// SubsystemStarting indicates the subsystem is starting
	SubsystemStarting
	// SubsystemRunning indicates the subsystem is running
	SubsystemRunning
	// SubsystemFailed indicates the subsystem has failed
	SubsystemFailed
	// SubsystemRecovering indicates the subsystem is recovering
	SubsystemRecovering
)

// String returns the string representation of the subsystem state
func (s SubsystemState) String() string {
	switch s {
	case SubsystemStopped:
		return "stopped"
	case SubsystemStarting:
		return "starting"
	case SubsystemRunning:
		return "running"
	case SubsystemFailed:
		return "failed"
	case SubsystemRecovering:
		return "recovering"
	default:
		return "unknown"
	}
}

// Subsystem represents a recoverable subsystem
type Subsystem struct {
	Name           string
	Start          func(ctx context.Context) error
	Stop           func(ctx context.Context) error
	HealthCheck    func(ctx context.Context) error
	state          atomic.Int32
	failures       atomic.Int32
	lastFailure    atomic.Int64
	circuitBreaker *CircuitBreaker
}

// SubsystemConfig holds configuration for a subsystem
type SubsystemConfig struct {
	Name           string
	Start          func(ctx context.Context) error
	Stop           func(ctx context.Context) error
	HealthCheck    func(ctx context.Context) error
	MaxRetries     int
	RetryInterval  time.Duration
	CircuitBreaker *CircuitBreakerConfig
}

// NewSubsystem creates a new subsystem
func NewSubsystem(cfg *SubsystemConfig) *Subsystem {
	var cb *CircuitBreaker
	if cfg.CircuitBreaker != nil {
		cb = NewCircuitBreaker(cfg.CircuitBreaker)
	}

	s := &Subsystem{
		Name:           cfg.Name,
		Start:          cfg.Start,
		Stop:           cfg.Stop,
		HealthCheck:    cfg.HealthCheck,
		circuitBreaker: cb,
	}
	s.state.Store(int32(SubsystemStopped))

	return s
}

// State returns the current subsystem state
func (s *Subsystem) State() SubsystemState {
	return SubsystemState(s.state.Load())
}

// SetState sets the subsystem state
func (s *Subsystem) SetState(state SubsystemState) {
	s.state.Store(int32(state))
}

// RecordFailure records a failure
func (s *Subsystem) RecordFailure() {
	s.failures.Add(1)
	s.lastFailure.Store(time.Now().UnixNano())
}

// ResetFailures resets the failure counter
func (s *Subsystem) ResetFailures() {
	s.failures.Store(0)
}

// Failures returns the number of failures
func (s *Subsystem) Failures() int {
	return int(s.failures.Load())
}

// LastFailure returns the time of the last failure
func (s *Subsystem) LastFailure() time.Time {
	return time.Unix(0, s.lastFailure.Load())
}

// RecoveryManager manages automatic recovery of subsystems
type RecoveryManager struct {
	subsystems    map[string]*Subsystem
	mu            sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	checkInterval time.Duration
	maxRetries    int
	retryInterval time.Duration
	onRecovery    func(name string, success bool, err error)
	onStateChange func(name string, from, to SubsystemState)
	running       atomic.Bool
}

// RecoveryManagerConfig holds configuration for the recovery manager
type RecoveryManagerConfig struct {
	// CheckInterval is the interval between health checks
	CheckInterval time.Duration
	// MaxRetries is the maximum number of recovery attempts
	MaxRetries int
	// RetryInterval is the interval between recovery attempts
	RetryInterval time.Duration
	// OnRecovery is called when a recovery attempt completes
	OnRecovery func(name string, success bool, err error)
	// OnStateChange is called when a subsystem state changes
	OnStateChange func(name string, from, to SubsystemState)
}

// DefaultRecoveryManagerConfig returns the default recovery manager configuration
func DefaultRecoveryManagerConfig() *RecoveryManagerConfig {
	return &RecoveryManagerConfig{
		CheckInterval: 10 * time.Second,
		MaxRetries:    3,
		RetryInterval: 5 * time.Second,
	}
}

// NewRecoveryManager creates a new recovery manager
func NewRecoveryManager(cfg *RecoveryManagerConfig) *RecoveryManager {
	if cfg == nil {
		cfg = DefaultRecoveryManagerConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &RecoveryManager{
		subsystems:    make(map[string]*Subsystem),
		ctx:           ctx,
		cancel:        cancel,
		checkInterval: cfg.CheckInterval,
		maxRetries:    cfg.MaxRetries,
		retryInterval: cfg.RetryInterval,
		onRecovery:    cfg.OnRecovery,
		onStateChange: cfg.OnStateChange,
	}
}

// RegisterSubsystem registers a subsystem for recovery management
func (rm *RecoveryManager) RegisterSubsystem(cfg *SubsystemConfig) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	subsystem := NewSubsystem(cfg)
	rm.subsystems[cfg.Name] = subsystem

	return nil
}

// UnregisterSubsystem unregisters a subsystem
func (rm *RecoveryManager) UnregisterSubsystem(name string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.subsystems[name]; !exists {
		return ErrSubsystemNotFound
	}

	delete(rm.subsystems, name)
	return nil
}

// Start starts the recovery manager
func (rm *RecoveryManager) Start() error {
	if rm.running.Swap(true) {
		return nil // Already running
	}

	rm.wg.Add(1)
	go rm.monitorLoop()

	return nil
}

// Stop stops the recovery manager
func (rm *RecoveryManager) Stop() error {
	if !rm.running.Swap(false) {
		return nil // Not running
	}

	rm.cancel()
	rm.wg.Wait()

	return nil
}

// monitorLoop monitors subsystems and triggers recovery
func (rm *RecoveryManager) monitorLoop() {
	defer rm.wg.Done()

	ticker := time.NewTicker(rm.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rm.ctx.Done():
			return
		case <-ticker.C:
			rm.checkSubsystems()
		}
	}
}

// checkSubsystems checks all subsystems and triggers recovery if needed
func (rm *RecoveryManager) checkSubsystems() {
	rm.mu.RLock()
	subsystems := make([]*Subsystem, 0, len(rm.subsystems))
	for _, s := range rm.subsystems {
		subsystems = append(subsystems, s)
	}
	rm.mu.RUnlock()

	for _, s := range subsystems {
		if s.State() != SubsystemRunning {
			continue
		}

		// Check health
		if s.HealthCheck != nil {
			ctx, cancel := context.WithTimeout(rm.ctx, 5*time.Second)
			err := s.HealthCheck(ctx)
			cancel()

			if err != nil {
				rm.handleFailure(s)
			}
		}
	}
}

// handleFailure handles a subsystem failure
func (rm *RecoveryManager) handleFailure(s *Subsystem) {
	oldState := s.State()
	s.SetState(SubsystemFailed)
	s.RecordFailure()

	if rm.onStateChange != nil {
		rm.onStateChange(s.Name, oldState, SubsystemFailed)
	}

	// Attempt recovery
	go rm.attemptRecovery(s)
}

// attemptRecovery attempts to recover a failed subsystem
func (rm *RecoveryManager) attemptRecovery(s *Subsystem) {
	oldState := s.State()
	s.SetState(SubsystemRecovering)

	if rm.onStateChange != nil {
		rm.onStateChange(s.Name, oldState, SubsystemRecovering)
	}

	var lastErr error
	for i := 0; i < rm.maxRetries; i++ {
		select {
		case <-rm.ctx.Done():
			return
		default:
		}

		// Stop the subsystem first
		if s.Stop != nil {
			ctx, cancel := context.WithTimeout(rm.ctx, 10*time.Second)
			// FIX: Log the error instead of silently ignoring it.
			// Previously _ = s.Stop(ctx) discarded the error, making it
			// impossible to diagnose subsystem stop failures during recovery.
			if err := s.Stop(ctx); err != nil {
				log.Printf("[recovery] failed to stop subsystem %q: %v", s.Name, err)
			}
			cancel()
		}

		// Wait before retry
		if i > 0 {
			time.Sleep(rm.retryInterval)
		}

		// Try to start the subsystem
		if s.Start != nil {
			ctx, cancel := context.WithTimeout(rm.ctx, 30*time.Second)
			err := s.Start(ctx)
			cancel()

			if err == nil {
				// Recovery successful
				oldState := s.State()
				s.SetState(SubsystemRunning)
				s.ResetFailures()

				if rm.onStateChange != nil {
					rm.onStateChange(s.Name, oldState, SubsystemRunning)
				}

				if rm.onRecovery != nil {
					rm.onRecovery(s.Name, true, nil)
				}
				return
			}
			lastErr = err
		}
	}

	// Recovery failed
	oldState = s.State()
	s.SetState(SubsystemFailed)

	if rm.onStateChange != nil {
		rm.onStateChange(s.Name, oldState, SubsystemFailed)
	}

	if rm.onRecovery != nil {
		rm.onRecovery(s.Name, false, lastErr)
	}
}

// RecoverSubsystem manually triggers recovery for a subsystem
func (rm *RecoveryManager) RecoverSubsystem(name string) error {
	rm.mu.RLock()
	s, exists := rm.subsystems[name]
	rm.mu.RUnlock()

	if !exists {
		return ErrSubsystemNotFound
	}

	go rm.attemptRecovery(s)
	return nil
}

// GetSubsystemState returns the state of a subsystem
func (rm *RecoveryManager) GetSubsystemState(name string) (SubsystemState, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	s, exists := rm.subsystems[name]
	if !exists {
		return SubsystemStopped, ErrSubsystemNotFound
	}

	return s.State(), nil
}

// GetAllSubsystemStates returns the states of all subsystems
func (rm *RecoveryManager) GetAllSubsystemStates() map[string]SubsystemState {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	states := make(map[string]SubsystemState, len(rm.subsystems))
	for name, s := range rm.subsystems {
		states[name] = s.State()
	}

	return states
}

// SetSubsystemRunning marks a subsystem as running
func (rm *RecoveryManager) SetSubsystemRunning(name string) error {
	rm.mu.RLock()
	s, exists := rm.subsystems[name]
	rm.mu.RUnlock()

	if !exists {
		return ErrSubsystemNotFound
	}

	oldState := s.State()
	s.SetState(SubsystemRunning)

	if rm.onStateChange != nil && oldState != SubsystemRunning {
		rm.onStateChange(name, oldState, SubsystemRunning)
	}

	return nil
}
