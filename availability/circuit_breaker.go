// Quantaureum Node source, version 1.0.0.
// Package ha provides high availability components for Quantaureum nodes.
package ha

import (
	"context"
	"errors"
	"sync/atomic"
	"time"
)

// Circuit breaker errors
var (
	ErrCircuitOpen     = errors.New("circuit breaker is open")
	ErrCircuitHalfOpen = errors.New("circuit breaker is half-open")
	ErrTooManyFailures = errors.New("too many failures")
)

// CircuitState represents the state of a circuit breaker
type CircuitState int32

const (
	// CircuitClosed indicates the circuit is closed (normal operation)
	CircuitClosed CircuitState = iota
	// CircuitOpen indicates the circuit is open (failing fast)
	CircuitOpen
	// CircuitHalfOpen indicates the circuit is half-open (testing recovery)
	CircuitHalfOpen
)

// String returns the string representation of the circuit state
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig holds configuration for a circuit breaker
type CircuitBreakerConfig struct {
	// Name is the name of the circuit breaker
	Name string
	// FailureThreshold is the number of failures before opening the circuit
	FailureThreshold int
	// SuccessThreshold is the number of successes needed to close the circuit
	SuccessThreshold int
	// Timeout is the time to wait before transitioning from open to half-open
	Timeout time.Duration
	// MaxConcurrent is the maximum number of concurrent requests in half-open state
	MaxConcurrent int
	// OnStateChange is called when the circuit state changes
	OnStateChange func(name string, from, to CircuitState)
}

// DefaultCircuitBreakerConfig returns the default circuit breaker configuration
func DefaultCircuitBreakerConfig() *CircuitBreakerConfig {
	return &CircuitBreakerConfig{
		Name:             "default",
		FailureThreshold: 5,
		SuccessThreshold: 3,
		Timeout:          30 * time.Second,
		MaxConcurrent:    1,
	}
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config           *CircuitBreakerConfig
	state            atomic.Int32
	failures         atomic.Int32
	successes        atomic.Int32
	lastFailure      atomic.Int64
	halfOpenRequests atomic.Int32
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(cfg *CircuitBreakerConfig) *CircuitBreaker {
	if cfg == nil {
		cfg = DefaultCircuitBreakerConfig()
	}

	cb := &CircuitBreaker{
		config: cfg,
	}
	cb.state.Store(int32(CircuitClosed))

	return cb
}

// Execute executes a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(fn func() error) error {
	if !cb.allowRequest() {
		return ErrCircuitOpen
	}

	err := fn()
	cb.recordResult(err)
	return err
}

// ExecuteWithContext executes a function with circuit breaker protection and context
func (cb *CircuitBreaker) ExecuteWithContext(ctx context.Context, fn func(context.Context) error) error {
	if !cb.allowRequest() {
		return ErrCircuitOpen
	}

	err := fn(ctx)
	cb.recordResult(err)
	return err
}

// allowRequest checks if a request should be allowed
func (cb *CircuitBreaker) allowRequest() bool {
	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitClosed:
		return true

	case CircuitOpen:
		// Check if timeout has passed
		lastFailure := time.Unix(0, cb.lastFailure.Load())
		if time.Since(lastFailure) > cb.config.Timeout {
			// Transition to half-open
			cb.transitionTo(CircuitHalfOpen)
			return cb.allowHalfOpenRequest()
		}
		return false

	case CircuitHalfOpen:
		return cb.allowHalfOpenRequest()

	default:
		return false
	}
}

// allowHalfOpenRequest checks if a request should be allowed in half-open state
func (cb *CircuitBreaker) allowHalfOpenRequest() bool {
	current := cb.halfOpenRequests.Add(1)
	if current > int32(cb.config.MaxConcurrent) { //nolint:gosec,G115
		cb.halfOpenRequests.Add(-1)
		return false
	}
	return true
}

// recordResult records the result of a request
func (cb *CircuitBreaker) recordResult(err error) {
	state := CircuitState(cb.state.Load())

	if state == CircuitHalfOpen {
		cb.halfOpenRequests.Add(-1)
	}

	if err != nil {
		cb.recordFailure()
	} else {
		cb.recordSuccess()
	}
}

// recordFailure records a failure
func (cb *CircuitBreaker) recordFailure() {
	cb.lastFailure.Store(time.Now().UnixNano())
	failures := cb.failures.Add(1)
	cb.successes.Store(0)

	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitClosed:
		if int(failures) >= cb.config.FailureThreshold {
			cb.transitionTo(CircuitOpen)
		}

	case CircuitHalfOpen:
		// Any failure in half-open state opens the circuit
		cb.transitionTo(CircuitOpen)
	}
}

// recordSuccess records a success
func (cb *CircuitBreaker) recordSuccess() {
	cb.failures.Store(0)
	successes := cb.successes.Add(1)

	state := CircuitState(cb.state.Load())

	if state == CircuitHalfOpen {
		if int(successes) >= cb.config.SuccessThreshold {
			cb.transitionTo(CircuitClosed)
		}
	}
}

// transitionTo transitions to a new state
func (cb *CircuitBreaker) transitionTo(newState CircuitState) {
	oldState := CircuitState(cb.state.Swap(int32(newState)))

	if oldState != newState {
		// Reset counters on state change
		cb.failures.Store(0)
		cb.successes.Store(0)
		cb.halfOpenRequests.Store(0)

		// Call state change callback
		if cb.config.OnStateChange != nil {
			cb.config.OnStateChange(cb.config.Name, oldState, newState)
		}
	}
}

// State returns the current circuit state
func (cb *CircuitBreaker) State() CircuitState {
	return CircuitState(cb.state.Load())
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.transitionTo(CircuitClosed)
}

// ForceOpen forces the circuit breaker to open state
func (cb *CircuitBreaker) ForceOpen() {
	cb.transitionTo(CircuitOpen)
}

// Stats returns circuit breaker statistics
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	return CircuitBreakerStats{
		Name:        cb.config.Name,
		State:       cb.State(),
		Failures:    int(cb.failures.Load()),
		Successes:   int(cb.successes.Load()),
		LastFailure: time.Unix(0, cb.lastFailure.Load()),
	}
}

// CircuitBreakerStats holds circuit breaker statistics
type CircuitBreakerStats struct {
	Name        string
	State       CircuitState
	Failures    int
	Successes   int
	LastFailure time.Time
}
