// Quantaureum Node source, version 1.0.0.
package ha

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestCircuitState_String(t *testing.T) {
	tests := []struct {
		state CircuitState
		want  string
	}{
		{CircuitClosed, "closed"},
		{CircuitOpen, "open"},
		{CircuitHalfOpen, "half-open"},
		{CircuitState(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestDefaultCircuitBreakerConfig(t *testing.T) {
	cfg := DefaultCircuitBreakerConfig()
	if cfg.Name != "default" {
		t.Errorf("expected default, got %s", cfg.Name)
	}
	if cfg.FailureThreshold != 5 {
		t.Errorf("expected 5, got %d", cfg.FailureThreshold)
	}
	if cfg.SuccessThreshold != 3 {
		t.Errorf("expected 3, got %d", cfg.SuccessThreshold)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("expected 30s, got %v", cfg.Timeout)
	}
	if cfg.MaxConcurrent != 1 {
		t.Errorf("expected 1, got %d", cfg.MaxConcurrent)
	}
}

func TestNewCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker(nil)
	if cb == nil {
		t.Fatal("expected non-nil breaker")
	}
	if cb.State() != CircuitClosed {
		t.Error("expected closed state")
	}

	cb2 := NewCircuitBreaker(&CircuitBreakerConfig{Name: "custom", FailureThreshold: 10, SuccessThreshold: 5, Timeout: time.Second})
	if cb2.config.Name != "custom" {
		t.Errorf("expected custom, got %s", cb2.config.Name)
	}
}

func TestCircuitBreaker_State(t *testing.T) {
	cb := NewCircuitBreaker(nil)
	if cb.State() != CircuitClosed {
		t.Error("expected closed")
	}
}

func TestCircuitBreaker_Reset(t *testing.T) {
	cb := NewCircuitBreaker(nil)
	cb.ForceOpen()
	if cb.State() != CircuitOpen {
		t.Error("expected open after ForceOpen")
	}
	cb.Reset()
	if cb.State() != CircuitClosed {
		t.Error("expected closed after Reset")
	}
}

func TestCircuitBreaker_ForceOpen(t *testing.T) {
	cb := NewCircuitBreaker(nil)
	cb.ForceOpen()
	if cb.State() != CircuitOpen {
		t.Error("expected open")
	}
}

func TestCircuitBreaker_Execute_Success(t *testing.T) {
	cb := NewCircuitBreaker(nil)
	err := cb.Execute(func() error {
		return nil
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCircuitBreaker_Execute_Error(t *testing.T) {
	cb := NewCircuitBreaker(nil)
	testErr := errors.New("test error")
	err := cb.Execute(func() error {
		return testErr
	})
	if err != testErr {
		t.Errorf("expected testErr, got %v", err)
	}
}

func TestCircuitBreaker_Execute_OpensOnThreshold(t *testing.T) {
	cfg := &CircuitBreakerConfig{FailureThreshold: 2, SuccessThreshold: 2, Timeout: time.Hour}
	cb := NewCircuitBreaker(cfg)

	err := cb.Execute(func() error { return errors.New("fail1") })
	_ = err
	if cb.State() != CircuitClosed {
		t.Error("should still be closed after 1 failure")
	}

	err = cb.Execute(func() error { return errors.New("fail2") })
	_ = err
	time.Sleep(10 * time.Millisecond)
	if cb.State() != CircuitOpen {
		t.Errorf("expected open, got %s", cb.State())
	}
}

func TestCircuitBreaker_Execute_RejectsWhenOpen(t *testing.T) {
	cfg := &CircuitBreakerConfig{FailureThreshold: 1, SuccessThreshold: 2, Timeout: time.Hour}
	cb := NewCircuitBreaker(cfg)

	cb.Execute(func() error { return errors.New("fail") })

	err := cb.Execute(func() error { return nil })
	if err != ErrCircuitOpen {
		t.Errorf("expected ErrCircuitOpen, got %v", err)
	}
}

func TestCircuitBreaker_ExecuteWithContext(t *testing.T) {
	cb := NewCircuitBreaker(nil)
	ctx := context.Background()
	err := cb.ExecuteWithContext(ctx, func(_ context.Context) error {
		return nil
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCircuitBreaker_ExecuteWithContext_Open(t *testing.T) {
	cfg := &CircuitBreakerConfig{FailureThreshold: 1, SuccessThreshold: 2, Timeout: time.Hour}
	cb := NewCircuitBreaker(cfg)

	cb.Execute(func() error { return errors.New("fail") })

	err := cb.ExecuteWithContext(context.Background(), func(_ context.Context) error {
		return nil
	})
	if err != ErrCircuitOpen {
		t.Errorf("expected ErrCircuitOpen, got %v", err)
	}
}

func TestCircuitBreaker_Stats(t *testing.T) {
	cb := NewCircuitBreaker(nil)
	stats := cb.Stats()
	if stats.Name != "default" {
		t.Errorf("expected default, got %s", stats.Name)
	}
	if stats.State != CircuitClosed {
		t.Error("expected closed")
	}
}

func TestCircuitBreaker_OnStateChange(t *testing.T) {
	var mu sync.Mutex
	transitions := make([]string, 0)
	cfg := &CircuitBreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 2,
		Timeout:          10 * time.Millisecond,
		OnStateChange: func(name string, from, to CircuitState) {
			mu.Lock()
			transitions = append(transitions, from.String()+"->"+to.String())
			mu.Unlock()
		},
	}
	cb := NewCircuitBreaker(cfg)

	cb.Execute(func() error { return errors.New("fail") })
	time.Sleep(20 * time.Millisecond)
	cb.Execute(func() error { return nil })
	cb.Execute(func() error { return nil })

	mu.Lock()
	defer mu.Unlock()
	if len(transitions) == 0 {
		t.Error("expected state transitions")
	}
}

func TestCircuitBreaker_Execute_Concurrent(t *testing.T) {
	cfg := &CircuitBreakerConfig{FailureThreshold: 100, SuccessThreshold: 10, Timeout: time.Hour, MaxConcurrent: 5}
	cb := NewCircuitBreaker(cfg)

	var wg sync.WaitGroup
	errors := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- cb.Execute(func() error { return nil })
		}()
	}
	wg.Wait()
	close(errors)

	for err := range errors {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}
}
