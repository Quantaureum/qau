// Quantaureum Node source, version 1.0.0.
package ha

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestDefaultHealthServerConfig(t *testing.T) {
	cfg := DefaultHealthServerConfig()
	if cfg.Addr != ":8080" {
		t.Errorf("expected :8080, got %s", cfg.Addr)
	}
	if cfg.Version != "1.0.0" {
		t.Errorf("expected 1.0.0, got %s", cfg.Version)
	}
	if cfg.ReadTimeout != 5*time.Second {
		t.Errorf("expected 5s, got %v", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 5*time.Second {
		t.Errorf("expected 5s, got %v", cfg.WriteTimeout)
	}
}

func TestNewHealthServer_NilConfig(t *testing.T) {
	hs := NewHealthServer(nil)
	if hs == nil {
		t.Fatal("expected non-nil server")
	}
	if hs.version != "1.0.0" {
		t.Errorf("expected 1.0.0, got %s", hs.version)
	}
}

func TestNewHealthServer_WithConfig(t *testing.T) {
	cfg := &HealthServerConfig{
		Addr:    ":9999",
		Version: "2.0.0",
	}
	hs := NewHealthServer(cfg)
	if hs == nil {
		t.Fatal("expected non-nil server")
	}
	if hs.version != "2.0.0" {
		t.Errorf("expected 2.0.0, got %s", hs.version)
	}
}

func TestHealthServer_RegisterHealthChecker(t *testing.T) {
	hs := NewHealthServer(nil)
	hs.RegisterHealthChecker(func(ctx context.Context) ComponentHealth {
		return ComponentHealth{Name: "db", Status: StatusHealthy}
	})
	hs.RegisterHealthChecker(func(ctx context.Context) ComponentHealth {
		return ComponentHealth{Name: "cache", Status: StatusHealthy}
	})
	if len(hs.healthCheckers) != 2 {
		t.Errorf("expected 2, got %d", len(hs.healthCheckers))
	}
}

func TestHealthServer_RegisterReadinessChecker(t *testing.T) {
	hs := NewHealthServer(nil)
	hs.RegisterReadinessChecker(func(ctx context.Context) ReadinessCheck {
		return ReadinessCheck{Name: "db", Ready: true}
	})
	if len(hs.readinessCheckers) != 1 {
		t.Errorf("expected 1, got %d", len(hs.readinessCheckers))
	}
}

func TestHealthServer_SetReady_IsReady(t *testing.T) {
	hs := NewHealthServer(nil)
	if hs.IsReady() {
		t.Error("expected not ready by default")
	}
	hs.SetReady(true)
	if !hs.IsReady() {
		t.Error("expected ready")
	}
	hs.SetReady(false)
	if hs.IsReady() {
		t.Error("expected not ready")
	}
}

func TestHealthServer_HandleHealth(t *testing.T) {
	hs := NewHealthServer(nil)
	hs.RegisterHealthChecker(func(ctx context.Context) ComponentHealth {
		return ComponentHealth{Name: "db", Status: StatusHealthy}
	})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	hs.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("expected json content type")
	}
}

func TestHealthServer_HandleHealth_Unhealthy(t *testing.T) {
	hs := NewHealthServer(nil)
	hs.RegisterHealthChecker(func(ctx context.Context) ComponentHealth {
		return ComponentHealth{Name: "db", Status: StatusUnhealthy}
	})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	hs.handleHealth(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestHealthServer_HandleHealth_Degraded(t *testing.T) {
	hs := NewHealthServer(nil)
	hs.RegisterHealthChecker(func(ctx context.Context) ComponentHealth {
		return ComponentHealth{Name: "db", Status: StatusDegraded}
	})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	hs.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHealthServer_HandleHealth_ShuttingDown(t *testing.T) {
	sh := NewShutdownHandler(nil)
	sh.Shutdown()
	hs := NewHealthServer(&HealthServerConfig{ShutdownHandler: sh})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	hs.handleHealth(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestHealthServer_HandleReady(t *testing.T) {
	hs := NewHealthServer(nil)
	hs.SetReady(true)

	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	hs.handleReady(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHealthServer_HandleReady_NotReady(t *testing.T) {
	hs := NewHealthServer(nil)
	hs.SetReady(false)

	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	hs.handleReady(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestHealthServer_HandleReady_WithChecker(t *testing.T) {
	hs := NewHealthServer(nil)
	hs.SetReady(true)
	hs.RegisterReadinessChecker(func(ctx context.Context) ReadinessCheck {
		return ReadinessCheck{Name: "db", Ready: false}
	})

	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	hs.handleReady(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestHealthServer_HandleReady_ShuttingDown(t *testing.T) {
	sh := NewShutdownHandler(nil)
	sh.Shutdown()
	hs := NewHealthServer(&HealthServerConfig{ShutdownHandler: sh})

	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	hs.handleReady(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestHealthServer_HandleLive(t *testing.T) {
	hs := NewHealthServer(nil)

	req := httptest.NewRequest("GET", "/live", nil)
	w := httptest.NewRecorder()
	hs.handleLive(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHealthServer_HandleLive_Stopped(t *testing.T) {
	sh := NewShutdownHandler(nil)
	sh.Shutdown()
	hs := NewHealthServer(&HealthServerConfig{ShutdownHandler: sh})

	req := httptest.NewRequest("GET", "/live", nil)
	w := httptest.NewRecorder()
	hs.handleLive(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestHealthStatus_Values(t *testing.T) {
	if StatusHealthy != "healthy" {
		t.Errorf("expected healthy, got %s", StatusHealthy)
	}
	if StatusUnhealthy != "unhealthy" {
		t.Errorf("expected unhealthy, got %s", StatusUnhealthy)
	}
	if StatusDegraded != "degraded" {
		t.Errorf("expected degraded, got %s", StatusDegraded)
	}
}

func TestComponentHealth(t *testing.T) {
	ch := ComponentHealth{
		Name:    "test",
		Status:  StatusHealthy,
		Message: "ok",
		Details: map[string]string{"key": "val"},
	}
	if ch.Name != "test" {
		t.Errorf("expected test, got %s", ch.Name)
	}
	if ch.Status != StatusHealthy {
		t.Errorf("expected healthy, got %s", ch.Status)
	}
}

func TestHealthResponse(t *testing.T) {
	hr := HealthResponse{
		Status:    StatusHealthy,
		Timestamp: time.Now().UTC(),
		Version:   "1.0.0",
	}
	if hr.Status != StatusHealthy {
		t.Errorf("expected healthy, got %s", hr.Status)
	}
}

func TestReadinessResponse(t *testing.T) {
	rr := ReadinessResponse{
		Ready:     true,
		Timestamp: time.Now().UTC(),
	}
	if !rr.Ready {
		t.Error("expected true")
	}
}

func TestReadinessCheck(t *testing.T) {
	rc := ReadinessCheck{
		Name:   "db",
		Ready:  false,
		Reason: "timeout",
	}
	if rc.Ready {
		t.Error("expected false")
	}
}

func TestSubsystemState_String(t *testing.T) {
	tests := []struct {
		state SubsystemState
		want  string
	}{
		{SubsystemStopped, "stopped"},
		{SubsystemStarting, "starting"},
		{SubsystemRunning, "running"},
		{SubsystemFailed, "failed"},
		{SubsystemRecovering, "recovering"},
		{SubsystemState(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestDefaultRecoveryManagerConfig(t *testing.T) {
	cfg := DefaultRecoveryManagerConfig()
	if cfg.CheckInterval != 10*time.Second {
		t.Errorf("expected 10s, got %v", cfg.CheckInterval)
	}
	if cfg.MaxRetries != 3 {
		t.Errorf("expected 3, got %d", cfg.MaxRetries)
	}
	if cfg.RetryInterval != 5*time.Second {
		t.Errorf("expected 5s, got %v", cfg.RetryInterval)
	}
}

func TestNewRecoveryManager_NilConfig(t *testing.T) {
	rm := NewRecoveryManager(nil)
	if rm == nil {
		t.Fatal("expected non-nil")
	}
	if rm.checkInterval != 10*time.Second {
		t.Errorf("expected 10s, got %v", rm.checkInterval)
	}
	rm.cancel()
}

func TestNewRecoveryManager_WithCallbacks(t *testing.T) {
	var recoveryCalled, stateChanged bool
	cfg := &RecoveryManagerConfig{
		OnRecovery: func(name string, success bool, err error) {
			recoveryCalled = true
		},
		OnStateChange: func(name string, from, to SubsystemState) {
			stateChanged = true
		},
	}
	rm := NewRecoveryManager(cfg)
	if rm.onRecovery == nil {
		t.Error("expected OnRecovery set")
	}
	if rm.onStateChange == nil {
		t.Error("expected OnStateChange set")
	}
	_ = recoveryCalled
	_ = stateChanged
	rm.cancel()
}

func TestNewSubsystem_Basic(t *testing.T) {
	s := NewSubsystem(&SubsystemConfig{
		Name: "test",
	})
	if s == nil {
		t.Fatal("expected non-nil")
	}
	if s.State() != SubsystemStopped {
		t.Errorf("expected stopped, got %s", s.State())
	}
	if s.Name != "test" {
		t.Errorf("expected test, got %s", s.Name)
	}
}

func TestNewSubsystem_WithCircuitBreaker(t *testing.T) {
	s := NewSubsystem(&SubsystemConfig{
		Name: "test",
		CircuitBreaker: &CircuitBreakerConfig{
			FailureThreshold: 3,
			Timeout:          time.Second,
		},
	})
	if s == nil {
		t.Fatal("expected non-nil")
	}
	if s.circuitBreaker == nil {
		t.Error("expected circuit breaker")
	}
}

func TestSubsystem_State_SetState(t *testing.T) {
	s := NewSubsystem(&SubsystemConfig{Name: "test"})
	s.SetState(SubsystemRunning)
	if s.State() != SubsystemRunning {
		t.Errorf("expected running, got %s", s.State())
	}
}

func TestSubsystem_RecordFailure_Failures(t *testing.T) {
	s := NewSubsystem(&SubsystemConfig{Name: "test"})
	if s.Failures() != 0 {
		t.Errorf("expected 0, got %d", s.Failures())
	}
	s.RecordFailure()
	if s.Failures() != 1 {
		t.Errorf("expected 1, got %d", s.Failures())
	}
	s.RecordFailure()
	if s.Failures() != 2 {
		t.Errorf("expected 2, got %d", s.Failures())
	}
}

func TestSubsystem_ResetFailures(t *testing.T) {
	s := NewSubsystem(&SubsystemConfig{Name: "test"})
	s.RecordFailure()
	s.RecordFailure()
	s.ResetFailures()
	if s.Failures() != 0 {
		t.Errorf("expected 0, got %d", s.Failures())
	}
}

func TestSubsystem_LastFailure(t *testing.T) {
	s := NewSubsystem(&SubsystemConfig{Name: "test"})
	before := time.Now()
	s.RecordFailure()
	after := time.Now()
	lf := s.LastFailure()
	if lf.Before(before) || lf.After(after) {
		t.Errorf("expected last failure between %v and %v, got %v", before, after, lf)
	}
}

func TestRecoveryManager_RegisterSubsystem(t *testing.T) {
	rm := NewRecoveryManager(nil)
	defer rm.cancel()
	err := rm.RegisterSubsystem(&SubsystemConfig{Name: "test"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRecoveryManager_UnregisterSubsystem(t *testing.T) {
	rm := NewRecoveryManager(nil)
	defer rm.cancel()
	rm.RegisterSubsystem(&SubsystemConfig{Name: "test"})
	err := rm.UnregisterSubsystem("test")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRecoveryManager_UnregisterSubsystem_NotFound(t *testing.T) {
	rm := NewRecoveryManager(nil)
	defer rm.cancel()
	err := rm.UnregisterSubsystem("nonexistent")
	if err != ErrSubsystemNotFound {
		t.Errorf("expected ErrSubsystemNotFound, got %v", err)
	}
}

func TestRecoveryManager_GetSubsystemState(t *testing.T) {
	rm := NewRecoveryManager(nil)
	defer rm.cancel()
	rm.RegisterSubsystem(&SubsystemConfig{Name: "test"})
	state, err := rm.GetSubsystemState("test")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if state != SubsystemStopped {
		t.Errorf("expected stopped, got %s", state)
	}
}

func TestRecoveryManager_GetSubsystemState_NotFound(t *testing.T) {
	rm := NewRecoveryManager(nil)
	defer rm.cancel()
	_, err := rm.GetSubsystemState("nonexistent")
	if err != ErrSubsystemNotFound {
		t.Errorf("expected ErrSubsystemNotFound, got %v", err)
	}
}

func TestRecoveryManager_GetAllSubsystemStates(t *testing.T) {
	rm := NewRecoveryManager(nil)
	defer rm.cancel()
	states := rm.GetAllSubsystemStates()
	if len(states) != 0 {
		t.Errorf("expected 0, got %d", len(states))
	}
	rm.RegisterSubsystem(&SubsystemConfig{Name: "test"})
	states = rm.GetAllSubsystemStates()
	if len(states) != 1 {
		t.Errorf("expected 1, got %d", len(states))
	}
}

func TestRecoveryManager_SetSubsystemRunning(t *testing.T) {
	rm := NewRecoveryManager(nil)
	defer rm.cancel()
	rm.RegisterSubsystem(&SubsystemConfig{Name: "test"})
	err := rm.SetSubsystemRunning("test")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	state, _ := rm.GetSubsystemState("test")
	if state != SubsystemRunning {
		t.Errorf("expected running, got %s", state)
	}
}

func TestRecoveryManager_SetSubsystemRunning_NotFound(t *testing.T) {
	rm := NewRecoveryManager(nil)
	defer rm.cancel()
	err := rm.SetSubsystemRunning("nonexistent")
	if err != ErrSubsystemNotFound {
		t.Errorf("expected ErrSubsystemNotFound, got %v", err)
	}
}

func TestRecoveryManager_RecoverSubsystem(t *testing.T) {
	rm := NewRecoveryManager(nil)
	defer rm.cancel()
	rm.RegisterSubsystem(&SubsystemConfig{Name: "test"})
	err := rm.RecoverSubsystem("test")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRecoveryManager_RecoverSubsystem_NotFound(t *testing.T) {
	rm := NewRecoveryManager(nil)
	defer rm.cancel()
	err := rm.RecoverSubsystem("nonexistent")
	if err != ErrSubsystemNotFound {
		t.Errorf("expected ErrSubsystemNotFound, got %v", err)
	}
}

func TestRecoveryErrors(t *testing.T) {
	if ErrSubsystemNotFound.Error() == "" {
		t.Error("expected non-empty error")
	}
	if ErrSubsystemNotRunning.Error() == "" {
		t.Error("expected non-empty error")
	}
	if ErrRecoveryFailed.Error() == "" {
		t.Error("expected non-empty error")
	}
	if ErrMaxRetriesExceeded.Error() == "" {
		t.Error("expected non-empty error")
	}
}

func TestDefaultShutdownConfig(t *testing.T) {
	cfg := DefaultShutdownConfig()
	if cfg.Timeout != 30*time.Second {
		t.Errorf("expected 30s, got %v", cfg.Timeout)
	}
	if len(cfg.Signals) != 2 {
		t.Errorf("expected 2 signals, got %d", len(cfg.Signals))
	}
}

func TestNewShutdownHandler_NilConfig(t *testing.T) {
	h := NewShutdownHandler(nil)
	if h == nil {
		t.Fatal("expected non-nil")
	}
	if h.State() != StateRunning {
		t.Errorf("expected running, got %d", h.State())
	}
	h.Stop()
}

func TestNewShutdownHandler_CustomConfig(t *testing.T) {
	cfg := &ShutdownConfig{
		Timeout: 10 * time.Second,
		Signals: nil,
	}
	h := NewShutdownHandler(cfg)
	if h.timeout != 10*time.Second {
		t.Errorf("expected 10s, got %v", h.timeout)
	}
	h.Stop()
}

func TestShutdownHandler_RegisterHook(t *testing.T) {
	h := NewShutdownHandler(nil)
	defer h.Stop()
	h.RegisterHook(ShutdownHook{Name: "h1", Priority: 10, Fn: func(ctx context.Context) error { return nil }})
	h.RegisterHook(ShutdownHook{Name: "h2", Priority: 5, Fn: func(ctx context.Context) error { return nil }})
	h.RegisterHook(ShutdownHook{Name: "h3", Priority: 20, Fn: func(ctx context.Context) error { return nil }})

	h.hooksMu.RLock()
	hooks := h.hooks
	h.hooksMu.RUnlock()

	if len(hooks) != 3 {
		t.Fatalf("expected 3, got %d", len(hooks))
	}
	if hooks[0].Name != "h2" || hooks[1].Name != "h1" || hooks[2].Name != "h3" {
		t.Errorf("unexpected order: %s, %s, %s", hooks[0].Name, hooks[1].Name, hooks[2].Name)
	}
}

func TestShutdownHandler_SetOnShutdown(t *testing.T) {
	h := NewShutdownHandler(nil)
	defer h.Stop()
	called := false
	h.SetOnShutdown(func() { called = true })
	h.Shutdown()
	if !called {
		t.Error("onShutdown not called")
	}
}

func TestShutdownHandler_Shutdown(t *testing.T) {
	h := NewShutdownHandler(nil)
	defer h.Stop()

	hookCalled := false
	h.RegisterHook(ShutdownHook{Name: "test", Priority: 1, Fn: func(ctx context.Context) error {
		hookCalled = true
		return nil
	}})

	h.Shutdown()

	if h.State() != StateStopped {
		t.Errorf("expected stopped, got %d", h.State())
	}
	if !hookCalled {
		t.Error("hook not called")
	}
}

func TestShutdownHandler_ShutdownOnce(t *testing.T) {
	h := NewShutdownHandler(nil)
	defer h.Stop()
	var count int32
	h.SetOnShutdown(func() {
		count++
	})
	h.Shutdown()
	h.Shutdown()
	if count != 1 {
		t.Errorf("expected 1, got %d", count)
	}
}

func TestShutdownHandler_State(t *testing.T) {
	h := NewShutdownHandler(nil)
	defer h.Stop()
	if h.State() != StateRunning {
		t.Errorf("expected running, got %d", h.State())
	}
	h.Shutdown()
	if h.State() != StateStopped {
		t.Errorf("expected stopped, got %d", h.State())
	}
}

func TestShutdownHandler_IsShuttingDown_IsStopped(t *testing.T) {
	h := NewShutdownHandler(nil)
	defer h.Stop()
	if h.IsShuttingDown() {
		t.Error("expected not shutting down")
	}
	if h.IsStopped() {
		t.Error("expected not stopped")
	}
	h.Shutdown()
	if !h.IsShuttingDown() {
		t.Error("expected shutting down")
	}
	if !h.IsStopped() {
		t.Error("expected stopped")
	}
}

func TestShutdownHandler_Channels(t *testing.T) {
	h := NewShutdownHandler(nil)
	defer h.Stop()

	shutdownCh := h.ShutdownCh()
	doneCh := h.DoneCh()

	select {
	case <-shutdownCh:
		t.Error("shutdownCh should not be closed")
	default:
	}
	select {
	case <-doneCh:
		t.Error("doneCh should not be closed")
	default:
	}

	h.Shutdown()

	select {
	case <-shutdownCh:
	default:
		t.Error("shutdownCh should be closed")
	}
	select {
	case <-doneCh:
	default:
		t.Error("doneCh should be closed")
	}
}

func TestShutdownHandler_Wait(t *testing.T) {
	h := NewShutdownHandler(nil)
	defer h.Stop()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.Wait()
	}()
	h.Shutdown()
	wg.Wait()
}

func TestShutdownHandler_WaitForSignal(t *testing.T) {
	h := NewShutdownHandler(nil)
	defer h.Stop()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.WaitForSignal()
	}()
	h.Shutdown()
	wg.Wait()
}

func TestShutdownHandler_Stop(t *testing.T) {
	h := NewShutdownHandler(nil)
	h.Stop()
}
