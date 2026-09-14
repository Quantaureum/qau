// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"
)

// ── Logger creation ──

func TestLogger_Component(t *testing.T) {
	l := &Logger{component: "TestComponent"}
	if l.component != "TestComponent" {
		t.Errorf("expected component 'TestComponent', got '%s'", l.component)
	}
}

// ── Logger methods (just verify they don't panic) ──

func TestLogger_Debug(t *testing.T) {
	l := &Logger{component: "Test"}
	l.Debug("debug message %d", 42)
}

func TestLogger_Info(t *testing.T) {
	l := &Logger{component: "Test"}
	l.Info("info message %s", "hello")
}

func TestLogger_Warn(t *testing.T) {
	l := &Logger{component: "Test"}
	l.Warn("warn message %v", "something")
}

func TestLogger_Error(t *testing.T) {
	l := &Logger{component: "Test"}
	l.Error("error message %d", 500)
}

// ── InitLogging ──

func TestInitLogging_InfoLevel(t *testing.T) {
	// Should not panic with valid level
	InitLogging("info", "text")
}

func TestInitLogging_DebugLevel(t *testing.T) {
	InitLogging("debug", "text")
}

func TestInitLogging_WarnLevel(t *testing.T) {
	InitLogging("warn", "text")
}

func TestInitLogging_ErrorLevel(t *testing.T) {
	InitLogging("error", "text")
}

func TestInitLogging_JSONFormat(t *testing.T) {
	InitLogging("info", "json")
}

func TestInitLogging_TextFormat(t *testing.T) {
	InitLogging("info", "text")
}

func TestInitLogging_UnknownLevel(t *testing.T) {
	// Unknown level should default to info
	InitLogging("unknown", "text")
}

func TestInitLogging_Idempotent(t *testing.T) {
	// Calling InitLogging multiple times should not panic
	// (sync.Once ensures it only initializes once)
	InitLogging("debug", "json")
	InitLogging("error", "text")
	InitLogging("info", "json")
}

// ── Package-level loggers ──

func TestPackageLoggers(t *testing.T) {
	// Verify package-level loggers exist and can be used
	nodeLog.Info("nodeLog test")
	bpLog.Info("bpLog test")
	syncLog.Info("syncLog test")
}
