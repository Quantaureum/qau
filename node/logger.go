// Quantaureum Node source, version 1.0.0.
// audit-fix R3-Info-3: structured logging for the node package.
// Replaces ad-hoc fmt.Printf calls with leveled, component-tagged output.
// When LogFormat is "json", output is machine-parsable; otherwise human-readable text.
package node

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Logger wraps slog with printf-style convenience methods and a component label.
type Logger struct {
	component string
}

// Package-level component loggers.
var (
	nodeLog = &Logger{component: "Node"}
	bpLog   = &Logger{component: "BlockProducer"}
	syncLog = &Logger{component: "Syncer"}
)

var (
	logLevel slog.LevelVar
	logOnce  sync.Once
)

// InitLogging configures the package-level structured logger.
// Must be called once during node startup; subsequent calls are no-ops.
func InitLogging(level, format string) {
	logOnce.Do(func() {
		applyLogLevel(level)

		opts := &slog.HandlerOptions{Level: &logLevel}
		var handler slog.Handler
		if strings.ToLower(format) == "json" {
			handler = slog.NewJSONHandler(os.Stdout, opts)
		} else {
			handler = slog.NewTextHandler(os.Stdout, opts)
		}
		slog.SetDefault(slog.New(handler))
	})
}

// applyLogLevel maps a config log level string onto the shared slog.LevelVar.
// The handler created in InitLogging holds a pointer to logLevel, so updates
// here take effect immediately for all already-emitted loggers.
func applyLogLevel(level string) {
	switch strings.ToLower(level) {
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "warn", "warning":
		logLevel.Set(slog.LevelWarn)
	case "error":
		logLevel.Set(slog.LevelError)
	default:
		logLevel.Set(slog.LevelInfo)
	}
}

// SetLogLevel updates the active log level at runtime without re-creating the
// handler. It is safe to call after InitLogging (the handler references the
// shared LevelVar) and is used by config hot-reload (audit-fix M6-3) to apply
// a reloaded LogLevel immediately. If called before InitLogging, the level is
// still recorded and will be honored when the handler is first created.
func SetLogLevel(level string) {
	applyLogLevel(level)
}

// Debug logs a debug-level message.
func (l *Logger) Debug(format string, args ...any) {
	slog.Default().Debug(fmt.Sprintf(format, args...), "component", l.component)
}

// Info logs an info-level message.
func (l *Logger) Info(format string, args ...any) {
	slog.Default().Info(fmt.Sprintf(format, args...), "component", l.component)
}

// Warn logs a warning-level message.
func (l *Logger) Warn(format string, args ...any) {
	slog.Default().Warn(fmt.Sprintf(format, args...), "component", l.component)
}

// Error logs an error-level message.
func (l *Logger) Error(format string, args ...any) {
	slog.Default().Error(fmt.Sprintf(format, args...), "component", l.component)
}

// Fatal logs a fatal-level message and exits the program.
func (l *Logger) Fatal(format string, args ...any) {
	slog.Default().Error(fmt.Sprintf(format, args...), "component", l.component)
	os.Exit(1)
}
