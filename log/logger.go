// Quantaureum Node source, version 1.0.0.
// Package logging provides structured JSON logging for Quantaureum.
//
// L14-038 SECURITY NOTE: Log rotation is not implemented in the logger
// itself. Production deployments should use external log rotation tools
// (e.g., logrotate on Linux, systemd journal rotation) to prevent log
// files from consuming all available disk space. Log files may contain
// sensitive information (addresses, transaction hashes) and should be
// stored with restrictive file permissions (0600) and retained according
// to the deployment's data retention policy.
package log

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
)

// Level represents a log level
type Level int

const (
	// LevelDebug is the debug log level
	LevelDebug Level = iota
	// LevelInfo is the info log level
	LevelInfo
	// LevelWarn is the warning log level
	LevelWarn
	// LevelError is the error log level
	LevelError
	// LevelFatal is the fatal log level
	LevelFatal
)

// String returns the string representation of the level
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	case LevelFatal:
		return "fatal"
	default:
		return "unknown"
	}
}

// ParseLevel parses a log level string
func ParseLevel(s string) Level {
	switch s {
	case "debug", "DEBUG":
		return LevelDebug
	case "info", "INFO":
		return LevelInfo
	case "warn", "WARN", "warning", "WARNING":
		return LevelWarn
	case "error", "ERROR":
		return LevelError
	case "fatal", "FATAL":
		return LevelFatal
	default:
		return LevelInfo
	}
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp string         `json:"timestamp"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Module    string         `json:"module,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
	Caller    string         `json:"caller,omitempty"`
	Stack     string         `json:"stack,omitempty"`
}

// Logger is a structured JSON logger
type Logger struct {
	mu            sync.Mutex
	output        io.Writer
	level         Level
	module        string
	fields        map[string]any
	includeCaller bool
	// P3-NODE-04 (2026-07-27): includeStack controls whether Error/Fatal
	// entries capture a goroutine stack trace. Default false (opt-in) to
	// prevent leaking key material (Dilithium3 private keys 4000 bytes,
	// Kyber768 private keys 2400 bytes, AES-256-GCM keys, etc.) from the
	// goroutine stack into log files. When true, the captured stack is
	// passed through SanitizeString to redact long hex/base64 patterns.
	includeStack bool
	timeFormat   string
	fatalHandler func() // audit-fix M3: configurable fatal handler instead of hardcoded os.Exit
}

// FatalHandler is the package-level default handler called on fatal errors.
// Set this to customize cleanup behavior before process exit.
// Default: os.Exit(1)
var FatalHandler = func() { os.Exit(1) }

// Config holds logger configuration
type Config struct {
	Output        io.Writer
	Level         Level
	Module        string
	IncludeCaller bool
	// P3-NODE-04 (2026-07-27): IncludeStack makes stack capture OPT-IN.
	// Default false. When true, Error/Fatal entries include a sanitized
	// goroutine stack trace for development debugging. Leaving this false
	// in production prevents leaking key material from the goroutine stack
	// (Dilithium3/Kyber768 private keys, AES keys, etc.) into log files.
	IncludeStack bool
	TimeFormat   string
}

// DefaultConfig returns default logger configuration
func DefaultConfig() *Config {
	return &Config{
		Output:        os.Stdout,
		Level:         LevelInfo,
		Module:        "",
		IncludeCaller: false,
		IncludeStack:  false,
		TimeFormat:    time.RFC3339Nano,
	}
}

// New creates a new Logger
func New(cfg *Config) *Logger {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.Output == nil {
		cfg.Output = os.Stdout
	}
	if cfg.TimeFormat == "" {
		cfg.TimeFormat = time.RFC3339Nano
	}

	return &Logger{
		output:        cfg.Output,
		level:         cfg.Level,
		module:        cfg.Module,
		fields:        make(map[string]any),
		includeCaller: cfg.IncludeCaller,
		includeStack:  cfg.IncludeStack,
		timeFormat:    cfg.TimeFormat,
	}
}

// WithModule creates a new logger with the specified module name
func (l *Logger) WithModule(module string) *Logger {
	return &Logger{
		output:        l.output,
		level:         l.level,
		module:        module,
		fields:        copyFields(l.fields),
		includeCaller: l.includeCaller,
		includeStack:  l.includeStack,
		timeFormat:    l.timeFormat,
		fatalHandler:  l.fatalHandler,
	}
}

// WithField creates a new logger with an additional field
func (l *Logger) WithField(key string, value any) *Logger {
	newFields := copyFields(l.fields)
	newFields[key] = value
	return &Logger{
		output:        l.output,
		level:         l.level,
		module:        l.module,
		fields:        newFields,
		includeCaller: l.includeCaller,
		includeStack:  l.includeStack,
		timeFormat:    l.timeFormat,
		fatalHandler:  l.fatalHandler,
	}
}

// WithFields creates a new logger with additional fields
func (l *Logger) WithFields(fields map[string]any) *Logger {
	newFields := copyFields(l.fields)
	for k, v := range fields {
		newFields[k] = v
	}
	return &Logger{
		output:        l.output,
		level:         l.level,
		module:        l.module,
		fields:        newFields,
		includeCaller: l.includeCaller,
		includeStack:  l.includeStack,
		timeFormat:    l.timeFormat,
		fatalHandler:  l.fatalHandler,
	}
}

// SetIncludeStack toggles stack capture at runtime.
// P3-NODE-04 (2026-07-27): allows operators to enable stack capture for
// debugging without restarting the process. Stack capture is still
// restricted to Error/Fatal levels and the captured stack is sanitized.
func (l *Logger) SetIncludeStack(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.includeStack = enabled
}

// SetLevel sets the log level
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetFatalHandler sets a custom fatal handler for this logger.
// When nil, the package-level FatalHandler is used.
func (l *Logger) SetFatalHandler(handler func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fatalHandler = handler
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// SetOutput sets the output writer
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

// log writes a log entry at the specified level
func (l *Logger) log(level Level, msg string, fields map[string]any) {
	if level < l.getLevel() {
		return
	}

	// Sanitize message and fields to prevent sensitive data leakage (#127)
	msg = SanitizeString(msg)

	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(l.getTimeFormat()),
		Level:     level.String(),
		Message:   msg,
		Module:    l.module,
	}

	// Merge fields
	if len(l.fields) > 0 || len(fields) > 0 {
		entry.Fields = make(map[string]any)
		for k, v := range l.fields {
			entry.Fields[k] = v
		}
		for k, v := range fields {
			entry.Fields[k] = v
		}
		// Sanitize merged fields to redact sensitive values
		entry.Fields = SanitizeFields(entry.Fields)
	}

	// Add caller info if enabled
	if l.includeCaller {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			entry.Caller = fmt.Sprintf("%s:%d", file, line)
		}
	}

	// P3-NODE-04 (2026-07-27): Only capture a goroutine stack trace when
	// includeStack is explicitly enabled (opt-in). Previously, the logger
	// unconditionally called runtime.Stack() for every Error/Fatal entry,
	// potentially leaking key material (Dilithium3 private keys 4000 bytes,
	// Kyber768 private keys 2400 bytes, AES-256-GCM keys, etc.) from the
	// goroutine stack into log files. Stack capture is restricted to
	// Error/Fatal levels; Info/Warn never capture a stack even when
	// includeStack is true. The captured stack is passed through
	// SanitizeString to redact long hex/base64 patterns as defense-in-depth.
	if level >= LevelError && l.getIncludeStack() {
		buf := make([]byte, 8192)
		n := runtime.Stack(buf, false)
		// Grow buffer if truncated (stack > 8KB). runtime.Stack returns the
		// full stack when the buffer is large enough; if n == len(buf), the
		// stack may have been truncated. Retry once with a larger buffer.
		if n == len(buf) {
			buf = make([]byte, 65536)
			n = runtime.Stack(buf, false)
		}
		entry.Stack = SanitizeString(string(buf[:n]))
	}

	l.writeEntry(&entry)
}

// getLevel returns the current log level under the mutex.
func (l *Logger) getLevel() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// getIncludeStack returns the includeStack flag under the mutex.
func (l *Logger) getIncludeStack() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.includeStack
}

// getTimeFormat returns the time format under the mutex.
func (l *Logger) getTimeFormat() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.timeFormat
}

// writeEntry writes a log entry to the output as JSON
func (l *Logger) writeEntry(entry *LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Output as JSON for structured logging
	data, err := json.Marshal(entry)
	if err != nil {
		// Fallback to simple format if JSON marshaling fails
		fmt.Fprintf(l.output, "[%s] [%s] %s\n", entry.Timestamp, entry.Level, entry.Message)
		return
	}
	fmt.Fprintln(l.output, string(data))
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, fields ...map[string]any) {
	var f map[string]any
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LevelDebug, msg, f)
}

// Info logs an info message
func (l *Logger) Info(msg string, fields ...map[string]any) {
	var f map[string]any
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LevelInfo, msg, f)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, fields ...map[string]any) {
	var f map[string]any
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LevelWarn, msg, f)
}

// Error logs an error message
func (l *Logger) Error(msg string, fields ...map[string]any) {
	var f map[string]any
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LevelError, msg, f)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, fields ...map[string]any) {
	var f map[string]any
	if len(fields) > 0 {
		f = fields[0]
	}
	l.log(LevelFatal, msg, f)
	if l.fatalHandler != nil {
		l.fatalHandler()
	} else {
		FatalHandler()
	}
}

// maxFormatStringLength is the maximum allowed length for a format string.
// L10-016 FIX: Prevents log-based memory exhaustion from oversized format strings.
const maxFormatStringLength = 4096

// safeFormatString validates that a format string only contains safe format verbs.
// It prevents format string attacks by rejecting specifiers that can write to memory
// or leak sensitive information like addresses.
func safeFormatString(format string) bool {
	// L10-016 FIX: Limit format string length to prevent memory exhaustion.
	if len(format) > maxFormatStringLength {
		return false
	}
	// Check for dangerous format specifiers that can write to memory or leak addresses
	dangerousSpecifiers := []string{
		"%n",   // Write count to variable - can corrupt memory
		"%p",   // Pointer address - can leak ASLR addresses
		"%lld", // Long long decimal - platform specific
		"%llu", // Long long unsigned - platform specific
		"%ld",  // Long decimal - platform specific
		"%lu",  // Long unsigned - platform specific
		"%hd",  // Half decimal - can cause integer truncation issues
		"%hu",  // Half unsigned - can cause integer truncation issues
		"%hhd", // Half half decimal - can cause integer truncation issues
		"%hhu", // Half half unsigned - can cause integer truncation issues
		"%zd",  // Size_t decimal - platform specific
		"%zu",  // Size_t unsigned - platform specific
		"%td",  // ptrdiff_t decimal - platform specific
		"%tx",  // pointer as hex - leaks addresses
		// L6-053/L7-004 FIX: Removed %g, %e, %a, %A from the dangerous list.
		// These are standard Go float format verbs that do not write to memory
		// like %n and do not leak addresses like %p. 'Precision issues' is a
		// usability concern, not a security one, and blocking them silently
		// discarded legitimate float logging (gas prices, stake amounts, etc).
	}

	for _, spec := range dangerousSpecifiers {
		if containsDangerousSpecifier(format, spec) {
			return false
		}
	}
	return true
}

// containsDangerousSpecifier reports whether `format` contains `spec` at a
// real format-verb introducer (a '%' that is NOT part of an escaped "%%").
// L7-016 FIX: the previous naive substring match (contains) flagged "%%n"
// (an escaped percent followed by a literal 'n') as the dangerous "%n"
// verb, a false positive that silently blocked safe format strings.
// Matching only at real '%' introducers keeps multi-character specifiers
// (e.g. "%td", "%tx") working while ignoring escaped percents.
// L8-016 CONFIRMED FIXED: containsDangerousSpecifier uses precise matching at
// real '%' introducers (L7-016 FIX), correctly skipping escaped "%%" sequences.
// This eliminates false positives like "%%n" being flagged as dangerous "%n".
func containsDangerousSpecifier(format, spec string) bool {
	n := len(spec)
	if n == 0 || n > len(format) {
		return false
	}
	for i := 0; i+n <= len(format); i++ {
		if format[i] != '%' {
			continue
		}
		// Skip escaped "%%": advance past both percent signs (the loop's
		// own i++ handles the second one).
		if i+1 < len(format) && format[i+1] == '%' {
			i++
			continue
		}
		if format[i:i+n] == spec {
			return true
		}
	}
	return false
}

// Debugf logs a formatted debug message
func (l *Logger) Debugf(format string, args ...any) {
	if !safeFormatString(format) {
		l.log(LevelError, "unsafe format string detected", map[string]any{"format": SanitizeString(format)})
		return
	}
	l.log(LevelDebug, fmt.Sprintf(format, args...), nil)
}

// Infof logs a formatted info message
func (l *Logger) Infof(format string, args ...any) {
	if !safeFormatString(format) {
		l.log(LevelError, "unsafe format string detected", map[string]any{"format": SanitizeString(format)})
		return
	}
	l.log(LevelInfo, fmt.Sprintf(format, args...), nil)
}

// Warnf logs a formatted warning message
func (l *Logger) Warnf(format string, args ...any) {
	if !safeFormatString(format) {
		l.log(LevelError, "unsafe format string detected", map[string]any{"format": SanitizeString(format)})
		return
	}
	l.log(LevelWarn, fmt.Sprintf(format, args...), nil)
}

// Errorf logs a formatted error message
func (l *Logger) Errorf(format string, args ...any) {
	if !safeFormatString(format) {
		l.log(LevelError, "unsafe format string detected", map[string]any{"format": SanitizeString(format)})
		return
	}
	l.log(LevelError, fmt.Sprintf(format, args...), nil)
}

// Fatalf logs a formatted fatal message and exits
func (l *Logger) Fatalf(format string, args ...any) {
	if !safeFormatString(format) {
		l.log(LevelFatal, "unsafe format string detected", map[string]any{"format": SanitizeString(format)})
		if l.fatalHandler != nil {
			l.fatalHandler()
		} else {
			FatalHandler()
		}
		return
	}
	l.log(LevelFatal, fmt.Sprintf(format, args...), nil)
	if l.fatalHandler != nil {
		l.fatalHandler()
	} else {
		FatalHandler()
	}
}

// copyFields creates a copy of a fields map
func copyFields(fields map[string]any) map[string]any {
	if fields == nil {
		return make(map[string]any)
	}
	result := make(map[string]any, len(fields))
	for k, v := range fields {
		result[k] = v
	}
	return result
}

// Global logger instance
var (
	globalLogger     *Logger
	globalLoggerOnce sync.Once
)

// Global returns the global logger instance
// R47-CR-04 FIX: Defensive nil check in case SetGlobal(nil) was called
// after the once block already executed.
func Global() *Logger {
	globalLoggerOnce.Do(func() {
		globalLogger = New(DefaultConfig())
	})
	if globalLogger == nil {
		globalLogger = New(DefaultConfig())
	}
	return globalLogger
}

// SetGlobal sets the global logger instance
func SetGlobal(l *Logger) {
	globalLogger = l
}

// Package-level convenience functions

// Debug logs a debug message using the global logger
func Debug(msg string, fields ...map[string]any) {
	Global().Debug(msg, fields...)
}

// Info logs an info message using the global logger
func Info(msg string, fields ...map[string]any) {
	Global().Info(msg, fields...)
}

// Warn logs a warning message using the global logger
func Warn(msg string, fields ...map[string]any) {
	Global().Warn(msg, fields...)
}

// Error logs an error message using the global logger
func Error(msg string, fields ...map[string]any) {
	Global().Error(msg, fields...)
}

// Fatal logs a fatal message using the global logger and exits
func Fatal(msg string, fields ...map[string]any) {
	Global().Fatal(msg, fields...)
}
