// Quantaureum Node source, version 1.0.0.
package log

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestP3_NODE_04_DefaultConfig_DisablesStack verifies that the default
// logger configuration does NOT capture stack traces on Error/Fatal logs.
//
// This is the core regression test for P3-NODE-04: previously the logger
// unconditionally called runtime.Stack() for every Error/Fatal entry,
// potentially leaking key material (Dilithium3 private keys 4000 bytes,
// Kyber768 private keys 2400 bytes, AES-256-GCM keys, etc.) from the
// goroutine stack into log files. The fix makes stack capture OPT-IN via
// Config.IncludeStack (default false).
//
// If this test fails, someone re-enabled unconditional stack capture
// (regression), or changed the default of IncludeStack to true.
func TestP3_NODE_04_DefaultConfig_DisablesStack(t *testing.T) {
	var buf bytes.Buffer
	// DefaultConfig must have IncludeStack=false.
	cfg := DefaultConfig()
	if cfg.IncludeStack {
		t.Fatalf("P3-NODE-04 REGRESSION: DefaultConfig().IncludeStack = true, " +
			"want false. Stack capture must be OPT-IN to prevent leaking " +
			"key material from the goroutine stack into log files.")
	}
	cfg.Output = &buf
	cfg.Level = LevelError

	l := New(cfg)
	l.Error("error without stack capture")

	// Parse the JSON output and verify Stack is empty.
	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v\noutput: %s", err, buf.String())
	}

	if entry.Stack != "" {
		t.Errorf("P3-NODE-04 REGRESSION: Stack field is non-empty under default "+
			"config (IncludeStack=false). Stack capture must NOT fire when "+
			"IncludeStack is false. Got stack of length %d:\n%s",
			len(entry.Stack), entry.Stack)
	}
}

// TestP3_NODE_04_NilConfig_DisablesStack verifies that New(nil) also
// disables stack capture (falls back to DefaultConfig).
func TestP3_NODE_04_NilConfig_DisablesStack(t *testing.T) {
	var buf bytes.Buffer
	l := New(nil)
	l.SetOutput(&buf)
	l.SetLevel(LevelError)
	l.Error("error with nil config")

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v\noutput: %s", err, buf.String())
	}

	if entry.Stack != "" {
		t.Errorf("P3-NODE-04 REGRESSION: New(nil) captured a stack trace. "+
			"New(nil) must fall back to DefaultConfig which has "+
			"IncludeStack=false. Got stack of length %d.", len(entry.Stack))
	}
}

// TestP3_NODE_04_IncludeStackEnabled_CapturesStack verifies that when
// IncludeStack=true is explicitly set, the logger DOES capture a stack
// trace for Error-level entries. This confirms the opt-in path still
// works for development debugging.
func TestP3_NODE_04_IncludeStackEnabled_CapturesStack(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{
		Output:       &buf,
		Level:        LevelError,
		IncludeStack: true,
	}
	l := New(cfg)
	l.Error("error with stack capture enabled")

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v\noutput: %s", err, buf.String())
	}

	if entry.Stack == "" {
		t.Error("P3-NODE-04 REGRESSION: Stack field is empty even though " +
			"IncludeStack=true. Stack capture should fire when explicitly " +
			"enabled for development debugging.")
	}

	// The captured stack should reference this test function.
	if !strings.Contains(entry.Stack, "TestP3_NODE_04_IncludeStackEnabled_CapturesStack") {
		t.Errorf("P3-NODE-04: captured stack does not contain expected test "+
			"function name. Got:\n%s", entry.Stack)
	}
}

// TestP3_NODE_04_SetIncludeStack_RuntimeToggle verifies that
// SetIncludeStack can toggle stack capture at runtime.
func TestP3_NODE_04_SetIncludeStack_RuntimeToggle(t *testing.T) {
	var buf bytes.Buffer
	l := New(&Config{Output: &buf, Level: LevelError})
	// Default: stack capture disabled.
	l.Error("first error, no stack")
	var entry1 LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry1); err != nil {
		t.Fatalf("failed to parse first log output: %v", err)
	}
	if entry1.Stack != "" {
		t.Errorf("P3-NODE-04: first error should have empty stack, got length %d",
			len(entry1.Stack))
	}

	// Enable at runtime.
	buf.Reset()
	l.SetIncludeStack(true)
	l.Error("second error, with stack")

	var entry2 LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry2); err != nil {
		t.Fatalf("failed to parse second log output: %v", err)
	}
	if entry2.Stack == "" {
		t.Error("P3-NODE-04: second error should have non-empty stack after " +
			"SetIncludeStack(true)")
	}

	// Disable again.
	buf.Reset()
	l.SetIncludeStack(false)
	l.Error("third error, no stack again")

	var entry3 LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry3); err != nil {
		t.Fatalf("failed to parse third log output: %v", err)
	}
	if entry3.Stack != "" {
		t.Errorf("P3-NODE-04: third error should have empty stack after "+
			"SetIncludeStack(false), got length %d", len(entry3.Stack))
	}
}

// TestP3_NODE_04_StackSanitized_RedactsHexKey verifies that when stack
// capture is enabled, long hex strings (which may be key material leaked
// from the goroutine stack) are redacted by SanitizeString.
//
// This is the defense-in-depth layer: even when a developer explicitly
// enables IncludeStack=true, the captured stack is passed through
// SanitizeString to redact patterns matching private keys (64+ hex chars)
// and base64 blobs (40+ chars).
//
// We cannot easily inject a real key into runtime.Stack() output, so we
// verify the sanitize integration by checking that the Stack field does
// not contain any unredacted 64+ hex char sequences that would match the
// sensitiveValuePatterns in sanitize.go.
func TestP3_NODE_04_StackSanitized_RedactsHexKey(t *testing.T) {
	var buf bytes.Buffer
	cfg := &Config{
		Output:       &buf,
		Level:        LevelError,
		IncludeStack: true,
	}
	l := New(cfg)
	// Log an error whose message itself is sanitized, but we care about
	// the Stack field. The stack captured here is the real goroutine
	// stack of this test, which should not contain key material — but
	// we verify the sanitize layer is applied by checking that no
	// 64+ hex char sequence survives in the output.
	//
	// To make the test robust against future changes to runtime.Stack
	// output format, we additionally craft a scenario where the message
	// contains a fake private-key-like hex string and verify it gets
	// redacted in the Message field (which also goes through SanitizeString).
	fakePrivateKey := "deadbeef" + strings.Repeat("a", 56) // 64 hex chars
	l.Error("error with fake key in message: " + fakePrivateKey)

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v\noutput: %s", err, buf.String())
	}

	// The fake private key in the MESSAGE must be redacted (SanitizeString
	// is applied to both Message and Stack).
	if strings.Contains(entry.Message, fakePrivateKey) {
		t.Errorf("P3-NODE-04: fake private key in message was NOT redacted. "+
			"SanitizeString should have replaced 64+ hex chars with [REDACTED]. "+
			"Message: %s", entry.Message)
	}
	if !strings.Contains(entry.Message, redactedValue) {
		t.Errorf("P3-NODE-04: expected message to contain %q after sanitization, "+
			"got: %s", redactedValue, entry.Message)
	}

	// Verify the Stack field (if non-empty) does not contain any
	// unredacted 64+ hex char sequence. We scan the stack output for
	// hex runs of 64+ characters that are NOT followed/preceded by
	// [REDACTED].
	if entry.Stack != "" {
		// Extract all maximal hex runs from the stack and check none
		// reaches 64 chars (which would indicate sanitize missed it).
		hexRun := 0
		for _, c := range entry.Stack {
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
				hexRun++
				if hexRun >= 64 {
					t.Errorf("P3-NODE-04: Stack field contains an unredacted "+
						"64+ hex char run at offset %d. SanitizeString should "+
						"have redacted it. Stack tail:\n%s",
						hexRun, entry.Stack[max(0, len(entry.Stack)-200):])
					break
				}
			} else {
				hexRun = 0
			}
		}
	}
}

// TestP3_NODE_04_WithModule_PropagatesIncludeStack verifies that the
// WithModule method propagates the includeStack policy to derived loggers.
func TestP3_NODE_04_WithModule_PropagatesIncludeStack(t *testing.T) {
	var buf bytes.Buffer
	l := New(&Config{
		Output:       &buf,
		Level:        LevelError,
		IncludeStack: true,
	})
	derived := l.WithModule("child")
	if !derived.includeStack {
		t.Error("P3-NODE-04: WithModule did not propagate includeStack=true " +
			"to the derived logger. Stack capture policy must be inherited.")
	}

	// Verify the derived logger actually captures a stack.
	derived.Error("error from derived logger")
	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v", err)
	}
	if entry.Stack == "" {
		t.Error("P3-NODE-04: derived logger (WithModule) did not capture a " +
			"stack trace despite includeStack=true being propagated.")
	}
}

// TestP3_NODE_04_WithField_PropagatesIncludeStack verifies that the
// WithField method propagates the includeStack policy to derived loggers.
func TestP3_NODE_04_WithField_PropagatesIncludeStack(t *testing.T) {
	var buf bytes.Buffer
	l := New(&Config{
		Output:       &buf,
		Level:        LevelError,
		IncludeStack: true,
	})
	derived := l.WithField("k", "v")
	if !derived.includeStack {
		t.Error("P3-NODE-04: WithField did not propagate includeStack=true " +
			"to the derived logger.")
	}
}

// TestP3_NODE_04_WithFields_PropagatesIncludeStack verifies that the
// WithFields method propagates the includeStack policy to derived loggers.
func TestP3_NODE_04_WithFields_PropagatesIncludeStack(t *testing.T) {
	var buf bytes.Buffer
	l := New(&Config{
		Output:       &buf,
		Level:        LevelError,
		IncludeStack: true,
	})
	derived := l.WithFields(map[string]any{"k": "v"})
	if !derived.includeStack {
		t.Error("P3-NODE-04: WithFields did not propagate includeStack=true " +
			"to the derived logger.")
	}
}

// TestP3_NODE_04_InfoLevel_NeverCapturesStack verifies that Info/Warn
// levels NEVER capture a stack trace, even when IncludeStack=true.
// Stack capture is reserved for Error/Fatal only.
func TestP3_NODE_04_InfoLevel_NeverCapturesStack(t *testing.T) {
	var buf bytes.Buffer
	l := New(&Config{
		Output:       &buf,
		Level:        LevelDebug, // capture everything
		IncludeStack: true,
	})

	l.Info("info message")
	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse info log: %v", err)
	}
	if entry.Stack != "" {
		t.Errorf("P3-NODE-04: Info level captured a stack trace. Stack capture "+
			"must be reserved for Error/Fatal only. Got stack length %d.",
			len(entry.Stack))
	}

	buf.Reset()
	l.Warn("warn message")
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse warn log: %v", err)
	}
	if entry.Stack != "" {
		t.Errorf("P3-NODE-04: Warn level captured a stack trace. Stack capture "+
			"must be reserved for Error/Fatal only. Got stack length %d.",
			len(entry.Stack))
	}
}

// TestP3_NODE_04_FatalLevel_CapturesStackWhenEnabled verifies that Fatal
// level captures a stack when IncludeStack=true. We use a custom fatal
// handler to prevent os.Exit.
func TestP3_NODE_04_FatalLevel_CapturesStackWhenEnabled(t *testing.T) {
	var buf bytes.Buffer
	l := New(&Config{
		Output:       &buf,
		Level:        LevelFatal,
		IncludeStack: true,
	})
	l.SetFatalHandler(func() {}) // prevent os.Exit

	l.Fatal("fatal with stack")

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse fatal log: %v\noutput: %s", err, buf.String())
	}
	if entry.Stack == "" {
		t.Error("P3-NODE-04: Fatal level should capture a stack trace when " +
			"IncludeStack=true.")
	}
}

// TestP3_NODE_04_FatalLevel_NoStackWhenDisabled verifies that Fatal level
// does NOT capture a stack when IncludeStack=false (the default).
func TestP3_NODE_04_FatalLevel_NoStackWhenDisabled(t *testing.T) {
	var buf bytes.Buffer
	l := New(&Config{
		Output:       &buf,
		Level:        LevelFatal,
		IncludeStack: false,
	})
	l.SetFatalHandler(func() {})

	l.Fatal("fatal without stack")

	var entry LogEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse fatal log: %v\noutput: %s", err, buf.String())
	}
	if entry.Stack != "" {
		t.Errorf("P3-NODE-04: Fatal level captured a stack trace even though "+
			"IncludeStack=false. Got stack length %d.", len(entry.Stack))
	}
}
