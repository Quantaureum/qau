// Quantaureum Node source, version 1.0.0.
package log

import (
	"os"
	"testing"
)

func TestLevel_String(t *testing.T) {
	tests := []struct {
		l    Level
		want string
	}{
		{LevelDebug, "debug"},
		{LevelInfo, "info"},
		{LevelWarn, "warn"},
		{LevelError, "error"},
		{LevelFatal, "fatal"},
		{Level(99), "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.l.String()
			if got != tt.want {
				t.Errorf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	tests := []struct {
		s    string
		want Level
	}{
		{"debug", LevelDebug},
		{"DEBUG", LevelDebug},
		{"info", LevelInfo},
		{"INFO", LevelInfo},
		{"warn", LevelWarn},
		{"WARN", LevelWarn},
		{"warning", LevelWarn},
		{"WARNING", LevelWarn},
		{"error", LevelError},
		{"ERROR", LevelError},
		{"fatal", LevelFatal},
		{"FATAL", LevelFatal},
		{"unknown", LevelInfo},
	}
	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			got := ParseLevel(tt.s)
			if got != tt.want {
				t.Errorf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Output != nil {
		t.Log("default output set")
	}
	if cfg.Level != LevelInfo {
		t.Errorf("expected info, got %s", cfg.Level)
	}
	if cfg.TimeFormat == "" {
		t.Error("expected non-empty time format")
	}
}

func TestNew(t *testing.T) {
	l := New(nil)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestNew_WithConfig(t *testing.T) {
	cfg := &Config{
		Output:        os.Stdout,
		Level:         LevelDebug,
		Module:        "test",
		IncludeCaller: true,
		TimeFormat:    "2006-01-02",
	}
	l := New(cfg)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestGetLevel(t *testing.T) {
	l := New(nil)
	lv := l.GetLevel()
	if lv != LevelInfo {
		t.Errorf("expected info level, got %s", lv)
	}
}

func TestSetLevel(t *testing.T) {
	l := New(nil)
	l.SetLevel(LevelDebug)
	if l.GetLevel() != LevelDebug {
		t.Error("expected debug level after set")
	}

	l.SetLevel(LevelError)
	if l.GetLevel() != LevelError {
		t.Error("expected error level after set")
	}
}

func TestSetOutput(t *testing.T) {
	l := New(nil)
	l.SetOutput(os.Stderr)
}

func TestWithModule(t *testing.T) {
	l := New(nil)
	l2 := l.WithModule("network")
	if l2 == nil {
		t.Fatal("expected non-nil logger")
	}

	l2.Info("test message")
}

func TestWithField(t *testing.T) {
	l := New(nil)
	l2 := l.WithField("component", "rpc")
	l2.Info("test with field")
}

func TestWithFields(t *testing.T) {
	l := New(nil)
	l2 := l.WithFields(map[string]any{
		"component": "qvm",
		"request":   "tx-001",
	})
	l2.Info("test with fields")
}

func TestDebug(t *testing.T) {
	l := New(nil)
	l.SetLevel(LevelDebug)
	l.Debug("debug message")
	l.Debugf("debug %s", "formatted")
}

func TestInfo(t *testing.T) {
	l := New(nil)
	l.Info("info message")
	l.Infof("info %s", "formatted")
}

func TestWarn(t *testing.T) {
	l := New(nil)
	l.Warn("warn message")
	l.Warnf("warn %s", "formatted")
}

func TestError(t *testing.T) {
	l := New(nil)
	l.Error("error message", map[string]any{"code": 500})
	l.Errorf("error %s", "formatted")
}

func TestDebug_FilteredByLevel(t *testing.T) {
	l := New(nil)
	l.SetLevel(LevelError)

	l.Debug("should not appear")
	l.Info("should not appear")
	l.Warn("should not appear")
	l.Error("should appear")
}

func TestSetFatalHandler(t *testing.T) {
	l := New(nil)

	called := false
	l.SetFatalHandler(func() {
		called = true
	})

	l.Fatal("fatal with custom handler")
	if !called {
		t.Error("custom fatal handler was not called")
	}
}

func TestGlobal(t *testing.T) {
	g := Global()
	if g == nil {
		t.Fatal("expected non-nil global logger")
	}
}

func TestSetGlobal(t *testing.T) {
	original := Global()

	l := New(nil)
	SetGlobal(l)
	defer SetGlobal(original)

	g := Global()
	if g == nil {
		t.Fatal("expected non-nil global logger")
	}
}

func TestPackageLevelFunctions(t *testing.T) {
	original := Global()

	l := New(nil)
	l.SetLevel(LevelDebug)
	SetGlobal(l)
	defer SetGlobal(original)

	Debug("pkg debug")
	Info("pkg info")
	Warn("pkg warn")
	Error("pkg error")
}

func TestLogEntry(t *testing.T) {
	entry := LogEntry{
		Timestamp: "2024-01-01T00:00:00Z",
		Level:     "info",
		Message:   "test",
		Module:    "test-module",
	}
	if entry.Message != "test" {
		t.Errorf("expected test, got %s", entry.Message)
	}
}

func TestSanitizeString(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"plain_text", "hello world"},
		{"short_hex", "0xabcd"},
		{"long_hex_key", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"},
		{"base64_like", "dGVzdCBrZXkgdmFsdWUgc3RyaW5nIHdpdGggcGFkZGluZw=="},
		{"mixed_content", "key is abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd in log"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)
			if result == "" && tt.input != "" {
				t.Error("expected non-empty result")
			}
			if len(result) > len(tt.input) {
				t.Error("result should not be longer than input")
			}
		})
	}
}

func TestSanitizeString_LongHex(t *testing.T) {
	result := SanitizeString("secret: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	if result == "secret: abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" {
		t.Error("expected hex key to be redacted")
	}
}

func TestSanitizeFields(t *testing.T) {
	tests := []struct {
		name   string
		fields map[string]any
	}{
		{"nil", nil},
		{"empty", map[string]any{}},
		{"normal_fields", map[string]any{"user": "alice", "count": 42}},
		{"password_field", map[string]any{"password": "secret123"}},
		{"private_key", map[string]any{"private_key": "0xabcdef1234567890"}},
		{"api_key", map[string]any{"api_key": "sk-1234567890"}},
		{"mixed", map[string]any{
			"user":     "alice",
			"password": "secret123",
			"count":    42,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeFields(tt.fields)
			if tt.fields == nil && result != nil {
				t.Error("expected nil result for nil input")
			}
			if tt.fields != nil && result == nil {
				t.Error("expected non-nil result")
			}
			if tt.fields != nil && len(tt.fields) > 0 && len(result) != len(tt.fields) {
				t.Errorf("expected %d fields, got %d", len(tt.fields), len(result))
			}
		})
	}
}

func TestSanitizeFields_RedactsPassword(t *testing.T) {
	fields := map[string]any{"password": "my_secret"}
	result := SanitizeFields(fields)
	if result["password"] != redactedValue {
		t.Errorf("expected %s, got %v", redactedValue, result["password"])
	}
}

func TestSanitizeFields_RedactsToken(t *testing.T) {
	fields := map[string]any{"auth_token": "bearer xyz"}
	result := SanitizeFields(fields)
	if result["auth_token"] != redactedValue {
		t.Errorf("expected %s, got %v", redactedValue, result["auth_token"])
	}
}

func TestSanitizeFields_RedactsMnemonic(t *testing.T) {
	fields := map[string]any{"mnemonic": "abandon ability able about ..."}
	result := SanitizeFields(fields)
	if result["mnemonic"] != redactedValue {
		t.Errorf("expected %s, got %v", redactedValue, result["mnemonic"])
	}
}

func TestSanitizeFields_NonSensitiveIntact(t *testing.T) {
	fields := map[string]any{"username": "alice", "count": 42}
	result := SanitizeFields(fields)
	if result["username"] != "alice" {
		t.Errorf("expected alice, got %v", result["username"])
	}
	if result["count"] != 42 {
		t.Errorf("expected 42, got %v", result["count"])
	}
}

func TestValidateJSONLog(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty", "", false},
		{"whitespace", "   ", false},
		{"valid_json", `{"timestamp":"2024-01-01T00:00:00Z","level":"info","message":"test"}`, false},
		{"invalid_json", `{invalid}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJSONLog(tt.input)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateJSONLogStrict(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantOK  bool
		wantErr bool
	}{
		{"empty", "", false, false},
		{"valid_complete", `{"timestamp":"2024-01-01T00:00:00Z","level":"info","message":"test"}`, true, false},
		{"missing_timestamp", `{"level":"info","message":"test"}`, false, false},
		{"missing_level", `{"timestamp":"2024-01-01T00:00:00Z","message":"test"}`, false, false},
		{"missing_message", `{"timestamp":"2024-01-01T00:00:00Z","level":"info"}`, false, false},
		{"invalid_json", `{bad}`, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := ValidateJSONLogStrict(tt.input)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if ok != tt.wantOK {
				t.Errorf("expected ok=%v, got ok=%v", tt.wantOK, ok)
			}
		})
	}
}

func TestParseLogEntry(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNil bool
		wantErr bool
	}{
		{"empty", "", true, false},
		{"valid", `{"timestamp":"2024-01-01T00:00:00Z","level":"info","message":"test"}`, false, false},
		{"invalid", `{bad}`, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := ParseLogEntry(tt.input)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantNil && entry != nil {
				t.Error("expected nil entry")
			}
			if !tt.wantNil && entry == nil {
				t.Error("expected non-nil entry")
			}
			if !tt.wantNil && entry != nil && entry.Message != "test" {
				t.Errorf("expected test message, got %s", entry.Message)
			}
		})
	}
}

func TestIsValidLevel(t *testing.T) {
	tests := []struct {
		level string
		want  bool
	}{
		{"debug", true},
		{"info", true},
		{"warn", true},
		{"error", true},
		{"fatal", true},
		{"Debug", false},
		{"INFO", false},
		{"trace", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			if got := IsValidLevel(tt.level); got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestFatal_WithPackageHandler(t *testing.T) {
	original := FatalHandler
	called := false
	FatalHandler = func() { called = true }
	defer func() { FatalHandler = original }()

	l := New(nil)
	l.Fatal("fatal with package handler")
	if !called {
		t.Error("FatalHandler was not called")
	}
}

func TestFatal_WithNilHandler(t *testing.T) {
	original := FatalHandler
	called := false
	FatalHandler = func() { called = true }
	defer func() { FatalHandler = original }()

	l := New(nil)
	l.fatalHandler = nil
	l.Fatal("fatal with nil handler")
	if !called {
		t.Error("FatalHandler was not called")
	}
}

func TestFatalf(t *testing.T) {
	original := FatalHandler
	called := false
	FatalHandler = func() { called = true }
	defer func() { FatalHandler = original }()

	l := New(nil)
	l.Fatalf("fatal %s", "formatted")
	if !called {
		t.Error("FatalHandler was not called for Fatalf")
	}
}

func TestDebugf(t *testing.T) {
	l := New(nil)
	l.SetLevel(LevelDebug)
	l.Debugf("debug %s %d", "msg", 42)
}

func TestInfof(t *testing.T) {
	l := New(nil)
	l.Infof("info %s", "test")
}

func TestWarnf(t *testing.T) {
	l := New(nil)
	l.Warnf("warn %s", "test")
}

func TestErrorf(t *testing.T) {
	l := New(nil)
	l.Errorf("error %d", 500)
}

func TestLogger_WithFieldsFromExisting(t *testing.T) {
	l := New(nil)
	l2 := l.WithField("base", "value")
	l3 := l2.WithField("extra", "more")
	l3.Info("chained fields")
}

func TestSanitizeFields_NestedSensitive(t *testing.T) {
	cfg := map[string]any{"password": "nested_secret"}
	fields := map[string]any{"config": cfg}
	result := SanitizeFields(fields)
	if _, ok := result["config"].(map[string]any); !ok {
		t.Error("expected config to remain as map")
	}
}

func TestLogger_Error_Stack(t *testing.T) {
	cfg := &Config{Output: os.Stderr, Level: LevelError, IncludeCaller: true}
	l := New(cfg)
	l.Error("error with stack")
}

func TestNew_EmptyTimeFormat(t *testing.T) {
	cfg := &Config{
		TimeFormat: "",
	}
	l := New(cfg)
	if l == nil {
		t.Fatal("expected non-nil logger")
	}
}

func TestDebug_WithFields(t *testing.T) {
	l := New(nil)
	l.SetLevel(LevelDebug)
	l.Debug("debug with fields", map[string]any{"key": "val"})
}

func TestInfo_WithFields(t *testing.T) {
	l := New(nil)
	l.Info("info with fields", map[string]any{"key": "val"})
}

func TestWarn_WithFields(t *testing.T) {
	l := New(nil)
	l.Warn("warn with fields", map[string]any{"key": "val"})
}

func TestFatal_PackageLevel(t *testing.T) {
	original := FatalHandler
	called := false
	FatalHandler = func() { called = true }
	defer func() { FatalHandler = original }()

	l := New(nil)
	originalGlobal := Global()
	SetGlobal(l)
	defer SetGlobal(originalGlobal)

	Fatal("pkg fatal")
	if !called {
		t.Error("FatalHandler was not called for package-level Fatal")
	}
}

func TestFatalf_WithCustomHandler(t *testing.T) {
	l := New(nil)

	called := false
	l.SetFatalHandler(func() {
		called = true
	})

	l.Fatalf("fatal %s", "with custom handler")
	if !called {
		t.Error("custom fatal handler was not called for Fatalf")
	}
}

func TestSanitizeFields_RedactsSecretKey(t *testing.T) {
	fields := map[string]any{"secret_key": "top_secret"}
	result := SanitizeFields(fields)
	if result["secret_key"] != redactedValue {
		t.Errorf("expected %s, got %v", redactedValue, result["secret_key"])
	}
}

func TestSanitizeFields_RedactsPassphrase(t *testing.T) {
	fields := map[string]any{"passphrase": "long secret phrase"}
	result := SanitizeFields(fields)
	if result["passphrase"] != redactedValue {
		t.Errorf("expected %s, got %v", redactedValue, result["passphrase"])
	}
}

func TestSanitizeFields_RedactsAccessToken(t *testing.T) {
	fields := map[string]any{"access_token": "at-secret-token"}
	result := SanitizeFields(fields)
	if result["access_token"] != redactedValue {
		t.Errorf("expected %s, got %v", redactedValue, result["access_token"])
	}
}

func TestSanitizeFields_SecretKey(t *testing.T) {
	fields := map[string]any{"secretkey": "secret"}
	result := SanitizeFields(fields)
	if result["secretkey"] != redactedValue {
		t.Errorf("expected %s, got %v", redactedValue, result["secretkey"])
	}
}

func TestSanitizeFields_ApiKeyCamel(t *testing.T) {
	fields := map[string]any{"apikey": "sk-12345"}
	result := SanitizeFields(fields)
	if result["apikey"] != redactedValue {
		t.Errorf("expected %s, got %v", redactedValue, result["apikey"])
	}
}

func TestSanitizeFields_RefreshToken(t *testing.T) {
	fields := map[string]any{"refresh_token": "rt-secret"}
	result := SanitizeFields(fields)
	if result["refresh_token"] != redactedValue {
		t.Errorf("expected %s, got %v", redactedValue, result["refresh_token"])
	}
}

func TestCopyFields_Nil(t *testing.T) {
	result := copyFields(nil)
	if result == nil {
		t.Error("expected non-nil result for nil input")
	}
	if len(result) != 0 {
		t.Errorf("expected empty map, got %d entries", len(result))
	}
}

func TestCopyFields_NonNil(t *testing.T) {
	src := map[string]any{"a": 1, "b": "two"}
	result := copyFields(src)
	if len(result) != 2 {
		t.Errorf("expected 2 entries, got %d", len(result))
	}
	if result["a"] != 1 || result["b"] != "two" {
		t.Error("values mismatch")
	}
	src["a"] = 99
	if result["a"] == 99 {
		t.Error("copy should not be affected by original modification")
	}
}

func TestSanitizeFields_NonStringValue(t *testing.T) {
	fields := map[string]any{"count": 42, "enabled": true, "ratio": 3.14}
	result := SanitizeFields(fields)
	if result["count"] != 42 {
		t.Errorf("expected 42, got %v", result["count"])
	}
	if result["enabled"] != true {
		t.Errorf("expected true, got %v", result["enabled"])
	}
	if result["ratio"] != 3.14 {
		t.Errorf("expected 3.14, got %v", result["ratio"])
	}
}

func TestSanitizeFields_SubstringMatch(t *testing.T) {
	fields := map[string]any{"my_private_key_field": "secret_value"}
	result := SanitizeFields(fields)
	if result["my_private_key_field"] != redactedValue {
		t.Errorf("expected %s for substring match, got %v", redactedValue, result["my_private_key_field"])
	}
}

func TestSanitizeFields_CredentialRegex(t *testing.T) {
	fields := map[string]any{"credential": "admin:secret"}
	result := SanitizeFields(fields)
	if result["credential"] != redactedValue {
		t.Errorf("expected %s for credential, got %v", redactedValue, result["credential"])
	}
}
