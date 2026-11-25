// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// captureNodeLogs redirects the package logger into a buffer for the duration
// of the test and returns a reader over the captured text.
func captureNodeLogs(t *testing.T) func() string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf.String
}

// Audit M-01: the hot-reload path must surface the effective trusted-proxy
// list in English logs (config value, env override, or the explicit
// "none" policy) so operators can verify what the running node trusts.
func TestLogEffectiveRPCTrustedProxies(t *testing.T) {
	tests := []struct {
		name         string
		config       []string
		env          string
		wantContains string
	}{
		{
			name:         "none configured",
			config:       nil,
			env:          "",
			wantContains: "effective RPC trusted proxies: none",
		},
		{
			name:         "config list",
			config:       []string{"10.0.0.1", "10.0.0.0/24"},
			env:          "",
			wantContains: "effective RPC trusted proxies (2): 10.0.0.1,10.0.0.0/24",
		},
		{
			name:         "env override wins",
			config:       []string{"10.0.0.1"},
			env:          "192.168.1.1",
			wantContains: "effective RPC trusted proxies (1): 192.168.1.1",
		},
		{
			name:         "invalid entry reported",
			config:       []string{"not-an-ip"},
			env:          "",
			wantContains: "configured RPC trusted proxies are invalid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			read := captureNodeLogs(t)
			t.Setenv("QAU_RPC_TRUSTED_PROXIES", tc.env)
			n := &Node{config: &Config{RPCTrustedProxies: tc.config}}
			n.logEffectiveRPCTrustedProxies()
			if got := read(); !strings.Contains(got, tc.wantContains) {
				t.Fatalf("log output %q does not contain %q", got, tc.wantContains)
			}
		})
	}
}

// Audit M-01: warnRestartRequired must flag rpcTrustedProxies changes as
// restart-required instead of silently ignoring them.
func TestWarnRestartRequiredFlagsTrustedProxies(t *testing.T) {
	read := captureNodeLogs(t)

	oldCfg := &Config{RPCTrustedProxies: []string{"10.0.0.1"}}
	newCfg := &Config{RPCTrustedProxies: []string{"10.0.0.2"}}
	n := &Node{}
	n.warnRestartRequired(oldCfg, newCfg)

	out := read()
	if !strings.Contains(out, "rpcTrustedProxies") {
		t.Fatalf("log output %q does not flag the rpcTrustedProxies change", out)
	}
	if !strings.Contains(out, "requires a node restart") {
		t.Fatalf("log output %q does not state that a restart is required", out)
	}

	// Same list (order included) must NOT produce the warning.
	read2 := captureNodeLogs(t)
	n.warnRestartRequired(newCfg, &Config{RPCTrustedProxies: []string{"10.0.0.2"}})
	if out2 := read2(); strings.Contains(out2, "rpcTrustedProxies") {
		t.Fatalf("unchanged trusted-proxy list must not be flagged, got %q", out2)
	}
}
