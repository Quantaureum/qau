// Quantaureum Node source, version 1.0.0.
// Package profiling — P3 regression tests for pprof default-off and token
// file cleanup.
//
// P3-PPROF-DEFAULT-OFF FIX (R29, 2026-07-26): DefaultProfileConfig() now
// returns EnablePprof=false. Previously it returned true, which meant any
// caller using the default config would expose a pprof HTTP server —
// leaking runtime data (heap, goroutines, CPU profiles) that can contain
// private keys and other secrets. Operators must now explicitly set
// EnablePprof=true to enable pprof.
//
// P3-PPROF-TOKEN-CLEANUP FIX (R29, 2026-07-26): When QAU_PPROF_TOKEN is
// not set, StartPprofServer generates a random token and writes it to
// os.TempDir()/.qau-pprof-token. Previously this file was NEVER cleaned
// up — accumulating one file per node start and allowing attackers with
// temp-dir read access to recover old tokens. StopPprofServer now securely
// deletes the auto-generated token file (overwrite with zeros + remove).
package profiling

import (
	"os"
	"path/filepath"
	"testing"
)

// TestP3_Pprof_DefaultConfigHasPprofDisabled verifies that
// DefaultProfileConfig returns EnablePprof=false. This is the core fix
// for P3-PPROF-DEFAULT-OFF: pprof must be opt-in, not opt-out.
func TestP3_Pprof_DefaultConfigHasPprofDisabled(t *testing.T) {
	cfg := DefaultProfileConfig()
	if cfg.EnablePprof {
		t.Fatal("P3-PPROF-DEFAULT-OFF REGRESSION: DefaultProfileConfig() " +
			"returns EnablePprof=true. pprof is opt-OUT (enabled by " +
			"default), which means any caller using the default config " +
			"exposes a pprof HTTP server leaking heap/goroutine/CPU data " +
			"that can contain private keys. pprof MUST be opt-IN.")
	}
}

// TestP3_Pprof_TokenFileCleanedUpOnStop verifies that StopPprofServer
// securely deletes the auto-generated pprof token file.
//
// Setup: Create a Profiler with EnablePprof=true, set QAU_PPROF_TOKEN=""
// (force auto-generation), call StartPprofServer (which writes the token
// file), verify the file exists, then call StopPprofServer and verify
// the file is removed.
func TestP3_Pprof_TokenFileCleanedUpOnStop(t *testing.T) {
	// Force auto-generation by clearing QAU_PPROF_TOKEN.
	originalToken := os.Getenv("QAU_PPROF_TOKEN")
	defer func() {
		if err := os.Setenv("QAU_PPROF_TOKEN", originalToken); err != nil {
			t.Logf("failed to restore QAU_PPROF_TOKEN: %v", err)
		}
	}()
	if err := os.Unsetenv("QAU_PPROF_TOKEN"); err != nil {
		t.Fatalf("Unsetenv failed: %v", err)
	}

	// Use a known token file path so we can verify cleanup.
	tokenPath := filepath.Join(os.TempDir(), ".qau-pprof-token-test-cleanup")
	// Clean up any leftover from a previous test run.
	_ = os.Remove(tokenPath)
	defer os.Remove(tokenPath) // safety net in case test fails before Stop

	cfg := &ProfileConfig{
		OutputDir:     os.TempDir(),
		EnablePprof:   true,
		PprofAddr:     "127.0.0.1:0", // ephemeral port, avoid conflicts
		BlockRate:     0,
		MutexFraction: 0,
	}
	p := NewProfiler(cfg)

	// Manually set tokenFile to our test path (simulating what
	// StartPprofServer does when QAU_PPROF_TOKEN is unset).
	p.tokenFile = tokenPath
	// Write a fake token file so we can verify StopPprofServer removes it.
	if err := os.WriteFile(tokenPath, []byte("fake-test-token"), 0600); err != nil {
		t.Fatalf("failed to write test token file: %v", err)
	}

	// Verify the file exists before StopPprofServer.
	if _, err := os.Stat(tokenPath); err != nil {
		t.Fatalf("test token file does not exist before StopPprofServer: %v", err)
	}

	// StopPprofServer should remove the token file.
	if err := p.StopPprofServer(); err != nil {
		t.Logf("StopPprofServer returned error (expected for test setup): %v", err)
	}

	// Verify the token file was removed.
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Errorf("P3-PPROF-TOKEN-CLEANUP REGRESSION: token file still exists "+
			"after StopPprofServer (err=%v). The auto-generated token file "+
			"must be securely deleted on shutdown to prevent token "+
			"accumulation and recovery by attackers with temp-dir access.",
			err)
	}

	// Verify tokenFile field was cleared (idempotent — second call is no-op).
	if p.tokenFile != "" {
		t.Errorf("P3-PPROF-TOKEN-CLEANUP REGRESSION: p.tokenFile was not "+
			"cleared after StopPprofServer (value=%q). A second call to "+
			"StopPprofServer would attempt to remove a non-existent file, "+
			"which is harmless but indicates the cleanup logic did not "+
			"complete properly.", p.tokenFile)
	}
}

// TestP3_Pprof_StopWithoutStartIsNoop verifies that calling StopPprofServer
// on a Profiler that never started pprof (or already stopped) is a safe
// no-op. This is important because main.go's shutdown path always calls
// StopPprofServer regardless of whether StartPprofServer succeeded.
func TestP3_Pprof_StopWithoutStartIsNoop(t *testing.T) {
	cfg := &ProfileConfig{
		OutputDir:     os.TempDir(),
		EnablePprof:   false, // pprof disabled — StartPprofServer is a no-op
		PprofAddr:     "127.0.0.1:0",
		BlockRate:     0,
		MutexFraction: 0,
	}
	p := NewProfiler(cfg)

	// StartPprofServer with EnablePprof=false is a no-op (returns nil).
	if err := p.StartPprofServer(); err != nil {
		t.Fatalf("StartPprofServer with EnablePprof=false failed: %v", err)
	}

	// StopPprofServer should also be a no-op — no server, no token file.
	if err := p.StopPprofServer(); err != nil {
		t.Errorf("StopPprofServer after no-op StartPprofServer returned "+
			"error: %v. StopPprofServer must be safe to call even when "+
			"pprof was never started (main.go's shutdown path always calls it).",
			err)
	}

	// Verify no token file was created.
	if p.tokenFile != "" {
		t.Errorf("P3-PPROF-TOKEN-CLEANUP REGRESSION: tokenFile was set "+
			"(value=%q) even though EnablePprof=false. No token file "+
			"should be created when pprof is disabled.", p.tokenFile)
	}
}
