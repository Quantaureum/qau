// Quantaureum Node source, version 1.0.0.
package visor

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestProcessState_String(t *testing.T) {
	tests := []struct {
		state ProcessState
		want  string
	}{
		{StateStopped, "stopped"},
		{StateStarting, "starting"},
		{StateRunning, "running"},
		{StateStopping, "stopping"},
		{StateCrashed, "crashed"},
		{ProcessState(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("ProcessState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.BinaryPath != "/usr/local/bin/qaud" {
		t.Errorf("DefaultConfig().BinaryPath = %q, want /usr/local/bin/qaud", cfg.BinaryPath)
	}
	if !cfg.AutoRestart {
		t.Error("DefaultConfig().AutoRestart should be true")
	}
	if cfg.MaxRestartAttempts != 5 {
		t.Errorf("DefaultConfig().MaxRestartAttempts = %d, want 5", cfg.MaxRestartAttempts)
	}
	if cfg.ShutdownTimeout != 30*time.Second {
		t.Errorf("DefaultConfig().ShutdownTimeout = %v, want 30s", cfg.ShutdownTimeout)
	}
}

func TestProcessManager_New(t *testing.T) {
	cfg := DefaultConfig()
	pm := NewProcessManager(cfg)

	if pm.IsRunning() {
		t.Error("new ProcessManager should not be running")
	}

	info := pm.Status()
	if info.State != StateStopped {
		t.Errorf("initial state = %v, want StateStopped", info.State)
	}
	if info.PID != 0 {
		t.Errorf("initial PID = %d, want 0", info.PID)
	}
}

func TestProcessManager_StartStop(t *testing.T) {
	// Find a suitable executable to run as a stand-in for qaud
	tmpDir := t.TempDir()

	var binaryPath string
	if runtime.GOOS == "windows" {
		// On Windows, use ping as a long-running stand-in
		// ping -n 3600 127.0.0.1 waits ~3600 seconds
		resolved, err := exec.LookPath("ping.exe")
		if err != nil {
			t.Skipf("cannot find ping.exe: %v", err)
		}
		binaryPath = resolved
	} else {
		// On Linux/Mac, create a simple shell script
		binaryPath = filepath.Join(tmpDir, "qaud")
		script := "#!/bin/sh\necho qaud started\nsleep 60\n"
		if err := os.WriteFile(binaryPath, []byte(script), 0755); err != nil {
			t.Skipf("cannot create test binary: %v", err)
		}
	}

	cfg := &Config{
		BinaryPath:          binaryPath,
		DataDir:             tmpDir,
		ConfigPath:          "/dev/null",
		GenesisPath:         "/dev/null",
		AutoRestart:         false,
		MaxRestartAttempts:  3,
		RestartDelay:        100 * time.Millisecond,
		HealthCheckInterval: 1 * time.Second,
		ShutdownTimeout:     5 * time.Second,
	}

	// Add platform-specific arguments
	if runtime.GOOS == "windows" {
		// ping doesn't understand qaud flags, pass only ping args
		cfg.QaudArgs = []string{"-n", "3600", "127.0.0.1"}
		cfg.ConfigPath = ""
		cfg.GenesisPath = ""
		cfg.DataDir = ""
	} else {
		cfg.QaudArgs = []string{}
	}

	pm := NewProcessManager(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := pm.Start(ctx); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// Give process time to start
	time.Sleep(300 * time.Millisecond)

	if !pm.IsRunning() {
		t.Error("process should be running after Start()")
	}

	info := pm.Status()
	if info.State != StateRunning {
		t.Errorf("state after start = %v, want StateRunning", info.State)
	}
	if info.PID <= 0 {
		t.Errorf("PID after start = %d, want > 0", info.PID)
	}

	if err := pm.Stop(); err != nil {
		t.Fatalf("Stop() failed: %v", err)
	}

	if pm.IsRunning() {
		t.Error("process should not be running after Stop()")
	}
}

func TestProcessManager_DoubleStart(t *testing.T) {
	cfg := DefaultConfig()
	pm := NewProcessManager(cfg)

	// Can't start with invalid binary path, but we can test the state check
	pm.mu.Lock()
	pm.state = StateRunning
	pm.mu.Unlock()

	if err := pm.Start(nil); err == nil {
		t.Error("Start() should fail when already running")
	}
}

func TestProcessManager_DoubleStop(t *testing.T) {
	cfg := DefaultConfig()
	pm := NewProcessManager(cfg)

	if err := pm.Stop(); err == nil {
		t.Error("Stop() should fail when already stopped")
	}
}
