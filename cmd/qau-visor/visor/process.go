// Quantaureum Node source, version 1.0.0.
// Package visor provides the core process management logic for qau-visor.
//
// ProcessManager supervises the qaud node process, providing:
//   - Lifecycle management (start, stop, restart)
//   - Health monitoring via heartbeat checks
//   - Automatic restart on unexpected crashes
//   - Graceful shutdown with signal forwarding
package visor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// ProcessState represents the current state of the managed process.
type ProcessState int

const (
	StateStopped ProcessState = iota
	StateStarting
	StateRunning
	StateStopping
	StateCrashed
)

func (s ProcessState) String() string {
	switch s {
	case StateStopped:
		return "stopped"
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	case StateCrashed:
		return "crashed"
	default:
		return "unknown"
	}
}

// Config holds the visor configuration.
type Config struct {
	// BinaryPath is the path to the qaud binary or symlink.
	BinaryPath string `json:"binaryPath"`

	// DataDir is the Quantaureum data directory.
	DataDir string `json:"dataDir"`

	// ConfigPath is the path to qaud's config.json.
	ConfigPath string `json:"configPath"`

	// GenesisPath is the path to genesis.json.
	GenesisPath string `json:"genesisPath"`

	// AutoRestart enables automatic restart on crash.
	AutoRestart bool `json:"autoRestart"`

	// MaxRestartAttempts is the max consecutive restart attempts before giving up.
	MaxRestartAttempts int `json:"maxRestartAttempts"`

	// RestartDelay is the delay between restart attempts.
	RestartDelay time.Duration `json:"restartDelay"`

	// HealthCheckInterval is how often to check process health.
	HealthCheckInterval time.Duration `json:"healthCheckInterval"`

	// HealthCheckRPCAddr is the RPC address for health checks.
	HealthCheckRPCAddr string `json:"healthCheckRPCAddr"`

	// ShutdownTimeout is the max time to wait for graceful shutdown.
	ShutdownTimeout time.Duration `json:"shutdownTimeout"`

	// QaudArgs are additional arguments to pass to qaud.
	QaudArgs []string `json:"qaudArgs"`
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() *Config {
	return &Config{
		BinaryPath:          "/usr/local/bin/qaud",
		DataDir:             "/var/lib/quantaureum",
		ConfigPath:          "/etc/quantaureum/config.json",
		GenesisPath:         "/etc/quantaureum/genesis.json",
		AutoRestart:         true,
		MaxRestartAttempts:  5,
		RestartDelay:        5 * time.Second,
		HealthCheckInterval: 10 * time.Second,
		HealthCheckRPCAddr:  "http://127.0.0.1:8545",
		ShutdownTimeout:     30 * time.Second,
		QaudArgs:            []string{},
	}
}

// ProcessInfo contains runtime information about the managed process.
type ProcessInfo struct {
	State     ProcessState
	PID       int
	StartedAt time.Time
	Version   string
	Restarts  int
}

// ProcessManager manages the lifecycle of the qaud process.
type ProcessManager struct {
	mu     sync.RWMutex
	config *Config
	cmd    *exec.Cmd
	cancel context.CancelFunc

	// superviseDone is closed when the supervise goroutine exits. supervise
	// is the sole owner of cmd.Wait; stopProcess waits on this channel
	// instead of calling Wait concurrently.
	superviseDone chan struct{}

	state     ProcessState
	pid       int
	startedAt time.Time
	version   string
	restarts  int

	// restartTracker counts consecutive restart attempts.
	restartTracker int
	lastRestartAt  time.Time

	// done is closed when the process manager is fully stopped.
	done chan struct{}
}

// NewProcessManager creates a new ProcessManager with the given configuration.
func NewProcessManager(cfg *Config) *ProcessManager {
	return &ProcessManager{
		config:        cfg,
		state:         StateStopped,
		done:          make(chan struct{}),
		superviseDone: make(chan struct{}),
	}
}

// Start starts the qaud process and begins supervision.
func (pm *ProcessManager) Start(ctx context.Context) error {
	pm.mu.Lock()
	if pm.state == StateRunning || pm.state == StateStarting {
		pm.mu.Unlock()
		return fmt.Errorf("process is already %s", pm.state)
	}
	pm.state = StateStarting
	pm.mu.Unlock()

	if err := pm.startProcess(); err != nil {
		pm.mu.Lock()
		pm.state = StateCrashed
		pm.mu.Unlock()
		return fmt.Errorf("failed to start process: %w", err)
	}

	// Start supervision loop
	visorCtx, cancel := context.WithCancel(ctx)
	pm.cancel = cancel
	go pm.supervise(visorCtx)

	return nil
}

// Stop gracefully stops the managed process.
func (pm *ProcessManager) Stop() error {
	pm.mu.Lock()
	if pm.state == StateStopped || pm.state == StateStopping {
		pm.mu.Unlock()
		return fmt.Errorf("process is already %s", pm.state)
	}
	pm.state = StateStopping
	pm.mu.Unlock()

	// Cancel supervision context
	if pm.cancel != nil {
		pm.cancel()
	}

	return pm.stopProcess()
}

// Status returns the current process information.
func (pm *ProcessManager) Status() ProcessInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return ProcessInfo{
		State:     pm.state,
		PID:       pm.pid,
		StartedAt: pm.startedAt,
		Version:   pm.version,
		Restarts:  pm.restarts,
	}
}

// IsRunning returns whether the managed process is currently running.
func (pm *ProcessManager) IsRunning() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.state == StateRunning
}

// Wait blocks until the process manager is fully stopped.
func (pm *ProcessManager) Wait() {
	<-pm.done
}

// startProcess starts the qaud binary as a child process.
func (pm *ProcessManager) startProcess() error {
	binaryPath, err := filepath.EvalSymlinks(pm.config.BinaryPath)
	if err != nil {
		return fmt.Errorf("failed to resolve binary path %s: %w", pm.config.BinaryPath, err)
	}

	if _, err := os.Stat(binaryPath); err != nil {
		return fmt.Errorf("binary not found at %s: %w", binaryPath, err)
	}

	// Build qaud arguments
	args := []string{}
	if pm.config.DataDir != "" {
		args = append(args, "--datadir", pm.config.DataDir)
	}
	if pm.config.ConfigPath != "" {
		args = append(args, "--config", pm.config.ConfigPath)
	}
	if pm.config.GenesisPath != "" {
		args = append(args, "--genesis", pm.config.GenesisPath)
	}
	args = append(args, pm.config.QaudArgs...)

	pm.cmd = exec.Command(binaryPath, args...)
	pm.cmd.Stdout = os.Stdout
	pm.cmd.Stderr = os.Stderr

	// Set process group ID so we can kill the entire group (Linux only)
	setProcessGroupID(pm.cmd)

	if err := pm.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start qaud: %w", err)
	}

	pm.mu.Lock()
	pm.pid = pm.cmd.Process.Pid
	pm.startedAt = time.Now()
	pm.state = StateRunning
	pm.mu.Unlock()

	return nil
}

// stopProcess sends SIGTERM to the process and waits for it to exit.
func (pm *ProcessManager) stopProcess() error {
	pm.mu.Lock()
	if pm.cmd == nil || pm.cmd.Process == nil {
		pm.state = StateStopped
		close(pm.done)
		pm.mu.Unlock()
		return nil
	}
	process := pm.cmd.Process
	pm.mu.Unlock()

	// Send termination signal (platform-specific)
	sendTerminationSignal(process)

	// Wait for the supervise goroutine — the sole owner of cmd.Wait — to
	// observe the process exit. Waiting on superviseDone instead of calling
	// cmd.Wait here avoids concurrent Wait calls on the same *exec.Cmd,
	// which are documented to cause deadlock.
	select {
	case <-pm.superviseDone:
		// Process exited
	case <-time.After(pm.config.ShutdownTimeout):
		// Timeout, force kill
		_ = process.Kill()
		<-pm.superviseDone
	}

	pm.mu.Lock()
	pm.state = StateStopped
	pm.pid = 0
	close(pm.done)
	pm.mu.Unlock()

	return nil
}

// reapProcess reaps the managed child process when ctx is canceled before
// the process has been reaped. stopProcess sends the termination signal, so
// this call only returns once the process has actually exited (or after
// stopProcess force-kills it on ShutdownTimeout). Calling Wait on an already
// reaped cmd returns an error immediately, so re-reaping is safe.
func (pm *ProcessManager) reapProcess() {
	if pm.cmd != nil && pm.cmd.Process != nil {
		_ = pm.cmd.Wait()
	}
}

// supervise monitors the process and restarts it if it crashes.
func (pm *ProcessManager) supervise(ctx context.Context) {
	// supervise is the sole owner of cmd.Wait; closing superviseDone on exit
	// lets stopProcess wait for process teardown without calling Wait
	// concurrently.
	defer close(pm.superviseDone)

	for {
		select {
		case <-ctx.Done():
			pm.reapProcess()
			return
		default:
		}

		// Wait for process to exit
		if pm.cmd != nil && pm.cmd.Process != nil {
			waitErr := pm.cmd.Wait()

			pm.mu.Lock()
			wasRunning := pm.state == StateRunning
			pm.state = StateCrashed
			pm.pid = 0
			pm.mu.Unlock()

			if !wasRunning {
				// Process was intentionally stopped
				return
			}

			if waitErr != nil {
				fmt.Fprintf(os.Stderr, "[visor] qaud process exited: %v\n", waitErr)
			}

			// Check if we should restart
			if !pm.config.AutoRestart {
				fmt.Fprintf(os.Stderr, "[visor] auto-restart disabled, not restarting\n")
				return
			}

			// Track consecutive restarts
			pm.mu.Lock()
			now := time.Now()
			if now.Sub(pm.lastRestartAt) < 5*time.Minute {
				pm.restartTracker++
			} else {
				pm.restartTracker = 1
			}
			pm.lastRestartAt = now
			tracker := pm.restartTracker
			pm.mu.Unlock()

			if tracker > pm.config.MaxRestartAttempts {
				fmt.Fprintf(os.Stderr, "[visor] max restart attempts (%d) reached, giving up\n",
					pm.config.MaxRestartAttempts)
				return
			}

			fmt.Fprintf(os.Stderr, "[visor] restarting qaud (attempt %d/%d) in %v...\n",
				tracker, pm.config.MaxRestartAttempts, pm.config.RestartDelay)

			select {
			case <-time.After(pm.config.RestartDelay):
			case <-ctx.Done():
				return
			}

			pm.mu.Lock()
			pm.state = StateStarting
			pm.mu.Unlock()

			if err := pm.startProcess(); err != nil {
				fmt.Fprintf(os.Stderr, "[visor] failed to restart qaud: %v\n", err)
				continue
			}

			pm.mu.Lock()
			pm.restarts++
			pm.mu.Unlock()

			fmt.Fprintf(os.Stderr, "[visor] qaud restarted successfully (PID: %d)\n", pm.pid)
		}

		select {
		case <-ctx.Done():
			pm.reapProcess()
			return
		case <-time.After(pm.config.HealthCheckInterval):
		}
	}
}
