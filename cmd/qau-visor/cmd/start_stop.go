// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for qau-visor.
package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/quantaureum/qau/cmd/qau-visor/visor"
	"github.com/spf13/cobra"
)

func newStartCmd() *cobra.Command {
	var autoRestart bool
	var maxRestarts int

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start the qaud process under visor supervision",
		Long: `Start the qaud node process under visor supervision.

The visor will monitor the process and automatically restart it if it crashes.
Use --no-auto-restart to disable automatic restarts.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := visor.DefaultConfig()
			cfg.BinaryPath = qaudBinaryPath
			cfg.DataDir = dataDir
			cfg.AutoRestart = autoRestart
			cfg.MaxRestartAttempts = maxRestarts

			pm := visor.NewProcessManager(cfg)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if err := pm.Start(ctx); err != nil {
				return fmt.Errorf("failed to start: %w", err)
			}

			fmt.Printf("[visor] qaud process started (PID: %d)\n", pm.Status().PID)
			fmt.Println("[visor] supervising... (Ctrl+C to stop)")

			// Wait for shutdown signal
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

			<-sig
			fmt.Println("\n[visor] shutting down...")

			cancel()
			if err := pm.Stop(); err != nil {
				return fmt.Errorf("failed to stop: %w", err)
			}

			fmt.Println("[visor] qaud stopped successfully")
			return nil
		},
	}

	cmd.Flags().BoolVar(&autoRestart, "auto-restart", true, "Automatically restart on crash")
	cmd.Flags().IntVar(&maxRestarts, "max-restarts", 5, "Max consecutive restart attempts")

	return cmd
}

func newStopCmd() *cobra.Command {
	timeout := 30

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the supervised qaud process",
		Long: `Stop the qaud node process managed by visor.

Sends SIGTERM for graceful shutdown. If the process doesn't exit within
the timeout, it will be force-killed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if qaud is running
			pid, err := findQaudPID()
			if err != nil || pid == 0 {
				return fmt.Errorf("qaud process not found (is it running?)")
			}

			fmt.Printf("[visor] stopping qaud (PID: %d)...\n", pid)

			// Send SIGTERM
			proc, err := os.FindProcess(pid)
			if err != nil {
				return fmt.Errorf("failed to find process: %w", err)
			}

			if err := proc.Signal(syscall.SIGTERM); err != nil {
				return fmt.Errorf("failed to send SIGTERM: %w", err)
			}

			// Wait for process to exit
			deadline := time.After(time.Duration(timeout) * time.Second)
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					// Check if process still exists
					if !isProcessRunning(pid) {
						fmt.Println("[visor] qaud stopped successfully")
						return nil
					}
				case <-deadline:
					fmt.Println("[visor] timeout reached, force killing...")
					_ = proc.Kill()
					return fmt.Errorf("qaud did not stop within %d seconds, force killed", timeout)
				}
			}
		},
	}

	cmd.Flags().IntVar(&timeout, "timeout", 30, "Shutdown timeout in seconds")

	return cmd
}

func newStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the status of the supervised qaud process",
		RunE: func(cmd *cobra.Command, args []string) error {
			pid, err := findQaudPID()
			if err != nil || pid == 0 {
				fmt.Println("Status: stopped (qaud not running)")
				return nil
			}

			fmt.Printf("Status: running (PID: %d)\n", pid)

			// Check if visor is managing it
			visorPID, _ := findVisorPID()
			if visorPID > 0 {
				fmt.Printf("Visor PID: %d\n", visorPID)
			}

			return nil
		},
	}

	return cmd
}

// findQaudPID finds the PID of a running qaud process.
func findQaudPID() (int, error) {
	// Read PID file if it exists
	pidFile := "/var/lib/quantaureum/qaud.pid"
	if data, err := os.ReadFile(pidFile); err == nil {
		var pid int
		if _, err := fmt.Sscanf(string(data), "%d", &pid); err == nil && pid > 0 {
			if isProcessRunning(pid) {
				return pid, nil
			}
		}
	}

	// Fallback: search for qaud process
	// On Linux, we can check /proc
	// For now, return 0 (not found)
	return 0, fmt.Errorf("qaud process not found")
}

// findVisorPID finds the PID of a running qau-visor process.
func findVisorPID() (int, error) {
	pidFile := "/var/lib/quantaureum/visor.pid"
	if data, err := os.ReadFile(pidFile); err == nil {
		var pid int
		if _, err := fmt.Sscanf(string(data), "%d", &pid); err == nil && pid > 0 {
			if isProcessRunning(pid) {
				return pid, nil
			}
		}
	}
	return 0, fmt.Errorf("visor process not found")
}

// isProcessRunning checks if a process with the given PID is running.
func isProcessRunning(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0 doesn't kill the process, just checks if it exists
	err = proc.Signal(syscall.Signal(0))
	return err == nil
}
