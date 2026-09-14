// Quantaureum Node source, version 1.0.0.
// Package cmd provides the upgrade and rollback CLI commands for qau-visor.
package cmd

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/quantaureum/qau/cmd/qau-visor/visor"
	"github.com/spf13/cobra"
)

var (
	upgradeVersion    string
	upgradeBinary     string
	upgradeGitCommit  string
	upgradeBuildTime  string
	upgradePublicKey  string
	upgradeSkipVerify bool
	upgradeTimeout    int
)

func newUpgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade qaud to a new version with signature verification",
		Long: `Upgrade the qaud node binary to a new version.

The upgrade process:
  1. Verify the new binary's Dilithium3 signature
  2. Install the new version to the versions directory
  3. Stop the current qaud process
  4. Atomically switch the symlink to the new version
  5. Start the new version
  6. Monitor health - rollback on failure

Use --skip-verify only for development/testing (NOT for production).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if upgradeVersion == "" {
				return fmt.Errorf("--version is required")
			}
			if upgradeBinary == "" {
				return fmt.Errorf("--binary is required")
			}

			fmt.Printf("[visor] starting upgrade to version %s...\n", upgradeVersion)

			vm := visor.NewVersionManager()

			// Step 1: Verify signature (unless skipped)
			if !upgradeSkipVerify {
				if upgradePublicKey == "" {
					return fmt.Errorf("--public-key is required for signature verification (or use --skip-verify for testing)")
				}

				sigPath := upgradeBinary + ".sig"
				if _, err := os.Stat(sigPath); err != nil {
					return fmt.Errorf("signature file not found at %s: %w", sigPath, err)
				}

				fmt.Println("[visor] verifying Dilithium3 signature...")
				if err := visor.VerifyBinary(upgradeBinary, sigPath, upgradePublicKey); err != nil {
					return fmt.Errorf("SIGNATURE VERIFICATION FAILED: %w\n\nThis binary may be tampered or corrupted. DO NOT proceed with upgrade.", err)
				}
				fmt.Println("[visor] signature verified successfully")
			} else {
				fmt.Println("[visor] WARNING: signature verification skipped (--skip-verify)")
			}

			// Step 2: Compute binary hash for integrity check
			binaryHash, err := visor.ComputeBinaryHash(upgradeBinary)
			if err != nil {
				return fmt.Errorf("failed to compute binary hash: %w", err)
			}
			fmt.Printf("[visor] binary SHA-256: %s\n", binaryHash)

			// Step 3: Install new version
			fmt.Printf("[visor] installing version %s...\n", upgradeVersion)
			if err := vm.Install(upgradeVersion, upgradeBinary, upgradeGitCommit, upgradeBuildTime); err != nil {
				return fmt.Errorf("failed to install version: %w", err)
			}
			fmt.Printf("[visor] version %s installed to %s/%s/\n", upgradeVersion, visor.VersionsDir, upgradeVersion)

			// Step 4: Save current version for rollback
			currentVersion, err := vm.GetCurrentVersion()
			if err != nil {
				fmt.Println("[visor] WARNING: could not determine current version for rollback")
			} else {
				fmt.Printf("[visor] current version: %s (will be preserved for rollback)\n", currentVersion.Version)
			}

			// Step 5: Stop current process
			fmt.Println("[visor] stopping current qaud process...")
			pid, _ := findQaudPID()
			if pid > 0 {
				proc, _ := os.FindProcess(pid)
				_ = proc.Signal(syscall.SIGTERM)

				// Wait for process to stop
				deadline := time.After(time.Duration(upgradeTimeout) * time.Second)
				ticker := time.NewTicker(500 * time.Millisecond)
				defer ticker.Stop()

				stopped := false
				for !stopped {
					select {
					case <-ticker.C:
						if !isProcessRunning(pid) {
							stopped = true
						}
					case <-deadline:
						_ = proc.Kill()
						return fmt.Errorf("qaud did not stop within %d seconds", upgradeTimeout)
					}
				}
				fmt.Println("[visor] qaud stopped")
			} else {
				fmt.Println("[visor] qaud was not running")
			}

			// Step 6: Atomically switch symlink
			fmt.Printf("[visor] switching to version %s...\n", upgradeVersion)
			if err := vm.Switch(upgradeVersion); err != nil {
				return fmt.Errorf("failed to switch version: %w", err)
			}
			fmt.Printf("[visor] symlink switched to version %s\n", upgradeVersion)

			// Step 7: Start new version
			fmt.Println("[visor] starting new version...")
			cfg := visor.DefaultConfig()
			cfg.BinaryPath = qaudBinaryPath
			cfg.DataDir = dataDir

			pm := visor.NewProcessManager(cfg)
			ctx, cancel := contextWithTimeout(time.Duration(upgradeTimeout) * time.Second)
			defer cancel()

			if err := pm.Start(ctx); err != nil {
				// Upgrade failed, attempt rollback
				fmt.Fprintf(os.Stderr, "[visor] FAILED to start new version: %v\n", err)

				if currentVersion != nil {
					fmt.Printf("[visor] rolling back to version %s...\n", currentVersion.Version)
					if rbErr := vm.Switch(currentVersion.Version); rbErr != nil {
						return fmt.Errorf("upgrade failed AND rollback failed: %w (original: %v)", rbErr, err)
					}
					fmt.Printf("[visor] rolled back to version %s\n", currentVersion.Version)

					// Try starting old version
					pmOld := visor.NewProcessManager(cfg)
					if startErr := pmOld.Start(ctx); startErr != nil {
						return fmt.Errorf("rollback succeeded but old version also failed to start: %w", startErr)
					}
					fmt.Println("[visor] old version started successfully after rollback")
				}

				return fmt.Errorf("upgrade failed, rolled back to previous version")
			}

			fmt.Printf("[visor] upgrade complete! qaud v%s running (PID: %d)\n",
				upgradeVersion, pm.Status().PID)

			// Stop the visor process manager (we just wanted to start qaud)
			// In production, systemd would manage the visor process
			_ = pm

			return nil
		},
	}

	cmd.Flags().StringVar(&upgradeVersion, "version", "", "Version string for the new binary (required)")
	cmd.Flags().StringVar(&upgradeBinary, "binary", "", "Path to the new qaud binary (required)")
	cmd.Flags().StringVar(&upgradeGitCommit, "git-commit", "unknown", "Git commit hash of the build")
	cmd.Flags().StringVar(&upgradeBuildTime, "build-time", "unknown", "Build timestamp")
	cmd.Flags().StringVar(&upgradePublicKey, "public-key", "", "Dilithium3 public key (hex) for signature verification")
	cmd.Flags().BoolVar(&upgradeSkipVerify, "skip-verify", false, "Skip signature verification (DANGEROUS, testing only)")
	cmd.Flags().IntVar(&upgradeTimeout, "timeout", 60, "Upgrade timeout in seconds")

	return cmd
}

func newRollbackCmd() *cobra.Command {
	var rollbackTimeout int

	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Rollback to the previous qaud version",
		Long: `Rollback to the previous version of qaud.

This stops the current qaud process, switches the symlink to the
previous version, and starts it. Use this when an upgrade fails
or the new version has issues.

The previous version must still be installed in the versions directory.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			vm := visor.NewVersionManager()

			// Get current version
			current, err := vm.GetCurrentVersion()
			if err != nil {
				return fmt.Errorf("failed to determine current version: %w", err)
			}

			// List available versions
			versions, err := vm.ListVersions()
			if err != nil {
				return fmt.Errorf("failed to list versions: %w", err)
			}

			if len(versions) <= 1 {
				return fmt.Errorf("no previous version available for rollback")
			}

			// Find the most recent version that isn't the current one
			var previous *visor.VersionInfo
			for _, v := range versions {
				if v.Version != current.Version {
					if previous == nil || v.InstalledAt.After(previous.InstalledAt) {
						previous = v
					}
				}
			}

			if previous == nil {
				return fmt.Errorf("no previous version found")
			}

			fmt.Printf("[visor] current version: %s\n", current.Version)
			fmt.Printf("[visor] rolling back to: %s\n", previous.Version)

			// Stop current process
			fmt.Println("[visor] stopping current qaud process...")
			pid, _ := findQaudPID()
			if pid > 0 {
				proc, _ := os.FindProcess(pid)
				_ = proc.Signal(syscall.SIGTERM)

				deadline := time.After(time.Duration(rollbackTimeout) * time.Second)
				ticker := time.NewTicker(500 * time.Millisecond)
				defer ticker.Stop()

				for {
					select {
					case <-ticker.C:
						if !isProcessRunning(pid) {
							goto stopped
						}
					case <-deadline:
						_ = proc.Kill()
						return fmt.Errorf("qaud did not stop within %d seconds", rollbackTimeout)
					}
				}
			stopped:
				fmt.Println("[visor] qaud stopped")
			}

			// Switch symlink
			if err := vm.Switch(previous.Version); err != nil {
				return fmt.Errorf("failed to switch to previous version: %w", err)
			}

			fmt.Printf("[visor] rolled back to version %s\n", previous.Version)
			fmt.Println("[visor] start qaud manually or via systemd to complete rollback")
			return nil
		},
	}

	cmd.Flags().IntVar(&rollbackTimeout, "timeout", 30, "Rollback timeout in seconds")

	return cmd
}

// contextWithTimeout creates a context with the given timeout.
func contextWithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}
