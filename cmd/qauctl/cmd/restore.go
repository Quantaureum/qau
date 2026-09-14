// Quantaureum Node source, version 1.0.0.
// Package cmd provides CLI commands for the qauctl management tool.
package cmd

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func newRestoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore node data",
		Long:  "Restore node data from backups or snapshots.",
	}

	cmd.AddCommand(newRestoreBackupCmd())
	cmd.AddCommand(newRestoreSnapshotCmd())
	cmd.AddCommand(newRestoreVerifyCmd())

	return cmd
}

func newRestoreBackupCmd() *cobra.Command {
	var force bool
	var skipKeystore bool
	cmd := &cobra.Command{
		Use:   "backup <backup-file>",
		Short: "Restore from a backup file",
		Long:  "Restore node data from a backup archive.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return restoreBackup(args[0], force, skipKeystore)
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing data without confirmation")
	cmd.Flags().BoolVar(&skipKeystore, "skip-keystore", false, "Skip restoring keystore")
	return cmd
}

func newRestoreSnapshotCmd() *cobra.Command {
	var height int64
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Restore from a state snapshot",
		Long:  "Restore state from a previously created snapshot.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return restoreSnapshot(height)
		},
	}
	cmd.Flags().Int64VarP(&height, "height", "n", -1, "Snapshot height to restore (-1 for latest)")
	return cmd
}

func newRestoreVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <backup-file>",
		Short: "Verify a backup file",
		Long:  "Verify the integrity of a backup archive without restoring.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return verifyBackup(args[0])
		},
	}
}

func restoreBackup(backupPath string, force, skipKeystore bool) error {
	// Check if backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file not found: %s", backupPath)
	}

	// Check if data directory has existing data
	if !force {
		hasData := false
		for _, dir := range []string{"chaindata", "state"} {
			dirPath := filepath.Join(dataDir, dir)
			if _, err := os.Stat(dirPath); err == nil {
				hasData = true
				break
			}
		}

		if hasData {
			fmt.Println("Warning: Data directory contains existing data.")
			fmt.Print("Do you want to overwrite? [y/N]: ")
			var response string
			fmt.Scanln(&response) // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
			if strings.ToLower(response) != "y" && strings.ToLower(response) != "yes" {
				fmt.Println("Restore canceled.")
				return nil
			}
		}
	}

	// Open backup file
	file, err := os.Open(backupPath) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()

	// Create gzip reader
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzReader)

	fmt.Println("Restoring from backup...")
	restoredFiles := 0

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar entry: %w", err)
		}

		// Skip keystore if requested
		if skipKeystore && strings.HasPrefix(header.Name, "keystore") {
			if verbose {
				fmt.Printf("  Skipping %s\n", header.Name)
			}
			continue
		}

		// #nosec audit-remediation R12-2: Tar Slip path traversal defense
		// Layer 1: Clean the path and reject absolute paths or parent references
		cleanName := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanName, "..") || strings.HasPrefix(cleanName, string(filepath.Separator)) {
			return fmt.Errorf("illegal tar entry path (traversal attempt): %s", header.Name)
		}

		// Layer 2: Create target path and verify it stays within dataDir
		targetPath := filepath.Join(dataDir, cleanName)
		absTarget, err := filepath.Abs(targetPath)
		if err != nil {
			return fmt.Errorf("failed to resolve target path: %w", err)
		}
		absDataDir, err := filepath.Abs(dataDir)
		if err != nil {
			return fmt.Errorf("failed to resolve data directory: %w", err)
		}
		if !strings.HasPrefix(absTarget, absDataDir+string(filepath.Separator)) && absTarget != absDataDir {
			return fmt.Errorf("illegal tar entry path escapes data directory: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode).Perm()); err != nil { //nolint:gosec,G115
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}

		case tar.TypeReg:
			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(targetPath), 0750); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode).Perm()) // #nosec G115 -- Perm() masks to 9 bits
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}

			const maxSingleFileSize = 1 << 30
			if _, err := io.Copy(outFile, io.LimitReader(tarReader, maxSingleFileSize)); err != nil { // #nosec G110 G104
				outFile.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
				return fmt.Errorf("failed to write file %s: %w", targetPath, err)
			}
			outFile.Close() // #nosec G104 -- error intentionally ignored: non-critical operation //nolint:errcheck
			restoredFiles++

			if verbose {
				fmt.Printf("  Restored %s\n", header.Name)
			}
		}
	}

	fmt.Printf("\nRestore completed successfully!\n")
	fmt.Printf("  Files restored: %d\n", restoredFiles)
	fmt.Printf("  Data directory: %s\n", dataDir)

	return nil
}

func restoreSnapshot(height int64) error {
	// Call RPC to restore from snapshot
	var params any
	if height >= 0 {
		params = []any{height}
	} else {
		params = nil
	}

	fmt.Println("Restoring from snapshot...")

	result, err := rpcCall("evm_revert", params)
	if err != nil {
		return fmt.Errorf("failed to restore snapshot: %w", err)
	}

	fmt.Printf("Snapshot restored: %s\n", string(result))
	return nil
}

func verifyBackup(backupPath string) error {
	// Check if backup file exists
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file not found: %s", backupPath)
	}

	// Open backup file
	file, err := os.Open(backupPath) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return fmt.Errorf("failed to open backup file: %w", err)
	}
	defer file.Close()

	// Create gzip reader
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("invalid gzip format: %w", err)
	}
	defer gzReader.Close()

	// Create tar reader
	tarReader := tar.NewReader(gzReader)

	fmt.Println("Verifying backup...")
	fileCount := 0
	totalSize := int64(0)
	directories := make(map[string]bool)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("backup corrupted: %w", err)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			directories[header.Name] = true
		case tar.TypeReg:
			fileCount++
			totalSize += header.Size

			// R59-G110 [HIGH] FIX: Add per-file decompressed size limit to prevent
			// decompression bomb attacks. A malicious tar could contain highly compressed
			// data (e.g. 10MB compressed → 10TB decompressed) to exhaust disk/memory.
			// We use a conservative 1GB per-file limit — reasonable for any legitimate
			// backup artifact while blocking decompression bombs.
			// LimitReader returns EOF after limit bytes are read, causing io.Copy to succeed.
			// We also validate header.Size is non-negative and capped to prevent int64 overflow.
			const maxDecompressedSize = 1 << 30 // 1 GB
			if header.Size < 0 || header.Size > maxDecompressedSize {
				return fmt.Errorf("file %s has invalid or excessive size %d: maximum allowed is %d",
					header.Name, header.Size, maxDecompressedSize)
			}
			if _, err := io.Copy(io.Discard, io.LimitReader(tarReader, maxDecompressedSize)); err != nil {
				return fmt.Errorf("failed to read file %s: %w", header.Name, err)
			}
		}

		if verbose {
			fmt.Printf("  Verified %s\n", header.Name)
		}
	}

	fmt.Printf("\nBackup verification successful!\n")
	fmt.Printf("  File:        %s\n", backupPath)
	fmt.Printf("  Directories: %d\n", len(directories))
	fmt.Printf("  Files:       %d\n", fileCount)
	fmt.Printf("  Total size:  %s\n", formatSize(totalSize))

	// List top-level directories
	fmt.Println("\nContents:")
	for dir := range directories {
		parts := strings.Split(dir, string(filepath.Separator))
		if len(parts) == 1 || (len(parts) == 2 && parts[1] == "") {
			fmt.Printf("  - %s\n", parts[0])
		}
	}

	return nil
}
