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
	"time"

	"github.com/spf13/cobra"
)

func newBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Backup node data",
		Long:  "Create backups of node data, including database and state snapshots.",
	}

	cmd.AddCommand(newBackupCreateCmd())
	cmd.AddCommand(newBackupListCmd())
	cmd.AddCommand(newBackupSnapshotCmd())

	return cmd
}

func newBackupCreateCmd() *cobra.Command {
	var output string
	var includeKeystore bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a full backup",
		Long:  "Create a full backup of the node data directory.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return createBackup(output, includeKeystore)
		},
	}
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file path (default: backup-<timestamp>.tar.gz)")
	cmd.Flags().BoolVar(&includeKeystore, "include-keystore", false, "Include keystore in backup (contains encrypted keys)")
	return cmd
}

func newBackupListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available backups",
		Long:  "List all backup files in the backup directory.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listBackups()
		},
	}
}

func newBackupSnapshotCmd() *cobra.Command {
	var height int64
	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Create a state snapshot",
		Long:  "Create a verifiable state snapshot at a specific height.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return createSnapshot(height)
		},
	}
	cmd.Flags().Int64VarP(&height, "height", "n", -1, "Block height for snapshot (-1 for latest)")
	return cmd
}

func getBackupDir() string {
	return filepath.Join(dataDir, "backups")
}

func createBackup(output string, includeKeystore bool) error {
	// Generate output filename if not provided
	if output == "" {
		timestamp := time.Now().Format("20060102-150405")
		output = filepath.Join(getBackupDir(), fmt.Sprintf("backup-%s.tar.gz", timestamp))
	}

	// Ensure backup directory exists
	backupDir := filepath.Dir(output)
	if err := os.MkdirAll(backupDir, 0750); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Create output file
	file, err := os.Create(output) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
	if err != nil {
		return fmt.Errorf("failed to create backup file: %w", err)
	}
	defer file.Close()

	// Create gzip writer
	gzWriter := gzip.NewWriter(file)
	defer gzWriter.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	// Directories to backup
	dirsToBackup := []string{"chaindata", "state"}
	if includeKeystore {
		dirsToBackup = append(dirsToBackup, "keystore")
	}

	fmt.Println("Creating backup...")
	totalFiles := 0

	for _, dir := range dirsToBackup {
		dirPath := filepath.Join(dataDir, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			if verbose {
				fmt.Printf("  Skipping %s (not found)\n", dir)
			}
			continue
		}

		fmt.Printf("  Backing up %s...\n", dir)
		count, err := addDirToTar(tarWriter, dirPath, dir)
		if err != nil {
			return fmt.Errorf("failed to backup %s: %w", dir, err)
		}
		totalFiles += count
	}

	// Add config file if exists
	configPath := filepath.Join(dataDir, "config.json")
	if _, err := os.Stat(configPath); err == nil {
		fmt.Println("  Backing up config.json...")
		if err := addFileToTar(tarWriter, configPath, "config.json"); err != nil {
			return fmt.Errorf("failed to backup config: %w", err)
		}
		totalFiles++
	}

	fmt.Printf("\nBackup created successfully!\n")
	fmt.Printf("  Output: %s\n", output)
	fmt.Printf("  Files:  %d\n", totalFiles)

	// Get file size
	info, err := os.Stat(output)
	if err == nil {
		fmt.Printf("  Size:   %s\n", formatSize(info.Size()))
	}

	return nil
}

func listBackups() error {
	backupDir := getBackupDir()

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No backups found.")
			return nil
		}
		return fmt.Errorf("failed to read backup directory: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("No backups found.")
		return nil
	}

	fmt.Printf("Backups in %s:\n", backupDir)
	fmt.Println("================================")

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		fmt.Printf("  %s  %s  %s\n",
			info.ModTime().Format("2006-01-02 15:04:05"),
			formatSize(info.Size()),
			entry.Name())
	}

	return nil
}

func createSnapshot(height int64) error {
	// Call RPC to create snapshot
	var params any
	if height >= 0 {
		params = []any{height}
	} else {
		params = nil
	}

	fmt.Println("Creating state snapshot...")

	result, err := rpcCall("evm_snapshot", params)
	if err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}

	fmt.Printf("Snapshot created: %s\n", string(result))
	return nil
}

func addDirToTar(tw *tar.Writer, srcDir, baseDir string) (int, error) {
	count := 0

	err := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		// Create tar path
		tarPath := filepath.Join(baseDir, relPath)
		if tarPath == baseDir {
			tarPath = baseDir
		}

		// Create header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = tarPath

		// Write header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		// Write file content if it's a regular file
		if info.Mode().IsRegular() {
			// R63-G122 [HIGH] FIX: Use O_NOFOLLOW to prevent symlink traversal attacks.
			// filepath.Walk visits a file; between that visit and the os.Open call below,
			// an attacker could replace the file with a symlink to a sensitive location
			// (e.g., /etc/passwd or private key files). O_NOFOLLOW causes OpenFile to
			// fail if path is a symlink, preventing the attack.
			file, err := openFileNoSymlink(path)
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(tw, file); err != nil {
				return err
			}
			count++
		}

		return nil
	})

	return count, err
}

func openFileNoSymlink(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to follow symlink: %s", path)
	}
	return os.Open(path) // #nosec G304 -- file path from trusted source: CLI arg / config / internal constant
}

func addFileToTar(tw *tar.Writer, srcPath, tarPath string) error {
	// R63-G122 [HIGH] FIX: Use O_NOFOLLOW to prevent symlink traversal.
	file, err := openFileNoSymlink(srcPath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = tarPath

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	_, err = io.Copy(tw, file)
	return err
}

func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
