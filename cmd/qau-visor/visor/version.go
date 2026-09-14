// Quantaureum Node source, version 1.0.0.
// Package visor provides version management for qau-visor.
//
// VersionManager handles:
//   - Storing multiple qaud binary versions
//   - Atomic version switching via symlinks
//   - Version metadata tracking
package visor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// VersionsDir is the directory where qaud versions are stored.
	VersionsDir = "/usr/local/lib/quantaureum/versions"

	// CurrentSymlink is the symlink pointing to the active version.
	CurrentSymlink = "/usr/local/bin/qaud"
)

// VersionInfo contains metadata about a qaud binary version.
type VersionInfo struct {
	Version     string    `json:"version"`
	GitCommit   string    `json:"gitCommit"`
	BuildTime   string    `json:"buildTime"`
	InstalledAt time.Time `json:"installedAt"`
	BinaryPath  string    `json:"binaryPath"`
	Signature   string    `json:"signature,omitempty"` // Dilithium3 signature hex
}

// VersionManager manages qaud binary versions.
type VersionManager struct {
	versionsDir string
	currentLink string
}

// NewVersionManager creates a new VersionManager.
func NewVersionManager() *VersionManager {
	return &VersionManager{
		versionsDir: VersionsDir,
		currentLink: CurrentSymlink,
	}
}

// Install installs a new qaud binary version.
// The binary is copied to the versions directory and metadata is saved.
func (vm *VersionManager) Install(version string, binaryPath string, gitCommit string, buildTime string) error {
	// Create version directory
	versionDir := filepath.Join(vm.versionsDir, version)
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		return fmt.Errorf("failed to create version directory: %w", err)
	}

	// Copy binary to version directory
	destBinary := filepath.Join(versionDir, "qaud")
	if err := copyFile(binaryPath, destBinary); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}

	// Make binary executable
	if err := os.Chmod(destBinary, 0755); err != nil {
		return fmt.Errorf("failed to make binary executable: %w", err)
	}

	// Save version metadata
	info := &VersionInfo{
		Version:     version,
		GitCommit:   gitCommit,
		BuildTime:   buildTime,
		InstalledAt: time.Now(),
		BinaryPath:  destBinary,
	}

	if err := vm.saveVersionInfo(version, info); err != nil {
		// Cleanup on failure
		_ = os.RemoveAll(versionDir)
		return fmt.Errorf("failed to save version info: %w", err)
	}

	return nil
}

// Switch atomically switches the current qaud binary to the specified version.
// On Linux, uses symlink + rename for atomicity.
// On Windows, uses file copy (non-atomic but functional for development).
func (vm *VersionManager) Switch(version string) error {
	versionDir := filepath.Join(vm.versionsDir, version)
	targetBinary := filepath.Join(versionDir, "qaud")

	// Verify target binary exists
	if _, err := os.Stat(targetBinary); err != nil {
		return fmt.Errorf("version %s not found: %w", version, err)
	}

	// Verify version metadata exists
	_, err := vm.GetVersionInfo(version)
	if err != nil {
		return fmt.Errorf("version %s metadata not found: %w", version, err)
	}

	// Try symlink-based switch first (Linux), fall back to copy (Windows)
	tmpLink := vm.currentLink + ".tmp"
	_ = os.Remove(tmpLink)

	if err := os.Symlink(targetBinary, tmpLink); err == nil {
		// Symlink created, atomically rename
		if err := os.Rename(tmpLink, vm.currentLink); err != nil {
			_ = os.Remove(tmpLink)
			return fmt.Errorf("failed to switch symlink: %w", err)
		}
		// Write version marker for GetCurrentVersion fallback
		markerPath := filepath.Join(filepath.Dir(vm.currentLink), ".qaud-version")
		//nolint:gosec // G306: non-sensitive version marker (public version string).
		_ = os.WriteFile(markerPath, []byte(version), 0644) // G306: non-sensitive version marker
		return nil
	}

	// Symlink failed (Windows or missing privileges), use file copy
	if err := copyFile(targetBinary, vm.currentLink); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}

	// Write version marker for GetCurrentVersion fallback
	markerPath := filepath.Join(filepath.Dir(vm.currentLink), ".qaud-version")
	//nolint:gosec // G306: non-sensitive version marker (public version string).
	_ = os.WriteFile(markerPath, []byte(version), 0644)

	return nil
}

// GetCurrentVersion returns the currently active version info.
func (vm *VersionManager) GetCurrentVersion() (*VersionInfo, error) {
	// Try resolving as symlink first (Linux)
	target, err := filepath.EvalSymlinks(vm.currentLink)
	if err == nil {
		// Extract version from path: /usr/local/lib/quantaureum/versions/{version}/qaud
		rel, relErr := filepath.Rel(vm.versionsDir, filepath.Dir(target))
		if relErr == nil {
			version := filepath.Base(rel)
			if info, infoErr := vm.GetVersionInfo(version); infoErr == nil {
				return info, nil
			}
		}
	}

	// Fallback: read current version marker file
	markerPath := filepath.Join(filepath.Dir(vm.currentLink), ".qaud-version")
	data, err := os.ReadFile(markerPath)
	if err != nil {
		return nil, fmt.Errorf("failed to determine current version: %w", err)
	}
	return vm.GetVersionInfo(string(data))
}

// GetVersionInfo returns the metadata for a specific version.
func (vm *VersionManager) GetVersionInfo(version string) (*VersionInfo, error) {
	infoPath := filepath.Join(vm.versionsDir, version, "version.json")
	data, err := os.ReadFile(infoPath)
	if err != nil {
		return nil, fmt.Errorf("version info not found: %w", err)
	}

	var info VersionInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("failed to parse version info: %w", err)
	}

	return &info, nil
}

// ListVersions returns all installed versions.
func (vm *VersionManager) ListVersions() ([]*VersionInfo, error) {
	entries, err := os.ReadDir(vm.versionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read versions directory: %w", err)
	}

	var versions []*VersionInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := vm.GetVersionInfo(entry.Name())
		if err != nil {
			continue // Skip invalid versions
		}
		versions = append(versions, info)
	}

	return versions, nil
}

// Remove removes a version from the versions directory.
func (vm *VersionManager) Remove(version string) error {
	// Don't allow removing the current version
	current, err := vm.GetCurrentVersion()
	if err == nil && current.Version == version {
		return fmt.Errorf("cannot remove currently active version %s", version)
	}

	versionDir := filepath.Join(vm.versionsDir, version)
	return os.RemoveAll(versionDir)
}

// saveVersionInfo saves version metadata to disk.
func (vm *VersionManager) saveVersionInfo(version string, info *VersionInfo) error {
	infoPath := filepath.Join(vm.versionsDir, version, "version.json")
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal version info: %w", err)
	}
	return os.WriteFile(infoPath, data, 0600) // G306: version metadata, owner-only
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	//nolint:gosec // G306: dst is a new node binary, 0755 is REQUIRED for it to
	// execute. This is a public binary, not sensitive data.
	return os.WriteFile(dst, data, 0755)
}
