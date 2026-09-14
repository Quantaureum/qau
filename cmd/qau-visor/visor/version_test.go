// Quantaureum Node source, version 1.0.0.
package visor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVersionManager_InstallAndSwitch(t *testing.T) {
	// Use temp directories
	tmpDir := t.TempDir()
	versionsDir := filepath.Join(tmpDir, "versions")
	binDir := filepath.Join(tmpDir, "bin")

	if err := os.MkdirAll(versionsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}

	vm := &VersionManager{
		versionsDir: versionsDir,
		currentLink: filepath.Join(binDir, "qaud"),
	}

	// Create a fake binary
	fakeBinary := filepath.Join(tmpDir, "qaud-v1.0.0")
	if err := os.WriteFile(fakeBinary, []byte("#!/bin/sh\necho v1.0.0\n"), 0755); err != nil {
		t.Fatal(err)
	}

	// Install version
	if err := vm.Install("v1.0.0", fakeBinary, "abc123", "2026-06-08"); err != nil {
		t.Fatalf("Install() failed: %v", err)
	}

	// Verify version directory was created
	versionDir := filepath.Join(versionsDir, "v1.0.0")
	if _, err := os.Stat(versionDir); os.IsNotExist(err) {
		t.Error("version directory was not created")
	}

	// Verify version.json was created
	info, err := vm.GetVersionInfo("v1.0.0")
	if err != nil {
		t.Fatalf("GetVersionInfo() failed: %v", err)
	}
	if info.Version != "v1.0.0" {
		t.Errorf("version = %q, want v1.0.0", info.Version)
	}
	if info.GitCommit != "abc123" {
		t.Errorf("gitCommit = %q, want abc123", info.GitCommit)
	}

	// Switch to the version
	if err := vm.Switch("v1.0.0"); err != nil {
		t.Fatalf("Switch() failed: %v", err)
	}

	// Verify symlink (Linux) or file copy (Windows)
	target, err := os.Readlink(vm.currentLink)
	if err == nil {
		// Linux: verify symlink target
		expectedTarget := filepath.Join(versionsDir, "v1.0.0", "qaud")
		if target != expectedTarget {
			t.Errorf("symlink target = %q, want %q", target, expectedTarget)
		}
	}
	// On Windows, Readlink fails for regular files, which is expected

	// Get current version
	current, err := vm.GetCurrentVersion()
	if err != nil {
		t.Fatalf("GetCurrentVersion() failed: %v", err)
	}
	if current.Version != "v1.0.0" {
		t.Errorf("current version = %q, want v1.0.0", current.Version)
	}
}

func TestVersionManager_ListVersions(t *testing.T) {
	tmpDir := t.TempDir()
	versionsDir := filepath.Join(tmpDir, "versions")

	if err := os.MkdirAll(versionsDir, 0755); err != nil {
		t.Fatal(err)
	}

	vm := &VersionManager{
		versionsDir: versionsDir,
		currentLink: filepath.Join(tmpDir, "bin", "qaud"),
	}

	// Install two versions
	for _, v := range []string{"v1.0.0", "v1.1.0"} {
		fakeBinary := filepath.Join(tmpDir, "qaud-"+v)
		if err := os.WriteFile(fakeBinary, []byte("#!/bin/sh\necho "+v+"\n"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := vm.Install(v, fakeBinary, "commit-"+v, "2026-06-08"); err != nil {
			t.Fatalf("Install(%s) failed: %v", v, err)
		}
	}

	versions, err := vm.ListVersions()
	if err != nil {
		t.Fatalf("ListVersions() failed: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("len(versions) = %d, want 2", len(versions))
	}
}

func TestVersionManager_RemoveCurrentVersion(t *testing.T) {
	tmpDir := t.TempDir()
	versionsDir := filepath.Join(tmpDir, "versions")
	binDir := filepath.Join(tmpDir, "bin")

	if err := os.MkdirAll(versionsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}

	vm := &VersionManager{
		versionsDir: versionsDir,
		currentLink: filepath.Join(binDir, "qaud"),
	}

	// Install and switch to a version
	fakeBinary := filepath.Join(tmpDir, "qaud-v1.0.0")
	if err := os.WriteFile(fakeBinary, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := vm.Install("v1.0.0", fakeBinary, "abc", "2026"); err != nil {
		t.Fatal(err)
	}
	if err := vm.Switch("v1.0.0"); err != nil {
		t.Fatal(err)
	}

	// Trying to remove the current version should fail
	if err := vm.Remove("v1.0.0"); err == nil {
		t.Error("Remove() should fail for current version")
	}
}

func TestVersionManager_RemoveNonCurrentVersion(t *testing.T) {
	tmpDir := t.TempDir()
	versionsDir := filepath.Join(tmpDir, "versions")
	binDir := filepath.Join(tmpDir, "bin")

	if err := os.MkdirAll(versionsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}

	vm := &VersionManager{
		versionsDir: versionsDir,
		currentLink: filepath.Join(binDir, "qaud"),
	}

	// Install two versions
	for _, v := range []string{"v1.0.0", "v0.9.0"} {
		fakeBinary := filepath.Join(tmpDir, "qaud-"+v)
		if err := os.WriteFile(fakeBinary, []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
		if err := vm.Install(v, fakeBinary, "commit-"+v, "2026"); err != nil {
			t.Fatal(err)
		}
	}

	// Switch to v1.0.0
	if err := vm.Switch("v1.0.0"); err != nil {
		t.Fatal(err)
	}

	// Removing the non-current version should succeed
	if err := vm.Remove("v0.9.0"); err != nil {
		t.Errorf("Remove() failed: %v", err)
	}

	// Verify it's gone
	if _, err := vm.GetVersionInfo("v0.9.0"); err == nil {
		t.Error("version should have been removed")
	}
}

func TestVersionInfo_JSON(t *testing.T) {
	info := &VersionInfo{
		Version:     "v1.0.0",
		GitCommit:   "abc123",
		BuildTime:   "2026-06-08",
		InstalledAt: time.Now().Truncate(time.Second),
		BinaryPath:  "/usr/local/lib/quantaureum/versions/v1.0.0/qaud",
	}

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}

	var decoded VersionInfo
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}

	if decoded.Version != info.Version {
		t.Errorf("version mismatch: got %q, want %q", decoded.Version, info.Version)
	}
	if decoded.GitCommit != info.GitCommit {
		t.Errorf("gitCommit mismatch: got %q, want %q", decoded.GitCommit, info.GitCommit)
	}
}
