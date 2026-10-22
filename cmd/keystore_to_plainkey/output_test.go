// Quantaureum Node source, version 1.0.0.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenSecureOutputCreatesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")

	f, err := openSecureOutput(path)
	if err != nil {
		t.Fatalf("openSecureOutput: %v", err)
	}
	if _, err := f.WriteString("dilithium3:00\n"); err != nil {
		_ = f.Close()
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "dilithium3:00\n" {
		t.Fatalf("unexpected content %q", got)
	}
}

func TestOpenSecureOutputOverwritesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("stale-key-material"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	f, err := openSecureOutput(path)
	if err != nil {
		t.Fatalf("openSecureOutput: %v", err)
	}
	if _, err := f.WriteString("dilithium3:11\n"); err != nil {
		_ = f.Close()
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "dilithium3:11\n" {
		t.Fatalf("overwrite left stale content %q", got)
	}
}

func TestOpenSecureOutputRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("untouched"), 0600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	f, err := openSecureOutput(link)
	if err == nil {
		_ = f.Close()
		t.Fatal("expected symlink output to be refused")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink-specific error, got %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(got) != "untouched" {
		t.Fatalf("symlink target was modified: %q", got)
	}
}

func TestOpenSecureOutputRejectsDirectory(t *testing.T) {
	dir := t.TempDir()

	f, err := openSecureOutput(dir)
	if err == nil {
		_ = f.Close()
		t.Fatal("expected directory output to be refused")
	}
}
