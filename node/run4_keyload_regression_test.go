package node

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestLoadOrGenerateValidatorKey_EmptyFileFailClosed is the regression guard for
// run-4 K-1: a zero-byte validator key file used to be treated as "missing",
// causing a freshly generated key to overwrite the validator identity. The
// loader must fail closed and leave the file untouched.
func TestLoadOrGenerateValidatorKey_EmptyFileFailClosed(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "validator.key")
	if err := os.WriteFile(keyPath, nil, 0600); err != nil {
		t.Fatalf("seed empty key file: %v", err)
	}

	bp := &BlockProducer{node: &Node{config: &Config{
		NetworkID:    TestnetNetworkID,
		ValidatorKey: keyPath,
	}}}

	keyPair, err := bp.loadOrGenerateValidatorKey()
	if err == nil {
		t.Fatal("an empty validator key file must fail closed")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("error = %v, want an empty-key refusal", err)
	}
	if keyPair != nil {
		t.Fatal("fail-closed path must not return a generated key pair")
	}

	info, statErr := os.Stat(keyPath)
	if statErr != nil {
		t.Fatalf("stat key file after failed load: %v", statErr)
	}
	if info.Size() != 0 {
		t.Fatalf("loader overwrote the existing key file (size %d)", info.Size())
	}
}

// TestLoadOrGenerateValidatorKey_UnreadableFileFailClosed covers a read error
// that is not os.IsNotExist: the loader must not fall through to generation.
func TestLoadOrGenerateValidatorKey_UnreadableFileFailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission-based read failure is not reproducible on Windows")
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "validator.key")
	if err := os.WriteFile(keyPath, []byte("not-a-valid-key"), 0600); err != nil {
		t.Fatalf("seed key file: %v", err)
	}
	if err := os.Chmod(keyPath, 0); err != nil {
		t.Skipf("chmod not supported: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(keyPath, 0600) })

	bp := &BlockProducer{node: &Node{config: &Config{
		NetworkID:    TestnetNetworkID,
		ValidatorKey: keyPath,
	}}}
	if _, err := bp.loadOrGenerateValidatorKey(); err == nil {
		t.Fatal("an unreadable validator key file must fail closed")
	}
}

// TestLoadOrGenerateValidatorKey_DirectoryPathFailClosed covers a portable
// non-NotExist read failure (the key path is a directory), so the fail-closed
// branch is exercised on Windows too, where permission-based read failures
// above are skipped.
func TestLoadOrGenerateValidatorKey_DirectoryPathFailClosed(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "validator.key")
	if err := os.MkdirAll(keyPath, 0o700); err != nil {
		t.Fatalf("seed key path as directory: %v", err)
	}

	bp := &BlockProducer{node: &Node{config: &Config{
		NetworkID:    TestnetNetworkID,
		ValidatorKey: keyPath,
	}}}
	keyPair, err := bp.loadOrGenerateValidatorKey()
	if err == nil {
		t.Fatal("a key path that exists but cannot be read must fail closed")
	}
	if !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("error = %v, want a read-refusal", err)
	}
	if keyPair != nil {
		t.Fatal("fail-closed path must not return a generated key pair")
	}
	info, statErr := os.Stat(keyPath)
	if statErr != nil || !info.IsDir() {
		t.Fatalf("fail-closed path must leave the live key path untouched (statErr=%v)", statErr)
	}
}

// TestWriteFileAtomic_ReplacesFileWithoutLeftovers pins the success contract:
// the live path carries the new bytes and no temporary file is leaked into the
// key directory.
func TestWriteFileAtomic_ReplacesFileWithoutLeftovers(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "validator.key")
	if err := os.WriteFile(keyPath, []byte("old-identity"), 0o600); err != nil {
		t.Fatalf("seed key file: %v", err)
	}

	if err := writeFileAtomic(keyPath, []byte("new-identity"), 0o600); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}
	got, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read replaced key file: %v", err)
	}
	if string(got) != "new-identity" {
		t.Fatalf("key file content = %q, want new-identity", got)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("list key dir: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("temporary files leaked into the key dir: %v", names)
	}
}

// TestWriteFileAtomic_FailureKeepsLivePath pins the crash-safety contract: a
// failed replacement must leave the live path exactly as it was, never truncated
// or deleted (the old os.WriteFile with O_TRUNC could leave a zero-byte key).
// The replacement is failed deterministically by making the live path a
// directory, which os.Rename refuses on every supported platform.
func TestWriteFileAtomic_FailureKeepsLivePath(t *testing.T) {
	dir := t.TempDir()
	livePath := filepath.Join(dir, "validator.key")
	if err := os.MkdirAll(livePath, 0o700); err != nil {
		t.Fatalf("seed live path as directory: %v", err)
	}
	marker := filepath.Join(livePath, "identity.txt")
	if err := os.WriteFile(marker, []byte("live-identity"), 0o600); err != nil {
		t.Fatalf("seed marker: %v", err)
	}

	err := writeFileAtomic(livePath, []byte("new-identity"), 0o600)
	if err == nil {
		t.Fatal("replacing a directory path must fail")
	}
	if !strings.Contains(err.Error(), "replace key file") {
		t.Fatalf("error = %v, want a replace failure", err)
	}
	got, readErr := os.ReadFile(marker)
	if readErr != nil {
		t.Fatalf("live path was disturbed by the failed write: %v", readErr)
	}
	if string(got) != "live-identity" {
		t.Fatalf("live path content = %q, want live-identity", got)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("failed write left temporary files behind (entries=%d, err=%v)", len(entries), err)
	}
}

// TestNewBlockProducer_FailClosedKeyLoadBlocksStartup verifies the startup
// gate contract: when the key load fails closed, the block producer surfaces a
// non-nil ValidatorKeyLoadError (which startServices turns into a refusal) and
// no replacement key is silently written.
func TestNewBlockProducer_FailClosedKeyLoadBlocksStartup(t *testing.T) {
	cfg := DevConfig()
	cfg.DataDir = t.TempDir()
	cfg.RPCEnabled = false
	cfg.WSEnabled = false
	cfg.MetricsEnabled = false
	cfg.HealthEnabled = false
	cfg.ValidatorEnabled = true

	keyPath := filepath.Join(cfg.DataDir, "validator.key")
	if err := os.WriteFile(keyPath, nil, 0o600); err != nil {
		t.Fatalf("seed empty key file: %v", err)
	}
	cfg.ValidatorKey = keyPath

	n, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("NewNode failed: %v", err)
	}
	defer closeNodeDB(n)

	bp := NewBlockProducer(n, 3*time.Second)
	if err := bp.ValidatorKeyLoadError(); err == nil {
		t.Fatal("startup gate must observe a non-nil key load error")
	}

	// Startup-level assertion: startServices must REFUSE to start block
	// production instead of quietly generating a fresh identity.
	startErr := n.startServices()
	if startErr == nil {
		t.Fatal("startServices must refuse to start with an unusable validator key")
	}
	if !strings.Contains(startErr.Error(), "refusing to start block production") {
		t.Fatalf("startServices error = %v, want a block-production refusal", startErr)
	}

	info, statErr := os.Stat(keyPath)
	if statErr != nil {
		t.Fatalf("stat key file: %v", statErr)
	}
	if info.Size() != 0 {
		t.Fatalf("a generated key silently replaced the live key file (size %d)", info.Size())
	}
}
