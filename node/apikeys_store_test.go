// Quantaureum Node source, version 1.0.0.
package node

// Tests for the API-key registry persistence: hook-triggered save, reload
// roundtrip, and fail-open on a corrupt file.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/rpc"
)

func newPersistenceTestNode(t *testing.T) *Node {
	t.Helper()
	dir := t.TempDir()
	return &Node{config: &Config{DataDir: dir}}
}

func TestAPIKeysSaveLoadRoundtrip(t *testing.T) {
	n := newPersistenceTestNode(t)
	n.authManager = rpc.NewAuthManager(rpc.DefaultAuthConfig())
	n.wireAPIKeyPersistence()

	// Generate a key: the hook must fire and write the file.
	info, err := n.authManager.GenerateAPIKey("consumer-a", []string{"qau_randomnessGet"}, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	path := n.apiKeysPath()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("registry file not written on mutation: %v", err)
	}

	// Simulate a restart: fresh node + manager, same data dir.
	n2 := newPersistenceTestNode(t)
	n2.config.DataDir = filepath.Dir(path)
	n2.authManager = rpc.NewAuthManager(rpc.DefaultAuthConfig())
	n2.wireAPIKeyPersistence()

	snaps := n2.authManager.SnapshotAPIKeys()
	if len(snaps) != 1 {
		t.Fatalf("reloaded %d keys, want 1", len(snaps))
	}
	if snaps[0].KeyHash != info.KeyHash {
		t.Errorf("reloaded KeyHash = %s, want %s", snaps[0].KeyHash, info.KeyHash)
	}
	if snaps[0].Name != "consumer-a" {
		t.Errorf("reloaded Name = %s", snaps[0].Name)
	}
	if snaps[0].ExpiresAt.IsZero() {
		t.Error("reloaded ExpiresAt is zero — expiry lost across restart")
	}
	// The plaintext must NOT be in the file.
	raw, _ := os.ReadFile(path)
	if len(info.Key) > 0 && strings.Contains(string(raw), info.Key) {
		t.Fatal("plaintext key leaked to the persistence file")
	}
}

func TestAPIKeysCorruptFileFailsOpen(t *testing.T) {
	n := newPersistenceTestNode(t)
	n.authManager = rpc.NewAuthManager(rpc.DefaultAuthConfig())
	if err := os.MkdirAll(n.config.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(n.apiKeysPath(), []byte("not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Must not panic and must leave a usable (empty) registry.
	n.wireAPIKeyPersistence()
	if len(n.authManager.SnapshotAPIKeys()) != 0 {
		t.Error("corrupt file must yield an empty registry")
	}
}

func TestAPIKeysFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		// NTFS does not map POSIX mode bits: os.WriteFile(0600) still reports
		// 0666 on Windows even though access is governed by ACLs. The 0600
		// intent is asserted on POSIX only.
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	n := newPersistenceTestNode(t)
	n.authManager = rpc.NewAuthManager(rpc.DefaultAuthConfig())
	n.wireAPIKeyPersistence()
	if _, err := n.authManager.GenerateAPIKey("k", nil, 0); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(n.apiKeysPath())
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("registry file perms = %v, want no group/world access", st.Mode().Perm())
	}
}
