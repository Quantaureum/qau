// Quantaureum Node source, version 1.0.0.
package node

// API-key registry persistence: the AuthManager keeps keys in memory only;
// this store serializes the plaintext-free snapshot to <dataDir>/apikeys.json
// on every mutation (via the AuthManager persistence hook) and reloads it at
// startup, so issued keys and their expiry survive node restarts.
//
// The file contains ONLY hashed key material (SHA-256 of the plaintext,
// computed inside rpc.AuthManager) plus non-secret metadata. Writing an
// actual plaintext key to this file would be a security bug — the plaintext
// exists exactly once, in the admin_generateAPIKey response.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/quantaureum/qau/rpc"
)

const apiKeysFileName = "apikeys.json"

// apiKeysSaveMu serializes saveAPIKeys.
//
// QR-02 (R2 audit): saveAPIKeys runs from the AuthManager persistence hook,
// which fires on every key mutation and can execute concurrently (HTTP
// handler goroutines). The temp-file path is shared (path+".tmp"), so two
// concurrent saves could interleave WriteFile/Rename — one writer's rename
// could publish a half-written file from the other, or a torn mix of both
// snapshots. AuthManager's own lock covers only the snapshot call, not the
// file write, so the mutex here guards the whole write→rename sequence.
var apiKeysSaveMu sync.Mutex

// apiKeyStoreFile is the on-disk envelope for the hashed key registry.
type apiKeyStoreFile struct {
	Version int                  `json:"version"`
	Keys    []rpc.APIKeySnapshot `json:"keys"`
}

// apiKeysPath returns the registry file path under the node data directory.
func (n *Node) apiKeysPath() string {
	return filepath.Join(n.config.DataDir, apiKeysFileName)
}

// saveAPIKeys writes the current snapshot atomically (temp file + rename)
// with 0600 permissions. Called from the AuthManager persistence hook on
// every key mutation. Serialized by apiKeysSaveMu — see the QR-02 note there.
func (n *Node) saveAPIKeys() {
	apiKeysSaveMu.Lock()
	defer apiKeysSaveMu.Unlock()

	snaps := n.authManager.SnapshotAPIKeys()
	data, err := json.MarshalIndent(apiKeyStoreFile{Version: 1, Keys: snaps}, "", "  ")
	if err != nil {
		nodeLog.Error("saveAPIKeys: marshal: %v", err)
		return
	}
	path := n.apiKeysPath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		nodeLog.Error("saveAPIKeys: write %s: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		nodeLog.Error("saveAPIKeys: rename to %s: %v", path, err)
	}
}

// loadAPIKeys restores persisted keys into the AuthManager before the RPC
// server starts serving authenticated requests. A missing file is normal
// (first boot); a corrupt file is logged and skipped fail-open — the admin
// can re-issue keys, and blocking boot over key metadata would be worse.
func (n *Node) loadAPIKeys() {
	path := n.apiKeysPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			nodeLog.Warn("loadAPIKeys: read %s: %v (starting with an empty key registry)", path, err)
		}
		return
	}
	var file apiKeyStoreFile
	if err := json.Unmarshal(raw, &file); err != nil {
		nodeLog.Error("loadAPIKeys: corrupt %s: %v (starting with an empty key registry)", path, err)
		return
	}
	for _, snap := range file.Keys {
		if snap.KeyHash == "" {
			continue
		}
		info := &rpc.APIKeyInfo{
			KeyHash:     snap.KeyHash,
			Name:        snap.Name,
			Permissions: snap.Permissions,
			IPWhitelist: snap.IPWhitelist,
			RateLimit:   snap.RateLimit,
			CreatedAt:   snap.CreatedAt,
			ExpiresAt:   snap.ExpiresAt,
		}
		// QR-47 (R2 audit): restore the persisted usage counter — dropping it
		// silently reset every key's usage statistics to zero on restart.
		info.UsageCount.Store(snap.UsageCount)
		n.authManager.AddAPIKey(info)
	}
	nodeLog.Info("loadAPIKeys: restored %d API key(s) from %s", len(file.Keys), path)
}

// wireAPIKeyPersistence loads persisted keys and registers the save hook.
// Hooks are registered AFTER the initial load so the load itself does not
// trigger a redundant write-back.
func (n *Node) wireAPIKeyPersistence() {
	if n.authManager == nil {
		return
	}
	n.loadAPIKeys()
	n.authManager.SetPersistenceHook(n.saveAPIKeys)
	// Persisted keys directory must exist before the first mutation writes.
	if err := os.MkdirAll(n.config.DataDir, 0o700); err != nil {
		nodeLog.Error("wireAPIKeyPersistence: mkdir %s: %v", n.config.DataDir, err)
	}
}
