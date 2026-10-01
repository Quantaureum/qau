// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/wallet/tss"
)

func TestPersistTSSStateRestoresRetiredShares(t *testing.T) {
	config := tss.DefaultTSSConfig()
	config.Threshold, config.TotalShares = 2, 2
	manager, err := tss.NewTSSManager(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.GenerateKeyShares(); err != nil {
		t.Fatal(err)
	}
	defer manager.ZeroizeAllShares()
	directory := t.TempDir()
	path := filepath.Join(directory, "state.enc")
	password := "DEVNET ONLY persistence test password"
	node := &Node{tssManager: manager, config: &Config{TSSKeyShareFile: path, ValidatorKeyPassword: password}}
	if err := node.persistTSSKeyState(); err != nil {
		t.Fatal(err)
	}
	if err := manager.RetireResharedShare([]int{4, 7}, 2); err != nil {
		t.Fatal(err)
	}
	if err := node.persistTSSKeyState(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !tss.IsEncryptedKeyShareData(data) {
		t.Fatalf("encrypted state not persisted: %v", err)
	}
	restored, err := tss.NewTSSManager(config)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.ZeroizeAllShares()
	if err := restored.ImportKeySharesEncrypted(data, []byte(password)); err != nil {
		t.Fatal(err)
	}
	if restored.ShareCount() != 0 || !bytes.Equal(restored.GroupPublicKey(), manager.GroupPublicKey()) {
		t.Fatal("retired state changed group key or reactivated old shares")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary state files remain: %v", err)
	}
	node.config.ValidatorKeyPassword = ""
	t.Setenv("QAU_VALIDATOR_KEY_PASSWORD", "")
	if err := node.persistTSSKeyState(); err == nil {
		t.Fatal("state persisted without a password")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, after) {
		t.Fatal("failed persistence changed the previous file")
	}
}

func TestRejectedTSSStateCannotBeOverwrittenByCleanup(t *testing.T) {
	config := tss.DefaultTSSConfig()
	manager, err := tss.NewTSSManager(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.enc")
	original := []byte("invalid state must remain untouched")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	node := &Node{tssManager: manager, config: &Config{TSSKeyShareFile: path, ValidatorKeyPassword: "DEVNET ONLY load test password"}}
	if loaded, err := node.loadTSSKeyState(); loaded || err == nil {
		t.Fatal("invalid existing state did not abort loading")
	}
	if _, err := manager.GenerateKeyShares(); err != nil {
		t.Fatal(err)
	}
	defer manager.ZeroizeAllShares()
	if err := node.persistTSSKeyState(); err == nil {
		t.Fatal("cleanup overwrote a state file rejected during startup")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("rejected state file changed")
	}
}
