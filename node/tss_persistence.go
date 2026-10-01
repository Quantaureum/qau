// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

func (n *Node) persistTSSKeyState() error {
	if n.config == nil || n.config.TSSKeyShareFile == "" || n.tssManager == nil {
		return fmt.Errorf("TSS state persistence is not configured")
	}
	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	if n.tssStateLoadErr != nil {
		return fmt.Errorf("TSS state write disabled after load failure: %w", n.tssStateLoadErr)
	}
	password, err := n.getTSSPassword()
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(password)
	data, err := n.tssManager.ExportKeySharesEncrypted(password)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(n.config.TSSKeyShareFile), ".tss-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), n.config.TSSKeyShareFile); err != nil {
		return err
	}
	return nil
}

func (n *Node) loadTSSKeyState() (loaded bool, loadErr error) {
	if n.config == nil || n.tssManager == nil {
		return false, fmt.Errorf("TSS state loading is not configured")
	}
	if n.config.TSSKeyShareFile == "" {
		return false, nil
	}
	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	defer func() { n.tssStateLoadErr = loadErr }()
	data, err := os.ReadFile(n.config.TSSKeyShareFile)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !tss.IsEncryptedKeyShareData(data) {
		return false, fmt.Errorf("TSS state file is not encrypted")
	}
	password, err := n.getTSSPassword()
	if err != nil {
		return false, err
	}
	defer qtd.SecurelyZeroMemory(password)
	if err := n.tssManager.ImportKeySharesEncrypted(data, password); err != nil {
		return false, err
	}
	return true, nil
}
