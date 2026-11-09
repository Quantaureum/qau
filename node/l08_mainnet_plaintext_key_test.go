package node

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quantaureum/qau/crypto"
)

// newKeyGenProducer builds a BlockProducer whose node config points at a
// temporary validator key path with no password sources configured.
func newKeyGenProducer(t *testing.T, networkID uint64) (*BlockProducer, string) {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "validator.key")
	return &BlockProducer{
		node: &Node{config: &Config{
			NetworkID:    networkID,
			ValidatorKey: keyPath,
		}},
	}, keyPath
}

// SECURITY (audit L-08): on mainnet, generation without a password must fail
// with an explicit SECURITY error and must not leave a plaintext key on disk.
func TestL08_MainnetGenerationRefusesPlaintextKey(t *testing.T) {
	t.Setenv("QAU_VALIDATOR_KEY_PASSWORD", "")

	bp, keyPath := newKeyGenProducer(t, MainnetNetworkID)

	_, err := bp.loadOrGenerateValidatorKey()
	if err == nil {
		t.Fatal("mainnet key generation without a password must fail")
	}
	if !strings.Contains(err.Error(), "SECURITY") {
		t.Fatalf("expected an explicit SECURITY error, got %v", err)
	}
	if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
		t.Fatalf("mainnet must not write a validator key file, stat err = %v", statErr)
	}
}

// SECURITY (audit L-08): the devnet/testnet plaintext fallback is unchanged.
func TestL08_DevnetGenerationStillWritesPlaintextKey(t *testing.T) {
	t.Setenv("QAU_VALIDATOR_KEY_PASSWORD", "")

	bp, keyPath := newKeyGenProducer(t, TestnetNetworkID)

	kp, err := bp.loadOrGenerateValidatorKey()
	if err != nil {
		t.Fatalf("devnet key generation must succeed: %v", err)
	}
	if kp == nil || kp.Private == nil {
		t.Fatal("expected a generated key pair")
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("expected plaintext key file on devnet: %v", err)
	}
	if len(data) != crypto.Dilithium3PrivateKeySize {
		t.Fatalf("expected raw %d-byte key, got %d bytes", crypto.Dilithium3PrivateKeySize, len(data))
	}
}

// SECURITY (audit L-08): with a password configured, mainnet generation still
// succeeds and writes the encrypted keystore format.
func TestL08_MainnetGenerationWithPasswordWritesEncryptedKey(t *testing.T) {
	t.Setenv("QAU_VALIDATOR_KEY_PASSWORD", "L08-test-password-0123456789abcdef")

	bp, keyPath := newKeyGenProducer(t, MainnetNetworkID)

	if _, err := bp.loadOrGenerateValidatorKey(); err != nil {
		t.Fatalf("mainnet key generation with a password must succeed: %v", err)
	}
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("expected encrypted key file: %v", err)
	}
	var probe struct {
		Version int             `json:"version"`
		Crypto  json.RawMessage `json:"crypto"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		t.Fatalf("expected JSON keystore, got %q: %v", data, err)
	}
	if probe.Version == 0 || len(probe.Crypto) == 0 {
		t.Fatalf("expected encrypted keystore fields, got %s", data)
	}
}
