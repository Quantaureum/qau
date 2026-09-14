// Quantaureum Node source, version 1.0.0.
package main

// Test helpers for account_create_test.go: derive the key pair from a
// canonical mnemonic seed the same way accountFromStdinMnemonic does
// (raw HKDF seed -> mode3.GenerateKey, NOT crypto.GenerateKeyPairFromSeed
// which adds a SHAKE-256 layer) and compute the hex address.

import (
	"bytes"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
)

func deriveTestKeyPair(seed []byte) (*crypto.KeyPair, error) {
	_, priv, err := mode3.GenerateKey(bytes.NewReader(seed))
	if err != nil {
		return nil, err
	}
	privBytes := priv.Bytes()
	pubBytes := priv.Public().(*mode3.PublicKey).Bytes()
	return crypto.ImportKeyPair(privBytes, pubBytes)
}

func testAddressOf(kp *crypto.KeyPair) string {
	return kp.Public.Address().ToHexAddress()
}

var _ = fmt.Sprintf // keep fmt for debugging edits
