// Quantaureum Node source, version 1.0.0.
// keyderive reads a private key hex file and outputs dilithium3:privkey:pubkey format.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/quantaureum/qau/crypto"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: keyderive <key-file>")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	content := strings.TrimSpace(string(data))

	// Remove dilithium3: prefix if present
	if strings.HasPrefix(content, "dilithium3:") {
		content = strings.TrimPrefix(content, "dilithium3:")
		content = strings.TrimSpace(content)
		// If there's a pubkey after :, take just the privkey
		if idx := strings.Index(content, ":"); idx >= 0 {
			content = content[:idx]
		}
	}

	// Decode private key
	keyBytes, err := hex.DecodeString(content)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid hex: %v\n", err)
		os.Exit(1)
	}

	if len(keyBytes) != crypto.Dilithium3PrivateKeySize {
		fmt.Fprintf(os.Stderr, "Invalid private key size: %d, expected %d\n", len(keyBytes), crypto.Dilithium3PrivateKeySize)
		os.Exit(1)
	}

	// Derive public key
	privKey, err := crypto.PrivateKeyFromBytes(keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid private key: %v\n", err)
		os.Exit(1)
	}

	pubKey := privKey.PublicKey()
	pubKeyBytes := pubKey.Bytes()
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	// Output full format: dilithium3:privkey:pubkey
	fmt.Printf("dilithium3:%s:%s\n", content, pubKeyHex)
}
