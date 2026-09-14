// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/quantaureum/qau/crypto"
)

func main() {
	if len(os.Args) < 3 {
		// SECURITY (audit P2-17): Password is read from environment variable
		// QAU_KEYTOOL_PASSWORD to avoid exposure via /proc/<pid>/cmdline.
		fmt.Fprintf(os.Stderr, "Usage: %s <private_key_file> <output_file>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Password is read from QAU_KEYTOOL_PASSWORD environment variable.\n")
		os.Exit(1)
	}

	keyFilePath := os.Args[1]
	outputFile := os.Args[2]
	// SECURITY (audit P2-17): Read password from environment, not command line
	password := os.Getenv("QAU_KEYTOOL_PASSWORD")
	if password == "" {
		fmt.Fprintf(os.Stderr, "Error: QAU_KEYTOOL_PASSWORD environment variable not set\n")
		os.Exit(1)
	}

	// Read private key from file
	data, err := os.ReadFile(keyFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read key file: %v\n", err)
		os.Exit(1)
	}

	keyHex := strings.TrimSpace(string(data))
	// Strip dilithium3: prefix if present
	keyHex = strings.TrimPrefix(keyHex, "dilithium3:")
	keyHex = strings.TrimPrefix(keyHex, "DILITHIUM3:")
	// Remove any remaining colons or whitespace
	keyHex = strings.ReplaceAll(keyHex, ":", "")
	keyHex = strings.TrimSpace(keyHex)

	fmt.Printf("Key hex length: %d\n", len(keyHex))

	// Decode hex
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode hex: %v\n", err)
		os.Exit(1)
	}
	// audit-fix HIGH: zero key bytes after use to prevent private key material
	// from persisting in heap memory after program exit.
	defer func() {
		for i := range keyBytes {
			keyBytes[i] = 0
		}
	}()

	fmt.Printf("Key bytes length: %d\n", len(keyBytes))

	// Dilithium3 private key is exactly 4000 bytes; the file may contain
	// additional data (e.g. public key appended). Truncate to expected size.
	const dilithium3PrivKeySize = 4000
	if len(keyBytes) > dilithium3PrivKeySize {
		fmt.Printf("Truncating key from %d to %d bytes (Dilithium3 private key size)\n", len(keyBytes), dilithium3PrivKeySize)
		keyBytes = keyBytes[:dilithium3PrivKeySize]
	}

	// Create private key from bytes
	privKey, err := crypto.PrivateKeyFromBytes(keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create private key: %v\n", err)
		os.Exit(1)
	}
	// audit-fix HIGH: zeroize private key after use to prevent key material
	// from remaining in memory after program exit.
	defer privKey.Zeroize()

	// Convert password to []byte so it can be zeroed after use.
	// audit-fix HIGH: Go strings are immutable and cannot be scrubbed from memory.
	// Use []byte and zero after use to minimize plaintext password exposure.
	passwordBytes := []byte(password)
	defer func() {
		for i := range passwordBytes {
			passwordBytes[i] = 0
		}
	}()

	// Encrypt with password
	keyFileObj, err := crypto.EncryptKeyBytes(privKey, passwordBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encrypt key: %v\n", err)
		os.Exit(1)
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(keyFileObj, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal JSON: %v\n", err)
		os.Exit(1)
	}

	// Write to file
	if err := os.WriteFile(outputFile, jsonData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write file: %v\n", err)
		os.Exit(1)
	}

	pubKey := privKey.PublicKey()
	fmt.Printf("Created keystore file: %s\n", outputFile)
	fmt.Printf("Address: %x\n", pubKey.Address())
}
