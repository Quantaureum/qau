// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/quantaureum/qau/crypto"
)

func main() {
	// AUDIT (2026) KEYS-14: Replace hardcoded production paths with CLI flags.
	// Previously these were hardcoded to /var/lib/quantaureum/validator.key and
	// /etc/quantaureum/validator-password, which only work on the server and
	// leak the production directory layout.
	keyPath := flag.String("key", "", "Path to validator key file (required)")
	pwdPath := flag.String("password-file", "", "Path to password file (required)")
	flag.Parse()

	if *keyPath == "" || *pwdPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: keydebug -key <key-file> -password-file <password-file>")
		os.Exit(1)
	}

	data, err := os.ReadFile(*keyPath) // #nosec G304 -- operator-supplied path
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read key file: %v\n", err)
		os.Exit(1)
	}

	pwdData, err := os.ReadFile(*pwdPath) // #nosec G304 -- operator-supplied path
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read password file: %v\n", err)
		os.Exit(1)
	}
	// AUDIT (2026) KEYS-14: Wipe password bytes after use.
	defer crypto.ZeroBytesSecure(pwdData)

	password := strings.TrimSpace(string(pwdData))
	fmt.Printf("Password len=%d\n", len(password))
	fmt.Printf("Key file size: %d bytes\n", len(data))

	var probe struct {
		Version int             `json:"version"`
		Crypto  json.RawMessage `json:"crypto"`
		Address string          `json:"address"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Version: %d\n", probe.Version)
	fmt.Printf("Address: %s\n", probe.Address)
	fmt.Printf("Has crypto: %v\n", len(probe.Crypto) > 0)

	keyFile, err := crypto.KeyFileFromJSON(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse key file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("KeyFile parsed OK, N=%d\n", keyFile.Crypto.KDFParams.N)

	privKey, err := crypto.DecryptKeyBytes(keyFile, []byte(password))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Decryption FAILED: %v\n", err)
		os.Exit(1)
	}
	// AUDIT (2026) KEYS-14: Zeroize private key after use.
	defer privKey.Zeroize()

	pubKey := privKey.PublicKey()
	fmt.Printf("Decryption SUCCESS! Address: %x\n", pubKey.Address())
}
