// Quantaureum Node source, version 1.0.0.
// keystore_to_plainkey decrypts a Dilithium3 keystore file (the AES-256-GCM
// JSON format produced by qaud for both validator and account keys) and
// prints the raw "dilithium3:<hex>" string that cmd/transfer_commit and
// cmd/deploy_vesting_all accept as their keyfile argument.
//
// Usage:
//
//	keystore_to_plainkey <keystore.json> <password>
//
// The password is the validator key password (stored on the node as
// QAU_VALIDATOR_KEY_PASSWORD in /etc/quantaureum/validator.env, decoded as
// base64 if it ends with '=').
//
// Output is written to stdout, suitable for piping into a file:
//
//	keystore_to_plainkey validator.key "$(base64 -d < /etc/quantaureum/validator.env | cut -d= -f2)" > /tmp/plain.key
//	transfer_commit /tmp/plain.key 0xABCDEF 5 1668 && shred -u /tmp/plain.key
//
// This tool is intentionally small and never persisted — it reads the
// keystore, decrypts once, writes the result, exits. The plaintext key
// should be erased from disk the moment transfer_commit returns.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/quantaureum/qau/crypto"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: keystore_to_plainkey <keystore.json> <password>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Password:")
		fmt.Fprintln(os.Stderr, "  - literal string for plain-text passwords")
		fmt.Fprintln(os.Stderr, "  - base64: prefix for stored base64-encoded passwords (e.g. /etc/quantaureum/validator.env)")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Example:")
		fmt.Fprintln(os.Stderr, "  keystore_to_plainkey /var/lib/quantaureum/validator.key 'base64:your_base64_encoded_password_here' > /tmp/plain.key")
		os.Exit(1)
	}
	keystorePath := os.Args[1]
	pwArg := os.Args[2]

	// Decode password (supports 'base64:' and 'file:' prefixes for the
	// base64: prefix and binary-safe transmission respectively)
	var password string
	switch {
	case strings.HasPrefix(pwArg, "base64:"):
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(pwArg, "base64:"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: decode base64 password: %v\n", err)
			os.Exit(1)
		}
		password = string(decoded)
	case strings.HasPrefix(pwArg, "file:"):
		data, err := os.ReadFile(strings.TrimPrefix(pwArg, "file:"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "FATAL: read password file: %v\n", err)
			os.Exit(1)
		}
		// trim trailing newline for human-edited files; preserve binary otherwise
		password = strings.TrimRight(string(data), "\n\r")
	default:
		password = pwArg
	}

	// Load keystore JSON
	data, err := os.ReadFile(keystorePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: read keystore %s: %v\n", keystorePath, err)
		os.Exit(1)
	}

	// Strip the "dilithium3:" prefix embedded in the keystore file (qaud
	// stores the keyfile JSON under that prefix to identify the algorithm).
	if idx := strings.Index(string(data), "{"); idx > 0 {
		data = data[idx:]
	}

	kf, err := crypto.KeyFileFromJSON(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: parse keystore JSON: %v\n", err)
		os.Exit(1)
	}

	priv, err := crypto.DecryptKey(kf, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: decrypt keystore (wrong password?): %v\n", err)
		os.Exit(1)
	}

	// Serialize as dilithium3:<hex> — the format cmd/transfer_commit expects.
	fmt.Printf("dilithium3:%s\n", hex.EncodeToString(priv.Bytes()))
}
