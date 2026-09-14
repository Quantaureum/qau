// Quantaureum Node source, version 1.0.0.
// export_key reads a Dilithium3 keystore file and outputs the raw key
// in dilithium3:privkey:pubkey format.
//
// Usage: export_key <keystore_file>
//
// The password is read from stdin (echo disabled when stdin is a terminal)
// so it does not appear in shell history or process listings.
//
// AUDIT (2026) KEYS-12 FIX: Previously the password was taken from
// os.Args[2], exposing it in shell history, ps(1)/Process Explorer output,
// and crash dumps. Read it from stdin via term.ReadPassword instead.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/quantaureum/qau/crypto"

	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: export_key <keystore_file>\n")
		fmt.Fprintf(os.Stderr, "Password will be prompted on stdin.\n")
		os.Exit(1)
	}

	keyPath := os.Args[1]

	fmt.Fprint(os.Stderr, "Keystore password: ")
	pwBytes, err := term.ReadPassword(int(os.Stdin.Fd())) // #nosec G115 -- stdin fd is always a small positive int
	fmt.Fprintln(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read password: %v\n", err)
		os.Exit(1)
	}
	password := string(pwBytes)

	data, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read keystore file: %v\n", err)
		os.Exit(1)
	}

	keyFile, err := crypto.KeyFileFromJSON(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse keystore JSON: %v\n", err)
		os.Exit(1)
	}

	privKey, err := crypto.DecryptKeyBytes(keyFile, []byte(password))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt key: %v\n", err)
		os.Exit(1)
	}

	// Zero the password copy as soon as decryption is done.
	for i := range pwBytes {
		pwBytes[i] = 0
	}

	privHex := hex.EncodeToString(privKey.Bytes())
	pubHex := hex.EncodeToString(privKey.PublicKey().Bytes())

	fmt.Printf("dilithium3:%s:%s\n", privHex, pubHex)
}
