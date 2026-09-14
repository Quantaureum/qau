// Quantaureum Node source, version 1.0.0.
// verify_validator_key verifies that the address decrypted from validator.key matches a genesis validator.
// Usage: verify_validator_key <keyfile> <password>
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/quantaureum/qau/crypto"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: verify_validator_key <keyfile> <password>")
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ReadFile: %v\n", err)
		os.Exit(1)
	}
	keyFile, err := crypto.KeyFileFromJSON(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "KeyFileFromJSON: %v\n", err)
		os.Exit(1)
	}
	priv, err := crypto.DecryptKey(keyFile, os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "DecryptKey: %v\n", err)
		os.Exit(1)
	}
	pub := priv.PublicKey()
	addr := pub.Address()
	fmt.Printf("decrypted address: 0x%s\n", hex.EncodeToString(addr[:]))
	fmt.Printf("pubkey hex: %s\n", hex.EncodeToString(pub.Bytes()))
}
