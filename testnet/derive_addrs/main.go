// Quantaureum Node source, version 1.0.0.
// Package main derives validator addresses from public keys
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"crypto/sha3"
	"github.com/quantaureum/qau/types"
)

const numValidators = 4

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./testnet/derive_addrs <secure-output-directory>")
		os.Exit(1)
	}
	baseDir := os.Args[1]
	for i := 1; i <= numValidators; i++ {
		pubKeyFile := filepath.Join(baseDir, fmt.Sprintf("validator%d.pub", i))
		data, err := os.ReadFile(pubKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read %s: %v\n", pubKeyFile, err)
			os.Exit(1)
		}
		pubKeyHex := string(data)
		pubKeyBytes, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to decode hex for validator %d: %v\n", i, err)
			os.Exit(1)
		}
		hash := sha3.Sum256(pubKeyBytes)
		var addr types.Address
		copy(addr[:], hash[len(hash)-20:])
		fmt.Printf("validator%d: %s\n", i, addr.String())
		// Also print 0x address for genesis.json
		fmt.Printf("validator%d 0x: 0x%x\n", i, addr[:])
	}
}
