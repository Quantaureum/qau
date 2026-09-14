// Quantaureum Node source, version 1.0.0.
// Package main generates Dilithium3 validator keys for the local testnet.
//
// Output format per validator:
//
//	validatorN.key      - dilithium3:hex_priv:hex_pub (node loadable)
//	validatorN.pub      - hex public key
//	validatorN.address  - 0x-prefixed hex address

// Run the command with an explicit output directory outside the source tree.
// Private key bytes are never printed to stdout; only the address and file
// paths are printed.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

const numValidators = 3

func main() {
	outputDir := flag.String("output", "", "secure output directory outside the source tree (required)")
	flag.Parse()

	if *outputDir == "" {
		fmt.Fprintln(os.Stderr, "usage: go run ./testnet/keygen -output <secure-output-directory>")
		os.Exit(1)
	}
	keysDir := *outputDir

	if err := os.MkdirAll(keysDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create keys directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=====================================================")
	fmt.Println("  Quantaureum Testnet Dilithium3 Key Generator")
	fmt.Println("  Post-Quantum Secure (NIST FIPS 204 / Dilithium3)")
	fmt.Println("=====================================================")
	fmt.Println()

	// Stable list of addresses for summary output (do not log private keys).
	addresses := make([]string, numValidators)

	for i := 1; i <= numValidators; i++ {
		fmt.Printf("Generating validator %d key pair (Dilithium3)...\n", i)

		keyPair, err := crypto.GenerateKeyPair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate key pair %d: %v\n", i, err)
			os.Exit(1)
		}

		privHex := hex.EncodeToString(keyPair.Private.Bytes())
		pubHex := hex.EncodeToString(keyPair.Public.Bytes())

		// Node-loadable format: dilithium3:hex_priv:hex_pub
		// The node's BlockProducer.loadValidatorKey accepts this format
		// and will migrate it to encrypted keystore on first load.
		keyFileContent := "dilithium3:" + privHex + ":" + pubHex

		privKeyFile := filepath.Join(keysDir, fmt.Sprintf("validator%d.key", i))
		if err := os.WriteFile(privKeyFile, []byte(keyFileContent), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write private key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  Private key (node-loadable): %s\n", privKeyFile)

		// Public key file (hex only)
		pubKeyFile := filepath.Join(keysDir, fmt.Sprintf("validator%d.pub", i))
		if err := os.WriteFile(pubKeyFile, []byte(pubHex), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write public key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  Public key:                  %s\n", pubKeyFile)

		// Derive address from public key.
		// H-01 (R8 2026-07-19): use error-returning variant so a malformed
		// key (should never happen from GenerateKeyPair, but defensive) is
		// caught here rather than silently producing a zero Address.
		addr, err := types.AddressFromPublicKeyE(keyPair.Public.Bytes())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to derive address for validator %d: %v\n", i, err)
			os.Exit(1)
		}
		addrHex := fmt.Sprintf("0x%s", hex.EncodeToString(addr[:]))
		addresses[i-1] = addrHex

		addrFile := filepath.Join(keysDir, fmt.Sprintf("validator%d.address", i))
		if err := os.WriteFile(addrFile, []byte(addrHex+"\n"), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write address file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  Address:                     %s\n", addrHex)

		// Zeroize private key hex from memory.
		privBytes := []byte(privHex)
		for j := range privBytes {
			privBytes[j] = 0
		}
		fmt.Println()
	}

	fmt.Println("=====================================================")
	fmt.Printf("Successfully generated %d testnet validators\n", numValidators)
	fmt.Println("=====================================================")
	fmt.Println()
	fmt.Println("Validator addresses (use these in genesis.json):")
	for i, addr := range addresses {
		fmt.Printf("  Validator %d: %s\n", i+1, addr)
	}
	fmt.Println()
	fmt.Println("Next step: regenerate testnet/genesis.json with qauctl:")
	fmt.Println("  qauctl genesis generate \\")
	fmt.Println("    --validator-keys testnet/keys/validator1.key,testnet/keys/validator2.key,testnet/keys/validator3.key \\")
	fmt.Println("    --output testnet/genesis.json \\")
	fmt.Println("    --chain-id 1669 \\")
	fmt.Println("    --network-id 1669")
	fmt.Println()
	fmt.Println("NOTE: Private keys are never printed. Keep .key files secure.")
}
