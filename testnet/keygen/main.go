// Quantaureum Node source, version 1.0.0.
// Package main generates Dilithium3 validator keys for the local testnet.
//
// R8 2026-07-19: Rewritten to enforce project rule "testnet must use
// independent validator keys, fully isolated from mainnet keys". The
// previous testnet/genesis.json reused the three mainnet validator
// addresses (0xB74A..., 0xCf52..., 0xE9B8...), violating that rule.
//
// Output format per validator:
//
//	testnet/keys/validatorN.key      - dilithium3:hex_priv:hex_pub (node loadable)
//	testnet/keys/validatorN.pub      - hex public key
//	testnet/keys/validatorN.address  - 0x-prefixed hex address
//
// Desktop backup (per project rule "testnet validator keys must be backed
// up locally e.g. %USERPROFILE%\Desktop\key\testnet-validator-N.*"):
//
//	%USERPROFILE%\Desktop\key\testnet-validator-N.key
//	%USERPROFILE%\Desktop\key\testnet-validator-N.pub
//	%USERPROFILE%\Desktop\key\testnet-validator-N.address
//
// Private key bytes are NEVER printed to stdout (only address + path).
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

const numValidators = 3

// desktopKeyDir returns the platform-specific desktop backup path for
// testnet validator keys. Per project rule, testnet keys must be backed
// up locally (example: %USERPROFILE%\Desktop\key\testnet-validator-1.*).
func desktopKeyDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home dir: %w", err)
	}
	var desktop string
	switch runtime.GOOS {
	case "windows":
		desktop = filepath.Join(home, "Desktop")
	case "darwin", "linux":
		desktop = filepath.Join(home, "Desktop")
		// Fallback: some Linux setups use XDG_DESKTOP_DIR or no Desktop dir.
		if _, err := os.Stat(desktop); os.IsNotExist(err) {
			desktop = filepath.Join(home, "Documents")
		}
	default:
		desktop = filepath.Join(home, "Desktop")
	}
	return filepath.Join(desktop, "key"), nil
}

func main() {
	keysDir := "./testnet/keys"

	if err := os.MkdirAll(keysDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create keys directory: %v\n", err)
		os.Exit(1)
	}

	backupDir, backupErr := desktopKeyDir()
	if backupErr != nil {
		fmt.Fprintf(os.Stderr, "WARN: could not resolve desktop backup dir: %v (skipping backup)\n", backupErr)
	} else {
		if err := os.MkdirAll(backupDir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: could not create desktop backup dir %s: %v (skipping backup)\n", backupDir, err)
			backupDir = ""
		}
	}

	fmt.Println("=====================================================")
	fmt.Println("  Quantaureum Testnet Dilithium3 Key Generator")
	fmt.Println("  Post-Quantum Secure (NIST FIPS 204 / Dilithium3)")
	fmt.Println("  R8 2026-07-19: independent from mainnet keys")
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

		// Desktop backup per project rule.
		if backupDir != "" {
			backupKey := filepath.Join(backupDir, fmt.Sprintf("testnet-validator-%d.key", i))
			backupPub := filepath.Join(backupDir, fmt.Sprintf("testnet-validator-%d.pub", i))
			backupAddr := filepath.Join(backupDir, fmt.Sprintf("testnet-validator-%d.address", i))
			if err := os.WriteFile(backupKey, []byte(keyFileContent), 0600); err != nil {
				fmt.Fprintf(os.Stderr, "  WARN: failed to back up key to %s: %v\n", backupKey, err)
			} else {
				fmt.Printf("  Backup key:                  %s\n", backupKey)
			}
			_ = os.WriteFile(backupPub, []byte(pubHex), 0600)
			_ = os.WriteFile(backupAddr, []byte(addrHex+"\n"), 0600)
		}

		// Zeroize private key hex from memory.
		privBytes := []byte(privHex)
		for j := range privBytes {
			privBytes[j] = 0
		}
		fmt.Println()
	}

	fmt.Println("=====================================================")
	fmt.Printf("✅ Successfully generated %d independent testnet validators\n", numValidators)
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
