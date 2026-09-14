// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/quantaureum/qau/crypto"
)

// GenesisValidator represents a validator entry in the genesis configuration.
type GenesisValidator struct {
	Address     string `json:"address"`
	Stake       string `json:"stake"`
	Commission  int    `json:"commission"`
	PublicKey   string `json:"publicKey"`
	Description string `json:"description"`
}

// readPassword reads the encryption password from the QAU_KEYSTORE_PASSWORD
// environment variable, or prompts the user via stdin if not set.
//
// SECURITY (audit 2026-06-26, P0-03): Password is never passed as a
// command-line argument to avoid exposure via /proc/<pid>/cmdline.
func readPassword() ([]byte, error) {
	if pwd := os.Getenv("QAU_KEYSTORE_PASSWORD"); pwd != "" {
		return []byte(pwd), nil
	}
	fmt.Print("Enter encryption password: ")
	var pwd string
	if _, err := fmt.Scanln(&pwd); err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	if len(pwd) < 8 {
		return nil, fmt.Errorf("password must be at least 8 characters")
	}
	return []byte(pwd), nil
}

func main() {
	count := 3
	outputDir := "keys_output"

	if err := os.MkdirAll(outputDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output dir: %v\n", err)
		os.Exit(1)
	}

	password, err := readPassword()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Password error: %v\n", err)
		os.Exit(1)
	}
	// Zero the password after use
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()

	validators := make([]GenesisValidator, count)

	fmt.Println("=====================================================")
	fmt.Println("  SECURITY WARNING: Raw private keys (dilithium3:hex)")
	fmt.Println("  are printed to STDOUT for deployment. Redirect to a")
	fmt.Println("  secure file if needed, then DELETE after deployment.")
	fmt.Println("  Encrypted keystores are saved to .keystore files.")
	fmt.Println("=====================================================")

	for i := 0; i < count; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate key pair %d: %v\n", i, err)
			os.Exit(1)
		}

		addr := kp.Public.Address()
		addrHex := fmt.Sprintf("0x%x", addr[:])
		pubKeyHex := hex.EncodeToString(kp.Public.Bytes())

		validators[i] = GenesisValidator{
			Address:     addrHex,
			Stake:       "30000000000000000000000",
			Commission:  100,
			PublicKey:   pubKeyHex,
			Description: fmt.Sprintf("Validator %d", i+1),
		}

		// SECURITY FIX (audit 2026-06-26, P0-03): Encrypt private key with
		// AES-256-GCM + scrypt(N=2^18) before writing to disk. Never write
		// raw private key bytes to disk.
		keyFileObj, err := crypto.EncryptKeyBytes(kp.Private, password)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to encrypt key %d: %v\n", i+1, err)
			os.Exit(1)
		}

		keystoreJSON, err := keyFileObj.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to serialize keystore %d: %v\n", i+1, err)
			os.Exit(1)
		}

		keystoreFile := filepath.Join(outputDir, fmt.Sprintf("validator_%d.keystore", i+1))
		if err := os.WriteFile(keystoreFile, keystoreJSON, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write keystore %s: %v\n", keystoreFile, err)
			os.Exit(1)
		}

		// SECURITY (audit P2-R2-03): Removed raw private key STDOUT output.
		// Private keys should only exist in encrypted keystore files.
		fmt.Printf("[Validator %d] Address: %s\n", i+1, addrHex)
		fmt.Printf("[Validator %d] Encrypted keystore: %s\n", i+1, keystoreFile)
		fmt.Println()
	}

	genesisValidatorsJSON, _ := json.MarshalIndent(validators, "  ", "  ")
	// G306 fix: genesis validator manifest contains addresses + keystore paths; owner-only.
	os.WriteFile(filepath.Join(outputDir, "genesis_validators.json"), genesisValidatorsJSON, 0600)

	summary := ""
	for i, v := range validators {
		summary += fmt.Sprintf("Validator %d: address=%s\n", i+1, v.Address)
	}
	//nolint:gosec // G306: summary.txt only lists public addresses; non-sensitive.
	os.WriteFile(filepath.Join(outputDir, "summary.txt"), []byte(summary), 0644)

	fmt.Println("=====================================================")
	fmt.Println("  Genesis validators generated successfully!")
	fmt.Println("  Encrypted keystores saved to: keys_output/validator_*.keystore")
	fmt.Println("  Genesis config: keys_output/genesis_validators.json")
	fmt.Println("  IMPORTANT: Save the password used for encryption!")
	fmt.Println("=====================================================")
}
