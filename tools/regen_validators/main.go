// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

type Genesis struct {
	ChainID    uint64                `json:"chainId"`
	NetworkID  uint64                `json:"networkId"`
	Timestamp  uint64                `json:"timestamp"`
	GasLimit   uint64                `json:"gasLimit"`
	ExtraData  string                `json:"extraData"`
	Alloc      map[string]AllocEntry `json:"alloc"`
	Validators []ValidatorEntry      `json:"validators"`
}

type AllocEntry struct {
	Balance string `json:"balance"`
	Nonce   int    `json:"nonce"`
}

type ValidatorEntry struct {
	Address   string `json:"address"`
	Stake     string `json:"stake"`
	PublicKey string `json:"publicKey"`
}

// readPassword reads the encryption password from the QAU_KEYSTORE_PASSWORD
// environment variable, or prompts the user via stdin if not set.
//
// SECURITY (audit 2026-06-26, P0-04): Password is never passed as a
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
	pwd, _ := os.Getwd()
	fmt.Println("Working directory:", pwd)

	genesisFile := "the Quantaureum repo"
	outputDir := "the Quantaureum repo"

	if _, err := os.Stat(genesisFile); os.IsNotExist(err) {
		genesisFile = "../../testnet/genesis.json"
		outputDir = "../../testnet/keys"
	}

	if err := os.MkdirAll(outputDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output dir: %v\n", err)
		os.Exit(1)
	}

	password, err := readPassword()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Password error: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		for i := range password {
			password[i] = 0
		}
	}()

	genesisData, err := os.ReadFile(genesisFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read genesis.json: %v\n", err)
		os.Exit(1)
	}

	var genesis Genesis
	if err := json.Unmarshal(genesisData, &genesis); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse genesis.json: %v\n", err)
		os.Exit(1)
	}

	genesis.Timestamp = uint64(time.Now().Unix())

	newAlloc := make(map[string]AllocEntry)
	newValidators := make([]ValidatorEntry, 0, 3)

	fmt.Println("=====================================================")
	fmt.Println("  SECURITY WARNING: Raw private keys (dilithium3:hex)")
	fmt.Println("  are printed to STDOUT for deployment. Redirect to a")
	fmt.Println("  secure file if needed, then DELETE after deployment.")
	fmt.Println("  Encrypted keystores are saved to .keystore files.")
	fmt.Println("=====================================================")

	for i := 1; i <= 3; i++ {
		fmt.Printf("Generating validator %d key pair (Dilithium3)...\n", i)

		keyPair, err := crypto.GenerateKeyPair()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate key pair: %v\n", err)
			os.Exit(1)
		}

		pubKeyBytes := keyPair.Public.Bytes()
		if len(pubKeyBytes) != types.QuantumPublicKeySize {
			fmt.Fprintf(os.Stderr, "ERROR: pubKey size=%d, expected=%d\n", len(pubKeyBytes), types.QuantumPublicKeySize)
			os.Exit(1)
		}

		pubKeyHex := hex.EncodeToString(pubKeyBytes)
		addr := types.AddressFromPublicKey(pubKeyBytes)

		// SECURITY FIX (audit 2026-06-26, P0-04): Encrypt private key with
		// AES-256-GCM + scrypt(N=2^18) before writing to disk. Never write
		// raw or hex-encoded private key bytes to disk.
		keyFileObj, err := crypto.EncryptKeyBytes(keyPair.Private, password)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to encrypt key %d: %v\n", i, err)
			os.Exit(1)
		}

		keystoreJSON, err := keyFileObj.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to serialize keystore %d: %v\n", i, err)
			os.Exit(1)
		}

		keystoreFile := filepath.Join(outputDir, fmt.Sprintf("validator%d.keystore", i))
		if err := os.WriteFile(keystoreFile, keystoreJSON, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write keystore: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  Encrypted keystore saved: %s\n", keystoreFile)

		// Public key file (safe to store in plaintext)
		pubKeyFile := filepath.Join(outputDir, fmt.Sprintf("validator%d.pub", i))
		if err := os.WriteFile(pubKeyFile, []byte(pubKeyHex), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write public key: %v\n", err)
			os.Exit(1)
		}

		addrStr := fmt.Sprintf("0x%x", addr[:])
		fmt.Printf("  Address: %s\n", addrStr)
		fmt.Printf("  Public key first 16: %s\n", pubKeyHex[:16])

		// Print the dilithium3:hex format to STDOUT for deployment (not to disk)
		rawKey := "dilithium3:" + hex.EncodeToString(keyPair.Private.Bytes()) + hex.EncodeToString(keyPair.Public.Bytes())
		fmt.Printf("  Raw key (for deployment, handle with care):\n%s\n", rawKey)
		fmt.Println()

		newValidators = append(newValidators, ValidatorEntry{
			Address:   addrStr,
			Stake:     "30000000000000000000000",
			PublicKey: pubKeyHex,
		})

		newAlloc[addrStr] = AllocEntry{
			Balance: "32000000000000000000000",
			Nonce:   0,
		}
	}

	for addr, entry := range genesis.Alloc {
		isValidator := false
		for _, v := range genesis.Validators {
			if v.Address == addr {
				isValidator = true
				break
			}
		}
		if !isValidator {
			newAlloc[addr] = entry
		}
	}

	genesis.Validators = newValidators
	genesis.Alloc = newAlloc

	newGenesisData, err := json.MarshalIndent(genesis, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal genesis: %v\n", err)
		os.Exit(1)
	}

	// G306 fix: genesis.json carries pre-allocation data; owner-only to match qauctl genesis generate.
	if err := os.WriteFile(genesisFile, newGenesisData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write genesis.json: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=====================================================")
	fmt.Println("  Genesis updated successfully!")
	fmt.Printf("  New timestamp: %d\n", genesis.Timestamp)
	fmt.Println("  Validator keystores saved to: testnet/keys/")
	fmt.Println()
	fmt.Println("  Deploy instructions:")
	fmt.Println("  1. Use the raw keys from STDOUT above to create validator.key on each server")
	fmt.Println("  2. Copy testnet/keys/validator1.pub to the first validator host (for reference)")
	fmt.Println("  3. Copy updated genesis.json to all servers: /etc/quantaureum/genesis.json")
	fmt.Println("  4. Delete /var/lib/quantaureum/tss_group_key.bin on all servers")
	fmt.Println("  5. Restart all nodes")
	fmt.Println("  IMPORTANT: Save the encryption password for the .keystore files!")
	fmt.Println("=====================================================")
}
