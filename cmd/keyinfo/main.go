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

type ValidatorInfo struct {
	Address   string `json:"address"`
	PublicKey string `json:"publicKey"`
	Stake     string `json:"stake"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: keyinfo <private_key_hex_file1> [file2] [file3]\n")
		os.Exit(1)
	}

	validators := make([]ValidatorInfo, 0, len(os.Args)-1)

	for _, file := range os.Args[1:] {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read %s: %v\n", file, err)
			os.Exit(1)
		}

		hexStr := strings.TrimSpace(string(data))
		if strings.HasPrefix(hexStr, "dilithium3:") {
			hexStr = hexStr[len("dilithium3:"):]
		}
		hexStr = strings.TrimSpace(hexStr)

		// Format: <private_key_hex_8000chars>:<public_key_hex_3904chars>
		parts := strings.SplitN(hexStr, ":", 2)
		privKeyHex := parts[0]
		privKeyHex = strings.TrimSpace(privKeyHex)

		keyBytes := make([]byte, crypto.Dilithium3PrivateKeySize)
		n, err := hex.Decode(keyBytes, []byte(privKeyHex))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to decode hex from %s: %v\n", file, err)
			os.Exit(1)
		}
		if n != crypto.Dilithium3PrivateKeySize {
			fmt.Fprintf(os.Stderr, "Invalid key size in %s: got %d bytes, expected %d\n", file, n, crypto.Dilithium3PrivateKeySize)
			os.Exit(1)
		}

		privKey, err := crypto.PrivateKeyFromBytes(keyBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load key from %s: %v\n", file, err)
			os.Exit(1)
		}

		pubKey := privKey.PublicKey()
		addr := pubKey.Address()
		pubKeyHex := hex.EncodeToString(pubKey.Bytes())

		vi := ValidatorInfo{
			Address:   fmt.Sprintf("0x%x", addr[:]),
			PublicKey: pubKeyHex,
			Stake:     "30000000000000000000000",
		}
		validators = append(validators, vi)
		fmt.Fprintf(os.Stderr, "Loaded: %s -> address=%s\n", file, vi.Address)
	}

	output, _ := json.MarshalIndent(validators, "", "  ")
	fmt.Println(string(output))
}
