// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/sha3"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <key_file>\n", os.Args[0])
		os.Exit(1)
	}

	keyFile := os.Args[1]
	data, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	content := strings.TrimSpace(string(data))
	var privKeyHex string

	if strings.HasPrefix(content, "dilithium3:") {
		parts := strings.SplitN(content, ":", 3)
		privKeyHex = parts[1]
	} else {
		lines := strings.Split(content, "\n")
		var hexParts []string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "0x") && len(line) == 42 {
				continue
			}
			if len(line) <= 4 && strings.Contains(line, ".") {
				continue
			}
			cleaned := strings.ToLower(line)
			if len(cleaned) > 100 {
				allHex := true
				for _, c := range cleaned {
					if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
						allHex = false
						break
					}
				}
				if allHex {
					hexParts = append(hexParts, cleaned)
				}
			}
		}
		privKeyHex = strings.Join(hexParts, "")
	}

	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error decoding hex: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Private key length: %d bytes\n", len(privKeyBytes))

	// Method 1: Use project's crypto package
	privKey, err := crypto.PrivateKeyFromBytes(privKeyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading private key via crypto package: %v\n", err)
		// Try circl directly
		fmt.Println("Trying circl directly...")
		key := new(mode3.PrivateKey)
		key.Unpack((*[4000]byte)(privKeyBytes))
		pubKey := key.Public().(*mode3.PublicKey)
		pubKeyBytes := pubKey.Bytes()
		hash := sha3.Sum256(pubKeyBytes)
		addr := hash[12:]
		fmt.Printf("Address (circl direct): 0x%x\n", addr)
		return
	}

	pubKey := privKey.PublicKey()
	pubKeyBytes := pubKey.Bytes()
	fmt.Printf("Public key length: %d bytes\n", len(pubKeyBytes))
	fmt.Printf("Public key prefix: %x...\n", pubKeyBytes[:20])
	fmt.Printf("Public key full: %x\n", pubKeyBytes)

	addr := types.AddressFromPublicKey(pubKeyBytes)
	fmt.Printf("Address (QAU format): %s\n", addr.String())

	// Also compute raw hex address for comparison
	hash := sha3.Sum256(pubKeyBytes)
	fmt.Printf("Address (0x format): 0x%x\n", hash[12:])

	// Verify against genesis public key if provided
	if len(os.Args) >= 3 {
		genesisPubKeyHex := os.Args[2]
		genesisPubKey, _ := hex.DecodeString(genesisPubKeyHex)
		if hex.EncodeToString(pubKeyBytes) == hex.EncodeToString(genesisPubKey) {
			fmt.Println("Public key MATCHES genesis!")
		} else {
			fmt.Printf("Public key DOES NOT match genesis\n")
			fmt.Printf("  File pubkey:  %x...\n", pubKeyBytes[:20])
			fmt.Printf("  Genesis pubkey: %x...\n", genesisPubKey[:20])
		}
	}
}
