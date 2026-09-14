// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
	"golang.org/x/crypto/sha3"
)

func main() {
	// Read the user's private key file
	keyData, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	content := string(keyData)
	// Strip dilithium3: prefix if present
	hexStr := content
	if len(content) > 11 && content[:11] == "dilithium3:" {
		hexStr = content[11:]
	}
	// Trim whitespace
	hexStr = hexStr[:8000]

	skBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		fmt.Printf("Error decoding hex: %v\n", err)
		return
	}

	fmt.Printf("SK bytes length: %d\n", len(skBytes))

	// Method 1: Direct PrivateKey.PublicKey() derivation via our crypto package
	priv1, err := crypto.PrivateKeyFromBytes(skBytes)
	if err != nil {
		fmt.Printf("Error creating private key: %v\n", err)
		return
	}
	pub1 := priv1.PublicKey()
	pub1Bytes := pub1.Bytes()
	addr1Hash := sha3.Sum256(pub1Bytes)
	fmt.Printf("\nMethod 1 (Direct PK derivation):\n")
	fmt.Printf("  PK first 32: %s\n", hex.EncodeToString(pub1Bytes[:32]))
	fmt.Printf("  Address: 0x%s\n", hex.EncodeToString(addr1Hash[12:]))

	// Method 2: Wallet extension method - keccak256(SK) as seed, then NewKeyFromSeed
	seedHash := sha3.Sum256(skBytes)
	var seed [32]byte
	copy(seed[:], seedHash[:32])

	pub2, priv2 := mode3.NewKeyFromSeed(&seed)
	_ = priv2
	pub2Bytes := pub2.Bytes()
	addr2Hash := sha3.Sum256(pub2Bytes)
	fmt.Printf("\nMethod 2 (keccak256(SK) -> seed -> NewKeyFromSeed):\n")
	fmt.Printf("  PK first 32: %s\n", hex.EncodeToString(pub2Bytes[:32]))
	fmt.Printf("  Address: 0x%s\n", hex.EncodeToString(addr2Hash[12:]))

	// Method 3: Maybe the file contains the WASM-generated SK which includes PK
	// Dilithium3 SK in circl is 4000 bytes, but maybe the WASM stores it differently
	// Let's check if the SK contains the PK at a specific offset
	fmt.Printf("\nMethod 3 (Check SK internal structure):\n")
	fmt.Printf("  SK length: %d bytes\n", len(skBytes))
}
