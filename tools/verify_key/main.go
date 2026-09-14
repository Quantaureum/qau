// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/quantaureum/qau/crypto"
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

	priv, err := crypto.PrivateKeyFromBytes(skBytes)
	if err != nil {
		fmt.Printf("Error creating private key: %v\n", err)
		return
	}

	pub := priv.PublicKey()
	if pub == nil {
		fmt.Println("Public key is nil!")
		return
	}

	pubBytes := pub.Bytes()
	fmt.Printf("PK bytes length: %d\n", len(pubBytes))
	fmt.Printf("PK hex (first 64): %s\n", hex.EncodeToString(pubBytes[:32]))

	addr := pub.Address()
	fmt.Printf("Derived address: 0x%s\n", hex.EncodeToString(addr[:]))
	fmt.Printf("Address first 8 bytes: %x\n", addr[:8])
}
