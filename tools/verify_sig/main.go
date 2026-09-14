// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/quantaureum/qau/crypto"
)

func main() {
	keyData, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	content := string(keyData)
	var skHex, pkHex string
	for _, line := range splitLines(content) {
		line = trimSpace(line)
		if hasPrefix(line, "dilithium3:") {
			parts := splitN(line, ":", 3)
			if len(parts) == 3 {
				skHex = parts[1]
				pkHex = parts[2]
			}
			break
		}
	}

	skBytes, _ := hex.DecodeString(skHex)
	pkBytes, _ := hex.DecodeString(pkHex)

	priv, err := crypto.PrivateKeyFromBytes(skBytes)
	if err != nil {
		fmt.Printf("PrivateKeyFromBytes error: %v\n", err)
		return
	}

	// Derived public key from private key
	derivedPub := priv.PublicKey()
	derivedPubBytes := derivedPub.Bytes()

	// Address from file's public key
	addrFromFile := crypto.PublicKeyAddressFromBytes(pkBytes)
	// Address from derived public key
	addrFromDerived := crypto.PublicKeyAddressFromBytes(derivedPubBytes)

	fmt.Printf("File PK address:    0x%s\n", hex.EncodeToString(addrFromFile[:]))
	fmt.Printf("Derived PK address: 0x%s\n", hex.EncodeToString(addrFromDerived[:]))
	fmt.Printf("PK match: %v\n", hex.EncodeToString(pkBytes) == hex.EncodeToString(derivedPubBytes))

	// Test signing with private key, verify with BOTH public keys
	testMsg := []byte("test message for verification")
	sig, err := priv.Sign(testMsg)
	if err != nil {
		fmt.Printf("Sign error: %v\n", err)
		return
	}

	// Verify with derived PK
	filePubKey, _ := crypto.PublicKeyFromBytes(pkBytes)
	derivedVerify := crypto.Verify(derivedPub, testMsg, sig)
	fileVerify := crypto.Verify(filePubKey, testMsg, sig)

	fmt.Printf("Verify with derived PK: %v\n", derivedVerify)
	fmt.Printf("Verify with file PK:    %v\n", fileVerify)
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func splitN(s, sep string, n int) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s) && len(parts) < n-1; i++ {
		if s[i] == sep[0] {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}
