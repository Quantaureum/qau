// Quantaureum Node source, version 1.0.0.
// sign_stake signs a staking/unstaking message using a validator keystore key.
// Usage: sign_stake <key_file> <password_file> <address> <amount_wei> [method]
// method defaults to "stake"; use "unstake" for qau_unstake signatures.
// Outputs JSON: {"nonce":"...","signature":"...","pubkey":"...","address":"...","amount":"...","method":"..."}
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/quantaureum/qau/crypto"
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "Usage: sign_stake <key_file> <password_file> <address> <amount_wei> [method]\n")
		os.Exit(1)
	}

	keyFile := os.Args[1]
	pwdFile := os.Args[2]
	address := strings.ToLower(os.Args[3])
	amountStr := os.Args[4]
	method := "stake"
	if len(os.Args) >= 6 {
		method = os.Args[5]
		if method != "stake" && method != "unstake" {
			fmt.Fprintf(os.Stderr, "invalid method: %s (must be stake or unstake)\n", method)
			os.Exit(1)
		}
	}

	// Read password
	pwdBytes, err := os.ReadFile(pwdFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read password file: %v\n", err)
		os.Exit(1)
	}
	password := strings.TrimSpace(string(pwdBytes))

	// Read keystore JSON
	ksBytes, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read key file: %v\n", err)
		os.Exit(1)
	}

	// Parse KeyFile
	var kf crypto.KeyFile
	if err := json.Unmarshal(ksBytes, &kf); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse key file: %v\n", err)
		os.Exit(1)
	}

	// Decrypt keystore
	privateKey, err := crypto.DecryptKey(&kf, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt key: %v\n", err)
		os.Exit(1)
	}
	defer privateKey.Destroy()

	// Generate random nonce (32 bytes hex)
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate nonce: %v\n", err)
		os.Exit(1)
	}
	nonce := hex.EncodeToString(nonceBytes)

	// Construct message: <method>|<address>|<nonce>|<amountStr>
	message := []byte(method + "|" + address + "|" + nonce + "|" + amountStr)

	// Sign
	signature, err := crypto.Sign(privateKey, message)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to sign: %v\n", err)
		os.Exit(1)
	}

	// Get public key bytes
	pubKeyBytes := privateKey.PublicKeyBytes()

	// Output JSON
	result := map[string]string{
		"nonce":     nonce,
		"signature": hex.EncodeToString(signature),
		"pubkey":    hex.EncodeToString(pubKeyBytes),
		"address":   address,
		"amount":    amountStr,
		"method":    method,
	}
	json.NewEncoder(os.Stdout).Encode(result)
}
