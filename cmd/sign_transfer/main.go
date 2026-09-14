// Quantaureum Node source, version 1.0.0.
// sign_transfer signs a transfer transaction using a validator keystore key.
// Usage: sign_transfer <key_file> <password_file> <from_addr> <to_addr> <amount_wei> <nonce> <chain_id>
// Outputs: hex-encoded signed transaction (protobuf)
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

func main() {
	if len(os.Args) < 8 {
		fmt.Fprintf(os.Stderr, "Usage: sign_transfer <key_file> <password_file> <from_addr> <to_addr> <amount_wei> <nonce> <chain_id>\n")
		os.Exit(1)
	}

	keyFile := os.Args[1]
	pwdFile := os.Args[2]
	fromStr := strings.ToLower(os.Args[3])
	toStr := strings.ToLower(os.Args[4])
	amountStr := os.Args[5]
	nonceStr := os.Args[6]
	chainIDStr := os.Args[7]

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

	// Parse from address
	from, err := types.ParseHexAddress(fromStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid from address: %v\n", err)
		os.Exit(1)
	}

	// Parse to address
	to, err := types.ParseHexAddress(toStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid to address: %v\n", err)
		os.Exit(1)
	}

	// Parse amount (wei)
	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		fmt.Fprintf(os.Stderr, "Invalid amount: %s\n", amountStr)
		os.Exit(1)
	}

	// Parse nonce
	var nonce uint64
	if _, err := fmt.Sscanf(nonceStr, "%d", &nonce); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid nonce: %v\n", err)
		os.Exit(1)
	}

	// Parse chain ID
	var chainID uint64
	if _, err := fmt.Sscanf(chainIDStr, "%d", &chainID); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid chain ID: %v\n", err)
		os.Exit(1)
	}

	// Build transaction
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		Nonce:    nonce,
		From:     from,
		To:       &to,
		Value:    amount,
		GasLimit: 100000,
		GasPrice: big.NewInt(1),
		Data:     nil,
		ChainID:  chainID,
	}

	// Get public key
	pubKeyBytes := privateKey.PublicKeyBytes()
	if pubKeyBytes == nil {
		fmt.Fprintf(os.Stderr, "Failed to derive public key\n")
		os.Exit(1)
	}

	// Compute signing hash
	signingHash, err := tx.SigningHash()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to compute signing hash: %v\n", err)
		os.Exit(1)
	}

	// Sign
	signature, err := crypto.Sign(privateKey, signingHash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to sign: %v\n", err)
		os.Exit(1)
	}

	// Set signature and public key
	tx.Signature = signature
	tx.PublicKey = pubKeyBytes

	// Marshal to protobuf
	txBytes, err := encoding.MarshalTransaction(tx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal transaction: %v\n", err)
		os.Exit(1)
	}

	// Output hex
	txHex := hex.EncodeToString(txBytes)
	txHash := tx.Hash()

	fmt.Fprintf(os.Stderr, "Transaction signed successfully!\n")
	fmt.Fprintf(os.Stderr, "  From:      %s\n", from.String())
	fmt.Fprintf(os.Stderr, "  To:        %s\n", to.String())
	fmt.Fprintf(os.Stderr, "  Value:     %s wei\n", amount.String())
	fmt.Fprintf(os.Stderr, "  Nonce:     %d\n", nonce)
	fmt.Fprintf(os.Stderr, "  Chain ID:  %d\n", chainID)
	fmt.Fprintf(os.Stderr, "  Tx Hash:   %s\n", txHash.String())
	fmt.Fprintf(os.Stderr, "\nSigned Transaction (hex):\n")
	// Print hex to stdout (for piping)
	fmt.Println(txHex)
}
