// Quantaureum Node source, version 1.0.0.
// sign_call signs a contract call transaction using a raw dilithium3 key.
// Usage: sign_call <keyfile> <from_addr> <to_addr> <amount_wei> <nonce> <chain_id> <calldata_hex>
// Outputs: hex-encoded signed transaction to stdout, info to stderr
package main

import (
	"encoding/hex"
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
		fmt.Fprintf(os.Stderr, "Usage: sign_call <keyfile> <from_addr> <to_addr> <amount_wei> <nonce> <chain_id> <calldata_hex>\n")
		os.Exit(1)
	}

	keyFile := os.Args[1]
	fromStr := strings.ToLower(os.Args[2])
	toStr := os.Args[3]
	amountStr := os.Args[4]
	nonceStr := os.Args[5]
	chainIDStr := os.Args[6]
	calldataHex := os.Args[7]

	// Read key file
	keyContent, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read key file: %v\n", err)
		os.Exit(1)
	}

	// Extract dilithium3:hex key
	keyStr := string(keyContent)
	idx := strings.Index(keyStr, "dilithium3:")
	if idx == -1 {
		fmt.Fprintf(os.Stderr, "Error: no dilithium3: found in key file\n")
		os.Exit(1)
	}
	keyStr = keyStr[idx+len("dilithium3:"):]

	var cleanHex strings.Builder
	for _, c := range keyStr {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			cleanHex.WriteRune(c)
		}
	}
	keyHex := cleanHex.String()

	const privKeyHexLen = crypto.Dilithium3PrivateKeySize * 2
	if len(keyHex) < privKeyHexLen {
		fmt.Fprintf(os.Stderr, "Key too short: got %d, need %d hex chars\n", len(keyHex), privKeyHexLen)
		os.Exit(1)
	}
	privKeyHex := keyHex[:privKeyHexLen]

	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode private key: %v\n", err)
		os.Exit(1)
	}

	privateKey, err := crypto.PrivateKeyFromBytes(privKeyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load Dilithium3 key: %v\n", err)
		os.Exit(1)
	}
	defer privateKey.Destroy()

	pubKeyBytes := privateKey.PublicKeyBytes()
	if pubKeyBytes == nil {
		fmt.Fprintf(os.Stderr, "Failed to derive public key\n")
		os.Exit(1)
	}

	from, err := types.ParseHexAddress(fromStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid from address: %v\n", err)
		os.Exit(1)
	}

	to, err := types.ParseHexAddress(toStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid to address: %v\n", err)
		os.Exit(1)
	}

	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		fmt.Fprintf(os.Stderr, "Invalid amount: %s\n", amountStr)
		os.Exit(1)
	}

	var nonce uint64
	fmt.Sscanf(nonceStr, "%d", &nonce)

	var chainID uint64
	fmt.Sscanf(chainIDStr, "%d", &chainID)

	// Decode calldata
	calldataHex = strings.TrimPrefix(calldataHex, "0x")
	calldata, err := hex.DecodeString(calldataHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode calldata: %v\n", err)
		os.Exit(1)
	}

	// Build transaction
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeContract,
		Nonce:    nonce,
		From:     from,
		To:       &to,
		Value:    amount,
		GasLimit: 500000,
		GasPrice: big.NewInt(1),
		Data:     calldata,
		ChainID:  chainID,
	}

	// Sign
	signingHash, err := tx.SigningHash()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to compute signing hash: %v\n", err)
		os.Exit(1)
	}

	signature, err := crypto.Sign(privateKey, signingHash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to sign: %v\n", err)
		os.Exit(1)
	}

	tx.Signature = signature
	tx.PublicKey = pubKeyBytes

	txBytes, err := encoding.MarshalTransaction(tx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal transaction: %v\n", err)
		os.Exit(1)
	}

	txHex := hex.EncodeToString(txBytes)
	txHash := tx.Hash()

	fmt.Fprintf(os.Stderr, "Contract call transaction signed!\n")
	fmt.Fprintf(os.Stderr, "  From:      %s\n", from.String())
	fmt.Fprintf(os.Stderr, "  To:        %s\n", to.String())
	fmt.Fprintf(os.Stderr, "  Value:     %s wei\n", amount.String())
	fmt.Fprintf(os.Stderr, "  Nonce:     %d\n", nonce)
	fmt.Fprintf(os.Stderr, "  Chain ID:  %d\n", chainID)
	fmt.Fprintf(os.Stderr, "  Data:      0x%s\n", calldataHex)
	fmt.Fprintf(os.Stderr, "  Tx Hash:   %s\n", txHash.String())

	fmt.Println(txHex)
}
