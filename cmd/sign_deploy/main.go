// Quantaureum Node source, version 1.0.0.
// sign_deploy signs a contract deployment transaction using a raw dilithium3 key.
// Usage: sign_deploy <keyfile> <from_addr> <amount_wei> <nonce> <chain_id> <bytecode_hex_file>
// Outputs: hex-encoded signed transaction (protobuf) to stdout, tx hash to stderr
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
	if len(os.Args) < 7 {
		fmt.Fprintf(os.Stderr, "Usage: sign_deploy <keyfile> <from_addr> <amount_wei> <nonce> <chain_id> <bytecode_hex_file>\n")
		os.Exit(1)
	}

	keyFile := os.Args[1]
	fromStr := strings.ToLower(os.Args[2])
	amountStr := os.Args[3]
	nonceStr := os.Args[4]
	chainIDStr := os.Args[5]
	bytecodeFile := os.Args[6]

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

	// Keep only hex chars
	var cleanHex strings.Builder
	for _, c := range keyStr {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			cleanHex.WriteRune(c)
		}
	}
	keyHex := cleanHex.String()

	// Extract private key (first 8000 hex chars = 4000 bytes)
	const privKeyHexLen = crypto.Dilithium3PrivateKeySize * 2 // 8000
	if len(keyHex) < privKeyHexLen {
		fmt.Fprintf(os.Stderr, "Key too short: got %d, need %d hex chars\n", len(keyHex), privKeyHexLen)
		os.Exit(1)
	}
	privKeyHex := keyHex[:privKeyHexLen]

	// Decode private key
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode private key: %v\n", err)
		os.Exit(1)
	}

	// Load Dilithium3 private key
	privateKey, err := crypto.PrivateKeyFromBytes(privKeyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load Dilithium3 key: %v\n", err)
		os.Exit(1)
	}
	defer privateKey.Destroy()

	// Get public key bytes
	pubKeyBytes := privateKey.PublicKeyBytes()
	if pubKeyBytes == nil {
		fmt.Fprintf(os.Stderr, "Failed to derive public key\n")
		os.Exit(1)
	}

	// Parse from address
	from, err := types.ParseHexAddress(fromStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid from address: %v\n", err)
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
	fmt.Sscanf(nonceStr, "%d", &nonce)

	// Parse chain ID
	var chainID uint64
	fmt.Sscanf(chainIDStr, "%d", &chainID)

	// Read bytecode (hex, may include constructor args appended)
	bytecodeHex, err := os.ReadFile(bytecodeFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read bytecode file: %v\n", err)
		os.Exit(1)
	}
	bytecodeStr := strings.TrimSpace(string(bytecodeHex))
	bytecodeStr = strings.TrimPrefix(bytecodeStr, "0x")

	// Decode bytecode
	bytecodeData, err := hex.DecodeString(bytecodeStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode bytecode: %v\n", err)
		os.Exit(1)
	}

	// Build contract creation transaction
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeCreate,
		Nonce:    nonce,
		From:     from,
		To:       nil, // Contract creation
		Value:    amount,
		GasLimit: 500000,
		GasPrice: big.NewInt(1),
		Data:     bytecodeData,
		ChainID:  chainID,
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

	// Output
	txHex := hex.EncodeToString(txBytes)
	txHash := tx.Hash()

	fmt.Fprintf(os.Stderr, "Contract deployment transaction signed!\n")
	fmt.Fprintf(os.Stderr, "  From:      %s\n", from.String())
	fmt.Fprintf(os.Stderr, "  To:        nil (contract creation)\n")
	fmt.Fprintf(os.Stderr, "  Value:     %s wei\n", amount.String())
	fmt.Fprintf(os.Stderr, "  Nonce:     %d\n", nonce)
	fmt.Fprintf(os.Stderr, "  Chain ID:  %d\n", chainID)
	fmt.Fprintf(os.Stderr, "  Data len:  %d bytes\n", len(bytecodeData))
	fmt.Fprintf(os.Stderr, "  Tx Hash:   %s\n", txHash.String())

	// Print hex to stdout
	fmt.Println(txHex)
}
