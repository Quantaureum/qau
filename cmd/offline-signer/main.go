// Quantaureum Node source, version 1.0.0.
// Offline transaction signer for Quantaureum blockchain.
// Uses protobuf encoding and Dilithium3 post-quantum signatures.
package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	ethTypes "github.com/quantaureum/qau/types"
)

func main() {
	// SECURITY: Prefer env var to avoid leaking private key via process listing (ps aux).
	keyHex := os.Getenv("QAU_PRIVATE_KEY_HEX")
	if keyHex == "" {
		fmt.Fprintf(os.Stderr, "ERROR: QAU_PRIVATE_KEY_HEX is not set\n")
		fmt.Fprintf(os.Stderr, "Usage: QAU_PRIVATE_KEY_HEX=<key> offline-signer\n")
		fmt.Fprintf(os.Stderr, "  The private key must not be passed as a command-line argument because process listings expose argv.\n")
		os.Exit(1)
	}
	keyHex = strings.TrimPrefix(keyHex, "dilithium3:")
	if idx := strings.Index(keyHex, ":"); idx >= 0 {
		keyHex = keyHex[:idx]
	}

	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode private key hex: %v\n", err)
		os.Exit(1)
	}
	if len(keyBytes) != mode3.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "Invalid private key size: expected %d bytes, got %d\n", mode3.PrivateKeySize, len(keyBytes))
		os.Exit(1)
	}

	// Security fix (Round 4): keyBytes holds raw private-key bytes and must be zeroized after use,
	// preventing heap-resident keys from being stolen via memory-dump attacks.
	defer func() {
		for i := range keyBytes {
			keyBytes[i] = 0
		}
	}()

	var privKey mode3.PrivateKey
	privKey.Unpack((*[mode3.PrivateKeySize]byte)(keyBytes))

	// Get public key and derive address using SHA3-256 (NIST standard)
	pubKey := privKey.Public().(*mode3.PublicKey)
	pubKeyBytes := pubKey.Bytes()

	// Use crypto.PublicKeyAddressFromBytes which uses sha3.Sum256
	fromAddr := crypto.PublicKeyAddressFromBytes(pubKeyBytes)

	fmt.Printf("Sender:    0x%x\n", fromAddr[:])

	// Transaction parameters
	// SECURITY (audit P3-R2-15): Support env vars for transaction parameters
	nonce := getEnvUint64("QAU_TX_NONCE", 3)
	gasLimit := getEnvUint64("QAU_TX_GAS_LIMIT", 21000)
	gasPrice := getEnvBigInt("QAU_TX_GAS_PRICE", big.NewInt(1_000_000_000))
	chainID := getEnvUint64("QAU_CHAIN_ID", 1668)

	// AUDIT (2026) KEYS-06: Value is now configurable via env var.
	// Previously hardcoded to 1000 QAU, which combined with the recipient
	// bug below would sign an irreversible 1000 QAU burn to 0x0 on default run.
	value := getEnvBigInt("QAU_TX_VALUE", big.NewInt(0)) // default 0 — safe

	// SECURITY (audit P3-R2-15): Use env var for recipient address
	toAddrHex := os.Getenv("QAU_TX_TO")
	// AUDIT (2026) KEYS-06: Fix comparison bug. The previous code
	// compared to " " (single space) instead of "" (empty string), so the
	// default was NEVER used when QAU_TX_TO was unset. os.Getenv returns ""
	// for unset vars, leaving toAddrHex empty → hex.DecodeString("") returns
	// empty bytes → toAddr stays zero address → 1000 QAU burned to 0x0.
	if toAddrHex == "" {
		fmt.Fprintln(os.Stderr, "ERROR: QAU_TX_TO environment variable is not set")
		fmt.Fprintln(os.Stderr, "Refusing to sign a transaction without an explicit recipient (would burn funds to 0x0).")
		os.Exit(1)
	}
	// Strip optional 0x prefix
	toAddrHex = strings.TrimPrefix(toAddrHex, "0x")
	toAddrHex = strings.TrimPrefix(toAddrHex, "0X")
	toHexBytes, err := hex.DecodeString(toAddrHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: QAU_TX_TO is not valid hex: %v\n", err)
		os.Exit(1)
	}
	if len(toHexBytes) != 20 {
		fmt.Fprintf(os.Stderr, "ERROR: QAU_TX_TO must be 20 bytes (40 hex chars), got %d bytes\n", len(toHexBytes))
		os.Exit(1)
	}
	var toAddr ethTypes.Address
	copy(toAddr[:], toHexBytes)

	fmt.Printf("Nonce:     %d\n", nonce)
	fmt.Printf("GasPrice:  %s wei (%d Gwei)\n", gasPrice.String(), gasPrice.Int64()/1_000_000_000)
	fmt.Printf("GasLimit:  %d\n", gasLimit)
	fmt.Printf("To:        0x%x\n", toAddr[:])
	fmt.Printf("Value:     %s wei\n", value.String())
	fmt.Printf("ChainID:   %d\n", chainID)

	// Build unsigned transaction
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		Nonce:    nonce,
		From:     fromAddr,
		To:       &toAddr,
		Value:    value,
		GasLimit: gasLimit,
		GasPrice: gasPrice,
		ChainID:  chainID,
	}

	// Compute signing hash
	signingHash, err := tx.SigningHash()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to compute signing hash: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("SignHash:  0x%x\n", signingHash[:])

	// Sign with Dilithium3
	signature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(&privKey, signingHash[:], signature)

	// Verify immediately
	if !mode3.Verify(pubKey, signingHash[:], signature) {
		fmt.Fprintf(os.Stderr, "ERROR: Self-verification failed!\n")
		os.Exit(1)
	}
	fmt.Println("Self-verification: PASSED")

	// Set signature and public key
	tx.PublicKey = pubKeyBytes
	tx.Signature = signature

	// Marshal to protobuf
	rawBytes, err := encoding.MarshalTransaction(tx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal transaction: %v\n", err)
		os.Exit(1)
	}

	rawHex := fmt.Sprintf("0x%x", rawBytes)
	fmt.Printf("\nSigned protobuf transaction (%d bytes):\n%s\n", len(rawBytes), rawHex)
}

// getEnvUint64 reads a uint64 from env var, returns default if not set.
func getEnvUint64(key string, defaultVal uint64) uint64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			return n
		}
	}
	return defaultVal
}

// getEnvBigInt reads a big.Int from env var, returns default if not set.
func getEnvBigInt(key string, defaultVal *big.Int) *big.Int {
	if v := os.Getenv(key); v != "" {
		if n, ok := new(big.Int).SetString(v, 10); ok {
			return n
		}
	}
	return defaultVal
}
