// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// Stake signs a staking message for qau_stake RPC.
//
// Usage:
//   stakevalidator <keyfile> <amount> <chainID> [commission]
//
// keyfile format: dilithium3:privhex:pubhex
// Output: JSON with address, nonce, signature, publicKey for qau_stake RPC
//
// AUDIT (2026) KEYS-08: The signed message now includes ChainID and
// commission to prevent cross-chain replay and commission tampering.
// The signed message is: "stake|chainID|0xADDRESS|nonce|amount|commission"

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "Usage: stakevalidator <keyfile> <amount> <chainID> [commission]")
		os.Exit(1)
	}

	keyFile := os.Args[1]
	amountStr := os.Args[2]
	chainIDStr := os.Args[3]
	chainID, err := strconv.ParseUint(chainIDStr, 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid chainID: %v\n", err)
		os.Exit(1)
	}
	commission := uint32(100) // default 1%
	if len(os.Args) > 4 {
		c, err := strconv.ParseUint(os.Args[4], 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid commission: %v\n", err)
			os.Exit(1)
		}
		commission = uint32(c)
	}

	// Read key file
	data, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read key file: %v\n", err)
		os.Exit(1)
	}

	line := strings.TrimSpace(string(data))
	// Strip dilithium3: prefix
	if strings.HasPrefix(line, "dilithium3:") {
		line = strings.TrimPrefix(line, "dilithium3:")
	}

	parts := strings.Split(line, ":")
	if len(parts) < 2 {
		fmt.Fprintln(os.Stderr, "invalid key format, expected privhex:pubhex")
		os.Exit(1)
	}

	privHex := parts[0]
	pubHex := parts[1]

	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode private key: %v\n", err)
		os.Exit(1)
	}

	pubBytes, err := hex.DecodeString(pubHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode public key: %v\n", err)
		os.Exit(1)
	}

	// Parse private key
	privKey, err := crypto.PrivateKeyFromBytes(privBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse private key: %v\n", err)
		os.Exit(1)
	}

	// Derive public key and address
	pubKey := privKey.PublicKey()
	derivedPubBytes := pubKey.Bytes()
	addr := pubKey.Address()

	// Verify public key matches
	if len(derivedPubBytes) != len(pubBytes) {
		fmt.Fprintf(os.Stderr, "public key length mismatch: file=%d derived=%d\n", len(pubBytes), len(derivedPubBytes))
		os.Exit(1)
	}
	for i := range pubBytes {
		if pubBytes[i] != derivedPubBytes[i] {
			fmt.Fprintln(os.Stderr, "public key in file does not match derived public key")
			os.Exit(1)
		}
	}

	// AUDIT (2026) KEYS-08: Include chainID and commission in the signed
	// message to prevent cross-chain replay and commission tampering.
	// R38-P0-02 (2026-08-01): the message is now the canonical
	// ComputeStakeAuthorizationHash, NOT a pipe-delimited string. The
	// canonical hash binds tx.To, tx.Value (encoded), txType-typed-byte,
	// and commission deterministically so a relay cannot tamper with any
	// of them post-signature.
	nonce := strconv.FormatInt(time.Now().Unix(), 10)
	addrHex := addr.ToHexAddress()

	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		amount, ok = new(big.Int).SetString(strings.TrimPrefix(strings.TrimPrefix(amountStr, "0x"), "0X"), 16)
		if !ok {
			fmt.Fprintf(os.Stderr, "cannot parse amount %q\n", amountStr)
			os.Exit(1)
		}
	}

	var stakingContractAddress types.Address
	stakingContractAddress[18] = 0x10
	stakingContractAddress[19] = 0x01
	authHash, err := types.ComputeStakeAuthorizationHash(
		chainID, addr, stakingContractAddress, types.StakeAuthTypeStake,
		amount, commission, nonce,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compute canonical hash: %v\n", err)
		os.Exit(1)
	}

	// Sign the canonical hash with Dilithium3.
	signature, err := crypto.Sign(privKey, authHash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign: %v\n", err)
		os.Exit(1)
	}

	// Output JSON for qau_stake RPC
	// qau_stake params: [address, amount, commission, nonce, signature, publicKey]
	fmt.Printf("{\n")
	fmt.Printf("  \"address\": \"%s\",\n", addrHex)
	fmt.Printf("  \"amount\": \"%s\",\n", amountStr)
	fmt.Printf("  \"commission\": %d,\n", commission)
	fmt.Printf("  \"nonce\": \"%s\",\n", nonce)
	fmt.Printf("  \"signature\": \"%s\",\n", hex.EncodeToString(signature))
	fmt.Printf("  \"publicKey\": \"%s\",\n", hex.EncodeToString(pubBytes))
	fmt.Printf("  \"authHash\": \"%s\"\n", hex.EncodeToString(authHash[:]))
	fmt.Printf("}\n")
}
