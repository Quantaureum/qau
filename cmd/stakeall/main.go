// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// StakeAll reads a validator key file, decrypts it, and signs staking messages
// using the canonical ComputeStakeAuthorizationHash domain (R38-P0-02).
//
// Usage: stakeall <keyfile> <password> <amount_qau> <chainID> [commission]
// Output: JSON with address, amount(wei), commission, nonce, signature, publicKey
//
// The amount_qau parameter accepts both integer ("6000") and decimal ("0.5")
// QAU representations. It is converted to wei internally.
//
// Key file can be either:
//  1. JSON keystore (encrypted, requires password)
//  2. Raw dilithium3:hex format (plaintext, password ignored)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "Usage: stakeall <keyfile> <password> <amount_qau> <chainID> [commission]")
		os.Exit(1)
	}

	keyFile := os.Args[1]
	password := os.Args[2]
	amountStr := os.Args[3]
	chainID, err := strconv.ParseUint(os.Args[4], 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid chainID: %v\n", err)
		os.Exit(1)
	}
	commission := uint32(100)
	if len(os.Args) > 5 {
		c, err := strconv.ParseUint(os.Args[5], 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid commission: %v\n", err)
			os.Exit(1)
		}
		commission = uint32(c)
	}

	// Read key file
	data, err := ioutil.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read key file: %v\n", err)
		os.Exit(1)
	}

	// Try JSON keystore format first, then raw dilithium3:hex format
	var privKey *crypto.PrivateKey
	keyStr := string(data)

	trimmed := strings.TrimSpace(keyStr)
	if strings.Contains(keyStr, "dilithium3:") {
		// Raw format: dilithium3:privhex+pubhex (validator.key on servers)
		privKey = parseRawKey(keyStr)
	} else if len(trimmed) > 0 && trimmed[0] == '{' {
		// JSON keystore format (encrypted)
		var keyFile2 crypto.KeyFile
		if err := json.Unmarshal(data, &keyFile2); err != nil {
			fmt.Fprintf(os.Stderr, "parse key file JSON: %v\n", err)
			os.Exit(1)
		}
		privKey, err = crypto.DecryptKey(&keyFile2, password)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decrypt key: %v\n", err)
			os.Exit(1)
		}
	} else if len(trimmed) > 0 {
		// Try as pure hex private key
		privKey = parseRawKey("dilithium3:" + trimmed)
	} else {
		fmt.Fprintln(os.Stderr, "empty key file")
		os.Exit(1)
	}

	// Derive public key and address
	pubKey := privKey.PublicKey()
	addr := pubKey.Address()
	addrHex := addr.ToHexAddress()

	// Parse amount: convert QAU to wei
	amountWei, err := parseQauAmountToWei(amountStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid amount %q: %v\n", amountStr, err)
		os.Exit(1)
	}

	// Build canonical stake authorization hash (R38-P0-02)
	// Recipient for stake: 0x000000000000000000000000000000001001
	var recipient types.Address
	recipient[18] = 0x10
	recipient[19] = 0x01

	nonce := strconv.FormatInt(time.Now().Unix(), 10)

	authHash, err := types.ComputeStakeAuthorizationHash(
		chainID, addr, recipient, types.StakeAuthTypeStake,
		amountWei, commission, nonce,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compute stake auth hash: %v\n", err)
		os.Exit(1)
	}

	// Sign the canonical hash with Dilithium3
	signature, err := crypto.Sign(privKey, authHash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign: %v\n", err)
		os.Exit(1)
	}

	// Output JSON
	pubBytes := pubKey.Bytes()
	fmt.Printf("{\n")
	fmt.Printf("  \"address\": \"%s\",\n", addrHex)
	fmt.Printf("  \"amount\": \"%s\",\n", amountWei.String())
	fmt.Printf("  \"commission\": %d,\n", commission)
	fmt.Printf("  \"nonce\": \"%s\",\n", nonce)
	fmt.Printf("  \"signature\": \"%s\",\n", hex.EncodeToString(signature))
	fmt.Printf("  \"publicKey\": \"%s\"\n", hex.EncodeToString(pubBytes))
	fmt.Printf("}\n")
}

// parseRawKey parses a dilithium3:hex key string and returns the private key.
func parseRawKey(keyStr string) *crypto.PrivateKey {
	idx := strings.Index(keyStr, "dilithium3:")
	if idx == -1 {
		fmt.Fprintln(os.Stderr, "no dilithium3: found in key file")
		os.Exit(1)
	}
	hexStr := keyStr[idx+len("dilithium3:"):]

	// Keep only hex chars
	var cleanHex strings.Builder
	for _, c := range hexStr {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			cleanHex.WriteRune(c)
		}
	}
	keyHex := cleanHex.String()

	const privKeyHexLen = crypto.Dilithium3PrivateKeySize * 2 // 8000
	if len(keyHex) < privKeyHexLen {
		fmt.Fprintf(os.Stderr, "key too short: got %d, need %d hex chars\n", len(keyHex), privKeyHexLen)
		os.Exit(1)
	}

	privBytes, err := hex.DecodeString(keyHex[:privKeyHexLen])
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode private key: %v\n", err)
		os.Exit(1)
	}

	privKey, err := crypto.PrivateKeyFromBytes(privBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse private key: %v\n", err)
		os.Exit(1)
	}
	return privKey
}

// parseQauAmountToWei converts a decimal QAU string (e.g. "0.5", "10", "6000")
// to wei using pure integer math. Accepts optional "0x" prefix for raw hex wei.
func parseQauAmountToWei(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return new(big.Int), nil
	}
	if s[0] == '-' {
		return nil, fmt.Errorf("negative amount: %q", s)
	}

	// 0x prefix → raw hex wei, no scaling.
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		hexStr := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
		val := new(big.Int)
		if _, ok := val.SetString(hexStr, 16); !ok {
			return nil, fmt.Errorf("invalid hex amount: %q", s)
		}
		return val, nil
	}

	// Integer QAU (no decimal point): parse and multiply by 10^18.
	if !strings.ContainsRune(s, '.') {
		wei := new(big.Int)
		if _, ok := wei.SetString(s, 10); !ok {
			return nil, fmt.Errorf("invalid integer amount: %q", s)
		}
		wei.Mul(wei, big.NewInt(1e18))
		return wei, nil
	}

	// Decimal QAU: split, pad fractional part to 18 digits, concatenate.
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid decimal amount: %q", s)
	}
	intPart, fracPart := parts[0], parts[1]
	if intPart == "" && fracPart == "" {
		return nil, fmt.Errorf("invalid decimal amount: %q", s)
	}
	if len(fracPart) > 18 {
		return nil, fmt.Errorf("too many fractional digits (%d > 18): %q", len(fracPart), s)
	}
	paddedFrac := fracPart + strings.Repeat("0", 18-len(fracPart))
	combined := strings.TrimLeft(intPart+paddedFrac, "0")
	if combined == "" {
		return new(big.Int), nil
	}
	wei := new(big.Int)
	if _, ok := wei.SetString(combined, 10); !ok {
		return nil, fmt.Errorf("invalid decimal amount: %q", s)
	}
	return wei, nil
}
