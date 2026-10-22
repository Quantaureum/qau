// Quantaureum Node source, version 1.0.0.
// sign_stake signs the canonical stake/unstake authorization digest using a
// validator keystore key.
//
// Usage: sign_stake <key_file> <password_file> <address> <amount_wei> [method] [chain_id] [commission]
//
// method defaults to "stake"; use "unstake" for qau_unstake signatures.
// chain_id defaults to 1668 (mainnet); commission defaults to 0 and is
// ignored for unstake.
//
// R2-07 FIX: the signature covers types.ComputeStakeAuthorizationHash, the
// same canonical digest the RPC layer and the L1 block validator verify
// (R38-P0-02), and the nonce embeds a deadline in the
// "<unixDeadline>:<random>" format ParseAuthNonceDeadline requires.
//
// Outputs JSON: {"nonce":"...","signature":"...","pubkey":"...",
// "address":"...","amount":"...","method":"...","chainId":...,
// "commission":...,"recipient":"...","deadline":...}
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

const (
	defaultChainID = 1668
	nonceLifetime  = 5 * time.Minute
)

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintf(os.Stderr, "Usage: sign_stake <key_file> <password_file> <address> <amount_wei> [method] [chain_id] [commission]\n")
		os.Exit(1)
	}

	keyFile := os.Args[1]
	pwdFile := os.Args[2]
	address := os.Args[3]
	amountStr := os.Args[4]
	method := "stake"
	if len(os.Args) >= 6 {
		method = os.Args[5]
		if method != "stake" && method != "unstake" {
			fmt.Fprintf(os.Stderr, "invalid method: %s (must be stake or unstake)\n", method)
			os.Exit(1)
		}
	}
	chainID := uint64(defaultChainID)
	if len(os.Args) >= 7 {
		id, err := strconv.ParseUint(os.Args[6], 10, 64)
		if err != nil || id == 0 {
			fmt.Fprintf(os.Stderr, "invalid chain_id: %q\n", os.Args[6])
			os.Exit(1)
		}
		chainID = id
	}
	var commission uint32
	if len(os.Args) >= 8 {
		c, err := strconv.ParseUint(os.Args[7], 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid commission: %q\n", os.Args[7])
			os.Exit(1)
		}
		commission = uint32(c)
	}

	from, err := types.ParseHexAddress(address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid address: %v\n", err)
		os.Exit(1)
	}
	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok || amount.Sign() < 0 {
		fmt.Fprintf(os.Stderr, "invalid amount_wei: %q\n", amountStr)
		os.Exit(1)
	}

	// Read password and decrypt the keystore without converting the password
	// to an immutable string.
	pwdBytes, err := os.ReadFile(pwdFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read password file: %v\n", err)
		os.Exit(1)
	}
	pwdBytes = bytes.TrimSpace(pwdBytes)
	defer func() { _ = crypto.ZeroBytesSecure(pwdBytes) }()

	ksBytes, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read key file: %v\n", err)
		os.Exit(1)
	}

	var kf crypto.KeyFile
	if err := json.Unmarshal(ksBytes, &kf); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse key file: %v\n", err)
		os.Exit(1)
	}

	privateKey, err := crypto.DecryptKeyBytes(&kf, pwdBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decrypt key: %v\n", err)
		os.Exit(1)
	}
	defer privateKey.Destroy() //nolint:errcheck // best-effort zeroization on exit

	// Nonce: signed deadline plus 16 random bytes, as required by
	// ParseAuthNonceDeadline.
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate nonce: %v\n", err)
		os.Exit(1)
	}
	deadline := time.Now().Add(nonceLifetime)
	nonce := fmt.Sprintf("%d:%s", deadline.Unix(), hex.EncodeToString(random))

	// Recipient and tx type must match rpc/api.go's canonical pre-parse.
	var recipient types.Address
	var authType types.StakeAuthTxType
	if method == "stake" {
		recipient[18] = 0x10
		recipient[19] = 0x01
		authType = types.StakeAuthTypeStake
	} else {
		recipient[18] = 0x10
		recipient[19] = 0x02
		authType = types.StakeAuthTypeUnstake
		commission = 0
	}

	canonical, err := types.ComputeStakeAuthorizationHash(
		chainID, from, recipient, authType, amount, commission, nonce,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to compute canonical stake digest: %v\n", err)
		os.Exit(1)
	}

	signature, err := crypto.Sign(privateKey, canonical[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to sign: %v\n", err)
		os.Exit(1)
	}

	result := map[string]any{
		"nonce":      nonce,
		"signature":  hex.EncodeToString(signature),
		"pubkey":     hex.EncodeToString(privateKey.PublicKeyBytes()),
		"address":    from.ToHexAddress(),
		"amount":     amount.String(),
		"method":     method,
		"chainId":    chainID,
		"commission": commission,
		"recipient":  recipient.ToHexAddress(),
		"deadline":   deadline.Unix(),
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write output: %v\n", err)
		os.Exit(1)
	}
}
