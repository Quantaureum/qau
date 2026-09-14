// Quantaureum Go SDK source, version 1.0.0.
package client

import (
	"context"
	"fmt"
	"math/big"
	"strconv"

	"github.com/quantaureum/qau/sdks/go-sdk/accounts"
	"github.com/quantaureum/qau/sdks/go-sdk/common"
)

// stakingResult mirrors the response object returned by the node for
// qau_stake, qau_unstake and qau_claimRewards.
type stakingResult struct {
	Success bool   `json:"success"`
	TxHash  string `json:"txHash"`
}

// signStakingAuth builds and signs the authentication message expected by the
// node's verifyStakingSignature (rpc/api.go):
//
//	method|0xaddress|nonce|params
//
// The signature is raw Dilithium3 over the message bytes (no pre-hashing),
// because the node verifies with crypto.Verify → mode3.Verify on the raw
// message. Account.SignMessage MUST NOT be used here: it prefixes and
// keccak-hashes the message, which the node would reject.
func signStakingAuth(acct *accounts.Account, method, nonce, params string) (sigHex, pubKeyHex string, err error) {
	message := []byte(method + "|" + acct.Address().Hex() + "|" + nonce + "|" + params)
	sig, err := acct.Sign(message)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign %s request: %w", method, err)
	}
	return fmt.Sprintf("0x%x", sig), fmt.Sprintf("0x%x", acct.PublicKeyBytes()), nil
}

// Stake stakes the given amount of QAU for the account.
// Requires Dilithium3 authentication (nonce, signature, publicKey).
func (c *Client) Stake(ctx context.Context, acct *accounts.Account, amount *big.Int, nonce uint64) (common.Hash, error) {
	if err := c.validateClientOpen(); err != nil {
		return common.Hash{}, err
	}

	nonceStr := strconv.FormatUint(nonce, 10)
	amountStr := fmt.Sprintf("0x%x", amount)
	sigHex, pubKeyHex, err := signStakingAuth(acct, "stake", nonceStr, amountStr)
	if err != nil {
		return common.Hash{}, err
	}

	var result stakingResult
	params := []any{acct.Address().Hex(), amountStr, nonceStr, sigHex, pubKeyHex}
	if err := c.rpc.Call(ctx, &result, "qau_stake", params...); err != nil {
		return common.Hash{}, fmt.Errorf("stake failed: %w", err)
	}

	return common.HexToHash(result.TxHash), nil
}

// Unstake unstakes the given amount of QAU.
func (c *Client) Unstake(ctx context.Context, acct *accounts.Account, amount *big.Int, nonce uint64) (common.Hash, error) {
	if err := c.validateClientOpen(); err != nil {
		return common.Hash{}, err
	}

	nonceStr := strconv.FormatUint(nonce, 10)
	amountStr := fmt.Sprintf("0x%x", amount)
	sigHex, pubKeyHex, err := signStakingAuth(acct, "unstake", nonceStr, amountStr)
	if err != nil {
		return common.Hash{}, err
	}

	var result stakingResult
	params := []any{acct.Address().Hex(), amountStr, nonceStr, sigHex, pubKeyHex}
	if err := c.rpc.Call(ctx, &result, "qau_unstake", params...); err != nil {
		return common.Hash{}, fmt.Errorf("unstake failed: %w", err)
	}

	return common.HexToHash(result.TxHash), nil
}

// ClaimRewards claims staking rewards.
func (c *Client) ClaimRewards(ctx context.Context, acct *accounts.Account, nonce uint64) (common.Hash, error) {
	if err := c.validateClientOpen(); err != nil {
		return common.Hash{}, err
	}

	nonceStr := strconv.FormatUint(nonce, 10)
	sigHex, pubKeyHex, err := signStakingAuth(acct, "claimRewards", nonceStr, "")
	if err != nil {
		return common.Hash{}, err
	}

	var result stakingResult
	params := []any{acct.Address().Hex(), nonceStr, sigHex, pubKeyHex}
	if err := c.rpc.Call(ctx, &result, "qau_claimRewards", params...); err != nil {
		return common.Hash{}, fmt.Errorf("claimRewards failed: %w", err)
	}

	return common.HexToHash(result.TxHash), nil
}
