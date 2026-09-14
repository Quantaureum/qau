// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// R78-UNSTAKE-DATA (2026-08-28)
//
// Root cause: API.Unstake emitted tx.Data = nonceLen(2) + nonce, while
// encoding.VerifyTransactionAuthorization (the canonical validator used at
// the block boundary) requires commission(4) + nonceLen(2) + nonce for BOTH
// TxTypeStake and TxTypeUnstake. API.Stake already emitted the canonical
// layout; only the unstake producer disagreed.
//
// These tests pin the producer/validator contract from both directions.
// ─────────────────────────────────────────────────────────────────────────────

// captureTxPool records the *encoding.Transaction handed to
// AddVerifiedTransaction so the test can run the canonical block-boundary
// validator over exactly what the RPC produced.
type captureTxPool struct {
	captured []*encoding.Transaction
}

func (c *captureTxPool) AddTransaction(tx []byte) (types.Hash, error) { return types.Hash{}, nil }
func (c *captureTxPool) AddVerifiedTransaction(tx *encoding.Transaction) (types.Hash, error) {
	c.captured = append(c.captured, tx)
	return types.Hash{0x78}, nil
}
func (c *captureTxPool) GetPendingTransactions() []any                            { return nil }
func (c *captureTxPool) GetPendingCount() int                                     { return 0 }
func (c *captureTxPool) GetQueuedCount() int                                      { return 0 }
func (c *captureTxPool) GetPendingNonce(addr types.Address) uint64                { return 0 }
func (c *captureTxPool) AddUserOperation(uo *encoding.UserOperation) error        { return nil }
func (c *captureTxPool) GetUserOperation(hash types.Hash) *encoding.UserOperation { return nil }
func (c *captureTxPool) PendingUserOps() []*encoding.UserOperation                { return nil }

// stakingSystemContract returns 0x…10<lo>, the canonical staking (0x1001) /
// unstaking (0x1002) system contract address.
func stakingSystemContract(lo byte) types.Address {
	var a types.Address
	a[18] = 0x10
	a[19] = lo
	return a
}

// newUnstakeAPI wires a full API whose txpool captures submitted txs.
func newUnstakeAPI(pool *captureTxPool) *API {
	api := NewAPI(
		newMockStateReader(),
		newMockBlockReader(),
		pool,
		newMockChainInfo(),
		&mockAccountManager{},
	)
	api.SetEnforceAdminAuth(false)
	api.SetStakingManager(newMockStakingManager())
	return api
}

// signStakeAuth produces the canonical Dilithium3 authorization signature the
// wallets send with qau_stake / qau_unstake.
func signStakeAuth(
	t *testing.T,
	kp *crypto.KeyPair,
	chainID uint64,
	to types.Address,
	authType types.StakeAuthTxType,
	amount *big.Int,
	commission uint32,
	nonce string,
) string {
	t.Helper()
	digest, err := types.ComputeStakeAuthorizationHash(
		chainID, kp.Public.Address(), to, authType, amount, commission, nonce)
	if err != nil {
		t.Fatalf("ComputeStakeAuthorizationHash: %v", err)
	}
	sig, err := kp.Private.Sign(digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return "0x" + hex.EncodeToString(sig)
}

// TestR78_UnstakeTxPassesCanonicalBlockValidator is the regression test: the
// tx produced by qau_unstake must satisfy the same validator that every
// follower runs when it inserts the block containing it.
func TestR78_UnstakeTxPassesCanonicalBlockValidator(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pool := &captureTxPool{}
	api := newUnstakeAPI(pool)

	const chainID = uint64(1668) // newMockChainInfo
	const nonce = "f9478462af1f13c2d1c063050454d55f0befcafe1234567890abcdef012345678"
	amount := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
	unstakeContract := stakingSystemContract(0x02)

	sig := signStakeAuth(t, kp, chainID, unstakeContract,
		types.StakeAuthTypeUnstake, amount, 0, nonce)

	params, _ := json.Marshal([]any{
		kp.Public.Address().ToHexAddress(),
		amount.String(),
		nonce,
		sig,
		"0x" + hex.EncodeToString(kp.Public.Bytes()),
	})
	if _, rpcErr := api.Unstake(ctx(), params); rpcErr != nil {
		t.Fatalf("Unstake returned error: %+v", rpcErr)
	}
	if len(pool.captured) != 1 {
		t.Fatalf("captured %d txs, want 1", len(pool.captured))
	}
	tx := pool.captured[0]

	if tx.Type != encoding.TxTypeUnstake {
		t.Fatalf("tx.Type = %v, want TxTypeUnstake", tx.Type)
	}
	// Canonical layout: commission(4 BE, zero for unstake) + nonceLen(2 BE) + nonce.
	wantLen := 4 + 2 + len(nonce)
	if len(tx.Data) != wantLen {
		t.Fatalf("len(tx.Data) = %d, want %d (commission4+len2+nonce%d)",
			len(tx.Data), wantLen, len(nonce))
	}
	for i := 0; i < 4; i++ {
		if tx.Data[i] != 0 {
			t.Fatalf("tx.Data[%d] = %#x, want 0 (unstake commission must be 0)", i, tx.Data[i])
		}
	}
	if got := int(tx.Data[4])<<8 | int(tx.Data[5]); got != len(nonce) {
		t.Fatalf("encoded nonceLen = %d, want %d", got, len(nonce))
	}
	if got := string(tx.Data[6:]); got != nonce {
		t.Fatalf("encoded nonce = %q, want %q", got, nonce)
	}

	// The whole point: the follower-side validator must accept it.
	if err := encoding.VerifyTransactionAuthorization(tx); err != nil {
		t.Fatalf("VerifyTransactionAuthorization rejected the qau_unstake tx: %v", err)
	}
}

// TestR78_LegacyUnstakeLayoutIsRejected pins the legacy behavior: the pre-fix
// layout (nonceLen(2)+nonce, no commission prefix) must still be rejected, so
// the test fails loudly if someone reintroduces it.
func TestR78_LegacyUnstakeLayoutIsRejected(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	const chainID = uint64(1668)
	const nonce = "f9478462af1f13c2d1c063050454d55f0befcafe1234567890abcdef012345678"
	amount := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
	unstakeContract := stakingSystemContract(0x02)

	digest, err := types.ComputeStakeAuthorizationHash(
		chainID, kp.Public.Address(), unstakeContract,
		types.StakeAuthTypeUnstake, amount, 0, nonce)
	if err != nil {
		t.Fatalf("ComputeStakeAuthorizationHash: %v", err)
	}
	sig, err := kp.Private.Sign(digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	legacyData := make([]byte, 2+len(nonce))
	legacyData[0] = byte(len(nonce) >> 8)
	legacyData[1] = byte(len(nonce))
	copy(legacyData[2:], nonce)

	tx := &encoding.Transaction{
		Type:      encoding.TxTypeUnstake,
		ChainID:   chainID,
		From:      kp.Public.Address(),
		To:        &unstakeContract,
		Value:     amount,
		Data:      legacyData,
		GasLimit:  100000,
		GasPrice:  big.NewInt(1),
		PublicKey: kp.Public.Bytes(),
		Signature: sig,
	}
	err = encoding.VerifyTransactionAuthorization(tx)
	if !errors.Is(err, encoding.ErrAuthStakeBadData) {
		t.Fatalf("legacy unstake layout: err = %v, want ErrAuthStakeBadData", err)
	}
}
