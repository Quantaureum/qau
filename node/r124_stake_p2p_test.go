// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/txpool"
	"github.com/quantaureum/qau/types"
)

// R124-STAKE-P2P (2026-09-07) FIX regression test.
//
// Background: an earlier policy discarded ALL p2p-arriving
// stake/unstake transactions in txProcessingLoop, on the theory that
// "legitimate stake txs are only created via local RPC (qau_stake) and
// reach validators by block propagation, not tx gossip". That
// assumption does not hold for deployments where a non-validator RPC entry
// point accepts qau_stake calls and relies on transaction gossip to deliver
// them to validators. Dropping such transactions at the validator would leave
// them stranded even though the submitting client observes successful
// admission to the RPC node's pool.
//
// Since the earlier authorization hardening, BatchValidateWithState
// now runs the canonical VerifyTransactionAuthorization for stake/
// unstake (ComputeStakeAuthorizationHash domain); forged stake txs are
// rejected at admission. The old p2p-drop was no longer a required
// defense — only a fatal block of the staking feature.
//
// This file verifies two behaviors:
//  1. shouldProcessP2PTx does not drop txs based on Type being
//     stake/unstake (they enter BatchAdd's canonical auth path).
//  2. A properly signed p2p stake tx can be admitted via BatchAdd
//     (canonical auth + field checks + nonce/balance checks all pass);
//     a stake tx with a forged signature is rejected.

// buildSignedStakeTxForP2P constructs a TxTypeStake transaction
// identical in shape to what rpc.API.Stake (qau_stake) produces:
//
//	To = 0x...1001, Data = commission(4) || nonceLen(2) || nonce,
//
// Signature = Dilithium3(ComputeStakeAuthorizationHash(...)), GasPrice=1,
// GasLimit=100000。
func buildSignedStakeTxForP2P(t *testing.T, chainID uint64, nonce int64, senderStateNonce uint64) (*encoding.Transaction, error) {
	t.Helper()

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	from := kp.Public.Address()

	var stakingContract types.Address
	stakingContract[18] = 0x10
	stakingContract[19] = 0x01

	amount := new(big.Int).Mul(big.NewInt(40), big.NewInt(1e18)) // 40 QAU
	stakeNonce := "p2p-stake-regress-1"

	digest, err := types.ComputeStakeAuthorizationHash(
		chainID, from, stakingContract, types.StakeAuthTypeStake,
		amount, 0, stakeNonce,
	)
	if err != nil {
		t.Fatalf("ComputeStakeAuthorizationHash: %v", err)
	}
	sig, err := crypto.Sign(kp.Private, digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Data layout = commission(4 BE) || nonceLen(2 BE) || nonce — mirrors
	// the txData construction in rpc/api.go Stake.
	nb := []byte(stakeNonce)
	data := make([]byte, 4+2+len(nb))
	data[4] = byte(len(nb) >> 8)
	data[5] = byte(len(nb))
	copy(data[6:], nb)

	return &encoding.Transaction{
		Type:      encoding.TxTypeStake,
		Nonce:     senderStateNonce,
		ChainID:   chainID,
		From:      from,
		To:        &stakingContract,
		Value:     amount,
		Data:      data,
		GasLimit:  100000,
		GasPrice:  big.NewInt(1),
		PublicKey: kp.Public.Bytes(),
		Signature: sig,
	}, nil
}

// r124TestState is the minimal StateReader implementation required by txpool.
type r124TestState struct {
	balances map[types.Address]*big.Int
	nonces   map[types.Address]uint64
}

func newR124TestState(t *testing.T, chainID uint64) *r124TestState {
	t.Helper()
	s := &r124TestState{
		balances: make(map[types.Address]*big.Int),
		nonces:   make(map[types.Address]uint64),
	}
	return s
}

func (s *r124TestState) GetBalance(addr types.Address) *big.Int {
	if b, ok := s.balances[addr]; ok {
		return new(big.Int).Set(b)
	}
	return new(big.Int)
}

func (s *r124TestState) GetNonce(addr types.Address) uint64 {
	return s.nonces[addr]
}

// TestR124ShouldProcessP2PTx_StakeNotDropped: p2p must not drop
// stake/unstake by Type — the previous drop has been replaced by canonical auth checks.
func TestR124ShouldProcessP2PTx_StakeNotDropped(t *testing.T) {
	tx, err := buildSignedStakeTxForP2P(t, 1668, 1, 0)
	if err != nil {
		t.Fatalf("buildSignedStakeTxForP2P: %v", err)
	}

	if !shouldProcessP2PTx(tx) {
		t.Fatalf("shouldProcessP2PTx(stake tx) = false, want true: p2p stake tx must reach BatchAdd canonical verification (R124-STAKE-P2P)")
	}

	txUnstake := *tx
	txUnstake.Type = encoding.TxTypeUnstake
	if !shouldProcessP2PTx(&txUnstake) {
		t.Fatalf("shouldProcessP2PTx(unstake tx) = false, want true")
	}

	// Other types are unaffected (still enter the batch path).
	txTransfer := *tx
	txTransfer.Type = encoding.TxTypeTransfer
	if !shouldProcessP2PTx(&txTransfer) {
		t.Fatalf("shouldProcessP2PTx(transfer tx) = false, want true")
	}
}

// TestR124P2PStakeTxEntersPoolViaBatchAdd: a properly signed stake tx
// arriving via p2p must be admitted via BatchAdd; a forged signature
// must be rejected. Models the relevant path in miniature: an RPC observer
// broadcasts, a validator receives the transaction through p2p, and BatchAdd
// applies canonical verification.
func TestR124P2PStakeTxEntersPoolViaBatchAdd(t *testing.T) {
	const chainID = uint64(1668)

	validator := txpool.NewTxValidator(big.NewInt(1), 30_000_000, chainID)
	state := newR124TestState(t, chainID)
	pool := txpool.NewTxPool(validator, state)

	// 1) Valid signature → must enter the pool.
	good, err := buildSignedStakeTxForP2P(t, chainID, 1, 0)
	if err != nil {
		t.Fatalf("buildSignedStakeTxForP2P: %v", err)
	}
	// Fund sender with enough for amount + gasCost (BatchValidateWithState
	// checks the balance).
	state.balances[good.From] = new(big.Int).Add(
		new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18)), // 1000 QAU
		big.NewInt(100000), // gasCost = GasLimit(100000) × GasPrice(1)
	)
	errs := pool.BatchAdd([]*encoding.Transaction{good})
	if errs[0] != nil {
		t.Fatalf("BatchAdd(legit p2p stake tx) err = %v, want nil — p2p-relayed stake tx must be admissible after canonical verification (R124-STAKE-P2P)", errs[0])
	}
	if pool.Count() != 1 {
		t.Fatalf("pool.Count() = %d, want 1", pool.Count())
	}

	// 2) Forged signature → must be rejected (canonical auth still
	// enforced). Tamper with the signed amount (40 QAU → 41 QAU) while
	// keeping the original signature — ComputeStakeAuthorizationHash
	// covers value, so verification must fail.
	bad, err := buildSignedStakeTxForP2P(t, chainID, 1, 1)
	if err != nil {
		t.Fatalf("buildSignedStakeTxForP2P: %v", err)
	}
	bad.Value = new(big.Int).Mul(big.NewInt(41), big.NewInt(1e18)) // tampered amount
	bad.Signature = good.Signature                                 // impersonate another's signature
	bad.PublicKey = good.PublicKey
	bad.From = good.From
	state.balances[bad.From] = state.balances[good.From]
	errs = pool.BatchAdd([]*encoding.Transaction{bad})
	if errs[0] == nil {
		t.Fatalf("BatchAdd(forged stake tx) = nil err, want error — canonical stake-signature verification must still reject forgeries")
	}
}
