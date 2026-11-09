package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

func h03TransferTx(chainID uint64) *encoding.Transaction {
	to := types.Address{3}
	return &encoding.Transaction{
		Type:      encoding.TxTypeTransfer,
		Nonce:     1,
		ChainID:   chainID,
		From:      types.Address{2},
		To:        &to,
		Value:     big.NewInt(1),
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		Signature: []byte{0x01},
	}
}

func h03Block(epoch, txChainID uint64) *encoding.Block {
	return &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:   1,
			ChainID:   1333,
			Height:    2,
			Timestamp: 2,
			Epoch:     epoch,
		},
		Transactions: []*encoding.Transaction{h03TransferTx(txChainID)},
	}
}

// TestH03TxChainIDGateDecision pins the epoch boundary semantics:
// 0 = effective from genesis; TxChainIDEnforcementDisabled = inactive on
// every block (legacy); any other activation grandfathers blocks below it and
// applies from the activation epoch onward.
func TestH03TxChainIDGateDecision(t *testing.T) {
	cases := []struct {
		name       string
		blockEpoch uint64
		activation uint64
		want       bool
	}{
		{"genesis default at epoch 0", 0, 0, true},
		{"genesis default at head", 50000, 0, true},
		{"disabled sentinel at epoch 0", 0, TxChainIDEnforcementDisabled, false},
		{"disabled sentinel at head", 50000, TxChainIDEnforcementDisabled, false},
		{"below activation", 99, 100, false},
		{"at activation", 100, 100, true},
		{"above activation", 101, 100, true},
	}
	for _, tc := range cases {
		if got := txChainIDEnforcementActive(tc.blockEpoch, tc.activation); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// TestH03ValidateTransactionsGenesisDefault proves activation 0 is the
// hardened default: a foreign-ChainID transaction is rejected from genesis,
// while an honest transaction is still accepted. The disabled sentinel is the
// explicit opt-out that restores legacy acceptance.
func TestH03ValidateTransactionsGenesisDefault(t *testing.T) {
	v := NewBlockValidator(1333, 30_000_000)
	err := v.validateTransactions(h03Block(0, 9999))
	if !errors.Is(err, encoding.ErrAuthChainIDMismatch) {
		t.Fatalf("activation 0 must enforce from genesis, got %v", err)
	}
	if err := v.validateTransactions(h03Block(0, 1333)); err != nil {
		t.Fatalf("honest block must still be accepted, got %v", err)
	}

	v.SetTxChainIDEnforcementEpoch(TxChainIDEnforcementDisabled)
	if err := v.validateTransactions(h03Block(0, 9999)); err != nil {
		t.Fatalf("disabled sentinel must keep legacy acceptance, got %v", err)
	}
}

// TestH03ValidateTransactionsActive pins the activated behavior and the
// historical grandfathering rule.
func TestH03ValidateTransactionsActive(t *testing.T) {
	v := NewBlockValidator(1333, 30_000_000)
	v.SetTxChainIDEnforcementEpoch(1)

	// Epoch 0 < activation 1: historical block stays accepted.
	if err := v.validateTransactions(h03Block(0, 9999)); err != nil {
		t.Fatalf("block below activation must be grandfathered, got %v", err)
	}

	// Epoch 1 >= activation 1 with a foreign ChainID: rejected.
	err := v.validateTransactions(h03Block(1, 9999))
	if !errors.Is(err, encoding.ErrAuthChainIDMismatch) {
		t.Fatalf("foreign ChainID must be rejected with ErrAuthChainIDMismatch, got %v", err)
	}

	// Matching ChainID still accepted (honest block unchanged).
	if err := v.validateTransactions(h03Block(1, 1333)); err != nil {
		t.Fatalf("honest block must still be accepted, got %v", err)
	}
}

// TestH03ValidateTransactionsFailClosed ensures an activated gate cannot
// silently degrade into a no-op when the validator has no chain ID.
func TestH03ValidateTransactionsFailClosed(t *testing.T) {
	v := NewBlockValidator(0, 30_000_000)
	v.SetTxChainIDEnforcementEpoch(1)
	if err := v.validateTransactions(h03Block(1, 1333)); err == nil {
		t.Fatal("activated gate with zero validator chain ID must fail closed")
	}
}

// TestH04VRFGateInactiveIsNoOp pins that activation epoch 0 disables VRF
// enforcement for every epoch, i.e. the dedicated switch added for H-04 is a
// strict no-op until explicitly configured.
func TestH04VRFGateInactiveIsNoOp(t *testing.T) {
	for _, epoch := range []uint64{0, 1, 100, 1_000_000} {
		if vrfEnforcementActive(epoch, false, 0) {
			t.Fatalf("activation 0 must be inactive at epoch %d", epoch)
		}
	}
	if vrfEnforcementActive(99, false, 100) {
		t.Fatal("epoch below activation must be inactive")
	}
	if !vrfEnforcementActive(100, false, 100) {
		t.Fatal("epoch at activation must be active")
	}
}
