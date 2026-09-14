// Quantaureum Node source, version 1.0.0.
// R37-P1-TXPOOL-01 regression tests (2026-07-30).
// Previously the executor's type switch lacked TxTypeDynamicFee/TxTypeBlob:
// both fell into a default branch that executed NOTHING but reported
// Status=1 (fake success — sender charged, nonce bumped, recipient never
// paid) and double-charged intrinsic gas. The fix routes DynamicFee by
// payload, rejects Blob explicitly, and makes default fail-closed.
package txpool

import (
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// TestTXPOOL_R37_P1_DynamicFeeTransfer_Executes verifies a DynamicFee value
// transfer actually moves funds and charges intrinsic gas exactly once.
func TestTXPOOL_R37_P1_DynamicFeeTransfer_Executes(t *testing.T) {
	state := newMockState()
	from := types.Address{0x01}
	to := types.Address{0x02}
	state.SetBalance(from, big.NewInt(1_000_000_000))

	executor := NewTxExecutor()
	tx := &encoding.Transaction{
		Version:              1,
		Type:                 encoding.TxTypeDynamicFee,
		Nonce:                0,
		From:                 from,
		To:                   &to,
		Value:                big.NewInt(1000),
		GasLimit:             100000,
		GasPrice:             big.NewInt(5),
		MaxFeePerGas:         big.NewInt(10),
		MaxPriorityFeePerGas: big.NewInt(1),
		ChainID:              1668,
	}

	receipt := executor.Execute(tx, state, &BlockContext{BlockNumber: 1, BaseFee: big.NewInt(1)})

	if receipt.Status != 1 {
		t.Fatalf("DynamicFee transfer should succeed, got status=%d err=%q", receipt.Status, receipt.Error)
	}
	if got := state.GetBalance(to); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("recipient should receive 1000, got %s (fake-success regression!)", got)
	}
	// Single intrinsic charge: executeTransfer returns 0, so GasUsed must be
	// exactly the intrinsic gas — not double (the old default branch bug).
	want := executor.intrinsicGas(tx)
	if receipt.GasUsed != want {
		t.Fatalf("GasUsed should be exactly intrinsic gas %d (single charge), got %d", want, receipt.GasUsed)
	}
}

// TestTXPOOL_R37_P1_BlobTx_FailsClosed verifies blob transactions are
// explicitly rejected instead of silently "succeeding".
func TestTXPOOL_R37_P1_BlobTx_FailsClosed(t *testing.T) {
	state := newMockState()
	from := types.Address{0x01}
	to := types.Address{0x02}
	state.SetBalance(from, big.NewInt(1_000_000_000))

	executor := NewTxExecutor()
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeBlob,
		Nonce:    0,
		From:     from,
		To:       &to,
		Value:    big.NewInt(1000),
		GasLimit: 100000,
		GasPrice: big.NewInt(1),
		ChainID:  1668,
	}

	receipt := executor.Execute(tx, state, &BlockContext{BlockNumber: 1})

	if receipt.Status != 0 {
		t.Fatalf("blob tx must fail (status 0), got status=%d", receipt.Status)
	}
	if !strings.Contains(receipt.Error, "not supported") {
		t.Fatalf("expected 'not supported' error, got %q", receipt.Error)
	}
	if got := state.GetBalance(to); got.Sign() != 0 {
		t.Fatalf("recipient must receive nothing on rejected blob tx, got %s", got)
	}
}

// TestTXPOOL_R37_P1_UnknownType_FailsClosed verifies the default branch is
// fail-closed: unknown transaction types produce an error receipt and move
// no funds, instead of the old silent Status=1.
func TestTXPOOL_R37_P1_UnknownType_FailsClosed(t *testing.T) {
	state := newMockState()
	from := types.Address{0x01}
	to := types.Address{0x02}
	state.SetBalance(from, big.NewInt(1_000_000_000))

	executor := NewTxExecutor()
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxType(250), // unknown
		Nonce:    0,
		From:     from,
		To:       &to,
		Value:    big.NewInt(1000),
		GasLimit: 100000,
		GasPrice: big.NewInt(1),
		ChainID:  1668,
	}

	receipt := executor.Execute(tx, state, &BlockContext{BlockNumber: 1})

	if receipt.Status != 0 {
		t.Fatalf("unknown tx type must fail (status 0), got status=%d", receipt.Status)
	}
	if !strings.Contains(receipt.Error, "unsupported transaction type") {
		t.Fatalf("expected 'unsupported transaction type' error, got %q", receipt.Error)
	}
	if got := state.GetBalance(to); got.Sign() != 0 {
		t.Fatalf("recipient must receive nothing for unknown tx type, got %s", got)
	}
}
