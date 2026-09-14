// Quantaureum Node source, version 1.0.0.
// R37-P3-35 regression tests (2026-07-31).
// TxExecutor.Execute dereferenced blockCtx unconditionally when building the
// receipt — a nil blockCtx panicked the caller (block importer / API path).
// The fix returns a failed receipt carrying ErrNilBlockContext instead.
package txpool

import (
	"strings"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// TestR37_P3_35_Execute_NilBlockContext_NoPanic verifies that Execute with a
// nil BlockContext returns a failed receipt with an explicit error rather
// than panicking.
func TestR37_P3_35_Execute_NilBlockContext_NoPanic(t *testing.T) {
	state := newMockState()
	executor := NewTxExecutor()
	to := types.Address{0x02}
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		Nonce:    0,
		From:     types.Address{0x01},
		To:       &to,
		GasLimit: 21000,
	}

	var receipt *Receipt
	// Pre-fix this panicked with a nil pointer dereference.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("R37-P3-35: Execute panicked on nil blockCtx: %v", r)
			}
		}()
		receipt = executor.Execute(tx, state, nil)
	}()

	if receipt == nil {
		t.Fatal("expected a receipt, got nil")
	}
	if receipt.Status != 0 {
		t.Errorf("expected Status=0 (failure), got %d", receipt.Status)
	}
	if receipt.GasUsed != 0 {
		t.Errorf("expected GasUsed=0 (no gas charged on entry rejection), got %d", receipt.GasUsed)
	}
	if !strings.Contains(receipt.Error, ErrNilBlockContext.Error()) {
		t.Errorf("expected receipt.Error to contain %q, got %q", ErrNilBlockContext.Error(), receipt.Error)
	}
	if receipt.TxHash != tx.Hash() {
		t.Error("receipt.TxHash should match the transaction hash")
	}
}
