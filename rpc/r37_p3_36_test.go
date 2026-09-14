// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/txpool"
)

// r37MockTxPool embeds mockTxPool and overrides GetPendingTransactions to
// return txpool.SafePendingTx structs — the real production return type.
type r37MockTxPool struct {
	mockTxPool
	pending []any
}

func (m *r37MockTxPool) GetPendingTransactions() []any { return m.pending }

// TestR37_P3_36_TxPoolInspectReturnsPending verifies the R37-P3-36 fix:
// TxPoolInspect must handle txpool.SafePendingTx (and *txpool.SafePendingTx)
// entries from GetPendingTransactions. The previous type assertion against
// map[string]any silently skipped every transaction, so txpool_inspect
// always returned an empty pending summary in production.
func TestR37_P3_36_TxPoolInspectReturnsPending(t *testing.T) {
	from := mustParseAddress(t, "0x08036632ada4ff720fbb5e4b8e226358280954cb")
	to := mustParseAddress(t, "0xaed46ccac8f17e429ba1f45a1c7c7533e40d8642")

	valueTx := txpool.SafePendingTx{
		Nonce:    7,
		From:     from,
		To:       &to,
		Value:    big.NewInt(1000),
		GasLimit: 21000,
		GasPrice: big.NewInt(5),
	}
	ptrFrom := mustParseAddress(t, "0x4ce1ad3155d9abf9193caeea9aae858b9a8cd268")
	ptrTx := &txpool.SafePendingTx{
		Nonce:    1,
		From:     ptrFrom,
		Value:    big.NewInt(42),
		GasLimit: 50000,
		GasPrice: big.NewInt(3),
	}

	tp := &r37MockTxPool{pending: []any{
		valueTx,
		ptrTx,
		(*txpool.SafePendingTx)(nil),     // nil pointer must be skipped, not panic
		map[string]any{"from": "0xdead"}, // legacy/wrong type must be skipped
	}}
	api := NewAPI(&mockStateReader{}, newMockBlockReader(), tp, newMockChainInfo(), nil)

	res, rpcErr := api.TxPoolInspect(context.Background(), nil)
	if rpcErr != nil {
		t.Fatalf("TxPoolInspect returned error: %+v", rpcErr)
	}
	out, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("unexpected result type %T", res)
	}
	pending, ok := out["pending"].(map[string]map[string]string)
	if !ok {
		t.Fatalf("pending has unexpected type %T", out["pending"])
	}

	if len(pending) != 2 {
		t.Fatalf("expected 2 senders in pending summary, got %d: %v", len(pending), pending)
	}

	// Value-typed entry
	fromKey := from.String()
	entries, ok := pending[fromKey]
	if !ok {
		t.Fatalf("missing pending entry for %s; got keys %v", fromKey, pending)
	}
	expectedGas := fmt.Sprintf("0x%x", uint64(21000))
	expected := fmt.Sprintf("%s -> %s: %s wei + %s gas × %s",
		fromKey, to.String(), "1000", expectedGas, "5")
	if entries["0x7"] != expected {
		t.Errorf("unexpected summary for nonce 0x7:\n got: %q\nwant: %q", entries["0x7"], expected)
	}

	// Pointer-typed entry (contract creation: To == nil)
	ptrKey := ptrFrom.String()
	ptrEntries, ok := pending[ptrKey]
	if !ok {
		t.Fatalf("missing pending entry for %s", ptrKey)
	}
	expectedPtr := fmt.Sprintf("%s -> %s: %s wei + %s gas × %s",
		ptrKey, "", "42", fmt.Sprintf("0x%x", uint64(50000)), "3")
	if ptrEntries["0x1"] != expectedPtr {
		t.Errorf("unexpected summary for nonce 0x1:\n got: %q\nwant: %q", ptrEntries["0x1"], expectedPtr)
	}
}

// TestR37_P3_36_TxPoolInspectEmptyPool ensures the empty-pool behavior is
// unchanged: an empty (but non-nil) summary map is returned.
func TestR37_P3_36_TxPoolInspectEmptyPool(t *testing.T) {
	tp := &r37MockTxPool{pending: nil}
	api := NewAPI(&mockStateReader{}, newMockBlockReader(), tp, newMockChainInfo(), nil)

	res, rpcErr := api.TxPoolInspect(context.Background(), nil)
	if rpcErr != nil {
		t.Fatalf("TxPoolInspect returned error: %+v", rpcErr)
	}
	out := res.(map[string]any)
	pending, ok := out["pending"].(map[string]map[string]string)
	if !ok {
		t.Fatalf("pending has unexpected type %T", out["pending"])
	}
	if len(pending) != 0 {
		t.Errorf("expected empty pending summary, got %v", pending)
	}
}
