// Quantaureum Node source, version 1.0.0.
package encoding

// Receipt persistence roundtrip tests: a receipt with NON-EMPTY logs must
// survive MarshalReceipt → UnmarshalReceipt byte-identically. Found while
// debugging the vrf-billing e2e where eth_getLogs stayed empty even though
// the txpool log-propagation fix was in: if this roundtrip breaks, every
// persisted receipt with events becomes unreadable (GetReceipt errors → the
// RPC silently falls back to the log-less inferred receipt).

import (
	"bytes"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestMarshalUnmarshalReceiptWithLogs(t *testing.T) {
	original := &StoredReceipt{
		TxHash:      types.Hash{0x01},
		BlockHash:   types.Hash{0x02},
		BlockNumber: 60,
		TxIndex:     0,
		Status:      1,
		GasUsed:     33585,
		Logs: []*StoredLog{
			{
				Address: types.Address{0x7c, 0xb5},
				Topics:  []types.Hash{{0x1a, 0x77}, {0x02}},
				Data:    bytes.Repeat([]byte{0xab}, 96),
			},
		},
	}

	data, err := MarshalReceipt(original)
	if err != nil {
		t.Fatalf("MarshalReceipt: %v", err)
	}
	decoded, err := UnmarshalReceipt(data)
	if err != nil {
		t.Fatalf("UnmarshalReceipt: %v (receipt with logs must roundtrip — GetReceipt fails closed otherwise)", err)
	}
	if decoded.Status != original.Status || decoded.GasUsed != original.GasUsed || decoded.BlockNumber != original.BlockNumber {
		t.Fatalf("scalar fields mismatch: %+v", decoded)
	}
	if len(decoded.Logs) != 1 {
		t.Fatalf("decoded %d logs, want 1", len(decoded.Logs))
	}
	lg := decoded.Logs[0]
	if lg.Address != original.Logs[0].Address {
		t.Errorf("log address mismatch")
	}
	if len(lg.Topics) != 2 || lg.Topics[0] != original.Logs[0].Topics[0] {
		t.Errorf("log topics mismatch: %x", lg.Topics)
	}
	if !bytes.Equal(lg.Data, original.Logs[0].Data) {
		t.Errorf("log data mismatch")
	}
}
