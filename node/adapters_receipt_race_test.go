// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// TestGetTransactionReceipt_RetryOnMissingPersistedReceipt is a regression test
// for the R40-DEPLOY FIX (2026-08-10): GetTransactionReceipt must not
// prematurely fall back to the inferred "0x0 / FAILED" status when the tx is
// in the block index but its persisted receipt is briefly missing (the
// PutBlock -> StoreReceipts write-order race window). Without the retry, the
// fallback returned a false "0x0" receipt — observed as spurious
// "DEPLOYMENT FAILED!" in deploy_vesting_all even when status=0x1.
//
// This test uses a real *block.BlockStore backed by an in-memory KV store and
// drives GetTransactionReceipt directly. It exercises two scenarios:
//
//  1. Truly-unknown tx: must return (nil, nil) WITHOUT entering the retry
//     loop (which would burn ~500ms for nothing).
//  2. Tx in the index but receipt missing initially, then persisted ~120ms
//     later: must return a NON-nil receipt with status="0x1" rather than the
//     stale inferred status.
func TestGetTransactionReceipt_RetryOnMissingPersistedReceipt(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	a := &blockReaderAdapter{blockStore: bs}

	// 1) Unknown tx: must bail out fast (no retry loop).
	unknownHash := types.Hash{0x01}
	start := time.Now()
	got, err := a.GetTransactionReceipt(unknownHash)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("unknown tx: unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("unknown tx: expected nil receipt, got %v", got)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("unknown tx: took %v, expected fast bail-out (<200ms)", elapsed)
	}

	// 2) Tx in index, receipt delayed.
	kp, _ := crypto.GenerateKeyPair()
	fromAddr := kp.Public.Address()
	toAddr := types.Address{0xbb}
	tx := &encoding.Transaction{
		Type:     encoding.TxTypeContract,
		From:     fromAddr,
		To:       &toAddr,
		Value:    big.NewInt(0),
		Nonce:    0,
		GasLimit: 21000,
		GasPrice: big.NewInt(1),
		Data:     []byte{},
		ChainID:  1668,
	}
	blk := &encoding.Block{
		Header:       &encoding.BlockHeader{Height: 1, Timestamp: time.Now().Unix(), ProposerAddr: types.Address{0xaa}},
		Transactions: []*encoding.Transaction{tx},
	}
	if err := bs.PutBlock(blk); err != nil {
		t.Fatalf("PutBlock: %v", err)
	}

	// Confirm the receipt is not yet persisted.
	txHash := block.ComputeTransactionHash(tx)
	if r, _ := bs.GetReceipt(txHash); r != nil {
		t.Fatalf("precondition violated: receipt already present for %x", txHash)
	}

	// Start GetTransactionReceipt in a goroutine, persist the receipt ~120ms
	// in (mid-window), and expect to get status=0x1 back from the retry loop.
	done := make(chan struct {
		receipt any
		err     error
	}, 1)
	go func() {
		r, e := a.GetTransactionReceipt(txHash)
		done <- struct {
			receipt any
			err     error
		}{r, e}
	}()

	time.Sleep(120 * time.Millisecond)

	stored := &encoding.StoredReceipt{
		TxHash:      txHash,
		BlockHash:   block.ComputeBlockHash(blk),
		BlockNumber: 1,
		TxIndex:     0,
		Status:      1,
		GasUsed:     0,
	}
	if err := bs.StoreReceipts([]*encoding.StoredReceipt{stored}); err != nil {
		t.Fatalf("StoreReceipts: %v", err)
	}

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("GetTransactionReceipt returned error: %v", res.err)
		}
		if res.receipt == nil {
			t.Fatalf("GetTransactionReceipt returned nil receipt after retry window — retry fix not effective")
		}
		m, ok := res.receipt.(map[string]interface{})
		if !ok {
			t.Fatalf("GetTransactionReceipt returned unexpected type %T", res.receipt)
		}
		st, _ := m["status"].(string)
		if st != "0x1" {
			t.Fatalf("expected status 0x1 (success), got %q (race-condition false negative re-appeared)", st)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("GetTransactionReceipt did not return within 20s (retry loop likely misbehaving)")
	}
}

// TestGetTransactionReceipt_BoundedWhenReceiptNeverPersisted verifies the retry
// loop is bounded: if no receipt is ever persisted, GetTransactionReceipt must
// still eventually return (instead of hanging). It exercises the fallback
// path's stale stateDB branch (nil stateDB here, so inferred status).
func TestGetTransactionReceipt_BoundedWhenReceiptNeverPersisted(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())
	a := &blockReaderAdapter{blockStore: bs}

	kp2, _ := crypto.GenerateKeyPair()
	fromAddr := kp2.Public.Address()
	tx := &encoding.Transaction{
		Type:     encoding.TxTypeCreate,
		From:     fromAddr,
		To:       nil,
		Nonce:    7,
		GasLimit: 1_000_000,
		GasPrice: big.NewInt(1),
		ChainID:  1668,
	}
	blk := &encoding.Block{
		Header:       &encoding.BlockHeader{Height: 2, Timestamp: time.Now().Unix(), ProposerAddr: types.Address{0xaa}},
		Transactions: []*encoding.Transaction{tx},
	}
	if err := bs.PutBlock(blk); err != nil {
		t.Fatalf("PutBlock: %v", err)
	}
	txHash := block.ComputeTransactionHash(tx)

	// No receipt persisted. GetTransactionReceipt must return within an
	// upper bound (the retry loop is ~500ms; allow generous 15s slack).
	done := make(chan struct {
		receipt any
		err     error
	}, 1)
	go func() {
		r, e := a.GetTransactionReceipt(txHash)
		done <- struct {
			receipt any
			err     error
		}{r, e}
	}()
	select {
	case <-done:
		// ok — returned within bounds
	case <-time.After(15 * time.Second):
		t.Fatalf("GetTransactionReceipt hung > 15s without returning — retry loop unbounded")
	}
}
