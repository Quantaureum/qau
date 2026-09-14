// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/block"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

// TestGetTransactionReceipt_R42_RaceContractDeployedButStaleStateDBCode
// reproduces the R42-RECEIPT-FIX server-side race: a contract-creation tx
// has been PutBlock'd and IndexTransactions'd (GetTransaction succeeds),
// StoreReceipts has NOT yet completed (GetReceipt returns nil), AND the
// RPC handler's stateDB snapshot does not yet have the deployed code.
//
// Pre-R42 behavior: fallback infers status="0x0" because
// sdb.GetCode(contractAddr) returns empty -> false "DEPLOYMENT FAILED!".
//
// R42-SERVER-HARDENING behavior: even without code visible on this sdb
// snapshot, if the sender's nonce has advanced past tx.Nonce, the tx
// must have executed (nonce is bumped ATOMICALLY with code deployment
// during consensus-level apply). The receipt MUST default to 0x1.
func TestGetTransactionReceipt_R42_RaceContractDeployedButStaleStateDBCode(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())

	kp, _ := crypto.GenerateKeyPair()
	fromAddr := kp.Public.Address()

	tx := &encoding.Transaction{
		Type:     encoding.TxTypeCreate,
		From:     fromAddr,
		To:       nil,
		Nonce:    0,
		Value:    big.NewInt(0),
		GasLimit: 1_000_000,
		GasPrice: big.NewInt(1),
		ChainID:  1668,
		Data:     []byte{0x60, 0x80},
	}

	blk := &encoding.Block{
		Header:       &encoding.BlockHeader{Height: 1, Timestamp: time.Now().Unix(), ProposerAddr: types.Address{0xaa}},
		Transactions: []*encoding.Transaction{tx},
	}
	if err := bs.PutBlock(blk); err != nil {
		t.Fatalf("PutBlock: %v", err)
	}
	// Do NOT StoreReceipts (race window: receipt write pending).

	// StateDB: nonce advanced to 1, deploy code NOT yet committed here.
	sdb := state.NewStateDB(db.NewMemDB())
	sdb.SetNonce(fromAddr, 1)

	a := &blockReaderAdapter{
		blockStore: bs,
		stateDB:    sdb,
	}

	txHash := block.ComputeTransactionHash(tx)
	got, err := a.GetTransactionReceipt(txHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatalf("R42 regression: expected non-nil receipt, got nil (race false-negative)")
	}
	m, ok := got.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", got)
	}
	st, _ := m["status"].(string)
	if st != "0x1" {
		t.Fatalf("R42 race false-negative re-appeared. Expected status=0x1 (deployed, nonce advanced), got %q", st)
	}

	// Verify contractAddress matches the deterministic derivation.
	ca, _ := m["contractAddress"].(string)
	addr := qvm.CreateAddress(qvm.Address(tx.From), tx.Nonce)
	expected := "0x" + hex.EncodeToString(addr[:])
	if ca != expected {
		t.Fatalf("contractAddress mismatch: expected %s, got %q", expected, ca)
	}
}

// TestGetTransactionReceipt_R42_GenuineFailureNotMaskedToSuccess verifies
// the non-race genuine-failure branch: a contract-creation tx is in the
// chain but its deployment truly failed, the sender's nonce did NOT
// advance past tx.Nonce, and no code exists at the contractAddr. The
// receipt MUST report status="0x0", not be masked to "0x1" by R42.
//
// Guards against the masking risk called out in R42-RECEIPT-FIX commit
// body ("expand retry to ~5s would risk masking genuinely failed
// deployments").
func TestGetTransactionReceipt_R42_GenuineFailureNotMaskedToSuccess(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())

	kp, _ := crypto.GenerateKeyPair()
	fromAddr := kp.Public.Address()
	tx := &encoding.Transaction{
		Type:     encoding.TxTypeCreate,
		From:     fromAddr,
		To:       nil,
		Nonce:    7,
		Value:    big.NewInt(0),
		GasLimit: 1_000_000,
		GasPrice: big.NewInt(1),
		ChainID:  1668,
		Data:     []byte{0xfd},
	}

	blk := &encoding.Block{
		Header:       &encoding.BlockHeader{Height: 5, Timestamp: time.Now().Unix(), ProposerAddr: types.Address{0xaa}},
		Transactions: []*encoding.Transaction{tx},
	}
	if err := bs.PutBlock(blk); err != nil {
		t.Fatalf("PutBlock: %v", err)
	}
	// No StoreReceipts (race window).

	// StateDB: nonce NOT advanced past tx.Nonce, NO code at contractAddr.
	sdb := state.NewStateDB(db.NewMemDB())
	sdb.SetNonce(fromAddr, tx.Nonce) // equal, not advanced

	a := &blockReaderAdapter{
		blockStore: bs,
		stateDB:    sdb,
	}

	txHash := block.ComputeTransactionHash(tx)
	got, err := a.GetTransactionReceipt(txHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatalf("expected non-nil receipt for genuine-failure branch, got nil")
	}
	m, ok := got.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", got)
	}
	st, _ := m["status"].(string)
	if st != "0x0" {
		t.Fatalf("R42 masking risk: genuine contract-deployment failure masked as success. Expected status=0x0, got %q", st)
	}
}

// TestGetTransactionReceipt_R42_NonContractTxRaceNeverReturnsStaleFailureStatus
// sanity guard: a non-contract-creation tx (transfer) hitting the same
// fallback path (receipt-still-missing window) must NEVER report
// status="0x0" purely because it is a non-create tx. The fallback must
// default status="0x1" for non-create txs regardless of stateDB code.
func TestGetTransactionReceipt_R42_NonContractTxRaceNeverReturnsStaleFailureStatus(t *testing.T) {
	bs := block.NewBlockStore(db.NewMemDB())

	kp, _ := crypto.GenerateKeyPair()
	fromAddr := kp.Public.Address()
	toAddr := types.Address{0xbb}
	tx := &encoding.Transaction{
		Type:     encoding.TxTypeContract,
		From:     fromAddr,
		To:       &toAddr,
		Nonce:    0,
		Value:    big.NewInt(1_000_000_000),
		GasLimit: 21000,
		GasPrice: big.NewInt(1),
		ChainID:  1668,
		Data:     []byte{},
	}

	blk := &encoding.Block{
		Header:       &encoding.BlockHeader{Height: 9, Timestamp: time.Now().Unix(), ProposerAddr: types.Address{0xaa}},
		Transactions: []*encoding.Transaction{tx},
	}
	if err := bs.PutBlock(blk); err != nil {
		t.Fatalf("PutBlock: %v", err)
	}
	// No StoreReceipts (race window).

	sdb := state.NewStateDB(db.NewMemDB())
	sdb.SetNonce(fromAddr, 1)

	a := &blockReaderAdapter{
		blockStore: bs,
		stateDB:    sdb,
	}

	txHash := block.ComputeTransactionHash(tx)
	got, err := a.GetTransactionReceipt(txHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatalf("expected non-nil receipt for non-create-tx fallback, got nil")
	}
	m, ok := got.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map, got %T", got)
	}
	st, _ := m["status"].(string)
	if st != "0x1" {
		t.Fatalf("R42 non-create-tx fallback regression: expected status=0x1, got %q", st)
	}
}
