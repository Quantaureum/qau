// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// ── FormatBlock tests ──

func TestFormatBlock_Nil(t *testing.T) {
	result := FormatBlock(nil, false)
	if result != nil {
		t.Error("expected nil for nil block")
	}
}

func TestFormatBlock_NilHeader(t *testing.T) {
	blk := &encoding.Block{Header: nil}
	result := FormatBlock(blk, false)
	if result != nil {
		t.Error("expected nil for block with nil header")
	}
}

func TestFormatBlock_ValidBlock(t *testing.T) {
	proposer := types.BytesToAddress([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
	blk := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			Height:       100,
			Timestamp:    1700000000,
			ParentHash:   types.Hash{},
			StateRoot:    types.Hash{},
			TxRoot:       types.Hash{},
			ReceiptRoot:  types.Hash{},
			ProposerAddr: proposer,
			GasLimit:     30000000,
			GasUsed:      21000,
		},
		Transactions: nil,
	}

	result := FormatBlock(blk, false)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Number != "0x64" {
		t.Errorf("expected number 0x64, got %s", result.Number)
	}
	if result.GasLimit != "0x1c9c380" {
		t.Errorf("expected gasLimit 0x1c9c380, got %s", result.GasLimit)
	}
	if result.Miner == "" {
		t.Error("expected non-empty miner")
	}
}

func TestFormatBlock_WithTransactions(t *testing.T) {
	from := types.BytesToAddress(make([]byte, 20))
	to := types.BytesToAddress([]byte{1})
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		Nonce:    1,
		From:     from,
		To:       &to,
		Value:    big.NewInt(1000),
		GasLimit: 21000,
		GasPrice: big.NewInt(1e9),
		Data:     nil,
		ChainID:  1668,
	}

	proposer := types.BytesToAddress([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
	blk := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			Height:       10,
			Timestamp:    1700000000,
			ProposerAddr: proposer,
			GasLimit:     30000000,
			ChainID:      1668,
		},
		Transactions: []*encoding.Transaction{tx},
	}

	// Test with fullTx=true
	result := FormatBlock(blk, true)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result.Transactions) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(result.Transactions))
	}
	txResp, ok := result.Transactions[0].(*TransactionResponse)
	if !ok {
		t.Fatalf("expected TransactionResponse, got %T", result.Transactions[0])
	}
	if txResp.Nonce != "0x1" {
		t.Errorf("expected nonce 0x1, got %s", txResp.Nonce)
	}

	// Test with fullTx=false
	result2 := FormatBlock(blk, false)
	if result2 == nil {
		t.Fatal("expected non-nil result")
	}
	if len(result2.Transactions) != 1 {
		t.Fatalf("expected 1 transaction hash, got %d", len(result2.Transactions))
	}
	hashStr, ok := result2.Transactions[0].(string)
	if !ok {
		t.Fatalf("expected string hash, got %T", result2.Transactions[0])
	}
	if len(hashStr) != 66 {
		t.Errorf("expected 66-char hash (0x + 64 hex), got %d chars", len(hashStr))
	}
}

func TestFormatBlock_WithBaseFee(t *testing.T) {
	proposer := types.BytesToAddress([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
	blk := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			Height:       10,
			Timestamp:    1700000000,
			ProposerAddr: proposer,
			GasLimit:     30000000,
			BaseFee:      big.NewInt(1e9),
		},
	}

	result := FormatBlock(blk, false)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.BaseFeePerGas == "" {
		t.Error("expected non-empty base fee")
	}
}

// ── FormatTransaction tests ──

func TestFormatTransaction_Nil(t *testing.T) {
	result := FormatTransaction(nil, types.Hash{}, 0, 0)
	if result != nil {
		t.Error("expected nil for nil transaction")
	}
}

func TestFormatTransaction_Valid(t *testing.T) {
	from := types.BytesToAddress([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})
	to := types.BytesToAddress([]byte{2})
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeTransfer,
		Nonce:    5,
		From:     from,
		To:       &to,
		Value:    big.NewInt(1e18),
		GasLimit: 21000,
		GasPrice: big.NewInt(1e9),
		Data:     []byte{0x60, 0x80},
		ChainID:  1668,
	}

	blockHash := types.BytesToHash([]byte{0xff})
	result := FormatTransaction(tx, blockHash, 100, 0)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Nonce != "0x5" {
		t.Errorf("expected nonce 0x5, got %s", result.Nonce)
	}
	if result.BlockNumber != "0x64" {
		t.Errorf("expected block number 0x64, got %s", result.BlockNumber)
	}
	if result.Gas != "0x5208" {
		t.Errorf("expected gas 0x5208, got %s", result.Gas)
	}
}

func TestFormatTransaction_ContractCreation(t *testing.T) {
	from := types.BytesToAddress([]byte{1})
	tx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeCreate,
		Nonce:    1,
		From:     from,
		To:       nil, // contract creation
		Value:    big.NewInt(0),
		GasLimit: 53000,
		GasPrice: big.NewInt(1e9),
		Data:     []byte{0x60},
		ChainID:  1668,
	}

	result := FormatTransaction(tx, types.Hash{}, 1, 0)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.To != nil {
		t.Errorf("expected nil 'to' for contract creation, got %v", result.To)
	}
}

func TestFormatTransaction_DynamicFee(t *testing.T) {
	from := types.BytesToAddress([]byte{1})
	to := types.BytesToAddress([]byte{2})
	tx := &encoding.Transaction{
		Version:              1,
		Type:                 encoding.TxTypeDynamicFee,
		Nonce:                1,
		From:                 from,
		To:                   &to,
		Value:                big.NewInt(1000),
		GasLimit:             21000,
		GasPrice:             big.NewInt(1e9),
		MaxFeePerGas:         big.NewInt(2e9),
		MaxPriorityFeePerGas: big.NewInt(1e8),
		Data:                 nil,
		ChainID:              1668,
	}

	result := FormatTransaction(tx, types.Hash{}, 1, 0)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Type != "0x2" {
		t.Errorf("expected type 0x2 for dynamic fee, got %s", result.Type)
	}
	if result.MaxFeePerGas == "" {
		t.Error("expected non-empty max fee per gas")
	}
	if result.MaxPriorityFeePerGas == "" {
		t.Error("expected non-empty max priority fee per gas")
	}
}

func TestFormatTransaction_WithQuantumSignature(t *testing.T) {
	from := types.BytesToAddress([]byte{1})
	to := types.BytesToAddress([]byte{2})

	// Dilithium3 signature: 3293 bytes, public key: 1952 bytes
	sig := make([]byte, 3293)
	pubKey := make([]byte, 1952)
	for i := range sig {
		sig[i] = byte(i % 256)
	}
	for i := range pubKey {
		pubKey[i] = byte(i % 256)
	}

	tx := &encoding.Transaction{
		Version:   1,
		Type:      encoding.TxTypeTransfer,
		Nonce:     1,
		From:      from,
		To:        &to,
		Value:     big.NewInt(1000),
		GasLimit:  21000,
		GasPrice:  big.NewInt(1e9),
		Data:      nil,
		ChainID:   1668,
		Signature: sig,
		PublicKey: pubKey,
	}

	result := FormatTransaction(tx, types.Hash{}, 1, 0)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.SignatureType != "dilithium3" {
		t.Errorf("expected signature type 'dilithium3', got '%s'", result.SignatureType)
	}
	if result.PublicKey == "" {
		t.Error("expected non-empty public key")
	}
	if result.Signature == "" {
		t.Error("expected non-empty signature")
	}
}

// ── Helper function tests ──

func TestFormatHex(t *testing.T) {
	if s := formatHex(0); s != "0x0" {
		t.Errorf("expected 0x0, got %s", s)
	}
	if s := formatHex(16); s != "0x10" {
		t.Errorf("expected 0x10, got %s", s)
	}
}

func TestFormatHashHex(t *testing.T) {
	var h types.Hash
	h[0] = 0x01
	s := formatHashHex(h)
	if len(s) != 66 {
		t.Errorf("expected 66-char hash string, got %d", len(s))
	}
	if s[:2] != "0x" {
		t.Error("expected 0x prefix")
	}
}

func TestFormatAddressHex(t *testing.T) {
	addr := types.BytesToAddress([]byte{0xff})
	s := formatAddressHex(addr)
	if len(s) != 42 {
		t.Errorf("expected 42-char address string, got %d", len(s))
	}
	if s[:2] != "0x" {
		t.Error("expected 0x prefix")
	}
}

func TestFormatBytesHex_Empty(t *testing.T) {
	if s := formatBytesHex(nil); s != "0x" {
		t.Errorf("expected '0x' for nil bytes, got '%s'", s)
	}
	if s := formatBytesHex([]byte{}); s != "0x" {
		t.Errorf("expected '0x' for empty bytes, got '%s'", s)
	}
}

func TestFormatBytesHex_NonEmpty(t *testing.T) {
	if s := formatBytesHex([]byte{0x60, 0x80}); s != "0x6080" {
		t.Errorf("expected '0x6080', got '%s'", s)
	}
}
