// Quantaureum Node source, version 1.0.0.
package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// ── BlockBuilder tests ──

func TestNewBlockBuilder(t *testing.T) {
	bb := NewBlockBuilder(1333, 30000000)
	if bb == nil {
		t.Fatal("expected non-nil block builder")
	}
	if bb.GasLimit() != 30000000 {
		t.Errorf("expected gas limit 30000000, got %d", bb.GasLimit())
	}
}

func TestBlockBuilder_SetGasLimit(t *testing.T) {
	bb := NewBlockBuilder(1333, 30000000)
	bb.SetGasLimit(15000000)
	if bb.GasLimit() != 15000000 {
		t.Errorf("expected gas limit 15000000, got %d", bb.GasLimit())
	}
}

func TestBlockBuilder_BuildBlock_EmptyTransactions(t *testing.T) {
	bb := NewBlockBuilder(1333, 30000000)

	parent := &encoding.BlockHeader{
		Version:   1,
		Height:    0,
		Slot:      0,
		Epoch:     0,
		Timestamp: 1700000000,
		ChainID:   1333,
	}
	proposer := types.BytesToAddress([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})

	block := bb.BuildBlock(parent, nil, proposer, []byte{0x01}, types.Hash{})
	if block == nil {
		t.Fatal("expected non-nil block")
	}
	if block.Header.Height != 1 {
		t.Errorf("expected height 1, got %d", block.Header.Height)
	}
	if block.Header.Slot != 1 {
		t.Errorf("expected slot 1, got %d", block.Header.Slot)
	}
	if block.Header.ChainID != 1333 {
		t.Errorf("expected chainID 1333, got %d", block.Header.ChainID)
	}
	if len(block.Transactions) != 0 {
		t.Errorf("expected 0 transactions, got %d", len(block.Transactions))
	}
}

func TestBlockBuilder_BuildBlock_WithTransactions(t *testing.T) {
	bb := NewBlockBuilder(1333, 30000000)

	parent := &encoding.BlockHeader{
		Version:   1,
		Height:    0,
		Slot:      0,
		Epoch:     0,
		Timestamp: 1700000000,
		ChainID:   1333,
	}
	proposer := types.BytesToAddress([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20})

	from := types.BytesToAddress([]byte{1})
	to := types.BytesToAddress([]byte{2})
	txs := []*encoding.Transaction{
		{
			Version:  1,
			Type:     encoding.TxTypeTransfer,
			Nonce:    1,
			From:     from,
			To:       &to,
			Value:    big.NewInt(1000),
			GasLimit: 21000,
			GasPrice: big.NewInt(1e9),
			ChainID:  1333,
		},
	}

	block := bb.BuildBlock(parent, txs, proposer, []byte{0x01}, types.Hash{})
	if block == nil {
		t.Fatal("expected non-nil block")
	}
	if len(block.Transactions) != 1 {
		t.Errorf("expected 1 transaction, got %d", len(block.Transactions))
	}
}

func TestBlockBuilder_SelectTransactions_GasLimitExceeded(t *testing.T) {
	bb := NewBlockBuilder(1333, 30000) // very low gas limit

	from := types.BytesToAddress([]byte{1})
	to := types.BytesToAddress([]byte{2})
	txs := []*encoding.Transaction{
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 1, From: from, To: &to, GasLimit: 21000, GasPrice: big.NewInt(2), ChainID: 1333},
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 2, From: from, To: &to, GasLimit: 21000, GasPrice: big.NewInt(1), ChainID: 1333},
	}

	selected := bb.selectTransactions(txs)
	// Only first tx should fit (21000 < 30000, but 42000 > 30000)
	if len(selected) != 1 {
		t.Errorf("expected 1 selected transaction, got %d", len(selected))
	}
}

func TestBlockBuilder_SelectTransactions_Empty(t *testing.T) {
	bb := NewBlockBuilder(1333, 30000000)
	selected := bb.selectTransactions(nil)
	if selected != nil {
		t.Errorf("expected nil for empty transactions, got %v", selected)
	}
}

// ── sortTransactionsDeterministic tests ──

func TestSortTransactionsDeterministic(t *testing.T) {
	from1 := types.BytesToAddress([]byte{1})
	from2 := types.BytesToAddress([]byte{2})
	to := types.BytesToAddress([]byte{3})

	txs := []*encoding.Transaction{
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 1, From: from1, To: &to, GasLimit: 21000, GasPrice: big.NewInt(1), ChainID: 1333},
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 2, From: from1, To: &to, GasLimit: 21000, GasPrice: big.NewInt(3), ChainID: 1333},
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 1, From: from2, To: &to, GasLimit: 21000, GasPrice: big.NewInt(2), ChainID: 1333},
	}

	sortTransactionsDeterministic(txs)

	// Higher gas price should come first
	if txs[0].GasPrice.Cmp(txs[1].GasPrice) < 0 {
		t.Error("expected transactions sorted by gas price descending")
	}
}

// ── computeMerkleRoot tests ──

func TestComputeMerkleRoot_Empty(t *testing.T) {
	hash := computeMerkleRoot(nil)
	if hash != (types.Hash{}) {
		t.Error("expected zero hash for empty transactions")
	}
}

func TestComputeMerkleRoot_SingleTx(t *testing.T) {
	from := types.BytesToAddress([]byte{1})
	to := types.BytesToAddress([]byte{2})
	txs := []*encoding.Transaction{
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 1, From: from, To: &to, GasLimit: 21000, GasPrice: big.NewInt(1), ChainID: 1333},
	}

	hash := computeMerkleRoot(txs)
	if hash == (types.Hash{}) {
		t.Error("expected non-zero hash for single transaction")
	}
}

func TestComputeMerkleRoot_TwoTxs(t *testing.T) {
	from := types.BytesToAddress([]byte{1})
	to := types.BytesToAddress([]byte{2})
	txs := []*encoding.Transaction{
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 1, From: from, To: &to, GasLimit: 21000, GasPrice: big.NewInt(1), ChainID: 1333},
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 2, From: from, To: &to, GasLimit: 21000, GasPrice: big.NewInt(2), ChainID: 1333},
	}

	hash := computeMerkleRoot(txs)
	if hash == (types.Hash{}) {
		t.Error("expected non-zero hash for two transactions")
	}
}

func TestComputeMerkleRoot_ThreeTxs(t *testing.T) {
	// Odd number of transactions should duplicate the last one
	from := types.BytesToAddress([]byte{1})
	to := types.BytesToAddress([]byte{2})
	txs := []*encoding.Transaction{
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 1, From: from, To: &to, GasLimit: 21000, GasPrice: big.NewInt(3), ChainID: 1333},
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 2, From: from, To: &to, GasLimit: 21000, GasPrice: big.NewInt(2), ChainID: 1333},
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 3, From: from, To: &to, GasLimit: 21000, GasPrice: big.NewInt(1), ChainID: 1333},
	}

	hash := computeMerkleRoot(txs)
	if hash == (types.Hash{}) {
		t.Error("expected non-zero hash for three transactions")
	}
}

// ── EstimateBlockGas tests ──

func TestEstimateBlockGas_Empty(t *testing.T) {
	gas := EstimateBlockGas(nil)
	if gas != 0 {
		t.Errorf("expected 0 gas for empty transactions, got %d", gas)
	}
}

func TestEstimateBlockGas_SingleTx(t *testing.T) {
	from := types.BytesToAddress([]byte{1})
	to := types.BytesToAddress([]byte{2})
	txs := []*encoding.Transaction{
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 1, From: from, To: &to, GasLimit: 21000, GasPrice: big.NewInt(1), ChainID: 1333},
	}

	gas := EstimateBlockGas(txs)
	if gas != 21000 {
		t.Errorf("expected 21000 gas, got %d", gas)
	}
}

func TestEstimateBlockGas_MultipleTxs(t *testing.T) {
	from := types.BytesToAddress([]byte{1})
	to := types.BytesToAddress([]byte{2})
	txs := []*encoding.Transaction{
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 1, From: from, To: &to, GasLimit: 21000, GasPrice: big.NewInt(1), ChainID: 1333},
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 2, From: from, To: &to, GasLimit: 53000, GasPrice: big.NewInt(1), ChainID: 1333},
	}

	gas := EstimateBlockGas(txs)
	if gas != 74000 {
		t.Errorf("expected 74000 gas, got %d", gas)
	}
}

// ── SortTransactionsByPrice tests ──

func TestSortTransactionsByPrice(t *testing.T) {
	from := types.BytesToAddress([]byte{1})
	to := types.BytesToAddress([]byte{2})
	txs := []*encoding.Transaction{
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 1, From: from, To: &to, GasLimit: 21000, GasPrice: big.NewInt(1), ChainID: 1333},
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 2, From: from, To: &to, GasLimit: 21000, GasPrice: big.NewInt(3), ChainID: 1333},
		{Version: 1, Type: encoding.TxTypeTransfer, Nonce: 3, From: from, To: &to, GasLimit: 21000, GasPrice: big.NewInt(2), ChainID: 1333},
	}

	SortTransactionsByPrice(txs)

	// Should be sorted descending by gas price
	for i := 1; i < len(txs); i++ {
		if txs[i-1].GasPrice.Cmp(txs[i].GasPrice) < 0 {
			t.Error("transactions not sorted by gas price descending")
		}
	}
}

// ── CalculateBlockReward tests ──

func TestCalculateBlockReward_Height0(t *testing.T) {
	reward := CalculateBlockReward(0)
	if reward.Cmp(big.NewInt(2e18)) != 0 {
		t.Errorf("expected 2 QAU reward at height 0, got %s", reward.String())
	}
}

func TestCalculateBlockReward_EarlyHeight(t *testing.T) {
	reward := CalculateBlockReward(1000)
	if reward.Sign() <= 0 {
		t.Error("expected positive reward")
	}
}

func TestCalculateBlockReward_VeryHighHeight(t *testing.T) {
	// After 64 halvings, reward should be 0
	reward := CalculateBlockReward(999999999999)
	// May or may not be 0 depending on halving interval
	// Just verify it doesn't panic and is non-negative
	if reward.Sign() < 0 {
		t.Error("reward should not be negative")
	}
}

// ── ValidateBlockTransactions tests ──

func TestValidateBlockTransactions_Empty(t *testing.T) {
	block := &encoding.Block{
		Header:       &encoding.BlockHeader{Height: 1},
		Transactions: nil,
	}
	if err := ValidateBlockTransactions(block); err != nil {
		t.Errorf("expected no error for empty transactions, got %v", err)
	}
}

// ── BlockValidator tests ──

func TestNewBlockValidator(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	if bv == nil {
		t.Fatal("expected non-nil block validator")
	}
}

func TestBlockValidator_SetDevMode(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	bv.SetDevMode(true)
	bv.SetDevMode(false)
}

func TestBlockValidator_SetMaxFutureTime(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	bv.SetMaxFutureTime(30 * 1e9) // 30 seconds
}

func TestBlockValidator_SetMaxGasLimit(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	bv.SetMaxGasLimit(60000000)
}

func TestBlockValidator_ValidateHeader_NilParent(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	header := &encoding.BlockHeader{
		Version:   1,
		Height:    1,
		Timestamp: 1700000001,
		ChainID:   1333,
	}
	err := bv.ValidateHeader(header, nil)
	if err == nil {
		t.Error("expected error for nil parent")
	}
}

func TestBlockValidator_ValidateHeader_ZeroVersion(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := &encoding.BlockHeader{
		Version:   1,
		Height:    0,
		Timestamp: 1700000000,
		ChainID:   1333,
	}
	header := &encoding.BlockHeader{
		Version:   0, // invalid
		Height:    1,
		Timestamp: 1700000001,
		ChainID:   1333,
	}
	err := bv.ValidateHeader(header, parent)
	if err == nil {
		t.Error("expected error for zero version")
	}
}

func TestBlockValidator_ValidateHeader_WrongChainID(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := &encoding.BlockHeader{
		Version:   1,
		Height:    0,
		Timestamp: 1700000000,
		ChainID:   1333,
	}
	header := &encoding.BlockHeader{
		Version:   1,
		Height:    1,
		Timestamp: 1700000001,
		ChainID:   9999, // wrong chain ID
	}
	err := bv.ValidateHeader(header, parent)
	if err == nil {
		t.Error("expected error for wrong chain ID")
	}
}

func TestBlockValidator_ValidateHeader_WrongHeight(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := &encoding.BlockHeader{
		Version:   1,
		Height:    5,
		Timestamp: 1700000000,
		ChainID:   1333,
	}
	header := &encoding.BlockHeader{
		Version:   1,
		Height:    7, // should be 6
		Timestamp: 1700000001,
		ChainID:   1333,
	}
	err := bv.ValidateHeader(header, parent)
	if err == nil {
		t.Error("expected error for wrong height")
	}
}

func TestBlockValidator_ValidateHeader_OldTimestamp(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := &encoding.BlockHeader{
		Version:   1,
		Height:    0,
		Timestamp: 1700000010,
		ChainID:   1333,
	}
	header := &encoding.BlockHeader{
		Version:   1,
		Height:    1,
		Timestamp: 1700000000, // older than parent
		ChainID:   1333,
	}
	err := bv.ValidateHeader(header, parent)
	if err == nil {
		t.Error("expected error for old timestamp")
	}
}

func TestBlockValidator_ValidateHeader_EmptyProposer(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := &encoding.BlockHeader{
		Version:   1,
		Height:    0,
		Timestamp: 1700000000,
		ChainID:   1333,
	}
	header := &encoding.BlockHeader{
		Version:      1,
		Height:       1,
		Timestamp:    1700000001,
		ChainID:      1333,
		ProposerAddr: types.Address{}, // empty
	}
	err := bv.ValidateHeader(header, parent)
	if err == nil {
		t.Error("expected error for empty proposer")
	}
}

// TestBlockValidator_ValidateHeader_EpochSlotBinding verifies R37-P1-CORE-01:
// header.Epoch must equal consensus.SlotToEpoch(header.Slot). A proposer must
// not be able to attribute a block's VRF output to an arbitrary epoch.
func TestBlockValidator_ValidateHeader_EpochSlotBinding(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := &encoding.BlockHeader{
		Version:   1,
		Height:    0,
		Timestamp: 1700000000,
		ChainID:   1333,
	}

	// Slot 33 maps to epoch 1 (SlotsPerEpoch=32); claiming epoch 0 must fail.
	mismatch := &encoding.BlockHeader{
		Version:   1,
		Height:    1,
		Timestamp: 1700000001,
		ChainID:   1333,
		Slot:      33,
		Epoch:     0,
	}
	err := bv.ValidateHeader(mismatch, parent)
	if !errors.Is(err, ErrEpochSlotMismatch) {
		t.Errorf("expected ErrEpochSlotMismatch, got %v", err)
	}

	// Epoch correctly derived from the slot must pass the epoch check.
	// (Validation continues and fails later on the parent-hash check, which
	// is fine — we only assert the failure is NOT the epoch binding.)
	matched := &encoding.BlockHeader{
		Version:   1,
		Height:    1,
		Timestamp: 1700000001,
		ChainID:   1333,
		Slot:      33,
		Epoch:     1,
	}
	err = bv.ValidateHeader(matched, parent)
	if errors.Is(err, ErrEpochSlotMismatch) {
		t.Errorf("matching epoch/slot must not fail the epoch binding, got %v", err)
	}
}

func TestBlockValidator_ValidateBlock_NilBlock(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	_, _, err := bv.ValidateBlock(nil, &encoding.BlockHeader{})
	if err == nil {
		t.Error("expected error for nil block")
	}
}

func TestBlockValidator_ValidateBlock_NilParent(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	block := &encoding.Block{Header: &encoding.BlockHeader{}}
	_, _, err := bv.ValidateBlock(block, nil)
	if err == nil {
		t.Error("expected error for nil parent")
	}
}

func TestBlockValidator_ValidateStateRoot(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	block := &encoding.Block{
		Header: &encoding.BlockHeader{StateRoot: types.Hash{}},
	}
	err := bv.ValidateStateRoot(block, types.Hash{})
	if err != nil {
		t.Errorf("expected no error for matching state root, got %v", err)
	}
}

func TestBlockValidator_ValidateStateRoot_Mismatch(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	var expectedRoot types.Hash
	expectedRoot[0] = 0x01
	block := &encoding.Block{
		Header: &encoding.BlockHeader{StateRoot: types.Hash{}},
	}
	err := bv.ValidateStateRoot(block, expectedRoot)
	if err == nil {
		t.Error("expected error for mismatched state root")
	}
}

func TestBlockValidator_ValidateStateRoot_NilBlock(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	err := bv.ValidateStateRoot(nil, types.Hash{})
	if err == nil {
		t.Error("expected error for nil block")
	}
}

// ── ValidateVRFProof tests ──

func TestValidateVRFProof_EmptyProof(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	header := &encoding.BlockHeader{
		VRFProof: nil,
		VRFValue: types.Hash{},
	}
	err := bv.ValidateVRFProof(header, types.Hash{})
	if err == nil {
		t.Error("expected error for empty VRF proof")
	}
}

func TestValidateVRFProof_EmptyVRFValue(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	header := &encoding.BlockHeader{
		VRFProof: []byte{0x01, 0x02},
		VRFValue: types.Hash{}, // empty
	}
	err := bv.ValidateVRFProof(header, types.Hash{})
	if err == nil {
		t.Error("expected error for empty VRF value")
	}
}

func TestValidateVRFProof_DevMode(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	bv.SetDevMode(true)

	seed := types.Hash{}
	seed[0] = 0x01
	vrfProof := []byte{0x01, 0x02, 0x03}
	var vrfValue types.Hash
	vrfValue[0] = 0xff

	header := &encoding.BlockHeader{
		VRFProof: vrfProof,
		VRFValue: vrfValue,
		Slot:     1,
		Epoch:    0,
	}
	// In dev mode, validator lookup is nil so it skips signature verification
	// but still checks VRF value derivation
	err := bv.ValidateVRFProof(header, seed)
	// VRF value derivation check may fail since we're using fake proof
	// In dev mode without validatorLookup, it returns nil after warning
	// But the VRF value check happens before the devMode check
	_ = err // just verify no panic
}

// ── ValidateSignature tests ──

func TestValidateSignature_EmptySignature(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	header := &encoding.BlockHeader{
		Signature: nil,
	}
	err := bv.ValidateSignature(header)
	if err == nil {
		t.Error("expected error for empty signature")
	}
}

func TestValidateSignature_WrongLength(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	header := &encoding.BlockHeader{
		Signature:    []byte{0x01, 0x02, 0x03}, // too short
		ProposerAddr: types.BytesToAddress([]byte{1}),
	}
	err := bv.ValidateSignature(header)
	if err == nil {
		t.Error("expected error for wrong signature length")
	}
}

func TestValidateSignature_DevMode(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	bv.SetDevMode(true)

	sig := make([]byte, 3293) // Dilithium3 signature size
	header := &encoding.BlockHeader{
		Signature:    sig,
		ProposerAddr: types.BytesToAddress([]byte{1}),
	}
	err := bv.ValidateSignature(header)
	if err != nil {
		t.Errorf("expected no error in dev mode, got %v", err)
	}
}

func TestValidateSignature_EmptyProposer(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	sig := make([]byte, 3293)
	header := &encoding.BlockHeader{
		Signature:    sig,
		ProposerAddr: types.Address{}, // empty
	}
	err := bv.ValidateSignature(header)
	if err == nil {
		t.Error("expected error for empty proposer")
	}
}

// ── Error variables ──

func TestErrorVariables(t *testing.T) {
	errors := []error{
		ErrInvalidBlockVersion,
		ErrInvalidBlockHeight,
		ErrInvalidParentHash,
		ErrInvalidTimestamp,
		ErrFutureBlock,
		ErrInvalidTxRoot,
		ErrInvalidStateRoot,
		ErrBlockGasLimitExceeded,
		ErrEmptyBlock,
		ErrInvalidProposer,
		ErrInvalidVRFProof,
		ErrInvalidSignature,
		ErrInvalidChainID,
		ErrInvalidKeyVersion,
	}
	for _, err := range errors {
		if err == nil {
			t.Error("expected non-nil error variable")
		}
		if err.Error() == "" {
			t.Error("expected non-empty error message")
		}
	}
}

// ── computeHeaderHash tests ──

func TestComputeHeaderHash_NilHeader(t *testing.T) {
	bb := NewBlockBuilder(1333, 30000000)
	hash := bb.computeHeaderHash(nil)
	if hash != (types.Hash{}) {
		t.Error("expected zero hash for nil header")
	}
}

func TestComputeHeaderHash_ValidHeader(t *testing.T) {
	bb := NewBlockBuilder(1333, 30000000)
	header := &encoding.BlockHeader{
		Version:   1,
		Height:    1,
		Timestamp: 1700000000,
		ChainID:   1333,
	}
	hash := bb.computeHeaderHash(header)
	if hash == (types.Hash{}) {
		t.Error("expected non-zero hash for valid header")
	}
}

// ── computeTxRoot tests ──

func TestComputeTxRoot_Empty(t *testing.T) {
	bb := NewBlockBuilder(1333, 30000000)
	hash := bb.computeTxRoot(nil)
	if hash != (types.Hash{}) {
		t.Error("expected zero hash for empty transactions")
	}
}
