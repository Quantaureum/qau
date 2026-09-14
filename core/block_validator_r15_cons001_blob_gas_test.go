// Quantaureum Node source, version 1.0.0.
package core

import (
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// CONS-R15-001 (2026-07-22): EIP-4844 blob gas validation tests.
//
// ValidateHeader must reject:
//  1. BlobGasUsed > MaxBlobsPerBlock * BlobGasPerBlob
//  2. ExcessBlobGas != CalcExcessBlobGas(parent.ExcessBlobGas, parent.BlobGasUsed)
//
// validateTransactions must reject:
//  3. Blob tx with nil/zero MaxFeePerBlobGas
//  4. Blob tx MaxFeePerBlobGas < CalcBlobFee(header.ExcessBlobGas)
//
// Genesis (Height=0) is exempt from header-level checks.
//
// NOTE: ValidateBlock runs many checks (signature, state root, etc.) that
// require a fully configured validator. These tests isolate the blob gas
// checks by asserting ONLY on ErrInvalidBlob* errors. A nil error or an
// unrelated error means the blob check passed.

// fakeBlobTx returns a blob transaction with a non-empty signature so it
// passes tx.Validate() (which requires len(Signature) > 0). The
// signingVerifier is nil in these tests, so the signature is not
// cryptographically verified.
// CONS-R18-CRIT-01 (2026-07-24): Updated to include MaxFeePerGas/
// MaxPriorityFeePerGas (Transaction.Validate now requires these for
// TxTypeBlob per EIP-1559/4844 validation). Removed GasPrice (blob txs
// use dynamic fee fields, not legacy GasPrice).
func fakeBlobTx(maxFee *big.Int) *encoding.Transaction {
	to := types.BytesToAddress([]byte{1})
	return &encoding.Transaction{
		Type:                 encoding.TxTypeBlob,
		Nonce:                1,
		ChainID:              1333,
		GasLimit:             100000,
		MaxFeePerGas:         big.NewInt(1e9), // 1 Gwei — above any reasonable BaseFee
		MaxPriorityFeePerGas: big.NewInt(1),   // 1 wei
		To:                   &to,
		BlobVersionedHashes:  []types.Hash{{0x01}},
		MaxFeePerBlobGas:     maxFee,
		Signature:            []byte{0x01}, // non-empty to pass tx.Validate()
	}
}

func TestCONS_R15_001_ZeroBlobGasValid(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := makeValidParentHeader()
	child := makeValidChildHeader(parent, bv)
	// Defaults: BlobGasUsed=0, ExcessBlobGas=0 → consistent with parent(0,0).
	block := &encoding.Block{Header: child, Transactions: nil}
	_, _, err := bv.ValidateBlock(block, parent)
	// Other checks may fail (signature, state root), but blob gas must NOT.
	if errors.Is(err, ErrInvalidBlobGasUsed) || errors.Is(err, ErrInvalidExcessBlobGas) {
		t.Errorf("zero blob gas should be valid, got %v", err)
	}
}

func TestCONS_R15_001_BlobGasUsedExceedsLimit(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := makeValidParentHeader()
	child := makeValidChildHeader(parent, bv)
	child.BlobGasUsed = uint64(encoding.MaxBlobsPerBlock)*uint64(encoding.BlobGasPerBlob) + 1

	block := &encoding.Block{Header: child, Transactions: nil}
	_, _, err := bv.ValidateBlock(block, parent)
	if !errors.Is(err, ErrInvalidBlobGasUsed) {
		t.Errorf("expected ErrInvalidBlobGasUsed, got %v", err)
	}
}

func TestCONS_R15_001_BlobGasUsedAtLimit(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := makeValidParentHeader()
	child := makeValidChildHeader(parent, bv)
	child.BlobGasUsed = uint64(encoding.MaxBlobsPerBlock) * uint64(encoding.BlobGasPerBlob)
	child.ExcessBlobGas = encoding.CalcExcessBlobGas(parent.ExcessBlobGas, parent.BlobGasUsed)

	// CONS-R18-H01 (2026-07-24): Block-level blob gas accounting requires
	// the header BlobGasUsed to match the actual blob count in transactions.
	// Add MaxBlobsPerBlock (6) blob txs, each with 1 blob hash, so
	// actualBlobCount=6 and expectedBlobGasUsed=6*BlobGasPerBlob=786432.
	txs := make([]*encoding.Transaction, 0, encoding.MaxBlobsPerBlock)
	for i := 0; i < encoding.MaxBlobsPerBlock; i++ {
		tx := fakeBlobTx(big.NewInt(1e18)) // high MaxFeePerBlobGas to pass blob fee check
		tx.Nonce = uint64(i + 1)           // unique nonce to avoid duplicate hash rejection
		// Unique blob hash per tx to avoid duplicate tx hash.
		tx.BlobVersionedHashes = []types.Hash{{byte(i + 1)}}
		txs = append(txs, tx)
	}
	block := &encoding.Block{Header: child, Transactions: txs}
	_, _, err := bv.ValidateBlock(block, parent)
	if errors.Is(err, ErrInvalidBlobGasUsed) {
		t.Errorf("BlobGasUsed at limit should be accepted, got %v", err)
	}
}

func TestCONS_R15_001_ExcessBlobGasMismatch(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := makeValidParentHeader()
	parent.ExcessBlobGas = 100000
	parent.BlobGasUsed = 200000

	child := makeValidChildHeader(parent, bv)
	expected := encoding.CalcExcessBlobGas(parent.ExcessBlobGas, parent.BlobGasUsed)
	child.ExcessBlobGas = expected + 1 // intentionally wrong

	block := &encoding.Block{Header: child, Transactions: nil}
	_, _, err := bv.ValidateBlock(block, parent)
	if !errors.Is(err, ErrInvalidExcessBlobGas) {
		t.Errorf("expected ErrInvalidExcessBlobGas, got %v", err)
	}
}

func TestCONS_R15_001_ExcessBlobGasCorrect(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := makeValidParentHeader()
	target := uint64(encoding.TargetBlobsPerBlock) * encoding.BlobGasPerBlob
	parent.ExcessBlobGas = target + 50000
	parent.BlobGasUsed = encoding.BlobGasPerBlob

	child := makeValidChildHeader(parent, bv)
	child.ExcessBlobGas = encoding.CalcExcessBlobGas(parent.ExcessBlobGas, parent.BlobGasUsed)
	child.BlobGasUsed = 0

	block := &encoding.Block{Header: child, Transactions: nil}
	_, _, err := bv.ValidateBlock(block, parent)
	if errors.Is(err, ErrInvalidExcessBlobGas) {
		t.Errorf("correct ExcessBlobGas should be accepted, got %v", err)
	}
}

func TestCONS_R15_001_GenesisExemptFromBlobChecks(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	genesis := &encoding.BlockHeader{
		Version:      1,
		Height:       0,
		Slot:         0,
		Epoch:        0,
		Timestamp:    time.Now().Unix(),
		ChainID:      1333,
		ProposerAddr: types.BytesToAddress([]byte{1, 2, 3, 4}),
		BlobGasUsed:  999999999, // would fail if checked
	}
	parent := &encoding.BlockHeader{Height: 0, ChainID: 1333}
	err := bv.ValidateHeader(genesis, parent)
	if errors.Is(err, ErrInvalidBlobGasUsed) || errors.Is(err, ErrInvalidExcessBlobGas) {
		t.Errorf("genesis should be exempt from blob gas checks, got %v", err)
	}
}

func TestCONS_R15_001_BlobTxNilMaxFee(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	// R37 FIX (2026-07-31): R37 P2-CORE-02 moved the block signature gate
	// BEFORE validateTransactions, so reaching the blob max fee check now
	// requires passing the signature gate first (mock lookup + dev mode +
	// correctly-sized signature), same pattern as cons_r12_003 tests.
	bv.SetValidatorLookup(&mockValidatorLookup{isValidator: true})
	bv.SetDevMode(true)
	parent := makeValidParentHeader()
	child := makeValidChildHeader(parent, bv)
	child.Signature = make([]byte, crypto.Dilithium3SignatureSize)
	child.ExcessBlobGas = encoding.CalcExcessBlobGas(parent.ExcessBlobGas, parent.BlobGasUsed)

	tx := fakeBlobTx(nil) // nil MaxFeePerBlobGas
	block := &encoding.Block{Header: child, Transactions: []*encoding.Transaction{tx}}
	_, _, err := bv.ValidateBlock(block, parent)
	if !errors.Is(err, ErrInvalidBlobMaxFee) {
		t.Errorf("expected ErrInvalidBlobMaxFee for nil MaxFeePerBlobGas, got %v", err)
	}
}

func TestCONS_R15_001_BlobTxMaxFeeBelowBase(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	// R37 FIX (2026-07-31): see TestCONS_R15_001_BlobTxNilMaxFee — the
	// signature gate now runs before validateTransactions (R37 P2-CORE-02).
	bv.SetValidatorLookup(&mockValidatorLookup{isValidator: true})
	bv.SetDevMode(true)
	parent := makeValidParentHeader()
	target := uint64(encoding.TargetBlobsPerBlock) * encoding.BlobGasPerBlob
	parent.ExcessBlobGas = target * 10 // large excess → non-trivial blob fee
	parent.BlobGasUsed = 0

	child := makeValidChildHeader(parent, bv)
	child.Signature = make([]byte, crypto.Dilithium3SignatureSize)
	child.ExcessBlobGas = encoding.CalcExcessBlobGas(parent.ExcessBlobGas, parent.BlobGasUsed)

	blobBaseFee := encoding.CalcBlobFee(child.ExcessBlobGas)
	if blobBaseFee.Sign() <= 0 {
		t.Fatalf("expected non-zero blob base fee, got %s", blobBaseFee.String())
	}

	lowFee := new(big.Int).Sub(blobBaseFee, big.NewInt(1))
	if lowFee.Sign() < 0 {
		lowFee = big.NewInt(0)
	}
	tx := fakeBlobTx(lowFee)
	block := &encoding.Block{Header: child, Transactions: []*encoding.Transaction{tx}}
	_, _, err := bv.ValidateBlock(block, parent)
	if !errors.Is(err, ErrInvalidBlobMaxFee) {
		t.Errorf("expected ErrInvalidBlobMaxFee for fee below base, got %v", err)
	}
}

func TestCONS_R15_001_BlobTxMaxFeeAtBase(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	parent := makeValidParentHeader()
	target := uint64(encoding.TargetBlobsPerBlock) * encoding.BlobGasPerBlob
	parent.ExcessBlobGas = target * 10
	parent.BlobGasUsed = 0

	child := makeValidChildHeader(parent, bv)
	child.ExcessBlobGas = encoding.CalcExcessBlobGas(parent.ExcessBlobGas, parent.BlobGasUsed)

	blobBaseFee := encoding.CalcBlobFee(child.ExcessBlobGas)
	tx := fakeBlobTx(blobBaseFee) // exactly equal — must be accepted (>=)
	block := &encoding.Block{Header: child, Transactions: []*encoding.Transaction{tx}}
	_, _, err := bv.ValidateBlock(block, parent)
	if errors.Is(err, ErrInvalidBlobMaxFee) {
		t.Errorf("MaxFee == baseFee should be accepted (>=), got %v", err)
	}
}
