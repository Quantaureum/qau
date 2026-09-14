// Quantaureum Node source, version 1.0.0.
package core

import (
	"math/big"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/economics"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// makeValidParentHeader builds a valid parent header for validator tests.
// It lives in a tracked test helper so CI can compile the audited regression
// tests that reference it (the local-only coverage file previously defining
// it is excluded by .gitignore's *_cover* pattern).
func makeValidParentHeader() *encoding.BlockHeader {
	return &encoding.BlockHeader{
		Version:      1,
		Height:       0,
		Slot:         0,
		Epoch:        0,
		Timestamp:    time.Now().Add(-10 * time.Second).Unix(),
		ChainID:      1333,
		ProposerAddr: types.BytesToAddress([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}),
		GasLimit:     30000000, // CONS-R16-001: valid GasLimit for EIP-1559 range check
	}
}

// makeValidChildHeader builds a valid child header from a parent header.
// It lives in a tracked test helper so CI can compile the audited regression
// tests that reference it (the local-only coverage file previously defining
// it is excluded by .gitignore's *_cover* pattern).
func makeValidChildHeader(parent *encoding.BlockHeader, bv *BlockValidator) *encoding.BlockHeader {
	epoch := (parent.Slot + 1) / 32
	vrfValue := types.Hash{0x01}
	return &encoding.BlockHeader{
		Version:        1,
		Height:         parent.Height + 1,
		Slot:           parent.Slot + 1,
		Epoch:          epoch,
		Timestamp:      parent.Timestamp + 12,
		ParentHash:     bv.computeHeaderHash(parent),
		ChainID:        parent.ChainID,
		ProposerAddr:   types.BytesToAddress([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}),
		VRFProof:       []byte{0x01},
		VRFValue:       vrfValue,
		GasLimit:       parent.GasLimit,
		VRFAccumulator: consensus.ComputeNextVRFAccumulator(parent.VRFAccumulator, parent.Epoch, epoch, vrfValue),
		BaseFee:        economics.CalculateNextBaseFee(parent.GasUsed, parent.GasLimit, parent.BaseFee),
	}
}

// mockValidatorLookup implements the ValidatorLookup interface for testing.
type mockValidatorLookup struct {
	pubKey      []byte
	pubKeyErr   error
	isValidator bool
}

func (m *mockValidatorLookup) GetValidatorPublicKey(addr types.Address) ([]byte, error) {
	return m.pubKey, m.pubKeyErr
}

func (m *mockValidatorLookup) IsValidator(addr types.Address) bool {
	return m.isValidator
}

// mockKeyVersionValidator implements the KeyVersionValidator interface for testing.
type mockKeyVersionValidator struct {
	err            error
	currentVersion uint64
}

func (m *mockKeyVersionValidator) ValidateKeyVersion(blockKeyVersion uint64, blockTimestamp int64) error {
	return m.err
}

func (m *mockKeyVersionValidator) GetCurrentKeyVersion() uint64 {
	return m.currentVersion
}

// mockTSSVerifier implements the TSSVerifier interface for testing.
type mockTSSVerifier struct {
	verifyErr   error
	hasGroupKey bool
}

func (m *mockTSSVerifier) VerifyCombinedSignature(signature []byte, message []byte) error {
	return m.verifyErr
}

func (m *mockTSSVerifier) HasGroupPublicKey() bool {
	return m.hasGroupKey
}

// makeValidTx creates a valid transaction for testing.
func makeValidTx(from types.Address, nonce uint64) *encoding.Transaction {
	to := types.BytesToAddress([]byte{2})
	return &encoding.Transaction{
		Version:   1,
		Type:      encoding.TxTypeTransfer,
		Nonce:     nonce,
		From:      from,
		To:        &to,
		Value:     big.NewInt(1000),
		GasLimit:  21000,
		GasPrice:  big.NewInt(1e9),
		ChainID:   1333,
		Signature: []byte{0x01},
	}
}
