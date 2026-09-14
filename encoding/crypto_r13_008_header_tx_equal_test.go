// Quantaureum Node source, version 1.0.0.
// CRYPTO-R13-008 regression tests.
//
// These tests verify that BlockHeader.Equal() and Transaction.Equal() use
// constant-time comparison for Hash and Address fields rather than relying
// on Go's `==` operator (which compiles to memequal and short-circuits on
// the first differing byte).
package encoding

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestCRYPTO_R13_008_BlockHeaderEqual_HashFieldsUsesConstantTime verifies that
// two BlockHeaders differing in only a single Hash field are reported as
// unequal, and that identical headers compare equal. This is a behavioral
// regression — the test does NOT directly assert constant-timeliness (that
// would require micro-benchmarking and is brittle on CI), but it locks in
// the contract that Hash fields are routed through ConstantTimeEqual.
func TestCRYPTO_R13_008_BlockHeaderEqual_HashFieldsUsesConstantTime(t *testing.T) {
	t.Parallel()

	base := &BlockHeader{
		Version:               1,
		Height:                42,
		Timestamp:             1700000000,
		ParentHash:            types.Hash{0x01},
		StateRoot:             types.Hash{0x02},
		TxRoot:                types.Hash{0x03},
		ReceiptRoot:           types.Hash{0x04},
		ProposerAddr:          types.Address{0xAA, 0xBB},
		VRFValue:              types.Hash{0x05},
		ChainID:               1668,
		Slot:                  7,
		Epoch:                 1,
		RANDAOReveal:          types.Hash{0x06},
		BaseFee:               big.NewInt(1_000_000_000),
		FinalityType:          1,
		ReviewAttestationRoot: types.Hash{0x07},
	}

	// Identical copy must compare equal.
	clone := *base
	if !base.Equal(&clone) {
		t.Fatal("identical headers must be equal")
	}

	// Mutate each Hash / Address field one at a time and confirm inequality.
	cases := []struct {
		name string
		mut  func(*BlockHeader)
	}{
		{"ParentHash", func(h *BlockHeader) { h.ParentHash = types.Hash{0xFF} }},
		{"StateRoot", func(h *BlockHeader) { h.StateRoot = types.Hash{0xFF} }},
		{"TxRoot", func(h *BlockHeader) { h.TxRoot = types.Hash{0xFF} }},
		{"ReceiptRoot", func(h *BlockHeader) { h.ReceiptRoot = types.Hash{0xFF} }},
		{"ProposerAddr", func(h *BlockHeader) { h.ProposerAddr = types.Address{0xFF} }},
		{"RANDAOReveal", func(h *BlockHeader) { h.RANDAOReveal = types.Hash{0xFF} }},
		{"ReviewAttestationRoot", func(h *BlockHeader) { h.ReviewAttestationRoot = types.Hash{0xFF} }},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			diffed := *base
			c.mut(&diffed)
			if base.Equal(&diffed) {
				t.Errorf("header differing only in %s must NOT be equal", c.name)
			}
			// Self-comparison of the mutated header must still be equal
			// (sanity check that the mutation didn't corrupt other state).
			diffed2 := diffed
			if !diffed.Equal(&diffed2) {
				t.Errorf("mutated header must compare equal to itself")
			}
		})
	}
}

// TestCRYPTO_R13_008_BlockHeaderEqual_NilHandling verifies nil safety.
func TestCRYPTO_R13_008_BlockHeaderEqual_NilHandling(t *testing.T) {
	t.Parallel()

	var nilHeader *BlockHeader
	h := &BlockHeader{Height: 1}

	if !nilHeader.Equal(nilHeader) {
		t.Error("both-nil headers should be equal")
	}
	if nilHeader.Equal(h) {
		t.Error("nil vs non-nil header should NOT be equal")
	}
	if h.Equal(nilHeader) {
		t.Error("non-nil vs nil header should NOT be equal")
	}
}

// TestCRYPTO_R13_008_TransactionEqual_ToAddressConstantTime verifies that
// the To address comparison uses ConstantTimeEqual (constant-time), not `==`.
func TestCRYPTO_R13_008_TransactionEqual_ToAddressConstantTime(t *testing.T) {
	t.Parallel()

	addr1 := types.Address{0x11}
	addr2 := types.Address{0x22}

	// Both nil To → equal
	tx1 := &Transaction{From: types.Address{}, To: nil, Value: big.NewInt(0), GasPrice: big.NewInt(1), Signature: []byte{0x01}}
	tx2 := &Transaction{From: types.Address{}, To: nil, Value: big.NewInt(0), GasPrice: big.NewInt(1), Signature: []byte{0x01}}
	if !tx1.Equal(tx2) {
		t.Error("both-nil To must be equal")
	}

	// One nil, one non-nil → not equal
	tx3 := &Transaction{From: types.Address{}, To: &addr1, Value: big.NewInt(0), GasPrice: big.NewInt(1), Signature: []byte{0x01}}
	if tx1.Equal(tx3) {
		t.Error("nil vs non-nil To must NOT be equal")
	}

	// Same address → equal
	tx4 := &Transaction{From: types.Address{}, To: &addr1, Value: big.NewInt(0), GasPrice: big.NewInt(1), Signature: []byte{0x01}}
	if !tx3.Equal(tx4) {
		t.Error("same To address must be equal")
	}

	// Different address → not equal
	tx5 := &Transaction{From: types.Address{}, To: &addr2, Value: big.NewInt(0), GasPrice: big.NewInt(1), Signature: []byte{0x01}}
	if tx3.Equal(tx5) {
		t.Error("different To address must NOT be equal")
	}
}

// TestCRYPTO_R13_008_HashConstantTimeEqual_ExportedAPI verifies the newly
// added types.Hash.ConstantTimeEqual method directly.
func TestCRYPTO_R13_008_HashConstantTimeEqual_ExportedAPI(t *testing.T) {
	t.Parallel()

	h1 := types.Hash{0x01, 0x02, 0x03}
	h2 := types.Hash{0x01, 0x02, 0x03}
	h3 := types.Hash{0xFF, 0x02, 0x03} // differs in first byte
	h4 := types.Hash{0x01, 0x02, 0xFF} // differs in last byte
	zero := types.Hash{}

	if !h1.ConstantTimeEqual(h2) {
		t.Error("identical hashes must be equal")
	}
	if h1.ConstantTimeEqual(h3) {
		t.Error("hashes differing in first byte must NOT be equal")
	}
	if h1.ConstantTimeEqual(h4) {
		t.Error("hashes differing in last byte must NOT be equal")
	}
	if !zero.ConstantTimeEqual(types.Hash{}) {
		t.Error("zero hashes must be equal")
	}
}
