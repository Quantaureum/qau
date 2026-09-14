// Quantaureum Node source, version 1.0.0.
package core

import (
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// TestCONS_R12003_ValidateBlock_ReturnsBothValidators verifies that
// ValidateBlock now returns BOTH the stateRootValidator AND the
// receiptRootValidator (previously receiptRootValidator was discarded with
// `_ =`).
//
// CONS-R12-003 (2026-07-20): The asymmetric API — returning only the state
// validator while discarding the receipt validator — meant callers could
// easily forget to verify the ReceiptRoot. The fix returns both as a pair,
// making the API symmetric.
func TestCONS_R12003_ValidateBlock_ReturnsBothValidators(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	bv.SetValidatorLookup(&mockValidatorLookup{isValidator: true})
	bv.SetDevMode(true)

	parent := makeValidParentHeader()
	child := makeValidChildHeader(parent, bv)
	child.Signature = make([]byte, crypto.Dilithium3SignatureSize)
	child.StateRoot = types.Hash{0xAA}
	child.ReceiptRoot = types.Hash{0xBB}

	block := &encoding.Block{
		Header:       child,
		Transactions: nil,
	}

	stateVal, receiptVal, err := bv.ValidateBlock(block, parent)
	if err != nil {
		t.Fatalf("ValidateBlock failed: %v", err)
	}
	if stateVal == nil {
		t.Fatal("stateRootValidator should not be nil")
	}
	if receiptVal == nil {
		t.Fatal("receiptRootValidator should not be nil — CONS-R12-003 requires it to be returned")
	}
}

// TestCONS_R12003_ReceiptValidator_RejectsMismatch verifies that the
// returned receiptValidator actually rejects a mismatched receipt root.
func TestCONS_R12003_ReceiptValidator_RejectsMismatch(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	bv.SetValidatorLookup(&mockValidatorLookup{isValidator: true})
	bv.SetDevMode(true)

	parent := makeValidParentHeader()
	child := makeValidChildHeader(parent, bv)
	child.Signature = make([]byte, crypto.Dilithium3SignatureSize)
	headerReceiptRoot := types.Hash{0xBB}
	child.StateRoot = types.Hash{0xAA}
	child.ReceiptRoot = headerReceiptRoot

	block := &encoding.Block{
		Header:       child,
		Transactions: nil,
	}

	_, receiptVal, err := bv.ValidateBlock(block, parent)
	if err != nil {
		t.Fatalf("ValidateBlock failed: %v", err)
	}

	// Computed receipt root that doesn't match the header.
	computed := types.Hash{0xCC}
	err = receiptVal(computed)
	if err == nil {
		t.Fatal("receiptValidator should reject mismatched receipt root")
	}
}

// TestCONS_R12003_ReceiptValidator_AcceptsMatch verifies that the
// returned receiptValidator accepts a matching receipt root.
func TestCONS_R12003_ReceiptValidator_AcceptsMatch(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	bv.SetValidatorLookup(&mockValidatorLookup{isValidator: true})
	bv.SetDevMode(true)

	parent := makeValidParentHeader()
	child := makeValidChildHeader(parent, bv)
	child.Signature = make([]byte, crypto.Dilithium3SignatureSize)
	headerReceiptRoot := types.Hash{0xBB}
	child.StateRoot = types.Hash{0xAA}
	child.ReceiptRoot = headerReceiptRoot

	block := &encoding.Block{
		Header:       child,
		Transactions: nil,
	}

	_, receiptVal, err := bv.ValidateBlock(block, parent)
	if err != nil {
		t.Fatalf("ValidateBlock failed: %v", err)
	}

	// Same as header — should pass.
	err = receiptVal(headerReceiptRoot)
	if err != nil {
		t.Fatalf("receiptValidator should accept matching receipt root, got: %v", err)
	}
}

// TestCONS_R12003_ReceiptValidator_RejectsZeroReceiptRoot verifies that a
// zero ReceiptRoot (non-genesis block) is rejected.
func TestCONS_R12003_ReceiptValidator_RejectsZeroReceiptRoot(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	bv.SetValidatorLookup(&mockValidatorLookup{isValidator: true})
	bv.SetDevMode(true)

	parent := makeValidParentHeader()
	child := makeValidChildHeader(parent, bv)
	child.Signature = make([]byte, crypto.Dilithium3SignatureSize)
	child.StateRoot = types.Hash{0xAA}
	child.ReceiptRoot = types.Hash{} // ZERO — should be rejected

	block := &encoding.Block{
		Header:       child,
		Transactions: nil,
	}

	_, receiptVal, err := bv.ValidateBlock(block, parent)
	if err != nil {
		t.Fatalf("ValidateBlock failed: %v", err)
	}

	err = receiptVal(types.Hash{})
	if err == nil {
		t.Fatal("receiptValidator should reject zero ReceiptRoot for non-genesis block")
	}
}

// TestCONS_R12003_GetReceiptRootValidator_StillWorks verifies that the
// deprecated GetReceiptRootValidator still works (backward compat).
func TestCONS_R12003_GetReceiptRootValidator_StillWorks(t *testing.T) {
	bv := NewBlockValidator(1333, 30000000)
	bv.SetValidatorLookup(&mockValidatorLookup{isValidator: true})
	bv.SetDevMode(true)

	parent := makeValidParentHeader()
	child := makeValidChildHeader(parent, bv)
	child.Signature = make([]byte, crypto.Dilithium3SignatureSize)
	headerReceiptRoot := types.Hash{0xBB}
	child.ReceiptRoot = headerReceiptRoot

	block := &encoding.Block{
		Header:       child,
		Transactions: nil,
	}

	// Deprecated API still works.
	receiptVal := bv.GetReceiptRootValidator(block)
	if receiptVal == nil {
		t.Fatal("GetReceiptRootValidator should not return nil")
	}

	// Same as header — should pass.
	err := receiptVal(headerReceiptRoot)
	if err != nil {
		t.Fatalf("GetReceiptRootValidator closure should accept matching receipt root, got: %v", err)
	}
}
