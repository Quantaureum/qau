package encoding

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// h03SignedTx builds a transaction whose signature is valid for its own
// ChainID. This lets the test reach the DefaultValidator ChainID branch
// instead of failing earlier in signature authorization.
func h03SignedTx(t *testing.T, chainID uint64) *Transaction {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pub, err := kp.Private.PublicKeySafe()
	if err != nil {
		t.Fatalf("PublicKeySafe: %v", err)
	}
	to := types.Address{1, 2, 3}
	tx := &Transaction{
		Type:      TxTypeTransfer,
		Nonce:     1,
		ChainID:   chainID,
		From:      pub.Address(),
		To:        &to,
		Value:     big.NewInt(1),
		GasLimit:  21000,
		GasPrice:  big.NewInt(1),
		PublicKey: pub.Bytes(),
	}
	hash, err := tx.SigningHash()
	if err != nil {
		t.Fatalf("SigningHash: %v", err)
	}
	sig, err := kp.Private.Sign(hash[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tx.Signature = sig
	return tx
}

// TestH03_DefaultValidator_ChainIDGate pins both halves of the H-03 fix:
//   - ExpectedChainID == 0 keeps the legacy behavior exactly (no ChainID check,
//     including tx.ChainID == 0) so untouched production paths are inert.
//   - ExpectedChainID > 0 now rejects zero and foreign ChainIDs. Previously the
//     `tx.ChainID != 0` escape admitted zero-chain-ID transactions.
func TestH03_DefaultValidator_ChainIDGate(t *testing.T) {
	zero := h03SignedTx(t, 0)
	if err := NewDefaultValidator(0).ValidateTx(zero); err != nil {
		t.Fatalf("legacy expected=0 must accept any tx (unchanged behavior), got %v", err)
	}

	err := NewDefaultValidator(1668).ValidateTx(zero)
	if !errors.Is(err, ErrAuthChainIDMismatch) {
		t.Fatalf("zero ChainID with expected=1668 must be rejected with ErrAuthChainIDMismatch, got %v", err)
	}

	matches := h03SignedTx(t, 1668)
	if err := NewDefaultValidator(1668).ValidateTx(matches); err != nil {
		t.Fatalf("matching ChainID must be accepted, got %v", err)
	}

	foreign := h03SignedTx(t, 9999)
	err = NewDefaultValidator(1668).ValidateTx(foreign)
	if !errors.Is(err, ErrAuthChainIDMismatch) {
		t.Fatalf("foreign ChainID must be rejected with ErrAuthChainIDMismatch, got %v", err)
	}
}
