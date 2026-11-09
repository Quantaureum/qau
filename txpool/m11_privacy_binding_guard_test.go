package txpool

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// m11StubVerifier counts calls so the tests can prove the verifier never
// reaches the privacy execution path.
type m11StubVerifier struct {
	calls int
}

func (v *m11StubVerifier) VerifyEncodedPrivacyTx(tx *encoding.Transaction) error {
	v.calls++
	return nil
}

// SECURITY (audit M-11): wiring a verifier while the qzkp commitment-binding
// gap is unresolved must fail immediately and must leave the executor
// unwired.
func TestM11_PrivacyVerifierWiringIsLocked(t *testing.T) {
	e := NewTxExecutor()
	v := &m11StubVerifier{}

	err := e.SetPrivacyTxVerifier(v)
	if !errors.Is(err, ErrPrivacyProofBindingUnresolved) {
		t.Fatalf("expected ErrPrivacyProofBindingUnresolved, got %v", err)
	}
	if e.privacyTxVerifier != nil {
		t.Fatal("verifier must not be wired while the binding gap is unresolved")
	}

	// Clearing the hook (nil verifier) remains allowed.
	if err := e.SetPrivacyTxVerifier(nil); err != nil {
		t.Fatalf("nil verifier must be accepted, got %v", err)
	}

	// The executor stays fail-closed: attempted wiring cannot unlock the path.
	if !e.requirePrivacyVerification {
		t.Fatal("fail-closed default must remain enabled")
	}
}

// SECURITY (audit M-11): disabling the fail-closed gate is an equivalent path
// to the unchecked privacy execution, so it must be refused as well.
func TestM11_PrivacyVerificationCannotBeDisabled(t *testing.T) {
	e := NewTxExecutor()

	err := e.SetRequirePrivacyVerification(false)
	if !errors.Is(err, ErrPrivacyVerificationCannotBeDisabled) {
		t.Fatalf("expected ErrPrivacyVerificationCannotBeDisabled, got %v", err)
	}
	if !e.requirePrivacyVerification {
		t.Fatal("fail-closed gate must stay enabled")
	}

	// Re-enabling is a no-op and must be accepted.
	if err := e.SetRequirePrivacyVerification(true); err != nil {
		t.Fatalf("re-enabling fail-closed must be accepted, got %v", err)
	}
}

// SECURITY (audit M-11): with the hook locked and fail-closed on, a privacy
// transaction is rejected before any gas or state mutation (pre-existing
// behavior that must not change).
func TestM11_UnwiredPrivacyTxStaysFailClosed(t *testing.T) {
	e := NewTxExecutor()

	tx := &encoding.Transaction{
		Type:     encoding.TxTypePrivacy,
		GasLimit: 100000,
	}
	tx.From = types.Address{0x01}

	state := newMockState()
	state.SetBalance(tx.From, big.NewInt(1000))

	receipt := e.Execute(tx, state, &BlockContext{})
	if receipt == nil {
		t.Fatal("Execute returned nil receipt")
	}
	if receipt.Status != 0 {
		t.Fatalf("privacy tx must fail, got status %d", receipt.Status)
	}
	if receipt.GasUsed != 0 {
		t.Fatalf("privacy tx must not consume gas, got %d", receipt.GasUsed)
	}
	if receipt.Error == "" {
		t.Fatal("expected an explicit fail-closed error")
	}
	if got := state.GetBalance(tx.From); got.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("balance must be untouched, got %s", got)
	}
}
