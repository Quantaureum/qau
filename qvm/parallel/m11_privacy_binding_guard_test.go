package parallel

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/encoding"
)

type m11StubVerifier struct {
	calls int
}

func (v *m11StubVerifier) VerifyEncodedPrivacyTx(tx *encoding.Transaction) error {
	v.calls++
	return nil
}

// SECURITY (audit M-11): wiring a verifier while the qzkp commitment-binding
// gap is unresolved must fail immediately and leave the executor unwired.
func TestM11_ParallelPrivacyVerifierWiringIsLocked(t *testing.T) {
	pe := NewParallelExecutor(nil)
	v := &m11StubVerifier{}

	err := pe.SetPrivacyTxVerifier(v)
	if !errors.Is(err, ErrPrivacyProofBindingUnresolved) {
		t.Fatalf("expected ErrPrivacyProofBindingUnresolved, got %v", err)
	}
	if pe.privacyTxVerifier != nil {
		t.Fatal("verifier must not be wired while the binding gap is unresolved")
	}

	if err := pe.SetPrivacyTxVerifier(nil); err != nil {
		t.Fatalf("nil verifier must be accepted, got %v", err)
	}
	if !pe.requirePrivacyVerification {
		t.Fatal("fail-closed default must remain enabled")
	}
}

// SECURITY (audit M-11): disabling the fail-closed gate is refused while the
// binding gap is unresolved.
func TestM11_ParallelPrivacyVerificationCannotBeDisabled(t *testing.T) {
	pe := NewParallelExecutor(nil)

	err := pe.SetRequirePrivacyVerification(false)
	if !errors.Is(err, ErrPrivacyVerificationCannotBeDisabled) {
		t.Fatalf("expected ErrPrivacyVerificationCannotBeDisabled, got %v", err)
	}
	if !pe.requirePrivacyVerification {
		t.Fatal("fail-closed gate must stay enabled")
	}

	if err := pe.SetRequirePrivacyVerification(true); err != nil {
		t.Fatalf("re-enabling fail-closed must be accepted, got %v", err)
	}
}
