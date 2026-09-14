// Quantaureum Node source, version 1.0.0.
package types

import (
	"testing"
)

// TestCRYPTO_R11004_IsSigned_BothSizesCorrect verifies the happy-path:
// when both Signature and PublicKey have exactly the right sizes,
// IsSigned returns true.
func TestCRYPTO_R11004_IsSigned_BothSizesCorrect(t *testing.T) {
	tx, err := NewQuantumTransfer(0, 1, Address{}, nil)
	if err != nil {
		t.Fatalf("NewQuantumTransfer failed: %v", err)
	}
	tx.PublicKey = make([]byte, QuantumPublicKeySize) // 1952
	tx.Signature = make([]byte, QuantumSignatureSize) // 3293

	if !tx.IsSigned() {
		t.Error("IsSigned() = false, want true (both sizes correct)")
	}
}

// TestCRYPTO_R11004_IsSigned_OnlySignatureWrong verifies that IsSigned
// returns false when only the Signature size is wrong. Before CRYPTO-R11-004,
// the `&&` operator would short-circuit after the first false condition;
// now the function uses constant-time AND so both conditions are always
// evaluated (no timing difference).
func TestCRYPTO_R11004_IsSigned_OnlySignatureWrong(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	tx.PublicKey = make([]byte, QuantumPublicKeySize)
	tx.Signature = make([]byte, QuantumSignatureSize-1) // wrong size

	if tx.IsSigned() {
		t.Error("IsSigned() = true, want false (Signature size wrong)")
	}
}

// TestCRYPTO_R11004_IsSigned_OnlyPublicKeyWrong verifies the symmetric
// case: PublicKey size wrong, Signature size correct.
func TestCRYPTO_R11004_IsSigned_OnlyPublicKeyWrong(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	tx.PublicKey = make([]byte, QuantumPublicKeySize+1) // wrong size
	tx.Signature = make([]byte, QuantumSignatureSize)

	if tx.IsSigned() {
		t.Error("IsSigned() = true, want false (PublicKey size wrong)")
	}
}

// TestCRYPTO_R11004_IsSigned_BothSizesWrong verifies the case where both
// sizes are wrong.
func TestCRYPTO_R11004_IsSigned_BothSizesWrong(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	tx.PublicKey = make([]byte, 10)
	tx.Signature = make([]byte, 10)

	if tx.IsSigned() {
		t.Error("IsSigned() = true, want false (both sizes wrong)")
	}
}

// TestCRYPTO_R11004_IsSigned_BothEmpty verifies the unsigned case (the
// existing TestQuantumTransaction_IsSigned_Unsigned already covers this,
// but we re-assert it under the CRYPTO-R11-004 contract).
func TestCRYPTO_R11004_IsSigned_BothEmpty(t *testing.T) {
	tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
	// Both Signature and PublicKey are nil/empty.

	if tx.IsSigned() {
		t.Error("IsSigned() = true, want false (both empty)")
	}
}

// TestCRYPTO_R11004_IsSigned_NonPanicOnZeroValues verifies that IsSigned
// does not panic when both Signature and PublicKey are nil (e.g. for a
// partially-initialized transaction).
func TestCRYPTO_R11004_IsSigned_NonPanicOnZeroValues(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("IsSigned() panicked on nil slices: %v", r)
		}
	}()
	tx := &QuantumTransaction{}
	_ = tx.IsSigned()
}

// TestCRYPTO_R11004_IsSigned_NeitherShortCircuits is a behavioral test
// that documents the CRYPTO-R11-004 contract: the function must evaluate
// BOTH length comparisons even when the first one is false. We can't
// directly observe whether the second comparison ran (constant-time
// code is designed to make that unobservable), but we can verify that
// the result is correct for all 4 combinations of (sigMatch, pubMatch),
// which proves both branches of the AND are wired up.
//
// This test exists primarily as documentation and a regression anchor:
// if someone refactors IsSigned back to `&&`, all 4 cases still pass —
// the regression would only be caught by a race/timing analysis, which
// is out of scope for unit tests. The audit's recommendation is to
// maintain coding consistency with the rest of the constant-time code
// in types/quantum_transaction.go (see Verify(), Sender()).
func TestCRYPTO_R11004_IsSigned_AllCombinationsCorrect(t *testing.T) {
	cases := []struct {
		name       string
		sigSize    int
		pubSize    int
		wantSigned bool
	}{
		{"both correct", QuantumSignatureSize, QuantumPublicKeySize, true},
		{"sig wrong, pub correct", QuantumSignatureSize - 1, QuantumPublicKeySize, false},
		{"sig correct, pub wrong", QuantumSignatureSize, QuantumPublicKeySize + 1, false},
		{"both wrong", 0, 0, false},
		{"both empty", -1, -1, false}, // negative means leave nil
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tx, _ := NewQuantumTransfer(0, 1, Address{}, nil)
			if c.sigSize >= 0 {
				tx.Signature = make([]byte, c.sigSize)
			}
			if c.pubSize >= 0 {
				tx.PublicKey = make([]byte, c.pubSize)
			}
			if got := tx.IsSigned(); got != c.wantSigned {
				t.Errorf("IsSigned() = %v, want %v", got, c.wantSigned)
			}
		})
	}
}
