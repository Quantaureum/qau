// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"math/big"
	"testing"
)

func TestDKGCommitmentRejectsBLSScalarFieldReuse(t *testing.T) {
	blsScalarOrder, ok := new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	if !ok {
		t.Fatal("invalid BLS12-381 scalar order test constant")
	}
	if err := ValidateCommitmentScalarField(big.NewInt(Q), blsScalarOrder); !errors.Is(err, ErrIncompatibleCommitmentField) {
		t.Fatalf("BLS12-381 scalar field error = %v", err)
	}

	left := new(big.Int).Sub(big.NewInt(Q), big.NewInt(1))
	shareSum := new(big.Int).Add(left, big.NewInt(1))
	shareSum.Mod(shareSum, big.NewInt(Q))
	commitmentSum := new(big.Int).Add(left, big.NewInt(1))
	commitmentSum.Mod(commitmentSum, blsScalarOrder)
	if shareSum.Sign() != 0 || commitmentSum.Sign() == 0 {
		t.Fatalf("expected explicit modular mismatch, got share=%s commitment=%s", shareSum, commitmentSum)
	}
}

func TestDKGCommitmentAcceptsOnlyMatchingPrimeOrder(t *testing.T) {
	if err := ValidateCommitmentScalarField(big.NewInt(Q), big.NewInt(Q)); err != nil {
		t.Fatalf("matching field rejected: %v", err)
	}
	if err := ValidateCommitmentScalarField(big.NewInt(Q), nil); !errors.Is(err, ErrIncompatibleCommitmentField) {
		t.Fatalf("nil field error = %v", err)
	}
}
