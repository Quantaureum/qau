// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"errors"
	"fmt"
	"math/big"
)

var ErrIncompatibleCommitmentField = errors.New("commitment scalar field is incompatible with Dilithium3 sharing")

// ValidateCommitmentScalarField requires commitment and sharing arithmetic to
// use the same prime modulus. An injective integer encoding alone is not enough.
func ValidateCommitmentScalarField(shareModulus, commitmentOrder *big.Int) error {
	if shareModulus == nil || commitmentOrder == nil || shareModulus.Sign() <= 0 || commitmentOrder.Sign() <= 0 {
		return ErrIncompatibleCommitmentField
	}
	if shareModulus.Cmp(commitmentOrder) != 0 {
		return fmt.Errorf("%w: share modulus %s, commitment order %s", ErrIncompatibleCommitmentField, shareModulus, commitmentOrder)
	}
	return nil
}
