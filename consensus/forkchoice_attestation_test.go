// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestForkChoiceOnAttestationIsIdempotentAndRejectsInvalidStake(t *testing.T) {
	genesis := types.Hash{1}
	block := types.Hash{2}
	fc := NewForkChoice(genesis)
	if err := fc.OnBlock(block, genesis, 1, 1); err != nil {
		t.Fatalf("OnBlock() error = %v", err)
	}

	stake := big.NewInt(7)
	fc.OnAttestation(0, block, stake)
	fc.OnAttestation(0, block, stake)
	if got := fc.GetBlockWeight(block); got.Cmp(stake) != 0 {
		t.Fatalf("duplicate attestation weight = %s, want %s", got, stake)
	}

	fc.OnAttestation(1, block, nil)
	fc.OnAttestation(1, block, big.NewInt(0))
	fc.OnAttestation(1, block, big.NewInt(-1))
	if got := fc.GetBlockWeight(block); got.Cmp(stake) != 0 {
		t.Fatalf("invalid stake changed weight to %s, want %s", got, stake)
	}
}
