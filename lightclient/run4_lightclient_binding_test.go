package lightclient

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestRun4_StateProofAccountBinding is the regression guard for run-4 L-1:
// VerifyStateProof verified the Verkle path but never compared the envelope's
// Account fields with the proven leaf, so a benign proof could present an
// arbitrary balance/nonce/storageRoot/codeHash.
func TestRun4_StateProofAccountBinding(t *testing.T) {
	sdb, root := newProvedStateDB(t)
	addr := types.Address{0xa1, 0xb2}
	proof, err := NewSPVProver(nil, sdb).GenerateStateProof(addr, nil)
	if err != nil {
		t.Fatalf("GenerateStateProof: %v", err)
	}
	if !VerifyStateProof(root, proof) {
		t.Fatal("baseline generated proof must verify")
	}

	tampered := *proof
	account := *proof.Account
	account.Balance = new(big.Int).SetUint64(1_000_000_000_000_000_000)
	tampered.Account = &account

	if VerifyStateProof(root, &tampered) {
		t.Fatal("VerifyStateProof accepted an envelope whose Account was not the proven leaf")
	}
}
