package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
)

// REG-02 regression: a validator entry that carries no publicKey (legacy or
// third-party genesis) must still register its address→PeerID mapping. The
// host has already checked that the claimed key derives the claimed address,
// so address-only active-set membership keeps the anti-hijack invariant while
// avoiding a permanent TSS/DKG routing break.
func TestREG02_ActiveValidatorWithoutPublicKeyAcceptsAddressMembership(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	addr := kp.Public.Address()

	vm := consensus.NewValidatorManager()
	if err := vm.AddGenesisValidator(addr, addr, nil, big.NewInt(6000), 100, 0); err != nil {
		t.Fatalf("AddGenesisValidator without public key: %v", err)
	}
	n := &Node{validatorManager: vm}

	if err := n.VerifyActiveValidator(addr, kp.Public.Bytes()); err != nil {
		t.Fatalf("address-only fallback must accept an active validator: %v", err)
	}

	other, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if err := n.VerifyActiveValidator(other.Public.Address(), other.Public.Bytes()); err == nil {
		t.Fatal("an address outside the active set must still be rejected")
	}
}
