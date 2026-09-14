// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// createTestValidatorSetHC builds a validator set with n validators.
// It lives in a tracked test helper so CI can compile the audited regression
// tests that reference it (the local-only coverage file previously defining
// it is excluded by .gitignore's *_cover* pattern).
func createTestValidatorSetHC(n int) *ValidatorSet {
	validators := make([]*Validator, n)
	for i := 0; i < n; i++ {
		addr := types.Address{byte(i + 1)}
		stake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
		validators[i] = &Validator{
			Address: addr,
			Stake:   stake,
			Active:  true,
		}
	}
	vs, _ := NewValidatorSet(validators)
	return vs
}

// setupQPOSWithKeys creates a QPOS instance with n validator key pairs.
// It lives in a tracked test helper so CI can compile the audited regression
// tests that reference it (the local-only coverage file previously defining
// it is excluded by .gitignore's *_cover* pattern).
func setupQPOSWithKeys(n int) (*QPOS, []*crypto.KeyPair) {
	keys := make([]*crypto.KeyPair, n)
	validators := make([]*Validator, n)
	for i := 0; i < n; i++ {
		kp, _ := crypto.GenerateKeyPair()
		keys[i] = kp
		addr := kp.Public.Address()
		validators[i] = &Validator{
			Address:        addr,
			PublicKeyBytes: kp.Public.Bytes(),
			Stake:          new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)),
			Active:         true,
		}
	}
	vs, _ := NewValidatorSet(validators)
	qpos := &QPOS{
		validators:             vs,
		attestations:           make(map[uint64][]*Attestation),
		committeeCache:         make(map[uint64][]*Validator),
		shuffleCache:           make(map[uint64][]int),
		validatorAttestations:  make(map[int]map[uint64]*Attestation),
		aggregatedAttestations: make(map[uint64]*AggregatedAttestation),
		randaoCommits:          make(map[uint64]map[int]types.Hash),
		slashedValidators:      make(map[int]*SlashedEntry),
		evidenceQueue:          make([]*SlashingEvidence, 0),
		slotBlockRoots:         make(map[uint64]types.Hash),
		epochBlockRoots:        make(map[uint64]types.Hash),
		epochVRFAccumulator:    make(map[uint64]types.Hash),
		stopCh:                 make(chan struct{}),
	}
	return qpos, keys
}

// findValidatorIndex finds a validator's index in the sorted validator set by address.
func findValidatorIndex(qpos *QPOS, addr types.Address) int {
	validators := qpos.validators.Validators()
	for i, v := range validators {
		if v.Address == addr {
			return i
		}
	}
	return -1
}

// newFinalityTrackerForTest creates a FinalityTracker with 3 active validators.
func newFinalityTrackerForTest() *FinalityTracker {
	vm := NewValidatorManager()
	sc := types.Address{0xaa}
	RegisterSystemCaller(sc)
	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()
	kp3, _ := crypto.GenerateKeyPair()
	addr1 := kp1.Public.Address()
	addr2 := kp2.Public.Address()
	addr3 := kp3.Public.Address()
	vm.AddValidator(sc, addr1, kp1.Public, new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)), 100, 0)
	vm.ActivateFromQueue(addr1)
	vm.AddValidator(sc, addr2, kp2.Public, new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)), 100, 0)
	vm.ActivateFromQueue(addr2)
	vm.AddValidator(sc, addr3, kp3.Public, new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)), 100, 0)
	vm.ActivateFromQueue(addr3)
	return NewFinalityTracker(vm)
}
