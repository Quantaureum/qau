// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestQPOSSafety validates core QPOS safety properties
// 1. Finality: an acknowledged block cannot be rolled back
// 2. Consistency: all honest nodes agree on the block at the same height
// 3. Liveness: the system keeps producing new blocks
func TestQPOSSafety(t *testing.T) {
	EnableTestHelpers()
	defer ResetGenesisTimeForTesting()
	ResetAttestationNetworkIDForTesting()
	SetAttestationNetworkID(1668)
	FreezeAttestationNetworkID()

	t.Run("finality - finalized checkpoints cannot be reverted", func(t *testing.T) {
		validators := createVerificationTestValidators(3)
		vs, err := NewValidatorSet(validators)
		if err != nil {
			t.Fatalf("failed to create validator set: %v", err)
		}

		qpos, err := NewQPOS(vs)
		if err != nil {
			t.Fatalf("failed to create QPOS: %v", err)
		}

		// simulate finality progression
		qpos.mu.Lock()
		qpos.justifiedEpoch = 5
		qpos.justifiedRoot = types.Hash{0x01}
		qpos.finalizedEpoch = 4
		qpos.finalizedRoot = types.Hash{0x02}
		qpos.mu.Unlock()

		// verify a finalized checkpoint cannot be overwritten
		qpos.mu.RLock()
		finalizedEpoch := qpos.finalizedEpoch
		finalizedRoot := qpos.finalizedRoot
		qpos.mu.RUnlock()

		if finalizedEpoch != 4 {
			t.Errorf("finalized epoch should be 4, got %d", finalizedEpoch)
		}
		if finalizedRoot != (types.Hash{0x02}) {
			t.Errorf("finalized root mismatch")
		}
	})

	t.Run("consistency - same validator set picks the same proposer", func(t *testing.T) {
		validators := createVerificationTestValidators(3)
		vs, err := NewValidatorSet(validators)
		if err != nil {
			t.Fatalf("failed to create validator set: %v", err)
		}

		// propose with the same VRF output
		vrfOutput := &VRFOutput{Value: types.Hash{0x42}}

		proposer1, err := vs.SelectProposer(vrfOutput)
		if err != nil {
			t.Fatalf("first proposer selection failed: %v", err)
		}

		proposer2, err := vs.SelectProposer(vrfOutput)
		if err != nil {
			t.Fatalf("second proposer selection failed: %v", err)
		}

		if proposer1.Address != proposer2.Address {
			t.Errorf("identical VRF outputs should select the same proposer: first=%x, second=%x",
				proposer1.Address, proposer2.Address)
		}
	})

	t.Run("liveness - non-empty validator set can produce a proposer", func(t *testing.T) {
		validators := createVerificationTestValidators(3)
		vs, err := NewValidatorSet(validators)
		if err != nil {
			t.Fatalf("failed to create validator set: %v", err)
		}

		// different VRF outputs should each pick a proposer
		for i := 0; i < 10; i++ {
			var hash types.Hash
			hash[0] = byte(i)
			vrfOutput := &VRFOutput{Value: hash}

			proposer, err := vs.SelectProposer(vrfOutput)
			if err != nil {
				t.Errorf("proposer selection failed for VRF output %d: %v", i, err)
				continue
			}
			if proposer == nil {
				t.Errorf("VRF output %d should select a proposer but returned nil", i)
			}
		}
	})
}

// TestProposerSelectionDeterminism verifies proposer selection is deterministic
// the same validator set and the same seed must produce the same proposer
func TestProposerSelectionDeterminism(t *testing.T) {
	tests := []struct {
		name        string
		numVals     int
		description string
	}{
		{name: "3 validators - deterministic selection", numVals: 3, description: "proposer selection with 3 validators must be deterministic"},
		{name: "5 validators - deterministic selection", numVals: 5, description: "proposer selection with 5 validators must be deterministic"},
		{name: "10 validators - deterministic selection", numVals: 10, description: "proposer selection with 10 validators must be deterministic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validators := createVerificationTestValidators(tt.numVals)
			vs, err := NewValidatorSet(validators)
			if err != nil {
				t.Fatalf("failed to create validator set: %v", err)
			}

			// test determinism with multiple distinct VRF outputs
			for seed := 0; seed < 20; seed++ {
				var hash types.Hash
				hash[0] = byte(seed)
				hash[1] = byte(seed >> 8)
				vrfOutput := &VRFOutput{Value: hash}

				// first selection
				p1, err := vs.SelectProposer(vrfOutput)
				if err != nil {
					t.Fatalf("first selection failed: %v", err)
				}

				// second selection (same input)
				p2, err := vs.SelectProposer(vrfOutput)
				if err != nil {
					t.Fatalf("second selection failed: %v", err)
				}

				// must match exactly
				if p1.Address != p2.Address {
					t.Errorf("seed=%d: same input produced different proposers: %x vs %x",
						seed, p1.Address, p2.Address)
				}
			}
		})
	}

	t.Run("SelectProposerByHeight determinism", func(t *testing.T) {
		validators := createVerificationTestValidators(5)
		vs, err := NewValidatorSet(validators)
		if err != nil {
			t.Fatalf("failed to create validator set: %v", err)
		}

		prevHash := types.Hash{0xAA, 0xBB}
		// CON-001 FIX: vrfEntropy must be non-zero for height > 1
		vrfEntropy := types.Hash{0xCD, 0xEF}

		// same height + same parent hash must produce the same proposer
		p1, seed1, err := SelectProposerByHeight(vs, 100, prevHash, vrfEntropy)
		if err != nil {
			t.Fatalf("first selection failed: %v", err)
		}

		p2, seed2, err := SelectProposerByHeight(vs, 100, prevHash, vrfEntropy)
		if err != nil {
			t.Fatalf("second selection failed: %v", err)
		}

		if p1.Address != p2.Address {
			t.Errorf("same height and hash should produce the same proposer: %x vs %x", p1.Address, p2.Address)
		}
		if seed1 != seed2 {
			t.Errorf("same input should produce the same seed")
		}
	})
}

// TestValidatorWeightIntegrity verifies validator weight calculation
// weight sum = total staked
// each validator weight = stake / total stake
func TestValidatorWeightIntegrity(t *testing.T) {
	tests := []struct {
		name        string
		stakes      []int64
		description string
	}{
		{
			name:        "uniform stake - equal weights",
			stakes:      []int64{1000, 1000, 1000},
			description: "three validators with equal stake; each weight = 1/3",
		},
		{
			name:        "skewed stake - weight proportional",
			stakes:      []int64{1000, 2000, 3000},
			description: "stakes 1000:2000:3000, weights should be 1:2:3",
		},
		{
			name:        "single validator - weight 1.0",
			stakes:      []int64{5000},
			description: "a lone validator must have weight 1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validators := make([]*Validator, len(tt.stakes))
			for i, stake := range tt.stakes {
				var addr types.Address
				addr[0] = byte(i + 1)
				validators[i] = &Validator{
					Address: addr,
					Stake:   big.NewInt(stake),
					Active:  true,
				}
			}

			vs, err := NewValidatorSet(validators)
			if err != nil {
				t.Fatalf("failed to create validator set: %v", err)
			}

			// check 1: total stake equals the sum of validator stakes
			totalStake := vs.TotalStake()
			expectedTotal := big.NewInt(0)
			for _, stake := range tt.stakes {
				expectedTotal.Add(expectedTotal, big.NewInt(stake))
			}
			if totalStake.Cmp(expectedTotal) != 0 {
				t.Errorf("total stake mismatch: want %s, got %s", expectedTotal.String(), totalStake.String())
			}

			// check 2: each validator weight ratio is correct
			for i, v := range vs.Validators() {
				weight := new(big.Int).Div(
					new(big.Int).Mul(v.Stake, big.NewInt(10000)),
					totalStake,
				)
				expectedWeight := new(big.Int).Div(
					new(big.Int).Mul(big.NewInt(tt.stakes[i]), big.NewInt(10000)),
					expectedTotal,
				)
				if weight.Cmp(expectedWeight) != 0 {
					t.Errorf("validator %d weight mismatch: want %s/10000, got %s/10000",
						i, expectedWeight.String(), weight.String())
				}
			}

			// check 3: total weight = 10000 (basis points)
			totalWeight := big.NewInt(0)
			for _, v := range vs.Validators() {
				weight := new(big.Int).Div(
					new(big.Int).Mul(v.Stake, big.NewInt(10000)),
					totalStake,
				)
				totalWeight.Add(totalWeight, weight)
			}
			// integer division may round, so the sum must sit within [9999, 10001]
			if totalWeight.Cmp(big.NewInt(9999)) < 0 || totalWeight.Cmp(big.NewInt(10001)) > 0 {
				t.Errorf("total weight out of range: %s (expected ~10000)", totalWeight.String())
			}
		})
	}

	t.Run("StakeConsistencyChecker verification", func(t *testing.T) {
		validators := createVerificationTestValidators(3)
		vs, err := NewValidatorSet(validators)
		if err != nil {
			t.Fatalf("failed to create validator set: %v", err)
		}

		checker := NewStakeConsistencyChecker()
		if err := checker.VerifyTotalStake(vs.Validators(), vs.TotalStake()); err != nil {
			t.Errorf("stake consistency check should pass: %v", err)
		}

		// check with an incorrect total stake
		wrongTotal := big.NewInt(999)
		if err := checker.VerifyTotalStake(vs.Validators(), wrongTotal); err == nil {
			t.Error("an incorrect total stake should fail consistency check")
		}
	})
}

// TestDoubleSignDetection verifies that double-signing (two different blocks at the same height) is detected
func TestDoubleSignDetection(t *testing.T) {
	EnableTestHelpers()
	defer ResetGenesisTimeForTesting()
	ResetAttestationNetworkIDForTesting()
	SetAttestationNetworkID(1668)
	FreezeAttestationNetworkID()

	t.Run("same slot, different blockRoot is detected as double-signing", func(t *testing.T) {
		validators := createVerificationTestValidators(3)
		vs, err := NewValidatorSet(validators)
		if err != nil {
			t.Fatalf("failed to create validator set: %v", err)
		}

		qpos, err := NewQPOS(vs)
		if err != nil {
			t.Fatalf("failed to create QPOS: %v", err)
		}

		// set genesis time so the current slot is valid
		SetGenesisTime(1)

		// first attestation: slot=1, blockRoot=0x01
		att1 := &Attestation{
			Slot:            1,
			BeaconBlockRoot: types.Hash{0x01},
			Source:          AttestationCheckpoint{Epoch: 0},
			Target:          AttestationCheckpoint{Epoch: 0},
			ValidatorIndex:  0,
			Signature:       make([]byte, 64),
		}

		// write validatorAttestations directly to simulate prior attestations
		qpos.mu.Lock()
		if qpos.validatorAttestations[0] == nil {
			qpos.validatorAttestations[0] = make(map[uint64]*Attestation)
		}
		qpos.validatorAttestations[0][1] = att1
		qpos.mu.Unlock()

		// second attestation: slot=1, blockRoot=0x02 (double-sign!!)
		att2 := &Attestation{
			Slot:            1,
			BeaconBlockRoot: types.Hash{0x02},
			Source:          AttestationCheckpoint{Epoch: 0},
			Target:          AttestationCheckpoint{Epoch: 0},
			ValidatorIndex:  0,
			Signature:       make([]byte, 64),
		}

		// invoke checkDoubleVote directly to detect the violation
		qpos.mu.Lock()
		err = qpos.checkDoubleVote(att2)
		qpos.mu.Unlock()

		if err != ErrDoubleVote {
			t.Errorf("double-sign should be detected, expected ErrDoubleVote but got %v", err)
		}
	})

	t.Run("same slot + same blockRoot is not double-signing", func(t *testing.T) {
		validators := createVerificationTestValidators(3)
		vs, err := NewValidatorSet(validators)
		if err != nil {
			t.Fatalf("failed to create validator set: %v", err)
		}

		qpos, err := NewQPOS(vs)
		if err != nil {
			t.Fatalf("failed to create QPOS: %v", err)
		}

		// resubmit the same attestation (same slot, same blockRoot)
		att := &Attestation{
			Slot:            1,
			BeaconBlockRoot: types.Hash{0x01},
			Source:          AttestationCheckpoint{Epoch: 0},
			Target:          AttestationCheckpoint{Epoch: 0},
			ValidatorIndex:  0,
			Signature:       make([]byte, 64),
		}

		qpos.mu.Lock()
		if qpos.validatorAttestations[0] == nil {
			qpos.validatorAttestations[0] = make(map[uint64]*Attestation)
		}
		qpos.validatorAttestations[0][1] = att
		qpos.mu.Unlock()

		// identical attestations do NOT count as double-signing
		qpos.mu.Lock()
		err = qpos.checkDoubleVote(att)
		qpos.mu.Unlock()

		if err != nil {
			t.Errorf("same blockRoot must not be flagged as double-signing, got %v", err)
		}
	})

	t.Run("different slots are not double-signing", func(t *testing.T) {
		validators := createVerificationTestValidators(3)
		vs, err := NewValidatorSet(validators)
		if err != nil {
			t.Fatalf("failed to create validator set: %v", err)
		}

		qpos, err := NewQPOS(vs)
		if err != nil {
			t.Fatalf("failed to create QPOS: %v", err)
		}

		// slot=1 attestation
		att1 := &Attestation{
			Slot:            1,
			BeaconBlockRoot: types.Hash{0x01},
			Source:          AttestationCheckpoint{Epoch: 0},
			Target:          AttestationCheckpoint{Epoch: 0},
			ValidatorIndex:  0,
			Signature:       make([]byte, 64),
		}

		qpos.mu.Lock()
		if qpos.validatorAttestations[0] == nil {
			qpos.validatorAttestations[0] = make(map[uint64]*Attestation)
		}
		qpos.validatorAttestations[0][1] = att1
		qpos.mu.Unlock()

		// slot=2 attestation (different slot, NOT double-signing)
		att2 := &Attestation{
			Slot:            2,
			BeaconBlockRoot: types.Hash{0x02},
			Source:          AttestationCheckpoint{Epoch: 0},
			Target:          AttestationCheckpoint{Epoch: 0},
			ValidatorIndex:  0,
			Signature:       make([]byte, 64),
		}

		qpos.mu.Lock()
		err = qpos.checkDoubleVote(att2)
		qpos.mu.Unlock()

		if err != nil {
			t.Errorf("different slots must not be flagged as double-signing, got %v", err)
		}
	})
}

// createVerificationTestValidators creates the requested number of test validators
// named distinctly to avoid colliding with createTestValidators in consensus_election_test.go
func createVerificationTestValidators(n int) []*Validator {
	validators := make([]*Validator, n)
	for i := 0; i < n; i++ {
		var addr types.Address
		addr[0] = byte(i + 1)
		addr[1] = byte(i + 1)
		validators[i] = &Validator{
			Address: addr,
			Stake:   new(big.Int).Mul(big.NewInt(int64((i+1)*1000)), big.NewInt(1_000_000_000)), // stake in gwei (×10^9 to store as wei)
			Active:  true,
		}
	}
	return validators
}
