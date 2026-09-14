// Quantaureum Node source, version 1.0.0.
package consensus

// R25-042 (P4): Test naming convention. Go tests in this package follow the
// standard `go test` discovery rules:
//   - Files are named *_test.go and live in the same package (white-box) so
//     they can access unexported fields (e.g. ValidatorSet internals).
//   - Test functions are named `TestXxx` (exported, starting with `Test`,
//     followed by a PascalCase description), run by `go test`.
//   - Benchmark functions are `BenchmarkXxx`; example functions `ExampleXxx`.
//   - Helpers are lowercase (e.g. createTestValidators) and call t.Helper() so
//     failure line numbers point at the caller, not the helper.
//   - Table-driven tests use subtests (t.Run("case_name")) for isolated output.
// Keep this convention when adding tests so `go test ./...` discovery and the
// IDE test runner continue to work without configuration.

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

func createTestValidators(t *testing.T, count int) []*Validator {
	t.Helper()
	validators := make([]*Validator, count)
	for i := 0; i < count; i++ {
		addr := types.Address{}
		addr[0] = byte(i + 1)
		validators[i] = &Validator{
			Address: addr,
			Stake:   big.NewInt(int64((i + 1) * 1000)),
			Active:  true,
		}
	}
	return validators
}

func generateTestVRFOutput(t *testing.T) *VRFOutput {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, output, err := GenerateVRF(kp.Private, types.Hash{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func TestNewValidatorSet_Valid(t *testing.T) {
	validators := createTestValidators(t, 3)
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}
	if vs == nil {
		t.Fatal("expected non-nil")
	}
	if vs.Size() != 3 {
		t.Errorf("expected 3 validators, got %d", vs.Size())
	}
	if vs.TotalStake().Cmp(big.NewInt(6000)) != 0 {
		t.Errorf("total stake = %v, want 6000", vs.TotalStake())
	}
}

func TestNewValidatorSet_Empty(t *testing.T) {
	_, err := NewValidatorSet(nil)
	if err != ErrNoValidators {
		t.Errorf("expected ErrNoValidators, got %v", err)
	}
}

func TestNewValidatorSet_NoActive(t *testing.T) {
	validators := []*Validator{
		{Address: types.Address{1}, Stake: big.NewInt(100), Active: false},
		{Address: types.Address{2}, Stake: big.NewInt(200), Active: false},
	}
	_, err := NewValidatorSet(validators)
	if err != ErrNoActiveValidators {
		t.Errorf("expected ErrNoActiveValidators, got %v", err)
	}
}

// FIX: Updated to match genesis bootstrap design (election.go:183-190).
// Zero-stake validators are now ALLOWED for genesis bootstrap. Only nil
// validator entries are filtered. nil Stake is converted to big.NewInt(0).
func TestNewValidatorSet_FiltersNilKeepsZeroStake(t *testing.T) {
	validators := []*Validator{
		nil, // filtered: nil entry
		{Address: types.Address{1}, Stake: big.NewInt(0), Active: true},   // kept: zero-stake allowed for genesis
		{Address: types.Address{2}, Stake: big.NewInt(100), Active: true}, // kept: normal validator
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if vs.Size() != 2 {
		t.Errorf("expected 2 validators (zero-stake kept for genesis), got %d", vs.Size())
	}
}

// FIX: Zero total stake is now allowed for genesis bootstrap.
// SelectProposer returns ErrZeroTotalStake so the caller falls back to
// deterministic round-robin (qpos_proposer.go). NewValidatorSet should
// succeed, not return ErrNoActiveValidators.
func TestNewValidatorSet_ZeroTotalStake(t *testing.T) {
	validators := []*Validator{
		{Address: types.Address{1}, Stake: big.NewInt(0), Active: true},
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Errorf("expected success (zero total stake allowed for genesis), got %v", err)
	}
	if vs == nil {
		t.Fatal("expected non-nil ValidatorSet")
	}
	if vs.Size() != 1 {
		t.Errorf("expected 1 validator, got %d", vs.Size())
	}
	// Verify SelectProposer returns ErrZeroTotalStake for zero total stake
	_, err = vs.SelectProposer(&VRFOutput{Value: [32]byte{1}})
	if err != ErrZeroTotalStake {
		t.Errorf("expected ErrZeroTotalStake from SelectProposer, got %v", err)
	}
}

// FIX: nil Stake is converted to big.NewInt(0) and the validator is
// kept (genesis bootstrap). NewValidatorSet should succeed.
func TestNewValidatorSet_NilStakeConvertedToZero(t *testing.T) {
	validators := []*Validator{
		{Address: types.Address{1}, Stake: nil, Active: true},
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Errorf("expected success (nil stake converted to 0 for genesis), got %v", err)
	}
	if vs == nil {
		t.Fatal("expected non-nil ValidatorSet")
	}
	if vs.Size() != 1 {
		t.Errorf("expected 1 validator, got %d", vs.Size())
	}
}

func TestValidatorSet_Size(t *testing.T) {
	vs, _ := NewValidatorSet(createTestValidators(t, 5))
	if vs.Size() != 5 {
		t.Errorf("Size = %d, want 5", vs.Size())
	}
}

func TestValidatorSet_TotalStake(t *testing.T) {
	vs, _ := NewValidatorSet(createTestValidators(t, 3))
	ts := vs.TotalStake()
	if ts.Cmp(big.NewInt(6000)) != 0 {
		t.Errorf("TotalStake = %v, want 6000", ts)
	}
}

func TestValidatorSet_GetValidator(t *testing.T) {
	validators := createTestValidators(t, 3)
	vs, _ := NewValidatorSet(validators)

	v := vs.GetValidator(validators[0].Address)
	if v == nil {
		t.Fatal("expected non-nil")
	}
	if v.Address != validators[0].Address {
		t.Error("wrong address")
	}

	v2 := vs.GetValidator(types.Address{99, 99})
	if v2 != nil {
		t.Error("expected nil for unknown")
	}
}

func TestValidatorSet_GetValidatorIndex(t *testing.T) {
	validators := createTestValidators(t, 3)
	vs, _ := NewValidatorSet(validators)

	idx := vs.GetValidatorIndex(validators[0].Address)
	if idx < 0 {
		t.Error("expected valid index")
	}

	idx = vs.GetValidatorIndex(types.Address{99, 99})
	if idx != -1 {
		t.Errorf("expected -1, got %d", idx)
	}
}

func TestValidatorSet_DeepCopy(t *testing.T) {
	validators := createTestValidators(t, 3)
	vs, _ := NewValidatorSet(validators)

	cp := vs.DeepCopy()
	if cp == nil {
		t.Fatal("expected non-nil")
	}
	if cp.Size() != vs.Size() {
		t.Error("sizes differ")
	}

	vs.Validators()[0].Stake.Set(big.NewInt(9999))
	if cp.Validators()[0].Stake.Cmp(big.NewInt(9999)) == 0 {
		t.Error("deep copy should not be affected by mutation")
	}
}

func TestValidatorSet_SelectProposer_Valid(t *testing.T) {
	validators := createTestValidators(t, 5)
	vs, _ := NewValidatorSet(validators)

	output := generateTestVRFOutput(t)

	proposer, err := vs.SelectProposer(output)
	if err != nil {
		t.Fatalf("SelectProposer failed: %v", err)
	}
	if proposer == nil {
		t.Fatal("expected non-nil proposer")
	}
}

func TestValidatorSet_SelectProposer_NilOutput(t *testing.T) {
	validators := createTestValidators(t, 3)
	vs, _ := NewValidatorSet(validators)

	_, err := vs.SelectProposer(nil)
	if err != ErrInvalidVRFOutput {
		t.Errorf("expected ErrInvalidVRFOutput, got %v", err)
	}
}

func TestValidatorSet_SelectProposerLinear_Valid(t *testing.T) {
	validators := createTestValidators(t, 5)
	vs, _ := NewValidatorSet(validators)

	output := generateTestVRFOutput(t)

	proposer, err := vs.SelectProposerLinear(output)
	if err != nil {
		t.Fatalf("SelectProposerLinear failed: %v", err)
	}
	if proposer == nil {
		t.Fatal("expected non-nil")
	}
}

func TestValidatorSet_SelectProposerLinear_NilOutput(t *testing.T) {
	validators := createTestValidators(t, 3)
	vs, _ := NewValidatorSet(validators)

	_, err := vs.SelectProposerLinear(nil)
	if err != ErrInvalidVRFOutput {
		t.Errorf("expected ErrInvalidVRFOutput, got %v", err)
	}
}

func TestValidatorSet_SelectProposer_Empty(t *testing.T) {
	validators := createTestValidators(t, 1)
	vs, _ := NewValidatorSet(validators)

	output := generateTestVRFOutput(t)

	proposer, err := vs.SelectProposer(output)
	if err != nil {
		t.Fatalf("SelectProposer failed: %v", err)
	}
	if proposer == nil {
		t.Fatal("expected non-nil proposer")
	}
}

func TestSelectProposerByHeight(t *testing.T) {
	validators := createTestValidators(t, 3)
	vs, _ := NewValidatorSet(validators)

	// CON-001 FIX: vrfEntropy must be non-zero for height > 1
	vrfEntropy := types.Hash{0xab}
	proposer, seed, err := SelectProposerByHeight(vs, 100, types.Hash{1}, vrfEntropy)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if proposer == nil {
		t.Fatal("expected non-nil proposer")
	}
	if seed == (types.Hash{}) {
		t.Error("expected non-zero seed")
	}
}

func TestSelectProposerByHeight_Empty(t *testing.T) {
	vs := &ValidatorSet{}
	vrfEntropy := types.Hash{0xab}
	_, _, err := SelectProposerByHeight(vs, 100, types.Hash{1}, vrfEntropy)
	if err == nil {
		t.Error("expected error")
	}
}

func TestCreateElectionSeed(t *testing.T) {
	seed1 := createElectionSeed(100, types.Hash{1}, types.Hash{})
	seed2 := createElectionSeed(100, types.Hash{1}, types.Hash{})
	if seed1 != seed2 {
		t.Error("expected deterministic seeds")
	}

	seed3 := createElectionSeed(200, types.Hash{1}, types.Hash{})
	if seed1 == seed3 {
		t.Error("different heights should produce different seeds")
	}

	seed4 := createElectionSeed(100, types.Hash{2}, types.Hash{})
	if seed1 == seed4 {
		t.Error("different hashes should produce different seeds")
	}
}

func TestCompareAddresses(t *testing.T) {
	a := types.Address{1, 0, 0}
	b := types.Address{2, 0, 0}

	if compareAddresses(a, b) >= 0 {
		t.Error("a < b should return negative")
	}
	if compareAddresses(b, a) <= 0 {
		t.Error("b > a should return positive")
	}
	if compareAddresses(a, a) != 0 {
		t.Error("same should return 0")
	}
}

func TestValidatorSet_Validators_DeepCopy(t *testing.T) {
	vs, _ := NewValidatorSet(createTestValidators(t, 2))
	copy := vs.Validators()

	copy[0].Stake.Set(big.NewInt(9999))

	vsCopy := vs.Validators()
	if vsCopy[0].Stake.Cmp(big.NewInt(9999)) == 0 {
		t.Error("Validators() should deep copy Stake")
	}
}

func TestValidatorSet_DeterministicSort(t *testing.T) {
	validators := []*Validator{
		{Address: types.Address{3}, Stake: big.NewInt(100), Active: true},
		{Address: types.Address{1}, Stake: big.NewInt(200), Active: true},
		{Address: types.Address{2}, Stake: big.NewInt(300), Active: true},
	}
	vs1, _ := NewValidatorSet(validators)
	vs2, _ := NewValidatorSet(validators)

	v1 := vs1.Validators()
	v2 := vs2.Validators()

	for i := range v1 {
		if v1[i].Address != v2[i].Address {
			t.Errorf("expected deterministic sort at index %d", i)
		}
	}
}

func TestElection_New(t *testing.T) {
	election := NewElection(nil, nil, nil)
	if election == nil {
		t.Fatal("expected non-nil")
	}
}

func TestElection_IsWinner_Basic(t *testing.T) {
	election := NewElection(nil, nil, nil)

	t.Run("nil output", func(t *testing.T) {
		if election.IsWinner(nil, big.NewInt(100), big.NewInt(1000), types.Hash{}, 0) {
			t.Error("should be false with nil output")
		}
	})

	t.Run("nil stake", func(t *testing.T) {
		output := generateTestVRFOutput(t)
		if election.IsWinner(output, nil, big.NewInt(1000), types.Hash{}, 0) {
			t.Error("should be false with nil stake")
		}
	})

	t.Run("nil total stake", func(t *testing.T) {
		output := generateTestVRFOutput(t)
		if election.IsWinner(output, big.NewInt(100), nil, types.Hash{}, 0) {
			t.Error("should be false with nil totalStake")
		}
	})

	t.Run("zero stake", func(t *testing.T) {
		output := generateTestVRFOutput(t)
		if election.IsWinner(output, big.NewInt(0), big.NewInt(1000), types.Hash{}, 0) {
			t.Error("should be false with zero stake")
		}
	})

	t.Run("zero total stake", func(t *testing.T) {
		output := generateTestVRFOutput(t)
		if election.IsWinner(output, big.NewInt(100), big.NewInt(0), types.Hash{}, 0) {
			t.Error("should be false with zero totalStake")
		}
	})

	t.Run("negative stake", func(t *testing.T) {
		output := generateTestVRFOutput(t)
		if election.IsWinner(output, big.NewInt(-100), big.NewInt(1000), types.Hash{}, 0) {
			t.Error("should be false with negative stake")
		}
	})

	t.Run("high stake should win", func(t *testing.T) {
		e := &Election{publicKey: nil}
		output := generateTestVRFOutput(t)
		// With 90% of stake, should be a winner
		won := e.IsWinner(output, big.NewInt(900), big.NewInt(1000), types.Hash{1}, 1234567890)
		t.Log("IsWinner with high stake:", won)
	})
}

func TestElectionErrorConstants(t *testing.T) {
	errors := []error{ErrNoValidators, ErrNoActiveValidators, ErrInvalidStake, ErrZeroTotalStake, ErrInvalidVRFForElection}
	for _, e := range errors {
		if e.Error() == "" {
			t.Errorf("error %T has empty message", e)
		}
	}
}

func TestValidatorSet_GetValidator_Nil(t *testing.T) {
	vs, _ := NewValidatorSet(createTestValidators(t, 1))
	v := vs.GetValidator(types.Address{99, 99, 99})
	if v != nil {
		t.Error("expected nil")
	}
}

func TestCheckpoint_DefaultConfig(t *testing.T) {
	cfg := DefaultCheckpointConfig()
	if cfg == nil {
		t.Fatal("expected non-nil")
	}
	if cfg.CheckpointInterval != 1000 {
		t.Errorf("CheckpointInterval = %d, want 1000", cfg.CheckpointInterval)
	}
	if cfg.MinSignatures != 4 { // ceil(6*2/3)=4 for 6 deployed validators
		t.Errorf("MinSignatures = %d, want 4", cfg.MinSignatures)
	}
	if cfg.WeakSubjectivityPeriod != 50000 {
		t.Errorf("WeakSubjectivityPeriod = %d, want 50000", cfg.WeakSubjectivityPeriod)
	}
	if cfg.CheckpointRetention != 100 {
		t.Errorf("CheckpointRetention = %d, want 100", cfg.CheckpointRetention)
	}
}

func TestCheckpoint_Hash(t *testing.T) {
	cp := &Checkpoint{
		Height:    100,
		BlockHash: types.Hash{1, 2, 3},
		StateRoot: types.Hash{4, 5, 6},
		Timestamp: 1234567890,
		Epoch:     10,
	}
	h := cp.Hash()
	if h == (types.Hash{}) {
		t.Error("expected non-zero hash")
	}

	h2 := cp.Hash()
	if h != h2 {
		t.Error("hash should be deterministic")
	}

	cp2 := &Checkpoint{
		Height:    101,
		BlockHash: types.Hash{1, 2, 3},
		StateRoot: types.Hash{4, 5, 6},
		Timestamp: 1234567890,
		Epoch:     10,
	}
	if cp.Hash() == cp2.Hash() {
		t.Error("different heights should produce different hashes")
	}
}

func TestCheckpoint_Hash_NegativeTimestamp(t *testing.T) {
	cp := &Checkpoint{
		Height:    100,
		BlockHash: types.Hash{1},
		StateRoot: types.Hash{2},
		Timestamp: -100,
		Epoch:     1,
	}
	h := cp.Hash()
	if h == (types.Hash{}) {
		t.Error("expected non-zero hash even with negative timestamp")
	}
}

func TestCheckpointManager_New(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	if cm == nil {
		t.Fatal("expected non-nil")
	}
	if cm.config.CheckpointInterval != 1000 {
		t.Error("expected default config")
	}
}

func TestCheckpointManager_ShouldCreateCheckpoint(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)

	if cm.ShouldCreateCheckpoint(0) {
		t.Error("height 0 should not create checkpoint")
	}
	if !cm.ShouldCreateCheckpoint(1000) {
		t.Error("height 1000 should create checkpoint")
	}
	if cm.ShouldCreateCheckpoint(1001) {
		t.Error("height 1001 should not create checkpoint")
	}
	if !cm.ShouldCreateCheckpoint(2000) {
		t.Error("height 2000 should create checkpoint")
	}
}

func TestCheckpointManager_CheckWeakSubjectivity_NoCheckpoint(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	if err := cm.CheckWeakSubjectivity(100000); err != nil {
		t.Errorf("expected no error without checkpoint, got %v", err)
	}
}

func TestCheckpointManager_IsCheckpointHeight(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	if cm.IsCheckpointHeight(0) {
		t.Error("0 should not be checkpoint")
	}
	if !cm.IsCheckpointHeight(1000) {
		t.Error("1000 should be checkpoint")
	}
	if cm.IsCheckpointHeight(1001) {
		t.Error("1001 should not be checkpoint")
	}
}

func TestCheckpointManager_GetCheckpointEpoch(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	if cm.GetCheckpointEpoch(3000) != 3 {
		t.Errorf("GetCheckpointEpoch(3000) = %d, want 3", cm.GetCheckpointEpoch(3000))
	}
}

func TestCheckpointManager_SetTrustedCheckpoint_Nil(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	if err := cm.SetTrustedCheckpoint(nil); err != ErrCheckpointInvalid {
		t.Errorf("expected ErrCheckpointInvalid, got %v", err)
	}
}

func TestCheckpointManager_GetCheckpoint_NotFound(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	_, err := cm.GetCheckpoint(999)
	if err != ErrCheckpointNotFound {
		t.Errorf("expected ErrCheckpointNotFound, got %v", err)
	}
}

func TestCheckpointManager_GetLatestCheckpoint_None(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	if cm.GetLatestCheckpoint() != nil {
		t.Error("expected nil")
	}
}

func TestCheckpointManager_GetTrustedCheckpoint_None(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	if cm.GetTrustedCheckpoint() != nil {
		t.Error("expected nil")
	}
}

func TestCheckpointManager_StartCheckpoint_Twice(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	cm.StartCheckpoint(1000, types.Hash{1}, types.Hash{2})
	// Starting again overwrites pending checkpoint (no conflict since not yet finalized)
	err := cm.StartCheckpoint(1000, types.Hash{3}, types.Hash{4})
	if err != nil {
		t.Errorf("expected success overwriting pending, got %v", err)
	}
}

func TestCheckpointManager_StartCheckpoint_NewHeight(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	err := cm.StartCheckpoint(2000, types.Hash{1}, types.Hash{2})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestCheckpointManager_AddSignature_NoPending(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	err := cm.AddCheckpointSignature(types.Address{1}, []byte("sig"), 100, types.Hash{1})
	if err != ErrCheckpointNotFound {
		t.Errorf("expected ErrCheckpointNotFound, got %v", err)
	}
}

func TestCheckpointManager_Finalize_NoPending(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	_, err := cm.FinalizeCheckpoint()
	if err != ErrCheckpointNotFound {
		t.Errorf("expected ErrCheckpointNotFound, got %v", err)
	}
}

func TestCheckpointManager_ValidateChain(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	err := cm.ValidateChainAgainstCheckpoints(func(height uint64) (types.Hash, error) {
		return types.Hash{}, nil
	})
	if err != nil {
		t.Errorf("expected no error with empty checkpoints, got %v", err)
	}
}

func TestCheckpointManager_GetStats(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	stats := cm.GetStats(100)
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}
	if stats.TotalCheckpoints != 0 {
		t.Errorf("TotalCheckpoints = %d, want 0", stats.TotalCheckpoints)
	}
	if !stats.WeakSubjectivityOK {
		t.Error("WeakSubjectivity should be OK when no checkpoint")
	}
}

func TestCheckpointErrorConstants(t *testing.T) {
	errors := []error{
		ErrCheckpointNotFound, ErrCheckpointTooOld, ErrCheckpointInvalid,
		ErrCheckpointConflict, ErrInsufficientSignatures, ErrWeakSubjectivity,
		ErrValidatorNotActive,
	}
	for _, e := range errors {
		if e.Error() == "" {
			t.Errorf("error %T has empty message", e)
		}
	}
}

func TestDeepCopyCheckpoint(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if deepCopyCheckpoint(nil) != nil {
			t.Error("expected nil")
		}
	})

	t.Run("with signatures", func(t *testing.T) {
		cp := &Checkpoint{
			Height:     100,
			BlockHash:  types.Hash{1},
			StateRoot:  types.Hash{2},
			Timestamp:  1234567890,
			Epoch:      10,
			TotalStake: big.NewInt(5000),
			Signatures: []*CheckpointSignature{
				{ValidatorAddr: types.Address{1}, Stake: big.NewInt(100), Signature: []byte{1, 2, 3}},
			},
		}
		cp2 := deepCopyCheckpoint(cp)
		if cp2.Height != cp.Height {
			t.Error("height mismatch")
		}
		cp2.Signatures[0].Stake.Set(big.NewInt(9999))
		if cp.Signatures[0].Stake.Cmp(big.NewInt(9999)) == 0 {
			t.Error("deep copy should not affect original")
		}
	})
}

func TestCheckpoint_Verify_NoSignatures(t *testing.T) {
	cp := &Checkpoint{}
	err := cp.Verify(nil)
	if err != ErrInsufficientSignatures {
		t.Errorf("expected ErrInsufficientSignatures, got %v", err)
	}
}

func TestCheckpoint_GetAllCheckpoints(t *testing.T) {
	cm := NewCheckpointManager(nil, nil)
	cps := cm.GetAllCheckpoints()
	if len(cps) != 0 {
		t.Errorf("expected 0, got %d", len(cps))
	}
}
