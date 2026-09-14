// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

func TestRandomBeacon_BasicFlow(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	contrib, err := beacon.Contribute(kp.Private, kp.Public, 1)
	if err != nil {
		t.Fatalf("contribute failed: %v", err)
	}

	if contrib.ValidatorAddr != kp.Public.Address() {
		t.Fatal("contributor address mismatch")
	}

	if beacon.ContributionCount() != 1 {
		t.Fatalf("expected 1 contribution, got %d", beacon.ContributionCount())
	}

	if beacon.Phase() != BeaconPhaseCollect {
		t.Fatal("expected COLLECT phase")
	}
}

func TestRandomBeacon_Finalize(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	for i := 0; i < 3; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("key generation failed: %v", err)
		}
		if _, err := beacon.Contribute(kp.Private, kp.Public, 1); err != nil {
			t.Fatalf("contribute %d failed: %v", i, err)
		}
	}

	output, err := beacon.Finalize()
	if err != nil {
		t.Fatalf("finalize failed: %v", err)
	}

	if output.Phase != BeaconPhaseFinalized {
		t.Fatal("expected FINALIZED phase")
	}
	if output.Contributions != 3 {
		t.Fatalf("expected 3 contributions, got %d", output.Contributions)
	}
	if output.Epoch != 1 {
		t.Fatalf("expected epoch 1, got %d", output.Epoch)
	}

	var zeroRandomness [32]byte
	if output.Randomness == zeroRandomness {
		t.Fatal("randomness should not be all zeros")
	}
}

func TestRandomBeacon_InsufficientContributions(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	beacon.Contribute(kp.Private, kp.Public, 1)

	_, err = beacon.Finalize()
	if err == nil {
		t.Fatal("expected error with insufficient contributions")
	}
}

func TestRandomBeacon_DoubleContribution(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	if _, err := beacon.Contribute(kp.Private, kp.Public, 1); err != nil {
		t.Fatalf("first contribute failed: %v", err)
	}

	_, err = beacon.Contribute(kp.Private, kp.Public, 1)
	if err != ErrBeaconAlreadyContribed {
		t.Fatalf("expected ErrBeaconAlreadyContribed, got: %v", err)
	}
}

func TestRandomBeacon_SubmitWithVerification(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	contrib, err := beacon.Contribute(kp.Private, kp.Public, 1)
	if err != nil {
		t.Fatalf("contribute failed: %v", err)
	}

	beacon2 := NewRandomBeacon(1, 3)
	if err := beacon2.SubmitContribution(contrib, kp.Public); err != nil {
		t.Fatalf("submit with verification failed: %v", err)
	}
}

func TestRandomBeacon_SubmitInvalidProof(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	kp1, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	kp2, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	contrib, err := beacon.Contribute(kp1.Private, kp1.Public, 1)
	if err != nil {
		t.Fatalf("contribute failed: %v", err)
	}

	beacon2 := NewRandomBeacon(1, 3)
	err = beacon2.SubmitContribution(contrib, kp2.Public)
	if err == nil {
		t.Fatal("expected error with wrong public key")
	}
}

func TestRandomBeacon_VerifyOutput(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	for i := 0; i < 3; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("key generation failed: %v", err)
		}
		beacon.Contribute(kp.Private, kp.Public, 1)
	}

	output, err := beacon.Finalize()
	if err != nil {
		t.Fatalf("finalize failed: %v", err)
	}

	if !beacon.VerifyOutput(output) {
		t.Fatal("output verification failed")
	}

	tampered := *output
	tampered.Randomness[0] ^= 0xFF
	if beacon.VerifyOutput(&tampered) {
		t.Fatal("tampered output should not verify")
	}
}

func TestRandomBeacon_DeterministicRandomness(t *testing.T) {
	beacon1 := NewRandomBeacon(1, 3)
	beacon2 := NewRandomBeacon(1, 3)

	for i := 0; i < 3; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("key generation failed: %v", err)
		}

		contrib, err := beacon1.Contribute(kp.Private, kp.Public, 1)
		if err != nil {
			t.Fatalf("contribute failed: %v", err)
		}

		beacon2.SubmitContribution(contrib, kp.Public)
	}

	out1, _ := beacon1.Finalize()
	out2, _ := beacon2.Finalize()

	if out1.Randomness != out2.Randomness {
		t.Fatal("same contributions should produce same randomness")
	}
}

func TestRandomBeacon_DifferentEpochs(t *testing.T) {
	beacon1 := NewRandomBeacon(1, 3)
	beacon2 := NewRandomBeacon(2, 3)

	for i := 0; i < 3; i++ {
		kp, _ := crypto.GenerateKeyPair()
		beacon1.Contribute(kp.Private, kp.Public, 1)
		beacon2.Contribute(kp.Private, kp.Public, 2)
	}

	out1, _ := beacon1.Finalize()
	out2, _ := beacon2.Finalize()

	if out1.Randomness == out2.Randomness {
		t.Fatal("different epochs should produce different randomness")
	}
}

func TestRandomBeacon_AlreadyFinalized(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	for i := 0; i < 3; i++ {
		kp, _ := crypto.GenerateKeyPair()
		beacon.Contribute(kp.Private, kp.Public, 1)
	}

	beacon.Finalize()

	_, err := beacon.Finalize()
	if err != ErrBeaconAlreadyFinalized {
		t.Fatalf("expected ErrBeaconAlreadyFinalized, got: %v", err)
	}
}

func TestBeaconChain(t *testing.T) {
	chain := NewBeaconChain()

	beacon := chain.CreateBeacon(1, 3)
	if beacon == nil {
		t.Fatal("CreateBeacon returned nil")
	}

	retrieved := chain.GetBeacon(1)
	if retrieved == nil {
		t.Fatal("GetBeacon returned nil")
	}

	_, err := chain.GetRandomness(1)
	if err == nil {
		t.Fatal("expected error for unfinalized beacon")
	}

	for i := 0; i < 3; i++ {
		kp, _ := crypto.GenerateKeyPair()
		beacon.Contribute(kp.Private, kp.Public, 1)
	}

	beacon.Finalize()

	randomness, err := chain.GetRandomness(1)
	if err != nil {
		t.Fatalf("GetRandomness failed: %v", err)
	}

	var zero [32]byte
	if randomness == zero {
		t.Fatal("randomness should not be all zeros")
	}

	if !chain.VerifyRandomness(1, randomness) {
		t.Fatal("VerifyRandomness failed")
	}
}

func TestSelectProposerByBeacon(t *testing.T) {
	validators := make([]types.Address, 10)
	for i := range validators {
		rand.Read(validators[i][:])
	}

	var randomness [32]byte
	rand.Read(randomness[:])

	proposer, err := SelectProposerByBeacon(randomness, validators)
	if err != nil {
		t.Fatalf("SelectProposerByBeacon failed: %v", err)
	}

	found := false
	for _, v := range validators {
		if v == proposer {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("selected proposer not in validator set")
	}
}

func TestSelectProposerByBeacon_Deterministic(t *testing.T) {
	validators := make([]types.Address, 10)
	for i := range validators {
		rand.Read(validators[i][:])
	}

	var randomness [32]byte
	rand.Read(randomness[:])

	p1, _ := SelectProposerByBeacon(randomness, validators)
	p2, _ := SelectProposerByBeacon(randomness, validators)

	if p1 != p2 {
		t.Fatal("same randomness should select same proposer")
	}
}

func TestSelectProposerByBeacon_DifferentRandomness(t *testing.T) {
	validators := make([]types.Address, 100)
	for i := range validators {
		rand.Read(validators[i][:])
	}

	selected := make(map[int]int)
	for trial := 0; trial < 100; trial++ {
		var randomness [32]byte
		rand.Read(randomness[:])
		proposer, _ := SelectProposerByBeacon(randomness, validators)
		for idx, v := range validators {
			if v == proposer {
				selected[idx]++
				break
			}
		}
	}

	if len(selected) < 5 {
		t.Fatalf("expected at least 5 different proposers selected, got %d", len(selected))
	}
}

func TestSelectProposerByBeacon_Empty(t *testing.T) {
	var randomness [32]byte
	_, err := SelectProposerByBeacon(randomness, nil)
	if err == nil {
		t.Fatal("expected error with empty validator set")
	}
}

func TestBeaconVRFInput_Deterministic(t *testing.T) {
	input1 := beaconVRFInput(1, 100)
	input2 := beaconVRFInput(1, 100)

	if len(input1) != 16 {
		t.Fatalf("expected 16-byte input, got %d", len(input1))
	}

	for i := range input1 {
		if input1[i] != input2[i] {
			t.Fatal("beacon VRF input should be deterministic")
		}
	}
}

func TestBeaconVRFInput_DifferentEpochs(t *testing.T) {
	input1 := beaconVRFInput(1, 100)
	input2 := beaconVRFInput(2, 100)

	same := true
	for i := range input1 {
		if input1[i] != input2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different epochs should produce different VRF inputs")
	}
}

func TestRandomBeacon_NilKey(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	_, err := beacon.Contribute(nil, nil, 1)
	if err != ErrBeaconNilKey {
		t.Fatalf("expected ErrBeaconNilKey, got: %v", err)
	}
}

func TestRandomBeacon_ManyContributors(t *testing.T) {
	beacon := NewRandomBeacon(1, 5)

	for i := 0; i < 10; i++ {
		kp, _ := crypto.GenerateKeyPair()
		if _, err := beacon.Contribute(kp.Private, kp.Public, 1); err != nil {
			t.Fatalf("contribute %d failed: %v", i, err)
		}
	}

	output, err := beacon.Finalize()
	if err != nil {
		t.Fatalf("finalize failed: %v", err)
	}

	if output.Contributions != 10 {
		t.Fatalf("expected 10 contributions, got %d", output.Contributions)
	}
}

// ============================================================================
// CRND-R2-01 TESTS: RandomBeacon publicKey↔ValidatorAddr binding
//
// CRND-R2-01: "SubmitContribution does not bind publicKey to ValidatorAddr → impersonation / multi-key grinding"
// Fix: verify publicKey.Address() == contribution.ValidatorAddr, and optionally
// verify the address is an active consensus validator via ValidatorSetLookup.
// ============================================================================

// mockBeaconValidatorLookup is a test-only ValidatorSetLookup.
type mockBeaconValidatorLookup struct {
	active map[types.Address]bool
}

func (m *mockBeaconValidatorLookup) IsActiveValidator(addr types.Address) bool {
	return m.active[addr]
}

// TestSubmitContribution_RejectsKeyAddrMismatch verifies that SubmitContribution
// rejects a contribution where the publicKey does not derive to the claimed
// ValidatorAddr. This prevents impersonation: an attacker cannot submit a
// contribution claiming to be validator V while verifying the VRF proof with
// their own publicKey.
func TestSubmitContribution_RejectsKeyAddrMismatch(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	kp1, _ := crypto.GenerateKeyPair()
	kp2, _ := crypto.GenerateKeyPair()

	// Create a valid contribution with kp1.
	contrib, err := beacon.Contribute(kp1.Private, kp1.Public, 1)
	if err != nil {
		t.Fatalf("contribute failed: %v", err)
	}

	// Submit to a fresh beacon with kp2's public key — the binding check
	// should reject because kp2.Address() != contrib.ValidatorAddr (= kp1.Address()).
	beacon2 := NewRandomBeacon(1, 3)
	err = beacon2.SubmitContribution(contrib, kp2.Public)
	if err == nil {
		t.Fatal("SubmitContribution should reject when publicKey doesn't match ValidatorAddr")
	}
}

// TestSubmitContribution_AcceptsMatchingKey verifies that SubmitContribution
// accepts when the publicKey correctly derives to the claimed ValidatorAddr.
func TestSubmitContribution_AcceptsMatchingKey(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	kp, _ := crypto.GenerateKeyPair()
	contrib, err := beacon.Contribute(kp.Private, kp.Public, 1)
	if err != nil {
		t.Fatalf("contribute failed: %v", err)
	}

	beacon2 := NewRandomBeacon(1, 3)
	if err := beacon2.SubmitContribution(contrib, kp.Public); err != nil {
		t.Fatalf("SubmitContribution with matching key should succeed: %v", err)
	}
}

// TestSubmitContribution_RejectsNonValidator verifies that when a
// ValidatorSetLookup is configured, SubmitContribution rejects contributions
// from addresses that are not active consensus validators. This prevents
// sybil/multi-key grinding attacks.
func TestSubmitContribution_RejectsNonValidator(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	kp, _ := crypto.GenerateKeyPair()
	contrib, err := beacon.Contribute(kp.Private, kp.Public, 1)
	if err != nil {
		t.Fatalf("contribute failed: %v", err)
	}

	// Configure a validator lookup that does NOT include the contributor.
	beacon2 := NewRandomBeacon(1, 3)
	beacon2.SetValidatorLookup(&mockBeaconValidatorLookup{
		active: map[types.Address]bool{}, // empty — no one is a validator
	})

	err = beacon2.SubmitContribution(contrib, kp.Public)
	if !errors.Is(err, ErrBeaconNotValidator) {
		t.Fatalf("expected ErrBeaconNotValidator, got: %v", err)
	}
}

// TestSubmitContribution_AcceptsActiveValidator verifies that when a
// ValidatorSetLookup is configured and the contributor IS an active validator,
// SubmitContribution accepts the contribution.
func TestSubmitContribution_AcceptsActiveValidator(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	kp, _ := crypto.GenerateKeyPair()
	contrib, err := beacon.Contribute(kp.Private, kp.Public, 1)
	if err != nil {
		t.Fatalf("contribute failed: %v", err)
	}

	// Configure a validator lookup that includes the contributor.
	beacon2 := NewRandomBeacon(1, 3)
	beacon2.SetValidatorLookup(&mockBeaconValidatorLookup{
		active: map[types.Address]bool{
			contrib.ValidatorAddr: true,
		},
	})

	if err := beacon2.SubmitContribution(contrib, kp.Public); err != nil {
		t.Fatalf("SubmitContribution with active validator should succeed: %v", err)
	}
}

// ============================================================================
// R33 P2-17 TESTS: Commit-then-reveal protocol for RandomBeacon
//
// P2-17: "RandomBeacon last-revealer 1-bit bias"
// Fix: Add commit-then-reveal protocol (SubmitCommit → TransitionToReveal →
// SubmitReveal) so the last revealer cannot bias the randomness by
// withholding their VRF output after seeing others' reveals.
// ============================================================================

// TestCommitReveal_BasicFlow verifies the basic commit-then-reveal protocol:
// SubmitCommit → TransitionToReveal → SubmitReveal → Finalize.
func TestCommitReveal_BasicFlow(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	// Generate 3 validators and their contributions.
	type validatorData struct {
		kp        *crypto.KeyPair
		contrib   *BeaconContribution
		commitHex [32]byte
	}
	validators := make([]validatorData, 3)

	for i := range validators {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("key generation %d failed: %v", i, err)
		}
		validators[i].kp = kp

		// Compute VRF output locally.
		vrfInput := beaconVRFInput(1, canonicalBeaconSlot(1))
		proof, output, err := PQVRFEval(kp.Private, vrfInput)
		if err != nil {
			t.Fatalf("VRF eval %d failed: %v", i, err)
		}

		addr := kp.Public.Address()
		validators[i].contrib = &BeaconContribution{
			ValidatorAddr: addr,
			VRFProof:      proof,
			VRFOutput:     output,
			Slot:          1,
			Timestamp:     time.Unix(1000, 0),
		}
		validators[i].commitHex = ComputeBeaconCommitmentHash(addr, output)
	}

	// Phase 1: Submit commits (only hashes, no VRF output revealed).
	for i, v := range validators {
		if err := beacon.SubmitCommit(v.contrib.ValidatorAddr, v.commitHex); err != nil {
			t.Fatalf("SubmitCommit %d failed: %v", i, err)
		}
	}
	if beacon.CommitCount() != 3 {
		t.Fatalf("expected 3 commits, got %d", beacon.CommitCount())
	}
	if beacon.ContributionCount() != 0 {
		t.Fatalf("expected 0 contributions before reveal, got %d", beacon.ContributionCount())
	}

	// Transition to reveal phase.
	if err := beacon.TransitionToReveal(); err != nil {
		t.Fatalf("TransitionToReveal failed: %v", err)
	}
	if beacon.Phase() != BeaconPhaseReveal {
		t.Fatalf("expected REVEAL phase, got %s", beacon.Phase())
	}

	// Phase 2: Submit reveals (full VRF output, verified against commit).
	for i, v := range validators {
		if err := beacon.SubmitReveal(v.contrib, v.kp.Public); err != nil {
			t.Fatalf("SubmitReveal %d failed: %v", i, err)
		}
	}
	if beacon.ContributionCount() != 3 {
		t.Fatalf("expected 3 contributions after reveal, got %d", beacon.ContributionCount())
	}

	// Finalize.
	output, err := beacon.Finalize()
	if err != nil {
		t.Fatalf("finalize failed: %v", err)
	}
	if output.Contributions != 3 {
		t.Fatalf("expected 3 contributions in output, got %d", output.Contributions)
	}
	if output.Phase != BeaconPhaseFinalized {
		t.Fatalf("expected FINALIZED phase, got %s", output.Phase)
	}
}

// TestSubmitCommit_RejectsAfterTransition verifies that SubmitCommit fails
// after TransitionToReveal has been called.
func TestSubmitCommit_RejectsAfterTransition(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	kp, _ := crypto.GenerateKeyPair()
	addr := kp.Public.Address()

	vrfInput := beaconVRFInput(1, canonicalBeaconSlot(1))
	_, output, err := PQVRFEval(kp.Private, vrfInput)
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}
	commitHash := ComputeBeaconCommitmentHash(addr, output)

	if err := beacon.SubmitCommit(addr, commitHash); err != nil {
		t.Fatalf("SubmitCommit failed: %v", err)
	}

	if err := beacon.TransitionToReveal(); err != nil {
		t.Fatalf("TransitionToReveal failed: %v", err)
	}

	// SubmitCommit should fail after transition.
	kp2, _ := crypto.GenerateKeyPair()
	addr2 := kp2.Public.Address()
	_, output2, _ := PQVRFEval(kp2.Private, vrfInput)
	commitHash2 := ComputeBeaconCommitmentHash(addr2, output2)

	err = beacon.SubmitCommit(addr2, commitHash2)
	if err == nil {
		t.Fatal("SubmitCommit should fail after TransitionToReveal")
	}
}

// TestSubmitReveal_RejectsBeforeTransition verifies that SubmitReveal fails
// before TransitionToReveal has been called.
func TestSubmitReveal_RejectsBeforeTransition(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	kp, _ := crypto.GenerateKeyPair()
	addr := kp.Public.Address()

	vrfInput := beaconVRFInput(1, canonicalBeaconSlot(1))
	proof, output, err := PQVRFEval(kp.Private, vrfInput)
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}
	commitHash := ComputeBeaconCommitmentHash(addr, output)

	if err := beacon.SubmitCommit(addr, commitHash); err != nil {
		t.Fatalf("SubmitCommit failed: %v", err)
	}

	contrib := &BeaconContribution{
		ValidatorAddr: addr,
		VRFProof:      proof,
		VRFOutput:     output,
		Slot:          1,
		Timestamp:     time.Unix(1000, 0),
	}

	// SubmitReveal should fail before transition (still in COLLECT phase).
	err = beacon.SubmitReveal(contrib, kp.Public)
	if !errors.Is(err, ErrBeaconNotInRevealPhase) {
		t.Fatalf("expected ErrBeaconNotInRevealPhase, got: %v", err)
	}
}

// TestSubmitReveal_RejectsCommitMismatch verifies that SubmitReveal rejects
// a reveal whose VRF output does not match the stored commitment hash.
func TestSubmitReveal_RejectsCommitMismatch(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	kp, _ := crypto.GenerateKeyPair()
	addr := kp.Public.Address()

	vrfInput := beaconVRFInput(1, canonicalBeaconSlot(1))
	proof, output, err := PQVRFEval(kp.Private, vrfInput)
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}

	// Submit a commit with a wrong hash (random bytes).
	var wrongHash [32]byte
	rand.Read(wrongHash[:])
	if err := beacon.SubmitCommit(addr, wrongHash); err != nil {
		t.Fatalf("SubmitCommit failed: %v", err)
	}

	if err := beacon.TransitionToReveal(); err != nil {
		t.Fatalf("TransitionToReveal failed: %v", err)
	}

	contrib := &BeaconContribution{
		ValidatorAddr: addr,
		VRFProof:      proof,
		VRFOutput:     output,
		Slot:          1,
		Timestamp:     time.Unix(1000, 0),
	}

	err = beacon.SubmitReveal(contrib, kp.Public)
	if !errors.Is(err, ErrBeaconCommitMismatch) {
		t.Fatalf("expected ErrBeaconCommitMismatch, got: %v", err)
	}
}

// TestSubmitReveal_RejectsNoCommit verifies that SubmitReveal rejects a
// reveal for an address that has not submitted a commit.
func TestSubmitReveal_RejectsNoCommit(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	kp, _ := crypto.GenerateKeyPair()
	addr := kp.Public.Address()

	vrfInput := beaconVRFInput(1, canonicalBeaconSlot(1))
	proof, output, err := PQVRFEval(kp.Private, vrfInput)
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}

	// Don't submit a commit for this validator.
	// Submit a commit for a different validator to allow transition.
	kp2, _ := crypto.GenerateKeyPair()
	addr2 := kp2.Public.Address()
	_, output2, _ := PQVRFEval(kp2.Private, vrfInput)
	commitHash2 := ComputeBeaconCommitmentHash(addr2, output2)
	beacon.SubmitCommit(addr2, commitHash2)

	if err := beacon.TransitionToReveal(); err != nil {
		t.Fatalf("TransitionToReveal failed: %v", err)
	}

	contrib := &BeaconContribution{
		ValidatorAddr: addr,
		VRFProof:      proof,
		VRFOutput:     output,
		Slot:          1,
		Timestamp:     time.Unix(1000, 0),
	}

	err = beacon.SubmitReveal(contrib, kp.Public)
	if !errors.Is(err, ErrBeaconCommitNotFound) {
		t.Fatalf("expected ErrBeaconCommitNotFound, got: %v", err)
	}
}

// TestSubmitCommit_RejectsDuplicate verifies that SubmitCommit rejects a
// duplicate commit from the same address.
func TestSubmitCommit_RejectsDuplicate(t *testing.T) {
	beacon := NewRandomBeacon(1, 3)

	kp, _ := crypto.GenerateKeyPair()
	addr := kp.Public.Address()

	vrfInput := beaconVRFInput(1, canonicalBeaconSlot(1))
	_, output, err := PQVRFEval(kp.Private, vrfInput)
	if err != nil {
		t.Fatalf("VRF eval failed: %v", err)
	}
	commitHash := ComputeBeaconCommitmentHash(addr, output)

	if err := beacon.SubmitCommit(addr, commitHash); err != nil {
		t.Fatalf("first SubmitCommit failed: %v", err)
	}

	err = beacon.SubmitCommit(addr, commitHash)
	if !errors.Is(err, ErrBeaconAlreadyCommitted) {
		t.Fatalf("expected ErrBeaconAlreadyCommitted, got: %v", err)
	}
}

// TestCommitReveal_DeterministicRandomness verifies that the commit-then-reveal
// protocol produces the same randomness as the legacy single-phase protocol
// for the same set of contributions.
func TestCommitReveal_DeterministicRandomness(t *testing.T) {
	// Generate contributions.
	epoch := uint64(1)
	type validatorData struct {
		kp      *crypto.KeyPair
		contrib *BeaconContribution
		commit  [32]byte
	}
	validators := make([]validatorData, 3)

	for i := range validators {
		kp, _ := crypto.GenerateKeyPair()
		validators[i].kp = kp

		vrfInput := beaconVRFInput(epoch, canonicalBeaconSlot(epoch))
		proof, output, _ := PQVRFEval(kp.Private, vrfInput)

		addr := kp.Public.Address()
		validators[i].contrib = &BeaconContribution{
			ValidatorAddr: addr,
			VRFProof:      proof,
			VRFOutput:     output,
			Slot:          1,
			Timestamp:     time.Unix(1000, 0),
		}
		validators[i].commit = ComputeBeaconCommitmentHash(addr, output)
	}

	// Beacon 1: commit-then-reveal protocol.
	beaconCR := NewRandomBeacon(epoch, 3)
	for _, v := range validators {
		beaconCR.SubmitCommit(v.contrib.ValidatorAddr, v.commit)
	}
	beaconCR.TransitionToReveal()
	for _, v := range validators {
		beaconCR.SubmitReveal(v.contrib, v.kp.Public)
	}
	outCR, err := beaconCR.Finalize()
	if err != nil {
		t.Fatalf("commit-reveal Finalize failed: %v", err)
	}

	// Beacon 2: legacy single-phase protocol.
	beaconLegacy := NewRandomBeacon(epoch, 3)
	for _, v := range validators {
		beaconLegacy.SubmitContribution(v.contrib, v.kp.Public)
	}
	outLegacy, err := beaconLegacy.Finalize()
	if err != nil {
		t.Fatalf("legacy Finalize failed: %v", err)
	}

	// Both should produce the same randomness.
	if outCR.Randomness != outLegacy.Randomness {
		t.Fatal("commit-then-reveal and legacy should produce same randomness for same contributions")
	}
}

// TestComputeBeaconCommitmentHash_Deterministic verifies that the commitment
// hash function is deterministic.
func TestComputeBeaconCommitmentHash_Deterministic(t *testing.T) {
	addr := types.Address{}
	rand.Read(addr[:])

	output := &PQVRFOutput{}
	rand.Read(output.Value[:])

	hash1 := ComputeBeaconCommitmentHash(addr, output)
	hash2 := ComputeBeaconCommitmentHash(addr, output)

	if hash1 != hash2 {
		t.Fatal("commitment hash should be deterministic")
	}
}

// TestComputeBeaconCommitmentHash_DifferentAddresses verifies that different
// addresses produce different commitment hashes (even with the same VRF output).
func TestComputeBeaconCommitmentHash_DifferentAddresses(t *testing.T) {
	addr1 := types.Address{}
	rand.Read(addr1[:])
	addr2 := types.Address{}
	rand.Read(addr2[:])

	output := &PQVRFOutput{}
	rand.Read(output.Value[:])

	hash1 := ComputeBeaconCommitmentHash(addr1, output)
	hash2 := ComputeBeaconCommitmentHash(addr2, output)

	if hash1 == hash2 {
		t.Fatal("different addresses should produce different commitment hashes")
	}
}

// TestComputeBeaconCommitmentHash_NilOutput verifies that nil VRF output
// returns a zero hash (which SubmitCommit rejects).
func TestComputeBeaconCommitmentHash_NilOutput(t *testing.T) {
	addr := types.Address{}
	rand.Read(addr[:])

	hash := ComputeBeaconCommitmentHash(addr, nil)
	var zero [32]byte
	if hash != zero {
		t.Fatal("nil output should produce zero hash")
	}
}
