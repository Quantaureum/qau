// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	qaucrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// ── ShardElectionVerifier tests (P0-5) ──

// TestShardElectionVerifier_NilQPOS verifies that VerifyProposerElection
// fails when no validator public key is registered for the proposer.
func TestShardElectionVerifier_UnregisteredProposer(t *testing.T) {
	v := NewShardElectionVerifier()
	v.UpdateEpochState(nil, types.Hash{0xAA}, nil)

	proposer := types.Address{0x01}
	err := v.VerifyProposerElection(proposer, []byte{0x01}, types.Hash{0x02}, 1)
	if err == nil {
		t.Fatal("expected error for unregistered proposer")
	}
}

// TestShardElectionVerifier_NoVRFSeed verifies that verification fails when
// the VRF seed is not configured (zero hash).
func TestShardElectionVerifier_NoVRFSeed(t *testing.T) {
	v := NewShardElectionVerifier()

	// Register a proposer public key but don't set VRF seed.
	kp, _ := qaucrypto.GenerateKeyPair()
	proposer := kp.Public.Address()
	pubKeys := map[types.Address][]byte{proposer: kp.Public.Bytes()}
	v.UpdateEpochState(pubKeys, types.Hash{}, nil) // zero VRF seed

	err := v.VerifyProposerElection(proposer, []byte{0x01}, types.Hash{0x02}, 1)
	if err == nil {
		t.Fatal("expected error when VRF seed is not configured")
	}
}

// TestShardElectionVerifier_EmptyVRFProof verifies that an empty VRF proof
// is rejected.
func TestShardElectionVerifier_EmptyVRFProof(t *testing.T) {
	v := NewShardElectionVerifier()

	kp, _ := qaucrypto.GenerateKeyPair()
	proposer := kp.Public.Address()
	pubKeys := map[types.Address][]byte{proposer: kp.Public.Bytes()}
	v.UpdateEpochState(pubKeys, types.Hash{0xAA}, nil)

	err := v.VerifyProposerElection(proposer, nil, types.Hash{0x02}, 1)
	if err == nil {
		t.Fatal("expected error for empty VRF proof")
	}
}

// TestShardElectionVerifier_InvalidVRFProof verifies that an invalid VRF
// proof is rejected. A valid proof must be produced by the proposer's private
// key over the VRF seed.
func TestShardElectionVerifier_InvalidVRFProof(t *testing.T) {
	v := NewShardElectionVerifier()

	kp, _ := qaucrypto.GenerateKeyPair()
	proposer := kp.Public.Address()
	pubKeys := map[types.Address][]byte{proposer: kp.Public.Bytes()}
	vrfSeed := types.Hash{0xAA}
	v.UpdateEpochState(pubKeys, vrfSeed, nil)

	// Use a random (invalid) proof.
	invalidProof := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	err := v.VerifyProposerElection(proposer, invalidProof, types.Hash{0x02}, 1)
	if err == nil {
		t.Fatal("expected error for invalid VRF proof")
	}
}

// TestShardElectionVerifier_ValidVRFWithoutValidatorSet verifies the path
// where VRF proof is valid but no validator set is configured (only proof
// validity is checked, not election result).
func TestShardElectionVerifier_ValidVRFWithoutValidatorSet(t *testing.T) {
	v := NewShardElectionVerifier()

	kp, _ := qaucrypto.GenerateKeyPair()
	proposer := kp.Public.Address()
	pubKeys := map[types.Address][]byte{proposer: kp.Public.Bytes()}
	vrfSeed := types.Hash{0xAA}
	v.UpdateEpochState(pubKeys, vrfSeed, nil)

	// Generate a valid VRF proof.
	proof, output, err := GenerateVRF(kp.Private, vrfSeed)
	if err != nil {
		t.Fatalf("GenerateVRF failed: %v", err)
	}

	err = v.VerifyProposerElection(proposer, proof.Proof, output.Value, 1)
	if err != nil {
		t.Fatalf("expected success for valid VRF proof without validator set, got: %v", err)
	}
}

// TestShardElectionVerifier_ValidVRFWithValidatorSet verifies the full path:
// valid VRF proof + valid election result.
func TestShardElectionVerifier_ValidVRFWithValidatorSet(t *testing.T) {
	v := NewShardElectionVerifier()

	// Generate proposer key pair.
	kp, _ := qaucrypto.GenerateKeyPair()
	proposer := kp.Public.Address()

	// Create a validator set containing the proposer.
	validators := []*Validator{
		{Address: proposer, Stake: big.NewInt(1000), Active: true},
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}

	pubKeys := map[types.Address][]byte{proposer: kp.Public.Bytes()}
	vrfSeed := types.Hash{0xAA}
	v.UpdateEpochState(pubKeys, vrfSeed, vs)

	// Generate a valid VRF proof.
	proof, output, err := GenerateVRF(kp.Private, vrfSeed)
	if err != nil {
		t.Fatalf("GenerateVRF failed: %v", err)
	}

	// SelectProposer should elect our proposer (only validator).
	elected, err := vs.SelectProposer(output)
	if err != nil {
		t.Fatalf("SelectProposer failed: %v", err)
	}
	if elected.Address != proposer {
		t.Fatalf("elected proposer %x != expected %x", elected.Address[:4], proposer[:4])
	}

	err = v.VerifyProposerElection(proposer, proof.Proof, output.Value, 1)
	if err != nil {
		t.Fatalf("expected success for valid VRF + election, got: %v", err)
	}
}

// TestShardElectionVerifier_WrongProposerElected verifies that when the VRF
// output elects a DIFFERENT proposer, verification fails.
func TestShardElectionVerifier_WrongProposerElected(t *testing.T) {
	v := NewShardElectionVerifier()

	// Generate two key pairs.
	kp1, _ := qaucrypto.GenerateKeyPair()
	proposer1 := kp1.Public.Address()
	kp2, _ := qaucrypto.GenerateKeyPair()
	proposer2 := kp2.Public.Address()

	// Validator set with both.
	validators := []*Validator{
		{Address: proposer1, Stake: big.NewInt(1000), Active: true},
		{Address: proposer2, Stake: big.NewInt(1000), Active: true},
	}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}

	pubKeys := map[types.Address][]byte{
		proposer1: kp1.Public.Bytes(),
		proposer2: kp2.Public.Bytes(),
	}
	vrfSeed := types.Hash{0xAA}
	v.UpdateEpochState(pubKeys, vrfSeed, vs)

	// Generate VRF proof with kp1's private key.
	proof, output, err := GenerateVRF(kp1.Private, vrfSeed)
	if err != nil {
		t.Fatalf("GenerateVRF failed: %v", err)
	}

	// Check who gets elected.
	elected, _ := vs.SelectProposer(output)

	// If proposer2 was elected but we claim proposer1, verification must fail.
	if elected.Address == proposer2 {
		err = v.VerifyProposerElection(proposer1, proof.Proof, output.Value, 1)
		if err == nil {
			t.Fatal("expected error when wrong proposer is elected")
		}
	} else if elected.Address == proposer1 {
		// proposer1 was elected — claim proposer2 should fail.
		err = v.VerifyProposerElection(proposer2, proof.Proof, output.Value, 1)
		if err == nil {
			t.Fatal("expected error when wrong proposer is elected")
		}
	}
}

// TestShardElectionVerifier_UpdateEpochState verifies that epoch state updates
// take effect and stale data is cleared.
func TestShardElectionVerifier_UpdateEpochState(t *testing.T) {
	v := NewShardElectionVerifier()

	kp1, _ := qaucrypto.GenerateKeyPair()
	proposer1 := kp1.Public.Address()
	pubKeys1 := map[types.Address][]byte{proposer1: kp1.Public.Bytes()}

	v.UpdateEpochState(pubKeys1, types.Hash{0x01}, nil)

	// Update with a different set.
	kp2, _ := qaucrypto.GenerateKeyPair()
	proposer2 := kp2.Public.Address()
	pubKeys2 := map[types.Address][]byte{proposer2: kp2.Public.Bytes()}
	v.UpdateEpochState(pubKeys2, types.Hash{0x02}, nil)

	// proposer1 should no longer be registered.
	err := v.VerifyProposerElection(proposer1, []byte{0x01}, types.Hash{0x02}, 1)
	if err == nil {
		t.Fatal("expected error for old proposer after UpdateEpochState")
	}

	// proposer2 should be registered (but will fail on VRF seed check with
	// empty proof — that's fine, we just want to confirm it's registered).
	vrfSeed := types.Hash{0x02}
	v.UpdateEpochState(pubKeys2, vrfSeed, nil)
	proof, output, _ := GenerateVRF(kp2.Private, vrfSeed)
	err = v.VerifyProposerElection(proposer2, proof.Proof, output.Value, 1)
	if err != nil {
		t.Fatalf("expected success for new proposer after UpdateEpochState, got: %v", err)
	}
}

// ── ShardQPOSAdapter tests (P0-5) ──

// TestShardQPOSAdapter_NilQPOS verifies that verification fails when QPOS
// is not configured.
func TestShardQPOSAdapter_NilQPOS(t *testing.T) {
	a := NewShardQPOSAdapter(nil, nil)
	err := a.VerifyProposerElection(types.Address{0x01}, nil, types.Hash{}, 1)
	if err == nil {
		t.Fatal("expected error when qpos is nil")
	}
}

// TestShardQPOSAdapter_WrongProposer verifies that a non-elected proposer
// is rejected.
func TestShardQPOSAdapter_WrongProposer(t *testing.T) {
	EnableTestHelpers()
	defer ResetGenesisTimeForTesting()
	ResetAttestationNetworkIDForTesting()
	SetAttestationNetworkID(1668)
	FreezeAttestationNetworkID()

	validators := createVerificationTestValidators(5)
	vs, _ := NewValidatorSet(validators)
	qpos, _ := NewQPOS(vs)

	// Get the real elected proposer for slot 0.
	elected, err := qpos.GetProposerForSlot(0)
	if err != nil {
		t.Fatalf("GetProposerForSlot failed: %v", err)
	}

	// Use a different address as the "wrong" proposer.
	wrongProposer := types.Address{0xFF, 0xFF}
	if wrongProposer == elected.Address {
		wrongProposer[0] ^= 0xFF
	}

	a := NewShardQPOSAdapter(qpos, nil)
	err = a.VerifyProposerElection(wrongProposer, nil, types.Hash{}, 0)
	if err == nil {
		t.Fatal("expected error for wrong proposer")
	}
}

// TestShardQPOSAdapter_CorrectProposer verifies that the elected proposer
// passes verification.
func TestShardQPOSAdapter_CorrectProposer(t *testing.T) {
	EnableTestHelpers()
	defer ResetGenesisTimeForTesting()
	ResetAttestationNetworkIDForTesting()
	SetAttestationNetworkID(1668)
	FreezeAttestationNetworkID()

	validators := createVerificationTestValidators(5)
	vs, _ := NewValidatorSet(validators)
	qpos, _ := NewQPOS(vs)

	elected, err := qpos.GetProposerForSlot(0)
	if err != nil {
		t.Fatalf("GetProposerForSlot failed: %v", err)
	}

	a := NewShardQPOSAdapter(qpos, nil)
	err = a.VerifyProposerElection(elected.Address, nil, types.Hash{}, 0)
	if err != nil {
		t.Fatalf("expected success for elected proposer, got: %v", err)
	}
}

// TestShardQPOSAdapter_CustomSlotResolver verifies that a custom slot
// resolver is used to map shard height to mainchain slot.
func TestShardQPOSAdapter_CustomSlotResolver(t *testing.T) {
	EnableTestHelpers()
	defer ResetGenesisTimeForTesting()
	ResetAttestationNetworkIDForTesting()
	SetAttestationNetworkID(1668)
	FreezeAttestationNetworkID()

	validators := createVerificationTestValidators(5)
	vs, _ := NewValidatorSet(validators)
	qpos, _ := NewQPOS(vs)

	// Get the elected proposer for slot 10.
	elected, err := qpos.GetProposerForSlot(10)
	if err != nil {
		t.Fatalf("GetProposerForSlot(10) failed: %v", err)
	}

	// Custom resolver: shard height 5 → mainchain slot 10.
	resolver := func(height uint64) uint64 { return height * 2 }
	a := NewShardQPOSAdapter(qpos, resolver)

	// Height 5 should map to slot 10 → elected proposer passes.
	err = a.VerifyProposerElection(elected.Address, nil, types.Hash{}, 5)
	if err != nil {
		t.Fatalf("expected success with custom resolver (height=5→slot=10), got: %v", err)
	}

	// Height 6 maps to slot 12 → likely different proposer. Verify it fails
	// if the proposer differs.
	elected12, _ := qpos.GetProposerForSlot(12)
	if elected12 != nil && elected12.Address != elected.Address {
		err = a.VerifyProposerElection(elected.Address, nil, types.Hash{}, 6)
		if err == nil {
			t.Fatal("expected error when slot resolver maps to different proposer")
		}
	}
}

// TestShardQPOSAdapter_NoProposer verifies that an invalid slot (no proposer
// elected) returns an error.
func TestShardQPOSAdapter_NoProposer(t *testing.T) {
	EnableTestHelpers()
	defer ResetGenesisTimeForTesting()
	ResetAttestationNetworkIDForTesting()
	SetAttestationNetworkID(1668)
	FreezeAttestationNetworkID()

	// Empty validator set → no proposer.
	validators := []*Validator{}
	vs, err := NewValidatorSet(validators)
	if err != nil {
		// NewValidatorSet may reject empty sets; create QPOS with nil validators.
		qpos, _ := NewQPOS(nil)
		if qpos != nil {
			a := NewShardQPOSAdapter(qpos, nil)
			err = a.VerifyProposerElection(types.Address{0x01}, nil, types.Hash{}, 0)
			if err == nil {
				t.Fatal("expected error when no proposer is elected")
			}
		}
		return
	}
	qpos, _ := NewQPOS(vs)
	a := NewShardQPOSAdapter(qpos, nil)
	err = a.VerifyProposerElection(types.Address{0x01}, nil, types.Hash{}, 0)
	if err == nil {
		t.Fatal("expected error when no proposer is elected")
	}
}
