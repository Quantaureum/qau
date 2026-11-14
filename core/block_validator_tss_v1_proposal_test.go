// Quantaureum Node source, version 1.0.0.
package core

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// Tests for the TSS-R3-B-1 P0 per-epoch Dilithium3 v1 group-signature
// verification branch in ValidateSignature. The invariant set:
//  1. gate unset (default) -> branch inert, behavior identical to main 792226b
//  2. gate armed + epoch reached + valid v1 group signature -> accepted
//  3. gate armed but group verification fails -> falls through to the
//     individual Dilithium3 path (the branch never rejects a 3293-byte
//     signature; a proposer may always legitimately fall back to an
//     individual signature)
//  4. the branch never touches non-3293-byte signatures (4064-byte GM-QTD
//     combined signatures keep their exclusive-legacy handling)

// tssV1StaticLookup resolves every validator address to the public key it
// was constructed with (the individual proposer key in these tests).
type tssV1StaticLookup struct {
	pub []byte
}

func (l *tssV1StaticLookup) GetValidatorPublicKey(addr types.Address) ([]byte, error) {
	return l.pub, nil
}

func (l *tssV1StaticLookup) IsValidator(addr types.Address) bool { return true }

// tssV1NewHeader builds the minimal header ValidateSignature consumes:
// ChainID/Epoch/Slot feed the canonical binding, ProposerAddr gates the
// early return, and computeSigningData marshals the whole header.
func tssV1NewHeader(epoch uint64) *encoding.BlockHeader {
	return &encoding.BlockHeader{
		ChainID:      1333,
		Height:       epoch*100 + 1,
		Epoch:        epoch,
		Slot:         epoch*100 + 1,
		ProposerAddr: types.BytesToAddress([]byte{0x42}),
	}
}

// tssV1SigningData mirrors ValidateSignature's own computation so the test
// signs exactly what the verifier reconstructs.
func tssV1SigningData(t *testing.T, v *BlockValidator, header *encoding.BlockHeader) []byte {
	t.Helper()
	signingData := v.computeSigningData(header)
	if signingData == nil {
		t.Fatal("computeSigningData returned nil")
	}
	return signingData
}

// tssV1Bound is the canonical TSS binding message the P1 proposal signer
// commits to (and the v1 branch therefore accepts as its second form).
func tssV1Bound(header *encoding.BlockHeader, signingData []byte) []byte {
	bound := consensus.ComputeTSSCanonicalBinding(header.ChainID, header.Epoch, header.Slot, header.ProposerAddr, "block", signingData)
	return bound[:]
}

func tssV1Sign(t *testing.T, kp *crypto.KeyPair, msg []byte) []byte {
	t.Helper()
	sig, err := kp.Private.Sign(msg)
	if err != nil {
		t.Fatalf("Dilithium3 sign failed: %v", err)
	}
	return sig
}

// TestValidateSignature_TSSV1_GateUnconfigured_Inert pins invariant 1: even
// with a group key lookup injected, an UNCONFIGURED activation epoch (0, the
// default) keeps the branch inert, so a valid GROUP signature over the
// header falls through to individual verification and is rejected exactly
// as on main 792226b (no tssVerifier configured).
func TestValidateSignature_TSSV1_GateUnconfigured_Inert(t *testing.T) {
	v := NewBlockValidator(1333, 30_000_000)

	groupKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	individualKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	// The registered proposer key is the INDIVIDUAL key, so a group signature
	// cannot pass the individual fallback path — only the (inert) v1 branch
	// could accept it, which is exactly what this test pins off.
	v.SetValidatorLookup(&tssV1StaticLookup{pub: individualKP.Public.Bytes()})
	v.SetTSSV1GroupKeyLookup(func(epoch uint64) []byte { return groupKP.Public.Bytes() })
	// No SetTSSV1ProposalActivationEpoch call: gate stays 0 (the default).

	header := tssV1NewHeader(10)
	signingData := tssV1SigningData(t, v, header)
	header.Signature = tssV1Sign(t, groupKP, signingData)

	if err := v.ValidateSignature(header); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("gate unset: group signature accepted (%v), want ErrInvalidSignature (branch must stay inert)", err)
	}
}

// TestValidateSignature_TSSV1_GateArmed_GroupSignatureAccepted pins
// invariant 2 for both accepted message forms: the raw signing hash and the
// canonical TSS binding (the form the P1 proposal signer commits to). A
// header below the activation epoch keeps the branch inert and is rejected.
func TestValidateSignature_TSSV1_GateArmed_GroupSignatureAccepted(t *testing.T) {
	groupKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	newArmedValidator := func(t *testing.T) *BlockValidator {
		t.Helper()
		v := NewBlockValidator(1333, 30_000_000)
		v.SetValidatorLookup(&tssV1StaticLookup{pub: groupKP.Public.Bytes()})
		v.SetTSSV1ProposalActivationEpoch(10)
		v.SetTSSV1GroupKeyLookup(func(epoch uint64) []byte { return groupKP.Public.Bytes() })
		return v
	}

	// Canonical-bound group signature at the activation epoch: accepted.
	v := newArmedValidator(t)
	header := tssV1NewHeader(10)
	signingData := tssV1SigningData(t, v, header)
	header.Signature = tssV1Sign(t, groupKP, tssV1Bound(header, signingData))
	if err := v.ValidateSignature(header); err != nil {
		t.Fatalf("canonical-bound v1 group signature rejected: %v", err)
	}

	// Raw-signing-data group signature (the legacy block's first form):
	// accepted too.
	v = newArmedValidator(t)
	header = tssV1NewHeader(10)
	signingData = tssV1SigningData(t, v, header)
	header.Signature = tssV1Sign(t, groupKP, signingData)
	if err := v.ValidateSignature(header); err != nil {
		t.Fatalf("raw-signing-data v1 group signature rejected: %v", err)
	}

	// Below the activation epoch the branch is inert: the same valid group
	// signature is rejected exactly as on main 792226b.
	v = newArmedValidator(t)
	header = tssV1NewHeader(9)
	signingData = tssV1SigningData(t, v, header)
	header.Signature = tssV1Sign(t, groupKP, tssV1Bound(header, signingData))
	if err := v.ValidateSignature(header); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("below activation epoch: group signature accepted (%v), want ErrInvalidSignature", err)
	}
}

// TestValidateSignature_TSSV1_GroupVerifyFails_FallsBackToIndividual pins
// invariant 3, the load-bearing acceptance criterion: with the gate armed and
// the epoch reached, a 3293-byte signature the group key does NOT verify
// (here a genuine individual signature) must fall through to the individual
// Dilithium3 path and be ACCEPTED — the v1 branch never rejects.
func TestValidateSignature_TSSV1_GroupVerifyFails_FallsBackToIndividual(t *testing.T) {
	groupKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	individualKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	v := NewBlockValidator(1333, 30_000_000)
	v.SetValidatorLookup(&tssV1StaticLookup{pub: individualKP.Public.Bytes()})
	v.SetTSSV1ProposalActivationEpoch(10)
	// The epoch DOES have a v1 group key — the individual signature just
	// does not verify under it.
	v.SetTSSV1GroupKeyLookup(func(epoch uint64) []byte { return groupKP.Public.Bytes() })

	header := tssV1NewHeader(10)
	signingData := tssV1SigningData(t, v, header)
	header.Signature = tssV1Sign(t, individualKP, signingData)

	if err := v.ValidateSignature(header); err != nil {
		t.Fatalf("individual fallback after group-verify failure rejected: %v", err)
	}
	// Note: the canonical-binding form is an acceptance form for GROUP
	// signatures only (both the legacy tssVerifier block and the v1 branch);
	// the individual path verifies the raw signing hash exclusively, so no
	// bound-form individual case exists here by contract.
}

// TestValidateSignature_TSSV1_NoOrBadKeyForEpoch_FallsBackToIndividual pins
// the fail-closed-empty lookup contract: an epoch with no validated v1 group
// key (empty export, or a key the verifier cannot unpack) keeps the branch
// inert for that epoch and the individual path decides.
func TestValidateSignature_TSSV1_NoOrBadKeyForEpoch_FallsBackToIndividual(t *testing.T) {
	individualKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	cases := []struct {
		name   string
		lookep func(epoch uint64) []byte
	}{
		{"no key for epoch", func(epoch uint64) []byte { return nil }},
		{"wrong-length key", func(epoch uint64) []byte { return []byte("short") }},
		{"degenerate key", func(epoch uint64) []byte { return make([]byte, crypto.Dilithium3PublicKeySize) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := NewBlockValidator(1333, 30_000_000)
			v.SetValidatorLookup(&tssV1StaticLookup{pub: individualKP.Public.Bytes()})
			v.SetTSSV1ProposalActivationEpoch(10)
			v.SetTSSV1GroupKeyLookup(tc.lookep)

			header := tssV1NewHeader(10)
			signingData := tssV1SigningData(t, v, header)
			header.Signature = tssV1Sign(t, individualKP, signingData)

			if err := v.ValidateSignature(header); err != nil {
				t.Fatalf("%s: individual fallback rejected: %v", tc.name, err)
			}
		})
	}
}

// TestValidateSignature_TSSV1_NeverTouches4064 pins invariant 4: a 4064-byte
// GM-QTD combined signature keeps its exclusive-legacy handling regardless of
// the v1 gate — the branch skips it, and with no tssVerifier configured it is
// rejected exactly as on main 792226b.
func TestValidateSignature_TSSV1_NeverTouches4064(t *testing.T) {
	groupKP, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	v := NewBlockValidator(1333, 30_000_000)
	v.SetValidatorLookup(&tssV1StaticLookup{pub: groupKP.Public.Bytes()})
	v.SetTSSV1ProposalActivationEpoch(10)
	v.SetTSSV1GroupKeyLookup(func(epoch uint64) []byte { return groupKP.Public.Bytes() })

	header := tssV1NewHeader(10)
	tssV1SigningData(t, v, header) // exercise the same computation path
	header.Signature = make([]byte, crypto.GMQTDCombinedSignatureSize)

	if err := v.ValidateSignature(header); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("4064-byte signature accepted (%v), want ErrInvalidSignature (branch must not engage on non-3293 signatures)", err)
	}
}
