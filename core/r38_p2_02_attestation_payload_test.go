// Quantaureum Node source, version 1.0.0.
package core

import (
	"crypto/sha3"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// r38P2_02_hashHeader mirrors BlockValidator.computeHeaderHash
// (core/block_validator.go:1606-1612) so this test can pre-compute the
// parent hash inline. Without a matching ParentHash the validator
// short-circuits at the parent-hash check and we never reach the
// R38-P2-02 attestation-payload bound we want to pin.
func r38P2_02_hashHeader(h *encoding.BlockHeader) types.Hash {
	data, err := encoding.MarshalBlockHeader(h)
	if err != nil || len(data) == 0 {
		return types.Hash{}
	}
	return sha3.Sum256(data)
}

// r38P2_02ValidatorLookup is a minimal ValidatorLookup
// (core/block_validator.go:128-134) that resolves exactly one validator
// address to the public key it was constructed with. ValidateBlock at
// block_validator.go:872 fails-closed when the lookup is nil, so we need
// one configured even though our attestation-bound test does not care
// about the proposer identity per se. Activate with SetDevMode(true) +
// SetSyncingMode(true) so the actually-business-relevant validators
// (VRF, election, key-version) all skip — R38-P2-02 only concerns the
// serialization invariant in the attestation-payload bound check.
type r38P2_02ValidatorLookup struct {
	pub []byte
}

func (l *r38P2_02ValidatorLookup) GetValidatorPublicKey(addr types.Address) ([]byte, error) {
	return l.pub, nil
}

func (l *r38P2_02ValidatorLookup) IsValidator(addr types.Address) bool { return true }

// r38P2_02_newValidatorWithSkipping builds a BlockValidator configured to
// skip every validator that precedes the R38-P2-02 attestation-payload
// bound in ValidateBlock's execution sequence, so that the bound itself
// is the deciding check. The look up is set to a freshly-generated
// Dilithium3 keypair whose private half the caller uses to sign the
// Header (see ValidateSignature at block_validator.go:1791+).
//
// ChainID MUST be the devnet (1333) because ValidateHeader gates devMode
// on devnet-only chains ("devMode rejected on non-devnet chain"); any
// other chainID flips the strict path and the test never reaches the
// R38-P2-02 bound.
func r38P2_02_newValidatorWithSkipping(t *testing.T) (*BlockValidator, *crypto.KeyPair) {
	t.Helper()
	v := NewBlockValidator(1333, 30_000_000)
	v.SetDevMode(true)
	v.SetSyncingMode(true)
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	v.SetValidatorLookup(&r38P2_02ValidatorLookup{pub: kp.Public.Bytes()})
	return v, kp
}

// TestR38P2_02_ZeroAttestationCountRejectsTrailingGarbage is the RED-regression
// test for audit issue R38-P2-02 (core/block_validator.go:967-993,
// "a zero attestation count bypasses the payload byte cap").
//
// Pre-fix behavior: the attestation-payload length check was gated on
// `if attestationCount > 0`. A block that declared count=0 in the first
// 4 bytes of Header.Attestations but appended an arbitrary trailing
// payload bypassed the bound entirely — a relayer could forward megabytes
// of attacker bytes for every block under the count=0 alibi.
//
// Post-fix behavior (block_validator.go:1054-1074): when count==0, the
// only legal payload is the 4-byte count prefix itself; anything beyond
// that is treated as fraud and ValidateBlock rejects the block with
// "attestations payload too large: %d bytes (max 4 for 0 attestations)".
//
// This test pins the post-fix invariant: declaring count=0 while
// supplying trailing bytes must reject, and a clean count=0 (just the
// 4-byte prefix) must pass the attestation-payload-bound check
// specifically (so subsequent block invariants don't see this RED test
// churn fail for unrelated reasons — we sample here only that the
// P2-02 boundary holds, by also asserting the bound for a count=1
// payload whose size exceeds the per-attestation payload max).
func TestR38P2_02_ZeroAttestationCountRejectsTrailingGarbage(t *testing.T) {
	v, kp := r38P2_02_newValidatorWithSkipping(t)

	parent := &encoding.BlockHeader{
		Version:      1,
		Height:       1,
		Slot:         1,
		Epoch:        0,
		Timestamp:    1,
		ProposerAddr: types.Address{1},
		ChainID:      1333,
		GasLimit:     30_000_000,
		BaseFee:      big.NewInt(1_000_000_000),
	}

	cases := []struct {
		name        string
		attest      []byte
		wantInError string
		mustErr     bool
	}{
		{
			// count=0 + trailing garbage — the exact R38-P2-02 attack.
			// Pre-fix this was accepted (no length check fired at all
			// because attestationCount == 0 short-circuited it).
			//
			// R60-CENSUS-FMT (2026-08-09): this block is non-boundary (Slot=2),
			// so the LEGACY serializeAttestations format applies:
			// count(4) + attestations. Declaring count=0 but appending garbage
			// must still be rejected by the unconditional payload-length bound.
			name: "zero_count_with_trailing_garbage_rejected",
			attest: append(
				binary.BigEndian.AppendUint32(nil, 0),
				[]byte("garbage-trailing-payload-that-must-not-be-accepted")...,
			),
			wantInError: "attestations payload too large",
			mustErr:     true,
		},
		{
			// Oversized well-formed count=1 payload — exercises the
			// count>0 path's per-attestation cap. Pre-fix this would
			// also be accepted on the lenient side (the old code used a
			// 60+2+sig max that was equal to today's, BUT this test
			// asserts the SAME bound fires; it doubles as regression
			// guard for R37-P3-30).
			// R60-CENSUS-FMT: legacy prefix = count(1).
			name: "count_one_with_oversized_payload_rejected",
			attest: append(
				binary.BigEndian.AppendUint32(nil, 1),
				make([]byte, 60+2+crypto.Dilithium3SignatureSize+1)...,
			),
			wantInError: "attestations payload too large",
			mustErr:     true,
		},
	}

	// Non-empty signature — devMode skips Verify but ValidateBlock
	// still requires len(Signature) > 0 at the early reject gate.
	_ = kp

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {
			block := &encoding.Block{
				Header: &encoding.BlockHeader{
					Version:      1,
					Height:       2,
					Slot:         2,
					Epoch:        0,
					Timestamp:    13,
					ParentHash:   r38P2_02_hashHeader(parent),
					ProposerAddr: types.Address{1},
					ChainID:      1333,
					GasLimit:     30_000_000,
					BaseFee:      big.NewInt(875_000_000),
					Signature:    make([]byte, crypto.Dilithium3SignatureSize),
					Attestations: tc.attest,
				},
				Transactions: nil,
			}

			_, _, err := v.ValidateBlock(block, parent)
			if tc.mustErr {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil — R38-P2-02 bound is NOT enforced for the %s scenario (regression)", tc.wantInError, tc.name)
				}
				if !contains(err.Error(), tc.wantInError) {
					t.Fatalf("expected error to contain %q, got: %v (scenario %s)", tc.wantInError, err, tc.name)
				}
			}
		})
	}
}

// TestR38P2_02_CleanZeroCountPrefixPassesBoundCheck pins the second half of
// the R38-P2-02 fix: a block declaring count=0 with EXACTLY the 4-byte
// count prefix (no trailing bytes) is the unique legal encoding for an
// empty attestation list and must NOT be rejected on the payload-length
// bound alone. Combined with the trailing-garbage rejection above this
// forms the two-sided invariant; it prevents a future regression that
// either (a) over-tightens the bound to reject every count=0 frame, or
// (b) re-opens the trailing-payload hole.
//
// We can't assert that ValidateBlock returns err==nil (other validators
// in the pipeline may reject for unrelated reasons — there is no
// validator lookup installed, parent stateRoot is unset, etc.). Instead,
// the test asserts that NONE of the error reasons the R38-P2-02 check
// would emit appears in the returned error. This pinpoints the bound
// itself rather than the downstream acceptance, which is what the
// audit's R38-P2-02 finding cares about.
func TestR38P2_02_CleanZeroCountPrefixPassesBoundCheck(t *testing.T) {
	v, _ := r38P2_02_newValidatorWithSkipping(t)
	parent := &encoding.BlockHeader{
		Version:      1,
		Height:       1,
		Slot:         1,
		Epoch:        0,
		Timestamp:    1,
		ProposerAddr: types.Address{1},
		ChainID:      1333,
		GasLimit:     30_000_000,
		BaseFee:      big.NewInt(1_000_000_000),
	}

	block := &encoding.Block{
		Header: &encoding.BlockHeader{
			Version:      1,
			Height:       2,
			Slot:         2,
			Epoch:        0,
			Timestamp:    13,
			ParentHash:   r38P2_02_hashHeader(parent),
			ProposerAddr: types.Address{1},
			ChainID:      1333,
			GasLimit:     30_000_000,
			BaseFee:      big.NewInt(875_000_000),
			Signature:    make([]byte, crypto.Dilithium3SignatureSize),
			// R60-CENSUS-FMT: this block is non-boundary (Slot=2), so the LEGACY
			// format applies. A clean empty attestation list is JUST the 4-byte
			// count prefix (count=0), with no trailing bytes.
			Attestations: binary.BigEndian.AppendUint32(nil, 0),
		},
		Transactions: nil,
	}

	_, _, err := v.ValidateBlock(block, parent)
	if err != nil && contains(err.Error(), "attestations payload too large") {
		t.Fatalf("clean count=0 (4-byte prefix only) must NOT be rejected by the R38-P2-02 bound, but got: %v", err)
	}
}

// contains is a tiny strings.Contains alias kept package-local to avoid
// pulling in "strings" and shadowing the file's educational narrative.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
