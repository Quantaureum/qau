// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestP2P_R12_CRIT_001_VerifyAttestationSignature_ValidSignature verifies
// that the exported VerifyAttestationSignature wrapper accepts a valid
// Dilithium3 signature produced by SignAttestation.
func TestP2P_R12_CRIT_001_VerifyAttestationSignature_ValidSignature(t *testing.T) {
	qpos, keys := setupQPOSWithKeys(1)

	// Find the actual validator index in the (possibly sorted) validator set.
	vIdx := findValidatorIndex(qpos, keys[0].Public.Address())
	if vIdx < 0 {
		t.Fatalf("validator not found in set")
	}

	// Build + sign an attestation.
	// R42-P4 FIX: set the epoch-5 boundary root or CreateAttestation returns nil.
	qpos.SetEpochBlockRoot(5, types.Hash{0xcc})
	att := qpos.CreateAttestation(uint64(SlotsPerEpoch*5), types.Hash{0xcc}, vIdx)
	if att == nil {
		t.Fatal("CreateAttestation returned nil")
	}
	if err := qpos.SignAttestation(att, keys[0].Private); err != nil {
		t.Fatalf("SignAttestation failed: %v", err)
	}

	// Exported wrapper must accept the same signature that verifyAttestationSignature accepts.
	if err := qpos.VerifyAttestationSignature(att); err != nil {
		t.Errorf("VerifyAttestationSignature rejected valid signature: %v", err)
	}
}

// TestP2P_R12_CRIT_001_VerifyAttestationSignature_ForgedSignature verifies
// that a tampered signature is rejected.
func TestP2P_R12_CRIT_001_VerifyAttestationSignature_ForgedSignature(t *testing.T) {
	qpos, keys := setupQPOSWithKeys(1)
	vIdx := findValidatorIndex(qpos, keys[0].Public.Address())
	if vIdx < 0 {
		t.Fatalf("validator not found")
	}

	// R42-P4 FIX: set the epoch-5 boundary root or CreateAttestation returns nil.
	qpos.SetEpochBlockRoot(5, types.Hash{0xcc})
	att := qpos.CreateAttestation(uint64(SlotsPerEpoch*5), types.Hash{0xcc}, vIdx)
	if err := qpos.SignAttestation(att, keys[0].Private); err != nil {
		t.Fatalf("SignAttestation failed: %v", err)
	}

	// Tamper: flip the first signature byte.
	att.Signature[0] ^= 0x01

	err := qpos.VerifyAttestationSignature(att)
	if err == nil {
		t.Errorf("expected error for tampered signature, got nil")
	}
	if !errors.Is(err, ErrInvalidAttestation) {
		t.Errorf("expected ErrInvalidAttestation wrap, got %v", err)
	}
}

// TestP2P_R12_CRIT_001_VerifyAttestationSignature_NilAttestation verifies
// nil-safety: the wrapper must return an error wrapping ErrInvalidAttestation.
func TestP2P_R12_CRIT_001_VerifyAttestationSignature_NilAttestation(t *testing.T) {
	qpos, _ := setupQPOSWithKeys(1)
	err := qpos.VerifyAttestationSignature(nil)
	if err == nil {
		t.Errorf("expected error for nil attestation, got nil")
	}
	if !errors.Is(err, ErrInvalidAttestation) {
		t.Errorf("expected ErrInvalidAttestation wrap, got %v", err)
	}
}

// TestP2P_R12_CRIT_001_VerifyAttestationSignature_ValidatorIndexOutOfRange
// verifies that an out-of-range validator index is rejected with a clear error.
func TestP2P_R12_CRIT_001_VerifyAttestationSignature_ValidatorIndexOutOfRange(t *testing.T) {
	qpos, _ := setupQPOSWithKeys(1)

	att := &Attestation{
		Slot:            1,
		BeaconBlockRoot: types.Hash{0xaa},
		ValidatorIndex:  99, // out of range
		Signature:       make([]byte, 3293),
	}
	err := qpos.VerifyAttestationSignature(att)
	if err == nil {
		t.Errorf("expected error for OOR index, got nil")
	}
	if !errors.Is(err, ErrInvalidAttestation) {
		t.Errorf("expected ErrInvalidAttestation wrap, got %v", err)
	}
}

// TestP2P_R12_CRIT_001_VerifyAttestationSignature_NegativeValidatorIndex
// verifies that a negative validator index is rejected (defensive bound check
// added during P2P-R12-CRIT-001 — protects the `validators[idx]` lookup).
func TestP2P_R12_CRIT_001_VerifyAttestationSignature_NegativeValidatorIndex(t *testing.T) {
	qpos, _ := setupQPOSWithKeys(1)

	att := &Attestation{
		Slot:            1,
		BeaconBlockRoot: types.Hash{0xaa},
		ValidatorIndex:  -1,
		Signature:       make([]byte, 3293),
	}
	err := qpos.VerifyAttestationSignature(att)
	if err == nil {
		t.Errorf("expected error for negative index, got nil")
	}
	if !errors.Is(err, ErrInvalidAttestation) {
		t.Errorf("expected ErrInvalidAttestation wrap, got %v", err)
	}
}

// TestP2P_R12_CRIT_001_VerifyAttestationSignature_EmptySignature verifies
// that an empty signature is rejected before any crypto work.
func TestP2P_R12_CRIT_001_VerifyAttestationSignature_EmptySignature(t *testing.T) {
	qpos, _ := setupQPOSWithKeys(1)

	att := &Attestation{
		Slot:            1,
		BeaconBlockRoot: types.Hash{0xaa},
		ValidatorIndex:  0,
		Signature:       nil,
	}
	err := qpos.VerifyAttestationSignature(att)
	if err == nil {
		t.Errorf("expected error for empty signature, got nil")
	}
	if !errors.Is(err, ErrInvalidAttestation) {
		t.Errorf("expected ErrInvalidAttestation wrap, got %v", err)
	}
}
