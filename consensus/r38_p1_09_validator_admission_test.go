// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// TestR38P1_09_RegisterValidator_GoesThroughValidatorManager verifies the
// R38-P1-09 fix: MinistryPersonnel.RegisterValidator must NOT call
// qpos.AddStakingValidator (which inserts the new validator directly into
// the active ValidatorSet). Instead it must route the registration through
// ValidatorManager.AddValidator so the new validator goes through the
// inactive/queue admission flow (Active=false until queue activation),
// public-key validation, the MaxValidators cap, and the queue delay.
//
// RED test (asserts the post-fix behavior):
//   - After RegisterValidator succeeds, the new validator MUST NOT appear in
//     qpos.GetValidatorSet() (AddStakingValidator is no longer called).
//   - After RegisterValidator succeeds, ValidatorManager.GetValidator(addr)
//     MUST exist and Active==false (inactive admission).
//   - The pubKey passed to RegisterValidator MUST be stored on the
//     ValidatorInfo (AddValidator enforces/records pubKey).
//
// This test ALSO wires vm.ministryPersonnel = mp so the
// ValidatorManager.AddValidator → RecordValidatorRegistration callback fires
// during the registration. RecordValidatorRegistration re-acquires mp.mu; if
// RegisterValidator kept holding mp.mu across the AddValidator call (the
// pre-fix pattern) this test would self-deadlock. Releasing mp.mu first
// (R38-P1-09) keeps the callback best-effort without blocking.
func TestR38P1_09_RegisterValidator_GoesThroughValidatorManager(t *testing.T) {
	// Build a QPOS with an existing validator set (3 validators).
	qpos, registry := setupMinistryRegistry(t, 3)
	mp := registry.Personnel()

	// Build a real key pair for the new validator (AddValidator stores pubKey).
	_, pub := createTestKeyPair(t)
	newAddr := pub.Address()

	// Wire a ValidatorManager + SlashingManager onto qpos so
	// MinistryPersonnel.RegisterValidator has the prerequisite references.
	vm := NewValidatorManager()
	// Wire mp into vm so AddValidator's RecordValidatorRegistration callback
	// path is exercised (regression for the self-deadlock guard).
	vm.SetMinistryPersonnel(mp)
	sm := NewSlashingManager(vm)
	// sm.systemCaller is auto-registered as a system caller by
	// NewSlashingManager ("slashing-system"); that is the caller used by
	// RegisterValidator to invoke vm.AddValidator. Attach without drain side
	// effects (mirrors r5_gov_r5_02_attachSlashingManager).
	qpos.slashingManager = sm

	// Capture the ValidatorSet pointer BEFORE registration. If the buggy path
	// (qpos.AddStakingValidator) were still in effect, vs.AddValidator would
	// mutate vs in place — we verify by checking that the validator count is
	// unchanged after RegisterValidator.
	vsBefore := qpos.GetValidatorSet()
	countBefore := vsBefore.Size()

	stake := validStake() // 100 QAU — above MinStakeAmount
	if err := mp.RegisterValidator(testSystemCaller, newAddr, pub, stake, 0, 1); err != nil {
		t.Fatalf("RegisterValidator failed: %v", err)
	}

	// Assertion 1: new validator is NOT in the active ValidatorSet.
	// (qpos.AddStakingValidator must NOT have been called.)
	vsAfter := qpos.GetValidatorSet()
	if got := vsAfter.GetValidator(newAddr); got != nil {
		t.Errorf("R38-P1-09 regression: new validator %x appears in active ValidatorSet "+
			"(AddStakingValidator was called instead of ValidatorManager.AddValidator)", newAddr[:4])
	}
	if vsAfter.Size() != countBefore {
		t.Errorf("R38-P1-09 regression: ValidatorSet size grew from %d to %d after RegisterValidator "+
			"(AddStakingValidator must not expand the active set)", countBefore, vsAfter.Size())
	}

	// Assertion 2: new validator IS tracked by ValidatorManager with Active=false
	// (inactive admission — must be activated via ValidatorQueue later).
	info, err := vm.GetValidator(newAddr)
	if err != nil {
		t.Fatalf("R38-P1-09: ValidatorManager.GetValidator(%x) returned %v; "+
			"RegisterValidator did not register with the ValidatorManager", newAddr[:4], err)
	}
	if info.Active {
		t.Errorf("R38-P1-09 regression: new validator Active=true after RegisterValidator; " +
			"non-genesis validators MUST start inactive and be activated via the queue")
	}

	// Assertion 3: pubKey was passed through to ValidatorManager.
	if info.PublicKey == nil {
		t.Error("R38-P1-09: ValidatorInfo.PublicKey is nil; pubKey was not stored on admission")
	} else if !pubKeyEqual(info.PublicKey, pub) {
		t.Error("R38-P1-09: ValidatorInfo.PublicKey does not match the pubKey passed to RegisterValidator")
	}

	// Assertion 4: stake recorded matches.
	if info.Stake == nil || info.Stake.Cmp(stake) != 0 {
		t.Errorf("R38-P1-09: ValidatorInfo.Stake = %v, want %s", info.Stake, stake.String())
	}

	// Sanity: ActivateFromQueue SHOULD now be able to flip Active to true,
	// confirming the validator is reachable via the queue admission path.
	if err := vm.ActivateFromQueue(newAddr); err != nil {
		t.Fatalf("R38-P1-09: ActivateFromQueue failed on the registered validator: %v", err)
	}
	info2, _ := vm.GetValidator(newAddr)
	if !info2.Active {
		t.Errorf("R38-P1-09: ActivateFromQueue did not flip Active to true (still %v)", info2.Active)
	}
}

// TestR38P1_09_RegisterValidator_FailClosedWithoutValidatorManager verifies
// the R38-P1-09 fail-closed contract: when the SlashingManager / ValidatorManager
// are not wired to qpos, RegisterValidator MUST return an error rather than
// fall back to the old qpos.AddStakingValidator bypass.
func TestR38P1_09_RegisterValidator_FailClosedWithoutValidatorManager(t *testing.T) {
	qpos, registry := setupMinistryRegistry(t, 3)
	mp := registry.Personnel()

	_, pub := createTestKeyPair(t)
	newAddr := pub.Address()

	// No SlashingManager set on qpos → AddValidator path is unavailable.
	if err := mp.RegisterValidator(testSystemCaller, newAddr, pub, validStake(), 0, 1); err == nil {
		t.Fatal("R38-P1-09: RegisterValidator must fail-closed when validator manager is not available, " +
			"instead of silently bypassing via qpos.AddStakingValidator")
	}

	// Confirm no validator was added to the active ValidatorSet.
	vs := qpos.GetValidatorSet()
	if vs.GetValidator(newAddr) != nil {
		t.Error("R38-P1-09: validator leaked into active ValidatorSet despite fail-closed")
	}
}

// TestR38P1_09_RegisterValidator_SelfRegistrationAuthorized verifies that
// self-registration (caller == addr) is still permitted through the
// ValidatorManager path, matching the documented authorization rule and the
// vm.AddValidator isSelf branch.
func TestR38P1_09_RegisterValidator_SelfRegistrationAuthorized(t *testing.T) {
	qpos, registry := setupMinistryRegistry(t, 3)
	mp := registry.Personnel()

	_, pub := createTestKeyPair(t)
	selfAddr := pub.Address()

	vm := NewValidatorManager()
	sm := NewSlashingManager(vm)
	qpos.slashingManager = sm

	// caller == addr → self-registration.
	if err := mp.RegisterValidator(selfAddr, selfAddr, pub, validStake(), 0, 1); err != nil {
		t.Fatalf("R38-P1-09: self-registration via RegisterValidator failed: %v", err)
	}
	if _, err := vm.GetValidator(selfAddr); err != nil {
		t.Errorf("R38-P1-09: self-registered validator not present in ValidatorManager: %v", err)
	}
}

// pubKeyEqual reports whether two Dilithium3 public keys are byte-equal,
// tolerating either side being wrapped via crypto.PublicKey (which exposes
// Bytes()).
func pubKeyEqual(a, b *crypto.PublicKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	ab := a.Bytes()
	bb := b.Bytes()
	if len(ab) != len(bb) {
		return false
	}
	for i := range ab {
		if ab[i] != bb[i] {
			return false
		}
	}
	return true
}

// keep imports stable across helper changes (e.g. if validStake() signatures
// ever change, the test files already declare the dependencies).
var _ = big.NewInt
var _ types.Address
