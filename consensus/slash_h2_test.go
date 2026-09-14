// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestSLASH_H2_DowntimeUsesDowntimePenaltyNotInactivity verifies that
// QPOS.SlashValidator maps "downtime" to SlashReasonDowntime (which uses
// DowntimePenalty = 1%) rather than SlashReasonInactivity (which uses
// InactivityPenalty = 0.1%).
//
// SLASH-H2 FIX (R29, 2026-07-25): Previously the switch case for "downtime"
// was missing, so it fell through to SlashReasonUnknown or was mapped to
// SlashReasonInactivity. SlashingManager.slashLocked always used its own
// DowntimePenalty (1%), creating a 10x penalty discrepancy for the same
// offense depending on which code path triggered the slash.
//
// This test verifies the penalty calculation directly via SlashingValidator
// to confirm SlashReasonDowntime yields a 1% penalty (not 0.1%).
func TestSLASH_H2_DowntimeUsesDowntimePenaltyNotInactivity(t *testing.T) {
	config, err := DefaultSlashingConfig()
	if err != nil {
		t.Fatalf("DefaultSlashingConfig failed: %v", err)
	}
	if config.DowntimePenalty != 100 {
		t.Fatalf("expected default DowntimePenalty=100 (1%%), got %d", config.DowntimePenalty)
	}
	if config.InactivityPenalty != 10 {
		t.Fatalf("expected default InactivityPenalty=10 (0.1%%), got %d", config.InactivityPenalty)
	}

	sv, err := NewSlashingValidator(config)
	if err != nil {
		t.Fatalf("NewSlashingValidator failed: %v", err)
	}

	stake := big.NewInt(1_000_000) // 1M units

	// Downtime penalty should be 1% = 10000 units
	downtimePenalty, err := sv.CalculatePenalty(stake, SlashReasonDowntime)
	if err != nil {
		t.Fatalf("CalculatePenalty(Downtime) failed: %v", err)
	}
	expectedDowntime := big.NewInt(10_000) // 1% of 1M
	if downtimePenalty.Cmp(expectedDowntime) != 0 {
		t.Errorf("SLASH-H2: downtime penalty = %s, want %s (1%% of %s) — if this is 1000 (0.1%%) the bug is still present",
			downtimePenalty.String(), expectedDowntime.String(), stake.String())
	}

	// Inactivity penalty should be 0.1% = 1000 units (regression guard)
	inactivityPenalty, err := sv.CalculatePenalty(stake, SlashReasonInactivity)
	if err != nil {
		t.Fatalf("CalculatePenalty(Inactivity) failed: %v", err)
	}
	expectedInactivity := big.NewInt(1_000) // 0.1% of 1M
	if inactivityPenalty.Cmp(expectedInactivity) != 0 {
		t.Errorf("inactivity penalty = %s, want %s (0.1%% of %s)",
			inactivityPenalty.String(), expectedInactivity.String(), stake.String())
	}

	// The key SLASH-H2 assertion: downtime penalty MUST be 10x inactivity penalty
	if downtimePenalty.Cmp(new(big.Int).Mul(inactivityPenalty, big.NewInt(10))) != 0 {
		t.Errorf("SLASH-H2: downtime penalty (%s) should be 10x inactivity penalty (%s) — both paths must be consistent",
			downtimePenalty.String(), inactivityPenalty.String())
	}
}

// TestSLASH_H2_QPOS_SlashValidator_DowntimePenalty verifies end-to-end that
// QPOS.SlashValidator("downtime") applies the DowntimePenalty (1%) and not
// InactivityPenalty (0.1%) by checking the actual stake reduction.
func TestSLASH_H2_QPOS_SlashValidator_DowntimePenalty(t *testing.T) {
	vs := createTestValidatorSet(t, 3)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	defer qpos.Stop()

	// Register a system caller authorized to slash.
	systemCaller := types.Address{0xAB, 0xCD}
	RegisterSystemCaller(systemCaller)
	defer UnregisterSystemCaller(systemCaller)
	qpos.authorizedCallers.AddCaller(systemCaller)

	// Capture the validator's original stake.
	validators := qpos.validators.Validators()
	validatorIdx := 0
	originalStake := new(big.Int).Set(validators[validatorIdx].Stake)

	// Trigger SlashValidator with "downtime" reason.
	if err := qpos.SlashValidator(validatorIdx, "downtime", systemCaller); err != nil {
		t.Fatalf("SlashValidator(downtime) failed: %v", err)
	}

	// Verify stake was reduced by 1% (DowntimePenalty = 100 bp = 1%).
	updatedValidators := qpos.validators.Validators()
	newStake := updatedValidators[validatorIdx].Stake
	expectedPenalty := new(big.Int).Div(originalStake, big.NewInt(100)) // 1%
	expectedStake := new(big.Int).Sub(originalStake, expectedPenalty)
	if newStake.Cmp(expectedStake) != 0 {
		t.Errorf("SLASH-H2: stake after downtime slash = %s, want %s (original %s - 1%% penalty %s)",
			newStake.String(), expectedStake.String(), originalStake.String(), expectedPenalty.String())
	}

	// Confirm the penalty is NOT 0.1% (which would be the InactivityPenalty bug).
	wrongExpectedStake := new(big.Int).Sub(originalStake, new(big.Int).Div(originalStake, big.NewInt(1000)))
	if newStake.Cmp(wrongExpectedStake) == 0 {
		t.Errorf("SLASH-H2 REGRESSION: stake after downtime slash matches 0.1%% (InactivityPenalty) — downtime is using the wrong penalty rate")
	}
}

// TestSLASH_H2_SetSlashingManager_PropagatesJailDuration verifies that
// SetSlashingManager propagates sm.params.JailDuration to q.jailDuration,
// so both slash paths (QPOS.SlashValidator and SlashingManager.slashLocked)
// produce the same jail expiry for temporary slashes.
func TestSLASH_H2_SetSlashingManager_PropagatesJailDuration(t *testing.T) {
	vs := createTestValidatorSet(t, 3)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	defer qpos.Stop()

	// Create a SlashingManager with a custom JailDuration.
	vm := NewValidatorManager()
	customJailDuration := int64(7200) // 2 hours
	params := &SlashingParams{
		DoubleSignPenalty:  big.NewInt(100),
		DowntimePenalty:    big.NewInt(1),
		InvalidVRFPenalty:  big.NewInt(10),
		DowntimeThreshold:  10,
		JailDuration:       customJailDuration,
		SignedBlocksWindow: 100,
	}
	sm := NewSlashingManagerWithParams(vm, params)

	// Before SetSlashingManager, q.jailDuration is 0.
	qpos.mu.RLock()
	jdBefore := qpos.jailDuration
	qpos.mu.RUnlock()
	if jdBefore != 0 {
		t.Fatalf("expected q.jailDuration=0 before SetSlashingManager, got %d", jdBefore)
	}

	qpos.SetSlashingManager(sm)

	qpos.mu.RLock()
	jdAfter := qpos.jailDuration
	qpos.mu.RUnlock()
	if jdAfter != customJailDuration {
		t.Errorf("SLASH-H2: q.jailDuration after SetSlashingManager = %d, want %d (must match sm.params.JailDuration)",
			jdAfter, customJailDuration)
	}
}

// TestSLASH_H2_SetJailDuration_MethodWorks verifies that SetJailDuration
// correctly updates q.jailDuration so external configuration can align
// QPOS.SlashValidator's jail expiry with SlashingManager's.
func TestSLASH_H2_SetJailDuration_MethodWorks(t *testing.T) {
	vs := createTestValidatorSet(t, 3)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	defer qpos.Stop()

	customJailDuration := int64(14400) // 4 hours
	qpos.SetJailDuration(customJailDuration)

	qpos.mu.RLock()
	jd := qpos.jailDuration
	qpos.mu.RUnlock()
	if jd != customJailDuration {
		t.Errorf("SLASH-H2: q.jailDuration after SetJailDuration = %d, want %d",
			jd, customJailDuration)
	}
}

// TestSLASH_H2_SlashValidator_DowntimeUsesConfiguredJailDuration verifies
// end-to-end that SlashValidator("downtime") uses q.jailDuration (propagated
// from SlashingManager) when computing JailUntil, NOT the hardcoded
// DefaultJailDuration. This is the core SLASH-H2 consistency fix: both slash
// paths must produce the same jail expiry for the same offense.
func TestSLASH_H2_SlashValidator_DowntimeUsesConfiguredJailDuration(t *testing.T) {
	vs := createTestValidatorSet(t, 3)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	defer qpos.Stop()

	// Register a system caller authorized to slash.
	systemCaller := types.Address{0xAB, 0xCD}
	RegisterSystemCaller(systemCaller)
	defer UnregisterSystemCaller(systemCaller)
	qpos.authorizedCallers.AddCaller(systemCaller)

	// Configure a non-default jail duration (e.g., 2 hours).
	// DefaultJailDuration is 3600 (1 hour); using 7200 ensures we can
	// distinguish the configured value from the hardcoded default.
	configuredJailDuration := int64(7200)
	vm := NewValidatorManager()
	params := &SlashingParams{
		DoubleSignPenalty:  big.NewInt(100),
		DowntimePenalty:    big.NewInt(1),
		InvalidVRFPenalty:  big.NewInt(10),
		DowntimeThreshold:  10,
		JailDuration:       configuredJailDuration,
		SignedBlocksWindow: 100,
	}
	sm := NewSlashingManagerWithParams(vm, params)
	qpos.SetSlashingManager(sm)

	// Record the time just before slashing to compute the expected JailUntil.
	validators := qpos.validators.Validators()
	validatorIdx := 0
	_ = validators[validatorIdx].Address // R30-IMPLEMENT (2026-07-27): documented for readability; SlashValidator takes idx

	timeBeforeSlash := time.Now().Unix()
	if err := qpos.SlashValidator(validatorIdx, "downtime", systemCaller); err != nil {
		t.Fatalf("SlashValidator(downtime) failed: %v", err)
	}
	timeAfterSlash := time.Now().Unix()

	// Verify the slashed entry's JailUntil reflects the configured jail duration.
	// R30-IMPLEMENT (2026-07-27): slashedValidators is keyed by validator index (int).
	qpos.mu.RLock()
	entry, ok := qpos.slashedValidators[validatorIdx]
	qpos.mu.RUnlock()
	if !ok {
		t.Fatal("slashedValidators[idx] not set after SlashValidator(downtime)")
	}

	if entry.Permanent {
		t.Fatal("downtime slash should be temporary (Permanent=false), not permanent")
	}

	expectedJailUntilMin := timeBeforeSlash + configuredJailDuration
	expectedJailUntilMax := timeAfterSlash + configuredJailDuration
	if entry.JailUntil < expectedJailUntilMin || entry.JailUntil > expectedJailUntilMax {
		t.Errorf("SLASH-H2: JailUntil = %d, want in range [%d, %d] (configured jail duration %d) — "+
			"if JailUntil is ~%d (1 hour) then DefaultJailDuration is still being used",
			entry.JailUntil, expectedJailUntilMin, expectedJailUntilMax,
			configuredJailDuration, timeBeforeSlash+DefaultJailDuration)
	}

	// Explicitly verify it's NOT the DefaultJailDuration (1 hour).
	defaultJailUntilApprox := timeBeforeSlash + DefaultJailDuration
	if entry.JailUntil >= defaultJailUntilApprox-5 && entry.JailUntil <= defaultJailUntilApprox+5 {
		t.Errorf("SLASH-H2 REGRESSION: JailUntil (%d) is within ±5s of default-jail-until (%d) — "+
			"QPOS.SlashValidator is still using DefaultJailDuration instead of q.jailDuration",
			entry.JailUntil, defaultJailUntilApprox)
	}
}

// TestSLASH_H2_SlashValidator_InactivityAlsoUsesConfiguredJailDuration
// verifies that SlashValidator("inactivity") also uses q.jailDuration,
// ensuring ALL temporary slash reasons benefit from the SLASH-H2 fix.
func TestSLASH_H2_SlashValidator_InactivityAlsoUsesConfiguredJailDuration(t *testing.T) {
	vs := createTestValidatorSet(t, 3)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	defer qpos.Stop()

	systemCaller := types.Address{0xAB, 0xCD}
	RegisterSystemCaller(systemCaller)
	defer UnregisterSystemCaller(systemCaller)
	qpos.authorizedCallers.AddCaller(systemCaller)

	configuredJailDuration := int64(14400) // 4 hours — distinct from DefaultJailDuration (1 hour)
	vm := NewValidatorManager()
	params := &SlashingParams{
		DoubleSignPenalty:  big.NewInt(100),
		DowntimePenalty:    big.NewInt(1),
		InvalidVRFPenalty:  big.NewInt(10),
		DowntimeThreshold:  10,
		JailDuration:       configuredJailDuration,
		SignedBlocksWindow: 100,
	}
	sm := NewSlashingManagerWithParams(vm, params)
	qpos.SetSlashingManager(sm)

	validators := qpos.validators.Validators()
	validatorIdx := 1                    // use a different validator than the downtime test
	_ = validators[validatorIdx].Address // R30-IMPLEMENT (2026-07-27): documented for readability; SlashValidator takes idx

	timeBeforeSlash := time.Now().Unix()
	if err := qpos.SlashValidator(validatorIdx, "inactivity", systemCaller); err != nil {
		t.Fatalf("SlashValidator(inactivity) failed: %v", err)
	}
	timeAfterSlash := time.Now().Unix()

	qpos.mu.RLock()
	entry, ok := qpos.slashedValidators[validatorIdx]
	qpos.mu.RUnlock()
	if !ok {
		t.Fatal("slashedValidators[idx] not set after SlashValidator(inactivity)")
	}
	if entry.Permanent {
		t.Fatal("inactivity slash should be temporary (Permanent=false), not permanent")
	}

	expectedJailUntilMin := timeBeforeSlash + configuredJailDuration
	expectedJailUntilMax := timeAfterSlash + configuredJailDuration
	if entry.JailUntil < expectedJailUntilMin || entry.JailUntil > expectedJailUntilMax {
		t.Errorf("SLASH-H2: inactivity JailUntil = %d, want in range [%d, %d] (configured jail duration %d)",
			entry.JailUntil, expectedJailUntilMin, expectedJailUntilMax, configuredJailDuration)
	}
}

// TestSLASH_H2_PermanentSlashHasZeroJailUntil verifies that permanent slashes
// (double_vote, surround_vote) have JailUntil=0 (no expiry), preserving the
// existing behavior for permanent bans. SLASH-H2 only changes the jail
// duration for TEMPORARY slashes; permanent slashes must remain permanent.
func TestSLASH_H2_PermanentSlashHasZeroJailUntil(t *testing.T) {
	vs := createTestValidatorSet(t, 3)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	defer qpos.Stop()

	systemCaller := types.Address{0xAB, 0xCD}
	RegisterSystemCaller(systemCaller)
	defer UnregisterSystemCaller(systemCaller)
	qpos.authorizedCallers.AddCaller(systemCaller)

	// Configure a non-default jail duration to ensure it doesn't leak into
	// permanent slash entries.
	configuredJailDuration := int64(7200)
	vm := NewValidatorManager()
	params := &SlashingParams{
		DoubleSignPenalty:  big.NewInt(100),
		DowntimePenalty:    big.NewInt(1),
		InvalidVRFPenalty:  big.NewInt(10),
		DowntimeThreshold:  10,
		JailDuration:       configuredJailDuration,
		SignedBlocksWindow: 100,
	}
	sm := NewSlashingManagerWithParams(vm, params)
	qpos.SetSlashingManager(sm)

	validators := qpos.validators.Validators()
	validatorIdx := 2
	_ = validators[validatorIdx].Address // R30-IMPLEMENT (2026-07-27): documented for readability; SlashValidator takes idx

	if err := qpos.SlashValidator(validatorIdx, "double_vote", systemCaller); err != nil {
		t.Fatalf("SlashValidator(double_vote) failed: %v", err)
	}

	qpos.mu.RLock()
	entry, ok := qpos.slashedValidators[validatorIdx]
	qpos.mu.RUnlock()
	if !ok {
		t.Fatal("slashedValidators[idx] not set after SlashValidator(double_vote)")
	}
	if !entry.Permanent {
		t.Error("double_vote slash should be Permanent=true")
	}
	if entry.JailUntil != 0 {
		t.Errorf("SLASH-H2: permanent slash JailUntil = %d, want 0 (permanent bans have no expiry)",
			entry.JailUntil)
	}
}
