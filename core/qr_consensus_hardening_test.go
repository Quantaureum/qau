// Quantaureum Node source, version 1.0.0.
package core

import "testing"

// TestVRFEnforcementActive_QR40 pins the epoch-gated VRF proof cutover.
// Blocks below the activation epoch (including genesis and all historical
// imports/replay) must keep the legacy path, so enabling the check can never
// invalidate already-finalized chain history.
func TestVRFEnforcementActive_QR40(t *testing.T) {
	cases := []struct {
		name       string
		blockEpoch uint64
		forced     bool
		activation uint64
		want       bool
	}{
		{"legacy default off", 100, false, 0, false},
		{"genesis stays legacy under gate", 0, false, 10, false},
		{"historical block below gate", 9, false, 10, false},
		{"activation boundary enforced", 10, false, 10, true},
		{"epoch after activation enforced", 11, false, 10, true},
		{"manual flag still independent of gate", 0, true, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := vrfEnforcementActive(tc.blockEpoch, tc.forced, tc.activation); got != tc.want {
				t.Fatalf("vrfEnforcementActive(%d, %v, %d) = %v, want %v",
					tc.blockEpoch, tc.forced, tc.activation, got, tc.want)
			}
		})
	}
}

// TestBlockValidatorVRFEnforcedEpoch_DefaultOff anchors the fail-safe default:
// a validator built by the production constructor never enforces VRF proofs
// until a coordinated activation epoch is explicitly wired.
func TestBlockValidatorVRFEnforcedEpoch_DefaultOff(t *testing.T) {
	v := NewBlockValidator(1333, 30_000_000)
	if got := v.VRFEnforcedEpoch(); got != 0 {
		t.Fatalf("default activation epoch = %d, want 0", got)
	}
	v.SetVRFEnforcedEpoch(42)
	if got := v.VRFEnforcedEpoch(); got != 42 {
		t.Fatalf("activation epoch after setter = %d, want 42", got)
	}
	v.SetVRFEnforcedEpoch(0)
	if got := v.VRFEnforcedEpoch(); got != 0 {
		t.Fatalf("activation epoch after reset = %d, want 0", got)
	}
}

// TestStrictVerificationOnMissingAccumulator_QR42 pins both required
// conditions: hardening must be active AND the canonical chain must prove
// the source epoch produced no block. Either missing keeps the legacy
// "trust canonical proposer" behavior and avoids stalling sync.
func TestStrictVerificationOnMissingAccumulator_QR42(t *testing.T) {
	cases := []struct {
		name          string
		hardening     bool
		chainEvidence bool
		want          bool
	}{
		{"legacy keeps trusting canonical", false, false, false},
		{"hardening without chain evidence stays fail-open", true, false, false},
		{"chain evidence without hardening stays legacy", false, true, false},
		{"hardened chain with proven empty epoch verifies strictly", true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := strictVerificationOnMissingAccumulator(tc.hardening, tc.chainEvidence); got != tc.want {
				t.Fatalf("strictVerificationOnMissingAccumulator(%v, %v) = %v, want %v",
					tc.hardening, tc.chainEvidence, got, tc.want)
			}
		})
	}
}
