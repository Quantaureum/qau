// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/params"
)

// run-4 P1 (node 8245a07 port): consensus production guards are keyed on
// params.IsProductionFailClosed(GetAttestationNetworkID()), and an UNSET
// network ID (0 = unknown identity) counts as production. This test pins the
// fail-closed behavior on the DA guard, which is the one with the widest
// blast radius (a missing checker must never let blocks skip DA review).
func TestCheckDAAvailability_FailClosedWhenNetworkIDUnknown(t *testing.T) {
	EnableTestHelpers()
	ResetAttestationNetworkIDForTesting()
	t.Cleanup(func() {
		SetAttestationNetworkID(params.DevnetChainID)
	})
	t.Setenv("QAU_PRODUCTION", "")

	qpos, err := NewQPOS(createTestValidatorSet(t, 4))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	// Network identity unknown (0) and no QAU_PRODUCTION ⇒ production mode ⇒
	// an unconfigured DA checker must be a hard error.
	if err := qpos.CheckDAAvailability(1); err == nil {
		t.Fatal("DA availability must fail closed when the attestation network ID is unknown (0)")
	}

	// Once the node declares a non-mainnet network, the legacy opt-in behavior
	// returns: no checker is non-fatal.
	SetAttestationNetworkID(params.DevnetChainID)
	if err := qpos.CheckDAAvailability(1); err != nil {
		t.Fatalf("devnet with no DA checker must stay non-fatal: %v", err)
	}
}

// TestCheckDAAvailability_MainnetRequiresChecker pins the explicit mainnet case
// independently of the unknown-ID rule.
func TestCheckDAAvailability_MainnetRequiresChecker(t *testing.T) {
	EnableTestHelpers()
	ResetAttestationNetworkIDForTesting()
	t.Cleanup(func() {
		SetAttestationNetworkID(params.DevnetChainID)
	})
	t.Setenv("QAU_PRODUCTION", "")

	qpos, err := NewQPOS(createTestValidatorSet(t, 4))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	SetAttestationNetworkID(params.MainnetChainID)
	if err := qpos.CheckDAAvailability(1); err == nil {
		t.Fatal("mainnet must require a configured DA availability checker")
	}
}
