// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/params"
)

// Regression tests for audit run-13 finding B6
// (qau.config/production-env-gate-not-backstopped, HIGH).
//
// Before the fix, every consensus production guard keyed solely on the
// QAU_PRODUCTION env var (params.IsProductionEnv), so a mainnet node that
// forgot to set the variable silently ran with dev-lenient guards. The fix
// switches the guard source to params.IsProduction(GetAttestationNetworkID()),
// which arms the guards whenever the node is configured for the mainnet
// network ID (params.MainnetChainID == 1668), env var or not.
//
// These tests pin the env var to unset via t.Setenv and toggle ONLY the
// configured network ID, proving the backstop is independent of operator
// env discipline while testnet behavior stays unchanged.

// enableConsensusTestHelpers unlocks the *ForTesting reset mutators used to
// restore the package-global attestation network ID between cases. Idempotent.
func enableConsensusTestHelpers() {
	EnableTestHelpers()
}

// withNetworkID sets the package-global attestation network ID for the
// duration of the test and restores the zero/unfrozen state afterwards. The
// reset helper also unfreezes the ID in case an earlier test froze it.
func withNetworkID(t *testing.T, id uint64) {
	t.Helper()
	ResetAttestationNetworkIDForTesting()
	SetAttestationNetworkID(id)
	t.Cleanup(func() {
		ResetAttestationNetworkIDForTesting()
	})
}

// TestProductionGateBackstopCheckDAAvailability verifies the run-13 B6
// backstop on QPOS.CheckDAAvailability: with NO checker configured and the
// env var unset, a mainnet network ID must fail closed while a testnet
// network ID must stay permissive (dev/test liveness behavior preserved).
func TestProductionGateBackstopCheckDAAvailability(t *testing.T) {
	enableConsensusTestHelpers()
	// Pin the env var to explicitly NOT production for the whole test.
	t.Setenv("QAU_PRODUCTION", "")

	qpos, err := NewQPOS(nil)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	t.Run("mainnet ID without env arms the guard", func(t *testing.T) {
		withNetworkID(t, params.MainnetChainID)
		err := qpos.CheckDAAvailability(1)
		if err == nil {
			t.Fatal("B6 REGRESSION: CheckDAAvailability must fail closed on mainnet network ID even when QAU_PRODUCTION is unset")
		}
		if err.Error() != "DA availability checker not configured (production mode requires DA verification)" {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("testnet ID without env stays permissive", func(t *testing.T) {
		withNetworkID(t, params.TestnetChainID)
		if err := qpos.CheckDAAvailability(1); err != nil {
			t.Fatalf("B6 REGRESSION: CheckDAAvailability must stay permissive on testnet network ID without env, got: %v", err)
		}
	})

	t.Run("unset network ID keeps legacy env-only behavior", func(t *testing.T) {
		withNetworkID(t, 0)
		if err := qpos.CheckDAAvailability(1); err != nil {
			t.Fatalf("B6 REGRESSION: network ID 0 (not configured) must degrade to env-only check, got: %v", err)
		}
	})

	t.Run("env var still arms the guard regardless of network ID", func(t *testing.T) {
		withNetworkID(t, params.TestnetChainID)
		t.Setenv("QAU_PRODUCTION", "1")
		if err := qpos.CheckDAAvailability(1); err == nil {
			t.Fatal("B6 REGRESSION: explicit QAU_PRODUCTION=1 must still arm the guard on testnet")
		}
	})
}

// TestProductionGateBackstopAssignExecutive verifies the run-13 B6 backstop
// on ThreeChambersCoordinator.AssignExecutive: with the env var unset, a
// mainnet network ID must reject direct executive assignment
// (ErrAssignExecutiveDisabledInProduction) while a testnet network ID must
// still allow it (dev/test workflow preserved).
func TestProductionGateBackstopAssignExecutive(t *testing.T) {
	enableConsensusTestHelpers()
	t.Setenv("QAU_PRODUCTION", "")

	newCoordinator := func(t *testing.T) *ThreeChambersCoordinator {
		t.Helper()
		qpos, err := NewQPOS(nil)
		if err != nil {
			t.Fatalf("NewQPOS failed: %v", err)
		}
		return NewThreeChambersCoordinator(qpos)
	}

	t.Run("mainnet ID without env rejects direct assignment", func(t *testing.T) {
		withNetworkID(t, params.MainnetChainID)
		err := newCoordinator(t).AssignExecutive([]int{0, 1, 2}, 999)
		if !errors.Is(err, ErrAssignExecutiveDisabledInProduction) {
			t.Fatalf("B6 REGRESSION: AssignExecutive must fail with ErrAssignExecutiveDisabledInProduction on mainnet network ID without env, got: %v", err)
		}
	})

	t.Run("testnet ID without env allows direct assignment", func(t *testing.T) {
		withNetworkID(t, params.TestnetChainID)
		if err := newCoordinator(t).AssignExecutive([]int{0, 1, 2}, 999); err != nil {
			t.Fatalf("B6 REGRESSION: AssignExecutive must stay allowed on testnet network ID without env, got: %v", err)
		}
	})

	t.Run("env var still rejects regardless of network ID", func(t *testing.T) {
		withNetworkID(t, params.TestnetChainID)
		t.Setenv("QAU_PRODUCTION", "1")
		if err := newCoordinator(t).AssignExecutive([]int{0, 1, 2}, 999); !errors.Is(err, ErrAssignExecutiveDisabledInProduction) {
			t.Fatalf("B6 REGRESSION: explicit QAU_PRODUCTION=1 must still reject direct assignment on testnet, got: %v", err)
		}
	})
}
