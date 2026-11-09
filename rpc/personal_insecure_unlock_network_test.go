// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"testing"

	"github.com/quantaureum/qau/params"
)

// AUDIT run-3 qau.config/production-env-gate-not-backstopped regression tests
// (ported from node 8245a07).
//
// SetAllowInsecureUnlock must refuse on a mainnet-configured node even when the
// operator forgot to set QAU_PRODUCTION=1. The network ID under which the node
// runs is the fail-closed backstop (params.IsProduction).
func TestSetAllowInsecureUnlock_MainnetNetworkIsProduction(t *testing.T) {
	t.Setenv("QAU_PRODUCTION", "")

	api := NewPersonalAPI(t.TempDir(), nil, nil, nil)
	api.SetNetworkID(params.MainnetChainID)
	api.SetAllowInsecureUnlock(true)

	api.mu.RLock()
	allowed := api.allowInsecureUnlock
	api.mu.RUnlock()
	if allowed {
		t.Fatal("allow-insecure-unlock must be rejected on mainnet network ID even without QAU_PRODUCTION")
	}
}

func TestSetAllowInsecureUnlock_DevnetStillAllowed(t *testing.T) {
	t.Setenv("QAU_PRODUCTION", "")

	api := NewPersonalAPI(t.TempDir(), nil, nil, nil)
	api.SetNetworkID(params.DevnetNetworkID)
	api.SetAllowInsecureUnlock(true)

	api.mu.RLock()
	allowed := api.allowInsecureUnlock
	api.mu.RUnlock()
	if !allowed {
		t.Fatal("allow-insecure-unlock should remain available on devnet without QAU_PRODUCTION")
	}
}

func TestSetAllowInsecureUnlock_ExplicitProductionEnvStillRejected(t *testing.T) {
	t.Setenv("QAU_PRODUCTION", "1")

	api := NewPersonalAPI(t.TempDir(), nil, nil, nil)
	api.SetNetworkID(params.DevnetNetworkID)
	api.SetAllowInsecureUnlock(true)

	api.mu.RLock()
	allowed := api.allowInsecureUnlock
	api.mu.RUnlock()
	if allowed {
		t.Fatal("allow-insecure-unlock must be rejected when QAU_PRODUCTION=1")
	}
}
