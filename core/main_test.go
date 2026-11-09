// Quantaureum Node source, version 1.0.0.
package core

import (
	"os"
	"testing"

	"github.com/quantaureum/qau/consensus"
)

// TestMain declares this test process a devnet (chain ID 1333) before any test
// runs. Without it, consensus.GetAttestationNetworkID() returns 0, and
// params.IsProductionFailClosed treats an unknown network as production
// (fail-closed) — which made the DA/danksharding devnet topologies built by
// these tests reject attestations with "DA committee disabled in production
// mode". Production-only gates must not fire inside devnet test topologies.
func TestMain(m *testing.M) {
	consensus.SetAttestationNetworkID(1333)
	os.Exit(m.Run())
}
