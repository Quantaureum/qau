// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"os"
	"testing"
)

// TestMain sets up the test environment for the consensus package.
//
// QTD-010 FIX (R30, 2026-07-26): The consensus tests use mock TSS partial
// signatures (non-Dilithium3-length byte slices) to exercise the QTD state
// machine without a real threshold signer. Production code now rejects these
// unverified partials unless QAU_ALLOW_UNVERIFIED_TSS=1 is set. This TestMain
// sets that flag for the test binary ONLY — it does NOT affect the production
// binary. Tests that need to verify the fail-closed behavior can unset the
// flag explicitly via t.Setenv("QAU_ALLOW_UNVERIFIED_TSS", "").
//
// R54-SYSCALLERS-RESET-01 (2026-08-11): Also enables the consensus test
// helpers invariant. ResetSystemCallersForTesting / ResetGenesisHashForTesting
// / etc. panic unless EnableTestHelpers() has been called. Centralizing the
// call in TestMain keeps the M-1 fail-closed panic-guard intact while letting
// 18+ tests defer ResetSystemCallersForTesting() without each individually
// enabling helpers. The idempotent flag (testHelpersEnabled = true) is set
// to true exactly once per test binary; calling EnableTestHelpers() here does
// not change behavior for tests that already invoke it themselves, and a
// production binary that never imports _test.go files never executes this
// code path.
func TestMain(m *testing.M) {
	// Allow unverified TSS partial signatures in tests. This is safe because:
	//   1. Tests run in a controlled environment with no external attackers.
	//   2. The mock partials are used only for state-machine testing, not
	//      cryptographic verification testing.
	//   3. The production binary (qaud) never imports _test.go files, so
	//      this setting never leaks into production.
	os.Setenv("QAU_ALLOW_UNVERIFIED_TSS", "1")

	// Enable test-only helpers (Reset*ForTesting, etc.) for the whole consensus
	// test binary so individual tests do not need to call EnableTestHelpers()
	// before deferring ResetSystemCallersForTesting / similar helpers.
	EnableTestHelpers()

	os.Exit(m.Run())
}
