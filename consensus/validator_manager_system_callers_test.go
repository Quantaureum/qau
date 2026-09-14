// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// FIX: The two regression tests below call
// ResetSystemCallersForTesting() which clears the ENTIRE global
// systemCallers map, including the init() in ministry_test.go that
// registers testSystemCaller = types.Address{0x7f} once for the whole
// test binary, AND the sync.Once-registered votingSystemCaller in
// voting.go (used by getVotingSystemCaller / ministry Rites /
// Defense.AddToBlacklist / etc). Without restoration, every
// TestMinistryDefense_* / TestMinistryJustice_* / TestP1T6_*Boost9 /
// TestCONS_R15_L01_*SetSlashingManager test that depends on
// isSystemCaller(0x7f) = true OR isSystemCaller(votingSystemCaller) = true
// cascades into "expected alert for low online ratio" /
// "unauthorized: only system callers can..." /
// "blacklisted 0/10 validators, want all blacklisted" failures when the
// consensus package is run in -count=N>1 mode (after the R54 regression
// tests execute and clear those entries from the map).
//
// The fix is a t.Cleanup that re-registers BOTH testSystemCaller AND
// votingSystemCaller after each of these R54 tests finishes. Note
// votingSystemCaller uses sync.Once so getVotingSystemCaller() itself
// never re-registers — we must explicitly call
// RegisterSystemCaller(GetVotingSystemCaller()) to push the cached
// address back into the (now-empty) global map.

func restoreTestSystemCaller(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		// Re-register the init() testSystemCaller so consensus tests
		// that depend on isSystemCaller(0x7f) = true (such as
		// TestMinistryDefense_DetectNetworkPartition_*, TestP1T6_*,
		// TestCONS_R15_L01_*SetSlashingManager) still PASS after our
		// ResetSystemCallersForTesting() clears the global map.
		RegisterSystemCaller(testSystemCaller)

		// Re-register votingSystemCaller (sync.Once-cached, but the
		// map entry was wiped by Reset). Without this,
		// HandleEmergencyAction → getVotingSystemCaller() returns a
		// cached address that no longer appears in systemCallers, so
		// Defense.AddToBlacklist returns "unauthorized: only system
		// callers can blacklist validators" and EmergencyAction
		// blacklists 0/10 validators (TestP1T6 fail mode).
		RegisterSystemCaller(GetVotingSystemCaller())

		// Clear the DeriveSystemCaller's local "registeredCallers" memo
		// (qpos_advanced.go): this memo survives ResetSystemCallers and
		// makes subsequent DeriveSystemCaller(epoch) calls SKIP
		// RegisterSystemCaller (returning cached addr WITHOUT pushing
		// back into systemCallers). Without this clear,
		// TestP1T2_EpochBoundaryRewardIntegration fails with
		// "DeriveSystemCaller did not register as system caller" under
		// -count=N>1 after the R54 regression tests.
		ResetRegisteredCallersForTesting()
	})
}

func TestResetSystemCallersForTesting_ClearsExistingRegistrations(t *testing.T) {
	if !testHelpersEnabled {
		t.Fatal("TestMain should have EnableTestHelpers(); testHelpersEnabled=false")
	}

	// FIX: restore init() testSystemCaller (0x7f)
	// AND votingSystemCaller registrations after this test clears
	// the global map.
	restoreTestSystemCaller(t)

	addrA := types.Address{0xAA}
	addrB := types.Address{0xBB}
	addrC := types.Address{0xCC}

	RegisterSystemCaller(addrA)
	RegisterSystemCaller(addrB)
	RegisterSystemCaller(addrC)

	if !isSystemCaller(addrA) {
		t.Fatalf("addrA should be system caller immediately after RegisterSystemCaller")
	}
	if !isSystemCaller(addrB) {
		t.Fatalf("addrB should be system caller immediately after RegisterSystemCaller")
	}
	if !isSystemCaller(addrC) {
		t.Fatalf("addrC should be system caller immediately after RegisterSystemCaller")
	}

	ResetSystemCallersForTesting()

	if isSystemCaller(addrA) {
		t.Fatalf("addrA should NOT be system caller after ResetSystemCallersForTesting")
	}
	if isSystemCaller(addrB) {
		t.Fatalf("addrB should NOT be system caller after ResetSystemCallersForTesting")
	}
	if isSystemCaller(addrC) {
		t.Fatalf("addrC should NOT be system caller after ResetSystemCallersForTesting")
	}

	t.Log("R52-SYSCALLERS-DEBT regression: ResetSystemCallersForTesting clears map ✓")
}

func TestResetSystemCallersForTesting_PreventsCrossIterationPollution(t *testing.T) {
	if !testHelpersEnabled {
		t.Fatal("TestMain should have EnableTestHelpers(); testHelpersEnabled=false")
	}

	// FIX: restore init() testSystemCaller (0x7f)
	// registration after this test clears the global map 3 times.
	restoreTestSystemCaller(t)

	iteration1 := types.Address{0xF0}
	iteration2 := types.Address{0xF1}
	iteration3 := types.Address{0xF2}

	RegisterSystemCaller(iteration1)
	if !isSystemCaller(iteration1) {
		t.Fatalf("iter1: addr should be system caller after Register")
	}
	ResetSystemCallersForTesting()

	RegisterSystemCaller(iteration2)
	if isSystemCaller(iteration1) {
		t.Fatalf("iter2: iter1 addr leaked after Reset+Register(iter2) → cross-iteration pollution")
	}
	if !isSystemCaller(iteration2) {
		t.Fatalf("iter2: addr should be system caller after Register")
	}
	ResetSystemCallersForTesting()

	RegisterSystemCaller(iteration3)
	if isSystemCaller(iteration1) || isSystemCaller(iteration2) {
		t.Fatalf("iter3: prior addrs leaked after Reset+Register(iter3) → cross-iteration pollution")
	}
	if !isSystemCaller(iteration3) {
		t.Fatalf("iter3: addr should be system caller after Register")
	}
	ResetSystemCallersForTesting()

	t.Log("R52-SYSCALLERS-DEBT regression: Reset prevents cross-iteration pollution ✓")
}
