// Quantaureum Node source, version 1.0.0.
package node

// R39-P3-03 (2026-08-02) regression tests for the blockInsertLoop
// panic-counter threshold that triggers a process restart.
//
// Audit (R39-P3-03): the blockInsertLoop's per-iteration recover simply
// dropped the panicking block and continued the loop. A malicious peer
// could repeatedly inject blocks that panic ProcessBlock and hold the
// node in a chronic drop-and-continue state, never making forward
// progress. The fix adds an atomic counter that increments on every
// panic-recovered iteration; once the counter crosses a configurable
// threshold, the node calls os.Exit(3) so systemd / watchdog restarts
// the process from a clean state.
//
// The threshold-decision logic is extracted into the helper
// shouldRestartAfterPanic so it can be unit-tested WITHOUT triggering
// an actual os.Exit (which would kill the test process itself). The
// counter is reset to 0 on every successful block insert, so the
// threshold is a "consecutive-panic budget", not a "lifetime crash
// budget" — a single bad-patch-of-blocks early in node life won't
// accumulate toward restart during otherwise-healthy operation.
//
// Tests in this file pin five guarantees:
//   1. shouldRestartAfterPanic returns FALSE when count is below
//      threshold (default keep-going path).
//   2. shouldRestartAfterPanic returns TRUE at the exact threshold
//      boundary (count == threshold).
//   3. shouldRestartAfterPanic returns TRUE when count exceeds
//      threshold.
//   4. shouldRestartAfterPanic falls back to default 50 when threshold
//      is <= 0 (defensive against a future refactor that drops the
//      NewNode initialization).
//   5. parsePanicRestartThreshold parses QAU_PANIC_RESTART_THRESHOLD
//      correctly (valid int, invalid int, empty, < 1, exact boundary).

import (
	"os"
	"testing"
)

// ── Test 1: count < threshold → keep going (false). ──

// TestR39_P3_03_ShouldRestart_BelowThreshold pins the keep-going path:
// a panic count strictly less than the threshold MUST NOT trigger a
// restart. The audit's intent is a "consecutive-panic budget", not a
// "any panic = restart" — a single transient panic from an ill-formed
// block shouldn't restart the production node, only a SUSTAINED attack.
//
// Fixture: count=49, threshold=50 → keep going.
func TestR39_P3_03_ShouldRestart_BelowThreshold(t *testing.T) {
	if shouldRestartAfterPanic(49, 50) {
		t.Fatalf("R39-P3-03: shouldRestartAfterPanic(49,50) returned TRUE — count is below threshold; the audit's intent is a consecutive-panic budget, not 'any panic = restart'; a single transient ill-formed block shouldn't restart the production node")
	}
}

// ── Test 2: count == threshold → restart (true). ──

// TestR39_P3_03_ShouldRestart_AtBoundary pins the exact boundary: at the
// precise threshold (count==threshold), the audit's chronic-injection
// DoS guard triggers. We use >= rather than > so that an operator who
// sets QAU_PANIC_RESTART_THRESHOLD=1 gets a restart on the FIRST panic
// (the minimum useful budget — useful for paranoid high-security
// deployments where ANY panic is treated as corruption). Tests 1 + 2
// together pin the boundary as inclusive (>=), not exclusive (>).
func TestR39_P3_03_ShouldRestart_AtBoundary(t *testing.T) {
	if !shouldRestartAfterPanic(50, 50) {
		t.Fatalf("R39-P3-03: shouldRestartAfterPanic(50,50) returned FALSE at the exact threshold boundary — the audit's guard MUST trigger at count==threshold, NOT count>threshold; an operator setting QAU_PANIC_RESTART_THRESHOLD=1 expects a restart on the FIRST panic (paranoid high-security deployment)")
	}
}

// ── Test 3: count > threshold → restart (true). ──

// TestR39_P3_03_ShouldRestart_AboveThreshold pins the clear-over case:
// count strictly above threshold MUST trigger restart. Without this
// contract, a malicious peer sustaining the chronic-injection attack
// past the threshold would silently keep the node in the
// drop-and-continue state forever.
func TestR39_P3_03_ShouldRestart_AboveThreshold(t *testing.T) {
	if !shouldRestartAfterPanic(51, 50) {
		t.Fatalf("R39-P3-03: shouldRestartAfterPanic(51,50) returned FALSE — count is ABOVE threshold; the audit's chronic-injection DoS guard MUST trigger, otherwise a malicious peer sustaining the attack past the threshold would silently keep the node in the drop-and-continue state forever")
	}
}

// ── Test 4: threshold <= 0 → fall back to default 50. ──

// TestR39_P3_03_ShouldRestart_DefensiveDefault pins the defensive
// fallback: a future refactor that accidentally drops the NewNode
// initialization of panicRestartThreshold would leave the field zero-
// valued. Without the fallback, shouldRestartAfterPanic(count, 0) would
// always return true (count >= 0 always), so EVERY single panic would
// restart the node — effectively disabling the recover-then-continue
// pattern entirely. The fallback to 50 keeps the safety effective even
// when the field is zero-valued.
//
// We pin the boundary: count=49 + threshold=0 → false (49 < 50 default);
// count=50 + threshold=0 → true (50 >= 50 default); count=49 + threshold
// = -5 → false (49 < 50 default).
func TestR39_P3_03_ShouldRestart_DefensiveDefault(t *testing.T) {
	cases := []struct {
		name      string
		count     uint64
		threshold int
		want      bool
	}{
		{"threshold=0, count=49 (below default 50)", 49, 0, false},
		{"threshold=0, count=50 (at default 50)", 50, 0, true},
		{"threshold=0, count=51 (above default 50)", 51, 0, true},
		{"threshold=-5, count=49 (below default 50)", 49, -5, false},
		{"threshold=-5, count=50 (at default 50)", 50, -5, true},
		{"threshold=-999, count=100 (above default 50)", 100, -999, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := shouldRestartAfterPanic(c.count, c.threshold)
			if got != c.want {
				t.Fatalf("R39-P3-03: shouldRestartAfterPanic(count=%d, threshold=%d) returned %v, want %v — the defensive-default fallback (threshold <= 0 → effectiveThreshold=50) is missing or wrong; a future refactor that drops the NewNode init would either always-restart (count >= 0 always true) or never-restart (some other wrong default), either way violating the audit's intent", c.count, c.threshold, got, c.want)
			}
		})
	}
}

// ── Test 5: parsePanicRestartThreshold parses QAU_PANIC_RESTART_THRESHOLD. ──

// TestR39_P3_03_ParseThreshold pins the env-var parsing contract:
//   - unset env var → defaultValue returned;
//   - valid positive int → that int returned;
//   - invalid int → defaultValue returned (no panic);
//   - zero / negative → defaultValue returned (the audit's intent is
//     "restart threshold MUST be >= 1"; an operator wanting to disable
//     should set a very high value, not 0);
//   - exact boundary value (e.g., 1) is honored.
//
// We restore the env var after each subtest to avoid cross-test bleed.
func TestR39_P3_03_ParseThreshold(t *testing.T) {
	const def = 50

	cases := []struct {
		name   string
		envVal string
		setEnv bool
		want   int
	}{
		{"unset env var → default", "", false, def},
		{"empty string → default", "", true, def},
		{"valid positive int → that int", "100", true, 100},
		{"valid 1 (boundary) → 1", "1", true, 1},
		{"very high int → that int", "999999999", true, 999999999},
		{"invalid int (letters) → default", "abc", true, def},
		{"invalid int (float) → default", "50.5", true, def},
		{"zero → default (audit's intent is >=1)", "0", true, def},
		{"negative → default", "-5", true, def},
		{"whitespace only → default", "   ", true, def},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Reset env var before each subtest.
			if err := os.Unsetenv("QAU_PANIC_RESTART_THRESHOLD"); err != nil {
				t.Fatalf("fixture: os.Unsetenv failed: %v", err)
			}
			if c.setEnv {
				if err := os.Setenv("QAU_PANIC_RESTART_THRESHOLD", c.envVal); err != nil {
					t.Fatalf("fixture: os.Setenv(%q) failed: %v", c.envVal, err)
				}
			}
			got := parsePanicRestartThreshold(def)
			if got != c.want {
				t.Fatalf("R39-P3-03: parsePanicRestartThreshold(default=%d) with env %q returned %d, want %d — the env parsing contract is broken; an operator setting QAU_PANIC_RESTART_THRESHOLD=%q would get the wrong threshold, potentially leaving the chronic-injection DoS guard ineffective (parsed as default) or too aggressive (parsed below intent)", def, c.envVal, got, c.want, c.envVal)
			}
		})
	}

	// Cleanup: unset the env var after the whole Test 5 to avoid bleed
	// into other tests in the package.
	if err := os.Unsetenv("QAU_PANIC_RESTART_THRESHOLD"); err != nil {
		t.Logf("cleanup: os.Unsetenv failed (non-fatal): %v", err)
	}
}
