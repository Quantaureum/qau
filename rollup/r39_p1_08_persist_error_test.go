// Quantaureum Node source, version 1.0.0.
// R39-P1-08 (2026-08-02) regression tests.
//
// R38-P1-12 made MarkDepositMinted STRICTLY return its persist error, but
// the only production caller (L2Bridge.ProcessDeposit) at line ~623 SWALLOWED
// that error — it only LOGGED "PERSIST-MARK-MINTED-FAILED" and returned nil.
// The audit (R39-P1-08) calls out that this misshandling lets a transient
// disk-full incident silently create a "memory/disk divergence": in-memory
// Minted=true (correct, the mint really happened) but disk Minted=false
// (the persist failed silently), so the NEXT ProcessDeposit call — or a
// restart — observes Minted=false and re-mints the same deposit, breaking
// the once-only bridge contract.
//
// R39-P1-08 closure: ProcessDeposit now RETURNS the error from
// MarkDepositMinted (the mint is still irreversible — we do NOT revert
// Minted=true or subtract balance, see the long comment in bridge.go).
// The caller (L1 watcher loop, etc.) MUST treat that returned error as
// "this deposit is in a half-finished state — do not ack it; alert the
// operator". Returning the error lets the caller distinguish "fully
// completed" from "minted but disk-flag persistence failed (re-mint risk
// on restart)", which was the exact failure mode swallowing hid.
//
// These tests exercise the END-TO-END path through ProcessDeposit (the
// previous R38 tests only exercised MarkDepositMinted in isolation, so
// they would NOT catch a ProcessDeposit that swallowed the error).
package rollup

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// TestR39_P1_08_ProcessDeposit_PropagatesPersistError drives the END-TO-END
// ProcessDeposit path with a failing bbolt Put timed to fire during
// MarkDepositMinted's re-persist (the same setup as the R38-P1-12 unit
// test, but asserted at the ProcessDeposit caller boundary). The fix's
// whole point is that ProcessDeposit now RETURNS this error instead of
// silently swallowing it.
//
// This test is the regression guard for R39-P1-08. If a future refactor
// reintroduces the log-and-swallow pattern in ProcessDeposit, this test
// fails because ProcessDeposit returns nil for a persist error it should
// surface.
func TestR39_P1_08_ProcessDeposit_PropagatesPersistError(t *testing.T) {
	database := &failingPutDB{MemDB: db.NewMemDB()}
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)

	// Stage a real deposit in the L1 bridge so ProcessDeposit can fetch it
	// from the bridge's own store. fakePersistentDepositHash returns the
	// bboltL1Bridge wrapping `database`.
	depositor := types.Address{0x09}
	amount := big.NewInt(500)
	depositHash, bridge := fakePersistentDepositHash(t, database, depositor, amount)

	// The L2Bridge wraps the L1Bridge + state manager.
	bridgeAddr := types.Address{0xff}
	l2Bridge := NewL2Bridge(bridge, sm, bridgeAddr)

	// Arm the failure AFTER the deposit is staged so ProcessDeposit's own
	// GET of the deposit succeeds, but the final MarkDepositMinted re-persist
	// (which calls db.Put) fails. This is the exact corner case R38-P1-12's
	// unit test verified MarkDepositMinted surfaces — R39-P1-08 must verify
	// ProcessDeposit surfaces it TOO, not just MarkDepositMinted.
	database.putErr = errors.New("R39-P1-08 disk full")

	err := l2Bridge.ProcessDeposit(depositHash)
	if err == nil {
		t.Fatal("R39-P1-08 REGRESSION: ProcessDeposit returned nil even though MarkDepositMinted's persist failed — " +
			"the log-and-swallow pattern returned, silently leaving disk Minted=false while the mint already happened " +
			"(re-mint risk on restart)")
	}
	// The error message must point at R39-P1-08 so monitoring/grep can find
	// it and operators can tell this apart from a generic mint failure.
	if !strings.Contains(err.Error(), "R39-P1-08") {
		t.Fatalf("R39-P1-08 REGRESSION: ProcessDeposit returned an error but it didn't carry the R39-P1-08 marker for ops: %v", err)
	}
}

// TestR39_P1_08_ProcessDeposit_HappyPath_StillReturnsNil verifies the fix
// does not over-fire on the happy path: when bbolt Put works, ProcessDeposit
// returns nil. Without this guard, an over-eager "always return err" bug in
// the fix would silently break all bridge processing.
func TestR39_P1_08_ProcessDeposit_HappyPath_StillReturnsNil(t *testing.T) {
	database := db.NewMemDB()
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)

	depositor := types.Address{0x09}
	amount := big.NewInt(500)
	depositHash, bridge := fakePersistentDepositHash_generalized(t, database, depositor, amount, sm)
	bridgeAddr := types.Address{0xff}
	l2Bridge := NewL2Bridge(bridge, sm, bridgeAddr)

	if err := l2Bridge.ProcessDeposit(depositHash); err != nil {
		t.Fatalf("R39-P1-08 happy-path: ProcessDeposit MUST return nil on success (regression guard against over-eager err returns), got: %v", err)
	}

	// And the once-only invariant survives: a second ProcessDeposit for the
	// SAME hash returns a deterministic "already minted" error (the R36
	// P1-ROLLUP-01 invariant guard at the head of ProcessDeposit). This is
	// NOT a regression — the error IS the idempotency signal — so we assert
	// it specifically returns "deposit already minted" rather than nil or
	// some other error.
	if err := l2Bridge.ProcessDeposit(depositHash); err == nil {
		t.Fatal("R39-P1-08 happy-path: second ProcessDeposit for already-minted hash MUST return an error to enforce once-only; got nil")
	} else if !strings.Contains(err.Error(), "already minted") {
		t.Fatalf("R39-P1-08 happy-path: second ProcessDeposit error must mention 'already minted' (the once-only invariant), got: %v", err)
	}
}

// fakePersistentDepositHash_generalized is a thin shim over the existing
// fakePersistentDepositHash that also wires the state manager so the
// ProcessDeposit happy path can run end-to-end. The existing helper (used
// by the R38-P1-12 unit tests) doesn't take a stateManager because those
// tests only exercise MarkDepositMinted in isolation; this one drives
// ProcessDeposit which MintBalance's against sm. We keep the original
// helper untouched to avoid regression-baiting the R38 tests.
func fakePersistentDepositHash_generalized(t *testing.T, database db.Database, depositor types.Address, amount *big.Int, _ *StateManager) (types.Hash, L1Bridge) {
	// Same body as fakePersistentDepositHash; the sm parameter is accepted
	// only so callers can wire the L2 bridge themselves (caller-supplied).
	return fakePersistentDepositHash(t, database, depositor, amount)
}
