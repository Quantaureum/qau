// Quantaureum Node source, version 1.0.0.
package state

import (
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// failingGetDB wraps a Database and makes Get always fail with a sentinel
// error when failOnGet is set. Used to simulate disk I/O errors in the
// SetNonce/SetBalance/SetCode paths so we can verify that the error is
// surfaced via Commit() instead of being silently swallowed.
//
// R33 P3-07 FIX regression test.
type failingGetDB struct {
	db.Database
	failOnGet bool
	getErr    error
}

func (f *failingGetDB) Get(key []byte) ([]byte, error) {
	if f.failOnGet {
		if f.getErr == nil {
			return nil, errors.New("simulated db read error")
		}
		return nil, f.getErr
	}
	return f.Database.Get(key)
}

func (f *failingGetDB) NewBatch() db.Batch {
	return f.Database.NewBatch()
}

// TestR33_P3_07_SetNonce_SurfacesSilentError verifies that when SetNonce
// encounters a DB error loading the account (other than ErrAccountNotFound),
// the error is recorded and surfaced by Commit() instead of being silently
// logged and dropped. Without the fix, Commit() would return success with a
// state root that did NOT reflect the intended nonce change, causing silent
// state drift.
func TestR33_P3_07_SetNonce_SurfacesSilentError(t *testing.T) {
	// Build a StateDB on top of a failing DB. We pre-seed an account in the
	// underlying MemDB so the account exists, then enable failOnGet so the
	// next Get (triggered by SetNonce's getAccountLocked) returns an error
	// rather than ErrAccountNotFound (which is the legitimate "new account"
	// signal and must not be treated as a hard failure).
	underlying := db.NewMemDB()
	failing := &failingGetDB{Database: underlying, failOnGet: false}
	sdb := NewStateDB(failing)

	addr := types.Address{0x42}

	// First, write an account normally so it exists in the DB.
	sdb.SetNonce(addr, 1)
	if _, err := sdb.Commit(); err != nil {
		t.Fatalf("initial Commit failed: %v", err)
	}

	// Clear the in-memory cache so the next SetNonce is forced to read from
	// the (failing) DB via getAccountLocked. In production, cache misses
	// happen naturally on restart or eviction; here we force one to test
	// the error path deterministically.
	sdb.ClearCacheForTesting()

	// Now flip the DB to fail on Get. The next SetNonce must record the
	// error; Commit must surface it.
	failing.failOnGet = true
	sdb.SetNonce(addr, 2)

	root, err := sdb.Commit()
	if err == nil {
		t.Fatalf("R33 P3-07 NOT FIXED: Commit returned nil error after SetNonce silently failed (root=%x)", root[:8])
	}
	// The error must mention SetNonce so callers can identify the source.
	if !containsStr(err.Error(), "SetNonce") {
		t.Errorf("error message %q does not mention SetNonce", err.Error())
	}
}

// TestR33_P3_07_SetBalance_SurfacesSilentError mirrors the nonce test for
// the SetBalance path.
func TestR33_P3_07_SetBalance_SurfacesSilentError(t *testing.T) {
	underlying := db.NewMemDB()
	failing := &failingGetDB{Database: underlying, failOnGet: false}
	sdb := NewStateDB(failing)

	addr := types.Address{0x99}
	sdb.SetBalance(addr, big.NewInt(100))
	if _, err := sdb.Commit(); err != nil {
		t.Fatalf("initial Commit failed: %v", err)
	}

	failing.failOnGet = true
	sdb.ClearCacheForTesting()
	sdb.SetBalance(addr, big.NewInt(200))

	_, err := sdb.Commit()
	if err == nil {
		t.Fatalf("R33 P3-07 NOT FIXED: Commit returned nil error after SetBalance silently failed")
	}
	if !containsStr(err.Error(), "SetBalance") {
		t.Errorf("error message %q does not mention SetBalance", err.Error())
	}
}

// TestR33_P3_07_SetCode_SurfacesSilentError mirrors the nonce test for the
// SetCode path. SetCode buffers the code in pendingCodeWrites, but it still
// calls getAccountLocked to stage the CodeHash on the dirty account. A DB
// error during that load must be surfaced by Commit.
func TestR33_P3_07_SetCode_SurfacesSilentError(t *testing.T) {
	underlying := db.NewMemDB()
	failing := &failingGetDB{Database: underlying, failOnGet: false}
	sdb := NewStateDB(failing)

	addr := types.Address{0xCC}
	sdb.SetCode(addr, []byte{0x01, 0x02})
	if _, err := sdb.Commit(); err != nil {
		t.Fatalf("initial Commit failed: %v", err)
	}

	failing.failOnGet = true
	sdb.ClearCacheForTesting()
	sdb.SetCode(addr, []byte{0x03, 0x04})

	_, err := sdb.Commit()
	if err == nil {
		t.Fatalf("R33 P3-07 NOT FIXED: Commit returned nil error after SetCode silently failed")
	}
	if !containsStr(err.Error(), "SetCode") {
		t.Errorf("error message %q does not mention SetCode", err.Error())
	}
}

// TestR33_P3_07_Revert_ClearsLastError verifies that a Revert() between the
// failed mutation and Commit() clears the recorded error so the next
// transaction is not spuriously aborted. This mirrors the production pattern
// where a QVM sub-call revert rolls back per-tx state.
func TestR33_P3_07_Revert_ClearsLastError(t *testing.T) {
	underlying := db.NewMemDB()
	failing := &failingGetDB{Database: underlying, failOnGet: false}
	sdb := NewStateDB(failing)

	addr := types.Address{0x77}
	sdb.SetNonce(addr, 1)
	if _, err := sdb.Commit(); err != nil {
		t.Fatalf("initial Commit failed: %v", err)
	}

	// Trigger a silent failure, then Revert — the error must be cleared.
	failing.failOnGet = true
	sdb.ClearCacheForTesting()
	sdb.SetNonce(addr, 2)
	sdb.Revert()
	failing.failOnGet = false
	sdb.ClearCacheForTesting()

	// A subsequent SetNonce on a fresh tx must succeed and Commit must NOT
	// surface the previous error.
	sdb.SetNonce(addr, 3)
	root, err := sdb.Commit()
	if err != nil {
		t.Fatalf("R33 P3-07 NOT FIXED: Commit returned error %v after Revert should have cleared lastError", err)
	}
	if root == (types.Hash{}) {
		t.Errorf("Commit returned zero root after successful tx")
	}
	// Verify the nonce was actually applied.
	if got := sdb.GetNonce(addr); got != 3 {
		t.Errorf("nonce after commit = %d, want 3", got)
	}
}

// TestR33_P3_07_FirstErrorWins verifies that when multiple mutations fail
// silently in the same transaction, Commit surfaces the FIRST error (we
// record only the first to avoid error-message proliferation and to match
// the "first failure wins" pattern used by SubBalance/AddBalance).
func TestR33_P3_07_FirstErrorWins(t *testing.T) {
	underlying := db.NewMemDB()
	failing := &failingGetDB{Database: underlying, failOnGet: false}
	sdb := NewStateDB(failing)

	addr1 := types.Address{0x11}
	addr2 := types.Address{0x22}
	// Seed both accounts.
	sdb.SetNonce(addr1, 1)
	sdb.SetNonce(addr2, 1)
	if _, err := sdb.Commit(); err != nil {
		t.Fatalf("initial Commit failed: %v", err)
	}

	// Enable failures and trigger two failed mutations.
	failing.failOnGet = true
	sdb.ClearCacheForTesting()
	sdb.SetNonce(addr1, 2)                // records first error
	sdb.SetBalance(addr2, big.NewInt(50)) // records second error (dropped)

	_, err := sdb.Commit()
	if err == nil {
		t.Fatalf("R33 P3-07 NOT FIXED: Commit returned nil error after two silent failures")
	}
	// Must surface the FIRST error (SetNonce), not the second (SetBalance).
	if !containsStr(err.Error(), "SetNonce") {
		t.Errorf("error message %q does not mention SetNonce (first error should win)", err.Error())
	}
	if containsStr(err.Error(), "SetBalance") {
		t.Errorf("error message %q mentions SetBalance (should only contain first error)", err.Error())
	}
}

// TestR33_P3_07_Copy_PreservesLastError verifies that a Copy() taken mid-tx
// preserves the silent error so the copy's Commit() also surfaces it. This
// matters for the block producer, which builds blocks on stateDB.Copy().
func TestR33_P3_07_Copy_PreservesLastError(t *testing.T) {
	underlying := db.NewMemDB()
	failing := &failingGetDB{Database: underlying, failOnGet: false}
	sdb := NewStateDB(failing)

	addr := types.Address{0xAD}
	sdb.SetNonce(addr, 1)
	if _, err := sdb.Commit(); err != nil {
		t.Fatalf("initial Commit failed: %v", err)
	}

	// Trigger a silent failure, then Copy — the copy must inherit the error.
	failing.failOnGet = true
	sdb.ClearCacheForTesting()
	sdb.SetNonce(addr, 2)
	cp := sdb.Copy()

	// Commit on the copy must surface the inherited error.
	if _, err := cp.Commit(); err == nil {
		t.Fatalf("R33 P3-07 NOT FIXED: Copy().Commit() returned nil error after inherited silent failure")
	}
}

// TestR33_P3_07_ErrAccountNotFound_NotTreatedAsError verifies that the
// legitimate "account does not exist" signal (ErrAccountNotFound) is NOT
// recorded as a silent error — SetNonce/SetBalance/SetCode must create a
// fresh account in that case. This is the happy path for new-account
// deployments.
func TestR33_P3_07_ErrAccountNotFound_NotTreatedAsError(t *testing.T) {
	sdb := NewStateDB()
	addr := types.Address{0xEE}

	// Address has never been written — getAccountLocked will return
	// ErrAccountNotFound. SetNonce must create a new account and Commit
	// must succeed.
	sdb.SetNonce(addr, 5)
	root, err := sdb.Commit()
	if err != nil {
		t.Fatalf("R33 P3-07 REGRESSION: Commit returned error %v for legitimate new-account SetNonce", err)
	}
	if root == (types.Hash{}) {
		t.Errorf("Commit returned zero root after successful new-account tx")
	}
	if got := sdb.GetNonce(addr); got != 5 {
		t.Errorf("nonce after commit = %d, want 5", got)
	}
}

// containsStr is the local string-contains helper. We don't import "strings"
// to keep the test file dependency-light and consistent with the rest of
// the package.
func containsStr(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// fmt is imported for potential future diagnostic formatting. Currently
// unused but kept to avoid churn if assertions are added later.
var _ = fmt.Sprintf
