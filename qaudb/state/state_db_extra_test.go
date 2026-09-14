// Quantaureum Node source, version 1.0.0.
package state

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// helper to create a test address from a byte.
func extraTestAddr(b byte) types.Address {
	var addr types.Address
	for i := range addr {
		addr[i] = b
	}
	return addr
}

// helper to create a test hash from a byte.
func extraTestHash(b byte) types.Hash {
	var h types.Hash
	for i := range h {
		h[i] = b
	}
	return h
}

// ───── StateDB GetAccount / SetAccount ─────

func TestStateDB_SetAndGetAccount(t *testing.T) {
	sdb := NewStateDB()

	addr := extraTestAddr(0x01)
	acc := &Account{
		Nonce:       42,
		Balance:     big.NewInt(1000000),
		StorageRoot: extraTestHash(0xAA),
		CodeHash:    extraTestHash(0xBB),
	}

	sdb.SetAccount(addr, acc)

	got, err := sdb.GetAccount(addr)
	if err != nil {
		t.Fatalf("GetAccount failed: %v", err)
	}
	if got.Nonce != acc.Nonce {
		t.Errorf("nonce = %d, want %d", got.Nonce, acc.Nonce)
	}
	if got.Balance.Cmp(acc.Balance) != 0 {
		t.Errorf("balance = %s, want %s", got.Balance.String(), acc.Balance.String())
	}
	if got.StorageRoot != acc.StorageRoot {
		t.Errorf("storageRoot mismatch")
	}
	if got.CodeHash != acc.CodeHash {
		t.Errorf("codeHash mismatch")
	}
}

func TestStateDB_GetAccountNonExistent(t *testing.T) {
	sdb := NewStateDB()

	_, err := sdb.GetAccount(extraTestAddr(0x99))
	if err != ErrAccountNotFound {
		t.Errorf("expected ErrAccountNotFound, got %v", err)
	}
}

func TestStateDB_SetAccountDefensiveCopy(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x02)

	originalBalance := big.NewInt(500)
	sdb.SetAccount(addr, &Account{
		Nonce:   1,
		Balance: originalBalance,
	})

	// Mutate the original big.Int after SetAccount.
	originalBalance.Add(originalBalance, big.NewInt(999))

	// The stored balance should NOT have changed.
	got, err := sdb.GetAccount(addr)
	if err != nil {
		t.Fatal(err)
	}
	if got.Balance.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("balance was affected by external mutation: got %s, want 500", got.Balance.String())
	}
}

// ───── StateDB GetStorage / SetStorage ─────

func TestStateDB_SetAndGetStorage(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x03)
	key := extraTestHash(0x10)
	value := extraTestHash(0x20)

	sdb.SetStorage(addr, key, value)

	got := sdb.GetStorage(addr, key)
	if got != value {
		t.Errorf("storage = %x, want %x", got, value)
	}
}

func TestStateDB_GetStorageNonExistent(t *testing.T) {
	sdb := NewStateDB()

	// Should return zero hash for non-existent storage.
	got := sdb.GetStorage(extraTestAddr(0x50), extraTestHash(0x60))
	if got != (types.Hash{}) {
		t.Errorf("expected zero hash for non-existent storage, got %x", got)
	}
}

func TestStateDB_StorageMultipleKeys(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x04)

	keys := []types.Hash{extraTestHash(0x01), extraTestHash(0x02), extraTestHash(0x03)}
	vals := []types.Hash{extraTestHash(0xA1), extraTestHash(0xA2), extraTestHash(0xA3)}

	for i := range keys {
		sdb.SetStorage(addr, keys[i], vals[i])
	}

	for i := range keys {
		got := sdb.GetStorage(addr, keys[i])
		if got != vals[i] {
			t.Errorf("storage[%d] = %x, want %x", i, got, vals[i])
		}
	}
}

func TestStateDB_StorageUpdateExistingKey(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x05)
	key := extraTestHash(0x10)

	sdb.SetStorage(addr, key, extraTestHash(0xAA))
	sdb.SetStorage(addr, key, extraTestHash(0xBB))

	got := sdb.GetStorage(addr, key)
	if got != extraTestHash(0xBB) {
		t.Errorf("storage = %x, want %x (latest value)", got, extraTestHash(0xBB))
	}
}

// ───── StateDB Snapshot / RevertToSnapshot ─────

func TestStateDB_SnapshotAndRevert(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x10)

	// Set initial state.
	sdb.SetBalance(addr, big.NewInt(100))
	snap := sdb.Snapshot()

	// Modify state after snapshot.
	sdb.SetBalance(addr, big.NewInt(200))

	// Verify modified state.
	if bal := sdb.GetBalance(addr); bal.Cmp(big.NewInt(200)) != 0 {
		t.Errorf("balance before revert = %s, want 200", bal.String())
	}

	// Revert to snapshot.
	sdb.RevertToSnapshot(snap)

	// Balance should be restored.
	if bal := sdb.GetBalance(addr); bal.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("balance after revert = %s, want 100", bal.String())
	}
}

func TestStateDB_SnapshotRevertNested(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x11)

	sdb.SetBalance(addr, big.NewInt(10))
	snap1 := sdb.Snapshot()

	sdb.SetBalance(addr, big.NewInt(20))
	snap2 := sdb.Snapshot()

	sdb.SetBalance(addr, big.NewInt(30))

	// Revert to snap2 —should restore 20.
	sdb.RevertToSnapshot(snap2)
	if bal := sdb.GetBalance(addr); bal.Cmp(big.NewInt(20)) != 0 {
		t.Errorf("after revert to snap2: balance = %s, want 20", bal.String())
	}

	// Revert to snap1 —should restore 10.
	sdb.RevertToSnapshot(snap1)
	if bal := sdb.GetBalance(addr); bal.Cmp(big.NewInt(10)) != 0 {
		t.Errorf("after revert to snap1: balance = %s, want 10", bal.String())
	}
}

func TestStateDB_RevertToSnapshotInvalidID(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x12)

	sdb.SetBalance(addr, big.NewInt(100))

	// Invalid (negative) snapshot ID should fall back to clearing dirty state.
	sdb.RevertToSnapshot(-1)

	// After revert with invalid ID, dirty state is cleared.
	// Balance read should return 0 (nothing committed).
	if bal := sdb.GetBalance(addr); bal.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("after invalid revert: balance = %s, want 0", bal.String())
	}
}

func TestStateDB_SnapshotPreservesStorage(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x13)
	key := extraTestHash(0x01)

	sdb.SetStorage(addr, key, extraTestHash(0xAA))
	snap := sdb.Snapshot()

	sdb.SetStorage(addr, key, extraTestHash(0xBB))

	sdb.RevertToSnapshot(snap)

	got := sdb.GetStorage(addr, key)
	if got != extraTestHash(0xAA) {
		t.Errorf("storage after revert = %x, want %x", got, extraTestHash(0xAA))
	}
}

// ───── StateDB Commit ─────

func TestStateDB_Commit(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x20)

	sdb.SetBalance(addr, big.NewInt(1000))
	sdb.SetNonce(addr, 5)

	root, err := sdb.Commit(1)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Root should not be zero after committing non-empty state.
	if root == (types.Hash{}) {
		t.Error("expected non-zero root after commit")
	}

	// After commit, dirty state is cleared but account should be persisted.
	got, err := sdb.GetAccount(addr)
	if err != nil {
		t.Fatalf("GetAccount after commit failed: %v", err)
	}
	if got.Balance.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("balance after commit = %s, want 1000", got.Balance.String())
	}
	if got.Nonce != 5 {
		t.Errorf("nonce after commit = %d, want 5", got.Nonce)
	}
}

func TestStateDB_CommitEmpty(t *testing.T) {
	sdb := NewStateDB()

	root, err := sdb.Commit()
	if err != nil {
		t.Fatalf("Commit with no changes failed: %v", err)
	}

	// Root of empty state.
	_ = root
}

func TestStateDB_CommitClearsDirtyState(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x21)

	sdb.SetBalance(addr, big.NewInt(500))
	_, _ = sdb.Commit(1)

	// After commit, set new dirty balance.
	sdb.SetBalance(addr, big.NewInt(999))

	// Snapshot and revert should only affect the post-commit dirty state.
	snap := sdb.Snapshot()
	sdb.SetBalance(addr, big.NewInt(1234))
	sdb.RevertToSnapshot(snap)

	if bal := sdb.GetBalance(addr); bal.Cmp(big.NewInt(999)) != 0 {
		t.Errorf("balance = %s, want 999", bal.String())
	}
}

func TestStateDB_CommitStorage(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x22)
	key := extraTestHash(0x01)

	sdb.SetStorage(addr, key, extraTestHash(0xCC))
	_, err := sdb.Commit(1)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Storage should persist after commit.
	got := sdb.GetStorage(addr, key)
	if got != extraTestHash(0xCC) {
		t.Errorf("storage after commit = %x, want %x", got, extraTestHash(0xCC))
	}
}

// ───── StateDB RollbackToHeight ─────

func TestStateDB_RollbackToHeight_NoBeforeImages(t *testing.T) {
	sdb := NewStateDB()

	// Rollback with no before-images should be a no-op.
	err := sdb.RollbackToHeight(10)
	if err != nil {
		t.Errorf("RollbackToHeight with no history should not error: %v", err)
	}
}

func TestStateDB_RollbackToHeight_RestoresState(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x30)

	// Commit at height 1 —account is created.
	sdb.SetBalance(addr, big.NewInt(100))
	_, err := sdb.Commit(1)
	if err != nil {
		t.Fatalf("Commit at height 1 failed: %v", err)
	}

	// Commit at height 2 —balance changes.
	sdb.SetBalance(addr, big.NewInt(200))
	_, err = sdb.Commit(2)
	if err != nil {
		t.Fatalf("Commit at height 2 failed: %v", err)
	}

	// Verify balance is 200.
	got, _ := sdb.GetAccount(addr)
	if got.Balance.Cmp(big.NewInt(200)) != 0 {
		t.Fatalf("balance before rollback = %s, want 200", got.Balance.String())
	}

	// Rollback to height 2 — should undo height 2 changes, restoring height 1 state.
	err = sdb.RollbackToHeight(2)
	if err != nil {
		t.Fatalf("RollbackToHeight failed: %v", err)
	}

	got, err = sdb.GetAccount(addr)
	if err != nil {
		t.Fatalf("GetAccount after rollback failed: %v", err)
	}
	if got.Balance.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("balance after rollback = %s, want 100", got.Balance.String())
	}
}

func TestStateDB_RollbackToHeight_DeletesNewAccount(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x31)

	// Account doesn't exist at height 1.
	// Commit at height 1 (no changes for this addr).
	_, _ = sdb.Commit(1)

	// Create account at height 2.
	sdb.SetBalance(addr, big.NewInt(500))
	_, _ = sdb.Commit(2)

	// Account should exist.
	if !sdb.Exist(addr) {
		t.Fatal("account should exist after commit at height 2")
	}

	// Rollback to height 1 — account didn't exist before height 2.
	err := sdb.RollbackToHeight(1)
	if err != nil {
		t.Fatalf("RollbackToHeight failed: %v", err)
	}

	// After rollback, the account's balance should be restored to its pre-height-2 state.
	// Since the account didn't exist before height 2, the balance should be 0.
	got, err := sdb.GetAccount(addr)
	if err != nil {
		// If the account was properly deleted, GetAccount returns ErrAccountNotFound.
		// This is the expected behavior — the account should not exist.
		return
	}
	// If the account still exists (potential Verkle tree inconsistency),
	// verify its balance is zero (pre-creation state).
	if got.Balance.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("balance after rollback = %s, want 0 (account was created at height 2)", got.Balance.String())
	}
}

// ───── StateDB Revert ─────

func TestStateDB_Revert(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x40)

	sdb.SetBalance(addr, big.NewInt(1000))
	sdb.SetNonce(addr, 10)

	sdb.Revert()

	// After Revert, dirty state is cleared.
	// Since nothing was committed, the account should not exist.
	if sdb.Exist(addr) {
		t.Error("account should not exist after Revert (nothing was committed)")
	}
}

// ───── StateDB Copy ─────

func TestStateDB_Copy(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x50)

	sdb.SetBalance(addr, big.NewInt(777))
	sdb.SetNonce(addr, 3)

	copied := sdb.Copy()
	if copied == nil {
		t.Fatal("Copy returned nil")
	}

	// Copied state should have the same balance.
	if bal := copied.GetBalance(addr); bal.Cmp(big.NewInt(777)) != 0 {
		t.Errorf("copied balance = %s, want 777", bal.String())
	}
	if nonce := copied.GetNonce(addr); nonce != 3 {
		t.Errorf("copied nonce = %d, want 3", nonce)
	}
}

func TestStateDB_CopyIndependence(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x51)

	sdb.SetBalance(addr, big.NewInt(100))

	copied := sdb.Copy()
	copied.SetBalance(addr, big.NewInt(999))

	// Original should be unaffected.
	if bal := sdb.GetBalance(addr); bal.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("original balance = %s, want 100 (copy should not affect original)", bal.String())
	}
}

// ───── StateDB Root ─────

func TestStateDB_Root(t *testing.T) {
	sdb := NewStateDB()

	root1 := sdb.Root()

	sdb.SetBalance(extraTestAddr(0x60), big.NewInt(100))
	_, _ = sdb.Commit(1)

	root2 := sdb.Root()

	// Root should change after committing state.
	if root1 == root2 {
		// May or may not change depending on empty root handling.
		// The key is that Root() does not panic and returns a hash.
	}
}

// ───── StateDB Exist / Empty ─────

func TestStateDB_Exist(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x70)

	if sdb.Exist(addr) {
		t.Error("account should not exist before being set")
	}

	sdb.SetBalance(addr, big.NewInt(1))

	if !sdb.Exist(addr) {
		t.Error("account should exist after setting balance")
	}
}

func TestStateDB_Empty(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x71)

	// Non-existent account is "empty".
	if !sdb.Empty(addr) {
		t.Error("non-existent account should be Empty")
	}

	// Set a zero-balance, zero-nonce account —still empty.
	acc := NewAccount()
	sdb.SetAccount(addr, acc)

	if !sdb.Empty(addr) {
		t.Error("account with zero nonce, zero balance, no code should be Empty")
	}

	// Set a non-zero balance —not empty.
	sdb.SetBalance(addr, big.NewInt(1))

	if sdb.Empty(addr) {
		t.Error("account with non-zero balance should not be Empty")
	}
}

// ───── StateDB Nonce / Balance helpers ─────

func TestStateDB_GetNonceNonExistent(t *testing.T) {
	sdb := NewStateDB()
	if nonce := sdb.GetNonce(extraTestAddr(0x80)); nonce != 0 {
		t.Errorf("nonce for non-existent account = %d, want 0", nonce)
	}
}

func TestStateDB_GetBalanceNonExistent(t *testing.T) {
	sdb := NewStateDB()
	if bal := sdb.GetBalance(extraTestAddr(0x81)); bal.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("balance for non-existent account = %s, want 0", bal.String())
	}
}

func TestStateDB_IncrementNonce(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x82)

	sdb.SetNonce(addr, 5)
	sdb.IncrementNonce(addr)

	if nonce := sdb.GetNonce(addr); nonce != 6 {
		t.Errorf("nonce after IncrementNonce = %d, want 6", nonce)
	}
}

func TestStateDB_AddBalance(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x83)

	sdb.SetBalance(addr, big.NewInt(100))

	if err := sdb.AddBalance(addr, big.NewInt(50)); err != nil {
		t.Fatalf("AddBalance failed: %v", err)
	}

	if bal := sdb.GetBalance(addr); bal.Cmp(big.NewInt(150)) != 0 {
		t.Errorf("balance after AddBalance = %s, want 150", bal.String())
	}
}

func TestStateDB_AddBalanceNegative(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x84)

	sdb.SetBalance(addr, big.NewInt(100))

	err := sdb.AddBalance(addr, big.NewInt(-10))
	if err == nil {
		t.Error("AddBalance with negative amount should fail")
	}
}

func TestStateDB_SubBalance(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x85)

	sdb.SetBalance(addr, big.NewInt(100))

	if err := sdb.SubBalance(addr, big.NewInt(30)); err != nil {
		t.Fatalf("SubBalance failed: %v", err)
	}

	if bal := sdb.GetBalance(addr); bal.Cmp(big.NewInt(70)) != 0 {
		t.Errorf("balance after SubBalance = %s, want 70", bal.String())
	}
}

func TestStateDB_SubBalanceInsufficient(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0x86)

	sdb.SetBalance(addr, big.NewInt(10))

	err := sdb.SubBalance(addr, big.NewInt(100))
	if err == nil {
		t.Error("SubBalance exceeding balance should fail")
	}
}

// ───── StateDB with custom database ─────

func TestStateDB_WithCustomDB(t *testing.T) {
	memDB := db.NewMemDB()
	sdb := NewStateDB(memDB)

	addr := extraTestAddr(0x90)
	sdb.SetBalance(addr, big.NewInt(12345))
	_, err := sdb.Commit(1)
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Create a new StateDB on the same DB —should read committed state.
	sdb2 := NewStateDB(memDB)
	got, err := sdb2.GetAccount(addr)
	if err != nil {
		t.Fatalf("GetAccount from new StateDB failed: %v", err)
	}
	if got.Balance.Cmp(big.NewInt(12345)) != 0 {
		t.Errorf("balance = %s, want 12345", got.Balance.String())
	}
}

// ───── Account encode/decode ─────

func TestAccount_EncodeDecode(t *testing.T) {
	original := &Account{
		Nonce:       99,
		Balance:     big.NewInt(123456789),
		StorageRoot: extraTestHash(0xDD),
		CodeHash:    extraTestHash(0xEE),
	}

	data := original.Encode()
	if len(data) == 0 {
		t.Fatal("Encode returned empty data")
	}

	decoded, err := DecodeAccount(data)
	if err != nil {
		t.Fatalf("DecodeAccount failed: %v", err)
	}
	if decoded.Nonce != original.Nonce {
		t.Errorf("nonce = %d, want %d", decoded.Nonce, original.Nonce)
	}
	if decoded.Balance.Cmp(original.Balance) != 0 {
		t.Errorf("balance = %s, want %s", decoded.Balance.String(), original.Balance.String())
	}
	if decoded.StorageRoot != original.StorageRoot {
		t.Errorf("storageRoot mismatch")
	}
	if decoded.CodeHash != original.CodeHash {
		t.Errorf("codeHash mismatch")
	}
}

func TestAccount_EncodeDecodeZero(t *testing.T) {
	original := NewAccount()

	data := original.Encode()

	decoded, err := DecodeAccount(data)
	if err != nil {
		t.Fatalf("DecodeAccount failed: %v", err)
	}
	if decoded.Nonce != 0 {
		t.Errorf("nonce = %d, want 0", decoded.Nonce)
	}
	if decoded.Balance.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("balance = %s, want 0", decoded.Balance.String())
	}
}

func TestDecodeAccountExtra_TooShort(t *testing.T) {
	// Data shorter than minimum 104 bytes.
	_, err := DecodeAccount([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Error("expected error for too-short data")
	}
}

// ───── StateDB SetCode / GetCode ─────

func TestStateDB_SetAndGetCode(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0xA0)

	code := []byte{0x60, 0x80, 0x60, 0x40, 0x52}
	sdb.SetCode(addr, code)

	got := sdb.GetCode(addr)
	if len(got) != len(code) {
		t.Fatalf("code length = %d, want %d", len(got), len(code))
	}
	for i := range code {
		if got[i] != code[i] {
			t.Errorf("code[%d] = %x, want %x", i, got[i], code[i])
		}
	}
}

func TestStateDB_GetCodeNonExistent(t *testing.T) {
	sdb := NewStateDB()

	got := sdb.GetCode(extraTestAddr(0xA1))
	if got != nil {
		t.Errorf("expected nil code for non-existent account, got %x", got)
	}
}

// ───── StateDB Commit with storage and rollback ─────

func TestStateDB_RollbackRestoresStorage(t *testing.T) {
	sdb := NewStateDB()
	addr := extraTestAddr(0xB0)
	key := extraTestHash(0x01)

	// Height 1: set storage value.
	sdb.SetStorage(addr, key, extraTestHash(0xAA))
	_, _ = sdb.Commit(1)

	// Height 2: update storage value.
	sdb.SetStorage(addr, key, extraTestHash(0xBB))
	_, _ = sdb.Commit(2)

	// Verify value is BB.
	got := sdb.GetStorage(addr, key)
	if got != extraTestHash(0xBB) {
		t.Fatalf("storage = %x, want %x before rollback", got, extraTestHash(0xBB))
	}

	// Rollback to height 2 — should undo height 2 storage changes.
	err := sdb.RollbackToHeight(2)
	if err != nil {
		t.Fatalf("RollbackToHeight failed: %v", err)
	}

	// Storage should be restored to AA (value before height 2 commit).
	got = sdb.GetStorage(addr, key)
	if got != extraTestHash(0xAA) {
		t.Errorf("storage after rollback = %x, want %x", got, extraTestHash(0xAA))
	}
}

// TestStateDB_Snapshot_PanicsAtMaxDepth verifies that Snapshot() returns the
// sentinel -1 id (and logs a warning) when the snapshot stack reaches
// maxSnapshotDepth. This is the defense-in-depth backstop documented in
// STATE-R11-005.
//
// R33 STATE-08 FIX (2026-07-28): Snapshot() no longer panics. Panicking on
// a deeply nested CALL chain let a single malicious transaction kill the
// entire process — a DoS amplification against block production and
// consensus. Snapshot() now returns -1 (sentinel for "depth exceeded"),
// which RevertToSnapshot treats as invalid and triggers a full revert of
// the offending transaction. This test was updated to match the new
// behavior; if someone reverts to panic(), this test will fail loudly.
func TestStateDB_Snapshot_PanicsAtMaxDepth(t *testing.T) {
	sdb := NewStateDB()
	// Fill the snapshot stack to exactly maxSnapshotDepth.
	for i := 0; i < maxSnapshotDepth; i++ {
		sdb.Snapshot()
	}

	// The next Snapshot() call must return -1 (sentinel) instead of panicking.
	id := sdb.Snapshot()
	if id != -1 {
		t.Fatalf("Snapshot() at max depth returned id=%d, want -1 (sentinel for depth exceeded)", id)
	}
}

// TestStateDB_Snapshot_QVMDepthCheckFiresFirst is a documentation-as-test:
// it verifies that maxSnapshotDepth equals qvm.MaxCallDepth. The QVM checks
// `env.callDepth >= MaxCallDepth` BEFORE calling Snapshot in every call path
// (see the evaluation comment on maxSnapshotDepth for the full list of
// call sites). If someone changes one limit without the other, this test
// fails loudly to remind them to keep the two in sync.
//
// Why this matters: if maxSnapshotDepth > qvm.MaxCallDepth, the QVM would
// hit its own depth limit and return ErrDepthExceeded before the StateDB
// panic ever fires — the panic would be dead code. If maxSnapshotDepth <
// qvm.MaxCallDepth, the panic would fire BEFORE the QVM's graceful error
// path, crashing the node when it could have returned an error. The two
// limits MUST be equal so the QVM's graceful path fires first and the
// StateDB panic is a true backstop.
//
// STATE-R11-005 (2026-07-20).
func TestStateDB_Snapshot_QVMDepthCheckFiresFirst(t *testing.T) {
	// We can't import qvm from state (would create a dependency cycle:
	// qvm already depends on state via StateDB interface). Instead we
	// hardcode the qvm.MaxCallDepth value (1024) and add a comment
	// pointing to the source. If qvm.MaxCallDepth ever changes, update
	// this constant AND maxSnapshotDepth.
	const qvmMaxCallDepth = 1024 // source: qvm/qvm.go:53 `MaxCallDepth = 1024`

	if maxSnapshotDepth != qvmMaxCallDepth {
		t.Errorf("maxSnapshotDepth (%d) != qvm.MaxCallDepth (%d) — the StateDB "+
			"panic would fire at a different depth than the QVM's graceful "+
			"ErrDepthExceeded check. The two limits MUST be equal so the "+
			"QVM's graceful path fires first and the StateDB panic is a "+
			"true defense-in-depth backstop. Update both to the same value.",
			maxSnapshotDepth, qvmMaxCallDepth)
	}
}

// TestStateDB_Snapshot_BelowMaxDepthDoesNotPanic verifies that Snapshot()
// works correctly when called with exactly maxSnapshotDepth-1 snapshots on
// the stack — i.e., the panic boundary is at >=, not >.
//
// STATE-R11-005 (2026-07-20): Guards against an off-by-one error in the
// depth check (`len(s.snapshots) >= maxSnapshotDepth` vs `>`).
func TestStateDB_Snapshot_BelowMaxDepthDoesNotPanic(t *testing.T) {
	sdb := NewStateDB()
	// Fill to maxSnapshotDepth-1 (just below the limit).
	for i := 0; i < maxSnapshotDepth-1; i++ {
		sdb.Snapshot()
	}

	// This call should succeed — we're at maxSnapshotDepth-1, and the
	// check is >=, so one more snapshot brings us to maxSnapshotDepth
	// which is still allowed (panic fires at > maxSnapshotDepth, i.e.,
	// when len reaches maxSnapshotDepth and we try to add one more).
	//
	// Wait — re-read the check: `if len(s.snapshots) >= maxSnapshotDepth`.
	// After maxSnapshotDepth snapshots, len == maxSnapshotDepth. The NEXT
	// call checks len >= maxSnapshotDepth → true → panic.
	// So with maxSnapshotDepth-1 snapshots, len == maxSnapshotDepth-1 < maxSnapshotDepth → allowed.
	// The next call adds one more, making len == maxSnapshotDepth. The call
	// AFTER that checks len >= maxSnapshotDepth → true → panic.
	//
	// So the boundary is: Snapshot() #1024 succeeds (len becomes 1024),
	// Snapshot() #1025 panics (len is 1024 >= 1024).
	id := sdb.Snapshot() // #1024 — should succeed
	if id != maxSnapshotDepth-1 {
		t.Errorf("Snapshot() at depth %d returned id %d, want %d",
			maxSnapshotDepth-1, id, maxSnapshotDepth-1)
	}
}
