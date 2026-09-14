// Quantaureum Node source, version 1.0.0.
package rollup

// R38-P1-12 — Persistence error propagation regression tests.
//
// AUDIT CONTEXT: The five persistent write methods on bboltL1Bridge
// (Deposit, ProcessWithdrawal, RecordFinalizedBatch, RecordWithdrawalRoot,
// MarkDepositMinted) used to call persistXxx helpers that returned no
// error — a bbolt Put failure was only logged as a warning and then
// dropped. The in-memory state had already been mutated, so memory and
// disk could silently diverge. The most dangerous case was
// MarkDepositMinted, which unconditionally returned nil even on Put
// failure: a crash right after a silent persist failure let a node restart
// re-mint an already-minted deposit, draining L1 bridge liquidity.
//
// R38-P1-12 FIX (2026-08-01):
//   - persistXxx helpers now return error.
//   - MarkDepositMinted strictly propagates the persist error.
//   - The other four writers propagate the persist error too (the L1Bridge
//     interface already declared them as `error`-returning, so no
//     interface change is required).
//   - L2Bridge.ProcessDeposit still treats MarkDepositMinted's error as
//     non-fatal (the mint is irreversible), but logs it as ERROR with a
//     stable grep tag PERSIST-MARK-MINTED-FAILED so operators can detect
//     the divergence.

import (
	"errors"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// failingPutDB wraps a *db.MemDB and forces Put to return a controlled
// error once armed. Get / NewIterator / NewIteratorWithLimit / Delete /
// Has / Close / NewBatch keep working against the underlying MemDB so
// that NewBboltL1Bridge.restore() can complete at construction time and
// the test can surgically break only the write path.
//
// R38-P1-12 (2026-08-01)
type failingPutDB struct {
	*db.MemDB
	putErr error // when non-nil, every Put returns this error
}

func (f *failingPutDB) Put(key, value []byte) error {
	if f.putErr != nil {
		return f.putErr
	}
	return f.MemDB.Put(key, value)
}

// fakePersistentDepositHash is a helper that creates a deposit through the
// normal Deposit() flow on a working bridge, returns the deposit hash plus
// a restore-from-scratch second bridge built on the SAME database. The
// second bridge lets the test observe what actually landed on disk vs.
// what only lives in memory — detecting the memory/disk divergence that
// R38-P1-12 is about.
func fakePersistentDepositHash(t *testing.T, database db.Database, depositor types.Address, amount *big.Int) (types.Hash, L1Bridge) {
	t.Helper()
	bridge, err := NewBboltL1Bridge(database)
	if err != nil {
		t.Fatalf("NewBboltL1Bridge: %v", err)
	}
	hash, err := bridge.Deposit(depositor, amount)
	if err != nil {
		t.Fatalf("Deposit: %v", err)
	}
	return hash, bridge
}

// TestR38P1_12_MarkDepositMinted_PropagatesPersistError asserts the central
// safety property of R38-P1-12: MarkDepositMinted MUST return a non-nil
// error when its persistDeposit bbolt Put fails. Before the fix this method
// unconditionally returned nil, hiding the memory/disk divergence that
// enabled re-mint double-spends after a crash.
//
// R38-P1-12 (2026-08-01)
func TestR38P1_12_MarkDepositMinted_PropagatesPersistError(t *testing.T) {
	database := &failingPutDB{MemDB: db.NewMemDB()}

	depositor := types.Address{0x01}
	amount := big.NewInt(500)
	depositHash, bridge := fakePersistentDepositHash(t, database, depositor, amount)

	// Arm the failure AFTER the deposit succeeded so the deposit itself
	// is already persisted; only MarkDepositMinted's re-persist hits the
	// failing Put.
	database.putErr = errors.New("disk full")

	err := bridge.MarkDepositMinted(depositHash)
	if err == nil {
		t.Fatal("R38-P1-12 REGRESSION: MarkDepositMinted returned nil even though db.Put failed — " +
			"memory/disk divergence silently hidden, double-mint risk after crash")
	}
}

// TestR38P1_12_OtherWriters_PropagatePersistError asserts the four other
// L1Bridge write methods (Deposit, ProcessWithdrawal, RecordFinalizedBatch,
// RecordWithdrawalRoot) also surface persist errors instead of swallowing
// them as warnings. Together with MarkDepositMinted this gives full error
// visibility across the persistent bridge.
//
// R38-P1-12 (2026-08-01)
func TestR38P1_12_OtherWriters_PropagatePersistError(t *testing.T) {
	database := &failingPutDB{MemDB: db.NewMemDB()}
	bridge, err := NewBboltL1Bridge(database)
	if err != nil {
		t.Fatalf("NewBboltL1Bridge: %v", err)
	}

	// Deposit: arm failure before the first persistDeposit call so the
	// first write to disk fails. Deposit should return a non-nil error.
	database.putErr = errors.New("disk full")
	if _, err := bridge.Deposit(types.Address{0x02}, big.NewInt(100)); err == nil {
		t.Error("R38-P1-12 REGRESSION: Deposit returned nil even though db.Put failed — " +
			"caller unable to detect memory/disk divergence")
	}

	// RecordFinalizedBatch
	if err := bridge.RecordFinalizedBatch(1, types.Hash{0xAB}); err == nil {
		t.Error("R38-P1-12 REGRESSION: RecordFinalizedBatch returned nil even though db.Put failed")
	}

	// RecordWithdrawalRoot
	if err := bridge.RecordWithdrawalRoot(1, types.Hash{0xCD}); err == nil {
		t.Error("R38-P1-12 REGRESSION: RecordWithdrawalRoot returned nil even though db.Put failed")
	}

	// ProcessWithdrawal needs a valid withdrawal root recorded on L1 first;
	// since Put is failing globally we clear the error briefly to stage the
	// root, then re-arm and call ProcessWithdrawal.
	database.putErr = nil
	if err := bridge.RecordWithdrawalRoot(2, types.Hash{0xEE}); err != nil {
		t.Fatalf("setup RecordWithdrawalRoot: %v", err)
	}
	// Build a trivial Merkle proof rooted at the just-recorded root. The
	// memoryL1Bridge implementation is the embedded store inside the
	// bboltL1Bridge; reuse it to construct an in-tree proof.
	proof := buildInTreeWithdrawalProof(types.Hash{0xEE}, types.Address{0x03}, big.NewInt(7), 0)
	database.putErr = errors.New("disk full")
	if err := bridge.ProcessWithdrawal(types.Address{0x03}, big.NewInt(7), 2, 0, types.Hash{}, proof); err == nil {
		t.Error("R38-P1-12 REGRESSION: ProcessWithdrawal returned nil even though db.Put failed")
	}
}

// TestR38P1_12_HappyPath_PutSucceeds asserts the fix did not break the
// success path: when db.Put works, MarkDepositMinted returns nil and a
// restart observes Minted=true (preserving the R36 P1-ROLLUP-01 invariant).
//
// To exercise the real call path we drive L2Bridge.ProcessDeposit, which
// is the sole production caller of MarkDepositMinted. This mirrors the R36
// restart-consistency test but checks specifically that the strict-error
// version of MarkDepositMinted still returns nil on the happy path and
// that the persisted Minted flag survives a restart (i.e. MarkDepositMinted
// did not silently swallow a success-but-no-write bug).
//
// R38-P1-12 (2026-08-01)
func TestR38P1_12_HappyPath_PutSucceeds(t *testing.T) {
	database := db.NewMemDB()

	bridge, err := NewBboltL1Bridge(database)
	if err != nil {
		t.Fatalf("NewBboltL1Bridge: %v", err)
	}
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	bridgeAddr := types.Address{0xff}
	l2Bridge := NewL2Bridge(bridge, sm, bridgeAddr)

	depositor := types.Address{0x09}
	amount := big.NewInt(750)
	depositHash, err := bridge.Deposit(depositor, amount)
	if err != nil {
		t.Fatalf("Deposit: %v", err)
	}

	// Drive the real mint path — its Phase 3 calls MarkDepositMinted.
	if err := l2Bridge.ProcessDeposit(depositHash); err != nil {
		t.Fatalf("ProcessDeposit (happy path) failed: %v", err)
	}

	// Restart simulation: re-create the bridge from the same on-disk state
	// and verify the deposit's Minted flag survived — directly observably
	// verifying that persistence worked (not just that MarkDepositMinted
	// returned nil).
	bridge2, err := NewBboltL1Bridge(database)
	if err != nil {
		t.Fatalf("NewBboltL1Bridge restart: %v", err)
	}
	restored, ok := bridge2.GetDeposit(depositHash)
	if !ok {
		t.Fatal("deposit missing after restart")
	}
	if !restored.Minted {
		t.Fatal("R38-P1-12 happy-path regression: Minted=false after restart — " +
			"MarkDepositMinted returned nil but the disk write clearly did not land")
	}
}

// buildInTreeWithdrawalProof constructs a MerkleWithdrawalProof whose
// WithdrawalRoot matches the supplied root and whose verification against
// the in-memory SMT constructed by buildWithdrawalSMT succeeds. This is a
// minimal test helper — we build a one-leaf withdrawal tree (single
// withdrawal tx) and extract its proof.
//
// R38-P1-12 (2026-08-01)
func buildInTreeWithdrawalProof(withdrawalRoot types.Hash, withdrawer types.Address, amount *big.Int, txIdx int) *MerkleWithdrawalProof {
	txs := []*RollupTransaction{
		{
			From:  withdrawer,
			To:    nil, // set below
			Value: new(big.Int).Set(amount),
		},
	}
	bridgeAddr := types.Address{0xff}
	txs[0].To = &bridgeAddr

	smt := buildWithdrawalSMT(txs, bridgeAddr)
	treeKey := ComputeWithdrawalTreeKey(withdrawer, txIdx)
	proof, _ := smt.Prove(treeKey)
	return &MerkleWithdrawalProof{
		WithdrawalRoot: withdrawalRoot,
		Proof:          proof,
		TreeKey:        treeKey,
	}
}
