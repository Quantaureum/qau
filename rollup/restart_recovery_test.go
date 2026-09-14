// Quantaureum Node source, version 1.0.0.
package rollup

// W-P2-4: Node restart recovery tests.
//
// Goal (per the rollup production-readiness plan):
//   Verify that L2 state persistence is correct.
//
// Steps:
//   1. Start node, submit several L2 transactions
//   2. Stop node
//   3. Restart node, verify L2 balances, batch history fully restored
//
// DoD: L2 state completely consistent before and after restart.
//
// These tests use a real bbolt database in a temporary directory to verify
// the full persistence → restore cycle that W-P1-3 implemented.

import (
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// newTestDBDir creates a temporary directory for a bbolt rollup database.
// The same dir can be reopened by newTestDBAtDir after closing the first DB,
// simulating a node restart.
func newTestDBDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "rollup")
}

// newTestDBAtDir opens (or creates) a bbolt database at the given directory.
// Returns the database and a cleanup function. The cleanup closes the DB.
func newTestDBAtDir(t *testing.T, dir string) (*db.BoltDB, func()) {
	t.Helper()
	database, err := db.NewBoltDB(dir)
	if err != nil {
		t.Fatalf("NewBoltDB: %v", err)
	}
	cleanup := func() {
		if err := database.Close(); err != nil {
			t.Logf("database close: %v", err)
		}
	}
	return database, cleanup
}

// --- W-P2-4 Test 1: Balance survives restart ---

// TestRestartRecovery_BalanceSurvivesRestart verifies that account balances
// are correctly persisted and restored across an engine restart.
func TestRestartRecovery_BalanceSurvivesRestart(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond
	cfg.MinTxPerBatch = 1

	dir := newTestDBDir(t)

	// --- Phase 1: Start engine, fund account, submit tx, stop ---
	db1, cleanup1 := newTestDBAtDir(t, dir)
	persistence1 := NewPersistence(db1)

	engine1, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine(1): %v", err)
	}
	engine1.SetPersistence(persistence1)
	engine1.SetRequireTxSig(false)

	sm1 := engine1.GetStateManager()
	from := types.Address{10}
	to := types.Address{20}
	sm1.getOrCreateAccount(from)
	sm1.accountStates[from].Balance = new(big.Int).SetInt64(1_000_000)

	preRoot := sm1.computeStateRoot()
	engine1.GetBatchManager().RestoreMeta(0, preRoot)

	if err := engine1.Start(); err != nil {
		t.Fatalf("Start(1): %v", err)
	}

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(500),
		From:     from,
		To:       &to,
		ChainID:  cfg.ChainID,
	}
	if err := engine1.SubmitL2Transaction(tx); err != nil {
		t.Fatalf("SubmitL2Transaction: %v", err)
	}

	waitForBatch(t, engine1, 2*time.Second)

	// Capture pre-stop state.
	fromBalanceBefore := sm1.GetAccount(from).Balance
	toBalanceBefore := sm1.GetAccount(to).Balance

	if err := engine1.Stop(); err != nil {
		t.Fatalf("Stop(1): %v", err)
	}
	cleanup1()

	// --- Phase 2: Reopen DB, create new engine, verify state ---
	db2, cleanup2 := newTestDBAtDir(t, dir)
	defer cleanup2()
	persistence2 := NewPersistence(db2)

	engine2, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine(2): %v", err)
	}
	engine2.SetPersistence(persistence2)
	engine2.SetRequireTxSig(false)

	// Start triggers RestoreState.
	if err := engine2.Start(); err != nil {
		t.Fatalf("Start(2): %v", err)
	}
	defer engine2.Stop()

	sm2 := engine2.GetStateManager()

	fromAcc2 := sm2.GetAccount(from)
	if fromAcc2 == nil {
		t.Fatal("from account not restored")
	}
	if fromAcc2.Balance.Cmp(fromBalanceBefore) != 0 {
		t.Errorf("from balance: got %s, want %s", fromAcc2.Balance.String(), fromBalanceBefore.String())
	}

	toAcc2 := sm2.GetAccount(to)
	if toAcc2 == nil {
		t.Fatal("to account not restored")
	}
	if toAcc2.Balance.Cmp(toBalanceBefore) != 0 {
		t.Errorf("to balance: got %s, want %s", toAcc2.Balance.String(), toBalanceBefore.String())
	}
	t.Log("✅ Account balances survived restart")
}

// --- W-P2-4 Test 2: Batch history survives restart ---

// TestRestartRecovery_BatchHistorySurvivesRestart verifies that batch records
// (index, transactions, postStateRoot, status) are correctly restored.
func TestRestartRecovery_BatchHistorySurvivesRestart(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond
	cfg.MinTxPerBatch = 1

	dir := newTestDBDir(t)
	db1, cleanup1 := newTestDBAtDir(t, dir)
	persistence1 := NewPersistence(db1)

	engine1, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine(1): %v", err)
	}
	engine1.SetPersistence(persistence1)
	engine1.SetRequireTxSig(false)

	sm1 := engine1.GetStateManager()
	from := types.Address{10}
	to := types.Address{20}
	sm1.getOrCreateAccount(from)
	sm1.accountStates[from].Balance = new(big.Int).SetInt64(10_000_000)

	preRoot := sm1.computeStateRoot()
	engine1.GetBatchManager().RestoreMeta(0, preRoot)

	if err := engine1.Start(); err != nil {
		t.Fatalf("Start(1): %v", err)
	}

	// Submit 3 transactions → 3 batches.
	for i := 0; i < 3; i++ {
		tx := &RollupTransaction{
			Nonce:    uint64(i),
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     from,
			To:       &to,
			ChainID:  cfg.ChainID,
		}
		if err := engine1.SubmitL2Transaction(tx); err != nil {
			t.Fatalf("SubmitL2Transaction(%d): %v", i, err)
		}
		waitForBatchCount(t, engine1, uint64(i+1), 2*time.Second)
	}

	bm1 := engine1.GetBatchManager()
	batchCountBefore := 0
	for i := uint64(0); i < 10; i++ {
		if _, err := bm1.GetBatch(i); err == nil {
			batchCountBefore++
		}
	}

	if err := engine1.Stop(); err != nil {
		t.Fatalf("Stop(1): %v", err)
	}
	cleanup1()

	// --- Restart ---
	db2, cleanup2 := newTestDBAtDir(t, dir)
	defer cleanup2()
	persistence2 := NewPersistence(db2)

	engine2, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine(2): %v", err)
	}
	engine2.SetPersistence(persistence2)
	engine2.SetRequireTxSig(false)

	if err := engine2.Start(); err != nil {
		t.Fatalf("Start(2): %v", err)
	}
	defer engine2.Stop()

	bm2 := engine2.GetBatchManager()
	batchCountAfter := 0
	for i := uint64(0); i < 10; i++ {
		if _, err := bm2.GetBatch(i); err == nil {
			batchCountAfter++
		}
	}

	if batchCountAfter != batchCountBefore {
		t.Errorf("batch count: got %d after restart, want %d", batchCountAfter, batchCountBefore)
	}

	// Verify each batch's postStateRoot matches.
	for i := uint64(0); i < uint64(batchCountBefore); i++ {
		b1, err1 := bm1.GetBatch(i)
		b2, err2 := bm2.GetBatch(i)
		if err1 != nil || err2 != nil {
			t.Errorf("batch %d: err1=%v, err2=%v", i, err1, err2)
			continue
		}
		if b1.PostStateRoot != b2.PostStateRoot {
			t.Errorf("batch %d postStateRoot: before=%x, after=%x", i, b1.PostStateRoot, b2.PostStateRoot)
		}
		if b1.Status != b2.Status {
			t.Errorf("batch %d status: before=%d, after=%d", i, b1.Status, b2.Status)
		}
		if b1.TxCount != b2.TxCount {
			t.Errorf("batch %d txCount: before=%d, after=%d", i, b1.TxCount, b2.TxCount)
		}
	}
	t.Logf("✅ Batch history survived restart (%d batches)", batchCountAfter)
}

// --- W-P2-4 Test 3: StateRoot survives restart ---

// TestRestartRecovery_StateRootSurvivesRestart verifies that the stateRoot
// map (batchIndex → stateRoot) is correctly restored.
func TestRestartRecovery_StateRootSurvivesRestart(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond
	cfg.MinTxPerBatch = 1

	dir := newTestDBDir(t)
	db1, cleanup1 := newTestDBAtDir(t, dir)
	persistence1 := NewPersistence(db1)

	engine1, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine(1): %v", err)
	}
	engine1.SetPersistence(persistence1)
	engine1.SetRequireTxSig(false)

	sm1 := engine1.GetStateManager()
	from := types.Address{10}
	to := types.Address{20}
	sm1.getOrCreateAccount(from)
	sm1.accountStates[from].Balance = new(big.Int).SetInt64(10_000_000)

	preRoot := sm1.computeStateRoot()
	engine1.GetBatchManager().RestoreMeta(0, preRoot)

	if err := engine1.Start(); err != nil {
		t.Fatalf("Start(1): %v", err)
	}

	for i := 0; i < 2; i++ {
		tx := &RollupTransaction{
			Nonce:    uint64(i),
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     from,
			To:       &to,
			ChainID:  cfg.ChainID,
		}
		if err := engine1.SubmitL2Transaction(tx); err != nil {
			t.Fatalf("SubmitL2Transaction(%d): %v", i, err)
		}
		waitForBatchCount(t, engine1, uint64(i+1), 2*time.Second)
	}

	root0Before, _ := sm1.GetStateRoot(0)
	root1Before, _ := sm1.GetStateRoot(1)
	currentRootBefore := sm1.GetCurrentRoot()

	if err := engine1.Stop(); err != nil {
		t.Fatalf("Stop(1): %v", err)
	}
	cleanup1()

	// --- Restart ---
	db2, cleanup2 := newTestDBAtDir(t, dir)
	defer cleanup2()
	persistence2 := NewPersistence(db2)

	engine2, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine(2): %v", err)
	}
	engine2.SetPersistence(persistence2)
	engine2.SetRequireTxSig(false)

	if err := engine2.Start(); err != nil {
		t.Fatalf("Start(2): %v", err)
	}
	defer engine2.Stop()

	sm2 := engine2.GetStateManager()

	root0After, _ := sm2.GetStateRoot(0)
	root1After, _ := sm2.GetStateRoot(1)
	currentRootAfter := sm2.GetCurrentRoot()

	if root0After != root0Before {
		t.Errorf("stateRoot[0]: before=%x, after=%x", root0Before, root0After)
	}
	if root1After != root1Before {
		t.Errorf("stateRoot[1]: before=%x, after=%x", root1Before, root1After)
	}
	if currentRootAfter != currentRootBefore {
		t.Errorf("currentRoot: before=%x, after=%x", currentRootBefore, currentRootAfter)
	}
	t.Log("✅ StateRoots survived restart")
}

// --- W-P2-4 Test 4: Next batch index continues correctly ---

// TestRestartRecovery_NextBatchIndexContinues verifies that after restart,
// the engine continues building batches from the correct next index (not 0).
func TestRestartRecovery_NextBatchIndexContinues(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond
	cfg.MinTxPerBatch = 1

	dir := newTestDBDir(t)
	db1, cleanup1 := newTestDBAtDir(t, dir)
	persistence1 := NewPersistence(db1)

	engine1, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine(1): %v", err)
	}
	engine1.SetPersistence(persistence1)
	engine1.SetRequireTxSig(false)

	sm1 := engine1.GetStateManager()
	from := types.Address{10}
	to := types.Address{20}
	sm1.getOrCreateAccount(from)
	sm1.accountStates[from].Balance = new(big.Int).SetInt64(10_000_000)

	preRoot := sm1.computeStateRoot()
	engine1.GetBatchManager().RestoreMeta(0, preRoot)

	if err := engine1.Start(); err != nil {
		t.Fatalf("Start(1): %v", err)
	}

	for i := 0; i < 2; i++ {
		tx := &RollupTransaction{
			Nonce:    uint64(i),
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     from,
			To:       &to,
			ChainID:  cfg.ChainID,
		}
		if err := engine1.SubmitL2Transaction(tx); err != nil {
			t.Fatalf("SubmitL2Transaction(%d): %v", i, err)
		}
		waitForBatchCount(t, engine1, uint64(i+1), 2*time.Second)
	}

	if err := engine1.Stop(); err != nil {
		t.Fatalf("Stop(1): %v", err)
	}
	cleanup1()

	// --- Restart ---
	db2, cleanup2 := newTestDBAtDir(t, dir)
	defer cleanup2()
	persistence2 := NewPersistence(db2)

	engine2, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine(2): %v", err)
	}
	engine2.SetPersistence(persistence2)
	engine2.SetRequireTxSig(false)

	if err := engine2.Start(); err != nil {
		t.Fatalf("Start(2): %v", err)
	}
	defer engine2.Stop()

	// Submit another tx — should be batch index 2 (not 0).
	tx := &RollupTransaction{
		Nonce:    2,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     from,
		To:       &to,
		ChainID:  cfg.ChainID,
	}
	if err := engine2.SubmitL2Transaction(tx); err != nil {
		t.Fatalf("SubmitL2Transaction after restart: %v", err)
	}
	waitForBatchCount(t, engine2, 3, 2*time.Second)

	bm2 := engine2.GetBatchManager()
	batch2, err := bm2.GetBatch(2)
	if err != nil {
		t.Fatalf("batch 2 not found after restart: %v", err)
	}
	if batch2.Index != 2 {
		t.Errorf("batch index: got %d, want 2", batch2.Index)
	}
	t.Log("✅ Next batch index continued correctly after restart (batch 2 built)")
}

// --- W-P2-4 Test 5: Engine stats survive restart ---

// TestRestartRecovery_StatsSurviveRestart verifies that totalBatches and
// totalTxs counters are correctly restored from the persisted batch history.
func TestRestartRecovery_StatsSurviveRestart(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond
	cfg.MinTxPerBatch = 1

	dir := newTestDBDir(t)
	db1, cleanup1 := newTestDBAtDir(t, dir)
	persistence1 := NewPersistence(db1)

	engine1, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine(1): %v", err)
	}
	engine1.SetPersistence(persistence1)
	engine1.SetRequireTxSig(false)

	sm1 := engine1.GetStateManager()
	from := types.Address{10}
	to := types.Address{20}
	sm1.getOrCreateAccount(from)
	sm1.accountStates[from].Balance = new(big.Int).SetInt64(10_000_000)

	preRoot := sm1.computeStateRoot()
	engine1.GetBatchManager().RestoreMeta(0, preRoot)

	if err := engine1.Start(); err != nil {
		t.Fatalf("Start(1): %v", err)
	}

	for i := 0; i < 3; i++ {
		tx := &RollupTransaction{
			Nonce:    uint64(i),
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     from,
			To:       &to,
			ChainID:  cfg.ChainID,
		}
		if err := engine1.SubmitL2Transaction(tx); err != nil {
			t.Fatalf("SubmitL2Transaction(%d): %v", i, err)
		}
		waitForBatchCount(t, engine1, uint64(i+1), 2*time.Second)
	}

	batchesBefore, txsBefore, _ := engine1.GetStats()

	if err := engine1.Stop(); err != nil {
		t.Fatalf("Stop(1): %v", err)
	}
	cleanup1()

	// --- Restart ---
	db2, cleanup2 := newTestDBAtDir(t, dir)
	defer cleanup2()
	persistence2 := NewPersistence(db2)

	engine2, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine(2): %v", err)
	}
	engine2.SetPersistence(persistence2)
	engine2.SetRequireTxSig(false)

	if err := engine2.Start(); err != nil {
		t.Fatalf("Start(2): %v", err)
	}
	defer engine2.Stop()

	batchesAfter, txsAfter, _ := engine2.GetStats()

	if batchesAfter != batchesBefore {
		t.Errorf("totalBatches: before=%d, after=%d", batchesBefore, batchesAfter)
	}
	if txsAfter != txsBefore {
		t.Errorf("totalTxs: before=%d, after=%d", txsBefore, txsAfter)
	}
	t.Logf("✅ Engine stats survived restart (batches=%d, txs=%d)", batchesAfter, txsAfter)
}

// --- helpers ---

func waitForBatch(t *testing.T, engine *RollupEngine, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		batches, _, _ := engine.GetStats()
		if batches > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	batches, txs, _ := engine.GetStats()
	t.Fatalf("no batch built within %v (batches=%d, txs=%d)", deadline, batches, txs)
}

func waitForBatchCount(t *testing.T, engine *RollupEngine, count uint64, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		batches, _, _ := engine.GetStats()
		if batches >= count {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	batches, _, _ := engine.GetStats()
	t.Fatalf("only %d batches built within %v (wanted %d)", batches, deadline, count)
}

// --- RLLP-R5-08 Test: lastAnchorHeight survives restart ---

// TestRLLP_R5_08_LastAnchorHeightReconstructedFromAnchors verifies that after
// a node restart, the engine's lastAnchorHeight is correctly reconstructed
// from the persisted L1 anchor records — instead of staying at its zero value
// default, which would make updateL1AnchorLag() short-circuit and silently
// disable the L1 anchor lag alert.
//
// Regression scenario BEFORE the fix:
//  1. Engine runs, anchors N batches → lastAnchorHeight = N (in-memory only)
//  2. Engine stops → lastAnchorHeight is lost (it is not persisted directly)
//  3. Engine restarts → RestoreState() loads anchors but did NOT rebuild
//     lastAnchorHeight, so it stayed 0
//  4. updateL1AnchorLag() sees lastAnchorHeight==0 → returns early → the
//     l1_anchor_lag gauge stays at 0 forever, masking a stuck sequencer
//
// AFTER the fix: RestoreState() rebuilds lastAnchorHeight as the maximum
// SubmitHeight across all restored anchors.
func TestRLLP_R5_08_LastAnchorHeightReconstructedFromAnchors(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond
	cfg.MinTxPerBatch = 1

	dir := newTestDBDir(t)

	// --- Phase 1: Start engine with persistence + L1 anchor, build batches ---
	db1, cleanup1 := newTestDBAtDir(t, dir)
	persistence1 := NewPersistence(db1)

	engine1, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine(1): %v", err)
	}
	engine1.SetPersistence(persistence1)
	engine1.SetRequireTxSig(false)
	// W-P1-4: Configure an in-memory L1 anchor with a challenge window of
	// 10 blocks. Each AnchorBatch() call increments currentHeight by 1, so
	// after N batches the SubmitHeight values will be 1..N and the max will
	// be N.
	engine1.SetL1Anchor(NewMemoryL1Anchor(10))

	sm1 := engine1.GetStateManager()
	from := types.Address{10}
	to := types.Address{20}
	sm1.getOrCreateAccount(from)
	sm1.accountStates[from].Balance = new(big.Int).SetInt64(10_000_000)

	preRoot := sm1.computeStateRoot()
	engine1.GetBatchManager().RestoreMeta(0, preRoot)

	if err := engine1.Start(); err != nil {
		t.Fatalf("Start(1): %v", err)
	}

	// Submit 3 transactions → 3 batches → 3 L1 anchors at heights 1, 2, 3.
	// Submit one at a time, waiting for each batch to be built before
	// submitting the next — otherwise all 3 txs land in the same 100ms
	// batchLoop tick and get packed into a single batch.
	const numBatches = 3
	for i := 0; i < numBatches; i++ {
		tx := &RollupTransaction{
			Nonce:    uint64(i),
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     from,
			To:       &to,
			ChainID:  cfg.ChainID,
		}
		if err := engine1.SubmitL2Transaction(tx); err != nil {
			t.Fatalf("SubmitL2Transaction(%d): %v", i, err)
		}
		waitForBatchCount(t, engine1, uint64(i+1), 2*time.Second)
	}

	// Capture the expected lastAnchorHeight before stopping. After 3
	// successful AnchorBatch calls, memoryL1Anchor.currentHeight == 3 and
	// engine1.lastAnchorHeight == 3. Poll briefly because anchorBatch
	// runs AFTER the batch counter is incremented (in tryBuildAndSubmitBatch),
	// so there is a small window where waitForBatchCount returns but the
	// 3rd anchor has not yet been recorded.
	expectedLastAnchorHeight := uint64(numBatches)
	anchorDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(anchorDeadline) {
		if engine1.GetLastAnchorHeight() == expectedLastAnchorHeight {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if engine1.GetLastAnchorHeight() != expectedLastAnchorHeight {
		t.Fatalf("pre-stop sanity check: engine1.lastAnchorHeight=%d, want %d (memoryL1Anchor should increment once per batch)",
			engine1.GetLastAnchorHeight(), expectedLastAnchorHeight)
	}

	// Verify the anchors were actually persisted to disk.
	anchor1 := engine1.GetL1Anchor()
	mp1, ok := anchor1.(*memoryL1Anchor)
	if !ok {
		t.Fatalf("expected *memoryL1Anchor, got %T", anchor1)
	}
	mp1.mu.RLock()
	persistedCount := len(mp1.anchors)
	mp1.mu.RUnlock()
	if persistedCount != numBatches {
		t.Fatalf("pre-stop sanity check: %d anchors in memory, want %d", persistedCount, numBatches)
	}

	if err := engine1.Stop(); err != nil {
		t.Fatalf("Stop(1): %v", err)
	}
	cleanup1()

	// --- Phase 2: Restart with a FRESH memoryL1Anchor ---
	// The in-memory anchor state is lost on restart (only the persisted
	// anchors on disk survive). This simulates a real node restart where
	// the L1 anchor client reconnects with no in-memory cache.
	db2, cleanup2 := newTestDBAtDir(t, dir)
	defer cleanup2()
	persistence2 := NewPersistence(db2)

	engine2, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine(2): %v", err)
	}
	engine2.SetPersistence(persistence2)
	engine2.SetRequireTxSig(false)
	// Fresh anchor — its currentHeight starts at 0. RestoreState() must
	// rebuild both mp.currentHeight AND e.lastAnchorHeight from the
	// persisted anchors.
	engine2.SetL1Anchor(NewMemoryL1Anchor(10))

	// Start triggers RestoreState, which must rebuild lastAnchorHeight.
	if err := engine2.Start(); err != nil {
		t.Fatalf("Start(2): %v", err)
	}
	defer engine2.Stop()

	// RLLP-R5-08 core assertion: lastAnchorHeight must be reconstructed
	// from the max SubmitHeight of the restored anchors.
	if got := engine2.GetLastAnchorHeight(); got != expectedLastAnchorHeight {
		t.Errorf("RLLP-R5-08 REGRESSION: engine2.lastAnchorHeight=%d after restart, want %d (max SubmitHeight from restored anchors)",
			got, expectedLastAnchorHeight)
	}

	// Also verify the memoryL1Anchor's internal currentHeight was rebuilt
	// (this is the existing pre-RLLP-R5-08 behavior, kept as a sanity check).
	anchor2 := engine2.GetL1Anchor()
	mp2, ok := anchor2.(*memoryL1Anchor)
	if !ok {
		t.Fatalf("expected *memoryL1Anchor after restart, got %T", anchor2)
	}
	mp2.mu.RLock()
	rebuiltCurrentHeight := mp2.currentHeight
	restoredAnchorCount := len(mp2.anchors)
	mp2.mu.RUnlock()
	if rebuiltCurrentHeight != expectedLastAnchorHeight {
		t.Errorf("memoryL1Anchor.currentHeight after restart=%d, want %d", rebuiltCurrentHeight, expectedLastAnchorHeight)
	}
	if restoredAnchorCount != numBatches {
		t.Errorf("restored anchor count=%d, want %d", restoredAnchorCount, numBatches)
	}

	// RLLP-R5-08 behavioral assertion: updateL1AnchorLag() must NOT
	// short-circuit after restart. Before the fix, lastAnchorHeight==0
	// caused updateL1AnchorLag() to return immediately without updating
	// the gauge. After the fix, with lastAnchorHeight=3 and a current L1
	// height of 5, the lag should be 2.
	mp2.SetHeight(5)
	engine2.updateL1AnchorLag()
	// We can't read the gauge directly without a metrics instance, but we
	// can verify the function did not short-circuit by checking that
	// lastAnchorHeight is non-zero (which is the short-circuit condition).
	// The lag computation itself is: current(5) - lastAnchorHeight(3) = 2.
	// The nil-safety of metrics means no panic occurs even without a
	// configured metrics instance.
	if engine2.GetLastAnchorHeight() == 0 {
		t.Errorf("RLLP-R5-08 REGRESSION: lastAnchorHeight reverted to 0 after updateL1AnchorLag (short-circuit condition)")
	}

	t.Logf("✅ RLLP-R5-08: lastAnchorHeight reconstructed to %d after restart (3 anchors restored, currentHeight=%d)",
		engine2.GetLastAnchorHeight(), rebuiltCurrentHeight)
}

// --- RLLP-R5-08 Test: restart with zero anchors (no regression for fresh state) ---

// TestRLLP_R5_08_NoAnchors_RestartsToZero verifies that the RLLP-R5-08 fix
// does not break the fresh-start case: when no batches were anchored before
// restart, lastAnchorHeight correctly stays at 0 (no spurious reconstruction).
func TestRLLP_R5_08_NoAnchors_RestartsToZero(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond
	cfg.MinTxPerBatch = 1

	dir := newTestDBDir(t)

	// Phase 1: Start engine with persistence + L1 anchor, but DON'T submit
	// any transactions (no batches built, no anchors recorded).
	db1, cleanup1 := newTestDBAtDir(t, dir)
	persistence1 := NewPersistence(db1)

	engine1, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine(1): %v", err)
	}
	engine1.SetPersistence(persistence1)
	engine1.SetRequireTxSig(false)
	engine1.SetL1Anchor(NewMemoryL1Anchor(10))

	if err := engine1.Start(); err != nil {
		t.Fatalf("Start(1): %v", err)
	}
	// No transactions submitted → no batches → no anchors.

	if err := engine1.Stop(); err != nil {
		t.Fatalf("Stop(1): %v", err)
	}
	cleanup1()

	// Phase 2: Restart with a fresh anchor.
	db2, cleanup2 := newTestDBAtDir(t, dir)
	defer cleanup2()
	persistence2 := NewPersistence(db2)

	engine2, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine(2): %v", err)
	}
	engine2.SetPersistence(persistence2)
	engine2.SetRequireTxSig(false)
	engine2.SetL1Anchor(NewMemoryL1Anchor(10))

	if err := engine2.Start(); err != nil {
		t.Fatalf("Start(2): %v", err)
	}
	defer engine2.Stop()

	// With no persisted anchors, lastAnchorHeight must remain 0 (the
	// safe default — updateL1AnchorLag will short-circuit, which is
	// correct because there is genuinely nothing to measure lag against).
	if got := engine2.GetLastAnchorHeight(); got != 0 {
		t.Errorf("RLLP-R5-08: lastAnchorHeight=%d after restart with no anchors, want 0", got)
	}

	t.Log("✅ RLLP-R5-08: lastAnchorHeight correctly stays 0 when no anchors were persisted")
}
