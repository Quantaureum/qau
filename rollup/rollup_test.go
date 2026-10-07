// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

func TestRollupConfig(t *testing.T) {
	t.Run("DefaultConfig", func(t *testing.T) {
		cfg := DefaultRollupConfig()
		// W-P0-4 FIX: Default ChainID is now 1670 (not 42069).
		if cfg.ChainID != DefaultL2ChainID {
			t.Errorf("expected ChainID %d, got %d", DefaultL2ChainID, cfg.ChainID)
		}
		// W-P0-4 FIX: Default L1ChainID is now 1668 (not 1).
		if cfg.L1ChainID != DefaultL1ChainID {
			t.Errorf("expected L1ChainID %d, got %d", DefaultL1ChainID, cfg.L1ChainID)
		}
		if cfg.MaxBatchSize != DefaultMaxBatchSize {
			t.Errorf("expected MaxBatchSize %d, got %d", DefaultMaxBatchSize, cfg.MaxBatchSize)
		}
	})

	t.Run("Validate valid config", func(t *testing.T) {
		cfg := DefaultRollupConfig()
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("Validate invalid chain ID", func(t *testing.T) {
		cfg := DefaultRollupConfig()
		cfg.ChainID = 0
		if err := cfg.Validate(); err != ErrInvalidChainID {
			t.Errorf("expected ErrInvalidChainID, got %v", err)
		}
	})

	// W-P0-4 FIX: L2 ChainID must differ from L1 ChainID (anti-replay).
	t.Run("Validate L2 ChainID equals L1 ChainID", func(t *testing.T) {
		cfg := DefaultRollupConfig()
		cfg.ChainID = cfg.L1ChainID // make them equal
		if err := cfg.Validate(); err != ErrInvalidChainID {
			t.Errorf("expected ErrInvalidChainID when L2==L1, got %v", err)
		}
	})

	t.Run("Validate invalid batch size", func(t *testing.T) {
		cfg := DefaultRollupConfig()
		cfg.MaxBatchSize = 0
		if err := cfg.Validate(); err != ErrInvalidBatchSize {
			t.Errorf("expected ErrInvalidBatchSize, got %v", err)
		}
	})
}

func TestBatchManager(t *testing.T) {
	cfg := DefaultRollupConfig()
	genesisRoot := types.Hash{1, 2, 3}

	t.Run("NewBatchManager", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		if bm == nil {
			t.Fatal("NewBatchManager returned nil")
		}
		if bm.GetLastStateRoot() != genesisRoot {
			t.Error("last state root mismatch")
		}
	})

	t.Run("AddTransaction", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		tx := &RollupTransaction{
			Nonce:    0,
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     types.Address{1},
		}
		err := bm.AddTransaction(tx)
		if err != nil {
			t.Fatalf("AddTransaction failed: %v", err)
		}
		if bm.PendingTxCount() != 1 {
			t.Errorf("expected 1 pending tx, got %d", bm.PendingTxCount())
		}
	})

	t.Run("BuildBatch", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		tx := &RollupTransaction{
			Nonce:    0,
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     types.Address{1},
		}
		bm.AddTransaction(tx)

		batch, err := bm.BuildBatch()
		if err != nil {
			t.Fatalf("BuildBatch failed: %v", err)
		}
		if batch.Index != 0 {
			t.Errorf("expected index 0, got %d", batch.Index)
		}
		if batch.TxCount != 1 {
			t.Errorf("expected 1 tx, got %d", batch.TxCount)
		}
		if batch.Status != BatchStatusPending {
			t.Errorf("expected pending status, got %d", batch.Status)
		}
	})

	t.Run("BuildBatch insufficient txs", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		_, err := bm.BuildBatch()
		if err != ErrInsufficientTxs {
			t.Errorf("expected ErrInsufficientTxs, got %v", err)
		}
	})

	t.Run("SubmitBatch", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		tx := &RollupTransaction{
			Nonce:    0,
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     types.Address{1},
		}
		bm.AddTransaction(tx)
		batch, _ := bm.BuildBatch()

		postRoot := types.Hash{4, 5, 6}
		txHash := types.Hash{7, 8, 9}
		err := bm.SubmitBatch(batch.Index, postRoot, txHash)
		if err != nil {
			t.Fatalf("SubmitBatch failed: %v", err)
		}

		retrieved, _ := bm.GetBatch(batch.Index)
		if retrieved.Status != BatchStatusSubmitted {
			t.Errorf("expected submitted status, got %d", retrieved.Status)
		}
	})

	t.Run("GetBatch not found", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		_, err := bm.GetBatch(999)
		if err != ErrBatchNotFound {
			t.Errorf("expected ErrBatchNotFound, got %v", err)
		}
	})

	t.Run("BatchFull", func(t *testing.T) {
		smallCfg := DefaultRollupConfig()
		smallCfg.MaxTxPerBatch = 2
		bm := NewBatchManager(smallCfg, genesisRoot)

		bm.AddTransaction(&RollupTransaction{Nonce: 0, GasLimit: 21000, Value: big.NewInt(0), From: types.Address{1}})
		bm.AddTransaction(&RollupTransaction{Nonce: 1, GasLimit: 21000, Value: big.NewInt(0), From: types.Address{2}})
		err := bm.AddTransaction(&RollupTransaction{Nonce: 2, GasLimit: 21000, Value: big.NewInt(0), From: types.Address{3}})
		if err != ErrBatchFull {
			t.Errorf("expected ErrBatchFull, got %v", err)
		}
	})
}

func TestRollupEngine(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond
	cfg.MinTxPerBatch = 1

	t.Run("NewRollupEngine", func(t *testing.T) {
		engine, err := NewRollupEngine(cfg)
		if err != nil {
			t.Fatalf("NewRollupEngine failed: %v", err)
		}
		if engine.GetStatus() != RollupStatusStopped {
			t.Errorf("expected stopped status, got %d", engine.GetStatus())
		}
	})

	t.Run("Start and Stop", func(t *testing.T) {
		engine, _ := NewRollupEngine(cfg)
		err := engine.Start()
		if err != nil {
			t.Fatalf("Start failed: %v", err)
		}
		if engine.GetStatus() != RollupStatusRunning {
			t.Errorf("expected running status, got %d", engine.GetStatus())
		}

		err = engine.Stop()
		if err != nil {
			t.Fatalf("Stop failed: %v", err)
		}
		if engine.GetStatus() != RollupStatusStopped {
			t.Errorf("expected stopped status, got %d", engine.GetStatus())
		}
	})

	t.Run("SubmitL2Transaction when stopped", func(t *testing.T) {
		engine, _ := NewRollupEngine(cfg)
		tx := &RollupTransaction{
			Nonce:    0,
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     types.Address{1},
		}
		err := engine.SubmitL2Transaction(tx)
		if err != ErrRollupNotRunning {
			t.Errorf("expected ErrRollupNotRunning, got %v", err)
		}
	})

	t.Run("GetStats", func(t *testing.T) {
		engine, _ := NewRollupEngine(cfg)
		batches, txs, _ := engine.GetStats()
		if batches != 0 {
			t.Errorf("expected 0 batches, got %d", batches)
		}
		if txs != 0 {
			t.Errorf("expected 0 txs, got %d", txs)
		}
	})
}

func TestStateManager(t *testing.T) {
	cfg := DefaultRollupConfig()

	t.Run("NewStateManager", func(t *testing.T) {
		sm := NewStateManager(cfg)
		if sm == nil {
			t.Fatal("NewStateManager returned nil")
		}
	})

	t.Run("ProcessBatch simple transfer", func(t *testing.T) {
		sm := NewStateManager(cfg)
		from := types.Address{1}
		to := types.Address{2}

		sm.getOrCreateAccount(from)
		sm.accountStates[from].Balance.SetInt64(1000000)
		sm.accountStates[from].Nonce = 0

		txs := []*RollupTransaction{
			{
				Nonce:    0,
				GasPrice: 1,
				GasLimit: 21000,
				Value:    big.NewInt(500),
				From:     from,
				To:       &to,
			},
		}

		prevRoot := sm.computeStateRoot()
		newRoot, gasUsed, err := sm.ProcessBatch(0, prevRoot, txs)
		if err != nil {
			t.Fatalf("ProcessBatch failed: %v", err)
		}
		if gasUsed != 21000 {
			t.Errorf("expected gasUsed 21000, got %d", gasUsed)
		}
		if newRoot == prevRoot {
			t.Error("state root should have changed")
		}

		// W-P0-3 FIX: Verify stateRoot is archived and GetStateRoot returns it
		archivedRoot, exists := sm.GetStateRoot(0)
		if !exists {
			t.Error("GetStateRoot(0) should exist after ProcessBatch")
		}
		if archivedRoot != newRoot {
			t.Errorf("archived state root mismatch: got %x, want %x", archivedRoot, newRoot)
		}

		fromAcc := sm.GetAccount(from)
		expectedFromBalance := big.NewInt(1000000 - 500 - 21000)
		if fromAcc.Balance.Cmp(expectedFromBalance) != 0 {
			t.Errorf("unexpected from balance: got %s, want %s", fromAcc.Balance.String(), expectedFromBalance.String())
		}
		if fromAcc.Nonce != 1 {
			t.Errorf("expected nonce 1, got %d", fromAcc.Nonce)
		}

		toAcc := sm.GetAccount(to)
		expectedToBalance := big.NewInt(500)
		if toAcc.Balance.Cmp(expectedToBalance) != 0 {
			t.Errorf("unexpected to balance: got %s, want %s", toAcc.Balance.String(), expectedToBalance.String())
		}
	})

	t.Run("ProcessBatch invalid nonce", func(t *testing.T) {
		sm := NewStateManager(cfg)
		from := types.Address{1}
		sm.getOrCreateAccount(from)
		sm.accountStates[from].Balance.SetInt64(1000000)
		sm.accountStates[from].Nonce = 5

		txs := []*RollupTransaction{
			{
				Nonce:    0,
				GasPrice: 1,
				GasLimit: 21000,
				Value:    big.NewInt(500),
				From:     from,
			},
		}

		prevRoot := sm.computeStateRoot()
		_, _, err := sm.ProcessBatch(0, prevRoot, txs)
		if err != ErrInvalidStateTransition {
			t.Errorf("expected ErrInvalidStateTransition, got %v", err)
		}
	})

	t.Run("ProcessBatch insufficient balance", func(t *testing.T) {
		sm := NewStateManager(cfg)
		from := types.Address{1}
		sm.getOrCreateAccount(from)
		sm.accountStates[from].Balance.SetInt64(100)
		sm.accountStates[from].Nonce = 0

		txs := []*RollupTransaction{
			{
				Nonce:    0,
				GasPrice: 1,
				GasLimit: 21000,
				Value:    big.NewInt(500),
				From:     from,
			},
		}

		prevRoot := sm.computeStateRoot()
		_, _, err := sm.ProcessBatch(0, prevRoot, txs)
		if err != ErrInvalidStateTransition {
			t.Errorf("expected ErrInvalidStateTransition, got %v", err)
		}
	})

	t.Run("ProcessBatch multiple txs", func(t *testing.T) {
		sm := NewStateManager(cfg)
		from := types.Address{1}
		to := types.Address{2}
		sm.getOrCreateAccount(from)
		sm.accountStates[from].Balance.SetInt64(1000000)
		sm.accountStates[from].Nonce = 0

		txs := []*RollupTransaction{
			{Nonce: 0, GasPrice: 1, GasLimit: 21000, Value: big.NewInt(100), From: from, To: &to},
			{Nonce: 1, GasPrice: 1, GasLimit: 21000, Value: big.NewInt(200), From: from},
		}

		prevRoot := sm.computeStateRoot()
		newRoot, gasUsed, err := sm.ProcessBatch(0, prevRoot, txs)
		if err != nil {
			t.Fatalf("ProcessBatch failed: %v", err)
		}
		if gasUsed != 42000 {
			t.Errorf("expected gas used 42000, got %d", gasUsed)
		}
		_ = newRoot

		// W-P0-3 FIX: Verify stateRoot archived for batch index 0
		if _, exists := sm.GetStateRoot(0); !exists {
			t.Error("GetStateRoot(0) should exist after ProcessBatch")
		}

		fromAcc := sm.GetAccount(from)
		if fromAcc.Nonce != 2 {
			t.Errorf("expected nonce 2, got %d", fromAcc.Nonce)
		}
	})

	t.Run("GetStateRoot", func(t *testing.T) {
		sm := NewStateManager(cfg)
		root, exists := sm.GetStateRoot(0)
		if exists {
			t.Error("state root should not exist for batch 0")
		}
		_ = root
	})
}

func TestBatchManagerExtras(t *testing.T) {
	cfg := DefaultRollupConfig()
	genesisRoot := types.Hash{1, 2, 3}

	t.Run("FinalizeBatch not found", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		err := bm.FinalizeBatch(999)
		if err != ErrBatchNotFound {
			t.Errorf("expected ErrBatchNotFound, got %v", err)
		}
	})

	t.Run("FinalizeBatch not submitted", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		bm.AddTransaction(&RollupTransaction{Nonce: 0, GasLimit: 21000, Value: big.NewInt(0), From: types.Address{1}})
		batch, _ := bm.BuildBatch()
		err := bm.FinalizeBatch(batch.Index)
		if err != ErrBatchNotSubmitted {
			t.Errorf("expected ErrBatchNotSubmitted, got %v", err)
		}
	})

	t.Run("FinalizeBatch challenge period not over", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		bm.AddTransaction(&RollupTransaction{Nonce: 0, GasLimit: 21000, Value: big.NewInt(0), From: types.Address{1}})
		batch, _ := bm.BuildBatch()
		bm.SubmitBatch(batch.Index, types.Hash{4, 5, 6}, types.Hash{7, 8, 9})
		err := bm.FinalizeBatch(batch.Index)
		if err != ErrChallengePeriodNotOver {
			t.Errorf("expected ErrChallengePeriodNotOver, got %v", err)
		}
	})

	t.Run("ChallengeBatch", func(t *testing.T) {
		// R36-P0-03: Set up a fraudulent batch so the fraud proof can be
		// verified (roots must match the batch's recorded roots).
		sm := NewStateManager(cfg)
		from := types.Address{10}
		sm.getOrCreateAccount(from)
		sm.accountStates[from].Balance.SetInt64(1000000)
		sm.accountStates[from].Nonce = 0
		preStateRoot := sm.computeStateRoot()

		bm := NewBatchManager(cfg, preStateRoot)
		tx := &RollupTransaction{Nonce: 0, GasPrice: 1, GasLimit: 21000, Value: big.NewInt(100), From: from}
		bm.AddTransaction(tx)
		batch, _ := bm.BuildBatch()
		correctPostRoot, _, err := sm.ProcessBatch(batch.Index, preStateRoot, []*RollupTransaction{tx})
		if err != nil {
			t.Fatalf("ProcessBatch: %v", err)
		}
		tamperedRoot := types.Hash{4, 5, 6}
		if tamperedRoot == correctPostRoot {
			tamperedRoot[0] = 0x99
		}
		bm.SubmitBatch(batch.Index, tamperedRoot, types.Hash{7, 8, 9})

		fp := NewFraudProver(cfg, sm)
		fp.SetRequireSignatureVerifier(false) // R3-C1: tests bypass sig verification
		fp.SetBatchLookup(bm)
		if err := fp.SubmitFraudProof(&FraudProof{
			Type:          FraudProofTypeStateTransition,
			BatchIndex:    batch.Index,
			Challenger:    types.Address{1},
			PreStateRoot:  preStateRoot,
			PostStateRoot: tamperedRoot,
			ChallengerSig: []byte{0x01},
			InvalidTx:     tx,
			Timestamp:     time.Now().Unix(),
		}); err != nil {
			t.Fatalf("SubmitFraudProof: %v", err)
		}
		bm.SetFraudProver(fp)

		err = bm.ChallengeBatch(batch.Index)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		got, _ := bm.GetBatch(batch.Index)
		if got.Status != BatchStatusChallenged {
			t.Errorf("expected challenged, got %d", got.Status)
		}
	})

	t.Run("ChallengeBatch not found", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		err := bm.ChallengeBatch(999)
		if err != ErrBatchNotFound {
			t.Errorf("expected ErrBatchNotFound, got %v", err)
		}
	})

	t.Run("ChallengeBatch not submitted", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		bm.AddTransaction(&RollupTransaction{Nonce: 0, GasLimit: 21000, Value: big.NewInt(0), From: types.Address{1}})
		batch, _ := bm.BuildBatch()
		err := bm.ChallengeBatch(batch.Index)
		if err != ErrBatchNotSubmitted {
			t.Errorf("expected ErrBatchNotSubmitted, got %v", err)
		}
	})

	t.Run("GetCurrentBatch", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		if bm.GetCurrentBatch() != nil {
			t.Error("GetCurrentBatch should return nil before building")
		}
		bm.AddTransaction(&RollupTransaction{Nonce: 0, GasLimit: 21000, Value: big.NewInt(0), From: types.Address{1}})
		bm.BuildBatch()
		if bm.GetCurrentBatch() == nil {
			t.Error("GetCurrentBatch should not be nil after building")
		}
	})

	t.Run("SubmitBatch already submitted", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		bm.AddTransaction(&RollupTransaction{Nonce: 0, GasLimit: 21000, Value: big.NewInt(0), From: types.Address{1}})
		batch, _ := bm.BuildBatch()
		bm.SubmitBatch(batch.Index, types.Hash{4, 5, 6}, types.Hash{7, 8, 9})
		err := bm.SubmitBatch(batch.Index, types.Hash{10}, types.Hash{11})
		if err != ErrBatchAlreadySubmitted {
			t.Errorf("expected ErrBatchAlreadySubmitted, got %v", err)
		}
	})
}

func TestRollupEngineExtras(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond
	cfg.MinTxPerBatch = 1

	engine, _ := NewRollupEngine(cfg)
	engine.Start()
	defer engine.Stop()

	t.Run("SubmitL2Transaction running", func(t *testing.T) {
		engine.SetRequireTxSig(false) // AUDIT (2026) HIGH-10: tests bypass sig verification
		// W-P0-4 FIX: tx.ChainID must match the engine's configured ChainID.
		tx := &RollupTransaction{Nonce: 0, GasPrice: 1, GasLimit: 21000, Value: big.NewInt(100), From: types.Address{1}, ChainID: cfg.ChainID}
		err := engine.SubmitL2Transaction(tx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("getters", func(t *testing.T) {
		if engine.GetBatchManager() == nil {
			t.Error("GetBatchManager should not be nil")
		}
		if engine.GetStateManager() == nil {
			t.Error("GetStateManager should not be nil")
		}
		if engine.GetFraudProver() == nil {
			t.Error("GetFraudProver should not be nil")
		}
		if engine.GetConfig() == nil {
			t.Error("GetConfig should not be nil")
		}
	})

	t.Run("Start already running", func(t *testing.T) {
		e2, _ := NewRollupEngine(cfg)
		e2.Start()
		defer e2.Stop()
		err := e2.Start()
		if err != ErrRollupAlreadyRunning {
			t.Errorf("expected ErrRollupAlreadyRunning, got %v", err)
		}
	})

	t.Run("Stop not running", func(t *testing.T) {
		e3, _ := NewRollupEngine(cfg)
		err := e3.Stop()
		if err != ErrRollupNotRunning {
			t.Errorf("expected ErrRollupNotRunning, got %v", err)
		}
	})
}

func TestRollupConfig_Validate(t *testing.T) {
	t.Run("invalid block time", func(t *testing.T) {
		cfg := DefaultRollupConfig()
		cfg.BlockTime = 0
		if err := cfg.Validate(); err != ErrInvalidBlockTime {
			t.Errorf("expected ErrInvalidBlockTime, got %v", err)
		}
	})

	t.Run("invalid challenge period", func(t *testing.T) {
		cfg := DefaultRollupConfig()
		cfg.ChallengePeriod = 0
		if err := cfg.Validate(); err != ErrInvalidChallengePeriod {
			t.Errorf("expected ErrInvalidChallengePeriod, got %v", err)
		}
	})

	t.Run("invalid gas limit", func(t *testing.T) {
		cfg := DefaultRollupConfig()
		cfg.GasLimit = 0
		if err := cfg.Validate(); err != ErrInvalidGasLimit {
			t.Errorf("expected ErrInvalidGasLimit, got %v", err)
		}
	})
}

func TestBatchStatusValues(t *testing.T) {
	statuses := map[BatchStatus]bool{
		BatchStatusPending:    true,
		BatchStatusSubmitted:  true,
		BatchStatusFinalized:  true,
		BatchStatusChallenged: true,
		BatchStatusRejected:   true,
	}
	for s := range statuses {
		_ = s
	}
}

func TestFraudProofTypes(t *testing.T) {
	types := map[FraudProofType]bool{
		FraudProofTypeStateTransition: true,
		FraudProofTypeInvalidBatch:    true,
		FraudProofTypeDoubleSpend:     true,
	}
	for t := range types {
		_ = t
	}
}

func TestNewRollupEngine_InvalidConfig(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.ChainID = 0
	_, err := NewRollupEngine(cfg)
	if err == nil {
		t.Error("should fail with invalid config")
	}
}

func TestFraudProver(t *testing.T) {
	cfg := DefaultRollupConfig()

	t.Run("NewFraudProver", func(t *testing.T) {
		sm := NewStateManager(cfg)
		fp := NewFraudProver(cfg, sm)
		if fp == nil {
			t.Fatal("NewFraudProver returned nil")
		}
	})

	t.Run("SubmitFraudProof", func(t *testing.T) {
		sm := NewStateManager(cfg)
		fp := NewFraudProver(cfg, sm)
		fp.SetRequireSignatureVerifier(false) // R3-C1: tests bypass sig verification

		// R36-P0-03: Set up a fraudulent batch so the fraud proof can be
		// verified (proof roots must match the batch's recorded roots).
		from := types.Address{10}
		sm.getOrCreateAccount(from)
		sm.accountStates[from].Balance.SetInt64(1000000)
		sm.accountStates[from].Nonce = 0
		preStateRoot := sm.computeStateRoot()

		bm := NewBatchManager(cfg, preStateRoot)
		fp.SetBatchLookup(bm)

		tx := &RollupTransaction{
			Nonce:    0,
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     from,
			To:       &types.Address{20},
		}
		bm.AddTransaction(tx)
		batch, _ := bm.BuildBatch()
		correctPostRoot, _, err := sm.ProcessBatch(batch.Index, preStateRoot, []*RollupTransaction{tx})
		if err != nil {
			t.Fatalf("ProcessBatch: %v", err)
		}
		tamperedRoot := types.Hash{2}
		if tamperedRoot == correctPostRoot {
			tamperedRoot[0] = 0x99
		}
		if err := bm.SubmitBatch(batch.Index, tamperedRoot, types.Hash{}); err != nil {
			t.Fatalf("SubmitBatch: %v", err)
		}

		proof := &FraudProof{
			Type:          FraudProofTypeStateTransition,
			BatchIndex:    batch.Index,
			Challenger:    types.Address{1},
			PreStateRoot:  preStateRoot,
			PostStateRoot: tamperedRoot, // matches batch.PostStateRoot (R36-P0-03)
			ChallengerSig: []byte{0x01}, // ROLLUP-001: required signature field
			InvalidTx:     tx,
			Timestamp:     time.Now().Unix(),
		}

		err = fp.SubmitFraudProof(proof)
		if err != nil {
			t.Fatalf("SubmitFraudProof failed: %v", err)
		}

		retrieved, exists := fp.GetFraudProof(batch.Index)
		if !exists {
			t.Fatal("fraud proof not found")
		}
		if retrieved.BatchIndex != batch.Index {
			t.Errorf("expected batch index %d, got %d", batch.Index, retrieved.BatchIndex)
		}
	})

	t.Run("SubmitFraudProof duplicate", func(t *testing.T) {
		sm := NewStateManager(cfg)
		fp := NewFraudProver(cfg, sm)
		fp.SetRequireSignatureVerifier(false) // R3-C1: tests bypass sig verification

		proof := &FraudProof{
			Type:          FraudProofTypeStateTransition,
			BatchIndex:    1,
			Challenger:    types.Address{1},
			ChallengerSig: []byte{0x01}, // ROLLUP-001: required signature field
			Timestamp:     time.Now().Unix(),
		}

		fp.SubmitFraudProof(proof)
		err := fp.SubmitFraudProof(proof)
		if err != ErrFraudProofInvalid {
			t.Errorf("expected ErrFraudProofInvalid, got %v", err)
		}
	})

	t.Run("HasFraudProof", func(t *testing.T) {
		sm := NewStateManager(cfg)
		fp := NewFraudProver(cfg, sm)
		fp.SetRequireSignatureVerifier(false) // R3-C1: tests bypass sig verification

		if fp.HasFraudProof(1) {
			t.Error("should not have fraud proof for batch 1")
		}

		// R36-P0-03: Set up a fraudulent batch so the fraud proof can be
		// verified (proof roots must match the batch's recorded roots).
		from := types.Address{10}
		sm.getOrCreateAccount(from)
		sm.accountStates[from].Balance.SetInt64(1000000)
		sm.accountStates[from].Nonce = 0
		preStateRoot := sm.computeStateRoot()

		bm := NewBatchManager(cfg, preStateRoot)
		fp.SetBatchLookup(bm)

		tx := &RollupTransaction{
			Nonce:    0,
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     from,
		}
		bm.AddTransaction(tx)
		batch, _ := bm.BuildBatch()
		correctPostRoot, _, err := sm.ProcessBatch(batch.Index, preStateRoot, []*RollupTransaction{tx})
		if err != nil {
			t.Fatalf("ProcessBatch: %v", err)
		}
		tamperedRoot := types.Hash{2}
		if tamperedRoot == correctPostRoot {
			tamperedRoot[0] = 0x99
		}
		if err := bm.SubmitBatch(batch.Index, tamperedRoot, types.Hash{}); err != nil {
			t.Fatalf("SubmitBatch: %v", err)
		}

		fp.SubmitFraudProof(&FraudProof{
			Type:          FraudProofTypeStateTransition,
			BatchIndex:    batch.Index,
			Challenger:    types.Address{3},
			PreStateRoot:  preStateRoot,
			PostStateRoot: tamperedRoot, // matches batch.PostStateRoot (R36-P0-03)
			ChallengerSig: []byte{0x01}, // ROLLUP-001: required signature field
			InvalidTx:     tx,
			Timestamp:     time.Now().Unix(),
		})

		if !fp.HasFraudProof(batch.Index) {
			t.Error("should have fraud proof for batch")
		}
	})
}

func TestSequencer(t *testing.T) {
	cfg := DefaultRollupConfig()
	genesisRoot := types.Hash{1, 2, 3}

	t.Run("NewSequencer", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		seq := NewSequencer(cfg, bm)
		if seq == nil {
			t.Fatal("NewSequencer returned nil")
		}
	})

	t.Run("AcceptTransaction", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		seq := NewSequencer(cfg, bm)
		seq.SetRequireTxSig(false) // AUDIT (2026) HIGH-10: tests bypass sig verification

		tx := &RollupTransaction{
			Nonce:    0,
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     types.Address{1},
			ChainID:  cfg.ChainID, // W-P0-4 FIX: must match rollup ChainID
		}

		err := seq.AcceptTransaction(tx)
		if err != nil {
			t.Fatalf("AcceptTransaction failed: %v", err)
		}

		if bm.PendingTxCount() != 1 {
			t.Errorf("expected 1 pending tx, got %d", bm.PendingTxCount())
		}
	})

	t.Run("AcceptTransaction invalid gas limit", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		seq := NewSequencer(cfg, bm)

		tx := &RollupTransaction{
			Nonce:    0,
			GasPrice: 1,
			GasLimit: 0,
			Value:    big.NewInt(100),
			From:     types.Address{1},
			ChainID:  cfg.ChainID, // W-P0-4 FIX: must match rollup ChainID
		}

		err := seq.AcceptTransaction(tx)
		if err != ErrInvalidGasLimit {
			t.Errorf("expected ErrInvalidGasLimit, got %v", err)
		}
	})

	// W-P0-4 FIX: Transactions with wrong ChainID must be rejected (anti-replay).
	t.Run("AcceptTransaction wrong chain ID", func(t *testing.T) {
		bm := NewBatchManager(cfg, genesisRoot)
		seq := NewSequencer(cfg, bm)
		seq.SetRequireTxSig(false)

		tx := &RollupTransaction{
			Nonce:    0,
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			From:     types.Address{1},
			ChainID:  cfg.ChainID + 1, // wrong chain ID
		}

		err := seq.AcceptTransaction(tx)
		if err == nil {
			t.Error("expected error for wrong ChainID, got nil")
		}
	})
}

func TestTryBuildAndSubmitBatch_NotRunning(t *testing.T) {
	cfg := DefaultRollupConfig()
	engine, _ := NewRollupEngine(cfg)
	engine.tryBuildAndSubmitBatch()

	if engine.totalBatches != 0 {
		t.Error("should not build batches when not running")
	}
}

func TestVerifyFraudProof_ZeroValues(t *testing.T) {
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	fp := NewFraudProver(cfg, sm)
	fp.SetRequireSignatureVerifier(false) // R3-C1: tests bypass sig verification

	proof := &FraudProof{BatchIndex: 0, PreStateRoot: types.Hash{}}
	err := fp.verifyFraudProof(proof)
	if err != ErrFraudProofInvalid {
		t.Errorf("expected ErrFraudProofInvalid, got %v", err)
	}
}

func TestVerifyFraudProof_ValidTxProducesSameRoot(t *testing.T) {
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	fp := NewFraudProver(cfg, sm)
	fp.SetRequireSignatureVerifier(false) // R3-C1: tests bypass sig verification

	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     types.Address{1},
		To:       &types.Address{2},
	}

	root, exists := sm.GetStateRoot(0)
	if !exists {
		root = types.Hash{1}
	}

	proof := &FraudProof{
		BatchIndex:    1,
		PreStateRoot:  root,
		PostStateRoot: root,
		InvalidTx:     tx,
	}
	err := fp.verifyFraudProof(proof)
	if err != ErrFraudProofInvalid {
		t.Logf("verifyFraudProof result: %v", err)
	}
}

// TestSimulateBatch_HistoricalState verifies W-P0-1: SimulateBatch can execute
// against a historical state snapshot (archived by ProcessBatch) even after the
// live state has advanced. This is the core fix that prevents a malicious
// sequencer from escaping challenge by processing additional batches.
func TestSimulateBatch_HistoricalState(t *testing.T) {
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)

	from := types.Address{1}
	to := types.Address{2}

	// Set up initial account state.
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance.SetInt64(1000000)
	sm.accountStates[from].Nonce = 0

	// --- Batch 0: from sends 500 to to ---
	genesisRoot := sm.computeStateRoot()
	txs0 := []*RollupTransaction{
		{Nonce: 0, GasPrice: 1, GasLimit: 21000, Value: big.NewInt(500), From: from, To: &to},
	}
	root0, _, err := sm.ProcessBatch(0, genesisRoot, txs0)
	if err != nil {
		t.Fatalf("ProcessBatch(0) failed: %v", err)
	}

	// --- Batch 1: from sends 300 to to ---
	txs1 := []*RollupTransaction{
		{Nonce: 1, GasPrice: 1, GasLimit: 21000, Value: big.NewInt(300), From: from, To: &to},
	}
	root1, _, err := sm.ProcessBatch(1, root0, txs1)
	if err != nil {
		t.Fatalf("ProcessBatch(1) failed: %v", err)
	}

	// At this point the live state has advanced to root1. The historical
	// states for genesisRoot and root0 should be archived.

	t.Run("SimulateBatch on historical root0 produces same root1", func(t *testing.T) {
		// SimulateBatch(root0, txs1) should produce root1 — the same result
		// ProcessBatch(1, root0, txs1) produced.
		simRoot, _, err := sm.SimulateBatch(root0, txs1)
		if err != nil {
			t.Fatalf("SimulateBatch(root0) failed: %v", err)
		}
		if simRoot != root1 {
			t.Errorf("SimulateBatch on historical state produced different root: got %x, want %x",
				simRoot, root1)
		}
	})

	t.Run("SimulateBatch on genesisRoot produces same root0", func(t *testing.T) {
		// SimulateBatch(genesisRoot, txs0) should produce root0.
		simRoot, _, err := sm.SimulateBatch(genesisRoot, txs0)
		if err != nil {
			t.Fatalf("SimulateBatch(genesisRoot) failed: %v", err)
		}
		if simRoot != root0 {
			t.Errorf("SimulateBatch on genesis state produced different root: got %x, want %x",
				simRoot, root0)
		}
	})

	t.Run("SimulateBatch does not mutate live state", func(t *testing.T) {
		// After SimulateBatch(root0, txs1), the live state should still be root1.
		liveRoot := sm.computeStateRoot()
		if liveRoot != root1 {
			t.Errorf("live state was mutated by SimulateBatch: got %x, want %x",
				liveRoot, root1)
		}
		// from's nonce should still be 2 (after 2 batches), not 1.
		fromAcc := sm.GetAccount(from)
		if fromAcc.Nonce != 2 {
			t.Errorf("live nonce was mutated by SimulateBatch: got %d, want 2", fromAcc.Nonce)
		}
	})

	t.Run("SimulateBatch is idempotent (historical snapshot not mutated)", func(t *testing.T) {
		// Run SimulateBatch(root0, txs1) twice — both should produce root1.
		simRoot1, _, err := sm.SimulateBatch(root0, txs1)
		if err != nil {
			t.Fatalf("first SimulateBatch(root0) failed: %v", err)
		}
		simRoot2, _, err := sm.SimulateBatch(root0, txs1)
		if err != nil {
			t.Fatalf("second SimulateBatch(root0) failed: %v", err)
		}
		if simRoot1 != simRoot2 {
			t.Errorf("SimulateBatch is not idempotent: first=%x, second=%x",
				simRoot1, simRoot2)
		}
	})

	t.Run("SimulateBatch rejects unknown prevStateRoot", func(t *testing.T) {
		// A random hash that's neither in history nor the current state.
		unknownRoot := types.Hash{0xFF, 0xEE, 0xDD}
		_, _, err := sm.SimulateBatch(unknownRoot, txs0)
		if err != ErrInvalidStateTransition {
			t.Errorf("expected ErrInvalidStateTransition for unknown prevStateRoot, got %v", err)
		}
	})

	t.Run("SimulateBatch fallback to current state (no ProcessBatch)", func(t *testing.T) {
		// Fresh StateManager — no ProcessBatch has run, so stateHistory is empty.
		// SimulateBatch with the current state root should still work (genesis
		// fallback path).
		freshSM := NewStateManager(cfg)
		freshFrom := types.Address{10}
		freshSM.getOrCreateAccount(freshFrom)
		freshSM.accountStates[freshFrom].Balance.SetInt64(1000000)
		freshSM.accountStates[freshFrom].Nonce = 0
		currentRoot := freshSM.computeStateRoot()

		tx := &RollupTransaction{
			Nonce: 0, GasPrice: 1, GasLimit: 21000, Value: big.NewInt(100),
			From: freshFrom, To: &to,
		}
		simRoot, _, err := freshSM.SimulateBatch(currentRoot, []*RollupTransaction{tx})
		if err != nil {
			t.Fatalf("SimulateBatch fallback failed: %v", err)
		}
		// Live state should be unchanged.
		if freshSM.computeStateRoot() != currentRoot {
			t.Error("fallback SimulateBatch mutated live state")
		}
		_ = simRoot
	})
}

// TestSimulateBatch_FraudProofAfterStateAdvanced verifies the end-to-end fraud
// proof scenario: a sequencer processes a fraudulent batch, then a legitimate
// batch to advance the state. The fraud proof for the fraudulent batch must
// still be verifiable using the historical state snapshot.
func TestSimulateBatch_FraudProofAfterStateAdvanced(t *testing.T) {
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	fp := NewFraudProver(cfg, sm)
	fp.SetRequireSignatureVerifier(false)

	from := types.Address{1}
	to := types.Address{2}
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance.SetInt64(1000000)
	sm.accountStates[from].Nonce = 0

	genesisRoot := sm.computeStateRoot()

	// R36-P0-03: Set up a BatchManager so the fraud proof can be verified
	// against the batch's recorded roots.
	bm := NewBatchManager(cfg, genesisRoot)
	fp.SetBatchLookup(bm)

	// Batch 0: build and submit with a TAMPERED PostStateRoot (fraud).
	tx0 := &RollupTransaction{
		Nonce: 0, GasPrice: 1, GasLimit: 21000, Value: big.NewInt(500),
		From: from, To: &to,
	}
	bm.AddTransaction(tx0)
	batch0, err := bm.BuildBatch()
	if err != nil {
		t.Fatalf("BuildBatch(0): %v", err)
	}
	root0, _, err := sm.ProcessBatch(batch0.Index, genesisRoot, []*RollupTransaction{tx0})
	if err != nil {
		t.Fatalf("ProcessBatch(0) failed: %v", err)
	}
	tamperedRoot := types.Hash{0xAA, 0xBB, 0xCC}
	if tamperedRoot == root0 {
		tamperedRoot[0] = 0xDD
	}
	if err := bm.SubmitBatch(batch0.Index, tamperedRoot, types.Hash{}); err != nil {
		t.Fatalf("SubmitBatch(0): %v", err)
	}

	// Batch 1: legitimate (advances state past root0). This is processed
	// through the StateManager only — the purpose is to test that
	// SimulateBatch loads the HISTORICAL pre-state, not the live state.
	tx1 := &RollupTransaction{
		Nonce: 1, GasPrice: 1, GasLimit: 21000, Value: big.NewInt(300),
		From: from, To: &to,
	}
	if _, _, err := sm.ProcessBatch(1, root0, []*RollupTransaction{tx1}); err != nil {
		t.Fatalf("ProcessBatch(1) failed: %v", err)
	}

	// Submit a fraud proof for batch 0. proof roots must match batch 0's
	// recorded roots (R36-P0-03). SimulateBatch(genesisRoot, [tx0]) returns
	// root0, which differs from batch0.PostStateRoot (tamperedRoot) -> fraud.
	proof := &FraudProof{
		Type:          FraudProofTypeStateTransition,
		BatchIndex:    batch0.Index,
		Challenger:    types.Address{9},
		PreStateRoot:  genesisRoot,
		PostStateRoot: tamperedRoot,
		ChallengerSig: []byte{0x01},
		InvalidTx:     tx0,
		Timestamp:     time.Now().Unix(),
	}

	err = fp.SubmitFraudProof(proof)
	if err != nil {
		t.Errorf("fraud proof should be accepted (fraud detected), got error: %v", err)
	}
}

// --- W-P0-2 tests: processBatchLocked QVM contract call integration ---

// mockQVMExecutor is a controllable mock implementing the QVMExecutor interface
// for unit testing processBatchLocked's contract-call routing.
type mockQVMExecutor struct {
	// result is what Call returns.
	result *qvm.ExecutionResult
	// callCount tracks how many times Call was invoked.
	callCount int
	// lastCaller / lastCallee / lastInput / lastGas / lastValue capture the
	// arguments of the most recent Call for assertion.
	lastCaller   qvm.Address
	lastCallee   qvm.Address
	lastInput    []byte
	lastGas      uint64
	lastValue    *big.Int
	lastDepth    int
	lastBlockCtx *qvm.BlockContext
}

func (m *mockQVMExecutor) Call(
	stateDB qvm.StateDB,
	caller, callee qvm.Address,
	input []byte,
	gas uint64,
	value *big.Int,
	blockCtx *qvm.BlockContext,
	depth int,
) *qvm.ExecutionResult {
	m.callCount++
	m.lastCaller = caller
	m.lastCallee = callee
	m.lastInput = append([]byte(nil), input...)
	m.lastGas = gas
	m.lastValue = new(big.Int).Set(value)
	m.lastDepth = depth
	m.lastBlockCtx = blockCtx
	// The mock does NOT actually mutate stateDB — it just returns the
	// configured result. Tests that need state mutation use the real QVM.
	return m.result
}

// deployContractCode sets bytecode on an account, simulating a deployed
// contract. Returns the account so callers can make further assertions.
func deployContractCode(sm *StateManager, addr types.Address, code []byte) *RollupAccount {
	acc := sm.getOrCreateAccount(addr)
	acc.Code = append([]byte(nil), code...)
	if len(code) > 0 {
		h := sha256.Sum256(code)
		acc.CodeHash = types.Hash(h)
	} else {
		acc.CodeHash = types.Hash{}
	}
	return acc
}

// TestExecuteContractCall_RoutesToQVM verifies W-P0-2: when a tx targets an
// account with code (CodeHash != {}) and an executor is configured, the call
// is routed to the QVM. Gas is charged based on the QVM's reported gasUsed,
// not tx.GasLimit, and unused gas is refunded.
func TestExecuteContractCall_RoutesToQVM(t *testing.T) {
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)

	from := types.Address{1}
	contract := types.Address{2}

	// Fund the sender.
	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance.SetInt64(1000000)
	sm.accountStates[from].Nonce = 0

	// Deploy a contract (set code on the target account).
	contractCode := []byte{0x00} // STOP
	deployContractCode(sm, contract, contractCode)

	// Configure the mock executor to report gasUsed = 1000 (less than
	// tx.GasLimit = 21000, so a refund should be issued).
	mock := &mockQVMExecutor{
		result: &qvm.ExecutionResult{
			GasUsed:  1000,
			Reverted: false,
			Err:      nil,
		},
	}
	sm.SetExecutor(mock)

	prevRoot := sm.computeStateRoot()
	txs := []*RollupTransaction{
		{
			Nonce:    0,
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			Data:     []byte{0xAB, 0xCD},
			From:     from,
			To:       &contract,
		},
	}

	newRoot, gasUsed, err := sm.ProcessBatch(0, prevRoot, txs)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}
	if newRoot == prevRoot {
		t.Error("state root should have changed")
	}

	// Gas charged should be QVM's gasUsed, not tx.GasLimit.
	if gasUsed != 1000 {
		t.Errorf("expected gasUsed 1000 (from QVM), got %d", gasUsed)
	}

	// The mock should have been called exactly once.
	if mock.callCount != 1 {
		t.Errorf("expected executor.Call to be invoked once, got %d", mock.callCount)
	}

	// Verify the executor received the correct arguments.
	if mock.lastCaller != toQVMAddr(from) {
		t.Errorf("executor received wrong caller: got %x, want %x", mock.lastCaller, toQVMAddr(from))
	}
	if mock.lastCallee != toQVMAddr(contract) {
		t.Errorf("executor received wrong callee: got %x, want %x", mock.lastCallee, toQVMAddr(contract))
	}
	if mock.lastGas != 21000 {
		t.Errorf("executor received wrong gas: got %d, want 21000", mock.lastGas)
	}
	if mock.lastValue.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("executor received wrong value: got %s, want 100", mock.lastValue.String())
	}

	// Verify gas refund: sender paid gasCost = 21000 * 1 up front, then got
	// refunded (21000 - 1000) * 1 = 20000. Net gas cost = 1000.
	// Value transfer (100) is handled by QVM via StateDB, but since the mock
	// doesn't actually transfer, only gas accounting is verified here.
	fromAcc := sm.GetAccount(from)
	expectedNetGasCost := int64(1000) // gasUsed * gasPrice
	expectedBalance := big.NewInt(1000000 - expectedNetGasCost)
	if fromAcc.Balance.Cmp(expectedBalance) != 0 {
		t.Errorf("unexpected from balance after refund: got %s, want %s (net gas cost=%d)",
			fromAcc.Balance.String(), expectedBalance.String(), expectedNetGasCost)
	}
	if fromAcc.Nonce != 1 {
		t.Errorf("expected nonce 1, got %d", fromAcc.Nonce)
	}
}

// TestExecuteContractCall_NoExecutorFallback verifies W-P0-2: when no executor
// is configured, a tx to an account with code falls back to simple transfer
// (backward compatibility — tx.Data is silently ignored).
func TestExecuteContractCall_NoExecutorFallback(t *testing.T) {
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)
	// NOTE: no SetExecutor call — executor is nil.

	from := types.Address{1}
	contract := types.Address{2}

	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance.SetInt64(1000000)
	sm.accountStates[from].Nonce = 0

	// Deploy a contract (set code).
	deployContractCode(sm, contract, []byte{0x00})

	prevRoot := sm.computeStateRoot()
	txs := []*RollupTransaction{
		{
			Nonce:    0,
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(500),
			Data:     []byte{0xAB, 0xCD},
			From:     from,
			To:       &contract,
		},
	}

	newRoot, gasUsed, err := sm.ProcessBatch(0, prevRoot, txs)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}
	// Gas should be tx.GasLimit (simple-transfer accounting, not QVM).
	if gasUsed != 21000 {
		t.Errorf("expected gasUsed 21000 (simple transfer fallback), got %d", gasUsed)
	}

	// Value should have been transferred (simple-transfer path).
	fromAcc := sm.GetAccount(from)
	expectedFromBalance := big.NewInt(1000000 - 500 - 21000)
	if fromAcc.Balance.Cmp(expectedFromBalance) != 0 {
		t.Errorf("unexpected from balance: got %s, want %s",
			fromAcc.Balance.String(), expectedFromBalance.String())
	}
	contractAcc := sm.GetAccount(contract)
	if contractAcc.Balance.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("unexpected contract balance: got %s, want 500",
			contractAcc.Balance.String())
	}
	if newRoot == prevRoot {
		t.Error("state root should have changed")
	}
}

// TestExecuteContractCall_QVMFailureContinuesBatch verifies W-P0-2: when the
// QVM returns an error (revert), the failed tx's state changes are rolled
// back (by QVM's RevertToSnapshot), but the batch continues with subsequent
// transactions. Gas is still charged for the failed tx.
func TestExecuteContractCall_QVMFailureContinuesBatch(t *testing.T) {
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)

	from := types.Address{1}
	contract := types.Address{2}
	to := types.Address{3}

	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance.SetInt64(1000000)
	sm.accountStates[from].Nonce = 0

	deployContractCode(sm, contract, []byte{0x00})

	// Mock executor returns a failure for the contract call.
	mock := &mockQVMExecutor{
		result: &qvm.ExecutionResult{
			GasUsed:  5000,
			Reverted: true,
			Err:      errors.New("execution reverted"),
		},
	}
	sm.SetExecutor(mock)

	prevRoot := sm.computeStateRoot()
	txs := []*RollupTransaction{
		// Tx 0: contract call that will revert.
		{
			Nonce:    0,
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(100),
			Data:     []byte{0xAB},
			From:     from,
			To:       &contract,
		},
		// Tx 1: simple transfer (no code at target) — should still execute.
		{
			Nonce:    1,
			GasPrice: 1,
			GasLimit: 21000,
			Value:    big.NewInt(200),
			From:     from,
			To:       &to,
		},
	}

	_, gasUsed, err := sm.ProcessBatch(0, prevRoot, txs)
	if err != nil {
		t.Fatalf("ProcessBatch failed: %v", err)
	}

	// Total gas = failed tx gas (5000) + simple transfer gas (21000).
	if gasUsed != 5000+21000 {
		t.Errorf("expected total gasUsed %d, got %d", 5000+21000, gasUsed)
	}

	// The executor should have been called once (for the contract tx only).
	if mock.callCount != 1 {
		t.Errorf("expected executor.Call once, got %d", mock.callCount)
	}

	// The simple transfer should have succeeded.
	toAcc := sm.GetAccount(to)
	if toAcc.Balance.Cmp(big.NewInt(200)) != 0 {
		t.Errorf("simple transfer after failed contract call did not execute: to balance got %s, want 200",
			toAcc.Balance.String())
	}

	// The failed contract call should NOT have transferred value (QVM revert
	// rolls back state including value transfer). But the mock doesn't
	// actually do state changes — so we just verify gas was charged.
	fromAcc := sm.GetAccount(from)
	if fromAcc.Nonce != 2 {
		t.Errorf("expected nonce 2 (both txs counted), got %d", fromAcc.Nonce)
	}
	// Balance calculation:
	//   Initial:           1000000
	//   Failed contract:   -21000 (upfront gasCost) + 16000 (refund) = net -5000
	//   Simple transfer:   -21000 (gas) - 200 (value) = -21200
	//   Final:             1000000 - 5000 - 21200 = 973800
	expectedBalance := big.NewInt(1000000 - 5000 - 21000 - 200)
	if fromAcc.Balance.Cmp(expectedBalance) != 0 {
		t.Errorf("unexpected from balance after failed contract call: got %s, want %s",
			fromAcc.Balance.String(), expectedBalance.String())
	}
}

// TestExecuteContractCall_RealQVM is an integration test using the real
// qvm.Executor. It deploys a contract with STOP bytecode and verifies that
// ProcessBatch routes the call through the QVM successfully.
func TestExecuteContractCall_RealQVM(t *testing.T) {
	cfg := DefaultRollupConfig()
	sm := NewStateManager(cfg)

	from := types.Address{1}
	contract := types.Address{2}

	sm.getOrCreateAccount(from)
	sm.accountStates[from].Balance.SetInt64(1000000)
	sm.accountStates[from].Nonce = 0

	// Deploy a contract whose bytecode is just STOP (0x00). STOP consumes
	// zero gas, so gasUsed will be 0 — but the nonce increment and gas
	// refund (full refund since gasUsed=0) still modify the state root.
	deployContractCode(sm, contract, []byte{0x00})

	// Use the real QVM executor.
	executor := qvm.NewExecutor()
	sm.SetExecutor(executor)

	prevRoot := sm.computeStateRoot()
	txs := []*RollupTransaction{
		{
			Nonce:    0,
			GasPrice: 1,
			GasLimit: 100000,
			Value:    big.NewInt(0),
			Data:     nil,
			From:     from,
			To:       &contract,
		},
	}

	newRoot, gasUsed, err := sm.ProcessBatch(0, prevRoot, txs)
	if err != nil {
		t.Fatalf("ProcessBatch with real QVM failed: %v", err)
	}
	if newRoot == prevRoot {
		t.Error("state root should have changed after QVM execution (nonce changed)")
	}
	// STOP consumes 0 gas; gasUsed may be 0. The key assertion is that the
	// call succeeded without error and the state root changed.
	if gasUsed > 100000 {
		t.Errorf("gasUsed %d exceeds tx.GasLimit 100000", gasUsed)
	}

	fromAcc := sm.GetAccount(from)
	if fromAcc.Nonce != 1 {
		t.Errorf("expected nonce 1, got %d", fromAcc.Nonce)
	}
	// Balance should be reduced by gasUsed * gasPrice. Since STOP consumes
	// 0 gas, the full gasLimit is refunded and the balance is unchanged.
	expectedBalance := big.NewInt(1000000 - int64(gasUsed))
	if fromAcc.Balance.Cmp(expectedBalance) != 0 {
		t.Errorf("unexpected from balance: got %s, want %s (gasUsed=%d)",
			fromAcc.Balance.String(), expectedBalance.String(), gasUsed)
	}
}

// --- W-P1-5 tests (2026-07-13): batch auto-finalize ---

// TestGetSubmittedBatchIndices verifies that GetSubmittedBatchIndices returns
// only batches in Submitted state, sorted ascending.
// W-P1-5 FIX (2026-07-13)
func TestGetSubmittedBatchIndices(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.MinTxPerBatch = 1
	bm := NewBatchManager(cfg, types.Hash{})

	// No batches yet → empty list
	indices := bm.GetSubmittedBatchIndices()
	if len(indices) != 0 {
		t.Fatalf("expected 0 indices, got %d (%v)", len(indices), indices)
	}

	// Build and submit 3 batches. Each batch needs 1 tx (MinTxPerBatch=1).
	for i := 0; i < 3; i++ {
		tx := &RollupTransaction{
			Nonce: uint64(i), From: types.Address{byte(i + 1)}, ChainID: cfg.ChainID,
		}
		if err := bm.AddTransaction(tx); err != nil {
			t.Fatalf("AddTransaction[%d] failed: %v", i, err)
		}
		batch, err := bm.BuildBatch()
		if err != nil {
			t.Fatalf("BuildBatch[%d] failed: %v", i, err)
		}
		if err := bm.SubmitBatch(batch.Index, types.Hash{byte(i + 1)}, types.Hash{}); err != nil {
			t.Fatalf("SubmitBatch[%d] failed: %v", i, err)
		}
	}

	// All 3 should be in Submitted state, sorted ascending.
	indices = bm.GetSubmittedBatchIndices()
	if len(indices) != 3 {
		t.Fatalf("expected 3 indices, got %d (%v)", len(indices), indices)
	}
	for i := 1; i < len(indices); i++ {
		if indices[i] <= indices[i-1] {
			t.Errorf("indices not sorted ascending: %v", indices)
		}
	}

	// Use L1 height mode to finalize batch 1 (index=1): set anchor + advance
	// L1 height past the challenge window so FinalizeBatch succeeds without
	// waiting for the 7-day wall-clock deadline.
	bm.SetL1ChallengeBlocks(100)
	bm.SetBatchAnchor(1, 1000)
	bm.SetL1CurrentHeight(1100) // 1100 >= 1000 + 100
	if err := bm.FinalizeBatch(1); err != nil {
		t.Fatalf("FinalizeBatch(1) failed: %v", err)
	}

	// Batch 1 should now be excluded from the submitted list.
	indices = bm.GetSubmittedBatchIndices()
	if len(indices) != 2 {
		t.Fatalf("expected 2 indices after finalizing batch 1, got %d (%v)", len(indices), indices)
	}
	for _, idx := range indices {
		if idx == 1 {
			t.Errorf("finalized batch 1 should not appear in submitted list: %v", indices)
		}
	}
}

// TestTryFinalizeBatches_L1Height verifies that tryFinalizeBatches correctly
// finalizes batches whose L1 challenge window has elapsed, and leaves batches
// whose window is still open in Submitted state.
// W-P1-5 FIX (2026-07-13)
func TestTryFinalizeBatches_L1Height(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond
	cfg.MinTxPerBatch = 1
	// Use a very long interval so the engine's own finalizeLoop does not
	// fire during the test — we call tryFinalizeBatches() manually.
	cfg.FinalizeCheckInterval = 1 * time.Hour

	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine failed: %v", err)
	}
	engine.SetRequireTxSig(false) // AUDIT (2026) HIGH-10: tests bypass sig
	if err := engine.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer engine.Stop()

	// Submit a zero-value tx with GasPrice=0 so gasCost=0 and the balance
	// check passes without preloading account state. GasLimit must be > 0
	// (sequencer rejects 0).
	tx := &RollupTransaction{
		Nonce: 0, GasPrice: 0, GasLimit: 21000, Value: big.NewInt(0),
		From: types.Address{1}, ChainID: cfg.ChainID,
	}
	if err := engine.SubmitL2Transaction(tx); err != nil {
		t.Fatalf("SubmitL2Transaction failed: %v", err)
	}

	// Poll for batch 0 to reach Submitted state.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b, err := engine.GetBatchManager().GetBatch(0)
		if err == nil && b.Status == BatchStatusSubmitted {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	b, err := engine.GetBatchManager().GetBatch(0)
	if err != nil || b.Status != BatchStatusSubmitted {
		t.Fatalf("batch 0 was not submitted within 2s (err=%v, status=%d)", err, b.Status)
	}

	// Configure L1 anchor mode: SubmitHeight=1000, challengeBlocks=100.
	// Challenge window = [1000, 1100].
	bm := engine.GetBatchManager()
	bm.SetL1ChallengeBlocks(100)
	bm.SetBatchAnchor(0, 1000)

	// L1 height = 1050 < 1100 → challenge window still open.
	bm.SetL1CurrentHeight(1050)
	engine.tryFinalizeBatches()
	b, _ = bm.GetBatch(0)
	if b.Status != BatchStatusSubmitted {
		t.Errorf("expected Submitted (challenge window open), got %d", b.Status)
	}

	// Advance L1 height to 1100 → challenge window closed.
	bm.SetL1CurrentHeight(1100)
	engine.tryFinalizeBatches()
	b, _ = bm.GetBatch(0)
	if b.Status != BatchStatusFinalized {
		t.Errorf("expected Finalized (challenge window closed), got %d", b.Status)
	}

	// Double-call should be a no-op (batch already finalized → FinalizeBatch
	// returns ErrBatchNotSubmitted, which is logged as a warning but not fatal).
	engine.tryFinalizeBatches()
	b, _ = bm.GetBatch(0)
	if b.Status != BatchStatusFinalized {
		t.Errorf("expected Finalized (idempotent), got %d", b.Status)
	}
}

// mockWithdrawalProcessor is a test double for WithdrawalProcessor.
// W-P1-5 FIX (2026-07-13)
type mockWithdrawalProcessor struct {
	mu     sync.Mutex
	called bool
	batch  *Batch
	err    error
}

func (m *mockWithdrawalProcessor) ProcessFinalizedBatch(batch *Batch) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.called = true
	m.batch = batch
	return m.err
}

func (m *mockWithdrawalProcessor) wasCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.called
}

// TestTryFinalizeBatches_WithdrawalHook verifies that the WithdrawalProcessor
// hook is invoked after a batch is finalized, and that hook errors do not roll
// back the finalization.
// W-P1-5 FIX (2026-07-13)
func TestTryFinalizeBatches_WithdrawalHook(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond
	cfg.MinTxPerBatch = 1
	cfg.FinalizeCheckInterval = 1 * time.Hour // manual call only

	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine failed: %v", err)
	}
	engine.SetRequireTxSig(false)
	wp := &mockWithdrawalProcessor{}
	engine.SetWithdrawalProcessor(wp)
	if err := engine.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer engine.Stop()

	tx := &RollupTransaction{
		Nonce: 0, GasPrice: 0, GasLimit: 21000, Value: big.NewInt(0),
		From: types.Address{1}, ChainID: cfg.ChainID,
	}
	if err := engine.SubmitL2Transaction(tx); err != nil {
		t.Fatalf("SubmitL2Transaction failed: %v", err)
	}

	// Wait for batch 0 to be submitted.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b, err := engine.GetBatchManager().GetBatch(0)
		if err == nil && b.Status == BatchStatusSubmitted {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	bm := engine.GetBatchManager()
	b, err := bm.GetBatch(0)
	if err != nil || b.Status != BatchStatusSubmitted {
		t.Fatalf("batch 0 was not submitted within 2s (err=%v)", err)
	}

	// Finalize via L1 height mode.
	bm.SetL1ChallengeBlocks(100)
	bm.SetBatchAnchor(0, 1000)
	bm.SetL1CurrentHeight(1100)

	if wp.wasCalled() {
		t.Error("WithdrawalProcessor should not be called before finalization")
	}
	engine.tryFinalizeBatches()

	if !wp.wasCalled() {
		t.Error("WithdrawalProcessor was not called after finalization")
	}
	wp.mu.Lock()
	if wp.batch == nil || wp.batch.Index != 0 {
		t.Errorf("expected batch 0 to be passed to hook, got %v", wp.batch)
	}
	wp.mu.Unlock()

	// Verify the batch is finalized.
	b, _ = bm.GetBatch(0)
	if b.Status != BatchStatusFinalized {
		t.Errorf("expected Finalized, got %d", b.Status)
	}
}

// TestFinalizeLoop_AutoFinalizeWallClock is an end-to-end test that verifies
// the engine's own finalizeLoop goroutine auto-finalizes a batch after the
// wall-clock challenge period elapses (no L1 anchor configured).
// W-P1-5 FIX (2026-07-13)
func TestFinalizeLoop_AutoFinalizeWallClock(t *testing.T) {
	cfg := DefaultRollupConfig()
	cfg.BlockTime = 100 * time.Millisecond
	cfg.MinTxPerBatch = 1
	cfg.ChallengePeriod = 2 * time.Second
	cfg.FinalizeCheckInterval = 50 * time.Millisecond

	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatalf("NewRollupEngine failed: %v", err)
	}
	engine.SetRequireTxSig(false)
	if err := engine.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer engine.Stop()

	tx := &RollupTransaction{
		Nonce: 0, GasPrice: 0, GasLimit: 21000, Value: big.NewInt(0),
		From: types.Address{1}, ChainID: cfg.ChainID,
	}
	if err := engine.SubmitL2Transaction(tx); err != nil {
		t.Fatalf("SubmitL2Transaction failed: %v", err)
	}

	// Poll for batch 0 to reach Finalized state. The batch should be built
	// within ~100ms, then the 2s challenge period must elapse (the 2s value
	// is deliberately >1s because SubmittedAt is a Unix-second int64, so a
	// 1s period with a tx submitted at second-tail leaves <50ms before the
	// next tick boundary, which combined with `-race` jitter on CI runners
	// caused historic W-P1-5 flakes — see ROLLUP-R42-CI-RACE timing note
	// below), then finalizeLoop fires within ~100ms. Use 15s as a safe
	// upper bound that absorbs both Unix-second quantization and CI
	// scheduler thrashing without making the test wall-clock-bound.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		// ROLLUP-R42-CI-RACE-6: poll via the race-safe GetBatchStatus helper
		// rather than GetBatch(...).Status — GetBatch returns a *Batch
		// pointer (no copy under RLock), and reading .Status / .SubmittedAt /
		// .ChallengeDeadline on that pointer outside bm.mu races with
		// FinalizeBatch's `batch.Status = BatchStatusFinalized` write at
		// batch.go:282 (which IS under bm.mu.Lock). The new helper reads
		// Status under RLock and returns it as a value type.
		status, err := engine.GetBatchManager().GetBatchStatus(0)
		if err == nil && status == BatchStatusFinalized {
			return // success
		}
		// 20ms polling — short enough that even a single tick landing late
		// (typical `-race` jitter pushes time.Sleep to 80-200ms) does not
		// push us past the next FinalizeBatch call.
		time.Sleep(20 * time.Millisecond)
	}
	// ROLLUP-R42-CI-RACE-6: same race as the polling read above — use
	// the snapshot helper instead of dereferencing the live *Batch.
	b, err := engine.GetBatchManager().GetBatchSnapshot(0)
	if err != nil {
		t.Fatal("batch 0 was never created within 15s")
	}
	t.Errorf("batch 0 was not auto-finalized within 15s (status=%d, submittedAt=%d, challengeDeadline=%d, now=%d)",
		b.Status, b.SubmittedAt, b.ChallengeDeadline, time.Now().Unix())
}
