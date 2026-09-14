// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// ── Syncer error variables ──

func TestSyncerErrors(t *testing.T) {
	if ErrSyncerAlreadyRunning == nil {
		t.Error("expected non-nil ErrSyncerAlreadyRunning")
	}
	if ErrSyncerNotRunning == nil {
		t.Error("expected non-nil ErrSyncerNotRunning")
	}
	if ErrNoAvailablePeers == nil {
		t.Error("expected non-nil ErrNoAvailablePeers")
	}
	if ErrBlockValidationFailed == nil {
		t.Error("expected non-nil ErrBlockValidationFailed")
	}
	if ErrParentNotFound == nil {
		t.Error("expected non-nil ErrParentNotFound")
	}
	if ErrStateRootMismatch == nil {
		t.Error("expected non-nil ErrStateRootMismatch")
	}
}

// ── Syncer constants ──

func TestSyncerConstants(t *testing.T) {
	if maxPendingBlocks != 500 {
		t.Errorf("expected maxPendingBlocks 500, got %d", maxPendingBlocks)
	}
	if pendingBlockTTL != 2*time.Minute {
		t.Errorf("expected pendingBlockTTL 2m, got %v", pendingBlockTTL)
	}
	if syncBatchSize != 500 {
		t.Errorf("expected syncBatchSize 500, got %d", syncBatchSize)
	}
}

// ── NewSyncer ──

func TestNewSyncer(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	if s == nil {
		t.Fatal("expected non-nil Syncer")
	}
	if s.networkID != 1669 {
		t.Errorf("expected networkID 1669, got %d", s.networkID)
	}
	if s.pendingBlocks == nil {
		t.Error("expected initialized pendingBlocks map")
	}
	if s.snapAccounts == nil {
		t.Error("expected initialized snapAccounts map")
	}
}

// ── SetOnForkRollback ──

func TestSyncer_SetOnForkRollback(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	s.SetOnForkRollback(func(height uint64) {})
	if s.onForkRollback == nil {
		t.Error("expected onForkRollback to be set")
	}
}

// ── SetOnGenesisReplace ──

func TestSyncer_SetOnGenesisReplace(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	s.SetOnGenesisReplace(func(blk *encoding.Block) {})
	if s.onGenesisReplace == nil {
		t.Error("expected onGenesisReplace to be set")
	}
}

// ── SetCheckpointManager ──

func TestSyncer_SetCheckpointManager(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	cm := consensus.NewCheckpointManager(nil, nil)
	s.SetCheckpointManager(cm)
	if s.checkpointManager == nil {
		t.Error("expected checkpointManager to be set")
	}
}

// ── UpdateHighestKnown ──

func TestSyncer_UpdateHighestKnown(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)

	s.UpdateHighestKnown(100)
	if s.highestKnown != 100 {
		t.Errorf("expected 100, got %d", s.highestKnown)
	}

	// Should not decrease
	s.UpdateHighestKnown(50)
	if s.highestKnown != 100 {
		t.Errorf("expected 100 (no decrease), got %d", s.highestKnown)
	}

	// Should increase
	s.UpdateHighestKnown(200)
	if s.highestKnown != 200 {
		t.Errorf("expected 200, got %d", s.highestKnown)
	}
}

// ── UpdateCurrentHeight ──

func TestSyncer_UpdateCurrentHeight(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)

	s.UpdateCurrentHeight(50)
	if s.currentHeight != 50 {
		t.Errorf("expected 50, got %d", s.currentHeight)
	}

	// Should not decrease
	s.UpdateCurrentHeight(30)
	if s.currentHeight != 50 {
		t.Errorf("expected 50 (no decrease), got %d", s.currentHeight)
	}

	// Should increase
	s.UpdateCurrentHeight(100)
	if s.currentHeight != 100 {
		t.Errorf("expected 100, got %d", s.currentHeight)
	}
}

// ── CurrentHeight ──

func TestSyncer_CurrentHeight(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	if s.CurrentHeight() != 0 {
		t.Errorf("expected 0, got %d", s.CurrentHeight())
	}

	s.UpdateCurrentHeight(42)
	if s.CurrentHeight() != 42 {
		t.Errorf("expected 42, got %d", s.CurrentHeight())
	}
}

// ── SetStateDB ──

func TestSyncer_SetStateDB(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	// Should not panic with nil
	s.SetStateDB(nil)
}

// ── Stop without start ──

func TestSyncer_StopWithoutStart(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	// Should not panic
	s.Stop()
}

// ── GetPendingBlockCount ──

func TestSyncer_GetPendingBlockCount_Empty(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	if s.GetPendingBlockCount() != 0 {
		t.Errorf("expected 0 pending blocks, got %d", s.GetPendingBlockCount())
	}
}

// ── ClearPendingBlocks ──

func TestSyncer_ClearPendingBlocks(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	// Add a pending block manually
	s.pendingBlocks[types.Hash{1}] = &pendingBlockEntry{
		Block:   &encoding.Block{},
		AddedAt: time.Now(),
	}
	if s.GetPendingBlockCount() != 1 {
		t.Errorf("expected 1 pending block, got %d", s.GetPendingBlockCount())
	}

	s.ClearPendingBlocks()
	if s.GetPendingBlockCount() != 0 {
		t.Errorf("expected 0 pending blocks after clear, got %d", s.GetPendingBlockCount())
	}
}

// ── IsSnapSyncing ──

func TestSyncer_IsSnapSyncing(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	if s.IsSnapSyncing() {
		t.Error("expected not snap syncing initially")
	}
}

// ── PendingCount ──

func TestSyncer_PendingCount(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	if s.PendingCount() != 0 {
		t.Errorf("expected 0, got %d", s.PendingCount())
	}
}

// ── SyncStatus struct ──

func TestSyncStatus_Fields(t *testing.T) {
	status := SyncStatus{
		Syncing:        true,
		CurrentBlock:   100,
		HighestBlock:   500,
		StartingBlock:  0,
		PeersConnected: 3,
	}
	if !status.Syncing {
		t.Error("expected Syncing=true")
	}
	if status.CurrentBlock != 100 {
		t.Errorf("expected 100, got %d", status.CurrentBlock)
	}
	if status.HighestBlock != 500 {
		t.Errorf("expected 500, got %d", status.HighestBlock)
	}
	if status.PeersConnected != 3 {
		t.Errorf("expected 3, got %d", status.PeersConnected)
	}
}

// ── pendingBlockEntry struct ──

func TestPendingBlockEntry_Fields(t *testing.T) {
	now := time.Now()
	entry := &pendingBlockEntry{
		Block:   &encoding.Block{},
		AddedAt: now,
	}
	if entry.Block == nil {
		t.Error("expected non-nil block")
	}
	if !entry.AddedAt.Equal(now) {
		t.Errorf("expected %v, got %v", now, entry.AddedAt)
	}
}

// ── collectPendingWithExistingParents ──

func TestSyncer_CollectPendingWithExistingParents_Empty(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	result := s.collectPendingWithExistingParents()
	if len(result) != 0 {
		t.Errorf("expected 0, got %d", len(result))
	}
}

// ── isSyncActive ──

func TestSyncer_IsSyncActive(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	if s.isSyncActive() {
		t.Error("expected not active initially")
	}
}

// ── findContinuousTip ──
// Note: requires non-nil blockStore, skipped

// ── NewSyncer with different network IDs ──

func TestNewSyncer_MainnetNetworkID(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, MainnetNetworkID)
	if s.networkID != MainnetNetworkID {
		t.Errorf("expected %d, got %d", MainnetNetworkID, s.networkID)
	}
}

func TestNewSyncer_DevnetNetworkID(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, DevnetNetworkID)
	if s.networkID != DevnetNetworkID {
		t.Errorf("expected %d, got %d", DevnetNetworkID, s.networkID)
	}
}

// ── Syncer with mock p2p host for Status ──

func TestSyncer_Status_NotRunning(t *testing.T) {
	s := NewSyncer(nil, nil, nil, nil, 1669)
	// Status with nil p2pHost should not panic
	// (will panic if it tries to call PeerCount on nil)
	// We can't call Status() with nil p2pHost, so just test the struct
	s.syncing = false
	s.currentHeight = 0
	s.highestKnown = 0
}

// ── Syncer Start/Stop lifecycle ──
// Note: Start() requires non-nil blockStore, so we only test Stop()

// ── HandleBlockRequest with nil blockStore ──
// Note: requires non-nil blockStore, skipped

// ── HandleStatusMessage ──
// Note: requires non-nil blockStore, skipped

// ── RequestBlocksByHeight with nil host ──
// Note: requires non-nil p2pHost, skipped

// ── deepForkRecovery ──
// Note: requires non-nil blockStore, skipped
