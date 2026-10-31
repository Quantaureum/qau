// Quantaureum Node source, version 1.0.0.
package node

import (
	"errors"
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
)

// ── mock BlockStoreReader ──

type mockBlockStore struct {
	latestHeight uint64
	oldestHeight uint64
	blocks       map[uint64]*encoding.Block
	deletedFrom  uint64
	deletedTo    uint64
	deleteErr    error
	bytesFreed   uint64
}

func newMockBlockStore() *mockBlockStore {
	return &mockBlockStore{
		blocks: make(map[uint64]*encoding.Block),
	}
}

func (m *mockBlockStore) GetBlockByHeight(height uint64) (*encoding.Block, error) {
	if blk, ok := m.blocks[height]; ok {
		return blk, nil
	}
	return nil, errors.New("block not found")
}

func (m *mockBlockStore) DeleteBlockRange(from, to uint64) (uint64, error) {
	if m.deleteErr != nil {
		return 0, m.deleteErr
	}
	m.deletedFrom = from
	m.deletedTo = to
	return m.bytesFreed, nil
}

func (m *mockBlockStore) GetLatestHeight() uint64 {
	return m.latestHeight
}

func (m *mockBlockStore) GetOldestHeight() uint64 {
	return m.oldestHeight
}

// ── DefaultHistoryExpirationConfig ──

func TestDefaultHistoryExpirationConfig(t *testing.T) {
	cfg := DefaultHistoryExpirationConfig()
	// R30 F4: block-history pruning is unsupported, so the default must not ask
	// for it (Start() would refuse).
	if cfg.Enabled {
		t.Error("expected disabled by default")
	}
	if cfg.RetentionBlocks != DefaultHistoryRetentionBlocks {
		t.Errorf("expected %d retention blocks, got %d", DefaultHistoryRetentionBlocks, cfg.RetentionBlocks)
	}
	if cfg.PruneBatchSize != 1000 {
		t.Errorf("expected prune batch size 1000, got %d", cfg.PruneBatchSize)
	}
	if cfg.PruneInterval != 1024 {
		t.Errorf("expected prune interval 1024, got %d", cfg.PruneInterval)
	}
}

// ── NewHistoryExpirer ──

func TestNewHistoryExpirer(t *testing.T) {
	cfg := DefaultHistoryExpirationConfig()
	bs := newMockBlockStore()
	he := NewHistoryExpirer(cfg, bs)
	if he == nil {
		t.Fatal("expected non-nil HistoryExpirer")
	}
}

// ── Start ──

func TestHistoryExpirer_Start_Disabled(t *testing.T) {
	cfg := HistoryExpirationConfig{Enabled: false}
	bs := newMockBlockStore()
	he := NewHistoryExpirer(cfg, bs)

	err := he.Start()
	if err != ErrHistoryExpirationDisabled {
		t.Errorf("expected ErrHistoryExpirationDisabled, got %v", err)
	}
}

func TestHistoryExpirer_Start_Enabled(t *testing.T) {
	cfg := DefaultHistoryExpirationConfig()
	cfg.Enabled = true
	bs := newMockBlockStore()
	he := NewHistoryExpirer(cfg, bs)

	// R30 F4: enabling block-history pruning must be refused, and nothing may be
	// deleted on the way out.
	err := he.Start()
	if !errors.Is(err, ErrHistoryExpiryUnsupported) {
		t.Fatalf("expected ErrHistoryExpiryUnsupported, got %v", err)
	}
	if bs.deletedFrom != 0 || bs.deletedTo != 0 {
		t.Errorf("Start must not delete anything, got delete range [%d, %d]", bs.deletedFrom, bs.deletedTo)
	}
	he.Stop()
}

func TestHistoryExpirer_Start_RepeatedRefusal(t *testing.T) {
	cfg := DefaultHistoryExpirationConfig()
	cfg.Enabled = true
	bs := newMockBlockStore()
	he := NewHistoryExpirer(cfg, bs)

	for i := 0; i < 2; i++ {
		if err := he.Start(); !errors.Is(err, ErrHistoryExpiryUnsupported) {
			t.Fatalf("Start #%d: expected ErrHistoryExpiryUnsupported, got %v", i+1, err)
		}
	}

	he.Stop()
}

// ── Stop ──

func TestHistoryExpirer_Stop_NotRunning(t *testing.T) {
	cfg := DefaultHistoryExpirationConfig()
	cfg.Enabled = true
	bs := newMockBlockStore()
	he := NewHistoryExpirer(cfg, bs)

	// Should not panic
	he.Stop()
}

// ── GetStats ──

func TestHistoryExpirer_GetStats_Initial(t *testing.T) {
	cfg := DefaultHistoryExpirationConfig()
	cfg.Enabled = true
	bs := newMockBlockStore()
	he := NewHistoryExpirer(cfg, bs)

	stats := he.GetStats()
	if !stats.Enabled {
		t.Error("expected enabled in stats")
	}
	if stats.RetentionBlocks != cfg.RetentionBlocks {
		t.Errorf("expected %d retention blocks, got %d", cfg.RetentionBlocks, stats.RetentionBlocks)
	}
	if stats.TotalBlocksPruned != 0 {
		t.Errorf("expected 0 pruned blocks, got %d", stats.TotalBlocksPruned)
	}
}

// ── UpdateConfig ──

func TestHistoryExpirer_UpdateConfig_TooSmall(t *testing.T) {
	cfg := DefaultHistoryExpirationConfig()
	bs := newMockBlockStore()
	he := NewHistoryExpirer(cfg, bs)

	err := he.UpdateConfig(HistoryExpirationConfig{
		Enabled:         true,
		RetentionBlocks: MinHistoryRetentionBlocks - 1,
	})
	if err != ErrInvalidRetentionPeriod {
		t.Errorf("expected ErrInvalidRetentionPeriod, got %v", err)
	}
}

func TestHistoryExpirer_UpdateConfig_TooLarge(t *testing.T) {
	cfg := DefaultHistoryExpirationConfig()
	bs := newMockBlockStore()
	he := NewHistoryExpirer(cfg, bs)

	err := he.UpdateConfig(HistoryExpirationConfig{
		Enabled:         true,
		RetentionBlocks: MaxHistoryRetentionBlocks + 1,
	})
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	stats := he.GetStats()
	if stats.RetentionBlocks != MaxHistoryRetentionBlocks {
		t.Errorf("expected capped to %d, got %d", MaxHistoryRetentionBlocks, stats.RetentionBlocks)
	}
}

func TestHistoryExpirer_UpdateConfig_Valid(t *testing.T) {
	cfg := DefaultHistoryExpirationConfig()
	bs := newMockBlockStore()
	he := NewHistoryExpirer(cfg, bs)

	newRetention := uint64(100000)
	err := he.UpdateConfig(HistoryExpirationConfig{
		Enabled:         true,
		RetentionBlocks: newRetention,
	})
	if err != nil {
		t.Fatalf("UpdateConfig failed: %v", err)
	}

	stats := he.GetStats()
	if stats.RetentionBlocks != newRetention {
		t.Errorf("expected %d, got %d", newRetention, stats.RetentionBlocks)
	}
}

// ── ForcePrune ──

func TestHistoryExpirer_ForcePrune_Disabled(t *testing.T) {
	cfg := HistoryExpirationConfig{Enabled: false}
	bs := newMockBlockStore()
	he := NewHistoryExpirer(cfg, bs)

	_, err := he.ForcePrune()
	if err != ErrHistoryExpirationDisabled {
		t.Errorf("expected ErrHistoryExpirationDisabled, got %v", err)
	}
}

func TestHistoryExpirer_ForcePrune_Refused(t *testing.T) {
	cfg := DefaultHistoryExpirationConfig()
	cfg.Enabled = true
	bs := newMockBlockStore()
	bs.latestHeight = 500
	bs.bytesFreed = 10000
	he := NewHistoryExpirer(cfg, bs)

	freed, err := he.ForcePrune()
	if !errors.Is(err, ErrHistoryExpiryUnsupported) {
		t.Fatalf("expected ErrHistoryExpiryUnsupported, got %v", err)
	}
	if freed != 0 {
		t.Errorf("expected 0 bytes freed, got %d", freed)
	}
	if bs.deletedFrom != 0 || bs.deletedTo != 0 {
		t.Errorf("ForcePrune must not delete anything, got [%d, %d]", bs.deletedFrom, bs.deletedTo)
	}
}

// ── pruneOnce (the dormant algorithm, kept under test) ──

func TestHistoryExpirer_PruneOnce_NotEnoughHistory(t *testing.T) {
	cfg := DefaultHistoryExpirationConfig()
	cfg.Enabled = true
	bs := newMockBlockStore()
	bs.latestHeight = 100
	bs.oldestHeight = 0
	he := NewHistoryExpirer(cfg, bs)

	freed, err := he.pruneOnce()
	if err != nil {
		t.Fatalf("pruneOnce failed: %v", err)
	}
	// Current height (100) < retention blocks, nothing to prune
	if freed != 0 {
		t.Errorf("expected 0 bytes freed, got %d", freed)
	}
}

func TestHistoryExpirer_PruneOnce_WithHistory(t *testing.T) {
	cfg := HistoryExpirationConfig{
		Enabled:         true,
		RetentionBlocks: 100,
		PruneBatchSize:  50,
		PruneInterval:   10,
	}
	bs := newMockBlockStore()
	bs.latestHeight = 500
	bs.oldestHeight = 0
	bs.bytesFreed = 10000
	he := NewHistoryExpirer(cfg, bs)

	freed, err := he.pruneOnce()
	if err != nil {
		t.Fatalf("pruneOnce failed: %v", err)
	}
	if freed != 10000 {
		t.Errorf("expected 10000 bytes freed, got %d", freed)
	}
	// An adapter reporting 0 must never cost us the genesis block: the delete
	// range starts at 1 and ends at latest-retention (400).
	if bs.deletedFrom != 1 || bs.deletedTo != 400 {
		t.Errorf("expected delete range [1, 400], got [%d, %d]", bs.deletedFrom, bs.deletedTo)
	}
}

func TestHistoryExpirer_PruneOnce_DeleteError(t *testing.T) {
	cfg := HistoryExpirationConfig{
		Enabled:         true,
		RetentionBlocks: 100,
	}
	bs := newMockBlockStore()
	bs.latestHeight = 500
	bs.oldestHeight = 0
	bs.deleteErr = errors.New("delete failed")
	he := NewHistoryExpirer(cfg, bs)

	_, err := he.pruneOnce()
	if err == nil {
		t.Error("expected error from pruneOnce when delete fails")
	}
}

func TestHistoryExpirer_PruneOnce_OldestAbovePruneBefore(t *testing.T) {
	cfg := HistoryExpirationConfig{
		Enabled:         true,
		RetentionBlocks: 100,
	}
	bs := newMockBlockStore()
	bs.latestHeight = 500
	bs.oldestHeight = 450 // oldest is above pruneBefore (400)
	he := NewHistoryExpirer(cfg, bs)

	freed, err := he.pruneOnce()
	if err != nil {
		t.Fatalf("pruneOnce failed: %v", err)
	}
	if freed != 0 {
		t.Errorf("expected 0 bytes freed when oldest > pruneBefore, got %d", freed)
	}
}

// ── Error variables ──

func TestHistoryExpirationErrors(t *testing.T) {
	if ErrHistoryExpirationDisabled == nil {
		t.Error("expected non-nil ErrHistoryExpirationDisabled")
	}
	if ErrInvalidRetentionPeriod == nil {
		t.Error("expected non-nil ErrInvalidRetentionPeriod")
	}
	if ErrHistoryExpiryUnsupported == nil {
		t.Error("expected non-nil ErrHistoryExpiryUnsupported")
	}
}

// ── Constants ──

func TestHistoryExpirationConstants(t *testing.T) {
	if DefaultHistoryRetentionBlocks != 31536000 {
		t.Errorf("expected 31536000, got %d", DefaultHistoryRetentionBlocks)
	}
	if MinHistoryRetentionBlocks != 50000 {
		t.Errorf("expected 50000, got %d", MinHistoryRetentionBlocks)
	}
	if MaxHistoryRetentionBlocks != 100000000 {
		t.Errorf("expected 100000000, got %d", MaxHistoryRetentionBlocks)
	}
	if DefaultHistoryRetentionTime != 365*24*time.Hour {
		t.Errorf("expected 365 days, got %v", DefaultHistoryRetentionTime)
	}
}
