// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/types"
)

// mockValidatorSetProvider is a test double for ValidatorSetProvider.
// W-P1-7 (2026-07-15). RLLP-R5-04 (2026-07-16) adds the seed field.
type mockValidatorSetProvider struct {
	validators []types.Address
	epoch      uint64
	seed       types.Hash // RLLP-R5-04: VRF seed returned by GetEpochSeed
}

func (m *mockValidatorSetProvider) GetValidators() []types.Address {
	return m.validators
}

func (m *mockValidatorSetProvider) GetCurrentEpoch() uint64 {
	return m.epoch
}

// GetEpochSeed returns the configured VRF seed. RLLP-R5-04 (2026-07-16).
func (m *mockValidatorSetProvider) GetEpochSeed(epoch uint64) types.Hash {
	return m.seed
}

// makeTestValidatorAddrs creates n distinct validator addresses for testing.
func makeTestValidatorAddrs(n int) []types.Address {
	addrs := make([]types.Address, n)
	for i := 0; i < n; i++ {
		addrs[i] = types.Address{byte(i + 1)}
	}
	return addrs
}

// --- SequencerElector interface tests ---

func TestSequencerElector_NormalRotation(t *testing.T) {
	// 3 validators: A={1}, B={2}, C={3}
	// RLLP-R5-04 (2026-07-16): Seed defaults to zero hash (bootstrap mode),
	// so the index is keccak256(epoch) % 3 — deterministic but hash-mixed,
	// NOT the old epoch % 3. Tests compute expected indices dynamically.
	addrs := makeTestValidatorAddrs(3)
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0}
	elector := NewQPOSSequencerElector(provider)

	for _, epoch := range []uint64{0, 1, 2, 3, 4, 5} {
		seq, err := elector.GetCurrentSequencer(epoch)
		if err != nil {
			t.Fatalf("epoch %d: unexpected error: %v", epoch, err)
		}
		expectedIdx := computeSequencerIndex(epoch, provider.seed, len(addrs))
		if seq != addrs[expectedIdx] {
			t.Errorf("epoch %d: expected %x (idx %d), got %x", epoch, addrs[expectedIdx][:4], expectedIdx, seq[:4])
		}
	}
}

func TestSequencerElector_IsCurrentSequencer(t *testing.T) {
	addrs := makeTestValidatorAddrs(3)
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0}
	elector := NewQPOSSequencerElector(provider)

	// RLLP-R5-04: dynamically compute the current sequencer for each epoch.
	currentIdx0 := computeSequencerIndex(0, provider.seed, len(addrs))
	currentIdx1 := computeSequencerIndex(1, provider.seed, len(addrs))

	t.Run("current sequencer returns true", func(t *testing.T) {
		is, err := elector.IsCurrentSequencer(addrs[currentIdx0], 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !is {
			t.Error("expected true for current sequencer")
		}
	})

	t.Run("non-current sequencer returns false", func(t *testing.T) {
		// Pick a validator that is NOT the current sequencer.
		nonCurrentIdx := (currentIdx0 + 1) % len(addrs)
		is, err := elector.IsCurrentSequencer(addrs[nonCurrentIdx], 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if is {
			t.Error("expected false for non-current sequencer")
		}
	})

	t.Run("different epoch changes current sequencer", func(t *testing.T) {
		// Epoch 1 → sequencer is addrs[currentIdx1]
		is, err := elector.IsCurrentSequencer(addrs[currentIdx1], 1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !is {
			t.Error("expected true for current sequencer at epoch 1")
		}
	})
}

func TestSequencerElector_GetNextSequencer(t *testing.T) {
	addrs := makeTestValidatorAddrs(3)
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0}
	elector := NewQPOSSequencerElector(provider)

	// RLLP-R5-04: next sequencer uses computeSequencerIndex(epoch+1, seed, n).
	t.Run("next sequencer for epoch 0 matches epoch 1 index", func(t *testing.T) {
		next, err := elector.GetNextSequencer(0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expectedIdx := computeSequencerIndex(1, provider.seed, len(addrs))
		if next != addrs[expectedIdx] {
			t.Errorf("expected %x (idx %d), got %x", addrs[expectedIdx][:4], expectedIdx, next[:4])
		}
	})

	t.Run("next sequencer for epoch 2 matches epoch 3 index", func(t *testing.T) {
		next, err := elector.GetNextSequencer(2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expectedIdx := computeSequencerIndex(3, provider.seed, len(addrs))
		if next != addrs[expectedIdx] {
			t.Errorf("expected %x (idx %d), got %x", addrs[expectedIdx][:4], expectedIdx, next[:4])
		}
	})
}

func TestSequencerElector_EmptyValidatorSet(t *testing.T) {
	provider := &mockValidatorSetProvider{validators: nil, epoch: 0}
	elector := NewQPOSSequencerElector(provider)

	_, err := elector.GetCurrentSequencer(0)
	if err != ErrNoValidators {
		t.Errorf("expected ErrNoValidators, got %v", err)
	}

	_, err = elector.GetNextSequencer(0)
	if err != ErrNoValidators {
		t.Errorf("expected ErrNoValidators, got %v", err)
	}

	is, err := elector.IsCurrentSequencer(types.Address{1}, 0)
	if err != ErrNoValidators {
		t.Errorf("expected ErrNoValidators, got %v", err)
	}
	if is {
		t.Error("expected false for empty validator set")
	}
}

func TestSequencerElector_MultiEpochContinuousRun(t *testing.T) {
	addrs := makeTestValidatorAddrs(5)
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0}
	elector := NewQPOSSequencerElector(provider)

	// RLLP-R5-04: Run through 15 epochs and verify deterministic mapping
	// (same epoch+seed → same sequencer). The index is keccak256(epoch) % 5
	// in bootstrap mode (zero seed).
	for epoch := uint64(0); epoch < 15; epoch++ {
		expectedIdx := computeSequencerIndex(epoch, provider.seed, len(addrs))
		seq, err := elector.GetCurrentSequencer(epoch)
		if err != nil {
			t.Fatalf("epoch %d: unexpected error: %v", epoch, err)
		}
		if seq != addrs[expectedIdx] {
			t.Errorf("epoch %d: expected %x, got %x", epoch, addrs[expectedIdx][:4], seq[:4])
		}

		// Next sequencer should be the one for epoch+1.
		next, err := elector.GetNextSequencer(epoch)
		if err != nil {
			t.Fatalf("epoch %d: unexpected error: %v", epoch, err)
		}
		expectedNextIdx := computeSequencerIndex(epoch+1, provider.seed, len(addrs))
		expectedNext := addrs[expectedNextIdx]
		if next != expectedNext {
			t.Errorf("epoch %d: expected next %x, got %x", epoch, expectedNext[:4], next[:4])
		}
	}
}

// --- RollupEngine integration tests ---

func TestRollupEngine_SequencerElector_NotConfigured(t *testing.T) {
	// When no elector is configured, shouldBuildBatch returns true (legacy mode).
	cfg := DefaultRollupConfig()
	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if !engine.shouldBuildBatch() {
		t.Error("expected shouldBuildBatch=true when no elector configured (legacy mode)")
	}
	if !engine.IsCurrentSequencer() {
		t.Error("expected IsCurrentSequencer=true when no elector configured (legacy mode)")
	}
}

func TestRollupEngine_SequencerElector_LocalSequencerBuilds(t *testing.T) {
	addrs := makeTestValidatorAddrs(3)
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0}
	elector := NewQPOSSequencerElector(provider)

	cfg := DefaultRollupConfig()
	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetSequencerElector(elector)
	// RLLP-R5-04: dynamically find the current sequencer at epoch 0.
	currentIdx := computeSequencerIndex(0, provider.seed, len(addrs))
	engine.SetLocalAddress(addrs[currentIdx])

	if !engine.shouldBuildBatch() {
		t.Error("expected shouldBuildBatch=true when local node is current sequencer")
	}
	if !engine.IsCurrentSequencer() {
		t.Error("expected IsCurrentSequencer=true when local node is current sequencer")
	}
}

func TestRollupEngine_SequencerElector_NonSequencerSkips(t *testing.T) {
	addrs := makeTestValidatorAddrs(3)
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0}
	elector := NewQPOSSequencerElector(provider)

	cfg := DefaultRollupConfig()
	cfg.SequencerTimeout = 3
	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetSequencerElector(elector)
	// RLLP-R5-04: dynamically find a non-current sequencer at epoch 0.
	currentIdx := computeSequencerIndex(0, provider.seed, len(addrs))
	nonCurrentIdx := (currentIdx + 1) % len(addrs)
	engine.SetLocalAddress(addrs[nonCurrentIdx])

	if engine.shouldBuildBatch() {
		t.Error("expected shouldBuildBatch=false when local node is not current sequencer")
	}
	if engine.IsCurrentSequencer() {
		t.Error("expected IsCurrentSequencer=false when local node is not current sequencer")
	}
}

func TestRollupEngine_SequencerElector_FailoverTakeover(t *testing.T) {
	addrs := makeTestValidatorAddrs(3)
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0}
	elector := NewQPOSSequencerElector(provider)

	cfg := DefaultRollupConfig()
	cfg.SequencerTimeout = 3
	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetSequencerElector(elector)
	// RLLP-R5-04: dynamically find the NEXT sequencer at epoch 0.
	nextIdx := computeSequencerIndex(1, provider.seed, len(addrs))
	engine.SetLocalAddress(addrs[nextIdx])

	// Simulate missed batch cycles by incrementing missedBatchCount.
	// Before timeout: should not build.
	engine.mu.Lock()
	engine.missedBatchCount = 0
	engine.mu.Unlock()
	if engine.shouldBuildBatch() {
		t.Error("expected shouldBuildBatch=false before SequencerTimeout")
	}

	// After 2 missed cycles (still < 3): should not build.
	engine.mu.Lock()
	engine.missedBatchCount = 2
	engine.mu.Unlock()
	if engine.shouldBuildBatch() {
		t.Error("expected shouldBuildBatch=false when missed < SequencerTimeout")
	}

	// After 3 missed cycles (>= SequencerTimeout): failover triggers.
	engine.mu.Lock()
	engine.missedBatchCount = 3
	engine.mu.Unlock()
	if !engine.shouldBuildBatch() {
		t.Error("expected shouldBuildBatch=true after SequencerTimeout (failover takeover)")
	}

	// After 5 missed cycles: still in failover.
	engine.mu.Lock()
	engine.missedBatchCount = 5
	engine.mu.Unlock()
	if !engine.shouldBuildBatch() {
		t.Error("expected shouldBuildBatch=true during extended failover")
	}
}

func TestRollupEngine_SequencerElector_FailoverNotNextSequencer(t *testing.T) {
	addrs := makeTestValidatorAddrs(3)
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0}
	elector := NewQPOSSequencerElector(provider)

	cfg := DefaultRollupConfig()
	cfg.SequencerTimeout = 3
	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetSequencerElector(elector)
	// RLLP-R5-04: dynamically find a validator that is NEITHER current NOR next.
	currentIdx := computeSequencerIndex(0, provider.seed, len(addrs))
	nextIdx := computeSequencerIndex(1, provider.seed, len(addrs))
	var neitherIdx int
	for i := 0; i < len(addrs); i++ {
		if i != currentIdx && i != nextIdx {
			neitherIdx = i
			break
		}
	}
	engine.SetLocalAddress(addrs[neitherIdx])

	// Even after timeout, should not build because local is not the next sequencer.
	engine.mu.Lock()
	engine.missedBatchCount = 10
	engine.mu.Unlock()
	if engine.shouldBuildBatch() {
		t.Error("expected shouldBuildBatch=false when local is not next sequencer")
	}
}

func TestRollupEngine_SequencerElector_EpochChangeResetsMissCount(t *testing.T) {
	addrs := makeTestValidatorAddrs(3)
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0}
	elector := NewQPOSSequencerElector(provider)

	cfg := DefaultRollupConfig()
	cfg.SequencerTimeout = 3
	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetSequencerElector(elector)
	// RLLP-R5-04: dynamically find who will be the sequencer at epoch 1.
	epoch1Idx := computeSequencerIndex(1, provider.seed, len(addrs))
	engine.SetLocalAddress(addrs[epoch1Idx])

	// Accumulate misses at epoch 0.
	epoch0Idx := computeSequencerIndex(0, provider.seed, len(addrs))
	engine.mu.Lock()
	engine.missedBatchCount = 2
	engine.lastSequencerAddr = addrs[epoch0Idx] // current sequencer at epoch 0
	engine.mu.Unlock()

	// Advance to epoch 1 — now addrs[epoch1Idx] IS the current sequencer.
	provider.epoch = 1

	// shouldBuildBatch should detect the sequencer change and reset miss count.
	if !engine.shouldBuildBatch() {
		t.Error("expected shouldBuildBatch=true when local becomes current sequencer at new epoch")
	}

	engine.mu.RLock()
	missed := engine.missedBatchCount
	engine.mu.RUnlock()
	if missed != 0 {
		t.Errorf("expected missedBatchCount reset to 0 on sequencer change, got %d", missed)
	}
}

func TestRollupEngine_SequencerElector_FailoverDisabled(t *testing.T) {
	addrs := makeTestValidatorAddrs(3)
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0}
	elector := NewQPOSSequencerElector(provider)

	cfg := DefaultRollupConfig()
	cfg.SequencerTimeout = 0 // disable failover
	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetSequencerElector(elector)
	// RLLP-R5-04: dynamically find the NEXT sequencer (which would take over
	// if failover were enabled).
	nextIdx := computeSequencerIndex(1, provider.seed, len(addrs))
	engine.SetLocalAddress(addrs[nextIdx])

	// Even with many misses, failover should not trigger when timeout=0.
	engine.mu.Lock()
	engine.missedBatchCount = 100
	engine.mu.Unlock()
	if engine.shouldBuildBatch() {
		t.Error("expected shouldBuildBatch=false when failover is disabled (timeout=0)")
	}
}

// TestRollupEngine_SequencerElector_FullBatchProduction verifies that the
// engine actually produces batches when the local node is the sequencer, and
// skips when it is not. This is an integration test for tryBuildAndSubmitBatch.
func TestRollupEngine_SequencerElector_FullBatchProduction(t *testing.T) {
	addrs := makeTestValidatorAddrs(2)
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0}
	elector := NewQPOSSequencerElector(provider)

	cfg := DefaultRollupConfig()
	cfg.SequencerTimeout = 2
	cfg.MinTxPerBatch = 1
	engine, err := NewRollupEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	engine.SetSequencerElector(elector)
	// RLLP-R5-04: dynamically find the current sequencer at epoch 0.
	currentIdx := computeSequencerIndex(0, provider.seed, len(addrs))
	engine.SetLocalAddress(addrs[currentIdx])
	engine.SetRequireTxSig(false) // bypass sig verification for test

	// Fund the sender account so ProcessBatch does not reject the tx.
	sender := types.Address{0xaa}
	sm := engine.GetStateManager()
	sm.mu.Lock()
	sm.accountStates[sender] = &RollupAccount{Balance: big.NewInt(1_000_000)}
	// Sync BatchManager.lastStateRoot with the current state root so
	// ProcessBatch's prevStateRoot check passes.
	currentRoot := sm.computeStateRoot()
	engine.GetBatchManager().lastStateRoot = currentRoot
	sm.mu.Unlock()

	// Set status to Running without calling Start() to avoid the batchLoop
	// goroutine competing with our manual tryBuildAndSubmitBatch call.
	engine.mu.Lock()
	engine.status = RollupStatusRunning
	engine.mu.Unlock()

	// Add a transaction and verify the engine builds a batch.
	tx := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     sender,
		ChainID:  cfg.ChainID,
	}
	if err := engine.SubmitL2Transaction(tx); err != nil {
		t.Fatalf("SubmitL2Transaction failed: %v", err)
	}

	// Manually trigger a batch build.
	engine.tryBuildAndSubmitBatch()

	// Verify a batch was produced.
	totalBatches, _, _ := engine.GetStats()
	if totalBatches != 1 {
		t.Errorf("expected 1 batch, got %d", totalBatches)
	}

	// Now test a non-sequencer node — verify no batches are produced.
	provider2 := &mockValidatorSetProvider{validators: addrs, epoch: 0}
	elector2 := NewQPOSSequencerElector(provider2)
	cfg2 := DefaultRollupConfig()
	cfg2.SequencerTimeout = 2
	cfg2.MinTxPerBatch = 1
	engine2, err := NewRollupEngine(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	engine2.SetSequencerElector(elector2)
	// RLLP-R5-04: dynamically find a NON-current sequencer.
	nonCurrentIdx := (currentIdx + 1) % len(addrs)
	engine2.SetLocalAddress(addrs[nonCurrentIdx])
	engine2.SetRequireTxSig(false)

	// Fund the sender account.
	sender2 := types.Address{0xbb}
	sm2 := engine2.GetStateManager()
	sm2.mu.Lock()
	sm2.accountStates[sender2] = &RollupAccount{Balance: big.NewInt(1_000_000)}
	currentRoot2 := sm2.computeStateRoot()
	engine2.GetBatchManager().lastStateRoot = currentRoot2
	sm2.mu.Unlock()

	engine2.mu.Lock()
	engine2.status = RollupStatusRunning
	engine2.mu.Unlock()

	tx2 := &RollupTransaction{
		Nonce:    0,
		GasPrice: 1,
		GasLimit: 21000,
		Value:    big.NewInt(100),
		From:     sender2,
		ChainID:  cfg2.ChainID,
	}
	if err := engine2.SubmitL2Transaction(tx2); err != nil {
		t.Fatalf("SubmitL2Transaction failed: %v", err)
	}

	// tryBuildAndSubmitBatch should skip because local is not the sequencer.
	engine2.tryBuildAndSubmitBatch()

	totalBatches2, _, _ := engine2.GetStats()
	if totalBatches2 != 0 {
		t.Errorf("expected 0 batches for non-sequencer, got %d", totalBatches2)
	}

	// Now simulate failover: increment misses past SequencerTimeout and verify
	// the next sequencer takes over. The next sequencer should be addrs[nonCurrentIdx]
	// (which is the computeSequencerIndex(1, seed, n) result).
	nextIdx := computeSequencerIndex(1, provider2.seed, len(addrs))
	if nextIdx != nonCurrentIdx {
		// If the next sequencer isn't our local node, adjust localAddress to
		// be the next sequencer so failover actually triggers.
		engine2.SetLocalAddress(addrs[nextIdx])
	}
	engine2.mu.Lock()
	engine2.missedBatchCount = 2 // >= SequencerTimeout (2)
	engine2.mu.Unlock()
	engine2.tryBuildAndSubmitBatch()

	totalBatches3, _, _ := engine2.GetStats()
	if totalBatches3 != 1 {
		t.Errorf("expected 1 batch after failover, got %d", totalBatches3)
	}
}
