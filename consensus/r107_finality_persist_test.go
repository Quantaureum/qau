// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/types"
)

func TestR107_RestoreFinalityStateRegistersCheckpointRoots(t *testing.T) {
	q := r101SetupQPOS(t, 1788110700)
	justifiedRoot := types.Hash{0x11}
	finalizedRoot := types.Hash{0x22}

	if err := q.RestoreFinalityState(27, 26, justifiedRoot, finalizedRoot); err != nil {
		t.Fatalf("RestoreFinalityState: %v", err)
	}
	if !q.HasEpochRoot(27) || !q.HasEpochRoot(26) {
		t.Fatalf("checkpoint roots were not registered: justified=%t finalized=%t",
			q.HasEpochRoot(27), q.HasEpochRoot(26))
	}
	if got := q.GetJustifiedEpoch(); got != 27 {
		t.Fatalf("justified epoch = %d, want 27", got)
	}
	if got := q.GetFinalizedEpoch(); got != 26 {
		t.Fatalf("finalized epoch = %d, want 26", got)
	}
	q.mu.RLock()
	gotJustified, gotFinalized := q.justifiedRoot, q.finalizedRoot
	q.mu.RUnlock()
	if gotJustified != justifiedRoot || gotFinalized != finalizedRoot {
		t.Fatalf("restored roots = (%x, %x), want (%x, %x)",
			gotJustified[:4], gotFinalized[:4], justifiedRoot[:4], finalizedRoot[:4])
	}
}

func TestR107_RestoredCheckpointLetsAttestationRatchetResume(t *testing.T) {
	genesisTime := int64(1788110700)
	first := r101SetupQPOS(t, genesisTime)
	rootFn := func(epoch uint64) types.Hash {
		return types.Hash{0xb0, byte(epoch), byte(epoch >> 8), byte(epoch >> 16)}
	}

	justified, finalized := uint64(0), uint64(0)
	for epoch := uint64(28); epoch <= 35; epoch++ {
		justified, finalized = r101AdvanceEpoch(t, first, genesisTime, epoch, rootFn)
	}
	if justified != 34 || finalized != 33 {
		t.Fatalf("pre-restart finality = (%d, %d), want (34, 33)", justified, finalized)
	}
	first.mu.RLock()
	justifiedRoot := first.justifiedRoot
	finalizedRoot := first.finalizedRoot
	first.mu.RUnlock()

	restarted := r101SetupQPOS(t, genesisTime)
	if err := restarted.RestoreFinalityState(
		justified,
		finalized,
		justifiedRoot,
		finalizedRoot,
	); err != nil {
		t.Fatalf("RestoreFinalityState: %v", err)
	}
	if !restarted.HasEpochRoot(justified) {
		t.Fatalf("restored justified root is missing from epochBlockRoots")
	}
	// The newest target root is not part of the two-checkpoint ledger. The
	// node-side R101 canonical-store backfill reconstructs it before the next
	// epoch is counted.
	restarted.BackfillEpochRoots(map[uint64]types.Hash{35: rootFn(35)})

	// Without the restored source root, the first post-restart vote is
	// rejected by CONS-003 and the ratchet remains frozen. With the restored
	// checkpoint, the same epoch transition advances normally.
	afterJustified, afterFinalized := r101AdvanceEpoch(t, restarted, genesisTime, 36, rootFn)
	if afterJustified != 35 || afterFinalized != 34 {
		t.Fatalf("post-restart finality = (%d, %d), want (35, 34)", afterJustified, afterFinalized)
	}
}

func TestR107_RestoreFinalityStateRegistersEpochZeroRoot(t *testing.T) {
	q, err := NewQPOS(makeSlotPruneTestValidatorSet(6))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	t.Cleanup(q.Stop)
	genesisRoot := types.Hash{0xAA}
	if err := q.RestoreFinalityState(0, 0, genesisRoot, genesisRoot); err != nil {
		t.Fatalf("RestoreFinalityState: %v", err)
	}
	if !q.HasEpochRoot(0) {
		t.Fatal("restored epoch-zero root is missing from epochBlockRoots")
	}
	if got, ok := q.GetSlotBlockRoot(0); !ok || got != genesisRoot {
		t.Fatalf(
			"restored genesis slot root = (%x, %t), want (%x, true)",
			got[:4],
			ok,
			genesisRoot[:4],
		)
	}
}

func TestR107_RestoreFinalityStateRejectsConflictingEpochZeroRoots(t *testing.T) {
	q, err := NewQPOS(makeSlotPruneTestValidatorSet(6))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	t.Cleanup(q.Stop)
	if err := q.RestoreFinalityState(0, 0, types.Hash{0xAA}, types.Hash{0xBB}); err == nil {
		t.Fatal("conflicting persisted epoch-zero roots were accepted")
	}
}

func TestR107_RestoreFinalityStateRejectsConflictingGenesisRoot(t *testing.T) {
	q := r101SetupQPOS(t, 1788110700)
	genesisRoot := types.Hash{0xAA}
	q.SetGenesisRoot(genesisRoot)

	if err := q.RestoreFinalityState(0, 0, types.Hash{0xFF}, types.Hash{0xFF}); err == nil {
		t.Fatal("conflicting persisted genesis root was accepted")
	}
	if got := q.GetJustifiedEpoch(); got != 0 {
		t.Fatalf("justified epoch after rejected genesis restore = %d, want 0", got)
	}
	q.mu.RLock()
	gotGenesisRoot := q.epochBlockRoots[0]
	gotJustifiedRoot := q.justifiedRoot
	q.mu.RUnlock()
	if gotGenesisRoot != genesisRoot || gotJustifiedRoot != (types.Hash{}) {
		t.Fatalf(
			"rejected genesis restore changed state: genesis=%x justified=%x",
			gotGenesisRoot[:4],
			gotJustifiedRoot[:4],
		)
	}
}

func TestR107_BackfillPersistsAdoptedCheckpointWhenCanonicalRootMatches(t *testing.T) {
	q := r101SetupQPOS(t, 1788110700)
	headerHash := types.Hash{0xAB}
	q.AdoptHeaderFinality(10, 9, headerHash)

	var calls int
	q.SetFinalityPersistCallback(func(uint64, uint64, types.Hash, types.Hash) error {
		calls++
		return nil
	})
	if applied := q.BackfillEpochRoots(map[uint64]types.Hash{9: headerHash, 10: headerHash}); applied != 2 {
		t.Fatalf("BackfillEpochRoots applied %d entries, want 2", applied)
	}
	if calls != 1 {
		t.Fatalf("checkpoint persistence calls = %d, want 1", calls)
	}
}

func TestR107_FinalityRootChangePersistsRestoredCheckpoint(t *testing.T) {
	q := r101SetupQPOS(t, 1788110700)
	justifiedRoot := types.Hash{0x11}
	finalizedRoot := types.Hash{0x22}
	if err := q.RestoreFinalityState(7, 6, justifiedRoot, finalizedRoot); err != nil {
		t.Fatalf("RestoreFinalityState: %v", err)
	}

	var gotEpochs [2]uint64
	var gotRoots [2]types.Hash
	q.SetFinalityPersistCallback(func(justifiedEpoch, finalizedEpoch uint64, justified, finalized types.Hash) error {
		gotEpochs = [2]uint64{justifiedEpoch, finalizedEpoch}
		gotRoots = [2]types.Hash{justified, finalized}
		return nil
	})
	authoritativeRoot := types.Hash{0x33}
	q.SetEpochBlockRoot(7, authoritativeRoot)
	if gotEpochs != [2]uint64{7, 6} || gotRoots[0] != authoritativeRoot || gotRoots[1] != finalizedRoot {
		t.Fatalf(
			"root reconciliation persisted epochs %v roots (%x, %x), want epochs [7 6] roots (%x, %x)",
			gotEpochs,
			gotRoots[0][:4],
			gotRoots[1][:4],
			authoritativeRoot[:4],
			finalizedRoot[:4],
		)
	}
}

func TestR107_SuccessfulFinalityPersistenceIsNotRepeated(t *testing.T) {
	q := r101SetupQPOS(t, 1788110700)
	justifiedRoot := types.Hash{0x11}
	finalizedRoot := types.Hash{0x22}
	q.SetEpochBlockRoot(7, justifiedRoot)
	q.SetEpochBlockRoot(6, finalizedRoot)
	if err := q.RestoreFinalityState(7, 6, justifiedRoot, finalizedRoot); err != nil {
		t.Fatalf("RestoreFinalityState: %v", err)
	}

	calls := 0
	q.SetFinalityPersistCallback(func(uint64, uint64, types.Hash, types.Hash) error {
		calls++
		return nil
	})
	q.SetEpochBlockRoot(7, justifiedRoot)
	if calls != 0 {
		t.Fatalf("unchanged canonical root triggered %d durable writes, want 0", calls)
	}
}

func TestR107_FinalityPersistenceFailureRemainsPendingForRetry(t *testing.T) {
	q := r101SetupQPOS(t, 1788110700)
	justifiedRoot := types.Hash{0x11}
	finalizedRoot := types.Hash{0x22}
	q.SetEpochBlockRoot(7, justifiedRoot)
	q.SetEpochBlockRoot(6, finalizedRoot)
	q.RestoreFinalityState(7, 6, justifiedRoot, finalizedRoot)

	calls := 0
	q.SetFinalityPersistCallback(func(uint64, uint64, types.Hash, types.Hash) error {
		calls++
		if calls == 1 {
			return errors.New("temporary database failure")
		}
		return nil
	})
	nextJustifiedRoot := types.Hash{0x33}
	q.SetEpochBlockRoot(8, nextJustifiedRoot)
	q.AdoptHeaderFinality(8, 7, types.Hash{0x44})
	if calls != 1 {
		t.Fatalf("initial persistence calls = %d, want 1", calls)
	}

	q.BackfillEpochRoots(map[uint64]types.Hash{
		7: justifiedRoot,
		8: nextJustifiedRoot,
	})
	if calls != 2 {
		t.Fatalf("persistence retry calls = %d, want 2", calls)
	}
}

func TestR107_BackfillRejectsConflictingFinalizedRoot(t *testing.T) {
	q, err := NewQPOS(makeSlotPruneTestValidatorSet(6))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	t.Cleanup(q.Stop)

	finalizedRoot := types.Hash{0x11}
	if err := q.RestoreFinalityState(5, 5, finalizedRoot, finalizedRoot); err != nil {
		t.Fatalf("RestoreFinalityState: %v", err)
	}
	if applied := q.BackfillEpochRoots(map[uint64]types.Hash{5: {0xEE}}); applied != 0 {
		t.Fatalf("conflicting finalized root was applied to %d entries", applied)
	}
	if got := q.GetFinalizedEpoch(); got != 5 {
		t.Fatalf("finalized epoch = %d, want 5", got)
	}
	q.mu.RLock()
	gotRoot := q.finalizedRoot
	q.mu.RUnlock()
	if gotRoot != finalizedRoot {
		t.Fatalf("finalized root changed to %x, want %x", gotRoot[:4], finalizedRoot[:4])
	}
}

func TestR107_SetEpochBlockRootRejectsConflictingFinalizedRoot(t *testing.T) {
	q, err := NewQPOS(makeSlotPruneTestValidatorSet(6))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	t.Cleanup(q.Stop)

	finalizedRoot := types.Hash{0x11}
	if err := q.RestoreFinalityState(5, 5, finalizedRoot, finalizedRoot); err != nil {
		t.Fatalf("RestoreFinalityState: %v", err)
	}
	q.SetEpochBlockRoot(5, types.Hash{0xEE})
	if !q.HasEpochRoot(5) {
		t.Fatal("finalized epoch root disappeared")
	}
	q.mu.RLock()
	gotRoot := q.finalizedRoot
	q.mu.RUnlock()
	if gotRoot != finalizedRoot {
		t.Fatalf("finalized root changed to %x, want %x", gotRoot[:4], finalizedRoot[:4])
	}
}

func TestR107_RestoreRejectsEqualEpochsWithDifferentRoots(t *testing.T) {
	q, err := NewQPOS(makeSlotPruneTestValidatorSet(6))
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	t.Cleanup(q.Stop)
	if err := q.RestoreFinalityState(5, 5, types.Hash{0x11}, types.Hash{0x22}); err == nil {
		t.Fatal("equal justified/finalized epochs with different roots were accepted")
	}
}

func TestR107_QTDCheckpointTransitionIsPersisted(t *testing.T) {
	q := r101SetupQPOS(t, 1788110700)
	q.InitChambers()
	qfs := q.GetQTDFinality()
	if qfs == nil {
		t.Fatal("QTD finality state is nil")
	}

	slot := uint64(35 * SlotsPerEpoch)
	root := types.Hash{0x55}
	q.SetSlotBlockRoot(slot, root)
	q.SetEpochBlockRoot(35, root)

	calls := 0
	q.SetFinalityPersistCallback(func(uint64, uint64, types.Hash, types.Hash) error {
		calls++
		return nil
	})
	qfs.completeSealLockedFinalize(slot, root)

	if got := q.GetFinalizedEpoch(); got != 35 {
		t.Fatalf("QTD finalized epoch = %d, want 35", got)
	}
	if got := q.GetJustifiedEpoch(); got != 35 {
		t.Fatalf("QTD justified epoch = %d, want 35", got)
	}
	if calls != 1 {
		t.Fatalf("QTD checkpoint persistence calls = %d, want 1", calls)
	}
}

func TestR107_BackfillRootChangePersistsRestoredCheckpoint(t *testing.T) {
	q := r101SetupQPOS(t, 1788110700)
	justifiedRoot := types.Hash{0x11}
	finalizedRoot := types.Hash{0x22}
	if err := q.RestoreFinalityState(7, 6, justifiedRoot, finalizedRoot); err != nil {
		t.Fatalf("RestoreFinalityState: %v", err)
	}

	calls := 0
	q.SetFinalityPersistCallback(func(uint64, uint64, types.Hash, types.Hash) error {
		calls++
		return nil
	})
	authoritativeRoot := types.Hash{0x33}
	if applied := q.BackfillEpochRoots(map[uint64]types.Hash{7: authoritativeRoot}); applied != 1 {
		t.Fatalf("BackfillEpochRoots applied %d entries, want 1", applied)
	}
	if calls != 1 {
		t.Fatalf("restored checkpoint root change persisted %d times, want 1", calls)
	}
}

func TestR107_BackfillReconcilesAndPersistsAdoptedCheckpointRoots(t *testing.T) {
	q := r101SetupQPOS(t, 1788110700)
	headerHash := types.Hash{0xAB}
	q.AdoptHeaderFinality(10, 9, headerHash)

	justifiedRoot := types.Hash{0xCD}
	finalizedRoot := types.Hash{0xEF}
	var calls int
	var gotEpochs [2]uint64
	var gotRoots [2]types.Hash
	q.SetFinalityPersistCallback(func(justifiedEpoch, finalizedEpoch uint64, justified, finalized types.Hash) error {
		calls++
		gotEpochs = [2]uint64{justifiedEpoch, finalizedEpoch}
		gotRoots = [2]types.Hash{justified, finalized}
		return nil
	})

	if applied := q.BackfillEpochRoots(map[uint64]types.Hash{
		9:  finalizedRoot,
		10: justifiedRoot,
	}); applied != 2 {
		t.Fatalf("BackfillEpochRoots applied %d entries, want 2", applied)
	}
	if calls != 1 {
		t.Fatalf("checkpoint persistence calls after canonical backfill = %d, want 1", calls)
	}
	if gotEpochs != [2]uint64{10, 9} || gotRoots[0] != justifiedRoot || gotRoots[1] != finalizedRoot {
		t.Fatalf(
			"persisted checkpoint = epochs %v roots (%x, %x), want epochs [10 9] roots (%x, %x)",
			gotEpochs,
			gotRoots[0][:4],
			gotRoots[1][:4],
			justifiedRoot[:4],
			finalizedRoot[:4],
		)
	}

	q.mu.RLock()
	gotJustifiedRoot := q.justifiedRoot
	gotFinalizedRoot := q.finalizedRoot
	q.mu.RUnlock()
	if gotJustifiedRoot != justifiedRoot || gotFinalizedRoot != finalizedRoot {
		t.Fatalf(
			"backfilled checkpoint roots = (%x, %x), want (%x, %x)",
			gotJustifiedRoot[:4],
			gotFinalizedRoot[:4],
			justifiedRoot[:4],
			finalizedRoot[:4],
		)
	}
}

func TestR107_AdoptHeaderFinalityPersistsAndReconcilesCheckpointRoot(t *testing.T) {
	q := r101SetupQPOS(t, 1788110700)
	headerHash := types.Hash{0xAB}
	justifiedRoot := types.Hash{0xCD}
	finalizedRoot := types.Hash{0xEF}
	var gotEpochs [2]uint64
	var gotRoots [2]types.Hash
	var calls int

	q.SetFinalityPersistCallback(func(justifiedEpoch, finalizedEpoch uint64, justifiedRoot, finalizedRoot types.Hash) error {
		gotEpochs = [2]uint64{justifiedEpoch, finalizedEpoch}
		gotRoots = [2]types.Hash{justifiedRoot, finalizedRoot}
		calls++
		return nil
	})
	q.AdoptHeaderFinality(7, 6, headerHash)
	if calls != 0 {
		t.Fatalf("fallback header roots were persisted before canonical roots were known (calls=%d)", calls)
	}

	q.SetEpochBlockRoot(7, justifiedRoot)
	if calls != 0 {
		t.Fatalf("partially canonical checkpoint was persisted (calls=%d)", calls)
	}
	q.SetEpochBlockRoot(6, finalizedRoot)
	if calls != 1 {
		t.Fatalf("persistence callback calls after both canonical roots = %d, want 1", calls)
	}
	if gotEpochs != [2]uint64{7, 6} || gotRoots[0] != justifiedRoot || gotRoots[1] != finalizedRoot {
		t.Fatalf("persisted checkpoint = epochs %v roots (%x, %x), want epochs [7 6] roots (%x, %x)",
			gotEpochs, gotRoots[0][:4], gotRoots[1][:4], justifiedRoot[:4], finalizedRoot[:4])
	}
}
