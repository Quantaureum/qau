// Quantaureum Node source, version 1.0.0.
package consensus

// CONS-R9-L-REDO-01 (2026-07-19) regression tests for genesis-epoch
// finalization.
//
// Background (audit-r9-cons-redo-2026-07-19.md L-REDO-01):
//   tryUpdateFinality previously guarded the finalize step with
//   `oldJustified > 0`. This permanently excluded the genesis epoch
//   (epoch 0) from being finalized — finalizedEpoch stayed at 0 with
//   finalizedRoot=zero-hash. Downstream consumers (slashing evidence
//   retention, state pruning, sync committee rotation) had to
//   special-case the genesis root.
//
// Fix:
//   1. Added SetGenesisRoot(root) so the genesis block root can be
//      registered into epochBlockRoots[0] and slotBlockRoots[0] at
//      node startup.
//   2. Relaxed the guard so oldJustified==0 is finalizable IF a
//      non-zero genesis root was registered (oldJustifiedRoot != zero).
//   3. Added an `oldJustified == finalizedEpoch && finalizedRoot == zero`
//      bootstrap branch — the initial state has finalizedEpoch=0 with
//      finalizedRoot=zero-hash, so the strict `>` comparison alone would
//      skip genesis finalization forever. This branch patches exactly
//      the bootstrap case and is only reachable once (after the first
//      finalization, finalizedRoot becomes non-zero).

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// r9LRedo01SetupQPOS builds a QPOS with `count` validators (each with
// stake 1000), configures the attestation network ID, and rewinds
// genesis time so GetCurrentEpoch() returns at least `targetEpoch`.
//
// The validator set is created with deterministic addresses so the test
// is reproducible. SetGenesisTime is called with a wall-clock-based
// timestamp; if a previous test froze genesis time, the test is skipped.
func r9LRedo01SetupQPOS(t *testing.T, count int, targetEpoch uint64) *QPOS {
	t.Helper()
	vs := createTestValidatorSet(t, count)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	SetAttestationNetworkID(1668)

	// Rewind genesis time so currentEpoch == targetEpoch exactly.
	// (now - genesisTime) = targetEpoch * EpochDuration + 1s margin so
	// GetCurrentSlot returns targetEpoch * SlotsPerEpoch (currentEpoch =
	// targetEpoch). The +1s absorbs sub-second clock drift between
	// SetGenesisTime and the call to GetCurrentEpoch(); it does not change
	// the integer division result but ensures (now - gt) is non-negative.
	//
	// IMPORTANT: tryUpdateFinality requires `oldJustified == prevEpoch - 1`
	// to fire the finalize branch. With oldJustified=0 (initial), prevEpoch
	// MUST be 1, i.e., currentEpoch MUST be 2 — NOT 3. Using
	// (targetEpoch+1) * EpochDuration here would push currentEpoch one
	// epoch too far, breaking the consecutive-epoch invariant.
	rewind := int64(targetEpoch)*int64(EpochDuration.Seconds()) + 1
	gt := time.Now().Unix() - rewind
	if err := SetGenesisTime(gt); err != nil {
		t.Skipf("SetGenesisTime failed (likely frozen by a prior test): %v", err)
	}
	return qpos
}

// r9LRedo01InjectAttestations writes `count` attestations into
// q.attestations for slots in prevEpoch (currentEpoch-1), all targeting
// the canonical (epochRoot, slotRoot) pair. Source is set to the genesis
// epoch (epoch 0) with the genesis root, so the Source→Target chain
// check inside tryUpdateFinality passes.
//
// The function writes attestations from DISTINCT validators so each
// one contributes fresh stake to attestedWeight (tryUpdateFinality
// deduplicates by validator index).
func r9LRedo01InjectAttestations(t *testing.T, q *QPOS, prevEpoch uint64, count int, epochRoot, slotRoot, genesisRoot types.Hash) {
	t.Helper()
	startSlot := EpochStartSlot(prevEpoch)
	endSlot := startSlot + SlotsPerEpoch - 1
	slotIdx := uint64(0)
	for i := 0; i < count; i++ {
		slot := startSlot + (slotIdx % SlotsPerEpoch)
		slotIdx++
		att := &Attestation{
			Slot:            slot,
			BeaconBlockRoot: slotRoot,
			Source:          AttestationCheckpoint{Epoch: 0, Root: genesisRoot},
			Target:          AttestationCheckpoint{Epoch: prevEpoch, Root: slotRoot},
			ValidatorIndex:  i,
			Signature:       make([]byte, 3293),
			KeyVersion:      1,
		}
		q.attestations[slot] = append(q.attestations[slot], att)
		// Also register the canonical slot root so the per-slot check
		// (canonicalSlotRoot == att.Target.Root) passes.
		q.slotBlockRoots[slot] = slotRoot
		_ = endSlot // reference for clarity; not strictly needed
	}
	// Register the epoch boundary root as well (canonicalEpochRoot).
	q.epochBlockRoots[prevEpoch] = epochRoot
}

// TestCONS_R9_L_REDO_01_GenesisRootRegistered_FinalizesGenesis verifies
// that when SetGenesisRoot was called with a real (non-zero) genesis
// root and epoch 1 reaches 2/3 supermajority, the genesis epoch (epoch 0)
// is finalized: finalizedRoot equals the genesis root.
//
// Pre-fix expectation: finalizedRoot stays zero (genesis never finalized).
// Post-fix expectation: finalizedRoot == genesisRoot.
func TestCONS_R9_L_REDO_01_GenesisRootRegistered_FinalizesGenesis(t *testing.T) {
	// 4 validators × 1000 stake = 4000 total. 2/3 threshold = 2666.67.
	// 3 attestations (distinct validators) = 3000 stake → >= threshold.
	qpos := r9LRedo01SetupQPOS(t, 4, 2)

	genesisRoot := types.Hash{0xAA, 0xBB, 0xCC}
	epoch1Root := types.Hash{0x11, 0x22, 0x33}
	slotRoot := epoch1Root

	qpos.SetGenesisRoot(genesisRoot)

	// Sanity: genesis root registered into both maps.
	qpos.mu.RLock()
	if got := qpos.epochBlockRoots[0]; got != genesisRoot {
		t.Fatalf("SetGenesisRoot did not register epochBlockRoots[0]: got %x, want %x", got, genesisRoot)
	}
	if got := qpos.slotBlockRoots[0]; got != genesisRoot {
		t.Fatalf("SetGenesisRoot did not register slotBlockRoots[0]: got %x, want %x", got, genesisRoot)
	}
	qpos.mu.RUnlock()

	// Inject 3 attestations for prevEpoch=1 (currentEpoch must be >= 2).
	currentEpoch := qpos.GetCurrentEpoch()
	if currentEpoch < 2 {
		t.Fatalf("setup precondition failed: currentEpoch=%d, need >= 2", currentEpoch)
	}
	prevEpoch := currentEpoch - 1

	qpos.mu.Lock()
	r9LRedo01InjectAttestations(t, qpos, prevEpoch, 3, epoch1Root, slotRoot, genesisRoot)
	qpos.mu.Unlock()

	// Drive finality.
	qpos.mu.Lock()
	qpos.tryUpdateFinality()
	finalizedEpoch := qpos.finalizedEpoch
	finalizedRoot := qpos.finalizedRoot
	justifiedEpoch := qpos.justifiedEpoch
	qpos.mu.Unlock()

	if justifiedEpoch != prevEpoch {
		t.Fatalf("justifiedEpoch = %d, want %d (epoch 1 should be justified after 2/3 supermajority)", justifiedEpoch, prevEpoch)
	}
	if finalizedRoot != genesisRoot {
		t.Fatalf("CONS-R9-L-REDO-01 regression: genesis root NOT finalized. "+
			"finalizedEpoch=%d finalizedRoot=%x, want finalizedRoot=%x (genesisRoot). "+
			"Pre-fix this branch was unreachable due to `oldJustified > 0` guard.",
			finalizedEpoch, finalizedRoot, genesisRoot)
	}
	if finalizedEpoch != 0 {
		t.Fatalf("finalizedEpoch = %d, want 0 (genesis epoch should be finalized at epoch 0)", finalizedEpoch)
	}
}

// TestCONS_R9_L_REDO_01_NoGenesisRoot_PreservesOldBehavior verifies the
// backward-compat safety property: if SetGenesisRoot was NEVER called
// (e.g., a node that hasn't been upgraded to call it), genesis stays
// unfinalizable. This preserves the old behavior for nodes that don't
// bootstrap the genesis root, so they aren't exposed to a zero-root
// finalization.
func TestCONS_R9_L_REDO_01_NoGenesisRoot_PreservesOldBehavior(t *testing.T) {
	qpos := r9LRedo01SetupQPOS(t, 4, 2)

	// Deliberately do NOT call SetGenesisRoot.
	epoch1Root := types.Hash{0x11, 0x22, 0x33}

	currentEpoch := qpos.GetCurrentEpoch()
	if currentEpoch < 2 {
		t.Fatalf("setup precondition failed: currentEpoch=%d, need >= 2", currentEpoch)
	}
	prevEpoch := currentEpoch - 1

	qpos.mu.Lock()
	// Source root is zero (genesis root not registered). tryUpdateFinality
	// should reject these attestations on the Source.Root canonical-root
	// check (canonicalSourceRoot == zero hash → skip).
	r9LRedo01InjectAttestations(t, qpos, prevEpoch, 3, epoch1Root, epoch1Root, types.Hash{})
	qpos.mu.Unlock()

	qpos.mu.Lock()
	qpos.tryUpdateFinality()
	finalizedRoot := qpos.finalizedRoot
	qpos.mu.Unlock()

	if finalizedRoot != (types.Hash{}) {
		t.Fatalf("CONS-R9-L-REDO-01 safety: when SetGenesisRoot was NOT called, "+
			"finalizedRoot must stay zero (old behavior preserved); got %x. "+
			"This would indicate the fix accidentally finalizes a zero genesis root.",
			finalizedRoot)
	}
}

// TestCONS_R9_L_REDO_01_SetGenesisRoot_Idempotent verifies that calling
// SetGenesisRoot twice with the SAME root is a no-op (idempotent), and
// calling it with a DIFFERENT root is rejected (logged, ignored) so a
// misconfigured restart cannot retroactively rewrite finalizedRoot for
// epoch 0.
func TestCONS_R9_L_REDO_01_SetGenesisRoot_Idempotent(t *testing.T) {
	qpos := r9LRedo01SetupQPOS(t, 4, 2)

	root1 := types.Hash{0xAA}
	root2 := types.Hash{0xBB}

	// First call: registers root1.
	qpos.SetGenesisRoot(root1)

	// Second call with SAME root: idempotent, no error.
	qpos.SetGenesisRoot(root1)

	qpos.mu.RLock()
	got := qpos.epochBlockRoots[0]
	qpos.mu.RUnlock()
	if got != root1 {
		t.Fatalf("after idempotent re-register, epochBlockRoots[0] = %x, want %x", got, root1)
	}

	// Third call with DIFFERENT root: rejected, original preserved.
	qpos.SetGenesisRoot(root2)

	qpos.mu.RLock()
	got = qpos.epochBlockRoots[0]
	qpos.mu.RUnlock()
	if got != root1 {
		t.Fatalf("after conflicting re-register, epochBlockRoots[0] = %x, want %x (original must be preserved)", got, root1)
	}
}

// TestCONS_R9_L_REDO_01_BootstrapBranch_OnlyReachableOnce verifies the
// `oldJustified == finalizedEpoch && finalizedRoot == zero` bootstrap
// branch is only reachable ONCE: after the first finalization,
// finalizedRoot becomes non-zero, so a subsequent tryUpdateFinality
// call must NOT re-enter the bootstrap branch. This guards against the
// fix accidentally rewriting finalizedRoot for non-genesis epochs.
//
// This test uses targetEpoch=2 (currentEpoch=2, prevEpoch=1) and calls
// tryUpdateFinality twice with the SAME state. The second call must
// be a no-op because finalizedRoot is now non-zero (the bootstrap
// branch's `finalizedRoot == zero` guard rejects re-entry).
func TestCONS_R9_L_REDO_01_BootstrapBranch_OnlyReachableOnce(t *testing.T) {
	qpos := r9LRedo01SetupQPOS(t, 4, 2)

	genesisRoot := types.Hash{0xAA}
	epoch1Root := types.Hash{0x11}

	qpos.SetGenesisRoot(genesisRoot)

	currentEpoch := qpos.GetCurrentEpoch()
	if currentEpoch < 2 {
		t.Fatalf("setup precondition failed: currentEpoch=%d, need >= 2", currentEpoch)
	}
	prevEpoch := currentEpoch - 1

	// --- Round 1: trigger the bootstrap branch ---
	qpos.mu.Lock()
	r9LRedo01InjectAttestations(t, qpos, prevEpoch, 3, epoch1Root, epoch1Root, genesisRoot)
	qpos.tryUpdateFinality()
	finalizedRootAfterRound1 := qpos.finalizedRoot
	finalizedEpochAfterRound1 := qpos.finalizedEpoch
	qpos.mu.Unlock()

	if finalizedRootAfterRound1 != genesisRoot {
		t.Fatalf("round 1: bootstrap branch should set finalizedRoot=genesisRoot; got %x",
			finalizedRootAfterRound1)
	}
	if finalizedEpochAfterRound1 != 0 {
		t.Fatalf("round 1: finalizedEpoch should stay 0 (genesis epoch); got %d",
			finalizedEpochAfterRound1)
	}

	// --- Round 2: re-call tryUpdateFinality with the SAME state ---
	// finalizedRoot is now genesisRoot (non-zero), so the bootstrap
	// branch's `finalizedRoot == zero` guard must reject re-entry.
	// The first branch `oldJustified > finalizedEpoch` is also false
	// (0 > 0 = false). So finalizedRoot must be UNCHANGED.
	qpos.mu.Lock()
	qpos.tryUpdateFinality()
	finalizedRootAfterRound2 := qpos.finalizedRoot
	finalizedEpochAfterRound2 := qpos.finalizedEpoch
	qpos.mu.Unlock()

	if finalizedRootAfterRound2 != genesisRoot {
		t.Fatalf("CONS-R9-L-REDO-01 regression: bootstrap branch re-entered on "+
			"second call and overwrote finalizedRoot. After round 1: %x, "+
			"after round 2: %x. The bootstrap branch must only fire when "+
			"finalizedRoot==zero (one-shot).",
			finalizedRootAfterRound1, finalizedRootAfterRound2)
	}
	if finalizedEpochAfterRound2 != finalizedEpochAfterRound1 {
		t.Fatalf("finalizedEpoch changed on no-op re-run: %d → %d",
			finalizedEpochAfterRound1, finalizedEpochAfterRound2)
	}
}

// TestCONS_R9_L_REDO_01_TotalStakeBelowThreshold_NoFinalization verifies
// that when attested weight is below 2/3 of total stake, neither genesis
// nor any other epoch gets finalized. This guards against the fix
// accidentally lowering the finality threshold.
func TestCONS_R9_L_REDO_01_TotalStakeBelowThreshold_NoFinalization(t *testing.T) {
	qpos := r9LRedo01SetupQPOS(t, 4, 2)

	genesisRoot := types.Hash{0xAA}
	epoch1Root := types.Hash{0x11}

	qpos.SetGenesisRoot(genesisRoot)

	currentEpoch := qpos.GetCurrentEpoch()
	if currentEpoch < 2 {
		t.Fatalf("setup precondition failed: currentEpoch=%d, need >= 2", currentEpoch)
	}
	prevEpoch := currentEpoch - 1

	// Inject only 2 attestations (2000 stake < 2666.67 threshold).
	qpos.mu.Lock()
	r9LRedo01InjectAttestations(t, qpos, prevEpoch, 2, epoch1Root, epoch1Root, genesisRoot)
	qpos.tryUpdateFinality()
	finalizedRoot := qpos.finalizedRoot
	justifiedEpoch := qpos.justifiedEpoch
	qpos.mu.Unlock()

	if justifiedEpoch != 0 {
		t.Fatalf("with 2/4 attestations (below 2/3 threshold), justifiedEpoch should stay 0; got %d", justifiedEpoch)
	}
	if finalizedRoot != (types.Hash{}) {
		t.Fatalf("with 2/4 attestations (below 2/3 threshold), finalizedRoot should stay zero; got %x", finalizedRoot)
	}
}

// reference: keep math/big import used even if thresholds change.
var _ = big.NewInt
