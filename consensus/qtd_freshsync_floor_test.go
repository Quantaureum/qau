// Quantaureum Node source, version 1.0.0.
package consensus

// Tests of the fresh-sync floor extension (TSS-R3-B-1 Fix B, 2026-11-15):
// getGroupPublicKeyForEpochLocked answers the CURRENT epoch from the custody
// floor when the node holds NO live signer. Before the change such a lookup
// fell through to the live-signer fallback and returned nil, so a fresh /
// verify-only node syncing from genesis was structurally wedged the moment
// its verification position reached the wall-clock epoch (every later epoch
// failed the lookup despite an adopted custody chain, and the wall-clock
// epoch kept advancing past each one).
//
// The invariants pinned here, mirroring the write-side trust model:
//   - the floor serves only custody-table entries installed through the
//     validated chokepoints (anchor adoption / ceremony re-root) — the same
//     trust root the past-epoch floor has always served;
//   - a node WITH a signer keeps the live-signer fallback byte-for-byte
//     (armed nodes: zero behavior change);
//   - empty custody and future epochs still fail closed;
//   - a degenerate custody entry is still rejected by the read-side guard.

import (
	"bytes"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
)

// newFreshSyncFloorQTDFinality builds a QTD finality state on a real QPOS so
// the wall-clock epoch arithmetic (GetCurrentEpoch) is live.
func newFreshSyncFloorQTDFinality(t *testing.T) *QTDFinalityState {
	t.Helper()
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	return NewQTDFinalityState(qpos)
}

// TestQTDFreshSyncFloor_CurrentEpochWithoutSigner pins the Fix B semantics on
// explicit locked lookups: with an adopted custody chain and no signer, the
// current epoch is answered from the floor (the pre-fix answer was nil — the
// structural wedge), while future epochs keep failing closed.
func TestQTDFreshSyncFloor_CurrentEpochWithoutSigner(t *testing.T) {
	qfs := newFreshSyncFloorQTDFinality(t)

	anchorKey := testExportGroupKey(0xA7)
	// Observer first establishment: the anchor custody chain of a fresh node.
	if !qfs.ObserveAnchoredGroupKey(7, anchorKey, nil) {
		t.Fatal("observer first establishment refused")
	}

	// The activation epoch itself: exact hit (unchanged behavior).
	qfs.mu.RLock()
	gotExact := qfs.getGroupPublicKeyForEpochLocked(7, 7)
	qfs.mu.RUnlock()
	if !bytes.Equal(gotExact, anchorKey) {
		t.Fatalf("lookup(7, current=7) = %d bytes, want the anchored key (exact hit)", len(gotExact))
	}

	// THE FIX: the NEXT epoch at the wall-clock current epoch (no exact entry,
	// no signer) is served by the floor — pre-fix this returned nil and wedged
	// every fresh node whose verification position reached the current epoch.
	qfs.mu.RLock()
	gotFloor := qfs.getGroupPublicKeyForEpochLocked(8, 8)
	qfs.mu.RUnlock()
	if !bytes.Equal(gotFloor, anchorKey) {
		t.Fatalf("lookup(8, current=8) = %d bytes, want the anchored key via the floor (Fix B)", len(gotFloor))
	}

	// A future epoch (beyond the wall-clock current epoch) still fails closed.
	qfs.mu.RLock()
	gotFuture := qfs.getGroupPublicKeyForEpochLocked(9, 8)
	qfs.mu.RUnlock()
	if gotFuture != nil {
		t.Fatalf("lookup(9, current=8) = %d bytes, want nil (future epoch: unchanged fail-closed)", len(gotFuture))
	}
}

// TestQTDFreshSyncFloor_WallClockCurrentEpoch is the definitive fresh-node
// shape: the QPOS wall-clock epoch IS the current epoch, the custody holds an
// adopted chain, there is no signer — the public export must serve the key
// for the wall-clock epoch (pre-fix: nil, the devnet wedge) and keep failing
// closed for the epoch after it (that one needs the next boundary carrier).
func TestQTDFreshSyncFloor_WallClockCurrentEpoch(t *testing.T) {
	qfs := newFreshSyncFloorQTDFinality(t)

	const anchoredEpoch = uint64(7)
	anchorKey := testExportGroupKey(0xB7)
	if !qfs.ObserveAnchoredGroupKey(anchoredEpoch, anchorKey, nil) {
		t.Fatal("observer first establishment refused")
	}

	// Move the chain clock into the anchored epoch: genesis now minus seven
	// epochs, so GetCurrentEpoch() == 7 for the next ~6.4 minutes.
	consensusGenesisForFloorTest(t, anchoredEpoch)

	if got := qfs.GroupPublicKeyForEpoch(anchoredEpoch); !bytes.Equal(got, anchorKey) {
		t.Fatalf("wall-clock current-epoch export = %d bytes, want the anchored key (Fix B floor; pre-fix nil)", len(got))
	}
	if got := qfs.GroupPublicKeyForEpoch(anchoredEpoch + 1); len(got) != 0 {
		t.Fatalf("wall-clock next-epoch export = %d bytes, want empty (future epoch: needs the next boundary carrier)", len(got))
	}
}

// TestQTDFreshSyncFloor_SignerPresentUnchanged pins the armed-node contract:
// with a signer installed, the current-epoch lookup still answers with the
// LIVE signer's key (the fallback is byte-for-byte unchanged), even when the
// custody floor holds an older entry.
func TestQTDFreshSyncFloor_SignerPresentUnchanged(t *testing.T) {
	qfs := newFreshSyncFloorQTDFinality(t)

	oldKey := testExportGroupKey(0x05)
	liveKey := testExportGroupKey(0x06)
	// A rotation happened at epoch 5; the live signer holds the new key.
	if !qfs.ObserveAnchoredGroupKey(5, oldKey, nil) {
		t.Fatal("observer first establishment refused")
	}
	qfs.SetQTDSignerForEpoch(&epochKeySigner{groupKey: liveKey}, 7)

	qfs.mu.RLock()
	got := qfs.getGroupPublicKeyForEpochLocked(7, 7)
	qfs.mu.RUnlock()
	if !bytes.Equal(got, liveKey) {
		t.Fatalf("lookup(7, current=7) with a live signer = %d bytes, want the LIVE signer key (fallback unchanged by Fix B)", len(got))
	}
}

// TestQTDFreshSyncFloor_FailClosedPreserved pins the fail-closed cases Fix B
// must not open: empty custody, a custody chain that starts after the target
// epoch, and a degenerate custody entry all still export nothing.
func TestQTDFreshSyncFloor_FailClosedPreserved(t *testing.T) {
	// Empty custody, no signer: nil (the fresh-node-before-first-anchor case).
	empty := newFreshSyncFloorQTDFinality(t)
	if got := empty.GroupPublicKeyForEpoch(7); len(got) != 0 {
		t.Fatalf("empty custody exported %d bytes, want empty (fail-closed)", len(got))
	}

	// Custody that starts AFTER the target epoch: no floor entry at or below
	// it — nil (the pre-activation case, unchanged).
	lagging := newFreshSyncFloorQTDFinality(t)
	if !lagging.ObserveAnchoredGroupKey(9, testExportGroupKey(0x99), nil) {
		t.Fatal("observer first establishment refused")
	}
	lagging.mu.RLock()
	got := lagging.getGroupPublicKeyForEpochLocked(7, 7)
	lagging.mu.RUnlock()
	if got != nil {
		t.Fatalf("lookup(7, current=7) with custody starting at 9 = %d bytes, want nil (no entry at-or-before the target)", len(got))
	}

	// A degenerate (all-zero) custody entry is rejected by the read-side
	// guard, so the floor does not resurrect the DKG-not-initialized forgery.
	degenerate := newFreshSyncFloorQTDFinality(t)
	degenerate.mu.Lock()
	degenerate.groupKeyHistory[9] = testAllZeroDilithium3GroupKey()
	degenerate.mu.Unlock()
	degenerate.mu.RLock()
	gotDegenerate := degenerate.getGroupPublicKeyForEpochLocked(9, 9)
	degenerate.mu.RUnlock()
	if gotDegenerate != nil {
		t.Fatalf("lookup(9, current=9) over an all-zero custody entry = %d bytes, want nil (read-side guard)", len(gotDegenerate))
	}
	if len(testAllZeroDilithium3GroupKey()) != crypto.Dilithium3PublicKeySize {
		t.Fatal("the degenerate fixture lost the canonical key size")
	}
}

// consensusGenesisForFloorTest pins the package-global chain clock so
// GetCurrentEpoch() equals wantEpoch, and restores the previous state at test
// end. The epoch length is SlotsPerEpoch 12-second slots, so the pin is valid
// for one epoch (~6.4 minutes) — far longer than any test.
func consensusGenesisForFloorTest(t *testing.T, wantEpoch uint64) {
	t.Helper()
	EnableTestHelpers()
	ResetGenesisTimeForTesting()
	t.Cleanup(ResetGenesisTimeForTesting)
	// Genesis such that now - genesis spans wantEpoch full epochs.
	genesis := time.Now().Unix() - int64(wantEpoch)*int64(SlotsPerEpoch)*12 - 5
	if err := SetGenesisTime(genesis); err != nil {
		t.Fatalf("SetGenesisTime: %v", err)
	}
}
