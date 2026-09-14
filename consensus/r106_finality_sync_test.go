// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// R106-FINALITY-SYNC regression tests.
//
// A non-sealer node that starts (or restarts) after the chain has been
// finalizing can report
// justifiedEpoch=0 / finalizedEpoch=0 forever via qau_qposStatus, while the
// sealers themselves advance normally. The in-memory finality state cannot be
// rebuilt from gossip: every live attestation carries Source.Epoch equal to
// the NETWORK's current justified epoch, which exceeds the restarted node's
// local 0 → tryUpdateFinality's CONS-003 gate skips every vote → the ratchet
// never re-engages (egg-and-chicken deadlock; see AdoptHeaderFinality for the
// full chain of causality).
//
// The fix adopts the checkpoint epochs carried in canonical block headers
// (consensus data stamped by the proposer's own ratchet), on every import and
// once at startup from the stored head.

func r106TestHash(b byte) types.Hash {
	var h types.Hash
	h[0] = b
	return h
}

// TestR106_AdoptHeaderFinality_AdvancesFrozenNode verifies the fix: a node at
// justified=0/finalized=0
// adopts the header values of a canonical block from a chain that has
// finalized epoch 41 (justified 42).
//
// Un-fixed behavior: state stays 0/0 (no adoption API existed at all).
func TestR106_AdoptHeaderFinality_AdvancesFrozenNode(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(6)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Simulate a restarted/fresh non-sealer: local checkpoints are zero.
	if got := qpos.GetJustifiedEpoch(); got != 0 {
		t.Fatalf("precondition: justifiedEpoch = %d, want 0", got)
	}
	if got := qpos.GetFinalizedEpoch(); got != 0 {
		t.Fatalf("precondition: finalizedEpoch = %d, want 0", got)
	}

	// A canonical head whose header stamps the network's consensus state.
	const headerJustified = uint64(42)
	const headerFinalized = uint64(41)
	headerHash := r106TestHash(0xA1)
	qpos.AdoptHeaderFinality(headerJustified, headerFinalized, headerHash)

	if got := qpos.GetJustifiedEpoch(); got != headerJustified {
		t.Errorf("justifiedEpoch after adoption = %d, want %d", got, headerJustified)
	}
	if got := qpos.GetFinalizedEpoch(); got != headerFinalized {
		t.Errorf("finalizedEpoch after adoption = %d, want %d", got, headerFinalized)
	}
}

// TestR106_AdoptHeaderFinality_MonotonicNoRollback verifies the anti-rollback
// guard: an older header (e.g. a late-delivered block from behind the head,
// or a malicious header) must never move the checkpoints backwards.
func TestR106_AdoptHeaderFinality_MonotonicNoRollback(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(6)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	qpos.AdoptHeaderFinality(42, 41, r106TestHash(0xA1))
	// A stale header claiming much older checkpoints.
	qpos.AdoptHeaderFinality(10, 9, r106TestHash(0xB2))
	// Equal epochs (re-delivery of the same head) must be a no-op.
	qpos.AdoptHeaderFinality(42, 41, r106TestHash(0xC3))

	if got := qpos.GetJustifiedEpoch(); got != 42 {
		t.Errorf("justifiedEpoch after stale adoption = %d, want 42 (no rollback)", got)
	}
	if got := qpos.GetFinalizedEpoch(); got != 41 {
		t.Errorf("finalizedEpoch after stale adoption = %d, want 41 (no rollback)", got)
	}
	// Roots must not be overwritten by the stale delivery either: the
	// recorded epoch root (0xA1's fallback root from the first adoption)
	// stays authoritative.
	wantRoot := r106TestHash(0xA1)
	qpos.mu.RLock()
	jRoot := qpos.justifiedRoot
	qpos.mu.RUnlock()
	if jRoot != wantRoot {
		t.Errorf("justifiedRoot changed by stale adoption: got %x, want %x", jRoot[:4], wantRoot[:4])
	}
}

// TestR106_AdoptHeaderFinality_RootPrefersRecordedEpochRoot verifies the root
// binding: when the adopted epoch's boundary root is already recorded locally
// (R101 backfill), the adopted checkpoint root must be that canonical root —
// not the header hash fallback.
func TestR106_AdoptHeaderFinality_RootPrefersRecordedEpochRoot(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(6)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	canonicalEpochRoot := r106TestHash(0xE5)
	qpos.SetEpochBlockRoot(42, canonicalEpochRoot)

	headerHash := r106TestHash(0xA1)
	qpos.AdoptHeaderFinality(42, 41, headerHash)

	qpos.mu.RLock()
	jRoot := qpos.justifiedRoot
	fRoot := qpos.finalizedRoot
	qpos.mu.RUnlock()

	if jRoot != canonicalEpochRoot {
		t.Errorf("justifiedRoot = %x, want recorded epoch root %x", jRoot[:4], canonicalEpochRoot[:4])
	}
	// Epoch 41 has no recorded root here → fallback to the header hash
	// (marker root; feeds display/ancestry only, never weight accounting).
	if fRoot != headerHash {
		t.Errorf("finalizedRoot = %x, want header hash fallback %x", fRoot[:4], headerHash[:4])
	}
}

// TestR106_AdoptHeaderFinality_EpochZeroKeepsZeroRoot verifies the genesis
// bootstrap contract: an adoption of epoch 0 without a registered genesis
// root keeps the zero hash, so the genesis-bootstrap branches in
// tryUpdateFinality (CONS-R9-L-REDO-01) remain reachable.
func TestR106_AdoptHeaderFinality_EpochZeroKeepsZeroRoot(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(6)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	headerHash := r106TestHash(0xA1)
	qpos.AdoptHeaderFinality(0, 0, headerHash)

	qpos.mu.RLock()
	jRoot, fRoot := qpos.justifiedRoot, qpos.finalizedRoot
	qpos.mu.RUnlock()

	if jRoot != (types.Hash{}) {
		t.Errorf("justifiedRoot for unregistered epoch 0 = %x, want zero hash", jRoot[:4])
	}
	if fRoot != (types.Hash{}) {
		t.Errorf("finalizedRoot for unregistered epoch 0 = %x, want zero hash", fRoot[:4])
	}
}

// TestR106_AdoptedStateLetsLiveAttestationsCount closes the loop on the
// deadlock: after adoption, an attestation whose Source is the ADOPTED
// justified epoch (the shape every live attestation has on the real network)
// must pass tryUpdateFinality's CONS-003/Source.Root gates and count toward
// the next epoch's justification.
//
// Un-fixed behavior: the same attestation is skipped (Source.Epoch 42 >
// local justifiedEpoch 0) and the node stays frozen forever.
func TestR106_AdoptedStateLetsLiveAttestationsCount(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(6)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Seed genesis time so wall-clock derives currentEpoch == 44 at the
	// moment tryUpdateFinality runs. 44 epochs of 32 slots × 12s = 16896s ≈ 4.7h.
	// Some sibling tests freeze genesis time; skip in that environment (same
	// pattern as cons_r13_m01_m04_test.go).
	slotDur := int64(SlotDuration.Seconds())
	currentEpoch := uint64(44)
	gt := time.Now().Unix() - int64(currentEpoch)*int64(SlotsPerEpoch)*slotDur - 10*slotDur // ensure we are 10+ slots INTO epoch 44
	if err := SetGenesisTime(gt); err != nil {
		t.Skipf("SetGenesisTime failed (likely frozen by a prior test): %v", err)
	}
	defer func() { _ = SetGenesisTime(time.Now().Unix()) }()

	// Adopt a state equivalent to a chain that justified epoch 42.
	justifiedRoot := r106TestHash(0xD4)
	qpos.SetEpochBlockRoot(42, justifiedRoot)
	qpos.AdoptHeaderFinality(42, 41, justifiedRoot)

	// Live attestations target the previous epoch boundary root with
	// Source = the adopted justified epoch. Set the previous-epoch
	// boundary root so the Target.Root check has its canonical value.
	prevEpoch := currentEpoch - 1
	prevEpochRoot := r106TestHash(0xF6)
	qpos.SetEpochBlockRoot(prevEpoch, prevEpochRoot)

	// 4 of 6 attesters (>= 2/3 weight) vote for prevEpoch.
	attSlot := EpochStartSlot(prevEpoch)
	for vi := 0; vi < 4; vi++ {
		att := &Attestation{
			Slot: attSlot,
			Source: AttestationCheckpoint{
				Epoch: 42,
				Root:  justifiedRoot,
			},
			Target: AttestationCheckpoint{
				Epoch: prevEpoch,
				Root:  prevEpochRoot,
			},
			ValidatorIndex:  vi,
			BeaconBlockRoot: prevEpochRoot,
		}
		// Direct insertion (bypasses ProcessAttestation's signature checks);
		// tryUpdateFinality reads attestations from the pool only.
		qpos.mu.Lock()
		qpos.attestations[attSlot] = append(qpos.attestations[attSlot], att)
		qpos.mu.Unlock()
	}

	// No SetLastKnownBlockTime needed: GetCurrentSlot is wall-clock driven;
	// genesis is 10 slots into epoch 44, so currentEpoch == 44 now.
	qpos.mu.Lock()
	qpos.tryUpdateFinality()
	justified := qpos.justifiedEpoch
	qpos.mu.Unlock()

	if justified != prevEpoch {
		t.Errorf("justifiedEpoch after ratchet = %d, want %d (adopted state must let live-source attestations count)", justified, prevEpoch)
	}
}
