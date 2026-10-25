package consensus

import (
	"testing"
	"time"
)

// FINALITY-9289 regression: after a cluster re-anchors its checkpoints to
// genesis (ReanchorFinalityToGenesis), votes carrying Source=(0, genesisRoot)
// must count toward justification again. This mirrors the mainnet failure:
// with the poisoned 9289 anchor, cross-node votes died in the CONS-003
// Source.Root binding; with the genesis anchor, the binding is exempt (epoch 0)
// and the exact same direct-insertion shape as the R106 test must justify.
func TestFinality9289_ReanchorThenGenesisSourceVoteJustifies(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(6)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Wall-clock: be ~10 slots INTO epoch 44 (same pattern as the R106 test).
	slotDur := int64(SlotDuration.Seconds())
	currentEpoch := uint64(44)
	gt := time.Now().Unix() - int64(currentEpoch)*int64(SlotsPerEpoch)*slotDur - 10*slotDur
	if err := SetGenesisTime(gt); err != nil {
		t.Skipf("SetGenesisTime failed (frozen by a prior test): %v", err)
	}
	defer func() { _ = SetGenesisTime(time.Now().Unix()) }()

	genesisRoot := r106TestHash(0x01)
	qpos.SetGenesisRoot(genesisRoot)

	// Poisoned pre-state: justified=9289 with a node-local divergent root.
	qpos.mu.Lock()
	qpos.justifiedEpoch = 9289
	qpos.justifiedRoot = r106TestHash(0xDE)
	qpos.mu.Unlock()

	if !qpos.ReanchorFinalityToGenesis() {
		t.Fatal("reanchor failed (genesis root is registered)")
	}
	qpos.mu.RLock()
	if qpos.justifiedEpoch != 0 || qpos.justifiedRoot != genesisRoot {
		qpos.mu.RUnlock()
		t.Fatalf("reanchor did not reset justified: (%d, %x)", qpos.justifiedEpoch, qpos.justifiedRoot)
	}
	if len(qpos.attestationSources) != 0 {
		qpos.mu.RUnlock()
		t.Fatalf("attestationSources not cleared")
	}
	qpos.mu.RUnlock()

	// 4 of 6 attesters (>= 2/3 weight, >= ComputeMinAttestations floor of 3)
	// vote for prevEpoch with Source=(0, genesisRoot) — the post-reanchor
	// vote shape on mainnet.
	prevEpoch := currentEpoch - 1
	prevEpochRoot := r106TestHash(0xF6)
	qpos.SetEpochBlockRoot(prevEpoch, prevEpochRoot)

	attSlot := EpochStartSlot(prevEpoch)
	for vi := 0; vi < 4; vi++ {
		att := &Attestation{
			Slot: attSlot,
			Source: AttestationCheckpoint{
				Epoch: 0,
				Root:  genesisRoot,
			},
			Target: AttestationCheckpoint{
				Epoch: prevEpoch,
				Root:  prevEpochRoot,
			},
			ValidatorIndex:  vi,
			BeaconBlockRoot: prevEpochRoot,
		}
		qpos.mu.Lock()
		qpos.attestations[attSlot] = append(qpos.attestations[attSlot], att)
		qpos.mu.Unlock()
	}

	qpos.mu.Lock()
	qpos.tryUpdateFinality()
	justified := qpos.justifiedEpoch
	qpos.mu.Unlock()

	if justified != prevEpoch {
		t.Fatalf("post-reanchor genesis-source votes did not justify: justifiedEpoch=%d, want %d", justified, prevEpoch)
	}
}

// Reanchor must fail closed when no genesis root is registered (re-anchoring
// to an unregistered root would recreate the divergence it is meant to cure).
func TestFinality9289_ReanchorFailsClosedWithoutGenesisRoot(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(6)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	if qpos.ReanchorFinalityToGenesis() {
		t.Fatal("reanchor must refuse when the genesis root is not registered")
	}
}
