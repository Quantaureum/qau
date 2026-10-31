// Quantaureum Node source, version 1.0.0.
package node

// R24 (2026-10-29) — auditor finding X03: the node-layer seal drivers used to
// abort as soon as ANY seal record existed for the slot
// (`qfs.GetFinalityRecord(slot) != nil`). A retained agreement over a
// side-branch block therefore wedged the canonical block of that slot: the
// driver refused to run, no pending seal was created, and the slot never got
// its canonical seal.
//
// The drivers now gate on `qfs.SealAlreadyCovers(slot, blockHash)`: a record
// closes the gate only when it covers EXACTLY the requested block, or when it
// is provably canonical. The tests below pin both sides of that gate through
// the executor start path (`tdilithium3SealSigningStart`), whose observable
// for "the driver ran" is the deferred-start latch (no pending seal exists in
// this fixture, so a started drive latches a deferred start instead of
// launching a session).

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
)

// r24AcceptingSigner is a consensus.ThresholdKeySigner stub whose
// verification accepts anything: the property under test is how the driver
// treats an EXISTING record, not whether the stub signature is valid.
type r24AcceptingSigner struct {
	groupKey []byte
}

func (s *r24AcceptingSigner) SignBlock(int, []byte) ([]byte, error) { return nil, nil }
func (s *r24AcceptingSigner) SignVote(int, []byte) ([]byte, error)  { return nil, nil }
func (s *r24AcceptingSigner) VerifyBlock([]byte, []byte, []byte) bool {
	return true
}
func (s *r24AcceptingSigner) VerifyVote([]byte, []byte, []byte) bool { return true }
func (s *r24AcceptingSigner) GroupPublicKey() []byte {
	return append([]byte(nil), s.groupKey...)
}
func (s *r24AcceptingSigner) IsThresholdMode() bool { return true }
func (s *r24AcceptingSigner) Threshold() int        { return 0 }
func (s *r24AcceptingSigner) AggregatePartialSignatures([]int, map[int][]byte, []byte) ([]byte, error) {
	return nil, nil
}

// r24NewDriverTestNode builds a bare node whose block producer carries a real
// QPOS with chambers and an accepting threshold signer.
func r24NewDriverTestNode(t *testing.T) (*Node, *consensus.QPOS) {
	t.Helper()
	validators := make([]*consensus.Validator, 9)
	for i := range validators {
		validators[i] = &consensus.Validator{
			Address: types.Address{byte(i + 1)},
			Stake:   new(big.Int).Mul(big.NewInt(6000), big.NewInt(1e18)),
			Active:  true,
		}
	}
	validatorSet, err := consensus.NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	qpos, err := consensus.NewQPOS(validatorSet)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qpos.InitChambers()
	// The group key is deliberately NOT Dilithium3-sized: the write-side gate
	// only records exact-size keys into the group key history, and a history
	// entry at epoch 0 would make every FUTURE epoch's lookup fail closed
	// ("no key for a future epoch"). A short key keeps the history empty, so
	// the lookup falls back to the live signer — the single-DKG-group shape
	// these tests model.
	qpos.SetThresholdSigner(&r24AcceptingSigner{
		groupKey: []byte("r24-accepting-group-key"),
	})
	node := &Node{
		config:        &Config{NetworkID: TestnetNetworkID},
		blockProducer: &BlockProducer{qpos: qpos},
	}
	return node, qpos
}

// r24DeferredStart reports whether the executor latched a deferred start for
// the slot, and for which block.
func r24DeferredStart(t *testing.T, node *Node, slot uint64) (types.Hash, bool) {
	t.Helper()
	node.tdilithium3SealDeferredMu.Lock()
	defer node.tdilithium3SealDeferredMu.Unlock()
	latch, ok := node.tdilithium3SealDeferred[slot]
	if !ok {
		return types.Hash{}, false
	}
	return latch.blockHash, true
}

// TestR24_SealDriver_ProceedsOverStaleNonCanonicalRecord requires the driver
// to RUN for the canonical block even though a stale agreement over a
// side-branch block is retained for the slot. Before R24 the driver aborted
// at the mere existence of the record and the slot was wedged forever.
func TestR24_SealDriver_ProceedsOverStaleNonCanonicalRecord(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	node, qpos := r24NewDriverTestNode(t)
	qfs := qpos.GetQTDFinality()

	const slot = uint64(32) // epoch 1
	sideBranch := types.Hash{0x5A}
	canonical := types.Hash{0xA5}

	// A side-branch agreement is learned via the P2P announcement path while
	// the canonical root is unknown. Six of the nine validators hold exactly
	// the 2/3 stake bar.
	if !qfs.ReceiveSealAnnouncement(slot, sideBranch, []byte("r24-announcement-signature"), []int{0, 1, 2, 3, 4, 5}) {
		t.Fatal("the side-branch announcement was rejected while the root was unknown")
	}
	// The canonical root lands and differs: the retained agreement is now
	// PROVABLY non-canonical.
	qpos.SetSlotBlockRoot(slot, canonical)

	// The executor start must get PAST the record check. Without a pending
	// seal it latches a deferred start (that is its "the drive ran" outcome).
	if node.tdilithium3SealSigningStart(slot, canonical, 0) {
		t.Fatal("the start reported a full session without a pending seal")
	}
	latchedHash, latched := r24DeferredStart(t, node, slot)
	if !latched {
		t.Fatal("the driver refused to run over a provably non-canonical record — the canonical seal is wedged (auditor finding X03)")
	}
	if latchedHash != canonical {
		t.Fatalf("deferred start is for %s, want the canonical %s", latchedHash.String(), canonical.String())
	}
}

// TestR24_SealDriver_StillSkipsCoveredAndCanonicalSeals is the negative
// control for the driver gate: a record covering the requested block, and a
// provably canonical record, must both still close the gate — the driver must
// not re-seal an already-sealed slot.
func TestR24_SealDriver_StillSkipsCoveredAndCanonicalSeals(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")

	t.Run("record covering the requested block", func(t *testing.T) {
		node, qpos := r24NewDriverTestNode(t)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(32)
		blockHash := types.Hash{0xA5}

		if !qfs.ReceiveSealAnnouncement(slot, blockHash, []byte("r24-announcement-signature"), []int{0, 1, 2, 3, 4, 5}) {
			t.Fatal("the announcement was rejected while the root was unknown")
		}

		if node.tdilithium3SealSigningStart(slot, blockHash, 0) {
			t.Fatal("the start reported a full session")
		}
		if _, latched := r24DeferredStart(t, node, slot); latched {
			t.Fatal("the driver ran for a slot whose agreement already covers the requested block")
		}
	})

	t.Run("provably canonical record for another block", func(t *testing.T) {
		node, qpos := r24NewDriverTestNode(t)
		qfs := qpos.GetQTDFinality()
		const slot = uint64(32)
		sealed := types.Hash{0xA5}
		other := types.Hash{0x0B}

		if !qfs.ReceiveSealAnnouncement(slot, sealed, []byte("r24-announcement-signature"), []int{0, 1, 2, 3, 4, 5}) {
			t.Fatal("the announcement was rejected while the root was unknown")
		}
		// The root lands and equals the sealed hash: the agreement is
		// canonical, so a drive for a DIFFERENT block is pointless.
		qpos.SetSlotBlockRoot(slot, sealed)

		if node.tdilithium3SealSigningStart(slot, other, 0) {
			t.Fatal("the start reported a full session")
		}
		if _, latched := r24DeferredStart(t, node, slot); latched {
			t.Fatal("the driver ran for a slot that already carries a canonical seal")
		}
	})
}
