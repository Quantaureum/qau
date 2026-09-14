// Quantaureum Node source, version 1.0.0.
// Package node — R88-E regression tests: the producer must STAND DOWN from
// proposing for an epoch whose local schedule the R61 persistent-reject heal
// diagnosed as diverged from the canonical chain.
//
// If an election verifier heals an epoch because the local proposer schedule
// diverges from the canonical chain, the producer must stop proposing for
// that epoch. Continuing to propose from the polluted local schedule would
// deepen the divergence.
package node

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/core"
	"github.com/quantaureum/qau/types"
)

// r88eSetup builds a QPOS with 3 validators, an election verifier with a
// heal threshold of 1 (first mismatch heals), and a BlockProducer wired to
// them via a minimal Node.
func r88eSetup(t *testing.T) (*BlockProducer, *core.QPOSElectionVerifier, *consensus.QPOS, uint64, types.Address) {
	t.Helper()
	vals := []*consensus.Validator{
		{Address: types.Address{0xAA}, Stake: big.NewInt(1000), Active: true, PublicKeyBytes: []byte{1}},
		{Address: types.Address{0xBB}, Stake: big.NewInt(1000), Active: true, PublicKeyBytes: []byte{2}},
		{Address: types.Address{0xCC}, Stake: big.NewInt(1000), Active: true, PublicKeyBytes: []byte{3}},
	}
	vs, err := consensus.NewValidatorSet(vals)
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}
	qpos, err := consensus.NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}

	verifier := core.NewQPOSElectionVerifier(qpos)
	verifier.SetHealThreshold(1)

	// Use a FUTURE epoch (beyond wall-clock) so the shuffle-cache eviction
	// does not interfere, and populate its accumulator so VerifyProposer
	// reaches the real mismatch path (a missing accumulator would return
	// ErrProposerScheduleNotReady instead).
	epoch := consensus.SlotToEpoch(uint64(0)) + 10_000
	qpos.SetEpochVRFAccumulator(epoch-2, types.Hash{0x55})

	slot := epoch*consensus.SlotsPerEpoch + 5
	proposer, err := qpos.GetProposerForSlot(slot)
	if err != nil || proposer == nil {
		t.Fatalf("GetProposerForSlot: %v %v", proposer, err)
	}

	bp := &BlockProducer{
		validatorSet:  vs,
		qpos:          qpos,
		validatorAddr: proposer.Address, // the producer IS the locally-elected proposer
		node:          &Node{proposerElectionVerifier: verifier},
	}
	return bp, verifier, qpos, slot, proposer.Address
}

// TestR88E_ProducerStandsDownAfterHeal verifies the full chain: a canonical
// proposer that mismatches the local election → R61 heal (threshold 1) →
// the producer refuses to propose for that epoch even though the local
// election says it IS the proposer.
//
// Fails without the R88-E fix: isProposerForSlot returned
// (true, locally-elected proposer) — the producer kept proposing on the
// diverged schedule.
func TestR88E_ProducerStandsDownAfterHeal(t *testing.T) {
	bp, verifier, _, slot, elected := r88eSetup(t)
	epoch := consensus.SlotToEpoch(slot)

	// Sanity: not healed yet → producer proposes normally.
	if isProposer, addr := bp.isProposerForSlot(slot); !isProposer || addr != elected {
		t.Fatalf("pre-heal: expected (true, %x), got (%v, %x)", elected[:4], isProposer, addr[:4])
	}

	// Canonical chain disagrees with the local election: some other honest
	// validator signed the block for this slot. First mismatch heals
	// (threshold=1). Iterate a couple of slots of the same epoch to mimic
	// the persistent-reject pattern; the heal is keyed by epoch.
	wrongProposer := types.Address{0x99}
	for i := uint64(0); i < 3; i++ {
		if err := verifier.VerifyProposer(wrongProposer, slot+i, epoch); err == nil {
			t.Fatalf("expected mismatch error on attempt %d", i)
		}
	}
	if !verifier.IsEpochHealed(epoch) {
		t.Fatal("R61 heal did not fire after persistent rejects (setup regression)")
	}

	// R88-E: the producer must now stand down for this epoch.
	if isProposer, addr := bp.isProposerForSlot(slot); isProposer || addr != (types.Address{}) {
		t.Fatalf("post-heal: producer still proposing on diverged schedule: isProposer=%v addr=%x (R88-E regression)",
			isProposer, addr[:4])
	}
	// Same epoch, other slots — all stood down.
	if isProposer, _ := bp.isProposerForSlot(slot + 10); isProposer {
		t.Fatal("post-heal: producer proposing at another slot of the healed epoch (R88-E regression)")
	}

	// The NEXT epoch is not healed — production resumes there (the healed
	// import's SetEpochVRFAccumulator repairs the accumulator by then).
	nextEpochSlot := (epoch + 1) * consensus.SlotsPerEpoch
	qpos := bp.qpos
	qpos.SetEpochVRFAccumulator(epoch+1-2, types.Hash{0x77}) // acc for the next epoch's shuffle
	if isProposer, _ := bp.isProposerForSlot(nextEpochSlot); isProposer {
		// The locally-elected proposer for a future epoch may or may not be
		// our validator — the assertion is only that the producer does NOT
		// stand down: it must answer the election instead of (false, {}).
		t.Log("next epoch: our validator is elected and proposes (good)")
	} else if healed := verifier.IsEpochHealed(epoch + 1); healed {
		t.Fatal("next epoch incorrectly healed (heal must be epoch-scoped)")
	}
}

// TestR88E_NoHealNoStandDown verifies the producer still proposes when the
// verifier is healthy (no false stand-down).
func TestR88E_NoHealNoStandDown(t *testing.T) {
	bp, verifier, _, slot, elected := r88eSetup(t)
	epoch := consensus.SlotToEpoch(slot)

	// Healthy verification: the canonical proposer matches the local election.
	if err := verifier.VerifyProposer(elected, slot, epoch); err != nil {
		t.Fatalf("healthy VerifyProposer failed: %v", err)
	}
	if verifier.IsEpochHealed(epoch) {
		t.Fatal("epoch incorrectly marked healed on a healthy verification")
	}

	if isProposer, addr := bp.isProposerForSlot(slot); !isProposer || addr != elected {
		t.Fatalf("healthy: expected (true, %x), got (%v, %x)", elected[:4], isProposer, addr[:4])
	}
}
