// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// qrHardeningSeedSource implements both the legacy vrfAccumulatorSource and
// the optional consensusHardeningEpochReader used by the gated selector.
type qrHardeningSeedSource struct {
	acc        map[uint64]types.Hash
	finalized  uint64
	randao     types.Hash
	activation uint64
}

func (s *qrHardeningSeedSource) GetEpochVRFAccumulator(epoch uint64) types.Hash {
	return s.acc[epoch]
}
func (s *qrHardeningSeedSource) GetFinalizedEpoch() uint64 { return s.finalized }
func (s *qrHardeningSeedSource) GetRANDAO() types.Hash     { return s.randao }
func (s *qrHardeningSeedSource) ConsensusHardeningEpoch() uint64 {
	return s.activation
}

func newQRHardeningSeedSource(finalized, activation uint64) *qrHardeningSeedSource {
	return &qrHardeningSeedSource{
		acc: map[uint64]types.Hash{
			3: {0x33},
			4: {0x44},
		},
		finalized:  finalized,
		randao:     types.Hash{0x99},
		activation: activation,
	}
}

// TestSelectDACommitteeSeedGated_LegacyEquivalent anchors that an unset
// activation epoch leaves the three-tier selection byte-identical.
func TestSelectDACommitteeSeedGated_LegacyEquivalent(t *testing.T) {
	src := newQRHardeningSeedSource(3, 0)
	if got, want := selectDACommitteeSeedGated(src, 5), selectDACommitteeSeed(src, 5); got != want {
		t.Fatalf("gated seed = %x, legacy seed = %x — activation 0 must be a no-op", got, want)
	}
	src.activation = 10
	if got, want := selectDACommitteeSeedGated(src, 5), selectDACommitteeSeed(src, 5); got != want {
		t.Fatalf("epoch below activation changed: gated = %x, legacy = %x", got, want)
	}
}

// TestSelectDACommitteeSeedGated_QR22PureFunction is the QR-22 anchor: from
// the activation epoch on, the seed is a pure function of chain data, so two
// nodes at different finality progress derive the same committee.
func TestSelectDACommitteeSeedGated_QR22PureFunction(t *testing.T) {
	fast := newQRHardeningSeedSource(4, 5) // finalized epoch 4
	slow := newQRHardeningSeedSource(3, 5) // finalized epoch 3

	fastSeed := selectDACommitteeSeedGated(fast, 5)
	slowSeed := selectDACommitteeSeedGated(slow, 5)
	if fastSeed != slowSeed {
		t.Fatalf("committee seed diverged across finality progress: fast=%x slow=%x", fastSeed, slowSeed)
	}
	if want := selectDACommitteeSeedPure(fast, 5); fastSeed != want {
		t.Fatalf("gated seed = %x, pure seed = %x", fastSeed, want)
	}
	// The legacy selector must still diverge for these two sources — this is
	// the defect QR-22 describes and proves the test is not vacuous.
	if selectDACommitteeSeed(fast, 5) == selectDACommitteeSeed(slow, 5) {
		t.Fatal("legacy selectors unexpectedly agree; the QR-22 test setup is not discriminating")
	}
}

// TestSelectDACommitteeSeedPure_EmptyEpochFallback pins the deterministic
// fallback: with no accumulator the seed depends only on the epoch, never on
// the node-local RANDAO mix or finality progress.
func TestSelectDACommitteeSeedPure_EmptyEpochFallback(t *testing.T) {
	a := newQRHardeningSeedSource(0, 5)
	a.acc = nil
	a.randao = types.Hash{0x01}
	b := newQRHardeningSeedSource(9, 5)
	b.acc = nil
	b.randao = types.Hash{0x02}

	seedA := selectDACommitteeSeedPure(a, 7)
	seedB := selectDACommitteeSeedPure(b, 7)
	if seedA != seedB {
		t.Fatalf("empty-epoch fallback diverged: %x vs %x", seedA, seedB)
	}
	if seedA == (types.Hash{}) {
		t.Fatal("empty-epoch fallback must not be the zero hash")
	}
	if seedA == a.randao || seedA == b.randao {
		t.Fatal("empty-epoch fallback must not use the node-local RANDAO mix")
	}
	if seedA == selectDACommitteeSeedPure(a, 8) {
		t.Fatal("different epochs must derive different fallback seeds")
	}
}
