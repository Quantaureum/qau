package rollup

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/types"
)

// l09Provider is a minimal ValidatorSetProvider whose epoch seed is always the
// zero hash, i.e. the bootstrap state the P3-RL-05 gate is about.
type l09Provider struct {
	validators []types.Address
	epoch      uint64
}

func (p *l09Provider) GetValidators() []types.Address { return p.validators }
func (p *l09Provider) GetCurrentEpoch() uint64        { return p.epoch }
func (p *l09Provider) GetEpochSeed(uint64) types.Hash { return types.Hash{} }

func newL09Provider() *l09Provider {
	return &l09Provider{
		validators: []types.Address{{0x01}, {0x02}, {0x03}},
		epoch:      7,
	}
}

// AUDIT L-09: with the activation value left at 0 the gate is inert — the
// wired elector must elect exactly the same sequencer as an untouched one
// (i.e. "inactive behavior is identical to current behavior").
func TestL09_MinVRFEpochZeroMatchesUnwiredBehavior(t *testing.T) {
	bare := NewQPOSSequencerElector(newL09Provider())
	wired := NewQPOSSequencerElector(newL09Provider())
	wired.SetMinVRFEpoch(0)

	for _, epoch := range []uint64{0, 1, 7, 1000000} {
		want, err := bare.GetCurrentSequencer(epoch)
		if err != nil {
			t.Fatalf("unwired elector failed for epoch %d: %v", epoch, err)
		}
		got, err := wired.GetCurrentSequencer(epoch)
		if err != nil {
			t.Fatalf("epoch %d: activation 0 must not defer election: %v", epoch, err)
		}
		if got != want {
			t.Fatalf("epoch %d: activation 0 changed the elected sequencer: got %x want %x", epoch, got, want)
		}

		wantNext, err := bare.GetNextSequencer(epoch)
		if err != nil {
			t.Fatalf("unwired elector failed for next epoch %d: %v", epoch, err)
		}
		gotNext, err := wired.GetNextSequencer(epoch)
		if err != nil {
			t.Fatalf("next epoch %d: activation 0 must not defer election: %v", epoch, err)
		}
		if gotNext != wantNext {
			t.Fatalf("next epoch %d: activation 0 changed the elected sequencer: got %x want %x", epoch, gotNext, wantNext)
		}
	}
}

// AUDIT L-09: with a positive activation the gate actually fires (proving the
// wiring is functional, not dead code), while epochs below the threshold keep
// the bootstrap fallback.
func TestL09_MinVRFEpochPositiveDefersElection(t *testing.T) {
	e := NewQPOSSequencerElector(newL09Provider())
	e.SetMinVRFEpoch(1)

	if _, err := e.GetCurrentSequencer(100); !errors.Is(err, ErrVRFSeedNotAvailable) {
		t.Fatalf("expected ErrVRFSeedNotAvailable, got %v", err)
	}
	if _, err := e.GetNextSequencer(0); !errors.Is(err, ErrVRFSeedNotAvailable) {
		t.Fatalf("expected ErrVRFSeedNotAvailable from GetNextSequencer, got %v", err)
	}

	// Epoch 0 is below the threshold: bootstrap fallback stays legal.
	if _, err := e.GetCurrentSequencer(0); err != nil {
		t.Fatalf("epoch 0 must keep the bootstrap fallback: %v", err)
	}
}
