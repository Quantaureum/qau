package node

import (
	"testing"

	"github.com/quantaureum/qau/rollup"
	"github.com/quantaureum/qau/types"
)

// l09ZeroSeedProvider always returns the zero epoch seed (bootstrap state).
type l09ZeroSeedProvider struct {
	validators []types.Address
}

func (p *l09ZeroSeedProvider) GetValidators() []types.Address { return p.validators }
func (p *l09ZeroSeedProvider) GetCurrentEpoch() uint64        { return 1 }
func (p *l09ZeroSeedProvider) GetEpochSeed(uint64) types.Hash { return types.Hash{} }

// AUDIT L-09: the minVRFEpoch gate is wired at startup from a config item
// whose default is 0 (inactive) — any other value is a sequencer-election
// (consensus behavior) change. This test pins the default and proves that
// activation 0 elects the same sequencer as the unwired elector.
func TestL09_MinVRFEpochGateWiredButInactive(t *testing.T) {
	defaultActivation := rollup.DefaultRollupConfig().MinVRFEpochActivation
	if defaultActivation != 0 {
		t.Fatalf("default minVRFEpoch activation is %d — the default must keep the gate inactive; a nonzero value alters sequencer-election semantics and needs an explicit approved rollout", defaultActivation)
	}
	var cfg Config
	if cfg.RollupMinVRFEpochActivation != 0 {
		t.Fatalf("zero-value node config must leave the gate inactive, got %d", cfg.RollupMinVRFEpochActivation)
	}

	provider := &l09ZeroSeedProvider{validators: []types.Address{{0x01}, {0x02}, {0x03}}}
	bare := rollup.NewQPOSSequencerElector(provider)

	wired := rollup.NewQPOSSequencerElector(provider)
	wired.SetMinVRFEpoch(cfg.RollupMinVRFEpochActivation)

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
	}
}
