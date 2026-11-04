// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/consensus"
)

// TestWireConsensusHardening_LegacyLeavesProbeUnset pins the fail-safe
// default: with activation 0 the gate is off and no stalled-chain probe is
// installed, so QR-28/QR-42 keep their pre-audit fail-closed behavior.
func TestWireConsensusHardening_LegacyLeavesProbeUnset(t *testing.T) {
	n := &Node{config: &Config{}}
	qpos := &consensus.QPOS{}
	n.wireConsensusHardening(qpos, nil)

	if got := qpos.ConsensusHardeningEpoch(); got != 0 {
		t.Fatalf("activation epoch = %d, want 0", got)
	}
	if qpos.HardeningActive(1_000) {
		t.Fatal("hardening must be inactive with activation 0")
	}
	if qpos.ChainHasNoBlockInEpoch(7) {
		t.Fatal("no probe may be wired in legacy mode")
	}
}

// TestWireConsensusHardening_ActivationWiresGate checks that a configured
// activation epoch reaches the consensus engine and that the probe stays
// fail-closed without peers / a block store.
func TestWireConsensusHardening_ActivationWiresGate(t *testing.T) {
	n := &Node{config: &Config{ConsensusHardeningActivationEpoch: 10}}
	qpos := &consensus.QPOS{}
	n.wireConsensusHardening(qpos, nil)

	if got := qpos.ConsensusHardeningEpoch(); got != 10 {
		t.Fatalf("activation epoch = %d, want 10", got)
	}
	if qpos.HardeningActive(9) || !qpos.HardeningActive(10) {
		t.Fatal("activation boundary is not >= the configured epoch")
	}
	// The probe is wired but must not fabricate chain evidence: this node
	// has no p2p host, so the answer stays fail-closed.
	if qpos.ChainHasNoBlockInEpoch(8) {
		t.Fatal("probe must not claim an empty epoch without peer evidence")
	}
}

// TestConsensusHardeningProbe_GateShortCircuit pins the gate arithmetic:
// the probe receives the SOURCE epoch (selectionEpoch-2), so an epoch whose
// selection epoch is below activation must never consult the chain.
func TestConsensusHardeningProbe_GateShortCircuit(t *testing.T) {
	n := &Node{config: &Config{ConsensusHardeningActivationEpoch: 10}}
	if n.consensusHardeningProbe(7) { // selection epoch 9 < 10
		t.Fatal("probe must be inert below the activation epoch")
	}
	legacy := &Node{config: &Config{}}
	if legacy.consensusHardeningProbe(7) {
		t.Fatal("probe must be inert when activation is unset")
	}
}
