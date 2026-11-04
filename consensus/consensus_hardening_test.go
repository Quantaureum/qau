// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"testing"
)

// TestConsensusHardeningGate_DefaultsLegacy pins the zero value: with no
// activation configured every consumer must see the legacy behavior, and the
// missing-probe path must fail closed rather than assume an empty epoch.
func TestConsensusHardeningGate_DefaultsLegacy(t *testing.T) {
	q := &QPOS{}
	if got := q.ConsensusHardeningEpoch(); got != 0 {
		t.Fatalf("default activation epoch = %d, want 0", got)
	}
	for _, epoch := range []uint64{0, 1, 2, 10_000} {
		if q.HardeningActive(epoch) {
			t.Fatalf("HardeningActive(%d) = true with activation unset", epoch)
		}
	}
	if q.ChainHasNoBlockInEpoch(7) {
		t.Fatal("ChainHasNoBlockInEpoch must fail closed when no probe is wired")
	}
	if q.VDFSeedStopped(7) {
		t.Fatal("VDFSeedStopped must be false before any failure is pinned")
	}
}

// TestConsensusHardeningGate_ActivationBoundary pins the >= semantics shared
// by all five QR follow-ups, and that resetting to 0 restores legacy.
func TestConsensusHardeningGate_ActivationBoundary(t *testing.T) {
	q := &QPOS{}
	q.SetConsensusHardeningEpoch(10)
	for _, tc := range []struct {
		epoch uint64
		want  bool
	}{
		{0, false}, {9, false}, {10, true}, {11, true}, {1_000, true},
	} {
		if got := q.HardeningActive(tc.epoch); got != tc.want {
			t.Fatalf("HardeningActive(%d) = %v, want %v", tc.epoch, got, tc.want)
		}
	}
	q.SetConsensusHardeningEpoch(0)
	if q.HardeningActive(10) {
		t.Fatal("resetting the activation epoch must restore legacy semantics")
	}
}

// TestConsensusHardeningGate_Probe checks the QR-28/QR-42 probe is only
// consulted while wired, and that unwiring restores fail-closed behavior.
func TestConsensusHardeningGate_Probe(t *testing.T) {
	q := &QPOS{}
	calls := 0
	q.SetStalledChainProbe(func(epoch uint64) bool {
		calls++
		return epoch == 7
	})
	if !q.ChainHasNoBlockInEpoch(7) {
		t.Fatal("probe should report the empty source epoch")
	}
	if q.ChainHasNoBlockInEpoch(8) {
		t.Fatal("probe should not report a non-empty source epoch")
	}
	if calls != 2 {
		t.Fatalf("probe called %d times, want 2", calls)
	}
	q.SetStalledChainProbe(nil)
	if q.ChainHasNoBlockInEpoch(7) {
		t.Fatal("unwiring the probe must fail closed")
	}
}

// TestVDFSeedStop_StandsDownOnEveryReturnPath is the QR-21 anchor: once an
// epoch is pinned, the three election entry points refuse to elect even on
// their early-return fast paths. Clearing the pin releases the stand-down.
func TestVDFSeedStop_StandsDownOnEveryReturnPath(t *testing.T) {
	q := &QPOS{}
	const epoch uint64 = 4
	slot := epoch * SlotsPerEpoch

	q.MarkVDFSeedStopped(epoch)
	if !q.VDFSeedStopped(epoch) {
		t.Fatal("epoch must be pinned after MarkVDFSeedStopped")
	}
	if _, err := q.GetProposerForSlot(slot); !errors.Is(err, ErrVDFSeedUnavailable) {
		t.Fatalf("GetProposerForSlot error = %v, want ErrVDFSeedUnavailable", err)
	}
	if got := q.GetProposerIndexForSlot(slot); got != -1 {
		t.Fatalf("GetProposerIndexForSlot = %d, want -1", got)
	}
	if q.IsProposerScheduleReadyForEpoch(epoch) {
		t.Fatal("IsProposerScheduleReadyForEpoch must stand down for a pinned epoch")
	}
	// A different epoch is unaffected.
	if q.VDFSeedStopped(epoch + 1) {
		t.Fatal("stand-down must be scoped to its own epoch")
	}

	q.ClearVDFSeedStopped(epoch)
	if q.VDFSeedStopped(epoch) {
		t.Fatal("ClearVDFSeedStopped must release the pin")
	}
}

// TestVDFSeedActiveFor_OnlyWhenConfigured guards a subtle QR-21 boundary:
// vdfSeedFor reports "unavailable" both before the VDF feature is configured
// and after a real evaluation failure. Only the latter may stand a node down,
// otherwise every network without VDFSeedActivationEpoch would halt forever.
func TestVDFSeedActiveFor_OnlyWhenConfigured(t *testing.T) {
	q := &QPOS{}
	q.SetConsensusHardeningEpoch(10)
	if q.vdfSeedActiveFor(10) {
		t.Fatal("VDF seed must be inactive before EnableVDFSeed")
	}
	if err := q.EnableVDFSeed(VDFSeedConfig{ActivationEpoch: 10, TimeSteps: 16_384}); err != nil {
		t.Fatalf("EnableVDFSeed: %v", err)
	}
	if q.vdfSeedActiveFor(9) {
		t.Fatal("VDF seed must be inactive below its own activation epoch")
	}
	if !q.vdfSeedActiveFor(10) {
		t.Fatal("VDF seed must be active at its activation epoch")
	}
}
