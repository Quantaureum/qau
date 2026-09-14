// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// stubVRFSource is a test stub implementing vrfAccumulatorSource.
// DA-R5-03 (2026-07-16).
type stubVRFSource struct {
	accumulators   map[uint64]types.Hash
	finalizedEpoch uint64
	randao         types.Hash

	// call counters for verifying tier selection
	getAccCalls    []uint64
	getFinalCalls  int
	getRANDAOCalls int
}

func (s *stubVRFSource) GetEpochVRFAccumulator(epoch uint64) types.Hash {
	s.getAccCalls = append(s.getAccCalls, epoch)
	return s.accumulators[epoch]
}

func (s *stubVRFSource) GetFinalizedEpoch() uint64 {
	s.getFinalCalls++
	return s.finalizedEpoch
}

func (s *stubVRFSource) GetRANDAO() types.Hash {
	s.getRANDAOCalls++
	return s.randao
}

// TestDA_R5_03_SelectSeed_NilQPOS returns zero hash when qpos is nil
// (matches the nil-guard in initDanksharding's closure).
func TestDA_R5_03_SelectSeed_NilQPOS(t *testing.T) {
	seed := selectDACommitteeSeed(nil, 5)
	if seed != (types.Hash{}) {
		t.Errorf("expected zero hash for nil qpos, got %x", seed)
	}
}

// TestDA_R5_03_SelectSeed_Tier1_FinalizedEpoch verifies that when a
// finalized epoch is available with a non-zero accumulator, it is used
// as the seed. This is the strongest guarantee — finalized entropy is
// immutable and cannot be ground by block withholding.
func TestDA_R5_03_SelectSeed_Tier1_FinalizedEpoch(t *testing.T) {
	finalizedAcc := types.Hash{0xAA, 0xBB, 0xCC}
	prevAcc := types.Hash{0x11, 0x22, 0x33}
	randao := types.Hash{0xFF}

	src := &stubVRFSource{
		accumulators: map[uint64]types.Hash{
			3: finalizedAcc, // finalized epoch's accumulator
			4: prevAcc,      // epoch-1's accumulator
		},
		finalizedEpoch: 3,
		randao:         randao,
	}

	seed := selectDACommitteeSeed(src, 5) // epoch 5, finalized at 3
	if seed != finalizedAcc {
		t.Errorf("expected finalized epoch's accumulator (Tier 1), got %x", seed)
	}
	if len(src.getAccCalls) != 1 {
		t.Errorf("expected 1 GetEpochVRFAccumulator call, got %d", len(src.getAccCalls))
	}
	if src.getAccCalls[0] != 3 {
		t.Errorf("expected GetEpochVRFAccumulator(3) for finalized epoch, got %d", src.getAccCalls[0])
	}
	if src.getRANDAOCalls != 0 {
		t.Errorf("RANDAO should not be called when Tier 1 succeeds, got %d calls", src.getRANDAOCalls)
	}
}

// TestDA_R5_03_SelectSeed_Tier1_NotUsedWhenFinalizedEqCurrent verifies
// that the finalized epoch is NOT used when finalizedEpoch == epoch
// (the accumulator for the current epoch is incomplete).
func TestDA_R5_03_SelectSeed_Tier1_NotUsedWhenFinalizedEqCurrent(t *testing.T) {
	finalizedAcc := types.Hash{0xAA}
	prevAcc := types.Hash{0x11}

	src := &stubVRFSource{
		accumulators: map[uint64]types.Hash{
			5: finalizedAcc, // same as epoch — should NOT be used
			4: prevAcc,      // epoch-1 — should be used (Tier 2)
		},
		finalizedEpoch: 5,
		randao:         types.Hash{0xFF},
	}

	seed := selectDACommitteeSeed(src, 5)
	if seed != prevAcc {
		t.Errorf("expected epoch-1 accumulator (Tier 2), got %x", seed)
	}
}

// TestDA_R5_03_SelectSeed_Tier1_NotUsedWhenFinalizedGtCurrent verifies
// that the finalized epoch is NOT used when finalizedEpoch > epoch
// (shouldn't happen in practice, but guard against uint64 edge cases).
func TestDA_R5_03_SelectSeed_Tier1_NotUsedWhenFinalizedGtCurrent(t *testing.T) {
	prevAcc := types.Hash{0x11}

	src := &stubVRFSource{
		accumulators: map[uint64]types.Hash{
			4: prevAcc,
		},
		finalizedEpoch: 10, // > epoch — shouldn't happen but guard anyway
		randao:         types.Hash{0xFF},
	}

	seed := selectDACommitteeSeed(src, 5)
	if seed != prevAcc {
		t.Errorf("expected epoch-1 accumulator (Tier 2) when finalized > epoch, got %x", seed)
	}
}

// TestDA_R5_03_SelectSeed_Tier2_PreviousEpoch verifies that when no
// finalized epoch is available (finalizedEpoch=0), the previous epoch's
// accumulator is used. This matches the proposer shuffle behavior.
func TestDA_R5_03_SelectSeed_Tier2_PreviousEpoch(t *testing.T) {
	prevAcc := types.Hash{0x11, 0x22, 0x33}
	randao := types.Hash{0xFF}

	src := &stubVRFSource{
		accumulators: map[uint64]types.Hash{
			4: prevAcc, // epoch-1's accumulator
		},
		finalizedEpoch: 0, // no finalized epoch yet
		randao:         randao,
	}

	seed := selectDACommitteeSeed(src, 5)
	if seed != prevAcc {
		t.Errorf("expected epoch-1 accumulator (Tier 2), got %x", seed)
	}
	if src.getRANDAOCalls != 0 {
		t.Errorf("RANDAO should not be called when Tier 2 succeeds, got %d calls", src.getRANDAOCalls)
	}
}

// TestDA_R5_03_SelectSeed_Tier2_FinalizedAccZero verifies that when
// finalizedEpoch > 0 but its accumulator is zero (not yet accumulated),
// the function falls through to Tier 2 (epoch-1's accumulator).
func TestDA_R5_03_SelectSeed_Tier2_FinalizedAccZero(t *testing.T) {
	prevAcc := types.Hash{0x11, 0x22}

	src := &stubVRFSource{
		accumulators: map[uint64]types.Hash{
			// epoch 3 (finalized) has NO accumulator entry → zero hash
			4: prevAcc, // epoch-1's accumulator
		},
		finalizedEpoch: 3,
		randao:         types.Hash{0xFF},
	}

	seed := selectDACommitteeSeed(src, 5)
	if seed != prevAcc {
		t.Errorf("expected epoch-1 accumulator (Tier 2 fallback), got %x", seed)
	}
}

// TestDA_R5_03_SelectSeed_Tier3_RANDAO verifies that when neither Tier 1
// nor Tier 2 is available (epoch 0, or no accumulators), RANDAO is used.
func TestDA_R5_03_SelectSeed_Tier3_RANDAO(t *testing.T) {
	randao := types.Hash{0xFF, 0xEE, 0xDD}

	src := &stubVRFSource{
		accumulators:   map[uint64]types.Hash{}, // no accumulators
		finalizedEpoch: 0,
		randao:         randao,
	}

	seed := selectDACommitteeSeed(src, 5)
	if seed != randao {
		t.Errorf("expected RANDAO (Tier 3), got %x", seed)
	}
	if src.getRANDAOCalls != 1 {
		t.Errorf("expected 1 GetRANDAO call, got %d", src.getRANDAOCalls)
	}
}

// TestDA_R5_03_SelectSeed_Tier3_EpochZero verifies that epoch 0 always
// falls through to RANDAO (no epoch-1 to look up).
func TestDA_R5_03_SelectSeed_Tier3_EpochZero(t *testing.T) {
	randao := types.Hash{0xFF}

	src := &stubVRFSource{
		accumulators:   map[uint64]types.Hash{},
		finalizedEpoch: 0,
		randao:         randao,
	}

	seed := selectDACommitteeSeed(src, 0)
	if seed != randao {
		t.Errorf("expected RANDAO for epoch 0, got %x", seed)
	}
}

// TestDA_R5_03_SelectSeed_DoesNotUseCurrentEpochAccumulator is the
// CRITICAL regression test: it verifies that the seed for epoch N does
// NOT use epoch N's own accumulator (the bug being fixed). Using the
// current epoch's accumulator allows the last block producer to
// withhold their VRF output and grind the DA committee shuffle.
func TestDA_R5_03_SelectSeed_DoesNotUseCurrentEpochAccumulator(t *testing.T) {
	currentAcc := types.Hash{0xAA, 0xBB, 0xCC} // epoch 5's accumulator (INCOMPLETE)
	prevAcc := types.Hash{0x11, 0x22, 0x33}    // epoch 4's accumulator (complete)

	src := &stubVRFSource{
		accumulators: map[uint64]types.Hash{
			5: currentAcc, // current epoch — MUST NOT be used
			4: prevAcc,    // previous epoch — should be used
		},
		finalizedEpoch: 0,
		randao:         types.Hash{0xFF},
	}

	seed := selectDACommitteeSeed(src, 5)
	if seed == currentAcc {
		t.Fatal("SECURITY: seed used the CURRENT epoch's accumulator — " +
			"this is the DA-R5-03 bug (last-revealer can grind by withholding blocks)")
	}
	if seed != prevAcc {
		t.Errorf("expected epoch-1 accumulator, got %x", seed)
	}
	// Verify epoch 5 was never queried
	for _, e := range src.getAccCalls {
		if e == 5 {
			t.Fatal("SECURITY: GetEpochVRFAccumulator(5) was called — " +
				"current epoch's accumulator must never be queried")
		}
	}
}

// TestDA_R5_03_SelectSeed_Tier1_PreferredOverTier2 verifies that when
// both finalized and previous-epoch accumulators are available, Tier 1
// (finalized) is preferred.
func TestDA_R5_03_SelectSeed_Tier1_PreferredOverTier2(t *testing.T) {
	finalizedAcc := types.Hash{0xAA}
	prevAcc := types.Hash{0x11}

	src := &stubVRFSource{
		accumulators: map[uint64]types.Hash{
			3: finalizedAcc,
			4: prevAcc,
		},
		finalizedEpoch: 3,
		randao:         types.Hash{0xFF},
	}

	seed := selectDACommitteeSeed(src, 5)
	if seed != finalizedAcc {
		t.Errorf("expected finalized accumulator (Tier 1 preferred), got %x", seed)
	}
	if seed == prevAcc {
		t.Error("Tier 2 should not be returned when Tier 1 is available")
	}
}
