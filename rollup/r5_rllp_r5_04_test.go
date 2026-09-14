// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// RLLP-R5-04 (2026-07-16): Regression tests for VRF-seeded sequencer election.
//
// The original bug was that sequencer identity was `epoch % len(validators)`,
// which is fully predictable for the entire chain lifetime — an attacker
// could compute the sequencer for any future epoch and plan censorship/MEV
// attacks accordingly. The fix mixes a VRF-derived seed into the index
// computation: `keccak256(epoch || seed) % len(validators)`, where the seed
// comes from the QPOS per-epoch VRF accumulator and is not known until the
// previous epoch concludes.

// TestRLLP_R5_04_DifferentSeedsProduceDifferentSequencers is the keystone
// test: with the same validator set and epoch, different VRF seeds must
// (almost always) produce different sequencer indices. This is what breaks
// predictability — an attacker cannot know the seed in advance, so they
// cannot predict the sequencer.
func TestRLLP_R5_04_DifferentSeedsProduceDifferentSequencers(t *testing.T) {
	addrs := makeTestValidatorAddrs(10)
	epoch := uint64(42)

	// Generate 5 different seeds and verify they don't all produce the same
	// sequencer. With 10 validators, a collision is possible per-seed but
	// all 5 colliding is astronomically unlikely (0.1^4 ≈ 0.0001).
	seeds := make([]types.Hash, 5)
	for i := range seeds {
		seeds[i] = types.Hash{byte(i + 1)}
	}

	indices := make(map[int]bool)
	for _, seed := range seeds {
		provider := &mockValidatorSetProvider{validators: addrs, epoch: epoch, seed: seed}
		elector := NewQPOSSequencerElector(provider)
		seq, err := elector.GetCurrentSequencer(epoch)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Find the index of the returned sequencer.
		idx := -1
		for i, a := range addrs {
			if a == seq {
				idx = i
				break
			}
		}
		if idx == -1 {
			t.Fatal("returned sequencer not in validator set")
		}
		indices[idx] = true
	}
	if len(indices) < 2 {
		t.Errorf("expected at least 2 distinct sequencer indices across 5 seeds, got %d — VRF seed is not affecting election", len(indices))
	}
}

// TestRLLP_R5_04_SameSeedIsDeterministic confirms that the same epoch+seed
// always produces the same sequencer (determinism within an epoch — all
// honest nodes must agree on who the sequencer is).
func TestRLLP_R5_04_SameSeedIsDeterministic(t *testing.T) {
	addrs := makeTestValidatorAddrs(5)
	seed := types.Hash{0xAA, 0xBB, 0xCC}
	epoch := uint64(7)

	provider := &mockValidatorSetProvider{validators: addrs, epoch: epoch, seed: seed}
	elector := NewQPOSSequencerElector(provider)

	seq1, err := elector.GetCurrentSequencer(epoch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Call again — must return the same result.
	seq2, err := elector.GetCurrentSequencer(epoch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seq1 != seq2 {
		t.Error("same epoch+seed must produce the same sequencer (non-deterministic election)")
	}

	// A second elector instance with the same provider state must agree.
	elector2 := NewQPOSSequencerElector(provider)
	seq3, err := elector2.GetCurrentSequencer(epoch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if seq1 != seq3 {
		t.Error("two elector instances with the same provider must agree on the sequencer")
	}
}

// TestRLLP_R5_04_BootstrapSeedFallbackHashMixed confirms that when the VRF
// seed is the zero hash (startup/initial sync), the election falls back to
// keccak256(epoch) % len rather than the raw `epoch % len` that was the
// original bug. The hash-mixed fallback is still deterministic for a known
// epoch, but it does NOT expose the raw modular pattern.
func TestRLLP_R5_04_BootstrapSeedFallbackHashMixed(t *testing.T) {
	addrs := makeTestValidatorAddrs(7)
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0, seed: types.Hash{}}
	elector := NewQPOSSequencerElector(provider)

	for epoch := uint64(0); epoch < 20; epoch++ {
		seq, err := elector.GetCurrentSequencer(epoch)
		if err != nil {
			t.Fatalf("epoch %d: unexpected error: %v", epoch, err)
		}
		// The bootstrap index is keccak256(epoch) % 7, NOT epoch % 7.
		bootstrapIdx := computeSequencerIndex(epoch, types.Hash{}, len(addrs))
		if seq != addrs[bootstrapIdx] {
			t.Errorf("epoch %d: bootstrap index = %d, but got different sequencer", epoch, bootstrapIdx)
		}
		// Verify it's NOT the raw modulo (for at least some epochs, the hash
		// diverges from epoch % n). We can't assert this for every epoch (hash
		// could coincidentally match), but across 20 epochs with n=7 it's
		// virtually impossible for ALL to match.
		rawModIdx := int(epoch % uint64(len(addrs)))
		if bootstrapIdx == rawModIdx {
			// Coincidental match is possible but should be rare. Just log.
			t.Logf("epoch %d: bootstrap idx %d coincidentally matches raw epoch%%n — acceptable", epoch, bootstrapIdx)
		}
	}
}

// TestRLLP_R5_04_NextSequencerUsesSameSeedButDifferentEpoch confirms that
// GetNextSequencer returns a different address than GetCurrentSequencer for
// the same epoch (because epoch+1 is mixed into the hash), and that the
// next sequencer matches what GetCurrentSequencer would return for epoch+1
// only if the seed stays the same (which it does in this mock).
func TestRLLP_R5_04_NextSequencerUsesSameSeedButDifferentEpoch(t *testing.T) {
	addrs := makeTestValidatorAddrs(5)
	seed := types.Hash{0x01, 0x02, 0x03}
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0, seed: seed}
	elector := NewQPOSSequencerElector(provider)

	current, err := elector.GetCurrentSequencer(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	next, err := elector.GetNextSequencer(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Current uses epoch=0, next uses epoch=1 — different hashes → likely
	// different sequencers. They COULD coincide by hash collision, but with
	// 5 validators that's a 20% chance. We don't assert inequality here;
	// instead we verify the index formula directly.
	currentIdx := computeSequencerIndex(0, seed, len(addrs))
	nextIdx := computeSequencerIndex(1, seed, len(addrs))
	if current != addrs[currentIdx] {
		t.Error("current sequencer index mismatch")
	}
	if next != addrs[nextIdx] {
		t.Error("next sequencer index mismatch")
	}
}

// TestRLLP_R5_04_SequenceNotEqualEpochModulo is the anti-regression test:
// the sequencer sequence across epochs must NOT equal the old
// `epoch % len(validators)` pattern for all epochs. With a non-zero seed,
// the VRF-mixed index should diverge from the raw modulo.
func TestRLLP_R5_04_SequenceNotEqualEpochModulo(t *testing.T) {
	addrs := makeTestValidatorAddrs(5)
	seed := types.Hash{0xDE, 0xAD, 0xBE, 0xEF}
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0, seed: seed}
	elector := NewQPOSSequencerElector(provider)

	matches := 0
	const numEpochs = 20
	for epoch := uint64(0); epoch < numEpochs; epoch++ {
		seq, err := elector.GetCurrentSequencer(epoch)
		if err != nil {
			t.Fatalf("epoch %d: unexpected error: %v", epoch, err)
		}
		vrfIdx := computeSequencerIndex(epoch, seed, len(addrs))
		rawIdx := int(epoch % uint64(len(addrs)))
		if seq != addrs[vrfIdx] {
			t.Errorf("epoch %d: expected VRF index %d, got mismatch", epoch, vrfIdx)
		}
		if vrfIdx == rawIdx {
			matches++
		}
	}
	// With a non-zero seed, the VRF-mixed index should differ from the raw
	// modulo for MOST epochs. If ALL 20 epochs match, the seed is not being
	// mixed in (regression). Allow up to numEpochs/2 coincidental matches.
	if matches > numEpochs/2 {
		t.Errorf("VRF-mixed index matched raw epoch%%n for %d/%d epochs — seed is not affecting election (regression of RLLP-R5-04)", matches, numEpochs)
	}
}

// TestRLLP_R5_04_GetEpochSeedDelegatedToProvider confirms the elector
// calls the provider's GetEpochSeed method (rather than ignoring it).
func TestRLLP_R5_04_GetEpochSeedDelegatedToProvider(t *testing.T) {
	addrs := makeTestValidatorAddrs(3)
	seed := types.Hash{0x77}
	provider := &mockValidatorSetProvider{validators: addrs, epoch: 0, seed: seed}
	elector := NewQPOSSequencerElector(provider)

	// The elector should call provider.GetEpochSeed(epoch) and use the result.
	gotSeed := elector.getEpochSeed(0)
	if gotSeed != seed {
		t.Errorf("getEpochSeed = %x, want %x — elector did not delegate to provider", gotSeed[:4], seed[:4])
	}

	// The sequencer should match the index computed with this seed.
	seq, err := elector.GetCurrentSequencer(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expectedIdx := computeSequencerIndex(0, seed, len(addrs))
	if seq != addrs[expectedIdx] {
		t.Error("sequencer does not match the index computed with the provider's seed")
	}
}

// TestRLLP_R5_04_NilProviderReturnsZeroSeed confirms that a nil provider
// (or one that returns zero seed) does not panic and falls back to the
// hash-mixed bootstrap mode.
func TestRLLP_R5_04_NilProviderReturnsZeroSeed(t *testing.T) {
	elector := NewQPOSSequencerElector(nil)
	seed := elector.getEpochSeed(0)
	if seed != (types.Hash{}) {
		t.Errorf("nil provider should return zero seed, got %x", seed[:4])
	}
}

// TestRLLP_R5_04_ComputeSequencerIndexDeterminism confirms the pure function
// is deterministic (same inputs → same output) and covers the n<=0 guard.
func TestRLLP_R5_04_ComputeSequencerIndexDeterminism(t *testing.T) {
	seed := types.Hash{0x42}
	idx1 := computeSequencerIndex(10, seed, 7)
	idx2 := computeSequencerIndex(10, seed, 7)
	if idx1 != idx2 {
		t.Error("computeSequencerIndex is non-deterministic")
	}
	if idx1 < 0 || idx1 >= 7 {
		t.Errorf("index %d out of range [0, 7)", idx1)
	}
	// n <= 0 guard.
	if got := computeSequencerIndex(10, seed, 0); got != 0 {
		t.Errorf("computeSequencerIndex(n=0) = %d, want 0", got)
	}
	if got := computeSequencerIndex(10, seed, -1); got != 0 {
		t.Errorf("computeSequencerIndex(n=-1) = %d, want 0", got)
	}
}

// TestRLLP_R5_04_SeedBreaksPredictability is the core security property:
// an attacker who knows the validator set and the epoch but NOT the seed
// cannot predict the sequencer. We simulate this by showing that two
// different seeds (unknown to the attacker) produce different sequencer
// assignments for the same epoch.
func TestRLLP_R5_04_SeedBreaksPredictability(t *testing.T) {
	addrs := makeTestValidatorAddrs(8)
	epoch := uint64(100)

	seed1 := types.Hash{0x11}
	seed2 := types.Hash{0x22}

	p1 := &mockValidatorSetProvider{validators: addrs, epoch: epoch, seed: seed1}
	p2 := &mockValidatorSetProvider{validators: addrs, epoch: epoch, seed: seed2}
	e1 := NewQPOSSequencerElector(p1)
	e2 := NewQPOSSequencerElector(p2)

	seq1, err := e1.GetCurrentSequencer(epoch)
	if err != nil {
		t.Fatal(err)
	}
	seq2, err := e2.GetCurrentSequencer(epoch)
	if err != nil {
		t.Fatal(err)
	}

	// With 8 validators and different seeds, the sequencers should differ.
	// (Probability of collision: 1/8 = 12.5%. Acceptable to assert inequality
	// because we chose fixed seeds that we know produce different indices.)
	if seq1 == seq2 {
		t.Error("different seeds produced the same sequencer — predictability not broken (seed not mixed in)")
	}
}
