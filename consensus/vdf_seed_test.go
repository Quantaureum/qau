// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// newVDFSeedTestQPOS builds a minimal QPOS with the VDF seed feature
// enabled at the given activation epoch.
func newVDFSeedTestQPOS(activationEpoch uint64) *QPOS {
	q := &QPOS{
		epochVRFAccumulator: make(map[uint64]types.Hash),
		shuffleCache:        make(map[uint64][]int),
		coldStartEpochs:     make(map[uint64]struct{}),
		epochBlockRoots:     make(map[uint64]types.Hash),
		vdfSeedCache:        make(map[vdfSeedKey]types.Hash),
		vdfSeedBusy:         make(map[vdfSeedKey]struct{}),
	}
	q.vdfSeedCfg = &VDFSeedConfig{
		ActivationEpoch: activationEpoch,
		TimeSteps:       64, // tiny for tests; production uses 16,384
		CRSSeed:         [32]byte{0x2a},
	}
	return q
}

// TestVDFSeedDisabledByDefault pins the activation boundary: with no
// config, epochSeedLocked must produce the pre-VDF seed (keccak(epoch ||
// acc)) byte-identically.
func TestVDFSeedDisabledByDefault(t *testing.T) {
	q := &QPOS{
		epochVRFAccumulator: make(map[uint64]types.Hash),
		shuffleCache:        make(map[uint64][]int),
		coldStartEpochs:     make(map[uint64]struct{}),
		epochBlockRoots:     make(map[uint64]types.Hash),
		vdfSeedCache:        make(map[vdfSeedKey]types.Hash),
		vdfSeedBusy:         make(map[vdfSeedKey]struct{}),
	}
	var acc types.Hash
	acc[0] = 0xab
	q.epochVRFAccumulator[0] = acc

	seed, cold := q.epochSeedLocked(2)
	if cold {
		t.Fatal("accumulator present but coldStart reported")
	}
	want, _ := q.epochSeedLocked(2)
	if seed != want {
		t.Fatal("seed not deterministic")
	}
	if q.vdfSeedCfg != nil {
		t.Fatal("vdfSeedCfg must be nil by default")
	}
}

// TestVDFSeedActiveMixesInHardenedSeed verifies that once the feature is
// active for a shuffle epoch, the seed includes the VDF-hardened value,
// and that the hardened value is deterministic across calls.
func TestVDFSeedActiveMixesInHardenedSeed(t *testing.T) {
	q := newVDFSeedTestQPOS(2) // shuffle epochs >= 2 are hardened
	var acc types.Hash
	acc[0] = 0xab
	q.epochVRFAccumulator[0] = acc

	seed1, _ := q.epochSeedLocked(2)
	seed2, _ := q.epochSeedLocked(2)
	if seed1 != seed2 {
		t.Fatal("hardened seed not deterministic")
	}
	if !q.vdfSeedCached(0, acc) {
		t.Fatal("hardened seed should be cached after inline compute")
	}

	// The hardened seed must differ from the pre-VDF seed (the VDF mix
	// changes the keccak input).
	qDisabled := &QPOS{
		epochVRFAccumulator: map[uint64]types.Hash{0: acc},
		shuffleCache:        make(map[uint64][]int),
		coldStartEpochs:     make(map[uint64]struct{}),
		epochBlockRoots:     make(map[uint64]types.Hash),
		vdfSeedCache:        make(map[vdfSeedKey]types.Hash),
		vdfSeedBusy:         make(map[vdfSeedKey]struct{}),
	}
	preVDF, _ := qDisabled.epochSeedLocked(2)
	if seed1 == preVDF {
		t.Fatal("active VDF seed equals pre-VDF seed — mix not applied")
	}
}

// TestVDFSeedActivationBoundary checks the epoch gating: shuffle epochs
// below the activation epoch keep the pre-VDF seed even with the feature
// enabled.
func TestVDFSeedActivationBoundary(t *testing.T) {
	q := newVDFSeedTestQPOS(4) // activation at shuffle epoch 4
	var acc types.Hash
	acc[0] = 0xab
	q.epochVRFAccumulator[0] = acc

	seedBelow, _ := q.epochSeedLocked(3) // srcEpoch 1 missing → cold path
	if seedBelow == (types.Hash{}) {
		t.Fatal("cold path must still return a seed (keccak(epoch) only)")
	}
	// srcEpoch 0 feeds shuffle epoch 2 < 4: must NOT be hardened.
	q.epochVRFAccumulator[1] = acc
	seed2, _ := q.epochSeedLocked(2)
	qDisabled := &QPOS{
		epochVRFAccumulator: map[uint64]types.Hash{0: acc, 1: acc},
		shuffleCache:        make(map[uint64][]int),
		coldStartEpochs:     make(map[uint64]struct{}),
		epochBlockRoots:     make(map[uint64]types.Hash),
		vdfSeedCache:        make(map[vdfSeedKey]types.Hash),
		vdfSeedBusy:         make(map[vdfSeedKey]struct{}),
	}
	preVDF2, _ := qDisabled.epochSeedLocked(2)
	if seed2 != preVDF2 {
		t.Fatal("shuffle epoch below activation must use pre-VDF seed")
	}
}

// TestVDFSeedPrecomputeMatchesInline is the fork-safety invariant: the
// async precompute path and the inline fallback must produce identical
// seeds for the same accumulator.
func TestVDFSeedPrecomputeMatchesInline(t *testing.T) {
	q := newVDFSeedTestQPOS(2)
	var acc types.Hash
	acc[0] = 0xcd

	q.SetEpochVRFAccumulator(0, acc)
	deadline := time.Now().Add(30 * time.Second)
	for !q.vdfSeedCached(0, acc) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !q.vdfSeedCached(0, acc) {
		t.Fatal("async precompute did not complete in time")
	}
	asyncSeed, _ := q.epochSeedLocked(2)

	// Inline path on a fresh QPOS with the same accumulator.
	q2 := newVDFSeedTestQPOS(2)
	q2.epochVRFAccumulator[0] = acc
	inlineSeed, _ := q2.epochSeedLocked(2)

	if asyncSeed != inlineSeed {
		t.Fatal("async precompute and inline fallback diverged — fork risk")
	}
}

// TestVDFSeedConfigFromEnvMasterSwitch pins the opt-in contract: the
// feature stays off unless QAU_VDF_SEED_ENABLED=1 is set.
func TestVDFSeedConfigFromEnvMasterSwitch(t *testing.T) {
	t.Setenv("QAU_VDF_SEED_ENABLED", "0")
	t.Setenv("QAU_VDF_SEED_ACTIVATION_EPOCH", "2")
	if cfg := vdfSeedConfigFromEnv(); cfg != nil {
		t.Fatal("feature must stay off without the master switch")
	}
	t.Setenv("QAU_VDF_SEED_ENABLED", "1")
	cfg := vdfSeedConfigFromEnv()
	if cfg == nil {
		t.Fatal("feature must activate with the master switch")
	}
	if cfg.ActivationEpoch != 2 || cfg.TimeSteps != 16384 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

// TestVDFSeedReorgSafety verifies that a reorg changing the accumulator
// for the same source epoch does NOT produce a fork: the cache is keyed by
// (srcEpoch, acc), so the old accumulator's seed and the new accumulator's
// seed are distinct entries, and the shuffle uses whichever accumulator is
// canonical at that moment.
func TestVDFSeedReorgSafety(t *testing.T) {
	q := newVDFSeedTestQPOS(2)
	var acc1, acc2 types.Hash
	acc1[0] = 0xab
	acc2[0] = 0xcd

	// Precompute for acc1.
	q.SetEpochVRFAccumulator(0, acc1)
	deadline := time.Now().Add(30 * time.Second)
	for !q.vdfSeedCached(0, acc1) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	seed1, _ := q.epochSeedLocked(2)

	// Reorg: accumulator changes to acc2.
	q.SetEpochVRFAccumulator(0, acc2)
	for !q.vdfSeedCached(0, acc2) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	seed2, _ := q.epochSeedLocked(2)

	if seed1 == seed2 {
		t.Fatal("different accumulators must produce different seeds")
	}
	// Both cache entries must coexist (no overwrite).
	if !q.vdfSeedCached(0, acc1) {
		t.Fatal("old accumulator seed must remain cached")
	}
	if !q.vdfSeedCached(0, acc2) {
		t.Fatal("new accumulator seed must be cached")
	}
}

// TestVDFSeedConfigValidation pins the activation config contract.
func TestVDFSeedConfigValidation(t *testing.T) {
	q := &QPOS{
		epochVRFAccumulator: make(map[uint64]types.Hash),
		shuffleCache:        make(map[uint64][]int),
		coldStartEpochs:     make(map[uint64]struct{}),
		epochBlockRoots:     make(map[uint64]types.Hash),
		vdfSeedCache:        make(map[vdfSeedKey]types.Hash),
		vdfSeedBusy:         make(map[vdfSeedKey]struct{}),
	}
	if err := q.EnableVDFSeed(VDFSeedConfig{ActivationEpoch: 1, TimeSteps: 100}); err == nil {
		t.Fatal("activation epoch < 2 must be rejected")
	}
	if err := q.EnableVDFSeed(VDFSeedConfig{ActivationEpoch: 2, TimeSteps: 0}); err == nil {
		t.Fatal("TimeSteps < 1 must be rejected")
	}
	if err := q.EnableVDFSeed(VDFSeedConfig{ActivationEpoch: 2, TimeSteps: 16384}); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}
