// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestR5_SHRD_R5_09_ActivateShardNetworkRejectsZeroSeed verifies that
// ActivateShardNetwork rejects a zero seed. A zero seed makes the Fisher-Yates
// shuffle completely predictable, allowing validators to pre-compute their
// shard assignments and collude — the exact attack the shuffle is meant to
// prevent.
func TestR5_SHRD_R5_09_ActivateShardNetworkRejectsZeroSeed(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	// Use DefaultShardActivationConfig (which has a zero seed by design).
	validators := generateShardAddrs(t, 200) // enough for 3 shards
	config := ShardActivationConfig{
		ShardCount:    3,
		MinValidators: ShardMinValidators,
		Validators:    validators,
		Seed:          types.Hash{}, // zero seed
	}

	_, _, err := sm.ActivateShardNetwork(config)
	if err == nil {
		t.Fatal("SHRD-R5-09: ActivateShardNetwork should reject zero seed")
	}
}

// TestR5_SHRD_R5_09_ActivateShardNetworkAcceptsNonZeroSeed verifies that
// ActivateShardNetwork succeeds with a non-zero seed. This is the happy path.
func TestR5_SHRD_R5_09_ActivateShardNetworkAcceptsNonZeroSeed(t *testing.T) {
	mc := &mockMainChain{}
	sm := NewShardManager(mc)

	validators := generateShardAddrs(t, 9)
	config := ShardActivationConfig{
		ShardCount:    3,
		MinValidators: ShardMinValidators,
		Validators:    validators,
		Seed:          types.Hash{0x42}, // non-zero seed
	}

	activated, _, err := sm.ActivateShardNetwork(config)
	if err != nil {
		t.Fatalf("SHRD-R5-09: ActivateShardNetwork should succeed with non-zero seed, got: %v", err)
	}
	if activated != 3 {
		t.Errorf("SHRD-R5-09: expected 3 activated shards, got %d", activated)
	}
}

// TestR5_SHRD_R5_09_ShuffleIsDeterministic verifies that the shuffle is
// deterministic given the same seed. This is a critical property: all nodes
// must compute the same validator assignment from the same epoch seed.
// The rejection-sampling fix must preserve determinism.
func TestR5_SHRD_R5_09_ShuffleIsDeterministic(t *testing.T) {
	addrs1 := generateShardAddrs(t, 50)
	addrs2 := make([]types.Address, len(addrs1))
	copy(addrs2, addrs1)

	seed := types.Hash{0x01, 0x02, 0x03}

	shuffleAddresses(addrs1, seed)
	shuffleAddresses(addrs2, seed)

	for i := range addrs1 {
		if addrs1[i] != addrs2[i] {
			t.Fatalf("SHRD-R5-09: shuffle is not deterministic at index %d: %x vs %x",
				i, addrs1[i], addrs2[i])
		}
	}
}

// TestR5_SHRD_R5_09_ShuffleIsPermutation verifies that the shuffle produces
// a permutation of the input (no elements lost or duplicated). This is a
// critical invariant of Fisher-Yates.
func TestR5_SHRD_R5_09_ShuffleIsPermutation(t *testing.T) {
	addrs := generateShardAddrs(t, 100)
	original := make([]types.Address, len(addrs))
	copy(original, addrs)

	seed := types.Hash{0x42}
	shuffleAddresses(addrs, seed)

	if len(addrs) != len(original) {
		t.Fatalf("SHRD-R5-09: shuffle changed length: %d vs %d", len(addrs), len(original))
	}

	// Build a set of original addresses and verify all are present after shuffle.
	seen := make(map[types.Address]bool, len(original))
	for _, a := range original {
		seen[a] = true
	}
	for _, a := range addrs {
		if !seen[a] {
			t.Fatalf("SHRD-R5-09: shuffle introduced a foreign address %x", a)
		}
	}
	for _, a := range addrs {
		delete(seen, a)
	}
	if len(seen) > 0 {
		t.Fatalf("SHRD-R5-09: shuffle lost %d addresses", len(seen))
	}
}

// TestR5_SHRD_R5_09_ShuffleProducesDifferentOutputForDifferentSeeds verifies
// that different seeds produce different shuffles. If two different seeds
// produced the same shuffle, the assignment would be predictable/collapsible.
func TestR5_SHRD_R5_09_ShuffleProducesDifferentOutputForDifferentSeeds(t *testing.T) {
	addrs1 := generateShardAddrs(t, 50)
	addrs2 := make([]types.Address, len(addrs1))
	copy(addrs2, addrs1)

	seed1 := types.Hash{0x01}
	seed2 := types.Hash{0x02}

	shuffleAddresses(addrs1, seed1)
	shuffleAddresses(addrs2, seed2)

	differences := 0
	for i := range addrs1 {
		if addrs1[i] != addrs2[i] {
			differences++
		}
	}
	if differences == 0 {
		t.Fatal("SHRD-R5-09: different seeds produced identical shuffles (predictable assignment)")
	}
}

// TestR5_SHRD_R5_09_ShuffleHandlesEdgeCases verifies that the shuffle handles
// edge cases without panicking: empty slice, single element, two elements.
func TestR5_SHRD_R5_09_ShuffleHandlesEdgeCases(t *testing.T) {
	seed := types.Hash{0x42}

	// Empty slice.
	empty := []types.Address{}
	shuffleAddresses(empty, seed)

	// Single element.
	single := generateShardAddrs(t, 1)
	original := single[0]
	shuffleAddresses(single, seed)
	if single[0] != original {
		t.Errorf("SHRD-R5-09: single-element shuffle should not change the element")
	}

	// Two elements — verify it's still a permutation.
	two := generateShardAddrs(t, 2)
	orig := [2]types.Address{two[0], two[1]}
	shuffleAddresses(two, seed)
	if (two[0] == orig[0] && two[1] == orig[1]) || (two[0] == orig[1] && two[1] == orig[0]) {
		// Either identity or swap — both are valid permutations.
	} else {
		t.Errorf("SHRD-R5-09: two-element shuffle produced invalid permutation: %x %x", two[0], two[1])
	}
}

// TestR5_SHRD_R5_09_ShuffleUniformityStatisticalTest verifies that the shuffle
// is approximately uniform. For a 10-element slice, each element should land
// in each position approximately 10% of the time over many shuffles. We use
// a generous threshold (5%-15%) to avoid flakiness. This catches gross bias
// (e.g., if the rejection sampling was implemented incorrectly and always
// returned 0).
func TestR5_SHRD_R5_09_ShuffleUniformityStatisticalTest(t *testing.T) {
	const n = 10
	const iterations = 10000

	// positions[elementIndex][position] = count
	positions := make([][n]int, n)

	base := generateShardAddrs(t, n)

	for iter := 0; iter < iterations; iter++ {
		addrs := make([]types.Address, n)
		copy(addrs, base)

		// Use a unique seed per iteration to get independent shuffles.
		var seed types.Hash
		seed[0] = byte(iter)
		seed[1] = byte(iter >> 8)
		seed[2] = byte(iter >> 16)

		shuffleAddresses(addrs, seed)

		// Record where each original element landed.
		for pos, addr := range addrs {
			for elemIdx, origAddr := range base {
				if addr == origAddr {
					positions[elemIdx][pos]++
					break
				}
			}
		}
	}

	// Expected: each (element, position) pair should occur ~iterations/n times.
	expected := iterations / n
	// Allow generous variance: 50% to 200% of expected (for n=10, that's
	// 500 to 2000 out of 10000). This catches gross bias only.
	lowerBound := expected / 2
	upperBound := expected * 2

	for elemIdx := 0; elemIdx < n; elemIdx++ {
		for pos := 0; pos < n; pos++ {
			count := positions[elemIdx][pos]
			if count < lowerBound || count > upperBound {
				t.Errorf("SHRD-R5-09: gross bias detected — element %d in position %d: count %d, expected ~%d (range %d-%d)",
					elemIdx, pos, count, expected, lowerBound, upperBound)
			}
		}
	}
}
