// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/crypto/vdf"
)

// buildFinalizableBeacon creates a beacon for the given epoch with three
// contributions from freshly generated keys, mirroring the flow in
// random_beacon_test.go.
func buildFinalizableBeacon(epoch uint64) *RandomBeacon {
	beacon := NewRandomBeacon(epoch, 3)
	for i := 0; i < 3; i++ {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		if _, err := beacon.Contribute(kp.Private, kp.Public, 1); err != nil {
			panic(err)
		}
	}
	return beacon
}

// smallVDFConfig returns an enabled config with a tiny evaluation length so
// tests finish quickly.
func smallVDFConfig() VDFBeaconConfig {
	return VDFBeaconConfig{
		Enabled:   true,
		TimeSteps: 8,
		CRSSeed:   [32]byte{0x2a},
		Timeout:   2 * time.Minute,
	}
}

// TestDeriveVDFInputDeterministic pins the input expansion: identical
// beacon outputs must expand to identical states, and different epochs or
// randomness must diverge.
func TestDeriveVDFInputDeterministic(t *testing.T) {
	var rnd [32]byte
	for i := range rnd {
		rnd[i] = byte(i)
	}
	a := DeriveVDFInput(rnd, 7, vdf.QBC)
	b := DeriveVDFInput(rnd, 7, vdf.QBC)
	for i := range a {
		if !a[i].Equal(b[i]) {
			t.Fatalf("input expansion not deterministic at element %d", i)
		}
	}
	c := DeriveVDFInput(rnd, 8, vdf.QBC)
	same := true
	for i := range a {
		if !a[i].Equal(c[i]) {
			same = false
		}
	}
	if same {
		t.Fatal("different epochs produced identical VDF inputs")
	}
}

// TestDeriveCRSMatrixDeterministicAndCached pins CRS derivation and caching.
func TestDeriveCRSMatrixDeterministicAndCached(t *testing.T) {
	var seed [32]byte
	seed[0] = 0x2a
	m1 := DeriveCRSMatrix(seed, vdf.QBC)
	m2 := DeriveCRSMatrix(seed, vdf.QBC)
	if len(m1) != vdf.ModuleSize {
		t.Fatalf("matrix rows = %d, want %d", len(m1), vdf.ModuleSize)
	}
	for i := range m1 {
		for j := range m1[i] {
			if !m1[i][j].Equal(m2[i][j]) {
				t.Fatalf("CRS matrix not deterministic at (%d,%d)", i, j)
			}
		}
	}
	var other [32]byte
	other[0] = 0x2b
	m3 := DeriveCRSMatrix(other, vdf.QBC)
	if m3[0][0].Equal(m1[0][0]) {
		t.Fatal("different CRS seeds produced identical matrices")
	}
}

// TestFinalizeUnaffectedByVDFConfig is the activation-boundary guarantee:
// Finalize itself produces identical randomness whether or not VDF
// hardening is configured (random_beacon.go is not modified by the feature).
func TestFinalizeUnaffectedByVDFConfig(t *testing.T) {
	kps := make([]*crypto.KeyPair, 3)
	for i := range kps {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		kps[i] = kp
	}

	build := func() (*RandomBeacon, *BeaconOutput) {
		beacon := NewRandomBeacon(1, 3)
		for _, kp := range kps {
			if _, err := beacon.Contribute(kp.Private, kp.Public, 1); err != nil {
				t.Fatal(err)
			}
		}
		out, err := beacon.Finalize()
		if err != nil {
			t.Fatal(err)
		}
		return beacon, out
	}

	_, out1 := build()
	beacon2, out2 := build()
	if out1.Randomness != out2.Randomness {
		t.Fatal("identical contributions produced different randomness")
	}

	// FinalizeWithVDF with the feature disabled must not change the output.
	if _, err := beacon2.Finalize(); err == nil {
		t.Fatal("beacon should already be finalized")
	}
	cfg := smallVDFConfig()
	cfg.Enabled = false
	beacon3 := NewRandomBeacon(1, 3)
	for _, kp := range kps {
		if _, err := beacon3.Contribute(kp.Private, kp.Public, 1); err != nil {
			t.Fatal(err)
		}
	}
	out3, _, hasSeed, err := beacon3.FinalizeWithVDF(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if hasSeed {
		t.Fatal("disabled config must not produce a seed")
	}
	if out3.Randomness != out1.Randomness {
		t.Fatal("disabled VDF changed the beacon output")
	}
}

// TestFinalizeWithVDFProducesSeed covers the happy path: enabled config,
// deterministic seed across identical beacon outputs (same keys, same
// epoch), non-zero seed.
func TestFinalizeWithVDFProducesSeed(t *testing.T) {
	cfg := smallVDFConfig()

	kps := make([]*crypto.KeyPair, 3)
	for i := range kps {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		kps[i] = kp
	}

	run := func() [32]byte {
		beacon := NewRandomBeacon(1, 3)
		for _, kp := range kps {
			if _, err := beacon.Contribute(kp.Private, kp.Public, 1); err != nil {
				t.Fatal(err)
			}
		}
		_, seed, hasSeed, err := beacon.FinalizeWithVDF(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if !hasSeed {
			t.Fatal("enabled config must produce a seed")
		}
		var zero [32]byte
		if seed == zero {
			t.Fatal("seed must not be all zeros")
		}
		return seed
	}

	seed1 := run()
	seed2 := run()
	if seed1 != seed2 {
		t.Fatal("identical beacon outputs produced different VDF seeds")
	}
}

// TestApplyVDFDisabled pins the opt-in contract.
func TestApplyVDFDisabled(t *testing.T) {
	beacon := buildFinalizableBeacon(1)
	out, err := beacon.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	cfg := smallVDFConfig()
	cfg.Enabled = false
	if _, err := ApplyVDF(out, cfg); err != ErrVDFDisabled {
		t.Fatalf("got %v, want ErrVDFDisabled", err)
	}
}

// TestApplyVDFTimeout covers the degradation path: an evaluation that
// cannot finish inside the deadline returns ErrVDFTimeout.
func TestApplyVDFTimeout(t *testing.T) {
	beacon := buildFinalizableBeacon(1)
	out, err := beacon.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	cfg := smallVDFConfig()
	cfg.TimeSteps = 4_000_000 // far beyond any deadline at current speed
	cfg.Timeout = 150 * time.Millisecond
	if _, err := ApplyVDF(out, cfg); err == nil {
		t.Fatal("expected timeout error")
	}
}

// TestVerifyVDFSeed covers the D1-a recompute-verification primitive:
// honest seeds verify, tampered seeds are rejected and counted.
func TestVerifyVDFSeed(t *testing.T) {
	beacon := buildFinalizableBeacon(1)
	out, err := beacon.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	cfg := smallVDFConfig()
	seed, err := ApplyVDF(out, cfg)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyVDFSeed(seed, out, cfg)
	if err != nil || !ok {
		t.Fatalf("honest seed failed verification: ok=%v err=%v", ok, err)
	}

	before := SnapshotVDFMetrics()
	var tampered [32]byte
	copy(tampered[:], seed[:])
	tampered[0] ^= 0xff
	ok, err = VerifyVDFSeed(tampered, out, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("tampered seed passed verification")
	}
	after := SnapshotVDFMetrics()
	if after.RecomputeMismatches != before.RecomputeMismatches+1 {
		t.Fatal("mismatch counter not incremented")
	}
}

// TestEpochSeedDeterministic pins the final seed derivation.
func TestEpochSeedDeterministic(t *testing.T) {
	img1 := DeriveVDFInput([32]byte{1}, 1, vdf.QBC)
	img2 := DeriveVDFInput([32]byte{2}, 1, vdf.QBC)
	s1a := EpochSeed(img1)
	s1b := EpochSeed(img1)
	s2 := EpochSeed(img2)
	if s1a != s1b {
		t.Fatal("EpochSeed not deterministic")
	}
	if s1a == s2 {
		t.Fatal("different images produced identical seeds")
	}
}
