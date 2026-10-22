// Quantaureum Node source, version 1.0.0.
package upgrade

import (
	"testing"
)

// F-11 (2026-10-21): baseline coverage for the upgrade package — version
// parsing/comparison and the ForkManager height scheduling. These gates
// decide consensus-rule activation, so the boundary heights and the
// rejection paths get explicit vectors.

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in      string
		want    Version
		wantErr bool
	}{
		{"1.2.3", Version{1, 2, 3}, false},
		{"v1.2.3", Version{1, 2, 3}, false},
		{"V2.0.0", Version{2, 0, 0}, false},
		{"0.0.1", Version{0, 0, 1}, false},
		{"", Version{}, true},
		{"1.2", Version{}, true},
		{"1.2.3.4", Version{}, true},
		{"1.2.x", Version{}, true},
		{"a.b.c", Version{}, true},
		{"-1.2.3", Version{}, true},
	}
	for _, tt := range tests {
		got, err := ParseVersion(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("ParseVersion(%q): expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseVersion(%q): %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("ParseVersion(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestVersionCompare(t *testing.T) {
	v := Version{1, 2, 3}
	if !v.Equal(Version{1, 2, 3}) {
		t.Fatal("equal versions not equal")
	}
	if !v.LessThan(Version{1, 2, 4}) {
		t.Fatal("1.2.3 not less than 1.2.4")
	}
	if !v.LessThan(Version{1, 3, 0}) {
		t.Fatal("1.2.3 not less than 1.3.0")
	}
	if !v.LessThan(Version{2, 0, 0}) {
		t.Fatal("1.2.3 not less than 2.0.0")
	}
	if !v.GreaterThan(Version{1, 2, 2}) {
		t.Fatal("1.2.3 not greater than 1.2.2")
	}
	if v.Compare(Version{1, 2, 3}) != 0 {
		t.Fatal("Compare(self) != 0")
	}
}

func TestVersionString(t *testing.T) {
	if got := (Version{1, 2, 3}).String(); got != "1.2.3" {
		t.Fatalf("String() = %q", got)
	}
}

func TestVersionCompatibility(t *testing.T) {
	vc := NewVersionCompatibility()

	// Current and minimum are compatible.
	if !vc.IsCompatible(CurrentVersion()) {
		t.Fatal("current version not compatible with itself")
	}
	if !vc.IsCompatible(MinCompatibleVersion()) {
		t.Fatal("minimum compatible version rejected")
	}

	// Older minor than the minimum is not.
	if vc.IsCompatible(Version{Major: 1, Minor: 0, Patch: 0}) && MinCompatibleVersion() != (Version{1, 0, 0}) {
		// (min IS 1.0.0 today, so this is compatible; the check below covers
		// the genuinely-below-minimum case.)
	}
	if vc.IsCompatible(Version{Major: 0, Minor: 9, Patch: 9}) {
		t.Fatal("below-minimum version accepted")
	}

	// Major mismatch is never compatible.
	if vc.IsCompatible(Version{Major: 2, Minor: 0, Patch: 0}) {
		t.Fatal("different major version accepted")
	}

	// Upper bound enforcement.
	vc.SetMaxCompatible(Version{1, 5, 0})
	if !vc.IsCompatible(Version{1, 4, 9}) {
		t.Fatal("in-range version rejected after SetMaxCompatible")
	}
	if vc.IsCompatible(Version{1, 6, 0}) {
		t.Fatal("above-maximum version accepted")
	}

	// CheckCompatibility error variants.
	if err := vc.CheckCompatibility(Version{Major: 0, Minor: 9, Patch: 0}); err == nil {
		t.Fatal("CheckCompatibility accepted below-minimum version")
	}
	if err := vc.CheckCompatibility(Version{Major: 2, Minor: 0, Patch: 0}); err == nil {
		t.Fatal("CheckCompatibility accepted major mismatch")
	}
	if err := vc.CheckCompatibility(CurrentVersion()); err != nil {
		t.Fatalf("CheckCompatibility rejected current version: %v", err)
	}
}

func TestVersionNegotiatorRequiresTrustedKey(t *testing.T) {
	vn := NewVersionNegotiator()
	// Without a trusted public key, negotiation must fail closed.
	if _, err := vn.NegotiateVersion(CurrentVersion(), nil); err == nil {
		t.Fatal("negotiation allowed without trusted public key")
	}
}

func testFork(id ForkID, height uint64) *Fork {
	return &Fork{
		ID:               id,
		Name:             string(id),
		ActivationHeight: height,
		Rules:            DefaultForkRules(),
	}
}

func TestForkManagerRegisterAndLookup(t *testing.T) {
	fm := NewForkManager()
	if err := fm.RegisterFork(testFork("alpha", 100)); err != nil {
		t.Fatalf("RegisterFork: %v", err)
	}
	if err := fm.RegisterFork(testFork("alpha", 200)); err == nil {
		t.Fatal("duplicate fork ID accepted")
	}
	// Height 0 is legal (the built-in genesis fork uses it); empty IDs are not.
	if err := fm.RegisterFork(&Fork{ID: "", ActivationHeight: 500}); err == nil {
		t.Fatal("empty fork ID accepted")
	}
	if err := fm.RegisterFork(nil); err == nil {
		t.Fatal("nil fork accepted")
	}
	if _, err := fm.GetFork("missing"); err == nil {
		t.Fatal("missing fork lookup succeeded")
	}
}

func TestForkManagerActivationBoundaries(t *testing.T) {
	fm := NewForkManager()
	if err := fm.RegisterFork(testFork("alpha", 100)); err != nil {
		t.Fatalf("RegisterFork: %v", err)
	}
	if err := fm.RegisterFork(testFork("beta", 300)); err != nil {
		t.Fatalf("RegisterFork: %v", err)
	}

	// One height BELOW activation the fork must not be active; at the
	// activation height it must be. These boundaries are consensus-critical.
	if fm.IsForkActive("alpha", 99) {
		t.Fatal("alpha active before its activation height")
	}
	if !fm.IsForkActive("alpha", 100) {
		t.Fatal("alpha not active at its activation height")
	}
	if !fm.IsForkActive("alpha", 101) {
		t.Fatal("alpha not active after its activation height")
	}
	if fm.IsForkActive("beta", 299) {
		t.Fatal("beta active before its activation height")
	}
	if !fm.IsForkActive("beta", 300) {
		t.Fatal("beta not active at its activation height")
	}
	if fm.IsForkActive("missing", 1000) {
		t.Fatal("unknown fork reported active")
	}

	// The active fork at a height is the latest activated one.
	if f := fm.GetActiveFork(150); f == nil || f.ID != "alpha" {
		t.Fatalf("GetActiveFork(150) = %v, want alpha", f)
	}
	if f := fm.GetActiveFork(400); f == nil || f.ID != "beta" {
		t.Fatalf("GetActiveFork(400) = %v, want beta", f)
	}
	// Below every registered fork, the built-in genesis fork (height 0,
	// registered by NewForkManager) governs.
	if f := fm.GetActiveFork(50); f == nil || f.ID != ForkGenesis {
		t.Fatalf("GetActiveFork(50) = %v, want genesis", f)
	}

	// Rules at a height come from the governing fork.
	if r := fm.GetRulesAtHeight(150); r == nil {
		t.Fatal("GetRulesAtHeight(150) returned nil")
	}

	// Upcoming forks and next transition height.
	if u := fm.GetUpcomingForks(150); len(u) != 1 || u[0].ID != "beta" {
		t.Fatalf("GetUpcomingForks(150) = %v, want [beta]", u)
	}
	if got := fm.NextForkHeight(150); got != 300 {
		t.Fatalf("NextForkHeight(150) = %d, want 300", got)
	}
	if fm.IsForkTransitionHeight(150) {
		t.Fatal("150 reported as a transition height")
	}
	if !fm.IsForkTransitionHeight(300) {
		t.Fatal("300 not reported as a transition height")
	}
}

func TestForkRulesCloneAndFeatures(t *testing.T) {
	r := DefaultForkRules()
	if r.IsFeatureEnabled(FeatureParallelExecution) {
		t.Fatal("parallel execution enabled by default")
	}
	r.SetFeature(FeatureParallelExecution, true, map[string]any{"workers": 4})
	if !r.IsFeatureEnabled(FeatureParallelExecution) {
		t.Fatal("SetFeature did not enable the feature")
	}
	if cfg := r.GetFeatureConfig(FeatureParallelExecution); cfg == nil || cfg["workers"] != 4 {
		t.Fatalf("GetFeatureConfig = %v", cfg)
	}

	clone := r.Clone()
	clone.SetFeature(FeatureParallelExecution, false, nil)
	if !r.IsFeatureEnabled(FeatureParallelExecution) {
		t.Fatal("Clone is shallow: mutating the clone changed the original")
	}

	// Encode/Decode round trip.
	data := r.Encode()
	decoded, err := DecodeForkRules(data)
	if err != nil {
		t.Fatalf("DecodeForkRules: %v", err)
	}
	if !decoded.IsFeatureEnabled(FeatureParallelExecution) {
		t.Fatal("decoded rules lost the feature flag")
	}
	if _, err := DecodeForkRules([]byte{0xff, 0xff, 0xff}); err == nil {
		t.Fatal("garbage data accepted by DecodeForkRules")
	}
}

func TestForkEncodeDecodeRoundTrip(t *testing.T) {
	f := testFork("gamma", 42)
	data := f.Encode()
	decoded, err := DecodeFork(data)
	if err != nil {
		t.Fatalf("DecodeFork: %v", err)
	}
	if decoded.ID != f.ID || decoded.ActivationHeight != f.ActivationHeight {
		t.Fatalf("round trip mismatch: %+v vs %+v", decoded, f)
	}
	if _, err := DecodeFork([]byte{0x00}); err == nil {
		t.Fatal("truncated fork accepted")
	}
}
