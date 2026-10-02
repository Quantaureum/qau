// Quantaureum Node source, version 1.0.0.
package vdf

import (
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/crypto/sha3"
)

// katFile mirrors the JSON produced by the Rust reference implementation's
// KAT mode (kat.rs): deterministic SplitMix64-seeded inputs, eval only, with
// SHA3-256 hashes binding the regenerated matrix and witness.
type katFile struct {
	Seed        uint64 `json:"seed"`
	Q           uint64 `json:"q"`
	Module      int    `json:"module"`
	LogQ        int    `json:"log_q"`
	Time        int    `json:"time"`
	YAHex       string `json:"ya_hex"`
	AHash       string `json:"a_hash"`
	OutputHex   string `json:"output_hex"`
	WitnessHash string `json:"witness_hash"`
}

// katRNG is SplitMix64, bit-identical to the Rust kat_next() in
// papercraft/src/arithmetic.rs (state advances before mixing).
type katRNG struct{ state uint64 }

func (k *katRNG) next() uint64 {
	k.state += 0x9E3779B97F4A7C15
	z := k.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// subringElement mirrors Ring::random_subring: DEGREE native coefficients,
// each drawn as next() % q, mapped through BASIS.
func (k *katRNG) subringElement(q uint64) Element {
	var n [NativeDegree]uint64
	for j := range n {
		n[j] = k.next() % q
	}
	return FromNative(n, q)
}

func elemBytes(e Element) []byte {
	out := make([]byte, 0, Phi*8)
	for _, c := range e {
		for k := 0; k < 8; k++ {
			out = append(out, byte(c>>(8*uint(k))))
		}
	}
	return out
}

func elemVecBytes(v []Element) []byte {
	out := make([]byte, 0, len(v)*Phi*8)
	for _, e := range v {
		out = append(out, elemBytes(e)...)
	}
	return out
}

func hexEncode(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, digits[x>>4], digits[x&0xf])
	}
	return string(out)
}

// regenerateKAT rebuilds y_a and A from the seed in the exact order the
// Rust KAT mode draws them (y_a first, then A row-major), verifying both
// against the hashes recorded in the file.
func regenerateKAT(t *testing.T, kf katFile) (StateVector, Matrix) {
	t.Helper()
	rng := &katRNG{state: kf.Seed}

	y := make(StateVector, kf.Module)
	for i := range y {
		y[i] = rng.subringElement(kf.Q)
	}
	if got := hexEncode(elemVecBytes(y)); got != kf.YAHex {
		t.Fatal("y_a regeneration mismatch: PRNG sequence differs from reference")
	}

	a := make(Matrix, kf.Module)
	h := sha3.New256()
	for r := range a {
		a[r] = make([]Element, kf.Module*kf.LogQ)
		for c := range a[r] {
			a[r][c] = rng.subringElement(kf.Q)
			h.Write(elemBytes(a[r][c]))
		}
	}
	if got := hexEncode(h.Sum(nil)); got != kf.AHash {
		t.Fatal("A regeneration mismatch: hash differs from reference")
	}
	return y, a
}

// TestKnownAnswer is the bit-exact cross-check against the Rust reference
// implementation: identical inputs must produce an identical output image
// and an identical witness (bound by hash).
//
// This demonstrates agreement with the reference, not security: the
// reference is an unreviewed academic prototype and the sequentiality
// premise is conjectured rather than proven. Treat a pass as a determinism
// check only.
func TestKnownAnswer(t *testing.T) {
	data, err := os.ReadFile("testdata/kat_smoke.json")
	if err != nil {
		t.Fatalf("KAT file missing: %v (generate via the reference KAT mode)", err)
	}
	var kf katFile
	if err := json.Unmarshal(data, &kf); err != nil {
		t.Fatalf("KAT file malformed: %v", err)
	}
	if kf.Q != QBC || kf.Module != ModuleSize || kf.LogQ != LogQBits {
		t.Fatalf("KAT parameters do not match this build: %+v", kf)
	}

	y, a := regenerateKAT(t, kf)
	out := ExecuteVDF(y, a, 1, kf.Time, kf.Q)

	if got := hexEncode(elemVecBytes(out.OutputImage)); got != kf.OutputHex {
		t.Fatal("output image mismatch: Go eval diverges from the Rust reference")
	}
	wh := sha3.New256()
	for _, e := range out.Witness {
		wh.Write(elemBytes(e))
	}
	if got := hexEncode(wh.Sum(nil)); got != kf.WitnessHash {
		t.Fatal("witness hash mismatch: intermediate states diverge")
	}
}

// TestKnownAnswerFull runs the full-scale C-S KAT (time = 43,776) when the
// KAT_FULL environment variable points at its JSON file. Skipped by default.
func TestKnownAnswerFull(t *testing.T) {
	path := os.Getenv("KAT_FULL")
	if path == "" {
		t.Skip("set KAT_FULL=<kat json> to run the full-scale cross-check")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("KAT file missing: %v", err)
	}
	var kf katFile
	if err := json.Unmarshal(data, &kf); err != nil {
		t.Fatalf("KAT file malformed: %v", err)
	}
	y, a := regenerateKAT(t, kf)
	out := ExecuteVDF(y, a, 1, kf.Time, kf.Q)
	wh := sha3.New256()
	for _, e := range out.Witness {
		wh.Write(elemBytes(e))
	}
	if got := hexEncode(wh.Sum(nil)); got != kf.WitnessHash {
		t.Fatal("full-scale witness hash mismatch")
	}
	if got := hexEncode(elemVecBytes(out.OutputImage)); got != kf.OutputHex {
		t.Fatal("full-scale output mismatch")
	}
}
