// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// =============================================================================
// DA-R7-03 / DA-R7-04 / DA-R7-05 Closure Tests (2026-07-17)
//
// DA-R7-03 [HIGH] FRI NumQueries insufficient — raised 50 → 80
// DA-R7-04 [HIGH] KZGCommitment truncated to types.Hash — type changed to []KZGCommitment
// DA-R7-05 [HIGH] GF64Inverse non-constant-time — fixed via ctSelect/ctReduceOnce
// =============================================================================

// TestDA_R7_03_NumQueriesRaisedTo80 verifies that DefaultFRIConfig
// produces NumQueries=80, the production-grade value that gives
// >= 100-bit reliability (theoretical 2^(-160)).
func TestDA_R7_03_NumQueriesRaisedTo80(t *testing.T) {
	cfg := DefaultFRIConfig(64) // polyDegree=64, common test size
	if cfg.NumQueries != 80 {
		t.Fatalf("DA-R7-03: expected NumQueries=80, got %d", cfg.NumQueries)
	}
	if cfg.NumQueries < 80 {
		t.Fatalf("DA-R7-03: NumQueries must be >= 80 for >= 100-bit reliability, got %d", cfg.NumQueries)
	}
	t.Logf("DA-R7-03 CLOSED: NumQueries=%d (theoretical reliability 2^(-160))", cfg.NumQueries)
}

// TestDA_R7_03_NumQueriesConsistentAcrossPolyDegrees verifies that the
// 80-query floor is independent of polyDegree (it's a fixed constant).
func TestDA_R7_03_NumQueriesConsistentAcrossPolyDegrees(t *testing.T) {
	for _, deg := range []int{4, 16, 64, 256, 1024} {
		cfg := DefaultFRIConfig(deg)
		if cfg.NumQueries != 80 {
			t.Errorf("polyDegree=%d: expected NumQueries=80, got %d", deg, cfg.NumQueries)
		}
	}
}

// TestDA_R7_04_KZGCommitmentIs48Bytes verifies that KZGCommitment is
// exactly 48 bytes (the production KZG commitment size), not 32 bytes
// (types.Hash, which was the truncated legacy form).
func TestDA_R7_04_KZGCommitmentIs48Bytes(t *testing.T) {
	var c KZGCommitment
	if size := len(c[:]); size != 48 {
		t.Fatalf("DA-R7-04: KZGCommitment must be 48 bytes, got %d", size)
	}
}

// TestDA_R7_04_DASAttestationBlobCommitmentsIsKZGCommitment verifies
// that DASAttestation.BlobCommitments is []KZGCommitment (not []types.Hash).
// This is the core type change that eliminates 48→32 byte truncation.
func TestDA_R7_04_DASAttestationBlobCommitmentsIsKZGCommitment(t *testing.T) {
	att := &DASAttestation{
		BlobCommitments: []KZGCommitment{{0x01}},
	}
	if len(att.BlobCommitments) != 1 {
		t.Fatalf("expected 1 commitment, got %d", len(att.BlobCommitments))
	}
	// Each entry must be 48 bytes.
	if size := len(att.BlobCommitments[0][:]); size != 48 {
		t.Errorf("DA-R7-04: BlobCommitments[0] must be 48 bytes, got %d", size)
	}
}

// TestDA_R7_04_NoTruncationInHash verifies that two distinct 48-byte
// commitments that map to the SAME legacy 32-byte types.Hash produce
// DIFFERENT attestation hashes. This is the core security property: the
// legacy 32-byte truncation would have produced identical hashes for such
// a pair, enabling cross-set attestation reuse.
//
// DA-R7-04 specifically guards against: attacker crafts two KZGCommitments
// c1, c2 where c1 != c2 but types.BytesToHash(c1[:]) == types.BytesToHash(c2[:]).
// With the old []types.Hash form, both would map to the same hash. With the
// new []KZGCommitment form (full 48 bytes), the hashes must differ.
//
// NOTE on types.BytesToHash behavior: when input length > 32, it takes the
// LAST 32 bytes (b[len(b)-HashLength:]). So for a 48-byte commitment, the
// legacy hash is derived from bytes 16..47. To make c1 and c2 share the
// same legacy hash while being distinct commitments, they must share bytes
// 16..47 and differ in bytes 0..15.
func TestDA_R7_04_NoTruncationInHash(t *testing.T) {
	// Two commitments sharing the LAST 32 bytes (16..47) but differing in
	// the FIRST 16 bytes (0..15). types.BytesToHash takes the last 32 bytes
	// of a 48-byte input, so both produce the same legacy BlobCommitment.
	c1 := KZGCommitment{}
	c2 := KZGCommitment{}
	for i := 0; i < 16; i++ {
		c1[i] = 0xAA // first 16 bytes differ
		c2[i] = 0xCC
	}
	for i := 16; i < 48; i++ {
		c1[i] = 0xBB // last 32 bytes identical
		c2[i] = 0xBB
	}

	att1 := &DASAttestation{
		Slot:            1,
		BlobCommitment:  types.BytesToHash(c1[:]), // legacy field: truncated (same for both)
		BlobCommitments: []KZGCommitment{c1},
	}
	att2 := &DASAttestation{
		Slot:            1,
		BlobCommitment:  types.BytesToHash(c2[:]), // legacy field: truncated (same for both)
		BlobCommitments: []KZGCommitment{c2},
	}

	// Sanity: legacy BlobCommitment field IS the same (truncation effect).
	if att1.BlobCommitment != att2.BlobCommitment {
		t.Fatalf("test setup error: legacy BlobCommitment must be identical, got %x vs %x",
			att1.BlobCommitment, att2.BlobCommitment)
	}

	// Core assertion: full Hash() must differ because BlobCommitments
	// carries the full 48 bytes (including byte 32 where c1 and c2 differ).
	if att1.Hash() == att2.Hash() {
		t.Fatal("DA-R7-04 NOT FIXED: Two commitments differing only in bytes 32..47 produced the same hash. The 48-byte form must be used.")
	}
	t.Log("DA-R7-04 CLOSED: Two commitments differing only in bytes 32..47 produce different hashes (no truncation)")
}

// TestDA_R7_04_EncodeUses48BytesPerCommitment verifies that the encoded
// size grows by exactly 48 bytes per additional commitment (not 32).
func TestDA_R7_04_EncodeUses48BytesPerCommitment(t *testing.T) {
	att0 := &DASAttestation{Slot: 1, BlobCommitments: nil}
	att1 := &DASAttestation{Slot: 1, BlobCommitments: []KZGCommitment{{0x01}}}
	att2 := &DASAttestation{Slot: 1, BlobCommitments: []KZGCommitment{{0x01}, {0x02}}}

	s0 := len(att0.Encode())
	s1 := len(att1.Encode())
	s2 := len(att2.Encode())

	if s1-s0 != 48 {
		t.Errorf("DA-R7-04: expected +48 bytes per commitment, got +%d", s1-s0)
	}
	if s2-s1 != 48 {
		t.Errorf("DA-R7-04: expected +48 bytes per commitment, got +%d", s2-s1)
	}
}

// TestDA_R7_04_EncodeDecodeRoundTrip48Bytes verifies that a full 48-byte
// commitment survives Encode → Decode without truncation.
func TestDA_R7_04_EncodeDecodeRoundTrip48Bytes(t *testing.T) {
	original := KZGCommitment{}
	for i := 0; i < 48; i++ {
		original[i] = byte(i + 1) // all 48 bytes set, including bytes 32..47
	}
	att := &DASAttestation{
		Slot:            42,
		BlobCommitment:  types.BytesToHash(original[:]),
		BlobCommitments: []KZGCommitment{original},
	}

	encoded := att.Encode()
	decoded, err := DecodeDASAttestation(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if len(decoded.BlobCommitments) != 1 {
		t.Fatalf("expected 1 commitment, got %d", len(decoded.BlobCommitments))
	}
	// All 48 bytes must survive the round trip.
	for i := 0; i < 48; i++ {
		if decoded.BlobCommitments[0][i] != original[i] {
			t.Fatalf("DA-R7-04: byte %d lost in round trip: got 0x%02x, want 0x%02x",
				i, decoded.BlobCommitments[0][i], original[i])
		}
	}
	t.Log("DA-R7-04: All 48 bytes survive Encode → Decode round trip")
}

// TestDA_R7_04_AggregateEncodeDecodeRoundTrip48Bytes verifies the same
// for DASAggregateAttestation.
func TestDA_R7_04_AggregateEncodeDecodeRoundTrip48Bytes(t *testing.T) {
	original := KZGCommitment{}
	for i := 0; i < 48; i++ {
		original[i] = byte(0xFF - i)
	}
	agg := &DASAggregateAttestation{
		Slot:            1,
		BlobCommitments: []KZGCommitment{original},
		AvailableCount:  1,
		TotalCount:      1,
	}

	encoded := agg.Encode()
	decoded, err := DecodeDASAggregateAttestation(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(decoded.BlobCommitments) != 1 {
		t.Fatalf("expected 1 commitment, got %d", len(decoded.BlobCommitments))
	}
	for i := 0; i < 48; i++ {
		if decoded.BlobCommitments[0][i] != original[i] {
			t.Fatalf("DA-R7-04: aggregate byte %d lost: got 0x%02x, want 0x%02x",
				i, decoded.BlobCommitments[0][i], original[i])
		}
	}
}

// =============================================================================
// DA-R7-05: Constant-time Goldilocks field arithmetic
// =============================================================================

// TestDA_R7_05_GF64InverseConstantTime verifies that GF64Inverse runs in
// (approximately) constant time regardless of input value. The
// implementation must NOT branch on the input.
//
// Method: run GF64Inverse many times for a small input vs a large input
// and measure the total time for each batch. The ratio should be close
// to 1.0 (within 2x to allow for noise). A non-constant-time impl would
// show >5x variance.
func TestDA_R7_05_GF64InverseConstantTime(t *testing.T) {
	small := GF64Element(2)
	large := GF64Element(GoldilocksP - 2) // large value, all bits set in representation

	const iterations = 50000

	// Warm up.
	for i := 0; i < 1000; i++ {
		_, _ = GF64Inverse(small)
		_, _ = GF64Inverse(large)
	}

	start := time.Now()
	for i := 0; i < iterations; i++ {
		_, _ = GF64Inverse(small)
	}
	smallTime := time.Since(start)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		_, _ = GF64Inverse(large)
	}
	largeTime := time.Since(start)

	ratio := float64(smallTime) / float64(largeTime)
	if ratio < 0.5 || ratio > 2.0 {
		t.Errorf("DA-R7-05: GF64Inverse not constant-time: small=%v, large=%v, ratio=%.2f (want 0.5..2.0)",
			smallTime, largeTime, ratio)
	}
	t.Logf("DA-R7-05 CLOSED: GF64Inverse small=%v large=%v ratio=%.2f (constant-time within 2x)",
		smallTime, largeTime, ratio)
}

// TestDA_R7_05_GF64PowConstantTime verifies GF64Pow runs the same number
// of iterations regardless of exponent value (fixed 64-iteration loop).
func TestDA_R7_05_GF64PowConstantTime(t *testing.T) {
	base := GF64Element(7)
	expSmall := uint64(1)                  // only bit 0 set
	expLarge := uint64(0xFFFFFFFFFFFFFFFF) // all bits set

	const iterations = 50000

	// Warm up.
	for i := 0; i < 1000; i++ {
		_ = GF64Pow(base, expSmall)
		_ = GF64Pow(base, expLarge)
	}

	start := time.Now()
	for i := 0; i < iterations; i++ {
		_ = GF64Pow(base, expSmall)
	}
	smallTime := time.Since(start)

	start = time.Now()
	for i := 0; i < iterations; i++ {
		_ = GF64Pow(base, expLarge)
	}
	largeTime := time.Since(start)

	ratio := float64(smallTime) / float64(largeTime)
	if ratio < 0.5 || ratio > 2.0 {
		t.Errorf("DA-R7-05: GF64Pow not constant-time: small=%v, large=%v, ratio=%.2f (want 0.5..2.0)",
			smallTime, largeTime, ratio)
	}
	t.Logf("DA-R7-05 CLOSED: GF64Pow small=%v large=%v ratio=%.2f (constant-time within 2x)",
		smallTime, largeTime, ratio)
}

// TestDA_R7_05_GF64InverseCorrectness verifies GF64Inverse still produces
// correct results after the constant-time refactor.
func TestDA_R7_05_GF64InverseCorrectness(t *testing.T) {
	testCases := []GF64Element{
		1,
		2,
		7,
		123456789,
		GF64Element(GoldilocksP - 1),
		GF64Element(GoldilocksP / 2),
	}
	for _, a := range testCases {
		inv, err := GF64Inverse(a)
		if err != nil {
			t.Errorf("GF64Inverse(%d) returned error: %v", a, err)
			continue
		}
		// a * a^(-1) ≡ 1 (mod p)
		product := GF64Mul(a, inv)
		if product != 1 {
			t.Errorf("GF64Inverse(%d) * %d = %d, want 1", a, inv, product)
		}
	}
}

// TestDA_R7_05_GF64AddMatchesModularArithmetic is a deterministic replacement
// for the deleted TestDA_R7_05_GF64AddConstantTime (R38-Plan Batch 0.2). The
// old benchmark used wall-clock timing and produced ratio=0 under scheduler
// jitter and low timer resolution (R38 regression §2). This oracle compares
// GF64Add against big.Int addition mod GoldilocksP, an independent
// implementation that exercises the same reduction cases the original
// constant-time branch covered: zero, small (no carry), boundary reduction,
// near-double-p, and the uint64 carry path.
func TestDA_R7_05_GF64AddMatchesModularArithmetic(t *testing.T) {
	p := new(big.Int).SetUint64(GoldilocksP)

	cases := []struct {
		name string
		a, b uint64
	}{
		{"zero+zero", 0, 0},
		{"one+one", 1, 1},
		{"reduce at p", GoldilocksP, 0},                 // p + 0 -> 0 (p reduces to 0)
		{"p-1 + 1", GoldilocksP - 1, 1},                 // boundary: sum = p -> 0
		{"p-1 + p-1", GoldilocksP - 1, GoldilocksP - 1}, // 2p-2 -> p-2
		{"uint64 carry max+1", ^uint64(0), 1},           // 2^64-1 + 1 = 2^64 -> 2^32-1 (mod p)
		{"carry at 2^64-1 + 2^32-1", ^uint64(0), (1 << 32) - 1},
		{"random-ish 0xdeadbeef", 0xdeadbeefcafebabe, 0x1234567890abcdef},
		{"one below p top", GoldilocksP - (1 << 32), (1 << 32)},
		{"two below p", GoldilocksP - 2, GoldilocksP - 2},
	}

	for _, tc := range cases {
		actual := uint64(GF64Add(GF64Element(tc.a), GF64Element(tc.b)))

		sum := new(big.Int).SetUint64(tc.a)
		sum.Add(sum, new(big.Int).SetUint64(tc.b))
		sum.Mod(sum, p)
		expected := sum.Uint64()

		if actual != expected {
			t.Errorf("DA-R7-05 GF64Add(%s): a=0x%x b=0x%x; got 0x%x, want 0x%x",
				tc.name, tc.a, tc.b, actual, expected)
		}
	}
}

// TestDA_R7_05_ctSelect verifies the constant-time select helper.
func TestDA_R7_05_ctSelect(t *testing.T) {
	x := GF64Element(0x1111111111111111)
	y := GF64Element(0x2222222222222222)

	if got := ctSelect(0, x, y); got != y {
		t.Errorf("ctSelect(0, x, y) = %x, want y=%x", got, y)
	}
	if got := ctSelect(1, x, y); got != x {
		t.Errorf("ctSelect(1, x, y) = %x, want x=%x", got, x)
	}
}

// TestDA_R7_05_ctReduceOnce verifies the constant-time conditional reduction.
func TestDA_R7_05_ctReduceOnce(t *testing.T) {
	// v < p: should return v unchanged.
	v := uint64(100)
	if got := ctReduceOnce(v); got != v {
		t.Errorf("ctReduceOnce(%d) = %d, want %d", v, got, v)
	}
	// v >= p: should return v - p.
	v = GoldilocksP + 5
	if got := ctReduceOnce(v); got != 5 {
		t.Errorf("ctReduceOnce(p+5) = %d, want 5", got)
	}
	// v == p: should return 0.
	v = GoldilocksP
	if got := ctReduceOnce(v); got != 0 {
		t.Errorf("ctReduceOnce(p) = %d, want 0", got)
	}
}

// =============================================================================
// DA-R7-08 Closure Tests (2026-07-17)
//
// DA-R7-08 [MEDIUM] FRIConfig.DomainSize must be a power of 2 (NTT/FFT requires
// it; non-power-of-2 causes biased hash mod domainSize index generation).
// =============================================================================

// TestDA_R7_08_DefaultFRIConfig_RoundsPolyDegreeToPowerOf2 verifies that
// DefaultFRIConfig rounds polyDegree UP to the next power of 2 so that
// DomainSize = polyDegree * 4 is also a power of 2.
func TestDA_R7_08_DefaultFRIConfig_RoundsPolyDegreeToPowerOf2(t *testing.T) {
	cases := []struct {
		input int
		want  int // expected effective polyDegree (power of 2)
	}{
		{1, 1},
		{2, 2},
		{3, 4}, // 3 → 4
		{4, 4},
		{5, 8}, // 5 → 8
		{6, 8},
		{7, 8},
		{8, 8},
		{9, 16},  // 9 → 16
		{64, 64}, // already power of 2
		{100, 128},
		{256, 256},
		{1000, 1024},
	}
	for _, c := range cases {
		cfg := DefaultFRIConfig(c.input)
		// DomainSize must be a power of 2.
		if cfg.DomainSize <= 0 || cfg.DomainSize&(cfg.DomainSize-1) != 0 {
			t.Errorf("input=%d: DomainSize=%d is not a power of 2", c.input, cfg.DomainSize)
		}
		// DomainSize must equal the rounded polyDegree * 4.
		if cfg.DomainSize != c.want*4 {
			t.Errorf("input=%d: expected DomainSize=%d (polyDegree=%d*4), got %d",
				c.input, c.want*4, c.want, cfg.DomainSize)
		}
	}
}

// TestDA_R7_08_FRIDACommitBlob_RejectsNonPowerOf2DomainSize verifies that
// FRIDACommitBlob rejects a FRIConfig with a non-power-of-2 DomainSize.
// Without this check, an attacker (or careless caller) could trigger biased
// index generation in FRI helpers, silently degrading reliability.
func TestDA_R7_08_FRIDACommitBlob_RejectsNonPowerOf2DomainSize(t *testing.T) {
	blob := []byte("test blob for non-power-of-2 domain size rejection")
	// 60 is not a power of 2 (the next power of 2 is 64).
	bad := FRIConfig{DomainSize: 60, CodeRate: 4, NumQueries: 10, FinalLayerSize: 4}
	if _, err := FRIDACommitBlob(blob, bad); err == nil {
		t.Error("DA-R7-08: FRIDACommitBlob accepted DomainSize=60 (not a power of 2)")
	}
	// 7 is not a power of 2.
	bad = FRIConfig{DomainSize: 7, CodeRate: 4, NumQueries: 10, FinalLayerSize: 4}
	if _, err := FRIDACommitBlob(blob, bad); err == nil {
		t.Error("DA-R7-08: FRIDACommitBlob accepted DomainSize=7 (not a power of 2)")
	}
	// 64 IS a power of 2 — must be accepted.
	good := FRIConfig{DomainSize: 64, CodeRate: 4, NumQueries: 10, FinalLayerSize: 4}
	if _, err := FRIDACommitBlob(blob, good); err != nil {
		t.Errorf("DA-R7-08: FRIDACommitBlob rejected valid DomainSize=64 (power of 2): %v", err)
	}
}

// TestDA_R7_08_FRIDAVerifyCell_RejectsNonPowerOf2CommitmentDomainSize
// verifies that FRIDAVerifyCell rejects a commitment whose DomainSize is
// not a power of 2. Such a commitment cannot have been produced by
// FRIDACommitBlob (which rejects non-power-of-2 DomainSize), so it must be
// attacker-crafted and should be rejected.
func TestDA_R7_08_FRIDAVerifyCell_RejectsNonPowerOf2CommitmentDomainSize(t *testing.T) {
	// Build a real commitment first (DomainSize=64, power of 2).
	blob := []byte("verify-cell non-power-of-2 commitment rejection")
	cfg := DefaultFRIConfig(16) // polyDegree=16 → DomainSize=64
	blobData, err := FRIDACommitBlob(blob, cfg)
	if err != nil {
		t.Fatalf("FRIDACommitBlob failed: %v", err)
	}
	cellIndex := 0
	proof, err := FRIDAGenerateCellProof(blobData, cellIndex)
	if err != nil {
		t.Fatalf("FRIDAGenerateCellProof failed: %v", err)
	}
	cell, err := FRIDAGetCellValue(blobData, cellIndex)
	if err != nil {
		t.Fatalf("FRIDAGetCellValue failed: %v", err)
	}

	// Sanity: the legitimate commitment verifies.
	if !FRIDAVerifyCell(cell, blobData.Commitment, proof, cellIndex) {
		t.Fatal("test setup error: legitimate cell did not verify")
	}

	// Tamper: set DomainSize to 60 (not a power of 2). FRIDAVerifyCell must
	// reject this — it cannot have come from FRIDACommitBlob.
	tampered := *blobData.Commitment
	tampered.DomainSize = 60
	if FRIDAVerifyCell(cell, &tampered, proof, cellIndex) {
		t.Error("DA-R7-08: FRIDAVerifyCell accepted a commitment with DomainSize=60 (not a power of 2)")
	}

	// Tamper: set DomainSize to 0 (also not a power of 2; also would cause
	// cellIndex >= DomainSize to be true, but the power-of-2 check must
	// still reject independently).
	tampered = *blobData.Commitment
	tampered.DomainSize = 0
	if FRIDAVerifyCell(cell, &tampered, proof, cellIndex) {
		t.Error("DA-R7-08: FRIDAVerifyCell accepted a commitment with DomainSize=0")
	}
}

// =============================================================================
// DA-R7-12 [LOW] BlobTxSidecar.Validate uses hash stub
//
// Validate performs only data-integrity validation via Keccak256/SHA3 hash
// stubs, NOT a polynomial commitment check. In production mode
// (QAU_PRODUCTION=1), Validate MUST refuse to run — the hash stub gives a
// false sense of DA security. Dev/test mode keeps the hash-stub validation
// for backward compatibility. Mainnet is further protected by the DA-R5-01
// hard guard (Danksharding disabled on mainnet).
// =============================================================================

// TestDA_R7_12_ProductionModeRejectsHashStubValidation verifies that
// BlobTxSidecar.Validate refuses to run in production mode.
func TestDA_R7_12_ProductionModeRejectsHashStubValidation(t *testing.T) {
	// Build a structurally valid sidecar (1 blob, 1 commitment, 1 proof).
	blob := Blob{}
	// Fill blob with deterministic non-zero data so the hash is non-zero.
	for i := range blob {
		blob[i] = byte(i % 256)
	}
	commitment := KZGCommitmentFromBlob(blob)
	proof, _ := ComputeBlobKZGProof(blob, commitment)
	sidecar := &BlobTxSidecar{
		Blobs:       []Blob{blob},
		Commitments: []KZGCommitment{commitment},
		Proofs:      []KZGProof{proof},
	}

	// Subtest 1: dev mode — hash-stub validation runs and succeeds.
	t.Run("dev_mode_accepts_hash_stub", func(t *testing.T) {
		orig := os.Getenv("QAU_PRODUCTION")
		os.Unsetenv("QAU_PRODUCTION")
		defer func() {
			if orig == "" {
				os.Unsetenv("QAU_PRODUCTION")
			} else {
				os.Setenv("QAU_PRODUCTION", orig)
			}
		}()

		if err := sidecar.Validate(); err != nil {
			t.Fatalf("dev mode: expected hash-stub validation to succeed, got: %v", err)
		}
	})

	// Subtest 2: production mode — Validate refuses to run.
	t.Run("production_mode_rejects_hash_stub", func(t *testing.T) {
		orig := os.Getenv("QAU_PRODUCTION")
		os.Setenv("QAU_PRODUCTION", "1")
		defer func() {
			if orig == "" {
				os.Unsetenv("QAU_PRODUCTION")
			} else {
				os.Setenv("QAU_PRODUCTION", orig)
			}
		}()

		err := sidecar.Validate()
		if err == nil {
			t.Fatal("production mode: expected Validate to refuse hash-stub validation, got nil error")
		}
		if !strings.Contains(err.Error(), "DA-R7-12") {
			t.Errorf("production mode: error should reference DA-R7-12, got: %v", err)
		}
	})
}
