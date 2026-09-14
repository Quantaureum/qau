// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

func TestPolyAddSub(t *testing.T) {
	var a, b, sum, result Poly
	for i := 0; i < N; i++ {
		a[i] = int32(i * 1000 % Q)
		b[i] = int32(i * 500 % Q)
	}

	sum.Add(&a, &b)
	result.Sub(&sum, &b)

	for i := 0; i < N; i++ {
		expected := a[i]
		if result[i] != expected {
			t.Errorf("index %d: got %d, want %d", i, result[i], expected)
		}
	}
}

func TestPolyScalarMul(t *testing.T) {
	var a, result Poly
	scalar := int64(12345)

	for i := 0; i < N; i++ {
		a[i] = int32(i + 1)
	}

	result.ScalarMul(&a, scalar)

	for i := 0; i < N; i++ {
		expected := (int64(a[i]) * scalar) % Q
		if int64(result[i]) != expected {
			t.Errorf("index %d: got %d, want %d", i, result[i], expected)
		}
	}
}

func TestPolyNormInf(t *testing.T) {
	var p Poly
	for i := 0; i < N; i++ {
		p[i] = int32(i + 1)
	}

	norm := p.NormInf()
	if norm != N {
		t.Errorf("norm: got %d, want %d", norm, N)
	}
}

func TestPolyNeg(t *testing.T) {
	var a, neg, result Poly
	for i := 0; i < N; i++ {
		a[i] = int32(i * 1000 % Q)
	}

	neg.Neg(&a)
	result.Add(&a, &neg)

	for i := 0; i < N; i++ {
		if result[i] != 0 {
			t.Errorf("index %d: a + (-a) = %d, want 0", i, result[i])
		}
	}
}

func TestPolyToFromBytes(t *testing.T) {
	var orig, recovered Poly
	for i := 0; i < N; i++ {
		orig[i] = int32(i * 32667 % Q)
	}

	bytes := orig.ToBytes()
	if len(bytes) != N*3 {
		t.Fatalf("bytes length: got %d, want %d", len(bytes), N*3)
	}

	err := recovered.FromBytes(bytes)
	if err != nil {
		t.Fatalf("FromBytes failed: %v", err)
	}

	for i := 0; i < N; i++ {
		if orig[i] != recovered[i] {
			t.Errorf("index %d: got %d, want %d", i, recovered[i], orig[i])
		}
	}
}

func TestPolyCopy(t *testing.T) {
	var a, b Poly
	for i := 0; i < N; i++ {
		a[i] = int32(i)
	}

	b.Copy(&a)

	for i := 0; i < N; i++ {
		if b[i] != a[i] {
			t.Errorf("index %d: got %d, want %d", i, b[i], a[i])
		}
	}
}

func TestPolyEquals(t *testing.T) {
	var a, b, c Poly
	for i := 0; i < N; i++ {
		a[i] = int32(i)
		b[i] = int32(i)
		c[i] = int32(i + 1)
	}

	if !a.Equals(&b) {
		t.Error("a should equal b")
	}

	if a.Equals(&c) {
		t.Error("a should not equal c")
	}
}

func TestPolyMulViaNTT(t *testing.T) {
	var a, b, prodNTT Poly
	for i := 0; i < N; i++ {
		a[i] = int32(i + 1)
		b[i] = int32(i * 2 % Q)
	}

	// NTT-based multiplication
	prodNTT.PolyMul(&a, &b)

	// Verify: x * 1 = x (identity)
	var one, result Poly
	one[0] = 1
	result.PolyMul(&a, &one)

	for i := 0; i < N; i++ {
		if result[i] != a[i] {
			t.Errorf("index %d: a*1 got %d, want %d", i, result[i], a[i])
		}
	}

	// Zero check
	var zero, zeroProd Poly
	zeroProd.PolyMul(&a, &zero)
	for i := 0; i < N; i++ {
		if zeroProd[i] != 0 {
			t.Errorf("index %d: a*0 got %d, want 0", i, zeroProd[i])
		}
	}

	_ = prodNTT // use it to avoid unused warning
}

func TestPolyZero(t *testing.T) {
	var p Poly
	for i := 0; i < N; i++ {
		p[i] = int32(i)
	}

	p.Zero()

	for i := 0; i < N; i++ {
		if p[i] != 0 {
			t.Errorf("index %d: got %d, want 0", i, p[i])
		}
	}
}

func TestPolyReduce(t *testing.T) {
	var p Poly
	for i := 0; i < N; i++ {
		p[i] = int32(i) - Q - 1
	}

	p.Reduce()

	for i := 0; i < N; i++ {
		if p[i] < 0 || p[i] >= Q {
			t.Errorf("index %d: coefficient %d out of range [0, Q)", i, p[i])
		}
	}
}

func TestVecAdd(t *testing.T) {
	a := make(PolyVec, 3)
	b := make(PolyVec, 3)

	for k := 0; k < 3; k++ {
		for i := 0; i < N; i++ {
			a[k][i] = int32(i * (k + 1))
			b[k][i] = int32(i * (k + 2))
		}
	}

	result := VecAdd(a, b)

	for k := 0; k < 3; k++ {
		for i := 0; i < N; i++ {
			expected := (a[k][i] + b[k][i]) % Q
			if result[k][i] != expected {
				t.Errorf("vec %d, index %d: got %d, want %d", k, i, result[k][i], expected)
			}
		}
	}
}

func TestVecScalarMul(t *testing.T) {
	vec := make(PolyVec, 2)
	scalar := int64(7)

	for k := 0; k < 2; k++ {
		for i := 0; i < N; i++ {
			vec[k][i] = int32(i + k + 1)
		}
	}

	result := VecScalarMul(vec, scalar)

	for k := 0; k < 2; k++ {
		for i := 0; i < N; i++ {
			expected := (int64(vec[k][i]) * scalar) % Q
			if int64(result[k][i]) != expected {
				t.Errorf("vec %d, index %d: got %d, want %d", k, i, result[k][i], expected)
			}
		}
	}
}

func TestVecNormInf(t *testing.T) {
	vec := make(PolyVec, 3)
	for k := 0; k < 3; k++ {
		for i := 0; i < N; i++ {
			vec[k][i] = int32((i + 1) * (k + 1))
		}
	}

	norm := VecNormInf(vec)
	if norm <= 0 {
		t.Errorf("norm: got %d, want positive value", norm)
	}
}

func TestVecToFromBytes(t *testing.T) {
	vec := make(PolyVec, 3)
	for k := 0; k < 3; k++ {
		for i := 0; i < N; i++ {
			vec[k][i] = int32(i * (k + 1) * 7 % Q)
		}
	}

	bytes := VecToBytes(vec)
	recovered, err := VecFromBytes(bytes, 3)
	if err != nil {
		t.Fatalf("VecFromBytes failed: %v", err)
	}

	if len(recovered) != 3 {
		t.Fatalf("recovered length: got %d, want 3", len(recovered))
	}

	for k := 0; k < 3; k++ {
		for i := 0; i < N; i++ {
			if recovered[k][i] != vec[k][i] {
				t.Errorf("vec %d, index %d: got %d, want %d", k, i, recovered[k][i], vec[k][i])
			}
		}
	}
}

func TestMatVecMul(t *testing.T) {
	mat := make([][]Poly, 2)
	for i := 0; i < 2; i++ {
		mat[i] = make([]Poly, 2)
	}

	vec := make(PolyVec, 2)
	for k := 0; k < 2; k++ {
		for i := 0; i < N; i++ {
			vec[k][i] = int32(i * (k + 1) % Q)
		}
	}

	result := MatVecMul(mat, vec)

	for i := 0; i < N; i++ {
		if result[0][i] != 0 {
			t.Errorf("result[0][%d]: got %d, want 0 (zero matrix)", i, result[0][i])
		}
		if result[1][i] != 0 {
			t.Errorf("result[1][%d]: got %d, want 0 (zero matrix)", i, result[1][i])
		}
	}

	// Test with constant polynomial 1 as "identity"
	mat[0][0][0] = 1
	mat[1][1][0] = 1

	result2 := MatVecMul(mat, vec)

	for i := 0; i < N; i++ {
		if result2[0][i] != vec[0][i] {
			t.Errorf("result2[0][%d]: got %d, want %d", i, result2[0][i], vec[0][i])
		}
		if result2[1][i] != vec[1][i] {
			t.Errorf("result2[1][%d]: got %d, want %d", i, result2[1][i], vec[1][i])
		}
	}
}

func TestModInverse(t *testing.T) {
	a := int64(7)
	m := int64(Q)

	inv := modInverse(a, m)
	result := (a * inv) % m

	if result != 1 {
		t.Errorf("modInverse(7, Q): %d * %d mod Q = %d, want 1", a, inv, result)
	}
}

// ============================================================================
// TSS-R5-07 (2026-07-17): constant-time modInverse regression tests.
//
// Verifies the Fermat little theorem + fixed-iteration square-and-multiply
// replacement for the non-constant-time extended Euclidean algorithm.
// ============================================================================

// TestTSS_R5_07_ModInverseCorrectness verifies modInverse(a, Q) produces
// the correct modular inverse across many values, including edge cases.
func TestTSS_R5_07_ModInverseCorrectness(t *testing.T) {
	m := int64(Q)

	// Edge cases.
	edgeCases := []struct {
		name string
		a    int64
	}{
		{"a=1", 1},
		{"a=2", 2},
		{"a=Q-1", m - 1},
		{"a=Q/2", m / 2},
		{"a=negative", -7},
		{"a=2*Q+7", 2*m + 7}, // must reduce to 7
	}
	for _, c := range edgeCases {
		t.Run(c.name, func(t *testing.T) {
			inv := modInverse(c.a, m)
			reducedA := ((c.a % m) + m) % m
			if reducedA == 0 {
				if inv != 0 {
					t.Errorf("modInverse(%d, Q)=%d, want 0 (no inverse for 0)", c.a, inv)
				}
				return
			}
			result := (reducedA * inv) % m
			if result != 1 {
				t.Errorf("modInverse(%d, Q)=%d: %d * %d mod Q = %d, want 1",
					c.a, inv, reducedA, inv, result)
			}
		})
	}

	// Random sweep across [1, Q).
	testCases := []int64{3, 5, 11, 13, 100, 1000, 12345, 65537, 999983, m - 2, m - 100}
	for _, a := range testCases {
		inv := modInverse(a, m)
		if inv < 0 || inv >= m {
			t.Errorf("modInverse(%d, Q)=%d out of [0,Q) range", a, inv)
			continue
		}
		result := (a * inv) % m
		if result != 1 {
			t.Errorf("modInverse(%d, Q)=%d: %d * %d mod Q = %d, want 1",
				a, inv, a, inv, result)
		}
	}
}

// TestTSS_R5_07_ModInverseEdgeCases verifies degenerate inputs.
func TestTSS_R5_07_ModInverseEdgeCases(t *testing.T) {
	// m <= 1: no inverse, return 0.
	if v := modInverse(5, 1); v != 0 {
		t.Errorf("modInverse(5, 1)=%d, want 0", v)
	}
	if v := modInverse(5, 0); v != 0 {
		t.Errorf("modInverse(5, 0)=%d, want 0", v)
	}
	// a=0 mod m: no inverse, return 0.
	if v := modInverse(0, int64(Q)); v != 0 {
		t.Errorf("modInverse(0, Q)=%d, want 0", v)
	}
	if v := modInverse(int64(Q), int64(Q)); v != 0 {
		t.Errorf("modInverse(Q, Q)=%d, want 0 (a reduces to 0)", v)
	}
}

// TestTSS_R5_07_ModInverseDeterministic verifies same input → same output.
func TestTSS_R5_07_ModInverseDeterministic(t *testing.T) {
	m := int64(Q)
	a := int64(12345)
	v1 := modInverse(a, m)
	v2 := modInverse(a, m)
	if v1 != v2 {
		t.Errorf("non-deterministic: %d vs %d", v1, v2)
	}
}

// TestTSS_R5_07_ModInverseLagrangeIntegration verifies that the constant-time
// modInverse produces identical Lagrange coefficients to the expected values
// for the 2-of-3 mainnet configuration (participants 1, 2, 3).
//
// Expected (computed by hand):
//
//	λ_1 = 3, λ_2 = Q-3, λ_3 = 1
func TestTSS_R5_07_ModInverseLagrangeIntegration(t *testing.T) {
	parts := []int{1, 2, 3}

	l1 := lagrangeCoeff(1, parts)
	l2 := lagrangeCoeff(2, parts)
	l3 := lagrangeCoeff(3, parts)

	// Known-good values for 2-of-3.
	if l1 != 3 {
		t.Errorf("λ_1 = %d, want 3", l1)
	}
	if l2 != int64(Q)-3 {
		t.Errorf("λ_2 = %d, want Q-3=%d", l2, int64(Q)-3)
	}
	if l3 != 1 {
		t.Errorf("λ_3 = %d, want 1", l3)
	}

	// Sum must be 1 mod Q (secret reconstruction at x=0).
	sum := (l1 + l2 + l3) % int64(Q)
	if sum != 1 {
		t.Errorf("Σλ_i mod Q = %d, want 1", sum)
	}
}

// TestTSS_R5_07_ModInverseMultipleThresholds verifies correctness across
// various threshold configurations used in production (2-of-3, 3-of-5, etc).
func TestTSS_R5_07_ModInverseMultipleThresholds(t *testing.T) {
	configs := [][]int{
		{1, 2, 3},             // 2-of-3
		{1, 2, 3, 4, 5},       // 3-of-5
		{1, 2, 3, 4, 5, 6, 7}, // 4-of-7
	}
	for _, parts := range configs {
		t.Run(fmt.Sprintf("n=%d", len(parts)), func(t *testing.T) {
			// Σλ_i must equal 1 mod Q for any valid participant set.
			var sum int64
			for _, id := range parts {
				c := lagrangeCoeff(id, parts)
				sum = (sum + c) % int64(Q)
			}
			if sum != 1 {
				t.Errorf("n=%d: Σλ_i mod Q = %d, want 1", len(parts), sum)
			}
		})
	}
}

func TestLagrangeCoeff(t *testing.T) {
	// 2-of-3 threshold: participants 1, 2, 3
	// Coefficient for participant 1 at x=0:
	// lambda_1 = (0-2)(0-3) / (1-2)(1-3) = 6/2 = 3
	// lambda_2 = (0-1)(0-3) / (2-1)(2-3) = 3/(-1) = -3 = Q-3
	// lambda_3 = (0-1)(0-2) / (3-1)(3-2) = 2/2 = 1

	parts := []int{1, 2, 3}
	l1 := lagrangeCoeff(1, parts)
	l2 := lagrangeCoeff(2, parts)
	l3 := lagrangeCoeff(3, parts)

	// Check: lambda_1 + lambda_2 + lambda_3 = 1 mod Q (for secret reconstruction at x=0)
	sum := (l1 + l2 + l3) % Q
	if sum != 1 {
		t.Errorf("Lagrange sum: %d, want 1", sum)
	}

	// Verify: secret = lambda_1*s_1 + lambda_2*s_2 + lambda_3*s_3
	// For f(0) = 42, f(1) = s1, f(2) = s2, f(3) = s3
	// Using f(x) = 42 + 0*x + 0*x^2 (constant polynomial)
	secret := int64(42)
	s1 := int64(42) // f(1)
	s2 := int64(42) // f(2)
	s3 := int64(42) // f(3)

	recovered := (l1*s1 + l2*s2 + l3*s3) % Q
	if recovered != secret {
		t.Errorf("recovered secret: %d, want %d", recovered, secret)
	}
}

func TestCheckRejection(t *testing.T) {
	// Create a vector that passes
	vec := make(PolyVec, 1)
	vec[0].Zero()

	if !CheckRejection(vec, 1000) {
		t.Error("zero vector should pass rejection check")
	}

	// Create a vector that fails
	vec2 := make(PolyVec, 1)
	for i := 0; i < N; i++ {
		vec2[0][i] = 2000
	}

	if CheckRejection(vec2, 1000) {
		t.Error("vector with norm > 1000 should fail rejection check")
	}
}

func TestSampleUniformPoly(t *testing.T) {
	var p Poly
	seed := []byte("test-seed-for-sampling-123456789")

	err := p.SampleUniform(seed)
	if err != nil {
		t.Fatalf("SampleUniform failed: %v", err)
	}

	for i := 0; i < N; i++ {
		if p[i] < 0 || p[i] >= Q {
			t.Errorf("index %d: coefficient %d out of range [0, Q)", i, p[i])
		}
	}
}

func TestQTDManager(t *testing.T) {
	m, err := NewQTDManager(2, 3)
	if err != nil {
		t.Fatalf("NewQTDManager failed: %v", err)
	}

	if m.threshold != 2 {
		t.Errorf("threshold: got %d, want 2", m.threshold)
	}

	if m.total != 3 {
		t.Errorf("total: got %d, want 3", m.total)
	}
}

func TestQTDManagerInvalidConfig(t *testing.T) {
	_, err := NewQTDManager(0, 3)
	if err == nil {
		t.Error("expected error for invalid threshold")
	}

	_, err = NewQTDManager(4, 3)
	if err == nil {
		t.Error("expected error for threshold > total")
	}
}

func TestQTDManagerAddShare(t *testing.T) {
	m, _ := NewQTDManager(2, 3)

	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
	}

	err := m.AddShare(share)
	if err != nil {
		t.Fatalf("AddShare failed: %v", err)
	}

	retrieved, err := m.GetShare(1)
	if err != nil {
		t.Fatalf("GetShare failed: %v", err)
	}

	if retrieved.ParticipantID != 1 {
		t.Errorf("participant ID: got %d, want 1", retrieved.ParticipantID)
	}
}

func TestQTDManagerAddShareInvalidIndex(t *testing.T) {
	m, _ := NewQTDManager(2, 3)

	share := &QTDShare{
		ParticipantID: 0,
		Rho:           make([]byte, 32),
	}

	err := m.AddShare(share)
	if err == nil {
		t.Error("expected error for invalid participant ID")
	}
}

func TestQTDManagerGetShareNotFound(t *testing.T) {
	m, _ := NewQTDManager(2, 3)

	_, err := m.GetShare(1)
	if err == nil {
		t.Error("expected error for non-existent share")
	}
}

func TestQTDManagerCreateSigningSession(t *testing.T) {
	m, _ := NewQTDManager(3, 3)

	m.AddShare(&QTDShare{ParticipantID: 1, Rho: make([]byte, 32)})
	m.AddShare(&QTDShare{ParticipantID: 2, Rho: make([]byte, 32)})
	m.AddShare(&QTDShare{ParticipantID: 3, Rho: make([]byte, 32)})

	session, err := m.CreateSigningSession([]byte("test-message"), []int{1, 2, 3})
	if err != nil {
		t.Fatalf("CreateSigningSession failed: %v", err)
	}

	if session == nil {
		t.Fatal("session is nil")
	}
}

func TestQTDManagerCreateSigningSessionInsufficient(t *testing.T) {
	m, _ := NewQTDManager(2, 3)

	m.AddShare(&QTDShare{ParticipantID: 1, Rho: make([]byte, 32)})

	_, err := m.CreateSigningSession([]byte("test"), []int{1})
	if err == nil {
		t.Error("expected error for insufficient participants")
	}
}

func TestBytesEqual(t *testing.T) {
	a := []byte{1, 2, 3}
	b := []byte{1, 2, 3}
	c := []byte{1, 2, 4}

	if !bytesEqual(a, b) {
		t.Error("bytesEqual: a == b expected")
	}

	if bytesEqual(a, c) {
		t.Error("bytesEqual: a != c expected")
	}

	if bytesEqual(a, []byte{1, 2}) {
		t.Error("bytesEqual: different lengths expected false")
	}
}

func TestShamirSplit(t *testing.T) {
	data := []byte{42, 100, 250}
	threshold := 2
	total := 3

	shares, err := shamirSplitAll(data, threshold, total)
	if err != nil {
		t.Fatalf("shamirSplitAll failed: %v", err)
	}

	if len(shares) != total {
		t.Errorf("number of shares: got %d, want %d", len(shares), total)
	}

	for id := 1; id <= total; id++ {
		if len(shares[id]) != len(data)*4 {
			t.Errorf("share %d length: got %d, want %d", id, len(shares[id]), len(data)*4)
		}
		for i := 0; i < len(data); i++ {
			val := binary.LittleEndian.Uint32(shares[id][i*4 : (i+1)*4])
			if val >= uint32(Q) {
				t.Errorf("share %d element %d has value %d >= Q %d", id, i, val, Q)
			}
		}
	}
}

func TestShamirReconstruct(t *testing.T) {
	data := []byte{42, 100, 250, 0, 1, 150}
	threshold := 2
	total := 3

	shares, err := shamirSplitAll(data, threshold, total)
	if err != nil {
		t.Fatalf("shamirSplitAll failed: %v", err)
	}

	subset := make(map[int][]byte)
	for id := 1; id <= threshold; id++ {
		subset[id] = shares[id]
	}

	reconstructed, err := shamirReconstruct(subset, threshold)
	if err != nil {
		t.Fatalf("shamirReconstruct failed: %v", err)
	}

	if !bytesEqual(reconstructed, data) {
		t.Errorf("reconstructed data doesn't match original: got %v, want %v", reconstructed, data)
	}
}

func TestShamirReconstructDifferentSubset(t *testing.T) {
	data := []byte{10, 20, 30, 40, 50}
	threshold := 3
	total := 5

	shares, err := shamirSplitAll(data, threshold, total)
	if err != nil {
		t.Fatalf("shamirSplitAll failed: %v", err)
	}

	for _, ids := range [][]int{{1, 2, 3}, {2, 4, 5}, {1, 3, 5}} {
		subset := make(map[int][]byte)
		for _, id := range ids {
			subset[id] = shares[id]
		}

		reconstructed, err := shamirReconstruct(subset, threshold)
		if err != nil {
			t.Fatalf("shamirReconstruct with subset %v failed: %v", ids, err)
		}

		if !bytesEqual(reconstructed, data) {
			t.Errorf("subset %v: reconstructed %v, want %v", ids, reconstructed, data)
		}
	}
}

func TestShamirSplitInvalidConfig(t *testing.T) {
	_, err := shamirSplitAll([]byte{42}, 0, 3)
	if err == nil {
		t.Error("expected error for zero threshold")
	}

	_, err = shamirSplitAll([]byte{42}, 4, 3)
	if err == nil {
		t.Error("expected error for threshold > total")
	}

	_, err = shamirSplitAll(nil, 2, 3)
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestVerifyShareWithPedersen(t *testing.T) {
	shareBytes := make([]byte, 12)
	binary.LittleEndian.PutUint32(shareBytes[0:4], 42)
	binary.LittleEndian.PutUint32(shareBytes[4:8], 100)
	binary.LittleEndian.PutUint32(shareBytes[8:12], 250)
	threshold := 2

	vVector, err := generateVerificationVector(shareBytes, threshold)
	if err != nil {
		t.Fatalf("generateVerificationVector failed: %v", err)
	}
	// TSS-R5-05 (2026-07-16): VerifyShare now fail-closes when S2/T0
	// verification vectors are missing. Generate real S2/T0 shares and
	// their VVectors so this test exercises the happy path (the DKG
	// paths in qtd_dkg.go do the same — see lines 370/530/1244/1503).
	s2ShareBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(s2ShareBytes[0:4], 7)
	binary.LittleEndian.PutUint32(s2ShareBytes[4:8], 11)
	t0ShareBytes := make([]byte, 8)
	binary.LittleEndian.PutUint32(t0ShareBytes[0:4], 19)
	binary.LittleEndian.PutUint32(t0ShareBytes[4:8], 23)
	vVectorS2, err := generateVerificationVector(s2ShareBytes, threshold)
	if err != nil {
		t.Fatalf("generateVerificationVector S2 failed: %v", err)
	}
	vVectorT0, err := generateVerificationVector(t0ShareBytes, threshold)
	if err != nil {
		t.Fatalf("generateVerificationVector T0 failed: %v", err)
	}

	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  shareBytes,
		S2ShareBytes:  s2ShareBytes,
		T0ShareBytes:  t0ShareBytes,
		VVectorS2:     vVectorS2,
		VVectorT0:     vVectorT0,
	}

	allVVectors := [][][]byte{vVector}

	if err := VerifyShare(share, allVVectors, 1); err != nil {
		t.Errorf("valid share failed verification: %v", err)
	}

	wrongShareBytes := make([]byte, 12)
	binary.LittleEndian.PutUint32(wrongShareBytes[0:4], 99)
	binary.LittleEndian.PutUint32(wrongShareBytes[4:8], 99)
	binary.LittleEndian.PutUint32(wrongShareBytes[8:12], 99)
	wrongShare := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  wrongShareBytes,
		S2ShareBytes:  s2ShareBytes,
		T0ShareBytes:  t0ShareBytes,
		VVectorS2:     vVectorS2,
		VVectorT0:     vVectorT0,
	}

	if err := VerifyShare(wrongShare, allVVectors, 1); err == nil {
		t.Error("wrong share should fail verification")
	}
}

func TestVerifyShareInvalidInput(t *testing.T) {
	vVector := [][]byte{make([]byte, 48)}
	allVVectors := [][][]byte{vVector}

	if err := VerifyShare(nil, allVVectors, 1); err == nil {
		t.Error("nil share should fail")
	}

	share := &QTDShare{
		ParticipantID: 1,
		Rho:           make([]byte, 32),
		S1ShareBytes:  make([]byte, 4),
		S2ShareBytes:  make([]byte, 4),
	}

	if err := VerifyShare(share, nil, 1); err == nil {
		t.Error("empty allVVectors should fail")
	}

	if err := VerifyShare(share, allVVectors, 0); err == nil {
		t.Error("participantID < 1 should fail")
	}
}

func TestLagrangeReconstruction(t *testing.T) {
	// f(x) = 42 + 7x (degree 1 polynomial, threshold = 2)
	// f(0) = 42 (secret)
	// f(1) = 49
	// f(2) = 56
	// f(3) = 63

	secret := big.NewInt(42)
	shares := []*big.Int{
		big.NewInt(49), // f(1)
		big.NewInt(56), // f(2)
		big.NewInt(63), // f(3)
	}

	// Reconstruct using participants 1, 2
	parts := []int{1, 2}
	l1 := lagrangeCoeff(1, parts)
	l2 := lagrangeCoeff(2, parts)

	l1Big := big.NewInt(l1)
	l2Big := big.NewInt(l2)

	reconstructed := new(big.Int)
	reconstructed.Mul(l1Big, shares[0])
	t2 := new(big.Int).Mul(l2Big, shares[1])
	reconstructed.Add(reconstructed, t2)

	q := big.NewInt(Q)
	reconstructed.Mod(reconstructed, q)

	if reconstructed.Cmp(secret) != 0 {
		t.Errorf("reconstructed: %d, want %d", reconstructed, secret)
	}
}

func TestAdditiveSplitReconstruct(t *testing.T) {
	var original Poly
	for i := 0; i < N; i++ {
		original[i] = int32(i%11 - 5)
	}

	vec := PolyVec{original}
	total := 3

	shares, err := additiveSplitPolyVec(vec, total)
	if err != nil {
		t.Fatalf("additiveSplitPolyVec failed: %v", err)
	}

	var reconstructed Poly
	for id := 1; id <= total; id++ {
		reconstructed.Add(&reconstructed, &shares[id][0])
	}

	for i := 0; i < N; i++ {
		want := int64(original[i])
		want = ((want % Q) + Q) % Q
		got := int64(reconstructed[i])
		if got != want {
			t.Errorf("coefficient %d: got %d, want %d", i, got, want)
			break
		}
	}
}

func TestAdditivePolyMul(t *testing.T) {
	var s1 Poly
	for i := 0; i < N; i++ {
		s1[i] = int32(i%11 - 5)
		if s1[i] < 0 {
			s1[i] += Q
		}
	}

	var c Poly
	c[0] = 1
	c[1] = -1
	if c[1] < 0 {
		c[1] += Q
	}
	c[3] = 1

	total := 3
	vec := PolyVec{s1}
	shares, err := additiveSplitPolyVec(vec, total)
	if err != nil {
		t.Fatalf("additiveSplitPolyVec failed: %v", err)
	}

	var expectedSC Poly
	expectedSC.PolyMul(&s1, &c)

	var aggregatedSC Poly
	for id := 1; id <= total; id++ {
		var sc Poly
		sc.PolyMul(&shares[id][0], &c)
		aggregatedSC.Add(&aggregatedSC, &sc)
	}

	for i := 0; i < N; i++ {
		if aggregatedSC[i] != expectedSC[i] {
			t.Errorf("coefficient %d: aggregated %d, expected %d", i, aggregatedSC[i], expectedSC[i])
			break
		}
	}

	norm := aggregatedSC.NormInf()
	t.Logf("||aggregated s*c||_∞ = %d", norm)
	if norm > 200 {
		t.Errorf("norm too large: %d", norm)
	}
}

func TestAMatrixKeyRelation(t *testing.T) {
	seed := [32]byte{}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i + 1)
	}

	pubKey, privKey := mode3.NewKeyFromSeed(&seed)
	rho := pubKey.Bytes()[:32]

	s1Packed := privKey.Bytes()[mode3.SeedSize*3 : mode3.SeedSize*3+Dilithium3L*128]
	s1Vec, err := UnpackEtaVec(s1Packed, Dilithium3L, Dilithium3EtaPoly)
	if err != nil {
		t.Fatalf("failed to unpack s1: %v", err)
	}

	s2Packed := privKey.Bytes()[mode3.SeedSize*3+Dilithium3L*128:]
	s2Packed = s2Packed[:Dilithium3K*128]
	s2Vec, err := UnpackEtaVec(s2Packed, Dilithium3K, Dilithium3EtaPoly)
	if err != nil {
		t.Fatalf("failed to unpack s2: %v", err)
	}

	t0Offset := mode3.SeedSize*3 + Dilithium3L*128 + Dilithium3K*128
	t0Packed := privKey.Bytes()[t0Offset : t0Offset+Dilithium3K*416]
	t0Vec := make(PolyVec, Dilithium3K)
	if err := parseT0PolyVec(t0Vec, t0Packed, Dilithium3K); err != nil {
		t.Fatalf("failed to parse t0: %v", err)
	}

	t1Packed := pubKey.Bytes()[32:]
	t1Vec, err := UnpackT1(t1Packed, Dilithium3K)
	if err != nil {
		t.Fatalf("failed to unpack t1: %v", err)
	}

	aMat, err := ComputeA(rho, Dilithium3K, Dilithium3L)
	if err != nil {
		t.Fatalf("failed to compute A: %v", err)
	}

	as1 := ComputeAz(aMat, s1Vec)

	as1s2 := make(PolyVec, Dilithium3K)
	for i := 0; i < Dilithium3K; i++ {
		as1s2[i].Add(&as1[i], &s2Vec[i])
	}

	t1Full := make(PolyVec, Dilithium3K)
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			t1Full[i][j] = int32((int64(t1Vec[i][j]) * (1 << Dilithium3D)) % Q)
		}
		t1Full[i].Add(&t1Full[i], &t0Vec[i])
	}

	mismatch := 0
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			a := int64(as1s2[i][j]) % Q
			if a < 0 {
				a += Q
			}
			b := int64(t1Full[i][j]) % Q
			if b < 0 {
				b += Q
			}
			if a != b {
				mismatch++
			}
		}
	}

	t.Logf("s1[0][0:4]=%v s2[0][0:4]=%v", []int32{s1Vec[0][0], s1Vec[0][1], s1Vec[0][2], s1Vec[0][3]}, []int32{s2Vec[0][0], s2Vec[0][1], s2Vec[0][2], s2Vec[0][3]})
	t.Logf("t1[0][0:4]=%v t0[0][0:4]=%v", []int32{t1Vec[0][0], t1Vec[0][1], t1Vec[0][2], t1Vec[0][3]}, []int32{t0Vec[0][0], t0Vec[0][1], t0Vec[0][2], t0Vec[0][3]})
	t.Logf("as1s2[0][0:4]=%v", []int32{as1s2[0][0], as1s2[0][1], as1s2[0][2], as1s2[0][3]})
	t.Logf("t1Full[0][0:4]=%v", []int32{t1Full[0][0], t1Full[0][1], t1Full[0][2], t1Full[0][3]})
	t.Logf("A[0][0][0]=%d", aMat[0][0][0])

	if mismatch > 0 {
		t.Fatalf("A*s1+s2 != t1*2^D+t0: mismatch=%d/1536", mismatch)
	}
}
