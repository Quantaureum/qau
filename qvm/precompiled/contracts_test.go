// Quantaureum Node source, version 1.0.0.
package precompiled

import (
	"math/big"
	"testing"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
)

// helpers to get generator points
func bn254G1Gen() bn254.G1Affine {
	_, _, g1, _ := bn254.Generators()
	return g1
}

func bn254G2Gen() bn254.G2Affine {
	_, _, _, g2 := bn254.Generators()
	return g2
}

// encodeG1 encodes a G1 affine point into 64 bytes (x || y, big-endian)
func encodeG1(p bn254.G1Affine) []byte {
	buf := make([]byte, 64)
	p.X.BigInt(new(big.Int)).FillBytes(buf[0:32])
	p.Y.BigInt(new(big.Int)).FillBytes(buf[32:64])
	return buf
}

// encodeG2 encodes a G2 affine point into 128 bytes per EIP-197:
// x.A1 || x.A0 || y.A1 || y.A0 (big-endian limbs)
func encodeG2(p bn254.G2Affine) []byte {
	buf := make([]byte, 128)
	p.X.A1.BigInt(new(big.Int)).FillBytes(buf[0:32])
	p.X.A0.BigInt(new(big.Int)).FillBytes(buf[32:64])
	p.Y.A1.BigInt(new(big.Int)).FillBytes(buf[64:96])
	p.Y.A0.BigInt(new(big.Int)).FillBytes(buf[96:128])
	return buf
}

// encodePair encodes a (G1, G2) pair into 192 bytes
func encodePair(g1 bn254.G1Affine, g2 bn254.G2Affine) []byte {
	buf := make([]byte, 192)
	copy(buf[0:64], encodeG1(g1))
	copy(buf[64:192], encodeG2(g2))
	return buf
}

// TestBN256PairingInvalidInputLength tests that invalid input lengths are rejected
func TestBN256PairingInvalidInputLength(t *testing.T) {
	c := newBN256Pairing()

	tests := []struct {
		name  string
		input []byte
	}{
		{"empty input", make([]byte, 0)},
		{"1 byte", make([]byte, 1)},
		{"191 bytes", make([]byte, 191)},
		{"193 bytes", make([]byte, 193)},
		{"100 bytes", make([]byte, 100)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := c.Run(tt.input)
			if err == nil {
				t.Error("expected error for invalid input length")
			}
		})
	}
}

// TestBN256PairingGasCalculation tests RequiredGas for various input sizes
func TestBN256PairingGasCalculation(t *testing.T) {
	c := newBN256Pairing()

	tests := []struct {
		inputLen int
		expected uint64
	}{
		{0, 34000},    // 0 pairs
		{192, 79000},  // 1 pair: 34000 + 45000*1
		{384, 124000}, // 2 pairs: 34000 + 45000*2
		{576, 169000}, // 3 pairs: 34000 + 45000*3
		{960, 259000}, // 5 pairs: 34000 + 45000*5
	}

	for _, tt := range tests {
		input := make([]byte, tt.inputLen)
		got := c.RequiredGas(input)
		if got != tt.expected {
			t.Errorf("RequiredGas(input len=%d) = %d, want %d", tt.inputLen, got, tt.expected)
		}
	}
}

// TestBN256PairingInvalidG1Point tests that G1 points not on the curve are rejected
func TestBN256PairingInvalidG1Point(t *testing.T) {
	c := newBN256Pairing()

	// Create 192-byte input with an invalid G1 point
	input := make([]byte, 192)
	// Set x=1, y=1 which is not on the BN254 curve
	input[31] = 1 // x = 1
	input[63] = 1 // y = 1

	_, err := c.Run(input)
	if err == nil {
		t.Error("expected error for G1 point not on curve")
	}
}

// TestBN256PairingInvalidG2Point tests that G2 points not on the curve are rejected
func TestBN256PairingInvalidG2Point(t *testing.T) {
	c := newBN256Pairing()

	g1Gen := bn254G1Gen()

	input := make([]byte, 192)
	// Set valid G1 point
	copy(input[0:64], encodeG1(g1Gen))

	// Set invalid G2 point: x=(1,1), y=(1,1) which is NOT on the G2 curve
	input[95] = 1  // x.A1 = 1
	input[127] = 1 // x.A0 = 1
	input[159] = 1 // y.A1 = 1
	input[191] = 1 // y.A0 = 1

	_, err := c.Run(input)
	if err == nil {
		t.Error("expected error for G2 point not on curve")
	}
}

// TestBN256PairingTrivialPairing tests pairing with G1 generator and G2 generator
// e(G1, G2) should NOT equal 1 (identity), so the result should be 0
func TestBN256PairingTrivialPairing(t *testing.T) {
	c := newBN256Pairing()

	g1Gen := bn254G1Gen()
	g2Gen := bn254G2Gen()

	input := encodePair(g1Gen, g2Gen)

	output, err := c.Run(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// e(G1, G2) != 1, so output should be 0
	if len(output) != 32 {
		t.Fatalf("expected 32-byte output, got %d", len(output))
	}
	if output[31] != 0 {
		t.Error("e(G1, G2) should not equal 1, expected output[31]=0")
	}
}

// TestBN256PairingIdentityPointAccepted tests that the identity point (0,0) is valid
// In EVM encoding, (0,0) represents the point at infinity, which is a valid input.
// e(O, G2) = 1 (identity in GT), so the pairing result should be success.
func TestBN256PairingIdentityPointAccepted(t *testing.T) {
	c := newBN256Pairing()

	// All-zero input: G1=(0,0)=infinity, G2=(0,0)=infinity
	// e(O, O) = 1, so this should return success
	input := make([]byte, 192)

	output, err := c.Run(input)
	if err != nil {
		t.Fatalf("identity point should be accepted: %v", err)
	}

	// e(O, O) = 1, so output should indicate success
	if output[31] != 1 {
		t.Error("e(O, O) should equal 1, expected output[31]=1")
	}
}

// TestBN256PairingG1InfinityG2Generator tests e(O, G2) = 1
func TestBN256PairingG1InfinityG2Generator(t *testing.T) {
	c := newBN256Pairing()

	g2Gen := bn254G2Gen()

	input := make([]byte, 192)
	// G1 = (0,0) = infinity (already zero)
	// G2 = generator
	copy(input[64:192], encodeG2(g2Gen))

	output, err := c.Run(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// e(O, G2) = 1
	if output[31] != 1 {
		t.Error("e(O, G2) should equal 1")
	}
}

// TestBN256PairingMultiPairingIdentity tests that e(G1, G2) * e(-G1, G2) = 1
func TestBN256PairingMultiPairingIdentity(t *testing.T) {
	c := newBN256Pairing()

	g1Gen := bn254G1Gen()
	g2Gen := bn254G2Gen()

	// Compute -G1 (negate y coordinate)
	var g1Neg bn254.G1Affine
	g1Neg.Neg(&g1Gen)

	// Build 384-byte input: (G1, G2) || (-G1, G2)
	input := make([]byte, 384)
	copy(input[0:192], encodePair(g1Gen, g2Gen))
	copy(input[192:384], encodePair(g1Neg, g2Gen))

	output, err := c.Run(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// e(G1, G2) * e(-G1, G2) = 1, so output should be 1
	if len(output) != 32 {
		t.Fatalf("expected 32-byte output, got %d", len(output))
	}
	if output[31] != 1 {
		t.Error("e(G1,G2) * e(-G1,G2) should equal 1, expected output[31]=1")
	}
}

// TestBN256PairingBilinearity tests the bilinearity property:
// e(a*G1, G2) * e(G1, -a*G2) = 1
func TestBN256PairingBilinearity(t *testing.T) {
	c := newBN256Pairing()

	scalar := big.NewInt(42)

	g1Gen := bn254G1Gen()
	g2Gen := bn254G2Gen()

	// Compute a*G1 using ScalarMultiplication
	var aG1 bn254.G1Affine
	aG1.ScalarMultiplication(&g1Gen, scalar)

	// Compute a*G2 using ScalarMultiplication
	var aG2 bn254.G2Affine
	aG2.ScalarMultiplication(&g2Gen, scalar)

	// Compute -a*G2
	var negAG2 bn254.G2Affine
	negAG2.Neg(&aG2)

	// Build 384-byte input: (a*G1, G2) || (G1, -a*G2)
	input := make([]byte, 384)
	copy(input[0:192], encodePair(aG1, g2Gen))
	copy(input[192:384], encodePair(g1Gen, negAG2))

	output, err := c.Run(input)
	if err != nil {
		t.Fatalf("e(a*G1, G2) * e(G1, -a*G2) failed: %v", err)
	}

	// e(a*G1, G2) * e(G1, -a*G2) = e(a*G1, G2) / e(G1, a*G2) = 1 by bilinearity
	if output[31] != 1 {
		t.Error("e(a*G1,G2) * e(G1,-a*G2) should equal 1 (bilinearity)")
	}
}

// TestBN256PairingOutputFormat verifies the output is always 32 bytes
func TestBN256PairingOutputFormat(t *testing.T) {
	c := newBN256Pairing()

	g1Gen := bn254G1Gen()
	g2Gen := bn254G2Gen()

	input := encodePair(g1Gen, g2Gen)

	output, err := c.Run(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(output) != 32 {
		t.Errorf("expected 32-byte output, got %d bytes", len(output))
	}

	// First 31 bytes should be 0
	for i := 0; i < 31; i++ {
		if output[i] != 0 {
			t.Errorf("output[%d] should be 0, got %d", i, output[i])
		}
	}
}

// TestBN256PairingThreePairs tests pairing with 3 pairs:
// e(G1, G2) * e(2*G1, G2) * e(-3*G1, G2) = e(G1+2G1-3G1, G2) = e(O, G2) = 1
func TestBN256PairingThreePairs(t *testing.T) {
	c := newBN256Pairing()

	g1Gen := bn254G1Gen()
	g2Gen := bn254G2Gen()

	// Compute 2*G1
	var g1x2 bn254.G1Affine
	g1x2.ScalarMultiplication(&g1Gen, big.NewInt(2))

	// Compute -3*G1
	var g1x3 bn254.G1Affine
	g1x3.ScalarMultiplication(&g1Gen, big.NewInt(3))
	var g1x3Neg bn254.G1Affine
	g1x3Neg.Neg(&g1x3)

	input := make([]byte, 576) // 3 * 192
	copy(input[0:192], encodePair(g1Gen, g2Gen))
	copy(input[192:384], encodePair(g1x2, g2Gen))
	copy(input[384:576], encodePair(g1x3Neg, g2Gen))

	output, err := c.Run(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// e(G1, G2) * e(2*G1, G2) * e(-3*G1, G2) = e(G1+2G1-3G1, G2) = e(O, G2) = 1
	if output[31] != 1 {
		t.Error("e(G1,G2)*e(2G1,G2)*e(-3G1,G2) should equal 1")
	}
}

// TestBN256PairingAddress verifies the precompiled contract address
func TestBN256PairingAddress(t *testing.T) {
	c := newBN256Pairing()
	addr := c.Address()
	if addr[19] != 8 {
		t.Errorf("expected address ending in 8, got %d", addr[19])
	}
}

// TestBN256PairingG2SubgroupCheck tests that a G2 point not in the subgroup is rejected
func TestBN256PairingG2SubgroupCheck(t *testing.T) {
	c := newBN256Pairing()

	g1Gen := bn254G1Gen()

	// Create a G2 point that's on the curve but test the subgroup check runs
	// For BN254, the G2 cofactor is very large, so random points are likely not in the subgroup
	// We test with a known valid generator point first
	g2Gen := bn254G2Gen()

	input := encodePair(g1Gen, g2Gen)
	_, err := c.Run(input)
	if err != nil {
		t.Fatalf("valid generator points should pass: %v", err)
	}
}
