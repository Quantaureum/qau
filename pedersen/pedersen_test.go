// Quantaureum Node source, version 1.0.0.
package pedersen

import (
	"math/big"
	"testing"
)

func TestNewGenerator(t *testing.T) {
	gen, err := NewGenerator()
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}
	if gen.G.IsInfinity() {
		t.Error("G should not be infinity")
	}
	if gen.H.IsInfinity() {
		t.Error("H should not be infinity")
	}
	if gen.G.Equal(&gen.H) {
		t.Error("G and H should be different points")
	}
	if !gen.G.IsOnCurve() {
		t.Error("G should be on curve")
	}
	if !gen.H.IsOnCurve() {
		t.Error("H should be on curve")
	}
	if !gen.G.IsInSubGroup() {
		t.Error("G should be in subgroup")
	}
	if !gen.H.IsInSubGroup() {
		t.Error("H should be in subgroup")
	}
}

func TestCommitAndVerify(t *testing.T) {
	gen, _ := NewGenerator()

	value := big.NewInt(1000)
	blinding, _ := RandomBlinding()

	c := gen.Commit(value, blinding)
	if c == nil {
		t.Fatal("commitment should not be nil")
	}
	if c.IsIdentity() {
		t.Error("commitment should not be identity")
	}

	if !gen.Verify(c, value, blinding) {
		t.Error("verification should succeed for correct value and blinding")
	}

	wrongValue := big.NewInt(999)
	if gen.Verify(c, wrongValue, blinding) {
		t.Error("verification should fail for wrong value")
	}

	wrongBlinding, _ := RandomBlinding()
	if gen.Verify(c, value, wrongBlinding) {
		t.Error("verification should fail for wrong blinding")
	}
}

func TestHomomorphicProperty(t *testing.T) {
	gen, _ := NewGenerator()

	v1 := big.NewInt(1000)
	r1, _ := RandomBlinding()
	c1 := gen.Commit(v1, r1)

	v2 := big.NewInt(2000)
	r2, _ := RandomBlinding()
	c2 := gen.Commit(v2, r2)

	cSum := gen.HomomorphicAdd(c1, c2)

	vSum := new(big.Int).Add(v1, v2)
	rSum := new(big.Int).Add(r1, r2)
	rSum.Mod(rSum, curveOrder)

	if !gen.Verify(cSum, vSum, rSum) {
		t.Error("homomorphic addition should hold: C(v1,r1) + C(v2,r2) = C(v1+v2, r1+r2)")
	}
}

func TestHomomorphicSub(t *testing.T) {
	gen, _ := NewGenerator()

	v1 := big.NewInt(5000)
	r1, _ := RandomBlinding()
	c1 := gen.Commit(v1, r1)

	v2 := big.NewInt(2000)
	r2, _ := RandomBlinding()
	c2 := gen.Commit(v2, r2)

	cDiff := gen.HomomorphicSub(c1, c2)

	vDiff := new(big.Int).Sub(v1, v2)
	rDiff := new(big.Int).Sub(r1, r2)
	rDiff.Mod(rDiff, curveOrder)

	if !gen.Verify(cDiff, vDiff, rDiff) {
		t.Error("homomorphic subtraction should hold")
	}
}

func TestVerifyBalance(t *testing.T) {
	gen, _ := NewGenerator()

	inputValues := []*big.Int{big.NewInt(10000), big.NewInt(5000)}
	outputValues := []*big.Int{big.NewInt(12000), big.NewInt(2900)}
	fee := big.NewInt(100)

	inputBlindings := make([]*big.Int, len(inputValues))
	inputCommitments := make([]*Commitment, len(inputValues))
	for i, v := range inputValues {
		inputBlindings[i], _ = RandomBlinding()
		inputCommitments[i] = gen.Commit(v, inputBlindings[i])
	}

	outputBlindings := make([]*big.Int, len(outputValues))
	outputCommitments := make([]*Commitment, len(outputValues))
	for i, v := range outputValues {
		outputBlindings[i], _ = RandomBlinding()
		outputCommitments[i] = gen.Commit(v, outputBlindings[i])
	}

	rBalance := new(big.Int)
	for _, r := range inputBlindings {
		rBalance.Add(rBalance, r)
	}
	for _, r := range outputBlindings {
		rBalance.Sub(rBalance, r)
	}
	rBalance.Mod(rBalance, curveOrder)

	feeCommitment := gen.Commit(fee, rBalance)

	if !gen.VerifyBalance(inputCommitments, outputCommitments, feeCommitment) {
		t.Error("balance verification should succeed for matching amounts")
	}

	wrongFeeCommitment := gen.Commit(big.NewInt(999), rBalance)
	if gen.VerifyBalance(inputCommitments, outputCommitments, wrongFeeCommitment) {
		t.Error("balance verification should fail for wrong fee commitment")
	}
}

func TestCommitmentSerialization(t *testing.T) {
	gen, _ := NewGenerator()

	value := big.NewInt(42)
	blinding, _ := RandomBlinding()
	c := gen.Commit(value, blinding)

	data := c.Bytes()
	if len(data) == 0 {
		t.Fatal("serialized commitment should not be empty")
	}

	recovered, err := CommitmentFromBytes(data)
	if err != nil {
		t.Fatalf("failed to deserialize commitment: %v", err)
	}

	if !c.Equal(recovered) {
		t.Error("deserialized commitment should equal original")
	}
}

func TestCommitmentFromBytesInvalid(t *testing.T) {
	_, err := CommitmentFromBytes([]byte{})
	if err == nil {
		t.Error("should fail for empty bytes")
	}

	_, err = CommitmentFromBytes([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Error("should fail for invalid bytes")
	}
}

func TestRandomBlinding(t *testing.T) {
	r1, err := RandomBlinding()
	if err != nil {
		t.Fatalf("failed to generate random blinding: %v", err)
	}
	if r1.Sign() <= 0 {
		t.Error("blinding should be positive")
	}

	r2, _ := RandomBlinding()
	if r1.Cmp(r2) == 0 {
		t.Error("two random blindings should be different (extremely unlikely to be equal)")
	}
}

func TestZeroValueCommitment(t *testing.T) {
	gen, _ := NewGenerator()

	zeroVal := big.NewInt(0)
	blinding, _ := RandomBlinding()
	c := gen.Commit(zeroVal, blinding)

	if c.IsIdentity() {
		t.Error("commitment to zero with non-zero blinding should not be identity")
	}

	if !gen.Verify(c, zeroVal, blinding) {
		t.Error("verification should succeed for zero value")
	}
}

func TestDeterministicCommitment(t *testing.T) {
	gen, _ := NewGenerator()

	value := big.NewInt(12345)
	blinding := big.NewInt(67890)

	c1 := gen.Commit(value, blinding)
	c2 := gen.Commit(value, blinding)

	if !c1.Equal(c2) {
		t.Error("same value and blinding should produce same commitment")
	}
}

func TestGeneratorDeterminism(t *testing.T) {
	gen1, _ := NewGenerator()
	gen2, _ := NewGenerator()

	if !gen1.G.Equal(&gen2.G) {
		t.Error("G generators should be deterministic")
	}
	if !gen1.H.Equal(&gen2.H) {
		t.Error("H generators should be deterministic")
	}
}

func TestScalarMulCommitment(t *testing.T) {
	gen, _ := NewGenerator()

	v := big.NewInt(100)
	r, _ := RandomBlinding()
	c := gen.Commit(v, r)

	scalar := big.NewInt(3)
	cScaled := gen.ScalarMulCommitment(c, scalar)

	vScaled := new(big.Int).Mul(v, scalar)
	rScaled := new(big.Int).Mul(r, scalar)
	rScaled.Mod(rScaled, curveOrder)

	expected := gen.Commit(vScaled, rScaled)
	if !cScaled.Equal(expected) {
		t.Error("scalar multiplication of commitment should equal commitment to scaled value")
	}
}

func TestHomomorphicAddEdgeCases(t *testing.T) {
	gen, _ := NewGenerator()

	t.Run("add zero commitment to non-zero", func(t *testing.T) {
		v1 := big.NewInt(1000)
		r1, _ := RandomBlinding()
		c1 := gen.Commit(v1, r1)

		v2 := big.NewInt(0)
		r2 := big.NewInt(0)
		c2 := gen.Commit(v2, r2)

		cSum := gen.HomomorphicAdd(c1, c2)

		rSum := new(big.Int).Add(r1, r2)
		rSum.Mod(rSum, curveOrder)

		if !gen.Verify(cSum, v1, rSum) {
			t.Error("adding zero commitment should preserve original value")
		}
	})

	t.Run("add commitment to itself", func(t *testing.T) {
		v := big.NewInt(500)
		r, _ := RandomBlinding()
		c := gen.Commit(v, r)

		cDouble := gen.HomomorphicAdd(c, c)

		vDouble := new(big.Int).Mul(v, big.NewInt(2))
		rDouble := new(big.Int).Mul(r, big.NewInt(2))
		rDouble.Mod(rDouble, curveOrder)

		if !gen.Verify(cDouble, vDouble, rDouble) {
			t.Error("adding commitment to itself should equal doubling")
		}
	})

	t.Run("add three commitments", func(t *testing.T) {
		v1 := big.NewInt(100)
		r1, _ := RandomBlinding()
		c1 := gen.Commit(v1, r1)

		v2 := big.NewInt(200)
		r2, _ := RandomBlinding()
		c2 := gen.Commit(v2, r2)

		v3 := big.NewInt(300)
		r3, _ := RandomBlinding()
		c3 := gen.Commit(v3, r3)

		cSum12 := gen.HomomorphicAdd(c1, c2)
		cSum123 := gen.HomomorphicAdd(cSum12, c3)

		vSum := new(big.Int).Add(v1, v2)
		vSum.Add(vSum, v3)
		rSum := new(big.Int).Add(r1, r2)
		rSum.Add(rSum, r3)
		rSum.Mod(rSum, curveOrder)

		if !gen.Verify(cSum123, vSum, rSum) {
			t.Error("adding three commitments should equal commitment to sum")
		}
	})

	t.Run("subtract then add back", func(t *testing.T) {
		v1 := big.NewInt(1000)
		r1, _ := RandomBlinding()
		c1 := gen.Commit(v1, r1)

		v2 := big.NewInt(300)
		r2, _ := RandomBlinding()
		c2 := gen.Commit(v2, r2)

		cDiff := gen.HomomorphicSub(c1, c2)
		cRestored := gen.HomomorphicAdd(cDiff, c2)

		rRestored := new(big.Int).Sub(r1, r2)
		rRestored.Add(rRestored, r2)
		rRestored.Mod(rRestored, curveOrder)

		if !gen.Verify(cRestored, v1, rRestored) {
			t.Error("subtract then add back should restore original")
		}
	})

	t.Run("large value homomorphic add", func(t *testing.T) {
		v1 := new(big.Int).Sub(curveOrder, big.NewInt(1))
		r1, _ := RandomBlinding()
		c1 := gen.Commit(v1, r1)

		v2 := big.NewInt(2)
		r2, _ := RandomBlinding()
		c2 := gen.Commit(v2, r2)

		cSum := gen.HomomorphicAdd(c1, c2)

		vSum := new(big.Int).Add(v1, v2)
		vSum.Mod(vSum, curveOrder)
		rSum := new(big.Int).Add(r1, r2)
		rSum.Mod(rSum, curveOrder)

		if !gen.Verify(cSum, vSum, rSum) {
			t.Error("homomorphic add with large values should work correctly with modular arithmetic")
		}
	})
}
