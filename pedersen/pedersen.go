// Quantaureum Node source, version 1.0.0.
package pedersen

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

var (
	ErrInvalidCommitment  = errors.New("pedersen: invalid commitment")
	ErrVerificationFailed = errors.New("pedersen: commitment verification failed")
	curveOrder            = fr.Modulus()
)

func CurveOrder() *big.Int {
	return new(big.Int).Set(curveOrder)
}

type Generator struct {
	G bls12381.G1Affine
	H bls12381.G1Affine
}

type Commitment struct {
	Point bls12381.G1Affine
}

func NewGenerator() (*Generator, error) {
	_, _, g1, _ := bls12381.Generators()
	if g1.IsInfinity() {
		return nil, fmt.Errorf("pedersen: generator G is point at infinity")
	}
	if !g1.IsOnCurve() {
		return nil, fmt.Errorf("pedersen: generator G is not on curve")
	}
	if !g1.IsInSubGroup() {
		return nil, fmt.Errorf("pedersen: generator G is not in subgroup")
	}

	h, err := bls12381.HashToG1(
		[]byte("Quantaureum-Pedersen-H-generator-v1"),
		[]byte("QUANTAUREUM_PEDERSEN_V1"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to derive H generator: %w", err)
	}

	if h.IsInfinity() {
		return nil, fmt.Errorf("derived H generator is point at infinity")
	}

	if !h.IsOnCurve() || !h.IsInSubGroup() {
		return nil, fmt.Errorf("derived H generator is not a valid subgroup element")
	}

	return &Generator{G: g1, H: h}, nil
}

func (gen *Generator) Commit(value *big.Int, blinding *big.Int) *Commitment {
	v := new(big.Int).Mod(value, curveOrder)
	r := new(big.Int).Mod(blinding, curveOrder)

	var vG, rH bls12381.G1Affine
	vG.ScalarMultiplication(&gen.G, v)
	rH.ScalarMultiplication(&gen.H, r)

	var c bls12381.G1Affine
	c.Add(&vG, &rH)

	return &Commitment{Point: c}
}

func (gen *Generator) Verify(c *Commitment, value *big.Int, blinding *big.Int) bool {
	expected := gen.Commit(value, blinding)
	return c.Point.Equal(&expected.Point)
}

func (gen *Generator) HomomorphicAdd(c1, c2 *Commitment) *Commitment {
	var result bls12381.G1Affine
	result.Add(&c1.Point, &c2.Point)
	return &Commitment{Point: result}
}

func (gen *Generator) HomomorphicSub(c1, c2 *Commitment) *Commitment {
	var result bls12381.G1Affine
	result.Sub(&c1.Point, &c2.Point)
	return &Commitment{Point: result}
}

func (gen *Generator) ScalarMulCommitment(c *Commitment, scalar *big.Int) *Commitment {
	s := new(big.Int).Mod(scalar, curveOrder)
	var result bls12381.G1Affine
	result.ScalarMultiplication(&c.Point, s)
	return &Commitment{Point: result}
}

func (gen *Generator) VerifyBalance(inputCommitments, outputCommitments []*Commitment, feeCommitment *Commitment) bool {
	if len(inputCommitments) == 0 {
		return false
	}

	var inputSum bls12381.G1Affine
	inputSum.Set(&inputCommitments[0].Point)
	for i := 1; i < len(inputCommitments); i++ {
		inputSum.Add(&inputSum, &inputCommitments[i].Point)
	}

	var outputSum bls12381.G1Affine
	if len(outputCommitments) > 0 {
		outputSum.Set(&outputCommitments[0].Point)
		for i := 1; i < len(outputCommitments); i++ {
			outputSum.Add(&outputSum, &outputCommitments[i].Point)
		}
	}

	var diff bls12381.G1Affine
	diff.Sub(&inputSum, &outputSum)

	return diff.Equal(&feeCommitment.Point)
}

func RandomBlinding() (*big.Int, error) {
	return rand.Int(rand.Reader, curveOrder)
}

func (c *Commitment) Bytes() []byte {
	b := c.Point.Bytes()
	return b[:]
}

func (c *Commitment) BytesFixed() [48]byte {
	return c.Point.Bytes()
}

func CommitmentFromBytes(data []byte) (*Commitment, error) {
	if len(data) == 0 {
		return nil, ErrInvalidCommitment
	}
	var p bls12381.G1Affine
	if _, err := p.SetBytes(data); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCommitment, err)
	}
	return &Commitment{Point: p}, nil
}

func (c *Commitment) IsIdentity() bool {
	return c.Point.IsInfinity()
}

func (c *Commitment) Equal(other *Commitment) bool {
	return c.Point.Equal(&other.Point)
}

func (gen *Generator) CommitToBytes(value *big.Int, blinding []byte) ([]byte, error) {
	if len(blinding) < 32 {
		return nil, fmt.Errorf("blinding factor must be at least 32 bytes, got %d", len(blinding))
	}
	r := new(big.Int).SetBytes(blinding)
	r.Mod(r, curveOrder)
	c := gen.Commit(value, r)
	return c.Bytes(), nil
}

func DeriveHFromSeed(seed []byte) (bls12381.G1Affine, error) {
	h := sha256.Sum256(seed)
	var u fp.Element
	u.SetBytes(h[:])

	for i := 0; i < 256; i++ {
		candidate := bls12381.MapToG1(u)
		candidate.ClearCofactor(&candidate)
		if candidate.IsOnCurve() && candidate.IsInSubGroup() && !candidate.IsInfinity() {
			return candidate, nil
		}
		h2 := sha256.Sum256(append(h[:], byte(i)))
		u.SetBytes(h2[:])
	}

	return bls12381.G1Affine{}, fmt.Errorf("failed to derive H from seed after 256 attempts")
}
