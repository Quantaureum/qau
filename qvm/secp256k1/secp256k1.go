// Quantaureum Node source, version 1.0.0.
// Package secp256k1 implements the secp256k1 elliptic curve
// (y^2 = x^3 + 7 over Fp, p = 2^256 - 2^32 - 977) in pure Go.
//
// R37-FIX (2026-07-30): Go 1.26 removed the generic elliptic.CurveParams
// point operations — Add/Double/ScalarMult/ScalarBaseMult now panic
// unconditionally ("crypto/elliptic: attempted operation on invalid point").
// The ecrecover precompile and the AUTH opcode both perform secp256k1
// ECDSA public-key recovery, so this package provides a self-contained
// implementation using Jacobian-coordinate arithmetic (EFD formulas for
// a=0 short-Weierstrass curves: dbl-2009-l, add-2007-bl).
//
// The point at infinity is represented internally by z == 0; public
// methods return (nil, nil) for it, matching the historical behavior
// callers were written against (all recovery call sites already reject
// nil results).
package secp256k1

import (
	"crypto/elliptic"
	"math/big"
	"sync"
)

var (
	p, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	n, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)

	params = &elliptic.CurveParams{
		P:       p,
		N:       n,
		B:       big.NewInt(7),
		Gx:      gx,
		Gy:      gy,
		BitSize: 256,
		Name:    "secp256k1",
	}
)

var (
	sharedOnce sync.Once
	sharedInst *Curve
)

// Curve implements elliptic.Curve for secp256k1.
type Curve struct{}

// Shared returns the process-wide Curve instance. The curve is stateless
// and safe for concurrent use.
func Shared() *Curve {
	sharedOnce.Do(func() {
		sharedInst = &Curve{}
	})
	return sharedInst
}

// Params returns the curve parameters.
func (c *Curve) Params() *elliptic.CurveParams {
	return params
}

// IsOnCurve reports whether (x, y) satisfies y^2 = x^3 + 7 (mod p).
// Coordinates must be in [0, p); nil or out-of-range inputs return false.
func (c *Curve) IsOnCurve(x, y *big.Int) bool {
	if x == nil || y == nil {
		return false
	}
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return false
	}
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, p)
	x3 := new(big.Int).Mul(x, x)
	x3.Mod(x3, p)
	x3.Mul(x3, x)
	x3.Add(x3, big.NewInt(7))
	x3.Mod(x3, p)
	return y2.Cmp(x3) == 0
}

// Add returns the sum of two affine points. Returns (nil, nil) if the
// result is the point at infinity.
func (c *Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if !c.IsOnCurve(x1, y1) || !c.IsOnCurve(x2, y2) {
		return nil, nil
	}
	rx, ry, rz := addJacobian(x1, y1, big.NewInt(1), x2, y2, big.NewInt(1))
	return affineFromJacobian(rx, ry, rz)
}

// Double returns 2*(x1, y1). Returns (nil, nil) if the result is the
// point at infinity (y1 == 0).
func (c *Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	if !c.IsOnCurve(x1, y1) {
		return nil, nil
	}
	rx, ry, rz := doubleJacobian(x1, y1, big.NewInt(1))
	return affineFromJacobian(rx, ry, rz)
}

// ScalarMult returns k*(bx, by) where k is a big-endian integer.
// Returns (nil, nil) for off-curve inputs or an infinity result.
func (c *Curve) ScalarMult(bx, by *big.Int, k []byte) (*big.Int, *big.Int) {
	if !c.IsOnCurve(bx, by) {
		return nil, nil
	}
	x, y, z := new(big.Int), new(big.Int), new(big.Int) // infinity
	one := big.NewInt(1)
	for _, b := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y, z = doubleJacobian(x, y, z)
			if b&0x80 == 0x80 {
				x, y, z = addJacobian(x, y, z, bx, by, one)
			}
			b <<= 1
		}
	}
	return affineFromJacobian(x, y, z)
}

// ScalarBaseMult returns k*G where G is the secp256k1 generator.
// Returns (nil, nil) for an infinity result (k ≡ 0 mod n).
func (c *Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return c.ScalarMult(gx, gy, k)
}

// doubleJacobian computes 2*(x, y, z) in Jacobian coordinates using the
// EFD dbl-2009-l formulas for a=0 curves. All inputs must be reduced
// mod p; results are reduced mod p.
func doubleJacobian(x, y, z *big.Int) (*big.Int, *big.Int, *big.Int) {
	if z.Sign() == 0 || y.Sign() == 0 {
		// Doubling infinity, or a point with a vertical tangent.
		return new(big.Int), new(big.Int), new(big.Int)
	}
	// A = X1^2
	a := new(big.Int).Mul(x, x)
	a.Mod(a, p)
	// B = Y1^2
	b := new(big.Int).Mul(y, y)
	b.Mod(b, p)
	// C = B^2
	cc := new(big.Int).Mul(b, b)
	cc.Mod(cc, p)
	// D = 2*((X1+B)^2 - A - C)
	d := new(big.Int).Add(x, b)
	d.Mul(d, d)
	d.Sub(d, a)
	d.Sub(d, cc)
	d.Lsh(d, 1)
	d.Mod(d, p)
	// E = 3*A
	e := new(big.Int).Mul(a, big.NewInt(3))
	e.Mod(e, p)
	// F = E^2
	f := new(big.Int).Mul(e, e)
	f.Mod(f, p)
	// X3 = F - 2*D
	x3 := new(big.Int).Sub(f, new(big.Int).Lsh(d, 1))
	x3.Mod(x3, p)
	// Y3 = E*(D - X3) - 8*C
	y3 := new(big.Int).Sub(d, x3)
	y3.Mul(e, y3)
	y3.Sub(y3, new(big.Int).Lsh(cc, 3))
	y3.Mod(y3, p)
	// Z3 = 2*Y1*Z1
	z3 := new(big.Int).Mul(y, z)
	z3.Lsh(z3, 1)
	z3.Mod(z3, p)
	return x3, y3, z3
}

// addJacobian computes (x1,y1,z1) + (x2,y2,z2) in Jacobian coordinates
// using the EFD add-2007-bl formulas. Handles the infinity (z==0) and
// P == ±Q edge cases explicitly. Results are reduced mod p.
func addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	if z1.Sign() == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2), new(big.Int).Set(z2)
	}
	if z2.Sign() == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1), new(big.Int).Set(z1)
	}
	// Z1Z1 = Z1^2, Z2Z2 = Z2^2
	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, p)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, p)
	// U1 = X1*Z2Z2, U2 = X2*Z1Z1
	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, p)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, p)
	// S1 = Y1*Z2*Z2Z2, S2 = Y2*Z1*Z1Z1
	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, p)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, p)
	// H = U2 - U1, r = 2*(S2 - S1)
	h := new(big.Int).Sub(u2, u1)
	h.Mod(h, p)
	r := new(big.Int).Sub(s2, s1)
	r.Lsh(r, 1)
	r.Mod(r, p)
	if h.Sign() == 0 {
		if r.Sign() == 0 {
			// P == Q: fall back to doubling.
			return doubleJacobian(x1, y1, z1)
		}
		// P == -Q: result is the point at infinity.
		return new(big.Int), new(big.Int), new(big.Int)
	}
	// I = (2*H)^2, J = H*I, V = U1*I
	i2 := new(big.Int).Lsh(h, 1)
	i2.Mul(i2, i2)
	i2.Mod(i2, p)
	j := new(big.Int).Mul(h, i2)
	j.Mod(j, p)
	v := new(big.Int).Mul(u1, i2)
	v.Mod(v, p)
	// X3 = r^2 - J - 2*V
	x3 := new(big.Int).Mul(r, r)
	x3.Sub(x3, j)
	x3.Sub(x3, new(big.Int).Lsh(v, 1))
	x3.Mod(x3, p)
	// Y3 = r*(V - X3) - 2*S1*J
	y3 := new(big.Int).Sub(v, x3)
	y3.Mul(r, y3)
	t := new(big.Int).Mul(s1, j)
	t.Lsh(t, 1)
	y3.Sub(y3, t)
	y3.Mod(y3, p)
	// Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) * H
	z3 := new(big.Int).Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	z3.Mod(z3, p)
	return x3, y3, z3
}

// affineFromJacobian converts a Jacobian point back to affine
// coordinates. Returns (nil, nil) for the point at infinity.
func affineFromJacobian(x, y, z *big.Int) (*big.Int, *big.Int) {
	if z.Sign() == 0 {
		return nil, nil
	}
	zinv := new(big.Int).ModInverse(z, p)
	if zinv == nil {
		return nil, nil
	}
	zinv2 := new(big.Int).Mul(zinv, zinv)
	zinv2.Mod(zinv2, p)
	xOut := new(big.Int).Mul(x, zinv2)
	xOut.Mod(xOut, p)
	zinv3 := new(big.Int).Mul(zinv2, zinv)
	zinv3.Mod(zinv3, p)
	yOut := new(big.Int).Mul(y, zinv3)
	yOut.Mod(yOut, p)
	return xOut, yOut
}
