// Quantaureum Node source, version 1.0.0.
package secp256k1

// F-07 (2026-10-21): differential and boundary tests for the hand-written
// secp256k1 implementation. gnark-crypto's secp256k1 (already a module
// dependency) is used as the reference implementation. The audit asked for
// differential coverage against a mature library plus the point-at-infinity,
// off-curve, and scalar edge cases (0, n-1, n, n+1).

import (
	"crypto/sha256"
	"math/big"
	"testing"

	gk "github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
)

func requireReferencePoint(t *testing.T, name string, gotX, gotY *big.Int, want *gk.G1Affine) {
	t.Helper()
	if want.IsInfinity() {
		if gotX != nil || gotY != nil {
			t.Fatalf("%s: expected infinity, got (%v, %v)", name, gotX, gotY)
		}
		return
	}
	if gotX == nil || gotY == nil {
		t.Fatalf("%s: unexpected infinity (want %s)", name, want.String())
	}
	wantX := want.X.BigInt(new(big.Int))
	wantY := want.Y.BigInt(new(big.Int))
	if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
		t.Fatalf("%s: point mismatch\n got=(%s, %s)\nwant=(%s, %s)", name, gotX, gotY, wantX, wantY)
	}
}

func deterministicScalars(n *big.Int, count int) []*big.Int {
	out := make([]*big.Int, 0, count)
	for i := 0; i < count; i++ {
		h := sha256.Sum256([]byte{byte(i), 0xA7, 0x3C})
		s := new(big.Int).SetBytes(h[:])
		s.Mod(s, new(big.Int).Sub(n, big.NewInt(1)))
		s.Add(s, big.NewInt(1))
		out = append(out, s)
	}
	return out
}

func TestCurve_FieldParametersMatchReference(t *testing.T) {
	params := Shared().Params()
	if params.P.Cmp(fp.Modulus()) != 0 {
		t.Fatalf("field modulus mismatch: got %s want %s", params.P, fp.Modulus())
	}
	if params.N.Cmp(fr.Modulus()) != 0 {
		t.Fatalf("group order mismatch: got %s want %s", params.N, fr.Modulus())
	}
}

func TestCurve_Differential_ScalarBaseMult(t *testing.T) {
	c := Shared()
	n := c.Params().N

	scalars := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		new(big.Int).Sub(n, big.NewInt(1)),
		n,
		new(big.Int).Add(n, big.NewInt(1)),
	}
	scalars = append(scalars, deterministicScalars(n, 16)...)

	for _, s := range scalars {
		scalarBytes := s.FillBytes(make([]byte, 32))
		gotX, gotY := c.ScalarBaseMult(scalarBytes)

		var want gk.G1Affine
		want.ScalarMultiplicationBase(s)
		requireReferencePoint(t, "ScalarBaseMult("+s.String()+")", gotX, gotY, &want)
	}
}

func TestCurve_Differential_ScalarMult(t *testing.T) {
	c := Shared()
	n := c.Params().N

	baseX, baseY := c.ScalarBaseMult(big.NewInt(2).FillBytes(make([]byte, 32)))
	if !c.IsOnCurve(baseX, baseY) {
		t.Fatal("base point 2G is not on the curve")
	}
	var wantBase gk.G1Affine
	wantBase.ScalarMultiplicationBase(big.NewInt(2))

	scalars := append([]*big.Int{
		big.NewInt(0),
		big.NewInt(5),
		new(big.Int).Sub(n, big.NewInt(1)),
		n,
	}, deterministicScalars(n, 8)...)

	for _, s := range scalars {
		gotX, gotY := c.ScalarMult(baseX, baseY, s.FillBytes(make([]byte, 32)))

		var want gk.G1Affine
		want.ScalarMultiplication(&wantBase, s)
		requireReferencePoint(t, "ScalarMult(2G, "+s.String()+")", gotX, gotY, &want)
	}
}

func TestCurve_Differential_AddAndDouble(t *testing.T) {
	c := Shared()

	k1 := big.NewInt(3)
	k2 := big.NewInt(5)
	pX, pY := c.ScalarBaseMult(k1.FillBytes(make([]byte, 32)))
	qX, qY := c.ScalarBaseMult(k2.FillBytes(make([]byte, 32)))

	var gP, gQ, gSum gk.G1Affine
	gP.ScalarMultiplicationBase(k1)
	gQ.ScalarMultiplicationBase(k2)
	gSum.Add(&gP, &gQ)

	gotX, gotY := c.Add(pX, pY, qX, qY)
	requireReferencePoint(t, "3G + 5G", gotX, gotY, &gSum)

	var gDouble gk.G1Affine
	gDouble.Add(&gP, &gP)
	doubleX, doubleY := c.Double(pX, pY)
	requireReferencePoint(t, "2*(3G)", doubleX, doubleY, &gDouble)

	// P + (-P) must collapse to the point at infinity, represented as (nil, nil).
	negY := new(big.Int).Sub(c.Params().P, pY)
	if !c.IsOnCurve(pX, negY) {
		t.Fatal("-P is not on the curve")
	}
	if x, y := c.Add(pX, pY, pX, negY); x != nil || y != nil {
		t.Fatalf("P + (-P) should be infinity, got (%v, %v)", x, y)
	}
}

func TestCurve_Boundary_IsOnCurve(t *testing.T) {
	c := Shared()
	params := c.Params()
	plusOne := big.NewInt(1)

	cases := []struct {
		name string
		x    *big.Int
		y    *big.Int
		want bool
	}{
		{"generator", params.Gx, params.Gy, true},
		{"negated generator", params.Gx, new(big.Int).Sub(params.P, params.Gy), true},
		{"point at infinity encoding", big.NewInt(0), big.NewInt(0), false},
		{"off-curve y", params.Gx, new(big.Int).Add(params.Gy, plusOne), false},
		{"x equal to field modulus", params.P, params.Gy, false},
		{"y above field modulus", params.Gx, new(big.Int).Add(params.P, params.Gy), false},
		{"negative x", big.NewInt(-1), params.Gy, false},
		{"nil x", nil, params.Gy, false},
		{"nil y", params.Gx, nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.IsOnCurve(tc.x, tc.y); got != tc.want {
				t.Fatalf("IsOnCurve(%v, %v) = %v, want %v", tc.x, tc.y, got, tc.want)
			}
		})
	}
}

func TestCurve_Boundary_InvalidPointOperations(t *testing.T) {
	c := Shared()
	params := c.Params()
	offCurveY := new(big.Int).Add(params.Gy, big.NewInt(1))

	if x, y := c.Add(params.Gx, params.Gy, params.Gx, offCurveY); x != nil || y != nil {
		t.Fatalf("Add with an off-curve operand should return infinity, got (%v, %v)", x, y)
	}
	if x, y := c.Double(big.NewInt(0), big.NewInt(0)); x != nil || y != nil {
		t.Fatalf("Double(origin) should return infinity, got (%v, %v)", x, y)
	}
	if x, y := c.ScalarMult(big.NewInt(0), big.NewInt(0), []byte{1}); x != nil || y != nil {
		t.Fatalf("ScalarMult with an off-curve base should return infinity, got (%v, %v)", x, y)
	}
	if x, y := c.ScalarMult(params.Gx, params.Gy, nil); x != nil || y != nil {
		t.Fatalf("ScalarMult by the empty scalar should return infinity, got (%v, %v)", x, y)
	}
}
