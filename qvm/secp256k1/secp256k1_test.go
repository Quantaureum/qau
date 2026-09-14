// Quantaureum Node source, version 1.0.0.
package secp256k1

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func fromHex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex")
	}
	return v
}

func TestScalarBaseMult_KnownVectors(t *testing.T) {
	c := Shared()

	// 1*G == G
	x, y := c.ScalarBaseMult(big.NewInt(1).Bytes())
	if x == nil || y == nil || x.Cmp(gx) != 0 || y.Cmp(gy) != 0 {
		t.Fatalf("1*G mismatch: got (%v, %v)", x, y)
	}

	// 2*G — well-known secp256k1 vector.
	x, y = c.ScalarBaseMult(big.NewInt(2).Bytes())
	wantX := fromHex("C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5")
	wantY := fromHex("1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A")
	if x == nil || y == nil || x.Cmp(wantX) != 0 || y.Cmp(wantY) != 0 {
		t.Fatalf("2*G mismatch:\n got (%x,\n      %x)", x, y)
	}

	// 3*G — well-known secp256k1 vector.
	x, y = c.ScalarBaseMult(big.NewInt(3).Bytes())
	wantX = fromHex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
	wantY = fromHex("388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672")
	if x == nil || y == nil || x.Cmp(wantX) != 0 || y.Cmp(wantY) != 0 {
		t.Fatalf("3*G mismatch:\n got (%x,\n      %x)", x, y)
	}

	// N*G == point at infinity.
	x, y = c.ScalarBaseMult(n.Bytes())
	if x != nil || y != nil {
		t.Fatalf("N*G should be infinity, got (%x, %x)", x, y)
	}

	// 0*G == point at infinity.
	x, y = c.ScalarBaseMult(nil)
	if x != nil || y != nil {
		t.Fatalf("0*G should be infinity, got (%x, %x)", x, y)
	}
}

func TestAdd_Double_Consistency(t *testing.T) {
	c := Shared()

	// G + G == 2*G (via Double) == ScalarBaseMult(2).
	dx, dy := c.Double(gx, gy)
	ax, ay := c.Add(gx, gy, gx, gy)
	if dx == nil || ax == nil || dx.Cmp(ax) != 0 || dy.Cmp(ay) != 0 {
		t.Fatalf("Double(G) != Add(G, G)")
	}

	// 2G + G == 3*G.
	tx, ty := c.ScalarBaseMult(big.NewInt(3).Bytes())
	px, py := c.Add(dx, dy, gx, gy)
	if px == nil || tx == nil || px.Cmp(tx) != 0 || py.Cmp(ty) != 0 {
		t.Fatalf("Add(2G, G) != 3*G")
	}

	// G + (-G) == infinity.
	negY := new(big.Int).Sub(p, gy)
	x, y := c.Add(gx, gy, gx, negY)
	if x != nil || y != nil {
		t.Fatalf("G + (-G) should be infinity, got (%x, %x)", x, y)
	}

	// Off-curve inputs rejected.
	if x, y := c.Add(gx, gy, big.NewInt(1), big.NewInt(1)); x != nil || y != nil {
		t.Fatalf("Add with off-curve point should return nil")
	}
	if x, y := c.ScalarMult(big.NewInt(1), big.NewInt(1), big.NewInt(5).Bytes()); x != nil || y != nil {
		t.Fatalf("ScalarMult with off-curve point should return nil")
	}
}

func TestScalarMult_Distributivity(t *testing.T) {
	c := Shared()
	for i := 0; i < 8; i++ {
		k1, err := rand.Int(rand.Reader, n)
		if err != nil {
			t.Fatal(err)
		}
		k2, err := rand.Int(rand.Reader, n)
		if err != nil {
			t.Fatal(err)
		}

		// (k1+k2 mod N)*G == k1*G + k2*G
		sum := new(big.Int).Add(k1, k2)
		sum.Mod(sum, n)
		sx, sy := c.ScalarBaseMult(sum.Bytes())

		a1x, a1y := c.ScalarBaseMult(k1.Bytes())
		a2x, a2y := c.ScalarBaseMult(k2.Bytes())
		if sum.Sign() == 0 {
			if sx != nil || sy != nil {
				t.Fatalf("0*G should be infinity")
			}
			continue
		}
		px, py := c.Add(a1x, a1y, a2x, a2y)
		if px == nil || sx == nil {
			// k1*G + k2*G == infinity only if k1+k2 == N; excluded by mod above
			// unless k1+k2 == N exactly (sum mod n == 0 handled) — treat as failure.
			t.Fatalf("unexpected infinity in distributivity check")
		}
		if px.Cmp(sx) != 0 || py.Cmp(sy) != 0 {
			t.Fatalf("(k1+k2)*G != k1*G + k2*G")
		}

		// ScalarMult on G must agree with ScalarBaseMult.
		mx, my := c.ScalarMult(gx, gy, k1.Bytes())
		if mx == nil || mx.Cmp(a1x) != 0 || my.Cmp(a1y) != 0 {
			t.Fatalf("ScalarMult(G, k) != ScalarBaseMult(k)")
		}

		// Result must be on the curve.
		if !c.IsOnCurve(sx, sy) {
			t.Fatalf("(k1+k2)*G not on curve")
		}
	}
}

func TestIsOnCurve(t *testing.T) {
	c := Shared()
	if !c.IsOnCurve(gx, gy) {
		t.Fatalf("generator not on curve")
	}
	// (Gx, Gy+1) must not be on the curve.
	if c.IsOnCurve(gx, new(big.Int).Add(gy, big.NewInt(1))) {
		t.Fatalf("invalid point accepted")
	}
	// nil / out-of-range rejected.
	if c.IsOnCurve(nil, gy) || c.IsOnCurve(gx, nil) {
		t.Fatalf("nil accepted")
	}
	if c.IsOnCurve(p, gy) || c.IsOnCurve(gx, p) {
		t.Fatalf("out-of-range coordinate accepted")
	}
}
