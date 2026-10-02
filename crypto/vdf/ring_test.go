// Quantaureum Node source, version 1.0.0.
package vdf

import (
	"math/big"
	"math/rand"
	"testing"
)

func randElement(r *rand.Rand, q uint64) Element {
	var e Element
	for i := range e {
		e[i] = rand.Uint64() % q
	}
	return e
}

// bigPolyMulReduce multiplies two polynomials over Z_q with math/big and
// reduces the degree-14 product modulo the monic Φ_24(x) = x^8 - x^4 + 1 by
// descending substitution (x^8 ≡ x^4 - 1, x^12 ≡ -1). It serves as an
// independent oracle for Element.Mul.
func bigPolyMulReduce(a, b Element, q uint64) Element {
	r := make([]*big.Int, 2*Phi-1)
	for i := range r {
		r[i] = new(big.Int)
	}
	qb := new(big.Int).SetUint64(q)
	for i := 0; i < Phi; i++ {
		ai := new(big.Int).SetUint64(a[i])
		for j := 0; j < Phi; j++ {
			t := new(big.Int).Mul(ai, new(big.Int).SetUint64(b[j]))
			r[i+j].Add(r[i+j], t)
		}
	}
	for j := 2*Phi - 2; j >= Phi; j-- {
		t := new(big.Int).Set(r[j])
		r[j] = new(big.Int)
		// x^j ≡ x^(j-4) - x^(j-8) for 8 ≤ j ≤ 14 (from x^8 ≡ x^4 - 1);
		// descending order ensures folded terms land on already-reduced degrees.
		r[j-4].Add(r[j-4], t)
		r[j-8].Sub(r[j-8], t)
	}
	var out Element
	for i := range out {
		out[i] = new(big.Int).Mod(r[i], qb).Uint64()
	}
	return out
}

func TestXPowerReductions(t *testing.T) {
	q := QBC
	x4 := Element{} // x^4
	x4[4] = 1
	x := X(q)

	got := x.Mul(x, q).Mul(x, q).Mul(x, q) // x^4
	want := x4
	if !got.Equal(want) {
		t.Fatalf("x^4 = %v, want %v", got, want)
	}

	// x^8 = x^4 * x^4 ≡ x^4 - 1 (Φ_24 vanishing).
	got = x4.Mul(x4, q)
	want = x4.Sub(One(q), q)
	if !got.Equal(want) {
		t.Fatalf("x^8 = %v, want x^4 - 1 = %v", got, want)
	}

	// x^12 = x^8 * x^4 ≡ -1.
	got = got.Mul(x4, q)
	want = One(q).Neg(q)
	if !got.Equal(want) {
		t.Fatalf("x^12 = %v, want -1", got)
	}

	// x^24 = (x^12)^2 ≡ 1.
	if got = got.Mul(got, q); !got.Equal(One(q)) {
		t.Fatalf("x^24 = %v, want 1", got)
	}
}

func TestMulAgainstBigOracle(t *testing.T) {
	q := QBC
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		a := randElement(r, q)
		b := randElement(r, q)
		got := a.Mul(b, q)
		want := bigPolyMulReduce(a, b, q)
		if !got.Equal(want) {
			t.Fatalf("iter %d: Mul mismatch\n a=%v\n b=%v\n got=%v\n want=%v", i, a, b, got, want)
		}
	}
}

func TestRingLaws(t *testing.T) {
	q := QBC
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 50; i++ {
		a := randElement(r, q)
		b := randElement(r, q)
		c := randElement(r, q)

		if ab := a.Mul(b, q); !ab.Equal(b.Mul(a, q)) {
			t.Fatal("Mul not commutative")
		}
		if ab := a.Mul(b, q).Mul(c, q); !ab.Equal(a.Mul(b.Mul(c, q), q)) {
			t.Fatal("Mul not associative")
		}
		lhs := a.Mul(b.Add(c, q), q)
		rhs := a.Mul(b, q).Add(a.Mul(c, q), q)
		if !lhs.Equal(rhs) {
			t.Fatal("Mul not distributive over Add")
		}
		if !a.Mul(One(q), q).Equal(a) {
			t.Fatal("One is not a multiplicative identity")
		}
		if !a.Add(a.Neg(q), q).IsZero() {
			t.Fatal("Neg is not an additive inverse")
		}
	}
}

func TestSerialization(t *testing.T) {
	q := QBC
	r := rand.New(rand.NewSource(3))
	a := randElement(r, q)
	data := a.Bytes()
	if len(data) != Phi*8 {
		t.Fatalf("serialized length = %d, want %d", len(data), Phi*8)
	}
	back, err := FromBytes(data, q)
	if err != nil {
		t.Fatalf("FromBytes: %v", err)
	}
	if !back.Equal(a) {
		t.Fatal("round-trip mismatch")
	}
	if _, err := FromBytes(data[:63], q); err != ErrShortBytes {
		t.Fatalf("short input: got %v, want ErrShortBytes", err)
	}
	bad := append([]byte(nil), data...)
	bad[0] = byte(q) // q ≈ 2^62 ⇒ first byte alone cannot exceed q; use high byte
	bad[7] = 0xff
	if _, err := FromBytes(bad, q); err != ErrCoeffOutOfRange {
		t.Fatalf("out-of-range coefficient: got %v, want ErrCoeffOutOfRange", err)
	}
}
