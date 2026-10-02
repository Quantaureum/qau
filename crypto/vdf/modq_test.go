// Quantaureum Node source, version 1.0.0.
package vdf

import (
	"math/big"
	"math/rand"
	"testing"
)

func TestMulModAgainstBig(t *testing.T) {
	q := QBC
	qb := new(big.Int).SetUint64(q)
	for i := 0; i < 500; i++ {
		a := rand.Uint64() % q
		b := rand.Uint64() % q
		got := MulMod(a, b, q)
		want := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).SetUint64(a), new(big.Int).SetUint64(b)), qb)
		if got != want.Uint64() {
			t.Fatalf("MulMod(%d,%d) = %d, want %d", a, b, got, want)
		}
	}
	// Boundary values.
	for _, pair := range [][2]uint64{{0, q - 1}, {q - 1, q - 1}, {1, q - 1}} {
		got := MulMod(pair[0], pair[1], q)
		want := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).SetUint64(pair[0]), new(big.Int).SetUint64(pair[1])), qb)
		if got != want.Uint64() {
			t.Fatalf("MulMod boundary %v = %d, want %d", pair, got, want)
		}
	}
}

func TestInvModAgainstBig(t *testing.T) {
	q := QBC
	qb := new(big.Int).SetUint64(q)
	r := rand.New(rand.NewSource(5))
	for i := 0; i < 100; i++ {
		a := r.Uint64() % q
		if a == 0 {
			continue
		}
		got := InvMod(a, q)
		want := new(big.Int).ModInverse(new(big.Int).SetUint64(a), qb)
		if want == nil {
			t.Fatalf("unexpected non-invertible %d", a)
		}
		if got != want.Uint64() {
			t.Fatalf("InvMod(%d) = %d, want %d", a, got, want)
		}
		if MulMod(a, got, q) != 1 {
			t.Fatalf("a * a^-1 != 1 for a=%d", a)
		}
	}
}

func TestPowModAgainstBig(t *testing.T) {
	q := QBC
	qb := new(big.Int).SetUint64(q)
	r := rand.New(rand.NewSource(6))
	for i := 0; i < 50; i++ {
		a := r.Uint64() % q
		e := r.Uint64()
		got := PowMod(a, e, q)
		want := new(big.Int).Exp(new(big.Int).SetUint64(a), new(big.Int).SetUint64(e), qb)
		if got != want.Uint64() {
			t.Fatalf("PowMod(%d,%d) = %d, want %d", a, e, got, want)
		}
	}
}
