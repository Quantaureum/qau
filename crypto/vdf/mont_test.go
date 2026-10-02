// Quantaureum Node source, version 1.0.0.
package vdf

import (
	"math/rand"
	"testing"
)

// TestMulMontAgainstPlain checks the Montgomery hot path against the plain
// schoolbook path on random operands.
func TestMulMontAgainstPlain(t *testing.T) {
	q := QBC
	red := NewReducer(q)
	r := rand.New(rand.NewSource(20))
	for i := 0; i < 200; i++ {
		a := randElement(r, q)
		b := randElement(r, q)
		want := a.Mul(b, q)
		prod := red.MulElement(red.ToMontElement(a), red.ToMontElement(b))
		got := fromMontVec([]Element{prod}, red)[0]
		if !got.Equal(want) {
			t.Fatalf("iter %d: Montgomery mismatch\n got=%v\n want=%v", i, got, want)
		}
	}
}

// ToMontElement converts a plain element into Montgomery form.
func (r *Reducer) ToMontElement(e Element) Element {
	return montElement(e, r)
}
