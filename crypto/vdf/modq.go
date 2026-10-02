// Quantaureum Node source, version 1.0.0.
package vdf

import (
	"math/bits"
	"sync"
)

// AddMod returns (a + b) mod q. Inputs must be < q, and q < 2^63 so that the
// sum cannot wrap twice.
func AddMod(a, b, q uint64) uint64 {
	s := a + b
	if s >= q {
		s -= q
	}
	return s
}

// SubMod returns (a - b) mod q. Inputs must be < q.
func SubMod(a, b, q uint64) uint64 {
	if a >= b {
		return a - b
	}
	return a + (q - b)
}

// MulMod returns (a * b) mod q for a, b < q. This is the scalar cold path
// (parameter setup, basis maps, tests); hot loops use Reducer.Mul instead.
func MulMod(a, b, q uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi >= q {
		hi %= q
	}
	_, r := bits.Div64(hi, lo, q)
	return r
}

// InvMod returns a^-1 mod q for odd prime q and 0 < a < q
// (extended Euclid; a and q must be coprime).
func InvMod(a, q uint64) uint64 {
	if a == 0 {
		panic("vdf: InvMod(0)")
	}
	// Extended Euclid on (a, q): track Bézout coefficient for a.
	var t, newT uint64 = 0, 1
	var r, newR uint64 = q, a % q
	for newR != 0 {
		quot := r / newR
		t, newT = newT, SubMod(t, MulMod(quot, newT, q), q)
		r, newR = newR, r-quot*newR
	}
	if r != 1 {
		panic("vdf: InvMod arguments not coprime")
	}
	return t
}

// PowMod returns a^e mod q by square-and-multiply.
func PowMod(a, e, q uint64) uint64 {
	result := uint64(1)
	base := a % q
	for e > 0 {
		if e&1 == 1 {
			result = MulMod(result, base, q)
		}
		base = MulMod(base, base, q)
		e >>= 1
	}
	return result
}

// Reducer holds the Montgomery-domain constants for one modulus q and
// provides division-free modular multiplication for hot loops.
//
// Montgomery representation of a is a·R mod q with R = 2^64. Addition,
// subtraction and negation are representation-linear; multiplication of two
// Montgomery values followed by REDC yields the Montgomery product.
type Reducer struct {
	Q       uint64 // the modulus
	R       uint64 // R mod q  (2^64 mod q)
	R2      uint64 // R^2 mod q (for domain entry)
	QNeg    uint64 // -q^-1 mod 2^64 (for REDC)
	MontOne uint64 // 1 in Montgomery form (= R mod q)
}

var reducerCache sync.Map // q -> *Reducer

// NewReducer returns the cached Montgomery context for q (odd, prime, q > 2^60).
func NewReducer(q uint64) *Reducer {
	if v, ok := reducerCache.Load(q); ok {
		return v.(*Reducer)
	}
	r := &Reducer{Q: q}
	_, r.R = bits.Div64(1, 0, q) // R = 2^64 mod q (Div64 returns quotient first)
	r.R2 = PowMod(2, 128, q)
	// Hensel lifting: q^-1 mod 2^64.
	inv := uint64(1)
	for i := 0; i < 6; i++ {
		inv *= 2 - q*inv
	}
	r.QNeg = uint64(0) - inv
	r.MontOne = r.R
	reducerCache.Store(q, r)
	return r
}

// Reduce is the Montgomery REDC: given T = (th, tl) with T < q·R, returns
// T·R^-1 mod q. The result is < 2q and is conditionally reduced once.
func (r *Reducer) Reduce(th, tl uint64) uint64 {
	m := tl * r.QNeg
	mh, ml := bits.Mul64(m, r.Q)
	_, carry := bits.Add64(tl, ml, 0) // low word dropped: this is the /R
	sh := th + mh + carry
	if sh >= r.Q {
		sh -= r.Q
	}
	return sh
}

// ToMont maps a plain value into the Montgomery domain.
func (r *Reducer) ToMont(a uint64) uint64 {
	th, tl := bits.Mul64(a, r.R2)
	return r.Reduce(th, tl)
}

// FromMont maps a Montgomery value back to the plain residue.
// The value sits in the LOW word: T = a (th = 0), so REDC(T) = a·R^-1.
func (r *Reducer) FromMont(a uint64) uint64 {
	return r.Reduce(0, a)
}
