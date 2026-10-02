// Quantaureum Node source, version 1.0.0.
package vdf

import "math/bits"

// Element is an element of R = Z_q[x]/(Φ_24(x)), stored as 8 coefficients in
// little-endian order (c[i] multiplies x^i), each reduced to [0, q).
//
// All operations take the modulus explicitly so that the package can serve
// both Papercraft parameter families (QA / QBC) without code changes.
type Element [Phi]uint64

// mulFlushInterval is the number of raw products accumulated in a 128-bit
// accumulator before a REDC flush. 3·q² < q·2^64 ⟺ 3q < 2^64 holds for
// every modulus in this package (QBC ≈ 4.61e18, QA ≈ 4.61e18), so each
// REDC input stays below q·R. The bound is 3q < 2^64, not q < 2^63.
const mulFlushInterval = 3

// MulMont returns a·b for Montgomery-form operands with the result also in
// Montgomery form. Per output coefficient the ≤8 raw products are summed in
// a 128-bit accumulator, flushed through REDC every mulFlushInterval terms;
// the Φ24 fold is applied on the Montgomery values (add/sub are linear).
func (r *Reducer) MulElement(a, b Element) Element {
	var out [2*Phi - 1]uint64
	for c := 0; c < 2*Phi-1; c++ {
		var accH, accL uint64
		var mont uint64
		n := 0
		for i := 0; i < Phi; i++ {
			j := c - i
			if j < 0 || j >= Phi {
				continue
			}
			h, l := bits.Mul64(a[i], b[j])
			var carry uint64
			accL, carry = bits.Add64(accL, l, 0)
			accH += h + carry
			n++
			if n == mulFlushInterval {
				mont = AddMod(mont, r.Reduce(accH, accL), r.Q)
				accH, accL, n = 0, 0, 0
			}
		}
		if n > 0 {
			mont = AddMod(mont, r.Reduce(accH, accL), r.Q)
		}
		out[c] = mont
	}
	var res Element
	copy(res[:Phi], out[:Phi])
	for k := 0; k < 4; k++ {
		if v := out[Phi+k]; v != 0 {
			res[phi24MidShift+k] = AddMod(res[phi24MidShift+k], v, r.Q)
			res[k] = SubMod(res[k], v, r.Q)
		}
	}
	for k := 0; k < 3; k++ {
		if v := out[12+k]; v != 0 {
			res[k] = SubMod(res[k], v, r.Q)
		}
	}
	return res
}

// phi24MidShift is the fold-back offset for product terms of degree 8..11:
// x^8 ≡ x^4 - 1 ⇒ those terms add to x^4..x^7 and subtract from x^0..x^3.
const phi24MidShift = 4

// Mul returns a·b in R using schoolbook multiplication followed by reduction
// modulo Φ_24(x): the degree-14 product folds via x^8 ≡ x^4 - 1 and
// x^12 ≡ -1 (which holds because (x^4+1)·Φ_24(x) = x^12 + 1).
func (a Element) Mul(b Element, q uint64) Element {
	var product [2*Phi - 1]uint64 // degree < 15
	for i := 0; i < Phi; i++ {
		if a[i] == 0 {
			continue
		}
		ai := a[i]
		for j := 0; j < Phi; j++ {
			product[i+j] = AddMod(product[i+j], MulMod(ai, b[j], q), q)
		}
	}
	var r Element
	for i := 0; i < Phi; i++ {
		r[i] = product[i]
	}
	// x^8..x^11 ≡ x^4..x^7 minus x^0..x^3.
	for k := 0; k < 4; k++ {
		if c := product[Phi+k]; c != 0 {
			r[phi24MidShift+k] = AddMod(r[phi24MidShift+k], c, q)
			r[k] = SubMod(r[k], c, q)
		}
	}
	// x^12..x^14 ≡ -x^0..-x^2.
	for k := 0; k < 3; k++ {
		if c := product[12+k]; c != 0 {
			r[k] = SubMod(r[k], c, q)
		}
	}
	return r
}

// Add returns a+b coefficient-wise mod q.
func (a Element) Add(b Element, q uint64) Element {
	var r Element
	for i := range r {
		r[i] = AddMod(a[i], b[i], q)
	}
	return r
}

// Sub returns a-b coefficient-wise mod q.
func (a Element) Sub(b Element, q uint64) Element {
	var r Element
	for i := range r {
		r[i] = SubMod(a[i], b[i], q)
	}
	return r
}

// Neg returns -a mod q.
func (a Element) Neg(q uint64) Element {
	var r Element
	for i := range r {
		if a[i] != 0 {
			r[i] = q - a[i]
		}
	}
	return r
}

// X returns the ring element x (the generator), i.e. coefficients [0,1,0,...].
func X(q uint64) Element {
	var r Element
	r[1] = 1 % q
	return r
}

// One returns the multiplicative identity.
func One(q uint64) Element {
	var r Element
	r[0] = 1 % q
	return r
}

// IsZero reports whether a is the additive identity.
func (a Element) IsZero() bool {
	for _, c := range a {
		if c != 0 {
			return false
		}
	}
	return true
}

// Equal reports whether a and b have identical coefficients.
func (a Element) Equal(b Element) bool {
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Bytes serializes a as 64 bytes, little-endian per coefficient.
func (a Element) Bytes() []byte {
	out := make([]byte, 0, Phi*8)
	for _, c := range a {
		var buf [8]byte
		for k := 0; k < 8; k++ {
			buf[k] = byte(c >> (8 * k))
		}
		out = append(out, buf[:]...)
	}
	return out
}

// FromBytes parses 64 bytes (little-endian per coefficient).
func FromBytes(data []byte, q uint64) (Element, error) {
	var e Element
	if len(data) != Phi*8 {
		return e, ErrShortBytes
	}
	for i := range e {
		var c uint64
		for k := 0; k < 8; k++ {
			c |= uint64(data[i*8+k]) << (8 * k)
		}
		if c >= q {
			return Element{}, ErrCoeffOutOfRange
		}
		e[i] = c
	}
	return e, nil
}
