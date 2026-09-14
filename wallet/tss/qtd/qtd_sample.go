// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"crypto/sha256"
	"encoding/binary"

	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/params"
	"golang.org/x/crypto/sha3"
)

// SampleMasking generates a masking vector y with coefficients in [-Eta2, Eta2].
// For Dilithium3, Eta2 = 72.
// DEPRECATED for threshold use: this produces narrow uniform masking that does
// NOT preserve zero-knowledge under aggregation. Use SampleGaussianMasking instead.
// Q21-006 FIX: This function is kept for backward compatibility but prints a
// deprecation warning. It should never be used in production threshold signing.
func SampleMasking(seed []byte) (PolyVec, error) {
	// FIX: Hard guard against production use. SampleMasking produces
	// narrow uniform masking that does NOT preserve zero-knowledge under
	// aggregation. If QAU_PRODUCTION=1 is set, panic immediately rather than
	// silently returning an insecure masking vector.
	if params.IsProductionEnv() {
		panic("SampleMasking is deprecated and must not be used in production")
	}
	// Q21-006 FIX: Log deprecation warning via structured logger
	logging.Warn("SampleMasking is deprecated and insecure for threshold use, use SampleGaussianMasking instead")
	eta := 72
	l := 5

	y := make(PolyVec, l)
	for i := 0; i < l; i++ {
		polySeed := make([]byte, len(seed)+1)
		copy(polySeed, seed)
		polySeed[len(seed)] = byte(i)
		if err := y[i].SampleError(polySeed, eta); err != nil {
			return nil, err
		}
	}
	return y, nil
}

// sampleUniformPoly fills a polynomial with coefficients uniform in [0, Q-1] using SHAKE128.
// This matches circl's internal Dilithium3 A matrix expansion (FIPS 204).
// seed[:32] is ρ, seed[32:34] encodes the matrix position as little-endian uint16 nonce.
func sampleUniformPoly(p *Poly, seed []byte, counter uint32) error {
	rho := make([]byte, 32)
	copy(rho, seed[:min(32, len(seed))])

	var nonce uint16
	if len(seed) >= 34 {
		nonce = binary.LittleEndian.Uint16(seed[32:34])
	}

	h := sha3.NewShake128()
	h.Write(rho)
	var nb [2]byte
	binary.LittleEndian.PutUint16(nb[:], nonce)
	h.Write(nb[:])

	i := 0
	for i < N {
		buf := make([]byte, 840)
		h.Read(buf)
		for j := 0; j < len(buf)-2 && i < N; j += 3 {
			t := (uint32(buf[j]) | uint32(buf[j+1])<<8 | uint32(buf[j+2])<<16) & 0x7fffff
			if t < Q {
				p[i] = int32(t)
				i++
			}
		}
	}
	return nil
}

// sampleInBall samples a polynomial with exactly tau non-zero coefficients
// each uniformly chosen from {-1, 1}. Used for challenge generation.
// Matches circl's PolyDeriveUniformBall: uses SHAKE-256 with inline sign bits.
func sampleInBall(p *Poly, seed []byte, tau int) error {
	if tau < 0 || tau > N {
		return ErrInvalidTau
	}

	p.Zero()

	if tau == 0 {
		return nil
	}

	var buf [136]byte // SHAKE-256 rate is 136
	h := sha3.NewShake256()
	h.Write(seed[:])
	h.Read(buf[:])

	// signs is read from the first 8 bytes of the SHAKE stream
	signs := binary.LittleEndian.Uint64(buf[:])
	bufOff := 8

	for i := uint16(N - tau); i < N; i++ {
		var b uint16
		for {
			if bufOff >= 136 {
				h.Read(buf[:])
				bufOff = 0
			}
			b = uint16(buf[bufOff])
			bufOff++
			if b <= i {
				break
			}
		}
		p[i] = p[b]
		p[b] = 1
		// Takes least significant bit of signs and uses it for the sign.
		// Note 1 ^ (1 | (Q-1)) = Q-1.
		p[b] = int32(uint32(p[b]) ^ uint32((-(signs & 1))&(1|(uint64(Q)-1))))
		signs >>= 1
	}

	return nil
}

// sampleError samples a polynomial with coefficients in [-eta, eta].
// Used for sampling secret key vectors.
//
// DEPRECATED: This function is only called by the deprecated SampleMasking, which
// does not preserve zero-knowledge under aggregation. The distribution formula is
// incorrect for eta=72: the bit-packing loop is capped at 18 bits regardless of eta,
// so large eta values (e.g. 72 used by Dilithium3 Eta2) produce a much narrower
// distribution than intended. If this function is reactivated, the distribution formula
// must be fixed to correctly handle the full eta range.
func sampleError(p *Poly, seed []byte, eta int) error {
	if eta <= 0 {
		return ErrInvalidEta
	}

	buf := make([]byte, 0, N*4)
	h := sha256.New()
	h.Write(seed)
	block := h.Sum(nil)
	buf = append(buf, block...)

	for i := 0; i < N; {
		if len(buf)-i/4*3 < 3 && i < N {
			h := sha256.New()
			h.Write(seed)
			h.Write([]byte{byte(len(buf) / 32)})
			block = h.Sum(nil)
			buf = append(buf, block...)
		}

		idx := (i / 2) * 3
		if idx+2 >= len(buf) {
			h := sha256.New()
			h.Write(seed)
			h.Write([]byte{byte(len(buf) / 32)})
			block = h.Sum(nil)
			buf = append(buf, block...)
		}

		if idx+2 < len(buf) {
			t := uint32(buf[idx]) | uint32(buf[idx+1])<<8 | uint32(buf[idx+2])<<16
			d := t & 0x7FFFF
			val := int32(0)
			for j := 0; j < 18 && j < 2*eta; j++ {
				val += int32((d >> j) & 1)
			}
			for j := 0; j < 18 && j < 2*eta; j++ {
				val -= int32((d >> (18 + j)) & 1)
			}
			p[i] = int32((int64(val)%Q + Q) % Q)
			i++
			if i >= N {
				break
			}
			d2 := t >> 18
			val2 := int32(0)
			bitsAvail := 32 - 18
			for j := 0; j < bitsAvail/2 && j < eta; j++ {
				val2 += int32((d2 >> j) & 1)
			}
			for j := 0; j < bitsAvail/2 && j < eta; j++ {
				val2 -= int32((d2 >> (bitsAvail/2 + j)) & 1)
			}
			p[i] = int32((int64(val2)%Q + Q) % Q)
			i++
		}
	}

	return nil
}

// ComputeHint implements circl's PolyMakeHint: given the pre-computed modified
// low bits z0 (= w0 − c·s₂ + c·t₀, coefficients in [0,Q)) and the original
// high bits w1 (= HighBits(w)), compute the hint polynomial and its popcount.
//
// For each coefficient, applies circl's makeHint(z0, r1):
//
//	hint = 0 if z0 ≤ γ₂ || z0 > Q−γ₂ || (z0 == Q−γ₂ && r1 == 0)
//	hint = 1 otherwise
//
// CRITICAL: z0 must be the UNWRAPPED modified low bits (w0 − c·s₂ + c·t₀),
// NOT LowBits(w − c·s₂ + c·t₀). When the modification crosses a decomposition
// boundary (|z0| > γ₂), these two formulas differ — and that is exactly when a
// hint is needed. Using LowBits(w − c·s₂ + c·t₀) wraps the value and produces
// incorrect hints, causing signature verification to fail.
//
// This matches circl's PolyMakeHint and FIPS 204 Algorithm 16 (MakeHint).
func ComputeHint(z0 PolyVec, w1 PolyVec, gamma2 int) (PolyVec, int) {
	hint := make(PolyVec, len(z0))
	popcount := 0
	g2 := uint32(gamma2)
	qMinusG2 := uint32(Q) - g2

	for i := range z0 {
		for j := 0; j < N; j++ {
			z0val := uint32(z0[i][j])
			r1val := uint32(w1[i][j])
			if z0val <= g2 || z0val > qMinusG2 || (z0val == qMinusG2 && r1val == 0) {
				hint[i][j] = 0
			} else {
				hint[i][j] = 1
				popcount++
			}
		}
	}

	return hint, popcount
}

// highBitsCoeff computes the high bits of a single coefficient.
// Matches circl's decompose() high part (a1) for Alpha=523776.
// Assumes 0 <= x < Q.
func highBitsCoeff(x int32, gamma2 int) int32 {
	_, a1 := decompose(x, gamma2)
	return a1
}

// lowBitsCoeff computes the low bits of a single coefficient.
// Uses circl's decompose, returns r0 (not r0+Q).
func lowBitsCoeff(x int32, gamma2 int) int32 {
	r0plusQ, _ := decompose(x, gamma2)
	r0 := r0plusQ - int32(Q)
	if r0 < 0 {
		r0 += int32(Q)
	}
	return r0
}

// LowBits computes the low-order bits of each coefficient in the vector.
func LowBits(vec PolyVec, gamma2 int) PolyVec {
	result := make(PolyVec, len(vec))
	for i := range vec {
		for j := 0; j < N; j++ {
			result[i][j] = lowBitsCoeff(vec[i][j], gamma2)
		}
	}
	return result
}

// decompose splits a coefficient into high and low parts.
// Matches circl's decompose() for Alpha=523776 (Dilithium3 with Gamma2=261888).
// Returns (r0plusQ, r1) where r0plusQ = r0 + Q.
// Assumes 0 <= x < Q.
func decompose(x int32, gamma2 int) (int32, int32) {
	// circl's Alpha = 523776 = 2*Gamma2 for Dilithium3
	const Alpha = 523776

	a := uint32(x)
	// a1 = ceil(a / 128)
	a1 := (a + 127) >> 7
	// 1025/2^22 is close enough to 1/4092 so that a1 becomes a/Alpha rounded down
	a1 = ((a1*1025 + (1 << 21)) >> 22)
	// For the corner-case a1 = (Q-1)/Alpha = 16, we have to set a1=0
	a1 &= 15

	a0plusQ := a - a1*Alpha
	// In the corner-case, when we set a1=0, we need to add Q if a0 < (Q-1)/2
	a0plusQ += uint32(int32(a0plusQ-(uint32(Q)-1)/2)>>31) & uint32(Q)

	return int32(a0plusQ), int32(a1)
}

// VerifyHint checks that the hint is consistent with w and r.
func VerifyHint(w PolyVec, r PolyVec, hint []byte, gamma2 int) bool {
	if len(hint) != len(w)*N/4 {
		return false
	}

	for i, wi := range w {
		for j := 0; j < N; j++ {
			diff := int64(wi[j]) - int64(r[i][j])
			if diff < 0 {
				diff += Q
			}
			byteIdx := (i*N + j) / 8
			bitIdx := (i*N + j) % 8
			hintBit := (hint[byteIdx] >> bitIdx) & 1

			if hintBit == 1 {
				if diff <= int64(gamma2) || diff >= Q-int64(gamma2) {
					return false
				}
			} else {
				if diff > int64(gamma2) && diff < Q-int64(gamma2) {
					return false
				}
			}
		}
	}

	return true
}

// CheckRejection checks if z passes the rejection sampling bound.
// Returns true if ||z||_infinity < eta - beta.
// TSS-SM-03 FIX (deep-audit 2026-07-12): the bound is STRICT. FIPS 204 / circl
// restart (reject) when ||z||_infinity >= gamma1 - beta, so the aggregator must
// accept only when the norm is strictly less. The previous <= admitted a z whose
// max coefficient equalled the bound, which mode3.Verify then rejects — emitting
// an invalid signature as if it were valid.
func CheckRejection(z PolyVec, etaMinusBeta int64) bool {
	return VecNormInf(z) < etaMinusBeta
}

// HighBits computes the high-order bits of each coefficient in the vector.
func HighBits(vec PolyVec, gamma2 int) PolyVec {
	result := make(PolyVec, len(vec))
	for i := range vec {
		for j := 0; j < N; j++ {
			result[i][j] = highBitsCoeff(vec[i][j], gamma2)
		}
	}
	return result
}

// UseHint applies the hint to recover the high-order bits of w.
// Matches circl's PolyUseHint for Gamma2=261888 (Alpha=523776).
// hint is a PolyVec with 0/1 values per coefficient.
func UseHint(hint PolyVec, r PolyVec, gamma2 int) PolyVec {
	w := make(PolyVec, len(r))
	for i := range r {
		for j := 0; j < N; j++ {
			rp0plusQ, rp1 := decompose(r[i][j], gamma2)
			if hint[i][j] == 0 {
				w[i][j] = rp1
			} else {
				// Gamma2 == 261888: use & 15
				if rp0plusQ > int32(Q) {
					w[i][j] = int32((uint32(rp1) + 1) & 15)
				} else {
					w[i][j] = int32((uint32(rp1) - 1) & 15)
				}
			}
		}
	}
	return w
}
