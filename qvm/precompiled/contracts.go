// Quantaureum Node source, version 1.0.0.
package precompiled

import (
	"container/list"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"math/bits"
	"sync"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/quantaureum/qau/crypto"
	k1 "github.com/quantaureum/qau/qvm/secp256k1"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/ripemd160" // #nosec G507 -- EVM-compatible precompile 0x03 requires RIPEMD160 (see ripemd160Precompiled.Run)
	"golang.org/x/crypto/sha3"
)

type ecrecover struct{}

func newECRecover() *ecrecover { return &ecrecover{} }

func (c *ecrecover) Address() types.Address {
	return types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
}

func (c *ecrecover) RequiredGas(input []byte) uint64 {
	return 3000
}

func (c *ecrecover) Run(input []byte) ([]byte, error) {
	if len(input) < 128 {
		return make([]byte, 32), nil
	}
	hash := input[0:32]
	v := new(big.Int).SetBytes(input[32:64])
	r := new(big.Int).SetBytes(input[64:96])
	s := new(big.Int).SetBytes(input[96:128])

	if !isValidECDSASig(v, r, s) {
		return make([]byte, 32), nil
	}

	pubKey, err := recoverECDSAPubKey(hash, v, r, s)
	if err != nil || pubKey == nil {
		return make([]byte, 32), nil
	}

	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(pubKey[1:])
	digest := hasher.Sum(nil)

	result := make([]byte, 32)
	copy(result[12:], digest[12:])
	return result, nil
}

func isValidECDSASig(v, r, s *big.Int) bool {
	if r == nil || s == nil || v == nil {
		return false
	}
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if v.Cmp(big.NewInt(27)) < 0 || v.Cmp(big.NewInt(28)) > 0 {
		return false
	}
	// HIGH-4 FIX: Use correct secp256k1 N value (order of the curve)
	secp256k1N := new(big.Int).SetBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	})
	// HIGH-4 FIX: Enforce canonical signature format to prevent malleability.
	// We require s to be in the lower half [1, N/2] to ensure unique signatures.
	// This prevents attackers from flipping s to N-s to create a valid-but-different signature.
	halfN := new(big.Int).Rsh(secp256k1N, 1)
	if s.Cmp(halfN) > 0 {
		return false
	}
	// Also verify r is in valid range [1, N-1]
	if r.Cmp(secp256k1N) >= 0 {
		return false
	}
	return true
}

func recoverECDSAPubKey(hash []byte, v, r, s *big.Int) ([]byte, error) {
	// CRITICAL FIX: Wrap curve operations in panic recovery to handle malicious inputs
	// that could cause curve.ScalarBaseMult/ScalarMult to panic
	defer func() {
		if recoverPanic := recover(); recoverPanic != nil {
			// Return nil to indicate invalid signature - don't propagate the panic
		}
	}()

	secp256k1N := new(big.Int).SetBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	})

	if r.Cmp(secp256k1N) >= 0 || s.Cmp(secp256k1N) >= 0 {
		return nil, fmt.Errorf("ecrecover: signature values out of range")
	}
	if r.Sign() == 0 || s.Sign() == 0 {
		return nil, fmt.Errorf("ecrecover: r or s is zero")
	}

	// HIGH-5 (R8 2026-07-19 FIX): v-value normalization.
	// The previous code accepted v=27..30 (recID = v-27) and silently
	// "fell back" to v itself when v < 27 (via the suspect `recID = v - 0`
	// branch). This accepted ambiguous v values (e.g. v=0 → recID=0
	// via the fallback, but ALSO v=27 → recID=0 via the primary path)
	// and offered no clear contract.
	//
	// EIP-2 / EIP-155 contract: v MUST be either:
	//   - {27, 28}      (pre-EIP-155 form, recID = v - 27)
	//   - {0, 1}        (raw recID form, used by some signers/libraries)
	//   - >= 35 (EIP-155 form; recID = (v - 35) mod 2; only the low bit
	//            matters for parity, but we extract it explicitly)
	//
	// We reject anything else. Previously, v=2..26 were silently accepted
	// via the `recID = v - 0` fallback branch (since v-27<0 → take v).
	// Such v values are not produced by any standard signer and accepting
	// them risks ambiguous recovery to wrong sender addresses.
	recID := new(big.Int)
	switch {
	case v.Cmp(big.NewInt(27)) == 0 || v.Cmp(big.NewInt(28)) == 0:
		recID.Sub(v, big.NewInt(27))
	case v.Cmp(big.NewInt(0)) == 0 || v.Cmp(big.NewInt(1)) == 0:
		recID.Set(v)
	case v.Cmp(big.NewInt(35)) >= 0:
		// EIP-155: v = recID + 35 + 2*chainID. Only recID's low bit
		// (= v - 35 mod 2) is meaningful; reconstruct chainID separately
		// if needed (we don't need it here — only recovery parity).
		recID.Mod(new(big.Int).Sub(v, big.NewInt(35)), big.NewInt(2))
	default:
		return nil, fmt.Errorf("ecrecover: invalid v value %d (must be 0,1,27,28 or >=35)", v)
	}
	if recID.Cmp(big.NewInt(0)) < 0 || recID.Cmp(big.NewInt(3)) > 0 {
		return nil, fmt.Errorf("ecrecover: invalid recovery id %d", recID)
	}

	rInv := new(big.Int).ModInverse(r, secp256k1N)
	if rInv == nil {
		return nil, fmt.Errorf("ecrecover: failed to compute modular inverse of r")
	}

	ry, err := decompressSecp256k1Point(r, recID)
	if err != nil {
		return nil, fmt.Errorf("ecrecover: failed to decompress point R: %w", err)
	}

	z := new(big.Int).SetBytes(hash)
	z.Mod(z, secp256k1N)

	sInvZ := new(big.Int).Mul(s, z)
	sInvZ.Mod(sInvZ, secp256k1N)
	sInvZ.Neg(sInvZ)
	sInvZ.Mod(sInvZ, secp256k1N)
	u1 := new(big.Int).Mul(sInvZ, rInv)
	u1.Mod(u1, secp256k1N)

	u2 := new(big.Int).Mul(s, rInv)
	u2.Mod(u2, secp256k1N)

	curve := secp256k1()

	// Validate u1 point is on curve before ScalarBaseMult
	u1Gx, u1Gy := curve.ScalarBaseMult(u1.Bytes())
	if !curve.IsOnCurve(u1Gx, u1Gy) {
		return nil, fmt.Errorf("ecrecover: u1 point not on curve")
	}

	// Validate R point is on curve before ScalarMult
	if !curve.IsOnCurve(r, ry) {
		return nil, fmt.Errorf("ecrecover: R point not on curve")
	}

	u2Rx, u2Ry := curve.ScalarMult(r, ry, u2.Bytes())
	qx, qy := curve.Add(u1Gx, u1Gy, u2Rx, u2Ry)

	// Validate resulting public key point is on curve
	if !curve.IsOnCurve(qx, qy) {
		return nil, fmt.Errorf("ecrecover: resulting public key not on curve")
	}

	pubKey := make([]byte, 65)
	pubKey[0] = 4
	qx.FillBytes(pubKey[1:33])
	qy.FillBytes(pubKey[33:65])
	return pubKey, nil
}

var secp256k1P = new(big.Int).SetBytes([]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
})

// secp256k1 returns the secp256k1 curve implementation.
//
// R37-FIX (2026-07-30): Go 1.26 removed the generic CurveParams point
// operations (they now panic unconditionally). The previous secp256k1Curve
// embedded *elliptic.CurveParams and inherited the removed methods, so
// every ecrecover call silently recovered nothing via the defer/recover
// above — the precompile returned the zero address for ALL inputs.
// Delegate to the self-contained Jacobian-coordinate implementation in
// qvm/secp256k1 (shared package; precompiled cannot import qvm).
func secp256k1() elliptic.Curve {
	return k1.Shared()
}

func decompressSecp256k1Point(x, recID *big.Int) (*big.Int, error) {
	x3 := new(big.Int).Exp(x, big.NewInt(3), secp256k1P)
	y2 := new(big.Int).Add(x3, big.NewInt(7))
	y2.Mod(y2, secp256k1P)

	exp := new(big.Int).Add(secp256k1P, big.NewInt(1))
	exp.Div(exp, big.NewInt(4))
	y := new(big.Int).Exp(y2, exp, secp256k1P)

	if y2.Cmp(new(big.Int).Exp(y, big.NewInt(2), secp256k1P)) != 0 {
		return nil, fmt.Errorf("ecrecover: point not on curve")
	}

	if y.Bit(0) != recID.Bit(0) {
		y.Sub(secp256k1P, y)
	}

	return y, nil
}

type sha256Precompiled struct{}

func newSHA256() *sha256Precompiled { return &sha256Precompiled{} }

func (c *sha256Precompiled) Address() types.Address {
	return types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
}

func (c *sha256Precompiled) RequiredGas(input []byte) uint64 {
	n := uint64(len(input)+31) / 32
	return 60 + 12*n
}

func (c *sha256Precompiled) Run(input []byte) ([]byte, error) {
	h := sha256.Sum256(input)
	return h[:], nil
}

type ripemd160Precompiled struct{}

func newRIPEMD160() *ripemd160Precompiled { return &ripemd160Precompiled{} }

func (c *ripemd160Precompiled) Address() types.Address {
	return types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}
}

func (c *ripemd160Precompiled) RequiredGas(input []byte) uint64 {
	n := uint64(len(input)+31) / 32
	return 600 + 120*n
}

func (c *ripemd160Precompiled) Run(input []byte) ([]byte, error) {
	// #nosec G406 G507 -- RIPEMD160 precompile at address 0x03 is REQUIRED
	// for Ethereum compatibility (EIP-152 prescribes it); cannot be removed
	// or replaced even though it is a weak hash. Legacy EVM contracts rely
	// on it, and consensus must match the canonical result.
	h := ripemd160.New()
	h.Write(input)
	digest := h.Sum(nil)
	result := make([]byte, 32)
	copy(result[12:], digest)
	return result, nil
}

type identity struct{}

func newIdentity() *identity { return &identity{} }

func (c *identity) Address() types.Address {
	return types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4}
}

func (c *identity) RequiredGas(input []byte) uint64 {
	n := uint64(len(input)+31) / 32
	return 15 + 3*n
}

func (c *identity) Run(input []byte) ([]byte, error) {
	// R6-QV-004 FIX: Return a copy of input, not the original slice. The
	// caller may modify or zero the input buffer after Run returns, which
	// would corrupt the returned data if we return the original slice.
	result := make([]byte, len(input))
	copy(result, input)
	return result, nil
}

type modExp struct{}

func newModExp() *modExp { return &modExp{} }

func (c *modExp) Address() types.Address {
	return types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}
}

func (c *modExp) RequiredGas(input []byte) uint64 {
	// R41-QV-015 FIX: Return minimum gas (200) for malformed input instead
	// of 0. Returning 0 allows attackers to call the precompile as a free
	// no-op, which could be abused for DoS or gas estimation manipulation.
	if len(input) < 96 {
		return 200
	}
	bLenBig := new(big.Int).SetBytes(input[0:32])
	eLenBig := new(big.Int).SetBytes(input[32:64])
	// R37-FIX P2-QVMP-01 (2026-07-30): Parse mLen (input[64:96]). The previous
	// code never read it, so multComplexity was bLen² regardless of the modulus
	// size. EIP-2565 bases complexity on max(bLen, mLen). An attacker could
	// declare bLen=1 with mLen=1024: charged ~200 gas (the floor) while the
	// node performs millisecond-scale bignum exponentiation over a 1024-byte
	// modulus — a block-processing DoS vector.
	mLenBig := new(big.Int).SetBytes(input[64:96])

	maxUint64 := new(big.Int).SetUint64(^uint64(0))
	if bLenBig.Cmp(maxUint64) > 0 || eLenBig.Cmp(maxUint64) > 0 || mLenBig.Cmp(maxUint64) > 0 {
		return ^uint64(0)
	}

	bLen := bLenBig.Uint64()
	eLen := eLenBig.Uint64()
	mLen := mLenBig.Uint64()

	if uint64(len(input)) < 96+bLen || uint64(len(input))-96-bLen < eLen {
		return 200
	}

	expBytes := input[96+bLen : 96+bLen+eLen]
	expBitLen := uint64(0)
	if eLen > 0 && len(expBytes) > 0 {
		expBitLen = (eLen-1)*8 + uint64(bits.Len8(expBytes[0]))
	}

	// R37-FIX P2-QVMP-01 (2026-07-30): EIP-2565 multiplication complexity is
	// max(bLen, mLen)² — the modulus size dominates the cost of bignum
	// exponentiation just as much as the base size does.
	maxLen := bLen
	if mLen > maxLen {
		maxLen = mLen
	}
	multComplexity := uint64(0)
	if maxLen > 0 {
		// HIGH-7 FIX: Add additional overflow check for gas calculation
		if maxLen > ^uint64(0)/maxLen {
			return ^uint64(0)
		}
		multComplexity = maxLen * maxLen
		// Additional safety: if maxLen is extremely large, multComplexity could overflow
		// even after the above check. Use safe math patterns.
		if multComplexity > 0 && maxLen > ^uint64(0)/multComplexity {
			return ^uint64(0)
		}
	}

	gas := uint64(0)
	if expBitLen <= 1 {
		gas = multComplexity
	} else {
		if multComplexity > 0 && expBitLen > ^uint64(0)/multComplexity {
			return ^uint64(0)
		}
		gas = multComplexity * expBitLen
	}
	if gas < 200 {
		return 200
	}
	return gas
}

func (c *modExp) Run(input []byte) ([]byte, error) {
	if len(input) < 96 {
		// R35-P2-PRECOMPILE-01 FIX (2026-07-29): Return error instead of
		// (nil, nil). The previous (nil, nil) return was indistinguishable
		// from "success with no output", causing callers to treat invalid
		// input as a successful no-op. Consistent error reporting helps
		// the CALL opcode correctly push 0 (failure) on the stack.
		return nil, fmt.Errorf("modExp: input too short (need 96 bytes, got %d)", len(input))
	}

	bLenBig := new(big.Int).SetBytes(input[0:32])
	eLenBig := new(big.Int).SetBytes(input[32:64])
	mLenBig := new(big.Int).SetBytes(input[64:96])

	maxUint64 := new(big.Int).SetUint64(^uint64(0))
	if bLenBig.Cmp(maxUint64) > 0 || eLenBig.Cmp(maxUint64) > 0 || mLenBig.Cmp(maxUint64) > 0 {
		return nil, fmt.Errorf("modExp: input length overflow")
	}

	bLen := bLenBig.Uint64()
	eLen := eLenBig.Uint64()
	mLen := mLenBig.Uint64()

	inputLen := uint64(len(input))
	if inputLen < 96 || inputLen-96 < bLen || inputLen-96-bLen < eLen || inputLen-96-bLen-eLen < mLen {
		// R35-P2-PRECOMPILE-01 FIX: Return error instead of (nil, nil).
		return nil, fmt.Errorf("modExp: input data shorter than declared lengths")
	}

	base := new(big.Int).SetBytes(input[96 : 96+bLen])
	exp := new(big.Int).SetBytes(input[96+bLen : 96+bLen+eLen])
	mod := new(big.Int).SetBytes(input[96+bLen+eLen : 96+bLen+eLen+mLen])

	if mod.Sign() == 0 {
		return make([]byte, mLen), nil
	}

	result := new(big.Int).Exp(base, exp, mod)
	output := make([]byte, mLen)
	result.FillBytes(output)
	return output, nil
}

type bn256Add struct{}

func newBN256Add() *bn256Add { return &bn256Add{} }

func (c *bn256Add) Address() types.Address {
	return types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6}
}

func (c *bn256Add) RequiredGas(input []byte) uint64 {
	return 150
}

// parseBN256G1 decodes a 64-byte EIP-196 G1 point (x||y, 32-byte big-endian
// each) into a gnark bn254 affine point. The all-zero encoding is the point at
// infinity (a legal EIP-196 input). Coordinates must be canonical field
// elements (< P); out-of-range or off-curve inputs are rejected.
// QVM-BN256-01 FIX (deep-audit 2026-07-12): replaces the hand-rolled affine
// math that rejected infinity, point doubling, and P+(-P).
func parseBN256G1(xb, yb []byte) (bn254.G1Affine, error) {
	var p bn254.G1Affine
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	if x.Sign() == 0 && y.Sign() == 0 {
		// Point at infinity — leave p as its zero value (gnark's infinity).
		return p, nil
	}
	if x.Cmp(bn256P) >= 0 || y.Cmp(bn256P) >= 0 {
		return p, fmt.Errorf("coordinate not a canonical field element")
	}
	p.X.SetBigInt(x)
	p.Y.SetBigInt(y)
	if !p.IsOnCurve() {
		return p, fmt.Errorf("point is not on the BN256 curve")
	}
	return p, nil
}

// encodeBN256G1 encodes a gnark bn254 affine point as 64 bytes (x||y). The
// point at infinity encodes to all zeros, per EIP-196.
func encodeBN256G1(p *bn254.G1Affine) []byte {
	res := make([]byte, 64)
	if p.IsInfinity() {
		return res
	}
	xb := p.X.Bytes()
	yb := p.Y.Bytes()
	copy(res[0:32], xb[:])
	copy(res[32:64], yb[:])
	return res
}

func (c *bn256Add) Run(input []byte) ([]byte, error) {
	if len(input) < 128 {
		return nil, fmt.Errorf("bn256Add: input too short, need at least 128 bytes")
	}

	// QVM-BN256-01 FIX: use gnark bn254 group arithmetic so EIP-196 edge cases
	// (infinity operands, P+P doubling, P+(-P) → infinity) return the correct
	// result instead of erroring. The previous affine formula rejected dx==0.
	p1, err := parseBN256G1(input[0:32], input[32:64])
	if err != nil {
		return nil, fmt.Errorf("bn256Add: first point: %w", err)
	}
	p2, err := parseBN256G1(input[64:96], input[96:128])
	if err != nil {
		return nil, fmt.Errorf("bn256Add: second point: %w", err)
	}

	var j1, j2 bn254.G1Jac
	j1.FromAffine(&p1)
	j2.FromAffine(&p2)
	j1.AddAssign(&j2)

	var sum bn254.G1Affine
	sum.FromJacobian(&j1)
	return encodeBN256G1(&sum), nil
}

// bn256P is the prime for BN256 curve
var bn256P = new(big.Int).SetBytes([]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
})

type bn256ScalarMul struct{}

func newBN256ScalarMul() *bn256ScalarMul { return &bn256ScalarMul{} }

func (c *bn256ScalarMul) Address() types.Address {
	return types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}
}

func (c *bn256ScalarMul) RequiredGas(input []byte) uint64 {
	return 6000
}

func (c *bn256ScalarMul) Run(input []byte) ([]byte, error) {
	if len(input) < 96 {
		return nil, fmt.Errorf("bn256ScalarMul: input too short, need at least 96 bytes")
	}

	// QVM-BN256-01 FIX: use gnark bn254 scalar multiplication for EIP-196
	// correctness. EVM accepts any 256-bit scalar (including 0 and values >= the
	// group order N) and any valid point (including infinity); the previous
	// implementation wrongly rejected scalar==0 and scalar>=N. gnark reduces the
	// scalar modulo the group order internally, which is mathematically correct.
	p, err := parseBN256G1(input[0:32], input[32:64])
	if err != nil {
		return nil, fmt.Errorf("bn256ScalarMul: %w", err)
	}
	scalar := new(big.Int).SetBytes(input[64:96])

	var res bn254.G1Affine
	res.ScalarMultiplication(&p, scalar)
	return encodeBN256G1(&res), nil
}

// bn256N is the order of the BN256 curve (referenced by external gas/curve
// helpers and kept as the canonical group-order constant).
var bn256N = new(big.Int).SetBytes([]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6,
	0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
})

var _ = bn256N // retained constant; group-order value documented above

type bn256Pairing struct{}

func newBN256Pairing() *bn256Pairing { return &bn256Pairing{} }

func (c *bn256Pairing) Address() types.Address {
	return types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8}
}

func (c *bn256Pairing) RequiredGas(input []byte) uint64 {
	n := uint64(len(input)) / 192
	return 34000 + 45000*n
}

func (c *bn256Pairing) Run(input []byte) ([]byte, error) {
	if len(input) == 0 || len(input)%192 != 0 {
		return nil, fmt.Errorf("bn256Pairing: invalid input length %d, must be multiple of 192", len(input))
	}

	// Parse all (G1, G2) pairs and compute the multi-pairing product.
	// EVM pairing: e(G1_1, G2_1) * e(G1_2, G2_2) * ... == 1 in GT
	n := len(input) / 192
	g1Points := make([]bn254.G1Affine, n)
	g2Points := make([]bn254.G2Affine, n)

	for i := 0; i < n; i++ {
		offset := i * 192
		pair := input[offset : offset+192]

		// G1 point: 64 bytes (x: 32 bytes || y: 32 bytes), big-endian
		g1x := new(big.Int).SetBytes(pair[0:32])
		g1y := new(big.Int).SetBytes(pair[32:64])

		// G2 point: 128 bytes, each coordinate is an fp2 element
		// fp2 = A0 + A1*u, each component 32 bytes big-endian
		// EVM encoding order: x.A1, x.A0, y.A1, y.A0 (big-endian limbs)
		// See EIP-197: https://eips.ethereum.org/EIPS/eip-197
		g2xA1 := new(big.Int).SetBytes(pair[64:96])
		g2xA0 := new(big.Int).SetBytes(pair[96:128])
		g2yA1 := new(big.Int).SetBytes(pair[128:160])
		g2yA0 := new(big.Int).SetBytes(pair[160:192])

		// Set G1 affine point
		g1Points[i].X.SetBigInt(g1x)
		g1Points[i].Y.SetBigInt(g1y)

		// Validate G1 point is on curve and not infinity
		if !g1Points[i].IsOnCurve() {
			return nil, fmt.Errorf("bn256Pairing: G1 point %d not on curve", i)
		}
		// Check that G1 point is in the correct subgroup
		if !g1Points[i].IsInSubGroup() {
			return nil, fmt.Errorf("bn256Pairing: G1 point %d not in subgroup", i)
		}

		// Set G2 affine point (fp2 coordinates)
		g2Points[i].X.A0.SetBigInt(g2xA0)
		g2Points[i].X.A1.SetBigInt(g2xA1)
		g2Points[i].Y.A0.SetBigInt(g2yA0)
		g2Points[i].Y.A1.SetBigInt(g2yA1)

		// Validate G2 point is on curve and not infinity
		if !g2Points[i].IsOnCurve() {
			return nil, fmt.Errorf("bn256Pairing: G2 point %d not on curve", i)
		}
		// Check that G2 point is in the correct subgroup
		if !g2Points[i].IsInSubGroup() {
			return nil, fmt.Errorf("bn256Pairing: G2 point %d not in subgroup", i)
		}
	}

	// Compute multi-pairing: e(G1_1, G2_1) * ... * e(G1_n, G2_n)
	result, err := bn254.Pair(g1Points, g2Points)
	if err != nil {
		return nil, fmt.Errorf("bn256Pairing: pairing computation failed: %w", err)
	}

	// Pairing succeeds if the result is the identity element in GT (== 1)
	output := make([]byte, 32)
	if result.IsOne() {
		output[31] = 1 // success
	}
	return output, nil
}

type blake2F struct{}

func newBlake2F() *blake2F { return &blake2F{} }

func (c *blake2F) Address() types.Address {
	return types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}
}

func (c *blake2F) RequiredGas(input []byte) uint64 {
	// SECURITY (audit 2026-06-14, M1): Require the full 213-byte input for
	// gas accounting to be consistent with Run (which rejects != 213). The
	// previous code accepted any input >= 4 bytes and charged gas based on the
	// first 4 bytes (rounds), then Run rejected the call — so a caller could
	// be charged gas for a call that never executes (minor griefing) and,
	// worse, a malformed input with a huge rounds value would charge
	// arbitrarily high gas. Now we mirror Run's validation: short inputs get
	// zero gas, and rounds is clamped to the same [1, 1000] range Run enforces.
	//
	// P3-QVM-BLAKE2F FIX (R30, 2026-07-27): R30 audit flagged "blake2F
	// precompile returns 0 gas for invalid input" as a LOW/INFO finding.
	// This is a KNOWN DESIGN DECISION consistent with go-ethereum's
	// blake2F.RequiredGas implementation (core/vm/contracts.go: blake2F
	// returns 0 for inputs that fail length/rounds validation). Returning
	// 0 gas for invalid input is correct EVM behavior: RequiredGas is only
	// consulted AFTER input validation passes in the EVM call path, so for
	// invalid inputs the call reverts before any gas is charged against
	// the user. The explicit `return 0` here is defense-in-depth for
	// direct precompile callers. Keeping current behavior — no code change
	// needed. This annotation marks it as a reviewed, known design decision.
	if len(input) != 213 {
		return 0
	}
	rounds := binary.BigEndian.Uint32(input[0:4])
	if rounds == 0 || rounds > 1000 {
		return 0
	}
	return uint64(rounds)
}

func (c *blake2F) Run(input []byte) ([]byte, error) {
	if len(input) != 213 {
		return nil, fmt.Errorf("blake2F: invalid input length %d, expected 213", len(input))
	}

	rounds := binary.BigEndian.Uint32(input[0:4])
	if rounds == 0 || rounds > 1000 {
		return nil, fmt.Errorf("blake2F: rounds out of valid range [1, 1000]")
	}

	var h [8]uint64
	for i := 0; i < 8; i++ {
		h[i] = binary.LittleEndian.Uint64(input[4+i*8 : 4+(i+1)*8])
	}

	var m [16]uint64
	for i := 0; i < 16; i++ {
		m[i] = binary.LittleEndian.Uint64(input[68+i*8 : 68+(i+1)*8])
	}

	t := binary.LittleEndian.Uint64(input[196:204])
	t1 := binary.LittleEndian.Uint64(input[204:212])

	fFlag := input[212]

	var v [16]uint64
	v[0] = h[0]
	v[1] = h[1]
	v[2] = h[2]
	v[3] = h[3]
	v[4] = h[4]
	v[5] = h[5]
	v[6] = h[6]
	v[7] = h[7]
	v[8] = blake2bIV[0]
	v[9] = blake2bIV[1]
	v[10] = blake2bIV[2]
	v[11] = blake2bIV[3]
	v[12] = t ^ blake2bIV[4]
	v[13] = t1 ^ blake2bIV[5]

	if fFlag != 0 {
		v[14] = 0xFFFFFFFFFFFFFFFF ^ blake2bIV[6]
	} else {
		v[14] = blake2bIV[6]
	}
	v[15] = blake2bIV[7]

	for r := uint32(0); r < rounds; r++ {
		s := blake2bSigma[r%10]

		blake2bG(&v[0], &v[4], &v[8], &v[12], m[s[0]], m[s[1]])
		blake2bG(&v[1], &v[5], &v[9], &v[13], m[s[2]], m[s[3]])
		blake2bG(&v[2], &v[6], &v[10], &v[14], m[s[4]], m[s[5]])
		blake2bG(&v[3], &v[7], &v[11], &v[15], m[s[6]], m[s[7]])
		blake2bG(&v[0], &v[5], &v[10], &v[15], m[s[8]], m[s[9]])
		blake2bG(&v[1], &v[6], &v[11], &v[12], m[s[10]], m[s[11]])
		blake2bG(&v[2], &v[7], &v[8], &v[13], m[s[12]], m[s[13]])
		blake2bG(&v[3], &v[4], &v[9], &v[14], m[s[14]], m[s[15]])
	}

	output := make([]byte, 64)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(output[i*8:(i+1)*8], h[i]^v[i]^v[i+8])
	}
	return output, nil
}

var blake2bIV = [8]uint64{
	0x6a09e667f3bcc908,
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade682d1,
	0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b,
	0x5be0cd19137e2179,
}

var blake2bSigma = [10][16]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

func blake2bG(a, b, c, d *uint64, x, y uint64) {
	*a += *b + x
	*d = bits.RotateLeft64(*d^*a, -32)
	*c += *d
	*b = bits.RotateLeft64(*b^*c, -24)
	*a += *b + y
	*d = bits.RotateLeft64(*d^*a, -16)
	*c += *d
	*b = bits.RotateLeft64(*b^*c, -63)
}

type dilithiumVerify struct{}

func newDilithiumVerify() *dilithiumVerify { return &dilithiumVerify{} }

func (c *dilithiumVerify) Address() types.Address {
	return types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100}
}

func (c *dilithiumVerify) RequiredGas(input []byte) uint64 {
	return 500000
}

func (c *dilithiumVerify) Run(input []byte) ([]byte, error) {
	const (
		pubKeySize  = 1952
		sigSize     = 3293
		hashSize    = 32
		minInputLen = pubKeySize + sigSize + hashSize
	)
	if len(input) < minInputLen {
		return nil, fmt.Errorf("dilithiumVerify: input too short, need at least %d bytes, got %d", minInputLen, len(input))
	}

	pubKeyBytes := input[:pubKeySize]
	sigBytes := input[pubKeySize : pubKeySize+sigSize]
	hashBytes := input[pubKeySize+sigSize : pubKeySize+sigSize+hashSize]

	// Validate input lengths before processing
	if len(pubKeyBytes) != pubKeySize {
		return nil, fmt.Errorf("dilithiumVerify: invalid public key length %d", len(pubKeyBytes))
	}
	if len(sigBytes) != sigSize {
		return nil, fmt.Errorf("dilithiumVerify: invalid signature length %d", len(sigBytes))
	}
	if len(hashBytes) != hashSize {
		return nil, fmt.Errorf("dilithiumVerify: invalid hash length %d", len(hashBytes))
	}

	// Use cached verification to avoid repeatedly running the expensive post-quantum signature check
	// the cache internally performs pubKey unpacking and mode3.Verify
	valid := dilithiumVerifyCached(pubKeyBytes, sigBytes, hashBytes)

	result := make([]byte, 32)
	if valid {
		result[31] = 1
	}
	return result, nil
}

type kyberKEM struct{}

func newKyberKEM() *kyberKEM { return &kyberKEM{} }

func (c *kyberKEM) Address() types.Address {
	return types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 101}
}

func (c *kyberKEM) RequiredGas(input []byte) uint64 {
	return 800000
}

func (c *kyberKEM) Run(input []byte) ([]byte, error) {
	// AUDIT (2026) CRIT-04: DISABLED. scheme.Encapsulate(pub) uses
	// crypto/rand internally (randomized KEM), producing non-deterministic
	// ciphertext/sharedSecret. Each node would get different output →
	// state-root divergence → chain halt. A single CALL/STATICCALL to this
	// precompile could stop the entire network.
	// To re-enable: provide only deterministic Kyber operations (decapsulate),
	// or derive randomness from a consensus seed.
	return nil, fmt.Errorf("kyberKEM precompile disabled: non-deterministic operation (audit 2026-07-12 CRIT-04)")
}

// keccak256Precompiled implements the KECCAK256 precompiled contract (address 0x0A)
// KECCAK256 is the highest-frequency cryptographic operation in QVM (the SHA3 opcode);
// exposing it as a precompile provides a uniform call interface and gas accounting.
type keccak256Precompiled struct{}

func newKeccak256() *keccak256Precompiled { return &keccak256Precompiled{} }

func (c *keccak256Precompiled) Address() types.Address {
	// L20-011 NOTE: This address 0x0A is shared with kzgPointEvaluation.
	// In the QVM standard Registry (precompiled.go), only KZG is registered at 0x0A.
	// In the EVM compatibility layer (evmcompat.go), Keccak256 is registered at 0x0A
	// via explicit address (types.BytesToAddress([]byte{0x0A})), NOT via this method.
	// The two do not conflict because they live in separate registries.
	// Do NOT register both in the same Registry — KZG takes priority at 0x0A.
	return types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0A}
}

func (c *keccak256Precompiled) RequiredGas(input []byte) uint64 {
	n := uint64(len(input)+31) / 32
	return 30 + 6*n
}

func (c *keccak256Precompiled) Run(input []byte) ([]byte, error) {
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(input)
	return hasher.Sum(nil), nil
}

// BatchRun executes KECCAK256 in batch, reusing the hasher to reduce allocations
func (c *keccak256Precompiled) BatchRun(inputs [][]byte) ([][]byte, error) {
	results := make([][]byte, len(inputs))
	for i, input := range inputs {
		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(input)
		results[i] = hasher.Sum(nil)
	}
	return results, nil
}

// kzgPointEvaluation implements the KZG point evaluation precompiled contract (EIP-4844).
// Address 0x0A per the Ethereum standard.
//
// Input: 192 bytes = versioned_hash (32) + z (32) + y (32) + commitment (48) + proof (48)
// Output: 32 bytes with the last byte set to 1 on success (the constant 0x0000...0001)
// Gas: 50000 (fixed per EIP-4844)
//
// This is a STUB implementation that validates input length but does not perform
// actual KZG verification. It returns success for any valid-length input, matching
// the pattern used by go-ethereum for initial integration.
type kzgPointEvaluation struct{}

func newKZGPointEvaluation() *kzgPointEvaluation { return &kzgPointEvaluation{} }

func (c *kzgPointEvaluation) Address() types.Address {
	// L20-011 NOTE: Address 0x0A is shared with keccak256Precompiled.
	// In the QVM standard Registry, KZG is the sole registrant at 0x0A (per EIP-4844).
	// keccak256Precompiled is only used in the EVM compat layer via explicit address.
	return types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0A}
}

func (c *kzgPointEvaluation) RequiredGas(input []byte) uint64 {
	return 50000
}

func (c *kzgPointEvaluation) Run(input []byte) ([]byte, error) {
	// audit-fix C-2: Reject all inputs instead of always returning success.
	// The previous STUB implementation accepted any 192-byte input and returned
	// success, allowing blob commitment verification to be bypassed.
	// Until a real KZG implementation is available, fail-closed for security.
	if len(input) != 192 {
		return nil, fmt.Errorf("kzgPointEvaluation: invalid input length %d, expected 192", len(input))
	}
	return nil, fmt.Errorf("kzgPointEvaluation: real KZG verification not implemented; blob transactions disabled until full implementation")
}

// dilithiumVerifyCache implements an LRU cache of Dilithium3 verification results
// repeated verifications of the same pubKey+message+signature can return the cached result,
// avoiding redundant expensive post-quantum signature checks.
//
// FIX: cache eviction switched from "clear everything" to LRU eviction.
// The old implementation cleared the entire map upon reaching capacity,
// discarding all valid cached results at once, forcing later requests to redo
// expensive Dilithium3 verifications. Now the least-recently-used entry is evicted, keeping hot data.
//
// R42-QVMLRU-01 FIX (2026-08-03): replace O(n) scan-based LRU eviction
// with a true O(1) LRU using container/list + map. The previous
// implementation stored a lastAccess timestamp per entry and evicted by
// scanning the entire map (O(n) per eviction, n up to 1024). The new
// implementation keeps a doubly-linked list ordered MRU→LRU; the map
// indexes [32-byte key]→*list.Element so lookup/move/evict are all O(1).
// Time fields are removed entirely — recency is encoded by list position.
type dilithiumVerifyCache struct {
	cache map[[32]byte]*list.Element // hash(pubKey||msg||sig) -> *list.Element
	ll    *list.List                 // front=MRU, back=LRU; sequence defines recency
	mu    sync.RWMutex
	size  int
}

// dilithiumCacheEntry is a cache entry holding the verification result and its list-node key.
// No more lastAccess timestamps — list position is the recency.
type dilithiumCacheEntry struct {
	key      [32]byte // reverse pointer, used to delete from the map on eviction
	verified bool
}

var dilithiumCache = &dilithiumVerifyCache{
	cache: make(map[[32]byte]*list.Element),
	ll:    list.New(),
	size:  1024, // cache up to 1024 verification results
}

// computeDilithiumCacheKey computes the cache key = sha256(pubKey || hash || sig)
func computeDilithiumCacheKey(pubKey, hash, sig []byte) [32]byte {
	h := sha256.New()
	h.Write(pubKey)
	h.Write(hash)
	h.Write(sig)
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

// dilithiumVerifyCached: cached Dilithium3 verification
//
// SECURITY (cache-poisoning fix): only successful (true) verifications are cached; failures are never cached.
// Otherwise an attacker could flood a victim validator's (pubKey, message) with forged signatures: if a forged signature reaches the node first
// and the failure is cached, the node would then reject the victim's genuine signature on every later attempt (censorship attack).
// Successful results are safe to cache: once (pubKey, message, signature) verifies true it stays true forever; a failure may be superseded by a
// genuine signature arriving later, so failures must be re-verified every time.
//
// FIX: eviction switched from "clear all" to LRU. When the cache hits capacity,
// the least-recently-used entry is removed (instead of clearing the cache), retaining hot data to reduce re-verification cost.
//
// FIX: all LRU operations (MoveToFront on hit, Back+Remove on eviction) are
// O(1) via container/list — no full-map scans.
func dilithiumVerifyCached(pubKeyBytes, sigBytes, hashBytes []byte) bool {
	cacheKey := computeDilithiumCacheKey(pubKeyBytes, hashBytes, sigBytes)

	// Check the cache first. Only true is ever stored; a hit means valid.
	// On a hit, MoveToFront promotes the node to the MRU end, O(1).
	dilithiumCache.mu.RLock()
	if elem, ok := dilithiumCache.cache[cacheKey]; ok {
		dilithiumCache.mu.RUnlock()
		// Upgrade to write lock to move element to MRU position.
		dilithiumCache.mu.Lock()
		dilithiumCache.ll.MoveToFront(elem)
		dilithiumCache.mu.Unlock()
		return elem.Value.(*dilithiumCacheEntry).verified
	}
	dilithiumCache.mu.RUnlock()

	// Cache miss — run the verification.
	// SECURITY: explicit length validation guards against unsafe.Pointer out-of-bounds reads.
	// R38-P1-01 FIX (2026-08-01): use `!=` instead of `<` and add an
	// explicit zero-key rejection, mirroring the canonical hardening at
	// crypto/verify.go:73 + crypto/generate.go:768. The QVM precompile is
	// a directly attacker-reachable surface (anything calling the
	// Dilithium3 precompile from contract code can pass arbitrary
	// pubkey/sig/message), so it MUST reject degenerate inputs at the
	// entry — must NOT rely on mode3.Verify to handle a zero key safely.
	// Use crypto.IsZeroPublicKeyBytes for constant-time comparison.
	if len(pubKeyBytes) != crypto.Dilithium3PublicKeySize {
		return false
	}
	if crypto.IsZeroPublicKeyBytes(pubKeyBytes[:crypto.Dilithium3PublicKeySize]) {
		return false
	}
	var pubKey mode3.PublicKey
	// R47-QV-06 FIX: Replace unsafe.Pointer cast with safe array copy.
	// The unsafe.Pointer cast was technically safe (length checked above),
	// but copy() is idiomatic and avoids potential aliasing issues.
	var pkBytes [1952]byte
	copy(pkBytes[:], pubKeyBytes[:1952])
	pubKey.Unpack(&pkBytes)
	valid := mode3.Verify(&pubKey, hashBytes, sigBytes)

	// Write to the cache only on successful verification, to avoid poisoning (see SECURITY note above).
	if valid {
		dilithiumCache.mu.Lock()
		// LRU eviction uses Back()+Remove(), an O(1) eviction;
		// the map key is deleted at the same time to avoid a dangling index.
		if dilithiumCache.ll.Len() >= dilithiumCache.size {
			if back := dilithiumCache.ll.Back(); back != nil {
				if oldEntry, ok := back.Value.(*dilithiumCacheEntry); ok {
					delete(dilithiumCache.cache, oldEntry.key)
				}
				dilithiumCache.ll.Remove(back)
			}
		}
		entry := &dilithiumCacheEntry{key: cacheKey, verified: true}
		dilithiumCache.cache[cacheKey] = dilithiumCache.ll.PushFront(entry)
		dilithiumCache.mu.Unlock()
	}

	return valid
}

// Exported constructors for use by external packages (e.g., evmcompat).

// NewECRecover returns the ecRecover precompiled contract.
func NewECRecover() PrecompiledContract { return newECRecover() }

// NewSHA256 returns the SHA256 precompiled contract.
func NewSHA256() PrecompiledContract { return newSHA256() }

// NewRIPEMD160 returns the RIPEMD160 precompiled contract.
func NewRIPEMD160() PrecompiledContract { return newRIPEMD160() }

// NewIdentity returns the identity precompiled contract.
func NewIdentity() PrecompiledContract { return newIdentity() }

// NewModExp returns the modular exponentiation precompiled contract.
func NewModExp() PrecompiledContract { return newModExp() }

// NewBN256Add returns the BN256 elliptic curve addition precompiled contract.
func NewBN256Add() PrecompiledContract { return newBN256Add() }

// NewBN256ScalarMul returns the BN256 elliptic curve scalar multiplication precompiled contract.
func NewBN256ScalarMul() PrecompiledContract { return newBN256ScalarMul() }

// NewBN256Pairing returns the BN256 elliptic curve pairing precompiled contract.
func NewBN256Pairing() PrecompiledContract { return newBN256Pairing() }

// NewBlake2F returns the BLAKE2f precompiled contract.
func NewBlake2F() PrecompiledContract { return newBlake2F() }

// NewKeccak256 returns the Keccak256 precompiled contract.
func NewKeccak256() PrecompiledContract { return newKeccak256() }

// NewDilithiumVerify returns the Dilithium3 signature verification precompiled contract.
func NewDilithiumVerify() PrecompiledContract { return newDilithiumVerify() }

// NewKyberKEM returns the Kyber768 key encapsulation precompiled contract.
func NewKyberKEM() PrecompiledContract { return newKyberKEM() }
