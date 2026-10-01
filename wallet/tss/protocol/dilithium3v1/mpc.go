// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import "context"

// MPCSession binds every secure operation to exactly one canonical signing
// session and to the DKG transcript that produced the shared key material.
type MPCSession struct {
	SessionID        [32]byte
	TranscriptDigest [32]byte
}

// PublicHighBits is the public w1 vector in its canonical four-bit encoding.
type PublicHighBits struct {
	Encoded [K][HighBitsEncodedSize]byte
}

// Evidence is public complaint metadata. It never carries secret-derived
// values, coefficients, or share material.
type Evidence struct {
	ParticipantID uint32
	Digest        [32]byte
}

// Challenge is the public mode3 challenge polynomial c.
type Challenge Poly

// MPCExecutor runs the authenticated operations that signing cannot compute
// locally. No method returns a complete secret polynomial, a raw authenticated
// share, LowBits, any partial nonce sum, any individual response share, or the
// carry vector. The layer is gated off by default and is not production-enabled;
// see docs/superpowers/specs/2026-09-24-qau-dilithium3-v1-signing-mpc.md.
type MPCExecutor interface {
	// OpenHighBits returns w1 of the shared value behind the handle. Only the
	// sixteen-valued high part is opened.
	OpenHighBits(context.Context, MPCSession, SecretHandle) (PublicHighBits, Evidence, error)

	// MultiplyPublicChallenge multiplies the shared vector behind the handle by
	// the public challenge and returns a handle to the product shares.
	MultiplyPublicChallenge(context.Context, MPCSession, SecretHandle, Challenge) (SecretHandle, Evidence, error)

	// CheckNorm opens exactly one bit: whether every coefficient of the shared
	// vector behind the handle is below the bound in absolute value.
	CheckNorm(context.Context, MPCSession, SecretHandle, int32) (bool, Evidence, error)

	// MakeHints derives the public hint vector for the attempt. The reviewed
	// construction computes hints from public values only (z, c, t1, and the
	// committed w1); the handle carries the attempt binding and nothing secret
	// is opened here.
	MakeHints(context.Context, MPCSession, SecretHandle) (HintVector, Evidence, error)

	// Burn consumes the handle fail-closed after a rejection or abort.
	Burn(MPCSession, SecretHandle) error
}

// EncodePublicHighBits packs six high-bit polynomials into the public w1 form.
func EncodePublicHighBits(high VectorK) (PublicHighBits, error) {
	var public PublicHighBits
	for row := 0; row < K; row++ {
		var rowHigh HighBitsPoly
		for index := 0; index < N; index++ {
			coefficient := high[row][index]
			if coefficient < 0 || coefficient > highBitsMask {
				return PublicHighBits{}, ErrInvalidHighBits
			}
			rowHigh[index] = uint8(coefficient)
		}
		encoded, err := EncodeHighBits(rowHigh)
		if err != nil {
			return PublicHighBits{}, err
		}
		public.Encoded[row] = encoded
	}
	return public, nil
}
