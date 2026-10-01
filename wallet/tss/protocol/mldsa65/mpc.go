// Quantaureum Node source, version 1.0.0.
package mldsa65

import "context"

// MPCSession binds an operation to one canonical threshold-signing transcript.
type MPCSession struct {
	SessionID        [32]byte
	TranscriptDigest [32]byte
}

// MPCPublicHighBits contains only the canonical public high-bit encodings.
type MPCPublicHighBits struct {
	Encoded [6][highBitsEncodedSize]byte
}

// MPCEvidence is public complaint or proof metadata.
type MPCEvidence struct {
	ParticipantID uint32
	Digest        [32]byte
}

// MPCExecutor defines required secure operations without exposing share values.
type MPCExecutor interface {
	OpenHighBits(
		context.Context,
		MPCSession,
		PreprocessingSecretHandle,
	) (MPCPublicHighBits, MPCEvidence, error)
	CheckNorm(
		context.Context,
		MPCSession,
		PreprocessingSecretHandle,
		int32,
	) (bool, MPCEvidence, error)
	MakeHints(
		context.Context,
		MPCSession,
		PreprocessingSecretHandle,
	) (HintVector, MPCEvidence, error)
}
