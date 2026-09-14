// Quantaureum Node source, version 1.0.0.
package qtd

import "errors"

var (
	ErrInvalidConfig            = errors.New("qtd: invalid config")
	ErrInvalidPolyBytes         = errors.New("qtd: invalid polynomial bytes")
	ErrInvalidSeed              = errors.New("qtd: invalid seed")
	ErrInvalidTau               = errors.New("qtd: invalid tau parameter")
	ErrInvalidEta               = errors.New("qtd: invalid eta parameter")
	ErrInsufficientParticipants = errors.New("qtd: insufficient participants")
	ErrParticipantNotFound      = errors.New("qtd: participant not found")
	ErrRoundNotComplete         = errors.New("qtd: round not complete")
	ErrCommitmentMismatch       = errors.New("qtd: commitment mismatch")
	ErrRejectionSamplingFailed  = errors.New("qtd: rejection sampling failed")
	ErrInvalidShare             = errors.New("qtd: invalid share")
	ErrShareVerification        = errors.New("qtd: share verification failed")
	ErrKeyGenerationFailed      = errors.New("qtd: key generation failed")
	ErrSigningFailed            = errors.New("qtd: signing failed")
	ErrVerificationFailed       = errors.New("qtd: verification failed")
	ErrInvalidSignature         = errors.New("qtd: invalid signature")
	ErrSessionExpired           = errors.New("qtd: session expired")
	ErrRefreshFailed            = errors.New("qtd: share refresh failed")
	ErrCannotRemoveShare        = errors.New("qtd: cannot remove share, would drop below threshold")
	// Security fix (Round 4): Round1Verify did not validate that participant IDs belong to the participant list
	// nor detect duplicate submissions. An attacker could submit commitments for unauthorized participants or duplicate a participant's commitment.
	ErrInvalidParticipant  = errors.New("qtd: invalid participant not in participant list")
	ErrDuplicateCommitment = errors.New("qtd: duplicate round1 commitment from same participant")
)
