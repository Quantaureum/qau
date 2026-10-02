// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

const dkgSessionDomain = "QAU-TDILITHIUM3-V1-DKG-SESSION"

var ErrInvalidDKGSession = errors.New("invalid Dilithium3 v1 DKG session")

// DKGSession identifies one fixed-committee key-generation attempt.
type DKGSession struct {
	Protocol             protocol.ThresholdProtocol
	ChainID              uint64
	KeyGeneration        uint64
	Committee            protocol.CommitteeID
	ActivationEpoch      uint64
	Nonce                [32]byte
	IdentityRosterDigest [32]byte
}

// Validate enforces the Dilithium3 v1 committee family (R76a).
func (session DKGSession) Validate() error {
	if session.Protocol != protocol.ThresholdProtocolDilithium3V1 {
		return fmt.Errorf("%w: wrong protocol", ErrInvalidDKGSession)
	}
	if err := session.Protocol.ValidateAlgorithm(protocol.Dilithium3V1Profile().Algorithm); err != nil {
		return fmt.Errorf("%w: algorithm profile: %v", ErrInvalidDKGSession, err)
	}
	if session.ChainID == 0 {
		return fmt.Errorf("%w: zero chain ID", ErrInvalidDKGSession)
	}
	if session.KeyGeneration == 0 {
		return fmt.Errorf("%w: zero key generation", ErrInvalidDKGSession)
	}
	if err := protocol.ValidateDilithium3V1Committee(session.Committee); err != nil {
		return fmt.Errorf("%w: committee: %v", ErrInvalidDKGSession, err)
	}
	if session.ActivationEpoch == 0 {
		return fmt.Errorf("%w: zero activation epoch", ErrInvalidDKGSession)
	}
	if session.Nonce == ([32]byte{}) {
		return fmt.Errorf("%w: zero nonce", ErrInvalidDKGSession)
	}
	if session.IdentityRosterDigest == ([32]byte{}) {
		return fmt.Errorf("%w: zero identity roster digest", ErrInvalidDKGSession)
	}
	return nil
}

// Clone returns a session that does not alias the committee participant slice.
func (session DKGSession) Clone() DKGSession {
	session.Committee = session.Committee.Clone()
	return session
}

// Digest returns the canonical identity bound into every DKG round.
func (session DKGSession) Digest() ([32]byte, error) {
	if err := session.Validate(); err != nil {
		return [32]byte{}, err
	}
	committeeDigest, err := session.Committee.CanonicalDigest()
	if err != nil {
		return [32]byte{}, fmt.Errorf("%w: committee digest: %v", ErrInvalidDKGSession, err)
	}
	encoded := make([]byte, 0, len(dkgSessionDomain)+2+8+8+32+8+32+32)
	encoded = append(encoded, dkgSessionDomain...)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(session.Protocol))
	encoded = binary.BigEndian.AppendUint64(encoded, session.ChainID)
	encoded = binary.BigEndian.AppendUint64(encoded, session.KeyGeneration)
	encoded = append(encoded, committeeDigest[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, session.ActivationEpoch)
	encoded = append(encoded, session.Nonce[:]...)
	encoded = append(encoded, session.IdentityRosterDigest[:]...)
	return sha3.Sum256(encoded), nil
}
