// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

var ErrInvalidSignedReshareAbortEvidence = errors.New("invalid signed TMLDSA v1 reshare abort evidence")

// SignedReshareAbortEvidence binds a public abort report to one authenticated
// committee identity and one exact reshare generation.
type SignedReshareAbortEvidence struct {
	SessionID         [32]byte
	Key               protocol.ThresholdKeyID
	OldCommittee      protocol.CommitteeID
	NewCommittee      protocol.CommitteeID
	DealerID          uint32
	ReporterID        uint32
	Evidence          ReshareAbortEvidence
	IdentitySignature []byte
}

// SigningBytes returns the canonical identity-signed abort evidence bytes.
func (signed SignedReshareAbortEvidence) SigningBytes() ([]byte, error) {
	if err := signed.validateUnsigned(); err != nil {
		return nil, err
	}
	keyDigest, _ := signed.Key.CanonicalDigest()
	oldDigest, _ := signed.OldCommittee.CanonicalDigest()
	newDigest, _ := signed.NewCommittee.CanonicalDigest()
	encoded := make([]byte, 0, 192)
	encoded = append(encoded, []byte("QAU-TMLDSA65-V1-RESHARE-ABORT-EVIDENCE")...)
	encoded = append(encoded, signed.SessionID[:]...)
	encoded = append(encoded, keyDigest[:]...)
	encoded = append(encoded, oldDigest[:]...)
	encoded = append(encoded, newDigest[:]...)
	encoded = binary.BigEndian.AppendUint32(encoded, signed.DealerID)
	encoded = binary.BigEndian.AppendUint32(encoded, signed.ReporterID)
	encoded = append(encoded, byte(signed.Evidence.Reason))
	encoded = binary.BigEndian.AppendUint32(encoded, signed.Evidence.OffenderID)
	encoded = binary.BigEndian.AppendUint32(encoded, signed.Evidence.Round)
	encoded = binary.BigEndian.AppendUint32(encoded, signed.Evidence.CheckID)
	encoded = append(encoded, signed.Evidence.DetailDigest[:]...)
	return encoded, nil
}

// Verify validates the evidence metadata and reporter identity signature.
func (signed SignedReshareAbortEvidence) Verify(verifier ReshareIdentityVerifier) error {
	if verifier == nil || len(signed.IdentitySignature) == 0 ||
		len(signed.IdentitySignature) > protocol.MaxThresholdIdentitySignature {
		return ErrInvalidSignedReshareAbortEvidence
	}
	message, err := signed.SigningBytes()
	if err != nil || !verifier(signed.ReporterID, message, signed.IdentitySignature) {
		return ErrInvalidSignedReshareAbortEvidence
	}
	return nil
}

// CanonicalDigest returns the stable digest including the identity signature.
func (signed SignedReshareAbortEvidence) CanonicalDigest() ([32]byte, error) {
	message, err := signed.SigningBytes()
	if err != nil || len(signed.IdentitySignature) == 0 ||
		len(signed.IdentitySignature) > protocol.MaxThresholdIdentitySignature {
		return [32]byte{}, ErrInvalidSignedReshareAbortEvidence
	}
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-RESHARE-SIGNED-ABORT"))
	_, _ = digest.Write(message)
	_, _ = digest.Write(signed.IdentitySignature)
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func (signed SignedReshareAbortEvidence) validateUnsigned() error {
	if signed.SessionID == ([32]byte{}) || signed.DealerID == 0 || signed.ReporterID == 0 ||
		signed.Evidence.Reason <= ReshareAbortReasonUnknown ||
		signed.Evidence.Reason > ReshareAbortReasonPersistence ||
		signed.Evidence.DetailDigest == ([32]byte{}) ||
		signed.Evidence.CheckID >= ReshareConsistencyChecksPerRound ||
		signed.Evidence.Round >= ReshareConsistencyRounds {
		return ErrInvalidSignedReshareAbortEvidence
	}
	if err := signed.Key.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignedReshareAbortEvidence, err)
	}
	if err := DefaultProfile().ValidateTransition(signed.OldCommittee, signed.NewCommittee); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSignedReshareAbortEvidence, err)
	}
	if !committeeContains(signed.OldCommittee, signed.DealerID) ||
		(!committeeContains(signed.OldCommittee, signed.ReporterID) &&
			!committeeContains(signed.NewCommittee, signed.ReporterID)) {
		return ErrInvalidSignedReshareAbortEvidence
	}
	return nil
}
