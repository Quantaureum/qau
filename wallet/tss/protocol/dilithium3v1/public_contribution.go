// Quantaureum Node source, version 1.0.0.
package dilithium3v1

import (
	"bytes"
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	publicContributionMagic   = "QTD3PC01"
	publicContributionVersion = uint16(1)
	publicContributionDomain  = "QAU-TDILITHIUM3-V1-PUBLIC-CONTRIBUTION"
)

var (
	ErrInvalidPublicContribution         = errors.New("invalid Dilithium3 v1 public contribution")
	ErrInvalidPublicContributionEncoding = errors.New("invalid Dilithium3 v1 public contribution encoding")
	ErrPublicContributionDigestMismatch  = errors.New("Dilithium3 v1 public contribution digest mismatch")
)

// PublicContribution binds one public t_U vector to its DKG group identity.
type PublicContribution struct {
	SessionDigest  [32]byte
	GroupMask      RSSGroupMask
	DealerPosition uint8
	T              VectorK
}

// NewPublicContribution computes the canonical public contribution for one group.
func NewPublicContribution(sessionDigest [32]byte, group RSSGroupMask, dealerPosition uint8, rho [32]byte, s1 VectorL, s2 VectorK) (PublicContribution, error) {
	vector, err := ComputePublicVector(rho, s1, s2)
	if err != nil {
		return PublicContribution{}, err
	}
	contribution := PublicContribution{SessionDigest: sessionDigest, GroupMask: group, DealerPosition: dealerPosition, T: vector}
	if err := contribution.Validate(); err != nil {
		return PublicContribution{}, err
	}
	return contribution, nil
}

// VerifyPublicContributionForComponent recomputes the canonical public
// contribution from one locally derived RSS component and rejects any published
// value that differs. Every group member must call this before accepting a
// leader's t_U, otherwise a malicious leader could activate a false partial
// public key that still assembles into a well-formed mode3 public key.
func VerifyPublicContributionForComponent(
	published PublicContribution,
	sessionDigest [32]byte,
	group RSSGroupMask,
	dealerPosition uint8,
	rho [32]byte,
	s1 VectorL,
	s2 VectorK,
) error {
	expected, err := NewPublicContribution(sessionDigest, group, dealerPosition, rho, s1, s2)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPublicContribution, err)
	}
	if err := published.Validate(); err != nil {
		return err
	}
	if published.SessionDigest != expected.SessionDigest ||
		published.GroupMask != expected.GroupMask ||
		published.DealerPosition != expected.DealerPosition {
		return ErrPublicContributionDigestMismatch
	}
	for polynomialIndex := range expected.T {
		for coefficientIndex := range expected.T[polynomialIndex] {
			if published.T[polynomialIndex][coefficientIndex] != expected.T[polynomialIndex][coefficientIndex] {
				return ErrPublicContributionDigestMismatch
			}
		}
	}
	return nil
}

// Validate rejects stale identities and non-canonical public coefficients.
func (contribution PublicContribution) Validate() error {
	if contribution.SessionDigest == ([32]byte{}) {
		return fmt.Errorf("%w: zero session digest", ErrInvalidPublicContribution)
	}
	if err := contribution.GroupMask.Validate(); err != nil {
		return fmt.Errorf("%w: group: %v", ErrInvalidPublicContribution, err)
	}
	if contribution.DealerPosition >= 6 || !contribution.GroupMask.Contains(contribution.DealerPosition) {
		return fmt.Errorf("%w: dealer %d is outside group", ErrInvalidPublicContribution, contribution.DealerPosition)
	}
	if err := validateVectorK("t", contribution.T); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPublicContribution, err)
	}
	return nil
}

// Digest returns the transcript digest of the canonical contribution payload.
func (contribution PublicContribution) Digest() ([32]byte, error) {
	payload, err := contribution.canonicalPayload()
	if err != nil {
		return [32]byte{}, err
	}
	encoded := make([]byte, 0, len(publicContributionDomain)+len(payload))
	encoded = append(encoded, publicContributionDomain...)
	encoded = append(encoded, payload...)
	return sha3.Sum256(encoded), nil
}

// MarshalBinary encodes one public contribution with an integrity checksum.
func (contribution PublicContribution) MarshalBinary() ([]byte, error) {
	payload, err := contribution.canonicalPayload()
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, publicContributionEncodedSize())
	encoded = append(encoded, publicContributionMagic...)
	encoded = binary.BigEndian.AppendUint16(encoded, publicContributionVersion)
	encoded = append(encoded, payload...)
	digest := sha3.Sum256(encoded)
	encoded = append(encoded, digest[:]...)
	return encoded, nil
}

// UnmarshalPublicContribution decodes and validates one canonical contribution.
func UnmarshalPublicContribution(encoded []byte) (PublicContribution, error) {
	if len(encoded) != publicContributionEncodedSize() || !bytes.Equal(encoded[:len(publicContributionMagic)], []byte(publicContributionMagic)) {
		return PublicContribution{}, ErrInvalidPublicContributionEncoding
	}
	payloadEnd := len(encoded) - 32
	wantDigest := sha3.Sum256(encoded[:payloadEnd])
	if subtle.ConstantTimeCompare(wantDigest[:], encoded[payloadEnd:]) != 1 {
		return PublicContribution{}, ErrPublicContributionDigestMismatch
	}
	offset := len(publicContributionMagic)
	if binary.BigEndian.Uint16(encoded[offset:offset+2]) != publicContributionVersion {
		return PublicContribution{}, ErrInvalidPublicContributionEncoding
	}
	offset += 2
	var contribution PublicContribution
	copy(contribution.SessionDigest[:], encoded[offset:offset+32])
	offset += 32
	contribution.GroupMask = RSSGroupMask(binary.BigEndian.Uint16(encoded[offset : offset+2]))
	offset += 2
	contribution.DealerPosition = encoded[offset]
	offset++
	for index := range contribution.T {
		polynomial, err := DecodePoly(encoded[offset : offset+PolyEncodedSize])
		if err != nil {
			return PublicContribution{}, ErrInvalidPublicContributionEncoding
		}
		contribution.T[index] = polynomial
		offset += PolyEncodedSize
	}
	if offset != payloadEnd {
		return PublicContribution{}, ErrInvalidPublicContributionEncoding
	}
	if err := contribution.Validate(); err != nil {
		return PublicContribution{}, err
	}
	return contribution, nil
}

func (contribution PublicContribution) canonicalPayload() ([]byte, error) {
	if err := contribution.Validate(); err != nil {
		return nil, err
	}
	payload := make([]byte, 0, 32+2+1+K*PolyEncodedSize)
	payload = append(payload, contribution.SessionDigest[:]...)
	payload = binary.BigEndian.AppendUint16(payload, uint16(contribution.GroupMask))
	payload = append(payload, contribution.DealerPosition)
	var err error
	payload, err = appendVectorK(payload, contribution.T)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func publicContributionEncodedSize() int {
	return len(publicContributionMagic) + 2 + 32 + 2 + 1 + K*PolyEncodedSize + 32
}
