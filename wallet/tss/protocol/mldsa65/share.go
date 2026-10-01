// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
)

var (
	ErrInvalidLocalShare       = errors.New("invalid TMLDSA v1 local share")
	ErrShareIdentityMismatch   = errors.New("TMLDSA v1 share identity mismatch")
	ErrShareCommitmentMismatch = errors.New("TMLDSA v1 share commitment mismatch")
	ErrLocalShareZeroized      = errors.New("TMLDSA v1 local share is zeroized")
)

// ShareMaterial contains one participant's shares of the ML-DSA secret vectors.
type ShareMaterial struct {
	S1 [5]Poly
	S2 [6]Poly
	T0 [6]Poly
}

// LocalShare binds one participant's share material to one key and committee.
type LocalShare struct {
	key         protocol.ThresholdKeyID
	committee   protocol.CommitteeID
	participant uint32
	material    ShareMaterial
	zeroized    bool
}

// NewLocalShare validates and installs one participant's local share.
func NewLocalShare(
	key protocol.ThresholdKeyID,
	committee protocol.CommitteeID,
	participant uint32,
	material ShareMaterial,
) (*LocalShare, error) {
	if err := key.Validate(); err != nil || key.Algorithm != qcrypto.SignatureAlgorithmMLDSA65 {
		return nil, fmt.Errorf("%w: key", ErrInvalidLocalShare)
	}
	if err := DefaultProfile().ValidateCommittee(committee); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidLocalShare, err)
	}
	if !committeeContains(committee, participant) {
		return nil, fmt.Errorf("%w: participant %d is not in the committee", ErrInvalidLocalShare, participant)
	}
	if err := validateShareMaterial(material); err != nil {
		return nil, err
	}
	return &LocalShare{
		key:         key.Clone(),
		committee:   committee.Clone(),
		participant: participant,
		material:    material,
	}, nil
}

// DefaultProfile returns the fixed qau-tmldsa65-v1 committee profile.
func DefaultProfile() protocol.TMLDSAV1Profile {
	return protocol.DefaultTMLDSAV1Profile()
}

// ValidateIdentity rejects generation, committee, or participant substitution.
func (share *LocalShare) ValidateIdentity(
	key protocol.ThresholdKeyID,
	committee protocol.CommitteeID,
	participant uint32,
) error {
	if share == nil {
		return ErrInvalidLocalShare
	}
	wantKeyDigest, err := share.key.CanonicalDigest()
	if err != nil {
		return ErrInvalidLocalShare
	}
	gotKeyDigest, err := key.CanonicalDigest()
	if err != nil {
		return ErrShareIdentityMismatch
	}
	wantCommitteeDigest, err := share.committee.CanonicalDigest()
	if err != nil {
		return ErrInvalidLocalShare
	}
	gotCommitteeDigest, err := committee.CanonicalDigest()
	if err != nil {
		return ErrShareIdentityMismatch
	}
	if subtle.ConstantTimeCompare(wantKeyDigest[:], gotKeyDigest[:]) != 1 ||
		subtle.ConstantTimeCompare(wantCommitteeDigest[:], gotCommitteeDigest[:]) != 1 ||
		share.participant != participant {
		return ErrShareIdentityMismatch
	}
	return nil
}

// Identity returns cloned public metadata without exposing share material.
func (share *LocalShare) Identity() (
	protocol.ThresholdKeyID,
	protocol.CommitteeID,
	uint32,
	error,
) {
	if share == nil {
		return protocol.ThresholdKeyID{}, protocol.CommitteeID{}, 0, ErrInvalidLocalShare
	}
	if share.zeroized {
		return protocol.ThresholdKeyID{}, protocol.CommitteeID{}, 0, ErrLocalShareZeroized
	}
	return share.key.Clone(), share.committee.Clone(), share.participant, nil
}

// Commitment returns a domain-separated digest of this exact local share.
func (share *LocalShare) Commitment() [32]byte {
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-LOCAL-SHARE"))
	writeLocalShareMetadata(digest, share)
	writeShareMaterial(digest, share.material)
	var commitment [32]byte
	copy(commitment[:], digest.Sum(nil))
	return commitment
}

// VerifyCommitment checks exact local-share byte consistency.
func (share *LocalShare) VerifyCommitment(commitment [32]byte) error {
	if share == nil {
		return ErrInvalidLocalShare
	}
	if share.zeroized {
		return ErrLocalShareZeroized
	}
	want := share.Commitment()
	if subtle.ConstantTimeCompare(want[:], commitment[:]) != 1 {
		return ErrShareCommitmentMismatch
	}
	return nil
}

// Zeroize clears all secret-share coefficients and permanently retires the value.
func (share *LocalShare) Zeroize() {
	if share == nil {
		return
	}
	share.material = ShareMaterial{}
	share.zeroized = true
}

// IsZeroized reports whether the share has been retired and cleared.
func (share *LocalShare) IsZeroized() bool {
	return share == nil || share.zeroized
}

func validateShareMaterial(material ShareMaterial) error {
	for vectorIndex := range material.S1 {
		if err := validateSharePoly("s1", vectorIndex, material.S1[vectorIndex]); err != nil {
			return err
		}
	}
	for vectorIndex := range material.S2 {
		if err := validateSharePoly("s2", vectorIndex, material.S2[vectorIndex]); err != nil {
			return err
		}
	}
	for vectorIndex := range material.T0 {
		if err := validateSharePoly("t0", vectorIndex, material.T0[vectorIndex]); err != nil {
			return err
		}
	}
	return nil
}

func validateSharePoly(name string, vectorIndex int, polynomial Poly) error {
	for coefficientIndex, coefficient := range polynomial {
		if !isCanonicalCoefficient(coefficient) {
			return fmt.Errorf(
				"%w: %s[%d][%d] is not canonical",
				ErrInvalidLocalShare,
				name,
				vectorIndex,
				coefficientIndex,
			)
		}
	}
	return nil
}

func committeeContains(committee protocol.CommitteeID, participant uint32) bool {
	for _, candidate := range committee.Participants {
		if candidate == participant {
			return true
		}
	}
	return false
}

func writeLocalShareMetadata(digest hash.Hash, share *LocalShare) {
	var encoded [8]byte
	binary.BigEndian.PutUint16(encoded[:2], uint16(share.key.Algorithm))
	_, _ = digest.Write(encoded[:2])
	binary.BigEndian.PutUint64(encoded[:], share.key.Generation)
	_, _ = digest.Write(encoded[:])
	_, _ = digest.Write(share.key.PublicKey)
	binary.BigEndian.PutUint64(encoded[:], share.committee.Version)
	_, _ = digest.Write(encoded[:])
	binary.BigEndian.PutUint32(encoded[:4], share.committee.Threshold)
	_, _ = digest.Write(encoded[:4])
	for _, participant := range share.committee.Participants {
		binary.BigEndian.PutUint32(encoded[:4], participant)
		_, _ = digest.Write(encoded[:4])
	}
	binary.BigEndian.PutUint32(encoded[:4], share.participant)
	_, _ = digest.Write(encoded[:4])
}

func writeShareMaterial(digest hash.Hash, material ShareMaterial) {
	var encoded [4]byte
	writeVector := func(vector []Poly) {
		for polynomialIndex := range vector {
			for _, coefficient := range vector[polynomialIndex] {
				binary.BigEndian.PutUint32(encoded[:], uint32(coefficient))
				_, _ = digest.Write(encoded[:])
			}
		}
	}
	writeVector(material.S1[:])
	writeVector(material.S2[:])
	writeVector(material.T0[:])
}
