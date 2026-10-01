// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

var ErrInvalidReshareConsistency = errors.New("invalid TMLDSA v1 reshare consistency proof")

// DeriveReshareConsistencySeed binds a post-commitment unpredictable nonce to
// the complete ordered contribution commitment set.
func DeriveReshareConsistencySeed(
	sessionID [32]byte,
	challengeNonce [32]byte,
	contributions []ReshareContribution,
) ([32]byte, error) {
	if sessionID == ([32]byte{}) || challengeNonce == ([32]byte{}) || len(contributions) != int(6) {
		return [32]byte{}, ErrInvalidReshareConsistency
	}
	ordered := append([]ReshareContribution(nil), contributions...)
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left].recipientID < ordered[right].recipientID
	})
	first := &ordered[0]
	if err := first.validate(first.key, first.oldCommittee, first.newCommittee, first.selectedDealers, first.recipientID); err != nil {
		return [32]byte{}, err
	}
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-RESHARE-CONSISTENCY"))
	_, _ = digest.Write(sessionID[:])
	_, _ = digest.Write(challengeNonce[:])
	keyDigest, _ := first.key.CanonicalDigest()
	oldDigest, _ := first.oldCommittee.CanonicalDigest()
	newDigest, _ := first.newCommittee.CanonicalDigest()
	_, _ = digest.Write(keyDigest[:])
	_, _ = digest.Write(oldDigest[:])
	_, _ = digest.Write(newDigest[:])
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], first.dealerID)
	_, _ = digest.Write(encoded[:])
	var previousRecipient uint32
	for index := range ordered {
		contribution := &ordered[index]
		if index > 0 && contribution.recipientID == previousRecipient {
			return [32]byte{}, ErrInvalidReshareConsistency
		}
		if contribution.dealerID != first.dealerID ||
			!sameKeyIdentity(contribution.key, first.key) ||
			!sameCommitteeIdentity(contribution.oldCommittee, first.oldCommittee) ||
			!sameCommitteeIdentity(contribution.newCommittee, first.newCommittee) ||
			!equalParticipants(contribution.selectedDealers, first.selectedDealers) {
			return [32]byte{}, ErrInvalidReshareConsistency
		}
		if err := contribution.validate(
			first.key,
			first.oldCommittee,
			first.newCommittee,
			first.selectedDealers,
			contribution.recipientID,
		); err != nil {
			return [32]byte{}, err
		}
		binary.BigEndian.PutUint32(encoded[:], contribution.recipientID)
		_, _ = digest.Write(encoded[:])
		_, _ = digest.Write(contribution.commitment[:])
		previousRecipient = contribution.recipientID
	}
	var seed [32]byte
	copy(seed[:], digest.Sum(nil))
	return seed, nil
}

// LinearProjection compresses one recipient contribution under a public challenge.
func (contribution ReshareContribution) LinearProjection(seed [32]byte, round uint32) (int32, error) {
	if seed == ([32]byte{}) {
		return 0, ErrInvalidReshareConsistency
	}
	if err := contribution.validate(
		contribution.key,
		contribution.oldCommittee,
		contribution.newCommittee,
		contribution.selectedDealers,
		contribution.recipientID,
	); err != nil {
		return 0, err
	}
	return projectShareMaterial(contribution.material, seed, round)
}

// LinearProjection compresses one old local share under the same public challenge.
func (share *LocalShare) LinearProjection(seed [32]byte, round uint32) (int32, error) {
	if share == nil || share.IsZeroized() || seed == ([32]byte{}) {
		return 0, ErrInvalidReshareConsistency
	}
	return projectShareMaterial(share.material, seed, round)
}

// ReshareEvaluationCheckCoefficients returns two parity checks for degree-three
// evaluations at six distinct recipient identifiers.
func ReshareEvaluationCheckCoefficients(recipients []uint32) ([2][6]int32, error) {
	if err := validateEvaluationPoints(recipients); err != nil {
		return [2][6]int32{}, err
	}
	basis := recipients[:4]
	var checks [2][6]int32
	for checkIndex, targetIndex := range []int{4, 5} {
		for basisIndex := range basis {
			coefficient, err := lagrangeBasisAt(int64(recipients[targetIndex]), basisIndex, basis)
			if err != nil {
				return [2][6]int32{}, err
			}
			checks[checkIndex][basisIndex] = NormalizeCoefficient(-int64(coefficient))
		}
		checks[checkIndex][targetIndex] = 1
	}
	return checks, nil
}

// ReshareConstantCheckCoefficients reconstructs the polynomial constant from
// the first four recipient evaluations.
func ReshareConstantCheckCoefficients(recipients []uint32) ([6]int32, error) {
	if err := validateEvaluationPoints(recipients); err != nil {
		return [6]int32{}, err
	}
	basis := recipients[:4]
	var coefficients [6]int32
	for basisIndex := range basis {
		coefficient, err := lagrangeBasisAt(0, basisIndex, basis)
		if err != nil {
			return [6]int32{}, err
		}
		coefficients[basisIndex] = coefficient
	}
	return coefficients, nil
}

// ReshareDealerConstantCheckCoefficient returns the dealer witness coefficient
// that links the reconstructed contribution constant to the weighted old share.
func ReshareDealerConstantCheckCoefficient(dealerID uint32, selectedDealers []uint32) (int32, error) {
	lambda, err := lagrangeCoefficientAtZero(dealerID, selectedDealers)
	if err != nil {
		return 0, err
	}
	return NormalizeCoefficient(-int64(lambda)), nil
}

// MaskedLinearTerm applies one public coefficient and one zero-sum private mask.
func MaskedLinearTerm(projection, coefficient, mask int32) int32 {
	return NormalizeCoefficient(int64(projection)*int64(coefficient) + int64(mask))
}

// AggregateLinearTerms reveals only the final syndrome modulo q.
func AggregateLinearTerms(terms []int32) int32 {
	var sum int64
	for _, term := range terms {
		sum += int64(term)
		sum %= Modulus
	}
	return NormalizeCoefficient(sum)
}

func projectShareMaterial(material ShareMaterial, seed [32]byte, round uint32) (int32, error) {
	shake := sha3.NewSHAKE256()
	_, _ = shake.Write([]byte("QAU-TMLDSA65-V1-LINEAR-PROJECTION"))
	_, _ = shake.Write(seed[:])
	var encodedRound [4]byte
	binary.BigEndian.PutUint32(encodedRound[:], round)
	_, _ = shake.Write(encodedRound[:])
	var result int64
	projectVector := func(polynomials []Poly) error {
		for polynomialIndex := range polynomials {
			for _, coefficient := range polynomials[polynomialIndex] {
				challenge, err := sampleUniformCoefficient(shake)
				if err != nil {
					return err
				}
				result += int64(coefficient) * int64(challenge)
				result %= Modulus
			}
		}
		return nil
	}
	if err := projectVector(material.S1[:]); err != nil {
		return 0, err
	}
	if err := projectVector(material.S2[:]); err != nil {
		return 0, err
	}
	if err := projectVector(material.T0[:]); err != nil {
		return 0, err
	}
	return NormalizeCoefficient(result), nil
}

func validateEvaluationPoints(recipients []uint32) error {
	if len(recipients) != 6 {
		return ErrInvalidReshareConsistency
	}
	seen := make(map[uint32]struct{}, len(recipients))
	for _, recipient := range recipients {
		if recipient == 0 || recipient >= Modulus {
			return ErrInvalidReshareConsistency
		}
		if _, duplicate := seen[recipient]; duplicate {
			return ErrInvalidReshareConsistency
		}
		seen[recipient] = struct{}{}
	}
	return nil
}

func lagrangeBasisAt(target int64, basisIndex int, basis []uint32) (int32, error) {
	if basisIndex < 0 || basisIndex >= len(basis) {
		return 0, ErrInvalidReshareConsistency
	}
	x := int64(basis[basisIndex])
	numerator := int64(1)
	denominator := int64(1)
	for index, otherValue := range basis {
		if index == basisIndex {
			continue
		}
		other := int64(otherValue)
		numerator = modQ64(numerator * (target - other))
		denominator = modQ64(denominator * (x - other))
	}
	if denominator == 0 {
		return 0, fmt.Errorf("%w: duplicate interpolation point", ErrInvalidReshareConsistency)
	}
	return int32(modQ64(numerator * modularInverse(denominator))), nil
}
