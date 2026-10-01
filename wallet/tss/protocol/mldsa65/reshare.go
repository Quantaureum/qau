// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"crypto/sha3"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

var (
	ErrInvalidReshareAuthorization = errors.New("invalid TMLDSA v1 reshare authorization")
	ErrInvalidReshareContribution  = errors.New("invalid TMLDSA v1 reshare contribution")
	ErrInvalidReshareEntropy       = errors.New("invalid TMLDSA v1 reshare entropy")
	ErrResharePlanZeroized         = errors.New("TMLDSA v1 reshare plan is zeroized")
)

// ReshareDealerPlan is one old holder's durable linear reshare polynomial.
type ReshareDealerPlan struct {
	mu              sync.Mutex
	key             protocol.ThresholdKeyID
	oldCommittee    protocol.CommitteeID
	newCommittee    protocol.CommitteeID
	selectedDealers []uint32
	dealerID        uint32
	constant        ShareMaterial
	coefficients    [3]ShareMaterial
	zeroized        bool
}

// ReshareContribution is one encrypted-recipient payload before transport encoding.
type ReshareContribution struct {
	key             protocol.ThresholdKeyID
	oldCommittee    protocol.CommitteeID
	newCommittee    protocol.CommitteeID
	selectedDealers []uint32
	dealerID        uint32
	recipientID     uint32
	material        ShareMaterial
	commitment      [32]byte
}

// Commitment returns the authenticated digest bound to this contribution.
func (contribution ReshareContribution) Commitment() ([32]byte, error) {
	if err := contribution.validate(
		contribution.key,
		contribution.oldCommittee,
		contribution.newCommittee,
		contribution.selectedDealers,
		contribution.recipientID,
	); err != nil {
		return [32]byte{}, err
	}
	return contribution.commitment, nil
}

// NewReshareDealerPlan creates a stable degree-three contribution plan.
func NewReshareDealerPlan(
	oldShare *LocalShare,
	oldCommittee protocol.CommitteeID,
	newCommittee protocol.CommitteeID,
	selectedDealers []uint32,
	entropy io.Reader,
) (*ReshareDealerPlan, error) {
	if oldShare == nil || oldShare.IsZeroized() {
		return nil, ErrInvalidLocalShare
	}
	if err := DefaultProfile().ValidateTransition(oldCommittee, newCommittee); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidReshareAuthorization, err)
	}
	if err := validateSelectedDealers(oldCommittee, selectedDealers); err != nil {
		return nil, err
	}
	if !containsParticipant(selectedDealers, oldShare.participant) {
		return nil, fmt.Errorf("%w: dealer %d is not authorized", ErrInvalidReshareAuthorization, oldShare.participant)
	}
	if err := oldShare.ValidateIdentity(oldShare.key, oldCommittee, oldShare.participant); err != nil {
		return nil, err
	}
	if entropy == nil {
		return nil, ErrInvalidReshareEntropy
	}

	lambda, err := lagrangeCoefficientAtZero(oldShare.participant, selectedDealers)
	if err != nil {
		return nil, err
	}
	plan := &ReshareDealerPlan{
		key:             oldShare.key.Clone(),
		oldCommittee:    oldCommittee.Clone(),
		newCommittee:    newCommittee.Clone(),
		selectedDealers: append([]uint32(nil), selectedDealers...),
		dealerID:        oldShare.participant,
		constant:        scalarMulShareMaterial(oldShare.material, int32(lambda)),
	}
	for index := range plan.coefficients {
		material, err := randomShareMaterial(entropy)
		if err != nil {
			plan.Zeroize()
			return nil, err
		}
		plan.coefficients[index] = material
	}
	return plan, nil
}

// Contribution deterministically evaluates the persisted plan for one recipient.
func (plan *ReshareDealerPlan) Contribution(recipientID uint32) (ReshareContribution, error) {
	if plan == nil {
		return ReshareContribution{}, ErrInvalidReshareContribution
	}
	plan.mu.Lock()
	defer plan.mu.Unlock()
	if plan.zeroized {
		return ReshareContribution{}, ErrResharePlanZeroized
	}
	if !committeeContains(plan.newCommittee, recipientID) || recipientID >= Modulus {
		return ReshareContribution{}, ErrInvalidReshareContribution
	}
	contribution := ReshareContribution{
		key:             plan.key.Clone(),
		oldCommittee:    plan.oldCommittee.Clone(),
		newCommittee:    plan.newCommittee.Clone(),
		selectedDealers: append([]uint32(nil), plan.selectedDealers...),
		dealerID:        plan.dealerID,
		recipientID:     recipientID,
		material:        evaluateResharePolynomial(plan.constant, plan.coefficients, int32(recipientID)),
	}
	contribution.commitment = contribution.digest()
	return contribution, nil
}

// Zeroize clears the weighted old share and every random polynomial coefficient.
func (plan *ReshareDealerPlan) Zeroize() {
	if plan == nil {
		return
	}
	plan.mu.Lock()
	defer plan.mu.Unlock()
	plan.constant = ShareMaterial{}
	plan.coefficients = [3]ShareMaterial{}
	plan.zeroized = true
}

// CombineReshareContributions installs one new local share after exact validation.
func CombineReshareContributions(
	key protocol.ThresholdKeyID,
	oldCommittee protocol.CommitteeID,
	newCommittee protocol.CommitteeID,
	selectedDealers []uint32,
	recipientID uint32,
	contributions []ReshareContribution,
) (*LocalShare, error) {
	if err := DefaultProfile().ValidateTransition(oldCommittee, newCommittee); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidReshareAuthorization, err)
	}
	if err := validateSelectedDealers(oldCommittee, selectedDealers); err != nil {
		return nil, err
	}
	if !committeeContains(newCommittee, recipientID) || recipientID >= Modulus {
		return nil, ErrInvalidReshareContribution
	}
	seen := make(map[uint32]struct{}, len(contributions))
	var combined ShareMaterial
	for index := range contributions {
		contribution := &contributions[index]
		if err := contribution.validate(key, oldCommittee, newCommittee, selectedDealers, recipientID); err != nil {
			return nil, err
		}
		if _, duplicate := seen[contribution.dealerID]; duplicate {
			return nil, ErrInvalidReshareContribution
		}
		seen[contribution.dealerID] = struct{}{}
		combined = addShareMaterial(combined, contribution.material)
	}
	if len(contributions) != len(selectedDealers) {
		return nil, ErrInvalidReshareAuthorization
	}
	for _, dealerID := range selectedDealers {
		if _, ok := seen[dealerID]; !ok {
			return nil, ErrInvalidReshareAuthorization
		}
	}
	return NewLocalShare(key, newCommittee, recipientID, combined)
}

func (contribution *ReshareContribution) validate(
	key protocol.ThresholdKeyID,
	oldCommittee protocol.CommitteeID,
	newCommittee protocol.CommitteeID,
	selectedDealers []uint32,
	recipientID uint32,
) error {
	if contribution == nil || contribution.dealerID == 0 || contribution.recipientID != recipientID {
		return ErrInvalidReshareContribution
	}
	if !containsParticipant(selectedDealers, contribution.dealerID) ||
		!equalParticipants(selectedDealers, contribution.selectedDealers) {
		return ErrInvalidReshareContribution
	}
	if !sameKeyIdentity(key, contribution.key) ||
		!sameCommitteeIdentity(oldCommittee, contribution.oldCommittee) ||
		!sameCommitteeIdentity(newCommittee, contribution.newCommittee) {
		return ErrInvalidReshareContribution
	}
	want := contribution.digest()
	if subtle.ConstantTimeCompare(want[:], contribution.commitment[:]) != 1 {
		return ErrInvalidReshareContribution
	}
	if err := validateShareMaterial(contribution.material); err != nil {
		return ErrInvalidReshareContribution
	}
	return nil
}

func (contribution *ReshareContribution) digest() [32]byte {
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-RESHARE-CONTRIBUTION"))
	keyDigest, _ := contribution.key.CanonicalDigest()
	oldDigest, _ := contribution.oldCommittee.CanonicalDigest()
	newDigest, _ := contribution.newCommittee.CanonicalDigest()
	_, _ = digest.Write(keyDigest[:])
	_, _ = digest.Write(oldDigest[:])
	_, _ = digest.Write(newDigest[:])
	var encoded [4]byte
	for _, dealerID := range contribution.selectedDealers {
		binary.BigEndian.PutUint32(encoded[:], dealerID)
		_, _ = digest.Write(encoded[:])
	}
	binary.BigEndian.PutUint32(encoded[:], contribution.dealerID)
	_, _ = digest.Write(encoded[:])
	binary.BigEndian.PutUint32(encoded[:], contribution.recipientID)
	_, _ = digest.Write(encoded[:])
	writeShareMaterial(digest, contribution.material)
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func validateSelectedDealers(committee protocol.CommitteeID, selected []uint32) error {
	if len(selected) != int(protocol.TMLDSAV1Threshold) {
		return ErrInvalidReshareAuthorization
	}
	var previous uint32
	for index, participant := range selected {
		if participant == 0 || participant >= Modulus || !committeeContains(committee, participant) {
			return ErrInvalidReshareAuthorization
		}
		if index > 0 && participant <= previous {
			return ErrInvalidReshareAuthorization
		}
		previous = participant
	}
	return nil
}

func lagrangeCoefficientAtZero(participant uint32, selected []uint32) (uint32, error) {
	if !containsParticipant(selected, participant) {
		return 0, ErrInvalidReshareAuthorization
	}
	numerator := int64(1)
	denominator := int64(1)
	for _, other := range selected {
		if other == participant {
			continue
		}
		numerator = modQ64(numerator * -int64(other))
		denominator = modQ64(denominator * (int64(participant) - int64(other)))
	}
	if denominator == 0 {
		return 0, ErrInvalidReshareAuthorization
	}
	return uint32(modQ64(numerator * modularInverse(denominator))), nil
}

func modularInverse(value int64) int64 {
	base := modQ64(value)
	exponent := int64(Modulus - 2)
	result := int64(1)
	for exponent > 0 {
		if exponent&1 == 1 {
			result = result * base % Modulus
		}
		base = base * base % Modulus
		exponent >>= 1
	}
	return result
}

func randomShareMaterial(entropy io.Reader) (ShareMaterial, error) {
	var material ShareMaterial
	fill := func(polynomials []Poly) error {
		for polynomialIndex := range polynomials {
			for coefficientIndex := range polynomials[polynomialIndex] {
				coefficient, err := sampleUniformCoefficient(entropy)
				if err != nil {
					return err
				}
				polynomials[polynomialIndex][coefficientIndex] = coefficient
			}
		}
		return nil
	}
	if err := fill(material.S1[:]); err != nil {
		return ShareMaterial{}, err
	}
	if err := fill(material.S2[:]); err != nil {
		return ShareMaterial{}, err
	}
	if err := fill(material.T0[:]); err != nil {
		return ShareMaterial{}, err
	}
	return material, nil
}

func sampleUniformCoefficient(entropy io.Reader) (int32, error) {
	const sampleSpace = uint64(1) << 32
	limit := sampleSpace - sampleSpace%Modulus
	var encoded [4]byte
	for {
		if _, err := io.ReadFull(entropy, encoded[:]); err != nil {
			return 0, fmt.Errorf("%w: %v", ErrInvalidReshareEntropy, err)
		}
		candidate := uint64(binary.LittleEndian.Uint32(encoded[:]))
		if candidate < limit {
			return int32(candidate % Modulus), nil
		}
	}
}

func evaluateResharePolynomial(constant ShareMaterial, coefficients [3]ShareMaterial, x int32) ShareMaterial {
	result := constant
	power := x
	for index := range coefficients {
		result = addShareMaterial(result, scalarMulShareMaterial(coefficients[index], power))
		power = NormalizeCoefficient(int64(power) * int64(x))
	}
	return result
}

func addShareMaterial(left, right ShareMaterial) ShareMaterial {
	var result ShareMaterial
	for index := range result.S1 {
		result.S1[index] = Add(left.S1[index], right.S1[index])
	}
	for index := range result.S2 {
		result.S2[index] = Add(left.S2[index], right.S2[index])
	}
	for index := range result.T0 {
		result.T0[index] = Add(left.T0[index], right.T0[index])
	}
	return result
}

func scalarMulShareMaterial(material ShareMaterial, scalar int32) ShareMaterial {
	var result ShareMaterial
	for index := range result.S1 {
		result.S1[index] = ScalarMul(material.S1[index], scalar)
	}
	for index := range result.S2 {
		result.S2[index] = ScalarMul(material.S2[index], scalar)
	}
	for index := range result.T0 {
		result.T0[index] = ScalarMul(material.T0[index], scalar)
	}
	return result
}

func containsParticipant(participants []uint32, participant uint32) bool {
	for _, candidate := range participants {
		if candidate == participant {
			return true
		}
	}
	return false
}

func equalParticipants(left, right []uint32) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sameKeyIdentity(left, right protocol.ThresholdKeyID) bool {
	leftDigest, leftErr := left.CanonicalDigest()
	rightDigest, rightErr := right.CanonicalDigest()
	return leftErr == nil && rightErr == nil && subtle.ConstantTimeCompare(leftDigest[:], rightDigest[:]) == 1
}

func sameCommitteeIdentity(left, right protocol.CommitteeID) bool {
	leftDigest, leftErr := left.CanonicalDigest()
	rightDigest, rightErr := right.CanonicalDigest()
	return leftErr == nil && rightErr == nil && subtle.ConstantTimeCompare(leftDigest[:], rightDigest[:]) == 1
}

func modQ64(value int64) int64 {
	value %= Modulus
	if value < 0 {
		value += Modulus
	}
	return value
}
