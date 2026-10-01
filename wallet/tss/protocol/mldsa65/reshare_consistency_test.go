// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"bytes"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestReshareEvaluationSyndromesAndConstantLink(t *testing.T) {
	key, oldCommittee := testShareIdentity(t)
	newCommittee := protocol.CommitteeID{Version: oldCommittee.Version + 1, Threshold: 4, Participants: []uint32{7, 8, 9, 10, 11, 12}}
	selectedDealers := []uint32{1, 2, 3, 4}
	oldMaterial := evaluateTestShareMaterial(ShareMaterial{}, 1)
	oldShare, err := NewLocalShare(key, oldCommittee, 1, oldMaterial)
	if err != nil {
		t.Fatalf("NewLocalShare(): %v", err)
	}
	plan, err := NewReshareDealerPlan(
		oldShare,
		oldCommittee,
		newCommittee,
		selectedDealers,
		bytes.NewReader(testEntropy(300000, 6)),
	)
	if err != nil {
		t.Fatalf("NewReshareDealerPlan(): %v", err)
	}
	contributions := make([]ReshareContribution, 0, len(newCommittee.Participants))
	for _, recipientID := range newCommittee.Participants {
		contribution, err := plan.Contribution(recipientID)
		if err != nil {
			t.Fatalf("Contribution(%d): %v", recipientID, err)
		}
		contributions = append(contributions, contribution)
	}

	var sessionID [32]byte
	sessionID[0] = 0xc6
	var challengeNonce [32]byte
	challengeNonce[0] = 0xd7
	seed, err := DeriveReshareConsistencySeed(sessionID, challengeNonce, contributions)
	if err != nil {
		t.Fatalf("DeriveReshareConsistencySeed(): %v", err)
	}
	evaluationCoefficients, err := ReshareEvaluationCheckCoefficients(newCommittee.Participants)
	if err != nil {
		t.Fatalf("ReshareEvaluationCheckCoefficients(): %v", err)
	}
	constantCoefficients, err := ReshareConstantCheckCoefficients(newCommittee.Participants)
	if err != nil {
		t.Fatalf("ReshareConstantCheckCoefficients(): %v", err)
	}
	oldLambda, err := lagrangeCoefficientAtZero(1, selectedDealers)
	if err != nil {
		t.Fatalf("lagrangeCoefficientAtZero(): %v", err)
	}

	for round := uint32(0); round < 4; round++ {
		projections := make([]int32, len(contributions))
		for index := range contributions {
			projection, err := contributions[index].LinearProjection(seed, round)
			if err != nil {
				t.Fatalf("LinearProjection(%d): %v", index, err)
			}
			projections[index] = projection
		}
		for checkIndex := range evaluationCoefficients {
			terms := make([]int32, len(projections))
			for index := range projections {
				terms[index] = MaskedLinearTerm(projections[index], evaluationCoefficients[checkIndex][index], 0)
			}
			if syndrome := AggregateLinearTerms(terms); syndrome != 0 {
				t.Fatalf("round %d evaluation check %d syndrome = %d", round, checkIndex, syndrome)
			}
		}

		oldProjection, err := oldShare.LinearProjection(seed, round)
		if err != nil {
			t.Fatalf("old share projection: %v", err)
		}
		constantTerms := make([]int32, 0, len(projections)+1)
		for index := range projections {
			constantTerms = append(constantTerms, MaskedLinearTerm(projections[index], constantCoefficients[index], 0))
		}
		constantTerms = append(constantTerms, MaskedLinearTerm(oldProjection, -int32(oldLambda), 0))
		if syndrome := AggregateLinearTerms(constantTerms); syndrome != 0 {
			t.Fatalf("round %d constant-link syndrome = %d", round, syndrome)
		}
	}
}

func TestReshareConsistencyDetectsCommittedInvalidVector(t *testing.T) {
	key, oldCommittee := testShareIdentity(t)
	newCommittee := protocol.CommitteeID{Version: oldCommittee.Version + 1, Threshold: 4, Participants: []uint32{7, 8, 9, 10, 11, 12}}
	selectedDealers := []uint32{1, 2, 3, 4}
	oldShare, err := NewLocalShare(key, oldCommittee, 1, evaluateTestShareMaterial(ShareMaterial{}, 1))
	if err != nil {
		t.Fatalf("NewLocalShare(): %v", err)
	}
	plan, err := NewReshareDealerPlan(oldShare, oldCommittee, newCommittee, selectedDealers, bytes.NewReader(testEntropy(300000, 7)))
	if err != nil {
		t.Fatalf("NewReshareDealerPlan(): %v", err)
	}
	contributions := make([]ReshareContribution, 0, 6)
	for _, recipientID := range newCommittee.Participants {
		contribution, err := plan.Contribution(recipientID)
		if err != nil {
			t.Fatal(err)
		}
		contributions = append(contributions, contribution)
	}
	contributions[5].material.S1[0][0] = NormalizeCoefficient(int64(contributions[5].material.S1[0][0]) + 1)
	contributions[5].commitment = contributions[5].digest()

	var sessionID [32]byte
	sessionID[0] = 0xe8
	var challengeNonce [32]byte
	challengeNonce[0] = 0xf9
	seed, err := DeriveReshareConsistencySeed(sessionID, challengeNonce, contributions)
	if err != nil {
		t.Fatal(err)
	}
	coefficients, err := ReshareEvaluationCheckCoefficients(newCommittee.Participants)
	if err != nil {
		t.Fatal(err)
	}
	detected := false
	for round := uint32(0); round < 8 && !detected; round++ {
		projections := make([]int32, len(contributions))
		for index := range contributions {
			projections[index], err = contributions[index].LinearProjection(seed, round)
			if err != nil {
				t.Fatal(err)
			}
		}
		for checkIndex := range coefficients {
			terms := make([]int32, len(projections))
			for index := range projections {
				terms[index] = MaskedLinearTerm(projections[index], coefficients[checkIndex][index], 0)
			}
			if AggregateLinearTerms(terms) != 0 {
				detected = true
				break
			}
		}
	}
	if !detected {
		t.Fatal("invalid committed contribution vector escaped all consistency rounds")
	}
}

func TestMaskedLinearTermsCancelWithoutChangingSyndrome(t *testing.T) {
	projections := []int32{11, 22, 33, 44, 55, 66}
	coefficients := []int32{3, 5, 7, 9, 11, 13}
	masks := []int32{101, 202, 303, 404, 505, -1515}
	unmasked := make([]int32, len(projections))
	masked := make([]int32, len(projections))
	for index := range projections {
		unmasked[index] = MaskedLinearTerm(projections[index], coefficients[index], 0)
		masked[index] = MaskedLinearTerm(projections[index], coefficients[index], masks[index])
		if masked[index] == unmasked[index] {
			t.Fatalf("term %d was not masked", index)
		}
	}
	if AggregateLinearTerms(masked) != AggregateLinearTerms(unmasked) {
		t.Fatal("zero-sum masks changed the aggregate syndrome")
	}
}

func TestReshareDealerConstantCheckCoefficientMatchesWeightedOldShare(t *testing.T) {
	selectedDealers := []uint32{1, 2, 3, 4}
	coefficient, err := ReshareDealerConstantCheckCoefficient(1, selectedDealers)
	if err != nil {
		t.Fatal(err)
	}
	lambda, err := lagrangeCoefficientAtZero(1, selectedDealers)
	if err != nil {
		t.Fatal(err)
	}
	want := NormalizeCoefficient(-int64(lambda))
	if coefficient != want {
		t.Fatalf("coefficient = %d, want %d", coefficient, want)
	}
}
