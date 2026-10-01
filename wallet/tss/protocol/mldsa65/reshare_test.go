// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"bytes"
	"errors"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestFourOfSixLinearResharePreservesSecret(t *testing.T) {
	key, oldCommittee := testShareIdentity(t)
	newCommittee := protocol.CommitteeID{
		Version:      oldCommittee.Version + 1,
		Threshold:    4,
		Participants: []uint32{7, 8, 9, 10, 11, 12},
	}
	selectedDealers := []uint32{1, 2, 3, 4}
	secret := ShareMaterial{}
	secret.S1[0][0] = 1234
	secret.S2[1][2] = 5678
	secret.T0[5][255] = 9012

	plans := make([]*ReshareDealerPlan, 0, len(selectedDealers))
	for _, dealerID := range selectedDealers {
		oldMaterial := evaluateTestShareMaterial(secret, int32(dealerID))
		oldShare, err := NewLocalShare(key, oldCommittee, dealerID, oldMaterial)
		if err != nil {
			t.Fatalf("NewLocalShare(%d): %v", dealerID, err)
		}
		entropy := bytes.NewReader(testEntropy(300000, byte(dealerID)))
		plan, err := NewReshareDealerPlan(
			oldShare,
			oldCommittee,
			newCommittee,
			selectedDealers,
			entropy,
		)
		if err != nil {
			t.Fatalf("NewReshareDealerPlan(%d): %v", dealerID, err)
		}
		plans = append(plans, plan)
	}

	newShares := make(map[int32]*LocalShare, len(newCommittee.Participants))
	for _, recipientID := range newCommittee.Participants {
		contributions := make([]ReshareContribution, 0, len(plans))
		for _, plan := range plans {
			contribution, err := plan.Contribution(recipientID)
			if err != nil {
				t.Fatalf("Contribution(%d): %v", recipientID, err)
			}
			contributions = append(contributions, contribution)
		}
		share, err := CombineReshareContributions(
			key,
			oldCommittee,
			newCommittee,
			selectedDealers,
			recipientID,
			contributions,
		)
		if err != nil {
			t.Fatalf("CombineReshareContributions(%d): %v", recipientID, err)
		}
		newShares[int32(recipientID)] = share
	}

	assertReconstructedCoefficient(t, newShares, func(material ShareMaterial) int32 { return material.S1[0][0] }, secret.S1[0][0])
	assertReconstructedCoefficient(t, newShares, func(material ShareMaterial) int32 { return material.S2[1][2] }, secret.S2[1][2])
	assertReconstructedCoefficient(t, newShares, func(material ShareMaterial) int32 { return material.T0[5][255] }, secret.T0[5][255])
}

func TestResharePlanIsStableAndZeroizable(t *testing.T) {
	key, oldCommittee := testShareIdentity(t)
	newCommittee := protocol.CommitteeID{Version: oldCommittee.Version + 1, Threshold: 4, Participants: []uint32{7, 8, 9, 10, 11, 12}}
	selectedDealers := []uint32{1, 2, 3, 4}
	oldShare, err := NewLocalShare(key, oldCommittee, 1, evaluateTestShareMaterial(ShareMaterial{}, 1))
	if err != nil {
		t.Fatalf("NewLocalShare(): %v", err)
	}
	plan, err := NewReshareDealerPlan(
		oldShare,
		oldCommittee,
		newCommittee,
		selectedDealers,
		bytes.NewReader(testEntropy(300000, 1)),
	)
	if err != nil {
		t.Fatalf("NewReshareDealerPlan(): %v", err)
	}
	first, err := plan.Contribution(12)
	if err != nil {
		t.Fatalf("first Contribution(): %v", err)
	}
	second, err := plan.Contribution(12)
	if err != nil {
		t.Fatalf("second Contribution(): %v", err)
	}
	if first.commitment != second.commitment || first.material != second.material {
		t.Fatal("delayed contribution changed across retransmission")
	}

	plan.Zeroize()
	if _, err := plan.Contribution(12); !errors.Is(err, ErrResharePlanZeroized) {
		t.Fatalf("Contribution() after zeroize error = %v, want %v", err, ErrResharePlanZeroized)
	}
}

func TestReshareRejectsInvalidAuthorizationAndMixing(t *testing.T) {
	key, oldCommittee := testShareIdentity(t)
	newCommittee := protocol.CommitteeID{Version: oldCommittee.Version + 1, Threshold: 4, Participants: []uint32{7, 8, 9, 10, 11, 12}}
	oldShare, err := NewLocalShare(key, oldCommittee, 1, evaluateTestShareMaterial(ShareMaterial{}, 1))
	if err != nil {
		t.Fatalf("NewLocalShare(): %v", err)
	}
	if _, err := NewReshareDealerPlan(
		oldShare,
		oldCommittee,
		newCommittee,
		[]uint32{1, 2, 3},
		bytes.NewReader(testEntropy(300000, 1)),
	); !errors.Is(err, ErrInvalidReshareAuthorization) {
		t.Fatalf("three-dealer error = %v, want %v", err, ErrInvalidReshareAuthorization)
	}

	selectedDealers := []uint32{1, 2, 3, 4}
	plan, err := NewReshareDealerPlan(
		oldShare,
		oldCommittee,
		newCommittee,
		selectedDealers,
		bytes.NewReader(testEntropy(300000, 2)),
	)
	if err != nil {
		t.Fatalf("NewReshareDealerPlan(): %v", err)
	}
	contribution, err := plan.Contribution(7)
	if err != nil {
		t.Fatalf("Contribution(): %v", err)
	}
	contribution.recipientID = 8
	if _, err := CombineReshareContributions(
		key,
		oldCommittee,
		newCommittee,
		selectedDealers,
		7,
		[]ReshareContribution{contribution},
	); !errors.Is(err, ErrInvalidReshareContribution) {
		t.Fatalf("mixed contribution error = %v, want %v", err, ErrInvalidReshareContribution)
	}
}

func evaluateTestShareMaterial(secret ShareMaterial, x int32) ShareMaterial {
	result := secret
	apply := func(polynomials []Poly) {
		for polynomialIndex := range polynomials {
			for coefficientIndex := range polynomials[polynomialIndex] {
				value := polynomials[polynomialIndex][coefficientIndex]
				polynomials[polynomialIndex][coefficientIndex] = NormalizeCoefficient(
					int64(value) + 2*int64(x) + 3*int64(x)*int64(x) + 4*int64(x)*int64(x)*int64(x),
				)
			}
		}
	}
	apply(result.S1[:])
	apply(result.S2[:])
	apply(result.T0[:])
	return result
}

func assertReconstructedCoefficient(
	t *testing.T,
	shares map[int32]*LocalShare,
	coefficient func(ShareMaterial) int32,
	want int32,
) {
	t.Helper()
	points := make(map[int32]int32, 4)
	for _, participant := range []int32{7, 8, 9, 10} {
		points[participant] = coefficient(shares[participant].material)
	}
	if got := interpolateAtZeroForTest(t, points); got != want {
		t.Fatalf("reconstructed coefficient = %d, want %d", got, want)
	}
}

func testEntropy(size int, seed byte) []byte {
	result := make([]byte, size)
	for index := range result {
		result[index] = byte((index*31 + int(seed)*17) & 0xff)
	}
	return result
}
