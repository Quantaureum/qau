// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"bytes"
	"errors"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func TestReshareContributionEncodingRoundTrip(t *testing.T) {
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
		bytes.NewReader(testEntropy(300000, 3)),
	)
	if err != nil {
		t.Fatalf("NewReshareDealerPlan(): %v", err)
	}
	want, err := plan.Contribution(7)
	if err != nil {
		t.Fatalf("Contribution(): %v", err)
	}
	encoded, err := EncodeReshareContribution(want)
	if err != nil {
		t.Fatalf("EncodeReshareContribution(): %v", err)
	}
	got, err := DecodeReshareContribution(
		encoded,
		key,
		oldCommittee,
		newCommittee,
		selectedDealers,
		1,
		7,
	)
	if err != nil {
		t.Fatalf("DecodeReshareContribution(): %v", err)
	}
	if got.material != want.material || got.commitment != want.commitment {
		t.Fatal("reshare contribution round trip mismatch")
	}
}

func TestReshareContributionEncodingRejectsTampering(t *testing.T) {
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
		bytes.NewReader(testEntropy(300000, 4)),
	)
	if err != nil {
		t.Fatalf("NewReshareDealerPlan(): %v", err)
	}
	contribution, err := plan.Contribution(7)
	if err != nil {
		t.Fatalf("Contribution(): %v", err)
	}
	encoded, err := EncodeReshareContribution(contribution)
	if err != nil {
		t.Fatalf("EncodeReshareContribution(): %v", err)
	}

	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)-33] ^= 1
	if _, err := DecodeReshareContribution(tampered, key, oldCommittee, newCommittee, selectedDealers, 1, 7); !errors.Is(err, ErrInvalidReshareContribution) {
		t.Fatalf("tampered payload error = %v, want %v", err, ErrInvalidReshareContribution)
	}
	if _, err := DecodeReshareContribution(encoded[:len(encoded)-1], key, oldCommittee, newCommittee, selectedDealers, 1, 7); !errors.Is(err, ErrInvalidReshareContribution) {
		t.Fatalf("truncated payload error = %v, want %v", err, ErrInvalidReshareContribution)
	}
	if _, err := DecodeReshareContribution(append(encoded, 0), key, oldCommittee, newCommittee, selectedDealers, 1, 7); !errors.Is(err, ErrInvalidReshareContribution) {
		t.Fatalf("trailing payload error = %v, want %v", err, ErrInvalidReshareContribution)
	}
	if _, err := DecodeReshareContribution(encoded, key, oldCommittee, newCommittee, selectedDealers, 2, 7); !errors.Is(err, ErrInvalidReshareContribution) {
		t.Fatalf("wrong dealer binding error = %v, want %v", err, ErrInvalidReshareContribution)
	}
}
