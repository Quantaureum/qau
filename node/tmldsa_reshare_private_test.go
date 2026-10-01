// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"testing"

	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

func TestTMLDSAResharePrivateContributionStrictRoundTrip(t *testing.T) {
	key, oldCommittee, newCommittee, selectedDealers := testTMLDSAActivationIdentity(t)
	oldShare, err := protocolmldsa65.NewLocalShare(key, oldCommittee, 1, protocolmldsa65.ShareMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := protocolmldsa65.NewReshareDealerPlan(
		oldShare,
		oldCommittee,
		newCommittee,
		selectedDealers,
		bytes.NewReader(bytes.Repeat([]byte{0xe1}, 100000)),
	)
	if err != nil {
		t.Fatal(err)
	}
	contribution, err := plan.Contribution(7)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocolmldsa65.EncodeReshareContribution(contribution)
	if err != nil {
		t.Fatal(err)
	}
	message := tmldsaResharePrivateContribution{
		SessionID:       [32]byte{0xe2},
		Key:             key,
		OldCommittee:    oldCommittee,
		NewCommittee:    newCommittee,
		SelectedDealers: selectedDealers,
		DealerID:        1,
		RecipientID:     7,
		Payload:         payload,
	}
	encoded, err := encodeTMLDSAResharePrivateContribution(message)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeTMLDSAResharePrivateContribution(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.DealerID != message.DealerID || decoded.RecipientID != message.RecipientID ||
		!bytes.Equal(decoded.Payload, payload) {
		t.Fatal("private contribution round trip mismatch")
	}
	encoded[len(encoded)-1] ^= 1
	if _, err := decodeTMLDSAResharePrivateContribution(encoded); err == nil {
		t.Fatal("tampered private contribution decoded")
	}
}
