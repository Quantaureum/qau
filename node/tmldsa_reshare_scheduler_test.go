// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"errors"
	"testing"

	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

func TestTMLDSAReshareAdvanceAppliesOnlyAfterBroadcast(t *testing.T) {
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TMLDSA_V1", "1")
	node := testTMLDSAJournalNode(t)
	key, oldCommittee, newCommittee, selectedDealers := testTMLDSAActivationIdentity(t)
	request := tmldsaReshareRunRequest{
		SessionID:       [32]byte{0x71},
		ActivationEpoch: 63,
		Key:             key,
		OldCommittee:    oldCommittee,
		NewCommittee:    newCommittee,
		SelectedDealers: selectedDealers,
	}
	oldShare, err := protocolmldsa65.NewLocalShare(key, oldCommittee, 1, protocolmldsa65.ShareMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	privateMessages, control, err := node.prepareTMLDSAReshareDealerMessages(
		request,
		1,
		oldShare,
		bytes.NewReader(bytes.Repeat([]byte{0x72}, 100000)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.applyTMLDSAReshareControlMessage(control); err != nil {
		t.Fatal(err)
	}
	if err := node.persistTMLDSAInboundResharePayload(tmldsaInboundReshareSet{
		SessionID:           request.SessionID,
		KeyGeneration:       key.Generation,
		OldCommitteeVersion: oldCommittee.Version,
		NewCommitteeVersion: newCommittee.Version,
		RecipientID:         7,
	}, 1, privateMessages[0].Payload); err != nil {
		t.Fatal(err)
	}

	wantErr := errors.New("network unavailable")
	if _, err := node.advanceTMLDSAReshareParticipant(
		request,
		7,
		bytes.NewReader(bytes.Repeat([]byte{0x73}, 128)),
		func(tmldsaReshareControlMessage) error { return wantErr },
	); !errors.Is(err, wantErr) {
		t.Fatalf("advance error = %v", err)
	}
	state, found, err := node.loadTMLDSAReshareConsistencyState(request.SessionID, 1)
	if err != nil || !found || state.EventCount() != 0 {
		t.Fatalf("failed broadcast advanced state: found=%v events=%d err=%v", found, state.EventCount(), err)
	}

	if _, err := node.advanceTMLDSAReshareParticipant(
		request,
		7,
		bytes.NewReader(bytes.Repeat([]byte{0x74}, 128)),
		func(tmldsaReshareControlMessage) error { return nil },
	); err != nil {
		t.Fatal(err)
	}
	state, found, err = node.loadTMLDSAReshareConsistencyState(request.SessionID, 1)
	if err != nil || !found || state.EventCount() != 1 {
		t.Fatalf("successful broadcast was not durable: found=%v events=%d err=%v", found, state.EventCount(), err)
	}
}
