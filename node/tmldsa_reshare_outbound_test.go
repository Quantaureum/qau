// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"testing"
)

func TestTMLDSAOutboundReshareSetRoundTrip(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	set := testTMLDSAOutboundReshareSet()
	if err := node.persistTMLDSAOutboundReshareSet(set); err != nil {
		t.Fatalf("persist outbound set: %v", err)
	}
	loaded, found, err := node.loadTMLDSAOutboundReshareSet(set.SessionID, set.DealerID, []uint32{7, 8, 9, 10, 11, 12})
	if err != nil {
		t.Fatalf("load outbound set: %v", err)
	}
	if !found {
		t.Fatal("outbound set not found")
	}
	if loaded.KeyGeneration != set.KeyGeneration || loaded.OldCommitteeVersion != set.OldCommitteeVersion || loaded.NewCommitteeVersion != set.NewCommitteeVersion {
		t.Fatalf("outbound metadata mismatch: %+v", loaded)
	}
	for recipient, want := range set.Payloads {
		if !bytes.Equal(loaded.Payloads[recipient], want) {
			t.Fatalf("recipient %d payload mismatch", recipient)
		}
	}
}

func TestTMLDSAOutboundReshareSetRejectsPartialRecovery(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	set := testTMLDSAOutboundReshareSet()
	partial := tmldsaReshareJournalRecord{
		Version:             tmldsaReshareJournalVersion,
		Kind:                tmldsaReshareJournalOutbound,
		SessionID:           set.SessionID,
		KeyGeneration:       set.KeyGeneration,
		OldCommitteeVersion: set.OldCommitteeVersion,
		NewCommitteeVersion: set.NewCommitteeVersion,
		DealerID:            set.DealerID,
		RecipientID:         7,
		Payload:             set.Payloads[7],
		PayloadDigest:       digestTMLDSAResharePayload(set.Payloads[7]),
	}
	if err := node.persistTMLDSAReshareJournalRecord(partial); err != nil {
		t.Fatal(err)
	}
	if _, _, err := node.loadTMLDSAOutboundReshareSet(set.SessionID, set.DealerID, []uint32{7, 8, 9, 10, 11, 12}); err == nil {
		t.Fatal("partial outbound set must fail closed")
	}
}

func TestTMLDSAOutboundReshareSetRejectsWrongCardinality(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	set := testTMLDSAOutboundReshareSet()
	delete(set.Payloads, 12)
	if err := node.persistTMLDSAOutboundReshareSet(set); err == nil {
		t.Fatal("five-recipient outbound set must fail")
	}
}

func testTMLDSAOutboundReshareSet() tmldsaOutboundReshareSet {
	var sessionID [32]byte
	sessionID[0] = 0x93
	payloads := make(map[uint32][]byte, 6)
	for recipient := uint32(7); recipient <= 12; recipient++ {
		payloads[recipient] = []byte{byte(recipient), 0xaa, 0x55}
	}
	return tmldsaOutboundReshareSet{
		SessionID:           sessionID,
		KeyGeneration:       4,
		OldCommitteeVersion: 9,
		NewCommitteeVersion: 10,
		DealerID:            2,
		Payloads:            payloads,
	}
}
