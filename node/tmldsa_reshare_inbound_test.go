// Quantaureum Node source, version 1.0.0.
package node

import "testing"

func TestTMLDSAInboundReshareSetRecoversPartialThenComplete(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	set := testTMLDSAInboundReshareSet()
	if err := node.persistTMLDSAInboundResharePayload(set, 1, set.Payloads[1]); err != nil {
		t.Fatalf("persist first inbound payload: %v", err)
	}
	partial, found, complete, err := node.loadTMLDSAInboundReshareSet(set.SessionID, set.RecipientID, []uint32{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("load partial inbound set: %v", err)
	}
	if !found || complete || len(partial.Payloads) != 1 {
		t.Fatalf("partial state found=%v complete=%v payloads=%d", found, complete, len(partial.Payloads))
	}

	for dealerID := uint32(2); dealerID <= 4; dealerID++ {
		if err := node.persistTMLDSAInboundResharePayload(set, dealerID, set.Payloads[dealerID]); err != nil {
			t.Fatalf("persist dealer %d: %v", dealerID, err)
		}
	}
	loaded, found, complete, err := node.loadTMLDSAInboundReshareSet(set.SessionID, set.RecipientID, []uint32{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("load complete inbound set: %v", err)
	}
	if !found || !complete || len(loaded.Payloads) != 4 {
		t.Fatalf("complete state found=%v complete=%v payloads=%d", found, complete, len(loaded.Payloads))
	}
}

func TestTMLDSAInboundReshareSetRejectsMixedMetadata(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	set := testTMLDSAInboundReshareSet()
	if err := node.persistTMLDSAInboundResharePayload(set, 1, set.Payloads[1]); err != nil {
		t.Fatal(err)
	}
	mixed := set
	mixed.NewCommitteeVersion++
	if err := node.persistTMLDSAInboundResharePayload(mixed, 2, mixed.Payloads[2]); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := node.loadTMLDSAInboundReshareSet(set.SessionID, set.RecipientID, []uint32{1, 2, 3, 4}); err == nil {
		t.Fatal("mixed inbound metadata must fail")
	}
}

func testTMLDSAInboundReshareSet() tmldsaInboundReshareSet {
	var sessionID [32]byte
	sessionID[0] = 0xa4
	payloads := make(map[uint32][]byte, 4)
	for dealerID := uint32(1); dealerID <= 4; dealerID++ {
		payloads[dealerID] = []byte{byte(dealerID), 0x33, 0xcc}
	}
	return tmldsaInboundReshareSet{
		SessionID:           sessionID,
		KeyGeneration:       5,
		OldCommitteeVersion: 11,
		NewCommitteeVersion: 12,
		RecipientID:         9,
		Payloads:            payloads,
	}
}
