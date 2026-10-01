// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"os"
	"testing"
)

func TestTMLDSAReshareJournalPersistsEncryptedPayload(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	record := testTMLDSAReshareJournalRecord()
	if err := node.persistTMLDSAReshareJournalRecord(record); err != nil {
		t.Fatalf("persist reshare record: %v", err)
	}
	if err := node.persistTMLDSAReshareJournalRecord(record); err != nil {
		t.Fatalf("idempotent persist: %v", err)
	}

	loaded, found, err := node.loadTMLDSAReshareJournalRecord(
		record.Kind,
		record.SessionID,
		record.DealerID,
		record.RecipientID,
	)
	if err != nil {
		t.Fatalf("load reshare record: %v", err)
	}
	if !found || !equalTMLDSAReshareJournalRecords(loaded, record) {
		t.Fatalf("loaded record mismatch: found=%v", found)
	}

	raw, err := os.ReadFile(node.tmldsaReshareJournalPath(record.Kind, record.SessionID, record.DealerID, record.RecipientID))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, record.Payload) || bytes.Contains(raw, []byte(tmldsaReshareJournalMagic)) {
		t.Fatal("reshare journal exposed plaintext")
	}
}

func TestTMLDSAReshareJournalRejectsConflictAndMetadataMismatch(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	record := testTMLDSAReshareJournalRecord()
	if err := node.persistTMLDSAReshareJournalRecord(record); err != nil {
		t.Fatal(err)
	}

	conflict := record
	conflict.Payload = append([]byte(nil), record.Payload...)
	conflict.Payload[0] ^= 1
	conflict.PayloadDigest = digestTMLDSAResharePayload(conflict.Payload)
	if err := node.persistTMLDSAReshareJournalRecord(conflict); err == nil {
		t.Fatal("conflicting reshare payload must fail")
	}

	if _, found, err := node.loadTMLDSAReshareJournalRecord(record.Kind, record.SessionID, record.DealerID, record.RecipientID+1); err != nil || found {
		t.Fatalf("wrong recipient path found=%v err=%v", found, err)
	}
}

func TestTMLDSAReshareJournalRejectsCorruptCiphertext(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	record := testTMLDSAReshareJournalRecord()
	if err := node.persistTMLDSAReshareJournalRecord(record); err != nil {
		t.Fatal(err)
	}
	path := node.tmldsaReshareJournalPath(record.Kind, record.SessionID, record.DealerID, record.RecipientID)
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := node.loadTMLDSAReshareJournalRecord(record.Kind, record.SessionID, record.DealerID, record.RecipientID); err == nil {
		t.Fatal("corrupt ciphertext must fail")
	}
}

func testTMLDSAReshareJournalRecord() tmldsaReshareJournalRecord {
	var sessionID [32]byte
	sessionID[0] = 0x82
	payload := []byte("sensitive TMLDSA v1 recipient contribution")
	return tmldsaReshareJournalRecord{
		Version:             tmldsaReshareJournalVersion,
		Kind:                tmldsaReshareJournalOutbound,
		SessionID:           sessionID,
		KeyGeneration:       3,
		OldCommitteeVersion: 7,
		NewCommitteeVersion: 8,
		DealerID:            1,
		RecipientID:         9,
		Payload:             payload,
		PayloadDigest:       digestTMLDSAResharePayload(payload),
	}
}
