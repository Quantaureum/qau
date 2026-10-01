// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

func testTMLDSAJournalNode(t *testing.T) *Node {
	t.Helper()
	return &Node{config: &Config{
		TSSKeyShareFile:      filepath.Join(t.TempDir(), "share.enc"),
		ValidatorKeyPassword: "DEVNET ONLY tmldsa signing journal password",
	}}
}

func testPreparedRecord(t *testing.T) protocol.SingleUseRecord {
	t.Helper()
	var sessionID [32]byte
	sessionID[0] = 0x71
	record, err := protocol.NewSingleUseRecord(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := record.Transition(protocol.SingleUsePrepared, []byte("prepared-secret-state"))
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestTMLDSASigningJournalPersistsEncryptedRecord(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	prepared := testPreparedRecord(t)
	if err := node.persistTMLDSASigningRecord(prepared); err != nil {
		t.Fatalf("persist prepared: %v", err)
	}
	if err := node.persistTMLDSASigningRecord(prepared); err != nil {
		t.Fatalf("idempotent persist: %v", err)
	}

	loaded, found, err := node.loadTMLDSASigningRecord(prepared.SessionID)
	if err != nil {
		t.Fatalf("load prepared: %v", err)
	}
	if !found || loaded != prepared {
		t.Fatalf("loaded record mismatch: found=%v loaded=%#v", found, loaded)
	}
	raw, err := os.ReadFile(node.tmldsaSigningSessionPath(prepared.SessionID))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("QAU-TMLDSA65")) || bytes.Contains(raw, []byte("prepared-secret-state")) {
		t.Fatal("signing journal exposed plaintext")
	}
}

func TestTMLDSASigningJournalRejectsConflictRollbackAndBrokenLink(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	prepared := testPreparedRecord(t)
	if err := node.persistTMLDSASigningRecord(prepared); err != nil {
		t.Fatal(err)
	}

	conflict := prepared
	conflict.PreparedHash[0] ^= 0xff
	if err := node.persistTMLDSASigningRecord(conflict); err == nil {
		t.Fatal("conflicting record at the same sequence must fail")
	}

	committed, err := prepared.Transition(protocol.SingleUseCommitted, []byte("public-commitment"))
	if err != nil {
		t.Fatal(err)
	}
	if err := node.persistTMLDSASigningRecord(committed); err != nil {
		t.Fatalf("persist committed: %v", err)
	}
	if err := node.persistTMLDSASigningRecord(prepared); err == nil {
		t.Fatal("sequence rollback must fail")
	}

	responded, err := committed.Transition(protocol.SingleUseResponded, []byte("one-time-response"))
	if err != nil {
		t.Fatal(err)
	}
	responded.PreviousHash[0] ^= 0xff
	if err := node.persistTMLDSASigningRecord(responded); err == nil {
		t.Fatal("broken previous hash must fail")
	}
}

func TestTMLDSASigningJournalBurnsCommittedRecordOnRecovery(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	prepared := testPreparedRecord(t)
	if err := node.persistTMLDSASigningRecord(prepared); err != nil {
		t.Fatal(err)
	}
	committed, err := prepared.Transition(protocol.SingleUseCommitted, []byte("public-commitment"))
	if err != nil {
		t.Fatal(err)
	}
	if err := node.persistTMLDSASigningRecord(committed); err != nil {
		t.Fatal(err)
	}

	recovered, found, err := node.loadTMLDSASigningRecord(committed.SessionID)
	if err != nil {
		t.Fatalf("recover committed: %v", err)
	}
	if !found || recovered.State != protocol.SingleUseBurned {
		t.Fatalf("recovered state = %v, found=%v", recovered.State, found)
	}
	again, found, err := node.loadTMLDSASigningRecord(committed.SessionID)
	if err != nil || !found || again != recovered {
		t.Fatalf("burned state was not durable: found=%v err=%v", found, err)
	}
}

func TestTMLDSASigningJournalRejectsCorruptCiphertext(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	prepared := testPreparedRecord(t)
	if err := node.persistTMLDSASigningRecord(prepared); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(node.tmldsaSigningSessionPath(prepared.SessionID), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := node.loadTMLDSASigningRecord(prepared.SessionID); err == nil {
		t.Fatal("corrupt ciphertext must fail")
	}
}
