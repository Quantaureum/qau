// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/quantaureum/qau/wallet/tss/qtd"
)

func testReshareJournalMessage(marker string) *reshareWireMessage {
	return &reshareWireMessage{
		SessionID:          []byte("01234567890123456789012345678901"),
		Epoch:              3,
		FromParticipant:    4,
		ToParticipant:      7,
		Threshold:          2,
		OldParticipants:    []int{4, 9},
		NewParticipants:    []int{7, 11},
		GroupPublicKeyData: []byte("group-key"),
		Contribution: &qtd.SubShare{
			FromParticipant: 4,
			ToParticipant:   7,
			S1SubShare:      []byte(marker),
			S2SubShare:      []byte("s2"),
			T0SubShare:      []byte("t0"),
		},
	}
}

func TestReshareJournalPersistsEncryptedIdempotentMessages(t *testing.T) {
	directory := t.TempDir()
	node := &Node{config: &Config{
		TSSKeyShareFile:      filepath.Join(directory, "share.enc"),
		ValidatorKeyPassword: "DEVNET ONLY reshare journal password",
	}}
	message := testReshareJournalMessage("secret-sub-share-marker")
	if err := node.persistOutboundReshareMessages(message.SessionID, []*reshareWireMessage{message}); err != nil {
		t.Fatal(err)
	}
	if err := node.persistOutboundReshareMessages(message.SessionID, []*reshareWireMessage{message}); err != nil {
		t.Fatalf("idempotent persistence failed: %v", err)
	}
	outbound, inbound, err := node.loadReshareJournal(message.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(outbound) != 1 || len(inbound) != 0 || !sameReshareMessage(outbound[0], message) {
		t.Fatalf("wrong journal contents: outbound=%d inbound=%d", len(outbound), len(inbound))
	}
	files, err := os.ReadDir(node.reshareJournalSessionDir(message.SessionID))
	if err != nil || len(files) != 1 {
		t.Fatalf("journal files = %d, err=%v", len(files), err)
	}
	raw, err := os.ReadFile(filepath.Join(node.reshareJournalSessionDir(message.SessionID), files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("secret-sub-share-marker")) {
		t.Fatal("journal exposed plaintext contribution")
	}
	conflict := testReshareJournalMessage("different-secret")
	if err := node.persistOutboundReshareMessages(conflict.SessionID, []*reshareWireMessage{conflict}); err == nil {
		t.Fatal("conflicting contribution replaced durable randomness")
	}
	if err := node.cleanupReshareJournal(message.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(node.reshareJournalSessionDir(message.SessionID)); !os.IsNotExist(err) {
		t.Fatalf("journal session directory remains: %v", err)
	}
}

func TestReshareJournalPersistsInboundBeforeAcknowledgement(t *testing.T) {
	directory := t.TempDir()
	node := &Node{config: &Config{
		TSSKeyShareFile:      filepath.Join(directory, "share.enc"),
		ValidatorKeyPassword: "DEVNET ONLY reshare journal password",
	}}
	message := testReshareJournalMessage("inbound-secret")
	if err := node.persistInboundReshareMessage(message); err != nil {
		t.Fatal(err)
	}
	outbound, inbound, err := node.loadReshareJournal(message.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(outbound) != 0 || len(inbound) != 1 || !sameReshareMessage(inbound[0], message) {
		t.Fatalf("wrong inbound journal contents: outbound=%d inbound=%d", len(outbound), len(inbound))
	}
}
