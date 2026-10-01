// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/sha3"
	"os"
	"testing"

	circlmldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

func TestTMLDSAReshareConsistencyJournalPersistsEncryptedOrderedState(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	coordinator := testTMLDSAReshareConsistencyCoordinator(t)
	if err := node.persistTMLDSAReshareConsistencyState(coordinator); err != nil {
		t.Fatalf("persist initial state: %v", err)
	}

	digest := coordinator.ContributionSetDigest()
	if err := coordinator.RecordContributionAgreement(7, digest); err != nil {
		t.Fatal(err)
	}
	if err := node.persistTMLDSAReshareConsistencyState(coordinator); err != nil {
		t.Fatalf("persist advanced state: %v", err)
	}
	if err := node.persistTMLDSAReshareConsistencyState(coordinator); err != nil {
		t.Fatalf("idempotent persist: %v", err)
	}

	loaded, found, err := node.loadTMLDSAReshareConsistencyState([32]byte{0x44}, 1)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if !found || loaded.EventCount() != coordinator.EventCount() ||
		loaded.TranscriptDigest() != coordinator.TranscriptDigest() ||
		loaded.Phase() != coordinator.Phase() {
		t.Fatal("loaded consistency state mismatch")
	}

	raw, err := os.ReadFile(node.tmldsaReshareConsistencyStatePath([32]byte{0x44}, 1))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("QTMLDSA-RESHARE-CONSISTENCY-1")) || bytes.Contains(raw, digest[:]) {
		t.Fatal("consistency journal exposed plaintext")
	}
}

func TestTMLDSAReshareConsistencyJournalRejectsRollbackAndCorruption(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	coordinator := testTMLDSAReshareConsistencyCoordinator(t)
	if err := node.persistTMLDSAReshareConsistencyState(coordinator); err != nil {
		t.Fatal(err)
	}
	oldState, found, err := node.loadTMLDSAReshareConsistencyState([32]byte{0x44}, 1)
	if err != nil || !found {
		t.Fatalf("load initial state: found=%v err=%v", found, err)
	}

	digest := coordinator.ContributionSetDigest()
	if err := coordinator.RecordContributionAgreement(7, digest); err != nil {
		t.Fatal(err)
	}
	if err := node.persistTMLDSAReshareConsistencyState(coordinator); err != nil {
		t.Fatal(err)
	}
	if err := node.persistTMLDSAReshareConsistencyState(oldState); err == nil {
		t.Fatal("consistency state rollback must fail")
	}

	path := node.tmldsaReshareConsistencyStatePath([32]byte{0x44}, 1)
	if err := os.WriteFile(path, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := node.loadTMLDSAReshareConsistencyState([32]byte{0x44}, 1); err == nil {
		t.Fatal("corrupt consistency ciphertext must fail")
	}
}

func testTMLDSAReshareConsistencyCoordinator(t *testing.T) *protocolmldsa65.ReshareConsistencyCoordinator {
	t.Helper()
	var seed [circlmldsa65.SeedSize]byte
	seed[0] = 0x28
	publicKey, _ := circlmldsa65.NewKeyFromSeed(&seed)
	key := protocol.ThresholdKeyID{
		Algorithm:  qcrypto.SignatureAlgorithmMLDSA65,
		Generation: 9,
		PublicKey:  publicKey.Bytes(),
	}
	oldCommittee := protocol.CommitteeID{Version: 21, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 6}}
	newCommittee := protocol.CommitteeID{Version: 22, Threshold: 4, Participants: []uint32{7, 8, 9, 10, 11, 12}}
	commitments := make(map[uint32][32]byte, 6)
	for _, participantID := range newCommittee.Participants {
		commitments[participantID] = sha3.Sum256([]byte{byte(participantID), 0xc1})
	}
	coordinator, err := protocolmldsa65.NewReshareConsistencyCoordinator(
		[32]byte{0x44},
		key,
		oldCommittee,
		newCommittee,
		[]uint32{1, 2, 3, 4},
		1,
		commitments,
	)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}
