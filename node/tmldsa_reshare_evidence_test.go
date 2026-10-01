// Quantaureum Node source, version 1.0.0.
package node

import (
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

func TestTMLDSAReshareAbortEvidencePersistsVerifiedIdentity(t *testing.T) {
	node := testTMLDSAJournalNode(t)
	key, oldCommittee, newCommittee, _ := testTMLDSAActivationIdentity(t)
	keyPair, err := qcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	evidence := protocolmldsa65.SignedReshareAbortEvidence{
		SessionID:    [32]byte{0xb1},
		Key:          key,
		OldCommittee: oldCommittee,
		NewCommittee: newCommittee,
		DealerID:     1,
		ReporterID:   7,
		Evidence: protocolmldsa65.ReshareAbortEvidence{
			Reason:       protocolmldsa65.ReshareAbortReasonTimeout,
			Round:        2,
			CheckID:      1,
			DetailDigest: [32]byte{0xb2},
		},
	}
	message, err := evidence.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	evidence.IdentitySignature, err = keyPair.Private.Sign(message)
	if err != nil {
		t.Fatal(err)
	}
	verifier := func(participantID uint32, message, signature []byte) bool {
		return participantID == evidence.ReporterID && qcrypto.Verify(keyPair.Public, message, signature)
	}
	if err := node.persistTMLDSAReshareAbortEvidence(evidence, verifier); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := node.loadTMLDSAReshareAbortEvidence(
		evidence.SessionID,
		evidence.DealerID,
		evidence.ReporterID,
	)
	if err != nil || !found {
		t.Fatalf("load evidence: found=%v err=%v", found, err)
	}
	wantDigest, _ := evidence.CanonicalDigest()
	gotDigest, _ := loaded.CanonicalDigest()
	if gotDigest != wantDigest {
		t.Fatal("loaded evidence digest mismatch")
	}
	if err := node.persistTMLDSAReshareAbortEvidence(evidence, verifier); err != nil {
		t.Fatalf("idempotent persist: %v", err)
	}

	conflict := evidence
	conflict.Evidence.DetailDigest[0] ^= 1
	conflictMessage, err := conflict.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	conflict.IdentitySignature, err = keyPair.Private.Sign(conflictMessage)
	if err != nil {
		t.Fatal(err)
	}
	if err := node.persistTMLDSAReshareAbortEvidence(conflict, verifier); err == nil {
		t.Fatal("conflicting evidence replaced durable record")
	}
}
