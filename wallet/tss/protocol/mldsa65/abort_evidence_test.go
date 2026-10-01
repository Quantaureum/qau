// Quantaureum Node source, version 1.0.0.
package mldsa65

import (
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
)

func TestSignedReshareAbortEvidenceBindsIdentityAndTranscript(t *testing.T) {
	key, oldCommittee := testShareIdentity(t)
	newCommittee := oldCommittee.Clone()
	newCommittee.Version++
	newCommittee.Participants = []uint32{7, 8, 9, 10, 11, 12}
	keyPair, err := qcrypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	evidence := SignedReshareAbortEvidence{
		SessionID:    [32]byte{0xa1},
		Key:          key,
		OldCommittee: oldCommittee,
		NewCommittee: newCommittee,
		DealerID:     1,
		ReporterID:   7,
		Evidence: ReshareAbortEvidence{
			Reason:       ReshareAbortReasonEquivocation,
			OffenderID:   8,
			Round:        3,
			CheckID:      2,
			DetailDigest: [32]byte{0xa2},
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
		return participantID == 7 && qcrypto.Verify(keyPair.Public, message, signature)
	}
	if err := evidence.Verify(verifier); err != nil {
		t.Fatalf("Verify(): %v", err)
	}

	tampered := evidence
	tampered.Evidence.Round++
	if err := tampered.Verify(verifier); err == nil {
		t.Fatal("tampered evidence verified")
	}

	outsider := evidence
	outsider.ReporterID = 13
	if _, err := outsider.SigningBytes(); err == nil {
		t.Fatal("evidence from noncommittee reporter encoded")
	}
}
