// Quantaureum Node source, version 1.0.0.
package node

import (
	"crypto/rand"
	"crypto/sha3"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// testAdoptionCertificate builds a fully signed activation certificate bound
// to the given session digest and the share's key, committee, transcript, and
// activation epoch. It mirrors testThresholdActivationCertificate but takes the
// session digest from the caller, because the adoption path derives the digest
// from the live inbox's session rather than from a fixed test vector.
func testAdoptionCertificate(t *testing.T, share *dilithium3v1.LocalShare, sessionDigest [32]byte) (dilithium3v1.DKGActivationCertificate, dilithium3v1.DKGIdentityVerifier, []dilithium3v1.DKGIdentityBinding) {
	t.Helper()
	encoded, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	localDigest := sha3.Sum256(encoded)
	clear(encoded)
	publicKeys := make(map[uint32]*mode3.PublicKey, len(share.Committee.Participants))
	certificate := dilithium3v1.DKGActivationCertificate{
		Acknowledgements: make([]dilithium3v1.DKGActivationAcknowledgement, len(share.Committee.Participants)),
	}
	for index, participantID := range share.Committee.Participants {
		publicKey, privateKey, err := mode3.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		publicKeys[participantID] = publicKey
		candidateDigest := sha3.Sum256([]byte{byte(participantID)})
		if participantID == share.ParticipantID {
			candidateDigest = localDigest
		}
		acknowledgement := dilithium3v1.DKGActivationAcknowledgement{
			SessionDigest:     sessionDigest,
			ActivationEpoch:   share.ActivationEpoch,
			Key:               share.Key.Clone(),
			Committee:         share.Committee.Clone(),
			TranscriptDigest:  share.TranscriptDigest,
			ParticipantID:     participantID,
			CandidateDigest:   candidateDigest,
			IdentitySignature: make([]byte, mode3.SignatureSize),
		}
		message, err := acknowledgement.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		mode3.SignTo(privateKey, message, acknowledgement.IdentitySignature)
		certificate.Acknowledgements[index] = acknowledgement
	}
	verifier := func(participantID uint32, message, signature []byte) bool {
		publicKey := publicKeys[participantID]
		return publicKey != nil && mode3.Verify(publicKey, message, signature)
	}
	// The v2 activation record persists the pid->identity binding the
	// certificate was verified under; hand the same material back so the
	// installing inbox can carry exactly what passed (mirrors
	// testThresholdActivationCertificate).
	bindings := make([]dilithium3v1.DKGIdentityBinding, 0, len(publicKeys))
	for _, participantID := range share.Committee.Participants {
		publicKey := publicKeys[participantID]
		bindings = append(bindings, dilithium3v1.DKGIdentityBinding{
			ParticipantID:    participantID,
			ValidatorAddress: types.AddressFromPublicKey(publicKey.Bytes()),
			PublicKey:        publicKey.Bytes(),
		})
	}
	return certificate, verifier, bindings
}

// testAdoptionNode builds the minimal node the adoption path touches: a config
// with a data directory, the share-store password, and the chain id the live
// inbox's session claims, plus the experimental gate the admissibility check
// requires.
func testAdoptionNode(t *testing.T, password []byte) *Node {
	t.Helper()
	t.Setenv("QAU_ENABLE_EXPERIMENTAL_TDILITHIUM3_V1", "1")
	return &Node{config: &Config{
		DataDir:              filepath.Join(t.TempDir(), "shares.enc"),
		ValidatorKeyPassword: string(password),
		NetworkID:            TestnetNetworkID,
	}}
}

// testAdoptionSession builds a syntactically valid v1 DKG session whose
// committee and activation epoch match the share.
func testAdoptionSession(t *testing.T, share *dilithium3v1.LocalShare) dilithium3v1.DKGSession {
	t.Helper()
	session := dilithium3v1.DKGSession{
		Protocol:             protocol.ThresholdProtocolDilithium3V1,
		ChainID:              TestnetNetworkID,
		KeyGeneration:        share.Key.Generation,
		Committee:            share.Committee.Clone(),
		ActivationEpoch:      share.ActivationEpoch,
		Nonce:                [32]byte{7, 7, 7},
		IdentityRosterDigest: [32]byte{9, 9, 9},
	}
	if err := session.Validate(); err != nil {
		t.Fatal(err)
	}
	return session
}

// installTestAdoptionInbox installs a roster-bound live inbox for the session
// on the node, using the certificate verifier as its identity verifier.
func installTestAdoptionInbox(t *testing.T, n *Node, session dilithium3v1.DKGSession, recipientPosition uint8, verifier dilithium3v1.DKGIdentityVerifier, bindings []dilithium3v1.DKGIdentityBinding) *tdilithium3DKGInbox {
	t.Helper()
	inbox, err := newTDilithium3DKGInbox(session, recipientPosition, verifier, func(p2p.PeerID) (uint32, bool) { return 0, false })
	if err != nil {
		t.Fatal(err)
	}
	inbox.rosterBound = true
	inbox.bindings = append([]dilithium3v1.DKGIdentityBinding(nil), bindings...)
	n.installTDilithium3DKGInbox(inbox)
	return inbox
}

func TestAdoptTDilithium3DKGActivationCertificateRejectsMalformedPayload(t *testing.T) {
	password := []byte("DEVNET ONLY adoption malformed payload password")
	n := testAdoptionNode(t, password)
	n.adoptTDilithium3DKGActivationCertificate([]byte("not a certificate"))
	n.adoptTDilithium3DKGActivationCertificate(nil)
	n.adoptTDilithium3DKGActivationCertificate([]byte(thresholdActivationMagic + `{"version":1,"certificate":{}}`))
	store := newThresholdShareStore(n.config.DataDir)
	if _, err := store.LoadActive(password); err == nil {
		t.Fatal("a malformed gossip payload activated a share")
	}
}

func TestAdoptTDilithium3DKGActivationCertificateLiveInboxAdopts(t *testing.T) {
	password := []byte("DEVNET ONLY adoption live inbox password")
	n := testAdoptionNode(t, password)
	share := testThresholdStoreShare(t, 2)
	session := testAdoptionSession(t, share)
	sessionDigest, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	certificate, verifier, bindings := testAdoptionCertificate(t, share, sessionDigest)
	installTestAdoptionInbox(t, n, session, share.ParticipantPosition, verifier, bindings)

	store := newThresholdShareStore(n.config.DataDir)
	if err := store.Store(share, password); err != nil {
		t.Fatal(err)
	}

	encoded, err := encodeThresholdActivationCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	n.adoptTDilithium3DKGActivationCertificate(encoded)

	active, err := store.LoadActiveAtEpoch(share.ActivationEpoch, verifier, password)
	if err != nil {
		t.Fatalf("adoption left no active share: %v", err)
	}
	if !slices.Equal(active.Components, share.Components) || active.ActivationEpoch != share.ActivationEpoch {
		t.Fatal("adopted share mismatch")
	}
	active.Zeroize()

	// Re-adoption of the identical certificate is idempotent.
	n.adoptTDilithium3DKGActivationCertificate(encoded)
	active, err = store.LoadActiveAtEpoch(share.ActivationEpoch, verifier, password)
	if err != nil {
		t.Fatalf("idempotent re-adoption broke the active share: %v", err)
	}
	active.Zeroize()
}

func TestAdoptTDilithium3DKGActivationCertificateRejectsTamperedSignature(t *testing.T) {
	password := []byte("DEVNET ONLY adoption tampered signature password")
	n := testAdoptionNode(t, password)
	share := testThresholdStoreShare(t, 2)
	session := testAdoptionSession(t, share)
	sessionDigest, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	certificate, verifier, bindings := testAdoptionCertificate(t, share, sessionDigest)
	certificate.Acknowledgements[4].IdentitySignature[0] ^= 1
	installTestAdoptionInbox(t, n, session, share.ParticipantPosition, verifier, bindings)

	store := newThresholdShareStore(n.config.DataDir)
	if err := store.Store(share, password); err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeThresholdActivationCertificate(certificate)
	if err == nil {
		n.adoptTDilithium3DKGActivationCertificate(encoded)
	}
	if _, err := store.LoadActive(password); err == nil {
		t.Fatal("a certificate with a forged acknowledgement was adopted")
	}
}

func TestAdoptTDilithium3DKGActivationCertificateRejectsWithoutCandidate(t *testing.T) {
	password := []byte("DEVNET ONLY adoption missing candidate password")
	n := testAdoptionNode(t, password)
	share := testThresholdStoreShare(t, 2)
	session := testAdoptionSession(t, share)
	sessionDigest, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	certificate, verifier, bindings := testAdoptionCertificate(t, share, sessionDigest)
	installTestAdoptionInbox(t, n, session, share.ParticipantPosition, verifier, bindings)

	// Deliberately no candidate share on disk: only a node that ran the same
	// DKG round holds one, so adoption without it must fail closed.
	encoded, err := encodeThresholdActivationCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	n.adoptTDilithium3DKGActivationCertificate(encoded)

	store := newThresholdShareStore(n.config.DataDir)
	if _, err := store.LoadActive(password); err == nil {
		t.Fatal("adoption succeeded without the candidate share")
	}
}

func TestAdoptTDilithium3DKGActivationCertificateRejectsUnknownSession(t *testing.T) {
	password := []byte("DEVNET ONLY adoption unknown session password")
	n := testAdoptionNode(t, password)
	share := testThresholdStoreShare(t, 2)
	session := testAdoptionSession(t, share)
	sessionDigest, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	certificate, _, _ := testAdoptionCertificate(t, share, sessionDigest)

	// No live inbox: adoption must derive the session from captured chain
	// state, which an unbootstrapped node does not have. The certificate is
	// well-formed and self-verifying but fails closed because this node has
	// no roster for the activation epoch.
	store := newThresholdShareStore(n.config.DataDir)
	if err := store.Store(share, password); err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeThresholdActivationCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	n.adoptTDilithium3DKGActivationCertificate(encoded)
	if _, err := store.LoadActive(password); err == nil {
		t.Fatal("adoption succeeded without derivable roster state")
	}
}

func TestAdoptTDilithium3DKGActivationCertificateInboxEpochMismatch(t *testing.T) {
	password := []byte("DEVNET ONLY adoption epoch mismatch password")
	n := testAdoptionNode(t, password)
	share := testThresholdStoreShare(t, 2)
	session := testAdoptionSession(t, share)
	sessionDigest, err := session.Digest()
	if err != nil {
		t.Fatal(err)
	}
	certificate, verifier, bindings := testAdoptionCertificate(t, share, sessionDigest)

	// The live inbox belongs to a different activation epoch than the
	// certificate, so it must not be reused; the derived path has no roster
	// on this bare node, so the adoption fails closed.
	mismatch := session.Clone()
	mismatch.ActivationEpoch = share.ActivationEpoch + 1
	installTestAdoptionInbox(t, n, mismatch, share.ParticipantPosition, verifier, bindings)

	store := newThresholdShareStore(n.config.DataDir)
	if err := store.Store(share, password); err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeThresholdActivationCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	n.adoptTDilithium3DKGActivationCertificate(encoded)
	if _, err := store.LoadActive(password); err == nil {
		t.Fatal("adoption reused an inbox from another activation epoch")
	}
}

func TestHandleTSSMessageRoutesActivationCertificateWithoutPanic(t *testing.T) {
	password := []byte("DEVNET ONLY certificate routing password")
	n := testAdoptionNode(t, password)
	n.handleTSSMessage(p2p.PeerMessage{Type: p2p.MsgTypeTDilithium3DKGActivationCertificate, From: "peer-x", Payload: []byte("garbage")})
	store := newThresholdShareStore(n.config.DataDir)
	if _, err := store.LoadActive(password); err == nil {
		t.Fatal("routed garbage was adopted")
	}
}
