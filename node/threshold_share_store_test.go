// Quantaureum Node source, version 1.0.0.
package node

import (
	"crypto/rand"
	"crypto/sha3"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

func tdilithium3ComponentsEqual(a, b []dilithium3v1.RSSComponent) bool {
	return slices.Equal(a, b)
}

func TestThresholdShareStoreProtocolPaths(t *testing.T) {
	base := filepath.Join(t.TempDir(), "shares.enc")
	paths, err := newThresholdProtocolPaths(base, protocol.ThresholdProtocolDilithium3V1, 7, 7, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(paths.Share, filepath.Join("dilithium3-v1", "generations", "7", "committees", "7", "shares", "3.enc")) {
		t.Fatalf("share path = %s", paths.Share)
	}
	if !strings.HasSuffix(paths.Active, filepath.Join("dilithium3-v1", "active.enc")) {
		t.Fatalf("active path = %s", paths.Active)
	}
	if !strings.HasSuffix(paths.LedgerHead, filepath.Join("dilithium3-v1", "ledger", "head.enc")) {
		t.Fatalf("ledger path = %s", paths.LedgerHead)
	}
	if !strings.HasSuffix(paths.CandidateHead, filepath.Join("dilithium3-v1", "ledger", "candidate.enc")) {
		t.Fatalf("candidate head path = %s", paths.CandidateHead)
	}
	if strings.Contains(paths.Share, "tmldsa") {
		t.Fatal("Dilithium path reused ML-DSA namespace")
	}
}

func TestThresholdShareStoreRoundTripAndRollbackProtection(t *testing.T) {
	base := filepath.Join(t.TempDir(), "shares.enc")
	store := newThresholdShareStore(base)
	password := []byte("DEVNET ONLY threshold share store password")
	share := testThresholdStoreShare(t, 2)
	if err := store.Store(share, password); err != nil {
		t.Fatalf("Store(): %v", err)
	}
	if _, err := store.LoadActive(password); !os.IsNotExist(err) {
		t.Fatalf("unactivated candidate was eligible for signing: %v", err)
	}
	loaded, err := store.LoadCandidate(share.Key.Generation, share.ParticipantID, password)
	if err != nil {
		t.Fatalf("LoadCandidate(): %v", err)
	}
	if loaded.Key.Generation != 2 || loaded.ParticipantID != share.ParticipantID || loaded.ParticipantPosition != share.ParticipantPosition || loaded.TranscriptDigest != share.TranscriptDigest {
		t.Fatal("loaded share mismatch")
	}
	if !tdilithium3ComponentsEqual(loaded.Components, share.Components) {
		t.Fatal("loaded RSS components mismatch")
	}
	loaded.Zeroize()

	rollback := testThresholdStoreShare(t, 1)
	if err := store.Store(rollback, password); err == nil {
		t.Fatal("generation rollback was accepted")
	}
	conflict := testThresholdStoreShare(t, 2)
	conflict.TranscriptDigest[0] ^= 1
	if err := store.Store(conflict, password); err == nil {
		t.Fatal("conflicting overwrite was accepted")
	}
	if _, err := store.LoadCandidate(share.Key.Generation, share.ParticipantID, []byte("wrong password")); err == nil {
		t.Fatal("wrong password was accepted")
	}

	paths, _ := newThresholdProtocolPaths(base, protocol.ThresholdProtocolDilithium3V1, 2, share.Committee.Version, share.ParticipantID)
	data, err := os.ReadFile(paths.CandidateHead)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(paths.CandidateHead, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadCandidate(share.Key.Generation, share.ParticipantID, password); err == nil {
		t.Fatal("corrupted candidate head was accepted")
	}
}

func TestThresholdShareStoreCandidateCrashRecovery(t *testing.T) {
	base := filepath.Join(t.TempDir(), "shares.enc")
	store := newThresholdShareStore(base)
	password := []byte("DEVNET ONLY threshold candidate crash recovery password")
	previous := testThresholdStoreShare(t, 2)
	if err := store.Store(previous, password); err != nil {
		t.Fatal(err)
	}

	upcoming := testThresholdStoreShare(t, 3)
	encoded, err := upcoming.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := thresholdEncryptPersistenceBlob(encoded, password)
	clear(encoded)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := newThresholdProtocolPaths(base, upcoming.Protocol, upcoming.Key.Generation, upcoming.Committee.Version, upcoming.ParticipantID)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteThresholdFile(paths.Share, encrypted); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadCandidate(upcoming.Key.Generation, upcoming.ParticipantID, password); err == nil {
		t.Fatal("candidate was loadable before its durable head")
	}
	if _, err := store.LoadActive(password); !os.IsNotExist(err) {
		t.Fatalf("partial candidate activated: %v", err)
	}

	restarted := newThresholdShareStore(base)
	if err := restarted.Store(upcoming, password); err != nil {
		t.Fatalf("idempotent recovery: %v", err)
	}
	loaded, err := restarted.LoadCandidate(upcoming.Key.Generation, upcoming.ParticipantID, password)
	if err != nil {
		t.Fatalf("recovered candidate: %v", err)
	}
	if !tdilithium3ComponentsEqual(loaded.Components, upcoming.Components) {
		t.Fatal("recovered candidate changed its components")
	}
	loaded.Zeroize()
	if _, err := restarted.LoadCandidate(previous.Key.Generation, previous.ParticipantID, password); err == nil {
		t.Fatal("superseded candidate was still loadable")
	}
	if _, err := restarted.LoadActive(password); !os.IsNotExist(err) {
		t.Fatalf("recovered candidate activated without certificate: %v", err)
	}
}

func TestThresholdShareStoreRequiresCertificateAtEpoch(t *testing.T) {
	base := filepath.Join(t.TempDir(), "shares.enc")
	store := newThresholdShareStore(base)
	password := []byte("DEVNET ONLY threshold activation password")
	share := testThresholdStoreShare(t, 2)
	if err := store.Store(share, password); err != nil {
		t.Fatal(err)
	}
	certificate, sessionDigest, verifier, bindings := testThresholdActivationCertificate(t, share)
	if err := store.ActivateCandidate(certificate, sessionDigest, share.ActivationEpoch-1, verifier, bindings, password); err == nil {
		t.Fatal("candidate activated before epoch boundary")
	}
	if _, err := store.LoadActiveAtEpoch(share.ActivationEpoch, verifier, password); !os.IsNotExist(err) {
		t.Fatalf("early activation left an active share: %v", err)
	}
	if err := store.ActivateCandidate(certificate, sessionDigest, share.ActivationEpoch, nil, bindings, password); err == nil {
		t.Fatal("candidate activated without signature verification")
	}
	if err := store.ActivateCandidate(certificate, sessionDigest, share.ActivationEpoch, verifier, bindings, password); err != nil {
		t.Fatalf("exact-epoch activation: %v", err)
	}
	if _, err := store.LoadActiveAtEpoch(share.ActivationEpoch-1, verifier, password); err == nil {
		t.Fatal("active share loaded before its activation epoch")
	}
	if _, err := store.LoadActiveAtEpoch(share.ActivationEpoch, nil, password); err == nil {
		t.Fatal("active share loaded without identity verifier")
	}
	restarted := newThresholdShareStore(base)
	loaded, err := restarted.LoadActiveAtEpoch(share.ActivationEpoch, verifier, password)
	if err != nil {
		t.Fatalf("load activated share after restart: %v", err)
	}
	if !tdilithium3ComponentsEqual(loaded.Components, share.Components) {
		t.Fatal("activated share components changed")
	}
	loaded.Zeroize()
	if err := restarted.ActivateCandidate(certificate, sessionDigest, share.ActivationEpoch, verifier, bindings, password); err != nil {
		t.Fatalf("idempotent activation: %v", err)
	}
	paths, err := newThresholdProtocolPaths(base, share.Protocol, share.Key.Generation, share.Committee.Version, share.ParticipantID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(paths.ActivationCertificate)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(paths.ActivationCertificate, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.LoadActiveAtEpoch(share.ActivationEpoch, verifier, password); err == nil {
		t.Fatal("corrupt activation certificate did not fail closed")
	}
}

func TestThresholdActivationRecoversInterruptedDurableWrites(t *testing.T) {
	base := filepath.Join(t.TempDir(), "shares.enc")
	store := newThresholdShareStore(base)
	password := []byte("DEVNET ONLY interrupted threshold activation password")
	first := testThresholdStoreShare(t, 2)
	if err := store.Store(first, password); err != nil {
		t.Fatal(err)
	}
	firstCertificate, firstSession, firstVerifier, firstBindings := testThresholdActivationCertificate(t, first)
	paths, err := newThresholdProtocolPaths(base, first.Protocol, first.Key.Generation, first.Committee.Version, first.ParticipantID)
	if err != nil {
		t.Fatal(err)
	}
	encodedCertificate, err := encodeThresholdActivationCertificate(firstCertificate)
	if err != nil {
		t.Fatal(err)
	}
	encryptedCertificate, err := thresholdEncryptPersistenceBlob(encodedCertificate, password)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteThresholdFile(paths.ActivationCertificate, encryptedCertificate); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadActiveAtEpoch(first.ActivationEpoch, firstVerifier, password); !os.IsNotExist(err) {
		t.Fatalf("certificate without active share was loadable: %v", err)
	}
	if err := store.ActivateCandidate(firstCertificate, firstSession, first.ActivationEpoch, firstVerifier, firstBindings, password); err != nil {
		t.Fatalf("resume after certificate write: %v", err)
	}

	second := testThresholdStoreShare(t, 3)
	if err := store.Store(second, password); err != nil {
		t.Fatal(err)
	}
	secondCertificate, secondSession, secondVerifier, secondBindings := testThresholdActivationCertificate(t, second)
	secondEncoding, err := encodeThresholdActivationCertificate(secondCertificate)
	if err != nil {
		t.Fatal(err)
	}
	secondEncryptedCertificate, err := thresholdEncryptPersistenceBlob(secondEncoding, password)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteThresholdFile(paths.ActivationCertificate, secondEncryptedCertificate); err != nil {
		t.Fatal(err)
	}
	secondCandidate, exists, err := loadThresholdPlaintext(paths.CandidateHead, password)
	if err != nil || !exists {
		t.Fatalf("load second candidate head: found=%v err=%v", exists, err)
	}
	encryptedActive, err := thresholdEncryptPersistenceBlob(secondCandidate, password)
	clear(secondCandidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteThresholdFile(paths.Active, encryptedActive); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadActiveAtEpoch(second.ActivationEpoch, secondVerifier, password); err == nil {
		t.Fatal("active share without matching ledger was loadable")
	}
	if err := store.ActivateCandidate(secondCertificate, secondSession, second.ActivationEpoch, secondVerifier, secondBindings, password); err != nil {
		t.Fatalf("resume after active write: %v", err)
	}
	restarted := newThresholdShareStore(base)
	loaded, err := restarted.LoadActiveAtEpoch(second.ActivationEpoch, secondVerifier, password)
	if err != nil {
		t.Fatalf("load after interrupted rotation recovery: %v", err)
	}
	if loaded.Key.Generation != second.Key.Generation || !tdilithium3ComponentsEqual(loaded.Components, second.Components) {
		t.Fatal("interrupted rotation recovered the wrong share")
	}
	loaded.Zeroize()
	if _, err := restarted.LoadActive(password); err == nil {
		t.Fatal("unverified active loader bypassed the epoch and certificate")
	}
}

// testThresholdStoreShareWithCommittee is testThresholdStoreShare generalized
// over the committee: the share's identity fields and RSS components are
// rebuilt for the given committee membership so the result stays
// Validate()-clean under a renumbered participant.
func testThresholdStoreShareWithCommittee(t *testing.T, generation uint64, participantID uint32, participants []uint32) *dilithium3v1.LocalShare {
	t.Helper()
	share := testThresholdStoreShare(t, generation)
	share.Committee.Participants = append([]uint32(nil), participants...)
	share.Committee.Threshold = protocol.Dilithium3V1ThresholdFor(uint32(len(participants)))
	position := -1
	for index, id := range participants {
		if id == participantID {
			position = index
			break
		}
	}
	if position < 0 {
		t.Fatalf("participant %d is not in committee %v", participantID, participants)
	}
	share.ParticipantID = participantID
	share.ParticipantPosition = uint8(position)
	groups, err := dilithium3v1.GroupsForPositionN(uint8(position), len(participants))
	if err != nil {
		t.Fatal(err)
	}
	share.Components = make([]dilithium3v1.RSSComponent, len(groups))
	for index, group := range groups {
		dealer, err := group.Leader(uint8(index % 3))
		if err != nil {
			t.Fatal(err)
		}
		coefficient := dilithium3v1.Coefficient(generation + uint64(index) + 1)
		share.Components[index] = dilithium3v1.RSSComponent{
			GroupMask:          group,
			DealerPosition:     dealer,
			ContributionDigest: [32]byte{byte(generation), byte(index + 1), byte(group)},
			Multiplicity:       1,
		}
		share.Components[index].S1[0][0] = coefficient
		share.Components[index].S2[0][0] = dilithium3v1.Q - coefficient
	}
	if err := share.Validate(); err != nil {
		t.Fatalf("fixture share is not valid: %v", err)
	}
	return share
}

// TestThresholdShareStoreRenumbersParticipantOnCommitteeChurn pins the R77
// rule: participant ids are roster-position-derived, so a membership change
// in front of a survivor in the canonical order shifts its numeric id. Two
// admissible renumberings must both stage: a fresh-key ceremony (generation
// increase) and a same-key rotation (same generation, committee version bump,
// unchanged group key). Same-version conflicts and in-generation key changes
// must still fail closed.
func TestThresholdShareStoreRenumbersParticipantOnCommitteeChurn(t *testing.T) {
	password := []byte("DEVNET ONLY renumbered rotation password")

	t.Run("fresh-key rekey accepts a renumbered participant", func(t *testing.T) {
		store := newThresholdShareStore(filepath.Join(t.TempDir(), "shares.enc"))
		current := testThresholdStoreShare(t, 2)
		if err := store.Store(current, password); err != nil {
			t.Fatal(err)
		}
		// A seventh validator joined in front of this node's roster position:
		// id 3 -> 4 under the seven-member committee.
		rekeyed := testThresholdStoreShareWithCommittee(t, 3, 4, []uint32{1, 2, 3, 4, 5, 6, 7})
		rekeyed.ActivationEpoch = current.ActivationEpoch + 1
		if err := store.Store(rekeyed, password); err != nil {
			t.Fatalf("fresh-key rekey with a renumbered participant was refused: %v", err)
		}
	})

	t.Run("same-key rotation accepts a renumbered participant", func(t *testing.T) {
		store := newThresholdShareStore(filepath.Join(t.TempDir(), "shares.enc"))
		// Seven-member committee; this node is id 4 (position 3).
		current := testThresholdStoreShareWithCommittee(t, 2, 4, []uint32{1, 2, 3, 4, 5, 6, 7})
		if err := store.Store(current, password); err != nil {
			t.Fatal(err)
		}
		// Participant 2 left; this node renumbers 4 -> 3 in the six-member
		// rotated committee, same generation, version bump, same group key.
		rotated := testThresholdStoreShareWithCommittee(t, current.Key.Generation, 3, []uint32{1, 3, 4, 5, 6, 7})
		rotated.Committee.Version = current.Committee.Version + 1
		rotated.ActivationEpoch = current.ActivationEpoch + 1
		rotated.TranscriptDigest = current.TranscriptDigest
		if err := store.Store(rotated, password); err != nil {
			t.Fatalf("same-key rotation with a renumbered participant was refused: %v", err)
		}
		loaded, err := store.LoadCandidate(rotated.Key.Generation, rotated.ParticipantID, password)
		if err != nil {
			t.Fatalf("load renumbered rotated candidate: %v", err)
		}
		if loaded.Committee.Version != rotated.Committee.Version || loaded.Key.Generation != current.Key.Generation {
			t.Fatal("rotated candidate changed the key identity")
		}
		loaded.Zeroize()
	})

	t.Run("in-generation guards still refuse conflicts and key changes", func(t *testing.T) {
		store := newThresholdShareStore(filepath.Join(t.TempDir(), "shares.enc"))
		current := testThresholdStoreShare(t, 2)
		if err := store.Store(current, password); err != nil {
			t.Fatal(err)
		}
		conflict := current.Clone()
		conflict.TranscriptDigest[0] ^= 1
		if err := store.Store(conflict, password); err == nil {
			t.Fatal("same-version conflicting write was accepted")
		}
		renumberedConflict := testThresholdStoreShareWithCommittee(t, current.Key.Generation, 4, []uint32{1, 2, 3, 4, 5, 6, 7})
		if err := store.Store(renumberedConflict, password); err == nil {
			t.Fatal("same-version renumbered write was accepted")
		}
		keyChange := current.Clone()
		keyChange.Committee.Version++
		keyChange.Key.PublicKey[0] ^= 1
		if err := store.Store(keyChange, password); err == nil {
			t.Fatal("in-generation group key change was accepted")
		}
		generationRollback := current.Clone()
		generationRollback.Key.Generation = 1
		if err := store.Store(generationRollback, password); err == nil {
			t.Fatal("generation rollback was accepted")
		}
	})
}

func TestThresholdShareStoreStagesSameKeyCommitteeRotation(t *testing.T) {
	base := filepath.Join(t.TempDir(), "shares.enc")
	store := newThresholdShareStore(base)
	password := []byte("DEVNET ONLY same-key committee rotation password")
	current := testThresholdStoreShare(t, 2)
	if err := store.Store(current, password); err != nil {
		t.Fatal(err)
	}
	currentCertificate, currentSession, currentVerifier, currentBindings := testThresholdActivationCertificate(t, current)
	if err := store.ActivateCandidate(currentCertificate, currentSession, current.ActivationEpoch, currentVerifier, currentBindings, password); err != nil {
		t.Fatal(err)
	}

	next := current.Clone()
	next.Committee.Version++
	next.Committee.Participants[5] = 7
	next.ActivationEpoch++
	next.TranscriptDigest[0]++
	if err := store.Store(next, password); err != nil {
		t.Fatalf("stage same-key candidate: %v", err)
	}
	oldActive, err := store.LoadActiveAtEpoch(current.ActivationEpoch, currentVerifier, password)
	if err != nil {
		t.Fatalf("staging replaced active share: %v", err)
	}
	if oldActive.Committee.Version != current.Committee.Version {
		t.Fatal("candidate activated before the new epoch")
	}
	oldActive.Zeroize()
	loaded, err := store.LoadCandidate(next.Key.Generation, next.ParticipantID, password)
	if err != nil {
		t.Fatalf("load staged same-key committee: %v", err)
	}
	if loaded.Committee.Version != next.Committee.Version || loaded.Key.Generation != current.Key.Generation || loaded.TranscriptDigest != next.TranscriptDigest {
		t.Fatal("candidate changed the public key generation or committee identity")
	}
	loaded.Zeroize()
	if err := store.Store(current, password); err == nil {
		t.Fatal("old committee candidate rollback was accepted")
	}
	otherKey := next.Clone()
	otherKey.Committee.Version++
	otherKey.ActivationEpoch++
	otherKey.Key.PublicKey[0] ^= 1
	if err := store.Store(otherKey, password); err == nil {
		t.Fatal("same generation candidate changed the group public key")
	}
	certificate, session, verifier, nextBindings := testThresholdActivationCertificate(t, next)
	historicalVerifier := func(participantID uint32, message, signature []byte) bool {
		return currentVerifier(participantID, message, signature) || verifier(participantID, message, signature)
	}
	if err := store.ActivateCandidate(certificate, session, next.ActivationEpoch, historicalVerifier, nextBindings, password); err != nil {
		t.Fatalf("activate same-key committee: %v", err)
	}
	rotated, err := store.LoadActiveAtEpoch(next.ActivationEpoch, verifier, password)
	if err != nil {
		t.Fatalf("load rotated committee: %v", err)
	}
	if rotated.Committee.Version != next.Committee.Version || rotated.Key.Generation != current.Key.Generation || rotated.TranscriptDigest != next.TranscriptDigest {
		t.Fatal("rotated active share identity mismatch")
	}
	rotated.Zeroize()
}

func testThresholdActivationCertificate(t *testing.T, share *dilithium3v1.LocalShare) (dilithium3v1.DKGActivationCertificate, [32]byte, dilithium3v1.DKGIdentityVerifier, []dilithium3v1.DKGIdentityBinding) {
	t.Helper()
	sessionDigest := sha3.Sum256([]byte("DEVNET ONLY threshold activation session"))
	encoded, err := share.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	localDigest := sha3.Sum256(encoded)
	clear(encoded)
	publicKeys := make(map[uint32]*mode3.PublicKey, 6)
	certificate := dilithium3v1.DKGActivationCertificate{Acknowledgements: make([]dilithium3v1.DKGActivationAcknowledgement, 6)}
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
	// certificate was verified under; the test helper hands the caller the same
	// material so production write paths can OPT to store exactly what passed.
	bindings := make([]dilithium3v1.DKGIdentityBinding, 0, len(publicKeys))
	for _, participantID := range share.Committee.Participants {
		publicKey := publicKeys[participantID]
		bindings = append(bindings, dilithium3v1.DKGIdentityBinding{
			ParticipantID:    participantID,
			ValidatorAddress: types.AddressFromPublicKey(publicKey.Bytes()),
			PublicKey:        publicKey.Bytes(),
		})
	}
	return certificate, sessionDigest, verifier, bindings
}

func testThresholdStoreShare(t *testing.T, generation uint64) *dilithium3v1.LocalShare {
	t.Helper()
	var seed [mode3.SeedSize]byte
	seed[0] = 9
	publicKey, _ := mode3.NewKeyFromSeed(&seed)
	share := &dilithium3v1.LocalShare{
		Protocol:            protocol.ThresholdProtocolDilithium3V1,
		Key:                 protocol.ThresholdKeyID{Algorithm: qcrypto.SignatureAlgorithmDilithium3Legacy, Generation: generation, PublicKey: publicKey.Bytes()},
		Committee:           protocol.CommitteeID{Version: generation, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 6}},
		ParticipantID:       3,
		ParticipantPosition: 2,
		ActivationEpoch:     10 + generation,
		TranscriptDigest:    [32]byte{byte(generation), 2, 3},
		Rho:                 [32]byte{4, 5, 6},
	}
	groups, err := dilithium3v1.GroupsForPosition(share.ParticipantPosition)
	if err != nil {
		t.Fatal(err)
	}
	share.Components = make([]dilithium3v1.RSSComponent, len(groups))
	for index, group := range groups {
		dealer, err := group.Leader(uint8(index % 3))
		if err != nil {
			t.Fatal(err)
		}
		coefficient := dilithium3v1.Coefficient(generation + uint64(index) + 1)
		share.Components[index] = dilithium3v1.RSSComponent{
			GroupMask:          group,
			DealerPosition:     dealer,
			ContributionDigest: [32]byte{byte(generation), byte(index + 1), byte(group)},
			Multiplicity:       1,
		}
		share.Components[index].S1[0][0] = coefficient
		share.Components[index].S2[0][0] = dilithium3v1.Q - coefficient
	}
	return share
}

// TestThresholdActivationIdempotentAcrossRenumberedCommittee is the
// rotation-era durable-identity regression: the same already-persisted
// certificate must stay idempotent even when the caller hands a verifier built
// over a DIFFERENT id map (whoever a reshare renumbered the survivors onto),
// and re-activating it must repair any durable-write trilogy that was cut
// mid-flight. The previous signature-reverification step refused exactly that
// situation because the stored pid set no longer matched a derived current
// view.
func TestThresholdActivationIdempotentAcrossRenumberedCommittee(t *testing.T) {
	base := filepath.Join(t.TempDir(), "shares.enc")
	store := newThresholdShareStore(base)
	password := []byte("DEVNET ONLY rotation-tolerant activation password")
	share := testThresholdStoreShare(t, 2)
	if err := store.Store(share, password); err != nil {
		t.Fatal(err)
	}
	certificate, session, verifier, bindings := testThresholdActivationCertificate(t, share)
	if err := store.ActivateCandidate(certificate, session, share.ActivationEpoch, verifier, bindings, password); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadActiveAtEpoch(share.ActivationEpoch, verifier, password)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	loaded.Zeroize()

	// Simulate the reshare-day picture: the caller's verifier is rebuilt over
	// the renumbered pid map — pid identities point at keys that differ from
	// every recorded one, exactly what the rotation's pid-preservation produces.
	foreignBindings := make([]dilithium3v1.DKGIdentityBinding, 0, len(bindings))
	for _, binding := range bindings {
		foreign, _, err := mode3.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		foreignBindings = append(foreignBindings, dilithium3v1.DKGIdentityBinding{
			ParticipantID:    binding.ParticipantID,
			ValidatorAddress: binding.ValidatorAddress,
			PublicKey:        foreign.Bytes(),
		})
	}
	foreignVerifier := func(participantID uint32, message, signature []byte) bool {
		_ = participantID
		_ = message
		_ = signature
		return false
	}
	if err := store.ActivateCandidate(certificate, session, share.ActivationEpoch, foreignVerifier, foreignBindings, password); err != nil {
		t.Fatalf("idempotent re-delivery must not be re-verified by anyone else's map: %v", err)
	}
	// Simulate the cut-mid-flight crash the durability test contract covers:
	// the certificate write survives, the ledger-head write did not land.
	paths, err := newThresholdProtocolPaths(base, share.Protocol, share.Key.Generation, share.Committee.Version, share.ParticipantID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths.LedgerHead); err != nil {
		t.Fatal(err)
	}
	// The same-certificate adoption call must repair the cut durable triple:
	// the digest of an already-persisted record is exactly the safe short-path.
	if err := store.ActivateCandidate(certificate, session, share.ActivationEpoch, verifier, bindings, password); err != nil {
		t.Fatalf("resume-side repair: %v", err)
	}
	reopened := newThresholdShareStore(base)
	still, err := reopened.LoadActiveAtEpoch(share.ActivationEpoch, verifier, password)
	if err != nil {
		t.Fatalf("ledger repair never fixed an interrupted activation: %v", err)
	}
	if still.Key.Generation != share.Key.Generation {
		t.Fatal("ledger repair served the wrong generation")
	}
	still.Zeroize()
}
