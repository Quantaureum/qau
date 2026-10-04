// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

const (
	thresholdActivationMagic   = "QTD3ACT1"
	thresholdActivationVersion = 1
	thresholdActivationMaxSize = 128 << 10
)

type thresholdActivationRecord struct {
	Version     int                                   `json:"version"`
	Certificate dilithium3v1.DKGActivationCertificate `json:"certificate"`
}

func encodeThresholdActivationCertificate(certificate dilithium3v1.DKGActivationCertificate) ([]byte, error) {
	if _, err := certificate.CanonicalDigest(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(thresholdActivationRecord{Version: thresholdActivationVersion, Certificate: certificate})
	if err != nil {
		return nil, err
	}
	if len(payload)+len(thresholdActivationMagic) > thresholdActivationMaxSize {
		return nil, fmt.Errorf("threshold activation certificate exceeds size limit")
	}
	return append([]byte(thresholdActivationMagic), payload...), nil
}

func decodeThresholdActivationCertificate(encoded []byte) (dilithium3v1.DKGActivationCertificate, error) {
	if len(encoded) > thresholdActivationMaxSize || !bytes.HasPrefix(encoded, []byte(thresholdActivationMagic)) {
		return dilithium3v1.DKGActivationCertificate{}, fmt.Errorf("invalid threshold activation certificate encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded[len(thresholdActivationMagic):]))
	decoder.DisallowUnknownFields()
	var record thresholdActivationRecord
	if err := decoder.Decode(&record); err != nil {
		return dilithium3v1.DKGActivationCertificate{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return dilithium3v1.DKGActivationCertificate{}, fmt.Errorf("trailing threshold activation certificate data")
	}
	if record.Version != thresholdActivationVersion {
		return dilithium3v1.DKGActivationCertificate{}, fmt.Errorf("unsupported threshold activation certificate version")
	}
	if _, err := record.Certificate.CanonicalDigest(); err != nil {
		return dilithium3v1.DKGActivationCertificate{}, err
	}
	return record.Certificate, nil
}

// R77-DIAG: break down a threshold-activation verification failure into the
// single byte-level check that actually fails. A committee-change JOIN leaves
// a straggler unable to adopt or self-commit a certificate, and the opaque
// "invalid Dilithium3 v1 DKG activation certificate" sentinel does not say
// which of (per-ack signature / position / participant id / activation epoch /
// transcript / key digest / committee digest / candidate digest) is broken;
// this logs each one so a devnet stall is attributed to one cause.
//
// `stored` is the on-disk candidate share ActivateCandidate verifies against;
// it is nil when the pure per-ack verification (certificate.Verify) is being
// diagnosed before the disk share is loaded.
func diagnoseTDilithium3ActivationCertificate(
	caller string,
	certificate dilithium3v1.DKGActivationCertificate,
	stored *dilithium3v1.LocalShare,
	sessionDigest [32]byte,
	verifier dilithium3v1.DKGIdentityVerifier,
) {
	// R77-DIAG: structural + ordering + signature view, logged unconditionally
	// (even when stored is nil on the verify-failed path) so a committee-change
	// JOIN that leaves a straggler unable to adopt a peer's certificate shows
	// exactly which check and which participant id diverges. A cert is only
	// admissible when it is internally consistent (each ack at index i carries
	// Committee.Participants[i]) AND every signature verifies against the
	// local roster-bound verifier.
	if len(certificate.Acknowledgements) > 0 {
		first := certificate.Acknowledgements[0]
		nodeLog.Warn("R77-DIAG activation [%s] nacks=%d threshold=%d nParticipants=%d storedNil=%v sessionDigest=%x certSession=%x",
			caller, len(certificate.Acknowledgements), int(first.Committee.Threshold), len(first.Committee.Participants), stored == nil, sessionDigest[:4], first.SessionDigest[:4])
		for i, ack := range certificate.Acknowledgements {
			var wantID uint32
			if i < len(first.Committee.Participants) {
				wantID = first.Committee.Participants[i]
			}
			sigOK := ack.Verify(verifier) == nil
			nodeLog.Warn("R77-DIAG activation [%s] ack[%d] gotID=%d wantID=%d orderingOK=%v sigOK=%v epoch=%d transcript=%x",
				caller, i, ack.ParticipantID, wantID, ack.ParticipantID == wantID, sigOK, ack.ActivationEpoch, ack.TranscriptDigest[:4])
		}
	}
	if stored == nil {
		return
	}
	if err := stored.Validate(); err != nil {
		nodeLog.Warn("R77-DIAG activation [%s] stored share.Validate: %v", caller, err)
		return
	}
	if int(stored.ParticipantPosition) >= len(certificate.Acknowledgements) {
		nodeLog.Warn("R77-DIAG activation [%s] stored.ParticipantPosition=%d out of range for %d acks",
			caller, stored.ParticipantPosition, len(certificate.Acknowledgements))
		return
	}
	ack := certificate.Acknowledgements[stored.ParticipantPosition]
	nodeLog.Warn("R77-DIAG activation [%s] stored(pos=%d id=%d epoch=%d transcript=%x pub=%x) ackAtPos(id=%d epoch=%d transcript=%x cand=%x session=%x)",
		caller,
		stored.ParticipantPosition, stored.ParticipantID, stored.ActivationEpoch, stored.TranscriptDigest[:4], stored.Key.PublicKey[:4],
		ack.ParticipantID, ack.ActivationEpoch, ack.TranscriptDigest[:4], ack.CandidateDigest[:4], sessionDigest[:4])
	if encoded, err := stored.MarshalBinary(); err == nil {
		digest := sha3.Sum256(encoded)
		ackKey, _ := ack.Key.CanonicalDigest()
		stKey, _ := stored.Key.CanonicalDigest()
		ackCommittee, _ := ack.Committee.CanonicalDigest()
		stCommittee, _ := stored.Committee.CanonicalDigest()
		nodeLog.Warn("R77-DIAG activation [%s] check: participantID=%v activationEpoch=%v transcript=%v candidateDigest=%v keyDigest=%v committeeDigest=%v sessionDigest=%v",
			caller,
			ack.ParticipantID == stored.ParticipantID,
			ack.ActivationEpoch == stored.ActivationEpoch,
			ack.TranscriptDigest == stored.TranscriptDigest,
			digest == ack.CandidateDigest,
			ackKey == stKey,
			ackCommittee == stCommittee,
			ack.SessionDigest == sessionDigest)
	}
}

func (store *thresholdShareStore) ActivateCandidate(
	certificate dilithium3v1.DKGActivationCertificate,
	sessionDigest [32]byte,
	currentEpoch uint64,
	verifier dilithium3v1.DKGIdentityVerifier,
	password []byte,
) error {
	if store == nil || store.basePath == "" || len(password) == 0 || sessionDigest == ([32]byte{}) || verifier == nil {
		return fmt.Errorf("threshold activation is not configured")
	}
	if err := certificate.Verify(verifier); err != nil {
		diagnoseTDilithium3ActivationCertificate("verify-failed", certificate, nil, sessionDigest, verifier)
		return err
	}
	first := certificate.Acknowledgements[0]
	if currentEpoch != first.ActivationEpoch || sessionDigest != first.SessionDigest {
		return fmt.Errorf("threshold activation is outside the certified epoch or session")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.lockFile()
	if err != nil {
		return err
	}
	defer lock.Close()
	paths, err := newThresholdProtocolPaths(store.basePath, protocol.ThresholdProtocolDilithium3V1, 1, 1, 1)
	if err != nil {
		return err
	}
	candidateHead, exists, err := loadThresholdPlaintext(paths.CandidateHead, password)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("threshold candidate head is missing")
	}
	defer tss.SecureZero(candidateHead)
	candidate, err := dilithium3v1.UnmarshalLocalShare(candidateHead)
	if err != nil {
		return err
	}
	defer candidate.Zeroize()
	stored, err := store.loadCandidateLocked(candidate.Key.Generation, candidate.ParticipantID, password)
	if err != nil {
		return err
	}
	defer stored.Zeroize()
	if err := certificate.VerifyCandidate(stored, sessionDigest, verifier); err != nil {
		diagnoseTDilithium3ActivationCertificate("verifyCandidate-failed", certificate, stored, sessionDigest, verifier)
		return err
	}
	paths, err = newThresholdProtocolPaths(store.basePath, candidate.Protocol, candidate.Key.Generation, candidate.Committee.Version, candidate.ParticipantID)
	if err != nil {
		return err
	}
	active, activeExists, err := loadThresholdPlaintext(paths.Active, password)
	if err != nil {
		return err
	}
	defer tss.SecureZero(active)
	ledger, ledgerExists, err := loadThresholdPlaintext(paths.LedgerHead, password)
	if err != nil {
		return err
	}
	defer tss.SecureZero(ledger)
	if ledgerExists {
		previous, err := dilithium3v1.UnmarshalLocalShare(ledger)
		if err != nil {
			return err
		}
		defer previous.Zeroize()
		// The participant id is not part of the identity check: R76/R77
		// committee churn renumbers surviving validators (roster-position ids),
		// so a legitimate rotation candidate can carry a new participant id.
		// What stays forbidden: generation or committee-version rollback, an
		// in-generation group-key change, and an equal-version byte conflict.
		if previous.Key.Generation > candidate.Key.Generation ||
			(previous.Key.Generation == candidate.Key.Generation &&
				(previous.Committee.Version > candidate.Committee.Version ||
					!bytes.Equal(previous.Key.PublicKey, candidate.Key.PublicKey) ||
					(previous.Committee.Version == candidate.Committee.Version && !bytes.Equal(ledger, candidateHead)))) {
			return fmt.Errorf("threshold activation generation rollback or conflict")
		}
	}
	if (activeExists && !ledgerExists && !bytes.Equal(active, candidateHead)) ||
		(!activeExists && ledgerExists) ||
		(activeExists && ledgerExists && !bytes.Equal(active, ledger) && !bytes.Equal(active, candidateHead)) {
		return fmt.Errorf("active threshold share and ledger are inconsistent")
	}

	encodedCertificate, err := encodeThresholdActivationCertificate(certificate)
	if err != nil {
		return err
	}
	previousCertificate, certificateExists, err := loadThresholdActivationCertificate(paths.ActivationCertificate, password)
	if err != nil {
		return err
	}
	if certificateExists {
		// R77-DIAG: a certificate is already persisted for this candidate path.
		// If it belongs to an earlier (stale) session the re-verification below
		// rejects the incoming adoption; compare the two up front so a devnet
		// JOIN stall names the divergence instead of returning a bare sentinel.
		if len(certificate.Acknowledgements) > 0 && len(previousCertificate.Acknowledgements) > 0 {
			nodeLog.Warn("R77-DIAG activation stored-cert present: stored(ackEpoch=%d session=%x nacks=%d pub=%x) vs incoming(session=%x nacks=%d)",
				previousCertificate.Acknowledgements[0].ActivationEpoch,
				previousCertificate.Acknowledgements[0].SessionDigest[:4], len(previousCertificate.Acknowledgements),
				previousCertificate.Acknowledgements[0].Key.PublicKey[:4],
				certificate.Acknowledgements[0].SessionDigest[:4], len(certificate.Acknowledgements))
		}
		// The stored certificate was verified against ITS OWN session when it
		// was written. Re-verifying it against the CURRENT roster-bound verifier
		// cannot survive committee churn: participant ids are roster-position-
		// derived (R76/R77), so after any membership change the old acks verify
		// only against the OLD committee's bindings — which the store does not
		// keep. Gate the re-verification on an unchanged committee; a churned
		// committee relies on the epoch-monotonicity and lineage checks below.
		sameCommittee := false
		if len(previousCertificate.Acknowledgements) > 0 && len(certificate.Acknowledgements) > 0 {
			previousCommitteeDigest, previousErr := previousCertificate.Acknowledgements[0].Committee.CanonicalDigest()
			incomingCommitteeDigest, incomingErr := certificate.Acknowledgements[0].Committee.CanonicalDigest()
			sameCommittee = previousErr == nil && incomingErr == nil && previousCommitteeDigest == incomingCommitteeDigest
		}
		if sameCommittee {
			if err := previousCertificate.Verify(verifier); err != nil {
				diagnoseTDilithium3ActivationCertificate("storedCert-verify-failed", previousCertificate, nil, previousCertificate.Acknowledgements[0].SessionDigest, verifier)
				return err
			}
		} else {
			nodeLog.Info("Dilithium3 v1 activation: stored certificate belongs to a previous committee; skipping signature re-verification (lineage checks below still apply)")
		}
		previousEncoding, err := encodeThresholdActivationCertificate(previousCertificate)
		if err != nil {
			return err
		}
		if !bytes.Equal(previousEncoding, encodedCertificate) {
			if previousCertificate.Acknowledgements[0].ActivationEpoch >= currentEpoch || !ledgerExists {
				return fmt.Errorf("conflicting threshold activation certificate")
			}
			if sameCommittee {
				previousShare, err := dilithium3v1.UnmarshalLocalShare(ledger)
				if err != nil {
					return err
				}
				previousErr := previousCertificate.VerifyCandidate(previousShare, previousCertificate.Acknowledgements[0].SessionDigest, verifier)
				if previousErr != nil {
					diagnoseTDilithium3ActivationCertificate("storedCert-candidate-failed", previousCertificate, previousShare, previousCertificate.Acknowledgements[0].SessionDigest, verifier)
				}
				previousShare.Zeroize()
				if previousErr != nil {
					return previousErr
				}
			}
		}
	}
	if certificateExists && activeExists && ledgerExists && bytes.Equal(active, candidateHead) && bytes.Equal(ledger, candidateHead) {
		return nil
	}
	encryptedCertificate, err := thresholdEncryptPersistenceBlob(encodedCertificate, password)
	if err != nil {
		return err
	}
	encryptedShare, err := thresholdEncryptPersistenceBlob(candidateHead, password)
	if err != nil {
		return err
	}
	if err := atomicWriteThresholdFile(paths.ActivationCertificate, encryptedCertificate); err != nil {
		return err
	}
	if err := atomicWriteThresholdFile(paths.Active, encryptedShare); err != nil {
		return err
	}
	return atomicWriteThresholdFile(paths.LedgerHead, encryptedShare)
}

func (store *thresholdShareStore) LoadActiveAtEpoch(currentEpoch uint64, verifier dilithium3v1.DKGIdentityVerifier, password []byte) (*dilithium3v1.LocalShare, error) {
	if store == nil || store.basePath == "" || len(password) == 0 || verifier == nil || currentEpoch == 0 {
		return nil, fmt.Errorf("threshold activation verifier, epoch, or store is not configured")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.lockFile()
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	paths, err := newThresholdProtocolPaths(store.basePath, protocol.ThresholdProtocolDilithium3V1, 1, 1, 1)
	if err != nil {
		return nil, err
	}
	active, exists, err := loadThresholdPlaintext(paths.Active, password)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, os.ErrNotExist
	}
	defer tss.SecureZero(active)
	ledger, exists, err := loadThresholdPlaintext(paths.LedgerHead, password)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("threshold activation ledger is missing")
	}
	defer tss.SecureZero(ledger)
	if !bytes.Equal(active, ledger) {
		return nil, fmt.Errorf("threshold activation ledger mismatch")
	}
	share, err := dilithium3v1.UnmarshalLocalShare(active)
	if err != nil {
		return nil, err
	}
	if currentEpoch < share.ActivationEpoch {
		share.Zeroize()
		return nil, fmt.Errorf("threshold share activation epoch is in the future")
	}
	certificate, exists, err := loadThresholdActivationCertificate(paths.ActivationCertificate, password)
	if err != nil || !exists {
		share.Zeroize()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("threshold activation certificate is missing")
	}
	if err := certificate.VerifyCandidate(share, certificate.Acknowledgements[0].SessionDigest, verifier); err != nil {
		share.Zeroize()
		return nil, err
	}
	return share, nil
}

// ActiveSharePublicIdentity reports the installed active share's activation
// epoch and group public key without a roster verifier. Callers that must
// derive the epoch's roster before they can build the identity verifier (the
// signing binding's assembly) or that only need the public binding (the
// finality surface registration) need this hint first; the authoritative load
// still runs LoadActiveAtEpoch with the roster verifier, which checks the
// activation certificate, so a forged or mismatched active share still fails
// closed there.
func (store *thresholdShareStore) ActiveSharePublicIdentity(password []byte) (uint64, []byte, uint32, error) {
	if store == nil || store.basePath == "" || len(password) == 0 {
		return 0, nil, 0, fmt.Errorf("threshold activation store or password is not configured")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.lockFile()
	if err != nil {
		return 0, nil, 0, err
	}
	defer lock.Close()
	paths, err := newThresholdProtocolPaths(store.basePath, protocol.ThresholdProtocolDilithium3V1, 1, 1, 1)
	if err != nil {
		return 0, nil, 0, err
	}
	active, exists, err := loadThresholdPlaintext(paths.Active, password)
	if err != nil {
		return 0, nil, 0, err
	}
	if !exists {
		return 0, nil, 0, os.ErrNotExist
	}
	defer tss.SecureZero(active)
	ledger, exists, err := loadThresholdPlaintext(paths.LedgerHead, password)
	if err != nil {
		return 0, nil, 0, err
	}
	if !exists {
		return 0, nil, 0, fmt.Errorf("threshold activation ledger is missing")
	}
	defer tss.SecureZero(ledger)
	if !bytes.Equal(active, ledger) {
		return 0, nil, 0, fmt.Errorf("threshold activation ledger mismatch")
	}
	share, err := dilithium3v1.UnmarshalLocalShare(active)
	if err != nil {
		return 0, nil, 0, err
	}
	epoch := share.ActivationEpoch
	publicKey := append([]byte(nil), share.Key.PublicKey...)
	share.Zeroize()
	if epoch == 0 || len(publicKey) == 0 {
		return 0, nil, 0, fmt.Errorf("threshold activation share has no activation epoch or group key")
	}
	return epoch, publicKey, share.Committee.Threshold, nil
}

func loadThresholdActivationCertificate(path string, password []byte) (dilithium3v1.DKGActivationCertificate, bool, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return dilithium3v1.DKGActivationCertificate{}, false, nil
	}
	if err != nil {
		return dilithium3v1.DKGActivationCertificate{}, false, err
	}
	if info.Size() > thresholdActivationMaxSize+256 {
		return dilithium3v1.DKGActivationCertificate{}, false, fmt.Errorf("threshold activation certificate exceeds size limit")
	}
	plaintext, exists, err := loadThresholdPlaintext(path, password)
	if err != nil || !exists {
		return dilithium3v1.DKGActivationCertificate{}, exists, err
	}
	defer tss.SecureZero(plaintext)
	certificate, err := decodeThresholdActivationCertificate(plaintext)
	return certificate, true, err
}
