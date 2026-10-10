// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

const (
	thresholdActivationMagic   = "QTD3ACT1"
	thresholdActivationVersion = 1
	// thresholdActivationVersionV2 records carry the pid->identity-key binding
	// the certificate was verified under at write time. Rotation committees
	// keep old participant ids while later roster-derived committees renumber,
	// so a v1 record cannot be re-verified via a currently-derived verifier —
	// the bindings must be self-describing.
	thresholdActivationVersionV2 = 2
	thresholdActivationMaxSize   = 256 << 10
)

type thresholdActivationBindingJSON struct {
	ParticipantID    uint32 `json:"participant_id"`
	ValidatorAddress string `json:"validator_address"`
	PublicKey        string `json:"public_key"`
}

type thresholdActivationRecord struct {
	Version     int                                   `json:"version"`
	Certificate dilithium3v1.DKGActivationCertificate `json:"certificate"`
	// v2 only: the pid -> identity binding the certificate was verified under
	// when activated. Absent in v1.
	Bindings []thresholdActivationBindingJSON `json:"bindings,omitempty"`
}

// encodeThresholdActivationCertificate marshal the certificate alone (v1). The
// writer that has the verifier's bindings in hand must use
// encodeThresholdActivationRecord (v2) so the record is self-describing.
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

// encodeThresholdActivationRecord marshal certificate + identity bindings (v2).
func encodeThresholdActivationRecord(certificate dilithium3v1.DKGActivationCertificate, bindings []dilithium3v1.DKGIdentityBinding) ([]byte, error) {
	if _, err := certificate.CanonicalDigest(); err != nil {
		return nil, err
	}
	if len(bindings) == 0 {
		return nil, fmt.Errorf("v2 threshold activation record requires identity bindings")
	}
	record := thresholdActivationRecord{Version: thresholdActivationVersionV2, Certificate: certificate}
	for _, binding := range bindings {
		record.Bindings = append(record.Bindings, thresholdActivationBindingJSON{
			ParticipantID:    binding.ParticipantID,
			ValidatorAddress: hex.EncodeToString(binding.ValidatorAddress[:]),
			PublicKey:        hex.EncodeToString(binding.PublicKey),
		})
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if len(payload)+len(thresholdActivationMagic) > thresholdActivationMaxSize {
		return nil, fmt.Errorf("threshold activation certificate exceeds size limit")
	}
	return append([]byte(thresholdActivationMagic), payload...), nil
}

// thresholdActivationRecordFrom decodes a record (v1 or v2) and returns the
// certificate plus the recorded identity bindings when present.
func thresholdActivationRecordFrom(encoded []byte) (dilithium3v1.DKGActivationCertificate, []dilithium3v1.DKGIdentityBinding, error) {
	if len(encoded) > thresholdActivationMaxSize || !bytes.HasPrefix(encoded, []byte(thresholdActivationMagic)) {
		return dilithium3v1.DKGActivationCertificate{}, nil, fmt.Errorf("invalid threshold activation certificate encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded[len(thresholdActivationMagic):]))
	decoder.DisallowUnknownFields()
	var record thresholdActivationRecord
	if err := decoder.Decode(&record); err != nil {
		return dilithium3v1.DKGActivationCertificate{}, nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return dilithium3v1.DKGActivationCertificate{}, nil, fmt.Errorf("trailing threshold activation certificate data")
	}
	if record.Version != thresholdActivationVersion && record.Version != thresholdActivationVersionV2 {
		return dilithium3v1.DKGActivationCertificate{}, nil, fmt.Errorf("unsupported threshold activation certificate version")
	}
	if _, err := record.Certificate.CanonicalDigest(); err != nil {
		return dilithium3v1.DKGActivationCertificate{}, nil, err
	}
	if record.Version == thresholdActivationVersionV2 && len(record.Bindings) == 0 {
		return dilithium3v1.DKGActivationCertificate{}, nil, fmt.Errorf("v2 threshold activation record carries no bindings")
	}
	var bindings []dilithium3v1.DKGIdentityBinding
	if record.Version == thresholdActivationVersionV2 {
		bindings = make([]dilithium3v1.DKGIdentityBinding, 0, len(record.Bindings))
		for _, raw := range record.Bindings {
			publicKey, err := hex.DecodeString(raw.PublicKey)
			if err != nil || len(publicKey) != qcrypto.Dilithium3PublicKeySize {
				return dilithium3v1.DKGActivationCertificate{}, nil, fmt.Errorf("threshold activation record has a malformed binding key")
			}
			addressBytes, err := hex.DecodeString(raw.ValidatorAddress)
			if err != nil || len(addressBytes) != len(types.Address{}) {
				return dilithium3v1.DKGActivationCertificate{}, nil, fmt.Errorf("threshold activation record has a malformed binding address")
			}
			var address types.Address
			copy(address[:], addressBytes)
			bindings = append(bindings, dilithium3v1.DKGIdentityBinding{
				ParticipantID:    raw.ParticipantID,
				ValidatorAddress: [20]byte(address),
				PublicKey:        publicKey,
			})
		}
	}
	return record.Certificate, bindings, nil
}

func decodeThresholdActivationCertificate(encoded []byte) (dilithium3v1.DKGActivationCertificate, error) {
	certificate, _, err := thresholdActivationRecordFrom(encoded)
	return certificate, err
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
	bindings []dilithium3v1.DKGIdentityBinding,
	password []byte,
) error {
	if store == nil || store.basePath == "" || len(password) == 0 || sessionDigest == ([32]byte{}) || verifier == nil {
		return fmt.Errorf("threshold activation is not configured")
	}
	// The bindings argument pins the pid->identity-key pairing this certificate
	// verified under. It is persisted with the record (v2) so a later session
	// can verify the certificate against the recorded bindings instead of a
	// currently-derived verifier — a remove rotation keeps the old participant
	// ids while a later session re-derives roster-position ids, and only the
	// recorded bindings distinguish the two views correctly.
	if len(bindings) == 0 {
		return fmt.Errorf("threshold activation requires the session identity bindings")
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
	defer unlockStoreLockfile(lock)
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

	var encodedCertificate []byte
	encodedCertificate, err = encodeThresholdActivationRecord(certificate, bindings)
	if err != nil {
		return err
	}

	// Idempotence precedes every verifier call: the already-persisted record's
	// canonical digest is the proof of content; the caller's current-view
	// verifier is irrelevant to a re-delivery — and after a rotation that view
	// of the pid space cannot see the preserved ids the record was signed under.
	previousCertificate, _, certificateExists, err := loadThresholdActivationCertificate(paths.ActivationCertificate, password)
	if err != nil {
		return err
	}
	if certificateExists {
		previousDigest, prevErr := previousCertificate.CanonicalDigest()
		incomingDigest, incErr := certificate.CanonicalDigest()
		if prevErr != nil || incErr != nil {
			return fmt.Errorf("threshold activation certificate digests: %v / %v", prevErr, incErr)
		}
		if previousDigest == incomingDigest {
			// Equal content: complete the durable write if it was interrupted,
			// or no-op. Verifier checks are unnecessary noise here.
			if activeExists && ledgerExists && bytes.Equal(active, candidateHead) && bytes.Equal(ledger, candidateHead) {
				return nil
			}
			goto writeDurable
		}
		if len(certificate.Acknowledgements) > 0 && len(previousCertificate.Acknowledgements) > 0 {
			nodeLog.Warn("R77-DIAG activation stored-cert present: stored(ackEpoch=%d session=%x nacks=%d pub=%x) vs incoming(session=%x nacks=%d)",
				previousCertificate.Acknowledgements[0].ActivationEpoch,
				previousCertificate.Acknowledgements[0].SessionDigest[:4], len(previousCertificate.Acknowledgements),
				previousCertificate.Acknowledgements[0].Key.PublicKey[:4],
				certificate.Acknowledgements[0].SessionDigest[:4], len(certificate.Acknowledgements))
		}
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
	if err := certificate.Verify(verifier); err != nil {
		diagnoseTDilithium3ActivationCertificate("verify-failed", certificate, nil, sessionDigest, verifier)
		return err
	}
	if err := certificate.VerifyCandidate(stored, sessionDigest, verifier); err != nil {
		diagnoseTDilithium3ActivationCertificate("verifyCandidate-failed", certificate, stored, sessionDigest, verifier)
		return err
	}
	if ledgerExists {
		previous, err := dilithium3v1.UnmarshalLocalShare(ledger)
		if err != nil {
			return err
		}
		defer previous.Zeroize()
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
writeDurable:
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
	defer unlockStoreLockfile(lock)
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
	certificate, storedBindings, exists, err := loadThresholdActivationCertificate(paths.ActivationCertificate, password)
	if err != nil || !exists {
		share.Zeroize()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("threshold activation certificate is missing")
	}
	// Rotation committees keep the previous participant ids across a removal
	// while every fresh derivation renumbers to roster positions; when the
	// record carries its write-time bindings (v2), verify against those.
	// Caller-passed verifiers remain the fallback for v1 records.
	if len(storedBindings) > 0 {
		recorded := make(map[uint32]*qcrypto.PublicKey, len(storedBindings))
		for _, binding := range storedBindings {
			key, err := qcrypto.PublicKeyFromBytes(binding.PublicKey)
			if err != nil {
				share.Zeroize()
				return nil, fmt.Errorf("stored activation binding has an unusable identity key: %w", err)
			}
			recorded[binding.ParticipantID] = key
		}
		verifier = func(participantID uint32, message, signature []byte) bool {
			key, found := recorded[participantID]
			return found && qcrypto.Verify(key, message, signature)
		}
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
// CandidateSharePublicIdentity reports the installed candidate share's
// activation epoch, group public key, threshold and participant ID without
// exposing secret bytes — the probe the offline-ceremony adoption driver runs
// before committing to an exchange. A missing candidate is os.ErrNotExist;
// the authoritative load still runs LoadCandidate/ActivateCandidate, which
// validate the full share, so a forged candidate head fails closed there.
func (store *thresholdShareStore) CandidateSharePublicIdentity(password []byte) (uint64, []byte, uint32, uint32, error) {
	if store == nil || store.basePath == "" || len(password) == 0 {
		return 0, nil, 0, 0, fmt.Errorf("threshold share store or password is not configured")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	lock, err := store.lockFile()
	if err != nil {
		return 0, nil, 0, 0, err
	}
	defer unlockStoreLockfile(lock)
	paths, err := newThresholdProtocolPaths(store.basePath, protocol.ThresholdProtocolDilithium3V1, 1, 1, 1)
	if err != nil {
		return 0, nil, 0, 0, err
	}
	candidate, exists, err := loadThresholdPlaintext(paths.CandidateHead, password)
	if err != nil {
		return 0, nil, 0, 0, err
	}
	if !exists {
		return 0, nil, 0, 0, os.ErrNotExist
	}
	defer tss.SecureZero(candidate)
	share, err := dilithium3v1.UnmarshalLocalShare(candidate)
	if err != nil {
		return 0, nil, 0, 0, err
	}
	epoch := share.ActivationEpoch
	publicKey := append([]byte(nil), share.Key.PublicKey...)
	threshold := share.Committee.Threshold
	participantID := share.ParticipantID
	share.Zeroize()
	if epoch == 0 || len(publicKey) == 0 {
		return 0, nil, 0, 0, fmt.Errorf("threshold candidate has no activation epoch or group key")
	}
	return epoch, publicKey, threshold, participantID, nil
}

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
	defer unlockStoreLockfile(lock)
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

func loadThresholdActivationCertificate(path string, password []byte) (dilithium3v1.DKGActivationCertificate, []dilithium3v1.DKGIdentityBinding, bool, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return dilithium3v1.DKGActivationCertificate{}, nil, false, nil
	}
	if err != nil {
		return dilithium3v1.DKGActivationCertificate{}, nil, false, err
	}
	if info.Size() > thresholdActivationMaxSize+256 {
		return dilithium3v1.DKGActivationCertificate{}, nil, false, fmt.Errorf("threshold activation certificate exceeds size limit")
	}
	plaintext, exists, err := loadThresholdPlaintext(path, password)
	if err != nil || !exists {
		return dilithium3v1.DKGActivationCertificate{}, nil, exists, err
	}
	defer tss.SecureZero(plaintext)
	certificate, bindings, err := thresholdActivationRecordFrom(plaintext)
	return certificate, bindings, true, err
}
