// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
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
		if previous.ParticipantID != candidate.ParticipantID ||
			previous.Key.Generation > candidate.Key.Generation ||
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
		if err := previousCertificate.Verify(verifier); err != nil {
			return err
		}
		previousEncoding, err := encodeThresholdActivationCertificate(previousCertificate)
		if err != nil {
			return err
		}
		if !bytes.Equal(previousEncoding, encodedCertificate) {
			if previousCertificate.Acknowledgements[0].ActivationEpoch >= currentEpoch || !ledgerExists {
				return fmt.Errorf("conflicting threshold activation certificate")
			}
			previousShare, err := dilithium3v1.UnmarshalLocalShare(ledger)
			if err != nil {
				return err
			}
			previousErr := previousCertificate.VerifyCandidate(previousShare, previousCertificate.Acknowledgements[0].SessionDigest, verifier)
			previousShare.Zeroize()
			if previousErr != nil {
				return previousErr
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
