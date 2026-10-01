// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

const (
	tmldsaReshareCertificateVersion   = 1
	tmldsaReshareCertificateMagic     = "QTMLDSA-RESHARE-CERTIFICATE-1"
	tmldsaReshareCertificateFileLimit = 1 << 20
	tmldsaReshareAckMagic             = "QTMLDSA-RESHARE-ACTIVATION-ACK-1"
	tmldsaReshareAckFileLimit         = 128 << 10
)

type tmldsaReshareCertificateRecord struct {
	Version     int                                          `json:"version"`
	Certificate protocolmldsa65.ReshareActivationCertificate `json:"certificate"`
	Digest      [32]byte                                     `json:"digest"`
}

type tmldsaReshareAckRecord struct {
	Version         int                                              `json:"version"`
	Acknowledgement protocolmldsa65.ReshareActivationAcknowledgement `json:"acknowledgement"`
	Digest          [32]byte                                         `json:"digest"`
}

func (n *Node) tmldsaReshareCertificatePath(sessionID [32]byte) string {
	base := n.tmldsaSigningBaseDir()
	if base == "" || sessionID == ([32]byte{}) {
		return ""
	}
	return filepath.Join(base, "reshare", hex.EncodeToString(sessionID[:]), "activation-certificate.enc")
}

func (n *Node) tmldsaReshareAckPath(sessionID [32]byte, participantID uint32) string {
	base := n.tmldsaSigningBaseDir()
	if base == "" || sessionID == ([32]byte{}) || participantID == 0 {
		return ""
	}
	return filepath.Join(
		base,
		"reshare",
		hex.EncodeToString(sessionID[:]),
		"activation-acks",
		fmt.Sprintf("%08d.enc", participantID),
	)
}

func encodeTMLDSAReshareAckRecord(record tmldsaReshareAckRecord) ([]byte, error) {
	if record.Version != tmldsaReshareCertificateVersion || record.Digest == ([32]byte{}) {
		return nil, fmt.Errorf("invalid TMLDSA reshare activation acknowledgement record")
	}
	digest, err := record.Acknowledgement.CanonicalDigest()
	if err != nil || digest != record.Digest {
		return nil, fmt.Errorf("invalid TMLDSA reshare activation acknowledgement digest")
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if len(payload)+len(tmldsaReshareAckMagic) > tmldsaReshareAckFileLimit {
		return nil, fmt.Errorf("TMLDSA reshare activation acknowledgement exceeds size limit")
	}
	return append([]byte(tmldsaReshareAckMagic), payload...), nil
}

func decodeTMLDSAReshareAckRecord(payload []byte) (tmldsaReshareAckRecord, error) {
	if len(payload) > tmldsaReshareAckFileLimit || !bytes.HasPrefix(payload, []byte(tmldsaReshareAckMagic)) {
		return tmldsaReshareAckRecord{}, fmt.Errorf("invalid TMLDSA reshare activation acknowledgement encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload[len(tmldsaReshareAckMagic):]))
	decoder.DisallowUnknownFields()
	var record tmldsaReshareAckRecord
	if err := decoder.Decode(&record); err != nil {
		return tmldsaReshareAckRecord{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return tmldsaReshareAckRecord{}, fmt.Errorf("invalid trailing TMLDSA reshare activation acknowledgement data")
	}
	if _, err := encodeTMLDSAReshareAckRecord(record); err != nil {
		return tmldsaReshareAckRecord{}, err
	}
	return record, nil
}

func (n *Node) persistTMLDSAReshareActivationAcknowledgement(
	acknowledgement protocolmldsa65.ReshareActivationAcknowledgement,
	verifier protocolmldsa65.ReshareIdentityVerifier,
) (bool, error) {
	if err := acknowledgement.Verify(verifier); err != nil {
		return false, err
	}
	digest, err := acknowledgement.CanonicalDigest()
	if err != nil {
		return false, err
	}
	record := tmldsaReshareAckRecord{
		Version:         tmldsaReshareCertificateVersion,
		Acknowledgement: acknowledgement,
		Digest:          digest,
	}
	plaintext, err := encodeTMLDSAReshareAckRecord(record)
	if err != nil {
		return false, err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	password, err := n.getTSSPassword()
	if err != nil {
		return false, err
	}
	defer qtd.SecurelyZeroMemory(password)

	n.tssPersistMu.Lock()
	existing, found, err := n.loadTMLDSAReshareActivationAcknowledgementLocked(
		acknowledgement.SessionID,
		acknowledgement.ParticipantID,
		password,
	)
	if err == nil && found {
		existingDigest, digestErr := existing.CanonicalDigest()
		if digestErr != nil || existingDigest != digest {
			err = fmt.Errorf("conflicting TMLDSA reshare activation acknowledgement")
		}
	} else if err == nil {
		encrypted, encryptErr := tmldsaEncryptPersistenceBlob(plaintext, password)
		if encryptErr != nil {
			err = encryptErr
		} else {
			err = writeTMLDSAEncryptedFile(
				n.tmldsaReshareAckPath(acknowledgement.SessionID, acknowledgement.ParticipantID),
				encrypted,
			)
		}
	}
	n.tssPersistMu.Unlock()
	if err != nil {
		return false, err
	}

	acknowledgements, complete, err := n.loadTMLDSAReshareActivationAcknowledgements(
		acknowledgement.SessionID,
		acknowledgement.NewCommittee.Participants,
	)
	if err != nil || !complete {
		return false, err
	}
	certificate := protocolmldsa65.ReshareActivationCertificate{Acknowledgements: acknowledgements}
	if err := n.persistTMLDSAReshareActivationCertificate(certificate, verifier); err != nil {
		return false, err
	}
	return true, nil
}

func (n *Node) loadTMLDSAReshareActivationAcknowledgements(
	sessionID [32]byte,
	participants []uint32,
) ([]protocolmldsa65.ReshareActivationAcknowledgement, bool, error) {
	password, err := n.getTSSPassword()
	if err != nil {
		return nil, false, err
	}
	defer qtd.SecurelyZeroMemory(password)
	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	acknowledgements := make([]protocolmldsa65.ReshareActivationAcknowledgement, 0, len(participants))
	for _, participantID := range participants {
		acknowledgement, found, err := n.loadTMLDSAReshareActivationAcknowledgementLocked(
			sessionID,
			participantID,
			password,
		)
		if err != nil {
			return nil, false, err
		}
		if !found {
			return nil, false, nil
		}
		acknowledgements = append(acknowledgements, acknowledgement)
	}
	return acknowledgements, true, nil
}

func (n *Node) loadTMLDSAReshareActivationAcknowledgementLocked(
	sessionID [32]byte,
	participantID uint32,
	password []byte,
) (protocolmldsa65.ReshareActivationAcknowledgement, bool, error) {
	path := n.tmldsaReshareAckPath(sessionID, participantID)
	if path == "" {
		return protocolmldsa65.ReshareActivationAcknowledgement{}, false, fmt.Errorf("invalid TMLDSA reshare activation acknowledgement lookup")
	}
	encrypted, err := readTMLDSABoundedFile(path, tmldsaReshareAckFileLimit)
	if os.IsNotExist(err) {
		return protocolmldsa65.ReshareActivationAcknowledgement{}, false, nil
	}
	if err != nil {
		return protocolmldsa65.ReshareActivationAcknowledgement{}, false, err
	}
	plaintext, err := tmldsaDecryptPersistenceBlob(encrypted, password)
	if err != nil {
		return protocolmldsa65.ReshareActivationAcknowledgement{}, false, err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	record, err := decodeTMLDSAReshareAckRecord(plaintext)
	if err != nil {
		return protocolmldsa65.ReshareActivationAcknowledgement{}, false, err
	}
	if record.Acknowledgement.SessionID != sessionID || record.Acknowledgement.ParticipantID != participantID {
		return protocolmldsa65.ReshareActivationAcknowledgement{}, false, fmt.Errorf("TMLDSA reshare activation acknowledgement path mismatch")
	}
	return record.Acknowledgement, true, nil
}

func encodeTMLDSAReshareCertificateRecord(record tmldsaReshareCertificateRecord) ([]byte, error) {
	if record.Version != tmldsaReshareCertificateVersion || record.Digest == ([32]byte{}) {
		return nil, fmt.Errorf("invalid TMLDSA reshare activation certificate record")
	}
	digest, err := record.Certificate.CanonicalDigest()
	if err != nil || digest != record.Digest {
		return nil, fmt.Errorf("invalid TMLDSA reshare activation certificate digest")
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if len(payload)+len(tmldsaReshareCertificateMagic) > tmldsaReshareCertificateFileLimit {
		return nil, fmt.Errorf("TMLDSA reshare activation certificate exceeds size limit")
	}
	return append([]byte(tmldsaReshareCertificateMagic), payload...), nil
}

func decodeTMLDSAReshareCertificateRecord(payload []byte) (tmldsaReshareCertificateRecord, error) {
	if len(payload) > tmldsaReshareCertificateFileLimit ||
		!bytes.HasPrefix(payload, []byte(tmldsaReshareCertificateMagic)) {
		return tmldsaReshareCertificateRecord{}, fmt.Errorf("invalid TMLDSA reshare activation certificate encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload[len(tmldsaReshareCertificateMagic):]))
	decoder.DisallowUnknownFields()
	var record tmldsaReshareCertificateRecord
	if err := decoder.Decode(&record); err != nil {
		return tmldsaReshareCertificateRecord{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return tmldsaReshareCertificateRecord{}, fmt.Errorf("invalid trailing TMLDSA reshare activation certificate data")
	}
	if _, err := encodeTMLDSAReshareCertificateRecord(record); err != nil {
		return tmldsaReshareCertificateRecord{}, err
	}
	return record, nil
}

func (n *Node) persistTMLDSAReshareActivationCertificate(
	certificate protocolmldsa65.ReshareActivationCertificate,
	verifier protocolmldsa65.ReshareIdentityVerifier,
) error {
	digest, err := certificate.Digest(verifier)
	if err != nil {
		return err
	}
	sessionID := certificate.Acknowledgements[0].SessionID
	path := n.tmldsaReshareCertificatePath(sessionID)
	if path == "" {
		return fmt.Errorf("TMLDSA reshare activation certificate storage is not configured")
	}
	record := tmldsaReshareCertificateRecord{
		Version:     tmldsaReshareCertificateVersion,
		Certificate: certificate,
		Digest:      digest,
	}
	plaintext, err := encodeTMLDSAReshareCertificateRecord(record)
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	password, err := n.getTSSPassword()
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(password)

	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	if existing, found, err := n.loadTMLDSAReshareActivationCertificateLocked(sessionID, password); err != nil {
		return err
	} else if found {
		if existing.Digest == digest {
			return nil
		}
		return fmt.Errorf("conflicting TMLDSA reshare activation certificate")
	}
	encrypted, err := tmldsaEncryptPersistenceBlob(plaintext, password)
	if err != nil {
		return err
	}
	return writeTMLDSAEncryptedFile(path, encrypted)
}

func (n *Node) loadTMLDSAReshareActivationCertificateLocked(
	sessionID [32]byte,
	password []byte,
) (tmldsaReshareCertificateRecord, bool, error) {
	path := n.tmldsaReshareCertificatePath(sessionID)
	if path == "" {
		return tmldsaReshareCertificateRecord{}, false, fmt.Errorf("invalid TMLDSA reshare activation certificate lookup")
	}
	encrypted, err := readTMLDSABoundedFile(path, tmldsaReshareCertificateFileLimit)
	if os.IsNotExist(err) {
		return tmldsaReshareCertificateRecord{}, false, nil
	}
	if err != nil {
		return tmldsaReshareCertificateRecord{}, false, err
	}
	plaintext, err := tmldsaDecryptPersistenceBlob(encrypted, password)
	if err != nil {
		return tmldsaReshareCertificateRecord{}, false, err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	record, err := decodeTMLDSAReshareCertificateRecord(plaintext)
	if err != nil {
		return tmldsaReshareCertificateRecord{}, false, err
	}
	if record.Certificate.Acknowledgements[0].SessionID != sessionID {
		return tmldsaReshareCertificateRecord{}, false, fmt.Errorf("TMLDSA reshare activation certificate path mismatch")
	}
	return record, true, nil
}

func (n *Node) loadTMLDSAReshareActivationCertificate(
	sessionID [32]byte,
) (tmldsaReshareCertificateRecord, bool, error) {
	password, err := n.getTSSPassword()
	if err != nil {
		return tmldsaReshareCertificateRecord{}, false, err
	}
	defer qtd.SecurelyZeroMemory(password)
	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	return n.loadTMLDSAReshareActivationCertificateLocked(sessionID, password)
}

func (n *Node) tmldsaReshareActivationEvidence(
	sessionID [32]byte,
	participantID uint32,
) ([32]byte, [32]byte, error) {
	password, err := n.getTSSPassword()
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	defer qtd.SecurelyZeroMemory(password)
	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	candidate, share, plaintext, err := n.loadTMLDSAReshareActivationCandidateLocked(sessionID, participantID, password)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	share.Zeroize()
	defer qtd.SecurelyZeroMemory(plaintext)
	return sha3.Sum256(plaintext), digestTMLDSAReshareTranscriptHeads(candidate.TranscriptHeads), nil
}

func digestTMLDSAReshareTranscriptHeads(heads []tmldsaReshareTranscriptHead) [32]byte {
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-RESHARE-TRANSCRIPT-HEADS"))
	var encoded [4]byte
	for _, head := range heads {
		binary.BigEndian.PutUint32(encoded[:], head.DealerID)
		_, _ = digest.Write(encoded[:])
		_, _ = digest.Write(head.Digest[:])
	}
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func validateTMLDSAReshareCertificateCandidate(
	record tmldsaReshareCertificateRecord,
	candidate tmldsaReshareActivationCandidate,
	candidateDigest [32]byte,
) error {
	if len(record.Certificate.Acknowledgements) == 0 {
		return fmt.Errorf("missing TMLDSA reshare activation certificate")
	}
	wantTranscriptDigest := digestTMLDSAReshareTranscriptHeads(candidate.TranscriptHeads)
	keyDigest, err := candidate.Key.CanonicalDigest()
	if err != nil {
		return err
	}
	oldDigest, err := candidate.OldCommittee.CanonicalDigest()
	if err != nil {
		return err
	}
	newDigest, err := candidate.NewCommittee.CanonicalDigest()
	if err != nil {
		return err
	}
	var localFound bool
	for _, acknowledgement := range record.Certificate.Acknowledgements {
		ackKeyDigest, keyErr := acknowledgement.Key.CanonicalDigest()
		ackOldDigest, oldErr := acknowledgement.OldCommittee.CanonicalDigest()
		ackNewDigest, newErr := acknowledgement.NewCommittee.CanonicalDigest()
		if keyErr != nil || oldErr != nil || newErr != nil ||
			acknowledgement.SessionID != candidate.SessionID ||
			acknowledgement.ActivationEpoch != candidate.ActivationEpoch ||
			acknowledgement.TranscriptDigest != wantTranscriptDigest ||
			ackKeyDigest != keyDigest || ackOldDigest != oldDigest || ackNewDigest != newDigest {
			return fmt.Errorf("TMLDSA reshare activation certificate metadata mismatch")
		}
		if acknowledgement.ParticipantID == candidate.ParticipantID {
			if acknowledgement.CandidateDigest != candidateDigest {
				return fmt.Errorf("TMLDSA reshare activation certificate candidate mismatch")
			}
			localFound = true
		}
	}
	if !localFound {
		return fmt.Errorf("TMLDSA reshare activation certificate lacks local acknowledgement")
	}
	return nil
}
