// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
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
	tmldsaReshareEvidenceVersion   = 1
	tmldsaReshareEvidenceMagic     = "QTMLDSA-RESHARE-EVIDENCE-1"
	tmldsaReshareEvidenceFileLimit = 128 << 10
)

type tmldsaReshareEvidenceRecord struct {
	Version  int                                        `json:"version"`
	Evidence protocolmldsa65.SignedReshareAbortEvidence `json:"evidence"`
	Digest   [32]byte                                   `json:"digest"`
}

func (n *Node) tmldsaReshareEvidencePath(sessionID [32]byte, dealerID, reporterID uint32) string {
	base := n.tmldsaSigningBaseDir()
	if base == "" || sessionID == ([32]byte{}) || dealerID == 0 || reporterID == 0 {
		return ""
	}
	return filepath.Join(
		base,
		"reshare",
		hex.EncodeToString(sessionID[:]),
		"evidence",
		fmt.Sprintf("%08d-%08d.enc", dealerID, reporterID),
	)
}

func encodeTMLDSAReshareEvidenceRecord(record tmldsaReshareEvidenceRecord) ([]byte, error) {
	if record.Version != tmldsaReshareEvidenceVersion || record.Digest == ([32]byte{}) {
		return nil, fmt.Errorf("invalid TMLDSA reshare evidence record")
	}
	digest, err := record.Evidence.CanonicalDigest()
	if err != nil || digest != record.Digest {
		return nil, fmt.Errorf("invalid TMLDSA reshare evidence digest")
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if len(payload)+len(tmldsaReshareEvidenceMagic) > tmldsaReshareEvidenceFileLimit {
		return nil, fmt.Errorf("TMLDSA reshare evidence exceeds size limit")
	}
	return append([]byte(tmldsaReshareEvidenceMagic), payload...), nil
}

func decodeTMLDSAReshareEvidenceRecord(payload []byte) (tmldsaReshareEvidenceRecord, error) {
	if len(payload) > tmldsaReshareEvidenceFileLimit ||
		!bytes.HasPrefix(payload, []byte(tmldsaReshareEvidenceMagic)) {
		return tmldsaReshareEvidenceRecord{}, fmt.Errorf("invalid TMLDSA reshare evidence encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload[len(tmldsaReshareEvidenceMagic):]))
	decoder.DisallowUnknownFields()
	var record tmldsaReshareEvidenceRecord
	if err := decoder.Decode(&record); err != nil {
		return tmldsaReshareEvidenceRecord{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return tmldsaReshareEvidenceRecord{}, fmt.Errorf("invalid trailing TMLDSA reshare evidence data")
	}
	if _, err := encodeTMLDSAReshareEvidenceRecord(record); err != nil {
		return tmldsaReshareEvidenceRecord{}, err
	}
	return record, nil
}

func (n *Node) persistTMLDSAReshareAbortEvidence(
	evidence protocolmldsa65.SignedReshareAbortEvidence,
	verifier protocolmldsa65.ReshareIdentityVerifier,
) error {
	if err := evidence.Verify(verifier); err != nil {
		return err
	}
	digest, err := evidence.CanonicalDigest()
	if err != nil {
		return err
	}
	record := tmldsaReshareEvidenceRecord{
		Version:  tmldsaReshareEvidenceVersion,
		Evidence: evidence,
		Digest:   digest,
	}
	plaintext, err := encodeTMLDSAReshareEvidenceRecord(record)
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
	existing, found, err := n.loadTMLDSAReshareAbortEvidenceLocked(
		evidence.SessionID,
		evidence.DealerID,
		evidence.ReporterID,
		password,
	)
	if err != nil {
		return err
	}
	if found {
		existingDigest, digestErr := existing.CanonicalDigest()
		if digestErr == nil && existingDigest == digest {
			return nil
		}
		return fmt.Errorf("conflicting TMLDSA reshare abort evidence")
	}
	encrypted, err := tmldsaEncryptPersistenceBlob(plaintext, password)
	if err != nil {
		return err
	}
	return writeTMLDSAEncryptedFile(
		n.tmldsaReshareEvidencePath(evidence.SessionID, evidence.DealerID, evidence.ReporterID),
		encrypted,
	)
}

func (n *Node) loadTMLDSAReshareAbortEvidence(
	sessionID [32]byte,
	dealerID uint32,
	reporterID uint32,
) (protocolmldsa65.SignedReshareAbortEvidence, bool, error) {
	password, err := n.getTSSPassword()
	if err != nil {
		return protocolmldsa65.SignedReshareAbortEvidence{}, false, err
	}
	defer qtd.SecurelyZeroMemory(password)
	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	return n.loadTMLDSAReshareAbortEvidenceLocked(sessionID, dealerID, reporterID, password)
}

func (n *Node) loadTMLDSAReshareAbortEvidenceLocked(
	sessionID [32]byte,
	dealerID uint32,
	reporterID uint32,
	password []byte,
) (protocolmldsa65.SignedReshareAbortEvidence, bool, error) {
	path := n.tmldsaReshareEvidencePath(sessionID, dealerID, reporterID)
	if path == "" {
		return protocolmldsa65.SignedReshareAbortEvidence{}, false, fmt.Errorf("invalid TMLDSA reshare evidence lookup")
	}
	encrypted, err := readTMLDSABoundedFile(path, tmldsaReshareEvidenceFileLimit)
	if os.IsNotExist(err) {
		return protocolmldsa65.SignedReshareAbortEvidence{}, false, nil
	}
	if err != nil {
		return protocolmldsa65.SignedReshareAbortEvidence{}, false, err
	}
	plaintext, err := tmldsaDecryptPersistenceBlob(encrypted, password)
	if err != nil {
		return protocolmldsa65.SignedReshareAbortEvidence{}, false, err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	record, err := decodeTMLDSAReshareEvidenceRecord(plaintext)
	if err != nil {
		return protocolmldsa65.SignedReshareAbortEvidence{}, false, err
	}
	if record.Evidence.SessionID != sessionID || record.Evidence.DealerID != dealerID ||
		record.Evidence.ReporterID != reporterID {
		return protocolmldsa65.SignedReshareAbortEvidence{}, false, fmt.Errorf("TMLDSA reshare evidence path mismatch")
	}
	return record.Evidence, true, nil
}
