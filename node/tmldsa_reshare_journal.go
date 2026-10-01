// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

const (
	tmldsaReshareJournalMagic     = "QTMLDSA-RESHARE-JOURNAL-1"
	tmldsaReshareJournalVersion   = 1
	tmldsaReshareJournalOutbound  = "outbound"
	tmldsaReshareJournalInbound   = "inbound"
	tmldsaReshareJournalFileLimit = 2 * protocol.MaxThresholdEnvelopePayload
)

type tmldsaReshareJournalRecord struct {
	Version             int      `json:"version"`
	Kind                string   `json:"kind"`
	SessionID           [32]byte `json:"session_id"`
	KeyGeneration       uint64   `json:"key_generation"`
	OldCommitteeVersion uint64   `json:"old_committee_version"`
	NewCommitteeVersion uint64   `json:"new_committee_version"`
	DealerID            uint32   `json:"dealer_id"`
	RecipientID         uint32   `json:"recipient_id"`
	Payload             []byte   `json:"payload"`
	PayloadDigest       [32]byte `json:"payload_digest"`
}

func (record tmldsaReshareJournalRecord) validate() error {
	if record.Version != tmldsaReshareJournalVersion {
		return fmt.Errorf("invalid TMLDSA reshare journal version")
	}
	if record.Kind != tmldsaReshareJournalOutbound && record.Kind != tmldsaReshareJournalInbound {
		return fmt.Errorf("invalid TMLDSA reshare journal kind")
	}
	if record.SessionID == ([32]byte{}) || record.KeyGeneration == 0 ||
		record.OldCommitteeVersion == 0 || record.NewCommitteeVersion <= record.OldCommitteeVersion ||
		record.DealerID == 0 || record.RecipientID == 0 {
		return fmt.Errorf("invalid TMLDSA reshare journal metadata")
	}
	if len(record.Payload) == 0 || len(record.Payload) > protocol.MaxThresholdEnvelopePayload {
		return fmt.Errorf("invalid TMLDSA reshare journal payload length")
	}
	if digestTMLDSAResharePayload(record.Payload) != record.PayloadDigest {
		return fmt.Errorf("invalid TMLDSA reshare journal payload digest")
	}
	return nil
}

func digestTMLDSAResharePayload(payload []byte) [32]byte {
	return sha3.Sum256(payload)
}

func (n *Node) tmldsaReshareJournalPath(
	kind string,
	sessionID [32]byte,
	dealerID uint32,
	recipientID uint32,
) string {
	base := n.tmldsaSigningBaseDir()
	if base == "" || (kind != tmldsaReshareJournalOutbound && kind != tmldsaReshareJournalInbound) {
		return ""
	}
	name := fmt.Sprintf("%s-%08d-%08d.enc", kind, dealerID, recipientID)
	return filepath.Join(base, "reshare", hex.EncodeToString(sessionID[:]), name)
}

func encodeTMLDSAReshareJournalRecord(record tmldsaReshareJournalRecord) ([]byte, error) {
	if err := record.validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	return append([]byte(tmldsaReshareJournalMagic), payload...), nil
}

func decodeTMLDSAReshareJournalRecord(payload []byte) (tmldsaReshareJournalRecord, error) {
	if len(payload) > tmldsaReshareJournalFileLimit || !bytes.HasPrefix(payload, []byte(tmldsaReshareJournalMagic)) {
		return tmldsaReshareJournalRecord{}, fmt.Errorf("invalid TMLDSA reshare journal encoding")
	}
	var record tmldsaReshareJournalRecord
	if err := json.Unmarshal(payload[len(tmldsaReshareJournalMagic):], &record); err != nil {
		return tmldsaReshareJournalRecord{}, err
	}
	if err := record.validate(); err != nil {
		return tmldsaReshareJournalRecord{}, err
	}
	return record, nil
}

func (n *Node) persistTMLDSAReshareJournalRecord(record tmldsaReshareJournalRecord) error {
	if err := record.validate(); err != nil {
		return err
	}
	path := n.tmldsaReshareJournalPath(record.Kind, record.SessionID, record.DealerID, record.RecipientID)
	if path == "" {
		return fmt.Errorf("TMLDSA reshare journal is not configured")
	}
	password, err := n.getTSSPassword()
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(password)

	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	if encrypted, readErr := readTMLDSABoundedFile(path, tmldsaReshareJournalFileLimit); readErr == nil {
		plaintext, decryptErr := tmldsaDecryptPersistenceBlob(encrypted, password)
		if decryptErr != nil {
			return decryptErr
		}
		defer qtd.SecurelyZeroMemory(plaintext)
		existing, decodeErr := decodeTMLDSAReshareJournalRecord(plaintext)
		if decodeErr != nil {
			return decodeErr
		}
		if !equalTMLDSAReshareJournalRecords(existing, record) {
			return fmt.Errorf("conflicting TMLDSA reshare journal record")
		}
		return nil
	} else if !os.IsNotExist(readErr) {
		return readErr
	}

	plaintext, err := encodeTMLDSAReshareJournalRecord(record)
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	encrypted, err := tmldsaEncryptPersistenceBlob(plaintext, password)
	if err != nil {
		return err
	}
	return writeTMLDSAEncryptedFile(path, encrypted)
}

func (n *Node) loadTMLDSAReshareJournalRecord(
	kind string,
	sessionID [32]byte,
	dealerID uint32,
	recipientID uint32,
) (tmldsaReshareJournalRecord, bool, error) {
	path := n.tmldsaReshareJournalPath(kind, sessionID, dealerID, recipientID)
	if path == "" || sessionID == ([32]byte{}) || dealerID == 0 || recipientID == 0 {
		return tmldsaReshareJournalRecord{}, false, fmt.Errorf("invalid TMLDSA reshare journal lookup")
	}
	password, err := n.getTSSPassword()
	if err != nil {
		return tmldsaReshareJournalRecord{}, false, err
	}
	defer qtd.SecurelyZeroMemory(password)

	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	encrypted, err := readTMLDSABoundedFile(path, tmldsaReshareJournalFileLimit)
	if os.IsNotExist(err) {
		return tmldsaReshareJournalRecord{}, false, nil
	}
	if err != nil {
		return tmldsaReshareJournalRecord{}, false, err
	}
	plaintext, err := tmldsaDecryptPersistenceBlob(encrypted, password)
	if err != nil {
		return tmldsaReshareJournalRecord{}, false, err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	record, err := decodeTMLDSAReshareJournalRecord(plaintext)
	if err != nil {
		return tmldsaReshareJournalRecord{}, false, err
	}
	if record.Kind != kind || record.SessionID != sessionID || record.DealerID != dealerID || record.RecipientID != recipientID {
		return tmldsaReshareJournalRecord{}, false, fmt.Errorf("TMLDSA reshare journal path mismatch")
	}
	return record, true, nil
}

func equalTMLDSAReshareJournalRecords(left, right tmldsaReshareJournalRecord) bool {
	return left.Version == right.Version &&
		left.Kind == right.Kind &&
		left.SessionID == right.SessionID &&
		left.KeyGeneration == right.KeyGeneration &&
		left.OldCommitteeVersion == right.OldCommitteeVersion &&
		left.NewCommitteeVersion == right.NewCommitteeVersion &&
		left.DealerID == right.DealerID &&
		left.RecipientID == right.RecipientID &&
		left.PayloadDigest == right.PayloadDigest &&
		bytes.Equal(left.Payload, right.Payload)
}

func readTMLDSABoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := io.LimitReader(file, limit+1)
	payload, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > limit {
		return nil, fmt.Errorf("TMLDSA journal file exceeds limit")
	}
	return payload, nil
}
