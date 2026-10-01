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

	"github.com/quantaureum/qau/wallet/tss/qtd"
)

const (
	tmldsaReshareNonceVersion   = 1
	tmldsaReshareNonceMagic     = "QTMLDSA-RESHARE-NONCE-1"
	tmldsaReshareNonceFileLimit = 16 << 10
)

type tmldsaReshareNonceRecord struct {
	Version       int      `json:"version"`
	SessionID     [32]byte `json:"session_id"`
	DealerID      uint32   `json:"dealer_id"`
	ParticipantID uint32   `json:"participant_id"`
	Nonce         [32]byte `json:"nonce"`
}

func (n *Node) tmldsaReshareNoncePath(sessionID [32]byte, dealerID, participantID uint32) string {
	base := n.tmldsaSigningBaseDir()
	if base == "" || sessionID == ([32]byte{}) || dealerID == 0 || participantID == 0 {
		return ""
	}
	return filepath.Join(
		base,
		"reshare",
		hex.EncodeToString(sessionID[:]),
		"nonces",
		fmt.Sprintf("%08d-%08d.enc", dealerID, participantID),
	)
}

func encodeTMLDSAReshareNonceRecord(record tmldsaReshareNonceRecord) ([]byte, error) {
	if record.Version != tmldsaReshareNonceVersion || record.SessionID == ([32]byte{}) ||
		record.DealerID == 0 || record.ParticipantID == 0 || record.Nonce == ([32]byte{}) {
		return nil, fmt.Errorf("invalid TMLDSA reshare nonce record")
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	return append([]byte(tmldsaReshareNonceMagic), payload...), nil
}

func decodeTMLDSAReshareNonceRecord(payload []byte) (tmldsaReshareNonceRecord, error) {
	if len(payload) > tmldsaReshareNonceFileLimit || !bytes.HasPrefix(payload, []byte(tmldsaReshareNonceMagic)) {
		return tmldsaReshareNonceRecord{}, fmt.Errorf("invalid TMLDSA reshare nonce encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload[len(tmldsaReshareNonceMagic):]))
	decoder.DisallowUnknownFields()
	var record tmldsaReshareNonceRecord
	if err := decoder.Decode(&record); err != nil {
		return tmldsaReshareNonceRecord{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return tmldsaReshareNonceRecord{}, fmt.Errorf("invalid trailing TMLDSA reshare nonce data")
	}
	if _, err := encodeTMLDSAReshareNonceRecord(record); err != nil {
		return tmldsaReshareNonceRecord{}, err
	}
	return record, nil
}

func (n *Node) loadOrCreateTMLDSAReshareNonce(
	sessionID [32]byte,
	dealerID uint32,
	participantID uint32,
	entropy io.Reader,
) ([32]byte, error) {
	path := n.tmldsaReshareNoncePath(sessionID, dealerID, participantID)
	if path == "" || entropy == nil {
		return [32]byte{}, fmt.Errorf("invalid TMLDSA reshare nonce request")
	}
	password, err := n.getTSSPassword()
	if err != nil {
		return [32]byte{}, err
	}
	defer qtd.SecurelyZeroMemory(password)
	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()

	encrypted, err := readTMLDSABoundedFile(path, tmldsaReshareNonceFileLimit)
	if err == nil {
		plaintext, decryptErr := tmldsaDecryptPersistenceBlob(encrypted, password)
		if decryptErr != nil {
			return [32]byte{}, decryptErr
		}
		defer qtd.SecurelyZeroMemory(plaintext)
		record, decodeErr := decodeTMLDSAReshareNonceRecord(plaintext)
		if decodeErr != nil {
			return [32]byte{}, decodeErr
		}
		if record.SessionID != sessionID || record.DealerID != dealerID || record.ParticipantID != participantID {
			return [32]byte{}, fmt.Errorf("TMLDSA reshare nonce path mismatch")
		}
		return record.Nonce, nil
	}
	if !os.IsNotExist(err) {
		return [32]byte{}, err
	}

	var nonce [32]byte
	if _, err := io.ReadFull(entropy, nonce[:]); err != nil {
		return [32]byte{}, err
	}
	if nonce == ([32]byte{}) {
		return [32]byte{}, fmt.Errorf("TMLDSA reshare nonce entropy produced zero")
	}
	record := tmldsaReshareNonceRecord{
		Version:       tmldsaReshareNonceVersion,
		SessionID:     sessionID,
		DealerID:      dealerID,
		ParticipantID: participantID,
		Nonce:         nonce,
	}
	plaintext, err := encodeTMLDSAReshareNonceRecord(record)
	if err != nil {
		return [32]byte{}, err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	encrypted, err = tmldsaEncryptPersistenceBlob(plaintext, password)
	if err != nil {
		return [32]byte{}, err
	}
	if err := writeTMLDSAEncryptedFile(path, encrypted); err != nil {
		return [32]byte{}, err
	}
	return nonce, nil
}
