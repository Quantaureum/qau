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
	tmldsaReshareTermVersion   = 1
	tmldsaReshareTermMagic     = "QTMLDSA-RESHARE-TERM-1"
	tmldsaReshareTermFileLimit = 16 << 10
)

type tmldsaReshareTermRecord struct {
	Version   int                                     `json:"version"`
	SessionID [32]byte                                `json:"session_id"`
	DealerID  uint32                                  `json:"dealer_id"`
	Round     uint32                                  `json:"round"`
	CheckID   uint32                                  `json:"check_id"`
	Reveal    protocolmldsa65.ReshareMaskedTermReveal `json:"reveal"`
}

func (n *Node) tmldsaReshareTermPath(
	sessionID [32]byte,
	dealerID uint32,
	round uint32,
	checkID uint32,
	senderID uint32,
) string {
	base := n.tmldsaSigningBaseDir()
	if base == "" || sessionID == ([32]byte{}) || dealerID == 0 || senderID == 0 {
		return ""
	}
	return filepath.Join(
		base,
		"reshare",
		hex.EncodeToString(sessionID[:]),
		"terms",
		fmt.Sprintf("%08d-%02d-%02d-%08d.enc", dealerID, round, checkID, senderID),
	)
}

func encodeTMLDSAReshareTermRecord(record tmldsaReshareTermRecord) ([]byte, error) {
	if record.Version != tmldsaReshareTermVersion || record.SessionID == ([32]byte{}) ||
		record.DealerID == 0 || record.Round >= protocolmldsa65.ReshareConsistencyRounds ||
		record.CheckID >= protocolmldsa65.ReshareConsistencyChecksPerRound || record.Reveal.SenderID == 0 {
		return nil, fmt.Errorf("invalid TMLDSA reshare term record")
	}
	if _, err := protocolmldsa65.CommitReshareMaskedTerm(
		record.SessionID,
		record.DealerID,
		record.Round,
		record.CheckID,
		record.Reveal.SenderID,
		record.Reveal.Term,
		record.Reveal.Salt,
	); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	return append([]byte(tmldsaReshareTermMagic), payload...), nil
}

func decodeTMLDSAReshareTermRecord(payload []byte) (tmldsaReshareTermRecord, error) {
	if len(payload) > tmldsaReshareTermFileLimit || !bytes.HasPrefix(payload, []byte(tmldsaReshareTermMagic)) {
		return tmldsaReshareTermRecord{}, fmt.Errorf("invalid TMLDSA reshare term encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload[len(tmldsaReshareTermMagic):]))
	decoder.DisallowUnknownFields()
	var record tmldsaReshareTermRecord
	if err := decoder.Decode(&record); err != nil {
		return tmldsaReshareTermRecord{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return tmldsaReshareTermRecord{}, fmt.Errorf("invalid trailing TMLDSA reshare term data")
	}
	if _, err := encodeTMLDSAReshareTermRecord(record); err != nil {
		return tmldsaReshareTermRecord{}, err
	}
	return record, nil
}

func (n *Node) loadOrPersistTMLDSAReshareTerm(
	sessionID [32]byte,
	dealerID uint32,
	round uint32,
	checkID uint32,
	senderID uint32,
	term int32,
	entropy io.Reader,
) (protocolmldsa65.ReshareMaskedTermReveal, error) {
	path := n.tmldsaReshareTermPath(sessionID, dealerID, round, checkID, senderID)
	if path == "" || entropy == nil {
		return protocolmldsa65.ReshareMaskedTermReveal{}, fmt.Errorf("invalid TMLDSA reshare term request")
	}
	password, err := n.getTSSPassword()
	if err != nil {
		return protocolmldsa65.ReshareMaskedTermReveal{}, err
	}
	defer qtd.SecurelyZeroMemory(password)
	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()

	encrypted, err := readTMLDSABoundedFile(path, tmldsaReshareTermFileLimit)
	if err == nil {
		plaintext, decryptErr := tmldsaDecryptPersistenceBlob(encrypted, password)
		if decryptErr != nil {
			return protocolmldsa65.ReshareMaskedTermReveal{}, decryptErr
		}
		defer qtd.SecurelyZeroMemory(plaintext)
		record, decodeErr := decodeTMLDSAReshareTermRecord(plaintext)
		if decodeErr != nil {
			return protocolmldsa65.ReshareMaskedTermReveal{}, decodeErr
		}
		if record.SessionID != sessionID || record.DealerID != dealerID || record.Round != round ||
			record.CheckID != checkID || record.Reveal.SenderID != senderID || record.Reveal.Term != term {
			return protocolmldsa65.ReshareMaskedTermReveal{}, fmt.Errorf("conflicting TMLDSA reshare term record")
		}
		return record.Reveal, nil
	}
	if !os.IsNotExist(err) {
		return protocolmldsa65.ReshareMaskedTermReveal{}, err
	}

	var salt [32]byte
	if _, err := io.ReadFull(entropy, salt[:]); err != nil {
		return protocolmldsa65.ReshareMaskedTermReveal{}, err
	}
	reveal := protocolmldsa65.ReshareMaskedTermReveal{SenderID: senderID, Term: term, Salt: salt}
	record := tmldsaReshareTermRecord{
		Version:   tmldsaReshareTermVersion,
		SessionID: sessionID,
		DealerID:  dealerID,
		Round:     round,
		CheckID:   checkID,
		Reveal:    reveal,
	}
	plaintext, err := encodeTMLDSAReshareTermRecord(record)
	if err != nil {
		return protocolmldsa65.ReshareMaskedTermReveal{}, err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	encrypted, err = tmldsaEncryptPersistenceBlob(plaintext, password)
	if err != nil {
		return protocolmldsa65.ReshareMaskedTermReveal{}, err
	}
	if err := writeTMLDSAEncryptedFile(path, encrypted); err != nil {
		return protocolmldsa65.ReshareMaskedTermReveal{}, err
	}
	return reveal, nil
}
