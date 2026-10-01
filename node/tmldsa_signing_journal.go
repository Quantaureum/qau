// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

const (
	tmldsaSigningJournalVersion = 1
	tmldsaSigningRecordMagic    = "QTMLDSA-SIGN-RECORD-1"
	tmldsaSigningLedgerMagic    = "QTMLDSA-SIGN-LEDGER-1"
)

type tmldsaSigningRecordFile struct {
	Version int                      `json:"version"`
	Record  protocol.SingleUseRecord `json:"record"`
}

type tmldsaSigningLedgerHead struct {
	Sequence uint64   `json:"sequence"`
	Digest   [32]byte `json:"digest"`
}

type tmldsaSigningLedgerFile struct {
	Version int                                `json:"version"`
	Heads   map[string]tmldsaSigningLedgerHead `json:"heads"`
}

func (n *Node) tmldsaSigningBaseDir() string {
	if n == nil || n.config == nil || n.config.TSSKeyShareFile == "" {
		return ""
	}
	return n.config.TSSKeyShareFile + ".tmldsa-v1"
}

func (n *Node) tmldsaSigningSessionPath(sessionID [32]byte) string {
	base := n.tmldsaSigningBaseDir()
	if base == "" {
		return ""
	}
	return filepath.Join(base, "sessions", hex.EncodeToString(sessionID[:])+".enc")
}

func (n *Node) tmldsaSigningLedgerPath() string {
	base := n.tmldsaSigningBaseDir()
	if base == "" {
		return ""
	}
	return filepath.Join(base, "ledger", "head.enc")
}

func tmldsaSigningSessionKey(sessionID [32]byte) string {
	return hex.EncodeToString(sessionID[:])
}

func encodeTMLDSASigningRecord(record protocol.SingleUseRecord) ([]byte, error) {
	payload, err := json.Marshal(tmldsaSigningRecordFile{Version: tmldsaSigningJournalVersion, Record: record})
	if err != nil {
		return nil, err
	}
	return append([]byte(tmldsaSigningRecordMagic), payload...), nil
}

func decodeTMLDSASigningRecord(payload []byte) (protocol.SingleUseRecord, error) {
	if !bytes.HasPrefix(payload, []byte(tmldsaSigningRecordMagic)) {
		return protocol.SingleUseRecord{}, fmt.Errorf("invalid TMLDSA signing record magic")
	}
	var file tmldsaSigningRecordFile
	if err := json.Unmarshal(payload[len(tmldsaSigningRecordMagic):], &file); err != nil {
		return protocol.SingleUseRecord{}, err
	}
	if file.Version != tmldsaSigningJournalVersion {
		return protocol.SingleUseRecord{}, fmt.Errorf("unsupported TMLDSA signing record version")
	}
	if err := file.Record.Validate(); err != nil {
		return protocol.SingleUseRecord{}, err
	}
	return file.Record, nil
}

func encodeTMLDSASigningLedger(ledger *tmldsaSigningLedgerFile) ([]byte, error) {
	payload, err := json.Marshal(ledger)
	if err != nil {
		return nil, err
	}
	return append([]byte(tmldsaSigningLedgerMagic), payload...), nil
}

func decodeTMLDSASigningLedger(payload []byte) (*tmldsaSigningLedgerFile, error) {
	if !bytes.HasPrefix(payload, []byte(tmldsaSigningLedgerMagic)) {
		return nil, fmt.Errorf("invalid TMLDSA signing ledger magic")
	}
	var ledger tmldsaSigningLedgerFile
	if err := json.Unmarshal(payload[len(tmldsaSigningLedgerMagic):], &ledger); err != nil {
		return nil, err
	}
	if ledger.Version != tmldsaSigningJournalVersion {
		return nil, fmt.Errorf("unsupported TMLDSA signing ledger version")
	}
	if ledger.Heads == nil {
		return nil, fmt.Errorf("missing TMLDSA signing ledger heads")
	}
	return &ledger, nil
}

func (n *Node) persistTMLDSASigningRecord(record protocol.SingleUseRecord) error {
	if err := record.Validate(); err != nil {
		return err
	}
	if n.tmldsaSigningBaseDir() == "" {
		return fmt.Errorf("TMLDSA signing journal is not configured")
	}
	password, err := n.getTSSPassword()
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(password)

	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	ledger, err := n.loadTMLDSASigningLedgerLocked(password)
	if err != nil {
		return err
	}
	return n.persistTMLDSASigningRecordLocked(record, password, ledger)
}

func (n *Node) persistTMLDSASigningRecordLocked(record protocol.SingleUseRecord, password []byte, ledger *tmldsaSigningLedgerFile) error {
	key := tmldsaSigningSessionKey(record.SessionID)
	digest := record.Digest()
	head, exists := ledger.Heads[key]
	if exists {
		switch {
		case record.Sequence < head.Sequence:
			return fmt.Errorf("TMLDSA signing record sequence rollback")
		case record.Sequence == head.Sequence:
			if digest != head.Digest {
				return fmt.Errorf("conflicting TMLDSA signing record")
			}
			existing, found, err := n.loadTMLDSASigningSessionLocked(record.SessionID, password)
			if err != nil {
				return err
			}
			if !found || existing != record {
				return fmt.Errorf("TMLDSA signing record and ledger disagree")
			}
			return nil
		case record.Sequence != head.Sequence+1:
			return fmt.Errorf("TMLDSA signing record sequence gap")
		case record.PreviousHash != head.Digest:
			return fmt.Errorf("TMLDSA signing record previous hash mismatch")
		}
	} else {
		if record.Sequence > 1 {
			return fmt.Errorf("TMLDSA signing record missing ledger ancestry")
		}
		if _, err := os.Stat(n.tmldsaSigningSessionPath(record.SessionID)); err == nil {
			return fmt.Errorf("TMLDSA signing session exists without ledger head")
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	plaintext, err := encodeTMLDSASigningRecord(record)
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	encrypted, err := tmldsaEncryptPersistenceBlob(plaintext, password)
	if err != nil {
		return err
	}
	if err := writeTMLDSAEncryptedFile(n.tmldsaSigningSessionPath(record.SessionID), encrypted); err != nil {
		return err
	}
	ledger.Heads[key] = tmldsaSigningLedgerHead{Sequence: record.Sequence, Digest: digest}
	return n.persistTMLDSASigningLedgerLocked(ledger, password)
}

func (n *Node) loadTMLDSASigningRecord(sessionID [32]byte) (protocol.SingleUseRecord, bool, error) {
	if n.tmldsaSigningBaseDir() == "" {
		return protocol.SingleUseRecord{}, false, fmt.Errorf("TMLDSA signing journal is not configured")
	}
	password, err := n.getTSSPassword()
	if err != nil {
		return protocol.SingleUseRecord{}, false, err
	}
	defer qtd.SecurelyZeroMemory(password)

	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	record, found, err := n.loadTMLDSASigningSessionLocked(sessionID, password)
	if err != nil || !found {
		return protocol.SingleUseRecord{}, found, err
	}
	ledger, err := n.loadTMLDSASigningLedgerLocked(password)
	if err != nil {
		return protocol.SingleUseRecord{}, false, err
	}
	head, exists := ledger.Heads[tmldsaSigningSessionKey(sessionID)]
	if !exists || head.Sequence != record.Sequence || head.Digest != record.Digest() {
		return protocol.SingleUseRecord{}, false, fmt.Errorf("TMLDSA signing record is behind or inconsistent with ledger head")
	}
	recovered, err := protocol.RecoverSingleUseRecord(record)
	if err != nil {
		return protocol.SingleUseRecord{}, false, err
	}
	if recovered != record {
		if err := n.persistTMLDSASigningRecordLocked(recovered, password, ledger); err != nil {
			return protocol.SingleUseRecord{}, false, err
		}
	}
	return recovered, true, nil
}

func (n *Node) loadTMLDSASigningSessionLocked(sessionID [32]byte, password []byte) (protocol.SingleUseRecord, bool, error) {
	encrypted, err := os.ReadFile(n.tmldsaSigningSessionPath(sessionID))
	if os.IsNotExist(err) {
		return protocol.SingleUseRecord{}, false, nil
	}
	if err != nil {
		return protocol.SingleUseRecord{}, false, err
	}
	plaintext, err := tmldsaDecryptPersistenceBlob(encrypted, password)
	if err != nil {
		return protocol.SingleUseRecord{}, false, err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	record, err := decodeTMLDSASigningRecord(plaintext)
	if err != nil {
		return protocol.SingleUseRecord{}, false, err
	}
	if record.SessionID != sessionID {
		return protocol.SingleUseRecord{}, false, fmt.Errorf("TMLDSA signing session path mismatch")
	}
	return record, true, nil
}

func (n *Node) loadTMLDSASigningLedgerLocked(password []byte) (*tmldsaSigningLedgerFile, error) {
	encrypted, err := os.ReadFile(n.tmldsaSigningLedgerPath())
	if os.IsNotExist(err) {
		return &tmldsaSigningLedgerFile{Version: tmldsaSigningJournalVersion, Heads: make(map[string]tmldsaSigningLedgerHead)}, nil
	}
	if err != nil {
		return nil, err
	}
	plaintext, err := tmldsaDecryptPersistenceBlob(encrypted, password)
	if err != nil {
		return nil, err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	return decodeTMLDSASigningLedger(plaintext)
}

func (n *Node) persistTMLDSASigningLedgerLocked(ledger *tmldsaSigningLedgerFile, password []byte) error {
	plaintext, err := encodeTMLDSASigningLedger(ledger)
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	encrypted, err := tmldsaEncryptPersistenceBlob(plaintext, password)
	if err != nil {
		return err
	}
	return writeTMLDSAEncryptedFile(n.tmldsaSigningLedgerPath(), encrypted)
}

func writeTMLDSAEncryptedFile(path string, encrypted []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".tmldsa-signing-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(encrypted); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
