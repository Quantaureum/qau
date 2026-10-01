// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

const (
	tmldsaReshareConsistencyJournalVersion = 1
	tmldsaReshareConsistencyLedgerMagic    = "QTMLDSA-RESHARE-CONSISTENCY-LEDGER-1"
)

type tmldsaReshareConsistencyHead struct {
	EventCount uint64   `json:"event_count"`
	Digest     [32]byte `json:"digest"`
}

type tmldsaReshareConsistencyLedger struct {
	Version int                                     `json:"version"`
	Heads   map[string]tmldsaReshareConsistencyHead `json:"heads"`
}

func (n *Node) tmldsaReshareConsistencyStatePath(sessionID [32]byte, dealerID uint32) string {
	base := n.tmldsaSigningBaseDir()
	if base == "" || sessionID == ([32]byte{}) || dealerID == 0 {
		return ""
	}
	return filepath.Join(
		base,
		"reshare",
		hex.EncodeToString(sessionID[:]),
		fmt.Sprintf("consistency-%08d.enc", dealerID),
	)
}

func (n *Node) tmldsaReshareConsistencyLedgerPath() string {
	base := n.tmldsaSigningBaseDir()
	if base == "" {
		return ""
	}
	return filepath.Join(base, "reshare", "consistency-head.enc")
}

func tmldsaReshareConsistencyStateKey(sessionID [32]byte, dealerID uint32) string {
	return fmt.Sprintf("%s/%08d", hex.EncodeToString(sessionID[:]), dealerID)
}

func encodeTMLDSAReshareConsistencyLedger(ledger *tmldsaReshareConsistencyLedger) ([]byte, error) {
	if ledger == nil || ledger.Version != tmldsaReshareConsistencyJournalVersion || ledger.Heads == nil {
		return nil, fmt.Errorf("invalid TMLDSA reshare consistency ledger")
	}
	payload, err := json.Marshal(ledger)
	if err != nil {
		return nil, err
	}
	return append([]byte(tmldsaReshareConsistencyLedgerMagic), payload...), nil
}

func decodeTMLDSAReshareConsistencyLedger(payload []byte) (*tmldsaReshareConsistencyLedger, error) {
	if !bytes.HasPrefix(payload, []byte(tmldsaReshareConsistencyLedgerMagic)) {
		return nil, fmt.Errorf("invalid TMLDSA reshare consistency ledger magic")
	}
	var ledger tmldsaReshareConsistencyLedger
	if err := json.Unmarshal(payload[len(tmldsaReshareConsistencyLedgerMagic):], &ledger); err != nil {
		return nil, err
	}
	if ledger.Version != tmldsaReshareConsistencyJournalVersion || ledger.Heads == nil {
		return nil, fmt.Errorf("invalid TMLDSA reshare consistency ledger")
	}
	return &ledger, nil
}

func (n *Node) persistTMLDSAReshareConsistencyState(
	coordinator *protocolmldsa65.ReshareConsistencyCoordinator,
) error {
	if coordinator == nil || n.tmldsaSigningBaseDir() == "" {
		return fmt.Errorf("TMLDSA reshare consistency journal is not configured")
	}
	encoded, err := coordinator.MarshalBinary()
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(encoded)
	password, err := n.getTSSPassword()
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(password)

	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	return n.persistTMLDSAReshareConsistencyStateLocked(coordinator, encoded, password)
}

func (n *Node) persistTMLDSAReshareConsistencyStateLocked(
	coordinator *protocolmldsa65.ReshareConsistencyCoordinator,
	encoded []byte,
	password []byte,
) error {
	ledger, err := n.loadTMLDSAReshareConsistencyLedgerLocked(password)
	if err != nil {
		return err
	}
	sessionID, dealerID, err := tmldsaReshareConsistencyIdentity(encoded)
	if err != nil {
		return err
	}
	key := tmldsaReshareConsistencyStateKey(sessionID, dealerID)
	head, hasHead := ledger.Heads[key]
	existing, found, err := n.loadTMLDSAReshareConsistencyStateFileLocked(sessionID, dealerID, password)
	if err != nil {
		return err
	}
	if hasHead {
		if !found || existing.EventCount() < head.EventCount {
			return fmt.Errorf("TMLDSA reshare consistency state is behind ledger head")
		}
		prefixDigest, err := existing.TranscriptDigestAt(head.EventCount)
		if err != nil || prefixDigest != head.Digest {
			return fmt.Errorf("TMLDSA reshare consistency ledger ancestry mismatch")
		}
		if err := coordinator.ValidateExtension(existing); err != nil {
			return err
		}
	} else {
		if found {
			return fmt.Errorf("TMLDSA reshare consistency state exists without ledger head")
		}
		if coordinator.EventCount() != 0 {
			return fmt.Errorf("TMLDSA reshare consistency state is missing initial ancestry")
		}
	}

	if found && existing.EventCount() == coordinator.EventCount() &&
		existing.TranscriptDigest() == coordinator.TranscriptDigest() {
		ledger.Heads[key] = tmldsaReshareConsistencyHead{
			EventCount: coordinator.EventCount(),
			Digest:     coordinator.TranscriptDigest(),
		}
		return n.persistTMLDSAReshareConsistencyLedgerLocked(ledger, password)
	}

	encrypted, err := tmldsaEncryptPersistenceBlob(encoded, password)
	if err != nil {
		return err
	}
	if err := writeTMLDSAEncryptedFile(n.tmldsaReshareConsistencyStatePath(sessionID, dealerID), encrypted); err != nil {
		return err
	}
	ledger.Heads[key] = tmldsaReshareConsistencyHead{
		EventCount: coordinator.EventCount(),
		Digest:     coordinator.TranscriptDigest(),
	}
	return n.persistTMLDSAReshareConsistencyLedgerLocked(ledger, password)
}

func (n *Node) loadTMLDSAReshareConsistencyState(
	sessionID [32]byte,
	dealerID uint32,
) (*protocolmldsa65.ReshareConsistencyCoordinator, bool, error) {
	if n.tmldsaReshareConsistencyStatePath(sessionID, dealerID) == "" {
		return nil, false, fmt.Errorf("TMLDSA reshare consistency journal is not configured")
	}
	password, err := n.getTSSPassword()
	if err != nil {
		return nil, false, err
	}
	defer qtd.SecurelyZeroMemory(password)

	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	coordinator, found, err := n.loadTMLDSAReshareConsistencyStateFileLocked(sessionID, dealerID, password)
	if err != nil || !found {
		return nil, found, err
	}
	ledger, err := n.loadTMLDSAReshareConsistencyLedgerLocked(password)
	if err != nil {
		return nil, false, err
	}
	head, ok := ledger.Heads[tmldsaReshareConsistencyStateKey(sessionID, dealerID)]
	if !ok || head.EventCount != coordinator.EventCount() || head.Digest != coordinator.TranscriptDigest() {
		return nil, false, fmt.Errorf("TMLDSA reshare consistency state and ledger disagree")
	}
	return coordinator, true, nil
}

func (n *Node) loadTMLDSAReshareConsistencyStateFileLocked(
	sessionID [32]byte,
	dealerID uint32,
	password []byte,
) (*protocolmldsa65.ReshareConsistencyCoordinator, bool, error) {
	encrypted, err := os.ReadFile(n.tmldsaReshareConsistencyStatePath(sessionID, dealerID))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	plaintext, err := tmldsaDecryptPersistenceBlob(encrypted, password)
	if err != nil {
		return nil, false, err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	coordinator, err := protocolmldsa65.UnmarshalReshareConsistencyCoordinator(plaintext)
	if err != nil {
		return nil, false, err
	}
	encodedSessionID, encodedDealerID, err := tmldsaReshareConsistencyIdentity(plaintext)
	if err != nil {
		return nil, false, err
	}
	if encodedSessionID != sessionID || encodedDealerID != dealerID {
		return nil, false, fmt.Errorf("TMLDSA reshare consistency path mismatch")
	}
	return coordinator, true, nil
}

func (n *Node) loadTMLDSAReshareConsistencyLedgerLocked(password []byte) (*tmldsaReshareConsistencyLedger, error) {
	encrypted, err := os.ReadFile(n.tmldsaReshareConsistencyLedgerPath())
	if os.IsNotExist(err) {
		return &tmldsaReshareConsistencyLedger{
			Version: tmldsaReshareConsistencyJournalVersion,
			Heads:   make(map[string]tmldsaReshareConsistencyHead),
		}, nil
	}
	if err != nil {
		return nil, err
	}
	plaintext, err := tmldsaDecryptPersistenceBlob(encrypted, password)
	if err != nil {
		return nil, err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	return decodeTMLDSAReshareConsistencyLedger(plaintext)
}

func (n *Node) persistTMLDSAReshareConsistencyLedgerLocked(
	ledger *tmldsaReshareConsistencyLedger,
	password []byte,
) error {
	plaintext, err := encodeTMLDSAReshareConsistencyLedger(ledger)
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	encrypted, err := tmldsaEncryptPersistenceBlob(plaintext, password)
	if err != nil {
		return err
	}
	return writeTMLDSAEncryptedFile(n.tmldsaReshareConsistencyLedgerPath(), encrypted)
}

func tmldsaReshareConsistencyIdentity(encoded []byte) ([32]byte, uint32, error) {
	coordinator, err := protocolmldsa65.UnmarshalReshareConsistencyCoordinator(encoded)
	if err != nil {
		return [32]byte{}, 0, err
	}
	return coordinator.SessionIdentity()
}
