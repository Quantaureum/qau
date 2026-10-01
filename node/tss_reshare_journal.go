// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/quantaureum/qau/wallet/tss"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

const reshareJournalMagic = "QRESHARE01"
const reshareJournalVersion = 1

type reshareJournalRecord struct {
	Version   int                   `json:"v"`
	Kind      string                `json:"k"`
	SessionID []byte                `json:"s"`
	Messages  []*reshareWireMessage `json:"m"`
}

func (n *Node) reshareJournalSessionDir(sessionID []byte) string {
	if n == nil || n.config == nil || n.config.TSSKeyShareFile == "" {
		return ""
	}
	return filepath.Join(n.config.TSSKeyShareFile+".reshare", hex.EncodeToString(sessionID))
}

func normalizeJournalMessages(messages []*reshareWireMessage) ([]*reshareWireMessage, error) {
	normalized := make([]*reshareWireMessage, 0, len(messages))
	for _, message := range messages {
		if message == nil || message.Contribution == nil || message.Acknowledgement || len(message.SessionID) != 32 {
			return nil, fmt.Errorf("invalid reshare journal message")
		}
		copyMessage := *message
		copyMessage.Attempt = 0
		copyMessage.SessionID = append([]byte(nil), message.SessionID...)
		copyMessage.OldParticipants = append([]int(nil), message.OldParticipants...)
		copyMessage.NewParticipants = append([]int(nil), message.NewParticipants...)
		copyMessage.GroupPublicKeyData = append([]byte(nil), message.GroupPublicKeyData...)
		copyContribution := *message.Contribution
		copyContribution.S1SubShare = append([]byte(nil), message.Contribution.S1SubShare...)
		copyContribution.S2SubShare = append([]byte(nil), message.Contribution.S2SubShare...)
		copyContribution.T0SubShare = append([]byte(nil), message.Contribution.T0SubShare...)
		copyMessage.Contribution = &copyContribution
		normalized = append(normalized, &copyMessage)
	}
	sort.Slice(normalized, func(left, right int) bool {
		if normalized[left].FromParticipant != normalized[right].FromParticipant {
			return normalized[left].FromParticipant < normalized[right].FromParticipant
		}
		return normalized[left].ToParticipant < normalized[right].ToParticipant
	})
	return normalized, nil
}

func encodeReshareJournalRecord(record *reshareJournalRecord) ([]byte, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	return append([]byte(reshareJournalMagic), data...), nil
}

func decodeReshareJournalRecord(data []byte) (*reshareJournalRecord, error) {
	if !bytes.HasPrefix(data, []byte(reshareJournalMagic)) {
		return nil, fmt.Errorf("invalid reshare journal magic")
	}
	var record reshareJournalRecord
	if err := json.Unmarshal(data[len(reshareJournalMagic):], &record); err != nil {
		return nil, err
	}
	if record.Version != reshareJournalVersion || (record.Kind != "outbound" && record.Kind != "inbound") || len(record.SessionID) != 32 {
		return nil, fmt.Errorf("invalid reshare journal record")
	}
	normalized, err := normalizeJournalMessages(record.Messages)
	if err != nil || len(normalized) == 0 {
		return nil, fmt.Errorf("invalid reshare journal messages")
	}
	record.Messages = normalized
	for _, message := range record.Messages {
		if !bytes.Equal(message.SessionID, record.SessionID) {
			return nil, fmt.Errorf("reshare journal session mismatch")
		}
	}
	return &record, nil
}

func (n *Node) persistOutboundReshareMessages(sessionID []byte, messages []*reshareWireMessage) error {
	return n.persistReshareJournalRecord("outbound", sessionID, messages, "outbound.enc")
}

func (n *Node) persistInboundReshareMessage(message *reshareWireMessage) error {
	if message == nil {
		return fmt.Errorf("nil inbound reshare message")
	}
	name := fmt.Sprintf("inbound-%08d.enc", message.FromParticipant)
	return n.persistReshareJournalRecord("inbound", message.SessionID, []*reshareWireMessage{message}, name)
}

func (n *Node) persistReshareJournalRecord(kind string, sessionID []byte, messages []*reshareWireMessage, name string) error {
	if len(sessionID) != 32 || (kind != "outbound" && kind != "inbound") {
		return fmt.Errorf("invalid reshare journal binding")
	}
	normalized, err := normalizeJournalMessages(messages)
	if err != nil || len(normalized) == 0 {
		return fmt.Errorf("normalize reshare journal: %w", err)
	}
	for _, message := range normalized {
		if !bytes.Equal(message.SessionID, sessionID) {
			return fmt.Errorf("reshare journal session mismatch")
		}
	}
	record := &reshareJournalRecord{Version: reshareJournalVersion, Kind: kind, SessionID: append([]byte(nil), sessionID...), Messages: normalized}
	plaintext, err := encodeReshareJournalRecord(record)
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(plaintext)

	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	directory := n.reshareJournalSessionDir(sessionID)
	if directory == "" {
		return fmt.Errorf("TSS reshare journal is not configured")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	path := filepath.Join(directory, name)
	password, err := n.getTSSPassword()
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(password)
	if existing, readErr := os.ReadFile(path); readErr == nil {
		decrypted, decryptErr := tss.DecryptSingleShareBlob(existing, password)
		if decryptErr != nil {
			return fmt.Errorf("decrypt existing reshare journal: %w", decryptErr)
		}
		defer qtd.SecurelyZeroMemory(decrypted)
		if !bytes.Equal(decrypted, plaintext) {
			return fmt.Errorf("conflicting durable reshare contribution")
		}
		return nil
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	encrypted, err := tss.EncryptSingleShareBlob(plaintext, password)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".reshare-journal-*")
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

func (n *Node) loadReshareJournal(sessionID []byte) (outbound, inbound []*reshareWireMessage, err error) {
	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	directory := n.reshareJournalSessionDir(sessionID)
	if directory == "" {
		return nil, nil, fmt.Errorf("TSS reshare journal is not configured")
	}
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if len(entries) > maxPendingReshareMessages+1 {
		return nil, nil, fmt.Errorf("too many reshare journal records")
	}
	password, err := n.getTSSPassword()
	if err != nil {
		return nil, nil, err
	}
	defer qtd.SecurelyZeroMemory(password)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".enc") {
			return nil, nil, fmt.Errorf("invalid reshare journal entry %q", entry.Name())
		}
		encrypted, readErr := os.ReadFile(filepath.Join(directory, entry.Name()))
		if readErr != nil {
			return nil, nil, readErr
		}
		plaintext, decryptErr := tss.DecryptSingleShareBlob(encrypted, password)
		if decryptErr != nil {
			return nil, nil, decryptErr
		}
		record, decodeErr := decodeReshareJournalRecord(plaintext)
		qtd.SecurelyZeroMemory(plaintext)
		if decodeErr != nil {
			return nil, nil, decodeErr
		}
		if !bytes.Equal(record.SessionID, sessionID) {
			return nil, nil, fmt.Errorf("reshare journal directory binding mismatch")
		}
		if record.Kind == "outbound" {
			if entry.Name() != "outbound.enc" {
				return nil, nil, fmt.Errorf("outbound reshare journal filename mismatch")
			}
			if len(outbound) != 0 {
				return nil, nil, fmt.Errorf("duplicate outbound reshare journal")
			}
			outbound = append(outbound, record.Messages...)
		} else {
			if len(record.Messages) != 1 {
				return nil, nil, fmt.Errorf("invalid inbound reshare journal")
			}
			expectedName := fmt.Sprintf("inbound-%08d.enc", record.Messages[0].FromParticipant)
			if entry.Name() != expectedName {
				return nil, nil, fmt.Errorf("inbound reshare journal filename mismatch")
			}
			inbound = append(inbound, record.Messages[0])
		}
	}
	sort.Slice(inbound, func(left, right int) bool { return inbound[left].FromParticipant < inbound[right].FromParticipant })
	return outbound, inbound, nil
}

func (n *Node) cleanupReshareJournal(sessionID []byte) error {
	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	directory := n.reshareJournalSessionDir(sessionID)
	if directory == "" {
		return fmt.Errorf("TSS reshare journal is not configured")
	}
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return fmt.Errorf("unexpected directory in reshare journal")
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
			return err
		}
	}
	if err := os.Remove(directory); err != nil {
		return err
	}
	base := filepath.Dir(directory)
	if remaining, readErr := os.ReadDir(base); readErr == nil && len(remaining) == 0 {
		_ = os.Remove(base)
	}
	return nil
}
