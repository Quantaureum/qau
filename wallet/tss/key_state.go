// Quantaureum Node source, version 1.0.0.
package tss

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/quantaureum/qau/wallet/tss/qtd"
)

const keyStateMagic = "QTSSSTATE02"
const maxKeyStateBytes = 128 << 20

func (m *TSSManager) exportKeyStateLocked() ([]byte, error) {
	if err := m.config.Validate(); err != nil {
		return nil, err
	}
	if m.qtdPubKey == nil {
		return nil, fmt.Errorf("no key shares available")
	}
	participants := append([]int(nil), m.participantIDs...)
	if len(participants) == 0 {
		for participant := 1; participant <= m.config.TotalShares; participant++ {
			participants = append(participants, participant)
		}
	}
	sort.Ints(participants)
	publicKey, err := m.exportGroupPublicKeyUnlocked()
	if err != nil {
		return nil, err
	}
	data := []byte(keyStateMagic)
	data = binary.BigEndian.AppendUint32(data, uint32(m.config.Threshold))
	data = binary.BigEndian.AppendUint32(data, uint32(len(participants)))
	for _, participant := range participants {
		data = binary.BigEndian.AppendUint32(data, uint32(participant))
	}
	data = binary.BigEndian.AppendUint32(data, uint32(len(publicKey)))
	data = append(data, publicKey...)
	for _, generation := range []map[int]*qtd.QTDShare{m.qtdShares, m.retiredShares} {
		ids := make([]int, 0, len(generation))
		for participant := range generation {
			ids = append(ids, participant)
		}
		sort.Ints(ids)
		data = binary.BigEndian.AppendUint32(data, uint32(len(ids)))
		for _, participant := range ids {
			if generation[participant] == nil {
				qtd.SecurelyZeroMemory(data)
				return nil, fmt.Errorf("nil share for participant %d", participant)
			}
			encoded := generation[participant].Encode()
			data = binary.BigEndian.AppendUint32(data, uint32(len(encoded)))
			data = append(data, encoded...)
			qtd.SecurelyZeroMemory(encoded)
		}
	}
	if len(data) > maxKeyStateBytes {
		qtd.SecurelyZeroMemory(data)
		return nil, fmt.Errorf("key state exceeds maximum size")
	}
	return data, nil
}

func (m *TSSManager) importKeyState(data []byte) error {
	reader := bytes.NewReader(data[len(keyStateMagic):])
	readUint := func() (int, error) {
		var value uint32
		err := binary.Read(reader, binary.BigEndian, &value)
		return int(value), err
	}
	readBytes := func(limit int) ([]byte, error) {
		length, err := readUint()
		if err != nil || length < 1 || length > limit || length > reader.Len() {
			return nil, fmt.Errorf("invalid key-state field length")
		}
		field := make([]byte, length)
		_, err = io.ReadFull(reader, field)
		return field, err
	}
	threshold, err := readUint()
	if err != nil {
		return err
	}
	total, err := readUint()
	if err != nil || total < 1 || total > MaxTotalShares || threshold < 2 || threshold > total || threshold > MaxThreshold {
		return fmt.Errorf("invalid key-state threshold or holder count")
	}
	participants := make([]int, total)
	for index := range participants {
		participant, err := readUint()
		if err != nil || participant < 1 || participant >= qtd.Q || (index > 0 && participant <= participants[index-1]) {
			return fmt.Errorf("invalid key-state participant")
		}
		participants[index] = participant
	}
	publicKey, err := readBytes(4096)
	if err != nil {
		return err
	}
	if err := m.importGroupPublicKeyUnlocked(publicKey); err != nil {
		return err
	}
	for generationIndex, generation := range []map[int]*qtd.QTDShare{m.qtdShares, m.retiredShares} {
		count, err := readUint()
		if err != nil || count > maxImportShareCountLimit() {
			return fmt.Errorf("invalid key-state share count")
		}
		for index := 0; index < count; index++ {
			encoded, err := readBytes(1 << 20)
			if err != nil {
				return err
			}
			share, err := qtd.DecodeQTDShare(encoded)
			qtd.SecurelyZeroMemory(encoded)
			if err != nil {
				return err
			}
			if generation[share.ParticipantID] != nil || share.ParticipantID >= qtd.Q ||
				(generationIndex == 0 && !containsParticipant(participants, share.ParticipantID)) ||
				!bytes.Equal(share.Rho, m.qtdPubKey.Rho) {
				share.Zeroize()
				return fmt.Errorf("key-state share does not match holder set or group key")
			}
			generation[share.ParticipantID] = share
		}
	}
	if reader.Len() != 0 {
		return fmt.Errorf("invalid trailing key-state data")
	}
	m.config.Threshold, m.config.TotalShares = threshold, total
	m.participantIDs = participants
	for participant, share := range m.qtdShares {
		commitment := sha256.Sum256(share.S1ShareBytes)
		m.shareCommitments[participant] = commitment[:]
		m.fullShareCommitments[participant] = computeFullShareCommitment(share)
	}
	return nil
}

func (m *TSSManager) ImportKeyShares(data []byte) error {
	if len(data) > maxKeyStateBytes {
		return fmt.Errorf("key state exceeds maximum size")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.activeSessions) != 0 || m.dkgInProgress {
		return fmt.Errorf("cannot replace key state during signing or DKG")
	}
	staged := &TSSManager{
		config:    m.config,
		qtdShares: make(map[int]*qtd.QTDShare), retiredShares: make(map[int]*qtd.QTDShare),
		shareCommitments: make(map[int][]byte), fullShareCommitments: make(map[int][]byte),
	}
	var err error
	if bytes.HasPrefix(data, []byte(keyStateMagic)) {
		err = staged.importKeyState(data)
	} else {
		err = staged.importLegacyKeyShares(data)
	}
	if err != nil {
		staged.ZeroizeAllShares()
		return err
	}
	for _, generation := range []map[int]*qtd.QTDShare{m.qtdShares, m.retiredShares} {
		for _, share := range generation {
			if share != nil {
				share.Zeroize()
			}
		}
	}
	m.qtdShares, m.retiredShares = staged.qtdShares, staged.retiredShares
	m.participantIDs = staged.participantIDs
	m.config.Threshold, m.config.TotalShares = staged.config.Threshold, staged.config.TotalShares
	m.shareCommitments, m.fullShareCommitments = staged.shareCommitments, staged.fullShareCommitments
	if staged.qtdPubKey != nil {
		m.qtdPubKey, m.groupPubKey = staged.qtdPubKey, staged.groupPubKey
	}
	return nil
}
