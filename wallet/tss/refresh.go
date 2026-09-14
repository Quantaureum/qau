// Quantaureum Node source, version 1.0.0.
package tss

import (
	"crypto/sha256"
	"fmt"

	"github.com/quantaureum/qau/wallet/tss/qtd"
)

func (m *TSSManager) RefreshShares() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.qtdShares) == 0 {
		return ErrRefreshFailed
	}

	if m.qtdPubKey == nil {
		return ErrRefreshFailed
	}

	participantIDs := make([]int, 0, len(m.qtdShares))
	for id := range m.qtdShares {
		participantIDs = append(participantIDs, id)
	}

	oldShares := make([]*qtd.QTDShare, 0, len(m.qtdShares))
	for _, id := range participantIDs {
		oldShares = append(oldShares, m.qtdShares[id])
	}

	allDeltas := make([]*qtd.RefreshDeltas, len(participantIDs))
	for i, id := range participantIDs {
		deltas, err := qtd.GenerateRefreshDeltas(id, participantIDs, qtd.Dilithium3L, qtd.Dilithium3K, qtd.Dilithium3K)
		if err != nil {
			return fmt.Errorf("%w: delta generation failed for participant %d: %v", ErrRefreshFailed, id, err)
		}
		allDeltas[i] = deltas
	}

	updatedShares, err := qtd.ApplyRefreshDeltas(oldShares, allDeltas)
	if err != nil {
		return fmt.Errorf("%w: apply deltas failed: %v", ErrRefreshFailed, err)
	}

	if err := qtd.VerifySecretPreservation(oldShares, updatedShares); err != nil {
		return fmt.Errorf("%w: secret preservation check failed: %v", ErrRefreshFailed, err)
	}

	// R47-QP-04/QP-06 FIX: Zero old share material before replacing maps.
	for _, share := range m.qtdShares {
		if share != nil {
			share.Zeroize()
		}
	}
	for _, commit := range m.shareCommitments {
		for i := range commit {
			commit[i] = 0
		}
	}
	for _, commit := range m.fullShareCommitments {
		for i := range commit {
			commit[i] = 0
		}
	}
	// Also zero the oldShares slice copies (they reference the same objects,
	// but Zeroize is idempotent).
	for _, s := range oldShares {
		if s != nil {
			s.Zeroize()
		}
	}

	m.qtdShares = make(map[int]*qtd.QTDShare, len(updatedShares))
	m.shareCommitments = make(map[int][]byte, len(updatedShares))
	m.fullShareCommitments = make(map[int][]byte, len(updatedShares))
	for _, s := range updatedShares {
		m.qtdShares[s.ParticipantID] = s
		h := sha256.Sum256(s.S1ShareBytes)
		m.shareCommitments[s.ParticipantID] = h[:]
		m.fullShareCommitments[s.ParticipantID] = computeFullShareCommitment(s)
	}

	return nil
}

// AddShare is a deprecated stub that always returns an error.
// R48-QP-08 FIX: Marked as deprecated. Use AddParticipant instead for QTD
// threshold signing. Kept for interface compatibility.
//
// Deprecated: Use AddParticipant.
func (m *TSSManager) AddShare(shareData []byte) (*KeyShare, error) {
	return nil, fmt.Errorf("%w: use AddParticipant instead for QTD threshold signing", ErrRefreshFailed)
}

func (m *TSSManager) AddParticipant(newParticipantID int) ([]*KeyShare, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.qtdShares) == 0 {
		return nil, ErrRefreshFailed
	}
	if m.qtdPubKey == nil {
		return nil, ErrRefreshFailed
	}

	existingShares := make([]*qtd.QTDShare, 0, len(m.qtdShares))
	for _, s := range m.qtdShares {
		existingShares = append(existingShares, s)
	}

	newShares, err := qtd.AddParticipant(existingShares, newParticipantID, m.config.Threshold, m.qtdPubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: add participant failed: %v", ErrRefreshFailed, err)
	}

	// R48-P1-01 FIX: Zero old share material before replacing maps.
	for _, share := range m.qtdShares {
		if share != nil {
			share.Zeroize()
		}
	}
	for _, commit := range m.shareCommitments {
		for i := range commit {
			commit[i] = 0
		}
	}
	for _, commit := range m.fullShareCommitments {
		for i := range commit {
			commit[i] = 0
		}
	}

	m.config.TotalShares = len(newShares)
	m.qtdShares = make(map[int]*qtd.QTDShare, len(newShares))
	m.shareCommitments = make(map[int][]byte, len(newShares))
	m.fullShareCommitments = make(map[int][]byte, len(newShares))

	result := make([]*KeyShare, len(newShares))
	for i, s := range newShares {
		m.qtdShares[s.ParticipantID] = s
		h := sha256.Sum256(s.S1ShareBytes)
		m.shareCommitments[s.ParticipantID] = h[:]
		m.fullShareCommitments[s.ParticipantID] = computeFullShareCommitment(s)
		result[i] = &KeyShare{
			Index:              s.ParticipantID,
			Share:              s.S1ShareBytes,
			PublicKey:          m.groupPubKey,
			VerificationVector: s.VVector,
		}
	}

	return result, nil
}

func (m *TSSManager) RemoveShare(index int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.qtdShares[index]; !ok {
		return ErrShareNotFound
	}

	remainingAfterRemove := len(m.qtdShares) - 1
	if remainingAfterRemove < m.config.Threshold {
		return ErrCannotRemoveShare
	}

	existingShares := make([]*qtd.QTDShare, 0, len(m.qtdShares))
	for _, s := range m.qtdShares {
		existingShares = append(existingShares, s)
	}

	newShares, err := qtd.RemoveParticipant(existingShares, index, m.config.Threshold, m.qtdPubKey)
	if err != nil {
		return fmt.Errorf("%w: remove participant failed: %v", ErrRefreshFailed, err)
	}

	// R48-P1-01 FIX: Zero old share material before replacing maps.
	for _, share := range m.qtdShares {
		if share != nil {
			share.Zeroize()
		}
	}
	for _, commit := range m.shareCommitments {
		for i := range commit {
			commit[i] = 0
		}
	}
	for _, commit := range m.fullShareCommitments {
		for i := range commit {
			commit[i] = 0
		}
	}

	m.config.TotalShares = len(newShares)
	m.qtdShares = make(map[int]*qtd.QTDShare, len(newShares))
	m.shareCommitments = make(map[int][]byte, len(newShares))
	m.fullShareCommitments = make(map[int][]byte, len(newShares))

	for _, s := range newShares {
		m.qtdShares[s.ParticipantID] = s
		h := sha256.Sum256(s.S1ShareBytes)
		m.shareCommitments[s.ParticipantID] = h[:]
		m.fullShareCommitments[s.ParticipantID] = computeFullShareCommitment(s)
	}

	return nil
}
