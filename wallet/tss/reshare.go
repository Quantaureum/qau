// Quantaureum Node source, version 1.0.0.
package tss

import (
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// ParticipantIDs returns the active share set used by distributed signing.
// A distributed node stores only its local share, so this list is persisted in
// manager state separately from qtdShares.
func (m *TSSManager) ParticipantIDs() []int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := append([]int(nil), m.participantIDs...)
	if len(ids) == 0 {
		ids = make([]int, m.config.TotalShares)
		for i := range ids {
			ids[i] = i + 1
		}
	}
	sort.Ints(ids)
	return ids
}

// GroupPublicKeyData returns the canonical public-key export used to bootstrap
// a late-joining validator before it receives its first private share.
func (m *TSSManager) GroupPublicKeyData() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.exportGroupPublicKeyUnlocked()
}

// PrepareReshare generates this node's private contribution for an epoch
// reshare. The contribution is a Shamir sub-share of the node's current share;
// it is sent only to the designated recipient.
func (m *TSSManager) PrepareReshare(participantID int, newParticipantIDs []int, newThreshold int) ([]*qtd.SubShare, error) {
	if participantID <= 0 || len(newParticipantIDs) == 0 || newThreshold <= 0 || newThreshold > len(newParticipantIDs) {
		return nil, fmt.Errorf("invalid reshare configuration")
	}

	m.mu.RLock()
	share, ok := m.qtdShares[participantID]
	if !ok || share == nil {
		// A holder that already parked its share (moved out of the committee
		// by an earlier rotation) can still contribute when consensus re-runs
		// a rotation from that generation after a failed attempt.
		share, ok = m.retiredShares[participantID]
	}
	if ok && share != nil {
		shareCopy := *share
		shareCopy.Rho = append([]byte(nil), share.Rho...)
		shareCopy.S1ShareBytes = append([]byte(nil), share.S1ShareBytes...)
		shareCopy.S2ShareBytes = append([]byte(nil), share.S2ShareBytes...)
		shareCopy.T0ShareBytes = append([]byte(nil), share.T0ShareBytes...)
		share = &shareCopy
	}
	m.mu.RUnlock()
	if !ok || share == nil {
		return nil, fmt.Errorf("reshare participant %d: local share not found", participantID)
	}

	return qtd.GenerateSubShares(participantID, share, newParticipantIDs, newThreshold)
}

// InstallResharedShare combines only the contributions addressed to this
// validator and atomically replaces its old share set. The group public key is
// preserved: resharing changes who holds shares, not the signing key.
func (m *TSSManager) InstallResharedShare(
	participantID int,
	newParticipantIDs []int,
	newThreshold int,
	oldParticipantIDs []int,
	contributions []*qtd.SubShare,
	groupPublicKeyData []byte,
) error {
	if !containsParticipant(newParticipantIDs, participantID) {
		return fmt.Errorf("participant %d is not in the new share set", participantID)
	}
	if newThreshold < 2 || newThreshold > len(newParticipantIDs) {
		return fmt.Errorf("invalid reshare threshold %d for %d participants", newThreshold, len(newParticipantIDs))
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.qtdPubKey == nil && len(groupPublicKeyData) > 0 {
		if err := m.importGroupPublicKeyUnlocked(groupPublicKeyData); err != nil {
			return fmt.Errorf("import reshare group public key: %w", err)
		}
	}
	if m.qtdPubKey == nil {
		return fmt.Errorf("reshare group public key is not available")
	}

	newShare, err := qtd.CombineSubShareForParticipant(
		contributions,
		participantID,
		newThreshold,
		oldParticipantIDs,
		m.qtdPubKey,
	)
	if err != nil {
		return fmt.Errorf("combine reshare contributions: %w", err)
	}

	m.retirePreviousGenerationLocked()
	m.qtdShares = map[int]*qtd.QTDShare{participantID: newShare}
	m.participantIDs = append([]int(nil), newParticipantIDs...)
	sort.Ints(m.participantIDs)
	m.config.Threshold = newThreshold
	m.config.TotalShares = len(newParticipantIDs)
	m.shareCommitments = make(map[int][]byte, 1)
	m.fullShareCommitments = make(map[int][]byte, 1)
	s1Commitment := sha256.Sum256(newShare.S1ShareBytes)
	m.shareCommitments[participantID] = s1Commitment[:]
	m.fullShareCommitments[participantID] = computeFullShareCommitment(newShare)
	m.groupPubKey = append(m.groupPubKey[:0], m.qtdPubKey.PubKey...)
	return nil
}

// RetireResharedShare parks this node's private share after it has delivered
// its contribution and was not selected for the new committee. The node stops
// signing with it immediately; the public key and the new holder set remain
// available for verification and future reshare rounds.
func (m *TSSManager) RetireResharedShare(newParticipantIDs []int, newThreshold int) error {
	if len(newParticipantIDs) == 0 || newThreshold < 2 || newThreshold > len(newParticipantIDs) {
		return fmt.Errorf("invalid retired reshare configuration")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.retirePreviousGenerationLocked()
	m.qtdShares = make(map[int]*qtd.QTDShare)
	m.participantIDs = append([]int(nil), newParticipantIDs...)
	sort.Ints(m.participantIDs)
	m.config.Threshold = newThreshold
	m.config.TotalShares = len(newParticipantIDs)
	m.shareCommitments = make(map[int][]byte)
	m.fullShareCommitments = make(map[int][]byte)
	return nil
}

// retirePreviousGenerationLocked parks the current share generation in
// retiredShares and zeroizes the generation that was parked before it, so at
// most one previous generation is ever kept.
//
// Why the old share is not destroyed immediately: a rotation is one-shot and
// unacknowledged, so an old holder cannot tell whether every new holder
// combined its contribution. Destroying the old generation on send would turn
// a transient delivery failure into permanent loss of the group key. Keeping
// exactly one previous generation, never used for signing, keeps the key
// recoverable by re-running the rotation from that generation. Acknowledged
// retirement (zeroize once the new holders confirm) is the remaining
// hardening step for the proactive-security guarantee.
func (m *TSSManager) retirePreviousGenerationLocked() {
	for _, share := range m.retiredShares {
		if share != nil {
			share.Zeroize()
		}
	}
	m.retiredShares = make(map[int]*qtd.QTDShare, len(m.qtdShares))
	for id, share := range m.qtdShares {
		if share != nil {
			m.retiredShares[id] = share
		}
	}
}

// ActiveParticipantIDs returns the holder set this manager learned from a DKG
// or reshare, without the 1..TotalShares fallback that ParticipantIDs applies
// for legacy single-process configurations. ok is false when no holder set
// has been established yet.
func (m *TSSManager) ActiveParticipantIDs() ([]int, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.participantIDs) == 0 {
		return nil, false
	}
	ids := append([]int(nil), m.participantIDs...)
	sort.Ints(ids)
	return ids, true
}

func containsParticipant(ids []int, participantID int) bool {
	for _, id := range ids {
		if id == participantID {
			return true
		}
	}
	return false
}
