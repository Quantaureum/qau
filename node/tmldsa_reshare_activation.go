// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/quantaureum/qau/wallet/tss/protocol"
	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

const (
	tmldsaReshareActivationVersion   = 1
	tmldsaReshareCandidateMagic      = "QTMLDSA-RESHARE-CANDIDATE-1"
	tmldsaReshareActivePointerMagic  = "QTMLDSA-RESHARE-ACTIVE-1"
	tmldsaReshareActivationFileLimit = 1 << 20
)

type tmldsaReshareTranscriptHead struct {
	DealerID uint32   `json:"dealer_id"`
	Digest   [32]byte `json:"digest"`
}

type tmldsaReshareActivationCandidate struct {
	Version           int                           `json:"version"`
	SessionID         [32]byte                      `json:"session_id"`
	ActivationEpoch   uint64                        `json:"activation_epoch"`
	Key               protocol.ThresholdKeyID       `json:"key"`
	OldCommittee      protocol.CommitteeID          `json:"old_committee"`
	NewCommittee      protocol.CommitteeID          `json:"new_committee"`
	SelectedDealers   []uint32                      `json:"selected_dealers"`
	ParticipantID     uint32                        `json:"participant_id"`
	TranscriptHeads   []tmldsaReshareTranscriptHead `json:"transcript_heads"`
	ShareEncoding     []byte                        `json:"share_encoding"`
	ShareCommitment   [32]byte                      `json:"share_commitment"`
	ContributionHeads [][32]byte                    `json:"contribution_heads"`
}

type tmldsaReshareActivePointer struct {
	Version           int      `json:"version"`
	SessionID         [32]byte `json:"session_id"`
	ActivationEpoch   uint64   `json:"activation_epoch"`
	KeyGeneration     uint64   `json:"key_generation"`
	CommitteeVersion  uint64   `json:"committee_version"`
	ParticipantID     uint32   `json:"participant_id"`
	CandidateDigest   [32]byte `json:"candidate_digest"`
	CertificateDigest [32]byte `json:"certificate_digest"`
}

func (n *Node) tmldsaReshareCandidatePath(sessionID [32]byte, participantID uint32) string {
	base := n.tmldsaSigningBaseDir()
	if base == "" || sessionID == ([32]byte{}) || participantID == 0 {
		return ""
	}
	return filepath.Join(
		base,
		"reshare",
		hex.EncodeToString(sessionID[:]),
		fmt.Sprintf("candidate-%08d.enc", participantID),
	)
}

func (n *Node) tmldsaActiveSharePointerPath() string {
	base := n.tmldsaSigningBaseDir()
	if base == "" {
		return ""
	}
	return filepath.Join(base, "generations", "active.enc")
}

func (candidate tmldsaReshareActivationCandidate) validate() (*protocolmldsa65.LocalShare, error) {
	if candidate.Version != tmldsaReshareActivationVersion ||
		candidate.SessionID == ([32]byte{}) || candidate.ActivationEpoch == 0 || candidate.ParticipantID == 0 {
		return nil, fmt.Errorf("invalid TMLDSA reshare activation metadata")
	}
	if err := protocol.DefaultTMLDSAV1Profile().ValidateTransition(candidate.OldCommittee, candidate.NewCommittee); err != nil {
		return nil, err
	}
	if len(candidate.SelectedDealers) != int(protocol.TMLDSAV1Threshold) ||
		len(candidate.TranscriptHeads) != len(candidate.SelectedDealers) ||
		len(candidate.ContributionHeads) != len(candidate.SelectedDealers) ||
		len(candidate.ShareEncoding) == 0 || len(candidate.ShareEncoding) > tmldsaReshareActivationFileLimit {
		return nil, fmt.Errorf("invalid TMLDSA reshare activation evidence")
	}
	for index, dealerID := range candidate.SelectedDealers {
		if dealerID == 0 || candidate.TranscriptHeads[index].DealerID != dealerID ||
			candidate.TranscriptHeads[index].Digest == ([32]byte{}) ||
			candidate.ContributionHeads[index] == ([32]byte{}) ||
			(index > 0 && candidate.SelectedDealers[index-1] >= dealerID) {
			return nil, fmt.Errorf("invalid TMLDSA reshare activation dealer evidence")
		}
	}
	share, err := protocolmldsa65.UnmarshalLocalShare(candidate.ShareEncoding)
	if err != nil {
		return nil, err
	}
	if err := share.ValidateIdentity(candidate.Key, candidate.NewCommittee, candidate.ParticipantID); err != nil {
		share.Zeroize()
		return nil, err
	}
	if share.Commitment() != candidate.ShareCommitment {
		share.Zeroize()
		return nil, fmt.Errorf("TMLDSA reshare activation share commitment mismatch")
	}
	return share, nil
}

func encodeTMLDSAReshareActivationCandidate(candidate tmldsaReshareActivationCandidate) ([]byte, error) {
	share, err := candidate.validate()
	if err != nil {
		return nil, err
	}
	share.Zeroize()
	payload, err := json.Marshal(candidate)
	if err != nil {
		return nil, err
	}
	if len(payload)+len(tmldsaReshareCandidateMagic) > tmldsaReshareActivationFileLimit {
		return nil, fmt.Errorf("TMLDSA reshare candidate exceeds size limit")
	}
	return append([]byte(tmldsaReshareCandidateMagic), payload...), nil
}

func decodeTMLDSAReshareActivationCandidate(payload []byte) (tmldsaReshareActivationCandidate, *protocolmldsa65.LocalShare, error) {
	if len(payload) > tmldsaReshareActivationFileLimit || !bytes.HasPrefix(payload, []byte(tmldsaReshareCandidateMagic)) {
		return tmldsaReshareActivationCandidate{}, nil, fmt.Errorf("invalid TMLDSA reshare candidate encoding")
	}
	var candidate tmldsaReshareActivationCandidate
	if err := json.Unmarshal(payload[len(tmldsaReshareCandidateMagic):], &candidate); err != nil {
		return tmldsaReshareActivationCandidate{}, nil, err
	}
	share, err := candidate.validate()
	if err != nil {
		return tmldsaReshareActivationCandidate{}, nil, err
	}
	return candidate, share, nil
}

func encodeTMLDSAReshareActivePointer(pointer tmldsaReshareActivePointer) ([]byte, error) {
	if pointer.Version != tmldsaReshareActivationVersion || pointer.SessionID == ([32]byte{}) ||
		pointer.ActivationEpoch == 0 || pointer.KeyGeneration == 0 || pointer.CommitteeVersion == 0 ||
		pointer.ParticipantID == 0 || pointer.CandidateDigest == ([32]byte{}) ||
		pointer.CertificateDigest == ([32]byte{}) {
		return nil, fmt.Errorf("invalid TMLDSA active share pointer")
	}
	payload, err := json.Marshal(pointer)
	if err != nil {
		return nil, err
	}
	return append([]byte(tmldsaReshareActivePointerMagic), payload...), nil
}

func decodeTMLDSAReshareActivePointer(payload []byte) (tmldsaReshareActivePointer, error) {
	if len(payload) > tmldsaReshareActivationFileLimit || !bytes.HasPrefix(payload, []byte(tmldsaReshareActivePointerMagic)) {
		return tmldsaReshareActivePointer{}, fmt.Errorf("invalid TMLDSA active share pointer encoding")
	}
	var pointer tmldsaReshareActivePointer
	if err := json.Unmarshal(payload[len(tmldsaReshareActivePointerMagic):], &pointer); err != nil {
		return tmldsaReshareActivePointer{}, err
	}
	if _, err := encodeTMLDSAReshareActivePointer(pointer); err != nil {
		return tmldsaReshareActivePointer{}, err
	}
	return pointer, nil
}

func (n *Node) prepareTMLDSAReshareActivation(
	sessionID [32]byte,
	activationEpoch uint64,
	key protocol.ThresholdKeyID,
	oldCommittee protocol.CommitteeID,
	newCommittee protocol.CommitteeID,
	selectedDealers []uint32,
	recipientID uint32,
) (*protocolmldsa65.LocalShare, error) {
	if !experimentalTMLDSAV1Enabled() {
		return nil, fmt.Errorf("experimental TMLDSA v1 is disabled")
	}
	if activationEpoch == 0 || sessionID == ([32]byte{}) {
		return nil, fmt.Errorf("invalid TMLDSA reshare activation target")
	}
	if err := protocol.DefaultTMLDSAV1Profile().ValidateTransition(oldCommittee, newCommittee); err != nil {
		return nil, err
	}
	inbound, found, complete, err := n.loadTMLDSAInboundReshareSet(sessionID, recipientID, selectedDealers)
	if err != nil {
		return nil, err
	}
	if !found || !complete || inbound.KeyGeneration != key.Generation ||
		inbound.OldCommitteeVersion != oldCommittee.Version || inbound.NewCommitteeVersion != newCommittee.Version {
		return nil, fmt.Errorf("TMLDSA reshare contributions are incomplete or mismatched")
	}
	contributions := make([]protocolmldsa65.ReshareContribution, 0, len(selectedDealers))
	transcriptHeads := make([]tmldsaReshareTranscriptHead, 0, len(selectedDealers))
	contributionHeads := make([][32]byte, 0, len(selectedDealers))
	for _, dealerID := range selectedDealers {
		contribution, err := protocolmldsa65.DecodeReshareContribution(
			inbound.Payloads[dealerID],
			key,
			oldCommittee,
			newCommittee,
			selectedDealers,
			dealerID,
			recipientID,
		)
		if err != nil {
			return nil, err
		}
		commitment, err := contribution.Commitment()
		if err != nil {
			return nil, err
		}
		coordinator, found, err := n.loadTMLDSAReshareConsistencyState(sessionID, dealerID)
		if err != nil {
			return nil, err
		}
		if !found || coordinator.Phase() != protocolmldsa65.ReshareConsistencyPhaseVerified {
			return nil, fmt.Errorf("TMLDSA reshare consistency transcript is not verified for dealer %d", dealerID)
		}
		if err := coordinator.ValidateContributionCommitment(recipientID, commitment); err != nil {
			return nil, err
		}
		contributions = append(contributions, contribution)
		transcriptHeads = append(transcriptHeads, tmldsaReshareTranscriptHead{DealerID: dealerID, Digest: coordinator.TranscriptDigest()})
		contributionHeads = append(contributionHeads, commitment)
	}
	share, err := protocolmldsa65.CombineReshareContributions(
		key,
		oldCommittee,
		newCommittee,
		selectedDealers,
		recipientID,
		contributions,
	)
	if err != nil {
		return nil, err
	}
	shareEncoding, err := share.MarshalBinary()
	if err != nil {
		share.Zeroize()
		return nil, err
	}
	candidate := tmldsaReshareActivationCandidate{
		Version:           tmldsaReshareActivationVersion,
		SessionID:         sessionID,
		ActivationEpoch:   activationEpoch,
		Key:               key.Clone(),
		OldCommittee:      oldCommittee.Clone(),
		NewCommittee:      newCommittee.Clone(),
		SelectedDealers:   append([]uint32(nil), selectedDealers...),
		ParticipantID:     recipientID,
		TranscriptHeads:   transcriptHeads,
		ShareEncoding:     shareEncoding,
		ShareCommitment:   share.Commitment(),
		ContributionHeads: contributionHeads,
	}
	if err := n.persistTMLDSAReshareActivationCandidate(candidate); err != nil {
		share.Zeroize()
		return nil, err
	}
	return share, nil
}

func (n *Node) persistTMLDSAReshareActivationCandidate(candidate tmldsaReshareActivationCandidate) error {
	plaintext, err := encodeTMLDSAReshareActivationCandidate(candidate)
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	password, err := n.getTSSPassword()
	if err != nil {
		return err
	}
	defer qtd.SecurelyZeroMemory(password)
	path := n.tmldsaReshareCandidatePath(candidate.SessionID, candidate.ParticipantID)
	if path == "" {
		return fmt.Errorf("TMLDSA reshare activation storage is not configured")
	}
	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	if encrypted, readErr := os.ReadFile(path); readErr == nil {
		existingPlaintext, decryptErr := tmldsaDecryptPersistenceBlob(encrypted, password)
		if decryptErr != nil {
			return decryptErr
		}
		defer qtd.SecurelyZeroMemory(existingPlaintext)
		if !bytes.Equal(existingPlaintext, plaintext) {
			return fmt.Errorf("conflicting TMLDSA reshare activation candidate")
		}
		return nil
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	encrypted, err := tmldsaEncryptPersistenceBlob(plaintext, password)
	if err != nil {
		return err
	}
	return writeTMLDSAEncryptedFile(path, encrypted)
}

func (n *Node) activateTMLDSAReshare(
	sessionID [32]byte,
	activationEpoch uint64,
	key protocol.ThresholdKeyID,
	committee protocol.CommitteeID,
	participantID uint32,
) (*protocolmldsa65.LocalShare, error) {
	if !experimentalTMLDSAV1Enabled() {
		return nil, fmt.Errorf("experimental TMLDSA v1 is disabled")
	}
	password, err := n.getTSSPassword()
	if err != nil {
		return nil, err
	}
	defer qtd.SecurelyZeroMemory(password)
	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	candidate, share, candidatePlaintext, err := n.loadTMLDSAReshareActivationCandidateLocked(sessionID, participantID, password)
	if err != nil {
		return nil, err
	}
	defer qtd.SecurelyZeroMemory(candidatePlaintext)
	if candidate.ActivationEpoch != activationEpoch || candidate.Key.Generation != key.Generation ||
		candidate.NewCommittee.Version != committee.Version || candidate.ParticipantID != participantID {
		share.Zeroize()
		return nil, fmt.Errorf("TMLDSA reshare activation target mismatch")
	}
	if err := share.ValidateIdentity(key, committee, participantID); err != nil {
		share.Zeroize()
		return nil, err
	}
	candidateDigest := sha3.Sum256(candidatePlaintext)
	certificate, found, err := n.loadTMLDSAReshareActivationCertificateLocked(sessionID, password)
	if err != nil {
		share.Zeroize()
		return nil, err
	}
	if !found {
		share.Zeroize()
		return nil, fmt.Errorf("TMLDSA reshare activation certificate is missing")
	}
	if err := validateTMLDSAReshareCertificateCandidate(certificate, candidate, candidateDigest); err != nil {
		share.Zeroize()
		return nil, err
	}
	pointer := tmldsaReshareActivePointer{
		Version:           tmldsaReshareActivationVersion,
		SessionID:         sessionID,
		ActivationEpoch:   activationEpoch,
		KeyGeneration:     key.Generation,
		CommitteeVersion:  committee.Version,
		ParticipantID:     participantID,
		CandidateDigest:   candidateDigest,
		CertificateDigest: certificate.Digest,
	}
	if existing, found, err := n.loadTMLDSAActiveSharePointerLocked(password); err != nil {
		share.Zeroize()
		return nil, err
	} else if found {
		if existing == pointer {
			return share, nil
		}
		if committee.Version <= existing.CommitteeVersion || activationEpoch <= existing.ActivationEpoch {
			share.Zeroize()
			return nil, fmt.Errorf("TMLDSA active share rollback or conflict")
		}
	}
	pointerPlaintext, err := encodeTMLDSAReshareActivePointer(pointer)
	if err != nil {
		share.Zeroize()
		return nil, err
	}
	defer qtd.SecurelyZeroMemory(pointerPlaintext)
	encrypted, err := tmldsaEncryptPersistenceBlob(pointerPlaintext, password)
	if err != nil {
		share.Zeroize()
		return nil, err
	}
	if err := writeTMLDSAEncryptedFile(n.tmldsaActiveSharePointerPath(), encrypted); err != nil {
		share.Zeroize()
		return nil, err
	}
	return share, nil
}

func (n *Node) loadActiveTMLDSAShare() (*protocolmldsa65.LocalShare, bool, error) {
	if n.tmldsaActiveSharePointerPath() == "" {
		return nil, false, fmt.Errorf("TMLDSA active share storage is not configured")
	}
	password, err := n.getTSSPassword()
	if err != nil {
		return nil, false, err
	}
	defer qtd.SecurelyZeroMemory(password)
	n.tssPersistMu.Lock()
	defer n.tssPersistMu.Unlock()
	pointer, found, err := n.loadTMLDSAActiveSharePointerLocked(password)
	if err != nil || !found {
		return nil, found, err
	}
	candidate, share, plaintext, err := n.loadTMLDSAReshareActivationCandidateLocked(pointer.SessionID, pointer.ParticipantID, password)
	if err != nil {
		return nil, false, err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	if sha3.Sum256(plaintext) != pointer.CandidateDigest || candidate.ActivationEpoch != pointer.ActivationEpoch ||
		candidate.Key.Generation != pointer.KeyGeneration || candidate.NewCommittee.Version != pointer.CommitteeVersion {
		share.Zeroize()
		return nil, false, fmt.Errorf("TMLDSA active pointer and candidate disagree")
	}
	certificate, found, err := n.loadTMLDSAReshareActivationCertificateLocked(pointer.SessionID, password)
	if err != nil {
		share.Zeroize()
		return nil, false, err
	}
	if !found || certificate.Digest != pointer.CertificateDigest ||
		validateTMLDSAReshareCertificateCandidate(certificate, candidate, pointer.CandidateDigest) != nil {
		share.Zeroize()
		return nil, false, fmt.Errorf("TMLDSA active pointer and certificate disagree")
	}
	return share, true, nil
}

func (n *Node) loadTMLDSAReshareActivationCandidateLocked(
	sessionID [32]byte,
	participantID uint32,
	password []byte,
) (tmldsaReshareActivationCandidate, *protocolmldsa65.LocalShare, []byte, error) {
	encrypted, err := os.ReadFile(n.tmldsaReshareCandidatePath(sessionID, participantID))
	if err != nil {
		return tmldsaReshareActivationCandidate{}, nil, nil, err
	}
	plaintext, err := tmldsaDecryptPersistenceBlob(encrypted, password)
	if err != nil {
		return tmldsaReshareActivationCandidate{}, nil, nil, err
	}
	candidate, share, err := decodeTMLDSAReshareActivationCandidate(plaintext)
	if err != nil {
		qtd.SecurelyZeroMemory(plaintext)
		return tmldsaReshareActivationCandidate{}, nil, nil, err
	}
	if candidate.SessionID != sessionID || candidate.ParticipantID != participantID {
		share.Zeroize()
		qtd.SecurelyZeroMemory(plaintext)
		return tmldsaReshareActivationCandidate{}, nil, nil, fmt.Errorf("TMLDSA reshare candidate path mismatch")
	}
	return candidate, share, plaintext, nil
}

func (n *Node) loadTMLDSAActiveSharePointerLocked(password []byte) (tmldsaReshareActivePointer, bool, error) {
	encrypted, err := os.ReadFile(n.tmldsaActiveSharePointerPath())
	if os.IsNotExist(err) {
		return tmldsaReshareActivePointer{}, false, nil
	}
	if err != nil {
		return tmldsaReshareActivePointer{}, false, err
	}
	plaintext, err := tmldsaDecryptPersistenceBlob(encrypted, password)
	if err != nil {
		return tmldsaReshareActivePointer{}, false, err
	}
	defer qtd.SecurelyZeroMemory(plaintext)
	pointer, err := decodeTMLDSAReshareActivePointer(plaintext)
	if err != nil {
		return tmldsaReshareActivePointer{}, false, err
	}
	return pointer, true, nil
}
