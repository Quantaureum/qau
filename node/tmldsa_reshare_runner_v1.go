// Quantaureum Node source, version 1.0.0.
package node

import (
	"context"
	crand "crypto/rand"
	"crypto/sha3"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
)

const tmldsaReshareRetryInterval = time.Second

type tmldsaReshareRunRequest struct {
	SessionID       [32]byte
	ActivationEpoch uint64
	Key             protocol.ThresholdKeyID
	OldCommittee    protocol.CommitteeID
	NewCommittee    protocol.CommitteeID
	SelectedDealers []uint32
}

type tmldsaReshareMaskFunc func(
	localTermSenderID uint32,
	peerParticipantID uint32,
	peerTermSenderID uint32,
) (int32, error)

func (request tmldsaReshareRunRequest) validate() error {
	if request.SessionID == ([32]byte{}) || request.ActivationEpoch == 0 ||
		request.Key.Algorithm != qcrypto.SignatureAlgorithmMLDSA65 {
		return fmt.Errorf("invalid TMLDSA reshare run request")
	}
	if err := request.Key.Validate(); err != nil {
		return err
	}
	if err := protocol.DefaultTMLDSAV1Profile().ValidateTransition(request.OldCommittee, request.NewCommittee); err != nil {
		return err
	}
	if len(request.SelectedDealers) != int(protocol.TMLDSAV1Threshold) {
		return fmt.Errorf("invalid TMLDSA reshare dealer set")
	}
	var previous uint32
	for index, dealerID := range request.SelectedDealers {
		if dealerID == 0 || !containsTMLDSAParticipant(request.OldCommittee.Participants, dealerID) ||
			(index > 0 && dealerID <= previous) {
			return fmt.Errorf("invalid TMLDSA reshare dealer set")
		}
		previous = dealerID
	}
	return nil
}

func buildTMLDSAReshareRunRequest(
	activationEpoch uint64,
	key protocol.ThresholdKeyID,
	oldCommittee protocol.CommitteeID,
	oldParticipantIDs []int,
	newParticipantIDs []int,
	threshold int,
) (tmldsaReshareRunRequest, error) {
	if activationEpoch == 0 || threshold != int(protocol.TMLDSAV1Threshold) ||
		len(oldParticipantIDs) != int(protocol.TMLDSAV1ParticipantCount) ||
		len(newParticipantIDs) != int(protocol.TMLDSAV1ParticipantCount) {
		return tmldsaReshareRunRequest{}, fmt.Errorf("invalid TMLDSA epoch rotation dimensions")
	}
	toParticipants := func(values []int) ([]uint32, error) {
		sorted := append([]int(nil), values...)
		sort.Ints(sorted)
		participants := make([]uint32, len(sorted))
		for index, value := range sorted {
			if value <= 0 || (index > 0 && sorted[index-1] == value) {
				return nil, fmt.Errorf("invalid TMLDSA epoch participant ID")
			}
			participants[index] = uint32(value)
		}
		return participants, nil
	}
	oldParticipants, err := toParticipants(oldParticipantIDs)
	if err != nil {
		return tmldsaReshareRunRequest{}, err
	}
	newParticipants, err := toParticipants(newParticipantIDs)
	if err != nil {
		return tmldsaReshareRunRequest{}, err
	}
	if len(oldParticipants) != len(oldCommittee.Participants) {
		return tmldsaReshareRunRequest{}, fmt.Errorf("TMLDSA active committee cardinality mismatch")
	}
	for index := range oldParticipants {
		if oldParticipants[index] != oldCommittee.Participants[index] {
			return tmldsaReshareRunRequest{}, fmt.Errorf("TMLDSA epoch old committee mismatch")
		}
	}
	newCommittee := protocol.CommitteeID{
		Version:      oldCommittee.Version + 1,
		Threshold:    protocol.TMLDSAV1Threshold,
		Participants: newParticipants,
	}
	request := tmldsaReshareRunRequest{
		ActivationEpoch: activationEpoch,
		Key:             key.Clone(),
		OldCommittee:    oldCommittee.Clone(),
		NewCommittee:    newCommittee,
		SelectedDealers: append([]uint32(nil), oldParticipants[:protocol.TMLDSAV1Threshold]...),
	}
	keyDigest, err := request.Key.CanonicalDigest()
	if err != nil {
		return tmldsaReshareRunRequest{}, err
	}
	oldDigest, err := request.OldCommittee.CanonicalDigest()
	if err != nil {
		return tmldsaReshareRunRequest{}, err
	}
	newDigest, err := request.NewCommittee.CanonicalDigest()
	if err != nil {
		return tmldsaReshareRunRequest{}, err
	}
	digest := sha3.New256()
	_, _ = digest.Write([]byte("QAU-TMLDSA65-V1-EPOCH-RESHARE"))
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], activationEpoch)
	_, _ = digest.Write(encoded[:])
	_, _ = digest.Write(keyDigest[:])
	_, _ = digest.Write(oldDigest[:])
	_, _ = digest.Write(newDigest[:])
	copy(request.SessionID[:], digest.Sum(nil))
	if err := request.validate(); err != nil {
		return tmldsaReshareRunRequest{}, err
	}
	return request, nil
}

func (n *Node) activeTMLDSAReshareRunRequest(
	activationEpoch uint64,
	oldParticipantIDs []int,
	newParticipantIDs []int,
	threshold int,
) (tmldsaReshareRunRequest, bool, error) {
	if !experimentalTMLDSAV1Enabled() {
		return tmldsaReshareRunRequest{}, false, nil
	}
	pointerPath := n.tmldsaActiveSharePointerPath()
	if pointerPath == "" {
		return tmldsaReshareRunRequest{}, false, nil
	}
	if _, err := os.Stat(pointerPath); os.IsNotExist(err) {
		return tmldsaReshareRunRequest{}, false, nil
	} else if err != nil {
		return tmldsaReshareRunRequest{}, true, err
	}
	share, found, err := n.loadActiveTMLDSAShare()
	if err != nil {
		return tmldsaReshareRunRequest{}, true, err
	}
	if !found {
		return tmldsaReshareRunRequest{}, true, fmt.Errorf("TMLDSA active pointer exists without an active share")
	}
	defer share.Zeroize()
	key, oldCommittee, _, err := share.Identity()
	if err != nil {
		return tmldsaReshareRunRequest{}, true, err
	}
	request, err := buildTMLDSAReshareRunRequest(
		activationEpoch,
		key,
		oldCommittee,
		oldParticipantIDs,
		newParticipantIDs,
		threshold,
	)
	if err != nil {
		return tmldsaReshareRunRequest{}, true, err
	}
	return request, true, nil
}

func (n *Node) prepareTMLDSAReshareDealerMessages(
	request tmldsaReshareRunRequest,
	dealerID uint32,
	oldShare *protocolmldsa65.LocalShare,
	entropy io.Reader,
) ([]tmldsaResharePrivateContribution, tmldsaReshareControlMessage, error) {
	if !experimentalTMLDSAV1Enabled() {
		return nil, tmldsaReshareControlMessage{}, fmt.Errorf("experimental TMLDSA v1 is disabled")
	}
	if err := request.validate(); err != nil {
		return nil, tmldsaReshareControlMessage{}, err
	}
	if oldShare == nil || entropy == nil || !containsTMLDSAParticipant(request.SelectedDealers, dealerID) {
		return nil, tmldsaReshareControlMessage{}, fmt.Errorf("invalid TMLDSA reshare dealer preparation")
	}
	if err := oldShare.ValidateIdentity(request.Key, request.OldCommittee, dealerID); err != nil {
		return nil, tmldsaReshareControlMessage{}, err
	}
	outbound, found, err := n.loadTMLDSAOutboundReshareSet(
		request.SessionID,
		dealerID,
		request.NewCommittee.Participants,
	)
	if err != nil {
		return nil, tmldsaReshareControlMessage{}, err
	}
	if !found {
		plan, err := protocolmldsa65.NewReshareDealerPlan(
			oldShare,
			request.OldCommittee,
			request.NewCommittee,
			request.SelectedDealers,
			entropy,
		)
		if err != nil {
			return nil, tmldsaReshareControlMessage{}, err
		}
		defer plan.Zeroize()
		outbound = tmldsaOutboundReshareSet{
			SessionID:           request.SessionID,
			KeyGeneration:       request.Key.Generation,
			OldCommitteeVersion: request.OldCommittee.Version,
			NewCommitteeVersion: request.NewCommittee.Version,
			DealerID:            dealerID,
			Payloads:            make(map[uint32][]byte, len(request.NewCommittee.Participants)),
		}
		for _, recipientID := range request.NewCommittee.Participants {
			contribution, err := plan.Contribution(recipientID)
			if err != nil {
				return nil, tmldsaReshareControlMessage{}, err
			}
			payload, err := protocolmldsa65.EncodeReshareContribution(contribution)
			if err != nil {
				return nil, tmldsaReshareControlMessage{}, err
			}
			outbound.Payloads[recipientID] = payload
		}
		if err := n.persistTMLDSAOutboundReshareSet(outbound); err != nil {
			return nil, tmldsaReshareControlMessage{}, err
		}
	}
	privateMessages := make([]tmldsaResharePrivateContribution, 0, len(request.NewCommittee.Participants))
	commitments := make([]tmldsaReshareControlCommitment, 0, len(request.NewCommittee.Participants))
	for _, recipientID := range request.NewCommittee.Participants {
		payload, ok := outbound.Payloads[recipientID]
		if !ok {
			return nil, tmldsaReshareControlMessage{}, fmt.Errorf("TMLDSA durable outbound contribution is incomplete")
		}
		contribution, err := protocolmldsa65.DecodeReshareContribution(
			payload,
			request.Key,
			request.OldCommittee,
			request.NewCommittee,
			request.SelectedDealers,
			dealerID,
			recipientID,
		)
		if err != nil {
			return nil, tmldsaReshareControlMessage{}, err
		}
		commitment, err := contribution.Commitment()
		if err != nil {
			return nil, tmldsaReshareControlMessage{}, err
		}
		privateMessages = append(privateMessages, tmldsaResharePrivateContribution{
			SessionID:       request.SessionID,
			Key:             request.Key.Clone(),
			OldCommittee:    request.OldCommittee.Clone(),
			NewCommittee:    request.NewCommittee.Clone(),
			SelectedDealers: append([]uint32(nil), request.SelectedDealers...),
			DealerID:        dealerID,
			RecipientID:     recipientID,
			Payload:         append([]byte(nil), payload...),
		})
		commitments = append(commitments, tmldsaReshareControlCommitment{
			RecipientID: recipientID,
			Commitment:  commitment,
		})
	}
	control := tmldsaReshareControlMessage{
		Protocol:          tmldsaReshareControlProtocol,
		Kind:              tmldsaReshareControlContributionSet,
		SessionID:         request.SessionID,
		Key:               request.Key.Clone(),
		OldCommittee:      request.OldCommittee.Clone(),
		NewCommittee:      request.NewCommittee.Clone(),
		SelectedDealers:   append([]uint32(nil), request.SelectedDealers...),
		DealerID:          dealerID,
		SenderID:          dealerID,
		ContributionHeads: commitments,
	}
	if err := control.validate(); err != nil {
		return nil, tmldsaReshareControlMessage{}, err
	}
	return privateMessages, control, nil
}

func (n *Node) advanceTMLDSAReshareParticipant(
	request tmldsaReshareRunRequest,
	participantID uint32,
	entropy io.Reader,
	broadcast func(tmldsaReshareControlMessage) error,
) (bool, error) {
	if broadcast == nil || entropy == nil {
		return false, fmt.Errorf("invalid TMLDSA reshare scheduler")
	}
	if err := request.validate(); err != nil {
		return false, err
	}
	allVerified := true
	for _, dealerID := range request.SelectedDealers {
		coordinator, found, err := n.loadTMLDSAReshareConsistencyState(request.SessionID, dealerID)
		if err != nil {
			return false, err
		}
		if !found {
			allVerified = false
			continue
		}
		if coordinator.Phase() == protocolmldsa65.ReshareConsistencyPhaseVerified {
			continue
		}
		allVerified = false
		messages, err := n.nextTMLDSAReshareParticipantMessages(
			request,
			dealerID,
			participantID,
			entropy,
		)
		if err != nil {
			return false, err
		}
		for _, message := range messages {
			if err := broadcast(message); err != nil {
				return false, err
			}
			if err := n.applyTMLDSAReshareControlMessage(message); err != nil {
				return false, err
			}
		}
	}
	if !allVerified {
		for _, dealerID := range request.SelectedDealers {
			coordinator, found, err := n.loadTMLDSAReshareConsistencyState(request.SessionID, dealerID)
			if err != nil {
				return false, err
			}
			if !found || coordinator.Phase() != protocolmldsa65.ReshareConsistencyPhaseVerified {
				return false, nil
			}
		}
	}
	return true, nil
}

func (n *Node) runTMLDSAReshareV1(ctx context.Context, request tmldsaReshareRunRequest) error {
	if !experimentalTMLDSAV1Enabled() {
		return fmt.Errorf("experimental TMLDSA v1 is disabled")
	}
	if err := request.validate(); err != nil {
		return err
	}
	if ctx == nil {
		return fmt.Errorf("TMLDSA reshare context is nil")
	}
	participantID := n.getMyParticipantID()
	if participantID < 1 {
		return fmt.Errorf("local TMLDSA participant ID is unavailable")
	}
	physicalID := uint32(participantID)
	if !containsTMLDSAParticipant(request.NewCommittee.Participants, physicalID) &&
		!containsTMLDSAParticipant(request.SelectedDealers, physicalID) {
		return fmt.Errorf("local validator has no TMLDSA reshare role")
	}

	n.reshareRunMu.Lock()
	defer n.reshareRunMu.Unlock()
	ticker := time.NewTicker(tmldsaReshareRetryInterval)
	defer ticker.Stop()
	for {
		done, err := n.advanceTMLDSAReshareRun(request, physicalID)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		select {
		case <-ctx.Done():
			abortErr := n.abortTMLDSAReshareRun(request, physicalID, ctx.Err())
			if abortErr != nil {
				return fmt.Errorf("TMLDSA reshare timeout: %w; abort evidence: %v", ctx.Err(), abortErr)
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (n *Node) advanceTMLDSAReshareRun(
	request tmldsaReshareRunRequest,
	participantID uint32,
) (bool, error) {
	currentEpoch, err := n.currentTMLDSAReshareEpoch()
	if err != nil {
		return false, err
	}
	if currentEpoch > request.ActivationEpoch {
		return false, fmt.Errorf("TMLDSA reshare missed activation epoch %d", request.ActivationEpoch)
	}
	if containsTMLDSAParticipant(request.SelectedDealers, participantID) {
		if err := n.dispatchTMLDSAReshareDealer(request, participantID); err != nil {
			return false, err
		}
	}
	verified, err := n.advanceTMLDSAReshareParticipant(
		request,
		participantID,
		crand.Reader,
		n.broadcastTMLDSAReshareControl,
	)
	if err != nil || !verified {
		return false, err
	}
	if !containsTMLDSAParticipant(request.NewCommittee.Participants, participantID) {
		return true, nil
	}
	return n.finalizeTMLDSAReshareRun(request, participantID, currentEpoch)
}

func (n *Node) currentTMLDSAReshareEpoch() (uint64, error) {
	if n == nil || n.blockProducer == nil || n.blockProducer.qpos == nil {
		return 0, fmt.Errorf("TMLDSA reshare epoch source is unavailable")
	}
	return n.blockProducer.qpos.GetCurrentEpoch(), nil
}

func (n *Node) dispatchTMLDSAReshareDealer(
	request tmldsaReshareRunRequest,
	dealerID uint32,
) error {
	if coordinator, found, err := n.loadTMLDSAReshareConsistencyState(request.SessionID, dealerID); err != nil {
		return err
	} else if found && coordinator.Phase() != protocolmldsa65.ReshareConsistencyPhaseContributionAgreement {
		return nil
	}
	oldShare, found, err := n.loadActiveTMLDSAShare()
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("TMLDSA reshare dealer has no active old share")
	}
	defer oldShare.Zeroize()
	privateMessages, control, err := n.prepareTMLDSAReshareDealerMessages(
		request,
		dealerID,
		oldShare,
		crand.Reader,
	)
	if err != nil {
		return err
	}
	for _, message := range privateMessages {
		if err := n.sendTMLDSAResharePrivateContribution(message); err != nil {
			return err
		}
	}
	if err := n.broadcastTMLDSAReshareControl(control); err != nil {
		return err
	}
	return n.applyTMLDSAReshareControlMessage(control)
}

func (n *Node) finalizeTMLDSAReshareRun(
	request tmldsaReshareRunRequest,
	participantID uint32,
	currentEpoch uint64,
) (bool, error) {
	share, err := n.prepareTMLDSAReshareActivation(
		request.SessionID,
		request.ActivationEpoch,
		request.Key,
		request.OldCommittee,
		request.NewCommittee,
		request.SelectedDealers,
		participantID,
	)
	if err != nil {
		return false, err
	}
	share.Zeroize()
	candidateDigest, transcriptDigest, err := n.tmldsaReshareActivationEvidence(request.SessionID, participantID)
	if err != nil {
		return false, err
	}
	acknowledgement := protocolmldsa65.ReshareActivationAcknowledgement{
		SessionID:        request.SessionID,
		ActivationEpoch:  request.ActivationEpoch,
		Key:              request.Key.Clone(),
		OldCommittee:     request.OldCommittee.Clone(),
		NewCommittee:     request.NewCommittee.Clone(),
		TranscriptDigest: transcriptDigest,
		ParticipantID:    participantID,
		CandidateDigest:  candidateDigest,
	}
	if n.blockProducer == nil || n.blockProducer.ValidatorKey() == nil {
		return false, fmt.Errorf("TMLDSA activation identity key is unavailable")
	}
	message, err := acknowledgement.SigningBytes()
	if err != nil {
		return false, err
	}
	acknowledgement.IdentitySignature, err = n.blockProducer.ValidatorKey().Sign(message)
	if err != nil {
		return false, err
	}
	control := tmldsaReshareControlMessage{
		Protocol:      tmldsaReshareControlProtocol,
		Kind:          tmldsaReshareControlActivationAck,
		SessionID:     request.SessionID,
		DealerID:      request.SelectedDealers[0],
		SenderID:      participantID,
		ActivationAck: &acknowledgement,
	}
	if err := n.broadcastTMLDSAReshareControl(control); err != nil {
		return false, err
	}
	if err := n.applyTMLDSAReshareControlMessage(control); err != nil {
		return false, err
	}
	certificate, found, err := n.loadTMLDSAReshareActivationCertificate(request.SessionID)
	if err != nil || !found {
		return false, err
	}
	certificateControl := tmldsaReshareControlMessage{
		Protocol:              tmldsaReshareControlProtocol,
		Kind:                  tmldsaReshareControlActivationCert,
		SessionID:             request.SessionID,
		DealerID:              request.SelectedDealers[0],
		SenderID:              participantID,
		ActivationCertificate: &certificate.Certificate,
	}
	if err := n.broadcastTMLDSAReshareControl(certificateControl); err != nil {
		return false, err
	}
	if currentEpoch < request.ActivationEpoch {
		return false, nil
	}
	activated, err := n.activateTMLDSAReshare(
		request.SessionID,
		currentEpoch,
		request.Key,
		request.NewCommittee,
		participantID,
	)
	if err != nil {
		return false, err
	}
	activated.Zeroize()
	return true, nil
}

func (n *Node) abortTMLDSAReshareRun(
	request tmldsaReshareRunRequest,
	reporterID uint32,
	cause error,
) error {
	detail := sha3.Sum256(append(
		append([]byte("QAU-TMLDSA65-V1-RESHARE-RUN-TIMEOUT"), request.SessionID[:]...),
		[]byte(cause.Error())...,
	))
	if n.blockProducer == nil || n.blockProducer.ValidatorKey() == nil {
		return fmt.Errorf("TMLDSA abort identity key is unavailable")
	}
	for _, dealerID := range request.SelectedDealers {
		coordinator, found, err := n.loadTMLDSAReshareConsistencyState(request.SessionID, dealerID)
		if err != nil {
			return err
		}
		if !found || coordinator.Phase() == protocolmldsa65.ReshareConsistencyPhaseVerified ||
			coordinator.Phase() == protocolmldsa65.ReshareConsistencyPhaseAborted {
			continue
		}
		if err := coordinator.AbortTimeout(detail); err != nil {
			return err
		}
		if err := n.persistTMLDSAReshareConsistencyState(coordinator); err != nil {
			return err
		}
		evidence, ok := coordinator.AbortEvidence()
		if !ok {
			return fmt.Errorf("TMLDSA timeout did not produce abort evidence")
		}
		signed := protocolmldsa65.SignedReshareAbortEvidence{
			SessionID:    request.SessionID,
			Key:          request.Key.Clone(),
			OldCommittee: request.OldCommittee.Clone(),
			NewCommittee: request.NewCommittee.Clone(),
			DealerID:     dealerID,
			ReporterID:   reporterID,
			Evidence:     evidence,
		}
		message, err := signed.SigningBytes()
		if err != nil {
			return err
		}
		signed.IdentitySignature, err = n.blockProducer.ValidatorKey().Sign(message)
		if err != nil {
			return err
		}
		control := tmldsaReshareControlMessage{
			Protocol:      tmldsaReshareControlProtocol,
			Kind:          tmldsaReshareControlAbortEvidence,
			SessionID:     request.SessionID,
			DealerID:      dealerID,
			SenderID:      reporterID,
			AbortEvidence: &signed,
		}
		if err := n.broadcastTMLDSAReshareControl(control); err != nil {
			return err
		}
		if err := n.applyTMLDSAReshareControlMessage(control); err != nil {
			return err
		}
	}
	return nil
}

func (n *Node) nextTMLDSAReshareParticipantMessages(
	request tmldsaReshareRunRequest,
	dealerID uint32,
	participantID uint32,
	entropy io.Reader,
) ([]tmldsaReshareControlMessage, error) {
	if !experimentalTMLDSAV1Enabled() {
		return nil, fmt.Errorf("experimental TMLDSA v1 is disabled")
	}
	if err := request.validate(); err != nil {
		return nil, err
	}
	if !containsTMLDSAParticipant(request.SelectedDealers, dealerID) ||
		(!containsTMLDSAParticipant(request.NewCommittee.Participants, participantID) && participantID != dealerID) ||
		entropy == nil {
		return nil, fmt.Errorf("invalid TMLDSA reshare participant driver request")
	}
	coordinator, found, err := n.loadTMLDSAReshareConsistencyState(request.SessionID, dealerID)
	if err != nil || !found {
		return nil, err
	}
	if err := coordinator.ValidateIdentity(
		request.SessionID,
		request.Key,
		request.OldCommittee,
		request.NewCommittee,
		request.SelectedDealers,
		dealerID,
	); err != nil {
		return nil, err
	}
	return n.nextTMLDSAReshareParticipantMessagesWithCoordinator(
		request,
		coordinator,
		dealerID,
		participantID,
		entropy,
	)
}

func (n *Node) nextTMLDSAReshareParticipantMessagesWithCoordinator(
	request tmldsaReshareRunRequest,
	coordinator *protocolmldsa65.ReshareConsistencyCoordinator,
	dealerID uint32,
	participantID uint32,
	entropy io.Reader,
) ([]tmldsaReshareControlMessage, error) {
	if coordinator == nil || entropy == nil {
		return nil, fmt.Errorf("invalid TMLDSA reshare participant coordinator")
	}
	if err := request.validate(); err != nil {
		return nil, err
	}
	if !containsTMLDSAParticipant(request.SelectedDealers, dealerID) ||
		(!containsTMLDSAParticipant(request.NewCommittee.Participants, participantID) && participantID != dealerID) {
		return nil, fmt.Errorf("invalid TMLDSA reshare participant driver request")
	}
	if err := coordinator.ValidateIdentity(
		request.SessionID,
		request.Key,
		request.OldCommittee,
		request.NewCommittee,
		request.SelectedDealers,
		dealerID,
	); err != nil {
		return nil, err
	}
	base := tmldsaReshareControlMessage{
		Protocol:  tmldsaReshareControlProtocol,
		SessionID: request.SessionID,
		DealerID:  dealerID,
		SenderID:  participantID,
	}
	switch coordinator.Phase() {
	case protocolmldsa65.ReshareConsistencyPhaseContributionAgreement:
		if !containsTMLDSAParticipant(request.NewCommittee.Participants, participantID) {
			return nil, nil
		}
		inbound, found, _, err := n.loadTMLDSAInboundReshareSet(
			request.SessionID,
			participantID,
			request.SelectedDealers,
		)
		if err != nil || !found {
			return nil, err
		}
		payload, ok := inbound.Payloads[dealerID]
		if !ok {
			return nil, nil
		}
		contribution, err := protocolmldsa65.DecodeReshareContribution(
			payload,
			request.Key,
			request.OldCommittee,
			request.NewCommittee,
			request.SelectedDealers,
			dealerID,
			participantID,
		)
		if err != nil {
			return nil, err
		}
		commitment, err := contribution.Commitment()
		if err != nil {
			return nil, err
		}
		if err := coordinator.ValidateContributionCommitment(participantID, commitment); err != nil {
			return nil, err
		}
		base.Kind = tmldsaReshareControlAgreement
		base.Value = coordinator.ContributionSetDigest()
		return []tmldsaReshareControlMessage{base}, nil
	case protocolmldsa65.ReshareConsistencyPhaseNonceCommitment:
		if !containsTMLDSAParticipant(request.NewCommittee.Participants, participantID) {
			return nil, nil
		}
		nonce, err := n.loadOrCreateTMLDSAReshareNonce(
			request.SessionID,
			dealerID,
			participantID,
			entropy,
		)
		if err != nil {
			return nil, err
		}
		base.Kind = tmldsaReshareControlNonceCommitment
		base.Value = protocolmldsa65.CommitReshareConsistencyNonce(
			request.SessionID,
			dealerID,
			participantID,
			nonce,
		)
		return []tmldsaReshareControlMessage{base}, nil
	case protocolmldsa65.ReshareConsistencyPhaseNonceReveal:
		if !containsTMLDSAParticipant(request.NewCommittee.Participants, participantID) {
			return nil, nil
		}
		nonce, err := n.loadOrCreateTMLDSAReshareNonce(
			request.SessionID,
			dealerID,
			participantID,
			entropy,
		)
		if err != nil {
			return nil, err
		}
		base.Kind = tmldsaReshareControlNonceReveal
		base.Value = nonce
		return []tmldsaReshareControlMessage{base}, nil
	case protocolmldsa65.ReshareConsistencyPhaseTermCommitment,
		protocolmldsa65.ReshareConsistencyPhaseTermReveal:
		return n.nextTMLDSAReshareTermMessages(request, coordinator, dealerID, participantID, entropy)
	default:
		return nil, nil
	}
}

func (n *Node) nextTMLDSAReshareTermMessages(
	request tmldsaReshareRunRequest,
	coordinator *protocolmldsa65.ReshareConsistencyCoordinator,
	dealerID uint32,
	participantID uint32,
	entropy io.Reader,
) ([]tmldsaReshareControlMessage, error) {
	round, checkID := coordinator.CurrentCheck()
	maskFn := func(localTermSenderID, peerParticipantID, peerTermSenderID uint32) (int32, error) {
		return n.tmldsaResharePairwiseTermMask(
			request.SessionID,
			dealerID,
			round,
			checkID,
			localTermSenderID,
			peerParticipantID,
			peerTermSenderID,
		)
	}
	var oldShare *protocolmldsa65.LocalShare
	if checkID == protocolmldsa65.ReshareConsistencyChecksPerRound-1 && participantID == dealerID {
		var found bool
		var err error
		oldShare, found, err = n.loadActiveTMLDSAShare()
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("TMLDSA reshare dealer witness has no active old share")
		}
		defer oldShare.Zeroize()
		if err := oldShare.ValidateIdentity(request.Key, request.OldCommittee, dealerID); err != nil {
			return nil, err
		}
	}
	return n.nextTMLDSAReshareTermMessagesWithMask(
		request,
		coordinator,
		dealerID,
		participantID,
		entropy,
		maskFn,
		oldShare,
	)
}

func (n *Node) nextTMLDSAReshareTermMessagesWithMask(
	request tmldsaReshareRunRequest,
	coordinator *protocolmldsa65.ReshareConsistencyCoordinator,
	dealerID uint32,
	participantID uint32,
	entropy io.Reader,
	maskFn tmldsaReshareMaskFunc,
	oldShare *protocolmldsa65.LocalShare,
) ([]tmldsaReshareControlMessage, error) {
	if coordinator == nil || entropy == nil || maskFn == nil {
		return nil, fmt.Errorf("invalid TMLDSA reshare term driver request")
	}
	round, checkID := coordinator.CurrentCheck()
	seed := coordinator.ChallengeSeed()
	if seed == ([32]byte{}) {
		return nil, fmt.Errorf("TMLDSA reshare challenge seed is unavailable")
	}
	type logicalTerm struct {
		senderID uint32
		term     int32
	}
	terms := make([]logicalTerm, 0, 2)
	if containsTMLDSAParticipant(request.NewCommittee.Participants, participantID) {
		inbound, found, _, err := n.loadTMLDSAInboundReshareSet(
			request.SessionID,
			participantID,
			request.SelectedDealers,
		)
		if err != nil || !found {
			return nil, err
		}
		payload, ok := inbound.Payloads[dealerID]
		if !ok {
			return nil, nil
		}
		contribution, err := protocolmldsa65.DecodeReshareContribution(
			payload,
			request.Key,
			request.OldCommittee,
			request.NewCommittee,
			request.SelectedDealers,
			dealerID,
			participantID,
		)
		if err != nil {
			return nil, err
		}
		term, err := computeTMLDSAReshareRecipientTerm(
			request,
			dealerID,
			participantID,
			round,
			checkID,
			seed,
			contribution,
			maskFn,
		)
		if err != nil {
			return nil, err
		}
		terms = append(terms, logicalTerm{senderID: participantID, term: term})
	}
	if checkID == protocolmldsa65.ReshareConsistencyChecksPerRound-1 && participantID == dealerID {
		if oldShare == nil {
			return nil, fmt.Errorf("TMLDSA reshare dealer witness share is unavailable")
		}
		term, err := computeTMLDSAReshareDealerWitnessTerm(
			request,
			dealerID,
			round,
			seed,
			oldShare,
			maskFn,
		)
		if err != nil {
			return nil, err
		}
		terms = append(terms, logicalTerm{
			senderID: protocolmldsa65.ReshareDealerWitnessID(dealerID),
			term:     term,
		})
	}
	messages := make([]tmldsaReshareControlMessage, 0, len(terms))
	for _, term := range terms {
		reveal, err := n.loadOrPersistTMLDSAReshareTerm(
			request.SessionID,
			dealerID,
			round,
			checkID,
			term.senderID,
			term.term,
			entropy,
		)
		if err != nil {
			return nil, err
		}
		message := tmldsaReshareControlMessage{
			Protocol:     tmldsaReshareControlProtocol,
			SessionID:    request.SessionID,
			DealerID:     dealerID,
			SenderID:     participantID,
			TermSenderID: term.senderID,
		}
		switch coordinator.Phase() {
		case protocolmldsa65.ReshareConsistencyPhaseTermCommitment:
			message.Kind = tmldsaReshareControlTermCommitment
			message.Value, err = protocolmldsa65.CommitReshareMaskedTerm(
				request.SessionID,
				dealerID,
				round,
				checkID,
				reveal.SenderID,
				reveal.Term,
				reveal.Salt,
			)
			if err != nil {
				return nil, err
			}
		case protocolmldsa65.ReshareConsistencyPhaseTermReveal:
			message.Kind = tmldsaReshareControlTermReveal
			message.Term = reveal.Term
			message.Salt = reveal.Salt
		default:
			return nil, fmt.Errorf("TMLDSA reshare term phase changed")
		}
		messages = append(messages, message)
	}
	return messages, nil
}

func computeTMLDSAReshareRecipientTerm(
	request tmldsaReshareRunRequest,
	dealerID uint32,
	participantID uint32,
	round uint32,
	checkID uint32,
	seed [32]byte,
	contribution protocolmldsa65.ReshareContribution,
	maskFn tmldsaReshareMaskFunc,
) (int32, error) {
	if err := request.validate(); err != nil || maskFn == nil ||
		checkID >= protocolmldsa65.ReshareConsistencyChecksPerRound {
		return 0, fmt.Errorf("invalid TMLDSA reshare recipient term request")
	}
	participantIndex := -1
	for index, candidateID := range request.NewCommittee.Participants {
		if candidateID == participantID {
			participantIndex = index
			break
		}
	}
	if participantIndex < 0 {
		return 0, fmt.Errorf("TMLDSA reshare term participant is not in the new committee")
	}
	projection, err := contribution.LinearProjection(seed, round)
	if err != nil {
		return 0, err
	}
	var coefficient int32
	if checkID < 2 {
		coefficients, err := protocolmldsa65.ReshareEvaluationCheckCoefficients(request.NewCommittee.Participants)
		if err != nil {
			return 0, err
		}
		// #nosec G602 -- checkID in {0,1} and participantIndex < 6 by the
		// evaluation-points contract of ReshareEvaluationCheckCoefficients.
		coefficient = coefficients[checkID][participantIndex]
	} else {
		coefficients, err := protocolmldsa65.ReshareConstantCheckCoefficients(request.NewCommittee.Participants)
		if err != nil {
			return 0, err
		}
		// #nosec G602 -- ReshareConstantCheckCoefficients returns [6]int32 and
		// participantIndex indexes the same validated participant set.
		coefficient = coefficients[participantIndex]
	}
	masks := make([]int32, 0, len(request.NewCommittee.Participants))
	for _, peerID := range request.NewCommittee.Participants {
		if peerID == participantID {
			continue
		}
		mask, err := maskFn(participantID, peerID, peerID)
		if err != nil {
			return 0, err
		}
		masks = append(masks, mask)
	}
	if checkID == protocolmldsa65.ReshareConsistencyChecksPerRound-1 && dealerID != participantID {
		witnessID := protocolmldsa65.ReshareDealerWitnessID(dealerID)
		mask, err := maskFn(participantID, dealerID, witnessID)
		if err != nil {
			return 0, err
		}
		masks = append(masks, mask)
	}
	return protocolmldsa65.MaskedLinearTerm(
		projection,
		coefficient,
		protocolmldsa65.AggregateLinearTerms(masks),
	), nil
}

func computeTMLDSAReshareDealerWitnessTerm(
	request tmldsaReshareRunRequest,
	dealerID uint32,
	round uint32,
	seed [32]byte,
	oldShare *protocolmldsa65.LocalShare,
	maskFn tmldsaReshareMaskFunc,
) (int32, error) {
	if err := request.validate(); err != nil || maskFn == nil || oldShare == nil ||
		!containsTMLDSAParticipant(request.SelectedDealers, dealerID) {
		return 0, fmt.Errorf("invalid TMLDSA reshare dealer witness request")
	}
	projection, err := oldShare.LinearProjection(seed, round)
	if err != nil {
		return 0, err
	}
	coefficient, err := protocolmldsa65.ReshareDealerConstantCheckCoefficient(dealerID, request.SelectedDealers)
	if err != nil {
		return 0, err
	}
	witnessID := protocolmldsa65.ReshareDealerWitnessID(dealerID)
	masks := make([]int32, 0, len(request.NewCommittee.Participants))
	for _, peerID := range request.NewCommittee.Participants {
		if peerID == dealerID {
			continue
		}
		mask, err := maskFn(witnessID, peerID, peerID)
		if err != nil {
			return 0, err
		}
		masks = append(masks, mask)
	}
	return protocolmldsa65.MaskedLinearTerm(
		projection,
		coefficient,
		protocolmldsa65.AggregateLinearTerms(masks),
	), nil
}
