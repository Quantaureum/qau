// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/binary"
	"fmt"

	"github.com/quantaureum/qau/types"
	protocolmldsa65 "github.com/quantaureum/qau/wallet/tss/protocol/mldsa65"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

const tmldsaResharePairwiseExporterLabel = "QAU-TMLDSA65-V1-RESHARE-MASK"

type tmldsaPairwiseSecretExporter interface {
	ExportPairwiseSecret(peerAddr types.Address, label string, context []byte) ([32]byte, error)
}

func deriveTMLDSAResharePairwiseMask(
	exporter tmldsaPairwiseSecretExporter,
	peerAddress types.Address,
	sessionID [32]byte,
	dealerID uint32,
	round uint32,
	checkID uint32,
	localID uint32,
	peerID uint32,
) (int32, error) {
	if exporter == nil || peerAddress == (types.Address{}) || sessionID == ([32]byte{}) ||
		dealerID == 0 || localID == 0 || peerID == 0 || localID == peerID {
		return 0, protocolmldsa65.ErrInvalidResharePairwiseMask
	}
	leftID, rightID := localID, peerID
	if leftID > rightID {
		leftID, rightID = rightID, leftID
	}
	context := make([]byte, 0, 32+5*4)
	context = append(context, sessionID[:]...)
	context = binary.BigEndian.AppendUint32(context, dealerID)
	context = binary.BigEndian.AppendUint32(context, round)
	context = binary.BigEndian.AppendUint32(context, checkID)
	context = binary.BigEndian.AppendUint32(context, leftID)
	context = binary.BigEndian.AppendUint32(context, rightID)
	sharedSecret, err := exporter.ExportPairwiseSecret(
		peerAddress,
		tmldsaResharePairwiseExporterLabel,
		context,
	)
	if err != nil {
		return 0, err
	}
	defer qtd.SecurelyZeroMemory(sharedSecret[:])
	return protocolmldsa65.DeriveResharePairwiseMask(
		sessionID,
		dealerID,
		round,
		checkID,
		localID,
		peerID,
		sharedSecret,
	)
}

func (n *Node) tmldsaResharePairwiseMask(
	sessionID [32]byte,
	dealerID uint32,
	round uint32,
	checkID uint32,
	peerID uint32,
) (int32, error) {
	localID := n.getMyParticipantID()
	if localID < 1 {
		return 0, fmt.Errorf("invalid TMLDSA pairwise participant binding")
	}
	return n.tmldsaResharePairwiseTermMask(
		sessionID,
		dealerID,
		round,
		checkID,
		uint32(localID),
		peerID,
		peerID,
	)
}

func (n *Node) tmldsaResharePairwiseTermMask(
	sessionID [32]byte,
	dealerID uint32,
	round uint32,
	checkID uint32,
	localTermSenderID uint32,
	peerParticipantID uint32,
	peerTermSenderID uint32,
) (int32, error) {
	if n == nil || n.keyExchange == nil || n.blockProducer == nil || n.blockProducer.qpos == nil {
		return 0, fmt.Errorf("TMLDSA pairwise key exchange is unavailable")
	}
	localID := n.getMyParticipantID()
	if localID < 1 {
		return 0, fmt.Errorf("invalid TMLDSA pairwise participant binding")
	}
	if err := validateTMLDSAResharePairwiseBinding(
		dealerID,
		uint32(localID),
		localTermSenderID,
		peerParticipantID,
		peerTermSenderID,
	); err != nil {
		return 0, err
	}
	validatorSet := n.blockProducer.qpos.GetValidatorSet()
	if validatorSet == nil {
		return 0, fmt.Errorf("TMLDSA pairwise validator set is unavailable")
	}
	validators := validatorSet.Validators()
	if peerParticipantID == 0 || int(peerParticipantID) > len(validators) ||
		validators[peerParticipantID-1] == nil || !validators[peerParticipantID-1].Active {
		return 0, fmt.Errorf("TMLDSA pairwise peer is not an active validator")
	}
	return deriveTMLDSAResharePairwiseMask(
		n.keyExchange,
		validators[peerParticipantID-1].Address,
		sessionID,
		dealerID,
		round,
		checkID,
		localTermSenderID,
		peerTermSenderID,
	)
}

func validateTMLDSAResharePairwiseBinding(
	dealerID uint32,
	localParticipantID uint32,
	localTermSenderID uint32,
	peerParticipantID uint32,
	peerTermSenderID uint32,
) error {
	if dealerID == 0 || localParticipantID == 0 || peerParticipantID == 0 ||
		localParticipantID == peerParticipantID || localTermSenderID == peerTermSenderID ||
		!validTMLDSAReshareTermSenderBinding(dealerID, localParticipantID, localTermSenderID) ||
		!validTMLDSAReshareTermSenderBinding(dealerID, peerParticipantID, peerTermSenderID) {
		return fmt.Errorf("invalid TMLDSA pairwise participant binding")
	}
	return nil
}

func validTMLDSAReshareTermSenderBinding(dealerID, participantID, termSenderID uint32) bool {
	return termSenderID == participantID ||
		(participantID == dealerID && termSenderID == protocolmldsa65.ReshareDealerWitnessID(dealerID))
}
