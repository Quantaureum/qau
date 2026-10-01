// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

type tmldsaInboundReshareSet struct {
	SessionID           [32]byte
	KeyGeneration       uint64
	OldCommitteeVersion uint64
	NewCommitteeVersion uint64
	RecipientID         uint32
	Payloads            map[uint32][]byte
}

func (set tmldsaInboundReshareSet) validateMetadata() error {
	if set.SessionID == ([32]byte{}) || set.KeyGeneration == 0 ||
		set.OldCommitteeVersion == 0 || set.NewCommitteeVersion <= set.OldCommitteeVersion ||
		set.RecipientID == 0 {
		return fmt.Errorf("invalid TMLDSA inbound reshare metadata")
	}
	return nil
}

func (n *Node) persistTMLDSAInboundResharePayload(
	set tmldsaInboundReshareSet,
	dealerID uint32,
	payload []byte,
) error {
	if err := set.validateMetadata(); err != nil {
		return err
	}
	if dealerID == 0 || len(payload) == 0 || len(payload) > protocol.MaxThresholdEnvelopePayload {
		return fmt.Errorf("invalid TMLDSA inbound reshare payload")
	}
	payloadCopy := append([]byte(nil), payload...)
	record := tmldsaReshareJournalRecord{
		Version:             tmldsaReshareJournalVersion,
		Kind:                tmldsaReshareJournalInbound,
		SessionID:           set.SessionID,
		KeyGeneration:       set.KeyGeneration,
		OldCommitteeVersion: set.OldCommitteeVersion,
		NewCommitteeVersion: set.NewCommitteeVersion,
		DealerID:            dealerID,
		RecipientID:         set.RecipientID,
		Payload:             payloadCopy,
		PayloadDigest:       digestTMLDSAResharePayload(payloadCopy),
	}
	return n.persistTMLDSAReshareJournalRecord(record)
}

func (n *Node) loadTMLDSAInboundReshareSet(
	sessionID [32]byte,
	recipientID uint32,
	dealers []uint32,
) (tmldsaInboundReshareSet, bool, bool, error) {
	if sessionID == ([32]byte{}) || recipientID == 0 || !validTMLDSADealerSet(dealers) {
		return tmldsaInboundReshareSet{}, false, false, fmt.Errorf("invalid TMLDSA inbound reshare lookup")
	}
	set := tmldsaInboundReshareSet{
		SessionID:   sessionID,
		RecipientID: recipientID,
		Payloads:    make(map[uint32][]byte, len(dealers)),
	}
	foundCount := 0
	for _, dealerID := range dealers {
		record, found, err := n.loadTMLDSAReshareJournalRecord(
			tmldsaReshareJournalInbound,
			sessionID,
			dealerID,
			recipientID,
		)
		if err != nil {
			return tmldsaInboundReshareSet{}, false, false, err
		}
		if !found {
			continue
		}
		foundCount++
		if foundCount == 1 {
			set.KeyGeneration = record.KeyGeneration
			set.OldCommitteeVersion = record.OldCommitteeVersion
			set.NewCommitteeVersion = record.NewCommitteeVersion
		} else if set.KeyGeneration != record.KeyGeneration ||
			set.OldCommitteeVersion != record.OldCommitteeVersion ||
			set.NewCommitteeVersion != record.NewCommitteeVersion {
			return tmldsaInboundReshareSet{}, false, false, fmt.Errorf("mixed TMLDSA inbound reshare metadata")
		}
		set.Payloads[dealerID] = append([]byte(nil), record.Payload...)
	}
	if foundCount == 0 {
		return tmldsaInboundReshareSet{}, false, false, nil
	}
	if err := set.validateMetadata(); err != nil {
		return tmldsaInboundReshareSet{}, false, false, err
	}
	return set, true, foundCount == len(dealers), nil
}

func validTMLDSADealerSet(dealers []uint32) bool {
	if len(dealers) != int(protocol.TMLDSAV1Threshold) {
		return false
	}
	seen := make(map[uint32]struct{}, len(dealers))
	for _, dealerID := range dealers {
		if dealerID == 0 {
			return false
		}
		if _, duplicate := seen[dealerID]; duplicate {
			return false
		}
		seen[dealerID] = struct{}{}
	}
	return true
}
