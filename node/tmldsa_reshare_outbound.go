// Quantaureum Node source, version 1.0.0.
package node

import (
	"fmt"
	"sort"

	"github.com/quantaureum/qau/wallet/tss/protocol"
)

type tmldsaOutboundReshareSet struct {
	SessionID           [32]byte
	KeyGeneration       uint64
	OldCommitteeVersion uint64
	NewCommitteeVersion uint64
	DealerID            uint32
	Payloads            map[uint32][]byte
}

func (set tmldsaOutboundReshareSet) validate() error {
	if set.SessionID == ([32]byte{}) || set.KeyGeneration == 0 ||
		set.OldCommitteeVersion == 0 || set.NewCommitteeVersion <= set.OldCommitteeVersion ||
		set.DealerID == 0 || len(set.Payloads) != int(protocol.TMLDSAV1ParticipantCount) {
		return fmt.Errorf("invalid TMLDSA outbound reshare set")
	}
	for recipientID, payload := range set.Payloads {
		if recipientID == 0 || len(payload) == 0 || len(payload) > protocol.MaxThresholdEnvelopePayload {
			return fmt.Errorf("invalid TMLDSA outbound reshare recipient payload")
		}
	}
	return nil
}

func (n *Node) persistTMLDSAOutboundReshareSet(set tmldsaOutboundReshareSet) error {
	if err := set.validate(); err != nil {
		return err
	}
	recipients := make([]uint32, 0, len(set.Payloads))
	for recipientID := range set.Payloads {
		recipients = append(recipients, recipientID)
	}
	sort.Slice(recipients, func(left, right int) bool { return recipients[left] < recipients[right] })
	for _, recipientID := range recipients {
		payload := append([]byte(nil), set.Payloads[recipientID]...)
		record := tmldsaReshareJournalRecord{
			Version:             tmldsaReshareJournalVersion,
			Kind:                tmldsaReshareJournalOutbound,
			SessionID:           set.SessionID,
			KeyGeneration:       set.KeyGeneration,
			OldCommitteeVersion: set.OldCommitteeVersion,
			NewCommitteeVersion: set.NewCommitteeVersion,
			DealerID:            set.DealerID,
			RecipientID:         recipientID,
			Payload:             payload,
			PayloadDigest:       digestTMLDSAResharePayload(payload),
		}
		if err := n.persistTMLDSAReshareJournalRecord(record); err != nil {
			return err
		}
	}
	return nil
}

func (n *Node) loadTMLDSAOutboundReshareSet(
	sessionID [32]byte,
	dealerID uint32,
	recipients []uint32,
) (tmldsaOutboundReshareSet, bool, error) {
	if sessionID == ([32]byte{}) || dealerID == 0 || !validTMLDSARecipientSet(recipients) {
		return tmldsaOutboundReshareSet{}, false, fmt.Errorf("invalid TMLDSA outbound reshare lookup")
	}
	set := tmldsaOutboundReshareSet{
		SessionID: sessionID,
		DealerID:  dealerID,
		Payloads:  make(map[uint32][]byte, len(recipients)),
	}
	foundCount := 0
	for _, recipientID := range recipients {
		record, found, err := n.loadTMLDSAReshareJournalRecord(
			tmldsaReshareJournalOutbound,
			sessionID,
			dealerID,
			recipientID,
		)
		if err != nil {
			return tmldsaOutboundReshareSet{}, false, err
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
			return tmldsaOutboundReshareSet{}, false, fmt.Errorf("mixed TMLDSA outbound reshare metadata")
		}
		set.Payloads[recipientID] = append([]byte(nil), record.Payload...)
	}
	if foundCount == 0 {
		return tmldsaOutboundReshareSet{}, false, nil
	}
	if foundCount != len(recipients) {
		return tmldsaOutboundReshareSet{}, false, fmt.Errorf("partial TMLDSA outbound reshare set")
	}
	if err := set.validate(); err != nil {
		return tmldsaOutboundReshareSet{}, false, err
	}
	return set, true, nil
}

func validTMLDSARecipientSet(recipients []uint32) bool {
	if len(recipients) != int(protocol.TMLDSAV1ParticipantCount) {
		return false
	}
	seen := make(map[uint32]struct{}, len(recipients))
	for _, recipientID := range recipients {
		if recipientID == 0 {
			return false
		}
		if _, duplicate := seen[recipientID]; duplicate {
			return false
		}
		seen[recipientID] = struct{}{}
	}
	return true
}
