// Quantaureum Node source, version 1.0.0.
package node

import (
	"encoding/binary"
	"fmt"

	"github.com/quantaureum/qau/p2p"
	"github.com/quantaureum/qau/types"
)

func encodeQTDSealAnnouncement(slot uint64, root types.Hash, signature []byte, sealers []int) ([]byte, error) {
	if len(signature) == 0 || len(signature) > 4096 || len(sealers) == 0 || len(sealers) > 64 {
		return nil, fmt.Errorf("invalid QTD seal dimensions")
	}
	payload := make([]byte, 48+len(signature)+4*len(sealers))
	binary.BigEndian.PutUint64(payload, slot)
	copy(payload[8:40], root[:])
	binary.BigEndian.PutUint32(payload[40:44], uint32(len(signature)))
	copy(payload[44:], signature)
	offset := 44 + len(signature)
	binary.BigEndian.PutUint32(payload[offset:], uint32(len(sealers)))
	seen := make(map[int]bool, len(sealers))
	for index, sealer := range sealers {
		if sealer < 0 || uint64(sealer) > uint64(^uint32(0)) || seen[sealer] {
			return nil, fmt.Errorf("invalid QTD sealer index")
		}
		seen[sealer] = true
		binary.BigEndian.PutUint32(payload[offset+4+index*4:], uint32(sealer))
	}
	return payload, nil
}

func decodeQTDSealAnnouncement(payload []byte) (uint64, types.Hash, []byte, []int, error) {
	var root types.Hash
	if err := (&p2p.QTDSealAnnouncementValidator{}).Validate(payload); err != nil {
		return 0, root, nil, nil, err
	}
	slot := binary.BigEndian.Uint64(payload)
	copy(root[:], payload[8:40])
	offset := 44 + int(binary.BigEndian.Uint32(payload[40:44]))
	signature := append([]byte(nil), payload[44:offset]...)
	count := int(binary.BigEndian.Uint32(payload[offset:]))
	if count == 0 {
		return 0, root, nil, nil, fmt.Errorf("empty QTD sealer set")
	}
	sealers := make([]int, count)
	seen := make(map[int]bool, count)
	for index := range sealers {
		sealers[index] = int(binary.BigEndian.Uint32(payload[offset+4+index*4:]))
		if sealers[index] < 0 || seen[sealers[index]] {
			return 0, root, nil, nil, fmt.Errorf("invalid QTD sealer set")
		}
		seen[sealers[index]] = true
	}
	return slot, root, signature, sealers, nil
}

func (n *Node) AnnounceQTDSeal(slot uint64, root types.Hash, signature []byte, sealers []int) {
	if n.p2pHost == nil {
		return
	}
	payload, err := encodeQTDSealAnnouncement(slot, root, signature, sealers)
	if err == nil {
		err = n.p2pHost.BroadcastQTDSealAnnouncement(payload)
	}
	if err != nil {
		nodeLog.Warn("QTD seal announcement failed (slot=%d): %v", slot, err)
	}
}

func (n *Node) handleQTDSealAnnouncement(message p2p.PeerMessage) {
	if !n.allowQTDSealFromPeer(message.From) || n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return
	}
	slot, root, signature, sealers, err := decodeQTDSealAnnouncement(message.Payload)
	if err != nil {
		return
	}
	engine := n.blockProducer.QPOS()
	canonical, known := engine.GetSlotBlockRoot(slot)
	if !known || canonical != root {
		return
	}
	state := engine.GetQTDFinality()
	if state == nil || !state.ReceiveSealAnnouncement(slot, root, signature, sealers) {
		return
	}
	if flow := n.blockProducer.ThreeChambersFlow(); flow != nil {
		_ = flow.CompleteSeal(slot)
		_ = flow.FinalizeBlock(slot)
	}
}
