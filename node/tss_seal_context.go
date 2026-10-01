// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
)

const tssDomainTagSeal = "qtd-seal"

type qtdSealSigningView struct {
	chainID, epoch, currentSlot uint64
	canonicalRoot               types.Hash
	rootKnown, approved, active bool
	members                     map[int]types.Address
}

func decodeQTDSealContext(message []byte) (*tssSessionInitBinding, types.Hash, error) {
	domainLength := len(consensus.QTDDomainSep)
	if len(message) != domainLength+56 || !bytes.HasPrefix(message, []byte(consensus.QTDDomainSep)) {
		return nil, types.Hash{}, fmt.Errorf("invalid QTD seal message")
	}
	context := &tssSessionInitBinding{
		chainID:   binary.BigEndian.Uint64(message[domainLength:]),
		epoch:     binary.BigEndian.Uint64(message[domainLength+8:]),
		slot:      binary.BigEndian.Uint64(message[domainLength+16:]),
		domainTag: tssDomainTagSeal, originalMessage: append([]byte(nil), message...),
	}
	var root types.Hash
	copy(root[:], message[domainLength+24:])
	if context.chainID == 0 || context.epoch != consensus.SlotToEpoch(context.slot) || root == (types.Hash{}) {
		return nil, root, fmt.Errorf("inconsistent QTD seal context")
	}
	return context, root, nil
}

func validateQTDSealSigning(message []byte, participants []int, sender types.Address, view qtdSealSigningView) (*tssSessionInitBinding, error) {
	context, root, err := decodeQTDSealContext(message)
	if err != nil {
		return nil, err
	}
	if context.chainID != view.chainID || context.epoch != view.epoch || context.slot > view.currentSlot {
		return nil, fmt.Errorf("QTD seal does not match the local chain, epoch or slot")
	}
	if !view.rootKnown || root != view.canonicalRoot || !view.approved || !view.active {
		return nil, fmt.Errorf("QTD seal requires a canonical reviewed block and active executive committee")
	}
	if len(participants) < 2 || len(participants) != len(view.members) {
		return nil, fmt.Errorf("QTD seal participant set differs from the executive committee")
	}
	seen := make(map[int]bool, len(participants))
	aggregatorID := 0
	for _, participant := range participants {
		address, member := view.members[participant]
		if participant < 1 || !member || seen[participant] || address == (types.Address{}) {
			return nil, fmt.Errorf("invalid QTD seal participant %d", participant)
		}
		seen[participant] = true
		if aggregatorID == 0 || participant < aggregatorID {
			aggregatorID = participant
		}
	}
	context.proposer = view.members[aggregatorID]
	if sender != context.proposer {
		return nil, fmt.Errorf("QTD seal sender is not the designated executive aggregator")
	}
	return context, nil
}

func (n *Node) authorizeQTDSealSigning(message []byte, participants []int, sender types.Address) (*tssSessionInitBinding, error) {
	context, root, err := decodeQTDSealContext(message)
	if err != nil {
		return nil, err
	}
	if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return nil, fmt.Errorf("QTD consensus is unavailable")
	}
	engine := n.blockProducer.QPOS()
	coordinator := engine.GetChambersCoordinator()
	if coordinator == nil {
		return nil, fmt.Errorf("QTD chambers are unavailable")
	}
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		return nil, fmt.Errorf("QTD executive committee is unavailable")
	}
	validatorSet := engine.GetValidatorSet()
	if validatorSet == nil {
		return nil, fmt.Errorf("QTD validator set is unavailable")
	}
	validators := validatorSet.Validators()
	view := qtdSealSigningView{
		chainID: n.chainID, epoch: executive.Epoch(), currentSlot: n.blockProducer.GetCurrentSlot(),
		active: executive.IsActive(), members: make(map[int]types.Address),
	}
	view.canonicalRoot, view.rootKnown = engine.GetSlotBlockRoot(context.slot)
	review := coordinator.GetReviewChamber()
	view.approved = review != nil && review.IsHashApproved(context.slot, root)
	for _, member := range executive.Members() {
		if member < 0 || member >= len(validators) || !validators[member].Active {
			return nil, fmt.Errorf("QTD executive member is not an active validator")
		}
		view.members[member+1] = validators[member].Address
	}
	return validateQTDSealSigning(message, participants, sender, view)
}

func (n *Node) isDesignatedQTDSealer(slot uint64) bool {
	if n.blockProducer == nil || n.blockProducer.QPOS() == nil {
		return false
	}
	coordinator := n.blockProducer.QPOS().GetChambersCoordinator()
	if coordinator == nil {
		return false
	}
	executive := coordinator.GetExecutiveChamber()
	if executive == nil || !executive.IsActive() || executive.Epoch() != consensus.SlotToEpoch(slot) {
		return false
	}
	members := executive.Members()
	if len(members) < 2 {
		return false
	}
	selected := members[0]
	for _, member := range members {
		if member < selected {
			selected = member
		}
	}
	return n.getMyParticipantID() == selected+1
}

type tssSessionRoute struct {
	aggregator types.Address
	message    []byte
	expires    time.Time
}

func (n *Node) registerTSSRoute(sessionID [32]byte, aggregator types.Address, message []byte, initiatedAt int64) error {
	n.aggregatorSessionMu.Lock()
	defer n.aggregatorSessionMu.Unlock()
	if n.tssSessionRoutes == nil {
		n.tssSessionRoutes = make(map[[32]byte]tssSessionRoute)
	}
	now := time.Now()
	for knownID, route := range n.tssSessionRoutes {
		if now.After(route.expires) {
			delete(n.tssSessionRoutes, knownID)
		}
	}
	if _, exists := n.tssSessionRoutes[sessionID]; exists {
		return fmt.Errorf("TSS session already authorized")
	}
	if len(n.tssSessionRoutes) >= 64 {
		return fmt.Errorf("TSS session routing limit reached")
	}
	if aggregator == (types.Address{}) || initiatedAt <= 0 {
		return fmt.Errorf("TSS session identity or timestamp missing")
	}
	n.tssSessionRoutes[sessionID] = tssSessionRoute{aggregator: aggregator, message: append([]byte(nil), message...), expires: time.Unix(0, initiatedAt).Add(45 * time.Second)}
	return nil
}

func (n *Node) tssRoute(sessionID [32]byte) (tssSessionRoute, bool) {
	n.aggregatorSessionMu.Lock()
	defer n.aggregatorSessionMu.Unlock()
	route, exists := n.tssSessionRoutes[sessionID]
	return route, exists && time.Now().Before(route.expires)
}

func (n *Node) isTSSAggregator(sessionID [32]byte) bool {
	route, exists := n.tssRoute(sessionID)
	return exists && n.blockProducer != nil && route.aggregator == n.blockProducer.ValidatorAddr()
}

func (n *Node) removeTSSRoute(sessionID [32]byte) {
	n.aggregatorSessionMu.Lock()
	delete(n.tssSessionRoutes, sessionID)
	n.aggregatorSessionMu.Unlock()
	n.round2PrivateTSMu.Lock()
	for key := range n.round2PrivateLastTS {
		if bytes.Equal(key[:32], sessionID[:]) {
			delete(n.round2PrivateLastTS, key)
		}
	}
	n.round2PrivateTSMu.Unlock()
}
