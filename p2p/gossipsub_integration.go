// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"fmt"

	"github.com/quantaureum/qau/p2p/gossipsub"
)

// =============================================================================
// GossipSub Integration — Phase 2
//
// This file integrates the GossipSub protocol with the existing P2P Host.
// The Host implements the MessageSender interface so GossipSub can send
// messages through the existing encrypted transport layer.
// =============================================================================

// GossipSub message type for routing
const MsgTypeGossipSub uint8 = 60

// GossipSubTopic wraps the GossipSub topic with a message type
type GossipSubTopic struct {
	Name    string
	MsgType uint8
}

// Standard GossipSub topics mapped to their message types
var (
	GossipSubTopicBlocks             = GossipSubTopic{Name: gossipsub.TopicBlocks, MsgType: MsgTypeBlock}
	GossipSubTopicTransactions       = GossipSubTopic{Name: gossipsub.TopicTransactions, MsgType: MsgTypeTransaction}
	GossipSubTopicVotes              = GossipSubTopic{Name: gossipsub.TopicVotes, MsgType: MsgTypeVote}
	GossipSubTopicAttestations       = GossipSubTopic{Name: gossipsub.TopicAttestations, MsgType: MsgTypeAttestation}
	GossipSubTopicShardBlocks        = GossipSubTopic{Name: gossipsub.TopicShardBlocks, MsgType: MsgTypeShardBlock}           // P1-1
	GossipSubTopicCrossShardMessages = GossipSubTopic{Name: gossipsub.TopicCrossShardMessages, MsgType: MsgTypeCrossShardMsg} // P1-1
)

// GossipSubTopics returns all standard topics
func GossipSubTopics() []GossipSubTopic {
	return []GossipSubTopic{
		GossipSubTopicBlocks,
		GossipSubTopicTransactions,
		GossipSubTopicVotes,
		GossipSubTopicAttestations,
		GossipSubTopicShardBlocks,
		GossipSubTopicCrossShardMessages,
	}
}

// =============================================================================
// Host implements gossipsub.MessageSender
// =============================================================================

// SendGossipSub sends a GossipSub RPC to a specific peer through the existing transport
func (h *Host) SendGossipSub(peerID gossipsub.PeerID, data []byte) error {
	msg, err := EncodeMessage(MsgTypeGossipSub, data)
	if err != nil {
		return fmt.Errorf("failed to encode GossipSub message: %w", err)
	}
	h.sendToPeer(PeerID(peerID), msg)
	return nil
}

// GetConnectedPeers returns the list of currently connected peer IDs
func (h *Host) GetConnectedPeers() []gossipsub.PeerID {
	h.peersMu.RLock()
	defer h.peersMu.RUnlock()

	peers := make([]gossipsub.PeerID, 0, len(h.peers))
	for pid := range h.peers {
		peers = append(peers, gossipsub.PeerID(pid))
	}
	return peers
}

// GetPeerScore returns the score for a peer from the existing scoring system
func (h *Host) GetPeerScore(peerID gossipsub.PeerID) float64 {
	// Use our existing peer scorer
	return h.peerScorer.GetScore(PeerID(peerID))
}

// =============================================================================
// GossipSub message routing in Host
// =============================================================================

// handleGossipSubMessage routes an incoming GossipSub RPC
func (h *Host) handleGossipSubMessage(from PeerID, data []byte) error {
	if h.gossipSubRouter == nil {
		return fmt.Errorf("GossipSub router not initialized")
	}
	return h.gossipSubRouter.HandleRPC(string(from), data)
}

// GossipSub returns the GossipSub router instance
func (h *Host) GossipSub() *gossipsub.GossipSub {
	return h.gossipSubRouter
}

// =============================================================================
// GossipSub-based broadcasting (replaces direct broadcast)
// =============================================================================

// BroadcastBlockGS broadcasts a block through GossipSub
func (h *Host) BroadcastBlockGS(data []byte) error {
	if h.gossipSubRouter == nil {
		// Fall back to legacy broadcast
		return h.broadcast(MsgTypeBlock, data)
	}
	return h.gossipSubRouter.Publish(gossipsub.TopicBlocks, data)
}

// BroadcastTransactionGS broadcasts a transaction through GossipSub
func (h *Host) BroadcastTransactionGS(data []byte) error {
	if h.gossipSubRouter == nil {
		return h.broadcast(MsgTypeTransaction, data)
	}
	return h.gossipSubRouter.Publish(gossipsub.TopicTransactions, data)
}

// BroadcastVoteGS broadcasts a vote through GossipSub
func (h *Host) BroadcastVoteGS(data []byte) error {
	if h.gossipSubRouter == nil {
		return h.broadcast(MsgTypeVote, data)
	}
	return h.gossipSubRouter.Publish(gossipsub.TopicVotes, data)
}

// BroadcastAttestationGS broadcasts an attestation through GossipSub
func (h *Host) BroadcastAttestationGS(data []byte) error {
	if h.gossipSubRouter == nil {
		return h.broadcast(MsgTypeAttestation, data)
	}
	return h.gossipSubRouter.Publish(gossipsub.TopicAttestations, data)
}
