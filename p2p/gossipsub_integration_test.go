// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"
)

func TestGossipSubTopics(t *testing.T) {
	topics := GossipSubTopics()
	// P1-1 (2026-07-14): added 2 shard topics (ShardBlocks, CrossShardMessages).
	if len(topics) != 6 {
		t.Fatalf("len(GossipSubTopics) = %d, want 6", len(topics))
	}

	expectedNames := map[string]bool{
		"qau_blocks_v1":           true,
		"qau_txs_v1":              true,
		"qau_votes_v1":            true,
		"qau_attestations_v1":     true,
		"qau_shard_blocks_v1":     true,
		"qau_cross_shard_msgs_v1": true,
	}

	for _, topic := range topics {
		if !expectedNames[topic.Name] {
			t.Errorf("unexpected topic name: %q", topic.Name)
		}
	}
}

func TestGossipSubTopicMsgTypes(t *testing.T) {
	topics := GossipSubTopics()

	for _, topic := range topics {
		if topic.MsgType == 0 {
			t.Errorf("topic %q has zero MsgType", topic.Name)
		}
	}
}

func TestGossipSubTopicBlocks(t *testing.T) {
	if GossipSubTopicBlocks.Name != "qau_blocks_v1" {
		t.Errorf("GossipSubTopicBlocks.Name = %q, want %q", GossipSubTopicBlocks.Name, "qau_blocks_v1")
	}
	if GossipSubTopicBlocks.MsgType != MsgTypeBlock {
		t.Errorf("GossipSubTopicBlocks.MsgType = %d, want %d", GossipSubTopicBlocks.MsgType, MsgTypeBlock)
	}
}

func TestGossipSubTopicTransactions(t *testing.T) {
	if GossipSubTopicTransactions.Name != "qau_txs_v1" {
		t.Errorf("GossipSubTopicTransactions.Name = %q, want %q", GossipSubTopicTransactions.Name, "qau_txs_v1")
	}
	if GossipSubTopicTransactions.MsgType != MsgTypeTransaction {
		t.Errorf("GossipSubTopicTransactions.MsgType = %d, want %d", GossipSubTopicTransactions.MsgType, MsgTypeTransaction)
	}
}

func TestGossipSubTopicVotes(t *testing.T) {
	if GossipSubTopicVotes.Name != "qau_votes_v1" {
		t.Errorf("GossipSubTopicVotes.Name = %q, want %q", GossipSubTopicVotes.Name, "qau_votes_v1")
	}
	if GossipSubTopicVotes.MsgType != MsgTypeVote {
		t.Errorf("GossipSubTopicVotes.MsgType = %d, want %d", GossipSubTopicVotes.MsgType, MsgTypeVote)
	}
}

func TestGossipSubTopicAttestations(t *testing.T) {
	if GossipSubTopicAttestations.Name != "qau_attestations_v1" {
		t.Errorf("GossipSubTopicAttestations.Name = %q, want %q", GossipSubTopicAttestations.Name, "qau_attestations_v1")
	}
	if GossipSubTopicAttestations.MsgType != MsgTypeAttestation {
		t.Errorf("GossipSubTopicAttestations.MsgType = %d, want %d", GossipSubTopicAttestations.MsgType, MsgTypeAttestation)
	}
}

func TestMsgTypeGossipSub(t *testing.T) {
	if MsgTypeGossipSub != 60 {
		t.Errorf("MsgTypeGossipSub = %d, want 60", MsgTypeGossipSub)
	}
}
