// Quantaureum Node source, version 1.0.0.
// Package node tests for the ShardBlockProducer wire format.
//
// P1-2 (2026-07-14): Tests the JSON encoding/decoding of shard blocks and
// attestations for P2P transport.
package node

import (
	"encoding/json"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
)

// TestEncodeDecodeShardBlock verifies that a shard block survives a
// encode→decode round-trip with all fields preserved.
func TestEncodeDecodeShardBlock(t *testing.T) {
	original := &consensus.ShardBlock{
		Header: &consensus.ShardBlockHeader{
			ShardID:      42,
			Height:       100,
			ParentHash:   types.Hash{0x01, 0x02, 0x03},
			StateRoot:    types.Hash{0x04, 0x05, 0x06},
			TxRoot:       types.Hash{0x07, 0x08, 0x09},
			CrossMsgRoot: types.Hash{0x0a, 0x0b, 0x0c},
			Timestamp:    1234567890,
			Proposer:     types.Address{0xaa, 0xbb, 0xcc},
			Signature:    []byte{0xde, 0xad, 0xbe, 0xef},
			VRFProof:     []byte{0x11, 0x22, 0x33},
			VRFOutput:    types.Hash{0x44, 0x55, 0x66},
		},
		Txs:       [][]byte{[]byte("tx1"), []byte("tx2")},
		CrossMsgs: nil,
	}

	data, err := encodeShardBlock(original)
	if err != nil {
		t.Fatalf("encodeShardBlock failed: %v", err)
	}

	decoded, err := decodeShardBlock(data)
	if err != nil {
		t.Fatalf("decodeShardBlock failed: %v", err)
	}

	// Verify all fields
	if decoded.Header.ShardID != original.Header.ShardID {
		t.Errorf("ShardID mismatch: got %d, want %d", decoded.Header.ShardID, original.Header.ShardID)
	}
	if decoded.Header.Height != original.Header.Height {
		t.Errorf("Height mismatch: got %d, want %d", decoded.Header.Height, original.Header.Height)
	}
	if decoded.Header.ParentHash != original.Header.ParentHash {
		t.Errorf("ParentHash mismatch")
	}
	if decoded.Header.StateRoot != original.Header.StateRoot {
		t.Errorf("StateRoot mismatch")
	}
	if decoded.Header.TxRoot != original.Header.TxRoot {
		t.Errorf("TxRoot mismatch")
	}
	if decoded.Header.CrossMsgRoot != original.Header.CrossMsgRoot {
		t.Errorf("CrossMsgRoot mismatch")
	}
	if decoded.Header.Timestamp != original.Header.Timestamp {
		t.Errorf("Timestamp mismatch: got %d, want %d", decoded.Header.Timestamp, original.Header.Timestamp)
	}
	if decoded.Header.Proposer != original.Header.Proposer {
		t.Errorf("Proposer mismatch")
	}
	if string(decoded.Header.Signature) != string(original.Header.Signature) {
		t.Errorf("Signature mismatch")
	}
	if string(decoded.Header.VRFProof) != string(original.Header.VRFProof) {
		t.Errorf("VRFProof mismatch")
	}
	if decoded.Header.VRFOutput != original.Header.VRFOutput {
		t.Errorf("VRFOutput mismatch")
	}
	if len(decoded.Txs) != len(original.Txs) {
		t.Errorf("Txs length mismatch: got %d, want %d", len(decoded.Txs), len(original.Txs))
	}
}

// TestEncodeDecodeShardAttestation verifies that an attestation survives a
// encode→decode round-trip.
func TestEncodeDecodeShardAttestation(t *testing.T) {
	shardID := uint64(7)
	height := uint64(99)
	validator := types.Address{0x11, 0x22, 0x33}
	sig := []byte{0xaa, 0xbb, 0xcc, 0xdd}

	data, err := encodeShardAttestation(shardID, height, validator, sig)
	if err != nil {
		t.Fatalf("encodeShardAttestation failed: %v", err)
	}

	dShardID, dHeight, dValidator, dSig, err := decodeShardAttestation(data)
	if err != nil {
		t.Fatalf("decodeShardAttestation failed: %v", err)
	}

	if dShardID != shardID {
		t.Errorf("ShardID mismatch: got %d, want %d", dShardID, shardID)
	}
	if dHeight != height {
		t.Errorf("Height mismatch: got %d, want %d", dHeight, height)
	}
	if dValidator != validator {
		t.Errorf("Validator mismatch")
	}
	if string(dSig) != string(sig) {
		t.Errorf("Signature mismatch")
	}
}

// TestDecodeShardBlock_InvalidJSON verifies that decoding invalid JSON
// returns an error.
func TestDecodeShardBlock_InvalidJSON(t *testing.T) {
	_, err := decodeShardBlock([]byte("not json"))
	if err == nil {
		t.Fatal("decodeShardBlock should fail on invalid JSON")
	}
}

// TestDecodeShardAttestation_InvalidJSON verifies that decoding invalid JSON
// returns an error.
func TestDecodeShardAttestation_InvalidJSON(t *testing.T) {
	_, _, _, _, err := decodeShardAttestation([]byte("not json"))
	if err == nil {
		t.Fatal("decodeShardAttestation should fail on invalid JSON")
	}
}

// TestCrossShardMessage_JSONRoundTrip verifies that CrossShardMessage can be
// JSON-serialized for P2P transport.
func TestCrossShardMessage_JSONRoundTrip(t *testing.T) {
	original := consensus.CrossShardMessage{
		ID:          types.Hash{0x01, 0x02},
		SourceShard: 1,
		DestShard:   2,
		Sender:      types.Address{0xaa},
		Recipient:   types.Address{0xbb},
		Payload:     []byte("payload"),
		Nonce:       42,
		Timestamp:   1234567890,
		Signature:   []byte{0xde, 0xad},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded consensus.CrossShardMessage
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID mismatch")
	}
	if decoded.SourceShard != original.SourceShard {
		t.Errorf("SourceShard mismatch")
	}
	if decoded.DestShard != original.DestShard {
		t.Errorf("DestShard mismatch")
	}
	if decoded.Nonce != original.Nonce {
		t.Errorf("Nonce mismatch")
	}
	if string(decoded.Payload) != string(original.Payload) {
		t.Errorf("Payload mismatch")
	}
	if string(decoded.Signature) != string(original.Signature) {
		t.Errorf("Signature mismatch")
	}
}
