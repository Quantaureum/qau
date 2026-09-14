// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"
	"time"
)

func TestEncodeDecodeMessage(t *testing.T) {
	payload := []byte("hello world")
	encoded, err := EncodeMessage(MsgTypeBlock, payload)
	if err != nil {
		t.Fatalf("EncodeMessage failed: %v", err)
	}

	msg, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeMessage failed: %v", err)
	}

	if msg.Type != MsgTypeBlock {
		t.Errorf("msg.Type = %d, want %d", msg.Type, MsgTypeBlock)
	}
	if string(msg.Payload) != string(payload) {
		t.Errorf("msg.Payload = %q, want %q", string(msg.Payload), string(payload))
	}
}

func TestEncodeMessageTooLarge(t *testing.T) {
	largePayload := make([]byte, MaxMsgSize+1)
	_, err := EncodeMessage(MsgTypeBlock, largePayload)
	if err != ErrMsgTooLarge {
		t.Errorf("expected ErrMsgTooLarge, got %v", err)
	}
}

func TestDecodeMessageTooShort(t *testing.T) {
	_, err := DecodeMessage([]byte{1, 2, 3})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage, got %v", err)
	}
}

func TestDecodeMessageInvalidChecksum(t *testing.T) {
	encoded, err := EncodeMessage(MsgTypeBlock, []byte("test"))
	if err != nil {
		t.Fatalf("EncodeMessage failed: %v", err)
	}
	// Corrupt checksum bytes
	encoded[5] ^= 0xFF
	_, err = DecodeMessage(encoded)
	if err != ErrInvalidChecksum {
		t.Errorf("expected ErrInvalidChecksum, got %v", err)
	}
}

func TestEncodeDecodeStatusMessage(t *testing.T) {
	status := &StatusMessage{
		Version:    1,
		NetworkID:  1668,
		BestHeight: 100,
	}
	copy(status.BestHash[:], []byte("best_hash_0001_0001_0001_0001"))
	copy(status.GenesisHash[:], []byte("genesis_hash_0001_0001_0001_01"))

	encoded := EncodeStatusMessage(status)
	decoded, err := DecodeStatusMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeStatusMessage failed: %v", err)
	}

	if decoded.Version != status.Version {
		t.Errorf("Version = %d, want %d", decoded.Version, status.Version)
	}
	if decoded.NetworkID != status.NetworkID {
		t.Errorf("NetworkID = %d, want %d", decoded.NetworkID, status.NetworkID)
	}
	if decoded.BestHeight != status.BestHeight {
		t.Errorf("BestHeight = %d, want %d", decoded.BestHeight, status.BestHeight)
	}
}

func TestDecodeStatusMessageTooShort(t *testing.T) {
	_, err := DecodeStatusMessage([]byte{1, 2, 3})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage, got %v", err)
	}
}

func TestEncodeDecodeBlockRequest(t *testing.T) {
	req := &BlockRequest{
		FromHeight: 10,
		ToHeight:   20,
		Hashes:     [][32]byte{{1, 2, 3}},
	}
	encoded := EncodeBlockRequest(req)
	decoded, err := DecodeBlockRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeBlockRequest failed: %v", err)
	}
	if decoded.FromHeight != req.FromHeight {
		t.Errorf("FromHeight = %d, want %d", decoded.FromHeight, req.FromHeight)
	}
	if decoded.ToHeight != req.ToHeight {
		t.Errorf("ToHeight = %d, want %d", decoded.ToHeight, req.ToHeight)
	}
	if len(decoded.Hashes) != 1 {
		t.Fatalf("len(Hashes) = %d, want 1", len(decoded.Hashes))
	}
	if decoded.Hashes[0] != req.Hashes[0] {
		t.Error("Hash mismatch")
	}
}

func TestDecodeBlockRequestTooShort(t *testing.T) {
	_, err := DecodeBlockRequest([]byte{1, 2, 3})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage, got %v", err)
	}
}

func TestEncodeDecodeBlockResponse(t *testing.T) {
	resp := &BlockResponse{
		Blocks: [][]byte{[]byte("block1"), []byte("block2")},
	}
	encoded := EncodeBlockResponse(resp)
	decoded, err := DecodeBlockResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeBlockResponse failed: %v", err)
	}
	if len(decoded.Blocks) != 2 {
		t.Fatalf("len(Blocks) = %d, want 2", len(decoded.Blocks))
	}
	if string(decoded.Blocks[0]) != "block1" {
		t.Errorf("Blocks[0] = %q, want %q", string(decoded.Blocks[0]), "block1")
	}
}

func TestDecodeBlockResponseTooShort(t *testing.T) {
	_, err := DecodeBlockResponse([]byte{1, 2})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage, got %v", err)
	}
}

func TestEncodeDecodeBatchMessage(t *testing.T) {
	batch := &BatchMessage{
		Messages: []*Message{
			{Type: MsgTypeBlock, Payload: []byte("block-data")},
			{Type: MsgTypeTransaction, Payload: []byte("tx-data")},
		},
	}
	encoded, err := EncodeBatchMessage(batch)
	if err != nil {
		t.Fatalf("EncodeBatchMessage failed: %v", err)
	}

	decoded, err := DecodeBatchMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeBatchMessage failed: %v", err)
	}
	if len(decoded.Messages) != 2 {
		t.Fatalf("len(Messages) = %d, want 2", len(decoded.Messages))
	}
	if decoded.Messages[0].Type != MsgTypeBlock {
		t.Errorf("Messages[0].Type = %d, want %d", decoded.Messages[0].Type, MsgTypeBlock)
	}
}

func TestEncodeBatchMessageEmpty(t *testing.T) {
	batch := &BatchMessage{Messages: []*Message{}}
	_, err := EncodeBatchMessage(batch)
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage for empty batch, got %v", err)
	}
}

func TestDecodeBatchMessageTooShort(t *testing.T) {
	_, err := DecodeBatchMessage([]byte{1, 2})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage, got %v", err)
	}
}

func TestEncodeDecodeSubMessage(t *testing.T) {
	msg := &Message{Type: MsgTypeVote, Payload: []byte("vote-data")}
	encoded, err := EncodeSubMessage(msg)
	if err != nil {
		t.Fatalf("EncodeSubMessage failed: %v", err)
	}

	decoded, err := DecodeSubMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeSubMessage failed: %v", err)
	}
	if decoded.Type != MsgTypeVote {
		t.Errorf("Type = %d, want %d", decoded.Type, MsgTypeVote)
	}
	if string(decoded.Payload) != "vote-data" {
		t.Errorf("Payload = %q, want %q", string(decoded.Payload), "vote-data")
	}
}

func TestDecodeSubMessageTooShort(t *testing.T) {
	_, err := DecodeSubMessage([]byte{1, 2, 3})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage, got %v", err)
	}
}

func TestValidateMessage(t *testing.T) {
	tests := []struct {
		name    string
		msg     *Message
		wantErr bool
	}{
		{"nil message", nil, true},
		{"block empty payload", &Message{Type: MsgTypeBlock, Payload: []byte{}}, true},
		{"block valid", &Message{Type: MsgTypeBlock, Payload: []byte("data")}, false},
		{"tx empty payload", &Message{Type: MsgTypeTransaction, Payload: []byte{}}, true},
		{"tx valid", &Message{Type: MsgTypeTransaction, Payload: []byte("data")}, false},
		{"vote empty", &Message{Type: MsgTypeVote, Payload: []byte{}}, true},
		{"vote valid", &Message{Type: MsgTypeVote, Payload: []byte("data")}, false},
		{"ping empty", &Message{Type: MsgTypePing, Payload: []byte{}}, false},
		{"pong empty", &Message{Type: MsgTypePong, Payload: []byte{}}, false},
		{"status valid", &Message{Type: MsgTypeStatus, Payload: []byte{}}, false},
		{"findnode wrong size", &Message{Type: MsgTypeFindNode, Payload: []byte("short")}, true},
		{"findnode valid", &Message{Type: MsgTypeFindNode, Payload: make([]byte, 32)}, false},
		{"neighbors too short", &Message{Type: MsgTypeNeighbors, Payload: []byte{1}}, true},
		{"neighbors valid", &Message{Type: MsgTypeNeighbors, Payload: []byte{0, 1}}, false},
		{"checkpoint sig too short", &Message{Type: MsgTypeCheckpointSig, Payload: make([]byte, 32)}, true},
		{"checkpoint sig valid", &Message{Type: MsgTypeCheckpointSig, Payload: make([]byte, 100)}, false},
		{"checkpoint req too short", &Message{Type: MsgTypeCheckpointReq, Payload: make([]byte, 4)}, true},
		{"checkpoint req valid", &Message{Type: MsgTypeCheckpointReq, Payload: make([]byte, 10)}, false},
		{"invalid type", &Message{Type: 99, Payload: []byte("data")}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMessage(tt.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMessage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncodeDecodeCheckpointSig(t *testing.T) {
	msg := &CheckpointSigMessage{
		Height:    100,
		Epoch:     5,
		Signature: []byte("dilithium3-signature-data"),
	}
	copy(msg.BlockHash[:], []byte("block_hash_0001_0001_0001_0001"))
	copy(msg.StateRoot[:], []byte("state_root_0001_0001_0001_0001"))
	copy(msg.ValidatorAddr[:], []byte("validator_addr_0001"))

	encoded := EncodeCheckpointSig(msg)
	decoded, err := DecodeCheckpointSig(encoded)
	if err != nil {
		t.Fatalf("DecodeCheckpointSig failed: %v", err)
	}
	if decoded.Height != msg.Height {
		t.Errorf("Height = %d, want %d", decoded.Height, msg.Height)
	}
	if decoded.Epoch != msg.Epoch {
		t.Errorf("Epoch = %d, want %d", decoded.Epoch, msg.Epoch)
	}
	if string(decoded.Signature) != string(msg.Signature) {
		t.Errorf("Signature mismatch")
	}
}

func TestDecodeCheckpointSigTooShort(t *testing.T) {
	_, err := DecodeCheckpointSig(make([]byte, 50))
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage, got %v", err)
	}
}

func TestEncodeDecodeCheckpointReq(t *testing.T) {
	msg := &CheckpointReqMessage{Height: 42}
	encoded := EncodeCheckpointReq(msg)
	decoded, err := DecodeCheckpointReq(encoded)
	if err != nil {
		t.Fatalf("DecodeCheckpointReq failed: %v", err)
	}
	if decoded.Height != msg.Height {
		t.Errorf("Height = %d, want %d", decoded.Height, msg.Height)
	}
}

func TestDecodeCheckpointReqTooShort(t *testing.T) {
	_, err := DecodeCheckpointReq([]byte{1, 2, 3})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage, got %v", err)
	}
}

func TestPeerIDString(t *testing.T) {
	id := PeerID("test-peer-id")
	if id.String() != "test-peer-id" {
		t.Errorf("PeerID.String() = %q, want %q", id.String(), "test-peer-id")
	}
}

func TestNewPeerID(t *testing.T) {
	id, err := NewPeerID()
	if err != nil {
		t.Fatalf("NewPeerID failed: %v", err)
	}
	if len(id) != 64 { // 32 bytes hex = 64 chars
		t.Errorf("len(PeerID) = %d, want 64", len(id))
	}
}

func TestCrc32Checksum(t *testing.T) {
	data := []byte("test data for crc32")
	checksum1 := crc32Checksum(data)
	checksum2 := crc32Checksum(data)
	if checksum1 != checksum2 {
		t.Error("crc32Checksum should be deterministic")
	}
	differentData := []byte("different data for crc32")
	checksum3 := crc32Checksum(differentData)
	if checksum1 == checksum3 {
		t.Error("different data should produce different checksums")
	}
}

func TestIsSyncMessage(t *testing.T) {
	syncTypes := []uint8{MsgTypeBlock, MsgTypeBlockReq, MsgTypeBlockResp, MsgTypeStatus,
		MsgTypeSnapStateReq, MsgTypeSnapStateResp, MsgTypeSnapRangeReq, MsgTypeSnapRangeResp}
	for _, mt := range syncTypes {
		if !isSyncMessage(mt) {
			t.Errorf("isSyncMessage(%d) = false, want true", mt)
		}
	}
	nonSyncTypes := []uint8{MsgTypeTransaction, MsgTypeVote, MsgTypePing, MsgTypePong}
	for _, mt := range nonSyncTypes {
		if isSyncMessage(mt) {
			t.Errorf("isSyncMessage(%d) = true, want false", mt)
		}
	}
}

func TestEncodeDecodeProtocolNegotiate(t *testing.T) {
	msg := &ProtocolNegotiateMessage{
		Protocols: []ProtocolSpec{
			{Name: "qau_blockchain", Version: 1},
			{Name: "qau_consensus", Version: 1},
		},
	}
	encoded, err := EncodeProtocolNegotiate(msg)
	if err != nil {
		t.Fatalf("EncodeProtocolNegotiate failed: %v", err)
	}
	decoded, err := DecodeProtocolNegotiate(encoded)
	if err != nil {
		t.Fatalf("DecodeProtocolNegotiate failed: %v", err)
	}
	if len(decoded.Protocols) != 2 {
		t.Fatalf("len(Protocols) = %d, want 2", len(decoded.Protocols))
	}
	if decoded.Protocols[0].Name != "qau_blockchain" {
		t.Errorf("Protocols[0].Name = %q, want %q", decoded.Protocols[0].Name, "qau_blockchain")
	}
	if decoded.Protocols[0].Version != 1 {
		t.Errorf("Protocols[0].Version = %d, want 1", decoded.Protocols[0].Version)
	}
}

func TestEncodeProtocolNegotiateEmpty(t *testing.T) {
	msg := &ProtocolNegotiateMessage{Protocols: []ProtocolSpec{}}
	_, err := EncodeProtocolNegotiate(msg)
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage for empty protocols, got %v", err)
	}
}

func TestDecodeProtocolNegotiateTooShort(t *testing.T) {
	_, err := DecodeProtocolNegotiate([]byte{1})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage, got %v", err)
	}
}

func TestEncodeDecodeProtocolNegotiateResp(t *testing.T) {
	msg := &ProtocolNegotiateRespMessage{
		AgreedProtocols: []ProtocolSpec{
			{Name: "qau_blockchain", Version: 1},
		},
	}
	encoded, err := EncodeProtocolNegotiateResp(msg)
	if err != nil {
		t.Fatalf("EncodeProtocolNegotiateResp failed: %v", err)
	}
	decoded, err := DecodeProtocolNegotiateResp(encoded)
	if err != nil {
		t.Fatalf("DecodeProtocolNegotiateResp failed: %v", err)
	}
	if len(decoded.AgreedProtocols) != 1 {
		t.Fatalf("len(AgreedProtocols) = %d, want 1", len(decoded.AgreedProtocols))
	}
	if decoded.AgreedProtocols[0].Name != "qau_blockchain" {
		t.Errorf("AgreedProtocols[0].Name = %q, want %q", decoded.AgreedProtocols[0].Name, "qau_blockchain")
	}
}

func TestMessageTimestamp(t *testing.T) {
	before := time.Now()
	encoded, _ := EncodeMessage(MsgTypePing, nil)
	msg, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeMessage failed: %v", err)
	}
	after := time.Now()
	if msg.Timestamp.Before(before) || msg.Timestamp.After(after) {
		t.Error("Message timestamp out of expected range")
	}
}

// ── TSS distributed DKG message types (Task 5) ──

func TestTSSDKGMessageTypeValues(t *testing.T) {
	if MsgTypeTSSDKGCommitment != 77 {
		t.Errorf("MsgTypeTSSDKGCommitment = %d, want 77", MsgTypeTSSDKGCommitment)
	}
	if MsgTypeTSSDKGAck != 78 {
		t.Errorf("MsgTypeTSSDKGAck = %d, want 78", MsgTypeTSSDKGAck)
	}
	// Both must sit inside the reserved TSS protocol range (70-79).
	if MsgTypeTSSDKGCommitment < 70 || MsgTypeTSSDKGCommitment > 79 {
		t.Errorf("MsgTypeTSSDKGCommitment=%d outside TSS range 70-79", MsgTypeTSSDKGCommitment)
	}
	if MsgTypeTSSDKGAck < 70 || MsgTypeTSSDKGAck > 79 {
		t.Errorf("MsgTypeTSSDKGAck=%d outside TSS range 70-79", MsgTypeTSSDKGAck)
	}
}

func TestTSSDKGMessageTypesValid(t *testing.T) {
	if !ValidateMessageType(MsgTypeTSSDKGCommitment) {
		t.Error("ValidateMessageType(MsgTypeTSSDKGCommitment) = false, want true")
	}
	if !ValidateMessageType(MsgTypeTSSDKGAck) {
		t.Error("ValidateMessageType(MsgTypeTSSDKGAck) = false, want true")
	}
}

func TestTSSDKGMessageEncodeDecode(t *testing.T) {
	for _, mt := range []uint8{MsgTypeTSSDKGCommitment, MsgTypeTSSDKGAck} {
		payload := []byte(`{"ParticipantID":1,"Commitment":"AA==","PubContribution":"AQ=="}`)
		encoded, err := EncodeMessage(mt, payload)
		if err != nil {
			t.Fatalf("EncodeMessage(%d) failed: %v", mt, err)
		}
		decoded, err := DecodeMessage(encoded)
		if err != nil {
			t.Fatalf("DecodeMessage(%d) failed: %v", mt, err)
		}
		if decoded.Type != mt {
			t.Errorf("decoded.Type = %d, want %d", decoded.Type, mt)
		}
		if string(decoded.Payload) != string(payload) {
			t.Errorf("payload mismatch for type %d", mt)
		}
	}
}

func TestValidateMessage_TSSDKGTypes(t *testing.T) {
	// Empty payloads must be rejected for both new DKG message types
	// (size-bounded in ValidateMessage to prevent unbounded memory use).
	for _, mt := range []uint8{MsgTypeTSSDKGCommitment, MsgTypeTSSDKGAck} {
		err := ValidateMessage(&Message{Type: mt, Payload: []byte{}})
		if err == nil {
			t.Errorf("ValidateMessage(%d) with empty payload: expected error, got nil", mt)
		}
	}
	// A realistic-size DKG commitment payload must be accepted.
	validCommit := make([]byte, 4096)
	if err := ValidateMessage(&Message{Type: MsgTypeTSSDKGCommitment, Payload: validCommit}); err != nil {
		t.Errorf("ValidateMessage(%d) with 4KB payload: unexpected error %v", MsgTypeTSSDKGCommitment, err)
	}
}
