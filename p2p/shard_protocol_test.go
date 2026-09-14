// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"
)

// TestValidateMessageType_Shard verifies shard message types are recognized.
// P1-1 (2026-07-14)
func TestValidateMessageType_Shard(t *testing.T) {
	shardTypes := []uint8{
		MsgTypeShardBlock, MsgTypeShardBlockReq, MsgTypeShardBlockResp,
		MsgTypeShardAttestation, MsgTypeCrossShardMsg, MsgTypeCrossShardReceipt,
	}
	for _, mt := range shardTypes {
		if !ValidateMessageType(mt) {
			t.Errorf("ValidateMessageType(%d) = false, want true", mt)
		}
	}
}

// TestValidateMessage_Shard verifies size bounds for shard messages.
// P1-1 (2026-07-14)
func TestValidateMessage_Shard(t *testing.T) {
	tests := []struct {
		name    string
		msgType uint8
		payload []byte
		wantErr bool
	}{
		{"ShardBlock valid", MsgTypeShardBlock, make([]byte, 100), false},
		{"ShardBlock too small", MsgTypeShardBlock, make([]byte, 16), true},
		{"ShardBlock too large", MsgTypeShardBlock, make([]byte, 3*1024*1024), true},
		{"ShardBlockReq valid", MsgTypeShardBlockReq, make([]byte, 16), false},
		{"ShardBlockReq wrong size", MsgTypeShardBlockReq, make([]byte, 15), true},
		{"ShardBlockResp valid", MsgTypeShardBlockResp, make([]byte, 100), false},
		{"ShardBlockResp too small", MsgTypeShardBlockResp, make([]byte, 16), true},
		{"ShardAttestation valid", MsgTypeShardAttestation, make([]byte, 100), false},
		{"ShardAttestation too small", MsgTypeShardAttestation, make([]byte, 16), true},
		{"ShardAttestation too large", MsgTypeShardAttestation, make([]byte, 8*1024), true},
		{"CrossShardMsg valid", MsgTypeCrossShardMsg, make([]byte, 100), false},
		{"CrossShardMsg too small", MsgTypeCrossShardMsg, make([]byte, 16), true},
		{"CrossShardMsg too large", MsgTypeCrossShardMsg, make([]byte, 128*1024), true},
		{"CrossShardReceipt valid", MsgTypeCrossShardReceipt, make([]byte, 100), false},
		{"CrossShardReceipt too small", MsgTypeCrossShardReceipt, make([]byte, 16), true},
		{"CrossShardReceipt too large", MsgTypeCrossShardReceipt, make([]byte, 8*1024), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &Message{Type: tt.msgType, Payload: tt.payload}
			err := ValidateMessage(msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMessage() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// TestProtocolRegistry_ShardRegistered verifies the shard protocol is registered.
// P1-1 (2026-07-14)
func TestProtocolRegistry_ShardRegistered(t *testing.T) {
	cfg := &Config{
		ListenAddr:   "127.0.0.1:0",
		MaxPeers:     10,
		TrustedPeers: []string{},
		DevMode:      true,
	}
	host, err := NewHost(cfg)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Stop()

	proto := host.protocolRegistry.GetProtocol(ProtocolShard)
	if proto == nil {
		t.Fatal("Shard protocol not registered")
	}
	if !proto.Enabled {
		t.Error("Shard protocol should be enabled")
	}
	shardTypes := []uint8{
		MsgTypeShardBlock, MsgTypeShardBlockReq, MsgTypeShardBlockResp,
		MsgTypeShardAttestation, MsgTypeCrossShardMsg, MsgTypeCrossShardReceipt,
	}
	for _, mt := range shardTypes {
		if !proto.Spec.MsgTypes[mt] {
			t.Errorf("message type %d not registered in Shard protocol", mt)
		}
	}
}

// TestHost_ShardChannels verifies that shard channel subscriptions return
// non-nil channels.
// P1-1 (2026-07-14)
func TestHost_ShardChannels(t *testing.T) {
	cfg := &Config{
		ListenAddr:   "127.0.0.1:0",
		MaxPeers:     10,
		TrustedPeers: []string{},
		DevMode:      true,
	}
	host, err := NewHost(cfg)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Stop()

	if host.SubscribeShardBlocks() == nil {
		t.Error("SubscribeShardBlocks returned nil")
	}
	if host.SubscribeShardBlockRequests() == nil {
		t.Error("SubscribeShardBlockRequests returned nil")
	}
	if host.SubscribeShardBlockResponses() == nil {
		t.Error("SubscribeShardBlockResponses returned nil")
	}
	if host.SubscribeShardAttestations() == nil {
		t.Error("SubscribeShardAttestations returned nil")
	}
	if host.SubscribeCrossShardMessages() == nil {
		t.Error("SubscribeCrossShardMessages returned nil")
	}
	if host.SubscribeCrossShardReceipts() == nil {
		t.Error("SubscribeCrossShardReceipts returned nil")
	}
}

// TestHandleShardProtocol_Routing verifies that handleShardProtocol routes
// messages to the correct channels.
// P1-1 (2026-07-14)
func TestHandleShardProtocol_Routing(t *testing.T) {
	cfg := &Config{
		ListenAddr:   "127.0.0.1:0",
		MaxPeers:     10,
		TrustedPeers: []string{},
		DevMode:      true,
	}
	host, err := NewHost(cfg)
	if err != nil {
		t.Fatalf("NewHost failed: %v", err)
	}
	defer host.Stop()

	// Send a shard block message and verify it arrives on shardBlockCh.
	blockPayload := make([]byte, 100)
	msg := &Message{Type: MsgTypeShardBlock, Payload: blockPayload}
	if err := host.handleShardProtocol(msg); err != nil {
		t.Fatalf("handleShardProtocol failed: %v", err)
	}
	select {
	case received := <-host.SubscribeShardBlocks():
		if len(received) != len(blockPayload) {
			t.Errorf("received payload size = %d, want %d", len(received), len(blockPayload))
		}
	default:
		t.Error("shard block not received on channel")
	}

	// Send a cross-shard message and verify it arrives on crossShardMsgCh.
	crossMsgPayload := make([]byte, 100)
	msg2 := &Message{Type: MsgTypeCrossShardMsg, Payload: crossMsgPayload}
	if err := host.handleShardProtocol(msg2); err != nil {
		t.Fatalf("handleShardProtocol failed: %v", err)
	}
	select {
	case received := <-host.SubscribeCrossShardMessages():
		if len(received) != len(crossMsgPayload) {
			t.Errorf("received payload size = %d, want %d", len(received), len(crossMsgPayload))
		}
	default:
		t.Error("cross-shard message not received on channel")
	}
}
