// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"
)

// TestMessageSizeLimits verifies that all message size limit constants are correctly defined.
func TestMessageSizeLimits(t *testing.T) {
	tests := []struct {
		name     string
		size     uint64
		minValue uint64
	}{
		{"DefaultMaxMessageSize", DefaultMaxMessageSize, 1 * 1024 * 1024},
		{"MaxBlockMessageSize", MaxBlockMessageSize, 10 * 1024 * 1024},
		{"MaxTransactionMessageSize", MaxTransactionMessageSize, 1 * 1024 * 1024},
		{"MaxVoteMessageSize", MaxVoteMessageSize, 64 * 1024},
		{"MaxStatusMessageSize", MaxStatusMessageSize, 1 * 1024},
		{"MaxPingPongMessageSize", MaxPingPongMessageSize, 256},
		{"MaxBlockResponseSize", MaxBlockResponseSize, 10 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.size != tt.minValue {
				t.Errorf("%s = %d, want %d", tt.name, tt.size, tt.minValue)
			}
		})
	}
}

// TestBlockMessageValidator verifies block message size validation.
func TestBlockMessageValidator(t *testing.T) {
	v := &BlockMessageValidator{}

	// Valid size (under 10MB)
	payload := make([]byte, 1024)
	if err := v.Validate(payload); err != nil {
		t.Errorf("Validate(1KB) = %v, want nil", err)
	}

	// Empty payload (below min size)
	if err := v.Validate([]byte{}); err != nil {
		t.Errorf("Validate(empty) = %v, want nil (min=1 byte)", err)
	}

	// Over max size (10MB + 1)
	oversized := make([]byte, MaxBlockMessageSize+1)
	if err := v.Validate(oversized); err == nil {
		t.Error("Validate(10MB+1) = nil, want error")
	}
}

// TestTransactionMessageValidator verifies transaction message size validation.
func TestTransactionMessageValidator(t *testing.T) {
	v := &TransactionMessageValidator{}

	// Valid size
	payload := make([]byte, 512)
	if err := v.Validate(payload); err != nil {
		t.Errorf("Validate(512B) = %v, want nil", err)
	}

	// Over max size (1MB + 1)
	oversized := make([]byte, MaxTransactionMessageSize+1)
	if err := v.Validate(oversized); err == nil {
		t.Error("Validate(1MB+1) = nil, want error")
	}
}

// TestVoteMessageValidator verifies vote message size validation.
func TestVoteMessageValidator(t *testing.T) {
	v := &VoteMessageValidator{}

	// Valid size
	payload := make([]byte, 32)
	if err := v.Validate(payload); err != nil {
		t.Errorf("Validate(32B) = %v, want nil", err)
	}

	// Over max size (64KB + 1)
	oversized := make([]byte, MaxVoteMessageSize+1)
	if err := v.Validate(oversized); err == nil {
		t.Error("Validate(64KB+1) = nil, want error")
	}
}

// TestPingPongValidator verifies ping/pong message size validation.
func TestPingPongValidator(t *testing.T) {
	v := &PingPongValidator{}

	// Empty payload is valid for ping/pong (min=0)
	if err := v.Validate([]byte{}); err != nil {
		t.Errorf("Validate(empty) = %v, want nil", err)
	}

	// Small payload
	if err := v.Validate([]byte{0x01}); err != nil {
		t.Errorf("Validate(1B) = %v, want nil", err)
	}

	// Over max size (256 + 1)
	oversized := make([]byte, MaxPingPongMessageSize+1)
	if err := v.Validate(oversized); err == nil {
		t.Error("Validate(257B) = nil, want error")
	}
}

// TestBatchMessageValidator verifies batch message size validation.
func TestBatchMessageValidator(t *testing.T) {
	v := &BatchMessageValidator{}

	// Valid size (just header, 4 bytes min)
	payload := make([]byte, 4)
	if err := v.Validate(payload); err != nil {
		t.Errorf("Validate(4B) = %v, want nil", err)
	}

	// Too small (below min=4)
	if err := v.Validate([]byte{0x01}); err == nil {
		t.Error("Validate(1B) = nil, want error (min=4)")
	}

	// Over max size (2MB + 1)
	oversized := make([]byte, 2*1024*1024+1)
	if err := v.Validate(oversized); err == nil {
		t.Error("Validate(2MB+1) = nil, want error")
	}
}

// TestGetMaxSizeForType verifies that GetMaxSizeForType returns correct sizes.
func TestGetMaxSizeForType(t *testing.T) {
	v := NewMessageValidator()

	tests := []struct {
		msgType  uint8
		expected uint64
	}{
		{MsgTypeBlock, MaxBlockMessageSize},
		{MsgTypeTransaction, MaxTransactionMessageSize},
		{MsgTypeVote, MaxVoteMessageSize},
		{MsgTypeStatus, MaxStatusMessageSize},
		{MsgTypePing, MaxPingPongMessageSize},
		{MsgTypePong, MaxPingPongMessageSize},
	}

	for _, tt := range tests {
		size, err := v.GetMaxSizeForType(tt.msgType)
		if err != nil {
			t.Errorf("GetMaxSizeForType(%d) error: %v", tt.msgType, err)
		}
		if size != tt.expected {
			t.Errorf("GetMaxSizeForType(%d) = %d, want %d", tt.msgType, size, tt.expected)
		}
	}
}
