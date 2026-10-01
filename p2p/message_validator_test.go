// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"errors"
	"testing"
	"time"
)

func TestNewMessageValidator(t *testing.T) {
	mv := NewMessageValidator()
	if mv == nil {
		t.Fatal("NewMessageValidator returned nil")
	}
}

func TestMessageValidatorValidateMessageNil(t *testing.T) {
	mv := NewMessageValidator()

	err := mv.ValidateMessage(nil)
	if err != ErrNilMessage {
		t.Errorf("expected ErrNilMessage, got %v", err)
	}
}

func TestMessageValidatorBlockValid(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypeBlock, Payload: []byte("valid-block-data"), Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err != nil {
		t.Errorf("ValidateMessage should pass for valid block: %v", err)
	}
}

func TestMessageValidatorBlockEmpty(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypeBlock, Payload: []byte{}, Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err == nil {
		t.Error("expected error for empty block payload")
	}
}

func TestMessageValidatorBlockTooLarge(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypeBlock, Payload: make([]byte, MaxBlockMessageSize+1), Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err == nil {
		t.Error("expected error for too large block payload")
	}
}

func TestMessageValidatorTxValid(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypeTransaction, Payload: []byte("valid-tx-data"), Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err != nil {
		t.Errorf("ValidateMessage should pass for valid tx: %v", err)
	}
}

func TestMessageValidatorTxEmpty(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypeTransaction, Payload: []byte{}, Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err == nil {
		t.Error("expected error for empty tx payload")
	}
}

func TestMessageValidatorVoteValid(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypeVote, Payload: []byte("valid-vote-data"), Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err != nil {
		t.Errorf("ValidateMessage should pass for valid vote: %v", err)
	}
}

func TestMessageValidatorVoteEmpty(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypeVote, Payload: []byte{}, Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err == nil {
		t.Error("expected error for empty vote payload")
	}
}

func TestMessageValidatorPingValid(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypePing, Payload: []byte{}, Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err != nil {
		t.Errorf("ValidateMessage should pass for valid ping: %v", err)
	}
}

func TestMessageValidatorPongValid(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypePong, Payload: []byte{}, Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err != nil {
		t.Errorf("ValidateMessage should pass for valid pong: %v", err)
	}
}

func TestMessageValidatorFindNodeValid(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypeFindNode, Payload: make([]byte, 32), Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err != nil {
		t.Errorf("ValidateMessage should pass for valid findnode: %v", err)
	}
}

func TestMessageValidatorFindNodeWrongSize(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypeFindNode, Payload: []byte("short"), Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err == nil {
		t.Error("expected error for wrong size findnode")
	}
}

func TestMessageValidatorNeighborsValid(t *testing.T) {
	mv := NewMessageValidator()

	// count=0, just the 2-byte header
	msg := &Message{Type: MsgTypeNeighbors, Payload: []byte{0, 0}, Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err != nil {
		t.Errorf("ValidateMessage should pass for valid neighbors: %v", err)
	}
}

func TestMessageValidatorNeighborsTooShort(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypeNeighbors, Payload: []byte{1}, Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err == nil {
		t.Error("expected error for too short neighbors")
	}
}

func TestMessageValidatorInvalidType(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: 99, Payload: []byte("data"), Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err == nil {
		t.Error("expected error for invalid message type")
	}
}

func TestMessageValidatorStatusValid(t *testing.T) {
	mv := NewMessageValidator()

	// Create a valid status message payload (at least 84 bytes)
	payload := make([]byte, MinStatusMessageSize)
	msg := &Message{Type: MsgTypeStatus, Payload: payload, Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err != nil {
		t.Errorf("ValidateMessage should pass for valid status: %v", err)
	}
}

func TestMessageValidatorStatusTooShort(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypeStatus, Payload: []byte("short"), Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err == nil {
		t.Error("expected error for too short status")
	}
}

func TestMessageValidatorRegisterValidator(t *testing.T) {
	mv := NewMessageValidator()

	called := false
	mv.RegisterValidator(99, &testValidator{
		maxSize: 1024,
		minSize: 1,
		validateFn: func(payload []byte) error {
			called = true
			return nil
		},
	})

	msg := &Message{Type: 99, Payload: []byte("data"), Timestamp: time.Now()}
	err := mv.ValidateMessage(msg)
	if err != nil {
		t.Fatalf("ValidateMessage failed: %v", err)
	}
	if !called {
		t.Error("custom validator should be called")
	}
}

func TestMessageValidatorGetMaxSizeForType(t *testing.T) {
	mv := NewMessageValidator()

	maxSize, err := mv.GetMaxSizeForType(MsgTypeBlock)
	if err != nil {
		t.Fatalf("GetMaxSizeForType failed: %v", err)
	}
	if maxSize != MaxBlockMessageSize {
		t.Errorf("maxSize = %d, want %d", maxSize, MaxBlockMessageSize)
	}
}

func TestMessageValidatorGetMaxSizeForInvalidType(t *testing.T) {
	mv := NewMessageValidator()

	// 102 is unassigned: types 90-101 are the threshold Dilithium3 v1
	// protocol block (DKG 90-96, signing 97-100, activation certificate 101).
	_, err := mv.GetMaxSizeForType(102)
	if err == nil {
		t.Error("expected error for invalid message type")
	}
}

func TestMessageValidatorValidateRawMessage(t *testing.T) {
	mv := NewMessageValidator()

	// Create a valid raw message header
	data := make([]byte, MsgHeaderSize+10)
	data[0] = MsgTypeBlock
	// length = 10
	data[1] = 0
	data[2] = 0
	data[3] = 0
	data[4] = 10

	err := mv.ValidateRawMessage(data)
	if err != nil {
		t.Errorf("ValidateRawMessage failed: %v", err)
	}
}

func TestMessageValidatorValidateRawMessageTooShort(t *testing.T) {
	mv := NewMessageValidator()

	err := mv.ValidateRawMessage([]byte{1, 2, 3})
	if err != ErrMalformedMessage {
		t.Errorf("expected ErrMalformedMessage, got %v", err)
	}
}

func TestMessageValidatorIsDuplicate(t *testing.T) {
	mv := NewMessageValidator()

	if mv.IsDuplicate("hash1") {
		t.Error("first check should not be duplicate")
	}
	if !mv.IsDuplicate("hash1") {
		t.Error("second check should be duplicate (within 30s)")
	}
	if mv.IsDuplicate("hash2") {
		t.Error("different hash should not be duplicate")
	}
}

func TestValidateMessageType(t *testing.T) {
	validTypes := []uint8{
		MsgTypeBlock, MsgTypeTransaction, MsgTypeVote,
		MsgTypeBlockReq, MsgTypeBlockResp,
		MsgTypeTxReq, MsgTypeTxResp,
		MsgTypeStatus, MsgTypePing, MsgTypePong,
		MsgTypeFindNode, MsgTypeNeighbors, MsgTypeQNR,
		MsgTypeExpert,
		MsgTypeSnapStateReq, MsgTypeSnapStateResp,
		MsgTypeSnapRangeReq, MsgTypeSnapRangeResp,
		// Dilithium3 v1 signing executor round messages (97-100)
		MsgTypeTDilithium3SigningCommit, MsgTypeTDilithium3SigningReveal,
		MsgTypeTDilithium3SigningAcceptance, MsgTypeTDilithium3SigningResponse,
		// Dilithium3 v1 DKG activation certificate broadcast (101)
		MsgTypeTDilithium3DKGActivationCertificate,
	}

	for _, mt := range validTypes {
		if !ValidateMessageType(mt) {
			t.Errorf("ValidateMessageType(%d) = false, want true", mt)
		}
	}

	// 102 is unassigned and must stay rejected.
	if ValidateMessageType(102) {
		t.Error("ValidateMessageType(102) should be false")
	}
}

func TestValidateStatusMessageFormat(t *testing.T) {
	payload := make([]byte, MinStatusMessageSize)
	// Version = 1
	payload[0] = 0
	payload[1] = 0
	payload[2] = 0
	payload[3] = 1
	// NetworkID = 1668
	payload[4] = 0
	payload[5] = 0
	payload[6] = 0x06
	payload[7] = 0x84
	// BestHeight = 100
	payload[12] = 0
	payload[13] = 0
	payload[14] = 0
	payload[15] = 100
	// BestHash (32 bytes)
	copy(payload[20:52], []byte("best_hash_0001_0001_0001_0001_00"))
	// GenesisHash (32 bytes) - non-zero
	copy(payload[52:84], []byte("genesis_hash_0001_0001_0001_0001"))

	status, err := ValidateStatusMessageFormat(payload)
	if err != nil {
		t.Fatalf("ValidateStatusMessageFormat failed: %v", err)
	}
	if status.Version != 1 {
		t.Errorf("Version = %d, want 1", status.Version)
	}
}

func TestValidateStatusMessageFormatTooShort(t *testing.T) {
	_, err := ValidateStatusMessageFormat([]byte("short"))
	if err == nil {
		t.Error("expected error for too short payload")
	}
}

func TestValidateStatusMessageFormatZeroVersion(t *testing.T) {
	payload := make([]byte, MinStatusMessageSize)
	// Version = 0 (invalid)
	// GenesisHash non-zero
	copy(payload[52:84], []byte("genesis_hash_0001_0001_0001_0001"))

	_, err := ValidateStatusMessageFormat(payload)
	if err == nil {
		t.Error("expected error for zero version")
	}
}

func TestValidateStatusMessageFormatZeroGenesisHash(t *testing.T) {
	payload := make([]byte, MinStatusMessageSize)
	// Version = 1
	payload[3] = 1
	// GenesisHash = all zeros (invalid)

	_, err := ValidateStatusMessageFormat(payload)
	if err == nil {
		t.Error("expected error for zero genesis hash")
	}
}

func TestValidateBlockRequestFormat(t *testing.T) {
	payload := make([]byte, MinBlockRequestSize)
	// FromHeight = 10
	payload[7] = 10
	// ToHeight = 20
	payload[15] = 20
	// HashCount = 0
	payload[19] = 0

	req, err := ValidateBlockRequestFormat(payload)
	if err != nil {
		t.Fatalf("ValidateBlockRequestFormat failed: %v", err)
	}
	if req.FromHeight != 10 {
		t.Errorf("FromHeight = %d, want 10", req.FromHeight)
	}
	if req.ToHeight != 20 {
		t.Errorf("ToHeight = %d, want 20", req.ToHeight)
	}
}

func TestValidateBlockRequestFormatTooShort(t *testing.T) {
	_, err := ValidateBlockRequestFormat([]byte("short"))
	if err == nil {
		t.Error("expected error for too short payload")
	}
}

func TestValidateBlockRequestFormatFromGtTo(t *testing.T) {
	payload := make([]byte, MinBlockRequestSize)
	// FromHeight = 20
	payload[7] = 20
	// ToHeight = 10
	payload[15] = 10

	_, err := ValidateBlockRequestFormat(payload)
	if err == nil {
		t.Error("expected error for FromHeight > ToHeight")
	}
}

func TestValidateBlockRequestFormatExcessiveRange(t *testing.T) {
	payload := make([]byte, MinBlockRequestSize)
	// FromHeight = 0
	// ToHeight = 1000 (exceeds maxBlockRange=64)
	payload[15] = 0x03
	payload[14] = 0xE8

	_, err := ValidateBlockRequestFormat(payload)
	if err == nil {
		t.Error("expected error for excessive block range")
	}
}

// testValidator is a helper for custom validator tests
type testValidator struct {
	maxSize    uint64
	minSize    uint64
	validateFn func(payload []byte) error
}

func (v *testValidator) MaxSize() uint64               { return v.maxSize }
func (v *testValidator) MinSize() uint64               { return v.minSize }
func (v *testValidator) Validate(payload []byte) error { return v.validateFn(payload) }

func TestMessageValidatorReplayProtection(t *testing.T) {
	mv := NewMessageValidator()

	// First message with current timestamp should pass
	msg1 := &Message{Type: MsgTypeBlock, Payload: []byte("data1"), Timestamp: time.Now(), From: "peer1"}
	err := mv.ValidateMessage(msg1)
	if err != nil {
		t.Fatalf("first message should pass: %v", err)
	}

	// Message with old timestamp should be rejected
	msg2 := &Message{Type: MsgTypeBlock, Payload: []byte("data2"), Timestamp: time.Now().Add(-60 * time.Second), From: "peer1"}
	err = mv.ValidateMessage(msg2)
	if err == nil {
		t.Error("expected error for old timestamp")
	}
}

func TestMessageValidatorFutureTimestamp(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypeBlock, Payload: []byte("data"), Timestamp: time.Now().Add(60 * time.Second), From: "peer1"}
	err := mv.ValidateMessage(msg)
	if err == nil {
		t.Error("expected error for future timestamp")
	}
}

func TestMessageValidatorValidateAndParse(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: MsgTypeBlock, Payload: []byte("block-data"), Timestamp: time.Now()}
	result, parsed := mv.ValidateAndParse(msg)
	if result == nil {
		t.Fatal("ValidateAndParse returned nil result")
	}
	if !result.Valid {
		t.Errorf("result should be valid, error: %v", result.Error)
	}
	_ = parsed
}

func TestMessageValidatorValidateAndParseInvalid(t *testing.T) {
	mv := NewMessageValidator()

	msg := &Message{Type: 99, Payload: []byte("data"), Timestamp: time.Now()}
	result, _ := mv.ValidateAndParse(msg)
	if result.Valid {
		t.Error("result should be invalid for unknown message type")
	}
}

// TestMessageValidatorRetransmittedDKGNotDuplicate is a regression test for
// R42-DKG-RETRANSMIT. The Dilithium3 v1 DKG phase drivers re-send the identical
// signed envelope every second until a phase completes, but content-hash dedup
// rejected every retransmission as ErrDuplicateMessage, so a message lost to a
// full inbound queue could not be recovered until the 30s dedup TTL expired.
func TestMessageValidatorRetransmittedDKGNotDuplicate(t *testing.T) {
	mv := NewMessageValidator()

	for _, messageType := range []uint8{
		MsgTypeTDilithium3DKGRandomness,
		MsgTypeTDilithium3DKGRandomnessCommitment,
		MsgTypeTDilithium3DKGGroupSeed,
		MsgTypeTDilithium3DKGAcknowledgement,
		MsgTypeTDilithium3DKGComplaint,
		MsgTypeTDilithium3DKGContribution,
		MsgTypeTDilithium3DKGActivation,
	} {
		payload := testTDilithium3Envelope(t, messageType, testTDilithium3Payload(t, messageType))
		// A fresh timestamp per retransmission mirrors the production send path;
		// the dedup hash covers type and payload only, so the payload is what the
		// retransmission repeats verbatim.
		message := &Message{
			Type:      messageType,
			From:      PeerID("validator-101"),
			Payload:   payload,
			Timestamp: time.Now(),
		}
		for attempt := 1; attempt <= 3; attempt++ {
			if err := mv.ValidateMessage(message); err != nil {
				t.Fatalf("DKG type %d retransmission %d rejected: %v", messageType, attempt, err)
			}
		}
	}

	// Non-DKG types must still be deduplicated: the second identical message is
	// reported as a duplicate before format validation runs.
	nonDKG := &Message{Type: MsgTypeTransaction, From: PeerID("peer-1"), Payload: make([]byte, 64)}
	_ = mv.ValidateMessage(nonDKG)
	if err := mv.ValidateMessage(nonDKG); !errors.Is(err, ErrDuplicateMessage) {
		t.Fatalf("identical non-DKG retransmission: got %v, want ErrDuplicateMessage", err)
	}
}
