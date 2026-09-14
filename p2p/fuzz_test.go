// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"
)

// FuzzHandshakeMessage: malformed handshake messages must never panic
func FuzzHandshakeMessage(f *testing.F) {
	// seed corpus: various protocol-negotiation messages
	f.Add([]byte{0x00, 0x01})                                  // count=1, not enough data
	f.Add([]byte{0x00, 0x01, 0x03, 'q', 'a', 'u', 0x00, 0x01}) // count=1, nameLen=3, "qau", version=1
	f.Add([]byte{})                                            // empty
	f.Add([]byte{0x00, 0x00})                                  // count=0 (invalid)
	f.Add([]byte{0x00, 0x21})                                  // count=33 (exceeds the 32 cap)
	f.Add([]byte{0x00, 0x01, 0xFF})                            // nameLen=255, not enough data
	f.Add([]byte{0x00, 0x01, 0x00})                            // nameLen=0

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		// protocol-negotiation decode must not panic
		msg, err := DecodeProtocolNegotiate(data)
		if err != nil {
			return // decode failure is expected
		}
		// if decoding succeeds, attempt re-encoding
		_, _ = EncodeProtocolNegotiate(msg)
	})
}

// FuzzBlockMessage: malformed block messages must never panic
func FuzzBlockMessage(f *testing.F) {
	// seed corpus: various block-message shapes
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 0x00})                                                                                                 // MsgTypeBlock + short payload
	f.Add([]byte{0x01})                                                                                                                         // type only, no payload
	f.Add([]byte{})                                                                                                                             // empty
	f.Add([]byte{0x05, 0x00, 0x00, 0x00, 0x01, 0x00})                                                                                           // MsgTypeBlockResp + 1 block
	f.Add([]byte{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // MsgTypeBlockReq

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}

		// message decode must not panic
		msg, err := DecodeMessage(data)
		if err != nil {
			return // decode failure is expected
		}

		// if decoding succeeds, validate the message
		_ = ValidateMessage(msg)

		// attempt re-encoding
		_, _ = EncodeMessage(msg.Type, msg.Payload)
	})
}

// FuzzTransactionMessage: malformed transaction messages must never panic
func FuzzTransactionMessage(f *testing.F) {
	// seed corpus: various transaction-message shapes
	f.Add([]byte{0x02, 0x00, 0x00, 0x00, 0x01, 0xAA})                                                                                                                   // MsgTypeTransaction + short payload
	f.Add([]byte{0x02})                                                                                                                                                 // type only
	f.Add([]byte{})                                                                                                                                                     // empty
	f.Add([]byte{0x07, 0x00, 0x00, 0x00, 0x01, 0x00})                                                                                                                   // MsgTypeTxResp + short payload
	f.Add([]byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // MsgTypeTxReq

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}

		// message decode must not panic
		msg, err := DecodeMessage(data)
		if err != nil {
			return
		}

		// validate the message
		_ = ValidateMessage(msg)
	})
}

// FuzzStatusMessage: malformed status messages must never panic
func FuzzStatusMessage(f *testing.F) {
	// seed corpus: various status messages
	f.Add(make([]byte, 84))  // exactly 84 bytes (minimum valid)
	f.Add(make([]byte, 100)) // slightly longer
	f.Add([]byte{})          // empty
	f.Add(make([]byte, 10))  // too short
	f.Add(make([]byte, 83))  // one byte short

	// a status message with real data
	validStatus := make([]byte, 84)
	validStatus[0] = 0x01  // version=1
	validStatus[4] = 0x01  // networkID
	validStatus[12] = 0x64 // bestHeight=100
	f.Add(validStatus)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		// status-message decode must not panic
		status, err := DecodeStatusMessage(data)
		if err != nil {
			return
		}
		// if decoding succeeds, attempt re-encoding
		encoded := EncodeStatusMessage(status)
		_ = encoded
	})
}

// FuzzBatchMessage: malformed batch messages must never panic
func FuzzBatchMessage(f *testing.F) {
	// seed corpus: various batch messages
	f.Add([]byte{0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0xAA}) // 1 sub-message
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})                                     // 0 messages (invalid)
	f.Add([]byte{})                                                           // empty
	f.Add([]byte{0x00, 0x00})                                                 // too short
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})                                     // huge message count

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		// batch-message decode must not panic
		batch, err := DecodeBatchMessage(data)
		if err != nil {
			return
		}
		// if decoding succeeds, attempt re-encoding
		_, _ = EncodeBatchMessage(batch)
	})
}

// FuzzBlockRequest: malformed block requests must never panic
func FuzzBlockRequest(f *testing.F) {
	// seed corpus
	f.Add(make([]byte, 20)) // minimum valid length (no hash)
	f.Add([]byte{})         // empty
	f.Add(make([]byte, 10)) // too short
	f.Add(make([]byte, 52)) // one hash

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		req, err := DecodeBlockRequest(data)
		if err != nil {
			return
		}
		encoded := EncodeBlockRequest(req)
		_ = encoded
	})
}

// FuzzBlockResponse: malformed block responses must never panic
func FuzzBlockResponse(f *testing.F) {
	// seed corpus
	f.Add([]byte{0x00, 0x00, 0x00, 0x00})                                     // 0 blocks
	f.Add([]byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB}) // 1 block
	f.Add([]byte{})                                                           // empty
	f.Add([]byte{0x00, 0x00})                                                 // too short

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		resp, err := DecodeBlockResponse(data)
		if err != nil {
			return
		}
		encoded := EncodeBlockResponse(resp)
		_ = encoded
	})
}

// FuzzCheckpointSigMessage: malformed checkpoint-signature messages must never panic
func FuzzCheckpointSigMessage(f *testing.F) {
	// seed corpus
	f.Add(make([]byte, 104)) // minimum valid length (no signature)
	f.Add(make([]byte, 200)) // message with signature
	f.Add([]byte{})          // empty
	f.Add(make([]byte, 50))  // too short
	f.Add(make([]byte, 103)) // one byte short

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		msg, err := DecodeCheckpointSig(data)
		if err != nil {
			return
		}
		encoded := EncodeCheckpointSig(msg)
		_ = encoded
	})
}

// FuzzProtocolNegotiateResp: malformed protocol-negotiation responses must never panic
func FuzzProtocolNegotiateResp(f *testing.F) {
	// seed corpus
	f.Add([]byte{0x00, 0x01, 0x03, 'q', 'a', 'u', 0x00, 0x01})
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x00, 0x21})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		msg, err := DecodeProtocolNegotiateResp(data)
		if err != nil {
			return
		}
		_, _ = EncodeProtocolNegotiateResp(msg)
	})
}

// FuzzCheckpointReqMessage: malformed checkpoint requests must never panic
func FuzzCheckpointReqMessage(f *testing.F) {
	// seed corpus
	f.Add(make([]byte, 8))  // exactly 8 bytes
	f.Add([]byte{})         // empty
	f.Add(make([]byte, 7))  // one byte short
	f.Add(make([]byte, 16)) // extra data

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			return
		}
		msg, err := DecodeCheckpointReq(data)
		if err != nil {
			return
		}
		encoded := EncodeCheckpointReq(msg)
		_ = encoded
	})
}
