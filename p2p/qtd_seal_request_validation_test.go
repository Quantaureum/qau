// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"encoding/binary"
	"testing"
)

func TestQTDSealRequestRawValidation(t *testing.T) {
	validator := NewMessageValidator()
	raw := make([]byte, MsgHeaderSize+40)
	raw[0] = MsgTypeQTDSealRequest
	binary.BigEndian.PutUint32(raw[1:5], 40)
	if err := validator.ValidateRawMessage(raw); err != nil {
		t.Fatalf("valid seal request rejected: %v", err)
	}
	payloadValidator := validator.validators[MsgTypeQTDSealRequest]
	if err := payloadValidator.Validate(make([]byte, 40)); err != nil {
		t.Fatal(err)
	}
	for _, length := range []int{0, 39, 41} {
		if err := payloadValidator.Validate(make([]byte, length)); err == nil {
			t.Fatalf("invalid length %d accepted", length)
		}
	}
}
