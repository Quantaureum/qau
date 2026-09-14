// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"bytes"
	"errors"
	"testing"
)

// TestVerifyPayload_KindOtherEmptyPayload is a regression test for
// R45-P2P-01 (2026-08-05): KindOther messages (Ping/Pong/Status) may
// legitimately carry an empty payload. Previously VerifyPayload checked
// len(payload)==0 BEFORE the kind switch, so Ping messages were rejected
// with ErrSignatureMissing, causing P2P mesh degradation and chain
// divergence. The empty-payload guard must only apply to kinds that
// actually require a signature.
func TestVerifyPayload_KindOtherEmptyPayload(t *testing.T) {
	v := &Dilithium3PayloadVerifier{}

	// KindOther with empty payload must NOT return ErrSignatureMissing.
	if err := v.VerifyPayload(KindOther, nil); err != nil {
		t.Fatalf("KindOther empty payload should pass, got %v", err)
	}
	if err := v.VerifyPayload(KindOther, []byte{}); err != nil {
		t.Fatalf("KindOther empty payload should pass, got %v", err)
	}
	// KindUnknown with empty payload must NOT return ErrSignatureMissing.
	if err := v.VerifyPayload(KindUnknown, nil); err != nil {
		t.Fatalf("KindUnknown empty payload should pass, got %v", err)
	}
}

// TestVerifyPayload_RequiredKindsRejectEmpty verifies that kinds which
// DO require a signature still reject empty payloads.
func TestVerifyPayload_RequiredKindsRejectEmpty(t *testing.T) {
	v := &Dilithium3PayloadVerifier{
		BlockVerify: func([]byte) error { return nil },
		VoteVerify:  func([]byte) error { return nil },
		CRLVerify:   func([]byte) error { return nil },
	}
	for _, kind := range []MessageKind{KindTransaction, KindBlock, KindVote, KindCRL} {
		if err := v.VerifyPayload(kind, nil); !errors.Is(err, ErrSignatureMissing) {
			t.Fatalf("kind %d empty payload should return ErrSignatureMissing, got %v", kind, err)
		}
		if err := v.VerifyPayload(kind, []byte{}); !errors.Is(err, ErrSignatureMissing) {
			t.Fatalf("kind %d empty payload should return ErrSignatureMissing, got %v", kind, err)
		}
	}
}

// TestVerifyPayload_PingPathEndToEnd verifies the full Ping path through
// KindFromMessageType (the function used by message_validator.go) maps
// MsgTypePing to KindOther and accepts an empty payload.
func TestVerifyPayload_PingPathEndToEnd(t *testing.T) {
	v := &Dilithium3PayloadVerifier{}
	kind := KindFromMessageType(MsgTypePing)
	if kind != KindOther {
		t.Fatalf("MsgTypePing should map to KindOther, got %d", kind)
	}
	if err := v.VerifyPayload(kind, nil); err != nil {
		t.Fatalf("Ping empty payload should pass, got %v", err)
	}
	// Pong too.
	kind = KindFromMessageType(MsgTypePong)
	if kind != KindOther {
		t.Fatalf("MsgTypePong should map to KindOther, got %d", kind)
	}
	if err := v.VerifyPayload(kind, nil); err != nil {
		t.Fatalf("Pong empty payload should pass, got %v", err)
	}
}

// TestVerifyPayload_BlockWithContent ensures non-empty KindBlock still
// routes to the BlockVerify callback (regression guard that the empty
// guard didn't accidentally short-circuit valid messages).
func TestVerifyPayload_BlockWithContent(t *testing.T) {
	called := false
	v := &Dilithium3PayloadVerifier{
		BlockVerify: func(p []byte) error {
			called = true
			if !bytes.Equal(p, []byte("block")) {
				t.Fatalf("unexpected payload %q", p)
			}
			return nil
		},
	}
	if err := v.VerifyPayload(KindBlock, []byte("block")); err != nil {
		t.Fatalf("Block verify failed: %v", err)
	}
	if !called {
		t.Fatal("BlockVerify callback was not invoked")
	}
}
