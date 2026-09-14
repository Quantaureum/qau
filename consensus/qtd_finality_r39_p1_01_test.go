// Quantaureum Node source, version 1.0.0.
// R39-P1-01 (2026-08-02) regression tests.
//
// R38-P1-01 only blocked the all-zero "DKG-uninitialized" forgery but still
// ACCEPTED any non-zero-length group key into groupKeyHistory, including
// truncated (e.g. 27-byte ASCII stubs) or padded keys. R39-P1-01 tightens the
// write-side gate to require the STRICT canonical length
// crypto.Dilithium3PublicKeySize (1952). This pins:
//
//	(a) a wrong-length key (>0 but != 1952) is NOT written to
//	    groupKeyHistory (rejected at the chokepoint);
//	(b) a legitimate non-zero 1952-byte key IS still written (regression
//	    guard: the strict gate doesn't over-reject).
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/crypto"
)

// TestR39_P1_01_WriteSide_RejectsWrongLengthKey verifies a 27-byte
// non-zero "stub" key (the kind the legacy code accepted because it only
// gated on `len > 0`) is now rejected by the strict-length write gate.
func TestR39_P1_01_WriteSide_RejectsWrongLengthKey(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	stubKey := []byte("dkg-key-for-activation-epoch") // 27 bytes — exactly the legacy test stub
	if len(stubKey) == crypto.Dilithium3PublicKeySize {
		t.Fatalf("test stub is not the wrong length; fixture drift")
	}
	if crypto.IsZeroPublicKeyBytes(stubKey) {
		t.Fatalf("test stub must be non-zero so the strict-LENGTH check (not the zero-key check) is what rejects it")
	}

	const activationEpoch uint64 = 9
	qfs.SetQTDSignerForEpoch(&epochKeySigner{groupKey: stubKey}, activationEpoch)

	qfs.mu.RLock()
	_, written := qfs.groupKeyHistory[activationEpoch]
	qfs.mu.RUnlock()
	if written {
		t.Fatalf("R39-P1-01 strict-length gate failed: wrong-length non-zero key (len=%d, want %d) was written into groupKeyHistory[%d]",
			len(stubKey), crypto.Dilithium3PublicKeySize, activationEpoch)
	}
}

// TestR39_P1_01_WriteSide_RejectsTruncatedRealKey verifies a key that is
// NEAR the canonical length but truncated by 1 byte is also rejected
// (defense against the "looks real but is malformed" key from a buggy DKG
// implementation, which the previous `len > 0` gate accepted).
func TestR39_P1_01_WriteSide_RejectsTruncatedRealKey(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	full := testDilithium3GroupKey(0xAA)
	truncated := full[:crypto.Dilithium3PublicKeySize-1] // 1951 bytes — off-by-one

	const activationEpoch uint64 = 13
	qfs.SetQTDSignerForEpoch(&epochKeySigner{groupKey: truncated}, activationEpoch)

	qfs.mu.RLock()
	_, written := qfs.groupKeyHistory[activationEpoch]
	qfs.mu.RUnlock()
	if written {
		t.Fatalf("R39-P1-01 strict-length gate failed: truncated key (len=%d, want %d) was written into groupKeyHistory[%d]",
			len(truncated), crypto.Dilithium3PublicKeySize, activationEpoch)
	}
}

// TestR39_P1_01_WriteSide_RejectsPaddedKey verifies a key that is PADDED
// past the canonical length is rejected too (closing the "any non-zero
// length" hole from both sides).
func TestR39_P1_01_WriteSide_RejectsPaddedKey(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	padded := make([]byte, crypto.Dilithium3PublicKeySize+10)
	for i := range padded {
		padded[i] = byte(0xBB)
	}

	const activationEpoch uint64 = 17
	qfs.SetQTDSignerForEpoch(&epochKeySigner{groupKey: padded}, activationEpoch)

	qfs.mu.RLock()
	_, written := qfs.groupKeyHistory[activationEpoch]
	qfs.mu.RUnlock()
	if written {
		t.Fatalf("R39-P1-01 strict-length gate failed: padded key (len=%d, want %d) was written into groupKeyHistory[%d]",
			len(padded), crypto.Dilithium3PublicKeySize, activationEpoch)
	}
}

// TestR39_P1_01_WriteSide_AcceptsCanonicalLengthKey is the GREEN sibling:
// a non-zero 1952-byte key is still written (regression guard against the
// strict gate over-rejecting legitimate DKG output).
func TestR39_P1_01_WriteSide_AcceptsCanonicalLengthKey(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	canonical := testDilithium3GroupKey(0x55)
	if len(canonical) != crypto.Dilithium3PublicKeySize {
		t.Fatalf("canonical len = %d, want %d", len(canonical), crypto.Dilithium3PublicKeySize)
	}
	if crypto.IsZeroPublicKeyBytes(canonical) {
		t.Fatalf("canonical test key must be non-zero so the length check (not the zero-key check) is what accepts it")
	}

	const activationEpoch uint64 = 21
	qfs.SetQTDSignerForEpoch(&epochKeySigner{groupKey: canonical}, activationEpoch)

	qfs.mu.RLock()
	stored, written := qfs.groupKeyHistory[activationEpoch]
	qfs.mu.RUnlock()
	if !written {
		t.Fatalf("R39-P1-01 over-rejected: legitimate 1952-byte non-zero key was NOT written to groupKeyHistory[%d]", activationEpoch)
	}
	if len(stored) != crypto.Dilithium3PublicKeySize {
		t.Fatalf("stored len = %d, want %d", len(stored), crypto.Dilithium3PublicKeySize)
	}
	for i, b := range stored {
		if b != canonical[i] {
			t.Fatalf("stored byte %d = %#x, want %#x (round-trip corruption)", i, b, canonical[i])
		}
	}
}
