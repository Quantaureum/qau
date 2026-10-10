// Quantaureum Node source, version 1.0.0.
package consensus

// Tests for the v1 observer anchor consumer (ObserveAnchoredGroupKey): the
// header-carried group key must validate shape, adopt when unknown, tolerate
// identical re-observation, and refuse to overwrite an established key.

import (
	"bytes"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
)

func TestObserveAnchoredGroupKeyValidateAdoptReject(t *testing.T) {
	qfs := &QTDFinalityState{}

	if qfs.ObserveAnchoredGroupKey(7, nil, nil) {
		t.Fatal("empty key accepted")
	}
	if qfs.ObserveAnchoredGroupKey(7, make([]byte, 4), nil) {
		t.Fatal("wrong-length key accepted")
	}
	if qfs.ObserveAnchoredGroupKey(7, make([]byte, qcrypto.Dilithium3PublicKeySize), nil) {
		t.Fatal("all-zero key accepted")
	}
	key := make([]byte, qcrypto.Dilithium3PublicKeySize)
	key[0] = 0x51
	key[len(key)-1] = 0x07
	if !qfs.ObserveAnchoredGroupKey(7, key, nil) {
		t.Fatal("valid key not adopted")
	}
	if !qfs.ObserveAnchoredGroupKey(7, key, nil) {
		t.Fatal("identical re-observation rejected")
	}
	other := make([]byte, qcrypto.Dilithium3PublicKeySize)
	other[0] = 0x52
	other[len(other)-1] = 0x07
	if qfs.ObserveAnchoredGroupKey(7, other, nil) {
		t.Fatal("conflicting key overwrote the established key")
	}
	if got := qfs.getGroupPublicKeyForEpoch(7); !bytes.Equal(got, key) {
		t.Fatal("established key changed after conflicting observation")
	}
}

// TestObserveAnchoredGroupKeyChainedAdoption pins the rotation hardening: a
// history-bearing node only adopts anchors that advance the chain of custody
// by exactly one epoch, and a key CHANGE at the boundary must carry the
// outgoing committee's handoff proof (missing proof on a rotation anchor is
// refused outright).
func TestObserveAnchoredGroupKeyChainedAdoption(t *testing.T) {
	mk := func(tag byte) []byte {
		key := make([]byte, qcrypto.Dilithium3PublicKeySize)
		key[0] = tag
		key[len(key)-1] = 0x07
		return key
	}
	qfs := &QTDFinalityState{}
	if !qfs.ObserveAnchoredGroupKey(4, mk(0x41), nil) {
		t.Fatal("first adoption of an observer's history refused")
	}

	// Same key continuing into the next epoch is not a rotation — no proof.
	if !qfs.ObserveAnchoredGroupKey(5, mk(0x41), nil) {
		t.Fatal("same-key continuation refused as rotation")
	}

	// Skip-ahead is refused (chained-adoption), proof or not.
	if qfs.ObserveAnchoredGroupKey(8, mk(0x41), nil) {
		t.Fatal("skip-ahead anchor adopted")
	}

	// A rotation to a NEW key without the handoff proof must be refused.
	if qfs.ObserveAnchoredGroupKey(6, mk(0x55), nil) {
		t.Fatal("rotation anchor without handoff proof adopted")
	}
	// Junk proof is refused as well (the signature is garbage).
	if qfs.ObserveAnchoredGroupKey(6, mk(0x55), []byte("bogus-proof")) {
		t.Fatal("rotation anchor with garbage proof adopted")
	}
	// Continuity kept intact: nothing new was learned.
	if got := qfs.getGroupPublicKeyForEpoch(6); got != nil {
		t.Fatal("unproven rotation anchor still recorded a key")
	}
}
