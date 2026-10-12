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
// history-bearing node adopts same-key anchors across epoch gaps (empty
// epochs and activation slips embed nothing, and know-nothing-trust continuity
// is what the key already supplies), while a key CHANGE must still move by
// exactly one epoch and carry the outgoing committee's handoff proof (missing
// or junk proof on a rotation anchor is refused outright).
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

	// M4.1 (mainnet 2026-10-11/12 evidence): an epoch with no anchor-embedding
	// block (stall, restart, activation slip) must not wedge custody forever.
	// Re-anchoring the established key across a gap is idempotent, not a fork.
	if !qfs.ObserveAnchoredGroupKey(8, mk(0x41), nil) {
		t.Fatal("same-key skip-ahead refused — gaps starve custody permanently")
	}
	if got := qfs.getGroupPublicKeyForEpoch(8); !bytes.Equal(got, mk(0x41)) {
		t.Fatal("gap-tolerant same-key anchor not recorded")
	}

	// A rotation to a NEW key without the handoff proof must still be refused…
	if qfs.ObserveAnchoredGroupKey(10, mk(0x55), nil) {
		t.Fatal("rotation anchor without handoff proof adopted")
	}
	// … even when it lands exactly at maxKnown+1.
	if qfs.ObserveAnchoredGroupKey(9, mk(0x55), nil) {
		t.Fatal("rotation anchor without handoff proof adopted")
	}
	// Junk proof is refused as well (the signature is garbage).
	if qfs.ObserveAnchoredGroupKey(9, mk(0x55), []byte("bogus-proof")) {
		t.Fatal("rotation anchor with garbage proof adopted")
	}
	// Continuity kept intact: nothing new was learned.
	if got := qfs.getGroupPublicKeyForEpoch(9); got != nil {
		t.Fatal("unproven rotation anchor still recorded a key")
	}
	// After all the refusals, the established key still answers.
	if got := qfs.getGroupPublicKeyForEpoch(8); !bytes.Equal(got, mk(0x41)) {
		t.Fatal("established key corrupted by refused rotation attempts")
	}
}
