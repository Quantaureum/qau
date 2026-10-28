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

// TestQTDActiveShareRegistrationPurgesLegacyCustody pins the M4.1 ceremony
// transition: when an offline-ceremony share becomes active, its group key is
// the custody chain's trusted head. Pre-existing entries that disagree with it
// (jurisdictional leftovers from replayed legacy blocks) must be PURGED,
// otherwise subsequent same-key anchors are refused forever as phantom
// rotations. Rotating AWAY from the registered key is unchanged: that still
// requires the next-epoch chain rule plus a handoff proof.
func TestQTDActiveShareRegistrationPurgesLegacyCustody(t *testing.T) {
	legacyKey := make([]byte, qcrypto.Dilithium3PublicKeySize)
	legacyKey[0] = 0xee
	legacyKey[len(legacyKey)-1] = 0xf1
	newKey := make([]byte, qcrypto.Dilithium3PublicKeySize)
	newKey[0] = 0x21
	newKey[len(newKey)-1] = 0x7e

	qfs := &QTDFinalityState{groupKeyHistory: map[uint64][]byte{}}
	if !qfs.ObserveAnchoredGroupKey(100, legacyKey, nil) {
		t.Fatal("bootstrap adoption of legacy anchor failed")
	}
	if !qfs.ObserveAnchoredGroupKey(101, legacyKey, nil) {
		t.Fatal("legacy same-key continuation refused")
	}

	// Registration of the activated v1 share purges foreign-keyeds entries.
	qfs.ReRootGroupKeyCustody(200, newKey)
	qfs.SetQTDSignerForEpoch(&epochKeySigner{groupKey: newKey}, 200)
	if got := qfs.getGroupPublicKeyForEpoch(100); got != nil {
		t.Fatal("legacy key entry at epoch 100 survived activation registration")
	}
	if got := qfs.getGroupPublicKeyForEpoch(101); got != nil {
		t.Fatal("legacy key entry at epoch 101 survived activation registration")
	}
	if got := qfs.getGroupPublicKeyForEpoch(200); !bytes.Equal(got, newKey) {
		t.Fatal("new key not recorded at activation epoch")
	}

	// After re-rooting, same-key anchors continue (gap-tolerant per prior test).
	if !qfs.ObserveAnchoredGroupKey(201, newKey, nil) {
		t.Fatal("same-key anchor refused after re-rooting")
	}
	// And a rotation without proof must still be refused as before.
	if qfs.ObserveAnchoredGroupKey(202, legacyKey, nil) {
		t.Fatal("rotation to legacy key accepted after re-rooting")
	}
	if got := qfs.getGroupPublicKeyForEpoch(202); got != nil {
		t.Fatal("unproven rotation anchor recorded a key after re-rooting")
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

// TestSetQTDSignerReRootsCustody pins M4.1 (2026-10-12): when the offline
// ceremony share becomes active, its group key must RE-ROOT the custody
// table — entries replayed from legacy blocks (foreign keys, e.g. a GM-QTD
// manager's) would otherwise make every ceremony-key anchor look like an
// unproven rotation and refuse forever. After the re-root, same-key anchors
// remain gap-tolerant and rotations still strict.
type fullLengthSigner struct{ key []byte }

func (m *fullLengthSigner) SignBlock(int, []byte) ([]byte, error)   { return nil, nil }
func (m *fullLengthSigner) SignVote(int, []byte) ([]byte, error)    { return nil, nil }
func (m *fullLengthSigner) VerifyBlock([]byte, []byte, []byte) bool { return true }
func (m *fullLengthSigner) VerifyVote([]byte, []byte, []byte) bool  { return true }
func (m *fullLengthSigner) GroupPublicKey() []byte                  { return m.key }
func (m *fullLengthSigner) IsThresholdMode() bool                   { return true }
func (m *fullLengthSigner) Threshold() int                          { return 1 }
func (m *fullLengthSigner) AggregatePartialSignatures([]int, map[int][]byte, []byte) ([]byte, error) {
	return nil, nil
}

func TestSetQTDSignerReRootsCustody(t *testing.T) {
	legacy := make([]byte, qcrypto.Dilithium3PublicKeySize)
	legacy[0], legacy[len(legacy)-1] = 0x5a, 0x5a
	ceremony := make([]byte, qcrypto.Dilithium3PublicKeySize)
	ceremony[0], ceremony[len(ceremony)-1] = 0x21, 0x7e

	qfs := &QTDFinalityState{}
	qfs.groupKeyHistory = map[uint64][]byte{7558: legacy, 7606: legacy, 7700: legacy}

	qfs.ReRootGroupKeyCustody(7634, ceremony)
	qfs.SetQTDSignerForEpoch(&fullLengthSigner{key: ceremony}, 7634)

	if len(qfs.groupKeyHistory) != 1 {
		t.Fatalf("re-root must purge foreign rows, got %d entries", len(qfs.groupKeyHistory))
	}
	if got := qfs.groupKeyHistory[7634]; !bytes.Equal(got, ceremony) {
		t.Fatal("ceremony key not installed at the activation epoch")
	}
	// Same-key gap adoption stays open after the re-root (M4.1 + 7c588ac pair).
	if !qfs.ObserveAnchoredGroupKey(7700, ceremony, nil) {
		t.Fatal("same-key anchor at a later epoch refused after custody re-root")
	}
	if got := qfs.groupKeyHistory[7700]; !bytes.Equal(got, ceremony) {
		t.Fatal("same-key continuation not recorded")
	}
	// Rotation semantics unchanged: a different key two epochs ahead is refused.
	other := make([]byte, qcrypto.Dilithium3PublicKeySize)
	other[0], other[len(other)-1] = 0x42, 0x42
	if qfs.ObserveAnchoredGroupKey(7702, other, nil) {
		t.Fatal("unproven rotation accepted after re-root")
	}
}

// TestR19_F02_FirstEstablishmentMustMatchLocalSigner pins the R19-F02
// hardening: when the node holds its own group key (qtdSigner configured),
// the FIRST anchor adopted into an empty history must match the local
// signer's key — otherwise a malicious proposer could anchor a forged
// QTDGroupKey (the header field is not covered by the proposer signature)
// into an observer's trust store and forge seals for that epoch.
func TestR19_F02_FirstEstablishmentMustMatchLocalSigner(t *testing.T) {
	localKey := make([]byte, qcrypto.Dilithium3PublicKeySize)
	localKey[0] = 0x11
	localKey[len(localKey)-1] = 0x22

	attackerKey := make([]byte, qcrypto.Dilithium3PublicKeySize)
	attackerKey[0] = 0x33
	attackerKey[len(attackerKey)-1] = 0x44

	qfs := &QTDFinalityState{}
	qfs.SetQTDSigner(&keyAwareSigner{currentKey: localKey, expectedKey: localKey})
	// SetQTDSigner records the signer's key in groupKeyHistory; clear it to
	// exercise the first-establishment branch (same trick as
	// cons_p0_01_03_test.go).
	qfs.mu.Lock()
	qfs.groupKeyHistory = make(map[uint64][]byte)
	qfs.mu.Unlock()

	// An attacker-anchored key that differs from the local signer's key must
	// be refused on first establishment.
	if qfs.ObserveAnchoredGroupKey(3, attackerKey, nil) {
		t.Fatal("first establishment with a key differing from the local signer key must be refused (R19-F02)")
	}
	if got := qfs.getGroupPublicKeyForEpoch(3); got != nil && bytes.Equal(got, attackerKey) {
		t.Fatal("attacker key must not have been adopted")
	}

	// The legitimate key (matching the local signer) is adopted.
	if !qfs.ObserveAnchoredGroupKey(3, localKey, nil) {
		t.Fatal("first establishment with the local signer's own key must be adopted")
	}
	if got := qfs.getGroupPublicKeyForEpoch(3); !bytes.Equal(got, localKey) {
		t.Fatal("local signer key must be the adopted group key")
	}
}
