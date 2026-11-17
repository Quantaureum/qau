// Quantaureum Node source, version 1.0.0.
package consensus

// Tests of the skipped-epoch rotation lane (TSS-R3-B-1, P2-4 posture-r5):
// when the chain itself skipped epoch numbers (an epoch passed with no block,
// so no boundary anchor ever landed), an observer with history must adopt the
// next ACTUAL rotation through the skip lane instead of refusing every later
// anchor forever. The lane requires (a) no observed anchor for any skipped
// intermediate epoch and (b) the currently recorded head key's handoff proof
// over exactly (chainID, epochNew, keyNew, committeeVersion).
//
// The proofs here are ordinary Dilithium3 signatures under the previous
// committee's group public key — the same shape a threshold signing session
// produces (the v1 session output verifies as one mode3 signature under the
// group key). Test keys use deterministic DEVNET ONLY seeds.

import (
	"bytes"
	"testing"

	qcrypto "github.com/quantaureum/qau/crypto"
)

// skipLaneTestKey builds a deterministic non-degenerate Dilithium3 keypair
// carrying the tag (DEVNET ONLY deterministic seed, same pattern as the
// anchor-bootstrap tests).
func skipLaneTestKey(t *testing.T, tag string) (*qcrypto.KeyPair, []byte) {
	t.Helper()
	pair, err := qcrypto.GenerateKeyPairFromSeed([]byte("DEVNET ONLY skipped-epoch handoff " + tag))
	if err != nil {
		t.Fatalf("key %s: %v", tag, err)
	}
	key := pair.Public.Bytes()
	if len(key) != qcrypto.Dilithium3PublicKeySize {
		t.Fatalf("key %s has %d bytes", tag, len(key))
	}
	return pair, key
}

// skipLaneSign signs the handoff tuple with the given keypair, returning the
// proof bytes an outgoing committee's session would produce.
func skipLaneSign(t *testing.T, pair *qcrypto.KeyPair, chainID, epochNew uint64, keyNew []byte, committeeVersion uint64) []byte {
	t.Helper()
	proof, err := qcrypto.Sign(pair.Private, QTDHandoffMessage(chainID, epochNew, keyNew, committeeVersion))
	if err != nil {
		t.Fatalf("handoff sign: %v", err)
	}
	return proof
}

// newSkipLaneObserver builds an observer QTDFinalityState (no local signer)
// with the chain ID pinned, matching the verify-only node shape the anchor
// import path serves.
func newSkipLaneObserver(t *testing.T) *QTDFinalityState {
	t.Helper()
	qfs := &QTDFinalityState{}
	qfs.SetChainID(1333)
	return qfs
}

// TestObserveAnchoredGroupKeySkippedEpochAdoption pins the positive lane: an
// observer holding epoch-5 custody adopts the epoch-7 rotation directly (no
// epoch-6 anchor ever existed) when the epoch-5 committee signed the handoff
// for (7, key7), and the custody chain continues normally afterwards.
func TestObserveAnchoredGroupKeySkippedEpochAdoption(t *testing.T) {
	qfs := newSkipLaneObserver(t)
	kp5, key5 := skipLaneTestKey(t, "head-5")
	_, key7 := skipLaneTestKey(t, "rot-7")
	_, key8 := skipLaneTestKey(t, "rot-8")

	// First establishment (observer, no signer): trust-on-first-use, unchanged.
	if !qfs.ObserveAnchoredGroupKey(5, key5, nil) {
		t.Fatal("first anchor establishment refused")
	}

	// The chain skipped epoch 6 entirely: no anchor was observed for it. The
	// epoch-7 rotation carries the epoch-5 committee's handoff proof.
	proof7 := skipLaneSign(t, kp5, 1333, 7, key7, 1)
	if !qfs.ObserveAnchoredGroupKey(7, key7, proof7) {
		t.Fatal("skipped-epoch rotation with a valid head-key handoff proof refused")
	}
	if got := qfs.GroupPublicKeyForEpoch(7); !bytes.Equal(got, key7) {
		t.Fatal("skipped-epoch adopted key not recorded at epoch 7")
	}

	// From the new head the ordinary chained lane continues unchanged: the
	// epoch-7 committee signs the epoch-8 handoff.
	kp7, key7again := skipLaneTestKey(t, "rot-7")
	if !bytes.Equal(key7, key7again) {
		t.Fatal("deterministic key derivation diverged")
	}
	proof8 := skipLaneSign(t, kp7, 1333, 8, key8, 1)
	if !qfs.ObserveAnchoredGroupKey(8, key8, proof8) {
		t.Fatal("chained rotation after a skipped-epoch adoption refused")
	}
	if got := qfs.GroupPublicKeyForEpoch(8); !bytes.Equal(got, key8) {
		t.Fatal("chained rotation key not recorded at epoch 8")
	}

	// The skipped intermediate epoch itself stays unanswered for exact-epoch
	// lookups ahead of the chain clock (fail-closed floor semantics govern
	// past epochs; epoch 6 has no entry of its own).
	if entry, ok := qfs.groupKeyHistory[6]; ok {
		t.Fatalf("epoch 6 gained a custody entry without an anchor: %d bytes", len(entry))
	}
}

// TestObserveAnchoredGroupKeySkippedEpochRefusals is the negative matrix: the
// skip lane adopts ONLY with a valid head-key proof AND no intermediate
// anchor — every deviation is refused and records nothing.
func TestObserveAnchoredGroupKeySkippedEpochRefusals(t *testing.T) {
	kp5, key5 := skipLaneTestKey(t, "head-5")
	_, key7 := skipLaneTestKey(t, "rot-7")
	kpStranger, _ := skipLaneTestKey(t, "stranger")

	build := func() *QTDFinalityState {
		qfs := newSkipLaneObserver(t)
		if !qfs.ObserveAnchoredGroupKey(5, key5, nil) {
			t.Fatal("first anchor establishment refused")
		}
		return qfs
	}
	expectRefused := func(name string, qfs *QTDFinalityState, epoch uint64, key, proof []byte) {
		t.Helper()
		if qfs.ObserveAnchoredGroupKey(epoch, key, proof) {
			t.Fatalf("%s: refused anchor was adopted", name)
		}
		if entry, ok := qfs.groupKeyHistory[epoch]; ok {
			t.Fatalf("%s: refused anchor recorded %d bytes at epoch %d", name, len(entry), epoch)
		}
	}

	// Missing proof.
	expectRefused("missing proof", build(), 7, key7, nil)
	// Junk proof.
	expectRefused("junk proof", build(), 7, key7, []byte("bogus-proof"))
	// Proof signed by a key that is NOT the custody head.
	expectRefused("wrong signer", build(), 7, key7, skipLaneSign(t, kpStranger, 1333, 7, key7, 1))
	// Proof bound to a different target epoch (replay across epochs).
	expectRefused("wrong epoch in proof", build(), 7, key7, skipLaneSign(t, kp5, 1333, 8, key7, 1))
	// Proof bound to a different new key (replay across keys).
	expectRefused("wrong key in proof", build(), 7, key7, skipLaneSign(t, kp5, 1333, 7, key5, 1))
	// Proof bound to a different chain ID (cross-chain replay).
	expectRefused("wrong chainID in proof", build(), 7, key7, skipLaneSign(t, kp5, 1, 7, key7, 1))
	// Proof bound to a different committee version.
	expectRefused("wrong committeeVersion in proof", build(), 7, key7, skipLaneSign(t, kp5, 1333, 7, key7, 2))

	// An OBSERVED (even refused) intermediate anchor blocks the lane: the
	// chain DID carry an epoch-6 anchor, so the proper path is the chained
	// lane with an epoch-6 proof — not a skip over it.
	qfs := build()
	expectRefused("intermediate anchor itself", qfs, 6, key7, []byte("bogus-proof"))
	expectRefused("skip over an anchored intermediate", qfs, 7, key7, skipLaneSign(t, kp5, 1333, 7, key7, 1))

	// A skip wider than the observation horizon is refused outright (the
	// ledger deliberately does not record that far ahead, so the lane could
	// not check the intermediates exhaustively).
	qfs = build()
	expectRefused("skip beyond horizon", qfs, 5+qtdAnchorObservationHorizon+1, key7, skipLaneSign(t, kp5, 1333, 5+qtdAnchorObservationHorizon+1, key7, 1))

	// Rotation anchored below the head stays refused (unchanged discipline).
	expectRefused("rotation below the head", build(), 4, key7, skipLaneSign(t, kp5, 1333, 4, key7, 1))
}

// TestObserveAnchoredGroupKeySkippedEpochLaneIsolation pins the R19-F02
// invariants around the new lane: the first-establishment rule (including the
// local-signer match) is unaffected, the chained lane is unaffected, the
// gap-tolerant same-key continuation is unaffected, and a refused skip leaves
// the head key fully in force.
func TestObserveAnchoredGroupKeySkippedEpochLaneIsolation(t *testing.T) {
	_, key5 := skipLaneTestKey(t, "head-5")
	_, key7 := skipLaneTestKey(t, "rot-7")

	// R19-F02 first establishment with a local signer: a mismatched first
	// anchor is refused even though a later skip lane exists — the lane never
	// bypasses the establishment rule.
	qfs := newSkipLaneObserver(t)
	qfs.SetQTDSigner(&epochKeySigner{groupKey: key5})
	qfs.mu.Lock()
	qfs.groupKeyHistory = make(map[uint64][]byte)
	qfs.mu.Unlock()
	_, foreignKey := skipLaneTestKey(t, "foreign")
	if qfs.ObserveAnchoredGroupKey(5, foreignKey, nil) {
		t.Fatal("mismatched first establishment accepted (R19-F02)")
	}

	// Empty history adopts without a proof (unchanged first establishment).
	qfs2 := newSkipLaneObserver(t)
	if !qfs2.ObserveAnchoredGroupKey(5, key5, nil) {
		t.Fatal("first establishment without proof refused")
	}

	// Chained rotation without a proof stays refused (unchanged).
	if qfs2.ObserveAnchoredGroupKey(6, key7, nil) {
		t.Fatal("chained rotation without proof accepted")
	}
	// Same-key gap continuation without a proof stays adopted (unchanged).
	if !qfs2.ObserveAnchoredGroupKey(9, key5, nil) {
		t.Fatal("gap-tolerant same-key continuation refused")
	}
	// After the refusals the custody table still holds exactly the head key's
	// entries (the refused rotation recorded nothing, the continuation did).
	qfs2.mu.RLock()
	defer qfs2.mu.RUnlock()
	if got := qfs2.groupKeyHistory[5]; !bytes.Equal(got, key5) {
		t.Fatal("head key entry at epoch 5 disturbed")
	}
	if got := qfs2.groupKeyHistory[9]; !bytes.Equal(got, key5) {
		t.Fatal("same-key continuation entry at epoch 9 disturbed")
	}
	if entry, ok := qfs2.groupKeyHistory[6]; ok {
		t.Fatalf("refused rotation recorded %d bytes at epoch 6", len(entry))
	}
}

// TestAnchorObservationLedgerBounds pins the ledger mechanics directly: only
// epochs strictly ahead of the head within the horizon are recorded, and an
// adoption prunes everything at or below the new head.
func TestAnchorObservationLedgerBounds(t *testing.T) {
	qfs := &QTDFinalityState{}

	qfs.mu.Lock()
	qfs.recordAnchorObservationLocked(5, 3)                               // at/below head: not recorded
	qfs.recordAnchorObservationLocked(5, 5)                               // equal to head: not recorded
	qfs.recordAnchorObservationLocked(5, 7)                               // ahead within horizon: recorded
	qfs.recordAnchorObservationLocked(5, 5+qtdAnchorObservationHorizon+1) // beyond horizon
	if len(qfs.anchorObservedEpochs) != 1 {
		t.Fatalf("ledger recorded %d entries, want 1", len(qfs.anchorObservedEpochs))
	}
	if _, ok := qfs.anchorObservedEpochs[7]; !ok {
		t.Fatal("the in-horizon observation was not recorded")
	}
	qfs.recordAnchorObservationLocked(5, 8)
	qfs.pruneAnchorObservationsLocked(7)
	qfs.mu.Unlock()

	if len(qfs.anchorObservedEpochs) != 1 {
		t.Fatalf("prune left %d entries, want 1", len(qfs.anchorObservedEpochs))
	}
	if _, ok := qfs.anchorObservedEpochs[8]; !ok {
		t.Fatal("the observation ahead of the new head was pruned")
	}
}
