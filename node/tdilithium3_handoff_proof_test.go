// Quantaureum Node source, version 1.0.0.
package node

// Tests of the rotation handoff proof channel (TSS-R3-B-1 Wave F): the record
// encoding and store, the anchor proof decision, the header anchor gate, and
// the subset resolution over a captured roster. The full cryptographic path —
// a real four-signer handoff session under the outgoing key, its record, and
// the observer adoption — is covered in tdilithium3_handoff_proof_e2e_test.go.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/wallet/tss/protocol"
	"github.com/quantaureum/qau/wallet/tss/protocol/dilithium3v1"
)

// handoffTestKeys returns a deterministic (outgoing, incoming) key pair pair
// for the given epoch, plus the handoff signature the outgoing key produces
// over the tuple binding the incoming key. The seeds are epoch-dependent, so
// distinct rotations get distinct keys. DEVNET ONLY deterministic seeds,
// matching the anchor fixture convention.
func handoffTestKeys(t *testing.T, epoch uint64, chainID uint64) (oldKey, newKey, signature []byte) {
	t.Helper()
	oldPair, err := qcrypto.GenerateKeyPairFromSeed([]byte("DEVNET ONLY handoff outgoing key " + strconv.FormatUint(epoch, 10)))
	if err != nil {
		t.Fatalf("outgoing key: %v", err)
	}
	newPair, err := qcrypto.GenerateKeyPairFromSeed([]byte("DEVNET ONLY handoff incoming key " + strconv.FormatUint(epoch, 10)))
	if err != nil {
		t.Fatalf("incoming key: %v", err)
	}
	oldKey = oldPair.Public.Bytes()
	newKey = newPair.Public.Bytes()
	signature, err = qcrypto.Sign(oldPair.Private, consensus.QTDHandoffMessage(chainID, epoch, newKey, consensus.QTDAnchorProofCommitteeVersion))
	if err != nil {
		t.Fatalf("handoff signature: %v", err)
	}
	return oldKey, newKey, signature
}

// handoffTestSignRecord fills the record's signature with the outgoing key's
// handoff signature over the record's own tuple (the incoming key the record
// endorses, not a fixture-side copy).
func handoffTestSignRecord(t *testing.T, record *tdilithium3HandoffProofRecord, chainID uint64) {
	t.Helper()
	oldPair, err := qcrypto.GenerateKeyPairFromSeed([]byte("DEVNET ONLY handoff outgoing key " + strconv.FormatUint(record.EpochNew, 10)))
	if err != nil {
		t.Fatalf("outgoing key: %v", err)
	}
	if !bytes.Equal(oldPair.Public.Bytes(), record.OldKey) {
		t.Fatal("record outgoing key does not match the deterministic key pair")
	}
	signature, err := qcrypto.Sign(oldPair.Private, consensus.QTDHandoffMessage(chainID, record.EpochNew, record.NewKey, record.CommitteeVersion))
	if err != nil {
		t.Fatalf("handoff signature: %v", err)
	}
	record.Signature = signature
}

// handoffTestNode returns a minimal configured node whose record store lives
// in a temp directory.
func handoffTestNode(t *testing.T, chainID uint64) *Node {
	t.Helper()
	return &Node{config: &Config{NetworkID: chainID, DataDir: t.TempDir()}}
}

// handoffTestRecord builds a valid signed record for the given epoch.
func handoffTestRecord(t *testing.T, epoch, chainID uint64) *tdilithium3HandoffProofRecord {
	t.Helper()
	oldKey, newKey, signature := handoffTestKeys(t, epoch, chainID)
	return &tdilithium3HandoffProofRecord{
		EpochNew:         epoch,
		CommitteeVersion: consensus.QTDAnchorProofCommitteeVersion,
		OldKey:           oldKey,
		NewKey:           newKey,
		Signature:        signature,
	}
}

// TestTDilithium3HandoffProofRecordRoundTrip pins the record encoding: a
// signed record and a pending record both round-trip, and every corrupted
// shape is refused.
func TestTDilithium3HandoffProofRecordRoundTrip(t *testing.T) {
	record := handoffTestRecord(t, 8, tdilithium3SeamTestChainID)
	encoded, err := record.encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := tdilithium3HandoffProofRecordFrom(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.EpochNew != record.EpochNew || decoded.CommitteeVersion != record.CommitteeVersion ||
		!bytes.Equal(decoded.OldKey, record.OldKey) || !bytes.Equal(decoded.NewKey, record.NewKey) ||
		!bytes.Equal(decoded.Signature, record.Signature) {
		t.Fatal("round trip changed the record")
	}

	// A pending record (session failed) round-trips with an empty signature.
	pending := &tdilithium3HandoffProofRecord{
		EpochNew:         9,
		CommitteeVersion: consensus.QTDAnchorProofCommitteeVersion,
		OldKey:           record.OldKey,
		NewKey:           record.NewKey,
	}
	pendingEncoded, err := pending.encode()
	if err != nil {
		t.Fatalf("encode pending: %v", err)
	}
	pendingDecoded, err := tdilithium3HandoffProofRecordFrom(pendingEncoded)
	if err != nil {
		t.Fatalf("decode pending: %v", err)
	}
	if len(pendingDecoded.Signature) != 0 {
		t.Fatal("pending record decoded with a signature")
	}

	// Corrupted encodings are refused.
	corruptions := map[string][]byte{
		"bad magic":     append([]byte("QTD4HANDOFF"), encoded[len(tdilithium3HandoffProofMagic):]...),
		"bad version":   append(append([]byte(nil), encoded[:len(tdilithium3HandoffProofMagic)]...), append([]byte{9}, encoded[len(tdilithium3HandoffProofMagic)+1:]...)...),
		"truncated":     encoded[:len(encoded)-1],
		"trailing":      append(append([]byte(nil), encoded...), 0),
		"short payload": encoded[:len(tdilithium3HandoffProofMagic)],
	}
	for name, broken := range corruptions {
		if _, err := tdilithium3HandoffProofRecordFrom(broken); err == nil {
			t.Fatalf("%s: corrupted record accepted", name)
		}
	}

	// A tampered signature byte is refused at the verification layer.
	tampered := append([]byte(nil), decoded.Signature...)
	tampered[0] ^= 0x01
	if consensus.VerifyAnchoredGroupKeyProof(decoded.OldKey, decoded.NewKey, decoded.EpochNew, tdilithium3SeamTestChainID, decoded.CommitteeVersion, tampered) {
		t.Fatal("a tampered handoff signature verified")
	}

	// Shape refusals: same key on both sides, degenerate key, bad lengths.
	badShapes := []*tdilithium3HandoffProofRecord{
		{EpochNew: 1, CommitteeVersion: 1, OldKey: record.NewKey, NewKey: record.NewKey, Signature: record.Signature},
		{EpochNew: 1, CommitteeVersion: 1, OldKey: make([]byte, qcrypto.Dilithium3PublicKeySize), NewKey: record.NewKey, Signature: record.Signature},
		{EpochNew: 1, CommitteeVersion: 1, OldKey: record.OldKey, NewKey: record.NewKey[:10], Signature: record.Signature},
		{EpochNew: 0, CommitteeVersion: 1, OldKey: record.OldKey, NewKey: record.NewKey},
		{EpochNew: 1, CommitteeVersion: 0, OldKey: record.OldKey, NewKey: record.NewKey},
	}
	for index, bad := range badShapes {
		if err := bad.validate(); err == nil {
			t.Fatalf("bad shape %d accepted", index)
		}
	}
}

// TestTDilithium3HandoffProofStoreMonotonic pins the store's write discipline:
// monotonic epochs, idempotent same-content rewrites, conflicting-bytes
// refusal, and pruning to the retention bound.
func TestTDilithium3HandoffProofStoreMonotonic(t *testing.T) {
	node := handoffTestNode(t, tdilithium3SeamTestChainID)
	record8 := handoffTestRecord(t, 8, tdilithium3SeamTestChainID)
	if err := node.storeTDilithium3HandoffProofRecord(record8); err != nil {
		t.Fatalf("store epoch 8: %v", err)
	}
	// An older epoch is refused (a straggler ceremony must not rewind).
	record7 := handoffTestRecord(t, 7, tdilithium3SeamTestChainID)
	if err := node.storeTDilithium3HandoffProofRecord(record7); err == nil {
		t.Fatal("an older-epoch record overwrote a newer one")
	}
	// Same-epoch same-content is idempotent.
	if err := node.storeTDilithium3HandoffProofRecord(record8); err != nil {
		t.Fatalf("idempotent rewrite: %v", err)
	}
	// Same-epoch different bytes are refused.
	conflicting := handoffTestRecord(t, 8, tdilithium3SeamTestChainID)
	conflicting.Signature[0] ^= 0x01
	if err := node.storeTDilithium3HandoffProofRecord(conflicting); err == nil {
		t.Fatal("a conflicting same-epoch record overwrote the stored one")
	}
	// The stored record loads back verified.
	loaded := node.loadTDilithium3HandoffProofRecord(8)
	if loaded == nil || !bytes.Equal(loaded.Signature, record8.Signature) {
		t.Fatal("stored record did not load back")
	}
	// A newer epoch prunes the oldest beyond the retention bound.
	for epoch := uint64(9); epoch <= 9+tdilithium3HandoffProofKeep; epoch++ {
		if err := node.storeTDilithium3HandoffProofRecord(handoffTestRecord(t, epoch, tdilithium3SeamTestChainID)); err != nil {
			t.Fatalf("store epoch %d: %v", epoch, err)
		}
	}
	dir, err := tdilithium3HandoffProofDir(node.config.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != tdilithium3HandoffProofKeep {
		t.Fatalf("retention kept %d records, want %d", len(entries), tdilithium3HandoffProofKeep)
	}
}

// TestTDilithium3V1AnchorProofDecision pins the anchor decision table: first
// establishment plain, exact-epoch proof attached, pending record suppressed,
// foreign-key and missing-proof rotations suppressed, same-key continuation
// plain, and a load-time-verified record (a tampered stored signature is
// treated as absent and fails closed on the rotation branch).
func TestTDilithium3V1AnchorProofDecision(t *testing.T) {
	node := handoffTestNode(t, tdilithium3SeamTestChainID)
	record8 := handoffTestRecord(t, 8, tdilithium3SeamTestChainID)
	firstKey, firstSig := record8.NewKey, record8.Signature

	// No records at all: first establishment embeds plain.
	if proof, keep := node.tdilithium3V1AnchorProofDecision(7, firstKey); !keep || proof != nil {
		t.Fatal("first establishment was not plain")
	}

	// Exact-epoch record endorsing this key: the proof attaches.
	if err := node.storeTDilithium3HandoffProofRecord(record8); err != nil {
		t.Fatalf("store: %v", err)
	}
	proof, keep := node.tdilithium3V1AnchorProofDecision(8, firstKey)
	if !keep || !bytes.Equal(proof, firstSig) {
		t.Fatal("exact-epoch rotation proof not attached")
	}

	// A different key at the recorded epoch: not what the committee
	// endorsed — suppress.
	if _, keep := node.tdilithium3V1AnchorProofDecision(8, record8.OldKey); keep {
		t.Fatal("an anchor key the record does not endorse was kept")
	}

	// A later epoch with the SAME key (the record's endorsement already
	// covers the key, the anchor is a same-key continuation): plain.
	if _, keep := node.tdilithium3V1AnchorProofDecision(9, firstKey); !keep {
		t.Fatal("same-key continuation after a recorded rotation was suppressed")
	}

	// A later epoch with a DIFFERENT key and no record of its own: a key
	// change without a usable proof — suppress.
	if _, keep := node.tdilithium3V1AnchorProofDecision(9, record8.OldKey); keep {
		t.Fatal("an unproven key change was kept")
	}

	// A pending record (empty signature) suppresses its own epoch's anchor.
	node2 := handoffTestNode(t, tdilithium3SeamTestChainID)
	pending := &tdilithium3HandoffProofRecord{
		EpochNew:         8,
		CommitteeVersion: consensus.QTDAnchorProofCommitteeVersion,
		OldKey:           record8.OldKey,
		NewKey:           record8.NewKey,
	}
	if err := node2.storeTDilithium3HandoffProofRecord(pending); err != nil {
		t.Fatalf("store pending: %v", err)
	}
	if _, keep := node2.tdilithium3V1AnchorProofDecision(8, record8.NewKey); keep {
		t.Fatal("a pending record's rotation anchor was kept")
	}

	// A tampered stored signature never attaches: the record does not verify
	// at load. On a FIRST rotation the decision then falls back to the plain
	// lane (a producer cannot distinguish "no rotation" from an unreadable
	// record) — the observer still refuses the unproven anchor, so the
	// protocol-level fail-closed holds. On a SECOND rotation the fallback
	// sees the previous rotation's record with a different key and
	// suppresses.
	node3 := handoffTestNode(t, tdilithium3SeamTestChainID)
	if err := node3.storeTDilithium3HandoffProofRecord(record8); err != nil {
		t.Fatalf("store: %v", err)
	}
	dir, err := tdilithium3HandoffProofDir(node3.config.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, tdilithium3HandoffProofRecordName(8))
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	if err := os.WriteFile(target, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if node3.loadTDilithium3HandoffProofRecord(8) != nil {
		t.Fatal("a tampered stored record loaded as valid")
	}
	if proof, keep := node3.tdilithium3V1AnchorProofDecision(8, record8.NewKey); !keep || proof != nil {
		t.Fatal("a tampered record's signature was attached")
	}

	// Second rotation with a tampered record: the previous rotation's
	// READABLE record (a different key) suppresses the anchor.
	node4 := handoffTestNode(t, tdilithium3SeamTestChainID)
	if err := node4.storeTDilithium3HandoffProofRecord(record8); err != nil {
		t.Fatalf("store epoch 8: %v", err)
	}
	record9 := handoffTestRecord(t, 9, tdilithium3SeamTestChainID)
	if err := node4.storeTDilithium3HandoffProofRecord(record9); err != nil {
		t.Fatalf("store epoch 9: %v", err)
	}
	dir4, err := tdilithium3HandoffProofDir(node4.config.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	target9 := filepath.Join(dir4, tdilithium3HandoffProofRecordName(9))
	raw9, err := os.ReadFile(target9)
	if err != nil {
		t.Fatal(err)
	}
	raw9[len(raw9)-1] ^= 0x01
	if err := os.WriteFile(target9, raw9, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, keep := node4.tdilithium3V1AnchorProofDecision(9, record9.NewKey); keep {
		t.Fatal("a second rotation with an unreadable record was kept")
	}
}

// TestTDilithium3V1GateHeaderAnchor pins the gate on a signer-table anchor:
// the armed experimental node keeps and proof-attaches its own key's anchor,
// strips a stale-key anchor (the key of an earlier epoch), strips an
// unprovable rotation, and leaves unarmed (legacy GM-QTD) anchors untouched.
func TestTDilithium3V1GateHeaderAnchor(t *testing.T) {
	node, groupKey, _, _, _ := triggerE2EFixture(t)
	activation := triggerE2EActivationEpoch
	boundarySlot := activation * consensus.SlotsPerEpoch

	// The node's own key at its activation epoch, no record: kept plain
	// (first establishment lane unchanged).
	header := &encoding.BlockHeader{Epoch: activation, Slot: boundarySlot}
	header.QTDGroupKey = append([]byte(nil), groupKey...)
	node.tdilithium3V1GateHeaderAnchor(header, boundarySlot)
	if !bytes.Equal(header.QTDGroupKey, groupKey) || header.QTDGroupKeyProof != nil {
		t.Fatal("the first-establishment anchor was altered")
	}

	// The same key at a LATER epoch on the runtime-DKG posture: the active
	// share belongs to the activation epoch only, so the stale anchor is
	// stripped (the Wave D stale-key carrier, closed on the signer-table
	// writer too).
	stale := &encoding.BlockHeader{Epoch: activation + 1, Slot: (activation + 1) * consensus.SlotsPerEpoch}
	stale.QTDGroupKey = append([]byte(nil), groupKey...)
	node.tdilithium3V1GateHeaderAnchor(stale, stale.Slot)
	if len(stale.QTDGroupKey) != 0 || stale.QTDGroupKeyProof != nil {
		t.Fatal("a stale-key boundary anchor survived the gate")
	}

	// A rotation anchor at the node's own activation epoch with a verified
	// record: the proof attaches. (The record's outgoing key stands in for
	// the predecessor ceremony the unit level cannot install; the e2e covers
	// the real predecessor.)
	rotOldKey, _, _ := handoffTestKeys(t, activation, node.config.NetworkID)
	record := &tdilithium3HandoffProofRecord{
		EpochNew:         activation,
		CommitteeVersion: consensus.QTDAnchorProofCommitteeVersion,
		OldKey:           rotOldKey,
		NewKey:           groupKey,
	}
	handoffTestSignRecord(t, record, node.config.NetworkID)
	if err := node.storeTDilithium3HandoffProofRecord(record); err != nil {
		t.Fatalf("store: %v", err)
	}
	rotated := &encoding.BlockHeader{Epoch: activation, Slot: boundarySlot}
	rotated.QTDGroupKey = append([]byte(nil), groupKey...)
	node.tdilithium3V1GateHeaderAnchor(rotated, boundarySlot)
	if len(rotated.QTDGroupKey) == 0 || !bytes.Equal(rotated.QTDGroupKeyProof, record.Signature) {
		t.Fatal("the rotation proof was not attached to the boundary anchor")
	}

	// A rotation anchor whose record is pending (session failed): suppressed.
	node2, groupKey2, _, _, _ := triggerE2EFixture(t)
	activation2 := triggerE2EActivationEpoch
	node2Slot := activation2 * consensus.SlotsPerEpoch
	pendingOldKey, _, _ := handoffTestKeys(t, activation2, node2.config.NetworkID)
	pendingRecord := &tdilithium3HandoffProofRecord{
		EpochNew:         activation2,
		CommitteeVersion: consensus.QTDAnchorProofCommitteeVersion,
		OldKey:           pendingOldKey,
		NewKey:           groupKey2,
	}
	if err := node2.storeTDilithium3HandoffProofRecord(pendingRecord); err != nil {
		t.Fatalf("store pending: %v", err)
	}
	pendingHeader := &encoding.BlockHeader{Epoch: activation2, Slot: node2Slot}
	pendingHeader.QTDGroupKey = append([]byte(nil), groupKey2...)
	node2.tdilithium3V1GateHeaderAnchor(pendingHeader, node2Slot)
	if len(pendingHeader.QTDGroupKey) != 0 {
		t.Fatal("an unprovable rotation anchor survived the gate")
	}
	if pendingHeader.QTDGroupKeyProof != nil {
		t.Fatal("a suppressed anchor kept its proof")
	}
}

// TestTDilithium3HandoffSignersDeterministic pins the handoff subset
// resolution over a captured roster: it is a pure function of the public
// inputs, keeps the threshold's signer count, walks the round's distinct
// excluded pairs before repeating them, and every member derives the same set
// (the property that lets the four signers form the session with no
// announcement round).
func TestTDilithium3HandoffSignersDeterministic(t *testing.T) {
	node, _, _, _, _ := triggerE2EFixture(t)
	activation := triggerE2EActivationEpoch
	slot := consensus.EpochStartSlot(activation + 1)
	seen := make(map[[2]uint32]bool)
	distinctPairs := 0
	for attempt := uint64(0); attempt < 6; attempt++ {
		signers, _, err := node.tdilithium3HandoffSigners(activation, slot, attempt)
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		if len(signers) != 4 {
			t.Fatalf("attempt %d subset has %d signers, want the threshold 4", attempt, len(signers))
		}
		// Re-derive: the same inputs must give the same subset.
		again, _, err := node.tdilithium3HandoffSigners(activation, slot, attempt)
		if err != nil || !bytes.Equal(signerBytes(signers), signerBytes(again)) {
			t.Fatalf("attempt %d subset is not deterministic", attempt)
		}
		pair := [2]uint32{signers[0], signers[3]}
		if !seen[pair] {
			seen[pair] = true
			distinctPairs++
		}
	}
	// At C=6, t=4 the attempts walk the round's three excluded pairs.
	if distinctPairs != 3 {
		t.Fatalf("the attempts walked %d distinct excluded pairs, want 3", distinctPairs)
	}
}

// signerBytes flattens a participant list for comparison.
func signerBytes(signers []uint32) []byte {
	out := make([]byte, 0, len(signers)*4)
	for _, signer := range signers {
		out = append(out, byte(signer), byte(signer>>8), byte(signer>>16), byte(signer>>24))
	}
	return out
}

// TestTDilithium3HandoffProofPendingOnSessionFailure pins the failure path of
// produceTDilithium3HandoffProof: a rotation whose session cannot converge
// (here: no peer signer reachable) still persists a PENDING record, so the
// anchor discipline suppresses the rotation's anchors instead of emitting an
// unprovable one.
func TestTDilithium3HandoffProofPendingOnSessionFailure(t *testing.T) {
	node, _, _, _, _ := triggerE2EFixture(t)
	activation := triggerE2EActivationEpoch
	freshKey := anchorTestKey(t, "fresh rotation key")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	node.produceTDilithium3HandoffProof(ctx, activation+1, freshKey,
		newThresholdShareStore(node.config.DataDir), []byte(node.config.ValidatorKeyPassword))
	record := node.loadTDilithium3HandoffProofRecord(activation + 1)
	if record == nil {
		t.Fatal("a failed handoff session persisted no record")
	}
	if len(record.Signature) != 0 {
		t.Fatal("a failed session persisted a signature")
	}
	if !bytes.Equal(record.NewKey, freshKey) {
		t.Fatal("the pending record does not carry the rotation key")
	}
	// The anchor decision then suppresses the rotation anchor.
	if _, keep := node.tdilithium3V1AnchorProofDecision(activation+1, freshKey); keep {
		t.Fatal("the failed rotation's anchor was kept")
	}
}

// TestTDilithium3V1GateHeaderAnchorOfflinePosture pins the offline-ceremony
// posture's branch of the anchor discipline: with a re-key armed at a later
// epoch (the operator's tssV1SealingActivationEpoch), the superseded active
// share's key never anchors (the re-key quiet rule extended to anchoring),
// the armed candidate's key anchors plain, and the armed candidate's key
// anchors WITH the proof once the rotation record exists. The fixture keeps
// the experimental env open (the roster capture requires it); the gate's
// offline branch takes precedence over it exactly as the early-ceremony
// beat's offline-configured precedence does.
func TestTDilithium3V1GateHeaderAnchorOfflinePosture(t *testing.T) {
	node, oldKey, _, _, _ := triggerE2EFixture(t)
	const armedEpoch = triggerE2EActivationEpoch + 1

	// The armed ceremony: a generation-2 candidate installed into the node's
	// own share store, activating at the armed epoch.
	armedSession := dilithium3v1.DKGSession{
		Protocol:        protocol.ThresholdProtocolDilithium3V1,
		ChainID:         tdilithium3SeamTestChainID,
		KeyGeneration:   triggerE2EActivationEpoch + 1,
		Committee:       protocol.CommitteeID{Version: 1, Threshold: 4, Participants: []uint32{1, 2, 3, 4, 5, 6}},
		ActivationEpoch: armedEpoch,
		Nonce:           [32]byte{5, 5, 5},
	}
	armedSession.IdentityRosterDigest = testTDilithium3IdentityRosterDigest(t, armedSession, "DEVNET ONLY offline posture id")
	runners, err := newTriggerE2ERunners(t, armedSession, node.config.DataDir)
	if err != nil {
		t.Fatalf("armed ceremony runners: %v", err)
	}
	transport := newTDilithium3DKGMemoryTransport(6)
	if _, err := runTDilithium3DKGCluster(context.Background(), runners, transport, tdilithium3DKGFaultPlan{}); err != nil {
		t.Fatalf("armed ceremony cluster: %v", err)
	}
	_, freshKey, _, _, err := newThresholdShareStore(node.config.DataDir).
		CandidateSharePublicIdentity([]byte(node.config.ValidatorKeyPassword))
	if err != nil || len(freshKey) != qcrypto.Dilithium3PublicKeySize {
		t.Fatalf("armed candidate probe: %v", err)
	}
	node.config.TSSV1SealingActivationEpoch = armedEpoch
	boundarySlot := armedEpoch * consensus.SlotsPerEpoch

	// The superseded key's boundary anchor is suppressed: the re-key quiet
	// rule (armed != activation) extends from signing to anchoring.
	superseded := &encoding.BlockHeader{Epoch: armedEpoch, Slot: boundarySlot}
	superseded.QTDGroupKey = append([]byte(nil), oldKey...)
	node.tdilithium3V1GateHeaderAnchor(superseded, boundarySlot)
	if len(superseded.QTDGroupKey) != 0 {
		t.Fatal("the superseded key's anchor survived the offline posture gate")
	}

	// The armed candidate's key anchors plain before any rotation record.
	fresh := &encoding.BlockHeader{Epoch: armedEpoch, Slot: boundarySlot}
	fresh.QTDGroupKey = append([]byte(nil), freshKey...)
	node.tdilithium3V1GateHeaderAnchor(fresh, boundarySlot)
	if !bytes.Equal(fresh.QTDGroupKey, freshKey) || fresh.QTDGroupKeyProof != nil {
		t.Fatal("the armed candidate's plain anchor was altered")
	}

	// With a rotation record the armed candidate's anchor carries the proof.
	// The record's outgoing key is a locally generated stand-in (the real
	// predecessor is the threshold group key no single test key signs for);
	// the decision only requires the record to verify under its own stored
	// outgoing key, which the real predecessor chain provides.
	predecessor, err := qcrypto.GenerateKeyPairFromSeed([]byte("DEVNET ONLY offline posture predecessor key"))
	if err != nil {
		t.Fatalf("predecessor key: %v", err)
	}
	predecessorSignature, err := qcrypto.Sign(predecessor.Private, consensus.QTDHandoffMessage(node.config.NetworkID, armedEpoch, freshKey, consensus.QTDAnchorProofCommitteeVersion))
	if err != nil {
		t.Fatalf("predecessor signature: %v", err)
	}
	record := &tdilithium3HandoffProofRecord{
		EpochNew:         armedEpoch,
		CommitteeVersion: consensus.QTDAnchorProofCommitteeVersion,
		OldKey:           predecessor.Public.Bytes(),
		NewKey:           append([]byte(nil), freshKey...),
		Signature:        predecessorSignature,
	}
	if err := node.storeTDilithium3HandoffProofRecord(record); err != nil {
		t.Fatalf("store: %v", err)
	}
	proven := &encoding.BlockHeader{Epoch: armedEpoch, Slot: boundarySlot}
	proven.QTDGroupKey = append([]byte(nil), freshKey...)
	node.tdilithium3V1GateHeaderAnchor(proven, boundarySlot)
	if len(proven.QTDGroupKey) == 0 || !bytes.Equal(proven.QTDGroupKeyProof, record.Signature) {
		t.Fatal("the offline posture's rotation proof was not attached")
	}
}

// TestTDilithium3HandoffProofStorePendingUpgrade pins the pending-to-signed
// upgrade (audit medium): a PENDING record is the strictly weaker state of
// the SAME rotation, so a converging session may upgrade it in place; every
// other divergence keeps the refuse guard.
func TestTDilithium3HandoffProofStorePendingUpgrade(t *testing.T) {
	node := handoffTestNode(t, tdilithium3SeamTestChainID)
	record := handoffTestRecord(t, 8, tdilithium3SeamTestChainID)
	pending := &tdilithium3HandoffProofRecord{
		EpochNew:         record.EpochNew,
		CommitteeVersion: record.CommitteeVersion,
		OldKey:           append([]byte(nil), record.OldKey...),
		NewKey:           append([]byte(nil), record.NewKey...),
	}
	if err := node.storeTDilithium3HandoffProofRecord(pending); err != nil {
		t.Fatalf("store pending: %v", err)
	}

	// Same-rotation signed record: the upgrade succeeds and the signature
	// becomes readable.
	if err := node.storeTDilithium3HandoffProofRecord(record); err != nil {
		t.Fatalf("pending-to-signed upgrade refused: %v", err)
	}
	loaded := node.loadTDilithium3HandoffProofRecord(8)
	if loaded == nil || len(loaded.Signature) == 0 || !bytes.Equal(loaded.Signature, record.Signature) {
		t.Fatal("the upgraded record did not carry the session signature")
	}

	// An already-signed record with different bytes stays refused, and the
	// stored signature is untouched.
	tampered := &tdilithium3HandoffProofRecord{
		EpochNew:         record.EpochNew,
		CommitteeVersion: record.CommitteeVersion,
		OldKey:           append([]byte(nil), record.OldKey...),
		NewKey:           append([]byte(nil), record.NewKey...),
		Signature:        append([]byte(nil), record.Signature...),
	}
	tampered.Signature[0] ^= 0x01
	if err := node.storeTDilithium3HandoffProofRecord(tampered); err == nil {
		t.Fatal("a different signed record overwrote a signed record")
	}
	if again := node.loadTDilithium3HandoffProofRecord(8); again == nil || !bytes.Equal(again.Signature, record.Signature) {
		t.Fatal("the refused rewrite altered the stored signature")
	}

	// A pending record of a DIFFERENT rotation identity is not overwritten by
	// a signed record of another identity.
	node2 := handoffTestNode(t, tdilithium3SeamTestChainID)
	pendingA := handoffTestRecord(t, 8, tdilithium3SeamTestChainID)
	pendingA.Signature = nil
	if err := node2.storeTDilithium3HandoffProofRecord(pendingA); err != nil {
		t.Fatalf("store pending A: %v", err)
	}
	// A signed record of a DIFFERENT rotation identity (same outgoing key,
	// foreign incoming key, self-consistently signed): the pending record of
	// the original identity must not be replaced by it.
	foreignPair, err := qcrypto.GenerateKeyPairFromSeed([]byte("DEVNET ONLY handoff outgoing key 8"))
	if err != nil {
		t.Fatalf("outgoing key: %v", err)
	}
	foreignIncoming, err := qcrypto.GenerateKeyPairFromSeed([]byte("DEVNET ONLY handoff foreign incoming key"))
	if err != nil {
		t.Fatalf("foreign incoming key: %v", err)
	}
	foreignSignature, err := qcrypto.Sign(foreignPair.Private, consensus.QTDHandoffMessage(tdilithium3SeamTestChainID, 8, foreignIncoming.Public.Bytes(), consensus.QTDAnchorProofCommitteeVersion))
	if err != nil {
		t.Fatalf("foreign signature: %v", err)
	}
	foreign := &tdilithium3HandoffProofRecord{
		EpochNew:         8,
		CommitteeVersion: consensus.QTDAnchorProofCommitteeVersion,
		OldKey:           pendingA.OldKey,
		NewKey:           foreignIncoming.Public.Bytes(),
		Signature:        foreignSignature,
	}
	if err := node2.storeTDilithium3HandoffProofRecord(foreign); err == nil {
		t.Fatal("a signed record of a different identity overwrote a pending record")
	}
	if loaded := node2.loadTDilithium3HandoffProofRecord(8); loaded == nil || !bytes.Equal(loaded.NewKey, pendingA.NewKey) {
		t.Fatal("the refused rewrite replaced the pending rotation identity")
	}
}

// TestTDilithium3HandoffProofProbeFailureAttribution pins the probe-failure
// attribution (audit low): a probe error that is not "no active share" logs a
// Warn carrying the rotation epoch and keeps the no-op lane, while the
// no-active-share lane stays quiet.
func TestTDilithium3HandoffProofProbeFailureAttribution(t *testing.T) {
	capture, restore := anchorTraceCapture(t)
	defer restore()
	node := handoffTestNode(t, tdilithium3SeamTestChainID)
	freshKey := anchorTestKey(t, "probe attribution key")
	password := []byte("DEVNET ONLY probe attribution password")
	store := newThresholdShareStore(node.config.DataDir)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// The no-active-share lane: quiet, no record.
	node.produceTDilithium3HandoffProof(ctx, 8, freshKey, store, password)
	if node.loadTDilithium3HandoffProofRecord(8) != nil {
		t.Fatal("the first-establishment lane wrote a record")
	}
	if bytes.Contains([]byte(capture.String()), []byte("handoff proof probe")) {
		t.Fatal("the no-active-share lane logged a probe failure")
	}

	// A corrupted active share: a real fault — Warn with the epoch, no record.
	dir, err := tdilithium3HandoffProofDir(node.config.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	activePath := filepath.Join(filepath.Dir(filepath.Dir(dir)), "active.enc")
	if err := os.WriteFile(activePath, []byte("corrupted ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	node.produceTDilithium3HandoffProof(ctx, 8, freshKey, store, password)
	if node.loadTDilithium3HandoffProofRecord(8) != nil {
		t.Fatal("the faulted probe wrote a record")
	}
	if !bytes.Contains([]byte(capture.String()), []byte("handoff proof probe for epoch 8")) {
		t.Fatalf("the faulted probe was not attributed (log: %s)", capture.String())
	}
}
