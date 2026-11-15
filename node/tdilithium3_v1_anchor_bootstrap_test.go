// Quantaureum Node source, version 1.0.0.
package node

// Tests of the Dilithium3 v1 fresh-sync bootstrap carriers (TSS-R3-B-1 R-1
// fix): the epoch-boundary anchor carrier, the un-anchored window, the
// canonical-anchor observation state, and the refusal of anchors that never
// legitimately entered the chain. See tdilithium3_v1_anchor_bootstrap.go for
// the design and the trust model.

import (
	"bytes"
	"log/slog"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/consensus"
	qcrypto "github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// big100 is the fixture stake the trigger e2e validators use.
func big100() *big.Int { return big.NewInt(100) }

// anchorTestKey builds a deterministic non-degenerate Dilithium3 public key
// carrying the tag, for anchor fixtures.
func anchorTestKey(t *testing.T, tag string) []byte {
	t.Helper()
	pair, err := qcrypto.GenerateKeyPairFromSeed([]byte("DEVNET ONLY anchor bootstrap " + tag))
	if err != nil {
		t.Fatalf("key %s: %v", tag, err)
	}
	key := pair.Public.Bytes()
	if len(key) != qcrypto.Dilithium3PublicKeySize {
		t.Fatalf("key %s has %d bytes", tag, len(key))
	}
	return key
}

// anchorTraceCapture installs a capturing default slog handler and returns the
// buffer plus a restore func.
func anchorTraceCapture(t *testing.T) (*triggerE2ELogBuffer, func()) {
	t.Helper()
	capture := &triggerE2ELogBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(capture, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return capture, func() { slog.SetDefault(previous) }
}

// TestTDilithium3V1CanonicalAnchorObserved pins the observation state's four
// outcomes: nothing recorded, an anchor below the activation epoch, a foreign
// key, and the legitimate (activation-epoch, ceremony-key) anchor.
func TestTDilithium3V1CanonicalAnchorObserved(t *testing.T) {
	ceremonyKey := anchorTestKey(t, "ceremony")
	otherKey := anchorTestKey(t, "other")
	node := &Node{}

	// Nothing observed: the un-anchored window is open.
	if node.tdilithium3V1CanonicalAnchorObserved(7, ceremonyKey) {
		t.Fatal("an empty observation reported the key as chain-anchored")
	}

	// An anchor below the activation epoch does not vouch for the key.
	node.recordTDilithium3CanonicalAnchor(6, ceremonyKey)
	if node.tdilithium3V1CanonicalAnchorObserved(7, ceremonyKey) {
		t.Fatal("an anchor below the activation epoch closed the un-anchored window")
	}

	// A foreign key at a sufficient epoch does not vouch either.
	node.recordTDilithium3CanonicalAnchor(7, otherKey)
	if node.tdilithium3V1CanonicalAnchorObserved(7, ceremonyKey) {
		t.Fatal("a foreign anchor closed the un-anchored window for the ceremony key")
	}

	// The legitimate anchor closes the window. The carrier lands at a strictly
	// newer epoch than the foreign record (the adoption discipline refuses a
	// conflicting key AT a recorded epoch, so a legitimate carrier is always
	// ahead of it); the record is epoch-monotonic (audit round-2 finding 3),
	// which is why the test does not overwrite at the same epoch.
	node.recordTDilithium3CanonicalAnchor(8, ceremonyKey)
	if !node.tdilithium3V1CanonicalAnchorObserved(7, ceremonyKey) {
		t.Fatal("the ceremony anchor did not close the un-anchored window")
	}
	// A later continuation anchor of the same key keeps the window closed
	// (the boundary carriers re-anchor every epoch in the steady state).
	node.recordTDilithium3CanonicalAnchor(9, ceremonyKey)
	if !node.tdilithium3V1CanonicalAnchorObserved(7, ceremonyKey) {
		t.Fatal("a later same-key anchor reopened the un-anchored window")
	}

	// Degenerate inputs fail closed.
	var nilNode *Node
	if nilNode.tdilithium3V1CanonicalAnchorObserved(7, ceremonyKey) {
		t.Fatal("nil node reported an observed anchor")
	}
	if node.tdilithium3V1CanonicalAnchorObserved(7, nil) {
		t.Fatal("an empty key reported an observed anchor")
	}
}

// TestTDilithium3V1HeaderAnchorKeyUnarmedSource pins the producer-side defense:
// a node that is not armed for the v1 path (neither the offline activation nor
// the proposal gate) anchors nothing, and an armed node whose share identity is
// unusable anchors nothing either. This is what keeps a non-armed source from
// writing an anchor of its own choosing into a header.
func TestTDilithium3V1HeaderAnchorKeyUnarmedSource(t *testing.T) {
	// Not armed: no v1 configuration at all (the GM-QTD-era and flags-off
	// posture). The overlay must stay inert — the GM-QTD anchor path
	// (PopulateStardustFields) is the only writer there, unchanged.
	unarmed := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	unarmed.blockProducer = &BlockProducer{node: unarmed}
	if key, err := unarmed.blockProducer.tdilithium3V1HeaderAnchorKey(&encoding.BlockHeader{Epoch: 9, Slot: 288}); key != nil || err != nil {
		t.Fatalf("an unarmed producer produced an anchor (key=%v err=%v)", key, err)
	}

	// Armed for the epoch (proposal gate open) but no share store: the
	// identity probe fails, the header carries no anchor, and the failure is
	// reported for the boundary carrier to log.
	t.Setenv("QAU_ENABLE_TDILITHIUM3_V1_PROPOSAL", "1")
	armed := &Node{config: &Config{
		NetworkID:                    TestnetNetworkID,
		TSSV1ProposalActivationEpoch: 9,
	}}
	armed.blockProducer = &BlockProducer{node: armed}
	key, err := armed.blockProducer.tdilithium3V1HeaderAnchorKey(&encoding.BlockHeader{Epoch: 9, Slot: 288})
	if key != nil || err == nil {
		t.Fatalf("an armed producer without a share anchored (key=%v err=%v)", key, err)
	}
}

// TestTDilithium3V1HeaderAnchorKeyCarriers pins the two carrier rules on an
// armed node with a real active share: the epoch's first block always anchors;
// a mid-epoch block anchors only while the key is not chain-observed; and a
// pre-activation epoch never anchors.
func TestTDilithium3V1HeaderAnchorKeyCarriers(t *testing.T) {
	node, groupKey, _, _, _ := triggerE2EFixture(t)
	const activation = triggerE2EActivationEpoch
	boundarySlot := activation * consensus.SlotsPerEpoch
	midSlot := boundarySlot + 3

	// Boundary carrier: the epoch's first block anchors while the un-anchored
	// window is open.
	header := &encoding.BlockHeader{Epoch: activation, Slot: boundarySlot}
	if key, err := node.blockProducer.tdilithium3V1HeaderAnchorKey(header); err != nil || !bytes.Equal(key, groupKey) {
		t.Fatalf("the epoch-boundary carrier did not anchor (key=%v err=%v)", key, err)
	}

	// Un-anchored window: a mid-epoch block anchors too.
	header = &encoding.BlockHeader{Epoch: activation, Slot: midSlot}
	if key, err := node.blockProducer.tdilithium3V1HeaderAnchorKey(header); err != nil || !bytes.Equal(key, groupKey) {
		t.Fatalf("the un-anchored window did not anchor a mid-epoch header (key=%v err=%v)", key, err)
	}

	// The window closes once a canonical block anchored the active key.
	node.recordTDilithium3CanonicalAnchor(activation, groupKey)
	if key, err := node.blockProducer.tdilithium3V1HeaderAnchorKey(header); key != nil || err != nil {
		t.Fatalf("a mid-epoch block anchored after the key was chain-observed (key=%v err=%v)", key, err)
	}

	// The boundary carrier keeps anchoring in the steady state.
	header = &encoding.BlockHeader{Epoch: activation, Slot: boundarySlot}
	if key, err := node.blockProducer.tdilithium3V1HeaderAnchorKey(header); err != nil || !bytes.Equal(key, groupKey) {
		t.Fatalf("the steady-state boundary carrier stopped anchoring (key=%v err=%v)", key, err)
	}

	// A pre-activation epoch never anchors: the GM-QTD key is active there,
	// and a v1 anchor recorded at such an epoch would mis-verify its seals.
	header = &encoding.BlockHeader{Epoch: activation - 1, Slot: midSlot - consensus.SlotsPerEpoch}
	if key, err := node.blockProducer.tdilithium3V1HeaderAnchorKey(header); key != nil || err != nil {
		t.Fatalf("a pre-activation epoch anchored (key=%v err=%v)", key, err)
	}
}

// TestTDilithium3V1SessionGates pins the session-side carrier gates through the
// production entry point, distinguished by the decision trace: a boundary
// header and an un-anchored mid-epoch header are refused by their named gate,
// and once the key is chain-observed a mid-epoch header passes the gates and
// reaches the attempt loop (whose exhaustion is the no-peer outcome). The
// record sequence follows the real chronology — the pre-activation foreign
// anchor (the GM-QTD-era shape) precedes the ceremony carrier, and the
// epoch-monotonic record only moves forward.
func TestTDilithium3V1SessionGates(t *testing.T) {
	node, groupKey, _, _, _ := triggerE2EFixture(t)
	const activation = triggerE2EActivationEpoch
	boundarySlot := activation * consensus.SlotsPerEpoch
	midSlot := boundarySlot + 5
	midHeader := &encoding.BlockHeader{
		ChainID: tdilithium3SeamTestChainID, Epoch: activation, Slot: midSlot,
		ProposerAddr: node.blockProducer.validatorAddr,
	}

	// The pre-activation foreign record (a GM-QTD-era anchor adopted before
	// the v1 key activates): the ceremony key's gate stays closed.
	node.recordTDilithium3CanonicalAnchor(activation-1, anchorTestKey(t, "foreign"))

	// Boundary header: refused by the boundary gate regardless of the anchor
	// state.
	capture, restore := anchorTraceCapture(t)
	if sig := node.tdilithium3V1ProposalHeaderSignature(&encoding.BlockHeader{
		ChainID: tdilithium3SeamTestChainID, Epoch: activation, Slot: boundarySlot,
		ProposerAddr: node.blockProducer.validatorAddr,
	}); sig != nil {
		t.Fatal("an epoch-boundary header produced a group signature")
	}
	if out := capture.String(); !bytes.Contains([]byte(out), []byte("epoch boundary keeps the individual anchor carrier")) {
		t.Fatalf("the boundary refusal left no trace: %s", out)
	}
	restore()

	// Un-anchored window: the ceremony key is not chain-anchored yet, so a
	// mid-epoch header stays individually signed.
	capture, restore = anchorTraceCapture(t)
	if sig := node.tdilithium3V1ProposalHeaderSignature(midHeader); sig != nil {
		t.Fatal("an un-anchored mid-epoch header produced a group signature")
	}
	if out := capture.String(); !bytes.Contains([]byte(out), []byte("not chain-anchored yet")) {
		t.Fatalf("the un-anchored refusal left no trace: %s", out)
	}
	restore()

	// The legitimate carrier lands at the activation epoch (strictly newer
	// than the foreign record, so the monotonic record accepts it): the gates
	// open for a mid-epoch header. The session itself cannot converge
	// in-process (no peers carry the round messages), so the nil result below
	// is the attempt loop running out, NOT the carrier gates refusing.
	node.recordTDilithium3CanonicalAnchor(activation, groupKey)
	capture, restore = anchorTraceCapture(t)
	if sig := node.tdilithium3V1ProposalHeaderSignature(midHeader); sig != nil {
		t.Fatal("the session produced a signature without peer round messages")
	}
	out := capture.String()
	if bytes.Contains([]byte(out), []byte("not chain-anchored yet")) ||
		bytes.Contains([]byte(out), []byte("epoch boundary keeps the individual anchor carrier")) {
		t.Fatalf("the carrier gates refused a chain-anchored mid-epoch header: %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("attempts exhausted")) &&
		!bytes.Contains([]byte(out), []byte("attempt")) {
		t.Fatalf("the gates opened but the attempt loop never ran: %s", out)
	}
	restore()
}

// TestTDilithium3CanonicalAnchorRecordRequiresAdoption pins the observer-side
// defense at the import hook: only an anchor that ObserveAnchoredGroupKey
// ADOPTED reaches the canonical-anchor record, so a rogue or mismatched anchor
// can never flip the producer gate open. This is the R19-F02 cross-protection
// carried into the fresh-sync bootstrap.
func TestTDilithium3CanonicalAnchorRecordRequiresAdoption(t *testing.T) {
	node, groupKey, _, _, _ := triggerE2EFixture(t)
	bp := node.blockProducer
	midSlot := triggerE2EActivationEpoch*consensus.SlotsPerEpoch + 4

	// A rogue anchor (an attacker-chosen key on an individually signed
	// header): the armed node's custody holds the ceremony key, so the
	// R19-F02 first-establishment check refuses the foreign key and nothing
	// is recorded.
	rogue := anchorTestKey(t, "rogue")
	bp.onCanonicalBlockImported(&encoding.BlockHeader{
		Epoch: triggerE2EActivationEpoch, Slot: midSlot, QTDGroupKey: append([]byte(nil), rogue...),
	})
	if node.tdilithium3V1CanonicalAnchorObserved(triggerE2EActivationEpoch, rogue) {
		t.Fatal("a refused rogue anchor was recorded as canonical evidence")
	}
	if node.tdilithium3V1CanonicalAnchorObserved(triggerE2EActivationEpoch, groupKey) {
		t.Fatal("the ceremony key was recorded without any carrier")
	}

	// The legitimate carrier (the ceremony key on an individual header) is
	// adopted and recorded.
	bp.onCanonicalBlockImported(&encoding.BlockHeader{
		Epoch: triggerE2EActivationEpoch, Slot: midSlot, QTDGroupKey: append([]byte(nil), groupKey...),
	})
	if !node.tdilithium3V1CanonicalAnchorObserved(triggerE2EActivationEpoch, groupKey) {
		t.Fatal("the adopted anchor was not recorded as canonical evidence")
	}
}

// TestTDilithium3CanonicalAnchorRecordMonotonic pins the epoch-monotonic
// guard (audit round-2 finding 3): import order is not chain order, so an
// older same-key anchor — delivered by a fork switch or a delayed import,
// adopted as a no-op true by ObserveAnchoredGroupKey — must NOT rewind the
// canonical-anchor record below the key's activation epoch (that would
// re-open the un-anchored window for a key that is already on the chain).
// A strictly newer epoch advances the record, rotation included.
func TestTDilithium3CanonicalAnchorRecordMonotonic(t *testing.T) {
	ceremonyKey := anchorTestKey(t, "monotonic")
	node := &Node{}

	// Baseline: the record is established at epoch 9 (activation 7).
	node.recordTDilithium3CanonicalAnchor(9, ceremonyKey)
	if !node.tdilithium3V1CanonicalAnchorObserved(7, ceremonyKey) {
		t.Fatal("the baseline record at epoch 9 did not close the window")
	}

	// An OLDER same-key anchor (fork import at epoch 5, below the activation):
	// the record must not be demoted — pre-fix this rewound the record to 5
	// and re-opened the window.
	node.recordTDilithium3CanonicalAnchor(5, ceremonyKey)
	if !node.tdilithium3V1CanonicalAnchorObserved(7, ceremonyKey) {
		t.Fatal("an older same-key anchor demoted the record below the activation epoch")
	}

	// Same-epoch re-anchor: skipped, record unchanged.
	node.recordTDilithium3CanonicalAnchor(9, ceremonyKey)
	if !node.tdilithium3V1CanonicalAnchorObserved(7, ceremonyKey) {
		t.Fatal("a same-epoch re-anchor disturbed the record")
	}

	// A strictly newer epoch advances the record — including a ROTATION to a
	// different key.
	newKey := anchorTestKey(t, "rotated")
	node.recordTDilithium3CanonicalAnchor(12, newKey)
	if !node.tdilithium3V1CanonicalAnchorObserved(12, newKey) {
		t.Fatal("a newer-epoch rotation anchor did not advance the record")
	}
	if node.tdilithium3V1CanonicalAnchorObserved(12, ceremonyKey) {
		t.Fatal("the replaced key still vouched after the rotation advanced the record")
	}

	// An older anchor of the REPLACED key cannot demote the rotation record.
	node.recordTDilithium3CanonicalAnchor(6, ceremonyKey)
	if !node.tdilithium3V1CanonicalAnchorObserved(12, newKey) {
		t.Fatal("an older anchor demoted the rotation record")
	}

	// The very first record below any activation is still a no-op for the
	// gate (epoch-0 anchors can never vouch for an activation >= 1).
	fresh := &Node{}
	fresh.recordTDilithium3CanonicalAnchor(0, ceremonyKey)
	if fresh.tdilithium3V1CanonicalAnchorObserved(1, ceremonyKey) {
		t.Fatal("an epoch-0 anchor closed the window for an activation-1 key")
	}
}

// TestTDilithium3V1AnchorOverlayLeavesGMQTDEraUntouched is the regression
// guard for the GM-QTD anchor behavior: a node with a legacy QTD signer but no
// v1 arming produces no v1 anchor from the overlay, so the GM-QTD boundary
// anchors (PopulateStardustFields) remain the only writer of that era and their
// semantics are unchanged.
func TestTDilithium3V1AnchorOverlayLeavesGMQTDEraUntouched(t *testing.T) {
	node := &Node{config: &Config{NetworkID: TestnetNetworkID}}
	validatorSet, err := consensus.NewValidatorSet([]*consensus.Validator{{
		Address: types.Address{0x11}, Stake: big100(), Active: true,
	}})
	if err != nil {
		t.Fatalf("validator set: %v", err)
	}
	qpos, err := consensus.NewQPOS(validatorSet)
	if err != nil {
		t.Fatalf("qpos: %v", err)
	}
	qpos.InitChambers()
	node.blockProducer = &BlockProducer{node: node, qpos: qpos}
	qfs := qpos.GetQTDFinality()
	if qfs == nil {
		t.Fatal("no QTD finality engine")
	}
	// Install the legacy GM-QTD-era signer: the v1 overlay must not care —
	// without v1 arming it anchors nothing.
	ceremonyKey := anchorTestKey(t, "gm-era")
	signer, err := newTDilithium3SigningFinalitySigner(ceremonyKey, 4)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	qfs.SetQTDSignerForEpoch(signer, 1)
	header := &encoding.BlockHeader{Epoch: 2, Slot: 64}
	if key, anchorErr := node.blockProducer.tdilithium3V1HeaderAnchorKey(header); key != nil || anchorErr != nil {
		t.Fatalf("the v1 overlay anchored in the GM-QTD era (key=%v err=%v)", key, anchorErr)
	}
}

// TestTDilithium3V1AnchorFieldStrippedFromSigning mirrors the header encoding
// contract the carriers rely on: the anchor rides OUTSIDE the signing root, so
// attaching it after the signature does not flip the signing hash on import.
func TestTDilithium3V1AnchorFieldStrippedFromSigning(t *testing.T) {
	header := &encoding.BlockHeader{Epoch: 3, Slot: 100, QTDGroupKey: anchorTestKey(t, "strip")}
	without := *header
	without.QTDGroupKey = nil
	rootWith, err := encoding.BlockHeaderSigningRoot(header)
	if err != nil {
		t.Fatal(err)
	}
	rootWithout, err := encoding.BlockHeaderSigningRoot(&without)
	if err != nil {
		t.Fatal(err)
	}
	if rootWith != rootWithout {
		t.Fatal("the anchor field changed the signing root")
	}
	// The group-signature message contract: the canonical TSS binding over the
	// signing root is what the v1 branch verifies, so the anchor cannot leak
	// into the signed material there either.
	boundWith := consensus.ComputeTSSCanonicalBinding(header.ChainID, header.Epoch, header.Slot, header.ProposerAddr, "block", rootWith[:])
	boundWithout := consensus.ComputeTSSCanonicalBinding(without.ChainID, without.Epoch, without.Slot, without.ProposerAddr, "block", rootWithout[:])
	if boundWith != boundWithout {
		t.Fatal("the anchor field changed the canonical TSS binding")
	}
	var _ = mode3.SignatureSize // keep the mode3 import tied to the signature-size contract
}

// TestTDilithium3V1AnchorProducedHeaderSelfCertifies pins the P2-4 devnet
// finding fix: a locally produced carrier header must flip the producer's
// OWN canonical-anchor record (anchorProducedHeader). The producer's own
// blocks never pass through BlockProducer.onCanonicalBlockImported — that
// hook runs only on the peer-import paths — so without self-certification an
// armed producer that seeded the era stays gate-closed forever while the
// anchored majority group-signs (the P2-4 fleet split: 23 minutes without
// self-heal, 5 of 19 headers group-signed).
func TestTDilithium3V1AnchorProducedHeaderSelfCertifies(t *testing.T) {
	node, groupKey, _, _, _ := triggerE2EFixture(t)
	const activation = triggerE2EActivationEpoch
	midSlot := activation*consensus.SlotsPerEpoch + 5

	// Before production: the un-anchored window is open for this producer.
	if node.tdilithium3V1CanonicalAnchorObserved(activation, groupKey) {
		t.Fatal("the anchor gate is open before any carrier was produced")
	}

	// The producer seeds its own carrier: anchorProducedHeader embeds the
	// active ceremony key and SELF-CERTIFIES the record under the same
	// monotonic guard the import path uses.
	header := &encoding.BlockHeader{
		ChainID:      tdilithium3SeamTestChainID,
		Epoch:        activation,
		Slot:         midSlot,
		ProposerAddr: node.blockProducer.validatorAddr,
	}
	node.blockProducer.anchorProducedHeader(header, midSlot)
	if len(header.QTDGroupKey) == 0 {
		t.Fatal("the carrier header left without the anchor embedded")
	}
	if !bytes.Equal(header.QTDGroupKey, groupKey) {
		t.Fatal("the embedded anchor is not the active ceremony key")
	}
	if !node.tdilithium3V1CanonicalAnchorObserved(activation, groupKey) {
		t.Fatal("self-certification did not close the un-anchored window: the producer of the era's own carrier would stay gate-closed forever (P2-4 regression)")
	}

	// The monotonic guard applies to self-certification: producing an
	// OLDER-epoch carrier cannot downgrade the record.
	oldHeader := &encoding.BlockHeader{
		ChainID:      tdilithium3SeamTestChainID,
		Epoch:        activation - 1,
		Slot:         (activation - 1) * consensus.SlotsPerEpoch,
		ProposerAddr: node.blockProducer.validatorAddr,
	}
	node.blockProducer.anchorProducedHeader(oldHeader, oldHeader.Slot)
	if !node.tdilithium3V1CanonicalAnchorObserved(activation, groupKey) {
		t.Fatal("an older-epoch carrier downgraded the anchor record")
	}

	// A nil-node producer (defensive shape) must not panic.
	var nilBP *BlockProducer
	nilBP.anchorProducedHeader(header, midSlot)
}
