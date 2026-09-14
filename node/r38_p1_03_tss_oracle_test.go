// Quantaureum Node source, version 1.0.0.
package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
	"github.com/quantaureum/qau/wallet/tss"
)

// ============================================================================
// R38-P1-03 (2026-08-01): distributed TSS proposer-controlled signing
// oracle for arbitrary messages.
//
// Vulnerability recap (from AUDIT-FULL-ROUND38-2026-07-31.md L154):
//   "Distributed TSS became a proposer-controlled arbitrary-message
//    signing oracle (functional gating). node/tss_distributed.go:365-430.
//    It only authenticated that the sender was the current proposer but
//    did not bind the message to chainID / epoch / slot / canonical
//    block hash / review verdict / executive set. Required two
//    environment vars to enable, but once enabled the impact reached
//    finality-breaking severity."
//
// Fix strategy:
//   1. Aggregator (proposer) side: when encoding SessionInit, replace
//      message with canonical = SHA-256("QAU-TSS-v1" || chainID ||
//      epoch || slot || proposer || domainTag || originalMessage),
//      and append chain context + originalMessage as a binding tail on
//      the wire payload.
//   2. Participant side: do not trust the chain context inside the
//      binding. Re-derive canonical from the local consensus view
//      (current slot / chainID / elected proposer), and require the
//      wire-level message to equal the expected canonical.
//   3. domainTag allow-list: only "block" / "vote" are accepted; any
//      other oracle topic (e.g. "execute-order-66") is rejected.
//
// Test matrix:
//   A. canonical envelope unit tests — determinism / curve-path access
//   B. aggregator (author) / participant (receiver) symmetric
//      construction → accept
//   C. Reject legacy v1 (binding == nil)
//   D. Reject cross-chain (binding.chainID != local)
//   E. Reject mismatching slot / epoch (replay from another slot)
//   F. Reject mismatching binding.proposer vs locally elected (impersonation)
//   G. Reject any forged message (the oracle-attack core)
//   H. Reject unknown domainTag (e.g. "vote-fake")
//   I. Codec round-trip + magic robustness (no magic = legacy)
// ============================================================================

// --- A. canonical envelope unit tests ------------------------------------

func TestR38P103_CanonicalBinding_IsDeterministicSameInputs(t *testing.T) {
	proposer := types.Address{0x11, 0x22, 0x33}
	orig := []byte("the-block-hash-or-vote-hash")
	out1 := computeTSSCanonicalBinding(1668, 5, 161, proposer, tssDomainTagBlock, orig)
	out2 := computeTSSCanonicalBinding(1668, 5, 161, proposer, tssDomainTagBlock, orig)
	if !bytes.Equal(out1[:], out2[:]) {
		t.Fatalf("canonical binding not deterministic: got %x vs %x", out1[:], out2[:])
	}
}

func TestR38P103_CanonicalBinding_ChangesWithChainID(t *testing.T) {
	proposer := types.Address{0x44}
	orig := []byte("block-hash")
	xMain := computeTSSCanonicalBinding(1668, 0, 0, proposer, tssDomainTagBlock, orig)
	xTest := computeTSSCanonicalBinding(1669, 0, 0, proposer, tssDomainTagBlock, orig)
	if bytes.Equal(xMain[:], xTest[:]) {
		t.Fatalf("canonical binding identical across chainIDs — cross-chain replay possible")
	}
}

func TestR38P103_CanonicalBinding_ChangesWithSlot(t *testing.T) {
	proposer := types.Address{0x55}
	orig := []byte("block-hash")
	a := computeTSSCanonicalBinding(1668, 0, 100, proposer, tssDomainTagBlock, orig)
	b := computeTSSCanonicalBinding(1668, 0, 101, proposer, tssDomainTagBlock, orig)
	if bytes.Equal(a[:], b[:]) {
		t.Fatalf("canonical binding identical across slots — slot replay possible")
	}
}

func TestR38P103_CanonicalBinding_ChangesWithProposer(t *testing.T) {
	p1 := types.Address{0x01}
	p2 := types.Address{0x02}
	orig := []byte("block-hash")
	a := computeTSSCanonicalBinding(1668, 0, 1, p1, tssDomainTagBlock, orig)
	b := computeTSSCanonicalBinding(1668, 0, 1, p2, tssDomainTagBlock, orig)
	if bytes.Equal(a[:], b[:]) {
		t.Fatalf("canonical binding identical across proposers — proposer impersonation replay possible")
	}
}

func TestR38P103_CanonicalBinding_ChangesWithDomainTag(t *testing.T) {
	proposer := types.Address{0x77}
	orig := []byte("payload-hash")
	a := computeTSSCanonicalBinding(1668, 0, 1, proposer, tssDomainTagBlock, orig)
	b := computeTSSCanonicalBinding(1668, 0, 1, proposer, tssDomainTagVote, orig)
	if bytes.Equal(a[:], b[:]) {
		t.Fatalf("canonical binding identical for block vs vote domain — cross-purpose replay possible")
	}
}

func TestR38P103_CanonicalBinding_ChangesWithOriginalMessage(t *testing.T) {
	proposer := types.Address{0x88}
	a := computeTSSCanonicalBinding(1668, 0, 1, proposer, tssDomainTagBlock, []byte("real-block-hash"))
	b := computeTSSCanonicalBinding(1668, 0, 1, proposer, tssDomainTagBlock, []byte("oracle-fake"))
	if bytes.Equal(a[:], b[:]) {
		t.Fatalf("canonical binding identical for different original messages — oracle binding failed")
	}
}

// --- B..H. verifyTSSSessionInitBinding black-box receiver tests --------------

// makeCanonicalBindingPayload builds a valid SessionInit payload from
// the aggregator's point of view. Returns the payload (a legacy frame
// with the canonicalMessage + binding tail) so the test can feed it
// decodeTSSSessionInitBound + verifyTSSSessionInitBinding。
func makeCanonicalBindingPayload(
	t *testing.T,
	aggrChainID, aggrSlot uint64,
	aggrProposer types.Address,
	domainTag string,
	originalMessage []byte,
) []byte {
	t.Helper()
	epoch := aggrSlot / consensus.SlotsPerEpoch
	canonicalMessage := computeTSSCanonicalBinding(aggrChainID, epoch, aggrSlot, aggrProposer, domainTag, originalMessage)
	// build a minimal legacy SessionInit (msg=canonicalMessage, no participants)
	// then append the binding tail. A simple sessionID is used for hash checks.
	var sessionID [32]byte
	sessionID[0] = 0xAA
	legacyFrame := tss.EncodeSessionInit(sessionID, canonicalMessage[:], nil, 0)
	tail := encodeBindingTail(aggrChainID, epoch, aggrSlot, aggrProposer, domainTag, originalMessage)
	return append(append([]byte{}, legacyFrame...), tail...)
}

// encodeBindingTail manually builds a binding tail so tests can vary fields for different attack scenarios.
// In production, this work is inline inside encodeTSSSessionInitBound.
func encodeBindingTail(
	chainID, epoch, slot uint64,
	proposer types.Address,
	domainTag string,
	originalMessage []byte,
) []byte {
	out := make([]byte, 0, 4+8+8+8+20+1+len(domainTag)+4+len(originalMessage))
	out = append(out, tssSessionInitBindingMagic[:]...)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], chainID)
	out = append(out, b[:]...)
	binary.BigEndian.PutUint64(b[:], epoch)
	out = append(out, b[:]...)
	binary.BigEndian.PutUint64(b[:], slot)
	out = append(out, b[:]...)
	out = append(out, proposer[:]...)
	out = append(out, byte(len(domainTag)))
	out = append(out, []byte(domainTag)...)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(originalMessage)))
	out = append(out, l[:]...)
	out = append(out, originalMessage...)
	return out
}

// decodeForVerify runs decodeTSSSessionInitBound + tss.DecodeSessionInit to obtain
// canonicalMessage, then delegates to verifyTSSSessionInitBinding.
func decodeForVerify(
	t *testing.T,
	payload []byte,
	localChainID uint64,
	localSlot uint64,
	localProposer types.Address,
) (bool, string) {
	t.Helper()
	legacyFrame, binding, _ := decodeTSSSessionInitBound(payload)
	_, message, _, _, err := tss.DecodeSessionInit(legacyFrame)
	if err != nil {
		t.Fatalf("legacy frame decode error: %v", err)
	}
	return verifyTSSSessionInitBinding(binding, message, localChainID, localSlot, localProposer)
}

// TestR38P103_Bound_AggregatorAndParticipantAgree: the legitimate path is accepted
func TestR38P103_Bound_AggregatorAndParticipantAgree(t *testing.T) {
	proposer := types.Address{0x11, 0x22}
	original := sha256.Sum256([]byte("block-101"))
	payload := makeCanonicalBindingPayload(t, 1668, 100, proposer, tssDomainTagBlock, original[:])
	ok, reason := decodeForVerify(t, payload, 1668, 100, proposer)
	if !ok {
		t.Fatalf("honest aggregator binding rejected: %s", reason)
	}
}

// TestR38P103_RejectLegacyV1Payload: binding == nil (no magic tail)
func TestR38P103_RejectLegacyV1Payload(t *testing.T) {
	proposer := types.Address{0x11, 0x22}
	original := sha256.Sum256([]byte("block-101"))
	// no binding tail — a legacy EncodeSessionInit payload
	var sessionID [32]byte
	legacyOnly := tss.EncodeSessionInit(sessionID, original[:], []int{1, 2, 3}, 0)
	ok, reason := decodeForVerify(t, legacyOnly, 1668, 100, proposer)
	if ok {
		t.Fatalf("legacy v1 SessionInit (no binding tail) was accepted — oracle attack returns")
	}
	if reason == "" {
		t.Fatalf("reject reason empty")
	}
}

// TestR38P103_RejectCrossChain: binding.chainID != local chainID
func TestR38P103_RejectCrossChain(t *testing.T) {
	proposer := types.Address{0x11, 0x22}
	original := sha256.Sum256([]byte("block-101"))
	// aggregator claims chainID=1669 but local is 1668
	payload := makeCanonicalBindingPayload(t, 1669, 100, proposer, tssDomainTagBlock, original[:])
	ok, reason := decodeForVerify(t, payload, 1668, 100, proposer)
	if ok {
		t.Fatalf("cross-chain binding accepted — chainID binding failed (reason=%q)", reason)
	}
}

// TestR38P103_RejectSlotMismatch: binding.slot != local slot
func TestR38P103_RejectSlotMismatch(t *testing.T) {
	proposer := types.Address{0x33}
	original := sha256.Sum256([]byte("block-X"))
	// aggregator claims slot=200 but local is 100
	payload := makeCanonicalBindingPayload(t, 1668, 200, proposer, tssDomainTagBlock, original[:])
	ok, _ := decodeForVerify(t, payload, 1668, 100, proposer)
	if ok {
		t.Fatalf("slot mismatch accepted — slot binding (anti-replay across slots) failed")
	}
}

// TestR38P103_RejectProposerImpersonation: binding.proposer != elected proposer
func TestR38P103_RejectProposerImpersonation(t *testing.T) {
	aggrProposer := types.Address{0x01}
	honestElectedProposer := types.Address{0x02}
	original := sha256.Sum256([]byte("block-101"))
	payload := makeCanonicalBindingPayload(t, 1668, 100, aggrProposer, tssDomainTagBlock, original[:])
	ok, _ := decodeForVerify(t, payload, 1668, 100, honestElectedProposer)
	if ok {
		t.Fatalf("proposer impersonation accepted — B-5+binding identity contract failed")
	}
}

// TestR38P103_RejectArbitraryOracleMessage: core oracle-attack test.
// aggregator crafts a bindingTail whose originalMessage = oracle-fake, but
// the wire-level message uses arbitrary bytes (not a canonical envelope).
// the attacker wants the participant set to threshold-sign this name.
func TestR38P103_RejectArbitraryOracleMessage(t *testing.T) {
	proposer := types.Address{0x44}
	// real view: aggregator uses real-block-hash
	realOriginal := sha256.Sum256([]byte("real-block-101"))
	// attack payload: tamper the legacy frame message field (arbitrary oracle bytes) while still claiming originalMessage = realOriginal in the binding tail
	epoch := uint64(100) / consensus.SlotsPerEpoch
	canonicalTail := encodeBindingTail(1668, epoch, 100, proposer, tssDomainTagBlock, realOriginal[:])
	// custom forged wire message (32 bytes, non-zero, shape-valid)
	oracleMessage := sha256.Sum256([]byte("oracle-attack-arbitrary-content"))
	var sessionID [32]byte
	sessionID[0] = 0xBB
	legacyFrame := tss.EncodeSessionInit(sessionID, oracleMessage[:], nil, 0)
	payload := append(append([]byte{}, legacyFrame...), canonicalTail...)
	ok, _ := decodeForVerify(t, payload, 1668, 100, proposer)
	if ok {
		t.Fatalf("ARBITRARY ORACLE ATTACK ACCEPTED — participant would threshold-sign oracle-chosen content; R38-P1-03 not mitigated")
	}
}

// TestR38P103_RejectUnknownDomainTag: domainTag="execute-order-66" is rejected
func TestR38P103_RejectUnknownDomainTag(t *testing.T) {
	proposer := types.Address{0x55}
	original := sha256.Sum256([]byte("block-101"))
	payload := makeCanonicalBindingPayload(t, 1668, 100, proposer, "execute-order-66", original[:])
	ok, _ := decodeForVerify(t, payload, 1668, 100, proposer)
	if ok {
		t.Fatalf("unknown domain tag accepted — oracle attack surface expanded")
	}
}

// TestR38P103_EncodeDecodeRoundTrip: full round-trip of a normal payload
func TestR38P103_EncodeDecodeRoundTrip(t *testing.T) {
	proposer := types.Address{0xEE}
	original := sha256.Sum256([]byte("block-101"))
	epoch := uint64(100) / consensus.SlotsPerEpoch
	canonicalMessage := computeTSSCanonicalBinding(1668, epoch, 100, proposer, tssDomainTagBlock, original[:])
	payload := encodeTSSSessionInitBound(
		[32]byte{0x01}, canonicalMessage[:], []int{1, 2, 3}, 123456,
		1668, epoch, 100, proposer,
		tssDomainTagBlock, original[:],
	)
	legacyFrame, binding, ok := decodeTSSSessionInitBound(payload)
	if !ok || binding == nil {
		t.Fatalf("round-trip decode: binding tail not found")
	}
	if binding.chainID != 1668 || binding.epoch != epoch || binding.slot != 100 {
		t.Fatalf("binding context mismatch: %+v", binding)
	}
	if binding.proposer != proposer {
		t.Fatalf("binding proposer mismatch: got %x want %x", binding.proposer, proposer)
	}
	if binding.domainTag != tssDomainTagBlock {
		t.Fatalf("binding domainTag mismatch: got %q want %q", binding.domainTag, tssDomainTagBlock)
	}
	if !bytes.Equal(binding.originalMessage, original[:]) {
		t.Fatalf("binding originalMessage mismatch")
	}
	_, msg, _, _, err := tss.DecodeSessionInit(legacyFrame)
	if err != nil {
		t.Fatalf("legacy frame decode error: %v", err)
	}
	if !bytes.Equal(msg, canonicalMessage[:]) {
		t.Fatalf("canonicalMessage not preserved in round-trip")
	}
}

// TestR38P103_NoMagicOnShortPayload: extremely short payloads must be treated as legacy, not panic
func TestR38P103_NoMagicOnShortPayload(t *testing.T) {
	_, _, ok := decodeTSSSessionInitBound(nil)
	if ok {
		t.Fatalf("nil payload should not report binding present")
	}
	_, _, ok = decodeTSSSessionInitBound([]byte{0x00, 0x01, 0x02})
	if ok {
		t.Fatalf("3-byte payload should not report binding present")
	}
}

// TestR38P103_MagicInsideLegacyFrameRejected: "QAU-T1" may appear
// incidentally inside an old-format payload, but the contrived case in
// this test does not actually work — we do not forge a complete binding
// at the end of the legacy frame, so the stripped legacyFrame is of a
// plausible size but fails tss.DecodeSessionInit due to length mismatch,
// and is rejected upstream. This test asserts the degenerate path does
// not panic.
func TestR38P103_MagicInsideLegacyFrameNoPanic(t *testing.T) {
	// build a payload: 30-byte legacy frame + 4-byte magic + NO complete binding tail
	var legacyPart [30]byte
	legacyPart[0] = 0xFF
	payload := append(append([]byte{}, legacyPart[:]...), tssSessionInitBindingMagic[:]...)
	legacyFrame, binding, present := decodeTSSSessionInitBound(payload)
	// magic present but tail truncated → binding=nil, present=false (truncated path per code)
	if present && binding != nil {
		t.Fatalf("malformed magic-tail payload was accepted as bound")
	}
	// legacyFrame should equal payload (unchanged — early return)
	if len(legacyFrame) != len(payload) {
		t.Fatalf("malformed payload mutated — round-trip inconsistency")
	}
}
