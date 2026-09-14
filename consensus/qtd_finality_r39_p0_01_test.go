// Quantaureum Node source, version 1.0.0.
// R39-P0-01 + R40-P0-01 regression tests for QTD domain separation.
//
// The QTD threshold seal previously covered the raw 32-byte blockHash with
// NO binding to chainID/epoch/slot. R39-P0-01 introduced the canonical
// signed message
//
//	QTDDomainSep(16) || chainID(8 BE) || epoch(8 BE) || slot(8 BE) || blockHash(32)
//
// total = 72 bytes. chainID == 0 (legacy unset / tests decoupled from chain
// config) falls back to the legacy raw blockHash so historical seals keep
// verifying; chainID > 0 forces the canonical message.
//
// R40-P0-01 (2026-08-03) FIX: removed the per-epoch legacy escape hatch
// from the chainID > 0 path. Previously, qtdVerifyMessageLocked took an
// `allowLegacyForEpoch` argument and re-tried raw-blockHash verification
// whenever `epoch == allowLegacyForEpoch`; every call site passed `epoch`
// (the very slot's epoch) as that argument, so the gate was tautological
// and domain separation was silently bypassed for EVERY epoch. The fix
// makes the verification unambiguous:
//   - chainID > 0  → verify strictly over the canonical message (NO fallback)
//   - chainID == 0 → legacy raw blockHash verification (backward compatibility)
//
// These tests pin:
//
//	(a) the byte layout / encoding of qtdSignedMessage and the legacy fallback;
//	(b) cross-chain / cross-epoch seal replay is rejected via the
//	    qtdVerifyMessageLocked helper (with a deterministic mock signer);
//	(c) R40-P0-01 fix: NO per-epoch escape hatch — a raw-blockHash seal is
//	    rejected on any node that has chainID > 0, regardless of epoch match;
//	(d) chainID == 0 still verifies raw-blockHash seals (pre-R39 nodes / tests).
package consensus

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// r39P001MockSigner is a deterministic ThresholdKeySigner stub. It accepts
// ANY group key and treats a signature as "valid" iff the signature bytes
// EXACTLY equal the (canonical) message bytes the verifier passed in. This
// lets the tests express behavior purely in terms of "did the verifier
// build the expected domain-separated message from (chainID, epoch, slot,
// blockHash)?" — which is the property R39-P0-01 fixes. It is a test-only
// stub; production uses wallet/tss.TSSManager (real Dilithium3).
type r39P001MockSigner struct {
	groupKey []byte
}

func (m *r39P001MockSigner) SignBlock(validatorIndex int, message []byte) ([]byte, error) {
	return append([]byte(nil), message...), nil
}
func (m *r39P001MockSigner) SignVote(validatorIndex int, message []byte) ([]byte, error) {
	return append([]byte(nil), message...), nil
}
func (m *r39P001MockSigner) VerifyBlock(pubKey []byte, message []byte, signature []byte) bool {
	_ = pubKey
	if len(message) != len(signature) {
		return false
	}
	for i := range message {
		if message[i] != signature[i] {
			return false
		}
	}
	return true
}
func (m *r39P001MockSigner) VerifyVote(pubKey []byte, message []byte, signature []byte) bool {
	return m.VerifyBlock(pubKey, message, signature)
}
func (m *r39P001MockSigner) GroupPublicKey() []byte { return append([]byte(nil), m.groupKey...) }
func (m *r39P001MockSigner) IsThresholdMode() bool  { return true }
func (m *r39P001MockSigner) AggregatePartialSignatures(sealers []int, partialSigs map[int][]byte, message []byte) ([]byte, error) {
	return append([]byte(nil), message...), nil
}

func newR39P001Finality(t *testing.T) *QTDFinalityState {
	t.Helper()
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)
	if qfs == nil {
		t.Fatal("NewQTDFinalityState returned nil")
	}
	qfs.qtdSigner = &r39P001MockSigner{groupKey: []byte{0x42}}
	return qfs
}

// TestR39_P0_01_MessageLayout_Canonical pins the exact byte layout of
// qtdSignedMessage so future refactors cannot silently change the wire
// format (which would invalidate every existing seal).
func TestR39_P0_01_MessageLayout_Canonical(t *testing.T) {
	chainID := uint64(1668)
	epoch := uint64(7)
	slot := uint64(42)
	var blockHash types.Hash
	for i := range blockHash {
		blockHash[i] = byte(i) // 0..31 sentinel
	}

	msg := qtdSignedMessage(chainID, epoch, slot, blockHash)
	if got, want := len(msg), qtdSignedMessageLen; got != want {
		t.Fatalf("message length: got %d, want %d", got, want)
	}
	if got, want := qtdSignedMessageLen, 17+8+8+8+32; got != want {
		t.Fatalf("qtdSignedMessageLen constant drift: got %d, want %d", got, want)
	}

	// [0..17): domain separator
	gotSep := string(msg[0:qtdDomainSepLen])
	if gotSep != QTDDomainSep {
		t.Errorf("domain sep: got %q, want %q", gotSep, QTDDomainSep)
	}
	if len(QTDDomainSep) != 17 {
		t.Errorf("QTDDomainSep must be exactly 17 bytes for the fixed layout; got %d", len(QTDDomainSep))
	}
	// [17..25): chainID BE
	if got := binary.BigEndian.Uint64(msg[17:25]); got != chainID {
		t.Errorf("chainID: got %d, want %d", got, chainID)
	}
	// [25..33): epoch BE
	if got := binary.BigEndian.Uint64(msg[25:33]); got != epoch {
		t.Errorf("epoch: got %d, want %d", got, epoch)
	}
	// [33..41): slot BE
	if got := binary.BigEndian.Uint64(msg[33:41]); got != slot {
		t.Errorf("slot: got %d, want %d", got, slot)
	}
	// [41..73): blockHash
	for i, b := range blockHash {
		if msg[41+i] != b {
			t.Fatalf("blockHash byte %d: got %x, want %x", i, msg[41+i], b)
		}
	}
}

// TestR39_P0_01_MessageLayout_LegacyFallback pins the chainID == 0 fallback
// used by pre-R39 nodes / tests decoupled from chain config: the message is
// the raw 32-byte blockHash copy, exactly as historical seals were signed.
func TestR39_P0_01_MessageLayout_LegacyFallback(t *testing.T) {
	var blockHash types.Hash
	for i := range blockHash {
		blockHash[i] = byte(0xFF - i)
	}
	// qtdSignedMessageOrLegacy with chainID == 0 → raw blockHash.
	got := qtdSignedMessageOrLegacy(0, 1, 2, blockHash)
	if len(got) != len(blockHash) {
		t.Fatalf("legacy message length: got %d, want %d (raw blockHash)", len(got), len(blockHash))
	}
	for i, b := range blockHash {
		if got[i] != b {
			t.Fatalf("legacy message byte %d: got %x, want %x", i, got[i], b)
		}
	}
	// Sanity: chainID > 0 produces the full 72-byte message.
	full := qtdSignedMessageOrLegacy(1668, 1, 2, blockHash)
	if len(full) != qtdSignedMessageLen {
		t.Fatalf("canonical message length: got %d, want %d", len(full), qtdSignedMessageLen)
	}
}

// TestR39_P0_01_CrossChainReplay_Rejected simulates the cross-chain seal
// replay attack: a seal signed on chain A (chainID_A, epoch, slot, blockHash)
// must NOT verify as a seal on chain B (chainID_B != chainID_A) sharing the
// same (epoch, slot, blockHash) — which is the original P0 concern.
func TestR39_P0_01_CrossChainReplay_Rejected(t *testing.T) {
	qfs := newR39P001Finality(t)
	qfs.SetChainID(1668) // chain A

	epoch := uint64(5)
	slot := uint64(100)
	var blockHash types.Hash
	for i := range blockHash {
		blockHash[i] = byte(i + 1)
	}

	// Produce a seal on chain A. With a mock signer where signature ==
	// canonical message, producing the seal is just "compute the signed
	// message under chain A".
	sealMsg := qtdSignedMessage(qfs.chainID, epoch, slot, blockHash)
	sig := append([]byte(nil), sealMsg...)

	// Verify the seal on chain A → MUST succeed.
	groupKey := []byte{0x42}
	if !qfs.qtdVerifyMessageLocked(groupKey, qfs.chainID, epoch, slot, blockHash, sig) {
		t.Fatal("seal must verify on the issuing chain (chain A)")
	}

	// Verify the SAME seal on chain B (different chainID). The
	// domain-separated message differs, so the mock signer sees a
	// different (message, signature) pair and rejects it.
	bChainID := uint64(1669)
	if qfs.qtdVerifyMessageLocked(groupKey, bChainID, epoch, slot, blockHash, sig) {
		t.Fatal("cross-chain seal replay MUST be rejected (chain A seal on chain B)")
	}
}

// TestR39_P0_01_CrossEpochReplay_Rejected simulates cross-epoch replay on the
// SAME chain: a seal for (epochA, slotA, blockHash) must NOT verify for a
// different (epochB, slotB, blockHash). This is enforced by the epoch/slot
// fields embedded in the canonical message.
func TestR39_P0_01_CrossEpochReplay_Rejected(t *testing.T) {
	qfs := newR39P001Finality(t)
	qfs.SetChainID(1668)

	epochA := uint64(3)
	slotA := uint64(50)
	var blockHash types.Hash
	for i := range blockHash {
		blockHash[i] = byte(0xA0 + i)
	}

	sealMsg := qtdSignedMessage(qfs.chainID, epochA, slotA, blockHash)
	sig := append([]byte(nil), sealMsg...)

	groupKey := []byte{0x42}
	if !qfs.qtdVerifyMessageLocked(groupKey, qfs.chainID, epochA, slotA, blockHash, sig) {
		t.Fatal("seal must verify for the originating epoch/slot")
	}
	// Same blockHash, different epoch → reject.
	if qfs.qtdVerifyMessageLocked(groupKey, qfs.chainID, epochA+1, slotA, blockHash, sig) {
		t.Fatal("cross-epoch seal replay MUST be rejected")
	}
	// Same blockHash, different slot → reject.
	if qfs.qtdVerifyMessageLocked(groupKey, qfs.chainID, epochA, slotA+1, blockHash, sig) {
		t.Fatal("cross-slot seal replay MUST be rejected")
	}
}

// TestR40_P0_01_NoPerEpochEscapeHatch pins the R40-P0-01 fix: there is NO
// per-epoch legacy-raw fallback on the chainID > 0 path. A raw-blockHash
// seal must be rejected on any node with chainID > 0 — regardless of epoch
// match — so a holder of historical group keys cannot forge finality proofs
// for current/future slots. The previous implementation's
// `allowLegacyForEpoch` tautology made all canonical signatures silently
// fall back to the raw blockHash; this test would have failed under that
// implementation.
//
// Pre-R39 records are still verifiable because they carry ChainID == 0 in
// their persisted state, which routes through the chainID == 0 branch — NOT
// through this chainID > 0 path. That property is covered separately in
// TestR39_P0_01_LegacyNode_ChainID0_RawStillWorks.
func TestR40_P0_01_NoPerEpochEscapeHatch(t *testing.T) {
	qfs := newR39P001Finality(t)
	qfs.SetChainID(1668)

	epoch := uint64(2)
	slot := uint64(40)
	var blockHash types.Hash
	for i := range blockHash {
		blockHash[i] = byte(0x50 + i)
	}

	// Legacy seal: signature == raw blockHash (what pre-R39 produced).
	legacySig := append([]byte(nil), blockHash[:]...)

	groupKey := []byte{0x42}

	// The canonical message (chainID>0 path) does NOT match the
	// raw-blockHash signature. Under the current (R40-P0-01) implementation
	// there is NO escape hatch — verification must reject.
	if qfs.qtdVerifyMessageLocked(groupKey, qfs.chainID, epoch, slot, blockHash, legacySig) {
		t.Fatal("R40-P0-01 regression: legacy raw-blockHash seal MUST be rejected when chainID > 0 (no per-epoch escape hatch)")
	}
	// Same seal under a DIFFERENT epoch must also be rejected — the epoch
	// field cannot be used to re-enable the bypass.
	if qfs.qtdVerifyMessageLocked(groupKey, qfs.chainID, epoch+1, slot, blockHash, legacySig) {
		t.Fatal("R40-P0-01 regression: legacy raw-blockHash seal MUST be rejected for any epoch when chainID > 0")
	}
}

// TestR39_P0_01_LegacyNode_ChainID0_RawStillWorks pins the "tests decoupled
// from chain config" path: a QTDFinalityState with chainID == 0 (no
// SetChainID call) continues to sign/verify over the raw blockHash, so all
// existing tests that never couple to chain config keep passing verbatim.
// This is the ONLY legitimate backward-compatibility path for pre-R39
// seals: the persisted record carries ChainID == 0, which short-circuits
// to raw-blockHash verification in qtdVerifyMessageLocked.
func TestR39_P0_01_LegacyNode_ChainID0_RawStillWorks(t *testing.T) {
	qfs := newR39P001Finality(t)
	// Intentionally do NOT call SetChainID; qfs.chainID stays 0.

	epoch := uint64(9)
	slot := uint64(72)
	var blockHash types.Hash
	for i := range blockHash {
		blockHash[i] = byte(0x70 + i)
	}

	// chainID == 0 → qtdSignedMessageOrLegacy returns raw blockHash.
	sealMsg := qtdSignedMessageOrLegacy(qfs.chainID, epoch, slot, blockHash)
	if len(sealMsg) != len(blockHash) {
		t.Fatalf("chainID==0 sign path must use raw blockHash; got len=%d", len(sealMsg))
	}
	sig := append([]byte(nil), sealMsg...)

	// qtdVerifyMessageLocked with chainID == 0 verifies over raw blockHash.
	groupKey := []byte{0x42}
	if !qfs.qtdVerifyMessageLocked(groupKey, qfs.chainID, epoch, slot, blockHash, sig) {
		t.Fatal("chainID == 0 legacy raw-blockHash verify MUST succeed (tests decoupled from chain config)")
	}
}

// TestR39_P0_01_DomainSep_StableAndUnique pins that the 16-byte ASCII
// domain separator is exactly what the audits/contract documents, and that
// it does not accidentally collide with the start of any obvious message
// in the protocol (a cheap sanity check that the value is not empty or
// trivially short).
func TestR39_P0_01_DomainSep_StableAndUnique(t *testing.T) {
	if QTDDomainSep != "QAU-QTD-BLOCKSEAL" {
		t.Fatalf("QTDDomainSep changed: %q — changing this invalidates all post-R39 seals", QTDDomainSep)
	}
	if qtdDomainSepLen != 17 {
		t.Fatalf("qtdDomainSepLen drift: %d", qtdDomainSepLen)
	}
	// Cheap uniqueness check: the separator must not be a prefix of the
	// ASCII printable range's common message starts ("0x", "{", etc.) —
	// in practice it just must not be empty or whitespace-only.
	if strings.TrimSpace(QTDDomainSep) == "" {
		t.Fatal("QTDDomainSep must not be empty / whitespace-only")
	}
}
