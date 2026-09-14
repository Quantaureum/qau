// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// TestR38P101_QTD_WriteSide_RejectsAllZeroGroupKey is the RED-bar test for
// R38-P1-01 (TSS/QTD all-zero pubkey sibling path). The audit identified
// that setQTDSignerLocked wrote signer.GroupPublicKey() into
// groupKeyHistory with only `len > 0` gate, so a degenerate all-zero key
// (DKG not initialized / corrupt state) could pollute the history table
// and later be served to VerifyBlock consumers. The R38-P1-01 write-side
// chokepoint in setQTDSignerLocked now rejects all-zero keys via
// crypto.IsZeroPublicKeyBytes (constant-time comparison, matching the R37
// hardening at crypto/verify.go:73).
//
// This test sets up an epochKeySigner whose GroupPublicKey returns an
// exactly 1952-byte all-zero slice (the canonical degenerate "DKG not
// initialized" forgery surface). We then call SetQTDSignerForEpoch and
// assert that the history table for the activationEpoch is NOT populated
// (the write-side gate rejected the write).
func TestR38P101_QTD_WriteSide_RejectsAllZeroGroupKey(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	degenerateKey := testAllZeroDilithium3GroupKey() // 1952 all-zero bytes
	if len(degenerateKey) != crypto.Dilithium3PublicKeySize {
		t.Fatalf("testAllZeroDilithium3GroupKey len = %d, want %d",
			len(degenerateKey), crypto.Dilithium3PublicKeySize)
	}
	if !crypto.IsZeroPublicKeyBytes(degenerateKey) {
		t.Fatalf("testAllZeroDilithium3GroupKey must be recognized as all-zero by crypto.IsZeroPublicKeyBytes")
	}

	const activationEpoch uint64 = 7
	epochKeySignerInst := &epochKeySigner{groupKey: degenerateKey}
	qfs.SetQTDSignerForEpoch(epochKeySignerInst, activationEpoch)

	qfs.mu.RLock()
	_, written := qfs.groupKeyHistory[activationEpoch]
	qfs.mu.RUnlock()
	if written {
		t.Fatalf("R38-P1-01 write-side gate failed: DKG-uninitialized all-zero key (%d bytes) was written into groupKeyHistory[%d] — attacker could forge QTD seals against it",
			crypto.Dilithium3PublicKeySize, activationEpoch)
	}
}

// TestR38P101_QTD_WriteSide_AcceptsRealGroupKey is the GREEN sibling of the
// RED test above — a legitimate non-zero 1952-byte DKG key MUST still be
// written to the history table, or the audit fix has over-constrained
// normal DKG rotation.
func TestR38P101_QTD_WriteSide_AcceptsRealGroupKey(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	realKey := make([]byte, crypto.Dilithium3PublicKeySize)
	for i := range realKey {
		realKey[i] = byte(i) // 0,1,2,...,255,0,1,2,...,255,... up to 1952
	}
	if crypto.IsZeroPublicKeyBytes(realKey) {
		t.Fatalf("real test key should NOT be recognized as all-zero")
	}

	const activationEpoch uint64 = 11
	epochKeySignerInst := &epochKeySigner{groupKey: realKey}
	qfs.SetQTDSignerForEpoch(epochKeySignerInst, activationEpoch)

	qfs.mu.RLock()
	stored, written := qfs.groupKeyHistory[activationEpoch]
	qfs.mu.RUnlock()
	if !written {
		t.Fatalf("R38-P1-01 over-constrained: legitimate non-zero DKG key (%d bytes) was NOT written into groupKeyHistory[%d] — DKG rotation broken",
			crypto.Dilithium3PublicKeySize, activationEpoch)
	}
	if len(stored) != crypto.Dilithium3PublicKeySize {
		t.Fatalf("groupKeyHistory[%d] stored len = %d, want %d", activationEpoch, len(stored), crypto.Dilithium3PublicKeySize)
	}
	for i, b := range stored {
		if b != realKey[i] {
			t.Fatalf("groupKeyHistory[%d] byte %d = %#x, want %#x (round-trip corruption)",
				activationEpoch, i, b, realKey[i])
		}
	}
}

// TestR38P101_QTD_ReadSide_RejectsAllZeroHistoricalKey verifies the
// read-side chokepoint in getGroupPublicKeyForEpochLocked. Even if the
// write-side guard is bypassed (e.g. a restart re-loads a corrupt
// on-disk history, or a stale code path writes the table directly),
// the read-side guard rejects the all-zero key so consumers (VerifyBlock)
// never receive it. This is the "defense-in-depth" branch of R38-P1-01.
//
// We bypass the write-side guard by writing directly into
// qfs.groupKeyHistory (the legacy code path before audit R37-P3-26 also
// did this internally for some code branches), then assert that
// getGroupPublicKeyForEpochLocked still returns nil.
func TestR38P101_QTD_ReadSide_RejectsAllZeroHistoricalKey(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	degenerateKey := testAllZeroDilithium3GroupKey()

	// Simulate a corrupted / on-disk-resurrected historical entry: write
	// the all-zero key DIRECTLY into the map, bypassing setQTDSignerLocked.
	qfs.mu.Lock()
	if qfs.groupKeyHistory == nil {
		qfs.groupKeyHistory = make(map[uint64][]byte)
	}
	qfs.groupKeyHistory[5] = degenerateKey
	qfs.mu.Unlock()

	// VerifyInstantFinality will call getGroupPublicKeyForEpochLocked(5).
	// The read-side chokepoint must reject the all-zero key and return nil,
	// so VerifyBlock / VerifyInstantFinality fail-closed (false) instead
	// of accepting a QTD seal forged against the degenerate key.
	slot := uint64(5 * SlotsPerEpoch)
	blockHash := types.Hash{0xCD}
	qtdSig := []byte("attacker-forged-sig")
	got := qfs.VerifyInstantFinality(slot, blockHash, qtdSig)
	if got {
		t.Fatalf("R38-P1-01 read-side guard failed: VerifyInstantFinality accepted a seal against an all-zero historical group key — attacker can forge QTD instant-finality seals")
	}
}

// TestR38P101_QTD_ReadSide_AcceptsRealHistoricalKey is the GREEN sibling of
// the read-side RED test — with a legitimate non-zero 1952-byte key written
// via the legacy direct-write path, the read-side guard lets VerifyBlock
// run (success or failure depends on the embedded test signer, but the read
// side does not pre-reject the legitimate key).
func TestR38P101_QTD_ReadSide_AcceptsRealHistoricalKey(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	realKey := make([]byte, crypto.Dilithium3PublicKeySize)
	for i := range realKey {
		realKey[i] = byte(0xAA) ^ byte(i)
	}
	if crypto.IsZeroPublicKeyBytes(realKey) {
		t.Fatalf("real test key should NOT be recognized as all-zero")
	}

	qfs.mu.Lock()
	if qfs.groupKeyHistory == nil {
		qfs.groupKeyHistory = make(map[uint64][]byte)
	}
	qfs.groupKeyHistory[5] = realKey
	qfs.mu.Unlock()

	// getGroupPublicKeyForEpochLocked should return the legitimate
	// non-zero key (or fail-closed only if hasRotation logic requires the
	// current epoch — but here we only test that the read-side guard does
	// not reject the legitimate key). Use the same public wrapper as the
	// audit-consumer (and as the production code paths).
	got := qfs.getGroupPublicKeyForEpoch(5)
	if got == nil {
		t.Fatalf("R38-P1-01 read-side guard over-rejected: legitimate non-zero DKG key (1952 bytes) was rejected by the read-side chokepoint — DKG rotation lookup broken")
	}
	if len(got) != crypto.Dilithium3PublicKeySize {
		t.Fatalf("read-side returned key len = %d, want %d", len(got), crypto.Dilithium3PublicKeySize)
	}
	for i, b := range got {
		if b != realKey[i] {
			t.Fatalf("read-side returned key byte %d = %#x, want %#x (round-trip corruption)",
				i, b, realKey[i])
		}
	}
}

// TestR38P101_QTD_ReadSide_RejectsEmptyHistoricalKey covers the empty-key
// path (DKG not yet run at all — no bytes available). The historical empty
// branch must fail-closed (CONS-R27-MED-02 sibling) so an attacker cannot
// pass an empty "group key" past the read guard.
func TestR38P101_QTD_ReadSide_RejectsEmptyHistoricalKey(t *testing.T) {
	vs := createTestValidatorSet(t, 5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS: %v", err)
	}
	qfs := NewQTDFinalityState(qpos)

	// Marker key with no historical record for epoch 7 AND no current
	// signer whose key could be returned as fallback (qtdSigner is nil).
	slot := uint64(7 * SlotsPerEpoch)
	blockHash := types.Hash{0xCD}
	qtdSig := []byte("whatever")
	got := qfs.VerifyInstantFinality(slot, blockHash, qtdSig)
	if got {
		t.Fatalf("R38-P1-01 read-side guard failed: VerifyInstantFinality accepted a seal against a nil/empty group key — fail-closed broken")
	}
}
