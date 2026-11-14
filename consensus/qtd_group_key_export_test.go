// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"bytes"
	"testing"

	"github.com/quantaureum/qau/crypto"
)

// Tests for the read-only per-epoch group public key export
// (QTDFinalityState.GroupPublicKeyForEpoch, TSS-R3-B-1 P0). The export is
// the learning channel for consumers outside the seal-verification path
// (the block validator's optional v1 group-signature branch); the invariant
// under test is that ONLY keys adopted through the validated anchor custody
// chokepoints are ever reachable — a key rejected by the anchor continuity
// discipline must stay unreachable (round19 F-02 cross-protection), and the
// export must be strictly read-only.

// testExportGroupKey builds a distinguishable 1952-byte group key fixture
// (the canonical Dilithium3 public key size the anchor path requires).
func testExportGroupKey(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, crypto.Dilithium3PublicKeySize)
}

func newExportTestQTDFinality(t *testing.T) *QTDFinalityState {
	t.Helper()
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	return NewQTDFinalityState(qpos)
}

// TestQTD_GroupPublicKeyForEpoch_AnchorAdoptionExport verifies that a key
// adopted through ObserveAnchoredGroupKey (first establishment, then a
// gap-tolerant same-key continuation) is served by the export for exactly
// the epochs the anchor discipline adopted it at, and that a key REFUSED by
// the anchor continuity discipline (skip-ahead rotation without a handoff
// proof) is never reachable.
func TestQTD_GroupPublicKeyForEpoch_AnchorAdoptionExport(t *testing.T) {
	qfs := newExportTestQTDFinality(t)

	keyA := testExportGroupKey(0xAA)
	keyB := testExportGroupKey(0xBB)

	// First establishment (observer, no local signer): trust-on-first-use.
	if !qfs.ObserveAnchoredGroupKey(5, keyA, nil) {
		t.Fatal("first anchor establishment refused")
	}
	if got := qfs.GroupPublicKeyForEpoch(5); !bytes.Equal(got, keyA) {
		t.Fatalf("export(5) != anchored key (got %d bytes, want %d)", len(got), len(keyA))
	}

	// Same-key continuation with a gap (epoch 5 -> 8, no boundary blocks in
	// between): gap-tolerant idempotent continuation, adopted.
	if !qfs.ObserveAnchoredGroupKey(8, keyA, nil) {
		t.Fatal("gap-tolerant same-key continuation refused")
	}
	if got := qfs.GroupPublicKeyForEpoch(8); !bytes.Equal(got, keyA) {
		t.Fatalf("export(8) != anchored key")
	}

	// Rotation without the previous committee's handoff proof: refused at the
	// leading edge (epoch must equal maxKnown+1 AND carry a valid handoff).
	// The refused key must NOT become reachable through the export.
	if qfs.ObserveAnchoredGroupKey(9, keyB, nil) {
		t.Fatal("rotation anchor without handoff proof accepted")
	}
	if got := qfs.GroupPublicKeyForEpoch(9); len(got) != 0 {
		t.Fatalf("export(9) served key material for a refused anchor (got %d bytes, want empty)", len(got))
	}

	// Skip-ahead with a different key (breaks chained adoption outright).
	if qfs.ObserveAnchoredGroupKey(20, keyB, nil) {
		t.Fatal("skip-ahead anchor accepted")
	}
	if got := qfs.GroupPublicKeyForEpoch(20); len(got) != 0 {
		t.Fatalf("export(20) served key material for a refused skip-ahead anchor (got %d bytes, want empty)", len(got))
	}

	// A degenerate (all-zero) anchor is rejected at the write side and must
	// stay unreachable.
	if qfs.ObserveAnchoredGroupKey(21, testAllZeroDilithium3GroupKey(), nil) {
		t.Fatal("degenerate all-zero anchor accepted")
	}
	if got := qfs.GroupPublicKeyForEpoch(21); len(got) != 0 {
		t.Fatalf("export(21) served key material for a refused degenerate anchor (got %d bytes, want empty)", len(got))
	}
}

// TestQTD_GroupPublicKeyForEpoch_FirstEstablishmentMismatchRefused pins the
// R19-F02 rule for nodes that hold their own group key: a first anchor that
// does not match the local signer's key is refused, and the export answers
// with the LOCAL trust root (the signer's key), never the refused foreign key.
func TestQTD_GroupPublicKeyForEpoch_FirstEstablishmentMismatchRefused(t *testing.T) {
	qfs := newExportTestQTDFinality(t)

	localKey := testExportGroupKey(0x11)
	foreignKey := testExportGroupKey(0x22)

	qfs.SetQTDSigner(&epochKeySigner{groupKey: localKey})
	// Pin the custody table to empty: SetQTDSigner auto-recorded the live key
	// under the REAL current epoch, which is non-deterministic in this package
	// (the global genesis time is mutable by other tests) and would turn the
	// export(5) assertion below into a floor-lookup case. With an empty table
	// the export falls back to the live signer's key — exactly the
	// "current key is the only key that ever existed" regime this test pins.
	qfs.mu.Lock()
	qfs.groupKeyHistory = make(map[uint64][]byte)
	qfs.mu.Unlock()

	if qfs.ObserveAnchoredGroupKey(5, foreignKey, nil) {
		t.Fatal("mismatched first establishment accepted (R19-F02)")
	}
	// The refused foreign key must not be reachable...
	qfs.mu.RLock()
	_, present := qfs.groupKeyHistory[5]
	qfs.mu.RUnlock()
	if present {
		t.Fatal("refused anchor key leaked into the custody table")
	}
	// ...while the local trust root remains the only key ever served (empty
	// history: the current signer's key is the only key that ever existed).
	if got := qfs.GroupPublicKeyForEpoch(5); !bytes.Equal(got, localKey) {
		t.Fatalf("export(5) != local signer group key")
	}
}

// TestQTD_GroupPublicKeyForEpoch_DefensiveCopy verifies the export returns a
// copy: mutating the returned slice must not corrupt the custody table.
func TestQTD_GroupPublicKeyForEpoch_DefensiveCopy(t *testing.T) {
	qfs := newExportTestQTDFinality(t)

	keyA := testExportGroupKey(0xAA)
	if !qfs.ObserveAnchoredGroupKey(5, keyA, nil) {
		t.Fatal("first anchor establishment refused")
	}

	got := qfs.GroupPublicKeyForEpoch(5)
	if !bytes.Equal(got, keyA) {
		t.Fatal("export != anchored key")
	}
	for i := range got {
		got[i] = 0x00
	}
	if got := qfs.GroupPublicKeyForEpoch(5); !bytes.Equal(got, keyA) {
		t.Fatal("mutating the exported slice corrupted the custody table (export is not copy-safe)")
	}
}

// TestQTD_GroupPublicKeyForEpoch_FailClosed verifies the empty cases: a nil
// receiver and a fresh state with no signer and no anchors export no key
// material at all.
func TestQTD_GroupPublicKeyForEpoch_FailClosed(t *testing.T) {
	var nilQFS *QTDFinalityState
	if got := nilQFS.GroupPublicKeyForEpoch(5); len(got) != 0 {
		t.Fatalf("nil receiver exported %d bytes, want empty", len(got))
	}

	qfs := newExportTestQTDFinality(t)
	if got := qfs.GroupPublicKeyForEpoch(5); len(got) != 0 {
		t.Fatalf("fresh state without signer/history exported %d bytes, want empty (fail-closed)", len(got))
	}
}
