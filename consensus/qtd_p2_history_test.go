// Quantaureum Node source, version 1.0.0.
// Package consensus contains regression tests for the R29 P2-QTD-HISTORY
// finding.
//
// P2-QTD-HISTORY (qtd_finality.go): SetQTDSigner recorded the signer's
// GroupPublicKey in groupKeyHistory under qpos.GetCurrentEpoch(). When
// ActivateQTDInstantFinality was called at an epoch boundary (after
// TransitionExecutiveForEpoch set the executive's epoch to N+1 but
// BEFORE qpos.currentEpoch was advanced to N+1), the new DKG key was
// wrongly recorded under epoch N (where the OLD key was actually used).
// Future verification of seals from epoch N+1 then failed because
// groupKeyHistory[N+1] was empty, falling back to a newer key.
//
// The fix: ActivateQTDInstantFinality now calls SetQTDSignerForEpoch
// with executive.Epoch() as the explicit activation epoch. The legacy
// SetQTDSigner (using currentEpoch) is retained for tests/startup.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/crypto"
)

// testDilithium3GroupKey returns a 1952-byte non-zero group key suitable
// for the strict-length invariant gate added by R39-P1-01. The previous
// tests used short ASCII stub keys (e.g. "dkg-key-for-activation-epoch",
// 27 bytes), which the R39-P1-01 strict-length gate now correctly rejects
// because they don't match crypto.Dilithium3PublicKeySize. Using a real
// 1952-byte key here keeps these tests pinning the SEMANTIC behavior of
// SetQTDSignerForEpoch (recording under the right epoch, fallback paths,
// non-threshold rejection) while also respecting the cryptographic length
// invariant.
//
// The seed byte lets different tests use distinct keys so round-trip
// corruption checks remain meaningful. The returned key is non-zero in
// every byte (so crypto.IsZeroPublicKeyBytes returns false) but is NOT a
// real Dilithium3 public key — these tests verify storage/retrieval and
// epoch attribution, NOT cryptographic verification (cryptographic
// verification uses the real signer in qtd_h03_test.go and the
// r39_p0_01 tests).
func testDilithium3GroupKey(seed byte) []byte {
	key := make([]byte, crypto.Dilithium3PublicKeySize)
	for i := range key {
		// Mix the seed with the index so collisions across fixtures
		// stay nonzero and distinct without being all-zero or all-0xFF.
		key[i] = byte(((int(seed) + i*7 + 3) % 250) + 1) // 1..250, never 0
	}
	return key
}

// TestP2_QTD_HISTORY_SetQTDSignerForEpoch_RecordsUnderExplicitEpoch
// verifies that SetQTDSignerForEpoch records the GroupPublicKey under
// the EXPLICIT activationEpoch parameter, NOT under qpos.GetCurrentEpoch().
//
// Setup:
//   - Capture currentEpoch (whatever it is — other tests in the suite
//     may have called SetGenesisTime, so we cannot assume 0).
//   - Choose activationEpoch = currentEpoch + 100 (definitely different).
//   - SetQTDSignerForEpoch(signer, activationEpoch) is called.
//
// Expected:
//   - groupKeyHistory[activationEpoch] contains the key
//   - groupKeyHistory[currentEpoch] is EMPTY
func TestP2_QTD_HISTORY_SetQTDSignerForEpoch_RecordsUnderExplicitEpoch(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()

	// Capture currentEpoch (may be non-zero if prior tests set genesis time).
	currentEpoch := qpos.GetCurrentEpoch()
	activationEpoch := currentEpoch + 100 // Definitely different.
	if activationEpoch == currentEpoch {
		t.Fatalf("setup invariant violated: activationEpoch == currentEpoch == %d", currentEpoch)
	}

	qfs := qpos.GetQTDFinality()

	// Call SetQTDSignerForEpoch with the explicit activationEpoch.
	// R39-P1-01: use a 1952-byte (crypto.Dilithium3PublicKeySize) group
	// key so the strict-length gate added in R39-P1-01 accepts it.
	signerKey := testDilithium3GroupKey(0x10)
	qfs.SetQTDSignerForEpoch(&epochKeySigner{groupKey: signerKey}, activationEpoch)

	qfs.mu.RLock()
	defer qfs.mu.RUnlock()

	// groupKeyHistory[activationEpoch] must contain the key.
	pkA, okA := qfs.groupKeyHistory[activationEpoch]
	if !okA {
		t.Fatalf("P2-QTD-HISTORY REGRESSION: groupKeyHistory[%d] is empty, "+
			"but SetQTDSignerForEpoch(signer, %d) should have recorded the key "+
			"under the explicit activationEpoch", activationEpoch, activationEpoch)
	}
	if string(pkA) != string(signerKey) {
		t.Errorf("P2-QTD-HISTORY: groupKeyHistory[%d] = %q, want %q",
			activationEpoch, string(pkA), string(signerKey))
	}

	// groupKeyHistory[currentEpoch] must be EMPTY — the key was
	// activated for activationEpoch, not currentEpoch.
	if pkC, okC := qfs.groupKeyHistory[currentEpoch]; okC {
		t.Errorf("P2-QTD-HISTORY REGRESSION: groupKeyHistory[%d (currentEpoch)] = %q, "+
			"but the key should be recorded under activationEpoch=%d (not "+
			"currentEpoch=%d). This is the exact off-by-one misattribution "+
			"that P2-QTD-HISTORY fixes.",
			currentEpoch, string(pkC), activationEpoch, currentEpoch)
	}
}

// TestP2_QTD_HISTORY_LegacySetQTDSigner_UsesCurrentEpoch verifies that
// the legacy SetQTDSigner (used by tests and startup) still records the
// key under qpos.GetCurrentEpoch(). This ensures backward compatibility
// — only ActivateQTDInstantFinality should use SetQTDSignerForEpoch.
func TestP2_QTD_HISTORY_LegacySetQTDSigner_UsesCurrentEpoch(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()

	// Capture currentEpoch (may be non-zero if prior tests set genesis time).
	currentEpoch := qpos.GetCurrentEpoch()

	qfs := qpos.GetQTDFinality()

	// Legacy SetQTDSigner uses currentEpoch.
	// R39-P1-01: use a 1952-byte group key (see testDilithium3GroupKey).
	signerKey := testDilithium3GroupKey(0x20)
	qfs.SetQTDSigner(&epochKeySigner{groupKey: signerKey})

	qfs.mu.RLock()
	defer qfs.mu.RUnlock()

	pkC, okC := qfs.groupKeyHistory[currentEpoch]
	if !okC {
		t.Fatalf("P2-QTD-HISTORY: legacy SetQTDSigner should record key "+
			"under currentEpoch=%d, but groupKeyHistory[%d] is empty",
			currentEpoch, currentEpoch)
	}
	if string(pkC) != string(signerKey) {
		t.Errorf("P2-QTD-HISTORY: groupKeyHistory[%d] = %q, want %q",
			currentEpoch, string(pkC), string(signerKey))
	}
}

// TestP2_QTD_HISTORY_ActivateQTDInstantFinality_UsesExecutiveEpoch
// verifies that ActivateQTDInstantFinality records the signer's key
// under executive.Epoch() (the actual activation epoch), NOT under
// qpos.GetCurrentEpoch().
//
// This is the core regression test for the P2-QTD-HISTORY fix: it
// simulates the boundary-mismatch scenario where the executive chamber
// is set up for a future epoch but qpos.currentEpoch is still the old
// value (not yet advanced).
func TestP2_QTD_HISTORY_ActivateQTDInstantFinality_UsesExecutiveEpoch(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()
	coordinator := qpos.GetChambersCoordinator()
	if coordinator == nil {
		t.Fatal("coordinator is nil")
	}

	// Capture currentEpoch BEFORE setting up the executive chamber.
	currentEpoch := qpos.GetCurrentEpoch()
	// Choose targetEpoch = currentEpoch + 7 (definitely different —
	// simulates "TransitionExecutiveForEpoch(N+7) just ran, but
	// qpos.currentEpoch has not yet advanced").
	targetEpoch := currentEpoch + 7

	_ = coordinator.AssignExecutive([]int{0, 1, 2}, targetEpoch)
	executive := coordinator.GetExecutiveChamber()
	if executive == nil {
		t.Fatal("executive chamber is nil")
	}

	// CHAMBER-H03 FIX (R31, 2026-07-27): AssignExecutive only records the
	// epoch→members mapping in the coordinator; it does NOT call SetMembers
	// on the ExecutiveChamber itself. SetMembers is what initializes the
	// chamber's epoch field (sc.epoch) and transitions state to DKGRunning.
	// Without SetMembers, executive.Epoch() stays 0 (the zero value), and
	// SetDKGComplete transitions to ExecutiveActive without the correct epoch.
	// Call SetMembers explicitly to initialize the chamber for targetEpoch.
	if err := executive.SetMembers([]int{0, 1, 2}, targetEpoch); err != nil {
		t.Fatalf("SetMembers failed: %v", err)
	}

	// Provide a group key that satisfies the production-mode minimum
	// length (32 bytes) and complete DKG for the executive chamber.
	groupKey := make([]byte, minGroupPublicKeyLen)
	for i := range groupKey {
		groupKey[i] = byte(i + 1)
	}
	if err := executive.SetDKGComplete(groupKey); err != nil {
		t.Fatalf("SetDKGComplete failed: %v", err)
	}

	// Sanity: the executive chamber's Epoch() must report targetEpoch.
	if got := executive.Epoch(); got != targetEpoch {
		t.Fatalf("executive.Epoch() = %d, want %d (setup invariant)", got, targetEpoch)
	}

	// qpos.currentEpoch must STILL be currentEpoch (not advanced).
	if got := qpos.GetCurrentEpoch(); got != currentEpoch {
		t.Fatalf("setup invariant: qpos.currentEpoch changed from %d to %d "+
			"during executive setup (expected unchanged)", currentEpoch, got)
	}
	if currentEpoch == targetEpoch {
		t.Fatalf("setup invariant violated: currentEpoch == targetEpoch == %d", currentEpoch)
	}

	qfs := qpos.GetQTDFinality()

	// ActivateQTDInstantFinality with a signer whose GroupPublicKey
	// matches the executive chamber's key (production-mode consistency
	// check). In test mode (requireDistributedDKG=false), the check
	// is skipped, but the key is still recorded under executive.Epoch().
	signer := &epochKeySigner{groupKey: groupKey}
	if err := qfs.ActivateQTDInstantFinality(signer, DefaultQTDConfig()); err != nil {
		t.Fatalf("ActivateQTDInstantFinality failed: %v", err)
	}

	qfs.mu.RLock()
	defer qfs.mu.RUnlock()

	// groupKeyHistory[targetEpoch] (executive.Epoch()) must contain the key.
	pkT, okT := qfs.groupKeyHistory[targetEpoch]
	if !okT {
		t.Fatalf("P2-QTD-HISTORY REGRESSION: ActivateQTDInstantFinality "+
			"should record the key under executive.Epoch()=%d, but "+
			"groupKeyHistory[%d] is empty", targetEpoch, targetEpoch)
	}
	if string(pkT) != string(groupKey) {
		t.Errorf("P2-QTD-HISTORY: groupKeyHistory[%d] = %x, want %x",
			targetEpoch, pkT, groupKey)
	}

	// groupKeyHistory[currentEpoch] (qpos.currentEpoch at activation time)
	// must be EMPTY — the key was activated for targetEpoch, not currentEpoch.
	if pkC, okC := qfs.groupKeyHistory[currentEpoch]; okC {
		t.Errorf("P2-QTD-HISTORY REGRESSION: groupKeyHistory[%d (currentEpoch)] = %x, "+
			"but the key should be recorded under executive.Epoch()=%d "+
			"(NOT currentEpoch=%d). This is the off-by-one misattribution "+
			"that P2-QTD-HISTORY fixes.",
			currentEpoch, pkC, targetEpoch, currentEpoch)
	}
}

// TestP2_QTD_HISTORY_NilSigner_DoesNotRecordHistory verifies that
// SetQTDSignerForEpoch(nil, ...) does NOT record anything new in
// groupKeyHistory (the deactivation path has no key to record), but
// also does NOT erase existing historical entries (future verification
// of seals from past epochs still needs the old key).
func TestP2_QTD_HISTORY_NilSigner_DoesNotRecordHistory(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()

	qfs := qpos.GetQTDFinality()

	// First, set a non-nil signer to populate groupKeyHistory[5].
	// R39-P1-01: use a 1952-byte group key (see testDilithium3GroupKey).
	qfs.SetQTDSignerForEpoch(&epochKeySigner{groupKey: testDilithium3GroupKey(0x30)}, 5)

	// Now deactivate with nil signer — groupKeyHistory[5] must remain
	// (deactivation must NOT erase historical entries, as future
	// verification of seals from epoch 5 still needs the old key).
	qfs.SetQTDSignerForEpoch(nil, 999)

	qfs.mu.RLock()
	defer qfs.mu.RUnlock()

	// groupKeyHistory[5] must still be present (deactivation doesn't
	// erase history).
	pk5, ok5 := qfs.groupKeyHistory[5]
	if !ok5 {
		t.Fatal("P2-QTD-HISTORY: SetQTDSignerForEpoch(nil) must not " +
			"erase existing groupKeyHistory[5], but it was deleted")
	}
	// R39-P1-01: the previous version hardcoded a string literal here
	// ("key-5"); with the strict-length write gate the test uses a real
	// 1952-byte key, so compare against the same fixture used for the
	// write above.
	want5 := testDilithium3GroupKey(0x30)
	if string(pk5) != string(want5) {
		t.Errorf("P2-QTD-HISTORY: groupKeyHistory[5] round-trip mismatch (R39-P1-01 fixture)")
	}

	// groupKeyHistory[999] must be EMPTY (nil signer has no key to record).
	if _, ok999 := qfs.groupKeyHistory[999]; ok999 {
		t.Error("P2-QTD-HISTORY: SetQTDSignerForEpoch(nil, 999) must not " +
			"record anything in groupKeyHistory[999], but an entry exists")
	}
}

// TestP2_QTD_HISTORY_NonThresholdSigner_DoesNotRecordHistory verifies
// that SetQTDSignerForEpoch with a non-threshold-mode signer does NOT
// record anything in groupKeyHistory. Non-threshold signers are
// rejected by QTD-H01 in setQTDSignerLocked (early return before the
// history-recording block), so the existing history is preserved.
func TestP2_QTD_HISTORY_NonThresholdSigner_DoesNotRecordHistory(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	qpos.InitChambers()

	qfs := qpos.GetQTDFinality()

	// First, populate groupKeyHistory[5] via a valid threshold signer.
	// R39-P1-01: use a 1952-byte group key (see testDilithium3GroupKey).
	qfs.SetQTDSignerForEpoch(&epochKeySigner{groupKey: testDilithium3GroupKey(0x40)}, 5)

	// Now attempt to set a non-threshold signer for epoch 7 — must be
	// rejected by QTD-H01 (early return, no state mutation).
	qfs.SetQTDSignerForEpoch(&nonThresholdSigner{}, 7)

	qfs.mu.RLock()
	defer qfs.mu.RUnlock()

	// groupKeyHistory[5] must still be present (rejection doesn't erase).
	pk5, ok5 := qfs.groupKeyHistory[5]
	if !ok5 {
		t.Fatal("P2-QTD-HISTORY: QTD-H01 rejection must not erase " +
			"existing groupKeyHistory[5], but it was deleted")
	}
	// R39-P1-01: same fixture as the write above (see testDilithium3GroupKey).
	want5 := testDilithium3GroupKey(0x40)
	if string(pk5) != string(want5) {
		t.Errorf("P2-QTD-HISTORY: groupKeyHistory[5] round-trip mismatch (R39-P1-01 fixture)")
	}

	// groupKeyHistory[7] must be EMPTY (non-threshold signer rejected).
	if _, ok7 := qfs.groupKeyHistory[7]; ok7 {
		t.Error("P2-QTD-HISTORY: non-threshold signer must not record " +
			"anything in groupKeyHistory[7], but an entry exists")
	}
}
