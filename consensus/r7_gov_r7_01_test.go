// Quantaureum Node source, version 1.0.0.
package consensus

// GOV-R7-01 (2026-07-17) regression tests.
//
// Audit finding (AUDIT-R7-MINISTRY-2026-07-17.md GOV-R7-01 [Medium]):
//   ExecutiveChamber.SetDKGComplete did not validate the length of the
//   supplied group public key. While upstream callers (CompleteDKGViaDistributedRunner,
//   TriggerDKG, TransitionExecutiveForEpoch) checked for empty keys, the public
//   method itself accepted arbitrarily short non-empty keys (e.g., 1 byte).
//   A malformed key would silently propagate into the QTD threshold-signing
//   root trust anchor, potentially causing signature verification failures or
//   consensus stall.
//
// Fix: SetDKGComplete now enforces a minimum key length (minGroupPublicKeyLen=32)
// at the public API boundary and returns an error on violation. This converts
// "caller-side defensive checks" into "callee-side enforced invariant".

import (
	"strings"
	"testing"
)

// TestGOV_R7_01_SetDKGComplete_RejectsShortPublicKey verifies that
// SetDKGComplete rejects group public keys shorter than the minimum length
// (32 bytes) and leaves the chamber state unchanged.
func TestGOV_R7_01_SetDKGComplete_RejectsShortPublicKey(t *testing.T) {
	executive := NewExecutiveChamber(3, 2)
	if err := executive.SetMembers([]int{0, 1, 2}, 0); err != nil {
		t.Fatalf("SetMembers failed: %v", err)
	}

	// Chamber must be in DKGRunning state before SetDKGComplete is called.
	if executive.State() != ExecutiveDKGRunning {
		t.Fatalf("expected DKGRunning, got %s", executive.State())
	}

	// Keys shorter than minGroupPublicKeyLen (32) must be rejected.
	shortKeys := [][]byte{
		nil,
		{},
		[]byte("a"),
		[]byte("short-key"),
		make([]byte, minGroupPublicKeyLen-1),
	}
	for _, key := range shortKeys {
		err := executive.SetDKGComplete(key)
		if err == nil {
			t.Errorf("SetDKGComplete(key len=%d) should return error, got nil", len(key))
			continue
		}
		if !strings.Contains(err.Error(), "too short") {
			t.Errorf("SetDKGComplete(key len=%d) error should mention 'too short'; got %v", len(key), err)
		}
		// Chamber must remain in DKGRunning (not activated) and have no public key.
		if executive.State() != ExecutiveDKGRunning {
			t.Errorf("after rejected SetDKGComplete(key len=%d), state should remain DKGRunning; got %s", len(key), executive.State())
		}
		if pk := executive.PublicKey(); len(pk) != 0 {
			t.Errorf("after rejected SetDKGComplete(key len=%d), public key must be empty; got %x", len(key), pk)
		}
	}
}

// TestGOV_R7_01_SetDKGComplete_AcceptsMinLengthKey verifies that a key with
// exactly minGroupPublicKeyLen (32) bytes is accepted and activates the chamber.
func TestGOV_R7_01_SetDKGComplete_AcceptsMinLengthKey(t *testing.T) {
	executive := NewExecutiveChamber(3, 2)
	if err := executive.SetMembers([]int{0, 1, 2}, 0); err != nil {
		t.Fatalf("SetMembers failed: %v", err)
	}

	key := make([]byte, minGroupPublicKeyLen)
	if err := executive.SetDKGComplete(key); err != nil {
		t.Fatalf("SetDKGComplete(min-length key) should succeed; got %v", err)
	}
	if executive.State() != ExecutiveActive {
		t.Errorf("expected Active after min-length key; got %s", executive.State())
	}
	if pk := executive.PublicKey(); len(pk) != minGroupPublicKeyLen {
		t.Errorf("public key length mismatch: got %d, want %d", len(pk), minGroupPublicKeyLen)
	}
}

// TestR33_CONS_07_NewExecutiveChamber_RejectsThresholdOne verifies that
// NewExecutiveChamber enforces threshold >= 2. Previously, only threshold <= 0
// was bumped to 2; an explicit threshold=1 would pass through, creating a
// 1-of-n "threshold" that is functionally a single-signer scheme.
func TestR33_CONS_07_NewExecutiveChamber_RejectsThresholdOne(t *testing.T) {
	cases := []struct {
		name          string
		size          int
		threshold     int
		wantThreshold int
		wantSize      int
	}{
		{"T=0 bumped to 2", 5, 0, 2, 5},
		{"T=1 bumped to 2 (R33 CONS-07)", 5, 1, 2, 5},
		{"T=2 accepted", 5, 2, 2, 5},
		{"T=3 accepted", 5, 3, 3, 5},
		{"T=1 size=1 bumped to size=2 T=2", 1, 1, 2, 2},
		{"T=0 size=1 bumped to size=2 T=2", 1, 0, 2, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ec := NewExecutiveChamber(tc.size, tc.threshold)
			if ec.Size() != tc.wantSize {
				t.Errorf("size: got %d, want %d", ec.Size(), tc.wantSize)
			}
			if ec.Threshold() != tc.wantThreshold {
				t.Errorf("threshold: got %d, want %d", ec.Threshold(), tc.wantThreshold)
			}
			if ec.Threshold() < 2 {
				t.Errorf("threshold must be >= 2, got %d (R33 CONS-07 violation)", ec.Threshold())
			}
		})
	}
}
