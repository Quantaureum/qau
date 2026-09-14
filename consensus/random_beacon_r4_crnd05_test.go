// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"errors"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
)

// TestR4CRND05_Finalize_HonorsDeadline verifies that Finalize honors the
// deadline per the R4-CRND-05 audit fix.
// AUDIT (2026) R4-CRND-05: Previously Finalize ignored the deadline
// entirely, so a stalled beacon (threshold never reached) would stay in
// Collect phase forever. Now it transitions to BeaconPhaseExpired after
// the deadline passes with insufficient contributions.
func TestR4CRND05_Finalize_HonorsDeadline(t *testing.T) {
	t.Run("expires_when_deadline_passes_below_threshold", func(t *testing.T) {
		// Deadline in the past, threshold=3 (no contributions submitted).
		pastDeadline := time.Now().Add(-1 * time.Hour)
		beacon := NewRandomBeaconWithDeadline(1, 3, pastDeadline)

		// Finalize should transition to Expired and return ErrBeaconExpired.
		_, err := beacon.Finalize()
		if !errors.Is(err, ErrBeaconExpired) {
			t.Fatalf("expected ErrBeaconExpired, got: %v", err)
		}
		if beacon.Phase() != BeaconPhaseExpired {
			t.Fatalf("expected Phase=Expired, got: %s", beacon.Phase())
		}
	})

	t.Run("insufficient_before_deadline_returns_insufficient", func(t *testing.T) {
		// Deadline in the future, threshold=3 (no contributions submitted).
		futureDeadline := time.Now().Add(1 * time.Hour)
		beacon := NewRandomBeaconWithDeadline(1, 3, futureDeadline)

		// Finalize should return ErrBeaconInsufficient (NOT ErrBeaconExpired).
		_, err := beacon.Finalize()
		if !errors.Is(err, ErrBeaconInsufficient) {
			t.Fatalf("expected ErrBeaconInsufficient, got: %v", err)
		}
		if beacon.Phase() != BeaconPhaseCollect {
			t.Fatalf("expected Phase=Collect (not yet expired), got: %s", beacon.Phase())
		}
	})

	t.Run("expired_beacon_rejects_contribute", func(t *testing.T) {
		pastDeadline := time.Now().Add(-1 * time.Hour)
		beacon := NewRandomBeaconWithDeadline(1, 1, pastDeadline)

		// Trigger expiration via Finalize.
		_, _ = beacon.Finalize()
		if beacon.Phase() != BeaconPhaseExpired {
			t.Fatalf("expected Phase=Expired after Finalize, got: %s", beacon.Phase())
		}

		// Generate a real key and try to Contribute — should be rejected
		// because phase is Expired (not Collect).
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("key generation failed: %v", err)
		}
		_, err = beacon.Contribute(kp.Private, kp.Public, 1)
		if !errors.Is(err, ErrBeaconInvalidPhase) {
			t.Fatalf("expected ErrBeaconInvalidPhase after expiration, got: %v", err)
		}
	})

	t.Run("expire_method_transitions_to_expired", func(t *testing.T) {
		pastDeadline := time.Now().Add(-1 * time.Hour)
		beacon := NewRandomBeaconWithDeadline(1, 1, pastDeadline)

		// Expire() should return true and transition to Expired.
		if !beacon.Expire() {
			t.Fatal("Expire() should return true when deadline has passed")
		}
		if beacon.Phase() != BeaconPhaseExpired {
			t.Fatalf("expected Phase=Expired, got: %s", beacon.Phase())
		}

		// Calling Expire() again should return false (already expired).
		if beacon.Expire() {
			t.Fatal("Expire() should return false when already expired")
		}
	})

	t.Run("expire_method_noop_before_deadline", func(t *testing.T) {
		futureDeadline := time.Now().Add(1 * time.Hour)
		beacon := NewRandomBeaconWithDeadline(1, 1, futureDeadline)

		// Expire() should return false (deadline not yet passed).
		if beacon.Expire() {
			t.Fatal("Expire() should return false before deadline")
		}
		if beacon.Phase() != BeaconPhaseCollect {
			t.Fatalf("expected Phase=Collect, got: %s", beacon.Phase())
		}
	})

	t.Run("deadline_accessor_returns_set_deadline", func(t *testing.T) {
		deadline := time.Now().Add(2 * time.Hour).Truncate(time.Second)
		beacon := NewRandomBeaconWithDeadline(1, 1, deadline)

		got := beacon.Deadline()
		if !got.Equal(deadline) {
			t.Fatalf("Deadline() = %v, want %v", got, deadline)
		}
	})

	t.Run("non_regression_finalize_succeeds_above_threshold_before_deadline", func(t *testing.T) {
		// Non-regression: a beacon with threshold=1 and 1 contribution
		// (collected via Contribute) should finalize successfully even
		// before the deadline. The deadline check only kicks in when
		// threshold is NOT met.
		futureDeadline := time.Now().Add(1 * time.Hour)
		beacon := NewRandomBeaconWithDeadline(1, 1, futureDeadline)

		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("key generation failed: %v", err)
		}
		if _, err := beacon.Contribute(kp.Private, kp.Public, 1); err != nil {
			t.Fatalf("Contribute failed: %v", err)
		}

		out, err := beacon.Finalize()
		if err != nil {
			t.Fatalf("Finalize failed (non-regression): %v", err)
		}
		if out.Phase != BeaconPhaseFinalized {
			t.Fatalf("expected Phase=Finalized, got: %s", out.Phase)
		}
	})

	t.Run("non_regression_finalize_succeeds_above_threshold_after_deadline", func(t *testing.T) {
		// Non-regression: even after the deadline, if threshold IS met,
		// Finalize should still succeed (the deadline triggers expiration
		// ONLY when threshold is not met).
		pastDeadline := time.Now().Add(-1 * time.Hour)
		beacon := NewRandomBeaconWithDeadline(1, 1, pastDeadline)

		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			t.Fatalf("key generation failed: %v", err)
		}
		if _, err := beacon.Contribute(kp.Private, kp.Public, 1); err != nil {
			t.Fatalf("Contribute failed: %v", err)
		}

		out, err := beacon.Finalize()
		if err != nil {
			t.Fatalf("Finalize failed (should succeed with threshold met even after deadline): %v", err)
		}
		if out.Phase != BeaconPhaseFinalized {
			t.Fatalf("expected Phase=Finalized, got: %s", out.Phase)
		}
	})
}
