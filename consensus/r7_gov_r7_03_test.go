// Quantaureum Node source, version 1.0.0.
package consensus

// GOV-R7-03 (2026-07-17) regression tests.
//
// Audit finding (AUDIT-R7-MINISTRY-2026-07-17.md GOV-R7-03 [Medium]):
//   MinistryDefense.AddToBlacklist accepted any validatorIndex without
//   range validation. Negative or oversized indices (e.g., 999999) were
//   silently added to the blacklist map, which:
//     - Allows unbounded blacklist growth (DoS vector).
//     - Produces "false whitelist" behavior in CanPropose/CanAttest/CanSeal
//       (which look up by index) — out-of-range indices never match real
//       validators, so the entry is effectively dead but still consumes
//       memory and audit-log space.
//     - Breaks consistency between audit logs and actual blacklist state.
//
// Fix: AddToBlacklist now validates validatorIndex against the current
// validator set size at the public API boundary (before md.mu.Lock() to
// avoid establishing an md.mu → qpos.mu lock ordering). Out-of-range
// indices are rejected with an error.

import (
	"strings"
	"testing"
	"time"
)

// TestGOV_R7_03_AddToBlacklist_RejectsOutOfRangeIndex verifies that
// AddToBlacklist rejects negative and oversized validator indices.
func TestGOV_R7_03_AddToBlacklist_RejectsOutOfRangeIndex(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	md := registry.Defense()

	cases := []struct {
		name      string
		index     int
		expectErr string
	}{
		{"negative", -1, "out of range"},
		{"zero_minus_one_via_negative", -999, "out of range"},
		{"equal_to_size", 10, "out of range"},
		{"way_over_size", 999999, "out of range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := md.AddToBlacklist(testSystemCaller, tc.index, "test", time.Hour)
			if err == nil {
				t.Fatalf("AddToBlacklist(%d) should return error", tc.index)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("AddToBlacklist(%d) error should contain %q; got %v", tc.index, tc.expectErr, err)
			}
			// Blacklist must NOT contain the rejected index.
			if md.IsBlacklisted(tc.index) {
				t.Errorf("validator %d must not be blacklisted after rejection", tc.index)
			}
		})
	}
}

// TestGOV_R7_03_AddToBlacklist_AcceptsBoundaryIndices verifies that
// AddToBlacklist accepts the boundary indices 0 and size-1.
func TestGOV_R7_03_AddToBlacklist_AcceptsBoundaryIndices(t *testing.T) {
	_, registry := setupMinistryRegistry(t, 10)
	md := registry.Defense()

	for _, idx := range []int{0, 9} {
		if err := md.AddToBlacklist(testSystemCaller, idx, "boundary test", time.Hour); err != nil {
			t.Fatalf("AddToBlacklist(%d) should succeed on 10-validator set; got %v", idx, err)
		}
		if !md.IsBlacklisted(idx) {
			t.Errorf("validator %d should be blacklisted after successful AddToBlacklist", idx)
		}
	}
}

// TestGOV_R7_03_AddToBlacklist_NilQPOSRejects verifies that when the
// MinistryDefense has no qpos reference, AddToBlacklist fails closed
// (rejects) instead of accepting any index.
func TestGOV_R7_03_AddToBlacklist_NilQPOSRejects(t *testing.T) {
	md := &MinistryDefense{
		blacklist:   make(map[int]*BlacklistEntry),
		alerts:      make(map[uint64]*SecurityAlert),
		nextAlertID: 1,
		maxAlerts:   10000,
		partition:   PartitionState{},
	}
	// qpos is nil — range check must reject before mutating blacklist.
	err := md.AddToBlacklist(testSystemCaller, 0, "test", time.Hour)
	if err == nil {
		t.Fatal("AddToBlacklist should fail when qpos is nil")
	}
	if !strings.Contains(err.Error(), "qpos not initialized") {
		t.Errorf("error should mention 'qpos not initialized'; got %v", err)
	}
	if md.IsBlacklisted(0) {
		t.Error("validator 0 must not be blacklisted when qpos is nil")
	}
}
