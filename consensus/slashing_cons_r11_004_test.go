// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestCONS_R11004_MarkValidatorRemovedCleansSlashedOffenses verifies that
// MarkValidatorRemoved correctly deletes all slashedOffenses entries for
// the removed validator, regardless of reason/height, while preserving
// entries belonging to other validators.
//
// CONS-R11-004 (2026-07-20): The previous implementation took key[:40]
// directly to parse the address. Because types.Address implements
// fmt.Stringer (String() returns "QAU"+base32(...)), Go's %x verb
// invokes String() first and hex-encodes that string, producing 70 hex
// chars (NOT 40). Taking key[:40] sliced only PART of the hex address and
// so never matched — every entry was silently leaked. The fix matches the
// key prefix using fmt.Sprintf("%x:", addr), which is the EXACT same
// format string used to create the offenseKey at slashing.go:863, 1110.
func TestCONS_R11004_MarkValidatorRemovedCleansSlashedOffenses(t *testing.T) {
	sm := NewSlashingManager(NewValidatorManager())

	// Two distinct validator addresses.
	addr1 := types.BytesToAddress([]byte("validator-1-------")) // 20 bytes
	addr2 := types.BytesToAddress([]byte("validator-2-------")) // 20 bytes

	// Inject slashedOffenses entries using the standard offenseKey format
	// fmt.Sprintf("%x:%d:%d", addr, reason, height) — see slashing.go:863, 1110.
	keysToInsert := []string{
		fmt.Sprintf("%x:%d:%d", addr1, 1, 100), // addr1, reason=1, height=100
		fmt.Sprintf("%x:%d:%d", addr1, 2, 200), // addr1, reason=2, height=200
		fmt.Sprintf("%x:%d:%d", addr1, 3, 300), // addr1, reason=3, height=300
		fmt.Sprintf("%x:%d:%d", addr2, 1, 100), // addr2 — must be PRESERVED
		fmt.Sprintf("%x:%d:%d", addr2, 4, 400), // addr2 — must be PRESERVED
	}
	for _, k := range keysToInsert {
		sm.slashedOffenses[k] = true
	}
	if len(sm.slashedOffenses) != len(keysToInsert) {
		t.Fatalf("setup: expected %d entries, got %d", len(keysToInsert), len(sm.slashedOffenses))
	}

	// Remove addr1 — should delete all 3 addr1 entries, preserve addr2's.
	sm.MarkValidatorRemoved(addr1)

	// All addr1 entries must be gone.
	for _, k := range keysToInsert[:3] {
		if sm.slashedOffenses[k] {
			t.Errorf("addr1 entry %q should have been deleted by MarkValidatorRemoved", k)
		}
	}
	// All addr2 entries must be preserved.
	for _, k := range keysToInsert[3:] {
		if !sm.slashedOffenses[k] {
			t.Errorf("addr2 entry %q should have been preserved, but was deleted", k)
		}
	}
	if len(sm.slashedOffenses) != 2 {
		t.Errorf("expected 2 remaining entries (addr2's), got %d", len(sm.slashedOffenses))
	}
}

// TestCONS_R11004_MarkValidatorRemovedHandlesZeroAddress verifies that the
// zero address does NOT falsely match entries whose address portion failed
// to parse (e.g., malformed keys). The HasPrefix approach uses the exact
// same %x format string as production code, so a zero address produces a
// specific 70-char hex prefix that no real validator address matches.
func TestCONS_R11004_MarkValidatorRemovedHandlesZeroAddress(t *testing.T) {
	sm := NewSlashingManager(NewValidatorManager())

	// Insert a few well-formed entries for a real address.
	realAddr := types.BytesToAddress([]byte("real-validator------"))
	goodKey := fmt.Sprintf("%x:%d:%d", realAddr, 1, 100)
	sm.slashedOffenses[goodKey] = true

	// Insert a malformed key with no colon.
	malformedKey := "malformed-key-no-colon"
	sm.slashedOffenses[malformedKey] = true

	// Insert a key with a different address encoding (raw hex, not the
	// Stringer-derived format). This key will NOT match because the
	// cleanup uses fmt.Sprintf("%x:", addr) which produces 70 hex chars
	// (hex of "QAU"+base32(...)), not 40 raw hex chars.
	rawHexAddr := fmt.Sprintf("%x", realAddr[:]) // 40 raw hex chars
	badFormatKey := rawHexAddr + ":1:100"
	sm.slashedOffenses[badFormatKey] = true

	// Call MarkValidatorRemoved(zeroAddr) — must NOT delete any of the above.
	zeroAddr := types.Address{}
	sm.MarkValidatorRemoved(zeroAddr)

	if !sm.slashedOffenses[goodKey] {
		t.Error("real address entry should not have been deleted by zero-addr cleanup")
	}
	if !sm.slashedOffenses[malformedKey] {
		t.Error("malformed entry should not have been deleted (would indicate zero-addr false match)")
	}
	if !sm.slashedOffenses[badFormatKey] {
		t.Error("different-format entry should not have been deleted (would indicate zero-addr false match)")
	}
}

// TestCONS_R11004_MarkValidatorRemovedOnlyMatchesSameFormat verifies that
// the cleanup uses the EXACT same format string as the offenseKey creation
// (fmt.Sprintf("%x:%d:%d", addr, reason, height)). Entries that use a
// DIFFERENT format (e.g., 0x prefix, raw hex bytes) must NOT be deleted —
// this is correct behavior because both sides must use the same format.
//
// This test guards against future regressions where someone changes the
// offenseKey creation format without also updating the cleanup. If both
// sides use the same format string ("%x:"), they will always agree.
func TestCONS_R11004_MarkValidatorRemovedOnlyMatchesSameFormat(t *testing.T) {
	sm := NewSlashingManager(NewValidatorManager())

	addr := types.BytesToAddress([]byte("prefix-test---------"))

	// Standard production format — must be deleted.
	standardKey := fmt.Sprintf("%x:%d:%d", addr, 1, 100)
	// Hypothetical future format with "0x" prefix on the address portion.
	// This is NOT the production format and must NOT be deleted by the
	// current cleanup (which uses "%x:" without "0x"). If someone later
	// changes the offenseKey creation to use "0x%x", they MUST also
	// update the cleanup format string — that coupling is intentional.
	prefixedKey := fmt.Sprintf("0x%x:%d:%d", addr, 2, 200)
	// Yet another format: raw bytes hex (40 chars), not Stringer-derived (70 chars).
	// Also must NOT be deleted — different format.
	rawHexKey := fmt.Sprintf("%x:%d:%d", addr[:], 3, 300)

	sm.slashedOffenses[standardKey] = true
	sm.slashedOffenses[prefixedKey] = true
	sm.slashedOffenses[rawHexKey] = true

	// Remove addr — only the standard-format entry should be deleted.
	sm.MarkValidatorRemoved(addr)

	if sm.slashedOffenses[standardKey] {
		t.Errorf("standard-format entry %q should have been deleted", standardKey)
	}
	if !sm.slashedOffenses[prefixedKey] {
		t.Errorf("0x-prefixed entry %q should have been preserved (different format)", prefixedKey)
	}
	if !sm.slashedOffenses[rawHexKey] {
		t.Errorf("raw-hex entry %q should have been preserved (different format)", rawHexKey)
	}
}
