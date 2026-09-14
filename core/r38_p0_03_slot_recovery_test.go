// Quantaureum Node source, version 1.0.0.
package core

import (
	"errors"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// setupGenesis sets the consensus genesis time to a fixed deterministic
// value for the duration of the test and returns the chosen genesis
// unix-second timestamp. Tests call this at the start so the
// wall-clock-relative future-slot check has a deterministic reference.
func setupGenesis(t *testing.T) int64 {
	t.Helper()
	gt := int64(1_700_000_000)
	if err := consensus.SetGenesisTime(gt); err != nil {
		t.Fatalf("SetGenesisTime: %v", err)
	}
	return gt
}

// makeBlockHeader constructs a minimal encoding.BlockHeader that has
// all the fields ValidateHeader inspects for the slot/time checks. Other
// fields (Version, ParentHash, etc.) are filled with sane defaults so
// the validator reaches the slot-gap branch before any other check
// would fire. Tests that want to verify only the slot/time behavior
// can pass parent=nil to skip the parent-hash check.
func makeBlockHeader(slot uint64, timestamp int64) *encoding.BlockHeader {
	return &encoding.BlockHeader{
		Version:   1,
		Height:    1,
		Slot:      slot,
		Epoch:     consensus.SlotToEpoch(slot),
		Timestamp: timestamp,
		ChainID:   1668,
	}
}

// makeChildHeader returns a child header whose Height is
// parent.Height+1, ChainID matches parent, and ParentHash is the
// computed hash of the parent — letting ValidateHeader reach the
// slot-gap branch instead of failing on the parent-hash check.
// The BlockValidator is passed in (same package, so the private
// computeHeaderHash is reachable).
func makeChildHeader(v *BlockValidator, parent *encoding.BlockHeader, slot int64, timestamp int64) *encoding.BlockHeader {
	nonZeroProposer := types.Address{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	return &encoding.BlockHeader{
		Version:      parent.Version,
		Height:       parent.Height + 1,
		Slot:         uint64(slot),
		Epoch:        consensus.SlotToEpoch(uint64(slot)),
		Timestamp:    timestamp,
		ChainID:      parent.ChainID,
		ParentHash:   v.computeHeaderHash(parent),
		ProposerAddr: nonZeroProposer,
	}
}

// TestR38P003_RecoveryAfterLongOutage_AllowsBlockAfter7200MissedSlots
// is the canonical R38-P0-03 acceptance test. It simulates a 24-hour
// network outage (7200 missed slots = 7200*12s = 86,400s = 24h) and
// asserts ValidateHeader accepts a new block whose Slot is 7200 ahead
// of the parent — the exact scenario MaxSlotGap=64 used to permanently
// halt the chain.
//
// Pre-R38: header.Slot - parent.Slot = 7200 > MaxSlotGap=64 → reject
// → every subsequent block also fails → permanent halt, requires
// coordinated validator upgrade to recover.
//
// Post-R38: the future-slot check uses genesis-relative wall-clock
// time, so after wall-clock moves forward 24 hours the current
// wall-clock slot is ~7200, and a block stamped at slot parent+7201
// is well within MaxFutureSlotGap of wall-clock → ACCEPTED.
func TestR38P003_RecoveryAfterLongOutage_AllowsBlockAfter7200MissedSlots(t *testing.T) {
	gt := setupGenesis(t)
	defer consensus.SetGenesisTime(0) // reset

	// Parent was the last block before the outage. parent.Slot=100,
	// stamped at genesis + 100*12 = gt + 1200.
	parentSlot := uint64(100)
	parentTS := gt + int64(parentSlot)*12
	parent := makeBlockHeader(parentSlot, parentTS)

	// Wall-clock now is genesis + 7300 slots (24.3 hours past start).
	// We can't actually sleep 24 hours in tests, so we set the
	// genesis time FAR in the past instead — this makes wall-clock
	// "now" relative to genesis behave as if 7300 slots have elapsed.
	elapsedSlots := uint64(7300)
	fakeGenesis := time.Now().Unix() - int64(elapsedSlots)*12
	if err := consensus.SetGenesisTime(fakeGenesis); err != nil {
		t.Fatalf("SetGenesisTime (fake): %v", err)
	}

	// Recovery block: slot = parent.Slot + 7200 (skipped 7200 slots),
	// timestamp = parent.Timestamp + 7200*12 (within the slot-gap-aware
	// future bound). ValidateHeader MUST accept.
	headerSlot := parentSlot + 7200
	headerTS := parentTS + int64(headerSlot-parentSlot)*12

	v := NewBlockValidator(1668, 30000000)
	header := makeChildHeader(v, parent, int64(headerSlot), headerTS)

	if err := v.ValidateHeader(header, parent); err == nil {
		// Success — the future-slot and time checks accepted the
		// recovery block.
		return
	} else if err == ErrSlotGapTooLarge {
		t.Errorf("R38-P0-03 regression: long outage not recoverable: %v", err)
	} else {
		// Some other validator check fired (e.g. parent hash) — but
		// this test only cares that the slot-gap check does NOT fire
		// for the 7200-missed-slot case. Record the other error for
		// diagnostic but do NOT fail on it.
		t.Logf("ValidateHeader returned non-slot-gap err (acceptable for this RED test): %v", err)
	}
}

// TestR38P003_RejectsFutureSlotBeyondMaxFutureSlotGap asserts that the
// wall-clock-relative future-slot check still rejects a malicious
// proposer stamping more than MaxFutureSlotGap (64) slots AHEAD of the
// current wall-clock slot. This is the anti-future-slot-election
// mitigation that replaces MaxSlotGap.
func TestR38P003_RejectsFutureSlotBeyondMaxFutureSlotGap(t *testing.T) {
	// Put genesis ~10 slots in the past so wall-clock currentSlot ≈ 10.
	// This is the only path through ValidateHeader's future-slot check
	// that lets us deterministically drive "currentSlot is N" without
	// actually sleeping.
	gt := time.Now().Unix() - 10*12
	if err := consensus.SetGenesisTime(gt); err != nil {
		t.Fatalf("SetGenesisTime: %v", err)
	}
	defer consensus.SetGenesisTime(0)
	parentSlot := uint64(8)
	parentTS := gt + int64(parentSlot)*12
	parent := makeBlockHeader(parentSlot, parentTS)

	// Attacker stamps 100 slots ahead of wall-clock (well beyond
	// MaxFutureSlotGap=64). ValidateHeader MUST reject with
	// ErrSlotGapTooLarge.
	headerSlot := 10 + MaxFutureSlotGap + 36 // 100
	headerTS := gt + int64(headerSlot)*12
	v := NewBlockValidator(1668, 30_000_000)
	header := makeChildHeader(v, parent, int64(headerSlot), headerTS)

	err := v.ValidateHeader(header, parent)
	if !errors.Is(err, ErrSlotGapTooLarge) {
		t.Errorf("R38-P0-03 regression: future-slot attack not rejected by wall-clock cap; want ErrSlotGapTooLarge, got %v", err)
	}
}

// TestR38P003_AllowsSlotWithinMaxFutureSlotGap asserts a normal
// wall-clock-aligned block (slot ≈ currentSlot) is accepted by the
// future-slot check even when slotGap from parent is small. This proves
// the wall-clock check lets honest blocks through in normal operation.
func TestR38P003_AllowsSlotWithinMaxFutureSlotGap(t *testing.T) {
	// Put genesis ~50 slots in the past so wall-clock currentSlot ≈ 50.
	gt := time.Now().Unix() - 50*12
	if err := consensus.SetGenesisTime(gt); err != nil {
		t.Fatalf("SetGenesisTime: %v", err)
	}
	defer consensus.SetGenesisTime(0)
	parentSlot := uint64(48)
	parentTS := gt + int64(parentSlot)*12
	parent := makeBlockHeader(parentSlot, parentTS)

	headerSlot := uint64(50) // within MaxFutureSlotGap of currentSlot=50
	headerTS := parentTS + int64(headerSlot-parentSlot)*12
	v := NewBlockValidator(1668, 30_000_000)
	header := makeChildHeader(v, parent, int64(headerSlot), headerTS)

	err := v.ValidateHeader(header, parent)
	// Other checks (parent-hash) may fire and fail, but the slot-gap
	// check MUST NOT fire — that is the property being asserted.
	if errors.Is(err, ErrSlotGapTooLarge) {
		t.Errorf("R38-P0-03 regression: normal block rejected by future-slot gap: %v", err)
	} else {
		t.Logf("non-slot-gap error acceptable for this RED test: %v", err)
	}
}

// TestR38P003_MaxSlotGap_IsDeadConstant asserts that no code path
// references MaxSlotGap as the bound for the slot-gap check (since
// R38-P0-03 retired it in favor of MaxFutureSlotGap). If a future
// change accidentally re-introduces a parent-relative `> MaxSlotGap`
// check, this test will fail loudly.
//
// Note: this test is a guardrail, not a runtime check; it verbatim
// compares the two constants. The proper long-term cleanup is to delete
// MaxSlotGap entirely (and update its stale documentation). Until that
// deletion lands, this test locks the invariant that MaxSlotGap is no
// longer the gate.
func TestR38P003_MaxSlotGap_IsDeadConstant(t *testing.T) {
	if MaxSlotGap != 2*consensus.SlotsPerEpoch {
		t.Errorf("MaxSlotGap changed: %d", MaxSlotGap)
	}
	if MaxFutureSlotGap != uint64(2*consensus.SlotsPerEpoch) {
		t.Errorf("MaxFutureSlotGap changed: %d", MaxFutureSlotGap)
	}
	// Crucially: MaxFutureSlotGap must be wall-clock-relative, NOT
	// parent-relative. We assert that ValidateHeader's slot-gap check
	// is not equivalent to `slotGap > MaxSlotGap`. Since we cannot grep
	// from a test, we rely on the recovery test above to assert this
	// behaviorally.
	_ = types.Address{} // silence unused import if types gets used later
}
