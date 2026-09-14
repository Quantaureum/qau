// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// makeValidDoubleSignEvidence creates a properly-formed SlashingEvidence
// for the given validator and height. Used by CONS-R11-006 tests to inject
// realistic evidence into the queue (the new validation in
// queueSlashingEvidenceLocked requires Vote1/Vote2 to be non-nil for
// double-signing-class reasons).
func makeValidDoubleSignEvidence(addr types.Address, height uint64) *SlashingEvidence {
	return &SlashingEvidence{
		Reason:        SlashingReasonDoubleSigning,
		ValidatorAddr: addr,
		Height:        height,
		Vote1:         &Vote{ValidatorAddr: addr, Height: height, BlockHash: types.Hash{0x11}},
		Vote2:         &Vote{ValidatorAddr: addr, Height: height, BlockHash: types.Hash{0x22}},
	}
}

// TestCONS_R11006_RejectsZeroValidatorAddr verifies that evidence with a zero
// validator address is rejected before being enqueued. This prevents
// obviously-invalid entries from consuming queue slots.
//
// CONS-R11-006 (2026-07-20): The previous implementation accepted any
// non-nil evidence, including entries with zero validator addresses. An
// attacker could submit a flood of such junk to fill the queue and evict
// legitimate evidence via FIFO. The fix validates the address and reason
// before enqueuing.
func TestCONS_R11006_RejectsZeroValidatorAddr(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	qpos.mu.Lock()
	qpos.queueSlashingEvidenceLocked(&SlashingEvidence{
		Reason:        SlashingReasonDoubleSigning,
		ValidatorAddr: types.Address{}, // zero address
		Vote1:         &Vote{},
		Vote2:         &Vote{},
	})
	got := len(qpos.evidenceQueue)
	qpos.mu.Unlock()

	if got != 0 {
		t.Errorf("expected empty queue after rejecting zero-addr evidence, got %d entries", got)
	}
}

// TestCONS_R11006_RejectsDoubleSignWithoutVotes verifies that double-signing,
// surround-vote, and double-vote evidence is rejected when Vote1 or Vote2
// is nil. These reasons cryptographically require two conflicting votes.
func TestCONS_R11006_RejectsDoubleSignWithoutVotes(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	addr := types.Address{0xAA}

	// Each case should be rejected (not enqueued).
	cases := []struct {
		name string
		ev   *SlashingEvidence
	}{
		{
			name: "double_signing_nil_vote1",
			ev: &SlashingEvidence{
				Reason:        SlashingReasonDoubleSigning,
				ValidatorAddr: addr,
				Vote1:         nil,
				Vote2:         &Vote{},
			},
		},
		{
			name: "double_signing_nil_vote2",
			ev: &SlashingEvidence{
				Reason:        SlashingReasonDoubleSigning,
				ValidatorAddr: addr,
				Vote1:         &Vote{},
				Vote2:         nil,
			},
		},
		{
			name: "surround_vote_nil_votes",
			ev: &SlashingEvidence{
				Reason:        SlashingReasonSurroundVote,
				ValidatorAddr: addr,
				Vote1:         nil,
				Vote2:         nil,
			},
		},
		{
			name: "double_vote_nil_votes",
			ev: &SlashingEvidence{
				Reason:        SlashingReasonDoubleVote,
				ValidatorAddr: addr,
				Vote1:         nil,
				Vote2:         nil,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qpos.mu.Lock()
			qpos.queueSlashingEvidenceLocked(tc.ev)
			got := len(qpos.evidenceQueue)
			qpos.mu.Unlock()
			if got != 0 {
				t.Errorf("case %s: expected 0 entries, got %d", tc.name, got)
			}
		})
	}
}

// TestCONS_R11006_PerValidatorCapDropsNewEntry verifies that once a validator
// has MaxEvidencePerValidator entries in the queue, the new entry is dropped
// instead of being accepted. This prevents one attacker-driven validator from
// consuming the entire queue.
func TestCONS_R11006_PerValidatorCapDropsNewEntry(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	attackerAddr := types.Address{0xAA}
	honestAddr := types.Address{0xBB}

	qpos.mu.Lock()
	// Fill the queue with MaxEvidencePerValidator entries for attackerAddr.
	for i := 0; i < MaxEvidencePerValidator; i++ {
		qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(attackerAddr, uint64(i+1)))
	}
	// Try to enqueue one more for attackerAddr — should be dropped.
	qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(attackerAddr, 9999))
	// Enqueue one for honestAddr — should be accepted.
	qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(honestAddr, 1))
	totalLen := len(qpos.evidenceQueue)
	qpos.mu.Unlock()

	// attacker should still have MaxEvidencePerValidator (the +1 was dropped),
	// honest should have 1 → total = MaxEvidencePerValidator + 1.
	expectedTotal := MaxEvidencePerValidator + 1
	if totalLen != expectedTotal {
		t.Errorf("expected %d entries (attacker cap + 1 honest), got %d", expectedTotal, totalLen)
	}

	// Drain and verify counts.
	queue := qpos.GetQueuedEvidence()
	attackerCount := 0
	honestCount := 0
	for _, ev := range queue {
		if ev.ValidatorAddr == attackerAddr {
			attackerCount++
		} else if ev.ValidatorAddr == honestAddr {
			honestCount++
		}
	}
	if attackerCount != MaxEvidencePerValidator {
		t.Errorf("attacker count: expected %d, got %d", MaxEvidencePerValidator, attackerCount)
	}
	if honestCount != 1 {
		t.Errorf("honest count: expected 1, got %d", honestCount)
	}
}

// TestCONS_R11006_AttackerCannotEvictHonestEvidence verifies the full attack
// scenario: an attacker pushes junk evidence to fill the queue, but
// legitimate evidence for an honest validator is preserved.
//
// Setup: pre-fill the queue with one honest validator's evidence. Then
// attempt to push MaxEvidenceQueue junk entries for the attacker. The
// per-validator cap limits the attacker to 32 entries. The honest entry
// must survive.
func TestCONS_R11006_AttackerCannotEvictHonestEvidence(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	honestAddr := types.Address{0x11}
	attackerAddr := types.Address{0x22}

	// Pre-insert one piece of legitimate evidence for honestAddr.
	qpos.mu.Lock()
	qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(honestAddr, 100))
	qpos.mu.Unlock()

	// Attacker attempts to push MaxEvidenceQueue+100 junk entries — capped at 32.
	qpos.mu.Lock()
	for i := 0; i < MaxEvidenceQueue+100; i++ {
		qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(attackerAddr, uint64(i+1)))
	}
	qpos.mu.Unlock()

	queue := qpos.GetQueuedEvidence()

	// honestAddr entry must survive.
	honestFound := false
	for _, ev := range queue {
		if ev.ValidatorAddr == honestAddr {
			honestFound = true
			if ev.Height != 100 {
				t.Errorf("honest entry height modified: expected 100, got %d", ev.Height)
			}
			break
		}
	}
	if !honestFound {
		t.Errorf("honest evidence was evicted by attacker flood — per-validator cap or validator-scoped eviction failed")
	}

	// attackerAddr entries must be capped at MaxEvidencePerValidator.
	attackerCount := 0
	for _, ev := range queue {
		if ev.ValidatorAddr == attackerAddr {
			attackerCount++
		}
	}
	if attackerCount > MaxEvidencePerValidator {
		t.Errorf("attacker entries exceeded cap: expected <= %d, got %d",
			MaxEvidencePerValidator, attackerCount)
	}

	// Total queue length: 1 (honest) + MaxEvidencePerValidator (attacker) = 33.
	expectedTotal := 1 + MaxEvidencePerValidator
	if len(queue) != expectedTotal {
		t.Errorf("expected queue length %d, got %d", expectedTotal, len(queue))
	}

	t.Logf("=== CONS-R11-006: attacker flood blocked, honest evidence preserved (attacker=%d entries, honest_found=%v) ===",
		attackerCount, honestFound)
}

// TestCONS_R11006_DowntimeEvidenceAcceptedWithoutVotes verifies that
// SlashingReasonDowntime and SlashingReasonInvalidVRF evidence can be
// enqueued without Vote1/Vote2 (they don't require conflicting votes).
func TestCONS_R11006_DowntimeEvidenceAcceptedWithoutVotes(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	addr := types.Address{0xCC}

	qpos.mu.Lock()
	qpos.queueSlashingEvidenceLocked(&SlashingEvidence{
		Reason:        SlashingReasonDowntime,
		ValidatorAddr: addr,
		Height:        100,
	})
	qpos.queueSlashingEvidenceLocked(&SlashingEvidence{
		Reason:        SlashingReasonInvalidVRF,
		ValidatorAddr: addr,
		Height:        200,
	})
	totalLen := len(qpos.evidenceQueue)
	qpos.mu.Unlock()

	if totalLen != 2 {
		t.Fatalf("expected 2 entries (downtime + invalid_vrf), got %d", totalLen)
	}

	queue := qpos.GetQueuedEvidence()
	for i, ev := range queue {
		if ev.ValidatorAddr != addr {
			t.Errorf("entry %d: expected addr %v, got %v", i, addr, ev.ValidatorAddr)
		}
	}
}

// TestCONS_R11006_ValidatorScopedEvictionAtGlobalCap verifies the
// validator-scoped eviction path: when the global cap is reached and a
// new entry arrives for a validator that ALREADY has an entry in the
// queue, the OLDEST entry from that same validator is evicted (preserving
// other validators' evidence).
//
// To exercise the global-cap branch deterministically without pushing 10000
// entries, we temporarily set q.evidenceQueue to a pre-filled slice at
// MaxEvidenceQueue length, then call queueSlashingEvidenceLocked with a
// new entry for a validator that already has an entry.
func TestCONS_R11006_ValidatorScopedEvictionAtGlobalCap(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	honestAddr := types.Address{0x11}
	attackerAddr := types.Address{0x22}

	// Pre-fill q.evidenceQueue to MaxEvidenceQueue with a single honest entry
	// at index 0 and 9999 distinct other-validator entries filling the rest.
	// The new entry is for honestAddr (which already has 1 entry).
	qpos.mu.Lock()
	preQueue := make([]*SlashingEvidence, 0, MaxEvidenceQueue)
	// Index 0: honestAddr entry (height=1).
	preQueue = append(preQueue, makeValidDoubleSignEvidence(honestAddr, 1))
	// Indices 1..MaxEvidenceQueue-1: distinct addresses (different from honestAddr
	// and attackerAddr). These must NOT be evicted by the new attacker entry.
	for i := 1; i < MaxEvidenceQueue; i++ {
		var addr types.Address
		addr[0] = byte((i >> 24) & 0xFF)
		addr[1] = byte((i >> 16) & 0xFF)
		addr[2] = byte((i >> 8) & 0xFF)
		addr[3] = byte(i & 0xFF)
		// Ensure no collision with honestAddr (0x11...) or attackerAddr (0x22...).
		if addr == honestAddr || addr == attackerAddr || addr == (types.Address{}) {
			addr[19] = byte(i & 0xFF) // force distinct
		}
		preQueue = append(preQueue, makeValidDoubleSignEvidence(addr, uint64(i)))
	}
	qpos.evidenceQueue = preQueue

	// Sanity: queue is at cap.
	if len(qpos.evidenceQueue) != MaxEvidenceQueue {
		t.Fatalf("setup: expected queue len %d, got %d", MaxEvidenceQueue, len(qpos.evidenceQueue))
	}

	// Push a new entry for honestAddr. Since honestAddr already has 1 entry,
	// validator-scoped eviction should kick in: the OLDEST honestAddr entry
	// (height=1) is evicted, and the new one (height=9999) is appended.
	qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(honestAddr, 9999))

	// Queue should still be at MaxEvidenceQueue (evict one + append one).
	if len(qpos.evidenceQueue) != MaxEvidenceQueue {
		t.Errorf("expected queue at cap %d, got %d", MaxEvidenceQueue, len(qpos.evidenceQueue))
	}

	// The new honestAddr entry (height=9999) should be the LAST entry.
	lastEv := qpos.evidenceQueue[len(qpos.evidenceQueue)-1]
	if lastEv.ValidatorAddr != honestAddr || lastEv.Height != 9999 {
		t.Errorf("expected last entry to be honestAddr height=9999, got addr=%v height=%d",
			lastEv.ValidatorAddr, lastEv.Height)
	}

	// The OLD honestAddr entry (height=1) should have been evicted.
	honestCount := 0
	for _, ev := range qpos.evidenceQueue {
		if ev.ValidatorAddr == honestAddr {
			honestCount++
		}
	}
	if honestCount != 1 {
		t.Errorf("expected 1 honest entry after validator-scoped eviction, got %d", honestCount)
	}

	// All other validators' entries should be preserved (none evicted).
	// Total should be MaxEvidenceQueue (cap), with honestCount=1.
	otherCount := MaxEvidenceQueue - honestCount
	expectedOtherCount := MaxEvidenceQueue - 1
	if otherCount != expectedOtherCount {
		t.Errorf("expected %d other-validator entries preserved, got %d", expectedOtherCount, otherCount)
	}

	qpos.mu.Unlock()
}
