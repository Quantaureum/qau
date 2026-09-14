// Quantaureum Node source, version 1.0.0.
// Package consensus — tests for CONS-R12-007 (multi-validator FIFO eviction
// attack via global FIFO fallback branch).
//
// Audit finding (R12 Medium): queueSlashingEvidenceLocked had a global FIFO
// fallback branch that fired when the queue was full AND the new evidence's
// validator had no prior entries in the queue. In that case the OLDEST entry
// (any validator) was evicted to make room. An attacker controlling many
// validators could each submit one junk evidence to fill the queue, then
// continue submitting to evict honest validators' real evidence via global
// FIFO.
//
// Fix: the global FIFO fallback branch now REJECTS new evidence instead of
// evicting existing entries. Existing evidence is protected; the new entry
// is dropped (with an error log). Real slashable offenses still propagate
// via P2P gossip and are submitted directly to slashingManager when
// available — the queue is only a backup.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// makeAddrFromInt returns a deterministic, distinct types.Address for the
// given integer (used to generate many validator addresses in tests).
func makeAddrFromInt(i int) types.Address {
	var addr types.Address
	addr[0] = byte((i >> 24) & 0xFF)
	addr[1] = byte((i >> 16) & 0xFF)
	addr[2] = byte((i >> 8) & 0xFF)
	addr[3] = byte(i & 0xFF)
	if addr == (types.Address{}) {
		addr[19] = 0x01
	}
	return addr
}

// TestCONS_R12007_GlobalFIFOFallbackRejecNewValidator verifies the core
// CONS-R12-007 fix: when the queue is full and the new evidence's validator
// has no prior entries, the new evidence is REJECTED (not enqueued, no
// eviction of existing entries).
//
// Setup: pre-fill the queue to MaxEvidenceQueue with entries from distinct
// validators. Then attempt to enqueue a new entry from a fresh validator
// not already in the queue. The new entry must be rejected; the queue
// must remain unchanged.
func TestCONS_R12007_GlobalFIFOFallbackRejecNewValidator(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	// Pre-fill q.evidenceQueue to MaxEvidenceQueue with distinct validators.
	qpos.mu.Lock()
	preQueue := make([]*SlashingEvidence, 0, MaxEvidenceQueue)
	for i := 0; i < MaxEvidenceQueue; i++ {
		addr := makeAddrFromInt(i + 1)
		preQueue = append(preQueue, makeValidDoubleSignEvidence(addr, uint64(i+1)))
	}
	qpos.evidenceQueue = preQueue

	if len(qpos.evidenceQueue) != MaxEvidenceQueue {
		t.Fatalf("setup: expected queue len %d, got %d", MaxEvidenceQueue, len(qpos.evidenceQueue))
	}

	// New validator (index MaxEvidenceQueue+1, not in queue).
	freshAddr := makeAddrFromInt(MaxEvidenceQueue + 1)
	newEvidence := makeValidDoubleSignEvidence(freshAddr, 9999)

	// Capture the first entry to verify it survives.
	firstBefore := qpos.evidenceQueue[0]

	// Attempt to enqueue — should be rejected by the CONS-R12-007 fix.
	qpos.queueSlashingEvidenceLocked(newEvidence)

	// Queue length must remain unchanged (no eviction, no append).
	if got := len(qpos.evidenceQueue); got != MaxEvidenceQueue {
		t.Errorf("expected queue len unchanged at %d, got %d (CONS-R12-007: new evidence should be rejected, not appended)", MaxEvidenceQueue, got)
	}

	// The first entry must be unchanged (not evicted).
	firstAfter := qpos.evidenceQueue[0]
	if firstAfter.ValidatorAddr != firstBefore.ValidatorAddr || firstAfter.Height != firstBefore.Height {
		t.Errorf("first entry was evicted/modified: before addr=%v height=%d, after addr=%v height=%d",
			firstBefore.ValidatorAddr, firstBefore.Height, firstAfter.ValidatorAddr, firstAfter.Height)
	}

	// The fresh validator's evidence must NOT appear anywhere in the queue.
	for i, ev := range qpos.evidenceQueue {
		if ev.ValidatorAddr == freshAddr {
			t.Errorf("fresh validator evidence was enqueued at index %d (CONS-R12-007 fix should have rejected it)", i)
			break
		}
	}

	qpos.mu.Unlock()
}

// TestCONS_R12007_MultiValidatorFloodPreservesHonestEvidence verifies the
// full attack scenario described in CONS-R12-007:
//
//  1. Honest validator submits one real evidence (entry at index 0).
//  2. Attacker controls MaxEvidenceQueue-1 validators, each submits one
//     junk evidence to fill the queue.
//  3. Attacker then submits evidence from a NEW validator (not already
//     in the queue). Under the OLD global FIFO behavior, this would
//     evict the honest evidence at index 0. Under the CONS-R12-007 fix,
//     the new entry is rejected and the honest evidence survives.
func TestCONS_R12007_MultiValidatorFloodPreservesHonestEvidence(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	honestAddr := types.Address{0xAA}

	// Step 1: honest validator submits one real evidence.
	qpos.mu.Lock()
	qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(honestAddr, 100))

	// Step 2: attacker fills the rest of the queue with MaxEvidenceQueue-1
	// distinct validators (each submitting one junk evidence).
	// honestAddr is at index 0, attackers fill indices 1..MaxEvidenceQueue-1.
	for i := 0; i < MaxEvidenceQueue-1; i++ {
		attackerAddr := makeAddrFromInt(i + 1000) // distinct from honestAddr
		qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(attackerAddr, uint64(i+1)))
	}

	if len(qpos.evidenceQueue) != MaxEvidenceQueue {
		t.Fatalf("setup: expected queue len %d, got %d", MaxEvidenceQueue, len(qpos.evidenceQueue))
	}

	// Step 3: attacker submits evidence from a NEW validator (not in queue).
	// Under the OLD code: global FIFO would evict index 0 (honestAddr).
	// Under the CONS-R12-007 fix: the new entry is rejected.
	// Note: makeAddrFromInt(200000) is outside the loop range (1000..10000+998)
	// to ensure the new validator is NOT already in the queue.
	newAttackerAddr := makeAddrFromInt(200000)
	qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(newAttackerAddr, 9999))

	// Queue length must remain MaxEvidenceQueue (new entry rejected, no eviction).
	if got := len(qpos.evidenceQueue); got != MaxEvidenceQueue {
		t.Errorf("expected queue len %d (new entry rejected), got %d", MaxEvidenceQueue, got)
	}

	// Honest evidence must survive at SOME position in the queue.
	honestFound := false
	for _, ev := range qpos.evidenceQueue {
		if ev.ValidatorAddr == honestAddr && ev.Height == 100 {
			honestFound = true
			break
		}
	}
	if !honestFound {
		t.Errorf("honest evidence was evicted by multi-validator flood (CONS-R12-007 fix should preserve it)")
	}

	// The new attacker evidence must NOT be in the queue.
	for _, ev := range qpos.evidenceQueue {
		if ev.ValidatorAddr == newAttackerAddr {
			t.Errorf("new attacker evidence was enqueued (CONS-R12-007 fix should reject it)")
			break
		}
	}

	qpos.mu.Unlock()
}

// TestCONS_R12007_ValidatorScopedEvictionStillWorksAtGlobalCap verifies that
// the validator-scoped eviction path (when the new validator ALREADY has an
// entry in the queue) still works after the CONS-R12-007 fix. This is a
// regression guard: the fix only changes the behavior when the validator
// has NO prior entries.
func TestCONS_R12007_ValidatorScopedEvictionStillWorksAtGlobalCap(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	existingAddr := types.Address{0xCC}

	// Pre-fill queue to MaxEvidenceQueue with distinct validators.
	// Index 0: existingAddr (height=1).
	// Indices 1..MaxEvidenceQueue-1: distinct other validators.
	qpos.mu.Lock()
	preQueue := make([]*SlashingEvidence, 0, MaxEvidenceQueue)
	preQueue = append(preQueue, makeValidDoubleSignEvidence(existingAddr, 1))
	for i := 1; i < MaxEvidenceQueue; i++ {
		addr := makeAddrFromInt(i + 5000)
		preQueue = append(preQueue, makeValidDoubleSignEvidence(addr, uint64(i+1)))
	}
	qpos.evidenceQueue = preQueue

	if len(qpos.evidenceQueue) != MaxEvidenceQueue {
		t.Fatalf("setup: expected queue len %d, got %d", MaxEvidenceQueue, len(qpos.evidenceQueue))
	}

	// New evidence from existingAddr (already in queue at index 0).
	// Validator-scoped eviction should kick in: oldest entry from existingAddr
	// (height=1) is evicted, new entry (height=9999) is appended.
	qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(existingAddr, 9999))

	// Queue length must remain MaxEvidenceQueue (1 evicted + 1 appended).
	if got := len(qpos.evidenceQueue); got != MaxEvidenceQueue {
		t.Errorf("expected queue len %d (1 evicted + 1 appended), got %d", MaxEvidenceQueue, got)
	}

	// The OLD existingAddr entry (height=1) must be gone.
	// The NEW existingAddr entry (height=9999) must be present.
	found := false
	for _, ev := range qpos.evidenceQueue {
		if ev.ValidatorAddr == existingAddr {
			if ev.Height == 1 {
				t.Errorf("old existingAddr entry (height=1) was not evicted by validator-scoped eviction")
			}
			if ev.Height == 9999 {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("new existingAddr entry (height=9999) was not appended")
	}

	// Other validators' entries must be preserved.
	otherCount := 0
	for _, ev := range qpos.evidenceQueue {
		if ev.ValidatorAddr != existingAddr {
			otherCount++
		}
	}
	if otherCount != MaxEvidenceQueue-1 {
		t.Errorf("expected %d other-validator entries preserved, got %d", MaxEvidenceQueue-1, otherCount)
	}

	qpos.mu.Unlock()
}

// TestCONS_R12007_HonestAndAttackerEvidenceCoexist verifies that when the
// queue is full with a mix of honest and attacker evidence, additional
// evidence from BOTH is handled correctly:
//   - Additional evidence from an EXISTING validator → validator-scoped eviction
//   - Additional evidence from a NEW validator → rejected (CONS-R12-007 fix)
func TestCONS_R12007_HonestAndAttackerEvidenceCoexist(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	honestAddr := types.Address{0x11}
	attackerAddr := types.Address{0x22}

	// Pre-fill queue to MaxEvidenceQueue: 1 honest + 1 attacker + (N-2) others.
	qpos.mu.Lock()
	preQueue := make([]*SlashingEvidence, 0, MaxEvidenceQueue)
	preQueue = append(preQueue, makeValidDoubleSignEvidence(honestAddr, 1))
	preQueue = append(preQueue, makeValidDoubleSignEvidence(attackerAddr, 1))
	for i := 2; i < MaxEvidenceQueue; i++ {
		addr := makeAddrFromInt(i + 7000)
		preQueue = append(preQueue, makeValidDoubleSignEvidence(addr, uint64(i+1)))
	}
	qpos.evidenceQueue = preQueue

	if len(qpos.evidenceQueue) != MaxEvidenceQueue {
		t.Fatalf("setup: expected queue len %d, got %d", MaxEvidenceQueue, len(qpos.evidenceQueue))
	}

	// 1. Additional evidence from honestAddr (already in queue).
	// Validator-scoped eviction: oldest honestAddr entry (height=1) evicted.
	qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(honestAddr, 200))
	if got := len(qpos.evidenceQueue); got != MaxEvidenceQueue {
		t.Errorf("after honest re-submit: expected %d, got %d", MaxEvidenceQueue, got)
	}

	// 2. Additional evidence from NEW validator (not in queue).
	// CONS-R12-007 fix: rejected, no eviction.
	newAddr := types.Address{0x33}
	qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(newAddr, 300))
	if got := len(qpos.evidenceQueue); got != MaxEvidenceQueue {
		t.Errorf("after new-validator submit: expected %d (rejected), got %d", MaxEvidenceQueue, got)
	}

	// Verify: honestAddr still in queue (with height=200, the new one).
	// attackerAddr still in queue (untouched). newAddr NOT in queue.
	honestFound := false
	attackerFound := false
	newFound := false
	for _, ev := range qpos.evidenceQueue {
		switch ev.ValidatorAddr {
		case honestAddr:
			honestFound = true
			if ev.Height != 200 {
				t.Errorf("honestAddr: expected height 200 (newest), got %d", ev.Height)
			}
		case attackerAddr:
			attackerFound = true
		case newAddr:
			newFound = true
		}
	}
	if !honestFound {
		t.Errorf("honestAddr evidence was lost (should have been updated to height=200)")
	}
	if !attackerFound {
		t.Errorf("attackerAddr evidence was lost (should be preserved)")
	}
	if newFound {
		t.Errorf("newAddr evidence was enqueued (CONS-R12-007 fix should reject it)")
	}

	qpos.mu.Unlock()
}

// TestCONS_R12007_PerValidatorCapStillAppliesBeforeGlobalCap verifies that
// the per-validator cap (MaxEvidencePerValidator) is checked BEFORE the
// global cap. A validator at its per-validator cap is dropped regardless
// of global queue state.
func TestCONS_R12007_PerValidatorCapStillAppliesBeforeGlobalCap(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	addr := types.Address{0xDD}

	// Fill the per-validator cap with MaxEvidencePerValidator entries.
	qpos.mu.Lock()
	for i := 0; i < MaxEvidencePerValidator; i++ {
		qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(addr, uint64(i+1)))
	}
	currentLen := len(qpos.evidenceQueue)

	// Try to enqueue one more for the same validator.
	// Per-validator cap should reject this BEFORE reaching the global cap branch.
	qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(addr, 9999))

	// Length must be unchanged (per-validator cap rejected the new entry).
	if got := len(qpos.evidenceQueue); got != currentLen {
		t.Errorf("per-validator cap not enforced: expected %d, got %d", currentLen, got)
	}

	// Verify only MaxEvidencePerValidator entries for addr.
	count := 0
	for _, ev := range qpos.evidenceQueue {
		if ev.ValidatorAddr == addr {
			count++
		}
	}
	if count != MaxEvidencePerValidator {
		t.Errorf("expected %d entries for addr, got %d", MaxEvidencePerValidator, count)
	}

	qpos.mu.Unlock()
}

// TestCONS_R12007_RejectionDoesNotConsumeSlot verifies that when a new
// validator's evidence is rejected at global cap, the queue's internal
// state (length, contents) is fully preserved — no slots are consumed
// or corrupted by the rejection.
func TestCONS_R12007_RejectionDoesNotConsumeSlot(t *testing.T) {
	vs := createTestValidatorSetHC(3)
	qpos, _ := NewQPOS(vs)
	defer qpos.Stop()

	// Pre-fill queue to MaxEvidenceQueue with distinct validators.
	qpos.mu.Lock()
	preQueue := make([]*SlashingEvidence, 0, MaxEvidenceQueue)
	originalFirsts := make([]*SlashingEvidence, 0, 5)
	for i := 0; i < MaxEvidenceQueue; i++ {
		addr := makeAddrFromInt(i + 200)
		ev := makeValidDoubleSignEvidence(addr, uint64(i+1))
		preQueue = append(preQueue, ev)
		if i < 5 {
			originalFirsts = append(originalFirsts, ev)
		}
	}
	qpos.evidenceQueue = preQueue

	// Attempt to enqueue 10 distinct new validators — all should be rejected.
	// Note: makeAddrFromInt(300000+i) is outside the loop range (200..10000+9999)
	// to ensure newAddr is NOT already in the queue (otherwise validator-scoped
	// eviction would kick in instead of the rejection path under test).
	for i := 0; i < 10; i++ {
		newAddr := makeAddrFromInt(300000 + i)
		qpos.queueSlashingEvidenceLocked(makeValidDoubleSignEvidence(newAddr, uint64(i+1)))
	}

	// Length must be unchanged.
	if got := len(qpos.evidenceQueue); got != MaxEvidenceQueue {
		t.Errorf("after 10 rejections: expected %d, got %d", MaxEvidenceQueue, got)
	}

	// First 5 entries must be unchanged (pointers intact).
	for i, expected := range originalFirsts {
		actual := qpos.evidenceQueue[i]
		if actual != expected {
			t.Errorf("entry %d pointer modified: expected %p, got %p", i, expected, actual)
		}
		if actual.ValidatorAddr != expected.ValidatorAddr || actual.Height != expected.Height {
			t.Errorf("entry %d content modified: expected addr=%v h=%d, got addr=%v h=%d",
				i, expected.ValidatorAddr, expected.Height, actual.ValidatorAddr, actual.Height)
		}
	}

	qpos.mu.Unlock()
}
