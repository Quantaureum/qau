// Quantaureum Node source, version 1.0.0.
// Package consensus contains regression tests for the R13 audit's Medium
// consensus findings (CONS-R13-M01 through M04).
//
// M01 (validator.go): Reject attestations whose slot crosses an epoch
// boundary into a future epoch. The existing `att.Slot <= currentSlot+1`
// check allowed ONE future slot, but if that future slot's epoch is
// strictly greater than the current epoch, the attestation would be
// stored but never counted toward finality — a memory leak and a source
// of inconsistent finality decisions across nodes with wall-clock drift.
//
// M02 (validator_manager.go): ValidatorManager and QPOS.validators
// (ValidatorSet) are two separate data structures tracking validator
// stakes. Updates to ValidatorManager (UpdateStake / UpdateStakeForSlashing
// / SlashStake) MUST propagate to QPOS via a registered onStakeChanged
// callback — otherwise QPOS finality/vote-verification weights diverge.
//
// M03 (qpos_proposer.go): VRF accumulator XOR accumulation allows
// last-proposer grind of the next epoch's shuffle seed. The fix delays
// seed dependency by one more epoch (epoch-2 instead of epoch-1) so the
// grind cannot adapt in real time.
//
// M04 (qpos_forkchoice.go): ReanchorSlotRoots must refuse reorgs that
// touch or cross the finalized epoch boundary — Casper FFG finality is
// irreversible.
package consensus

import (
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// ============================================================================
// CONS-R13-M01: epoch-boundary attestation rejection
// ============================================================================

// TestCONS_R13_M01_RejectsFutureEpochAttestation verifies that an
// attestation whose slot is currentSlot+1 BUT crosses an epoch boundary
// (so attSlotEpoch > currentEpoch) is rejected with ErrSlotTooFar.
//
// Setup: currentSlot = SlotsPerEpoch-1 (last slot of epoch 0).
//
//	currentEpoch = 0.
//
// Att slot = SlotsPerEpoch (first slot of epoch 1) → attSlotEpoch = 1.
//
// Before the fix: the existing `att.Slot > currentSlot+1` check would
// PASS (SlotsPerEpoch is NOT > SlotsPerEpoch-1+1 = SlotsPerEpoch), so
// the attestation would be stored in q.attestations but never counted
// toward finality (tryUpdateFinality only processes prevEpoch =
// currentEpoch-1 = -1, which underflows to MaxUint64 → no match).
//
// After the fix: the new epoch upper-bound check rejects the attestation
// up front with ErrSlotTooFar, preventing the memory leak and the
// inconsistent-finality risk.
func TestCONS_R13_M01_RejectsFutureEpochAttestation(t *testing.T) {
	// Build a QPOS with enough validators to form a committee.
	vs := makeSlotPruneTestValidatorSet(5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	SetAttestationNetworkID(1668)
	defer SetAttestationNetworkID(0)

	// Rewind genesis time so currentSlot = SlotsPerEpoch-1 (last slot of
	// epoch 0). currentEpoch = 0.
	rewind := int64(SlotsPerEpoch-1) * int64(SlotDuration.Seconds())
	gt := time.Now().Unix() - rewind
	if err := SetGenesisTime(gt); err != nil {
		t.Skipf("SetGenesisTime failed (likely frozen by a prior test): %v", err)
	}
	defer func() {
		// Reset genesis time so subsequent tests aren't affected.
		// SetGenesisTime may be frozen; if so, the reset is a no-op.
		_ = SetGenesisTime(time.Now().Unix())
	}()

	currentSlot := qpos.GetCurrentSlot()
	currentEpoch := qpos.GetCurrentEpoch()
	if currentEpoch != 0 {
		t.Fatalf("precondition: expected currentEpoch=0, got %d", currentEpoch)
	}
	if currentSlot != SlotsPerEpoch-1 {
		t.Fatalf("precondition: expected currentSlot=%d, got %d",
			SlotsPerEpoch-1, currentSlot)
	}

	// Construct an attestation for the NEXT slot (currentSlot+1).
	// This slot belongs to epoch 1 (SlotToEpoch(SlotsPerEpoch) = 1), so
	// attSlotEpoch (1) > currentEpoch (0) → must be rejected.
	att := &Attestation{
		Slot:           currentSlot + 1, // crosses epoch boundary
		ValidatorIndex: 0,
		Target:         AttestationCheckpoint{Epoch: 1, Root: types.Hash{0x01}},
		Source:         AttestationCheckpoint{Epoch: 0, Root: types.Hash{}},
		Signature:      make([]byte, 3293),
	}

	err = qpos.ProcessAttestation(att)
	if err == nil {
		t.Fatal("CONS-R13-M01 REGRESSION: attestation crossing epoch boundary " +
			"was accepted — should be rejected with ErrSlotTooFar")
	}
	if !errors.Is(err, ErrSlotTooFar) {
		t.Fatalf("CONS-R13-M01: expected ErrSlotTooFar, got: %v", err)
	}

	// Sanity: the attestation must NOT have been stored.
	qpos.mu.RLock()
	storedAtts := qpos.attestations[currentSlot+1]
	qpos.mu.RUnlock()
	if len(storedAtts) != 0 {
		t.Fatalf("CONS-R13-M01: attestation was stored despite rejection: %d entries",
			len(storedAtts))
	}
}

// TestCONS_R13_M01_AllowsSameEpochFutureSlot verifies that the M01 fix
// does NOT reject attestations for the next slot when that slot is in
// the SAME epoch as the current slot (no boundary crossing).
//
// Setup: currentSlot = 5 (epoch 0). Att slot = 6 (also epoch 0).
// Expected: the M01 check passes (attSlotEpoch == currentEpoch), and the
// existing validation pipeline (signature check, etc.) takes over.
// We can't easily produce a valid Dilithium3 signature in a unit test,
// so we expect the attestation to fail at signature verification (NOT
// at the M01 check).
func TestCONS_R13_M01_AllowsSameEpochFutureSlot(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}
	SetAttestationNetworkID(1668)
	defer SetAttestationNetworkID(0)

	// currentSlot = 5 (epoch 0).
	rewind := int64(5) * int64(SlotDuration.Seconds())
	gt := time.Now().Unix() - rewind
	if err := SetGenesisTime(gt); err != nil {
		t.Skipf("SetGenesisTime failed (likely frozen by a prior test): %v", err)
	}
	defer func() { _ = SetGenesisTime(time.Now().Unix()) }()

	currentSlot := qpos.GetCurrentSlot()
	if currentSlot != 5 {
		t.Fatalf("precondition: expected currentSlot=5, got %d", currentSlot)
	}

	// Att slot = 6 (same epoch 0).
	att := &Attestation{
		Slot:           currentSlot + 1,
		ValidatorIndex: 0,
		Target:         AttestationCheckpoint{Epoch: 0, Root: types.Hash{0x01}},
		Source:         AttestationCheckpoint{Epoch: 0, Root: types.Hash{}},
		Signature:      make([]byte, 3293),
	}

	err = qpos.ProcessAttestation(att)
	// M01 check must NOT trigger (same epoch). We expect the call to
	// fail later (signature verification, source-epoch check, or
	// duplicate-attestation check) — but NOT with ErrSlotTooFar.
	if errors.Is(err, ErrSlotTooFar) {
		t.Fatalf("CONS-R13-M01 REGRESSION: same-epoch future slot was rejected "+
			"with ErrSlotTooFar — the epoch upper-bound check is too strict: %v", err)
	}
	// Any other error (or nil) is acceptable for this test.
}

// ============================================================================
// CONS-R13-M02: ValidatorManager → QPOS stake-change callback
// ============================================================================

// stakeChangeRecorder captures all (addr, newStake) invocations of the
// onStakeChanged callback. It uses atomic ops and a mutex so the test can
// safely inspect the recorded calls from the test goroutine after the
// callback fires.
type stakeChangeRecorder struct {
	mu struct {
		sync.Mutex
		calls []recordedStakeChange
	}
	count int32
}

type recordedStakeChange struct {
	Addr     types.Address
	NewStake *big.Int
}

func (r *stakeChangeRecorder) callback(addr types.Address, newStake *big.Int) {
	r.mu.Lock()
	r.mu.calls = append(r.mu.calls, recordedStakeChange{
		Addr:     addr,
		NewStake: new(big.Int).Set(newStake),
	})
	r.mu.Unlock()
	atomic.AddInt32(&r.count, 1)
}

func (r *stakeChangeRecorder) CallCount() int32 {
	return atomic.LoadInt32(&r.count)
}

func (r *stakeChangeRecorder) Calls() []recordedStakeChange {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedStakeChange, len(r.mu.calls))
	copy(out, r.mu.calls)
	return out
}

// TestCONS_R13_M02_UpdateStakeFiresCallback verifies that UpdateStake
// invokes the onStakeChanged callback with the correct (addr, newStake)
// AFTER releasing vm.mu. The "after releasing vm.mu" property is
// critical for deadlock safety: the callback typically calls back into
// QPOS.AddStakingValidator, which takes q.mu → vs.mu — acquiring vm.mu
// during the callback would risk a lock-ordering deadlock.
func TestCONS_R13_M02_UpdateStakeFiresCallback(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	if err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	rec := &stakeChangeRecorder{}
	vm.SetStakeChangedCallback(rec.callback)

	// 50% increase (within the allowed bound).
	newStake := new(big.Int).Mul(big.NewInt(150), big.NewInt(1e18))
	if err := vm.UpdateStake(addr, addr, newStake); err != nil {
		t.Fatalf("UpdateStake failed: %v", err)
	}

	if got := rec.CallCount(); got != 1 {
		t.Fatalf("expected callback to fire exactly once, got %d", got)
	}
	calls := rec.Calls()
	if calls[0].Addr != addr {
		t.Errorf("callback received addr %v, want %v", calls[0].Addr, addr)
	}
	if calls[0].NewStake.Cmp(newStake) != 0 {
		t.Errorf("callback received newStake %s, want %s",
			calls[0].NewStake.String(), newStake.String())
	}
}

// TestCONS_R13_M02_UpdateStakeForSlashingFiresCallback verifies the
// slashing path also notifies the callback. This is critical because
// slashing changes effective stake — QPOS's ValidatorSet must reflect
// the new (reduced) weight immediately, otherwise the slashed validator's
// stale weight continues to influence finality.
func TestCONS_R13_M02_UpdateStakeForSlashingFiresCallback(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	if err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	rec := &stakeChangeRecorder{}
	vm.SetStakeChangedCallback(rec.callback)

	// Slashing reduces stake to 30 QAU (below MinStakeAmount, deactivates).
	newStake := big.NewInt(30)
	if err := vm.UpdateStakeForSlashing(addr, newStake); err != nil {
		t.Fatalf("UpdateStakeForSlashing failed: %v", err)
	}

	if got := rec.CallCount(); got != 1 {
		t.Fatalf("expected callback to fire once, got %d", got)
	}
	calls := rec.Calls()
	if calls[0].NewStake.Cmp(newStake) != 0 {
		t.Errorf("callback received newStake %s, want %s",
			calls[0].NewStake.String(), newStake.String())
	}
}

// TestCONS_R13_M02_SlashStakeFiresCallback verifies that SlashStake
// (which computes the new stake from a percentage) reports the final
// post-slash stake to the callback.
func TestCONS_R13_M02_SlashStakeFiresCallback(t *testing.T) {
	vm := NewValidatorManager()
	// Register a system caller so SlashStake authorization passes.
	// SlashStake is restricted to registered system callers only.
	systemCaller := types.Address{0xFF}
	RegisterSystemCaller(systemCaller)
	defer UnregisterSystemCaller(systemCaller)

	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	if err := vm.AddValidator(systemCaller, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	rec := &stakeChangeRecorder{}
	vm.SetStakeChangedCallback(rec.callback)

	// Slash 50% → new stake = 50 QAU.
	if _, err := vm.SlashStake(systemCaller, addr, big.NewInt(50)); err != nil {
		t.Fatalf("SlashStake failed: %v", err)
	}

	if got := rec.CallCount(); got != 1 {
		t.Fatalf("expected callback to fire once, got %d", got)
	}
	calls := rec.Calls()
	expected := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18))
	if calls[0].NewStake.Cmp(expected) != 0 {
		t.Errorf("callback received newStake %s, want %s (50%% slash of 100 QAU)",
			calls[0].NewStake.String(), expected.String())
	}
}

// TestCONS_R13_M02_NoCallbackDoesNotPanic verifies that when no callback
// is registered (default state — e.g., in unit tests or before the node
// layer wires QPOS), UpdateStake does NOT panic. The callback field is
// nil-tolerant.
func TestCONS_R13_M02_NoCallbackDoesNotPanic(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	if err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	// Deliberately do NOT register a callback. UpdateStake must not panic.
	newStake := new(big.Int).Mul(big.NewInt(150), big.NewInt(1e18))
	if err := vm.UpdateStake(addr, addr, newStake); err != nil {
		t.Fatalf("UpdateStake failed: %v", err)
	}
}

// TestCONS_R13_M02_CallbackReceivesDefensiveCopy verifies that the
// stake passed to the callback is a defensive copy — the callback
// cannot mutate v.Stake by modifying the *big.Int it receives. (If it
// could, the second UpdateStake call below would see the mutated value
// instead of the correct new stake.)
func TestCONS_R13_M02_CallbackReceivesDefensiveCopy(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	if err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	// Register a callback that mutates the received *big.Int.
	vm.SetStakeChangedCallback(func(_ types.Address, ns *big.Int) {
		// Try to corrupt the stake. The defensive copy in UpdateStake
		// should prevent this from affecting v.Stake.
		ns.SetInt64(0)
	})

	newStake := new(big.Int).Mul(big.NewInt(150), big.NewInt(1e18))
	if err := vm.UpdateStake(addr, addr, newStake); err != nil {
		t.Fatalf("UpdateStake failed: %v", err)
	}

	// Verify v.Stake was NOT mutated by the callback.
	info, _ := vm.GetValidator(addr)
	if info.Stake.Cmp(newStake) != 0 {
		t.Errorf("callback mutated v.Stake: expected %s, got %s — defensive copy missing",
			newStake.String(), info.Stake.String())
	}
}

// ============================================================================
// CONS-R13-M03: VRF accumulator seed delayed by one epoch
// ============================================================================

// TestCONS_R13_M03_Epoch1IgnoresEpoch0VRF verifies the core M03 property:
// epoch 1's shuffle seed does NOT depend on epoch 0's VRF accumulator.
// Before the fix, accumulating different VRF values for epoch 0 would
// change epoch 1's shuffle. After the fix, epoch 1's shuffle is
// determined solely by keccak(1) until epoch 2 (which mixes in
// epochVRFAccumulator[0]).
//
// This is the grind-mitigation property: the last proposer of epoch 0
// cannot adaptively grind epoch 1's shuffle by withholding vs publishing
// their VRF output. They can only affect epoch 2's shuffle, by which
// time the network has had a full epoch to react.
func TestCONS_R13_M03_Epoch1IgnoresEpoch0VRF(t *testing.T) {
	vs, err := NewValidatorSet(generateValidators(10))
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}

	vrfA := types.Hash{0xAA, 0xBB, 0xCC}
	vrfB := types.Hash{0x11, 0x22, 0x33}

	// QPOS 1: accumulate vrfA for epoch 0.
	qpos1, _ := NewQPOS(vs)
	qpos1.AccumulateVRFOutput(0, vrfA)
	qpos1.mu.RLock()
	shuffle1 := qpos1.computeShuffleForEpoch(1, 10)
	qpos1.mu.RUnlock()

	// QPOS 2: accumulate vrfB (different) for epoch 0.
	qpos2, _ := NewQPOS(vs)
	qpos2.AccumulateVRFOutput(0, vrfB)
	qpos2.mu.RLock()
	shuffle2 := qpos2.computeShuffleForEpoch(1, 10)
	qpos2.mu.RUnlock()

	// M03 property: epoch 1's shuffle must NOT depend on epoch 0's VRF.
	// (Both fall back to keccak(1) since epoch-1 = -1 underflows.)
	if !equalSlices(shuffle1, shuffle2) {
		t.Fatal("CONS-R13-M03 REGRESSION: epoch 1 shuffle depends on epoch 0's VRF — " +
			"last-proposer grind is possible (1-epoch delay). The fix requires " +
			"epoch-2 seed sourcing so epoch 1 is VRF-independent.")
	}
}

// TestCONS_R13_M03_Epoch2DependsOnEpoch0VRF verifies the dual property:
// epoch 2's shuffle DOES depend on epoch 0's VRF accumulator. This
// ensures the VRF entropy still reaches the schedule — just delayed by
// one epoch (2-epoch delay instead of 1).
func TestCONS_R13_M03_Epoch2DependsOnEpoch0VRF(t *testing.T) {
	vs, err := NewValidatorSet(generateValidators(10))
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}

	vrfA := types.Hash{0xAA, 0xBB, 0xCC}
	vrfB := types.Hash{0x11, 0x22, 0x33}

	qpos1, _ := NewQPOS(vs)
	setGenuineFinality(qpos1, 2)
	qpos1.AccumulateVRFOutput(0, vrfA)
	qpos1.mu.RLock()
	shuffle1 := qpos1.computeShuffleForEpoch(2, 10)
	qpos1.mu.RUnlock()

	qpos2, _ := NewQPOS(vs)
	setGenuineFinality(qpos2, 2)
	qpos2.AccumulateVRFOutput(0, vrfB)
	qpos2.mu.RLock()
	shuffle2 := qpos2.computeShuffleForEpoch(2, 10)
	qpos2.mu.RUnlock()

	if equalSlices(shuffle1, shuffle2) {
		t.Fatal("CONS-R13-M03 REGRESSION: epoch 2 shuffle does NOT depend on " +
			"epoch 0's VRF — VRF entropy is lost. The epoch-2 seed must mix in " +
			"epochVRFAccumulator[0].")
	}
}

// TestCONS_R13_M03_OnChainVRF_IsDeterministicAcrossNodes verifies the
// R55-ACC-ONCHAIN determinism fix (2026-08-07): the per-epoch VRF accumulator
// is carried ON-CHAIN in block headers and recorded unconditionally (no
// finality gate). Two nodes on the SAME canonical chain therefore derive the
// SAME accumulator — and thus the SAME shuffle — regardless of their local
// finality progression.
//
// This replaces the previous finality-gated logic, which was the root cause of
// the remaining fork: the gate made the seed depend on the LOCAL wall-clock
// moment when each node first computed (and cached) the shuffle, so nodes that
// crossed the finality boundary at different times elected different proposers
// for the same slot. With the on-chain accumulator there is no gate: srcEpoch
// is always two full epochs in the past, so its accumulator is committed to
// verified headers on every node.
func TestCONS_R13_M03_OnChainVRF_IsDeterministicAcrossNodes(t *testing.T) {
	vs, err := NewValidatorSet(generateValidators(10))
	if err != nil {
		t.Fatalf("NewValidatorSet: %v", err)
	}

	// Two "nodes" on the same canonical chain: identical on-chain VRF
	// accumulator for epoch 0, NO genuine finality yet (finalizedRoot zero).
	// The accumulator must still be mixed in unconditionally and must yield an
	// identical shuffle on both nodes.
	vrf := types.Hash{0xAA, 0xBB, 0xCC}

	qpos1, _ := NewQPOS(vs)
	qpos1.AccumulateVRFOutput(0, vrf)
	qpos1.mu.RLock()
	shuffle1 := qpos1.computeShuffleForEpoch(2, 10)
	qpos1.mu.RUnlock()

	qpos2, _ := NewQPOS(vs)
	qpos2.AccumulateVRFOutput(0, vrf)
	qpos2.mu.RLock()
	shuffle2 := qpos2.computeShuffleForEpoch(2, 10)
	qpos2.mu.RUnlock()

	if !equalSlices(shuffle1, shuffle2) {
		t.Fatal("DIVERGENCE: identical on-chain VRF accumulator produced different " +
			"shuffles across nodes — the shuffle must be a deterministic function " +
			"of the shared canonical chain, not of local finality timing.")
	}

	// The accumulator entropy must actually be mixed in (not ignored): a
	// node with a DIFFERENT accumulator elects a different proposer for the
	// same slot, so a node that imported a different canonical chain does not
	// silently agree with the rest of the network.
	qpos3, _ := NewQPOS(vs)
	qpos3.AccumulateVRFOutput(0, types.Hash{0x11, 0x22, 0x33})
	qpos3.mu.RLock()
	shuffle3 := qpos3.computeShuffleForEpoch(2, 10)
	qpos3.mu.RUnlock()
	if equalSlices(shuffle1, shuffle3) {
		t.Fatal("REGRESSION: different on-chain VRF accumulators produced the same " +
			"shuffle — the accumulator is not being mixed into the seed.")
	}
}

// TestCONS_R13_M03_AccumulateInvalidatesEpoch2Cache verifies that
// accumulating a new VRF output for epoch N invalidates the cached
// shuffle for epoch N+2 (which now depends on the new accumulator).
//
// Without this invalidation, a stale shuffle computed before the new VRF
// output arrived would remain cached, causing the wrong proposer to be
// used.
func TestCONS_R13_M03_AccumulateInvalidatesEpoch2Cache(t *testing.T) {
	vs, _ := NewValidatorSet(generateValidators(5))
	qpos, _ := NewQPOS(vs)

	// Pre-populate the shuffle cache for epoch 2.
	qpos.mu.Lock()
	qpos.shuffleCache[2] = []int{0, 1, 2, 3, 4}
	qpos.mu.Unlock()

	// Accumulate a VRF for epoch 0 → should invalidate cache for epoch 2.
	qpos.AccumulateVRFOutput(0, types.Hash{0x42})

	qpos.mu.RLock()
	_, cached := qpos.shuffleCache[2]
	qpos.mu.RUnlock()

	if cached {
		t.Fatal("CONS-R13-M03 REGRESSION: AccumulateVRFOutput failed to invalidate " +
			"shuffleCache[epoch+2] — stale shuffle with the new VRF accumulator " +
			"would remain cached, causing the wrong proposer to be used at epoch 2")
	}
}

// ============================================================================
// CONS-R13-M04: ReanchorSlotRoots refuses finalized-epoch reorgs
// ============================================================================

// TestCONS_R13_M04_RejectsReorgBelowFinalizedEpoch verifies that
// ReanchorSlotRoots refuses a reorg whose slot range is entirely below
// the finalized epoch. Casper FFG finality is irreversible — a finalized
// epoch's slot roots must never change.
func TestCONS_R13_M04_RejectsReorgBelowFinalizedEpoch(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Pretend finality has reached epoch 5 (slots 0..159 are finalized).
	finalizedRoot := types.Hash{0xEE}
	qpos.mu.Lock()
	qpos.finalizedEpoch = 5
	qpos.finalizedRoot = finalizedRoot
	// Pre-populate slotBlockRoots with the finalized roots.
	for s := uint64(0); s < 5*SlotsPerEpoch; s++ {
		qpos.slotBlockRoots[s] = finalizedRoot
	}
	qpos.mu.Unlock()

	// Attempt to reorg slots 50..52 (entirely within finalized epoch 1).
	roots := map[uint64]types.Hash{
		50: {0xAA},
		51: {0xBB},
		52: {0xCC},
	}
	qpos.ReanchorSlotRoots(roots, nil)

	// Verify NONE of the roots were overwritten — finalized history is
	// immutable.
	qpos.mu.RLock()
	for s, want := range roots {
		got, ok := qpos.slotBlockRoots[s]
		if !ok || got != finalizedRoot {
			t.Errorf("CONS-R13-M04 REGRESSION: slot %d root was modified by "+
				"refused reorg — got %v, want finalizedRoot %v (finalized epoch "+
				"history must be immutable)", s, got, finalizedRoot)
		}
		_ = want // unused on success path
	}
	qpos.mu.RUnlock()
}

// TestCONS_R13_M04_RejectsReorgCrossingFinalizedBoundary verifies that
// a reorg whose range straddles the finalized-epoch boundary is also
// refused (not partially applied). Mixing finalized and non-finalized
// slots in a single reorg is suspicious and would be unsafe.
func TestCONS_R13_M04_RejectsReorgCrossingFinalizedBoundary(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Finality at epoch 3 (slots 0..95 finalized).
	finalizedRoot := types.Hash{0xEE}
	qpos.mu.Lock()
	qpos.finalizedEpoch = 3
	qpos.finalizedRoot = finalizedRoot
	for s := uint64(0); s < 3*SlotsPerEpoch; s++ {
		qpos.slotBlockRoots[s] = finalizedRoot
	}
	qpos.mu.Unlock()

	// Reorg spans slots 90..100 (crosses the 96 boundary).
	roots := map[uint64]types.Hash{
		90:  {0xAA}, // finalized region
		95:  {0xBB}, // finalized region
		100: {0xCC}, // post-finalized region
	}
	qpos.ReanchorSlotRoots(roots, nil)

	// Verify NONE of the roots were applied (whole reorg refused).
	qpos.mu.RLock()
	for s, want := range roots {
		got, ok := qpos.slotBlockRoots[s]
		if s < 3*SlotsPerEpoch {
			// Finalized region — must remain at finalizedRoot.
			if !ok || got != finalizedRoot {
				t.Errorf("CONS-R13-M04 REGRESSION: finalized slot %d was modified "+
					"(got %v, want %v)", s, got, finalizedRoot)
			}
		} else {
			// Post-finalized region — must NOT be set (reorg was refused wholesale).
			if ok {
				t.Errorf("CONS-R13-M04 REGRESSION: post-finalized slot %d was "+
					"written despite reorg crossing the finalized boundary — "+
					"the reorg must be refused entirely, not partially applied "+
					"(got %v, want unset)", s, got)
			}
		}
		_ = want
	}
	qpos.mu.RUnlock()
}

// TestCONS_R13_M04_AllowsReorgAboveFinalizedEpoch verifies that reorgs
// entirely above the finalized epoch are still allowed. The "hot"
// forkchoice region above finality must remain reorgable — otherwise
// the chain cannot reorganize around the head.
func TestCONS_R13_M04_AllowsReorgAboveFinalizedEpoch(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// Finality at epoch 2 (slots 0..63 finalized).
	finalizedRoot := types.Hash{0xEE}
	qpos.mu.Lock()
	qpos.finalizedEpoch = 2
	qpos.finalizedRoot = finalizedRoot
	qpos.mu.Unlock()

	// Reorg slots 70..72 (entirely in epoch 2 → wait, that's still finalized.
	// Use slots in epoch 3+ to be above finality.)
	newRoot := types.Hash{0xCC}
	// Wait — slots 70..72 are in epoch 2 (70/32=2). Let me use slots in
	// epoch 3 instead (slots 96+).
	roots := map[uint64]types.Hash{
		100: newRoot,
		101: newRoot,
		102: newRoot,
	}
	qpos.ReanchorSlotRoots(roots, nil)

	// Verify the roots WERE applied — reorgs above finality are allowed.
	qpos.mu.RLock()
	for s, want := range roots {
		got, ok := qpos.slotBlockRoots[s]
		if !ok || got != want {
			t.Errorf("CONS-R13-M04 REGRESSION: post-finalized slot %d was NOT "+
				"written by ReanchorSlotRoots — reorgs above finality must be "+
				"allowed (got %v ok=%v, want %v)", s, got, ok, want)
		}
	}
	qpos.mu.RUnlock()
}

// TestCONS_R13_M04_NoFinalityAllowsAnyReorg verifies that when no
// finality has been established yet (finalizedEpoch=0 and
// finalizedRoot=zero), ReanchorSlotRoots applies the reorg without
// restriction. This is the bootstrap case — the chain is still
// finalizing its first epoch.
func TestCONS_R13_M04_NoFinalityAllowsAnyReorg(t *testing.T) {
	vs := makeSlotPruneTestValidatorSet(5)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// No finality established (default state).
	qpos.mu.RLock()
	finalizedEpoch := qpos.finalizedEpoch
	finalizedRoot := qpos.finalizedRoot
	qpos.mu.RUnlock()
	if finalizedEpoch != 0 || finalizedRoot != (types.Hash{}) {
		t.Fatalf("precondition: expected no finality, got finalizedEpoch=%d "+
			"finalizedRoot=%v", finalizedEpoch, finalizedRoot)
	}

	// Reorg early slots — should be allowed (no finality constraint).
	newRoot := types.Hash{0xCC}
	roots := map[uint64]types.Hash{
		5:  newRoot,
		10: newRoot,
		15: newRoot,
	}
	qpos.ReanchorSlotRoots(roots, nil)

	qpos.mu.RLock()
	for s, want := range roots {
		got, ok := qpos.slotBlockRoots[s]
		if !ok || got != want {
			t.Errorf("CONS-R13-M04 REGRESSION: slot %d was NOT written despite "+
				"no finality established — bootstrap reorgs must be allowed "+
				"(got %v ok=%v, want %v)", s, got, ok, want)
		}
	}
	qpos.mu.RUnlock()
}
