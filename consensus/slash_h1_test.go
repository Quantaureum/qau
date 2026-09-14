// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"testing"

	"github.com/quantaureum/qau/types"
)

// TestSLASH_H1_WithdrawStake_InvokesRemovedCallback verifies that
// WithdrawStake invokes the onValidatorRemoved callback after deleting
// the validator from vm.validators.
//
// SLASH-H1 FIX (R29, 2026-07-25): Previously, WithdrawStake only
// deleted from vm.validators, leaving residual entries in
// QPOS.slashedValidators, QPOS.pendingDeactivationAddrs, and
// ValidatorSet (validators slice, validatorMap, addrIndexMap).
// These stale entries caused unbounded memory growth and could
// block re-registration of the same address (slashedValidators
// check in CanPropose/CanAttest/CanSeal would reject the new
// validator). The fix adds an onValidatorRemoved callback that
// node.go registers to clean up ALL residual state.
func TestSLASH_H1_WithdrawStake_InvokesRemovedCallback(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	if err := vm.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	// Activate the validator (needed before RemoveValidator).
	activateValidatorForTest(t, vm, addr)

	// Mark validator as exiting.
	vm.SetCurrentHeight(500)
	if err := vm.RemoveValidator(addr, addr); err != nil {
		t.Fatalf("RemoveValidator failed: %v", err)
	}

	// Register the onValidatorRemoved callback.
	var removedAddr types.Address
	callbackInvoked := false
	vm.SetValidatorRemovedCallback(func(a types.Address) {
		removedAddr = a
		callbackInvoked = true
	})

	// Advance height past cooldown (ExitHeight + ValidatorCooldownBlocks).
	vm.SetCurrentHeight(500 + ValidatorCooldownBlocks + 1)

	// WithdrawStake should invoke the callback.
	stake, err := vm.WithdrawStake(addr, addr)
	if err != nil {
		t.Fatalf("WithdrawStake failed: %v", err)
	}
	if stake == nil || stake.Sign() <= 0 {
		t.Errorf("WithdrawStake returned invalid stake: %v", stake)
	}

	if !callbackInvoked {
		t.Fatal("onValidatorRemoved callback was NOT invoked by WithdrawStake — SLASH-H1 fix not wired")
	}
	if removedAddr != addr {
		t.Errorf("callback received addr %v, want %v", removedAddr, addr)
	}

	// Verify validator was actually deleted from vm.validators.
	if _, err := vm.GetValidator(addr); err == nil {
		t.Error("validator still exists in vm.validators after WithdrawStake — should be deleted")
	}
}

// TestSLASH_H1_WithdrawStake_NoCallbackNoLeak verifies that without
// the callback, the validator is still deleted from vm.validators
// (the callback is for cleaning up EXTERNAL state in QPOS/ValidatorSet,
// not for vm.validators itself).
func TestSLASH_H1_WithdrawStake_NoCallbackNoLeak(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	if err := vm.AddValidator(addr, addr, pubKey, validStake(), 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}
	activateValidatorForTest(t, vm, addr)

	vm.SetCurrentHeight(500)
	if err := vm.RemoveValidator(addr, addr); err != nil {
		t.Fatalf("RemoveValidator failed: %v", err)
	}

	// Do NOT register a callback — WithdrawStake should still work.
	vm.SetCurrentHeight(500 + ValidatorCooldownBlocks + 1)

	_, err := vm.WithdrawStake(addr, addr)
	if err != nil {
		t.Fatalf("WithdrawStake without callback failed: %v", err)
	}

	// vm.validators entry must be deleted regardless of callback.
	if _, err := vm.GetValidator(addr); err == nil {
		t.Error("validator still exists in vm.validators after WithdrawStake (no callback) — should be deleted")
	}
}

// TestSLASH_H1_CleanupValidatorState_RemovesSlashedEntries verifies
// that QPOS.CleanupValidatorState removes slashedValidators and
// pendingDeactivationAddrs entries for the given address. This is
// the cleanup method invoked by the onValidatorRemoved callback.
func TestSLASH_H1_CleanupValidatorState_RemovesSlashedEntries(t *testing.T) {
	vs := createTestValidatorSet(t, 10)
	qpos, err := NewQPOS(vs)
	if err != nil {
		t.Fatalf("NewQPOS failed: %v", err)
	}

	// R30-IMPLEMENT (2026-07-27): Use the first validator's address (which
	// IS in the validator set) so CleanupValidatorState can look up its
	// index. Previously this test generated a fresh key pair whose address
	// was NOT in the validator set, so GetValidatorIndex returned -1 and
	// the slashedValidators entry (keyed by index) was never cleaned up.
	validators := qpos.validators.Validators()
	if len(validators) == 0 {
		t.Fatal("validator set is empty")
	}
	addr := validators[0].Address
	idx := qpos.validators.GetValidatorIndex(addr)
	if idx < 0 {
		t.Fatalf("validator index for %x not found", addr)
	}

	// Manually mark the validator as slashed and pending deactivation.
	// R30-IMPLEMENT: slashedValidators is keyed by validator INDEX (int),
	// not by address. pendingDeactivationAddrs is keyed by address.
	qpos.mu.Lock()
	if qpos.slashedValidators == nil {
		qpos.slashedValidators = make(map[int]*SlashedEntry)
	}
	qpos.slashedValidators[idx] = &SlashedEntry{Epoch: 0, Permanent: true}
	if qpos.pendingDeactivationAddrs == nil {
		qpos.pendingDeactivationAddrs = make(map[types.Address]bool)
	}
	qpos.pendingDeactivationAddrs[addr] = true
	qpos.mu.Unlock()

	// Verify entries exist.
	qpos.mu.RLock()
	_, slashedExists := qpos.slashedValidators[idx]
	_, pendingExists := qpos.pendingDeactivationAddrs[addr]
	qpos.mu.RUnlock()
	if !slashedExists {
		t.Fatal("slashedValidators[idx] not set")
	}
	if !pendingExists {
		t.Fatal("pendingDeactivationAddrs[addr] not set")
	}

	// Call CleanupValidatorState — should remove both entries.
	qpos.CleanupValidatorState(addr)

	qpos.mu.RLock()
	_, slashedAfter := qpos.slashedValidators[idx]
	_, pendingAfter := qpos.pendingDeactivationAddrs[addr]
	qpos.mu.RUnlock()
	if slashedAfter {
		t.Error("slashedValidators[addr] still exists after CleanupValidatorState — SLASH-H1 fix not working")
	}
	if pendingAfter {
		t.Error("pendingDeactivationAddrs[addr] still exists after CleanupValidatorState — SLASH-H1 fix not working")
	}
}

// TestSLASH_H1_RemoveValidatorByAddr_RemovesFromAllMaps verifies
// that ValidatorSet.RemoveValidatorByAddr removes the validator
// from validators slice, validatorMap, and addrIndexMap. This is
// the ValidatorSet cleanup invoked by the onValidatorRemoved callback.
func TestSLASH_H1_RemoveValidatorByAddr_RemovesFromAllMaps(t *testing.T) {
	vs := createTestValidatorSet(t, 10)

	// Get the first validator's address.
	validators := vs.Validators()
	if len(validators) == 0 {
		t.Fatal("no validators in set")
	}
	addr := validators[0].Address

	// Verify the address exists in all maps.
	vs.mu.RLock()
	_, inValidatorMap := vs.validatorMap[addr]
	idx, inAddrIndexMap := vs.addrIndexMap[addr]
	vs.mu.RUnlock()
	if !inValidatorMap {
		t.Fatal("validator not in validatorMap before removal")
	}
	if !inAddrIndexMap {
		t.Fatal("validator not in addrIndexMap before removal")
	}
	_ = idx

	// Remove by address.
	removed := vs.RemoveValidatorByAddr(addr)
	if !removed {
		t.Fatal("RemoveValidatorByAddr returned false")
	}

	// Verify all maps no longer contain the address.
	vs.mu.RLock()
	_, inValidatorMapAfter := vs.validatorMap[addr]
	_, inAddrIndexMapAfter := vs.addrIndexMap[addr]
	validatorsAfter := vs.validators
	vs.mu.RUnlock()
	if inValidatorMapAfter {
		t.Error("validator still in validatorMap after RemoveValidatorByAddr — SLASH-H1 leak")
	}
	if inAddrIndexMapAfter {
		t.Error("validator still in addrIndexMap after RemoveValidatorByAddr — SLASH-H1 leak")
	}
	// Verify the validator is not in the slice.
	for _, v := range validatorsAfter {
		if v.Address == addr {
			t.Error("validator still in validators slice after RemoveValidatorByAddr — SLASH-H1 leak")
			break
		}
	}
}
