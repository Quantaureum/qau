// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/types"
)

// TestSLASH_H3_SlashStakeBasisPoints_CallbackNoSelfDeadlock verifies that the
// onStakeChanged callback fires AFTER vm.mu is released, so the callback can
// safely re-acquire vm.mu (e.g. via vm.GetValidator) without self-deadlock.
//
// SLASH-H3 FIX (R29, 2026-07-25): Previously the defer order in
// SlashStakeBasisPoints was:
//
//	vm.mu.Lock()
//	defer vm.mu.Unlock()       // registered first → runs last (LIFO)
//	defer func() { callback }() // registered last → runs first (LIFO)
//
// This meant the callback ran WHILE HOLDING vm.mu. The node.go onStakeChanged
// callback calls vmRef.GetValidator which acquires vm.mu.RLock() — a
// self-deadlock because Go's sync.RWMutex does not support recursive locking.
//
// The fix swaps the defer registration order so the callback defer is
// registered BEFORE the Unlock defer, making LIFO order:
//  1. vm.mu.Unlock() (registered last → runs first)
//  2. callback (registered first → runs last)
//
// This test registers a callback that calls vm.GetValidator (acquiring
// vm.mu.RLock). If the callback fires while vm.mu is still held, the test
// will hang and time out.
func TestSLASH_H3_SlashStakeBasisPoints_CallbackNoSelfDeadlock(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	if err := vm.AddGenesisValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	// Register a callback that re-acquires vm.mu via GetValidator.
	// If the callback fires while vm.mu is held (write-locked), GetValidator
	// (which calls vm.mu.RLock) will self-deadlock and the test will time out.
	callbackFired := make(chan struct{})
	vm.SetStakeChangedCallback(func(callbackAddr types.Address, newStake *big.Int) {
		// This call acquires vm.mu.RLock(). If vm.mu is still held by
		// SlashStakeBasisPoints, this will self-deadlock.
		info, err := vm.GetValidator(callbackAddr)
		if err != nil {
			t.Errorf("callback: GetValidator failed: %v", err)
		}
		if info == nil {
			t.Error("callback: GetValidator returned nil info")
		}
		close(callbackFired)
	})

	// Slash 10% (1000 basis points). Use a registered system caller for
	// authorization.
	systemCaller := types.Address{0xFF}
	RegisterSystemCaller(systemCaller)
	defer UnregisterSystemCaller(systemCaller)
	slashBP := big.NewInt(1000)

	// Run the slash in a goroutine so we can detect a hang via timeout.
	done := make(chan error, 1)
	go func() {
		_, err := vm.SlashStakeBasisPoints(systemCaller, addr, slashBP)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SlashStakeBasisPoints failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SlashStakeBasisPoints hung — callback self-deadlock (SLASH-H3 regression)")
	}

	select {
	case <-callbackFired:
		// Success: callback fired without deadlock.
	case <-time.After(5 * time.Second):
		t.Fatal("onStakeChanged callback did not fire within timeout")
	}
}

// TestSLASH_H3_SetActive_CallbackNoSelfDeadlock verifies that the
// onActiveChanged callback fires AFTER vm.mu is released, so the callback can
// safely re-acquire vm.mu without self-deadlock.
//
// Same rationale as TestSLASH_H3_SlashStakeBasisPoints_CallbackNoSelfDeadlock
// but for the SetActive path. The node.go onActiveChanged callback calls
// vm.GetValidatorSet which acquires vm.mu.RLock().
func TestSLASH_H3_SetActive_CallbackNoSelfDeadlock(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	if err := vm.AddGenesisValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	// Register a callback that re-acquires vm.mu via GetValidatorSet.
	// The key check is that this callback can ACQUIRE vm.mu.RLock() without
	// self-deadlock — whether GetValidatorSet returns a non-nil result is
	// irrelevant (after deactivation there may be no active validators left,
	// which is a normal "no-op" condition for the callback, not an error).
	callbackFired := make(chan struct{})
	vm.SetActiveChangedCallback(func(callbackAddr types.Address, active bool) {
		// This call acquires vm.mu.RLock(). If vm.mu is still held by
		// SetActive, this will self-deadlock.
		_, _ = vm.GetValidatorSet() // ignore result — just verify no deadlock
		close(callbackFired)
	})

	systemCaller := types.Address{0xFF}
	RegisterSystemCaller(systemCaller)
	defer UnregisterSystemCaller(systemCaller)

	// Deactivate the validator. This should trigger onActiveChanged.
	done := make(chan error, 1)
	go func() {
		err := vm.SetActive(systemCaller, addr, false)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SetActive failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SetActive hung — callback self-deadlock (SLASH-H3 regression)")
	}

	select {
	case <-callbackFired:
		// Success: callback fired without deadlock.
	case <-time.After(5 * time.Second):
		t.Fatal("onActiveChanged callback did not fire within timeout")
	}
}

// TestSLASH_H3_UpdateStake_CallbackNoSelfDeadlock verifies the same for
// UpdateStake, which has the same defer pattern.
func TestSLASH_H3_UpdateStake_CallbackNoSelfDeadlock(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	if err := vm.AddGenesisValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	callbackFired := make(chan struct{})
	vm.SetStakeChangedCallback(func(callbackAddr types.Address, newStake *big.Int) {
		// Re-acquire vm.mu via GetValidator — would self-deadlock if
		// the callback fired while vm.mu is held.
		info, err := vm.GetValidator(callbackAddr)
		if err != nil {
			t.Errorf("callback: GetValidator failed: %v", err)
		}
		if info == nil {
			t.Error("callback: GetValidator returned nil info")
		}
		close(callbackFired)
	})

	// 50% increase (within allowed bound, no cooldown since first stake change).
	newStake := new(big.Int).Mul(big.NewInt(150), big.NewInt(1e18))

	done := make(chan error, 1)
	go func() {
		err := vm.UpdateStake(addr, addr, newStake)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("UpdateStake failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("UpdateStake hung — callback self-deadlock (SLASH-H3 regression)")
	}

	select {
	case <-callbackFired:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("onStakeChanged callback did not fire within timeout")
	}
}

// TestSLASH_H3_MarkPermanentlySlashed_CallbackNoSelfDeadlock verifies the
// same for MarkPermanentlySlashed.
func TestSLASH_H3_MarkPermanentlySlashed_CallbackNoSelfDeadlock(t *testing.T) {
	vm := NewValidatorManager()
	_, pubKey := createTestKeyPair(t)
	addr := pubKey.Address()

	initialStake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
	if err := vm.AddGenesisValidator(addr, addr, pubKey, initialStake, 1000, 0); err != nil {
		t.Fatalf("AddValidator failed: %v", err)
	}

	callbackFired := make(chan struct{})
	vm.SetActiveChangedCallback(func(callbackAddr types.Address, active bool) {
		// Same rationale as TestSLASH_H3_SetActive_CallbackNoSelfDeadlock:
		// ignore GetValidatorSet result — the key check is that the
		// callback can acquire vm.mu.RLock() without self-deadlock.
		_, _ = vm.GetValidatorSet()
		close(callbackFired)
	})

	systemCaller := types.Address{0xFF}
	RegisterSystemCaller(systemCaller)
	defer UnregisterSystemCaller(systemCaller)

	done := make(chan error, 1)
	go func() {
		err := vm.MarkPermanentlySlashed(systemCaller, addr)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("MarkPermanentlySlashed failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MarkPermanentlySlashed hung — callback self-deadlock (SLASH-H3 regression)")
	}

	select {
	case <-callbackFired:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("onActiveChanged callback did not fire within timeout")
	}
}
