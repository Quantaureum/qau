// Quantaureum Node source, version 1.0.0.
// Package consensus implements the QPOS consensus mechanism for Quantaureum.
// This file contains unit tests for the ValidatorManager.
package consensus

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// Helper function to create a valid stake amount
func validStake() *big.Int {
	return new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
}

// Helper function to create a key pair for testing
func createTestKeyPair(t *testing.T) (*crypto.PrivateKey, *crypto.PublicKey) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}
	return kp.Private, kp.Public
}

// TestValidatorManager_NewValidatorManager tests the initialization of ValidatorManager.
func TestValidatorManager_NewValidatorManager(t *testing.T) {
	t.Parallel()

	t.Run("Initialization with valid params", func(t *testing.T) {
		vm := NewValidatorManager()
		if vm == nil {
			t.Fatal("NewValidatorManager returned nil")
		}
		if vm.validators == nil {
			t.Fatal("validators map is nil")
		}
		// Initial state should be empty
		if vm.ValidatorCount() != 0 {
			t.Errorf("expected ValidatorCount 0, got %d", vm.ValidatorCount())
		}
		if vm.TotalStake().Sign() != 0 {
			t.Errorf("expected TotalStake 0, got %s", vm.TotalStake().String())
		}
	})
}

// TestValidatorManager_AddValidator tests adding validators to the manager.
func TestValidatorManager_AddValidator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		stake       *big.Int
		expectError bool
	}{
		{
			name:        "Add validator with valid stake",
			stake:       validStake(),
			expectError: false,
		},
		{
			name:        "Add with nil stake",
			stake:       nil,
			expectError: true,
		},
		{
			name:        "Add with negative stake",
			stake:       big.NewInt(-1000),
			expectError: true,
		},
		{
			name:        "Add with stake below minimum",
			stake:       big.NewInt(1e17), // 0.1 QAU, below 32 QAU minimum
			expectError: true,
		},
		{
			name:        "Add with exactly minimum stake",
			stake:       MinStakeAmount,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vm := NewValidatorManager()
			_, pubKey := createTestKeyPair(t)
			addr := pubKey.Address()

			commission := uint32(1000) // 10%
			// R28-SEC FIX: Add caller parameter (self-registration)
			err := vm.AddValidator(addr, addr, pubKey, tt.stake, commission, 0)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				// Verify validator was added
				info, err := vm.GetValidator(addr)
				if err != nil {
					t.Errorf("GetValidator failed: %v", err)
				}
				if info == nil {
					t.Error("validator not found after AddValidator")
				}
			}
		})
	}

	t.Run("Add duplicate validator", func(t *testing.T) {
		vm := NewValidatorManager()
		_, pubKey := createTestKeyPair(t)
		addr := pubKey.Address()
		stake := validStake()

		// First add should succeed
		err := vm.AddValidator(addr, addr, pubKey, stake, 1000, 0)
		if err != nil {
			t.Fatalf("first AddValidator failed: %v", err)
		}

		// Second add should fail
		err = vm.AddValidator(addr, addr, pubKey, stake, 1000, 0)
		if err != ErrValidatorAlreadyExists {
			t.Errorf("expected ErrValidatorAlreadyExists, got: %v", err)
		}
	})

	t.Run("Add validator with invalid commission", func(t *testing.T) {
		vm := NewValidatorManager()
		_, pubKey := createTestKeyPair(t)
		addr := pubKey.Address()

		commission := MaxCommission + 1 // Exceeds 100%
		err := vm.AddValidator(addr, addr, pubKey, validStake(), commission, 0)
		if err != ErrInvalidCommission {
			t.Errorf("expected ErrInvalidCommission, got: %v", err)
		}
	})
}

// TestValidatorManager_RemoveValidator tests removing validators.
func TestValidatorManager_RemoveValidator(t *testing.T) {
	t.Parallel()

	t.Run("Remove existing validator", func(t *testing.T) {
		vm := NewValidatorManager()
		_, pubKey := createTestKeyPair(t)
		addr := pubKey.Address()

		err := vm.AddValidator(addr, addr, pubKey, validStake(), 1000, 0)
		if err != nil {
			t.Fatalf("AddValidator failed: %v", err)
		}

		vm.SetCurrentHeight(500)

		err = vm.RemoveValidator(addr, addr)
		if err != nil {
			t.Fatalf("RemoveValidator failed: %v", err)
		}

		info, err := vm.GetValidator(addr)
		if err != nil {
			t.Fatalf("expected validator to still exist during exit cooldown, got error: %v", err)
		}
		if info.Active {
			t.Error("validator should be inactive after RemoveValidator")
		}
		if info.ExitHeight != 500 {
			t.Errorf("ExitHeight should be 500 after RemoveValidator, got %d", info.ExitHeight)
		}
	})

	t.Run("Remove non-existent validator", func(t *testing.T) {
		vm := NewValidatorManager()
		_, pubKey := createTestKeyPair(t)
		addr := pubKey.Address()

		err := vm.RemoveValidator(addr, addr)
		if err != ErrValidatorNotFound {
			t.Errorf("expected ErrValidatorNotFound, got: %v", err)
		}
	})

	t.Run("Remove validator with unauthorized caller", func(t *testing.T) {
		vm := NewValidatorManager()
		_, pubKey1 := createTestKeyPair(t)
		addr1 := pubKey1.Address()
		_, pubKey2 := createTestKeyPair(t)
		addr2 := pubKey2.Address()

		// Add validator 1
		err := vm.AddValidator(addr1, addr1, pubKey1, validStake(), 1000, 0)
		if err != nil {
			t.Fatalf("AddValidator failed: %v", err)
		}

		// Validator 2 tries to remove validator 1 - should fail
		err = vm.RemoveValidator(addr2, addr1)
		if err == nil {
			t.Error("expected error when unauthorized caller removes validator")
		}
	})
}

// TestValidatorManager_GetValidator tests retrieving validator info.
func TestValidatorManager_GetValidator(t *testing.T) {
	t.Parallel()

	t.Run("Get existing validator", func(t *testing.T) {
		vm := NewValidatorManager()
		_, pubKey := createTestKeyPair(t)
		addr := pubKey.Address()
		stake := validStake()

		err := vm.AddValidator(addr, addr, pubKey, stake, 1000, 100)
		if err != nil {
			t.Fatalf("AddValidator failed: %v", err)
		}

		info, err := vm.GetValidator(addr)
		if err != nil {
			t.Fatalf("GetValidator failed: %v", err)
		}
		if info == nil {
			t.Fatal("GetValidator returned nil")
		}
		if info.Stake.Cmp(stake) != 0 {
			t.Errorf("expected stake %s, got %s", stake.String(), info.Stake.String())
		}
		if info.Commission != 1000 {
			t.Errorf("expected commission 1000, got %d", info.Commission)
		}
		if info.JoinHeight != 100 {
			t.Errorf("expected JoinHeight 100, got %d", info.JoinHeight)
		}
	})

	t.Run("Get non-existent validator", func(t *testing.T) {
		vm := NewValidatorManager()
		_, pubKey := createTestKeyPair(t)
		addr := pubKey.Address()

		info, err := vm.GetValidator(addr)
		if err != ErrValidatorNotFound {
			t.Errorf("expected ErrValidatorNotFound, got: %v", err)
		}
		if info != nil {
			t.Error("expected nil info for non-existent validator")
		}
	})
}

// TestValidatorManager_UpdateStake tests stake updates.
func TestValidatorManager_UpdateStake(t *testing.T) {
	t.Parallel()

	t.Run("Update stake with proper authorization", func(t *testing.T) {
		vm := NewValidatorManager()
		_, pubKey := createTestKeyPair(t)
		addr := pubKey.Address()

		// Add validator
		initialStake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
		err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0)
		if err != nil {
			t.Fatalf("AddValidator failed: %v", err)
		}

		// Update stake - increase by 50% (allowed)
		newStake := new(big.Int).Mul(big.NewInt(150), big.NewInt(1e18))
		err = vm.UpdateStake(addr, addr, newStake)
		if err != nil {
			t.Fatalf("UpdateStake failed: %v", err)
		}

		// Verify update
		info, _ := vm.GetValidator(addr)
		if info.Stake.Cmp(newStake) != 0 {
			t.Errorf("expected stake %s, got %s", newStake.String(), info.Stake.String())
		}
	})

	t.Run("Update stake without authorization", func(t *testing.T) {
		vm := NewValidatorManager()
		_, pubKey := createTestKeyPair(t)
		addr := pubKey.Address()

		err := vm.AddValidator(addr, addr, pubKey, validStake(), 1000, 0)
		if err != nil {
			t.Fatalf("AddValidator failed: %v", err)
		}

		// Try to update from different address
		_, pubKey2 := createTestKeyPair(t)
		attackerAddr := pubKey2.Address()

		newStake := new(big.Int).Mul(big.NewInt(200), big.NewInt(1e18))
		err = vm.UpdateStake(attackerAddr, addr, newStake)
		// Should get an error about authorization
		if err == nil {
			t.Error("expected error when unauthorized caller updates stake")
		}
	})

	t.Run("Update stake exceeding 50% limit fails", func(t *testing.T) {
		vm := NewValidatorManager()
		_, pubKey := createTestKeyPair(t)
		addr := pubKey.Address()

		initialStake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
		err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0)
		if err != nil {
			t.Fatalf("AddValidator failed: %v", err)
		}

		// Try to double stake (100% increase) - should fail due to 50% limit
		newStake := new(big.Int).Mul(big.NewInt(200), big.NewInt(1e18))
		err = vm.UpdateStake(addr, addr, newStake)
		if err == nil {
			t.Error("expected error when stake change exceeds 50% limit")
		}
	})

	t.Run("Update stake within 50% limit succeeds", func(t *testing.T) {
		vm := NewValidatorManager()
		_, pubKey := createTestKeyPair(t)
		addr := pubKey.Address()

		initialStake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
		err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0)
		if err != nil {
			t.Fatalf("AddValidator failed: %v", err)
		}

		// Increase by exactly 50% - should succeed
		newStake := new(big.Int).Mul(big.NewInt(150), big.NewInt(1e18))
		err = vm.UpdateStake(addr, addr, newStake)
		if err != nil {
			t.Errorf("50%% stake increase should succeed, got: %v", err)
		}
	})
}

// TestValidatorManager_UpdateStakeForSlashing tests slashing.
func TestValidatorManager_UpdateStakeForSlashing(t *testing.T) {
	t.Parallel()

	t.Run("Slashing bypasses normal stake limits", func(t *testing.T) {
		vm := NewValidatorManager()
		_, pubKey := createTestKeyPair(t)
		addr := pubKey.Address()

		// Add validator
		initialStake := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
		err := vm.AddValidator(addr, addr, pubKey, initialStake, 1000, 0)
		if err != nil {
			t.Fatalf("AddValidator failed: %v", err)
		}

		// Slash 50% - should succeed even though it's a large reduction
		// Slashing bypasses the 50% limit via UpdateStakeForSlashing
		slashAmount := new(big.Int).Div(initialStake, big.NewInt(2))
		err = vm.UpdateStakeForSlashing(addr, slashAmount)
		if err != nil {
			t.Fatalf("UpdateStakeForSlashing failed: %v", err)
		}

		// Verify slash was applied
		info, _ := vm.GetValidator(addr)
		expected := new(big.Int).Sub(initialStake, slashAmount)
		if info.Stake.Cmp(expected) != 0 {
			t.Errorf("expected stake %s after slashing, got %s", expected.String(), info.Stake.String())
		}
	})
}

// TestValidatorManager_GetActiveValidators tests getting active validator set.
func TestValidatorManager_GetActiveValidators(t *testing.T) {
	t.Parallel()

	t.Run("Empty set returns empty", func(t *testing.T) {
		vm := NewValidatorManager()
		active := vm.GetActiveValidators()
		if len(active) != 0 {
			t.Errorf("expected empty active set, got %d validators", len(active))
		}
	})

	t.Run("Multiple active validators", func(t *testing.T) {
		vm := NewValidatorManager()

		addrs := make([]types.Address, 3)
		for i := 0; i < 3; i++ {
			_, pubKey := createTestKeyPair(t)
			addr := pubKey.Address()
			addrs[i] = addr
			err := vm.AddValidator(addr, addr, pubKey, validStake(), 1000, 0)
			if err != nil {
				t.Fatalf("AddValidator %d failed: %v", i, err)
			}
			// VAL-H04 FIX (R31, 2026-07-27): AddValidator now leaves
			// non-genesis validators Active=false. Use ActivateFromQueue
			// (the production first-time-activation path) instead of
			// SetActive, which is now reserved for re-activation only.
			if err := vm.ActivateFromQueue(addr); err != nil {
				t.Fatalf("ActivateFromQueue %d failed: %v", i, err)
			}
		}

		active := vm.GetActiveValidators()
		if len(active) != 3 {
			t.Errorf("expected 3 active validators, got %d", len(active))
		}

		for _, addr := range addrs {
			found := false
			for _, v := range active {
				if v.Address == addr {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("address %s not in active set", addr.String())
			}
		}
	})
}

// TestValidatorManager_TotalStake tests total stake calculation.
func TestValidatorManager_TotalStake(t *testing.T) {
	t.Parallel()

	t.Run("Empty returns zero", func(t *testing.T) {
		vm := NewValidatorManager()
		total := vm.TotalStake()
		if total.Sign() != 0 {
			t.Errorf("expected zero total stake, got %s", total.String())
		}
	})

	t.Run("Single validator stake", func(t *testing.T) {
		vm := NewValidatorManager()
		_, pubKey := createTestKeyPair(t)
		addr := pubKey.Address()
		stake := validStake()

		vm.AddValidator(addr, addr, pubKey, stake, 1000, 0)
		// VAL-H04 FIX (R31, 2026-07-27): Use ActivateFromQueue for
		// first-time activation; SetActive now rejects EverActivated=false.
		if err := vm.ActivateFromQueue(addr); err != nil {
			t.Fatalf("ActivateFromQueue failed: %v", err)
		}

		total := vm.TotalStake()
		if total.Cmp(stake) != 0 {
			t.Errorf("expected total stake %s, got %s", stake.String(), total.String())
		}
	})

	t.Run("Multiple validators aggregate stake", func(t *testing.T) {
		vm := NewValidatorManager()

		stake1 := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18))
		stake2 := new(big.Int).Mul(big.NewInt(200), big.NewInt(1e18))
		stake3 := new(big.Int).Mul(big.NewInt(150), big.NewInt(1e18))
		expectedTotal := new(big.Int).Add(stake1, stake2)
		expectedTotal.Add(expectedTotal, stake3)

		_, pubKey1 := createTestKeyPair(t)
		vm.AddValidator(pubKey1.Address(), pubKey1.Address(), pubKey1, stake1, 1000, 0)
		if err := vm.ActivateFromQueue(pubKey1.Address()); err != nil {
			t.Fatalf("ActivateFromQueue 1 failed: %v", err)
		}
		_, pubKey2 := createTestKeyPair(t)
		vm.AddValidator(pubKey2.Address(), pubKey2.Address(), pubKey2, stake2, 1000, 0)
		if err := vm.ActivateFromQueue(pubKey2.Address()); err != nil {
			t.Fatalf("ActivateFromQueue 2 failed: %v", err)
		}
		_, pubKey3 := createTestKeyPair(t)
		vm.AddValidator(pubKey3.Address(), pubKey3.Address(), pubKey3, stake3, 1000, 0)
		if err := vm.ActivateFromQueue(pubKey3.Address()); err != nil {
			t.Fatalf("ActivateFromQueue 3 failed: %v", err)
		}

		total := vm.TotalStake()
		if total.Cmp(expectedTotal) != 0 {
			t.Errorf("expected total stake %s, got %s", expectedTotal.String(), total.String())
		}
	})
}

// TestValidatorManager_ValidatorCount tests validator counting.
func TestValidatorManager_ValidatorCount(t *testing.T) {
	t.Parallel()

	t.Run("Empty returns zero", func(t *testing.T) {
		vm := NewValidatorManager()
		if vm.ValidatorCount() != 0 {
			t.Errorf("expected 0 validators, got %d", vm.ValidatorCount())
		}
	})

	t.Run("Count increments correctly", func(t *testing.T) {
		vm := NewValidatorManager()

		for i := 0; i < 5; i++ {
			_, pubKey := createTestKeyPair(t)
			vm.AddValidator(pubKey.Address(), pubKey.Address(), pubKey, validStake(), 1000, 0)
			if vm.ValidatorCount() != i+1 {
				t.Errorf("expected %d validators, got %d", i+1, vm.ValidatorCount())
			}
		}
	})
}

// TestValidatorManager_SetActive tests validator activation/deactivation.
func TestValidatorManager_SetActive(t *testing.T) {
	t.Parallel()

	// Note: SetActive requires system caller authorization
	t.Run("Non-system caller cannot set active status", func(t *testing.T) {
		vm := NewValidatorManager()
		_, pubKey := createTestKeyPair(t)
		addr := pubKey.Address()

		vm.AddValidator(addr, addr, pubKey, validStake(), 1000, 0)

		// Generate a different caller (not the validator itself)
		_, callerPubKey := createTestKeyPair(t)
		callerAddr := callerPubKey.Address()

		// Try to deactivate from non-system, non-self address
		err := vm.SetActive(callerAddr, addr, false)
		if err == nil {
			t.Error("expected error when non-system caller changes active status")
		}
	})
}
