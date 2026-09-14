// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"strings"
	"testing"

	"github.com/quantaureum/qau/types"
)

// ============================================================================
// R23-014/R24-035: DeFi admin authentication fail-closed behavior
// ============================================================================

// TestDeFiAdminAuth_FailClosedWhenNotConfigured verifies that when
// enforceAdminAuth is enabled (production mode) and no admin allowlist has
// been configured, state-mutating DeFi operations are blocked.
func TestDeFiAdminAuth_FailClosedWhenNotConfigured(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(true)

	// No admin addresses configured - should fail-closed.
	err := api.verifyDeFiSignature("test", types.Address{1}, "nonce1", "params", "0x01", "0x02")
	if err == nil {
		t.Fatal("expected error when admin allowlist not configured in production mode")
	}
	if !strings.Contains(err.Error(), "authorized-user allowlist not configured") {
		t.Errorf("expected 'authorized-user allowlist not configured' error, got: %v", err)
	}
}

// TestDeFiAdminAuth_AuthorizedAddressPassesAdminCheck verifies that an
// authorized admin address passes the admin check, allowing the request to
// proceed to subsequent signature validation.
func TestDeFiAdminAuth_AuthorizedAddressPassesAdminCheck(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(true)

	adminAddr := types.Address{1}
	api.SetAdminAddresses([]types.Address{adminAddr})

	// Admin check passes, then signature validation fails on empty signature.
	err := api.verifyDeFiSignature("test", adminAddr, "nonce1", "params", "", "")
	if err == nil {
		t.Fatal("expected error for empty signature after admin check passes")
	}
	if strings.Contains(err.Error(), "admin allowlist") {
		t.Errorf("admin check should have passed, got admin error: %v", err)
	}
	if !strings.Contains(err.Error(), "signature and publicKey are required") {
		t.Errorf("expected signature validation error, got: %v", err)
	}
}

// TestDeFiAdminAuth_UnauthorizedAddressRejected verifies that a non-admin
// address is rejected even when an allowlist is configured.
func TestDeFiAdminAuth_UnauthorizedAddressRejected(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(true)

	adminAddr := types.Address{1}
	api.SetAdminAddresses([]types.Address{adminAddr})

	nonAdmin := types.Address{2}
	err := api.verifyDeFiSignature("test", nonAdmin, "nonce1", "params", "0x01", "0x02")
	if err == nil {
		t.Fatal("expected error for unauthorized address")
	}
	if !strings.Contains(err.Error(), "not in the authorized-user allowlist") {
		t.Errorf("expected 'not in the authorized-user allowlist' error, got: %v", err)
	}
}

// TestDeFiAdminAuth_BackwardCompatNoEnforcement verifies that when
// enforceAdminAuth is false (default), an empty allowlist does NOT block
// operations (backward-compatible with existing test/dev behavior).
func TestDeFiAdminAuth_BackwardCompatNoEnforcement(t *testing.T) {
	api := NewDeFiAPI(nil, nil)
	api.SetEnforceAdminAuth(false) // R25-003: explicitly disable for backward-compat test
	// enforceAdminAuth is now true by default (fail-closed).

	err := api.verifyDeFiSignature("test", types.Address{1}, "nonce1", "params", "", "")
	if err == nil {
		t.Fatal("expected error for empty signature (backward-compat mode)")
	}
	if strings.Contains(err.Error(), "admin allowlist") {
		t.Errorf("admin check should be skipped in backward-compat mode, got: %v", err)
	}
	if !strings.Contains(err.Error(), "signature and publicKey are required") {
		t.Errorf("expected signature validation error, got: %v", err)
	}
}

// ============================================================================
// R23-015: Staking admin authentication fail-closed behavior
// ============================================================================

// TestStakingAdminAuth_FailClosedWhenNotConfigured verifies that when
// enforceAdminAuth is enabled (production mode) and no admin allowlist has
// been configured, state-mutating staking operations are blocked.
func TestStakingAdminAuth_FailClosedWhenNotConfigured(t *testing.T) {
	api := newTestAPI()
	api.SetEnforceAdminAuth(true)

	err := api.verifyStakingSignature("test", types.Address{1}, "nonce1", "params", "0x01", "0x02")
	if err == nil {
		t.Fatal("expected error when admin allowlist not configured in production mode")
	}
	if !strings.Contains(err.Error(), "authorized-user allowlist not configured") {
		t.Errorf("expected 'authorized-user allowlist not configured' error, got: %v", err)
	}
}

// TestStakingAdminAuth_AuthorizedAddressPassesAdminCheck verifies that an
// authorized admin address passes the admin check, allowing the request to
// proceed to subsequent signature validation.
func TestStakingAdminAuth_AuthorizedAddressPassesAdminCheck(t *testing.T) {
	api := newTestAPI()
	api.SetEnforceAdminAuth(true)

	adminAddr := types.Address{1}
	api.SetAdminAddresses([]types.Address{adminAddr})

	err := api.verifyStakingSignature("test", adminAddr, "nonce1", "params", "", "")
	if err == nil {
		t.Fatal("expected error for empty signature after admin check passes")
	}
	if strings.Contains(err.Error(), "admin allowlist") {
		t.Errorf("admin check should have passed, got admin error: %v", err)
	}
	if !strings.Contains(err.Error(), "signature and publicKey are required") {
		t.Errorf("expected signature validation error, got: %v", err)
	}
}

// TestStakingAdminAuth_UnauthorizedAddressRejected verifies that a non-admin
// address is rejected even when an allowlist is configured.
func TestStakingAdminAuth_UnauthorizedAddressRejected(t *testing.T) {
	api := newTestAPI()
	api.SetEnforceAdminAuth(true)

	adminAddr := types.Address{1}
	api.SetAdminAddresses([]types.Address{adminAddr})

	nonAdmin := types.Address{2}
	err := api.verifyStakingSignature("test", nonAdmin, "nonce1", "params", "0x01", "0x02")
	if err == nil {
		t.Fatal("expected error for unauthorized address")
	}
	if !strings.Contains(err.Error(), "not in the authorized-user allowlist") {
		t.Errorf("expected 'not in the authorized-user allowlist' error, got: %v", err)
	}
}

// TestStakingAdminAuth_BackwardCompatNoEnforcement verifies that when
// enforceAdminAuth is false (default), an empty allowlist does NOT block
// operations (backward-compatible with existing test/dev behavior).
func TestStakingAdminAuth_BackwardCompatNoEnforcement(t *testing.T) {
	api := newTestAPI()
	api.SetEnforceAdminAuth(false) // R25-004: explicitly disable for backward-compat test
	// enforceAdminAuth is now true by default (fail-closed).

	err := api.verifyStakingSignature("test", types.Address{1}, "nonce1", "params", "", "")
	if err == nil {
		t.Fatal("expected error for empty signature (backward-compat mode)")
	}
	if strings.Contains(err.Error(), "admin allowlist") {
		t.Errorf("admin check should be skipped in backward-compat mode, got: %v", err)
	}
	if !strings.Contains(err.Error(), "signature and publicKey are required") {
		t.Errorf("expected signature validation error, got: %v", err)
	}
}
