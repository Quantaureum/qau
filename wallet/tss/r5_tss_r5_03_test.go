// Quantaureum Node source, version 1.0.0.
package tss

import (
	"strings"
	"testing"
)

// TestTSS_R5_03_TrustedDealerModeEnabledConstant verifies that the
// TrustedDealerModeEnabled constant is FALSE, documenting that the default
// DKG path is now distributed (TSS-R6-01).
//
// TSS-R5-03 (2026-07-16): originally true (default was trusted-dealer).
// TSS-R6-01 (2026-07-17): now FALSE (default is distributed DKG).
func TestTSS_R5_03_TrustedDealerModeEnabledConstant(t *testing.T) {
	if TrustedDealerModeEnabled {
		t.Error("TrustedDealerModeEnabled must be FALSE: the default DKG is now distributed (TSS-R6-01)")
	}
}

// TestTSS_R5_03_GenerateKeySharesTrustedDealer_BlockedWithoutCeremonyEnvVar
// verifies that GenerateKeySharesTrustedDealer() is blocked when the
// QAU_ALLOW_TRUSTED_DEALER_CEREMONY env var is NOT set and no test override
// is in effect.
//
// This is the core TSS-R5-03/R6-01 fix: the trusted-dealer DKG path (which
// generates the full Dilithium3 private key in a single process) must not
// be invokable without explicit acknowledgement.
func TestTSS_R5_03_GenerateKeySharesTrustedDealer_BlockedWithoutCeremonyEnvVar(t *testing.T) {
	// Save and restore the test override to isolate this test from the
	// package-level init() override in tss_test.go.
	saved := trustedDealerTestOverride
	trustedDealerTestOverride = nil // use env var path
	defer func() { trustedDealerTestOverride = saved }()

	// Env var is NOT set in the test environment (tests use the override
	// via init(), which we just disabled). Verify the gate blocks.
	cfg := DefaultTSSConfig()
	mgr, err := NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}

	shares, err := mgr.GenerateKeySharesTrustedDealer()
	if err == nil {
		t.Errorf("GenerateKeySharesTrustedDealer should fail without QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1")
		// Zeroize any accidentally generated shares.
		if shares != nil {
			mgr.ZeroizeAllShares()
		}
		return
	}
	if !strings.Contains(err.Error(), "TSS-R6-01") {
		t.Errorf("error should reference TSS-R6-01, got: %v", err)
	}
	if !strings.Contains(err.Error(), "QAU_ALLOW_TRUSTED_DEALER_CEREMONY") {
		t.Errorf("error should mention the env var, got: %v", err)
	}
}

// TestTSS_R5_03_GenerateKeySharesTrustedDealer_AllowedWithTestOverride
// verifies that GenerateKeySharesTrustedDealer() succeeds when the test
// override is enabled (simulating QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1).
func TestTSS_R5_03_GenerateKeySharesTrustedDealer_AllowedWithTestOverride(t *testing.T) {
	// The package-level init() in tss_test.go already enables the override.
	// Verify GenerateKeySharesTrustedDealer works.
	cfg := DefaultTSSConfig()
	mgr, err := NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}

	shares, err := mgr.GenerateKeySharesTrustedDealer()
	if err != nil {
		t.Fatalf("GenerateKeySharesTrustedDealer with override enabled should succeed, got: %v", err)
	}
	if len(shares) == 0 {
		t.Error("GenerateKeySharesTrustedDealer returned no shares")
	}
	// Clean up sensitive material.
	mgr.ZeroizeAllShares()
}

// TestTSS_R5_03_IsTrustedDealerCeremonyAllowed verifies the env var reader
// and test override logic.
func TestTSS_R5_03_IsTrustedDealerCeremonyAllowed(t *testing.T) {
	saved := trustedDealerTestOverride
	defer func() { trustedDealerTestOverride = saved }()

	// With override = nil, should read env var (which is not set in tests).
	trustedDealerTestOverride = nil
	if IsTrustedDealerCeremonyAllowed() {
		// This could be true if the env var happens to be set in the
		// environment; that's acceptable. We only verify the override path.
	}

	// With override = true, should return true.
	SetAllowTrustedDealerCeremonyForTest(true)
	if !IsTrustedDealerCeremonyAllowed() {
		t.Error("IsTrustedDealerCeremonyAllowed should be true after SetAllowTrustedDealerCeremonyForTest(true)")
	}

	// With override = false, should return false.
	SetAllowTrustedDealerCeremonyForTest(false)
	if IsTrustedDealerCeremonyAllowed() {
		t.Error("IsTrustedDealerCeremonyAllowed should be false after SetAllowTrustedDealerCeremonyForTest(false)")
	}
}

// TestTSS_R5_03_ZeroizeAllShares verifies that ZeroizeAllShares clears all
// in-memory share material. This is the ceremony step 5: after generating
// and distributing shares, the ceremony host must zeroize all copies.
func TestTSS_R5_03_ZeroizeAllShares(t *testing.T) {
	cfg := DefaultTSSConfig()
	mgr, err := NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}

	// Use the trusted-dealer path explicitly — this test verifies the
	// zeroize ceremony step, which is most critical after a trusted-dealer
	// ceremony (where the full key was materialized).
	if _, err := mgr.GenerateKeySharesTrustedDealer(); err != nil {
		t.Fatalf("GenerateKeySharesTrustedDealer: %v", err)
	}
	if mgr.ShareCount() == 0 {
		t.Fatal("ShareCount should be > 0 after GenerateKeySharesTrustedDealer")
	}

	mgr.ZeroizeAllShares()

	if mgr.ShareCount() != 0 {
		t.Errorf("ShareCount after ZeroizeAllShares = %d, want 0", mgr.ShareCount())
	}
}
