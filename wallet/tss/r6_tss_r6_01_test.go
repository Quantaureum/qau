// Quantaureum Node source, version 1.0.0.
package tss

import (
	"os"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// TSS-R6-01 (2026-07-17) CLOSURE TESTS
//
// The audit finding TSS-R6-01 [High / ACTIVE] identified that the default DKG
// path (GenerateKeyShares) was trusted-dealer: it called
// qtd.GenerateDKGSharesShamir / qtd.GenerateDKGShares, which use
// mode3.NewKeyFromSeed to materialize the COMPLETE Dilithium3 private key in
// a single process before splitting. The dealer host briefly held the full
// private key in plaintext memory, defeating the threshold security goal at
// key-generation time.
//
// FIX: GenerateKeyShares() now delegates to qtd.GenerateDKGDistributedSimulated
// (renamed from GenerateDKGDistributed by TSS-R7-01), which has each
// participant independently sample s1_i/s2_i (no shared seed), aggregates
// them, computes t = A·s1 + s2, Shamir-splits the result, and sets
// CombinedSeed = nil. The legacy trusted-dealer path is moved to
// GenerateKeySharesTrustedDealer() and remains gated behind
// QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1.
//
// TSS-R7-01 CAVEAT: The "distributed" path is a single-process simulation
// (the caller holds all shares and can reconstruct the full key). The real
// P2P closure path is qtd.DistributedDKGRunner (dkg_runner.go). These
// closure tests verify the simulation's functional correctness; they do NOT
// verify real multi-party DKG, which requires a P2P transport implementation.
//
// These closure tests verify the fix is functional, not just structural:
//  1. The default path produces distributed DKG shares (CombinedSeed == nil).
//  2. The default path rejects threshold < 2.
//  3. The default path rejects Seed input.
//  4. The trusted-dealer path is gated by the env var.
//  5. The trusted-dealer path produces shares with CombinedSeed set
//     (negative confirmation that the two paths are genuinely distinct).
//  6. End-to-end threshold signing works with distributed-DKG shares.
//  7. TrustedDealerModeEnabled == false (constant reflects new default).

// TestTSS_R6_01_DefaultPathIsDistributed_DKG verifies that the default
// GenerateKeyShares() path produces distributed DKG shares, identifiable by
// CombinedSeed == nil. If CombinedSeed is non-nil, the path fell back to
// trusted-dealer, which would mean the fix is not actually in effect.
func TestTSS_R6_01_DefaultPathIsDistributed_DKG(t *testing.T) {
	cfg := TSSConfig{Threshold: 3, TotalShares: 5, SecurityLevel: 256}
	mgr, err := NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}

	shares, err := mgr.GenerateKeyShares()
	if err != nil {
		t.Fatalf("GenerateKeyShares (default distributed path) failed: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}
	defer mgr.ZeroizeAllShares()

	// SECURITY-CRITICAL ASSERTION: CombinedSeed MUST be nil.
	// This is the defining property distinguishing distributed DKG from
	// trusted-dealer. If CombinedSeed is non-nil, the dealer host held the
	// full private key seed, and TSS-R6-01 is NOT closed.
	mgr.mu.RLock()
	qtdPubKey := mgr.qtdPubKey
	mgr.mu.RUnlock()
	if qtdPubKey == nil {
		t.Fatal("qtdPubKey is nil after GenerateKeyShares")
	}
	if qtdPubKey.CombinedSeed != nil {
		t.Errorf("TSS-R6-01 NOT CLOSED: CombinedSeed must be nil for distributed DKG, got %d bytes — "+
			"the default path is still trusted-dealer", len(qtdPubKey.CombinedSeed))
	}

	// The public key must be a valid Dilithium3 public key.
	if len(qtdPubKey.PubKey) != mode3.PublicKeySize {
		t.Errorf("PubKey size: got %d, want %d", len(qtdPubKey.PubKey), mode3.PublicKeySize)
	}
}

// TestTSS_R6_01_DefaultPathRejectsThresholdBelow2 verifies that threshold < 2
// is rejected. A 1-of-n threshold puts the entire key in a single share,
// defeating the purpose of DKG.
//
// R33 CONS-05 FIX (2026-07-28): The rejection now happens at NewTSSManager
// (config validation layer), not at GenerateKeyShares. This is stronger —
// the threshold invariant is enforced before any key generation path is
// selected, closing the loophole where the trusted-dealer path could be
// used with T=1.
func TestTSS_R6_01_DefaultPathRejectsThresholdBelow2(t *testing.T) {
	cfg := TSSConfig{Threshold: 1, TotalShares: 1, SecurityLevel: 256}
	_, err := NewTSSManager(cfg)
	if err == nil {
		t.Fatal("NewTSSManager should reject threshold=1 — T=1 defeats TSS purpose (R33 CONS-05)")
	}
	if !strings.Contains(err.Error(), "threshold must be at least 2") {
		t.Errorf("error should mention 'threshold must be at least 2', got: %v", err)
	}
	t.Logf("threshold=1 correctly rejected at config validation: %v", err)
}

// TestTSS_R6_01_DefaultPathRejectsSeedInput verifies that the default
// distributed DKG path rejects deterministic Seed input. Distributed DKG
// requires that no single party controls the seed — if a seed is accepted,
// the path is NOT distributed.
func TestTSS_R6_01_DefaultPathRejectsSeedInput(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	cfg := TSSConfig{
		Threshold:     3,
		TotalShares:   5,
		SecurityLevel: 256,
		Seed:          seed,
	}
	mgr, err := NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}

	_, err = mgr.GenerateKeyShares()
	if err == nil {
		t.Fatal("GenerateKeyShares should fail when Seed is set — distributed DKG does not support seed input")
	}
	if !strings.Contains(err.Error(), "TSS-R6-01") {
		t.Errorf("error should reference TSS-R6-01, got: %v", err)
	}
	if !strings.Contains(err.Error(), "seed") {
		t.Errorf("error should mention 'seed', got: %v", err)
	}
}

// TestTSS_R6_01_TrustedDealerPathGatedByEnvVar verifies that the
// trusted-dealer path (GenerateKeySharesTrustedDealer) is blocked when
// QAU_ALLOW_TRUSTED_DEALER_CEREMONY is not set.
func TestTSS_R6_01_TrustedDealerPathGatedByEnvVar(t *testing.T) {
	saved := trustedDealerTestOverride
	trustedDealerTestOverride = nil
	defer func() { trustedDealerTestOverride = saved }()

	cfg := DefaultTSSConfig()
	mgr, err := NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}

	shares, err := mgr.GenerateKeySharesTrustedDealer()
	if err == nil {
		t.Fatal("GenerateKeySharesTrustedDealer should fail without QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1")
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

// TestTSS_R6_01_TrustedDealerProducesCombinedSeed verifies that the
// trusted-dealer path (when explicitly enabled) produces shares with
// CombinedSeed set — negative confirmation that the two paths are genuinely
// distinct, and that the CombinedSeed assertion in the distributed path test
// is meaningful (not just always nil).
func TestTSS_R6_01_TrustedDealerProducesCombinedSeed(t *testing.T) {
	// init() in tss_test.go enables the trusted-dealer override.
	cfg := TSSConfig{Threshold: 3, TotalShares: 5, SecurityLevel: 256}
	mgr, err := NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}

	if _, err := mgr.GenerateKeySharesTrustedDealer(); err != nil {
		t.Fatalf("GenerateKeySharesTrustedDealer: %v", err)
	}
	defer mgr.ZeroizeAllShares()

	mgr.mu.RLock()
	qtdPubKey := mgr.qtdPubKey
	mgr.mu.RUnlock()
	if qtdPubKey == nil {
		t.Fatal("qtdPubKey is nil after GenerateKeySharesTrustedDealer")
	}
	// Trusted-dealer DOES set CombinedSeed (this is what makes it risky).
	// If this assertion fails, the trusted-dealer path was silently changed
	// to not store the seed, which would break signWithCircl().
	if qtdPubKey.CombinedSeed == nil {
		t.Error("Trusted-dealer path should set CombinedSeed (it materializes the full key) — " +
			"if this is nil, the trusted-dealer path no longer produces seed-bearing shares")
	}
}

// TestTSS_R6_01_EndToEndSigningWithDistributedShares verifies that
// threshold signing works end-to-end with shares produced by the default
// distributed DKG path. This proves the fix is functional, not just
// structural — distributed-DKG shares can sign and verify.
func TestTSS_R6_01_EndToEndSigningWithDistributedShares(t *testing.T) {
	cfg := TSSConfig{Threshold: 3, TotalShares: 5, SecurityLevel: 256}
	mgr, err := NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}

	if _, err := mgr.GenerateKeyShares(); err != nil {
		t.Fatalf("GenerateKeyShares (distributed DKG) failed: %v", err)
	}
	defer mgr.ZeroizeAllShares()

	message := []byte("TSS-R6-01 regression: end-to-end signing with distributed DKG shares")
	participants := []int{1, 2, 3}

	sig, err := mgr.SignWithRetry(message, participants)
	if err != nil {
		t.Fatalf("SignWithRetry with distributed DKG shares failed: %v", err)
	}
	if len(sig) != 3293 && len(sig) != 4064 {
		t.Fatalf("unexpected signature size: %d (expected 3293 or 4064)", len(sig))
	}

	// Verify against the group public key.
	groupPK := mgr.GroupPublicKey()
	if len(groupPK) == 0 {
		t.Fatal("GroupPublicKey is empty after distributed DKG")
	}
	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

	switch len(sig) {
	case 3293:
		if !mode3.Verify(&pk, message, sig) {
			t.Fatal("3293-byte signature from distributed DKG shares FAILED verification")
		}
	case 4064:
		if !qtd.CheckGMQTDFullSignature(&pk, message, sig) {
			t.Fatal("4064-byte GM-QTD signature from distributed DKG shares FAILED verification")
		}
	}

	// Negative test: signature must NOT verify against a wrong message.
	wrongMessage := []byte("wrong-message-distributed-dkg")
	switch len(sig) {
	case 3293:
		if mode3.Verify(&pk, wrongMessage, sig) {
			t.Fatal("signature should NOT verify against wrong message")
		}
	case 4064:
		if qtd.CheckGMQTDFullSignature(&pk, wrongMessage, sig) {
			t.Fatal("signature should NOT verify against wrong message")
		}
	}
}

// TestTSS_R6_01_TrustedDealerModeEnabledFalse verifies that the
// TrustedDealerModeEnabled constant is FALSE, documenting that the default
// DKG path is distributed.
func TestTSS_R6_01_TrustedDealerModeEnabledFalse(t *testing.T) {
	if TrustedDealerModeEnabled {
		t.Error("TrustedDealerModeEnabled must be FALSE after TSS-R6-01 fix — " +
			"the default DKG is now distributed")
	}
}

// TestTSS_R6_01_GenerateKeySharesDistributedIsAlias verifies that the
// deprecated GenerateKeySharesDistributed() method still works as an alias
// for GenerateKeyShares(). This ensures backward compatibility for any
// callers that explicitly requested the distributed path before R6-01.
func TestTSS_R6_01_GenerateKeySharesDistributedIsAlias(t *testing.T) {
	cfg := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	mgr, err := NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}

	shares, err := mgr.GenerateKeySharesDistributed()
	if err != nil {
		t.Fatalf("GenerateKeySharesDistributed (deprecated alias) failed: %v", err)
	}
	if len(shares) != 3 {
		t.Errorf("expected 3 shares, got %d", len(shares))
	}
	defer mgr.ZeroizeAllShares()

	// Verify the alias produces distributed DKG output (CombinedSeed == nil).
	mgr.mu.RLock()
	qtdPubKey := mgr.qtdPubKey
	mgr.mu.RUnlock()
	if qtdPubKey == nil {
		t.Fatal("qtdPubKey is nil after GenerateKeySharesDistributed")
	}
	if qtdPubKey.CombinedSeed != nil {
		t.Errorf("GenerateKeySharesDistributed (alias) should produce CombinedSeed == nil, got %d bytes",
			len(qtdPubKey.CombinedSeed))
	}
}

// TestR33_CONS_05_ThresholdGe2EnforcedAtConfigLevel verifies that
// TSSConfig.Validate() rejects threshold < 2 uniformly, closing the
// R33 CONS-05 vulnerability where T=1 was accepted at config validation
// and only rejected by the distributed DKG path (leaving the trusted-dealer
// path open to T=1, which provides no threshold security).
func TestR33_CONS_05_ThresholdGe2EnforcedAtConfigLevel(t *testing.T) {
	cases := []struct {
		name      string
		threshold int
		wantErr   bool
	}{
		{"T=0 rejected", 0, true},
		{"T=1 rejected (R33 CONS-05)", 1, true},
		{"T=2 accepted (minimum secure)", 2, false},
		{"T=3 accepted", 3, false},
		{"T=5 accepted", 5, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := TSSConfig{Threshold: tc.threshold, TotalShares: 5, SecurityLevel: 256}
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("Validate() should reject threshold=%d", tc.threshold)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate() should accept threshold=%d, got: %v", tc.threshold, err)
			}
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "threshold must be at least 2") {
				t.Errorf("error should mention 'threshold must be at least 2', got: %v", err)
			}
		})
	}
}

// TestR33_CONS_08_ProductionModeBlocksSimulatedDKG verifies that
// GenerateKeyShares refuses to fall back to the simulated DKG path when
// QAU_PRODUCTION=1 is set and no DistributedDKGRunner is injected.
// The simulated path holds ALL shares in a single process, defeating
// threshold security at key-generation time.
func TestR33_CONS_08_ProductionModeBlocksSimulatedDKG(t *testing.T) {
	// Save and restore the environment variable.
	oldVal := os.Getenv("QAU_PRODUCTION")
	defer os.Setenv("QAU_PRODUCTION", oldVal)

	cfg := TSSConfig{Threshold: 3, TotalShares: 5, SecurityLevel: 256}
	mgr, err := NewTSSManager(cfg)
	if err != nil {
		t.Fatalf("NewTSSManager: %v", err)
	}

	// Ensure no runner is injected.
	if mgr.HasDistributedDKGRunner() {
		t.Skip("a DistributedDKGRunner is already injected; cannot test the no-runner path")
	}

	// Case 1: Production mode — must return an error.
	os.Setenv("QAU_PRODUCTION", "1")
	_, err = mgr.GenerateKeyShares()
	if err == nil {
		t.Fatal("R33 CONS-08: GenerateKeyShares should fail in production mode without a runner")
	}
	if !strings.Contains(err.Error(), "R33 CONS-08") {
		t.Errorf("error should reference R33 CONS-08, got: %v", err)
	}
	if !strings.Contains(err.Error(), "PRODUCTION") {
		t.Errorf("error should mention PRODUCTION, got: %v", err)
	}
	t.Logf("production mode correctly blocked simulated DKG: %v", err)

	// Case 2: Non-production mode — simulated fallback should work (with warning).
	os.Setenv("QAU_PRODUCTION", "")
	shares, err := mgr.GenerateKeyShares()
	if err != nil {
		t.Fatalf("non-production GenerateKeyShares should succeed via simulated fallback: %v", err)
	}
	if len(shares) != 5 {
		t.Errorf("expected 5 shares, got %d", len(shares))
	}
	defer mgr.ZeroizeAllShares()
	t.Log("non-production mode correctly allowed simulated DKG fallback")
}
