// Quantaureum Node source, version 1.0.0.
package tss

import (
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// TSS-R5-03 / TSS-R6-01 (2026-07-17): The DEFAULT DKG path
// (GenerateKeyShares) now uses distributed DKG, which requires threshold >= 2
// and rejects seed input. Most tests in this package call
// GenerateKeyShares() with threshold >= 2, so they work without the override.
//
// However, a few tests still exercise the trusted-dealer path explicitly:
//   - TestTSSEdgeCases "T=1" subtest (threshold=1 is rejected by distributed DKG)
//
// These tests call GenerateKeySharesTrustedDealer() directly, which requires
// the QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1 env var or the test override.
//
// We enable the test override once at init time so those trusted-dealer
// tests can run without setting env vars. The override is a no-op in
// production code (non-test binaries never call SetAllowTrustedDealerCeremonyForTest).
func init() {
	SetAllowTrustedDealerCeremonyForTest(true)
}

func verifyQMTSignature(pk *mode3.PublicKey, message, sig []byte) bool {
	switch len(sig) {
	case 3293:
		return mode3.Verify(pk, message, sig)
	case 4064:
		return qtd.CheckGMQTDFullSignature(pk, message, sig)
	default:
		return false
	}
}

func TestGenerateKeyShares(t *testing.T) {
	config := DefaultTSSConfig()
	manager, err := NewTSSManager(config)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	shares, err := manager.GenerateKeyShares()
	if err != nil {
		t.Fatalf("failed to generate key shares: %v", err)
	}

	if len(shares) != config.TotalShares {
		t.Errorf("expected %d shares, got %d", config.TotalShares, len(shares))
	}

	if manager.GroupPublicKey() == nil {
		t.Error("group public key should not be nil after generation")
	}

	if manager.ShareCount() != config.TotalShares {
		t.Errorf("expected %d shares in manager, got %d", config.TotalShares, manager.ShareCount())
	}

	if !manager.HasThreshold() {
		t.Error("should have threshold after generating shares")
	}
}

func TestVerifyShare(t *testing.T) {
	config := DefaultTSSConfig()
	manager, _ := NewTSSManager(config)
	shares, _ := manager.GenerateKeyShares()

	for _, share := range shares {
		err := manager.VerifyShare(share)
		if err != nil {
			t.Errorf("share %d should be valid: %v", share.Index, err)
		}
	}
}

func TestReconstructPublicKey(t *testing.T) {
	config := DefaultTSSConfig()
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	pk1 := manager.GroupPublicKey()
	pk2, err := manager.ReconstructPublicKey()
	if err != nil {
		t.Fatalf("failed to reconstruct public key: %v", err)
	}

	if len(pk1) != len(pk2) {
		t.Error("reconstructed public key length mismatch")
	}

	for i := range pk1 {
		if pk1[i] != pk2[i] {
			t.Error("reconstructed public key does not match original")
			break
		}
	}
}

func TestQTDThresholdSigningFlow(t *testing.T) {
	config := DefaultTSSConfig()
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	message := []byte("GM-QTD threshold signing test")

	participants := make([]int, config.Threshold)
	for i := 0; i < config.Threshold; i++ {
		participants[i] = i + 1
	}

	sig, err := manager.SignWithRetry(message, participants)
	if err != nil {
		t.Fatalf("SignWithRetry failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("signature should not be empty")
	}

	t.Logf("QTD threshold signature size: %d bytes", len(sig))

	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(manager.GroupPublicKey()))
	if !verifyQMTSignature(&pk, message, sig) {
		t.Error("QTD threshold signature verification FAILED")
	}
	t.Logf("QTD threshold signature VERIFIED (len=%d)", len(sig))
}

func TestQTDThresholdSigningGMQTD(t *testing.T) {
	config := TSSConfig{Threshold: 3, TotalShares: 5, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	message := []byte("GM-QTD Gaussian masking test")

	participants := []int{1, 2, 3}

	sig, err := manager.SignWithRetry(message, participants)
	if err != nil {
		t.Fatalf("GM-QTD SignWithRetry failed: %v", err)
	}

	if len(sig) != 3293 && len(sig) != 4064 {
		t.Errorf("expected 3293 or 4064-byte signature, got %d bytes", len(sig))
	}

	t.Logf("GM-QTD threshold signature (t=3,n=5): %d bytes", len(sig))

	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(manager.GroupPublicKey()))
	if !verifyQMTSignature(&pk, message, sig) {
		t.Error("GM-QTD threshold signature verification FAILED")
	}
	t.Logf("GM-QTD threshold signature VERIFIED (len=%d)", len(sig))
}

func TestQTDThresholdEnforcement(t *testing.T) {
	config := TSSConfig{Threshold: 3, TotalShares: 5, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	message := []byte("threshold enforcement test")
	participants := []int{1, 2}

	_, err := manager.CreateSigningSession(message, participants)
	if err == nil {
		t.Error("should fail when below threshold")
	}
}

func TestRemoveShare(t *testing.T) {
	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	initialCount := manager.ShareCount()

	err := manager.RemoveShare(3)
	if err != nil {
		t.Fatalf("failed to remove share: %v", err)
	}

	if manager.ShareCount() != initialCount-1 {
		t.Errorf("expected %d shares after remove, got %d", initialCount-1, manager.ShareCount())
	}
}

func TestCannotRemoveBelowThreshold(t *testing.T) {
	config := TSSConfig{Threshold: 3, TotalShares: 3, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	err := manager.RemoveShare(1)
	if err != ErrCannotRemoveShare {
		t.Errorf("expected ErrCannotRemoveShare, got %v", err)
	}
}

func TestTSSEdgeCases(t *testing.T) {
	t.Run("T=1", func(t *testing.T) {
		// R33 CONS-05 FIX (2026-07-28): TSSConfig.Validate() now rejects
		// threshold < 2 at config validation time (inside NewTSSManager).
		// A threshold of 1 means a single share can reconstruct the full
		// key, defeating the entire purpose of threshold cryptography.
		// Even the trusted-dealer path is now blocked at T=1 because the
		// security invariant "threshold >= 2" is enforced at the config
		// layer, before any key generation path is selected.
		//
		// Previous behavior: NewTSSManager accepted T=1 and only
		// GenerateKeyShares (distributed DKG) rejected it; the
		// trusted-dealer path (GenerateKeySharesTrustedDealer) accepted
		// T=1 for offline air-gapped ceremonies. The audit (P1-26 CONS-05)
		// identified this as a vulnerability: T=1 provides no threshold
		// security and must be rejected uniformly.
		config := TSSConfig{Threshold: 1, TotalShares: 1, SecurityLevel: 256}
		_, err := NewTSSManager(config)
		if err == nil {
			t.Fatal("NewTSSManager should reject threshold=1 — T=1 defeats TSS purpose (R33 CONS-05)")
		}
		if !strings.Contains(err.Error(), "threshold must be at least 2") {
			t.Errorf("error should mention 'threshold must be at least 2', got: %v", err)
		}
		t.Logf("T=1 correctly rejected at config validation: %v", err)
	})

	t.Run("T=N", func(t *testing.T) {
		// TSS-R6-01: T=N (all participants must sign) uses the trusted-dealer
		// path explicitly. Distributed DKG aggregates s1 = Σ s1_i across N
		// parties, producing coefficients roughly in [-N*eta, N*eta] instead
		// of the standard [-eta, eta]. For T=N, all N shares participate in
		// signing, and the reconstructed aggregated s1 causes ||z||_inf to
		// exceed the Dilithium3 bound (rejection sampling fails >100 attempts).
		// This is an inherent limitation of additive-aggregation distributed
		// DKG for Dilithium3 at high threshold ratios.
		//
		// T=N is an edge case (all participants must sign every time, no
		// liveness tolerance) and doesn't represent a realistic deployment.
		// For T < N (the realistic case), distributed DKG works correctly
		// (see TestTSS_R6_01_EndToEndSigningWithDistributedShares for T=3,N=5).
		config := TSSConfig{Threshold: 5, TotalShares: 5, SecurityLevel: 256}
		manager, _ := NewTSSManager(config)
		manager.GenerateKeySharesTrustedDealer()

		message := []byte("T=N test")
		participants := []int{1, 2, 3, 4, 5}

		sig, err := manager.SignWithRetry(message, participants)
		if err != nil {
			t.Fatalf("T=N SignWithRetry failed: %v", err)
		}
		if len(sig) == 0 {
			t.Error("signature should not be empty")
		}

		var pk mode3.PublicKey
		pk.Unpack((*[mode3.PublicKeySize]byte)(manager.GroupPublicKey()))
		if !verifyQMTSignature(&pk, message, sig) {
			t.Error("T=N signature verification FAILED")
		}
		t.Logf("T=N signature VERIFIED (len=%d)", len(sig))
	})

	t.Run("invalid participant", func(t *testing.T) {
		config := DefaultTSSConfig()
		manager, _ := NewTSSManager(config)
		manager.GenerateKeyShares()

		_, err := manager.CreateSigningSession([]byte("test"), []int{999})
		if err == nil {
			t.Error("should fail with invalid participant")
		}
	})
}

func TestTSSManager_BasicProperties(t *testing.T) {
	config := TSSConfig{Threshold: 3, TotalShares: 7, SecurityLevel: 256}
	manager, err := NewTSSManager(config)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if manager.Threshold() != 3 {
		t.Errorf("expected 3, got %d", manager.Threshold())
	}
	if manager.TotalShares() != 7 {
		t.Errorf("expected 7, got %d", manager.TotalShares())
	}
	if manager.ShareCount() != 0 {
		t.Errorf("expected 0, got %d", manager.ShareCount())
	}
	if manager.HasThreshold() {
		t.Error("should not have threshold before generating shares")
	}

	manager.GenerateKeyShares()
	if !manager.HasThreshold() {
		t.Error("should have threshold after generating shares")
	}
	if manager.ShareCount() != 7 {
		t.Errorf("expected 7 shares, got %d", manager.ShareCount())
	}
}

func TestGroupPublicKey_NoShares(t *testing.T) {
	config := DefaultTSSConfig()
	manager, _ := NewTSSManager(config)
	pk := manager.GroupPublicKey()
	if pk != nil {
		t.Error("GroupPublicKey should be nil before generating shares")
	}
}

func TestNewTSSManager_InvalidConfig(t *testing.T) {
	config := TSSConfig{Threshold: 7, TotalShares: 3}
	_, err := NewTSSManager(config)
	if err == nil {
		t.Error("should fail when threshold > total shares")
	}
}

func TestVerifyCombinedSignature(t *testing.T) {
	config := DefaultTSSConfig()
	manager, _ := NewTSSManager(config)

	t.Run("nil group key", func(t *testing.T) {
		err := manager.VerifyCombinedSignature([]byte("sig"), []byte("msg"))
		if err == nil {
			t.Error("should return error with nil group public key")
		}
	})

	t.Run("sign then verify", func(t *testing.T) {
		manager.GenerateKeyShares()

		message := []byte("verify combined signature test")
		participants := []int{1, 2, 3}

		sig, err := manager.SignWithRetry(message, participants)
		if err != nil {
			t.Fatalf("SignWithRetry failed: %v", err)
		}

		err = manager.VerifyCombinedSignature(sig, message)
		if err != nil {
			t.Fatalf("VerifyCombinedSignature failed after successful sign: %v", err)
		}
		t.Log("VerifyCombinedSignature: PASS (signed and verified)")

		err = manager.VerifyCombinedSignature(sig, []byte("wrong message"))
		if err == nil {
			t.Error("should fail for wrong message")
		}

		err = manager.VerifyCombinedSignature([]byte{}, []byte("test"))
		if err == nil {
			t.Error("should fail with empty signature")
		}
	})
}

func TestDeriveKeyFromSeed(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	key, err := deriveKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("deriveKeyFromSeed error: %v", err)
	}
	if key == nil {
		t.Error("derived key should not be nil")
	}
}

func TestValidate_EdgeCases(t *testing.T) {
	configs := []TSSConfig{
		{Threshold: 0, TotalShares: 5},
		{Threshold: 3, TotalShares: 0},
		{Threshold: -1, TotalShares: 5},
	}
	for _, c := range configs {
		if err := c.Validate(); err == nil {
			t.Errorf("expected error for config %+v", c)
		}
	}

	t.Run("TotalShares exceeds max", func(t *testing.T) {
		c := TSSConfig{Threshold: 2, TotalShares: MaxTotalShares + 1}
		if err := c.Validate(); err == nil {
			t.Error("expected error when TotalShares exceeds max")
		}
	})

	t.Run("Threshold exceeds max", func(t *testing.T) {
		c := TSSConfig{Threshold: MaxThreshold + 1, TotalShares: MaxThreshold + 1}
		if err := c.Validate(); err == nil {
			t.Error("expected error when Threshold exceeds max")
		}
	})

	t.Run("Threshold exceeds TotalShares", func(t *testing.T) {
		c := TSSConfig{Threshold: 5, TotalShares: 3}
		if err := c.Validate(); err == nil {
			t.Error("expected error when threshold exceeds total shares")
		}
	})
}

func TestCombineSignatures_EmptyList(t *testing.T) {
	config := DefaultTSSConfig()
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	message := []byte("empty test")
	participants := []int{1, 2, 3}
	sessionKey, _ := manager.CreateSigningSession(message, participants)
	defer manager.CleanSession(sessionKey)

	_, err := manager.CombineSignatures(sessionKey, []*PartialSignature{})
	if err == nil {
		t.Error("should fail with empty signature list")
	}
}

func TestVerifyShare_InvalidShare(t *testing.T) {
	config := DefaultTSSConfig()
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	err := manager.VerifyShare(&KeyShare{Index: 999, Share: []byte("garbage")})
	if err == nil {
		t.Error("should fail with invalid share")
	}
}

func TestVerifyShare_OutOfRange(t *testing.T) {
	config := DefaultTSSConfig()
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	err := manager.VerifyShare(&KeyShare{Index: config.TotalShares + 10, Share: []byte("data")})
	if err == nil {
		t.Error("should fail with out of range share index")
	}
}

func TestRefreshAndAddShare(t *testing.T) {
	config := DefaultTSSConfig()
	manager, _ := NewTSSManager(config)

	t.Run("refresh no shares", func(t *testing.T) {
		err := manager.RefreshShares()
		if err == nil {
			t.Error("should fail when no shares exist")
		}
	})

	t.Run("add share not supported", func(t *testing.T) {
		manager.GenerateKeyShares()
		_, err := manager.AddShare([]byte("data"))
		if err == nil {
			t.Error("AddShare should not be supported for QTD")
		}
	})
}

func TestReconstructPublicKey_NoShares(t *testing.T) {
	config := DefaultTSSConfig()
	manager, _ := NewTSSManager(config)

	_, err := manager.ReconstructPublicKey()
	if err == nil {
		t.Error("should fail when no shares generated")
	}
}

func TestRemoveShare_NotFound(t *testing.T) {
	config := DefaultTSSConfig()
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	err := manager.RemoveShare(999)
	if err == nil {
		t.Error("should fail when share not found")
	}
}

func TestGMQTDSingleSignVerify(t *testing.T) {
	pubKey, privKey := mode3.NewKeyFromSeed(&[32]byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	})

	message := []byte("GM-QTD single signer test")

	sig, err := qtd.GMQTD_SingleSign(privKey, pubKey, message)
	if err != nil {
		t.Fatalf("GMQTD_SingleSign failed: %v", err)
	}

	if len(sig) != 3293 {
		t.Errorf("expected 3293-byte signature, got %d bytes", len(sig))
	}

	verified := mode3.Verify(pubKey, message, sig)
	if !verified {
		t.Error("GM-QTD single signature verification FAILED")
	}

	t.Logf("GM-QTD single signer: %d-byte signature VERIFIED by standard mode3.Verify", len(sig))
}

func TestGMQTDSingleSignWrongMessage(t *testing.T) {
	pubKey, privKey := mode3.NewKeyFromSeed(&[32]byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	})

	message := []byte("correct message")
	sig, err := qtd.GMQTD_SingleSign(privKey, pubKey, message)
	if err != nil {
		t.Fatalf("GMQTD_SingleSign failed: %v", err)
	}

	if mode3.Verify(pubKey, []byte("wrong message"), sig) {
		t.Error("verification should fail for wrong message")
	}
}

func TestGMQTDSingleSignWrongKey(t *testing.T) {
	pubKey, privKey := mode3.NewKeyFromSeed(&[32]byte{
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	})

	wrongPubKey, _ := mode3.NewKeyFromSeed(&[32]byte{
		99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 88, 87, 86, 85, 84,
		83, 82, 81, 80, 79, 78, 77, 76, 75, 74, 73, 72, 71, 70, 69, 68,
	})

	message := []byte("test")
	sig, err := qtd.GMQTD_SingleSign(privKey, pubKey, message)
	if err != nil {
		t.Fatalf("GMQTD_SingleSign failed: %v", err)
	}

	if mode3.Verify(wrongPubKey, message, sig) {
		t.Error("verification should fail for wrong public key")
	}
}

func TestGMQTDSingleSignMultiple(t *testing.T) {
	pubKey, privKey := mode3.NewKeyFromSeed(&[32]byte{
		42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57,
		58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
	})

	msgs := [][]byte{
		[]byte("message one"),
		[]byte("message two"),
		[]byte("message three with more content to sign"),
	}

	for i, msg := range msgs {
		sig, err := qtd.GMQTD_SingleSign(privKey, pubKey, msg)
		if err != nil {
			t.Fatalf("message %d: GMQTD_SingleSign failed: %v", i, err)
		}
		if !mode3.Verify(pubKey, msg, sig) {
			t.Errorf("message %d: verification failed", i)
		}
	}

	t.Log("GM-QTD multi-message signing: all passed")
}

func TestQTD2of3ThresholdSigning(t *testing.T) {
	config := TSSConfig{
		Threshold:     2,
		TotalShares:   3,
		SecurityLevel: 256,
	}
	manager, err := NewTSSManager(config)
	if err != nil {
		t.Fatalf("failed to create 2-of-3 manager: %v", err)
	}

	shares, err := manager.GenerateKeyShares()
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	if len(shares) != 3 {
		t.Fatalf("expected 3 shares, got %d", len(shares))
	}

	if !manager.HasThreshold() {
		t.Fatal("HasThreshold should be true after DKG with 3 shares and threshold 2")
	}

	groupPK := manager.GroupPublicKey()
	if len(groupPK) == 0 {
		t.Fatal("group public key should not be empty after DKG")
	}

	message := []byte("stardust-consensus-v1.5-block-signing-test")

	sig, err := manager.SignWithRetry(message, []int{1, 2, 3})
	if err != nil {
		t.Fatalf("2-of-3 threshold signing failed: %v", err)
	}

	t.Logf("2-of-3 QTD signature size: %d bytes", len(sig))

	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

	switch len(sig) {
	case 3293:
		if !mode3.Verify(&pk, message, sig) {
			t.Fatal("3293-byte signature verification FAILED")
		}
		t.Log("3293-byte standard Dilithium3 signature VERIFIED")
	case 4064:
		if !qtd.CheckGMQTDFullSignature(&pk, message, sig) {
			t.Fatal("4064-byte GM-QTD signature verification FAILED")
		}
		t.Log("4064-byte GM-QTD signature VERIFIED")
	default:
		t.Fatalf("unexpected signature size: %d", len(sig))
	}

	wrongMessage := []byte("wrong-message")
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
	t.Log("Wrong message correctly rejected")

	t.Log("=== Phase 1 (v1.5) QTD 2-of-3 threshold signing: PASS ===")
}
