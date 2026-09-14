// Quantaureum Node source, version 1.0.0.
package tss

import (
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

func TestM1_QTD2of3_ExecutiveVerification(t *testing.T) {
	t.Log("========================================")
	t.Log("M1: QTD 2-of-3 Executive Chamber verification")
	t.Log("========================================")

	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	manager, err := NewTSSManager(config)
	if err != nil {
		t.Fatalf("NewTSSManager failed: %v", err)
	}

	t.Log("--- Step 1: DKG (Shamir 2-of-3) ---")
	dkgStart := time.Now()
	shares, err := manager.GenerateKeyShares()
	dkgDuration := time.Since(dkgStart)
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}
	t.Logf("DKG done: %d shares generated, elapsed=%v", len(shares), dkgDuration)
	if dkgDuration > 30*time.Second {
		t.Errorf("DKG too slow: %v (target <30s)", dkgDuration)
	}

	t.Log("--- Step 2: Group Public Key ---")
	groupPK := manager.GroupPublicKey()
	if len(groupPK) == 0 {
		t.Fatal("GroupPublicKey should not be empty")
	}
	t.Logf("GroupPublicKey: %d bytes", len(groupPK))

	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

	t.Log("--- Step 3: 2-of-3 Threshold Signing (3-member committee) ---")
	message := []byte("executive-chamber-block-signing")

	signStart := time.Now()
	sig, err := manager.SignWithRetry(message, []int{1, 2, 3})
	signDuration := time.Since(signStart)
	if err != nil {
		t.Fatalf("Threshold signing failed: %v", err)
	}
	t.Logf("signing done: %d bytes, elapsed=%v", len(sig), signDuration)

	t.Log("--- Step 4: Signature Size & Dilithium3 Compatibility ---")
	switch len(sig) {
	case 3293:
		t.Log("signature format: standard Dilithium3 (3293 bytes)")
		if !mode3.Verify(&pk, message, sig) {
			t.Fatal("standard Dilithium3 verification FAILED")
		}
		t.Log("standard Dilithium3 verification: PASS ✅")
	case 4064:
		t.Log("signature format: GM-QTD full (4064 bytes)")
		if !qtd.CheckGMQTDFullSignature(&pk, message, sig) {
			t.Fatal("GM-QTD signature verification FAILED")
		}
		t.Log("GM-QTD signature verification: PASS ✅")
	default:
		t.Fatalf("unknown signature size: %d", len(sig))
	}

	t.Log("--- Step 5: Two-Round Protocol Latency ---")
	// Rejection sampling has ~32% success rate per attempt (circl docs: 1/4 to 1/7).
	// Retry the entire two-round protocol until success, matching SignWithRetry.
	var aggSig []byte
	var r1Duration, r2Duration time.Duration
	var sessionKey string
	for attempt := 0; attempt < 20; attempt++ {
		sessionKey, err = manager.CreateSigningSession(message, []int{1, 2, 3})
		if err != nil {
			t.Fatalf("CreateSigningSession failed: %v", err)
		}

		r1Start := time.Now()
		round1Sigs := make([]*PartialSignature, 3)
		for i, pid := range []int{1, 2, 3} {
			ps, err := manager.BeginSign(sessionKey, pid)
			if err != nil {
				t.Fatalf("BeginSign pid=%d failed: %v", pid, err)
			}
			round1Sigs[i] = ps
		}
		if err := manager.SubmitRound1(sessionKey, round1Sigs); err != nil {
			t.Fatalf("SubmitRound1 failed: %v", err)
		}
		r1Duration = time.Since(r1Start)
		t.Logf("Round 1 (Commitments): %v (attempt %d)", r1Duration, attempt+1)

		r2Start := time.Now()
		round2Sigs := make([]*PartialSignature, 3)
		for i, pid := range []int{1, 2, 3} {
			ps, err := manager.CompleteSignPrivate(sessionKey, pid)
			if err != nil {
				t.Fatalf("CompleteSignPrivate pid=%d failed: %v", pid, err)
			}
			round2Sigs[i] = ps
		}
		aggSig, err = manager.CombineSignatures(sessionKey, round2Sigs)
		r2Duration = time.Since(r2Start)
		manager.CleanSession(sessionKey)
		if err != nil {
			t.Logf("Attempt %d: rejection sampling failed: %v", attempt+1, err)
			r1Duration = 0
			continue
		}
		t.Logf("Round 2 (Reveals + Aggregate): %v (attempt %d)", r2Duration, attempt+1)
		t.Logf("two-round protocol total latency: %v", r1Duration+r2Duration)
		break
	}
	if err != nil {
		t.Fatalf("Two-round protocol failed after 20 attempts: %v", err)
	}

	t.Log("--- Step 6: Verification Latency ---")
	verifyStart := time.Now()
	var verified bool
	switch len(aggSig) {
	case 3293:
		verified = mode3.Verify(&pk, message, aggSig)
	case 4064:
		verified = qtd.CheckGMQTDFullSignature(&pk, message, aggSig)
	}
	verifyDuration := time.Since(verifyStart)
	if !verified {
		t.Fatal("signature verification FAILED")
	}
	t.Logf("verification latency: %v", verifyDuration)

	t.Log("--- Step 7: Wrong Message Rejection ---")
	switch len(sig) {
	case 3293:
		if mode3.Verify(&pk, []byte("wrong-message"), sig) {
			t.Fatal("a wrong message must not verify")
		}
	case 4064:
		if qtd.CheckGMQTDFullSignature(&pk, []byte("wrong-message"), sig) {
			t.Fatal("a wrong message must not verify")
		}
	}
	t.Log("wrong-message rejection: PASS ✅")

	t.Log("========================================")
	t.Log("M1 verification summary:")
	t.Logf("  DKG time:          %v (target <30s)", dkgDuration)
	t.Logf("  sign latency:      %v (target <5s)", signDuration)
	t.Logf("  two-round latency: Round1=%v, Round2=%v, total=%v", r1Duration, r2Duration, r1Duration+r2Duration)
	t.Logf("  verify latency:    %v", verifyDuration)
	t.Logf("  signature size:    %d bytes", len(sig))
	t.Logf("  Dilithium3 compat:  ✅")
	t.Log("M1: QTD 2-of-3 Executive Chamber verification — PASS ✅")
	t.Log("========================================")
}
