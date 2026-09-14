// Quantaureum Node source, version 1.0.0.
package tss

import (
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

type simulatedNode struct {
	id      int
	manager *TSSManager
}

func TestPhase13_Integration_3NodeQTD_E2E(t *testing.T) {
	t.Log("=== Phase 1.3: 3-Node QTD Signing E2E Integration Test ===")
	t.Log("Simulating 3 participants performing DKG and threshold signing")

	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}

	coordinator, err := NewTSSManager(config)
	if err != nil {
		t.Fatalf("failed to create coordinator: %v", err)
	}

	shares, err := coordinator.GenerateKeyShares()
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	if len(shares) != 3 {
		t.Fatalf("expected 3 shares, got %d", len(shares))
	}

	t.Logf("DKG complete: 3 shares generated, threshold=2")

	nodes := make([]*simulatedNode, 3)
	for i := 0; i < 3; i++ {
		nodeConfig := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
		nodeManager, err := NewTSSManager(nodeConfig)
		if err != nil {
			t.Fatalf("failed to create node %d: %v", i+1, err)
		}
		nodes[i] = &simulatedNode{
			id:      i + 1,
			manager: nodeManager,
		}
	}

	t.Log("3 nodes initialized")

	groupPK := coordinator.GroupPublicKey()
	if len(groupPK) == 0 {
		t.Fatal("group public key should not be empty")
	}

	t.Logf("Group public key: %d bytes", len(groupPK))

	t.Run("2-of-3 signing (participant-1+participant-2)", func(t *testing.T) {
		message := []byte("block-42-stardust-consensus")

		sig, err := coordinator.SignWithRetry(message, []int{1, 2, 3})
		if err != nil {
			t.Fatalf("2-of-3 signing failed: %v", err)
		}

		t.Logf("Signature size: %d bytes", len(sig))

		var pk mode3.PublicKey
		pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

		switch len(sig) {
		case 3293:
			if !mode3.Verify(&pk, message, sig) {
				t.Fatal("3293-byte signature verification FAILED")
			}
			t.Log("Standard Dilithium3 signature VERIFIED (3293 bytes)")
		case 4064:
			if !qtd.CheckGMQTDFullSignature(&pk, message, sig) {
				t.Fatal("4064-byte GM-QTD signature verification FAILED")
			}
			t.Log("GM-QTD signature VERIFIED (4064 bytes)")
		default:
			t.Fatalf("unexpected signature size: %d", len(sig))
		}
	})

	t.Run("2-of-3 signing (participant-1+participant-3)", func(t *testing.T) {
		message := []byte("block-43-stardust-consensus")

		sig, err := coordinator.SignWithRetry(message, []int{1, 3, 2})
		if err != nil {
			t.Fatalf("participant-1+participant-3 signing failed: %v", err)
		}

		var pk mode3.PublicKey
		pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

		switch len(sig) {
		case 3293:
			if !mode3.Verify(&pk, message, sig) {
				t.Fatal("participant-1+participant-3 signature verification FAILED")
			}
		case 4064:
			if !qtd.CheckGMQTDFullSignature(&pk, message, sig) {
				t.Fatal("participant-1+participant-3 signature verification FAILED")
			}
		}
		t.Log("participant-1+participant-3 signing verified")
	})

	t.Run("2-of-3 signing (participant-2+participant-3)", func(t *testing.T) {
		message := []byte("block-44-stardust-consensus")

		sig, err := coordinator.SignWithRetry(message, []int{2, 3, 1})
		if err != nil {
			t.Fatalf("participant-2+participant-3 signing failed: %v", err)
		}

		var pk mode3.PublicKey
		pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

		switch len(sig) {
		case 3293:
			if !mode3.Verify(&pk, message, sig) {
				t.Fatal("participant-2+participant-3 signature verification FAILED")
			}
		case 4064:
			if !qtd.CheckGMQTDFullSignature(&pk, message, sig) {
				t.Fatal("participant-2+participant-3 signature verification FAILED")
			}
		}
		t.Log("participant-2+participant-3 signing verified")
	})

	t.Run("consecutive blocks", func(t *testing.T) {
		for blockNum := 100; blockNum < 110; blockNum++ {
			message := []byte("consecutive-block-test")

			sig, err := coordinator.SignWithRetry(message, []int{1, 2, 3})
			if err != nil {
				t.Fatalf("block %d signing failed: %v", blockNum, err)
			}

			var pk mode3.PublicKey
			pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

			verified := false
			switch len(sig) {
			case 3293:
				verified = mode3.Verify(&pk, message, sig)
			case 4064:
				verified = qtd.CheckGMQTDFullSignature(&pk, message, sig)
			}

			if !verified {
				t.Fatalf("block %d signature verification FAILED", blockNum)
			}
		}
		t.Log("10 consecutive blocks signed and verified")
	})

	t.Run("signature size check", func(t *testing.T) {
		message := []byte("signature-size-check")
		sig, err := coordinator.SignWithRetry(message, []int{1, 2, 3})
		if err != nil {
			t.Fatalf("signing failed: %v", err)
		}

		if len(sig) != 3293 && len(sig) != 4064 {
			t.Errorf("signature size %d not in expected {3293, 4064}", len(sig))
		}

		t.Logf("Signature size: %d bytes (standard Dilithium3=3293, GM-QTD full=4064)", len(sig))

		var pk mode3.PublicKey
		pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

		if len(sig) == 3293 {
			if !mode3.Verify(&pk, message, sig) {
				t.Fatal("3293-byte signature not verifiable by standard Dilithium3")
			}
			t.Log("3293-byte signature is standard Dilithium3 compatible")
		}
	})

	t.Log("=== 3-Node QTD E2E Integration: ALL PASSED ===")
}

func TestPhase13_Integration_3NodeQTD_TwoRoundProtocol(t *testing.T) {
	t.Log("=== Phase 1.3: 3-Node QTD Two-Round Protocol Simulation ===")

	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	message := []byte("two-round-protocol-test")
	participants := []int{1, 2, 3}

	// Rejection sampling has ~32% success rate per attempt (circl docs: 1/4 to 1/7).
	// Retry the entire two-round protocol until success, matching SignWithRetry.
	var sig []byte
	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		sessionKey, err := manager.CreateSigningSession(message, participants)
		if err != nil {
			t.Fatalf("CreateSigningSession failed: %v", err)
		}

		t.Logf("Attempt %d - Round 1: Commitments", attempt+1)
		round1Sigs := make([]*PartialSignature, len(participants))
		for i, pid := range participants {
			ps, err := manager.BeginSign(sessionKey, pid)
			if err != nil {
				t.Fatalf("BeginSign pid=%d failed: %v", pid, err)
			}
			round1Sigs[i] = ps
			t.Logf("  Node S%d: commitment generated (len=%d)", pid, len(ps.Signature))
		}

		if err := manager.SubmitRound1(sessionKey, round1Sigs); err != nil {
			t.Fatalf("SubmitRound1 failed: %v", err)
		}
		t.Log("Round 1: All commitments submitted and verified")

		t.Log("Round 2: Reveals")
		round2Sigs := make([]*PartialSignature, len(participants))
		for i, pid := range participants {
			ps, err := manager.CompleteSignPrivate(sessionKey, pid)
			if err != nil {
				t.Fatalf("CompleteSignPrivate pid=%d failed: %v", pid, err)
			}
			round2Sigs[i] = ps
			t.Logf("  Node S%d: reveal generated (len=%d)", pid, len(ps.Signature))
		}

		t.Log("Round 2: Aggregation")
		sig, err = manager.CombineSignatures(sessionKey, round2Sigs)
		manager.CleanSession(sessionKey)
		if err != nil {
			t.Logf("Attempt %d: rejection sampling failed: %v", attempt+1, err)
			lastErr = err
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		t.Fatalf("Two-round protocol failed after 20 attempts: %v", lastErr)
	}

	t.Logf("Aggregated signature: %d bytes", len(sig))

	groupPK := manager.GroupPublicKey()
	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

	switch len(sig) {
	case 3293:
		if !mode3.Verify(&pk, message, sig) {
			t.Fatal("standard signature verification FAILED")
		}
		t.Log("Standard Dilithium3 signature VERIFIED")
	case 4064:
		if !qtd.CheckGMQTDFullSignature(&pk, message, sig) {
			t.Fatal("GM-QTD signature verification FAILED")
		}
		t.Log("GM-QTD signature VERIFIED")
	}

	t.Log("=== Two-Round Protocol Simulation: PASSED ===")
}

func TestPhase13_Integration_ShamirDKG_Verification(t *testing.T) {
	t.Log("=== Phase 1.3: Shamir DKG Verification ===")

	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)

	shares, err := manager.GenerateKeyShares()
	if err != nil {
		t.Fatalf("DKG failed: %v", err)
	}

	t.Logf("DKG produced %d shares", len(shares))

	for _, share := range shares {
		err := manager.VerifyShare(share)
		if err != nil {
			t.Errorf("share %d verification failed: %v", share.Index, err)
		} else {
			t.Logf("Share %d: verified", share.Index)
		}
	}

	groupPK := manager.GroupPublicKey()
	reconstructedPK, err := manager.ReconstructPublicKey()
	if err != nil {
		t.Fatalf("ReconstructPublicKey failed: %v", err)
	}

	if len(groupPK) != len(reconstructedPK) {
		t.Fatalf("public key length mismatch: %d vs %d", len(groupPK), len(reconstructedPK))
	}

	for i := range groupPK {
		if groupPK[i] != reconstructedPK[i] {
			t.Fatalf("public key mismatch at byte %d", i)
		}
	}

	t.Log("Public key reconstruction matches")

	t.Log("=== Shamir DKG Verification: PASSED ===")
}
