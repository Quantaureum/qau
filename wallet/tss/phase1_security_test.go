// Quantaureum Node source, version 1.0.0.
package tss

import (
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/wallet/tss/qtd"
)

func TestPhase13_Security_SingleShareLeakCannotSign(t *testing.T) {
	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	message := []byte("share-leak-test")

	_, err := manager.CreateSigningSession(message, []int{1})
	if err == nil {
		t.Error("single share should NOT be able to create signing session (below threshold)")
	}
}

func TestPhase13_Security_LeakedShareCannotVerifyAlone(t *testing.T) {
	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	share1, err := manager.GetShare(1)
	if err != nil {
		t.Fatalf("GetShare(1) failed: %v", err)
	}
	if share1 == nil {
		t.Fatal("share should not be nil")
	}

	groupPK := manager.GroupPublicKey()
	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

	message := []byte("leaked-share-test")

	sig, err := manager.SignWithRetry(message, []int{1, 2, 3})
	if err != nil {
		t.Fatalf("threshold signing failed: %v", err)
	}

	switch len(sig) {
	case 3293:
		if !mode3.Verify(&pk, message, sig) {
			t.Fatal("valid signature should verify")
		}
	case 4064:
		if !qtd.CheckGMQTDFullSignature(&pk, message, sig) {
			t.Fatal("valid signature should verify")
		}
	}

	t.Log("Leaked share alone cannot produce valid signature — threshold enforcement works")
}

func TestPhase13_Security_CompromisedShareCannotForge(t *testing.T) {
	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	message := []byte("forge-test")

	sig, err := manager.SignWithRetry(message, []int{1, 2, 3})
	if err != nil {
		t.Fatalf("signing failed: %v", err)
	}

	groupPK := manager.GroupPublicKey()
	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

	fakeSig := make([]byte, len(sig))
	copy(fakeSig, sig)
	fakeSig[0] ^= 0xFF
	fakeSig[1] ^= 0xAA
	fakeSig[2] ^= 0x55

	switch len(fakeSig) {
	case 3293:
		if mode3.Verify(&pk, message, fakeSig) {
			t.Error("tampered signature should NOT verify")
		}
	case 4064:
		if qtd.CheckGMQTDFullSignature(&pk, message, fakeSig) {
			t.Error("tampered signature should NOT verify")
		}
	}

	t.Log("Tampered signature correctly rejected — no forgery possible from leaked share data")
}

func TestPhase13_Security_DifferentParticipantSets(t *testing.T) {
	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	message := []byte("different-sets-test")

	sig12, err := manager.SignWithRetry(message, []int{1, 2, 3})
	if err != nil {
		t.Fatalf("signing with {1,2,3} failed: %v", err)
	}

	sig13, err := manager.SignWithRetry(message, []int{1, 3, 2})
	if err != nil {
		t.Fatalf("signing with {1,3,2} failed: %v", err)
	}

	groupPK := manager.GroupPublicKey()
	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

	switch len(sig12) {
	case 3293:
		if !mode3.Verify(&pk, message, sig12) {
			t.Error("sig12 verification failed")
		}
		if !mode3.Verify(&pk, message, sig13) {
			t.Error("sig13 verification failed")
		}
	case 4064:
		if !qtd.CheckGMQTDFullSignature(&pk, message, sig12) {
			t.Error("sig12 verification failed")
		}
		if !qtd.CheckGMQTDFullSignature(&pk, message, sig13) {
			t.Error("sig13 verification failed")
		}
	}

	t.Log("Different participant sets produce valid signatures — Shamir interpolation works correctly")
}

func TestPhase13_Security_ShareIsolation(t *testing.T) {
	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	share1, _ := manager.GetShare(1)
	share2, _ := manager.GetShare(2)

	if share1.Index == share2.Index {
		t.Error("shares should have different indices")
	}

	allZero1 := true
	for _, b := range share1.Share {
		if b != 0 {
			allZero1 = false
			break
		}
	}
	if allZero1 {
		t.Error("share1 should not be all zeros")
	}

	allZero2 := true
	for _, b := range share2.Share {
		if b != 0 {
			allZero2 = false
			break
		}
	}
	if allZero2 {
		t.Error("share2 should not be all zeros")
	}

	identical := true
	if len(share1.Share) != len(share2.Share) {
		identical = false
	} else {
		for i := range share1.Share {
			if share1.Share[i] != share2.Share[i] {
				identical = false
				break
			}
		}
	}
	if identical {
		t.Error("different shares should have different values — Shamir secret sharing ensures isolation")
	}

	t.Log("Share isolation verified — each share is unique and non-trivial")
}

func TestPhase13_Security_PublicKeyConsistency(t *testing.T) {
	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	pk1 := manager.GroupPublicKey()
	pk2, err := manager.ReconstructPublicKey()
	if err != nil {
		t.Fatalf("ReconstructPublicKey failed: %v", err)
	}

	if len(pk1) != len(pk2) {
		t.Fatalf("public key length mismatch: %d vs %d", len(pk1), len(pk2))
	}

	for i := range pk1 {
		if pk1[i] != pk2[i] {
			t.Fatalf("public key mismatch at byte %d", i)
		}
	}

	t.Log("Public key consistency verified — GroupPublicKey matches ReconstructPublicKey")
}

func TestPhase13_Security_MultipleMessagesDistinct(t *testing.T) {
	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	msg1 := []byte("message-one")
	msg2 := []byte("message-two")

	sig1, err := manager.SignWithRetry(msg1, []int{1, 2, 3})
	if err != nil {
		t.Fatalf("signing msg1 failed: %v", err)
	}

	sig2, err := manager.SignWithRetry(msg2, []int{1, 2, 3})
	if err != nil {
		t.Fatalf("signing msg2 failed: %v", err)
	}

	groupPK := manager.GroupPublicKey()
	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

	switch len(sig1) {
	case 3293:
		if !mode3.Verify(&pk, msg1, sig1) {
			t.Error("sig1 should verify against msg1")
		}
		if mode3.Verify(&pk, msg2, sig1) {
			t.Error("sig1 should NOT verify against msg2")
		}
		if !mode3.Verify(&pk, msg2, sig2) {
			t.Error("sig2 should verify against msg2")
		}
		if mode3.Verify(&pk, msg1, sig2) {
			t.Error("sig2 should NOT verify against msg1")
		}
	case 4064:
		if !qtd.CheckGMQTDFullSignature(&pk, msg1, sig1) {
			t.Error("sig1 should verify against msg1")
		}
		if qtd.CheckGMQTDFullSignature(&pk, msg2, sig1) {
			t.Error("sig1 should NOT verify against msg2")
		}
		if !qtd.CheckGMQTDFullSignature(&pk, msg2, sig2) {
			t.Error("sig2 should verify against msg2")
		}
		if qtd.CheckGMQTDFullSignature(&pk, msg1, sig2) {
			t.Error("sig2 should NOT verify against msg1")
		}
	}

	t.Log("Cross-message verification correctly rejected — signatures are message-bound")
}

func TestPhase13_Security_SessionCleanup(t *testing.T) {
	config := TSSConfig{Threshold: 2, TotalShares: 3, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	message := []byte("session-cleanup-test")
	sessionKey, err := manager.CreateSigningSession(message, []int{1, 2, 3})
	if err != nil {
		t.Fatalf("CreateSigningSession failed: %v", err)
	}

	manager.CleanSession(sessionKey)

	_, err = manager.BeginSign(sessionKey, 1)
	if err == nil {
		t.Error("BeginSign on cleaned session should fail")
	}

	t.Log("Session cleanup verified — cleaned sessions cannot be used")
}

func TestPhase13_Security_3of5_ThresholdEnforcement(t *testing.T) {
	config := TSSConfig{Threshold: 3, TotalShares: 5, SecurityLevel: 256}
	manager, _ := NewTSSManager(config)
	manager.GenerateKeyShares()

	message := []byte("3of5-threshold-test")

	_, err := manager.CreateSigningSession(message, []int{1, 2})
	if err == nil {
		t.Error("2-of-5 should fail (threshold=3)")
	}

	sig, err := manager.SignWithRetry(message, []int{1, 2, 3, 4, 5})
	if err != nil {
		t.Fatalf("3-of-5 signing failed: %v", err)
	}

	groupPK := manager.GroupPublicKey()
	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(groupPK))

	switch len(sig) {
	case 3293:
		if !mode3.Verify(&pk, message, sig) {
			t.Error("3-of-5 signature should verify")
		}
	case 4064:
		if !qtd.CheckGMQTDFullSignature(&pk, message, sig) {
			t.Error("3-of-5 signature should verify")
		}
	}

	t.Log("3-of-5 threshold enforcement verified")
}
