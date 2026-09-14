// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"bytes"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

func generateTestAddress(suffix byte) types.Address {
	addr := types.Address{}
	for i := range addr {
		addr[i] = suffix
	}
	return addr
}

func TestValidatorKeyExchange_RegisterKyberKey(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, err := NewValidatorKeyExchange(addr)
	if err != nil {
		t.Fatalf("NewValidatorKeyExchange failed: %v", err)
	}

	kp, err := crypto.GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair failed: %v", err)
	}
	pubBytes, err := kp.Public.Bytes()
	if err != nil {
		t.Fatalf("Public.Bytes failed: %v", err)
	}

	err = vke.RegisterKyberKey(generateTestAddress(0x02), pubBytes)
	if err != nil {
		t.Fatalf("RegisterKyberKey failed: %v", err)
	}

	retrieved, err := vke.GetKyberKey(generateTestAddress(0x02))
	if err != nil {
		t.Fatalf("GetKyberKey failed: %v", err)
	}
	if len(retrieved) != crypto.KyberPublicKeySize {
		t.Fatalf("retrieved key wrong size: got %d, want %d", len(retrieved), crypto.KyberPublicKeySize)
	}
}

func TestValidatorKeyExchange_RegisterInvalidKyberKey(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, err := NewValidatorKeyExchange(addr)
	if err != nil {
		t.Fatalf("NewValidatorKeyExchange failed: %v", err)
	}

	err = vke.RegisterKyberKey(generateTestAddress(0x02), []byte{1, 2, 3})
	if err == nil {
		t.Fatal("RegisterKyberKey should fail with invalid key size")
	}
}

func TestValidatorKeyExchange_GetUnregisteredKey(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, err := NewValidatorKeyExchange(addr)
	if err != nil {
		t.Fatalf("NewValidatorKeyExchange failed: %v", err)
	}

	_, err = vke.GetKyberKey(generateTestAddress(0x99))
	if err == nil {
		t.Fatal("GetKyberKey should fail for unregistered key")
	}
}

func TestValidatorKeyExchange_UnregisterKyberKey(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, err := NewValidatorKeyExchange(addr)
	if err != nil {
		t.Fatalf("NewValidatorKeyExchange failed: %v", err)
	}

	peerAddr := generateTestAddress(0x02)
	kp, _ := crypto.GenerateKyberKeyPair()
	pubBytes, _ := kp.Public.Bytes()

	vke.RegisterKyberKey(peerAddr, pubBytes)

	vke.UnregisterKyberKey(peerAddr)

	_, err = vke.GetKyberKey(peerAddr)
	if err == nil {
		t.Fatal("GetKyberKey should fail after unregister")
	}
}

func TestValidatorKeyExchange_LocalKyberPublicKey(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, err := NewValidatorKeyExchange(addr)
	if err != nil {
		t.Fatalf("NewValidatorKeyExchange failed: %v", err)
	}

	pubBytes, err := vke.LocalKyberPublicKey()
	if err != nil {
		t.Fatalf("LocalKyberPublicKey failed: %v", err)
	}
	if len(pubBytes) != crypto.KyberPublicKeySize {
		t.Fatalf("local public key wrong size: got %d, want %d", len(pubBytes), crypto.KyberPublicKeySize)
	}
}

func TestValidatorKeyExchange_FullSession(t *testing.T) {
	addrA := generateTestAddress(0x01)
	addrB := generateTestAddress(0x02)

	vkeA, err := NewValidatorKeyExchange(addrA)
	if err != nil {
		t.Fatalf("NewValidatorKeyExchange A failed: %v", err)
	}
	vkeB, err := NewValidatorKeyExchange(addrB)
	if err != nil {
		t.Fatalf("NewValidatorKeyExchange B failed: %v", err)
	}

	pubA, _ := vkeA.LocalKyberPublicKey()
	pubB, _ := vkeB.LocalKyberPublicKey()

	vkeA.RegisterKyberKey(addrB, pubB)
	vkeB.RegisterKyberKey(addrA, pubA)

	ciphertext, err := vkeA.InitiateSession(addrB)
	if err != nil {
		t.Fatalf("InitiateSession failed: %v", err)
	}
	if len(ciphertext) != crypto.KyberCiphertextSize {
		t.Fatalf("ciphertext wrong size: got %d, want %d", len(ciphertext), crypto.KyberCiphertextSize)
	}

	err = vkeB.CompleteSession(addrA, ciphertext)
	if err != nil {
		t.Fatalf("CompleteSession failed: %v", err)
	}

	testMsg := []byte("hello from validator A to validator B")
	encrypted, err := vkeA.EncryptForPeer(addrB, testMsg)
	if err != nil {
		t.Fatalf("EncryptForPeer failed: %v", err)
	}

	decrypted, err := vkeB.DecryptFromPeer(addrA, encrypted)
	if err != nil {
		t.Fatalf("DecryptFromPeer failed: %v", err)
	}

	if string(decrypted) != string(testMsg) {
		t.Fatalf("decrypted message mismatch: got %q, want %q", string(decrypted), string(testMsg))
	}
}

func TestValidatorKeyExchange_BidirectionalSession(t *testing.T) {
	addrA := generateTestAddress(0x01)
	addrB := generateTestAddress(0x02)

	vkeA, _ := NewValidatorKeyExchange(addrA)
	vkeB, _ := NewValidatorKeyExchange(addrB)

	pubA, _ := vkeA.LocalKyberPublicKey()
	pubB, _ := vkeB.LocalKyberPublicKey()

	vkeA.RegisterKyberKey(addrB, pubB)
	vkeB.RegisterKyberKey(addrA, pubA)

	ciphertextAB, err := vkeA.InitiateSession(addrB)
	if err != nil {
		t.Fatalf("A→B InitiateSession failed: %v", err)
	}
	vkeB.CompleteSession(addrA, ciphertextAB)

	ciphertextBA, err := vkeB.InitiateSession(addrA)
	if err != nil {
		t.Fatalf("B→A InitiateSession failed: %v", err)
	}
	vkeA.CompleteSession(addrB, ciphertextBA)

	msgAB := []byte("A to B")
	encAB, err := vkeA.EncryptForPeer(addrB, msgAB)
	if err != nil {
		t.Fatalf("A encrypt failed: %v", err)
	}
	decAB, err := vkeB.DecryptFromPeer(addrA, encAB)
	if err != nil {
		t.Fatalf("B decrypt failed: %v", err)
	}
	if string(decAB) != string(msgAB) {
		t.Fatalf("A→B message mismatch: got %q, want %q", string(decAB), string(msgAB))
	}

	msgBA := []byte("B to A")
	encBA, err := vkeB.EncryptForPeer(addrA, msgBA)
	if err != nil {
		t.Fatalf("B encrypt failed: %v", err)
	}
	decBA, err := vkeA.DecryptFromPeer(addrB, encBA)
	if err != nil {
		t.Fatalf("A decrypt failed: %v", err)
	}
	if string(decBA) != string(msgBA) {
		t.Fatalf("B→A message mismatch: got %q, want %q", string(decBA), string(msgBA))
	}
}

func TestValidatorKeyExchange_SessionNotFound(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, _ := NewValidatorKeyExchange(addr)

	_, err := vke.EncryptForPeer(generateTestAddress(0x02), []byte("test"))
	if err == nil {
		t.Fatal("EncryptForPeer should fail with no session")
	}

	_, err = vke.DecryptFromPeer(generateTestAddress(0x02), []byte("test"))
	if err == nil {
		t.Fatal("DecryptFromPeer should fail with no session")
	}
}

func TestValidatorKeyExchange_SessionExpiry(t *testing.T) {
	addrA := generateTestAddress(0x01)
	addrB := generateTestAddress(0x02)

	vkeA, _ := NewValidatorKeyExchange(addrA)
	vkeB, _ := NewValidatorKeyExchange(addrB)

	pubA, _ := vkeA.LocalKyberPublicKey()
	pubB, _ := vkeB.LocalKyberPublicKey()

	vkeA.RegisterKyberKey(addrB, pubB)
	vkeB.RegisterKyberKey(addrA, pubA)

	ciphertext, _ := vkeA.InitiateSession(addrB)
	vkeB.CompleteSession(addrA, ciphertext)

	sid := sessionID(addrA, addrB)
	vkeA.mu.Lock()
	if s, ok := vkeA.sessions[sid]; ok {
		s.ExpiresAt = time.Now().Add(-1 * time.Second)
	}
	vkeA.mu.Unlock()

	_, err := vkeA.EncryptForPeer(addrB, []byte("expired"))
	if err == nil {
		t.Fatal("EncryptForPeer should fail with expired session")
	}
}

func TestValidatorKeyExchange_RotateLocalKey(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, _ := NewValidatorKeyExchange(addr)

	oldPub, _ := vke.LocalKyberPublicKey()

	err := vke.RotateLocalKey()
	if err != nil {
		t.Fatalf("RotateLocalKey failed: %v", err)
	}

	newPub, _ := vke.LocalKyberPublicKey()

	if len(oldPub) == len(newPub) {
		match := true
		for i := range oldPub {
			if oldPub[i] != newPub[i] {
				match = false
				break
			}
		}
		if match {
			t.Fatal("key should change after rotation")
		}
	}

	if vke.ActiveSessionCount() != 0 {
		t.Fatal("sessions should be cleared after key rotation")
	}
}

func TestValidatorKeyExchange_InvalidCiphertextSize(t *testing.T) {
	addrA := generateTestAddress(0x01)

	NewValidatorKeyExchange(addrA)

	vkeB, _ := NewValidatorKeyExchange(generateTestAddress(0x02))
	err := vkeB.CompleteSession(addrA, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("CompleteSession should fail with invalid ciphertext size")
	}
}

func TestValidatorKeyExchange_InitiateWithoutPeerKey(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, _ := NewValidatorKeyExchange(addr)

	_, err := vke.InitiateSession(generateTestAddress(0x02))
	if err == nil {
		t.Fatal("InitiateSession should fail without peer key")
	}
}

func TestValidatorKeyExchange_ActiveSessionCount(t *testing.T) {
	addrA := generateTestAddress(0x01)
	addrB := generateTestAddress(0x02)

	vkeA, _ := NewValidatorKeyExchange(addrA)
	vkeB, _ := NewValidatorKeyExchange(addrB)

	pubA, _ := vkeA.LocalKyberPublicKey()
	pubB, _ := vkeB.LocalKyberPublicKey()

	vkeA.RegisterKyberKey(addrB, pubB)
	vkeB.RegisterKyberKey(addrA, pubA)

	if vkeA.ActiveSessionCount() != 0 {
		t.Fatal("should start with 0 sessions")
	}

	ciphertext, _ := vkeA.InitiateSession(addrB)
	vkeB.CompleteSession(addrA, ciphertext)

	if vkeA.ActiveSessionCount() != 1 {
		t.Fatalf("expected 1 active session, got %d", vkeA.ActiveSessionCount())
	}
	if vkeB.ActiveSessionCount() != 1 {
		t.Fatalf("expected 1 active session on B, got %d", vkeB.ActiveSessionCount())
	}
}

func TestValidatorKeyExchange_GetStatus(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, _ := NewValidatorKeyExchange(addr)

	status := vke.GetStatus()
	if status["registered_keys"].(int) != 0 {
		t.Fatal("should start with 0 registered keys")
	}
	if status["active_sessions"].(int) != 0 {
		t.Fatal("should start with 0 active sessions")
	}
	if !status["has_local_key"].(bool) {
		t.Fatal("should have local key")
	}
}

func TestValidatorKeyExchange_SyncFromValidatorSet(t *testing.T) {
	validators := make([]*Validator, 5)
	for i := 0; i < 5; i++ {
		kp, _ := crypto.GenerateKyberKeyPair()
		kyberPub, _ := kp.Public.Bytes()
		dilithiumKP, _ := crypto.GenerateKeyPair()
		dilithiumPub := dilithiumKP.Public.Bytes()

		addr := generateTestAddress(byte(i + 1))
		validators[i] = &Validator{
			Address:             addr,
			Stake:               big.NewInt(1000),
			Active:              true,
			PublicKeyBytes:      dilithiumPub,
			KyberPublicKeyBytes: kyberPub,
		}
	}

	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}

	vke, _ := NewValidatorKeyExchange(generateTestAddress(0x00))
	vke.SyncFromValidatorSet(vs)

	if vke.RegisteredKeyCount() != 5 {
		t.Fatalf("expected 5 registered keys, got %d", vke.RegisteredKeyCount())
	}
}

func TestValidatorKeyExchange_MultipleMessages(t *testing.T) {
	addrA := generateTestAddress(0x01)
	addrB := generateTestAddress(0x02)

	vkeA, _ := NewValidatorKeyExchange(addrA)
	vkeB, _ := NewValidatorKeyExchange(addrB)

	pubA, _ := vkeA.LocalKyberPublicKey()
	pubB, _ := vkeB.LocalKyberPublicKey()

	vkeA.RegisterKyberKey(addrB, pubB)
	vkeB.RegisterKyberKey(addrA, pubA)

	ciphertext, _ := vkeA.InitiateSession(addrB)
	vkeB.CompleteSession(addrA, ciphertext)

	for i := 0; i < 10; i++ {
		msg := []byte{byte(i)}
		enc, err := vkeA.EncryptForPeer(addrB, msg)
		if err != nil {
			t.Fatalf("encrypt message %d failed: %v", i, err)
		}
		dec, err := vkeB.DecryptFromPeer(addrA, enc)
		if err != nil {
			t.Fatalf("decrypt message %d failed: %v", i, err)
		}
		if dec[0] != msg[0] {
			t.Fatalf("message %d mismatch: got %d, want %d", i, dec[0], msg[0])
		}
	}
}

func TestVerifyKyberPublicKey(t *testing.T) {
	kp, _ := crypto.GenerateKyberKeyPair()
	validPub, _ := kp.Public.Bytes()

	err := VerifyKyberPublicKey(validPub)
	if err != nil {
		t.Fatalf("VerifyKyberPublicKey failed for valid key: %v", err)
	}

	err = VerifyKyberPublicKey([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("VerifyKyberPublicKey should fail for invalid size")
	}
}

func TestCreateValidatorKyberRegistration(t *testing.T) {
	addr := generateTestAddress(0x01)
	pubBytes, kp, err := CreateValidatorKyberRegistration(addr)
	if err != nil {
		t.Fatalf("CreateValidatorKyberRegistration failed: %v", err)
	}
	if len(pubBytes) != crypto.KyberPublicKeySize {
		t.Fatalf("public key wrong size: got %d, want %d", len(pubBytes), crypto.KyberPublicKeySize)
	}
	if kp == nil {
		t.Fatal("keypair should not be nil")
	}
	if kp.Private == nil {
		t.Fatal("private key should not be nil")
	}
}

func TestValidatorKeyExchange_WithKeyPair(t *testing.T) {
	addr := generateTestAddress(0x01)
	kp, _ := crypto.GenerateKyberKeyPair()

	vke := NewValidatorKeyExchangeWithKey(addr, kp)

	pub, err := vke.LocalKyberPublicKey()
	if err != nil {
		t.Fatalf("LocalKyberPublicKey failed: %v", err)
	}
	if len(pub) != crypto.KyberPublicKeySize {
		t.Fatalf("public key wrong size: got %d", len(pub))
	}
}

func TestValidatorStruct_KyberPublicKeyBytes(t *testing.T) {
	kp, _ := crypto.GenerateKyberKeyPair()
	kyberPub, _ := kp.Public.Bytes()
	dilithiumKP, _ := crypto.GenerateKeyPair()
	dilithiumPub := dilithiumKP.Public.Bytes()

	addr := generateTestAddress(0x01)
	v := &Validator{
		Address:             addr,
		Stake:               big.NewInt(1000),
		Active:              true,
		PublicKeyBytes:      dilithiumPub,
		KyberPublicKeyBytes: kyberPub,
	}

	if len(v.KyberPublicKeyBytes) != crypto.KyberPublicKeySize {
		t.Fatalf("KyberPublicKeyBytes wrong size: got %d, want %d", len(v.KyberPublicKeyBytes), crypto.KyberPublicKeySize)
	}
}

func TestValidatorSet_KyberPublicKeyBytes_Preserved(t *testing.T) {
	kp, _ := crypto.GenerateKyberKeyPair()
	kyberPub, _ := kp.Public.Bytes()
	dilithiumKP, _ := crypto.GenerateKeyPair()
	dilithiumPub := dilithiumKP.Public.Bytes()

	addr := generateTestAddress(0x01)
	validators := []*Validator{
		{
			Address:             addr,
			Stake:               big.NewInt(1000),
			Active:              true,
			PublicKeyBytes:      dilithiumPub,
			KyberPublicKeyBytes: kyberPub,
		},
	}

	vs, err := NewValidatorSet(validators)
	if err != nil {
		t.Fatalf("NewValidatorSet failed: %v", err)
	}

	got := vs.GetValidator(addr)
	if got == nil {
		t.Fatal("GetValidator returned nil")
	}
	if len(got.KyberPublicKeyBytes) != crypto.KyberPublicKeySize {
		t.Fatalf("KyberPublicKeyBytes not preserved: got %d bytes, want %d", len(got.KyberPublicKeyBytes), crypto.KyberPublicKeySize)
	}

	gotByIdx := vs.GetValidatorByIndex(0)
	if gotByIdx == nil {
		t.Fatal("GetValidatorByIndex returned nil")
	}
	if len(gotByIdx.KyberPublicKeyBytes) != crypto.KyberPublicKeySize {
		t.Fatalf("KyberPublicKeyBytes not preserved in GetValidatorByIndex: got %d bytes", len(gotByIdx.KyberPublicKeyBytes))
	}

	allValidators := vs.Validators()
	if len(allValidators[0].KyberPublicKeyBytes) != crypto.KyberPublicKeySize {
		t.Fatalf("KyberPublicKeyBytes not preserved in Validators(): got %d bytes", len(allValidators[0].KyberPublicKeyBytes))
	}

	deepCopy := vs.DeepCopy()
	gotCopy := deepCopy.GetValidator(addr)
	if len(gotCopy.KyberPublicKeyBytes) != crypto.KyberPublicKeySize {
		t.Fatalf("KyberPublicKeyBytes not preserved in DeepCopy: got %d bytes", len(gotCopy.KyberPublicKeyBytes))
	}
}

// ============================================================================
// SECURITY FIX (P1) TESTS: Kyber key replacement prevention
// ============================================================================

func TestRegisterKyberKey_PreventReplacement(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, _ := NewValidatorKeyExchange(addr)

	peerAddr := generateTestAddress(0x02)
	kp1, _ := crypto.GenerateKyberKeyPair()
	pub1, _ := kp1.Public.Bytes()

	// First registration should succeed
	if err := vke.RegisterKyberKey(peerAddr, pub1); err != nil {
		t.Fatalf("first RegisterKyberKey failed: %v", err)
	}

	// Registering the SAME key again should succeed (idempotent)
	if err := vke.RegisterKyberKey(peerAddr, pub1); err != nil {
		t.Fatalf("idempotent RegisterKyberKey failed: %v", err)
	}

	// Registering a DIFFERENT key should fail with ErrKyberKeyAlreadyExists
	kp2, _ := crypto.GenerateKyberKeyPair()
	pub2, _ := kp2.Public.Bytes()

	err := vke.RegisterKyberKey(peerAddr, pub2)
	if !errors.Is(err, ErrKyberKeyAlreadyExists) {
		t.Fatalf("expected ErrKyberKeyAlreadyExists, got: %v", err)
	}

	// Verify the original key is still registered (not overwritten)
	retrieved, err := vke.GetKyberKey(peerAddr)
	if err != nil {
		t.Fatalf("GetKyberKey failed: %v", err)
	}
	if !bytes.Equal(retrieved, pub1) {
		t.Fatal("original key should still be registered after failed replacement attempt")
	}
}

func TestRegisterKyberKey_IdempotentSameKey(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, _ := NewValidatorKeyExchange(addr)

	peerAddr := generateTestAddress(0x02)
	kp, _ := crypto.GenerateKyberKeyPair()
	pub, _ := kp.Public.Bytes()

	// Register key
	if err := vke.RegisterKyberKey(peerAddr, pub); err != nil {
		t.Fatalf("first RegisterKyberKey failed: %v", err)
	}

	// Register same key again — must not error
	if err := vke.RegisterKyberKey(peerAddr, pub); err != nil {
		t.Fatalf("idempotent RegisterKyberKey failed: %v", err)
	}

	// Register same key a third time — still must not error
	if err := vke.RegisterKyberKey(peerAddr, pub); err != nil {
		t.Fatalf("third idempotent RegisterKyberKey failed: %v", err)
	}

	if vke.RegisteredKeyCount() != 1 {
		t.Fatalf("expected 1 registered key, got %d", vke.RegisteredKeyCount())
	}
}

// ============================================================================
// SECURITY FIX (P1) TESTS: SealForPeer/OpenFromPeer sender authentication
// ============================================================================

func TestSealForPeer_OpenFromPeer_RoundTrip(t *testing.T) {
	addrA := generateTestAddress(0x01)
	addrB := generateTestAddress(0x02)

	vkeA, _ := NewValidatorKeyExchange(addrA)
	vkeB, _ := NewValidatorKeyExchange(addrB)
	// AUDIT (2026) HIGH-07: tests without a Dilithium3 signer disable auth.
	vkeA.SetRequireAuth(false)
	vkeB.SetRequireAuth(false)

	pubA, _ := vkeA.LocalKyberPublicKey()
	pubB, _ := vkeB.LocalKyberPublicKey()

	vkeA.RegisterKyberKey(addrB, pubB)
	vkeB.RegisterKyberKey(addrA, pubA)

	plaintext := []byte("secret TSS share data")
	ciphertext, err := vkeA.SealForPeer(addrB, plaintext)
	if err != nil {
		t.Fatalf("SealForPeer failed: %v", err)
	}

	decrypted, err := vkeB.OpenFromPeer(addrA, ciphertext)
	if err != nil {
		t.Fatalf("OpenFromPeer failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted mismatch: got %x, want %x", decrypted, plaintext)
	}
}

func TestSealForPeer_SelfEncryption(t *testing.T) {
	addrA := generateTestAddress(0x01)

	vkeA, _ := NewValidatorKeyExchange(addrA)
	vkeA.SetRequireAuth(false) // AUDIT (2026) HIGH-07: no Dilithium3 signer in test
	pubA, _ := vkeA.LocalKyberPublicKey()
	vkeA.RegisterKyberKey(addrA, pubA)

	plaintext := []byte("self-encrypted private share")
	ciphertext, err := vkeA.SealForPeer(addrA, plaintext)
	if err != nil {
		t.Fatalf("SealForPeer self failed: %v", err)
	}

	decrypted, err := vkeA.OpenFromPeer(addrA, ciphertext)
	if err != nil {
		t.Fatalf("OpenFromPeer self failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("self decrypted mismatch: got %x, want %x", decrypted, plaintext)
	}
}

func TestOpenFromPeer_SenderNotValidator(t *testing.T) {
	addrA := generateTestAddress(0x01)
	addrB := generateTestAddress(0x02)

	vkeA, _ := NewValidatorKeyExchange(addrA)
	vkeB, _ := NewValidatorKeyExchange(addrB)
	vkeA.SetRequireAuth(false) // AUDIT (2026) HIGH-07: no Dilithium3 signer in test
	vkeB.SetRequireAuth(false)

	pubA, _ := vkeA.LocalKyberPublicKey()
	pubB, _ := vkeB.LocalKyberPublicKey()

	vkeA.RegisterKyberKey(addrB, pubB)
	vkeB.RegisterKyberKey(addrA, pubA)

	plaintext := []byte("secret share")
	ciphertext, err := vkeA.SealForPeer(addrB, plaintext)
	if err != nil {
		t.Fatalf("SealForPeer failed: %v", err)
	}

	// Unregister A's Kyber key from B — simulates A not being a registered validator
	vkeB.UnregisterKyberKey(addrA)

	// OpenFromPeer should fail: A is no longer a registered validator on B
	_, err = vkeB.OpenFromPeer(addrA, ciphertext)
	if err == nil {
		t.Fatal("OpenFromPeer should fail when sender is not a registered validator")
	}
	if !errors.Is(err, ErrSenderNotValidator) {
		t.Fatalf("expected ErrSenderNotValidator, got: %v", err)
	}
}

func TestOpenFromPeer_PeerAddrMismatch(t *testing.T) {
	addrA := generateTestAddress(0x01)
	addrB := generateTestAddress(0x02)
	addrC := generateTestAddress(0x03)

	vkeA, _ := NewValidatorKeyExchange(addrA)
	vkeB, _ := NewValidatorKeyExchange(addrB)
	vkeC, _ := NewValidatorKeyExchange(addrC)
	vkeA.SetRequireAuth(false) // AUDIT (2026) HIGH-07: no Dilithium3 signer in test
	vkeB.SetRequireAuth(false)
	vkeC.SetRequireAuth(false)

	pubA, _ := vkeA.LocalKyberPublicKey()
	pubB, _ := vkeB.LocalKyberPublicKey()
	pubC, _ := vkeC.LocalKyberPublicKey()

	// A and B know each other; C knows B
	vkeA.RegisterKyberKey(addrB, pubB)
	vkeB.RegisterKyberKey(addrA, pubA)
	vkeB.RegisterKyberKey(addrC, pubC)
	vkeC.RegisterKyberKey(addrB, pubB)

	// C seals for B (C's address is embedded inside the encrypted payload)
	plaintext := []byte("share from C")
	ciphertext, err := vkeC.SealForPeer(addrB, plaintext)
	if err != nil {
		t.Fatalf("SealForPeer (C→B) failed: %v", err)
	}

	// B tries to open with peerAddr=A (mismatch: embedded=C, expected=A)
	// The key derivation uses (A, B) but the ciphertext was sealed with (C, B),
	// so AES-GCM decryption fails before the sender address check.
	_, err = vkeB.OpenFromPeer(addrA, ciphertext)
	if err == nil {
		t.Fatal("OpenFromPeer should fail when peerAddr does not match the actual sender")
	}
}

// testTSSAuthSigner implements TSSAuthSigner using Dilithium3 keys.
// AUDIT (2026) HIGH-07: verifies SealForPeer/OpenFromPeer Dilithium3 auth.
type testTSSAuthSigner struct {
	localPriv *crypto.PrivateKey
	localAddr types.Address
	pubKeys   map[types.Address]*crypto.PublicKey
}

func (s *testTSSAuthSigner) SignTSS(msg []byte) ([]byte, error) {
	return s.localPriv.Sign(msg)
}

func (s *testTSSAuthSigner) VerifyTSS(sender types.Address, msg, sig []byte) bool {
	pub, ok := s.pubKeys[sender]
	if !ok {
		return false
	}
	return crypto.Verify(pub, msg, sig)
}

// TestSealForPeer_OpenFromPeer_WithAuth verifies the full Dilithium3-authenticated
// flow: SealForPeer signs the payload, OpenFromPeer verifies the signature.
// AUDIT (2026) HIGH-07/CRND-07.
func TestSealForPeer_OpenFromPeer_WithAuth(t *testing.T) {
	addrA := generateTestAddress(0x01)
	addrB := generateTestAddress(0x02)

	// Generate Dilithium3 keypairs for A and B.
	privA, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair A failed: %v", err)
	}
	privB, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair B failed: %v", err)
	}

	vkeA, _ := NewValidatorKeyExchange(addrA)
	vkeB, _ := NewValidatorKeyExchange(addrB)

	pubA, _ := vkeA.LocalKyberPublicKey()
	pubB, _ := vkeB.LocalKyberPublicKey()

	vkeA.RegisterKyberKey(addrB, pubB)
	vkeB.RegisterKyberKey(addrA, pubA)

	// Configure auth signers. A signs with its Dilithium3 key; B verifies
	// against A's public key. requireAuth stays true (default, fail-closed).
	signerA := &testTSSAuthSigner{
		localPriv: privA.Private,
		localAddr: addrA,
		pubKeys: map[types.Address]*crypto.PublicKey{
			addrA: privA.Public,
			addrB: privB.Public,
		},
	}
	signerB := &testTSSAuthSigner{
		localPriv: privB.Private,
		localAddr: addrB,
		pubKeys: map[types.Address]*crypto.PublicKey{
			addrA: privA.Public,
			addrB: privB.Public,
		},
	}
	vkeA.SetAuthSigner(signerA)
	vkeB.SetAuthSigner(signerB)

	plaintext := []byte("authenticated TSS share")
	ciphertext, err := vkeA.SealForPeer(addrB, plaintext)
	if err != nil {
		t.Fatalf("SealForPeer with auth failed: %v", err)
	}

	decrypted, err := vkeB.OpenFromPeer(addrA, ciphertext)
	if err != nil {
		t.Fatalf("OpenFromPeer with auth failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted mismatch: got %x, want %x", decrypted, plaintext)
	}
}

// TestSealForPeer_FailClosedWithoutSigner verifies that SealForPeer rejects
// when requireAuth=true and no signer is configured (fail-closed).
// AUDIT (2026) HIGH-07.
func TestSealForPeer_FailClosedWithoutSigner(t *testing.T) {
	addrA := generateTestAddress(0x01)
	addrB := generateTestAddress(0x02)

	vkeA, _ := NewValidatorKeyExchange(addrA)
	vkeB, _ := NewValidatorKeyExchange(addrB)
	// requireAuth defaults to true, no signer configured.

	pubB, _ := vkeB.LocalKyberPublicKey()
	vkeA.RegisterKyberKey(addrB, pubB)

	_, err := vkeA.SealForPeer(addrB, []byte("should fail"))
	if err == nil {
		t.Fatal("SealForPeer should fail-closed when requireAuth=true and no signer configured")
	}
}

// TestOpenFromPeer_RejectTamperedSignature verifies that a tampered Dilithium3
// signature is rejected by OpenFromPeer.
// AUDIT (2026) HIGH-07.
func TestOpenFromPeer_RejectTamperedSignature(t *testing.T) {
	addrA := generateTestAddress(0x01)
	addrB := generateTestAddress(0x02)

	privA, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair A failed: %v", err)
	}
	privB, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair B failed: %v", err)
	}

	vkeA, _ := NewValidatorKeyExchange(addrA)
	vkeB, _ := NewValidatorKeyExchange(addrB)

	pubA, _ := vkeA.LocalKyberPublicKey()
	pubB, _ := vkeB.LocalKyberPublicKey()

	vkeA.RegisterKyberKey(addrB, pubB)
	vkeB.RegisterKyberKey(addrA, pubA)

	signerA := &testTSSAuthSigner{
		localPriv: privA.Private,
		localAddr: addrA,
		pubKeys: map[types.Address]*crypto.PublicKey{
			addrA: privA.Public,
			addrB: privB.Public,
		},
	}
	// B uses a DIFFERENT key for verification (wrong public key for A).
	wrongPriv, _ := crypto.GenerateKeyPair()
	signerB := &testTSSAuthSigner{
		localPriv: privB.Private,
		localAddr: addrB,
		pubKeys: map[types.Address]*crypto.PublicKey{
			addrA: wrongPriv.Public, // wrong key for A
			addrB: privB.Public,
		},
	}
	vkeA.SetAuthSigner(signerA)
	vkeB.SetAuthSigner(signerB)

	plaintext := []byte("share with wrong verification key")
	ciphertext, err := vkeA.SealForPeer(addrB, plaintext)
	if err != nil {
		t.Fatalf("SealForPeer failed: %v", err)
	}

	_, err = vkeB.OpenFromPeer(addrA, ciphertext)
	if err == nil {
		t.Fatal("OpenFromPeer should reject when signature verification key is wrong")
	}
}

// ============================================================================
// SECURITY FIX (P1) TESTS: RotateLocalKey syncs registry
// ============================================================================

func TestRotateLocalKey_UpdatesRegistry(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, _ := NewValidatorKeyExchange(addr)

	// Register own key locally (simulates broadcastKyberPublicKey)
	pubOld, _ := vke.LocalKyberPublicKey()
	if err := vke.RegisterKyberKey(addr, pubOld); err != nil {
		t.Fatalf("register own key failed: %v", err)
	}

	// Rotate local key
	if err := vke.RotateLocalKey(); err != nil {
		t.Fatalf("RotateLocalKey failed: %v", err)
	}

	pubNew, _ := vke.LocalKyberPublicKey()

	// The registry should now contain the new key
	retrieved, err := vke.GetKyberKey(addr)
	if err != nil {
		t.Fatalf("GetKyberKey after rotation failed: %v", err)
	}
	if !bytes.Equal(retrieved, pubNew) {
		t.Fatal("registry should contain the new key after rotation")
	}

	// Registering the new key again should be idempotent (not ErrKyberKeyAlreadyExists)
	if err := vke.RegisterKyberKey(addr, pubNew); err != nil {
		t.Fatalf("idempotent register after rotation failed: %v", err)
	}

	// Old key should no longer match
	if bytes.Equal(retrieved, pubOld) {
		t.Fatal("key should have changed after rotation")
	}
}

func TestIsRegisteredValidator(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, _ := NewValidatorKeyExchange(addr)

	peerAddr := generateTestAddress(0x02)

	// Not registered yet
	if vke.IsRegisteredValidator(peerAddr) {
		t.Fatal("peer should not be registered initially")
	}

	kp, _ := crypto.GenerateKyberKeyPair()
	pub, _ := kp.Public.Bytes()
	vke.RegisterKyberKey(peerAddr, pub)

	// Now registered
	if !vke.IsRegisteredValidator(peerAddr) {
		t.Fatal("peer should be registered after RegisterKyberKey")
	}

	vke.UnregisterKyberKey(peerAddr)

	// Unregistered again
	if vke.IsRegisteredValidator(peerAddr) {
		t.Fatal("peer should not be registered after UnregisterKyberKey")
	}
}

// ============================================================================
// CRND-R2-02 TESTS: Kyber broadcast freshness / replay protection
//
// CRND-R2-02: "Kyber key-exchange signatures lack freshness (no timestamp
// / nonce / version) → an attacker can replay stale rotation messages and
// roll validators back to retired Kyber keys → TSS liveness DoS"
//
// The fix (CRND-01 + CRND-R3-01) adds:
//  - Timestamp in the signed broadcast payload (addr || timestamp || kyberPubKey)
//  - CheckKyberBroadcastFreshness: ±5 min skew window + strictly-monotonic check
//  - CommitKyberBroadcastFreshness: commits high-water mark ONLY after sig verify
// ============================================================================

// TestCheckKyberBroadcastFreshness_RejectsStaleTimestamp verifies that a
// broadcast with a timestamp older than the 5-minute clock-skew window is
// rejected. This prevents replaying a captured old rotation broadcast.
func TestCheckKyberBroadcastFreshness_RejectsStaleTimestamp(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, _ := NewValidatorKeyExchange(addr)

	peerAddr := generateTestAddress(0x02)
	staleTs := time.Now().Unix() - 600 // 10 minutes ago (> 5 min window)

	err := vke.CheckKyberBroadcastFreshness(peerAddr, staleTs)
	if err == nil {
		t.Fatal("CheckKyberBroadcastFreshness should reject stale timestamp")
	}
}

// TestCheckKyberBroadcastFreshness_RejectsFutureTimestamp verifies that a
// broadcast with a timestamp too far in the future is rejected. This prevents
// a forged broadcast from poisoning the high-water mark with a future timestamp.
func TestCheckKyberBroadcastFreshness_RejectsFutureTimestamp(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, _ := NewValidatorKeyExchange(addr)

	peerAddr := generateTestAddress(0x02)
	futureTs := time.Now().Unix() + 600 // 10 minutes in future (> 5 min window)

	err := vke.CheckKyberBroadcastFreshness(peerAddr, futureTs)
	if err == nil {
		t.Fatal("CheckKyberBroadcastFreshness should reject future timestamp")
	}
}

// TestCheckKyberBroadcastFreshness_RejectsReplay verifies that after a
// timestamp is committed, replaying the same or older timestamp is rejected.
// This is the core CRND-R2-02 protection: prevents rolling back to a
// deprecated Kyber key by replaying an old rotation broadcast.
func TestCheckKyberBroadcastFreshness_RejectsReplay(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, _ := NewValidatorKeyExchange(addr)

	peerAddr := generateTestAddress(0x02)
	now := time.Now().Unix()

	// First broadcast: fresh timestamp — should pass check.
	if err := vke.CheckKyberBroadcastFreshness(peerAddr, now); err != nil {
		t.Fatalf("first fresh broadcast should pass: %v", err)
	}
	// Commit after (simulated) signature verification.
	vke.CommitKyberBroadcastFreshness(peerAddr, now)

	// Replay the SAME timestamp — should be rejected (not strictly greater).
	if err := vke.CheckKyberBroadcastFreshness(peerAddr, now); err == nil {
		t.Fatal("replay of same timestamp should be rejected")
	}

	// Replay an OLDER timestamp — should be rejected.
	if err := vke.CheckKyberBroadcastFreshness(peerAddr, now-1); err == nil {
		t.Fatal("replay of older timestamp should be rejected")
	}
}

// TestCheckKyberBroadcastFreshness_CheckDoesNotCommit verifies that
// CheckKyberBroadcastFreshness does NOT update the high-water mark.
// Only CommitKyberBroadcastFreshness (called after signature verification)
// updates it. This is the CRND-R3-01 fix: prevents a forged broadcast with
// a future timestamp from blocking the legitimate validator's next broadcast.
func TestCheckKyberBroadcastFreshness_CheckDoesNotCommit(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, _ := NewValidatorKeyExchange(addr)

	peerAddr := generateTestAddress(0x02)
	now := time.Now().Unix()

	// Check passes but does NOT commit.
	if err := vke.CheckKyberBroadcastFreshness(peerAddr, now); err != nil {
		t.Fatalf("check should pass for fresh timestamp: %v", err)
	}

	// A second check with the SAME timestamp should still pass because
	// the high-water mark was NOT updated by the first check.
	if err := vke.CheckKyberBroadcastFreshness(peerAddr, now); err != nil {
		t.Fatalf("second check with same timestamp should pass (check does not commit): %v", err)
	}

	// Now commit.
	vke.CommitKyberBroadcastFreshness(peerAddr, now)

	// After commit, the same timestamp should be rejected.
	if err := vke.CheckKyberBroadcastFreshness(peerAddr, now); err == nil {
		t.Fatal("after commit, same timestamp should be rejected")
	}
}

// TestCheckKyberBroadcastFreshness_AllowsMonotonicIncrease verifies that
// a newer timestamp is accepted after an older one is committed. This is
// the legitimate key rotation flow.
func TestCheckKyberBroadcastFreshness_AllowsMonotonicIncrease(t *testing.T) {
	addr := generateTestAddress(0x01)
	vke, _ := NewValidatorKeyExchange(addr)

	peerAddr := generateTestAddress(0x02)
	now := time.Now().Unix()

	// First rotation at time T1.
	if err := vke.CheckKyberBroadcastFreshness(peerAddr, now); err != nil {
		t.Fatalf("first broadcast should pass: %v", err)
	}
	vke.CommitKyberBroadcastFreshness(peerAddr, now)

	// Second rotation at T2 > T1 — should pass.
	if err := vke.CheckKyberBroadcastFreshness(peerAddr, now+1); err != nil {
		t.Fatalf("second broadcast with newer timestamp should pass: %v", err)
	}
	vke.CommitKyberBroadcastFreshness(peerAddr, now+1)
}

// TestOpenFromPeer_RejectsReplayedTimestamp verifies that the per-message
// path (SealForPeer/OpenFromPeer) rejects replayed ciphertexts via the
// timestamp anti-replay high-water mark. Replaying the exact same ciphertext
// must fail because its timestamp is ≤ the recorded high-water mark.
func TestOpenFromPeer_RejectsReplayedTimestamp(t *testing.T) {
	addrA := generateTestAddress(0x01)
	addrB := generateTestAddress(0x02)

	vkeA, _ := NewValidatorKeyExchange(addrA)
	vkeB, _ := NewValidatorKeyExchange(addrB)
	vkeA.SetRequireAuth(false)
	vkeB.SetRequireAuth(false)

	pubA, _ := vkeA.LocalKyberPublicKey()
	pubB, _ := vkeB.LocalKyberPublicKey()

	vkeA.RegisterKyberKey(addrB, pubB)
	vkeB.RegisterKyberKey(addrA, pubA)

	// First message: should decrypt successfully.
	plaintext := []byte("secret TSS share")
	ciphertext, err := vkeA.SealForPeer(addrB, plaintext)
	if err != nil {
		t.Fatalf("SealForPeer failed: %v", err)
	}
	if _, err := vkeB.OpenFromPeer(addrA, ciphertext); err != nil {
		t.Fatalf("first OpenFromPeer failed: %v", err)
	}

	// Replaying the EXACT same ciphertext must fail — its embedded timestamp
	// is now ≤ the high-water mark recorded by the first successful open.
	_, err = vkeB.OpenFromPeer(addrA, ciphertext)
	if err == nil {
		t.Fatal("OpenFromPeer should reject replayed ciphertext (timestamp <= high-water mark)")
	}
}
