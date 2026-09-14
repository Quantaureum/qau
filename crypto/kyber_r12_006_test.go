// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"testing"
)

// =============================================================================
// CRYPTO-R12-006 (2026-07-20) tests: KyberEncapsulate standalone function
//
// These tests verify that:
//  1. KyberEncapsulate works without requiring a private key receiver
//  2. The deprecated Exchange method still works (backward compatibility)
//  3. Both produce equivalent results given the same recipient public key
//     (modulo the inherent non-determinism of KEM encapsulation)
//  4. Nil inputs are properly rejected
//  5. Round-trip (Encapsulate + Decapsulate) produces matching shared secret
// =============================================================================

// TestCRYPTO_R12_006_KyberEncapsulate_RoundTrip verifies that a shared secret
// produced by KyberEncapsulate can be decapsulated by the matching private key.
func TestCRYPTO_R12_006_KyberEncapsulate_RoundTrip(t *testing.T) {
	recipientKP, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair failed: %v", err)
	}

	sharedSecret, ciphertext, err := KyberEncapsulate(recipientKP.Public)
	if err != nil {
		t.Fatalf("KyberEncapsulate failed: %v", err)
	}
	if len(sharedSecret) == 0 {
		t.Fatal("shared secret is empty")
	}
	if len(ciphertext) != KyberCiphertextSize {
		t.Errorf("expected ciphertext length %d, got %d", KyberCiphertextSize, len(ciphertext))
	}

	// Recipient decapsulates using their private key
	decapsulated, err := recipientKP.Private.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	// Shared secrets must match
	if len(sharedSecret) != len(decapsulated) {
		t.Fatalf("shared secret length mismatch: encapsulate=%d, decapsulate=%d",
			len(sharedSecret), len(decapsulated))
	}
	for i := range sharedSecret {
		if sharedSecret[i] != decapsulated[i] {
			t.Fatalf("shared secret mismatch at byte %d", i)
		}
	}
}

// TestCRYPTO_R12_006_KyberEncapsulate_NilRecipient verifies that nil
// recipient public key is rejected.
func TestCRYPTO_R12_006_KyberEncapsulate_NilRecipient(t *testing.T) {
	_, _, err := KyberEncapsulate(nil)
	if err != ErrKyberKeyExchangeFailed {
		t.Errorf("expected ErrKyberKeyExchangeFailed, got %v", err)
	}
}

// TestCRYPTO_R12_006_KyberEncapsulate_NilInnerKey verifies that a
// KyberPublicKey with nil inner key is rejected.
func TestCRYPTO_R12_006_KyberEncapsulate_NilInnerKey(t *testing.T) {
	_, _, err := KyberEncapsulate(&KyberPublicKey{key: nil})
	if err != ErrKyberKeyExchangeFailed {
		t.Errorf("expected ErrKyberKeyExchangeFailed, got %v", err)
	}
}

// TestCRYPTO_R12_006_KyberEncapsulate_DoesNotNeedPrivateKey verifies that
// KyberEncapsulate does not accept or require a private key. This is the
// core fix for CRYPTO-R12-006: the API no longer misleadingly suggests
// the private key is involved in encapsulation.
func TestCRYPTO_R12_006_KyberEncapsulate_DoesNotNeedPrivateKey(t *testing.T) {
	recipientKP, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair failed: %v", err)
	}
	// We only pass the public key — no private key in sight.
	sharedSecret, ciphertext, err := KyberEncapsulate(recipientKP.Public)
	if err != nil {
		t.Fatalf("KyberEncapsulate failed without private key: %v", err)
	}
	if sharedSecret == nil {
		t.Fatal("shared secret is nil")
	}
	if ciphertext == nil {
		t.Fatal("ciphertext is nil")
	}
}

// TestCRYPTO_R12_006_Exchange_DeprecatedStillWorks verifies that the
// deprecated Exchange method still works for backward compatibility.
func TestCRYPTO_R12_006_Exchange_DeprecatedStillWorks(t *testing.T) {
	senderKP, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair (sender) failed: %v", err)
	}
	recipientKP, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair (recipient) failed: %v", err)
	}

	// Use deprecated Exchange method
	sharedSecret, ciphertext, err := senderKP.Private.Exchange(recipientKP.Public)
	if err != nil {
		t.Fatalf("Exchange (deprecated) failed: %v", err)
	}
	if len(sharedSecret) == 0 {
		t.Fatal("shared secret is empty")
	}
	if len(ciphertext) != KyberCiphertextSize {
		t.Errorf("expected ciphertext length %d, got %d", KyberCiphertextSize, len(ciphertext))
	}

	// Recipient must be able to decapsulate
	decapsulated, err := recipientKP.Private.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}
	if len(sharedSecret) != len(decapsulated) {
		t.Fatalf("shared secret length mismatch: exchange=%d, decapsulate=%d",
			len(sharedSecret), len(decapsulated))
	}
	for i := range sharedSecret {
		if sharedSecret[i] != decapsulated[i] {
			t.Fatalf("shared secret mismatch at byte %d", i)
		}
	}
}

// TestCRYPTO_R12_006_Exchange_NilReceiver verifies that the deprecated
// Exchange method still rejects nil receiver (use-after-Destroy safety).
func TestCRYPTO_R12_006_Exchange_NilReceiver(t *testing.T) {
	recipientKP, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair failed: %v", err)
	}
	var nilPriv *KyberPrivateKey
	_, _, err = nilPriv.Exchange(recipientKP.Public)
	if err != ErrKyberKeyExchangeFailed {
		t.Errorf("expected ErrKyberKeyExchangeFailed, got %v", err)
	}
}

// TestCRYPTO_R12_006_Exchange_NilInnerReceiver verifies that the deprecated
// Exchange method rejects a KyberPrivateKey with nil inner key.
func TestCRYPTO_R12_006_Exchange_NilInnerReceiver(t *testing.T) {
	recipientKP, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair failed: %v", err)
	}
	emptyPriv := &KyberPrivateKey{key: nil}
	_, _, err = emptyPriv.Exchange(recipientKP.Public)
	if err != ErrKyberKeyExchangeFailed {
		t.Errorf("expected ErrKyberKeyExchangeFailed, got %v", err)
	}
}

// TestCRYPTO_R12_006_Exchange_NilRecipient verifies that the deprecated
// Exchange method rejects nil recipient.
func TestCRYPTO_R12_006_Exchange_NilRecipient(t *testing.T) {
	senderKP, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair failed: %v", err)
	}
	_, _, err = senderKP.Private.Exchange(nil)
	if err != ErrKyberKeyExchangeFailed {
		t.Errorf("expected ErrKyberKeyExchangeFailed, got %v", err)
	}
}

// TestCRYPTO_R12_006_Encapsulate_ThenDecapsulate_MultipleRecipients verifies
// that KyberEncapsulate produces a fresh shared secret for each recipient,
// and only the matching private key can decapsulate.
func TestCRYPTO_R12_006_Encapsulate_ThenDecapsulate_MultipleRecipients(t *testing.T) {
	aliceKP, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair (alice) failed: %v", err)
	}
	bobKP, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair (bob) failed: %v", err)
	}

	// Encapsulate to Alice
	aliceShared, aliceCiphertext, err := KyberEncapsulate(aliceKP.Public)
	if err != nil {
		t.Fatalf("KyberEncapsulate to Alice failed: %v", err)
	}

	// Encapsulate to Bob
	bobShared, bobCiphertext, err := KyberEncapsulate(bobKP.Public)
	if err != nil {
		t.Fatalf("KyberEncapsulate to Bob failed: %v", err)
	}

	// Alice decapsulates her ciphertext — must match her shared secret
	aliceDecap, err := aliceKP.Private.Decapsulate(aliceCiphertext)
	if err != nil {
		t.Fatalf("Alice Decapsulate failed: %v", err)
	}
	if len(aliceShared) != len(aliceDecap) {
		t.Fatalf("Alice shared secret length mismatch")
	}
	for i := range aliceShared {
		if aliceShared[i] != aliceDecap[i] {
			t.Fatalf("Alice shared secret mismatch at byte %d", i)
		}
	}

	// Bob decapsulates his ciphertext — must match his shared secret
	bobDecap, err := bobKP.Private.Decapsulate(bobCiphertext)
	if err != nil {
		t.Fatalf("Bob Decapsulate failed: %v", err)
	}
	if len(bobShared) != len(bobDecap) {
		t.Fatalf("Bob shared secret length mismatch")
	}
	for i := range bobShared {
		if bobShared[i] != bobDecap[i] {
			t.Fatalf("Bob shared secret mismatch at byte %d", i)
		}
	}

	// Alice's ciphertext must NOT produce the same shared secret when
	// decapsulated by Bob (Kyber KEM uses FO transform which returns a
	// decoupled/dummy shared secret on mismatch rather than an error —
	// this is by design to prevent CCA attacks).
	bobDecapAlice, err := bobKP.Private.Decapsulate(aliceCiphertext)
	if err != nil {
		t.Fatalf("Bob Decapsulate of Alice's ciphertext errored (Kyber KEM should not error on wrong key): %v", err)
	}
	// Bob's "decapsulation" of Alice's ciphertext must NOT equal Alice's
	// original shared secret — that would be a catastrophic KEM failure.
	if len(aliceShared) == len(bobDecapAlice) {
		matched := true
		for i := range aliceShared {
			if aliceShared[i] != bobDecapAlice[i] {
				matched = false
				break
			}
		}
		if matched {
			t.Fatal("SECURITY: Bob's decapsulation of Alice's ciphertext produced the same shared secret as Alice — KEM failure")
		}
	}
}
