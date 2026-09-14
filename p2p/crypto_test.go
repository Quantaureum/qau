// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"testing"
)

func TestCryptoNewSecureChannel(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	ch, err := NewSecureChannel(sharedSecret, true)
	if err != nil {
		t.Fatalf("NewSecureChannel failed: %v", err)
	}
	defer ch.Close()
}

func TestCryptoNewSecureChannelShortKey(t *testing.T) {
	_, err := NewSecureChannel([]byte{1, 2, 3}, true)
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestCryptoEncryptDecrypt(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	// Initiator side
	ch1, err := NewSecureChannel(sharedSecret, true)
	if err != nil {
		t.Fatalf("NewSecureChannel (initiator) failed: %v", err)
	}
	defer ch1.Close()

	// Responder side
	ch2, err := NewSecureChannel(sharedSecret, false)
	if err != nil {
		t.Fatalf("NewSecureChannel (responder) failed: %v", err)
	}
	defer ch2.Close()

	plaintext := []byte("hello secure world")

	// ch1 encrypts, ch2 decrypts
	ciphertext, err := ch1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := ch2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestCryptoEncryptWithKeyDecryptWithKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("test data for encryption")

	ciphertext, err := EncryptWithKey(key, plaintext)
	if err != nil {
		t.Fatalf("EncryptWithKey failed: %v", err)
	}

	decrypted, err := DecryptWithKey(key, ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithKey failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestCryptoEncryptWithKeyInvalidKey(t *testing.T) {
	_, err := EncryptWithKey([]byte{1, 2, 3}, []byte("data"))
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestCryptoDecryptWithKeyInvalidKey(t *testing.T) {
	_, err := DecryptWithKey([]byte{1, 2, 3}, []byte("data"))
	if err != ErrInvalidKey {
		t.Errorf("expected ErrInvalidKey, got %v", err)
	}
}

func TestCryptoDecryptWithKeyTooShort(t *testing.T) {
	key := make([]byte, 32)
	_, err := DecryptWithKey(key, []byte{1, 2})
	if err != ErrInvalidNonce {
		t.Errorf("expected ErrInvalidNonce, got %v", err)
	}
}

func TestCryptoDeriveKey(t *testing.T) {
	key, err := DeriveKey([]byte("password"), []byte("salt"))
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("len(key) = %d, want 32", len(key))
	}
}

func TestCryptoDeriveKeyFromPassword(t *testing.T) {
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}

	key, err := DeriveKeyFromPassword([]byte("password123"), salt)
	if err != nil {
		t.Fatalf("DeriveKeyFromPassword failed: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("len(key) = %d, want 32", len(key))
	}
}

func TestCryptoDeriveKeyFromPasswordEmptyPassword(t *testing.T) {
	_, err := DeriveKeyFromPassword([]byte{}, make([]byte, 16))
	if err == nil {
		t.Error("expected error for empty password")
	}
}

func TestCryptoDeriveKeyFromPasswordShortSalt(t *testing.T) {
	_, err := DeriveKeyFromPassword([]byte("password"), []byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for short salt")
	}
}

func TestCryptoGenerateRandomKey(t *testing.T) {
	key1, err := GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey failed: %v", err)
	}
	if len(key1) != 32 {
		t.Errorf("len(key) = %d, want 32", len(key1))
	}

	key2, err := GenerateRandomKey()
	if err != nil {
		t.Fatalf("GenerateRandomKey failed: %v", err)
	}

	// Two random keys should be different
	same := true
	for i := range key1 {
		if key1[i] != key2[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("two random keys should be different")
	}
}

func TestCryptoSecureChannelDecryptReplay(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	ch1, _ := NewSecureChannel(sharedSecret, true)
	defer ch1.Close()
	ch2, _ := NewSecureChannel(sharedSecret, false)
	defer ch2.Close()

	plaintext := []byte("test message")
	ciphertext, _ := ch1.Encrypt(plaintext)

	// First decrypt should succeed
	_, err := ch2.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("first Decrypt failed: %v", err)
	}

	// Replay should be rejected
	_, err = ch2.Decrypt(ciphertext)
	if err != ErrInvalidNonce {
		t.Errorf("expected ErrInvalidNonce for replay, got %v", err)
	}
}

func TestCryptoSecureChannelDecryptTooShort(t *testing.T) {
	sharedSecret := make([]byte, 32)
	ch, _ := NewSecureChannel(sharedSecret, true)
	defer ch.Close()

	_, err := ch.Decrypt([]byte{1, 2})
	if err != ErrInvalidNonce {
		t.Errorf("expected ErrInvalidNonce, got %v", err)
	}
}

func TestCryptoSecureChannelCloseIdempotent(t *testing.T) {
	sharedSecret := make([]byte, 32)
	ch, _ := NewSecureChannel(sharedSecret, true)

	// Close twice should not panic
	ch.Close()
	ch.Close()
}

func TestCryptoSecureChannelMultipleEncrypt(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}

	ch1, _ := NewSecureChannel(sharedSecret, true)
	defer ch1.Close()
	ch2, _ := NewSecureChannel(sharedSecret, false)
	defer ch2.Close()

	for i := 0; i < 10; i++ {
		plaintext := []byte("message")
		ciphertext, err := ch1.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt(%d) failed: %v", i, err)
		}

		decrypted, err := ch2.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt(%d) failed: %v", i, err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Decrypt(%d) = %q, want %q", i, string(decrypted), string(plaintext))
		}
	}
}

func TestConstantTimeEqual(t *testing.T) {
	a := []byte("hello")
	b := []byte("hello")
	c := []byte("world")

	if !ConstantTimeEqual(a, b) {
		t.Error("identical slices should be equal")
	}
	if ConstantTimeEqual(a, c) {
		t.Error("different slices should not be equal")
	}
}

func TestCryptoSecureChannelDecryptInvalidCiphertext(t *testing.T) {
	sharedSecret := make([]byte, 32)
	ch, _ := NewSecureChannel(sharedSecret, true)
	defer ch.Close()

	// Create a ciphertext with valid nonce but invalid encrypted data
	nonce := make([]byte, 12) // AES-GCM nonce size
	fakeCiphertext := append(nonce, make([]byte, 20)...)

	_, err := ch.Decrypt(fakeCiphertext)
	if err == nil {
		t.Error("expected error for invalid ciphertext")
	}
}

func TestCryptoSecureChannelNonceExhaustion(t *testing.T) {
	sharedSecret := make([]byte, 32)
	ch, _ := NewSecureChannel(sharedSecret, true)
	defer ch.Close()

	// Simulate nonce exhaustion by setting sendNonce to MaxUint64
	ch.sendMu.Lock()
	ch.sendNonce = ^uint64(0) // MaxUint64
	ch.sendMu.Unlock()

	_, err := ch.Encrypt([]byte("test"))
	if err != ErrNonceExhausted {
		t.Errorf("expected ErrNonceExhausted, got %v", err)
	}
}
