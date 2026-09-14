// Quantaureum Node source, version 1.0.0.
package p2p

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

// Errors
var (
	ErrInvalidKey       = errors.New("invalid key")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrInvalidNonce     = errors.New("invalid nonce")
	// audit-fix M-1: nonce exhaustion requires key renegotiation
	ErrNonceExhausted = errors.New("nonce counter exhausted, renegotiate keys")
)

// SecureChannel provides encrypted communication
type SecureChannel struct {
	sendKey    []byte
	recvKey    []byte
	sendCipher cipher.AEAD
	recvCipher cipher.AEAD
	sendNonce  uint64
	recvNonce  uint64
	// audit-fix C-2: protect nonce counters from concurrent access
	sendMu sync.Mutex
	recvMu sync.Mutex
	// audit-fix M-4: sync.Once ensures Close is idempotent and avoids
	// potential deadlock from repeated lock acquisition.
	closeOnce sync.Once
}

// NewSecureChannel creates a new secure channel from a shared secret.
// audit-fix H-3: works on an internal copy of the shared secret and zeros it
// after key derivation to prevent key material from lingering in memory.
func NewSecureChannel(sharedSecret []byte, isInitiator bool) (*SecureChannel, error) {
	if len(sharedSecret) < 32 {
		return nil, ErrInvalidKey
	}

	// audit-fix H-3: copy the secret so we can zero our copy without
	// affecting the caller (who may still need the original, e.g. for a
	// second channel). Callers SHOULD zero their own copy when done.
	secretCopy := make([]byte, len(sharedSecret))
	copy(secretCopy, sharedSecret)
	defer func() {
		for i := range secretCopy {
			secretCopy[i] = 0
		}
	}()

	// Derive keys using HKDF
	hkdfReader := hkdf.New(sha256.New, secretCopy, nil, []byte("qau-p2p-channel"))

	key1 := make([]byte, 32)
	key2 := make([]byte, 32)

	if _, err := io.ReadFull(hkdfReader, key1); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(hkdfReader, key2); err != nil {
		return nil, err
	}

	var sendKey, recvKey []byte
	if isInitiator {
		sendKey, recvKey = key1, key2
	} else {
		sendKey, recvKey = key2, key1
	}

	// Create AES-GCM ciphers
	sendBlock, err := aes.NewCipher(sendKey)
	if err != nil {
		return nil, err
	}
	sendCipher, err := cipher.NewGCM(sendBlock)
	if err != nil {
		return nil, err
	}

	recvBlock, err := aes.NewCipher(recvKey)
	if err != nil {
		return nil, err
	}
	recvCipher, err := cipher.NewGCM(recvBlock)
	if err != nil {
		return nil, err
	}

	return &SecureChannel{
		sendKey:    sendKey,
		recvKey:    recvKey,
		sendCipher: sendCipher,
		recvCipher: recvCipher,
		sendNonce:  0,
		recvNonce:  0,
	}, nil
}

// Encrypt encrypts a message.
// audit-fix C-2: mutex protects sendNonce from concurrent access to prevent nonce reuse.
func (sc *SecureChannel) Encrypt(plaintext []byte) ([]byte, error) {
	sc.sendMu.Lock()
	defer sc.sendMu.Unlock()

	// audit-fix M-1: check for nonce counter exhaustion before increment
	if sc.sendNonce == math.MaxUint64 {
		return nil, ErrNonceExhausted
	}

	// Generate nonce from counter
	nonce := make([]byte, sc.sendCipher.NonceSize())
	sc.sendNonce++
	for i := 0; i < 8 && i < len(nonce); i++ {
		nonce[i] = byte(sc.sendNonce >> (8 * (7 - i))) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	}

	// Encrypt
	aad := []byte("QAU-P2P-v1") // SECURITY (audit P3-R2-09): Bind protocol identifier to AAD
	ciphertext := sc.sendCipher.Seal(nil, nonce, plaintext, aad)

	// Prepend nonce
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// Decrypt decrypts a message.
// audit-fix C-2: mutex protects recvNonce from concurrent access.
// audit-fix R2-H1: validates nonce is strictly monotonically increasing to
// prevent replay attacks. Replayed ciphertexts carry a stale nonce and are
// rejected before decryption.
func (sc *SecureChannel) Decrypt(ciphertext []byte) ([]byte, error) {
	sc.recvMu.Lock()
	defer sc.recvMu.Unlock()

	nonceSize := sc.recvCipher.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidNonce
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	// audit-fix R2-H1: parse nonce as big-endian uint64 and enforce monotonicity
	var receivedNonce uint64
	for i := 0; i < 8 && i < len(nonce); i++ {
		receivedNonce |= uint64(nonce[i]) << (8 * (7 - i))
	}
	if receivedNonce <= sc.recvNonce {
		return nil, ErrInvalidNonce
	}

	// Decrypt
	aad := []byte("QAU-P2P-v1")
	plaintext, err := sc.recvCipher.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// Update recvNonce only after successful decryption
	sc.recvNonce = receivedNonce

	return plaintext, nil
}

// EncryptWithKey encrypts data with a given key (for one-off encryption)
func EncryptWithKey(key, plaintext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte("QAU-P2P-v1")) // P3-R2-09: AAD protocol binding

	// Prepend nonce
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// DecryptWithKey decrypts data with a given key
func DecryptWithKey(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrInvalidNonce
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte("QAU-P2P-v1")) // P3-R2-09: AAD protocol binding
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// DeriveKey derives a key from a password and salt using HKDF.
// audit-fix N-5: returns error instead of silently ignoring HKDF failures.
func DeriveKey(password, salt []byte) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, password, salt, []byte("qau-key-derivation"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}
	return key, nil
}

func DeriveKeyFromPassword(password, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password must not be empty")
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("salt must be at least 16 bytes for password derivation")
	}
	// audit-fix LOW: Use N=262144 (2^18) to match project standard in
	// crypto/keystore.go and security/keyrotation/rotation.go. Previous
	// N=32768 (2^15) only met OWASP minimum but was inconsistent with
	// the project's stronger security baseline.
	key, err := scrypt.Key(password, salt, 262144, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}
	return key, nil
}

// Close zeros all key material and resets nonce counters.
// audit-fix L-3: prevents key material from persisting in memory after use.
// audit-fix M-4: uses sync.Once for idempotent close. Lock ordering is
// sendMu -> recvMu; this is safe because Encrypt only holds sendMu and
// Decrypt only holds recvMu — no inverse ordering exists.
func (sc *SecureChannel) Close() {
	sc.closeOnce.Do(func() {
		sc.sendMu.Lock()
		sc.recvMu.Lock()

		for i := range sc.sendKey {
			sc.sendKey[i] = 0
		}
		for i := range sc.recvKey {
			sc.recvKey[i] = 0
		}
		sc.sendNonce = 0
		sc.recvNonce = 0
		// audit-fix H-5: nil cipher objects to release internal expanded key
		// state held by the AES-GCM implementation. Subsequent Encrypt/Decrypt
		// calls will panic (nil dereference), which is correct — the channel
		// must not be used after Close.
		sc.sendCipher = nil
		sc.recvCipher = nil

		sc.recvMu.Unlock()
		sc.sendMu.Unlock()
	})
}

// GenerateRandomKey generates a random 32-byte key
func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}
