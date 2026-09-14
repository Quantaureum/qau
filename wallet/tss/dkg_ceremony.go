// Quantaureum Node source, version 1.0.0.
// dkg_ceremony.go — exported helpers for the offline DKG ceremony tool
// (cmd/tss_dkg_gen). The DKG tool needs to encrypt ONE validator's share
// blob with the same AES-256-GCM + scrypt(N=2^18) scheme used by the
// node-side ImportKeySharesEncrypted path, so that the node can decrypt
// the share file on startup with QAU_VALIDATOR_KEY_PASSWORD.
//
// WHY EXPORTED HELPERS IN wallet/tss (not in cmd/tss_dkg_gen):
//  1. The encryption shares the tssMagic header constant with the node path
//     so a single validator file is wire-compatible. tssMagic is package-
//     private; moving it to an exported helper keeps the wire-format
//     definition in one place (DRY/ceremony single-source-of-truth).
//  2. The Decryption round-trip is unit-testable from the tss package
//     without forcing cmd/tss_dkg_gen to duplicate scrypt/GCM parameters.
//  3. wallet/tss is the canonical location for share persistence format
//     decisions; re-implementing crypto in the cmd tool would create a
//     parallel format that could drift.
//
// FORMAT (matches ExportKeySharesEncrypted):
//
//	[tssMagic (6 bytes)] [salt (32 bytes)] [nonce (12 bytes)] [ciphertext]
//
// The ciphertext is AES-256-GCM of the plaintext with tssMagic as AAD
// (the SAME AAD ImportKeySharesEncrypted uses). This is mandatory: any
// ceremony file written here MUST decrypt cleanly through the node's
// existing ImportKeySharesEncrypted path with the same password.
package tss

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/scrypt"
)

// EncryptSingleShareBlob encrypts a single-validator share wire payload
// (built by the caller) using the SAME AES-256-GCM + scrypt(N=2^18)
// parameters + tssMagic AAD as ExportKeySharesEncrypted. The output is
// byte-for-byte compatible with ImportKeySharesEncrypted on the node side:
//
//	node-side import:
//	  data := os.ReadFile(tssKeyShareFile)
//	  tss.ImportKeySharesEncrypted(data, password)
//	  -> one share loaded with ParticipantID=N
//
// Inputs:
//   - plaintext:  the single-share wire blob (owner: caller)
//   - password:   TSS encryption password (16+ bytes recommended)
//
// The AAD is fixed to tssMagic so node-side ImportKeySharesEncrypted
// (which uses tssMagic as AAD) can decrypt the file without changes. The
// plaintext is NOT modified; the caller is responsible for zeroizing it
// (via SecureZero) once encryption succeeds.
func EncryptSingleShareBlob(plaintext, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password required for encrypted TSS single-share export")
	}
	if len(plaintext) == 0 {
		return nil, errors.New("plaintext empty")
	}

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	key, err := scrypt.Key(password, salt, 1<<18, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// CRITICAL: tssMagic is the AES-GCM AAD here, mirroring
	// ExportKeySharesEncrypted. Node-side ImportKeySharesEncrypted uses the
	// same AAD — any divergence breaks wire compatibility.
	ciphertext := gcm.Seal(nil, nonce, plaintext, tssMagic)
	zeroBytes(key)

	output := make([]byte, 0, len(tssMagic)+32+12+len(ciphertext))
	output = append(output, tssMagic...)
	output = append(output, salt...)
	output = append(output, nonce...)
	output = append(output, ciphertext...)
	return output, nil
}

// DecryptSingleShareBlob is the inverse of EncryptSingleShareBlob. Uses
// tssMagic as AAD (matching ImportKeySharesEncrypted) so the test suite can
// verify round-trips and so ceremonies can inspect previously written share
// files' wire-format content before distribution.
//
// Most operators will NOT use this function directly — the node's
// ImportKeySharesEncrypted is the canonical decryption path. This function
// exists for tool-side round-trip tests.
func DecryptSingleShareBlob(data, password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password required for TSS single-share decrypt")
	}

	magicLen := len(tssMagic)
	if len(data) < magicLen+32+12 {
		return nil, errors.New("encrypted single-share data too short")
	}
	if string(data[:magicLen]) != string(tssMagic) {
		return nil, errors.New("invalid magic header: not an encrypted TSS key share file")
	}

	offset := magicLen
	salt := data[offset : offset+32]
	offset += 32
	nonce := data[offset : offset+12]
	offset += 12
	ciphertext := data[offset:]

	key, err := scrypt.Key(password, salt, 1<<18, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("scrypt key derivation failed: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		zeroBytes(key)
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, tssMagic)
	zeroBytes(key)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password or corrupted data): %w", err)
	}
	return plaintext, nil
}

// SecureZero overwrites a byte slice with zeros. Re-exported here so the
// ceremony tool (cmd/tss_dkg_gen) doesn't need to depend on the qtd
// sub-package just for memory wipe.
//
// Note: for cryptographic-grade zeroization that resists compiler
// optimisations and dead-store elimination, use qtd.SecurelyZeroMemory
// instead. This helper is a convenience wrapper for tool-internal buffers.
func SecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroBytes is an internal convenience that calls SecureZero. Avoids
// shadowing behavior across files.
func zeroBytes(b []byte) {
	SecureZero(b)
}
