// Quantaureum Node source, version 1.0.0.
// Package accounts provides account management for Quantaureum blockchain.
// It handles key generation, storage, and signing using Dilithium3 post-quantum cryptography.
package accounts

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// Errors
var (
	ErrAccountNotFound   = errors.New("account not found")
	ErrInvalidPassword   = errors.New("invalid password")
	ErrInvalidKeystore   = errors.New("invalid keystore format")
	ErrKeystoreCorrupted = errors.New("keystore corrupted")
	ErrAccountLocked     = errors.New("account is locked")
	ErrInvalidPrivateKey = errors.New("invalid private key")
)

// Account represents a Quantaureum account with Dilithium3 keys
type Account struct {
	Address    types.Address
	PrivateKey *crypto.PrivateKey
	PublicKey  *crypto.PublicKey
	CreatedAt  time.Time
}

// NewAccount generates a new account with a fresh key pair
func NewAccount() (*Account, error) {
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return &Account{
		Address:    keyPair.Public.Address(),
		PrivateKey: keyPair.Private,
		PublicKey:  keyPair.Public,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// NewAccountFromPrivateKey creates an account from an existing private key
func NewAccountFromPrivateKey(privateKey *crypto.PrivateKey) (*Account, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}

	publicKey := privateKey.PublicKey()
	if publicKey == nil {
		return nil, ErrInvalidPrivateKey
	}

	return &Account{
		Address:    publicKey.Address(),
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// Sign signs a message using the account's private key
func (a *Account) Sign(message []byte) ([]byte, error) {
	if a.PrivateKey == nil {
		return nil, ErrAccountLocked
	}
	return a.PrivateKey.Sign(message)
}

// Verify verifies a signature using the account's public key
func (a *Account) Verify(message, signature []byte) bool {
	if a.PublicKey == nil {
		return false
	}
	return a.PublicKey.Verify(message, signature)
}

// IsLocked returns true if the account's private key is not available
func (a *Account) IsLocked() bool {
	return a.PrivateKey == nil
}

// Lock securely zeroes and clears the private key from memory.
// audit-fix NEW-20 / LEGACY-2: Use Zeroize() for deterministic multi-pass
// key zeroing instead of single-pass Destroy().
func (a *Account) Lock() {
	if a.PrivateKey != nil {
		a.PrivateKey.Zeroize()
	}
	a.PrivateKey = nil
}

// KeystoreParams holds parameters for keystore encryption
type KeystoreParams struct {
	N     int // scrypt N parameter
	R     int // scrypt R parameter
	P     int // scrypt P parameter
	DKLen int // derived key length
}

// DefaultKeystoreParams returns default keystore encryption parameters
func DefaultKeystoreParams() KeystoreParams {
	return KeystoreParams{
		N:     262144, // 2^18
		R:     8,
		P:     1,
		DKLen: 32,
	}
}

// LightKeystoreParams returns lighter parameters for testing
func LightKeystoreParams() KeystoreParams {
	return KeystoreParams{
		// Must be >= crypto.MinScryptN to pass keystore validation.
		N:     crypto.MinScryptN,
		R:     8,
		P:     1,
		DKLen: 32,
	}
}

// ExportKeystore encrypts and exports an account to keystore format.
//
// SECURITY (AUDIT-FULL ROUND4 LOW-01): The string password parameter cannot
// be reliably zeroed from memory after use because Go strings are immutable
// and their backing memory is managed by the GC. Prefer ExportKeystoreBytes
// with a []byte password that callers can zero via crypto.ZeroBytesSecure.
// This function is retained for backward compatibility; new code MUST use
// the Bytes variant.
func ExportKeystore(account *Account, password string) ([]byte, error) {
	return ExportKeystoreWithParams(account, password, DefaultKeystoreParams())
}

// ExportKeystoreBytes encrypts and exports an account to keystore format with []byte password.
// audit-fix L-2: callers should zero the password slice after use.
func ExportKeystoreBytes(account *Account, password []byte) ([]byte, error) {
	return ExportKeystoreWithParamsBytes(account, password, DefaultKeystoreParams())
}

// ExportKeystoreWithParams encrypts and exports an account with custom
// parameters.
//
// SECURITY (AUDIT-FULL ROUND4 LOW-01): Same string-password concern as
// ExportKeystore — the string cannot be zeroed. Prefer
// ExportKeystoreWithParamsBytes with a []byte password that can be cleared
// after use. This function is retained for backward compatibility; new code
// MUST use the Bytes variant.
func ExportKeystoreWithParams(account *Account, password string, params KeystoreParams) ([]byte, error) {
	return ExportKeystoreWithParamsBytes(account, []byte(password), params)
}

// ExportKeystoreWithParamsBytes encrypts and exports an account with custom parameters and []byte password.
// audit-fix L-2: callers should zero the password slice after use.
func ExportKeystoreWithParamsBytes(account *Account, password []byte, params KeystoreParams) ([]byte, error) {
	if account == nil || account.PrivateKey == nil {
		return nil, ErrAccountLocked
	}

	scryptParams := crypto.ScryptParams{
		N:     params.N,
		R:     params.R,
		P:     params.P,
		DKLen: params.DKLen,
	}

	keyFile, err := crypto.EncryptKeyWithParamsBytes(account.PrivateKey, password, scryptParams)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	return keyFile.ToJSON()
}

// ImportKeystore decrypts a keystore file and returns the account.
// SECURITY: Prefer ImportKeystoreBytes with a []byte password that can be
// zeroed after use. This string-based variant cannot reliably clear the
// password from memory because Go strings are immutable.
func ImportKeystore(keystoreData []byte, password string) (*Account, error) {
	// Convert to []byte so we can zero it, but note the original string
	// remains in memory until GC — callers should prefer ImportKeystoreBytes.
	pwdBytes := []byte(password)
	return ImportKeystoreBytes(keystoreData, pwdBytes)
}

// ImportKeystoreBytes decrypts a keystore file and returns the account with []byte password.
// audit-fix L-2: callers should zero the password slice after use.
//
//	[HIGH] FIX: zero the password slice via defer to prevent plaintext password
//
// from persisting in memory after decryption. The previous comment left this to callers,
// creating a fragile contract. Now enforced internally.
func ImportKeystoreBytes(keystoreData []byte, password []byte) (*Account, error) {
	// SECURITY (audit P3-13): Make a local copy of the password to avoid
	// modifying the caller's slice. Zeroize the local copy after use.
	pwdCopy := make([]byte, len(password))
	copy(pwdCopy, password)
	// FIX: defer password zeroization regardless of success/failure path.
	// L11-005 FIX: Use crypto.ZeroBytesSecure to prevent compiler optimization.
	defer func() {
		crypto.ZeroBytesSecure(pwdCopy)
	}()

	keyFile, err := crypto.KeyFileFromJSON(keystoreData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeystore, err)
	}

	privateKey, err := crypto.DecryptKeyBytes(keyFile, pwdCopy)
	if err != nil {
		if err == crypto.ErrInvalidPassword {
			return nil, ErrInvalidPassword
		}
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	return NewAccountFromPrivateKey(privateKey)
}

// GetKeystoreAddress extracts the address from a keystore file without decrypting
func GetKeystoreAddress(keystoreData []byte) (types.Address, error) {
	// Keep address-only parsing subject to the same bound as full keystore parsing.
	// This prevents oversized JSON from reaching encoding/json.
	const maxKeystoreSize = 16 * 1024
	if len(keystoreData) > maxKeystoreSize {
		return types.Address{}, ErrInvalidKeystore
	}

	var keyFile struct {
		Address string `json:"address"`
	}

	if err := json.Unmarshal(keystoreData, &keyFile); err != nil {
		return types.Address{}, ErrInvalidKeystore
	}

	return types.ParseAddress(keyFile.Address)
}

// ValidateKeystore checks if a keystore file is valid (without decrypting).
//
// R30-IMPLEMENT (2026-07-27): P2-KEYSTORE-COMPLETENESS — previously this
// function only checked version == 1, cipher name, and KDF name, missing:
//   - Input size limit (OOM protection — a malicious 100MB JSON blob would
//     be parsed before any check)
//   - Version 2 support (v2 uses AAD, see crypto.KeyFileVersionV2)
//   - Address non-empty check (v2 only)
//   - Ciphertext non-empty check (v2 only)
//   - Nonce length check (v2 only, must be exactly crypto.NonceSize = 12 for AES-GCM)
//   - Salt length check (v2 only, must be exactly crypto.SaltSize = 32 for scrypt)
//   - Scrypt parameter range checks (v2 only, N, R, P, DKLen)
//
// Version 1 (legacy) validation is intentionally LENIENT: it only checks
// version number, cipher name, and kdf name. This preserves backward
// compatibility with existing v1 keystore files that may have been created
// with incomplete fields, and matches the original ValidateKeystore
// contract (the old TestValidateKeystore_Valid provides a minimal v1
// keystore with only version/address/cipher/kdf and expects it to pass).
//
// Version 2 (KeyFileVersionV2) validation is STRICT: it checks ALL fields
// comprehensively so malformed v2 keystores are rejected WITHOUT performing
// expensive cryptographic work (scrypt derivation). v2 is the new format
// that binds metadata as AAD (CRYPTO-); new encryptions use v2, and
// callers should migrate legacy v1 keystores via crypto.MigrateKeyFile.
//
// JSON parse errors return ErrInvalidKeystore directly (not wrapped) so
// callers using == comparison (e.g. the personal_* RPC handlers) can
// distinguish "not a keystore" from "keystore with invalid fields".
func ValidateKeystore(keystoreData []byte) error {
	// SECURITY (audit P2-11): Limit total JSON input size to prevent OOM DoS.
	// A valid keystore JSON is typically 8-12KB; 16KB is a safe upper bound
	// (matches crypto.KeyFileFromJSON's maxKeyFileJSONSize). Use strict >
	// so exactly 16KB passes (JSON allows leading/trailing whitespace).
	const maxKeystoreSize = 16 * 1024 // 16KB
	if len(keystoreData) > maxKeystoreSize {
		return fmt.Errorf("%w: input exceeds size limit", ErrInvalidKeystore)
	}

	var keyFile struct {
		Version int    `json:"version"`
		Address string `json:"address"`
		Crypto  struct {
			Cipher       string `json:"cipher"`
			Ciphertext   string `json:"ciphertext"`
			CipherParams struct {
				Nonce string `json:"nonce"`
			} `json:"cipherparams"`
			KDF       string `json:"kdf"`
			KDFParams struct {
				Salt  string `json:"salt"`
				N     int    `json:"n"`
				R     int    `json:"r"`
				P     int    `json:"p"`
				DKLen int    `json:"dklen"`
			} `json:"kdfparams"`
		} `json:"crypto"`
	}

	// Return ErrInvalidKeystore DIRECTLY (not wrapped) for JSON parse errors
	// so callers using == comparison work (legacy contract).
	if err := json.Unmarshal(keystoreData, &keyFile); err != nil {
		return ErrInvalidKeystore
	}

	// R30-IMPLEMENT: Accept both v1 (legacy, no AAD) and v2 (with AAD).
	// See crypto.KeyFileVersion / crypto.KeyFileVersionV2 doc comments.
	if keyFile.Version != crypto.KeyFileVersion && keyFile.Version != crypto.KeyFileVersionV2 {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidKeystore, keyFile.Version)
	}

	// Cipher must be aes-256-gcm (checked for both v1 and v2).
	if keyFile.Crypto.Cipher != "aes-256-gcm" {
		return fmt.Errorf("%w: unsupported cipher", ErrInvalidKeystore)
	}

	// KDF must be scrypt (checked for both v1 and v2).
	if keyFile.Crypto.KDF != "scrypt" {
		return fmt.Errorf("%w: unsupported KDF", ErrInvalidKeystore)
	}

	// R30-IMPLEMENT: v1 (legacy) validation is LENIENT — only version,
	// cipher name, and kdf name are checked. This preserves backward
	// compatibility with existing v1 keystore files and matches the
	// original ValidateKeystore contract. v1 keystores created before the
	// strict validation was introduced may have incomplete fields; rejecting
	// them now would break existing workflows. Callers who need strict
	// validation should migrate to v2 via crypto.MigrateKeyFile.
	if keyFile.Version == crypto.KeyFileVersion {
		return nil
	}

	// R30-IMPLEMENT: v2 (KeyFileVersionV2) validation is STRICT — check ALL
	// fields comprehensively so malformed v2 keystores are rejected upfront
	// without performing expensive scrypt derivation. v2 is the new format
	// and callers expect it to be well-formed.

	// Address must be non-empty.
	if keyFile.Address == "" {
		return fmt.Errorf("%w: missing address", ErrInvalidKeystore)
	}

	// Ciphertext must be non-empty (base64-decoded).
	if keyFile.Crypto.Ciphertext == "" {
		return fmt.Errorf("%w: missing ciphertext", ErrInvalidKeystore)
	}
	if _, err := base64.StdEncoding.DecodeString(keyFile.Crypto.Ciphertext); err != nil {
		return fmt.Errorf("%w: invalid ciphertext encoding", ErrInvalidKeystore)
	}

	// Nonce must be exactly crypto.NonceSize bytes (base64-decoded).
	nonce, err := base64.StdEncoding.DecodeString(keyFile.Crypto.CipherParams.Nonce)
	if err != nil {
		return fmt.Errorf("%w: invalid nonce encoding", ErrInvalidKeystore)
	}
	if len(nonce) != crypto.NonceSize {
		return fmt.Errorf("%w: invalid nonce length", ErrInvalidKeystore)
	}

	// Salt must be exactly crypto.SaltSize bytes (base64-decoded).
	salt, err := base64.StdEncoding.DecodeString(keyFile.Crypto.KDFParams.Salt)
	if err != nil {
		return fmt.Errorf("%w: invalid salt encoding", ErrInvalidKeystore)
	}
	if len(salt) != crypto.SaltSize {
		return fmt.Errorf("%w: invalid salt length", ErrInvalidKeystore)
	}

	// Scrypt N must be in [MinScryptN, MaxScryptN].
	if keyFile.Crypto.KDFParams.N < crypto.MinScryptN || keyFile.Crypto.KDFParams.N > crypto.MaxScryptN {
		return fmt.Errorf("%w: invalid scrypt N", ErrInvalidKeystore)
	}

	// Scrypt R must be in [MinScryptR, MaxScryptR].
	if keyFile.Crypto.KDFParams.R < crypto.MinScryptR || keyFile.Crypto.KDFParams.R > crypto.MaxScryptR {
		return fmt.Errorf("%w: invalid scrypt R", ErrInvalidKeystore)
	}

	// Scrypt P must be in [MinScryptP, MaxScryptP].
	if keyFile.Crypto.KDFParams.P < crypto.MinScryptP || keyFile.Crypto.KDFParams.P > crypto.MaxScryptP {
		return fmt.Errorf("%w: invalid scrypt P", ErrInvalidKeystore)
	}

	// DKLen must be exactly 32 for aes-256-gcm.
	if keyFile.Crypto.KDFParams.DKLen != 32 {
		return fmt.Errorf("%w: invalid DKLen", ErrInvalidKeystore)
	}

	return nil
}
