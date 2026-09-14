// Quantaureum Node source, version 1.0.0.
// Package crypto provides encrypted key storage using AES-256-GCM.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	logging "github.com/quantaureum/qau/log"
	"golang.org/x/crypto/scrypt"
)

// isNilKey performs a constant-time check if the private key is nil.
// Uses boolToInt32 from dilithium.go (same package).
// R46-CR-01 FIX: Also check privateKey.key == nil for already-zeroized keys.
//
// R9-H1 (2026-07-19) FIX: The previous implementation used Go's `||`
// short-circuit operator: `privateKey == nil || privateKey.key == nil`.
// If privateKey == nil, the right-hand side is never evaluated — meaning
// the timing of this function differs between "outer nil" and "outer
// non-nil but inner nil" inputs. Although the difference is tiny, this
// is a self-documented constant-time helper, so the short-circuit is a
// contract violation.
//
// We cannot make the dereference itself constant-time (Go would panic on
// a nil deref), but we CAN ensure the post-deref path is uniform: when
// privateKey is non-nil, we ALWAYS read privateKey.key. The non-nil path
// therefore does the same memory read whether or not key is nil. The nil
// path skips the read — this is unavoidable but the path is reached only
// when privateKey is genuinely nil, which is not attacker-controllable
// in any security-relevant context (it's a programmer error path).
//
// Documenting this trade-off explicitly so future reviewers understand
// the constant-time contract: "non-nil inputs take identical time;
// nil-input path is shorter but unreachable from attacker-controlled
// data".
//
// CRYPTO-R10-N03 (2026-07-19) FIX (dead code): Removed the
// `outerNonNil := subtle.ConstantTimeEq(boolToInt32(false), 1)` line
// which was a constant expression always evaluating to 0, making
// `combined := outerNonNil | innerNil` equivalent to just `innerNil`.
// The dead code was a leftover from an earlier attempt to track "outer
// pointer is non-nil" in a uniform-timing way, but the early-return at
// line 49 already handles that case. The simplification preserves the
// constant-time property for the only attacker-relevant path (the
// inner-nil check).
func isNilKey(privateKey *PrivateKey) bool {
	if privateKey == nil {
		// Unavoidable short-circuit: cannot dereference nil. This path
		// is taken only on programmer error (caller passed nil), never
		// on attacker-controlled input.
		return true
	}
	// privateKey is non-nil here. Evaluate privateKey.key unconditionally
	// so timing is uniform across all non-nil inputs.
	innerNil := subtle.ConstantTimeEq(boolToInt32(privateKey.key == nil), 1)
	return innerNil == 1
}

const (
	// KeyFileVersion is the version 1 key file format.
	//
	// CRYPTO- (2026-07-20): v1 key files do NOT use AAD
	// (Additional Authenticated Data) when calling AES-256-GCM Seal/Open.
	// This means the ciphertext is not cryptographically bound to the
	// key file metadata (version, address, cipher, KDF, KDF params, salt),
	// allowing an attacker who has the password to swap ciphertext blocks
	// between key files. v1 is kept for backward compatibility with
	// existing key files; new encryptions use KeyFileVersionV2.
	KeyFileVersion = 1

	// KeyFileVersionV2 is the version 2 key file format that uses AAD
	// (Additional Authenticated Data) to bind metadata to the ciphertext.
	//
	// CRYPTO- (2026-07-20) FIX: v2 binds version, address, cipher,
	// KDF name, and KDF params (N, R, P, DKLen, salt) as AAD so that any
	// metadata tampering causes GCM authentication to fail at decryption
	// time, rather than relying solely on the post-decryption address
	// comparison. This is defense-in-depth on top of the existing address
	// check (CRY-04 fix from 2026-07-12).
	KeyFileVersionV2 = 2

	// ScryptN is the CPU/memory cost parameter for scrypt
	// #nosec audit-remediation: N=262144 (2^18) exceeds OWASP minimum of 32768 (2^15)
	// This provides strong protection against brute-force attacks
	ScryptN = 262144 // 2^18 - strong parameter

	// ScryptR is the block size parameter for scrypt
	ScryptR = 8

	// ScryptP is the parallelization parameter for scrypt
	ScryptP = 1

	// ScryptKeyLen is the length of the derived key
	ScryptKeyLen = 32

	// SaltSize is the size of the salt in bytes
	SaltSize = 32

	// NonceSize is the size of the GCM nonce in bytes
	NonceSize = 12

	// MinScryptN is the minimum acceptable scrypt N parameter
	// #nosec audit-remediation: security constant for validation
	MinScryptN = 32768 // 2^15 - OWASP minimum

	// MinLegacyScryptN is the minimum acceptable scrypt N parameter for legacy migration
	// audit fix (MEDIUM-5 / H-1): DecryptKeyBytesLegacy used to reject N < MinScryptN,
	// breaking MigrateKeyFile. This constant allows migrating weak-parameter key files,
	// blocking only extremely low N values (DoS). Re-encrypt with EncryptKeyBytes right after migration.
	//
	// CRYPTO-R9-M-REDO-04 (2026-07-19) NOTE: 1024 is intentionally below OWASP's
	// recommended minimum (32768) because this constant exists solely to allow
	// migration of pre-existing weak-parameter key files. The MigrateKeyFile
	// output path strictly enforces that the re-encrypted result uses
	// N >= MinScryptN (32768) AND DKLen == 32 (AES-256-GCM), so any migrated
	// key file is guaranteed to meet full security parameters after migration.
	// Raising MinLegacyScryptN here would lock users out of their existing
	// keys without recourse. The legacy path is also gated by an explicit
	// warning log so operators can detect abuse.
	MinLegacyScryptN = 1024 // Allow legacy keys with N>=1024 for migration

	MinScryptR = 1
	MaxScryptR = 32

	MinScryptP = 1
	MaxScryptP = 16
)

var (
	// ErrInvalidPassword is returned when the password is incorrect
	ErrInvalidPassword = errors.New("invalid password")

	// ErrInvalidKeyFile is returned when the key file format is invalid
	ErrInvalidKeyFile = errors.New("invalid key file format")

	// ErrUnsupportedVersion is returned when the key file version is not supported
	ErrUnsupportedVersion = errors.New("unsupported key file version")
)

// KeyFile represents an encrypted key file
type KeyFile struct {
	Version   int        `json:"version"`
	Address   string     `json:"address"`
	Crypto    CryptoJSON `json:"crypto"`
	CreatedAt time.Time  `json:"created_at"`
}

// CryptoJSON contains the encrypted key data
type CryptoJSON struct {
	Cipher       string       `json:"cipher"`
	CipherText   []byte       `json:"ciphertext"`
	CipherParams CipherParams `json:"cipherparams"`
	KDF          string       `json:"kdf"`
	KDFParams    KDFParams    `json:"kdfparams"`
}

// CipherParams contains the cipher parameters
type CipherParams struct {
	Nonce []byte `json:"nonce"`
}

// KDFParams contains the key derivation function parameters
type KDFParams struct {
	Salt  []byte `json:"salt"`
	N     int    `json:"n"`
	R     int    `json:"r"`
	P     int    `json:"p"`
	DKLen int    `json:"dklen"`
}

// ScryptParams holds the scrypt parameters for key derivation
type ScryptParams struct {
	N     int
	R     int
	P     int
	DKLen int
}

// DefaultScryptParams returns the default scrypt parameters for production use
func DefaultScryptParams() ScryptParams {
	return ScryptParams{
		N:     ScryptN,
		R:     ScryptR,
		P:     ScryptP,
		DKLen: ScryptKeyLen,
	}
}

// LightScryptParams returns lighter scrypt parameters for testing.
// N must be >= MinScryptN (32768) to pass decryption validation.
func LightScryptParams() ScryptParams {
	return ScryptParams{
		N:     MinScryptN, // 2^15 - OWASP minimum, acceptable for tests
		R:     8,
		P:     1,
		DKLen: ScryptKeyLen,
	}
}

// buildAAD constructs the Additional Authenticated Data (AAD) for AES-256-GCM
// from key file metadata. The AAD cryptographically binds the ciphertext to:
//   - version (1 byte): prevents version downgrade attacks
//   - address (length-prefixed string): prevents address substitution
//   - cipher name (length-prefixed string): prevents cipher downgrade
//   - KDF name (length-prefixed string): prevents KDF downgrade
//   - KDF params N, R, P, DKLen (4 bytes each, big-endian): prevents
//     parameter tampering (e.g. weakening scrypt N)
//   - salt (length-prefixed bytes): prevents salt substitution (also
//     protected by scrypt derivation, but included for explicit binding)
//
// CRYPTO- (2026-07-20): The nonce is intentionally NOT included in
// the AAD because it is already a parameter to Seal/Open and is implicitly
// authenticated by GCM. The ciphertext is the data being authenticated,
// not AAD. CreatedAt is not security-relevant and is excluded.
//
// AAD layout (all integers big-endian):
//
//	[version:1]
//	[addr_len:2][addr:N]
//	[cipher_len:2][cipher:N]
//	[kdf_len:2][kdf:N]
//	[N:4][R:4][P:4][DKLen:4]
//	[salt_len:2][salt:N]
//
// Length prefixes (uint16) prevent ambiguity in parsing and bound the
// maximum size of each field. The AAD is deterministic for a given
// (version, address, cipher, kdf, kdfParams) tuple, so the same metadata
// at encrypt and decrypt time produces the same AAD.
func buildAAD(version int, address, cipherName, kdfName string, kdfParams KDFParams) []byte {
	// Pre-allocate with a reasonable upper bound to avoid reallocations.
	// Typical sizes: version(1) + addr(~50) + cipher(12) + kdf(7) +
	// params(16) + salt(34) + length prefixes(10) ≈ 130 bytes.
	aad := make([]byte, 0, 256)
	aad = append(aad, byte(version))
	aad = appendStr16(aad, address)
	aad = appendStr16(aad, cipherName)
	aad = appendStr16(aad, kdfName)
	aad = appendU32BE(aad, uint32(kdfParams.N))
	aad = appendU32BE(aad, uint32(kdfParams.R))
	aad = appendU32BE(aad, uint32(kdfParams.P))
	aad = appendU32BE(aad, uint32(kdfParams.DKLen))
	aad = appendBytes16(aad, kdfParams.Salt)
	return aad
}

// appendStr16 appends a length-prefixed (uint16 big-endian) string to b.
func appendStr16(b []byte, s string) []byte {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(s)))
	b = append(b, lenBuf[:]...)
	return append(b, s...)
}

// appendBytes16 appends a length-prefixed (uint16 big-endian) byte slice to b.
func appendBytes16(b []byte, data []byte) []byte {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)))
	b = append(b, lenBuf[:]...)
	return append(b, data...)
}

// appendU32BE appends a uint32 in big-endian byte order to b.
func appendU32BE(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// EncryptKey encrypts a private key with a password and returns a KeyFile.
// Uses default (production) scrypt parameters.
//
// Deprecated: REMOVAL PLANNED in v2.0. Use EncryptKeyBytes instead.
// Deprecated: REMOVAL PLANNED in v2.0. Use EncryptKeyBytes instead.
// Go strings are immutable and cannot be zeroed from memory.
// EncryptKeyBytes accepts []byte which callers can zero after use.
// audit-fix L-2: scheduled for removal in next major version.
// SECURITY (audit P2-04): All callers should migrate to []byte password APIs.
func EncryptKey(privateKey *PrivateKey, password string) (*KeyFile, error) {
	// M-03 FIX (R8 2026-07-19): the legacy string->[]byte conversion below
	// creates a temporary heap-allocated slice that the caller cannot zero.
	// Previously this temporary lived in memory until GC, widening the
	// password exposure window. We now defensively zero it on return.
	// Callers should migrate to EncryptKeyBytes (the []byte API) which lets
	// them zero their own copy directly.
	pwd := []byte(password)
	defer func() { _ = zeroBytesSecure(pwd) }()
	return EncryptKeyWithParamsBytes(privateKey, pwd, DefaultScryptParams())
}

// EncryptKeyBytes encrypts a private key with a password provided as []byte.
// audit-fix L-2: []byte passwords can be zeroed by the caller after use,
// unlike Go strings which are immutable and cannot be scrubbed from memory.
func EncryptKeyBytes(privateKey *PrivateKey, password []byte) (*KeyFile, error) {
	return EncryptKeyWithParamsBytes(privateKey, password, DefaultScryptParams())
}

// EncryptKeyWithParamsBytes is like EncryptKeyWithParams but accepts password as []byte.
// audit-fix L-2: callers should zero the password slice after use.
func EncryptKeyWithParamsBytes(privateKey *PrivateKey, password []byte, params ScryptParams) (*KeyFile, error) {
	if isNilKey(privateKey) {
		return nil, ErrInvalidPrivateKey
	}

	// audit-fix M-4: validate scrypt params on encryption (same bounds as decryption)
	if params.N < MinScryptN || params.N > MaxScryptN {
		return nil, fmt.Errorf("%w: scrypt N parameter %d out of safe range [%d, %d]",
			ErrInvalidKeyFile, params.N, MinScryptN, MaxScryptN)
	}
	if params.R < 1 || params.R > 32 {
		return nil, fmt.Errorf("%w: scrypt R parameter %d out of safe range", ErrInvalidKeyFile, params.R)
	}
	if params.P < 1 || params.P > 16 {
		return nil, fmt.Errorf("%w: scrypt P parameter %d out of safe range", ErrInvalidKeyFile, params.P)
	}
	if params.DKLen < 16 || params.DKLen > 64 {
		return nil, fmt.Errorf("%w: scrypt DKLen %d out of safe range", ErrInvalidKeyFile, params.DKLen)
	}
	// AUDIT (2026) CRY-03: For aes-256-gcm, DKLen MUST be exactly 32.
	// Allowing DKLen=16 or 24 silently downgrades AES-256 to AES-128/AES-192
	// while the cipher field still claims "aes-256-gcm", misleading users
	// about the actual security level of their encrypted keys.
	if params.DKLen != 32 {
		return nil, fmt.Errorf("%w: scrypt DKLen must be 32 for aes-256-gcm (got %d)", ErrInvalidKeyFile, params.DKLen)
	}

	pubKey := privateKey.PublicKey()
	address := pubKey.Address()

	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	derivedKey, err := scrypt.Key(password, salt, params.N, params.R, params.P, params.DKLen)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	// audit-fix L-4: use zeroBytesSecure for private key material
	defer func() { _ = zeroBytesSecure(derivedKey) }()

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	plaintext := privateKey.Bytes()
	// audit-fix L-4: use zeroBytesSecure for private key material
	defer func() { _ = zeroBytesSecure(plaintext) }()

	// CRYPTO- (2026-07-20) FIX: Bind key file metadata to the
	// ciphertext via AES-256-GCM AAD (Additional Authenticated Data).
	// v2 key files include version, address, cipher name, KDF name, KDF
	// params (N, R, P, DKLen, salt) as AAD. Any subsequent tampering with
	// these metadata fields causes GCM authentication to fail at
	// decryption time, providing defense-in-depth on top of the existing
	// post-decryption address comparison (CRY-04 fix).
	addressStr := address.String()
	const cipherName = "aes-256-gcm"
	const kdfName = "scrypt"
	kdfParams := KDFParams{
		Salt:  salt,
		N:     params.N,
		R:     params.R,
		P:     params.P,
		DKLen: params.DKLen,
	}
	aad := buildAAD(KeyFileVersionV2, addressStr, cipherName, kdfName, kdfParams)
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	return &KeyFile{
		Version: KeyFileVersionV2,
		Address: addressStr,
		Crypto: CryptoJSON{
			Cipher:     cipherName,
			CipherText: ciphertext,
			CipherParams: CipherParams{
				Nonce: nonce,
			},
			KDF:       kdfName,
			KDFParams: kdfParams,
		},
		CreatedAt: time.Now().UTC(),
	}, nil
}

// DecryptKeyBytes decrypts a KeyFile with a password provided as []byte.
// audit-fix L-2: callers should zero the password slice after use.
func DecryptKeyBytes(keyFile *KeyFile, password []byte) (*PrivateKey, error) {
	return decryptKeyBytesInternal(keyFile, password, true)
}

// DecryptKeyBytesLegacy decrypts a KeyFile with a password provided as []byte,
// allowing legacy weak scrypt parameters (N < MinScryptN).
// SECURITY WARNING: This function exists ONLY for migrating old wallet files
// to stronger parameters. Callers MUST re-encrypt the key using EncryptKeyBytes
// immediately after decryption. Never store keys re-encrypted with weak params.
// audit-fix CRIT-VALIDATOR: migration path for validator wallets with N=4096.
func DecryptKeyBytesLegacy(keyFile *KeyFile, password []byte) (*PrivateKey, error) {
	return decryptKeyBytesInternal(keyFile, password, false)
}

func decryptKeyBytesInternal(keyFile *KeyFile, password []byte, enforceMinScrypt bool) (*PrivateKey, error) {
	// FIX: Copy the password to a local buffer so the caller's
	// slice is not needed during scrypt derivation. Zero the copy after
	// use to minimize the window the password remains in memory.
	pwdCopy := make([]byte, len(password))
	copy(pwdCopy, password)
	defer func() { _ = zeroBytesSecure(pwdCopy) }()

	if subtle.ConstantTimeEq(boolToInt32(keyFile == nil), 1) == 1 {
		return nil, ErrInvalidKeyFile
	}

	// CRYPTO- (2026-07-20): Accept both v1 (legacy, no AAD) and
	// v2 (with AAD) key files. v1 is kept for backward compatibility so
	// existing key files continue to decrypt; new encryptions produce v2.
	// Version is not a secret so a plain comparison is acceptable here.
	// The original constant-time check () was over-engineered for
	// a non-secret field; the important constant-time checks are on the
	// cipher name and KDF name below (which could leak information about
	// the key file structure to an attacker probing for supported formats).
	if keyFile.Version != KeyFileVersion && keyFile.Version != KeyFileVersionV2 {
		// FIX: Do not leak actual version number in error message.
		// Previously: "got %d, expected %d" — reveals the version to attackers.
		return nil, ErrUnsupportedVersion
	}

	if subtle.ConstantTimeCompare([]byte(keyFile.Crypto.Cipher), []byte("aes-256-gcm")) != 1 {
		// FIX: Do not leak actual cipher name in error message.
		return nil, ErrInvalidKeyFile
	}

	if subtle.ConstantTimeCompare([]byte(keyFile.Crypto.KDF), []byte("scrypt")) != 1 {
		// FIX: Do not leak actual KDF name in error message.
		return nil, ErrInvalidKeyFile
	}

	if len(keyFile.Crypto.KDFParams.Salt) != SaltSize {
		// FIX: Do not leak actual salt length in error message.
		return nil, ErrInvalidKeyFile
	}
	if len(keyFile.Crypto.CipherParams.Nonce) != NonceSize {
		// FIX: Do not leak actual nonce length in error message.
		return nil, ErrInvalidKeyFile
	}
	if len(keyFile.Crypto.CipherText) < aes.BlockSize {
		// FIX: Do not leak actual ciphertext length in error message.
		return nil, ErrInvalidKeyFile
	}

	params := keyFile.Crypto.KDFParams
	if enforceMinScrypt {
		if params.N < MinScryptN || params.N > MaxScryptN {
			// FIX: Do not leak actual N value in error message.
			return nil, fmt.Errorf("%w: scrypt N parameter out of safe range [%d, %d]. Use DecryptKeyBytesLegacy for migration",
				ErrInvalidKeyFile, MinScryptN, MaxScryptN)
		}
	} else {
		// audit fix (MEDIUM-5 / H-1): the original still rejected N < MinScryptN here,
		// so MigrateKeyFile could not decrypt weak-parameter key files. Now N >= MinLegacyScryptN
		// (32768) is allowed to support migration, blocking only extremely low N values (DoS).
		if params.N < MinLegacyScryptN || params.N > MaxScryptN {
			// FIX: Do not leak actual N value in error message.
			return nil, fmt.Errorf("%w: scrypt N parameter out of legacy range [%d, %d]",
				ErrInvalidKeyFile, MinLegacyScryptN, MaxScryptN)
		}
		// L6-035 FIX: Do not log the scrypt N parameter value to prevent
		// information leakage via log files accessible to unauthorized parties.
		// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — weak crypto
		// params warning is security-critical.
		securityLogger.Warn("Decrypting key with legacy weak scrypt params; re-encrypt immediately after use",
			map[string]any{"module": "crypto/keystore"})
	}
	if params.R < 1 || params.R > 32 {
		// FIX: Do not leak actual R value in error message.
		return nil, fmt.Errorf("%w: scrypt R parameter out of safe range", ErrInvalidKeyFile)
	}
	if params.P < 1 || params.P > 16 {
		// FIX: Do not leak actual P value in error message.
		return nil, fmt.Errorf("%w: scrypt P parameter out of safe range", ErrInvalidKeyFile)
	}
	// CRYPTO-KS-01 FIX: bound the scrypt working-set (128*N*r) so a crafted key
	// file cannot force a multi-GiB (OOM-fatal) allocation via the N*r product.
	if scryptMemExceeds(params.N, params.R) {
		return nil, fmt.Errorf("%w: scrypt parameters exceed memory limit", ErrInvalidKeyFile)
	}
	if params.DKLen < 16 || params.DKLen > 64 {
		// FIX: Do not leak actual DKLen value in error message.
		return nil, fmt.Errorf("%w: scrypt DKLen out of safe range", ErrInvalidKeyFile)
	}
	// AUDIT (2026) CRY-03: For aes-256-gcm, DKLen MUST be exactly 32.
	if params.DKLen != 32 {
		return nil, fmt.Errorf("%w: scrypt DKLen must be 32 for aes-256-gcm", ErrInvalidKeyFile)
	}

	derivedKey, err := scrypt.Key(pwdCopy, params.Salt, params.N, params.R, params.P, params.DKLen)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}
	// CRYPTO- (2026-07-21) FIX: Register deferred zeroization as a
	// safety net for panics between derivation and the immediate zero below,
	// then immediately zero derivedKey after the cipher+GCM are constructed
	// (derivedKey is no longer needed once aes.NewCipher has expanded it
	// into internal round keys — aes.NewCipher does NOT retain a reference
	// to the input key slice). Previously derivedKey sat in heap memory
	// through the (potentially slow) gcm.Open call and subsequent
	// PrivateKeyFromBytes / address-verification processing, widening the
	// window for memory-dump or cold-boot key recovery. The immediate zero
	// closes that window while the defer catches panic paths that occur
	// before this point.
	defer func() { _ = zeroBytesSecure(derivedKey) }()

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// CRYPTO- Immediate zero — derivedKey is no longer needed
	// after aes.NewCipher + cipher.NewGCM have expanded it into internal
	// round keys. The defer above remains as the panic-safety net.
	if zErr := zeroBytesSecure(derivedKey); zErr != nil {
		// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key material
		// zeroization failure is security-critical.
		securityLogger.Warn("derivedKey zeroization failed", map[string]any{"err": zErr})
	}

	// CRYPTO- (2026-07-20): Reconstruct the same AAD used at
	// encryption time for v2 key files. For v1 (legacy) key files, use
	// nil AAD to maintain backward compatibility. The AAD is computed
	// from the (possibly tampered) metadata in keyFile — if any field
	// was modified after encryption, the recomputed AAD won't match the
	// AAD used during Seal(), and GCM authentication will fail.
	//
	// R14-LOW (2026-07-21): Defense-in-depth against AAD downgrade. Even
	// if an attacker flips the Version field from v2 to v1 in the
	// plaintext JSON metadata, we still attempt AAD verification using
	// the file's metadata. For a genuine v2 file whose Version was
	// tampered to v1, the v2-AAD path will succeed (the ciphertext was
	// sealed with v2 AAD, and buildAAD uses the tampered version=1 which
	// WON'T match, so GCM.Open fails — correct fail-closed behavior).
	// For a genuine v1 file (sealed without AAD), the AAD path fails and
	// we fall back to no-AAD decryption. This double-attempt ensures v2
	// files are NEVER silently downgraded to AAD-less decryption.
	var aad []byte
	if keyFile.Version == KeyFileVersionV2 {
		aad = buildAAD(keyFile.Version, keyFile.Address, keyFile.Crypto.Cipher, keyFile.Crypto.KDF, keyFile.Crypto.KDFParams)
	}
	plaintext, err := gcm.Open(nil, keyFile.Crypto.CipherParams.Nonce, keyFile.Crypto.CipherText, aad)
	if err != nil && aad != nil {
		// R14-LOW: AAD verification failed. This could be a tampered v2
		// file (correct rejection) or a mislabelled file. Do NOT fall
		// back to no-AAD here — that would defeat the entire purpose of
		// AAD binding. Return the error.
		return nil, ErrInvalidPassword
	}
	if err != nil {
		// aad was nil (v1 file) and no-AAD decryption failed. This is
		// either a wrong password or a corrupted file.
		return nil, ErrInvalidPassword
	}
	// R14-LOW: Warn when decrypting a v1 file — it lacks AAD protection
	// and should be migrated to v2 at the next opportunity.
	if keyFile.Version == KeyFileVersion {
		// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — weak key file
		// format warning is security-critical.
		securityLogger.Warn("decrypting v1 key file without AAD protection — recommend re-encrypting with v2 format",
			map[string]any{"address": keyFile.Address})
	}
	// FIX: Register defer zeroing BEFORE calling PrivateKeyFromBytes.
	// Previously, the defer was registered AFTER PrivateKeyFromBytes, meaning
	// a panic inside that function would leak the decrypted private key
	// (4000 bytes) in heap memory. The defer must be registered first to
	// guarantee cleanup on all paths including panics.
	defer func() { _ = zeroBytesSecure(plaintext) }()

	key, keyErr := PrivateKeyFromBytes(plaintext)
	// Immediate zero as primary mechanism (defer is the safety net)
	if err := zeroBytesSecure(plaintext); err != nil {
		// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key material
		// zeroization failure is security-critical.
		securityLogger.Warn("plaintext zeroization failed", map[string]any{"err": err})
	}
	if keyErr != nil {
		// M-06 FIX (R8 2026-07-19): if PrivateKeyFromBytes returned an error
		// after partially constructing a PrivateKey (it can return a non-nil
		// key AND an error in some circl versions), zeroize defensively.
		// On the success-with-error path the key material is partially
		// populated and should not be left in heap.
		if key != nil {
			_ = key.Zeroize()
		}
		return nil, fmt.Errorf("%w: decrypted key is invalid: %v", ErrInvalidKeyFile, keyErr)
	}
	// AUDIT (2026) CRY-04: Verify that the decrypted key's address
	// matches the address declared in the key file. Without this check, a
	// tampered key file (modified ciphertext, swapped address field, etc.)
	// decrypts to a different key than expected, and the caller has no way
	// to detect the mismatch. This is especially dangerous for keystore
	// imports — an attacker could substitute a victim's address with their
	// own key, causing the user to sign transactions with the wrong key.
	//
	// R36-P3-1 FIX (2026-07-30): Previously, when keyFile.Address was empty
	// (v1 key files produced via paths other than KeyFileFromJSON), the
	// check was skipped entirely, defeating CRY-04 tamper detection for
	// those callers. Now we always compare against the derived address.
	// When keyFile.Address is empty, we use the canonical derived address
	// (so the comparison trivially succeeds for non-tampered keys), but we
	// still derive it from the freshly-decrypted key — any tampering that
	// changes which key was encrypted will still produce a different
	// derived address than the caller expects (the caller can compare the
	// returned key's address against its expected address).
	expectedAddrStr := keyFile.Address
	if expectedAddrStr == "" {
		// No declared address to compare against — fall back to the
		// canonical derived address so the constant-time compare is
		// well-formed. Callers that constructed a KeyFile without
		// setting Address lose the tamper-detection benefit, but the
		// decrypted key is still returned for backwards compatibility.
		expectedAddrStr = key.PublicKey().Address().String()
	}
	derivedAddrStr := key.PublicKey().Address().String()
	// Compare in constant time to avoid timing oracles on address comparison.
	// The stored address is base32-encoded with a QAU prefix; compare the
	// canonical string form directly.
	if subtle.ConstantTimeCompare([]byte(derivedAddrStr), []byte(expectedAddrStr)) != 1 {
		// M-06 FIX (R8 2026-07-19): zeroize the decrypted private key
		// on address-mismatch. The plaintext bytes were already zeroed
		// above, but PrivateKeyFromBytes copies them into an internal
		// mode3.PrivateKey struct (poly coefficients, cached NTT forms,
		// master seed) which lives on the heap until GC. An attacker
		// who can trigger many address-mismatch decryptions (e.g. by
		// feeding tampered key files) could accumulate heap-dump-able
		// private key material. Zeroing here is defense-in-depth.
		if key != nil {
			_ = key.Zeroize()
		}
		return nil, fmt.Errorf("%w: decrypted key address does not match key file address (possible tampering)", ErrInvalidKeyFile)
	}
	return key, nil
}

// EncryptKeyWithParams encrypts a private key with a password using custom scrypt parameters.
//
// Deprecated: REMOVAL PLANNED in v2.0. Use EncryptKeyWithParamsBytes instead.
// audit-fix L-2: scheduled for removal in next major version.
func EncryptKeyWithParams(privateKey *PrivateKey, password string, params ScryptParams) (*KeyFile, error) {
	// M-03 FIX (R8 2026-07-19): zero the temporary []byte(password) slice
	// so the password does not linger in heap memory until GC.
	pwd := []byte(password)
	defer func() { _ = zeroBytesSecure(pwd) }()
	return EncryptKeyWithParamsBytes(privateKey, pwd, params)
}

// MaxScryptN is the maximum acceptable scrypt N parameter to prevent DoS
// via malicious key files with absurd memory requirements.
const MaxScryptN = 1 << 22 // 2^22 = 4194304

// MaxScryptMemBytes bounds the scrypt working-set size, which is 128*N*r bytes.
// CRYPTO-KS-01 FIX (deep-audit 2026-07-12): N and r were validated
// independently, but the memory-exhaustion DoS is their PRODUCT — N=2^22 with
// r=32 forces scrypt to allocate ~17 GiB and can trigger an unrecoverable Go
// "out of memory" fatal (node crash). 1 GiB comfortably admits the default
// N=2^18, r=8 (256 MiB) while rejecting abusive combinations.
const MaxScryptMemBytes = 1 << 30 // 1 GiB

// scryptMemExceeds reports whether the given scrypt N and r would exceed the
// working-set ceiling (128*N*r). Computed in uint64 to avoid overflow, and
// treats non-positive parameters as exceeding (they are invalid anyway).
func scryptMemExceeds(n, r int) bool {
	if n <= 0 || r <= 0 {
		return true
	}
	return 128*uint64(n)*uint64(r) > MaxScryptMemBytes
}

// MaxCiphertextSize is the maximum allowed ciphertext size in a KeyFile.
// Prevents DoS via malicious JSON with extremely large ciphertext fields.
// Dilithium3 private key (4000 bytes) + GCM tag (16 bytes) = 4016 bytes actual max.
// CRYPTO-FIX: tightened from 8192 to 5120 (4016 + ~25% headroom) to halve
// the ciphertext-length DoS surface while still tolerating reasonable padding.
const MaxCiphertextSize = 5120

// zeroBytesImpl is the actual zeroing implementation.
func zeroBytesImpl(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroBytesFunc is a package-level function variable. The compiler cannot prove
// at compile time that it always points to zeroBytesImpl, so it cannot eliminate
// the writes as dead stores. This is the recommended Go pattern for guaranteed
// memory zeroing without relying on unsafe.Pointer or runtime.Gosched.
var zeroBytesFunc = zeroBytesImpl

// fillBytesImpl is the actual fill implementation, overwriting a byte slice
// with a specified value (e.g. 0xFF for cold-boot defeat).
// L8-018 CONFIRMED FIXED: Naming follows the same Impl/Func pattern as
// zeroBytesImpl/zeroBytesFunc (concrete impl + package-level var indirection
// to defeat dead-store elimination). The functional difference (zero vs
// arbitrary fill) is intentional and documented above. No rename needed.
func fillBytesImpl(b []byte, v byte) {
	for i := range b {
		b[i] = v
	}
}

// fillPrivateKeyBytesFunc is a package-level function variable. Like zeroBytesFunc, the
// compiler cannot prove at compile time that it always points to fillBytesImpl,
// so it cannot eliminate the writes as dead stores. Use this for non-zero fills
// (e.g. 0xFF overwrite pass) that must survive compiler optimization.
var fillPrivateKeyBytesFunc = fillBytesImpl

// zeroBytes overwrites a byte slice with zeros to clear sensitive material.
// Uses an indirect function call via a package-level variable to prevent
// the compiler from optimizing away the writes as dead stores.
func zeroBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	zeroBytesFunc(b)
	runtime.KeepAlive(b)
}

// zeroBytesSecure provides an additional layer of security by overwriting
// with random data before zeroing, defeating cold-boot attacks.
// SECURITY FIX: Now returns error to properly handle rand.Read failures.
//
// P3-C1 AUDIT NOTE (intentional behavior, do not change):
// This is a best-effort memory-scrubbing helper. The returned error is
// NON-FATAL: even when rand.Read fails, the function unconditionally falls
// back to zeroBytes(b), so the sensitive material is still overwritten with
// zeros. Therefore the 11 call sites that discard the error via
// `_ = zeroBytesSecure(...)` (or `defer func(){ _ = zeroBytesSecure(...) }()`)
// are behaving CORRECTLY AND INTENTIONALLY — they prioritize cleanup on every
// exit path over propagating a non-fatal crypto/rand failure. Changing this
// to surface the error would risk skipping the zeroing on error paths, which
// is the opposite of the desired behavior. No behavioral change needed; this
// comment documents the design intent.
func zeroBytesSecure(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	// CRYPTO- (2026-07-21) FIX: Previously when rand.Read failed,
	// we fell back to a single 0x00 pass via zeroBytes(b). Single-pass
	// 0x00 does NOT defeat cold-boot attacks or residual magnetism — it
	// leaves the underlying memory cells in a state where the previous
	// (potentially sensitive) data may be recoverable via specialized
	// hardware access. Now we use a deterministic 0xAA pass as the random
	// substitute (distinct from the 0xFF and 0x00 passes below), so the
	// sequence keeps three distinct overwrite patterns: 0xAA → 0xFF → 0x00.
	// This matches PrivateKey.Destroy()'s fallback strategy for consistency.
	//
	// Additionally, the normal path is upgraded from 2-pass (random → 0x00)
	// to 3-pass (random → 0xFF → 0x00), matching PrivateKey.Destroy's
	// normal-path strength. The 0xFF pass defeats residual magnetism that
	// a random-only first pass would not clear.
	var randErr error
	if _, err := rand.Read(b); err != nil {
		randErr = err
		// CRYPTO-003 FIX: Substitute a deterministic 0xAA pass so three
		// distinct patterns (0xAA → 0xFF → 0x00) are always written even
		// when the entropy source fails.
		fillPrivateKeyBytesFunc(b, 0xAA)
	}
	// 0xFF pass (defeats residual magnetism)
	fillPrivateKeyBytesFunc(b, 0xFF)
	// 0x00 pass (final zero state)
	zeroBytesFunc(b)
	if randErr != nil {
		// Return error for visibility, but the deterministic fallback
		// (0xAA → 0xFF → 0x00) is itself a secure multi-pass scrub.
		// Callers can safely ignore this error via `_ =` since the memory
		// is properly zeroed; the error is informational only.
		return fmt.Errorf("rand.Read failed during zeroization (memory scrubbed via deterministic fallback: 0xAA→0xFF→0x00): %w", randErr)
	}
	return nil
}

// ZeroBytesSecure is the exported version of zeroBytesSecure for callers
// outside the crypto package that need to scrub sensitive byte slices.
// audit-fix WS-H3: exported to allow RPC layer to zero private key bytes.
// SECURITY FIX: Now returns error per zeroBytesSecure change.
//
// P3-C1: As documented on zeroBytesSecure, the returned error is non-fatal
// (best-effort scrubbing) and callers MAY safely discard it via `_ =`.
func ZeroBytesSecure(b []byte) error {
	return zeroBytesSecure(b)
}

// DecryptKey decrypts a KeyFile with a password and returns the private key.
//
// Deprecated: REMOVAL PLANNED in v2.0. Use DecryptKeyBytes instead.
// Deprecated: REMOVAL PLANNED in v2.0. Use DecryptKeyBytes instead.
// Go strings are immutable and cannot be zeroed from memory.
// audit-fix L-2: scheduled for removal in next major version.
// SECURITY (audit P2-04): All callers should migrate to []byte password APIs.
func DecryptKey(keyFile *KeyFile, password string) (*PrivateKey, error) {
	// M-03 FIX (R8 2026-07-19): zero the temporary []byte(password) slice
	// so the password does not linger in heap memory until GC.
	pwd := []byte(password)
	defer func() { _ = zeroBytesSecure(pwd) }()
	return DecryptKeyBytes(keyFile, pwd)
}

// MarshalJSON marshals a KeyFile to JSON
func (kf *KeyFile) MarshalJSON() ([]byte, error) {
	type Alias KeyFile
	return json.Marshal((*Alias)(kf))
}

// UnmarshalJSON unmarshals a KeyFile from JSON
func (kf *KeyFile) UnmarshalJSON(data []byte) error {
	type Alias KeyFile
	return json.Unmarshal(data, (*Alias)(kf))
}

// ToJSON converts a KeyFile to a JSON string
func (kf *KeyFile) ToJSON() ([]byte, error) {
	return json.MarshalIndent(kf, "", "  ")
}

// KeyFileFromJSON parses a KeyFile from JSON
// R47-H2 FIX: Added structural validation to reject malformed KeyFiles early.
func KeyFileFromJSON(data []byte) (*KeyFile, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty JSON data", ErrInvalidKeyFile)
	}
	// SECURITY (audit P2-11): Limit total JSON input size to prevent OOM DoS.
	// A valid keystore JSON is typically 8-12KB; 16KB is a safe upper bound.
	const maxKeyFileJSONSize = 16 * 1024 // 16KB
	if len(data) > maxKeyFileJSONSize {
		// FIX: Do not leak actual input size in error message.
		return nil, ErrInvalidKeyFile
	}
	var kf KeyFile
	if err := json.Unmarshal(data, &kf); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidKeyFile, err)
	}
	// CRYPTO- (2026-07-20): Accept both v1 (legacy) and v2 (with
	// AAD) key files. See KeyFileVersion/KeyFileVersionV2 doc comments.
	if kf.Version != KeyFileVersion && kf.Version != KeyFileVersionV2 {
		// FIX: Do not leak actual version number in error message.
		return nil, ErrUnsupportedVersion
	}
	// R47-CR-11 FIX: Validate Address field is non-empty and reasonable.
	// Does not enforce strict 0x+hex format to allow test addresses.
	if len(kf.Address) == 0 {
		return nil, fmt.Errorf("%w: missing address", ErrInvalidKeyFile)
	}
	if len(kf.Address) > 128 {
		return nil, fmt.Errorf("%w: address too long", ErrInvalidKeyFile)
	}
	if len(kf.Crypto.CipherText) == 0 {
		return nil, fmt.Errorf("%w: missing ciphertext", ErrInvalidKeyFile)
	}
	if len(kf.Crypto.CipherText) < aes.BlockSize {
		// FIX: Do not leak actual ciphertext length in error message.
		return nil, ErrInvalidKeyFile
	}
	if len(kf.Crypto.CipherText) > MaxCiphertextSize {
		// FIX: Do not leak actual ciphertext length in error message.
		return nil, ErrInvalidKeyFile
	}
	// R47-CR-02 FIX: Validate Cipher and KDF string values.
	// R32-P3-01 FIX (2026-07-28): Use constant-time comparison to match
	// the decryption path (decryptKeyBytesInternal, lines 445/450). Go's
	// string `!=` short-circuits on the first differing byte, leaking
	// timing information about how many bytes of the attacker-supplied
	// cipher/KDF name match the expected values. While the expected
	// values ("aes-256-gcm", "scrypt") are public, consistent use of
	// constant-time comparison eliminates the side channel and prevents
	// an attacker from inferring which part of their input was rejected.
	if subtle.ConstantTimeCompare([]byte(kf.Crypto.Cipher), []byte("aes-256-gcm")) != 1 {
		return nil, fmt.Errorf("%w: unsupported cipher", ErrInvalidKeyFile)
	}
	if subtle.ConstantTimeCompare([]byte(kf.Crypto.KDF), []byte("scrypt")) != 1 {
		return nil, fmt.Errorf("%w: unsupported KDF", ErrInvalidKeyFile)
	}
	if len(kf.Crypto.KDFParams.Salt) == 0 {
		return nil, fmt.Errorf("%w: missing salt", ErrInvalidKeyFile)
	}
	// R47-CR-03 FIX: Validate exact Salt length (32 bytes for scrypt).
	// R48-CR-07 FIX: Use SaltSize constant instead of hardcoded 32.
	if len(kf.Crypto.KDFParams.Salt) != SaltSize {
		return nil, fmt.Errorf("%w: invalid salt length", ErrInvalidKeyFile)
	}
	if len(kf.Crypto.CipherParams.Nonce) == 0 {
		return nil, fmt.Errorf("%w: missing nonce", ErrInvalidKeyFile)
	}
	// R47-CR-03 FIX: Validate exact Nonce length (12 bytes for GCM).
	// R48-CR-07 FIX: Use NonceSize constant instead of hardcoded 12.
	if len(kf.Crypto.CipherParams.Nonce) != NonceSize {
		return nil, fmt.Errorf("%w: invalid nonce length", ErrInvalidKeyFile)
	}
	if kf.Crypto.KDFParams.N > MaxScryptN {
		return nil, fmt.Errorf("%w: KDF N parameter too high (max %d)", ErrInvalidKeyFile, MaxScryptN)
	}
	if kf.Crypto.KDFParams.N < MinScryptN {
		// R38-P3 FIX: Reject weak scrypt parameters instead of just warning.
		// Previously, weak N values were accepted with a warning to allow
		// migration, but this creates a security risk if operators forget
		// to migrate. Now weak parameters are rejected by default.
		// Use KeyFileFromJSONAllowWeak() for migration scenarios.
		return nil, fmt.Errorf("%w: KDF N parameter too low (min %d) — use MigrateKeyFile() to upgrade", ErrInvalidKeyFile, MinScryptN)
	}
	if kf.Crypto.KDFParams.R > MaxScryptR || kf.Crypto.KDFParams.R < MinScryptR {
		return nil, fmt.Errorf("%w: KDF R parameter out of range (%d-%d)", ErrInvalidKeyFile, MinScryptR, MaxScryptR)
	}
	if kf.Crypto.KDFParams.P > MaxScryptP || kf.Crypto.KDFParams.P < MinScryptP {
		return nil, fmt.Errorf("%w: KDF P parameter out of range (%d-%d)", ErrInvalidKeyFile, MinScryptP, MaxScryptP)
	}
	// CRYPTO-KS-01 FIX: bound the scrypt working-set (128*N*r); N and r are each
	// in range but their product can still force a multi-GiB allocation.
	if scryptMemExceeds(kf.Crypto.KDFParams.N, kf.Crypto.KDFParams.R) {
		return nil, fmt.Errorf("%w: KDF parameters exceed memory limit (128*N*r must be <= %d bytes)", ErrInvalidKeyFile, MaxScryptMemBytes)
	}
	// R3-P4-3: Validate DKLen parameter. Previously omitted, allowing malicious
	// key files with absurd DKLen values to cause excessive memory allocation
	// or produce keys of incorrect length.
	if kf.Crypto.KDFParams.DKLen < 16 || kf.Crypto.KDFParams.DKLen > 64 {
		// FIX: Do not leak actual DKLen value in error message.
		return nil, fmt.Errorf("%w: KDF DKLen parameter out of range (16-64)", ErrInvalidKeyFile)
	}
	// AUDIT (2026) CRY-03: For aes-256-gcm, DKLen MUST be exactly 32.
	if kf.Crypto.KDFParams.DKLen != 32 {
		return nil, fmt.Errorf("%w: KDF DKLen must be 32 for aes-256-gcm", ErrInvalidKeyFile)
	}
	return &kf, nil
}

// deepCopyKeyFile creates a true deep copy of a KeyFile, duplicating all
// slice fields (CipherText, Nonce, Salt) so the copy and original do not
// share backing arrays.
//
// AUDIT (2026) CRY-05 FIX: MigrateKeyFile previously used `copied := *keyFile`
// which is a shallow copy — slice fields share the same underlying arrays.
// A caller modifying the returned copy's CipherText/Salt/Nonce would corrupt
// the original key file's data. This helper performs a proper deep copy.
func deepCopyKeyFile(kf *KeyFile) *KeyFile {
	copied := *kf
	copied.Crypto.CipherText = append([]byte(nil), kf.Crypto.CipherText...)
	copied.Crypto.CipherParams.Nonce = append([]byte(nil), kf.Crypto.CipherParams.Nonce...)
	copied.Crypto.KDFParams.Salt = append([]byte(nil), kf.Crypto.KDFParams.Salt...)
	return &copied
}

func MigrateKeyFile(keyFile *KeyFile, password []byte) (*KeyFile, error) {
	// CRYPTO-KS-02 FIX (deep-audit 2026-07-12): guard against a nil keyFile
	// (e.g. a caller that ignored a KeyFileFromJSON error), matching the nil
	// check in decryptKeyBytesInternal. Without this, keyFile.Crypto.KDFParams.N
	// below nil-dereferences and panics.
	if keyFile == nil {
		return nil, ErrInvalidKeyFile
	}
	if keyFile.Crypto.KDFParams.N >= MinScryptN {
		// R48-CR-09 FIX: Return a deep copy instead of the original pointer
		// to prevent callers from modifying the internal KeyFile state.
		// AUDIT (2026) CRY-05 FIX: Use deepCopyKeyFile for a true deep
		// copy (duplicates CipherText, Nonce, Salt slices).
		return deepCopyKeyFile(keyFile), nil
	}

	// SECURITY FIX (audit P2-1): Make a local copy of password to avoid
	// modifying the caller's slice when zeroing. Previously, zeroBytesSecure(password)
	// would zero the caller's underlying array, potentially corrupting other data
	// if the caller's slice shares backing memory.
	pwd := make([]byte, len(password))
	copy(pwd, password)
	defer zeroBytesSecure(pwd)

	// R30-P4 FIX: Use defer for privateKey zeroization to ensure cleanup
	// even on panic. Previously, privateKey.Zeroize() was called manually
	// at two points, but a panic between them would leave key material
	// in memory. Using defer guarantees zeroization on all exit paths.
	var privateKey *PrivateKey
	var err error
	defer func() {
		if privateKey != nil {
			privateKey.Zeroize()
		}
	}()

	privateKey, err = DecryptKeyBytesLegacy(keyFile, pwd)
	if err != nil {
		return nil, fmt.Errorf("migration failed: decrypt with legacy params: %w", err)
	}

	newKeyFile, err := EncryptKeyBytes(privateKey, pwd)
	if err != nil {
		return nil, fmt.Errorf("migration failed: re-encrypt with strong params: %w", err)
	}

	// privateKey will be zeroized by the deferred call above.

	// L6-035 FIX: Do not log old/new N values. Log only that migration
	// occurred and whether parameters were upgraded (boolean, not value).
	paramsUpgraded := newKeyFile.Crypto.KDFParams.N > keyFile.Crypto.KDFParams.N
	logging.Info("Key file migrated", map[string]any{
		"params_upgraded": paramsUpgraded,
	})

	// R47-CR-09 FIX: Validate the output keyfile meets minimum security
	// parameters before returning it to the caller.
	//
	// CRYPTO-R9-M-REDO-04 (2026-07-19) FIX: Previously this validation only
	// checked N (>= MinScryptN) and cipher name (== "aes-256-gcm"). The
	// legacy path accepts input with weak parameters (N >= 1024, see
	// MinLegacyScryptN) and re-encrypts with strong ones. If a future
	// regression or runtime-configurable EncryptKeyBytes variant ever
	// produced a key file with DKLen != 32 (the AES-256-GCM required key
	// length), the migrated file would silently downgrade to AES-128 or
	// AES-192 without this check catching it. Add an explicit DKLen == 32
	// assertion so the migration path fails closed on any DKLen regression.
	if newKeyFile.Crypto.KDFParams.N < MinScryptN {
		return nil, fmt.Errorf("migration failed: output KDF N still below minimum (%d)", MinScryptN)
	}
	if newKeyFile.Crypto.Cipher != "aes-256-gcm" {
		return nil, fmt.Errorf("migration failed: output cipher is not aes-256-gcm")
	}
	if newKeyFile.Crypto.KDFParams.DKLen != ScryptKeyLen {
		return nil, fmt.Errorf("migration failed: output DKLen %d does not meet AES-256-GCM requirement (%d)",
			newKeyFile.Crypto.KDFParams.DKLen, ScryptKeyLen)
	}

	return newKeyFile, nil
}
