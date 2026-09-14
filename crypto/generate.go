// Quantaureum Node source, version 1.0.0.
// Package crypto provides cryptographic primitives for the Quantaureum blockchain.
// It implements post-quantum cryptography using Dilithium3 for digital signatures.
//
// =============================================================================
// SHARED INTERFACE WARNING - DO NOT MODIFY WITHOUT SYNCING WITH WALLET
// =============================================================================
// This file implements a SHARED INTERFACE with Quantaureum Wallet
// (app/scripts/lib/quantum-crypto/dilithium3.ts).
// Any changes to signature sizes, key formats, or serialization MUST be
// synchronized with the Wallet implementation.
//
// Shared parameters:
//   - Dilithium3PublicKeySize: 1952 bytes
//   - Dilithium3PrivateKeySize: 4000 bytes
//   - Dilithium3SignatureSize: 3293 bytes
//
// Wallet implementation: the quantaureum-wallet repo
// =============================================================================
package crypto

// L14-033 SECURITY NOTE: Key derivation uses scrypt with N=2^18, r=8, p=1
// parameters for password-based key encryption. This provides strong
// resistance against brute-force and rainbow table attacks. The scrypt
// parameters require approximately 256MB of memory per derivation,
// making GPU/ASIC-based attacks prohibitively expensive. For Dilithium3
// keys, the derived key is used with AES-256-GCM for symmetric encryption.
// The keystore format is "dilithium3:privkey_hex+pubkey_hex".

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"unsafe"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/sha3"

	"github.com/quantaureum/qau/types"
)

// L11-030 FIX: Compile-time assertion that bool is exactly 1 byte.
// boolToInt32 below dereferences the bool's single underlying byte via
// unsafe.Pointer, which is only valid while bool occupies exactly one byte.
// The Go spec guarantees bool is 1 byte, but we assert it at compile time so
// that a future change to the representation would break the build rather than
// silently corrupting the constant-time conversion. If unsafe.Sizeof(true) != 1,
// the array length "1 - <size>" becomes negative and the array type is invalid,
// failing compilation.
//
// C1 FIX (2026-07-06): Additionally, we add a runtime init() check as a
// defense-in-depth measure. While unsafe.Sizeof is compile-time determined in
// all mainstream Go compilers (gc, gccgo), the runtime check ensures correctness
// even on exotic implementations. The init function runs before any code that
// uses boolToInt32, providing an early failure if the invariant is violated.
var _ [1 - unsafe.Sizeof(true)]byte

func init() {
	// C1 FIX: Runtime assertion as defense-in-depth for constant-time safety.
	if unsafe.Sizeof(true) != 1 {
		panic("constant-time safety violation: bool is not 1 byte on this platform")
	}
}

// boolToInt32 converts a boolean to int32 in constant time.
//
// SECURITY FIX (R63-CRIT-1): We must convert bool→int32 (0 or 1) without any
// conditional branch, because the bool value often derives from a secret
// comparison (e.g., key equality checks in Sign/Verify/Equal methods). A branch
// on a secret-dependent condition leaks timing via the branch predictor.
//
// In Go, bool is always 1 byte (0x00=false, 0x01=true). We read that byte
// directly via unsafe.Pointer dereference — a single CPU read, no branching.
// The compiler cannot optimize this into a conditional because there is none.
// The 1-byte invariant is asserted at compile time by the var declaration above.
func boolToInt32(b bool) int32 {
	return int32(*(*byte)(unsafe.Pointer(&b)))
}

const (
	// Dilithium3PublicKeySize is the size of a Dilithium3 public key in bytes
	Dilithium3PublicKeySize = mode3.PublicKeySize // 1952 bytes

	// Dilithium3PrivateKeySize is the size of a Dilithium3 private key in bytes
	Dilithium3PrivateKeySize = mode3.PrivateKeySize // 4000 bytes

	// Dilithium3SignatureSize is the size of a Dilithium3 signature in bytes
	Dilithium3SignatureSize = mode3.SignatureSize // 3293 bytes

	// GMQTDCombinedSignatureSize is the size of a GM-QTD combined (full) threshold
	// signature in bytes. This is the signature format produced by the QTD
	// protocol when aggregating partial signatures from multiple validators.
	//
	// Composition (see wallet/tss/qtd/qtd_pack.go PackGMQTDFullSignature):
	//   ctilde      32 bytes   - challenge hash (SHA-256 of w1||message)
	//   z_vector   3840 bytes   - 5 packed response polynomials (L=5, 768 bytes each)
	//   hint_bitmap 192 bytes   - 6 hint polynomials as bitmap (K=6, 256 bits each)
	//   Total      4064 bytes
	//
	// This is distinct from Dilithium3SignatureSize (3293) which is the standard
	// single-signer Dilithium3 signature. The GM-QTD full signature uses a
	// bitmap-encoded hint instead of the packed hint format, resulting in a
	// larger but threshold-compatible signature.
	GMQTDCombinedSignatureSize = 4064
)

// R38-P3 FIX: Package-level zero buffers for Equal() comparisons.
// These live in BSS (zero-initialized) and avoid stack allocation of
// 1952/4000-byte arrays on every Equal() call.
var (
	zeroPubKeyBuf  [Dilithium3PublicKeySize]byte
	zeroPrivKeyBuf [Dilithium3PrivateKeySize]byte
)

var (
	// ErrInvalidPublicKey is returned when a public key is invalid
	ErrInvalidPublicKey = errors.New("invalid public key")

	// ErrInvalidPrivateKey is returned when a private key is invalid
	ErrInvalidPrivateKey = errors.New("invalid private key")

	// ErrInvalidSignature is returned when a signature is invalid
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrKeyGenerationFailed is returned when key generation fails
	ErrKeyGenerationFailed = errors.New("key generation failed")
)

// PrivateKey represents a Dilithium3 private key
type PrivateKey struct {
	key *mode3.PrivateKey
}

// PublicKey represents a Dilithium3 public key
type PublicKey struct {
	key *mode3.PublicKey
}

// KeyPair represents a Dilithium3 key pair
type KeyPair struct {
	Private *PrivateKey
	Public  *PublicKey
}

// GenerateKeyPair generates a new Dilithium3 key pair
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyGenerationFailed, err)
	}

	return &KeyPair{
		Private: &PrivateKey{key: priv},
		Public:  &PublicKey{key: pub},
	}, nil
}

// GenerateKeyPairFromSeed generates a deterministic Dilithium3 key pair from a 32-byte seed.
// Uses SHAKE-256 as a deterministic CSPRNG, following the NIST FIPS 204 specification
// for deterministic key generation (Algorithm 1, step 1: ξ ← H(seed)).
func GenerateKeyPairFromSeed(seed []byte) (*KeyPair, error) {
	const minSeedSize = 32 // NIST FIPS 204 requires 256-bit seed
	if len(seed) < minSeedSize {
		return nil, fmt.Errorf("%w: seed must be at least %d bytes (256 bits) for security", ErrKeyGenerationFailed, minSeedSize)
	}

	// R42-CR-001 FIX: Create a copy of the seed and zero only the copy.
	// The original seed slice may share a backing array with other data
	// (e.g., HD key derivation parent seed). Zeroing the caller's slice
	// in-place can corrupt shared memory. This is consistent with the
	// R41-CR-005 fix applied to ImportKeyPair.
	seedCopy := make([]byte, len(seed))
	copy(seedCopy, seed)
	defer zeroBytesSecure(seedCopy)

	reader := newShakeReader(seedCopy)
	pub, priv, err := mode3.GenerateKey(reader)
	if err != nil {
		// S2 FIX (2026-07-06): Reset SHAKE state on error to prevent seed
		// recovery from residual heap state.
		reader.Reset()
		return nil, fmt.Errorf("%w: %v", ErrKeyGenerationFailed, err)
	}
	// S2 FIX (2026-07-06): Reset SHAKE state after successful key generation
	// to clear internal absorbed seed material from heap memory.
	reader.Reset()

	return &KeyPair{
		Private: &PrivateKey{key: priv},
		Public:  &PublicKey{key: pub},
	}, nil
}

// shakeReader is a deterministic io.Reader backed by SHAKE-256.
type shakeReader struct {
	shake sha3.ShakeHash
}

func newShakeReader(seed []byte) *shakeReader {
	s := &shakeReader{shake: sha3.NewShake256()}
	s.shake.Write(seed)
	return s
}

func (r *shakeReader) Read(p []byte) (n int, err error) {
	return r.shake.Read(p)
}

// Reset clears the SHAKE internal state to prevent seed material from
// lingering in heap memory after key generation.
// S2 FIX (2026-07-06): Explicit state cleanup for security.
func (r *shakeReader) Reset() {
	r.shake.Reset()
}

// Bytes returns the private key as a byte slice
func (k *PrivateKey) Bytes() []byte {
	// Sequential constant-time nil checks to avoid short-circuit evaluation
	kIsNil := k == nil
	if subtle.ConstantTimeEq(boolToInt32(kIsNil), 1) == 1 {
		return nil
	}
	kKeyIsNil := k.key == nil
	if subtle.ConstantTimeEq(boolToInt32(kKeyIsNil), 1) == 1 {
		return nil
	}
	src := k.key.Bytes()
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

// Bytes returns the public key as a byte slice
func (k *PublicKey) Bytes() []byte {
	// Sequential constant-time nil checks to avoid short-circuit evaluation
	kIsNil := k == nil
	if subtle.ConstantTimeEq(boolToInt32(kIsNil), 1) == 1 {
		return nil
	}
	kKeyIsNil := k.key == nil
	if subtle.ConstantTimeEq(boolToInt32(kKeyIsNil), 1) == 1 {
		return nil
	}
	src := k.key.Bytes()
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

// PublicKey returns the public key corresponding to this private key.
// R48-CR-03 NOTE: Returns nil on error (nil receiver or nil key) for backward
// compatibility with 20+ callers. Kyber's PublicKey() returns (*Key, error),
// but changing this signature would be a breaking API change. Callers should
// check for nil return value.
// C2 FIX (2026-07-06): Added PublicKeySafe() as the preferred API returning
// (*PublicKey, error). New code should use PublicKeySafe() instead.
func (k *PrivateKey) PublicKey() *PublicKey {
	// Sequential constant-time nil checks to avoid short-circuit evaluation
	kIsNil := k == nil
	if subtle.ConstantTimeEq(boolToInt32(kIsNil), 1) == 1 {
		return nil
	}
	kKeyIsNil := k.key == nil
	if subtle.ConstantTimeEq(boolToInt32(kKeyIsNil), 1) == 1 {
		return nil
	}
	pubInterface := k.key.Public()
	pub, ok := pubInterface.(*mode3.PublicKey)
	if !ok {
		return nil
	}
	return &PublicKey{key: pub}
}

// PublicKeySafe returns the public key corresponding to this private key,
// returning an explicit error on failure instead of nil.
// C2 FIX (2026-07-06): This is the preferred API for new code, providing
// consistent error handling with Kyber's PublicKey() method.
func (k *PrivateKey) PublicKeySafe() (*PublicKey, error) {
	if k == nil || k.key == nil {
		return nil, fmt.Errorf("%w: nil private key", ErrInvalidPrivateKey)
	}
	pubInterface := k.key.Public()
	pub, ok := pubInterface.(*mode3.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: unexpected public key type", ErrInvalidPublicKey)
	}
	return &PublicKey{key: pub}, nil
}

// Address returns the Quantaureum address derived from this public key
func (k *PublicKey) Address() types.Address {
	// Sequential constant-time nil checks to avoid short-circuit evaluation
	kIsNil := k == nil
	if subtle.ConstantTimeEq(boolToInt32(kIsNil), 1) == 1 {
		return types.Address{}
	}
	kKeyIsNil := k.key == nil
	if subtle.ConstantTimeEq(boolToInt32(kKeyIsNil), 1) == 1 {
		return types.Address{}
	}
	return types.AddressFromPublicKey(k.Bytes())
}

// PublicKeyAddressFromBytes derives the address from raw public key bytes.
func PublicKeyAddressFromBytes(pubKeyBytes []byte) types.Address {
	return types.AddressFromPublicKey(pubKeyBytes)
}

// Destroy securely zeros the internal private key material.
// After calling Destroy, the PrivateKey must not be used for signing.
//
// audit-fix H-3 [CRITICAL]: Replaced broken two-step Unpack+Serialize approach.
// The original code called k.key.Unpack(&zeroed) which overwrites the INTERNAL
// key state with zeros, then k.key.Bytes() returned an already-zeroed result.
// This meant the subsequent zeroBytesSecure call was scrubbing zeros, not key bytes.
// FIX: Serialize first (captures actual key material), then multi-pass overwrite
// that serialized copy: random → 0xFF → 0x00. Additionally, the Unpack call
// is retained but moved after Bytes() so the key bytes are captured before any
// internal state modification.
//
// KNOWN LIMITATIONS:
//
//   - Go Language Limitation: Go does not provide a cryptographically secure
//     memory zeroing mechanism. Unlike languages with "volatile" or explicit
//     zeroing primitives (e.g., memset_s in C11), Go's memory model makes it
//     impossible to guarantee that the compiler or GC will not retain copies of
//     zeroed memory. This is a fundamental Go language limitation, not a circl bug.
//
//   - Go's garbage collector may retain copies of key bytes in freed heap memory.
//     For long-lived keys requiring stronger guarantees, consider using OS-level
//     memory locking (mlock/VirtualLock) on the key buffer.
//
//     ACTION REQUIRED: Monitor cloudflare/circl for a dedicated Zeroize() or
//     SecureZero() API. When available, replace this best-effort implementation.
//
// zeroDilithiumSeedField uses reflect+unsafe to zero the unexported `seed`
// field inside circl's mode3.PrivateKey. The seed is the master seed from
// which the entire private key can be reconstructed via NewKeyFromSeed.
//
// AUDIT (2026) CRY-01: Destroy()/Zeroize() already call Unpack with a
// zeroed buffer to overwrite rho/key/s1/s2/t0/tr and their cached NTT forms,
// but Unpack only sets seedSet=false without zeroing the seed[32]byte field.
// This leaves the master seed in memory, allowing forensic recovery of the
// full signing key. We use reflect to locate the field by name and unsafe
// to overwrite its bytes (reflect.CanSet() returns false for unexported
// fields, so direct SetUint is not possible).
func zeroDilithiumSeedField(key *mode3.PrivateKey) {
	if key == nil {
		return
	}
	// CRYPTO- (2026-07-20) FIX: Mirror the deferred-recover pattern
	// already used by kyber.go zeroInternalKeyState(). Reflection on
	// unexported fields and UnsafeAddr can panic if a future circl version
	// changes mode3.PrivateKey layout (field renamed, type changed, etc.).
	// Without this guard, a panic propagates up through Destroy()/Zeroize()
	// and crashes the node during key disposal — a denial of service that
	// an attacker could trigger by feeding a malformed key. The serialized
	// key copy is already zeroed by the caller before this function runs,
	// so the reflection work here is best-effort only: on panic we log a
	// warning and return.
	defer func() {
		if r := recover(); r != nil {
			// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger (module=crypto,
			// category=SECURITY) — key material zeroing failure is security-critical.
			securityLogger.Warn("zeroDilithiumSeedField: reflection-based zeroing panicked (best-effort fallback)", map[string]any{
				"panic":     fmt.Sprintf("%v", r),
				"component": "crypto/dilithium",
			})
		}
	}()
	v := reflect.ValueOf(key).Elem()
	seedField := v.FieldByName("seed")
	if !seedField.IsValid() {
		// M-05 FIX (R8 2026-07-19): The 'seed' field was not found — circl
		// has either renamed the field or changed mode3.PrivateKey layout.
		// Without this warning, CRY-01 (master seed residue) silently
		// regresses: the master seed remains in memory and is silently
		// undiscoverable by Destroy()/Zeroize(). Surface a warning so
		// operators notice after a circl upgrade.
		// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key material
		// residue is security-critical.
		securityLogger.Warn("zeroDilithiumSeedField: 'seed' field not found in "+
			"circl mode3.PrivateKey (layout changed?) — master seed will "+
			"remain in memory. Verify circl version compatibility.",
			map[string]any{"component": "crypto/dilithium"})
		return
	}
	// seed is [32]byte; use UnsafeAddr to get a pointer and zero via
	// zeroBytesFunc (indirect call to prevent dead-store optimization).
	ptr := unsafe.Pointer(seedField.UnsafeAddr())
	size := seedField.Type().Size()
	if size == 0 {
		return
	}
	slice := unsafe.Slice((*byte)(ptr), size)
	zeroBytesFunc(slice)
	runtime.KeepAlive(slice)

	// Also zero seedSet bool to prevent Seed() from returning stale data.
	seedSetField := v.FieldByName("seedSet")
	if seedSetField.IsValid() && seedSetField.Kind() == reflect.Bool {
		boolPtr := (*bool)(unsafe.Pointer(seedSetField.UnsafeAddr()))
		*boolPtr = false
	}
}

//	DESIGN NOTE: Destroy() and Zeroize() intentionally do not return
//
// errors, consistent with circl's API design. Key destruction is best-effort
// in Go (see KNOWN LIMITATIONS above) — the GC may retain copies regardless.
// Returning an error would imply the caller can meaningfully react to failure,
// which is misleading: if zeroing fails, there is no recovery action.
// R31-P4-2 FIX: The previous comment incorrectly stated Kyber's Zeroize returns
// an error because "it calls a C primitive that can fail." This is inaccurate —
// Kyber's Destroy/Zeroize return errors from MarshalBinary()/zeroBytesSecure()
// failures, not C primitives. Both implementations now log warnings internally
// (Dilithium3 via logging.Warn, Kyber via log.Printf), ensuring visibility even
// when callers ignore the returned error.
// FIX: Return error to match KyberPrivateKey.Destroy() API.
//
// CRYPTO- (2026-07-21) FIX: Previously this function always returned
// nil even when circl's Bytes()/Unpack() panicked internally — making the
// error return misleading (callers checked it expecting meaningful signal).
// The error return now actually carries signal: it returns nil on the
// normal zeroization paths (including the deterministic 0xAA fallback
// when rand.Read fails — that fallback is itself secure, so callers can
// treat it as success), and returns a non-nil error only when an
// unexpected panic occurs during circl's internal state manipulation.
// On such panic paths, the serialized bytes may not have been fully
// overwritten, so callers should treat the key as still potentially
// resident in memory (log loudly, prefer process exit for high-security
// contexts).
func (k *PrivateKey) Destroy() error {
	if k == nil || k.key == nil {
		return nil
	}
	var panicErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicErr = fmt.Errorf("private key destruction panicked (key material may not be fully zeroed): %v", r)
				// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key destruction
				// failure is security-critical.
				securityLogger.Warn("PrivateKey.Destroy panic recovered; key material may persist in memory",
					map[string]any{"error": panicErr.Error()})
			}
		}()
		// Serialize first — captures actual key material before any state modification.
		keyBytes := k.key.Bytes()
		// Three-pass overwrite: random → 0xFF → 0x00. Defeats cold-boot & residual magnetism.
		if _, err := rand.Read(keyBytes); err != nil {
			// L6-036 FIX: Only the error object is logged, not keyBytes or random
			// data. The error from crypto/rand is a standard I/O error (e.g. EOF)
			// and does not contain key material or random number content.
			// CRYPTO-003 FIX: Substitute a deterministic 0xAA pass so three
			// distinct patterns (0xAA → 0xFF → 0x00) are always written even
			// when the entropy source fails.
			// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key destruction
			// entropy failure is security-critical.
			securityLogger.Warn("rand.Read during key destruction failed; using deterministic 0xAA pass", map[string]any{"err": err})
			fillPrivateKeyBytesFunc(keyBytes, 0xAA)
		}
		// audit-fix L5-008: Use zeroBytesFunc (indirect function call) instead of
		// simple for loops to prevent compiler dead-store optimization.
		// audit-fix L6-011: The 0xFF overwrite pass previously used a simple for
		// loop which the compiler could optimize as a dead store. Replaced with
		// fillPrivateKeyBytesFunc (indirect function call), mirroring the zeroBytesFunc
		// pattern to guarantee the 0xFF writes are not eliminated.
		// 0xFF pass
		fillPrivateKeyBytesFunc(keyBytes, 0xFF)
		// 0x00 pass
		zeroBytesFunc(keyBytes)
		runtime.KeepAlive(keyBytes)
		// Overwrite internal polynomial coefficients via Unpack with zeroed buffer.
		var zeroed [Dilithium3PrivateKeySize]byte
		k.key.Unpack(&zeroed)
		// L9-026 FIX: Use zeroBytesFunc (indirect function call) instead of
		// a simple for loop to prevent compiler dead-store elimination.
		zeroBytesFunc(zeroed[:])
		// AUDIT (2026) CRY-01: Zero the master seed field that Unpack skips.
		zeroDilithiumSeedField(k.key)
		// Nil the reference and force a GC scheduling point.
		k.key = nil
		runtime.KeepAlive(k)
	}()
	return panicErr
}

// Zeroize performs deterministic multi-pass zeroing of the private key material.
// audit-fix LEGACY-2: Unlike Destroy() which relies on circl's Unpack for internal
// state zeroing (not contractually guaranteed), Zeroize uses a more aggressive
// multi-pass approach:
//
//  1. Serialize the key to obtain all cached byte representations
//  2. Three-pass overwrite: random → 0xFF → 0x00 (defeats cold-boot & residual magnetism)
//  3. Unpack a zeroed buffer to overwrite internal polynomial coefficients
//  4. Re-serialize and zero again to catch any representations cached by Unpack
//  5. Nil the reference
//
// After calling Zeroize, the PrivateKey must not be used for signing.
// Callers should prefer Zeroize over Destroy for security-critical key disposal.
//
// R30-P3 NOTE: The nil check below is not constant-time. This is acceptable
// because: (1) it checks pointer nil-ness, not secret data; (2) Go does not
// provide constant-time pointer comparison; (3) the timing difference does not
// leak whether a specific key is present — any caller that has a reference to
// the PrivateKey already knows it exists. The circl library's own Destroy/Zeroize
// implementations use the same pattern.
// FIX: Return error to match KyberPrivateKey.Zeroize() API.
//
// CRYPTO- (2026-07-21) FIX: Previously this function always returned
// nil even when circl's Bytes()/Unpack() panicked internally — making the
// error return misleading (callers checked it expecting meaningful signal).
// The error return now actually carries signal: it returns nil on the
// normal zeroization paths (including the deterministic 0xAA fallback
// when rand.Read fails — that fallback is itself secure, so callers can
// treat it as success), and returns a non-nil error only when an
// unexpected panic occurs during circl's internal state manipulation.
// On such panic paths, the serialized bytes may not have been fully
// overwritten, so callers should treat the key as still potentially
// resident in memory (log loudly, prefer process exit for high-security
// contexts).
func (k *PrivateKey) Zeroize() error {
	if k == nil || k.key == nil {
		return nil
	}
	var panicErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicErr = fmt.Errorf("private key zeroization panicked (key material may not be fully zeroed): %v", r)
				// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key zeroization
				// failure is security-critical.
				securityLogger.Warn("PrivateKey.Zeroize panic recovered; key material may persist in memory",
					map[string]any{"error": panicErr.Error()})
			}
		}()

		// Pass 1: Serialize and multi-pass overwrite the byte representation.
		// This catches any cached serialized forms inside circl's PrivateKey.
		keyBytes := k.key.Bytes()
		if len(keyBytes) > 0 {
			// Three-pass overwrite: random → 0xFF → 0x00
			// This defeats cold-boot attacks (residual data in RAM) and
			// residual magnetism on storage media.
			if _, err := rand.Read(keyBytes); err != nil {
				// L6-036 FIX: Only the error is logged. keyBytes (which may contain
				// old key material since rand.Read failed) is NOT logged.
				// CRYPTO-003 FIX: Substitute a deterministic 0xAA pass (distinct
				// from the unconditional 0xFF pass below) so the sequence keeps
				// three distinct patterns (0xAA → 0xFF → 0x00) instead of
				// degrading to two passes when the entropy source fails.
				// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key zeroization
				// entropy failure is security-critical.
				securityLogger.Warn("rand.Read during key zeroization failed; using deterministic 0xAA pass", map[string]any{"err": err})
				fillPrivateKeyBytesFunc(keyBytes, 0xAA)
			}
			// L8-002 FIX: Use fillPrivateKeyBytesFunc/zeroBytesFunc (indirect function calls)
			// instead of simple for loops to prevent compiler dead-store elimination.
			// 0xFF pass
			fillPrivateKeyBytesFunc(keyBytes, 0xFF)
			// 0x00 pass
			zeroBytesFunc(keyBytes)
			runtime.KeepAlive(keyBytes)
		}

		// Pass 2: Overwrite internal state by unpacking a zeroed buffer.
		// This targets the internal polynomial coefficient arrays that are
		// not covered by the serialized byte representation.
		var zeroed [Dilithium3PrivateKeySize]byte
		k.key.Unpack(&zeroed)
		// Clear the zeroed buffer from stack
		// L8-002 FIX: Use zeroBytesFunc (indirect function call) instead of a
		// simple for loop to prevent compiler dead-store elimination.
		zeroBytesFunc(zeroed[:])

		// AUDIT (2026) CRY-01: Zero the master seed field that Unpack skips.
		// Placed after Unpack (which overwrites rho/key/s1/s2/t0) and before
		// the re-serialize pass, so the seed is zeroed even if re-serialization
		// would re-cache it.
		zeroDilithiumSeedField(k.key)

		// Pass 3: Re-serialize and zero again.
		// Unpack may have caused circl to cache a new serialized representation.
		// We zero it again to ensure no key material remains.
		keyBytes2 := k.key.Bytes()
		if len(keyBytes2) > 0 {
			if _, err := rand.Read(keyBytes2); err != nil {
				// L6-036 FIX: Only the error is logged. keyBytes2 is NOT logged.
				// CRYPTO-003 FIX: Substitute a deterministic 0xAA pass (same as pass 1).
				// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key zeroization
				// entropy failure is security-critical.
				securityLogger.Warn("rand.Read during key zeroization (pass 3) failed; using deterministic 0xAA pass", map[string]any{"err": err})
				fillPrivateKeyBytesFunc(keyBytes2, 0xAA)
			}
			// 0xFF pass
			fillPrivateKeyBytesFunc(keyBytes2, 0xFF)
			// 0x00 pass
			zeroBytesFunc(keyBytes2)
			runtime.KeepAlive(keyBytes2)
		}

		// Nil the reference to allow GC and prevent further use.
		k.key = nil
		runtime.KeepAlive(k)
	}()
	return panicErr
}

// PrivateKeyFromBytes creates a PrivateKey from exactly Dilithium3PrivateKeySize (4000) bytes.
// R5-C2 fix: STRICT length enforcement - only exactly 4000 bytes is valid.
// Reject any extended formats to ensure cryptographic integrity.
// SECURITY FIX: Unpack may panic on invalid input, so we recover and return an error.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	// Use constant-time comparison for length check to prevent timing attacks
	if subtle.ConstantTimeEq(int32(len(b)), int32(Dilithium3PrivateKeySize)) != 1 {
		// FIX: Do not leak actual input length in error message.
		return nil, ErrInvalidPrivateKey
	}

	key := new(mode3.PrivateKey)
	var unpackErr error

	// SECURITY FIX: Unpack can panic on malformed input - recover and capture error
	func() {
		defer func() {
			if r := recover(); r != nil {
				unpackErr = fmt.Errorf("unpack panicked with invalid key data: %v", r)
			}
		}()
		key.Unpack((*[Dilithium3PrivateKeySize]byte)(b))
	}()

	if unpackErr != nil {
		// R9-H4 (2026-07-19) FIX: Zeroize partial key material on panic.
		// Unpack may have partially populated the mode3.PrivateKey struct
		// (polynomial coefficients, cached NTT forms) before panicking.
		// Although the input bytes are attacker-controlled (so the partial
		// state is just garbage the attacker already knows), leaving
		// polynomial-sized buffers in heap memory is defense-in-depth
		// against future memory-disclosure vulnerabilities. Mirrors the
		// zeroization already performed on verifyKeyUsable failure below.
		keyBytes := key.Bytes()
		_ = zeroBytesSecure(keyBytes)
		var zeroed [Dilithium3PrivateKeySize]byte
		key.Unpack(&zeroed)
		zeroBytesFunc(zeroed[:])
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, unpackErr)
	}

	// Verify the unpacked key is usable by checking public key derivation
	if err := verifyKeyUsable(key); err != nil {
		// R3-P3-2: Zeroize the already-deserialized key material on failure.
		// The key was successfully unpacked but failed usability verification;
		// the sensitive key material must not linger in memory.
		// R6-P3-4: Use zeroBytesSecure instead of a simple for loop to prevent
		// compiler dead-store optimization from eliminating the zeroing.
		keyBytes := key.Bytes()
		_ = zeroBytesSecure(keyBytes)
		var zeroed [Dilithium3PrivateKeySize]byte
		key.Unpack(&zeroed)
		// L9-025 FIX: Use zeroBytesFunc (indirect function call) instead of
		// a simple for loop to prevent compiler dead-store elimination.
		zeroBytesFunc(zeroed[:])
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}

	return &PrivateKey{key: key}, nil
}

// verifyKeyUsable checks if a private key is cryptographically usable.
// This catches keys that unpacked but have invalid internal structure.
// R26-Crypto-C1 FIX: Added cryptographic self-test (sign/verify) to validate key integrity.
//
// CRYPTO-R9-L-REDO-02 (2026-07-19) FIX: Added explicit nil-key guard so
// callers that forget to nil-check still get a typed error rather than
// a nil-pointer panic propagating up to PrivateKeyFromBytes (where it
// would crash the RPC path that imports an invalid raw key).
//
// R33 CRYPT-01 FIX (2026-07-28): Wrap the entire self-test in recover()
// to capture any panic from key.Public(), pub.Bytes(), or mode3.Verify().
// Previously only SignTo had recover; a panic in Public() (e.g., from a
// corrupted polynomial causing an out-of-bounds access in circl's
// internal derivation) or Verify() would propagate up through
// PrivateKeyFromBytes and crash the RPC personal_importRawKey path.
// The recovered panic is converted to a typed error so callers can
// handle it gracefully. Key material is zeroed by PrivateKeyFromBytes's
// error path.
func verifyKeyUsable(key *mode3.PrivateKey) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("verifyKeyUsable panicked (key may be corrupted): %v", r)
		}
	}()
	if key == nil {
		return ErrInvalidPrivateKey
	}
	// Try to derive the public key - this will fail if the key is invalid
	pubInterface := key.Public()
	if pubInterface == nil {
		return errors.New("failed to derive public key from private key")
	}
	pub, ok := pubInterface.(*mode3.PublicKey)
	if !ok {
		return errors.New("failed to cast public key")
	}
	// R26-Crypto-C1 FIX: Perform sign/verify self-test to catch malformed keys
	//
	// CRYPTO-R9-L-REDO-02 (2026-07-19) FIX: Previously this used a fixed,
	// publicly known test message ("quantaureum-key-validity-check").
	// Although the signature is never returned to the caller (only used for
	// a verify self-test), a fixed message is poor cryptographic hygiene:
	//   (a) an observer who can read memory (e.g., cold-boot attack) can
	//       recognize the partial signature bytes because they always sign
	//       the same well-known message, helping identify which bytes are
	//       key-derived vs. message-derived;
	//   (b) if the verify path is ever weakened (regression), a fixed
	//       message is the easiest target for an attacker to precompute
	//       a forgery for.
	// Derive the test message from the public key itself so each key
	// self-tests against a unique, key-bound challenge. The message is
	// not secret — its purpose is to avoid a globally fixed input.
	testMsg := sha256.Sum256(pub.Bytes())
	testMsgSlice := testMsg[:]
	sig := make([]byte, Dilithium3SignatureSize)
	// P3-C2 FIX: Wrap SignTo in panic recovery. A corrupted key with valid
	// internal structure may still cause SignTo to panic deep in the circl
	// library (e.g. out-of-bounds index, division by zero). Without recovery
	// the panic would propagate up and crash the caller. We capture it as an
	// error instead, mirroring the recovery pattern used in crypto/sign.go's
	// Sign(). The signature buffer is zeroed on every exit path (see below).
	var signPanicErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				signPanicErr = fmt.Errorf("SignTo panicked (key may be corrupted): %v", r)
			}
		}()
		mode3.SignTo(key, testMsgSlice, sig)
	}()
	if signPanicErr != nil {
		// FIX: Zero signature buffer on all exit paths — it may contain
		// partial key-derived material written before the panic.
		// R31-P3 FIX: Use zeroBytesSecure for consistency with Destroy/Zeroize.
		zeroBytesSecure(sig)
		return fmt.Errorf("%w: %v", ErrInvalidPrivateKey, signPanicErr)
	}
	if !mode3.Verify(pub, testMsgSlice, sig) {
		// FIX: Zero signature buffer on all exit paths — the signature
		// contains cryptographic material derived from the private key.
		// R31-P3 FIX: Use zeroBytesSecure for consistency with Destroy/Zeroize.
		zeroBytesSecure(sig)
		return errors.New("key pair failed cryptographic self-test")
	}
	// FIX: Zero signature buffer after verification is complete.
	// R31-P3 FIX: Use zeroBytesSecure for consistency with Destroy/Zeroize.
	zeroBytesSecure(sig)
	return nil
}

// PublicKeyFromBytes creates a PublicKey from bytes
// SECURITY FIX: Unpack may panic on invalid input, so we recover and return an error.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	// Use constant-time comparison for length check to prevent timing attacks
	if subtle.ConstantTimeEq(int32(len(b)), int32(Dilithium3PublicKeySize)) != 1 {
		// FIX: Do not leak actual input length in error message.
		return nil, ErrInvalidPublicKey
	}

	// R37-P0-03 FIX (2026-07-30): Reject all-zero public keys. An all-zero
	// key has t1=0, degenerating the Dilithium verification equation to
	// w' = A·z — mode3.Verify then accepts keyless forged signatures
	// (z=0, h=0) for ANY message. circl does not check for degenerate keys,
	// so this entry point (used by tx verification, multisig, consensus key
	// loading and keystore import) must.
	if IsZeroPublicKeyBytes(b) {
		return nil, ErrInvalidPublicKey
	}

	var key mode3.PublicKey
	var unpackErr error

	// SECURITY FIX: Unpack can panic on malformed input - recover and capture error
	func() {
		defer func() {
			if r := recover(); r != nil {
				unpackErr = fmt.Errorf("unpack panicked with invalid public key data: %v", r)
			}
		}()
		key.Unpack((*[Dilithium3PublicKeySize]byte)(b))
	}()

	if unpackErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPublicKey, unpackErr)
	}

	return &PublicKey{key: &key}, nil
}

// ExportKeyPair exports a key pair to bytes.
// audit-fix L-6: returns explicit copies to prevent callers from mutating
// internal key state if the underlying implementation returns a reference.
func ExportKeyPair(kp *KeyPair) (privateKey, publicKey []byte, err error) {
	// Sequential constant-time nil checks to avoid short-circuit evaluation
	kpIsNil := kp == nil
	if subtle.ConstantTimeEq(boolToInt32(kpIsNil), 1) == 1 {
		return nil, nil, ErrInvalidPrivateKey
	}
	kpPrivIsNil := kp.Private == nil
	if subtle.ConstantTimeEq(boolToInt32(kpPrivIsNil), 1) == 1 {
		return nil, nil, ErrInvalidPrivateKey
	}
	kpPubIsNil := kp.Public == nil
	if subtle.ConstantTimeEq(boolToInt32(kpPubIsNil), 1) == 1 {
		return nil, nil, ErrInvalidPrivateKey
	}

	privBytes := kp.Private.Bytes()
	pubBytes := kp.Public.Bytes()
	return append([]byte(nil), privBytes...), append([]byte(nil), pubBytes...), nil
}

// ImportKeyPair imports a key pair from bytes
// R26-Crypto-C2 FIX: Verify that public key matches the private key
// L8-007 CONFIRMED FIXED: ImportKeyPair itself does not call rand.Read.
// The rand.Read failure logs elsewhere in this file (Destroy/Zeroize)
// already use L6-036 FIX and only log the error object, never keyBytes
// or random data content.
//
// FIX: Caller responsibility for input zeroing.
// This function creates an internal COPY of privateKeyBytes and zeros that copy
// via defer. The original privateKeyBytes and publicKeyBytes slices passed by
// the caller are NOT modified. The caller MUST zeroize the original input
// slices after this function returns to prevent key material from lingering
// in memory. Use crypto.Zeroize(privKeyBytes) / crypto.Zeroize(pubKeyBytes).
// R41-CR-005 FIX: Reverted the R39-P3 change that zeroed the caller's
// privateKeyBytes in-place. Go slices can share backing arrays, so zeroing
// the caller's slice can corrupt other live data that aliases the same memory.
func ImportKeyPair(privateKeyBytes, publicKeyBytes []byte) (*KeyPair, error) {
	priv, err := PrivateKeyFromBytes(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	// R72-PK-3 [MEDIUM] FIX: Zeroize a COPY of the input, not the caller's slice.
	// The caller may still need the original bytes (e.g., for verification).
	//  AUDIT NOTE: This uses zero-fill (not random-fill) for the copy.
	// Zero-fill is sufficient for defense-in-depth because the copy is a
	// transient stack/heap allocation that goes out of scope immediately
	// after zeroing. Random-fill would add overhead without meaningful
	// security benefit since the Go GC does not guarantee zeroed memory
	// cannot be recovered by a privileged attacker with memory access.
	privCopy := make([]byte, len(privateKeyBytes))
	copy(privCopy, privateKeyBytes)
	// L7-007 FIX: Use the package-level zeroBytesFunc indirect call (already
	// used elsewhere in this file) instead of an explicit zeroing loop. The
	// indirect call prevents the compiler from optimizing the zeroing away
	// as a dead store, and keeps the zeroing idiom consistent across the file.
	defer func() {
		zeroBytesFunc(privCopy)
	}()

	pub, err := PublicKeyFromBytes(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	// R26-Crypto-C2 FIX: Derive public from private and verify it matches provided public key
	derivedPub := priv.PublicKey()
	if derivedPub == nil || !pub.Equal(derivedPub) {
		return nil, fmt.Errorf("%w: public key does not match private key", ErrInvalidPublicKey)
	}

	return &KeyPair{
		Private: priv,
		Public:  pub,
	}, nil
}

// Equal returns true if two public keys are equal
// Uses constant-time comparison to prevent timing attacks
// R24-C3 FIX: Eliminated ALL early returns that leak nil status via timing.
// The final RESULT is computed via subtle.ConstantTimeSelect /
// ConstantTimeCompare so the equality outcome does not leak via timing.
// NOTE: The `if k != nil` / `if other != nil` guards below are NOT
// constant-time — they exist solely to avoid nil-pointer dereference when
// reading k.key / other.key. They leak nil-status (not the comparison
// result), which is unavoidable in Go without reflect.ValueOf(...).IsNil().
// The nil-status flags are fed into constant-time combinators so the
// observable equality RESULT remains timing-invariant.
func (k *PublicKey) Equal(other *PublicKey) bool {
	kIsNil := k == nil
	otherIsNil := other == nil

	// Both nil => equal; exactly one nil => not equal
	bothNil := int(subtle.ConstantTimeEq(boolToInt32(kIsNil), 1)) & int(subtle.ConstantTimeEq(boolToInt32(otherIsNil), 1))
	oneNil := int(subtle.ConstantTimeEq(boolToInt32(kIsNil), 1)) ^ int(subtle.ConstantTimeEq(boolToInt32(otherIsNil), 1))

	// nilEquality: 1 if both-nil (equal) or both-non-nil (defer to key bytes), 0 if one-nil (not equal)
	nilEquality := subtle.ConstantTimeSelect(oneNil, 0, 1)

	// For key bytes comparison: only valid when both non-nil.
	// CRYPTO- (2026-07-20) FIX: R10 fixed Kyber's Equal() to remove
	// short-circuit `||`/`&&` (kyber.go:719-731) but missed Dilithium's
	// PublicKey.Equal() / PrivateKey.Equal(). The previous code passed
	// `boolToInt32(k == nil || k.key == nil)` into subtle.ConstantTimeEq —
	// while ConstantTimeEq is constant-time, the `||` short-circuits BEFORE
	// reaching it: when `k == nil`, `k.key` is not even evaluated, so the
	// receiver-nil path runs faster than the key-field-nil path. Compute
	// each nil flag independently and combine with constant-time OR, then
	// gate the Bytes() call on the resulting flag (matching kyber.go).
	kIsNilCT := int(subtle.ConstantTimeEq(boolToInt32(kIsNil), 1))
	kKeyFieldIsNil := 0
	if k != nil {
		kKeyFieldIsNil = int(subtle.ConstantTimeEq(boolToInt32(k.key == nil), 1))
	}
	otherIsNilCT := int(subtle.ConstantTimeEq(boolToInt32(otherIsNil), 1))
	otherKeyFieldIsNil := 0
	if other != nil {
		otherKeyFieldIsNil = int(subtle.ConstantTimeEq(boolToInt32(other.key == nil), 1))
	}
	// kKeyIsNil = kIsNil OR kKeyFieldIsNil (constant-time OR via `|`).
	kKeyIsNil := kIsNilCT | kKeyFieldIsNil
	otherKeyIsNil := otherIsNilCT | otherKeyFieldIsNil

	oneKeyNil := kKeyIsNil ^ otherKeyIsNil
	keyNilEquality := subtle.ConstantTimeSelect(oneKeyNil, 0, 1)

	// Compare actual bytes using fixed-length zero buffers for nil keys
	// to ensure consistent execution path regardless of nil state.
	// R38-P3 FIX: Use package-level zero buffers instead of stack-allocated
	// arrays to avoid 1952-byte stack allocation on every Equal() call.
	// R48-CR-02 FIX: Use separate halves of the zero buffer to prevent
	// aliasing when both keys are nil (same fix as R47-CR-01 for Kyber).
	halfPub := len(zeroPubKeyBuf) / 2
	kBytes := zeroPubKeyBuf[:halfPub]
	otherBytes := zeroPubKeyBuf[halfPub:]
	// CRYPTO-FIX: gate on the constant-time nil flag instead of
	// `if k != nil && k.key != nil` (short-circuit `&&` leaks nil status).
	if kKeyIsNil == 0 {
		kBytes = k.Bytes()
	}
	if otherKeyIsNil == 0 {
		otherBytes = other.Bytes()
	}
	lenEq := int(subtle.ConstantTimeEq(int32(len(kBytes)), int32(len(otherBytes))))
	bytesEq := lenEq & subtle.ConstantTimeCompare(kBytes, otherBytes)

	// Final result: bothNil OR (nilEquality AND keyNilEquality AND bytesEq)
	result := bothNil | (nilEquality & keyNilEquality & bytesEq)
	return result == 1
}

// Equal returns true if two private keys are equal
// Uses constant-time comparison to prevent timing attacks
// R24-C3 FIX: Eliminated ALL early returns that leak nil status via timing.
// The final RESULT is computed via subtle.ConstantTimeSelect /
// ConstantTimeCompare so the equality outcome does not leak via timing.
// NOTE: The `if k != nil` / `if other != nil` guards below are NOT
// constant-time — they exist solely to avoid nil-pointer dereference when
// reading k.key / other.key. They leak nil-status (not the comparison
// result), which is unavoidable in Go without reflect.ValueOf(...).IsNil().
// The nil-status flags are fed into constant-time combinators so the
// observable equality RESULT remains timing-invariant.
func (k *PrivateKey) Equal(other *PrivateKey) bool {
	kIsNil := k == nil
	otherIsNil := other == nil

	bothNil := int(subtle.ConstantTimeEq(boolToInt32(kIsNil), 1)) & int(subtle.ConstantTimeEq(boolToInt32(otherIsNil), 1))
	oneNil := int(subtle.ConstantTimeEq(boolToInt32(kIsNil), 1)) ^ int(subtle.ConstantTimeEq(boolToInt32(otherIsNil), 1))

	nilEquality := subtle.ConstantTimeSelect(oneNil, 0, 1)

	// CRYPTO- (2026-07-20) FIX: Same short-circuit `||`/`&&` leak as
	// PublicKey.Equal() above — see that function's comment for full rationale.
	// Compute each nil flag independently and combine with constant-time OR.
	kIsNilCT := int(subtle.ConstantTimeEq(boolToInt32(kIsNil), 1))
	kKeyFieldIsNil := 0
	if k != nil {
		kKeyFieldIsNil = int(subtle.ConstantTimeEq(boolToInt32(k.key == nil), 1))
	}
	otherIsNilCT := int(subtle.ConstantTimeEq(boolToInt32(otherIsNil), 1))
	otherKeyFieldIsNil := 0
	if other != nil {
		otherKeyFieldIsNil = int(subtle.ConstantTimeEq(boolToInt32(other.key == nil), 1))
	}
	kKeyIsNil := kIsNilCT | kKeyFieldIsNil
	otherKeyIsNil := otherIsNilCT | otherKeyFieldIsNil

	oneKeyNil := kKeyIsNil ^ otherKeyIsNil
	keyNilEquality := subtle.ConstantTimeSelect(oneKeyNil, 0, 1)

	// Compare actual bytes using fixed-length zero buffers for nil keys
	// to ensure consistent execution path regardless of nil state.
	// R38-P3 FIX: Use package-level zero buffers instead of stack-allocated
	// arrays to avoid 4000-byte stack allocation on every Equal() call.
	// R48-CR-02 FIX: Use separate halves of the zero buffer to prevent
	// aliasing when both keys are nil (same fix as R47-CR-01 for Kyber).
	halfPriv := len(zeroPrivKeyBuf) / 2
	kBytes := zeroPrivKeyBuf[:halfPriv]
	otherBytes := zeroPrivKeyBuf[halfPriv:]
	// CRYPTO-FIX: gate on the constant-time nil flag instead of
	// `if k != nil && k.key != nil` (short-circuit `&&` leaks nil status).
	if kKeyIsNil == 0 {
		kBytes = k.Bytes()
	}
	if otherKeyIsNil == 0 {
		otherBytes = other.Bytes()
	}
	lenEq := int(subtle.ConstantTimeEq(int32(len(kBytes)), int32(len(otherBytes))))
	bytesEq := lenEq & subtle.ConstantTimeCompare(kBytes, otherBytes)

	result := bothNil | (nilEquality & keyNilEquality & bytesEq)
	return result == 1
}

// PublicKeyBytes returns the public key bytes for this private key.
// This method satisfies the types.QuantumSigner interface.
// audit-fix CR-2: Added nil check to prevent panic if PublicKey() returns nil
func (k *PrivateKey) PublicKeyBytes() []byte {
	pub := k.PublicKey()
	if pub == nil {
		return nil
	}
	return pub.Bytes()
}
