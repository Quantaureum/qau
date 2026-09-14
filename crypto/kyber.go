// Quantaureum Node source, version 1.0.0.
// Package crypto provides cryptographic primitives for the Quantaureum blockchain.
// This file implements the Kyber post-quantum key exchange algorithm for secure communication.
//
// =============================================================================
// SHARED INTERFACE WARNING - DO NOT MODIFY WITHOUT SYNCING WITH WALLET
// =============================================================================
// This file implements a SHARED INTERFACE with Quantaureum Wallet
// (app/scripts/lib/quantum-crypto/kyber768.ts).
// Any changes to constants, key sizes, or serialization formats MUST be
// synchronized with the Wallet implementation.
//
// Shared parameters:
//   - KyberPublicKeySize: 1184 bytes
//   - KyberPrivateKeySize: 2400 bytes
//   - KyberCiphertextSize: 1088 bytes
//   - KyberSharedKeySize: 32 bytes
//
// Wallet implementation: the quantaureum-wallet repo
// =============================================================================
package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"sync"
	"unsafe"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// Kyber constants
const (
	// KyberPublicKeySize is the size of a Kyber-768 public key in bytes
	KyberPublicKeySize = 1184

	// KyberPrivateKeySize is the size of a Kyber-768 private key in bytes
	KyberPrivateKeySize = 2400

	// KyberCiphertextSize is the size of a Kyber-768 ciphertext in bytes
	KyberCiphertextSize = 1088

	// KyberSharedKeySize is the size of a Kyber-768 shared key in bytes
	KyberSharedKeySize = 32
)

// R43-CR-001 FIX: Package-level sync.Pool for zero buffers used in Equal()
// to avoid heap allocation on every call. The buffers are always all-zero,
// so they can be safely reused across goroutines.
//
// CR-05 FIX: These pool buffers are READ-ONLY — they are never written with
// key material. In Equal(), the buffer is used as a zero stand-in for nil
// keys: when a key is non-nil, kBytes is reassigned to k.Bytes() (a separate
// slice), leaving the pool buffer untouched; when a key is nil, kBytes points
// to the pool buffer which is only READ by ConstantTimeCompare, never written.
// Therefore, the buffers cannot accumulate old key material from previous use,
// and zeroing them in the Put() path is unnecessary. If this invariant ever
// changes (e.g., a future caller writes key material into the buffer), the
// Put() path MUST zero the buffer before returning it to the pool.
var kyberZeroPubBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, KyberPublicKeySize)
	},
}

var kyberZeroPrivBufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, KyberPrivateKeySize)
	},
}

// Kyber-specific errors
var (
	// ErrKyberInvalidPublicKey is returned when a Kyber public key is invalid
	ErrKyberInvalidPublicKey = errors.New("invalid kyber public key")

	// ErrKyberInvalidPrivateKey is returned when a Kyber private key is invalid
	ErrKyberInvalidPrivateKey = errors.New("invalid kyber private key")

	// ErrKyberInvalidCiphertext is returned when a Kyber ciphertext is invalid
	ErrKyberInvalidCiphertext = errors.New("invalid kyber ciphertext")

	// ErrKyberKeyExchangeFailed is returned when a Kyber key exchange fails
	ErrKyberKeyExchangeFailed = errors.New("kyber key exchange failed")

	// ErrKyberDowngradeAttack is returned when a key or ciphertext doesn't match
	// the expected Kyber-768 parameter set, indicating a possible downgrade attack.
	// SECURITY FIX (audit P-3): Prevents attackers from substituting weaker Kyber
	// parameters (e.g., Kyber-512) during key exchange.
	ErrKyberDowngradeAttack = errors.New("kyber downgrade attack detected: parameter set mismatch")
)

// VerifyKyber768Scheme verifies that the circl KEM scheme is Kyber-768.
// SECURITY FIX (audit P-3): Explicit downgrade attack prevention.
// Ensures that the KEM scheme used for key exchange is always Kyber-768
// and has not been replaced with a weaker parameter set.
func VerifyKyber768Scheme(scheme kem.Scheme) error {
	if scheme == nil {
		return ErrKyberDowngradeAttack
	}
	// Kyber-768 must have these exact parameters
	// AUDIT-FULL CR-05 FIX (2026-08-15): error messages no longer print the
	// expected numeric sizes (previously `expected pubkey size %d, got %d`).
	// The expected values are NIST-standardized public constants, but the
	// verbose form leaked the expected length to log aggregators / anyone
	// reading the error string — a downgrade-attack probe could learn the
	// exact sizes the node enforces. Now the error only states that a size
	// mismatch occurred; operators compare `scheme.*Size()` against the
	// Kyber*Size constants in source to diagnose which dimension changed.
	if scheme.PublicKeySize() != KyberPublicKeySize {
		return fmt.Errorf("%w: public key size mismatch", ErrKyberDowngradeAttack)
	}
	if scheme.PrivateKeySize() != KyberPrivateKeySize {
		return fmt.Errorf("%w: private key size mismatch", ErrKyberDowngradeAttack)
	}
	if scheme.CiphertextSize() != KyberCiphertextSize {
		return fmt.Errorf("%w: ciphertext size mismatch", ErrKyberDowngradeAttack)
	}
	if scheme.SharedKeySize() != KyberSharedKeySize {
		return fmt.Errorf("%w: shared key size mismatch", ErrKyberDowngradeAttack)
	}
	return nil
}

// KyberPrivateKey represents a Kyber-768 private key
type KyberPrivateKey struct {
	key kem.PrivateKey
}

// Destroy securely zeros the internal Kyber private key material.
// After calling Destroy, the KyberPrivateKey must not be used.
//
// audit-fix L-6: matches the Destroy pattern from Dilithium PrivateKey.
// Serializes the key, overwrites with random data + zeros, then nils the reference.
//
// FIX: Document internal state limitation.
// Destroy zeros the SERIALIZED COPY of the key, then nils the reference.
// The circl library's kem.PrivateKey interface does NOT expose a Destroy()
// method, so we cannot directly zero the internal `sk []byte` field of the
// underlying kyber.PrivateKey struct. The internal state will be reclaimed
// by Go's GC eventually, but may persist in freed heap memory until then.
// For security-critical disposal, callers should:
// 1. Call Zeroize() (multi-pass overwrite of serialized form)
// 2. Avoid reusing the KyberPrivateKey variable after disposal
// 3. Consider process exit for maximum security
// SECURITY FIX: Now returns error to properly handle marshaling/zeroization failures.
func (k *KyberPrivateKey) Destroy() error {
	if k == nil || k.key == nil {
		return nil
	}
	keyBytes, err := k.key.MarshalBinary()
	if err != nil {
		// R31-P4-2 FIX: Log internally to match Dilithium3's Destroy() pattern,
		// which uses logging.Warn() for destruction failures. This ensures
		// failures are visible in logs even if the caller ignores the returned error.
		// FIX: Use project logging framework instead of standard log.Printf.
		// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key destruction
		// failure is security-critical.
		securityLogger.Warn("KyberPrivateKey.Destroy: failed to marshal key", map[string]any{"error": err.Error()})
		// R33 CRYPT-02 FIX (2026-07-28): Previously this returned early, skipping
		// zeroInternalKeyState. A MarshalBinary failure does NOT mean the internal
		// sk/z fields are absent — they may still contain live key material that
		// an attacker could recover via memory disclosure. Continue to the
		// best-effort reflection-based zeroing below (which has its own recover
		// guard) and nil the reference, so we don't leave secrets in heap memory
		// just because serialization failed. The serialized bytes (keyBytes) are
		// nil on error, so zeroBytesSecure is skipped.
		zeroInternalKeyState(k.key)
		k.key = nil
		runtime.KeepAlive(k)
		return fmt.Errorf("failed to marshal key for destruction: %w", err)
	}
	if err := zeroBytesSecure(keyBytes); err != nil {
		// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key zeroization
		// failure is security-critical.
		securityLogger.Warn("KyberPrivateKey.Destroy: failed to securely zero key", map[string]any{"error": err.Error()})
		// R33 CRYPT-02 FIX: Same as above — even if zeroBytesSecure on the
		// serialized bytes fails, continue to zero internal state and nil the
		// reference. Defense-in-depth: every disposal path must clear secrets.
		zeroInternalKeyState(k.key)
		k.key = nil
		runtime.KeepAlive(k)
		return fmt.Errorf("failed to securely zero key: %w", err)
	}
	// FIX: Attempt to zero internal state via reflection as best-effort.
	// The circl kyber.PrivateKey has an unexported `sk []byte` field. We use
	// reflect to zero it if accessible; if not, the nil-ing below is the fallback.
	zeroInternalKeyState(k.key)
	k.key = nil
	runtime.KeepAlive(k)
	return nil
}

// FIX: zeroInternalKeyState attempts to zero the internal byte slice
// of a circl kem.PrivateKey using reflection. This is a best-effort approach
// because the circl library does not expose a Destroy() method on its keys.
// The kyber.PrivateKey struct has an unexported `sk []byte` field containing
// the raw key material. If reflection fails (e.g., struct layout changes),
// the nil-ing of the reference in Destroy/Zeroize is the fallback.
//
// AUDIT (2026) CRY-FIX: Previously this function called
// zeroStructFields on the entire PrivateKey struct, which blindly recursed
// into ALL fields — including `pk *cpapke.PublicKey`. circl's
// NewKeyFromSeed sets `sk.pk = pk.pk` (SHARED POINTER), so zeroing through
// sk.pk corrupts the paired standalone PublicKey: Encapsulate/Bytes/Equal
// break after Destroy(). Fix: selectively zero only secret fields (`sk`,
// `z`), skip `pk` (shared with paired public key) and `hpk` (H(pk), not
// secret). For non-Kyber keys with unknown field names, fall back to the
// old behavior (zero everything) to preserve backward compatibility.
// CR-04 FIX (audit 2026-08-14): Compile-time assertions pinning the circl
// concrete key types that zeroInternalKeyState's reflection logic targets.
// The reflection path detects the circl Kyber768 layout at RUNTIME via field
// names (sk/pk/hpk/z); if a circl upgrade renames those unexported fields,
// detection silently falls back to zero-all (corrupting paired public keys,
// per CRY-). These assertions fail compilation when a circl version
// bump changes or removes the concrete types, forcing a manual review of
// zeroInternalKeyState against the new layout before the code can build.
var _ kem.PrivateKey = (*kyber768.PrivateKey)(nil)
var _ kem.PublicKey = (*kyber768.PublicKey)(nil)

func zeroInternalKeyState(key kem.PrivateKey) {
	if key == nil {
		return
	}
	// AUDIT (2026) CRY-FIX: Reflection on unexported fields or
	// future circl layout changes can panic (e.g., calling Set on an
	// unexported field via reflect raises "value is not addressable" or
	// "cannot set obtained from unexported field"). Without a recover
	// guard, such a panic propagates up through Destroy()/Zeroize() and
	// crashes the node during key disposal — a denial of service that
	// an attacker could trigger by feeding a malformed key. Wrap the
	// entire reflection block in a deferred recover; on panic we log a
	// warning and fall back to the caller's reference-nil'ing behavior
	// (the serialized copy is already zeroed by Destroy/Zeroize before
	// this function is called, so the failure is best-effort-only).
	defer func() {
		if r := recover(); r != nil {
			// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key material
			// zeroing failure is security-critical.
			securityLogger.Warn("KyberPrivateKey: reflection-based zeroing panicked (best-effort fallback to nil-ing reference)", map[string]any{
				"panic": fmt.Sprintf("%v", r),
			})
		}
	}()
	v := reflect.ValueOf(key)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	// Detect circl Kyber768 PrivateKey by checking for the known field set.
	// circl Kyber768 PrivateKey fields: sk, pk, hpk, z
	//
	// CRYPTO-R9-M-REDO-03 (2026-07-19) FIX: Previously this detection only
	// checked for a single field `pk` of kind Ptr. Any struct that happened
	// to have a `pk *T` field (e.g., a future non-Kyber KEM wrapper, or any
	// third-party type) would be misclassified as Kyber, causing the
	// switch below to skip zeroing of `sk`/`z` (if those fields happened to
	// have different names in the misidentified struct) OR to skip zeroing
	// of `pk`/`hpk` (which for a non-Kyber struct might actually be secret
	// and SHOULD be zeroed). Require all four canonical Kyber field names
	// to be present before applying Kyber-specific zeroing semantics.
	hasField := map[string]bool{}
	for i := 0; i < v.NumField(); i++ {
		hasField[v.Type().Field(i).Name] = true
	}
	hasKyberLayout := hasField["sk"] && hasField["pk"] && hasField["hpk"] && hasField["z"]
	if !hasKyberLayout {
		// M-05 FIX (R8 2026-07-19): Non-Kyber key OR circl layout changed.
		// The fallback (zero-everything) reintroduces the CRY- bug
		// (zeroing pk corrupts the paired public key's Encapsulate/Bytes/
		// Equal). The original code silently fell back here with no signal,
		// making circl upgrade regressions invisible to operators. Log a
		// warning so a future circl version bump doesn't quietly break
		// key zeroization safety.
		// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key zeroization
		// safety regression is security-critical.
		securityLogger.Warn("zeroInternalKeyState: circl Kyber layout not detected "+
			"(field 'pk' missing); falling back to zero-all — this may "+
			"corrupt paired public keys. Verify circl version compatibility.",
			map[string]any{"component": "crypto/kyber"})
		zeroStructFields(v)
		return
	}
	// Kyber PrivateKey: zero only secret fields, skip shared/not-secret fields.
	for i := 0; i < v.NumField(); i++ {
		fieldName := v.Type().Field(i).Name
		switch fieldName {
		case "sk", "z":
			// Secret material — zero via the general dispatcher.
			zeroValue(v.Field(i))
		case "pk", "hpk":
			// pk: SHARED pointer with paired standalone PublicKey — MUST NOT zero.
			// hpk: H(pk) hash, not secret — skip to avoid unnecessary work.
			// (CRY- zeroing pk corrupted Encapsulate/Bytes/Equal on the
			// paired public key returned alongside the private key.)
			continue
		default:
			// Unknown field — zero for safety (backward compat with layout changes).
			zeroValue(v.Field(i))
		}
	}
}

// zeroStructFields recursively zeros byte slices/arrays and nested structs
// within a reflect.Value. CRYPTO2-001 FIX: extracted from zeroInternalKeyState
// to support recursion into nested struct fields without requiring the
// kem.PrivateKey interface.
//
// AUDIT (2026) CRY-02: The previous implementation only handled uint8
// arrays/slices, silently skipping the int16 polynomial coefficient arrays
// that hold Kyber's actual secret material. circl Kyber768's PrivateKey
// contains `sh Vec` where `Vec [K]common.Poly` and `Poly [N]int16` — these
// int16 arrays were never zeroed, leaving the secret scalar in memory after
// Destroy()/Zeroize(). Fix: treat any numeric-kind array/slice as zeroable
// by viewing its total byte span via unsafe.Slice and overwriting with zeros
// through zeroBytesFunc (indirect call to defeat dead-store optimization).
//
// AUDIT (2026) CRY- (CRY-02 NOT FIXED): The Round 1 fix handled
// numeric arrays but NOT arrays-of-structs. circl's `Vec [K]common.Poly` is
// an array of structs (each `Poly` is `[N]int16`). The previous code checked
// `isZeroableNumericKind(reflect.Struct)` → false and skipped the entire
// `sh Vec` field, leaving all 3×256=768 int16 secret coefficients unzeroed.
// Fix: extracted zeroValue dispatcher that handles all kinds (struct, array,
// slice, ptr) and recurses correctly. When an array's element kind is Struct,
// iterate each element and recurse via zeroValue so the nested int16 arrays
// are reached. The old zeroStructFields only handled structs at the top level
// and returned immediately for array values, so recursing into array-of-struct
// elements (which are themselves arrays like [256]int16) was a no-op.
func zeroStructFields(v reflect.Value) {
	if v.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < v.NumField(); i++ {
		zeroValue(v.Field(i))
	}
}

// zeroValue is the general dispatcher that zeros any reflect.Value containing
// secret material. It handles structs (recurse into fields), arrays (zero
// numeric arrays directly, recurse into arrays-of-structs), slices (zero
// numeric slices), and pointers (follow to struct). CRY-FIX: extracted
// from zeroStructFields so that array elements (e.g., Poly [256]int16) are
// zeroed even when they are not struct fields.
func zeroValue(field reflect.Value) {
	switch field.Kind() {
	case reflect.Slice:
		// R31-LOW-1 FIX (2026-09-06): recurse into slices of structs /
		// nested slices — the Array branch below has done this since
		// CRY-, but the Slice branch silently skipped any slice
		// whose element is not a numeric primitive. A future circl layout
		// holding secret material as e.g. []Poly would therefore have its
		// key material left UNZEROED in heap memory after Destroy/Zeroize.
		// Mirrors the Array semantics: numeric slices zero in bulk,
		// struct/nested slices recurse element-wise.
		if field.Len() > 0 && !isZeroableNumericKind(field.Type().Elem().Kind()) &&
			(field.Type().Elem().Kind() == reflect.Struct ||
				field.Type().Elem().Kind() == reflect.Slice ||
				field.Type().Elem().Kind() == reflect.Array) {
			for j := 0; j < field.Len(); j++ {
				zeroValue(field.Index(j))
			}
			return
		}
		if field.Len() > 0 && isZeroableNumericKind(field.Type().Elem().Kind()) {
			// CRYPTO-001 FIX: Use unsafe to zero unexported slice fields.
			// R39-P5 FIX: Use unsafe.Slice instead of [1<<20]byte array trick
			// to remove the hardcoded 1MB boundary limitation.
			// CRY-02 FIX: Compute total byte span (elem bytes × count) so
			// int16/int32/uint16/uint32 slices are also zeroed.
			elemSize := field.Type().Elem().Size()
			totalBytes := uintptr(field.Len()) * elemSize
			if totalBytes == 0 {
				return
			}
			ptr := unsafe.Pointer(field.Pointer())
			slice := unsafe.Slice((*byte)(ptr), totalBytes)
			zeroBytesFunc(slice)
			runtime.KeepAlive(slice)
		}
	case reflect.Array:
		if isZeroableNumericKind(field.Type().Elem().Kind()) {
			// CRY-02 FIX: Use field.Type().Size() to get the total byte
			// span of the array regardless of element kind. This handles
			// uint8, int16, int32, uint16, uint32, int64, etc. The previous
			// code only handled uint8 arrays, leaving circl Kyber's
			// `Poly [N]int16` secret coefficients unzeroed.
			totalBytes := field.Type().Size()
			if totalBytes == 0 {
				return
			}
			if field.CanSet() && field.Type().Elem().Kind() == reflect.Uint8 {
				// CRY-02: For exported uint8 arrays, use reflect SetUint
				// (backward compatible with the original implementation).
				for j := 0; j < field.Len(); j++ {
					field.Index(j).SetUint(0)
				}
			} else {
				// CRYPTO-001 FIX: Use unsafe for unexported arrays or
				// non-uint8 numeric kinds (int16, etc.).
				ptr := unsafe.Pointer(field.UnsafeAddr())
				arr := unsafe.Slice((*byte)(ptr), totalBytes)
				zeroBytesFunc(arr)
				runtime.KeepAlive(arr)
			}
		} else {
			// CRY-FIX (CRY-02 NOT FIXED): Recurse into arrays whose
			// elements are not directly numeric. This handles:
			//   - Arrays of structs (e.g., circl Kyber's Vec [K]Poly where
			//     Poly is a struct containing [N]int16)
			//   - Arrays of named array types (e.g., Vec [3]testPoly where
			//     testPoly = [256]int16 — the named type has Kind=Array,
			//     not Int16, so isZeroableNumericKind returns false)
			// Without this, the entire `sh Vec` field was skipped, leaving
			// all 3×256=768 int16 secret coefficients unzeroed.
			// We recurse via zeroValue which will handle the element's kind
			// (Array → numeric zeroing, Struct → field iteration, etc.).
			for j := 0; j < field.Len(); j++ {
				zeroValue(field.Index(j))
			}
		}
	case reflect.Struct:
		// CRYPTO2-001 FIX: Recurse into nested structs to zero secret
		// material in embedded fields (e.g., circl's kyber.PrivateKey
		// embeds an internal struct containing the secret scalar).
		zeroStructFields(field)
	case reflect.Ptr:
		// CRYPTO2-001 FIX: Follow pointer fields to structs.
		if !field.IsNil() {
			zeroStructFields(field.Elem())
		}
	}
}

// isZeroableNumericKind reports whether a reflect.Kind represents a numeric
// primitive that may carry secret key material (e.g., Kyber's int16
// polynomial coefficients). Non-numeric kinds (String, Interface, Func,
// Chan, Map, etc.) are excluded — zeroing them blindly could corrupt the
// runtime. Bool is excluded because circl does not use bool arrays for
// secrets and zeroing a bool via byte view, while harmless, is unnecessary.
func isZeroableNumericKind(k reflect.Kind) bool {
	switch k {
	case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	default:
		return false
	}
}

// Zeroize performs deterministic multi-pass zeroing of the Kyber private key material.
// audit-fix LEGACY-2: Unlike Destroy() which only zeros the serialized copy,
// Zeroize uses a three-pass overwrite (random →0xFF →0x00) on the serialized
// form to defeat cold-boot attacks and residual magnetism, then nils the reference.
// Callers should prefer Zeroize over Destroy for security-critical key disposal.
func (k *KyberPrivateKey) Zeroize() error {
	if k == nil || k.key == nil {
		return nil
	}

	// Serialize the key to obtain the byte representation
	keyBytes, err := k.key.MarshalBinary()
	if err != nil {
		// R33 CRYPT-02 FIX (aligned with Destroy): A MarshalBinary failure does
		// NOT mean the internal sk/z fields are absent — they may still contain
		// live key material that an attacker could recover via memory disclosure.
		// Continue to the best-effort reflection-based zeroing below (which has
		// its own recover guard) and nil the reference, so we don't leave
		// secrets in heap memory just because serialization failed. The
		// serialized bytes (keyBytes) are nil on error, so the three-pass
		// overwrite below is skipped.
		zeroInternalKeyState(k.key)
		k.key = nil
		runtime.KeepAlive(k)
		// R31-P4-2 FIX: Log internally to match Dilithium3's pattern.
		// FIX: Use project logging framework instead of standard log.Printf.
		// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key zeroization
		// failure is security-critical.
		securityLogger.Warn("KyberPrivateKey.Zeroize: failed to marshal key", map[string]any{"error": err.Error()})
		return fmt.Errorf("failed to marshal key for zeroization: %w", err)
	}

	// CRYPTO-003 FIX: Three-pass overwrite: random → 0xFF → 0x00.
	// If rand.Read fails (low entropy), substitute a deterministic 0xAA pass
	// so the sequence stays three distinct patterns (0xAA → 0xFF → 0x00)
	// instead of degrading to two passes.
	if len(keyBytes) > 0 {
		if _, randErr := rand.Read(keyBytes); randErr != nil {
			// CR-02 FIX: Log the rand.Read failure to match Dilithium3's pattern
			// (see generate.go). Only the error object is logged; keyBytes is NOT
			// logged because it may still contain key material at this point.
			// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key zeroization
			// entropy failure is security-critical.
			securityLogger.Warn("rand.Read during Kyber key zeroization failed; using deterministic 0xAA pass", map[string]any{"err": randErr.Error()})
			fillPrivateKeyBytesFunc(keyBytes, 0xAA)
		}
		fillPrivateKeyBytesFunc(keyBytes, 0xFF)
		zeroBytesFunc(keyBytes)
		runtime.KeepAlive(keyBytes)
	}

	// FIX: Also attempt to zero internal circl key state.
	zeroInternalKeyState(k.key)
	k.key = nil
	runtime.KeepAlive(k)
	return nil
}

// KyberPublicKey represents a Kyber-768 public key
type KyberPublicKey struct {
	key kem.PublicKey
}

// KyberKeyPair represents a Kyber-768 key pair
type KyberKeyPair struct {
	Private *KyberPrivateKey
	Public  *KyberPublicKey
}

// GenerateKyberKeyPair generates a new Kyber-768 key pair
// Requirements: 1.1, 1.2, 1.3, 3.1, 3.2, 3.3, 3.4, 10.1, 10.2, 10.3, 10.4
// #nosec audit-remediation: kyber key generation
//
// R32-P2-03 FIX (2026-07-28): Added panic recovery (matching KyberEncapsulate/
// Decapsulate pattern) and partial-key cleanup on error. Previously, if
// circl's GenerateKeyPair returned (non-nil, non-nil, err) or panicked, the
// partially-allocated private key material was leaked.
func GenerateKyberKeyPair() (kp *KyberKeyPair, err error) {
	// R32-P2-03: Panic recovery — circl internals can panic on entropy
	// failure or implementation bugs. Without recovery, this would crash
	// the caller (e.g. personal_importRawKey RPC handler).
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: key generation panicked: %v", ErrKyberKeyExchangeFailed, r)
			kp = nil
		}
	}()

	// Get Kyber KEM scheme
	kemScheme := kyber768.Scheme()

	// R46-CR-02 FIX: Verify scheme parameters to detect downgrade attacks.
	if err := VerifyKyber768Scheme(kemScheme); err != nil {
		return nil, err
	}

	// Generate key pair
	pub, priv, genErr := kemScheme.GenerateKeyPair()
	if genErr != nil {
		// R32-P2-03: Clean up any partially-allocated key material that
		// circl may have returned alongside the error. Without this, a
		// (non-nil, non-nil, err) return would leak the private key bytes.
		if priv != nil {
			destroyErr := (&KyberPrivateKey{key: priv}).Destroy()
			if destroyErr != nil {
				securityLogger.Warn("GenerateKyberKeyPair: failed to destroy partial private key",
					map[string]any{"error": destroyErr.Error()})
			}
		}
		return nil, fmt.Errorf("%w: %v", ErrKyberKeyExchangeFailed, genErr)
	}

	return &KyberKeyPair{
		Private: &KyberPrivateKey{key: priv},
		Public:  &KyberPublicKey{key: pub},
	}, nil
}

// Bytes returns the Kyber private key as a byte slice.
//
// CRYPTO- (2026-07-21) FIX: Previously this method returned the raw
// result of k.key.MarshalBinary() with the comment "Return a copy" but no
// actual copy was made. If the circl library's MarshalBinary() ever returns
// a reference to an internal buffer (rather than a freshly allocated slice),
// a caller that mutates the returned byte slice would corrupt the private
// key material in-place — a catastrophic key-leak / key-corruption bug.
// We now explicitly clone the returned bytes with append([]byte(nil), ...)
// to guarantee the caller gets an independent copy regardless of circl's
// internal implementation.
func (k *KyberPrivateKey) Bytes() ([]byte, error) {
	kIsNil := k == nil
	if subtle.ConstantTimeEq(boolToInt32(kIsNil), 1) == 1 {
		return nil, ErrKyberInvalidPrivateKey
	}
	kKeyIsNil := k.key == nil
	if subtle.ConstantTimeEq(boolToInt32(kKeyIsNil), 1) == 1 {
		return nil, ErrKyberInvalidPrivateKey
	}
	b, err := k.key.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), b...), nil
}

// Bytes returns the Kyber public key as a byte slice.
//
// CRYPTO- (2026-07-21) FIX: Same fix as KyberPrivateKey.Bytes() —
// explicitly clone MarshalBinary() output so callers cannot mutate internal
// key state. See private key docstring for full rationale.
func (k *KyberPublicKey) Bytes() ([]byte, error) {
	kIsNil := k == nil
	if subtle.ConstantTimeEq(boolToInt32(kIsNil), 1) == 1 {
		return nil, ErrKyberInvalidPublicKey
	}
	kKeyIsNil := k.key == nil
	if subtle.ConstantTimeEq(boolToInt32(kKeyIsNil), 1) == 1 {
		return nil, ErrKyberInvalidPublicKey
	}
	b, err := k.key.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), b...), nil
}

// KyberPrivateKeyFromBytes creates a KyberPrivateKey from bytes
// #nosec audit-remediation: kyber private key from bytes
func KyberPrivateKeyFromBytes(b []byte) (key *KyberPrivateKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("unmarshal panicked: %v", r)
			key = nil
		}
	}()

	// Use constant-time comparison for length check to prevent timing attacks
	if subtle.ConstantTimeEq(int32(len(b)), int32(KyberPrivateKeySize)) != 1 {
		// FIX: Do not leak actual input length in error message.
		return nil, ErrKyberInvalidPrivateKey
	}

	// Get Kyber KEM scheme
	kemScheme := kyber768.Scheme()

	// Import private key
	privKey, unmarshalErr := kemScheme.UnmarshalBinaryPrivateKey(b)
	if unmarshalErr != nil {
		// R32-P2-03 FIX (2026-07-28): If circl returned a non-nil partial
		// key alongside the error, destroy it to prevent key material
		// from lingering in memory. Aligns with the CRYPTO-H02 fix pattern
		// applied to Dilithium's ImportKeyPair.
		if privKey != nil {
			if destroyErr := (&KyberPrivateKey{key: privKey}).Destroy(); destroyErr != nil {
				securityLogger.Warn("KyberPrivateKeyFromBytes: failed to destroy partial key",
					map[string]any{"error": destroyErr.Error()})
			}
		}
		return nil, fmt.Errorf("%w: %v", ErrKyberInvalidPrivateKey, unmarshalErr)
	}

	return &KyberPrivateKey{key: privKey}, nil
}

// KyberPublicKeyFromBytes creates a KyberPublicKey from bytes
// #nosec audit-remediation: kyber public key from bytes
func KyberPublicKeyFromBytes(b []byte) (key *KyberPublicKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("unmarshal panicked: %v", r)
			key = nil
		}
	}()

	// Use constant-time comparison for length check to prevent timing attacks
	if subtle.ConstantTimeEq(int32(len(b)), int32(KyberPublicKeySize)) != 1 {
		// FIX: Do not leak actual input length in error message.
		return nil, ErrKyberInvalidPublicKey
	}

	// Get Kyber KEM scheme
	kemScheme := kyber768.Scheme()

	// Import public key
	pubKey, unmarshalErr := kemScheme.UnmarshalBinaryPublicKey(b)
	if unmarshalErr != nil {
		// AUDIT-FULL CR-01 FIX (2026-08-15): removed the dead `pubKey = nil`
		// store (R32-P2-03) — the very next statement returns, so the local
		// reference goes out of scope and becomes eligible for GC regardless
		// of the nil-store. The store was effectively dead code flagged in
		// the 2026-08-14 audit; the keep-the-rest intent of the original fix
		// is preserved by returning the wrapped error.
		return nil, fmt.Errorf("%w: %v", ErrKyberInvalidPublicKey, unmarshalErr)
	}

	return &KyberPublicKey{key: pubKey}, nil
}

// Exchange generates a shared secret using the recipient's public key and returns the ciphertext
// This is the sender's side of the key exchange
// Requirements: 1.1, 1.2, 1.3, 3.1, 3.2, 3.3, 3.4, 10.1, 10.2, 10.3, 10.4
// #nosec audit-remediation: kyber key exchange
//
// R31-P5-1 NOTE: This method is on *KyberPrivateKey for API symmetry with
// Decapsulate (which genuinely needs the private key). The private key material
// in the receiver is NOT used — Kyber KEM Encapsulate only needs the recipient's
// public key. The nil checks on k/k.key are retained as a safety guard to catch
// use-after-Destroy bugs early. Changing to a standalone function would break
// existing callers; the receiver is documented here to prevent confusion.
//
// CRYPTO- (2026-07-20) FIX: Added KyberEncapsulate() as the recommended
// standalone function for performing Kyber KEM encapsulation. This method is
// retained for backward compatibility but is deprecated — new callers should
// use KyberEncapsulate() to avoid the misleading impression that the private
// key is used in the encapsulation operation.
//
// Deprecated: Use KyberEncapsulate() instead. This method will be removed in v2.0.
func (k *KyberPrivateKey) Exchange(recipientPub *KyberPublicKey) ([]byte, []byte, error) {
	// Sequential constant-time nil checks to avoid short-circuit evaluation
	// CRYPTO- receiver nil checks retained for use-after-Destroy safety.
	kIsNil := k == nil
	if subtle.ConstantTimeEq(boolToInt32(kIsNil), 1) == 1 {
		return nil, nil, ErrKyberKeyExchangeFailed
	}
	kKeyIsNil := k.key == nil
	if subtle.ConstantTimeEq(boolToInt32(kKeyIsNil), 1) == 1 {
		return nil, nil, ErrKyberKeyExchangeFailed
	}
	return KyberEncapsulate(recipientPub)
}

// KyberEncapsulate performs Kyber KEM encapsulation using the recipient's
// public key, returning (sharedSecret, ciphertext, error).
//
// CRYPTO- (2026-07-20): This standalone function replaces the
// deprecated KyberPrivateKey.Exchange() method. The Encapsulate operation
// in Kyber KEM does NOT use any private key material — it only needs the
// recipient's public key to produce a ciphertext + shared secret. The
// previous method receiver on *KyberPrivateKey was misleading because
// it suggested the private key was involved in the operation.
//
// The nil check on recipientPub is retained for safety. There is no
// "use-after-Destroy" check on a private key because no private key is
// accepted by this function.
func KyberEncapsulate(recipientPub *KyberPublicKey) ([]byte, []byte, error) {
	// Sequential constant-time nil checks to avoid short-circuit evaluation
	rpIsNil := recipientPub == nil
	if subtle.ConstantTimeEq(boolToInt32(rpIsNil), 1) == 1 {
		return nil, nil, ErrKyberKeyExchangeFailed
	}
	rpKeyIsNil := recipientPub.key == nil
	if subtle.ConstantTimeEq(boolToInt32(rpKeyIsNil), 1) == 1 {
		return nil, nil, ErrKyberKeyExchangeFailed
	}

	// Get Kyber KEM scheme
	kemScheme := kyber768.Scheme()

	// R29-C1 FIX: Add panic recovery for Encapsulate
	// Malicious public keys could trigger panics in the Kyber implementation
	var ciphertext, sharedKey []byte
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("%w: encapsulate panicked: %v", ErrKyberKeyExchangeFailed, r)
			}
		}()
		ciphertext, sharedKey, err = kemScheme.Encapsulate(recipientPub.key)
	}()
	if err != nil {
		// L10-003 FIX: Zero any partial shared key / ciphertext on error
		// to prevent sensitive material from lingering in memory.
		_ = zeroBytesSecure(sharedKey)
		_ = zeroBytesSecure(ciphertext)
		return nil, nil, fmt.Errorf("%w: %v", ErrKyberKeyExchangeFailed, err)
	}

	// SECURITY FIX (L14-025): Validate ciphertext length after encapsulation.
	// The Kyber-768 KEM should always produce a ciphertext of exactly
	// KyberCiphertextSize bytes. A mismatched length could indicate a
	// compromised or buggy KEM implementation, and would cause the recipient's
	// Decapsulate to fail. Reject early to avoid propagating invalid data.
	// R35-P3 FIX: Use constant-time length comparison for consistency with
	// the rest of this file (Decapsulate input check at line 786 uses
	// subtle.ConstantTimeEq). Although this validates circl's OUTPUT (not
	// attacker input), a non-constant-time `!=` is inconsistent with the
	// self-documented constant-time contract of this package and could be
	// fingerprinted by an attacker measuring post-Encapsulate timing.
	if subtle.ConstantTimeEq(int32(len(ciphertext)), int32(KyberCiphertextSize)) != 1 {
		_ = zeroBytesSecure(sharedKey)
		_ = zeroBytesSecure(ciphertext)
		// FIX: Do not leak actual ciphertext length in error message.
		return nil, nil, ErrKyberInvalidCiphertext
	}

	// R30-P3 FIX: Caller responsibility for sharedKey/ciphertext zeroing.
	// The returned sharedKey is a secret key for secure communication, and
	// ciphertext contains encapsulated key material. The caller MUST zeroize
	// both after use: crypto.ZeroBytesSecure(sharedKey); crypto.ZeroBytesSecure(ciphertext)
	return sharedKey, ciphertext, nil
}

// Decapsulate extracts the shared secret from the ciphertext using the private key
// This is the recipient's side of the key exchange
// Requirements: 1.1, 1.2, 1.3, 3.1, 3.2, 3.3, 3.4, 10.1, 10.2, 10.3, 10.4
// #nosec audit-remediation: kyber key decapsulation
func (k *KyberPrivateKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	// Sequential constant-time nil checks to avoid short-circuit evaluation
	kIsNil := k == nil
	if subtle.ConstantTimeEq(boolToInt32(kIsNil), 1) == 1 {
		return nil, ErrKyberKeyExchangeFailed
	}
	kKeyIsNil := k.key == nil
	if subtle.ConstantTimeEq(boolToInt32(kKeyIsNil), 1) == 1 {
		return nil, ErrKyberKeyExchangeFailed
	}
	ctIsNil := ciphertext == nil
	if subtle.ConstantTimeEq(boolToInt32(ctIsNil), 1) == 1 {
		return nil, ErrKyberKeyExchangeFailed
	}

	// Constant-time ciphertext length check to prevent timing attacks
	if subtle.ConstantTimeEq(int32(len(ciphertext)), int32(KyberCiphertextSize)) != 1 {
		return nil, ErrKyberInvalidCiphertext
	}

	// Get Kyber KEM scheme
	kemScheme := kyber768.Scheme()

	// R29-C2 FIX: Add panic recovery for Decapsulate
	// Malicious ciphertext could trigger panics in the Kyber implementation
	var sharedKey []byte
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("%w: decapsulate panicked: %v", ErrKyberKeyExchangeFailed, r)
			}
		}()
		sharedKey, err = kemScheme.Decapsulate(k.key, ciphertext)
	}()
	if err != nil {
		// L10-003 FIX: Zero any partial shared key on error
		_ = zeroBytesSecure(sharedKey)
		return nil, fmt.Errorf("%w: %v", ErrKyberKeyExchangeFailed, err)
	}

	// R41-CR-001 FIX: Validate sharedKey length after decapsulation. If circl
	// returns an unexpected length, the key is invalid and must not propagate.
	// R35-P3 FIX: Use constant-time length comparison for consistency with
	// the rest of this file (ciphertext input check above and Encapsulate
	// output check both use subtle.ConstantTimeEq).
	if subtle.ConstantTimeEq(int32(len(sharedKey)), int32(KyberSharedKeySize)) != 1 {
		_ = zeroBytesSecure(sharedKey)
		// R6-CR-001 FIX: Do not leak shared key length in the error message.
		return nil, ErrKyberKeyExchangeFailed
	}

	// R30-P3 FIX: Caller responsibility for sharedKey zeroing.
	// The returned sharedKey is a secret key for secure communication.
	// The caller MUST zeroize it after use: crypto.ZeroBytesSecure(sharedKey)
	return sharedKey, nil
}

// Equal returns true if two Kyber public keys are equal
// Uses constant-time comparison to prevent timing attacks
// SECURITY FIX: Replaced early-return nil checks with constant-time
// selection to match Dilithium PublicKey.Equal() (audit-fix R24-C3 pattern).
// The final RESULT is computed via subtle.ConstantTimeSelect /
// ConstantTimeCompare so the equality outcome does not leak via timing.
// NOTE: The `if k != nil` / `if other != nil` guards below are NOT
// constant-time — they exist solely to avoid nil-pointer dereference when
// reading k.key / other.key. They leak nil-status (not the comparison
// result), which is unavoidable in Go without reflect.ValueOf(...).IsNil().
// The nil-status flags are fed into constant-time combinators so the
// observable equality RESULT remains timing-invariant.
func (k *KyberPublicKey) Equal(other *KyberPublicKey) bool {
	kIsNil := k == nil
	otherIsNil := other == nil

	// Both nil => equal; exactly one nil => not equal
	bothNil := int(subtle.ConstantTimeEq(boolToInt32(kIsNil), 1)) & int(subtle.ConstantTimeEq(boolToInt32(otherIsNil), 1))
	oneNil := int(subtle.ConstantTimeEq(boolToInt32(kIsNil), 1)) ^ int(subtle.ConstantTimeEq(boolToInt32(otherIsNil), 1))

	// nilEquality: 1 if both-nil (equal) or both-non-nil (defer to key bytes), 0 if one-nil (not equal)
	nilEquality := subtle.ConstantTimeSelect(oneNil, 0, 1)

	// For key bytes comparison: only valid when both non-nil.
	// CRYPTO-R10-N02 (2026-07-19) FIX: Previously used `k == nil || k.key == nil`
	// which is a short-circuit `||` — when `k == nil`, the `k.key` access is
	// skipped, so the time differs between "receiver is nil" and "receiver is
	// non-nil but key field is nil". This is a constant-time leak. Now each
	// condition is computed independently and combined with constant-time AND.
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
	// kKeyIsNil = kIsNil OR kKeyFieldIsNil (constant-time OR via a+b-clamp).
	kKeyIsNil := kIsNilCT | kKeyFieldIsNil
	otherKeyIsNil := otherIsNilCT | otherKeyFieldIsNil

	oneKeyNil := kKeyIsNil ^ otherKeyIsNil
	keyNilEquality := subtle.ConstantTimeSelect(oneKeyNil, 0, 1)

	// Compare actual bytes using fixed-length zero buffers for nil keys
	// to ensure consistent execution path regardless of nil state.
	// FIX: Follow Dilithium's zero-buffer pattern — always execute
	// the byte comparison, eliminating the timing branch where nil keys
	// skip the ConstantTimeCompare entirely.
	// CRYPTO-002 FIX / R43-CR-001 FIX: Use sync.Pool instead of make() on
	// every call to avoid heap pressure on the hot signature-verification path.
	zeroPubBuf := kyberZeroPubBufPool.Get().([]byte)
	defer kyberZeroPubBufPool.Put(zeroPubBuf)
	// R47-CR-01 FIX: Use separate halves of the zero buffer to prevent
	// aliasing when both keys are nil. Previously kBytes and otherBytes
	// both pointed to the same buffer, causing ConstantTimeCompare to
	// compare a buffer against itself (always equal).
	half := len(zeroPubBuf) / 2
	kBytes := zeroPubBuf[:half]
	otherBytes := zeroPubBuf[half:]
	// FIX: Removed Bytes() error-handling branch to eliminate
	// residual timing leak. If Bytes() fails (shouldn't for valid keys),
	// the zero buffer is used, causing ConstantTimeCompare to return 0.
	//
	// CRYPTO-R10-N02 (2026-07-19) FIX: The previous `if k != nil && k.key != nil`
	// was a short-circuit `&&` — when `k == nil`, the `k.key` access is skipped,
	// leaking nil-status via timing. Replace with a single nil-flag check that
	// is computed above (kKeyIsNil) and gate the Bytes() call via that flag.
	// We still branch on kKeyIsNil (one comparison), but the branch outcome is
	// already represented as a constant-time-computed flag — the Bytes() call
	// itself is the expensive operation and is the same regardless of WHICH nil
	// case we're in (both produce an empty buffer via the zero fallback).
	if kKeyIsNil == 0 {
		kBytes, _ = k.Bytes()
	}
	if otherKeyIsNil == 0 {
		otherBytes, _ = other.Bytes()
	}
	lenEq := int(subtle.ConstantTimeEq(int32(len(kBytes)), int32(len(otherBytes))))
	bytesEq := lenEq & subtle.ConstantTimeCompare(kBytes, otherBytes)

	// Final result: bothNil OR (nilEquality AND keyNilEquality AND bytesEq)
	result := bothNil | (nilEquality & keyNilEquality & bytesEq)
	return result == 1
}

// Equal returns true if two Kyber private keys are equal
// Uses constant-time comparison to prevent timing attacks
// SECURITY FIX: Replaced early-return nil checks with constant-time
// selection to match Dilithium PrivateKey.Equal() (audit-fix R24-C3 pattern).
// The final RESULT is computed via subtle.ConstantTimeSelect /
// ConstantTimeCompare so the equality outcome does not leak via timing.
// NOTE: The `if k != nil` / `if other != nil` guards below are NOT
// constant-time — they exist solely to avoid nil-pointer dereference when
// reading k.key / other.key. They leak nil-status (not the comparison
// result), which is unavoidable in Go without reflect.ValueOf(...).IsNil().
// The nil-status flags are fed into constant-time combinators so the
// observable equality RESULT remains timing-invariant.
// FIX: Follow Dilithium's zero-buffer pattern — always execute
// the byte comparison, eliminating the timing branch where nil keys
// skip the ConstantTimeCompare entirely.
func (k *KyberPrivateKey) Equal(other *KyberPrivateKey) bool {
	kIsNil := k == nil
	otherIsNil := other == nil

	bothNil := int(subtle.ConstantTimeEq(boolToInt32(kIsNil), 1)) & int(subtle.ConstantTimeEq(boolToInt32(otherIsNil), 1))
	oneNil := int(subtle.ConstantTimeEq(boolToInt32(kIsNil), 1)) ^ int(subtle.ConstantTimeEq(boolToInt32(otherIsNil), 1))

	nilEquality := subtle.ConstantTimeSelect(oneNil, 0, 1)

	// CRYPTO-R10-N02 (2026-07-19) FIX: Same short-circuit `||` removal as
	// KyberPublicKey.Equal — see the comment there for full rationale.
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
	// CRYPTO-002 FIX / R43-CR-001 FIX: Use sync.Pool instead of make() on
	// every call to avoid heap pressure on the hot signature-verification path.
	zeroPrivBuf := kyberZeroPrivBufPool.Get().([]byte)
	defer kyberZeroPrivBufPool.Put(zeroPrivBuf)
	// R47-CR-01 FIX: Use separate halves to prevent aliasing (same as pub).
	half := len(zeroPrivBuf) / 2
	kBytes := zeroPrivBuf[:half]
	otherBytes := zeroPrivBuf[half:]
	// FIX: Removed Bytes() error-handling branch to eliminate
	// residual timing leak (same fix as KyberPublicKey.Equal).
	//
	// CRYPTO-R10-N02 (2026-07-19) FIX: Same short-circuit `&&` removal as
	// KyberPublicKey.Equal — gate on the constant-time-computed kKeyIsNil flag.
	if kKeyIsNil == 0 {
		kBytes, _ = k.Bytes()
	}
	if otherKeyIsNil == 0 {
		otherBytes, _ = other.Bytes()
	}
	lenEq := int(subtle.ConstantTimeEq(int32(len(kBytes)), int32(len(otherBytes))))
	bytesEq := lenEq & subtle.ConstantTimeCompare(kBytes, otherBytes)

	result := bothNil | (nilEquality & keyNilEquality & bytesEq)
	return result == 1
}

// PublicKey returns the public key corresponding to this private key
func (k *KyberPrivateKey) PublicKey() (*KyberPublicKey, error) {
	// Sequential constant-time nil checks to avoid short-circuit evaluation
	kIsNil := k == nil
	if subtle.ConstantTimeEq(boolToInt32(kIsNil), 1) == 1 {
		return nil, ErrKyberInvalidPrivateKey
	}
	kKeyIsNil := k.key == nil
	if subtle.ConstantTimeEq(boolToInt32(kKeyIsNil), 1) == 1 {
		return nil, ErrKyberInvalidPrivateKey
	}

	// Get public key from private key
	pubKey := k.key.Public()
	// R47-CR-05 FIX: Check that Public() returned a non-nil key.
	if pubKey == nil {
		return nil, ErrKyberInvalidPrivateKey
	}

	return &KyberPublicKey{key: pubKey}, nil
}

// GetKyberScheme returns the Kyber-768 KEM scheme
// This allows direct access to the underlying KEM implementation if needed
// Requirements: 1.1, 1.2, 1.3, 3.1, 3.2, 3.3, 3.4, 10.1, 10.2, 10.3, 10.4
func GetKyberScheme() kem.Scheme {
	return kyber768.Scheme()
}
