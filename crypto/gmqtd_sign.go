// Quantaureum Node source, version 1.0.0.
package crypto

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	logging "github.com/quantaureum/qau/log"
)

// ErrQTDNotImplemented is returned when the GM-QTD threshold signing protocol
// is invoked but the signer has not been registered via SetQTDSingleSigner.
//
// SECURITY (audit 2026-06-26, P0-01): The previous implementation was a stub
// that always returned this error because it imported a package that did not
// exist. The qtd package now exists at wallet/tss/qtd/. The crypto package
// (L1) cannot import wallet/tss/qtd (higher layer) without violating the
// architectural layering rules, so a callback injection pattern is used
// instead: the higher layer calls SetQTDSingleSigner at startup to register
// the real implementation.
var ErrQTDNotImplemented = errors.New("GM-QTD threshold signing is not initialized: call SetQTDSingleSigner first")

// QTDSingleSignFunc is the signature of the GM-QTD single-signer function.
// It is implemented by wallet/tss/qtd.GMQTD_SingleSign and injected at
// startup via SetQTDSingleSigner to avoid a reverse dependency from crypto
// (L1) to wallet/tss/qtd (higher layer).
type QTDSingleSignFunc func(privKey *mode3.PrivateKey, pubKey *mode3.PublicKey, message []byte) ([]byte, error)

var (
	qtdSingleSigner     atomic.Pointer[QTDSingleSignFunc]
	qtdSignerRegistered atomic.Bool // C-04: CAS guard for one-shot registration
)

// SetQTDSingleSigner registers the GM-QTD single-signer implementation.
// This should be called once during node/TSSManager initialization, after
// the wallet/tss/qtd package is available.
//
// SECURITY (audit 2026-06-26, P0-01): This callback injection pattern allows
// the crypto package (L1) to delegate to the qtd package (higher layer)
// without creating a reverse dependency, respecting the architectural
// layering rules (crypto must not import consensus/rpc/wallet).
//
// C-04 (R8 2026-07-19 FIX): One-shot registration via atomic CAS. The
// signer is a process-wide singleton that handles all threshold signing
// operations. Without this guard, an attacker (or buggy startup code)
// could replace the signer after registration — registering a nil signer
// would cause every subsequent QTD signing to fail with DoS, or a
// malicious signer could silently leak signing messages or return
// crafted non-signatures that fork consensus. After first successful
// registration, subsequent calls are rejected and logged at WARN level
// with a SECURITY category tag so operators can detect tampering.
//
// R9-C04 (2026-07-19) FIX — R8 C-04 partial closure TOCTOU completed:
// R8's CAS was followed by a separate mutex-protected store of
// qtdSingleSigner = fn. Between the CAS success and the mutex Lock,
// a concurrent GMQTD_Sign caller could acquire the read lock, observe
// qtdSingleSigner == nil (the old zero value), and wrongly fail with
// ErrQTDNotImplemented — even though registration had already "succeeded"
// from the caller's perspective. Worse, two callers could race such that
// the second sees registered=true but signer=nil, masking the
// not-registered error condition.
//
// FIX: store the signer pointer via atomic.Pointer.Store BEFORE flipping
// qtdSignerRegistered. GMQTD_Sign now loads the signer atomically and
// only checks qtdSignerRegistered as a fast-path hint. The atomic.Pointer
// provides linearizability: a Load() either sees nil (not yet registered)
// or the exact fn pointer (fully registered), with no intermediate
// state. The mutex is removed entirely.
//
// nil is explicitly rejected (would crash signer callers).
func SetQTDSingleSigner(fn QTDSingleSignFunc) {
	if fn == nil {
		logging.Global().Error("SetQTDSingleSigner: rejected nil signer (C-04 guard)",
			map[string]any{
				"category": "SECURITY",
				"reason":   "nil signer would cause DoS on every QTD signing operation",
			})
		return
	}
	if !qtdSignerRegistered.CompareAndSwap(false, true) {
		// SECURITY event: subsequent registration attempts indicate
		// either a startup bug (double-init) or an active tampering
		// attempt. Log at WARN with SECURITY category for SIEM
		// correlation. Do not overwrite the existing signer.
		logging.Global().Warn("SetQTDSingleSigner: rejected duplicate registration (C-04 guard)",
			map[string]any{
				"category": "SECURITY",
				"reason":   "signer already registered; subsequent registration attempts may indicate tampering",
			})
		return
	}
	// R9-C04 FIX: Store the signer pointer atomically BEFORE any other
	// code runs. Combined with the CAS above, this guarantees:
	//   - At most one goroutine ever reaches this Store.
	//   - Any concurrent GMQTD_Sign that loads qtdSingleSigner sees
	//     either nil (pre-Store) or the exact fn pointer (post-Store).
	//   - No TOCTOU window between "registered=true" and "signer=fn".
	qtdSingleSigner.Store(&fn)
	logging.Global().Info("GM-QTD single signer registered",
		map[string]any{
			"category":  "CRYPTO",
			"component": "GMQTD",
		})
}

// UnsetQTDSingleSigner resets the GM-QTD single-signer registration state.
//
// CRYPTO-R9-L-REDO-01 (2026-07-19) FIX: Previously the one-shot CAS guard
// (qtdSignerRegistered) made it impossible for tests to register a fresh
// signer between subtests — the second SetQTDSingleSigner call in the same
// process would be silently rejected, leaving stale signer state that
// masked regressions. This function is strictly test-only: in production
// the signer is registered exactly once at node startup and must never be
// reset. The testing.Testing() guard hard-rejects any call from a
// production binary so an attacker cannot exploit this entry point to
// clear the registered signer and force every QTD signing to fail with
// ErrQTDNotImplemented (a node-wide DoS).
func UnsetQTDSingleSigner() {
	if !testing.Testing() {
		logging.Global().Error("UnsetQTDSingleSigner: rejected call from non-test binary (C-04 guard)",
			map[string]any{
				"category": "SECURITY",
				"reason":   "runtime signer reset is only permitted inside Go test binaries",
			})
		return
	}
	qtdSingleSigner.Store(nil)
	qtdSignerRegistered.Store(false)
}

// GMQTD_Sign performs GM-QTD single-signer signing using the Dilithium3
// private key. The actual signing is delegated to the qtd package via a
// callback injected by SetQTDSingleSigner.
//
// This function is the low-level entry point called by TSSManager when a
// single participant needs to create their signature share. The full
// threshold signing protocol (DKG, partial signing, aggregation) is
// orchestrated by the TSSManager at wallet/tss/manager.go.
func GMQTD_Sign(privateKey *PrivateKey, publicKey *PublicKey, message []byte) ([]byte, error) {
	pkIsNil := privateKey == nil
	if subtle.ConstantTimeEq(boolToInt32(pkIsNil), 1) == 1 {
		return nil, ErrInvalidPrivateKey
	}
	pkKeyIsNil := privateKey.key == nil
	if subtle.ConstantTimeEq(boolToInt32(pkKeyIsNil), 1) == 1 {
		return nil, ErrInvalidPrivateKey
	}
	pubIsNil := publicKey == nil
	if subtle.ConstantTimeEq(boolToInt32(pubIsNil), 1) == 1 {
		return nil, ErrInvalidPublicKey
	}
	// CRYPTO-GM-03 FIX (deep-audit 2026-07-12): also reject a nil inner key.
	// L-04 (R8 2026-07-19) NOTE: defense-in-depth — even though C-02 wraps the
	// signer() call below in a deferred recover that would catch the
	// nil-deref panic, we reject PublicKey{key:nil} early here to:
	//   (a) avoid the recover overhead on a clearly-invalid input,
	//   (b) keep the panic log clean (only genuine signer bugs surface), and
	//   (c) guard against a future code path that calls publicKey.key without
	//       going through the recovered signer callback.
	pubKeyIsNil := publicKey.key == nil
	if subtle.ConstantTimeEq(boolToInt32(pubKeyIsNil), 1) == 1 {
		return nil, ErrInvalidPublicKey
	}

	// R9-C04 (2026-07-19) FIX: Atomic load — no mutex, no TOCTOU window.
	// The signer pointer is set via atomic.Pointer.Store in
	// SetQTDSingleSigner, so this Load() is linearizable with respect
	// to that Store.
	signerPtr := qtdSingleSigner.Load()
	if signerPtr == nil {
		logging.Global().Error("GM-QTD signing requested but signer not registered",
			map[string]any{
				"category": "SECURITY",
				"reason":   "SetQTDSingleSigner was not called during initialization",
			})
		return nil, ErrQTDNotImplemented
	}
	signer := *signerPtr

	// C-02 (R8 2026-07-19 FIX): Wrap the signer callback in a deferred
	// recover so that a panic inside the injected signer (whether from a
	// bug in wallet/tss/qtd or a malicious signer that replaces itself
	// before C-04 CAS is reached) cannot crash the calling goroutine and
	// take down consensus / RPC paths. A panic in threshold signing would
	// otherwise propagate up to the block producer or block validator and
	// halt the node — a single malformed signing message could DoS the
	// whole network. We translate the panic into a logged error so the
	// caller can react (e.g. skip the signature) and the chain keeps
	// running. Constant-time behavior is not affected: recovery only
	// triggers on abnormal panics, and the panic value is never used in a
	// comparison that could leak timing.
	var sig []byte
	var signErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Global().Error("GM-QTD signer callback panicked (C-02 guard)",
					map[string]any{
						"category": "SECURITY",
						"reason":   "signer callback panic converted to error to prevent node-wide DoS",
						"panic":    fmt.Sprintf("%v", r),
					})
				sig, signErr = nil, fmt.Errorf("GM-QTD signer callback panicked: %v", r)
			}
		}()
		sig, signErr = signer(privateKey.key, publicKey.key, message)
	}()
	return sig, signErr
}

// GMQTD_SignMode3 performs GM-QTD signing with raw mode3 key bytes.
// The keys are parsed into typed mode3 keys and signing is delegated to
// the injected signer.
//
// FIX (documentation): Slice modification contract — this function
// does NOT modify the caller's slices. A private copy of privKey is made
// (R44-CR-002) and securely zeroed before returning. Callers can safely
// reuse the original privKey and pubKey slices after this function returns.
// R48-CR-08 FIX: Updated comment to reflect R44-CR-002 change (copy, not in-place).
func GMQTD_SignMode3(pubKey, privKey []byte, message []byte) ([]byte, error) {
	// R46-CR-03 FIX: Explicit nil checks for all inputs.
	//
	// CRYPTO- (2026-07-20) FIX: The previous implementation used
	// Go's `||` short-circuit operator: `pubKey == nil || privKey == nil
	// || message == nil`. The short-circuit means the timing of this
	// function differs based on WHICH input is nil (e.g. if pubKey is nil,
	// the privKey and message comparisons are never evaluated). Although
	// the timing difference is small, this is a self-documented
	// constant-time crypto package, so the short-circuit is a contract
	// violation. The fix evaluates all three comparisons unconditionally
	// and combines them with bitwise OR (no short-circuit), then checks
	// the combined result. This matches the pattern used in
	// keystore.go's isNilKey and generate.go's Equal methods.
	pubKeyIsNil := boolToInt32(pubKey == nil)
	privKeyIsNil := boolToInt32(privKey == nil)
	messageIsNil := boolToInt32(message == nil)
	anyNil := pubKeyIsNil | privKeyIsNil | messageIsNil
	if subtle.ConstantTimeEq(anyNil, 1) == 1 {
		return nil, fmt.Errorf("nil input to GMQTD_SignMode3")
	}
	// R44-CR-002 FIX: Copy privKey before use so we only zero our own copy,
	// not the caller's backing array. The caller may need the original key
	// material for subsequent operations (e.g. multiple sign calls).
	privKeyCopy := make([]byte, len(privKey))
	copy(privKeyCopy, privKey)

	// SECURITY FIX (P2-1): Zero the raw private key bytes before returning.
	// QP-03 FIX: Log zeroization failures instead of silently ignoring them,
	// matching the pattern used in kyber.go and keystore.go. A failed wipe
	// leaves key material in memory and must be observable in logs.
	defer func() {
		if err := zeroBytesSecure(privKeyCopy); err != nil {
			// P3-LOG-02 FIX (R30, 2026-07-27): Use securityLogger — key material
			// zeroization failure is security-critical.
			securityLogger.Warn("GMQTD_SignMode3: failed to securely zero private key copy", map[string]any{"error": err.Error()})
		}
	}()

	// L6-042 FIX: Validate pubKey length before parsing. Defense-in-depth:
	// PublicKeyFromBytes also checks this, but failing early avoids unnecessary
	// key parsing work on malformed input. Uses constant-time comparison.
	if subtle.ConstantTimeEq(int32(len(pubKey)), int32(Dilithium3PublicKeySize)) != 1 {
		// FIX: Do not leak actual input length in error message.
		return nil, ErrInvalidPublicKey
	}

	priv, err := PrivateKeyFromBytes(privKeyCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	// FIX: Zero the parsed PrivateKey struct after use. The raw privKey
	// bytes are zeroed by the defer above, but PrivateKeyFromBytes creates a
	// new struct with its own copy of the key material that also needs cleanup.
	defer func() {
		_ = priv.Zeroize()
	}()
	pub, err := PublicKeyFromBytes(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	return GMQTD_Sign(priv, pub, message)
}
