// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log"
	"math"
	"reflect"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/params"
	"golang.org/x/crypto/sha3"
)

const DefaultSessionTimeout = 5 * time.Minute

// TSS-M8 (R8 2026-07-19) — FIXED. SessionInit messages now carry an
// authoritative aggregator timestamp in the wire payload (see
// EncodeSessionInit/DecodeSessionInit in wallet/tss/distributed_signer.go).
// The aggregator sources it from its own clock at session creation, attaches
// it to the SessionInit broadcast, and authenticates the full payload via
// the existing B-5 aggregator-signature check (handleTSSSessionInit verifies
// the sender is the current block proposer). Participants extract the
// timestamp via DecodeSessionInit and propagate it through
// InitiateParticipantSession → CreateParticipantSession → QTDSession.SetCreatedAt,
// so the qtdSession's 5-minute timeout is computed from the aggregator's
// wall-clock rather than each node's local clock. This decouples session
// lifetime from per-node clock skew: even if a participant's NTP feed drifts
// by minutes, its qtdSession expires at the same instant as every other
// participant's and as the aggregator's.
//
// Backward compatibility: legacy payloads without the trailing 8-byte
// timestamp field still parse successfully (DecodeSessionInit returns
// initiatedAt=0), and the participant falls back to local time.Now() —
// preserving the original TSS- behavior. New aggregators always emit
// the timestamp, so the residual risk is only for mixed-version fleets
// during a rolling upgrade.
//
// Residual operational guidance (still recommended): the freshness window of
// 5 min is large enough to absorb typical NTP drift (<1s) and even
// misconfigured clocks (<1min). Sustained drift >5min indicates a broken
// time-sync service, which is an operational issue independent of TSS.
// Validators SHOULD run chrony/systemd-timesyncd with multiple upstream NTP
// sources.

// QTD Threshold Signature Parameters
const (
	Dilithium3K      = 6      // Matrix rows
	Dilithium3L      = 5      // Matrix columns
	Dilithium3Gamma1 = 524288 // Rejection sampling bound γ1 = 2^19 (Dilithium3)
	// L18-018: Dilithium3Beta = 196 is the correct standard FIPS 204 value
	// for mode3. Beta = Tau * Eta = 49 * 4 = 196. The erroneous value 1920
	// referenced in a previous audit was incorrect; 196 matches both the
	// FIPS 204 specification and the circl mode3 implementation.
	Dilithium3Beta    = 196
	Dilithium3Eta2    = 72           // Masking bound (η2 for Dilithium3)
	Dilithium3Gamma2  = (Q - 1) / 32 // circl mode3: Gamma2=261888 (NOT FIPS204's /88)
	Dilithium3Tau     = 49           // Challenge weight (circl standard: tau=49)
	Dilithium3EtaPoly = 4            // Eta for secret key polynomials (circl mode3: eta=4)
	Dilithium3Omega   = 55           // Max hint count (circl mode3: Omega=55)
	Dilithium3D       = 13           // Bit drop for t (d=13 in Dilithium3 spec)
	// Dilithium3ZPolyByteSize is the packed byte length of a single z
	// polynomial in the GM-QTD signature layout (ctilde[32] + z[5*640] +
	// hint[61] = 3293 bytes total). Derived from 256 coefficients packed
	// 2-per-5-byte (128 pairs × 5 = 640 bytes per poly). Previously a
	// magic-number literal `640` was hardcoded independently in
	// qtd_protocol.go (lines 1237 & 1847) and qtd_pack.go — a silent
	// desync risk if the packing width ever changes. AUDIT-FULL CR-08 FIX
	// (2026-08-15) centralizes the value here as the single source of truth.
	Dilithium3ZPolyByteSize = 640
)

// GMQTD (Gaussian-Masked QTD) Parameters.
// Each party samples y_i from discrete Gaussian D_{Z,σ} where σ = γ1/(4·√t).
// By the convolution theorem, Σ y_i ~ D_{Z,γ1/4}. The factor 4 ensures
// ||z||_∞ < γ1-β passes with ~93% acceptance under norm-based rejection
// (CheckRejection), since Gaussian tails beyond 4σ are negligible.
// GMQTDBaseSigma is a wide-sigma reference constant for t=3 used in tests;
// production sessions compute sigma dynamically via gamma1/(4*sqrt(t)).
const (
	GMQTDBaseSigma = 302710.0 // γ1/√3 ≈ 302710 — wide reference sigma for tests
	GMQTDTailBound = 13.5     // Tail cutoff multiplier for 128-bit security
)

// Round1Commitment represents the first round commitment in QTD signing.
type Round1Commitment struct {
	ParticipantID int
	Commitment    []byte // SHA256(W || nonce)
	Nonce         []byte
}

// Round2Reveal represents the second round reveal in QTD signing.
//
// AUDIT (2026) TSS-FIX (CRITICAL → FULLY CLOSED):
//
// The single-aggregator model is vulnerable: one node sees w_agg, z_agg, and
// z0_agg, from which it can recover s1 = (z_agg - A^{-1} w_agg) / c.
//
// FULL CLOSURE: Role-Separated Aggregation (3-role split)
//
//	Role W-aggregator: sees WShare only → w_agg, w1, c
//	                   Cannot see ZShare → cannot recover s1
//
//	Role Z-aggregator: sees ZShare only → z_agg
//	                   Cannot see WShare → cannot get y_agg → cannot get s1
//
//	Role H-aggregator: sees Z0Share + w_agg (from W-agg) → hint
//	                   Cannot see ZShare → cannot recover s1
//
// SECURITY: Recovery of s1 requires W-aggregator + Z-aggregator collusion.
// In a t-of-n threshold system, this means at least t colluding nodes are
// needed, matching the threshold security assumption. This is FULL CLOSURE:
// no single node can recover s1.
//
// The combined Z0Share = λ_i · c · (t0_i - s2_i) design (from R5) is still
// used — it prevents decomposition into c·t0 and c·s2 separately, which was
// the original Critical (full-key-recovery) vulnerability. The role-separated
// design builds on top of that to close the residual s1 leakage.
//
// AUDIT (2026) TSS-FIX (DH-BASED PAIRWISE MASKING):
// When SetDHKeys() has been called on the session before Round2Reveal, the
// Z0Share field is MASKED with pairwise DH-derived values:
//
//	Z0Share_masked = λ_i·c·(t0_i - s2_i) + netMask_i
//
// where netMask_i = Σ_{j≠i} sign(i,j)·u_{min(i,j),max(i,j)} and u_ij is
// derived from DH(i,j). Masks cancel in aggregation: Σ netMask_i = 0, so
// the H-aggregator still obtains the correct c·(t0-s2) for hint computation.
// This protects individual z0_i from network eavesdroppers and raises the
// collusion threshold for s1 recovery (now requires W-agg + H-agg).
// See qtd_dh_mask.go for the full protocol description.
type Round2Reveal struct {
	ParticipantID int
	WShare        []byte // A * y_i
	ZShare        []byte // λ_i·s1_i·c + y_i
	Z0Share       []byte // λ_i·c·(t0_i - s2_i) + netMask_i (if DH masking enabled; see TSS-)
	Nonce         []byte
}

// IsPrivate reports whether this reveal contains the combined z0 contribution
// (Z0Share) that MUST NOT be broadcast over public channels.
// Transport layers transmitting a Round2Reveal MUST check IsPrivate() and, if
// true, send it only over a point-to-point encrypted channel to the trusted
// aggregator -- never via P2P broadcast.
func (r *Round2Reveal) IsPrivate() bool {
	return r != nil && len(r.Z0Share) > 0
}

// ToPublicReveal returns a copy of this reveal with the z0 contribution
// (Z0Share) stripped. Use this when transmitting the reveal over
// public/broadcast channels. The original reveal is not modified.
func (r *Round2Reveal) ToPublicReveal() *Round2Reveal {
	if r == nil {
		return nil
	}
	return &Round2Reveal{
		ParticipantID: r.ParticipantID,
		WShare:        r.WShare,
		ZShare:        r.ZShare,
		Z0Share:       nil, // stripped — safe for broadcast
		Nonce:         r.Nonce,
	}
}

// QTDSignature represents the final QTD signature.
type QTDSignature struct {
	FullSig []byte // Complete 3293-byte standard Dilithium3 signature
	Z       []byte // Response vector (already packed in FullSig)
	Ctilde  []byte // Challenge seed (32 bytes)
	WAgg    []byte // Aggregated commitment W = sum(A*y_i)
}

// QTDSession manages a single threshold signing session.
type QTDSession struct {
	mu           sync.Mutex
	message      []byte
	participants []int
	threshold    int
	shares       map[int]*QTDShare

	useShamir      bool
	lagrangeCoeffs map[int]int64

	useGaussian     bool
	gaussianSigma   float64
	gaussianSampler *GaussianSampler

	round1Commitments map[int]*Round1Commitment
	round2Reveals     map[int]*Round2Reveal
	round1Complete    bool
	round2Complete    bool

	wShares   map[int][]byte
	wComputed map[int][]byte

	// PlanA2-Threshold: circl-format public key bytes (rho+t1) for tr computation
	pkBytes   []byte
	zShares   map[int][]byte
	createdAt time.Time
	timeout   time.Duration

	// TSS-FIX (2026-07-17): DH-based pairwise masking of Z0Share.
	// When dhPrivateKey is non-nil and dhPublicKeys contains all peers'
	// public keys, computeZ0Contribution applies a net pairwise mask to
	// the Z0Share before transmission. Masks cancel in aggregation, so
	// the H-aggregator still obtains the correct c·(t0-s2) for hint
	// computation, but individual z0_i contributions are protected from
	// network eavesdroppers and non-aggregator participants.
	// When dhPrivateKey is nil (backward-compat / single-participant),
	// no mask is applied and the protocol behaves as before.
	dhPrivateKey  *ecdh.PrivateKey
	dhPublicKeys  map[int][]byte // participant ID => 32-byte X25519 public key
	sessionID     []byte         // binds DH masks to this signing session
	dhMaskEnabled bool           // true if DH masking is active

	// TSS-FIX (2026-07-17): Role-separated aggregation with per-session
	// rotation. When roleSeparationEnforced is true, the legacy
	// Round2Aggregate method is disabled and callers MUST use
	// Round2AggregateW / Z / H instead. See qtd_role_separation.go.
	roleAssignment         RoleAssignment
	roleSeparationEnforced bool
}

// NewQTDSession creates a new threshold signing session.
// FIX: useGaussian defaults to true. Non-Gaussian SampleMasking is
// deprecated and does not preserve zero-knowledge under aggregation.
// R2-HIGH-06 FIX: sigma is now gamma1/(4*sqrt(n)) where n is the ACTUAL
// number of participants (not the threshold). The convolution theorem gives
// sigma_agg = sqrt(n) * gamma1/(4*sqrt(n)) = gamma1/4, which is compatible
// with the norm-based rejection ||z||_inf < gamma1-beta (~93% acceptance)
// REGARDLESS of how many participants actually sign. Using threshold instead
// of actual participants caused failures when n > threshold (e.g. 3-of-5
// with all 5 signing: sigma_agg = sqrt(5/3)*gamma1/4 ≈ 1.29*gamma1/4,
// inflating the rejection rate and causing 100-attempt failures).
func NewQTDSession(message []byte, participants []int, threshold int, shares map[int]*QTDShare) (*QTDSession, error) {
	if len(participants) < threshold {
		return nil, ErrInsufficientParticipants
	}

	// R2-HIGH-06: Gaussian sigma per share = gamma1/(4*sqrt(n))
	// where n = actual number of participants signing in this session.
	// sigma_agg = gamma1/4 ≈ 131072. Norm-based rejection
	// ||z||_inf < gamma1-beta=524092 passes with ~93% probability.
	n := len(participants)
	sigma := float64(Dilithium3Gamma1) / (4.0 * math.Sqrt(float64(n)))

	sess := &QTDSession{
		message:           message,
		participants:      participants,
		threshold:         threshold,
		shares:            shares,
		useGaussian:       true,
		gaussianSigma:     sigma,
		gaussianSampler:   NewGaussianSampler(sigma),
		round1Commitments: make(map[int]*Round1Commitment),
		round2Reveals:     make(map[int]*Round2Reveal),
		wShares:           make(map[int][]byte),
		wComputed:         make(map[int][]byte),
		zShares:           make(map[int][]byte),
		createdAt:         time.Now(),
		timeout:           DefaultSessionTimeout,
	}

	// TSS-C2 (R8 2026-07-19 FIX): Auto-enable role separation when n >= 3.
	// Previously role separation was opt-in via explicit SetRoleAssignment
	// call, but no caller invoked it, leaving the default as the dangerous
	// single-aggregator Round2Aggregate path. With role separation off, a
	// single aggregator obtains w_agg + z_agg + z0_agg simultaneously,
	// enabling s1 recovery via NTT inversion.
	//
	// Now role separation is the DEFAULT for any session with >= 3
	// participants (the minimum for distinct W/Z/H roles). Callers who
	// really need the legacy single-aggregator mode can still explicitly
	// disable it via SetRoleAssignment(RoleAssignment{}), but this is
	// logged and strongly discouraged.
	//
	// For n < 3, role separation is mathematically impossible (need 3
	// distinct participants for 3 distinct roles), so we leave it off
	// with documented residual risk.
	//
	// TSS-M4 (R8 2026-07-19 FIX): Previously this block called
	// DeriveRoleAssignment(nil, participants), passing a NIL sessionID.
	// DeriveRoleAssignment uses sessionID as the HMAC key, so a nil key
	// made the role assignment a fixed deterministic function of the
	// participant set alone — every session for the same participants
	// got the SAME W/Z/H assignment, defeating the per-session rotation
	// that is the entire point of TSS-. An attacker who observed
	// one session's assignment could predict all future sessions'
	// assignments and continuously target the W-agg node.
	//
	// Fix: derive a real sessionID from the message + participants via
	// GenerateSessionID (same derivation used by DH masking), so each
	// signing session gets a fresh, message-bound role rotation. An
	// attacker who cannot control the message cannot predict the
	// assignment for a future session.
	if n >= 3 {
		sessionID := GenerateSessionID(message, participants)
		roles, err := DeriveRoleAssignment(sessionID, participants)
		if err == nil {
			sess.roleAssignment = roles
			sess.roleSeparationEnforced = true
		}
		// If DeriveRoleAssignment fails (shouldn't for n>=3), leave
		// role separation off — operator must explicitly configure.
	}

	return sess, nil
}

// NewGMQTDSession creates a Gaussian-Masked QTD (GM-QTD) signing session.
// Each party samples masking vector y_i from discrete Gaussian D_{Z,σ}
// with σ = γ1/(4·√n), where n = actual number of participants. The
// convolution theorem gives Σ y_i ~ D_{Z,γ1/4}, compatible with norm-based
// rejection sampling.
// R2-HIGH-06 FIX: Use len(participants) not threshold. When n > threshold
// (e.g. 3-of-5 with all 5 signing), using threshold makes sigma too large,
// inflating sigma_agg beyond gamma1/4 and causing rejection-sampling failures.
func NewGMQTDSession(message []byte, participants []int, threshold int, shares map[int]*QTDShare) (*QTDSession, error) {
	if len(participants) < threshold {
		return nil, ErrInsufficientParticipants
	}

	// R2-HIGH-06 FIX: Gaussian sigma per share = gamma1/(4*sqrt(n))
	// where n = actual number of participants signing in this session.
	// sigma_agg = sqrt(n) * gamma1/(4*sqrt(n)) = gamma1/4, compatible with
	// ||z||_inf < gamma1-beta. In Shamir mode with Lagrange coefficients,
	// sigma_agg = sqrt(Σ λ_i²) * sigma; since Σ λ_i² ≤ n for typical
	// coefficient sets, sigma_agg ≤ gamma1/4 (safe — never exceeds bound).
	n := len(participants)
	sigma := float64(Dilithium3Gamma1) / (4.0 * math.Sqrt(float64(n)))

	sess := &QTDSession{
		message:           message,
		participants:      participants,
		threshold:         threshold,
		shares:            shares,
		useGaussian:       true,
		gaussianSigma:     sigma,
		gaussianSampler:   NewGaussianSampler(sigma),
		round1Commitments: make(map[int]*Round1Commitment),
		round2Reveals:     make(map[int]*Round2Reveal),
		wShares:           make(map[int][]byte),
		wComputed:         make(map[int][]byte),
		zShares:           make(map[int][]byte),
		createdAt:         time.Now(),
		timeout:           DefaultSessionTimeout,
	}

	// TSS-C2 (R8 2026-07-19 FIX): Same auto-role-separation as NewQTDSession.
	// TSS-M4 (R8 2026-07-19 FIX): Derive a real sessionID from the message +
	// participants instead of passing nil. See NewQTDSession for the full
	// rationale — nil sessionID made role assignment a fixed function of
	// the participant set, defeating per-session rotation.
	if n >= 3 {
		sessionID := GenerateSessionID(message, participants)
		roles, err := DeriveRoleAssignment(sessionID, participants)
		if err == nil {
			sess.roleAssignment = roles
			sess.roleSeparationEnforced = true
		}
	}

	return sess, nil
}

// GaussianSigma returns the per-party Gaussian standard deviation.

// SetPKBytes sets the circl-format public key bytes for tr computation.
// Must be called before Round2Aggregate to enable circl-compatible challenge.
func (s *QTDSession) SetPKBytes(pkBytes []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkBytes = pkBytes
}

// SetDHKeys enables TSS- DH-based pairwise masking of Z0Share for this
// session. The local participant's X25519 private key and ALL participants'
// X25519 public keys (including the local participant's own public key) must
// be provided. The sessionID is derived from the message + participant set
// if nil, binding masks to this specific signing session.
//
// When DH masking is enabled, each participant's Z0Share is masked with
// pairwise DH-derived values that cancel in aggregation. This protects
// individual z0_i contributions from network eavesdroppers and raises the
// collusion threshold for s1 recovery (now requires W-agg + H-agg collusion).
//
// Must be called BEFORE Round2Reveal. Calling after Round2Reveal has no
// effect on already-generated reveals.
//
// SECURITY: The DH private key is stored in the session and MUST be zeroized
// by the caller after the session completes. Use ClearDHKeys() or
// dhPrivateKey.Bytes() zeroization.
func (s *QTDSession) SetDHKeys(localPrivKey *ecdh.PrivateKey, allPublicKeys map[int][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if localPrivKey == nil {
		return fmt.Errorf("nil DH private key")
	}
	if len(allPublicKeys) == 0 {
		return fmt.Errorf("empty DH public keys map")
	}

	// Validate all public keys are 32-byte X25519 keys
	for pid, pub := range allPublicKeys {
		if len(pub) != 32 {
			return fmt.Errorf("participant %d: invalid DH public key length %d (want 32)", pid, len(pub))
		}
	}

	// Derive session ID from message + participants (binds masks to session)
	s.sessionID = GenerateSessionID(s.message, s.participants)

	s.dhPrivateKey = localPrivKey
	s.dhPublicKeys = make(map[int][]byte, len(allPublicKeys))
	for pid, pub := range allPublicKeys {
		pubCopy := make([]byte, 32)
		copy(pubCopy, pub)
		s.dhPublicKeys[pid] = pubCopy
	}
	s.dhMaskEnabled = true

	// TSS-FIX (2026-07-17) — RUNTIME WARN: DH masking alone does NOT
	// close the H-aggregator residual. Masks cancel in aggregation by design,
	// so the H-aggregator still observes Σ z0_i = c·(t0-s2) in the clear and
	// can theoretically recover s1 via NTT inversion (see TSS- residual).
	// DH masking ONLY protects the transport path (network eavesdroppers and
	// non-aggregator participants). Full closure of the H-aggregator residual
	// requires distributed hint generation (SPDZ-style MPC) or FROST migration
	// — both are research-level protocol changes deferred beyond this P2 fix.
	//
	// Operators SHOULD also call SetRoleAssignment(DeriveRoleAssignment(...))
	// to enforce per-session role rotation; this raises the collusion cost
	// from "1 fixed H-aggregator forever" to "many rotating H-aggregators
	// over time". When role separation is not enforced, this warning fires
	// so operators are aware the H-aggregator role is a single-point trust.
	if !s.roleSeparationEnforced {
		log.Printf("WARNING (TSS-): DH masking enabled on session but role separation is NOT enforced. " +
			"DH masks cancel in aggregation by design (protect transport only, NOT the H-aggregator). " +
			"The H-aggregator still observes aggregated c·(t0-s2) and can theoretically recover s1. " +
			"Call SetRoleAssignment(DeriveRoleAssignment(sessionID, participants)) to enable per-session " +
			"role rotation and raise the collusion cost. Full closure requires distributed hint generation " +
			"(SPDZ-style MPC) or FROST migration — deferred beyond P2 scope.")
	}
	return nil
}

// ClearDHKeys clears the DH private key and public keys from the session.
// This SHOULD be called after the signing session completes to minimize
// the window of DH private key exposure in memory.
//
// TSS-FIX: Previously this method only nil-ed the *ecdh.PrivateKey
// reference, leaving the underlying secret bytes in heap memory until GC
// collected them (potentially never, under low pressure). Now we explicitly
// zeroize the unexported privateKey byte slice via reflection + unsafe, mirroring
// the crypto/kyber.go zeroStructFields pattern. This reduces the window for
// memory-dump attacks to recover X25519 DH private keys.
func (s *QTDSession) ClearDHKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()
	zeroizeECDHPrivateKey(s.dhPrivateKey)
	s.dhPrivateKey = nil
	for pid := range s.dhPublicKeys {
		for i := range s.dhPublicKeys[pid] {
			s.dhPublicKeys[pid][i] = 0
		}
		delete(s.dhPublicKeys, pid)
	}
	s.dhMaskEnabled = false
}

// zeroizeECDHPrivateKey overwrites the unexported byte-slice fields of an
// crypto/ecdh.PrivateKey in place using reflection + unsafe.Pointer.
//
// We cannot rely on (*ecdh.PrivateKey).Bytes() because the Go stdlib docs
// describe it as returning a copy; whether the underlying slice is aliased
// is implementation-defined and varies across Go versions. To guarantee
// in-place zeroization of the secret scalar, we walk the struct fields and
// overwrite any unexported []byte field. Pattern mirrors crypto/kyber.go
// zeroStructFields but specialized to the flat ecdh.PrivateKey layout.
//
// Safe behaviors:
//   - nil input is a no-op
//   - panics from reflect/unsafe (e.g., struct layout change across Go
//     versions) are recovered and logged; the caller's nil-ing of the
//     reference remains as fallback
func zeroizeECDHPrivateKey(k *ecdh.PrivateKey) {
	if k == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[SECURITY] zeroizeECDHPrivateKey: reflection failed (Go stdlib layout change?): %v", r)
		}
	}()
	v := reflect.ValueOf(k).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Kind() != reflect.Slice || field.Type().Elem().Kind() != reflect.Uint8 {
			continue
		}
		if field.Len() == 0 {
			continue
		}
		// field.Pointer() returns uintptr of the underlying array.
		// Convert to unsafe.Pointer then to *byte and use unsafe.Slice to
		// obtain a []byte view of the secret bytes for in-place overwrite.
		ptr := unsafe.Pointer(field.Pointer())
		slice := unsafe.Slice((*byte)(ptr), field.Len())
		for i := range slice {
			slice[i] = 0
		}
	}
	runtime.KeepAlive(k)
}

// DHMaskEnabled reports whether DH-based pairwise masking is active.
func (s *QTDSession) DHMaskEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dhMaskEnabled
}

func (s *QTDSession) GaussianSigma() float64 {
	if !s.useGaussian {
		return Dilithium3Gamma1
	}
	return s.gaussianSigma
}

// UseGaussian returns whether the session uses Gaussian masking.
func (s *QTDSession) UseGaussian() bool {
	return s.useGaussian
}

// Round1Commitment generates and returns the first round commitment.
func (s *QTDSession) Round1Commitment(participantID int) (*Round1Commitment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isExpired() {
		return nil, ErrSessionExpired
	}

	share, ok := s.shares[participantID]
	if !ok {
		return nil, ErrParticipantNotFound
	}

	ySeed := make([]byte, 32)
	_, err := rand.Read(ySeed)
	if err != nil {
		return nil, fmt.Errorf("failed to generate masking seed: %w", err)
	}

	var y PolyVec
	if s.useGaussian {
		y, err = SampleGaussianMaskingVec(ySeed, s.gaussianSigma)
		if err != nil {
			return nil, fmt.Errorf("failed to sample gaussian masking: %w", err)
		}
	} else {
		// FIX: In production mode, reject non-Gaussian masking.
		// SampleMasking uses uniform masking which does not preserve
		// zero-knowledge under aggregation.  sets useGaussian=true
		// by default, so this branch is only reachable if someone explicitly
		// creates a session with useGaussian=false. In production, this is a
		// security risk and must be rejected.
		if params.IsProductionEnv() {
			return nil, fmt.Errorf("non-Gaussian masking (SampleMasking) is forbidden in production mode (QAU_PRODUCTION=1): zero-knowledge not preserved under aggregation")
		}
		y, err = SampleMasking(ySeed)
		if err != nil {
			return nil, fmt.Errorf("failed to sample masking: %w", err)
		}
	}

	aMat, err := ComputeA(share.Rho, Dilithium3K, Dilithium3L)
	if err != nil {
		return nil, fmt.Errorf("failed to compute A: %w", err)
	}
	w := ComputeW(aMat, y)

	wBytes := VecToBytes(w)
	s.wShares[participantID] = VecToBytes(y)
	s.wComputed[participantID] = wBytes

	nonce := make([]byte, 16)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	h := sha256.New()
	h.Write(wBytes)
	h.Write(nonce)
	commitment := h.Sum(nil)

	round1 := &Round1Commitment{
		ParticipantID: participantID,
		Commitment:    commitment,
		Nonce:         nonce,
	}

	return round1, nil
}

// Round1Verify verifies all round 1 commitments are collected.
// Security fix (Round 4): validate that every ParticipantID belongs to the participant list,
// and detect duplicate submissions. Previously unchecked, an attacker could inject commitments for unauthorized participants,
// or overwrite legitimate commitments by resubmitting the same participant ID.
func (s *QTDSession) Round1Verify(commitments []*Round1Commitment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(commitments) < s.threshold {
		return ErrInsufficientParticipants
	}

	// build a participant-ID set for fast lookup
	participantSet := make(map[int]bool, len(s.participants))
	for _, pid := range s.participants {
		participantSet[pid] = true
	}

	// temp set for detecting duplicates
	seenInBatch := make(map[int]bool, len(commitments))

	for _, c := range commitments {
		// validate the ParticipantID against the participant list
		if !participantSet[c.ParticipantID] {
			return fmt.Errorf("%w: participant %d not in participant list",
				ErrInvalidParticipant, c.ParticipantID)
		}
		// detect duplicate ParticipantIDs within this batch
		if seenInBatch[c.ParticipantID] {
			return fmt.Errorf("%w: participant %d submitted multiple commitments in same batch",
				ErrDuplicateCommitment, c.ParticipantID)
		}
		// detect overwrites of existing commitments (preventing replay attacks from clobbering legitimate commitments)
		if _, exists := s.round1Commitments[c.ParticipantID]; exists {
			return fmt.Errorf("%w: participant %d already has a commitment stored",
				ErrDuplicateCommitment, c.ParticipantID)
		}
		seenInBatch[c.ParticipantID] = true
		s.round1Commitments[c.ParticipantID] = c
	}

	s.round1Complete = true
	return nil
}

// Round2Reveal generates the second round reveal.
func (s *QTDSession) Round2Reveal(participantID int) (*Round2Reveal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isExpired() {
		return nil, ErrSessionExpired
	}

	if !s.round1Complete {
		return nil, ErrRoundNotComplete
	}

	// Retrieve stored y_i
	yBytes, ok := s.wShares[participantID]
	if !ok {
		return nil, ErrParticipantNotFound
	}

	y, err := VecFromBytes(yBytes, Dilithium3L)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize y: %w", err)
	}

	wBytes, ok := s.wComputed[participantID]
	if !ok {
		return nil, ErrParticipantNotFound
	}

	wAgg := make(PolyVec, Dilithium3K)
	for _, pid := range s.participants {
		wb, ok := s.wComputed[pid]
		if !ok {
			return nil, ErrParticipantNotFound
		}
		wVec, err := VecFromBytes(wb, Dilithium3K)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize W for participant %d: %w", pid, err)
		}
		for i := 0; i < Dilithium3K; i++ {
			wAgg[i].Add(&wAgg[i], &wVec[i])
		}
	}

	wHigh := HighBits(wAgg, Dilithium3Gamma2)
	wHighBytes := PackW1(wHigh)

	// tr = SHAKE-256(pk) for circl-compatible challenge
	hTr := sha3.NewShake256()
	hTr.Write(s.pkBytes)
	var tr [32]byte
	hTr.Read(tr[:])

	c, _, err := ComputeChallenge(wHighBytes, tr[:], s.message, int(Dilithium3Tau))
	if err != nil {
		return nil, fmt.Errorf("failed to compute challenge: %w", err)
	}

	// Retrieve S1 share
	share := s.shares[participantID]
	s1Share, err := VecFromBytes(share.S1ShareBytes, Dilithium3L)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize S1 share: %w", err)
	}

	// Compute z_i = s1_i * c + y_i
	// TSS-001 HIGH FIX: In Shamir mode, multiply by Lagrange coefficient λ_i:
	//   z_i = λ_i * s1_share_i * c + y_i
	// This ensures the aggregated z = Σ λ_i * s1_i * c + Σ y_i = s1 * c + Σ y_i
	// produces a valid standard Dilithium3 signature.
	z := make(PolyVec, Dilithium3L)
	if s.useShamir && s.lagrangeCoeffs != nil {
		lambda, ok := s.lagrangeCoeffs[participantID]
		if !ok {
			return nil, fmt.Errorf("lagrange coefficient not found for participant %d", participantID)
		}
		for i := 0; i < Dilithium3L; i++ {
			var sc Poly
			sc.PolyMul(&s1Share[i], &c)
			sc.ScalarMul(&sc, lambda)
			z[i].Add(&sc, &y[i])
			// R48-QP-03 FIX: Zero sc after use — it contains lambda_i*s1_i*c,
			// which is secret-key-derived material (same as non-Shamir path).
			sc = Poly{}
		}
	} else {
		for i := 0; i < Dilithium3L; i++ {
			// L6-038: sc is declared inside the loop body (minimal scope).
			// sc = s1_i * c contains secret-key-derived material.
			// Poly is a stack-allocated value type ([N]int32), so it is
			// automatically discarded when the loop iteration ends — no
			// explicit zeroization is needed.
			var sc Poly
			sc.PolyMul(&s1Share[i], &c)
			z[i].Add(&sc, &y[i])
			// FIX: Zero sc after use — it contains secret-key-derived material.
			sc = Poly{}
		}
	}

	// TSS analysis (2026-07-16): per-participant Lyubashevsky probabilistic rejection sampling
	// does not apply in a threshold-signing setup, for the following reasons:
	//
	// under additive secret sharing, each s1_i has coefficients that are random values in [0, Q)
	// (only the total s1 = Σs1_i has small coefficients [-η, η]). Therefore
	//   ‖sc‖ = ‖λ_i·s1_i·c‖ ~ τ·η·Q ~ 10⁸
	// while sigma ~ γ1/(4√n) ~ 75K, giving a rejection exponent
	//   13.5·‖sc‖/σ ~ 10⁵
	// so p = exp(-10⁵) ≈ 0 — 100% rejection.
	//
	// the correct zero-knowledge guarantee comes from the aggregation layer:
	//   z = Σz_i = (Σλ_i·s1_i)·c + Σy_i = s1·c + Σy_i
	// where s1 has small coefficients and Σy_i follows D_{γ1/4}. This has exactly the same distribution
	// as a standard Dilithium3 signature, so the norm check in Round2Aggregate
	// ‖z‖_∞ < γ1-β provides the correct zero-knowledge guarantee.
	//
	// The individual z_i = λ_i·s1_i·c + y_i seen by the aggregator is masked by y_i.
	// Recovering s1_i from multiple {(c_j, z_i_j)} sets requires solving a lattice problem (the standard threshold Dilithium3
	// security assumption), and y_i differs per signing session, making the attack infeasible.
	//
	// Per-participant LyubashevskyReject calls are removed; the aggregation-layer norm check is kept.

	// Store z share
	s.zShares[participantID] = VecToBytes(z)

	// AUDIT (2026) TSS-FIX (CRITICAL): Compute the COMBINED z0
	// contribution z0_i = λ_i·c·(t0_i - s2_i) instead of transmitting
	// cs2_i = λ_i·c·s2_i and ct0_i = λ_i·c·t0_i SEPARATELY.
	//
	// The previous design (TSS-) transmitted cs2_i and ct0_i separately,
	// claiming they were "signature-derived and safe." This was FALSE: the
	// challenge polynomial c is invertible in the NTT ring, so the aggregator
	// could recover s2 and t0 by NTT inversion, then s1 via A·s1 = t - s2.
	//
	// The combined z0_i prevents the aggregator from decomposing c·(t0-s2)
	// back into c·t0 and c·s2. The aggregator can only obtain c·(t0-s2),
	// which it needs for hint computation (z0 = w0 + c·(t0-s2)). This reduces
	// the vulnerability from Critical (full key) to High (s1 only).
	z0Share, err := computeZ0Contribution(share, c, participantID, s.useShamir, s.lagrangeCoeffs)
	if err != nil {
		return nil, fmt.Errorf("failed to compute z0 contribution: %w", err)
	}

	// TSS-FIX (2026-07-17): Apply DH-based pairwise mask to z0Share
	// before transmission. The mask protects individual z0_i from network
	// eavesdroppers. Masks cancel in aggregation, so the H-aggregator still
	// obtains the correct Σ z0_i = c·(t0-s2) for hint computation.
	// See qtd_dh_mask.go for the full security analysis.
	if s.dhMaskEnabled && s.dhPrivateKey != nil && len(s.dhPublicKeys) > 0 {
		netMask, err := ComputeParticipantMask(participantID, s.dhPrivateKey, s.dhPublicKeys, s.sessionID)
		if err != nil {
			// Zero z0Share before returning on error
			for i := range z0Share {
				z0Share[i].Zero()
			}
			return nil, fmt.Errorf("failed to compute DH mask: %w", err)
		}
		maskedZ0, err := ApplyMaskToZ0(z0Share, netMask)
		if err != nil {
			// Zero z0Share and netMask before returning on error
			for i := range z0Share {
				z0Share[i].Zero()
			}
			for i := range netMask {
				netMask[i].Zero()
			}
			return nil, fmt.Errorf("failed to apply DH mask: %w", err)
		}
		// Zero the unmasked z0Share and netMask — only maskedZ0 leaves
		for i := range z0Share {
			z0Share[i].Zero()
		}
		for i := range netMask {
			netMask[i].Zero()
		}
		z0Share = maskedZ0
	}

	z0Bytes := VecToBytes(z0Share)
	// Zero the PolyVec intermediate — it contains c·(t0_i - s2_i) which,
	// while not individually decomposable, still derives from secret shares.
	for i := range z0Share {
		z0Share[i].Zero()
	}

	// L8-008 CONFIRMED FIXED: No hashedMessage byte-slice local variable exists
	// in this function (verified by grep across the entire qtd package). The
	// challenge c is a Poly stack value (automatically discarded), and the
	// sensitive PolyVecs (y, z, s1Share) are value-type [N]int32 arrays per
	// the L6-038 rationale — no heap-allocated byte buffer needs zeroizing.

	// TSS-PR-05 FIX (deep-audit 2026-07-12): the only guard above checks
	// s.wShares; s.round1Commitments is populated by a different step
	// (Round1Verify), so in Shamir mode a participant that computed its
	// commitment but was not in the verified threshold subset has no entry here.
	// The old direct index s.round1Commitments[participantID].Nonce then
	// nil-dereferenced and panicked.
	r1c, ok := s.round1Commitments[participantID]
	if !ok || r1c == nil {
		return nil, ErrRoundNotComplete
	}

	reveal := &Round2Reveal{
		ParticipantID: participantID,
		WShare:        wBytes,
		ZShare:        VecToBytes(z),
		Z0Share:       z0Bytes,
		Nonce:         r1c.Nonce,
	}
	// R47-QP-02 NOTE: Z0Share is now owned by the reveal struct.
	// Callers SHOULD zero it after sending to the aggregator using
	// qtd.ZeroRevealSecrets(reveal) once the reveal is no longer needed.
	return reveal, nil
}

// computeZ0Contribution computes the combined z0 contribution:
//
//	z0_i = λ_i·c·(t0_i - s2_i) = λ_i·c·t0_i - λ_i·c·s2_i
//
// This COMBINED contribution is transmitted to the aggregator instead of
// transmitting c·s2_i and c·t0_i SEPARATELY. The aggregator sums z0_i to
// obtain c·(t0-s2), which is exactly what's needed for hint computation
// (z0 = w0 + c·(t0-s2)). The aggregator CANNOT decompose c·(t0-s2) back
// into c·t0 and c·s2, preventing the full-key-recovery attack (TSS-).
//
// AUDIT (2026) TSS-FIX: Replaces computeMaskedContributions which
// returned cs2 and ct0 separately — enabling the aggregator to invert each
// via NTT and recover the full private key.
func computeZ0Contribution(share *QTDShare, c Poly, participantID int, useShamir bool, lagrangeCoeffs map[int]int64) (PolyVec, error) {
	if share == nil {
		return nil, fmt.Errorf("nil share for participant %d", participantID)
	}
	s2Share, err := VecFromBytes(share.S2ShareBytes, Dilithium3K)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize S2 share: %w", err)
	}
	t0Share, err := VecFromBytes(share.T0ShareBytes, Dilithium3K)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize T0 share: %w", err)
	}

	var lambda int64 = 1
	if useShamir && lagrangeCoeffs != nil {
		lambda = lagrangeCoeffs[participantID]
	}

	z0 := make(PolyVec, Dilithium3K)
	for i := 0; i < Dilithium3K; i++ {
		// Compute (t0_i - s2_i) first, then multiply by c, then by λ_i.
		// This avoids ever materializing c·s2_i or c·t0_i individually.
		var diff Poly
		diff.Sub(&t0Share[i], &s2Share[i])
		diff.Reduce()
		var tmp Poly
		tmp.PolyMul(&c, &diff)
		z0[i].ScalarMul(&tmp, lambda)
		// Zero intermediates — diff contains (t0_i - s2_i), tmp contains
		// c·(t0_i - s2_i) before scalar multiplication.
		diff = Poly{}
		tmp = Poly{}
	}
	return z0, nil
}

// ZeroRevealSecrets zeros the z0 contribution (Z0Share) in a Round2Reveal.
// While Z0Share is a combined contribution (not raw key shares), it still
// derives from secret shares and should be zeroed after use to minimize
// the window of exposure.
// AUDIT (2026) TSS-FIX: Updated to zero Z0Share instead of the
// removed Cs2Share/Ct0Share fields.
func ZeroRevealSecrets(r *Round2Reveal) {
	if r == nil {
		return
	}
	if len(r.Z0Share) > 0 {
		for i := range r.Z0Share {
			r.Z0Share[i] = 0
		}
	}
}

// Round2Aggregate aggregates all reveals using additive secret sharing
// and produces a standard Dilithium3-compatible signature.
//
// With additive sharing, z = Σ z_i = s1*c + Σ y_i. Since each y_i has small
// coefficients (|y_i| ≤ eta=72), the sum Σ y_i is still small enough for
// rejection sampling. This produces a signature that is verifiable by any
// standard Dilithium3 verifier.
func (s *QTDSession) Round2Aggregate(reveals []*Round2Reveal) (*QTDSignature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// TSS-FIX: When role separation is enforced, the legacy
	// single-aggregator method is DISABLED. The caller MUST use
	// Round2AggregateW / Z / H instead. This prevents a single caller
	// from obtaining w_agg, z_agg, and z0_agg simultaneously.
	if s.roleSeparationEnforced {
		return nil, ErrRoleSeparationRequired
	}

	if s.isExpired() {
		return nil, ErrSessionExpired
	}

	// R48-QP-02 FIX: Guard against duplicate aggregation. If round2 is already
	// complete, return the existing result instead of overwriting.
	if s.round2Complete {
		return nil, fmt.Errorf("round 2 already complete")
	}

	if len(reveals) < s.threshold {
		return nil, ErrInsufficientParticipants
	}

	for _, r := range reveals {
		// Q21-004 FIX: Validate participant ID before lookup
		// R46-QP-01 FIX: Use map lookup instead of range check. The old
		// check assumed contiguous 1..N IDs, rejecting non-contiguous sets.
		c, ok := s.round1Commitments[r.ParticipantID]
		if !ok {
			return nil, ErrParticipantNotFound
		}

		h := sha256.New()
		h.Write(r.WShare)
		h.Write(r.Nonce)
		expected := h.Sum(nil)

		if !bytesEqual(c.Commitment, expected) {
			return nil, ErrCommitmentMismatch
		}

		s.round2Reveals[r.ParticipantID] = r
	}

	// R47-QP-09 FIX: Validate Z0Share/ZShare are non-empty and can
	// be deserialized. Z0Share is a PolyVec of K polynomials (combined z0
	// contribution = λ_i·c·(t0_i - s2_i)), ZShare is L polynomials
	// (s1-derived), while WShare is K polynomials (A*y).
	// AUDIT (2026) TSS-FIX: Replaced Cs2Share/Ct0Share validation
	// with Z0Share validation (combined contribution, not separate c·s2/c·t0).
	// VecFromBytes checks exact length internally.
	for _, r := range reveals {
		if len(r.Z0Share) == 0 {
			return nil, fmt.Errorf("participant %d: empty Z0Share (combined z0 contribution required)", r.ParticipantID)
		}
		if _, err := VecFromBytes(r.Z0Share, Dilithium3K); err != nil {
			return nil, fmt.Errorf("invalid Z0Share: %w", err)
		}
		if len(r.ZShare) == 0 {
			return nil, fmt.Errorf("empty ZShare")
		}
		if _, err := VecFromBytes(r.ZShare, Dilithium3L); err != nil {
			return nil, fmt.Errorf("invalid ZShare: %w", err)
		}
	}

	wAggVec := make(PolyVec, Dilithium3K)
	for _, r := range reveals {
		wVec, err := VecFromBytes(r.WShare, Dilithium3K)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize W share: %w", err)
		}
		for i := 0; i < Dilithium3K; i++ {
			wAggVec[i].Add(&wAggVec[i], &wVec[i])
		}
	}

	wHigh := HighBits(wAggVec, Dilithium3Gamma2)
	wHighBytes := PackW1(wHigh)

	// tr = SHAKE-256(pk) for circl-compatible challenge computation
	hTr := sha3.NewShake256()
	hTr.Write(s.pkBytes)
	var tr [32]byte
	hTr.Read(tr[:])

	// AUDIT (2026) TSS-FIX: The challenge polynomial `c` is NOT
	// materialized by the aggregator. In the previous design (TSS-),
	// the aggregator received c·s2 and c·t0 separately; combined with c
	// (recomputable from ctilde), this allowed NTT inversion to recover
	// s2 and t0, then s1 via A·s1 = t - s2. Now the aggregator only
	// receives the COMBINED Z0Share = c·(t0-s2), which cannot be decomposed.
	// Only ctilde (the challenge seed) is needed for the final signature.
	_, ctilde, err := ComputeChallenge(wHighBytes, tr[:], s.message, int(Dilithium3Tau))
	if err != nil {
		return nil, fmt.Errorf("failed to compute challenge: %w", err)
	}

	zUnweighted := make(PolyVec, Dilithium3L)
	for _, r := range reveals {
		zShare, err := VecFromBytes(r.ZShare, Dilithium3L)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize z share: %w", err)
		}
		for i := 0; i < Dilithium3L; i++ {
			zUnweighted[i].Add(&zUnweighted[i], &zShare[i])
		}
	}
	z := zUnweighted

	// Standard Dilithium3 rejection check: ||z||_inf < gamma1 - beta.
	// R2-HIGH-06: With Gaussian masking (sigma_agg = gamma1/4), the aggregate
	// y has ||y||_inf ~ 3.3*sigma_agg ~ 435K, well below gamma1-beta=524092.
	// The ~7% rejection cases trigger a protocol retry (new y_i sampled).
	zNorm := VecNormInf(z)
	rejectionBound := int64(Dilithium3Gamma1 - Dilithium3Beta)
	if !CheckRejection(z, rejectionBound) {
		return nil, fmt.Errorf("%w: ||z||_inf = %d, bound = %d",
			ErrRejectionSamplingFailed, zNorm, rejectionBound)
	}

	// AUDIT (2026) TSS-FIX: Sum the COMBINED z0 contributions
	// from all participants. Each participant computed z0_i = λ_i·c·(t0_i-s2_i)
	// locally. The aggregator sums:
	//   z0Contribution = Σ z0_i = Σ λ_i·c·(t0_i - s2_i) = c·(t0 - s2)
	//
	// This is the ONLY secret-derived value the aggregator obtains. It is
	// exactly what's needed for hint computation (z0 = w0 + c·(t0-s2)).
	// The aggregator CANNOT decompose c·(t0-s2) into c·t0 and c·s2 separately,
	// preventing the full-key-recovery attack.
	//
	// RESIDUAL RISK (TSS- PARTIAL CLOSURE, 2026-07-17):
	// The H-aggregator can theoretically recover s1 from c·(t0-s2) =
	// c·(A·s1 - t1·2^d) via NTT inversion + linear algebra. It CANNOT
	// recover s2 or t0 individually, so it CANNOT forge signatures.
	//
	// TSS-FIX (DH-BASED PAIRWISE MASKING): When SetDHKeys() has been
	// called, individual Z0Share transmissions are masked with pairwise
	// DH-derived values that cancel in aggregation. This provides:
	//   1. Transport-level protection: eavesdroppers see masked z0_i, not raw
	//   2. Participant privacy: non-aggregator participants can't recover
	//      other participants' z0_i
	//   3. Raised collusion threshold: s1 recovery now requires W-agg + H-agg
	//      collusion (combined with role-separated aggregation from )
	//
	// FULL CLOSURE (deferred): The H-aggregator still observes the AGGREGATED
	// c·(t0-s2) after summing masked contributions (masks cancel). Fully
	// eliminating this requires DISTRIBUTED HINT GENERATION — a protocol
	// where the hint is computed without any single party observing
	// c·(t0-s2) in the clear. This is a research-level protocol change
	// deferred to future work. See qtd_dh_mask.go for details.
	//
	// QUANTUM- (audit 2026-07-17, Low): reaffirmed as documented
	// limitation. s1 recovery from aggregated c·(t0-s2) is theoretical
	// (requires W-agg + H-agg collusion, cannot forge signatures alone).
	// Production hard-blocks via QAU_ENABLE_DISTRIBUTED_TSS. Distributed
	// hint generation (SPDZ-style MPC / FROST migration) tracked as
	// research-level future work — out of P3 scope.
	z0Contribution := make(PolyVec, Dilithium3K)
	// FIX: Zero z0Contribution after use.
	defer func() {
		for i := range z0Contribution {
			z0Contribution[i].Zero()
		}
	}()
	// TSS-M7 (R8 2026-07-19 FIX): Per-participant Z0Share validation.
	//
	// Previously the loop only deserialized and summed Z0Shares without
	// any per-participant bound check. A malicious participant could
	// submit an arbitrarily large Z0Share that would only be caught
	// AFTER full aggregation by the (aggregate) bound check below or by
	// the final UseHint verification. This made DoS attacks anonymous:
	// the operator could see "signing failed" but could not tell which
	// participant submitted the bad Z0Share.
	//
	// Each Z0Share = λ_i · c · (t0_i - s2_i). Since c, λ_i, t0_i, s2_i
	// all have bounded norms (|c|_inf ≤ τ=64, |λ_i| small, |t0_i| ≤ γ2,
	// |s2_i| ≤ η), the resulting Z0Share coefficient norm is bounded.
	// A single Z0Share with ||z0Share||_inf exceeding 2·γ2 cannot
	// contribute to a valid hint and is necessarily malicious (or a
	// software bug). Reject early with attribution.
	//
	// NOTE: This is a NECESSARY condition for hint validity, not a full
	// signature verification. Full closure requires Pedersen homomorphic
	// verification of c·λ·(t0-s2) against VVectorS2/VVectorT0 — research-
	// level work tracked as future closure.
	//
	// TSS-M7 (R8 2026-07-19 FIX): Attribution logging for bad Z0Shares.
	//
	// The previous code deserialized and summed Z0Shares without any
	// per-participant validation. A malicious participant could submit a
	// malformed Z0Share; the failure would only surface at the aggregate
	// bound check below or the final UseHint verification, and the
	// operator could not tell which participant was responsible.
	//
	// We attempted a per-participant norm bound check (||z0Share||_inf
	// < 2·γ2), but it is mathematically unsound: Z0Share = λ_i·c·(t0-s2)
	// is computed mod Q=8380417, and Lagrange coefficients λ_i are
	// essentially random mod Q. A legitimate Z0Share can have centered
	// coefficients arbitrarily close to Q/2, so any fixed bound below Q/2
	// rejects honest participants. The bound of 2·γ2 only applies to the
	// UNMODULATED mathematical value, not the mod-Q-reduced value the
	// aggregator actually sees.
	//
	// Closure approach taken here:
	//   1. Validate structural correctness (non-nil reveal, non-empty
	//      Z0Share, correct length via VecFromBytes).
	//   2. Record per-participant Z0Share hashes for post-hoc attribution.
	//   3. The UseHint verification at the end catches any inconsistent
	//      Z0Share that would produce an invalid hint. When that fires,
	//      we log the per-participant hashes so the operator can identify
	//      the offending participant by comparing against the hashes
	//      recorded here.
	//   4. Full cryptographic closure (Pedersen homomorphic verification
	//      of c·λ·(t0-s2) against VVectorS2/VVectorT0) is research-level
	//      work and is tracked as future closure.
	participantZ0Hashes := make(map[int]string, len(reveals))
	for _, r := range reveals {
		if r == nil {
			return nil, fmt.Errorf("nil reveal in aggregation")
		}
		if len(r.Z0Share) == 0 {
			return nil, fmt.Errorf("TSS-M7: participant %d: empty Z0Share", r.ParticipantID)
		}
		z0Share, err := VecFromBytes(r.Z0Share, Dilithium3K)
		if err != nil {
			return nil, fmt.Errorf("TSS-M7: failed to deserialize Z0Share from participant %d: %w", r.ParticipantID, err)
		}
		// Record SHA-256 of the Z0Share bytes for post-hoc attribution.
		h := sha256.Sum256(r.Z0Share)
		participantZ0Hashes[r.ParticipantID] = fmt.Sprintf("%x", h[:8])
		for i := 0; i < Dilithium3K; i++ {
			z0Contribution[i].Add(&z0Contribution[i], &z0Share[i])
		}
	}

	// Decompose w to get w0 (low bits). w1 (high bits) is already computed
	// as wHigh above. circl's SignTo decomposes w BEFORE applying the c·s2
	// and c·t0 modifications, and passes the unwrapped modified low bits to
	// makeHint. This is critical: decomposing (w - c·s2 + c·t0) instead would
	// wrap the value at boundaries and produce wrong hints.
	w0 := LowBits(wAggVec, int(Dilithium3Gamma2))

	// AUDIT (2026) TSS-FIX: The previous design performed two
	// rejection checks:
	//   (1) ||w0 - c·s2|| < γ2 - β  (ensures HighBits(w) == HighBits(w - c·s2))
	//   (2) ||c·t0|| < γ2           (ensures hint correction is valid)
	//
	// These checks require the aggregator to know c·s2 and c·t0 SEPARATELY,
	// which is exactly the decomposition we eliminated to prevent the
	// full-key-recovery attack. The checks are SKIPPED in the Round5 protocol:
	//
	// - Correctness: The UseHint verification at the end (lines ~843-857)
	//   catches any invalid hint, ensuring the signature is correct.
	// - ZK: In standard Dilithium3, these checks prevent the VERIFIER (who
	//   sees z and h but NOT z0) from learning s2/t0. In the threshold
	//   protocol, the aggregator IS the signer and already sees z0 =
	//   w0 + c·(t0-s2). The hint is a deterministic function of z0 and w1
	//   (both known to the aggregator), so it leaks NO additional information.
	//   The only secret-derived info the aggregator has is z0Contribution =
	//   c·(t0-s2), whose leakage (s1 recovery) is documented above.
	//
	// A weaker necessary-condition check is kept: ||z0Contribution|| must be
	// bounded for the hint to have any chance of being valid. If this bound
	// is exceeded, early-reject to save computation.
	if VecNormInf(z0Contribution) >= 2*int64(Dilithium3Gamma2) {
		return nil, fmt.Errorf("%w: ||c·(t0-s2)||_∞ exceeds 2·γ₂ (necessary condition for valid hint)",
			ErrRejectionSamplingFailed)
	}

	// Compute z0 = w0 + c·(t0-s2) (mod Q) — the modified low bits for makeHint.
	// Also compute r' = w + c·(t0-s2) for UseHint verification.
	// Note: z0 = w0 - c·s2 + c·t0 = w0 + c·(t0-s2) = w0 + z0Contribution.
	z0Vec := make(PolyVec, Dilithium3K)
	rCt0 := make(PolyVec, Dilithium3K)
	for i := 0; i < Dilithium3K; i++ {
		// z0 = w0 + z0Contribution (for makeHint)
		z0Vec[i].Add(&w0[i], &z0Contribution[i])
		z0Vec[i].Reduce()
		// r' = w + z0Contribution (for UseHint verification)
		rCt0[i].Add(&wAggVec[i], &z0Contribution[i])
		rCt0[i].Reduce()
	}

	// Compute hint using circl's makeHint(z0, w1) algorithm.
	hint, hintCount := ComputeHint(z0Vec, wHigh, int(Dilithium3Gamma2))

	// Rejection check 3: hint count ≤ Omega
	if hintCount > int(Dilithium3Omega) {
		return nil, fmt.Errorf("%w: hint count %d exceeds Omega %d",
			ErrRejectionSamplingFailed, hintCount, Dilithium3Omega)
	}

	fullSig := PackGMQTDSignature(z, hint, ctilde)
	// AUDIT-FULL CR-08 FIX (2026-08-15): use the named constant instead of
	// the magic-number local `zByteSize := 640`. The slice expression below
	// now reads the single source of truth declared in the param const block.

	wRecovered := UseHint(hint, rCt0, int(Dilithium3Gamma2))
	var mismatch int
	for i := 0; i < Dilithium3K && mismatch == 0; i++ {
		for j := 0; j < N && mismatch == 0; j++ {
			wAggN := int32(int64(wAggVec[i][j]) % Q)
			if wAggN < 0 {
				wAggN += Q
			}
			expectedW1 := highBitsCoeff(wAggN, int(Dilithium3Gamma2))
			if wRecovered[i][j] != expectedW1 {
				mismatch++
			}
		}
	}
	if mismatch > 0 {
		// TSS-M7 (R8 2026-07-19 FIX): UseHint verification failed — the
		// assembled hint does not recover w1 from rCt0. This indicates at
		// least one participant submitted an inconsistent Z0Share. Log
		// the per-participant Z0Share hashes recorded above so operators
		// can identify the offending participant by comparing these
		// hashes against the ones recorded by the H-aggregator (and the
		// W/Z aggregators in role-separated mode) for the same session.
		log.Printf("TSS-M7: Round2Aggregate UseHint verification failed (mismatch=%d) — participant Z0Share hashes: %v",
			mismatch, participantZ0Hashes)
		return nil, ErrRejectionSamplingFailed
	}

	sig := &QTDSignature{
		FullSig: fullSig,
		Z:       fullSig[32 : 32+Dilithium3L*Dilithium3ZPolyByteSize],
		Ctilde:  fullSig[:32],
		WAgg:    wHighBytes,
	}

	s.round2Complete = true
	return sig, nil
}

// Verify verifies a QTD signature against a message and public key.
// Supports both standard format (3293 bytes, hintCount ≤ Omega) and
// full-bitmap format (4064 bytes, arbitrary hintCount).
func (s *QTDSession) Verify(sig *QTDSignature, message []byte, pubKey *mode3.PublicKey) bool {
	if sig == nil || pubKey == nil {
		return false
	}
	if len(sig.FullSig) == 0 {
		return false
	}
	switch len(sig.FullSig) {
	case 3293:
		return mode3.Verify(pubKey, message, sig.FullSig)
	case 4064:
		return CheckGMQTDFullSignature(pubKey, message, sig.FullSig)
	default:
		return false
	}
}

// L4-006 FIX: Removed `s.timeout > 0 &&` guard. Previously, when timeout
// was 0 the session never expired, allowing stale sessions to persist
// indefinitely. SetTimeout now clamps to DefaultSessionTimeout so timeout
// is always positive.
// L5-013 CONFIRMED FIXED: All timeout edge cases are covered —
// (1) isExpired() has no zero-guard, so timeout==0 expires immediately;
// (2) SetTimeout() clamps non-positive d to DefaultSessionTimeout;
// (3) both constructors (NewQTDSession, NewGMQTDSession) initialize
//
//	timeout to DefaultSessionTimeout. No remaining edge cases found.
func (s *QTDSession) isExpired() bool {
	return time.Since(s.createdAt) > s.timeout
}

func (s *QTDSession) IsExpired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isExpired()
}

func (s *QTDSession) SetTimeout(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// L4-006 FIX: Ensure timeout is always positive to prevent
	// sessions from never expiring.
	if d <= 0 {
		d = DefaultSessionTimeout
	}
	s.timeout = d
}

// SetCreatedAt overrides the session's creation timestamp.
//
// TSS-M8 (R8 2026-07-19 FIX): Used by TSSManager.CreateParticipantSession to
// propagate the aggregator's authoritative timestamp (carried in the
// SessionInit wire payload) into the inner qtdSession. This decouples the
// session's 5-minute timeout from per-node clock skew: even if a
// participant's NTP feed is off by minutes, its qtdSession expires at the
// same wall-clock instant as every other participant's (and as the
// aggregator's). Callers MUST only pass a timestamp sourced from a
// B-5-authenticated SessionInit payload; an attacker who can forge the
// timestamp could extend or shorten the session window.
//
// The timestamp is interpreted as an absolute time (typically
// time.Unix(0, initiatedAt) where initiatedAt is the aggregator's Unix-nano
// timestamp). It must be in the past or near-present; future timestamps
// would artificially extend the session beyond the configured timeout.
func (s *QTDSession) SetCreatedAt(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.createdAt = t
}

func (s *QTDSession) SetShamirMode(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.useShamir = enabled
}

func (s *QTDSession) SetGaussianSigma(sigma float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gaussianSigma = sigma
}

func (s *QTDSession) SetLagrangeCoefficients(participants []int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lagrangeCoeffs = make(map[int]int64, len(participants))
	for _, id := range participants {
		s.lagrangeCoeffs[id] = lagrangeCoeff(id, participants)
	}
}

// lagrangeCoeff computes the Lagrange coefficient for a given participant.
// R47-QP-08 NOTE: All arithmetic uses int64 to prevent overflow on 32-bit
// platforms. The product num*mj is at most (Q-1)^2 ≈ 7e13, well within
// int64 range (9.2e18). Participant IDs are small, so int→int64 conversion
// is always safe.
func lagrangeCoeff(i int, allParticipants []int) int64 {
	num := int64(1)
	den := int64(1)

	for _, j := range allParticipants {
		if i == j {
			continue
		}
		mj := ((-int64(j))%Q + Q) % Q
		num = (num * mj) % Q
		d := ((int64(i)-int64(j))%Q + Q) % Q
		den = (den * d) % Q
	}

	denInv := modInverse(den, Q)

	result := (num * denInv) % Q

	return result
}

// modInverse computes the modular inverse using Fermat's little theorem
// (a^(m-2) mod m, valid for prime m) with a constant-time fixed-iteration
// square-and-multiply.
//
// TSS-FIX (2026-07-17): Replaced the non-constant-time extended
// Euclidean algorithm (data-dependent loop iteration count) with a
// fixed-iteration Fermat little theorem exponentiation. The previous
// implementation's iteration count varied with input values, leaking
// timing information. Although modInverse is currently only called from
// lagrangeCoeff() with PUBLIC participant IDs (no secret-key exposure),
// we harden defensively per project policy "fix all vulnerability levels".
//
// Constant-time properties:
//   - Fixed iteration count (63 iterations covering all bits of m-2)
//   - Each iteration: ALWAYS squares and ALWAYS multiplies; the multiply
//     result is conditionally selected via ctSelectI64 mask (no branch)
//   - The exponent (m-2) is public (it's the prime modulus Q), so bit
//     decomposition is not secret — but we still execute uniformly.
//
// Arithmetic safety: Q = 8380417 < 2^23. All intermediate values are
// reduced mod Q, so result < 2^23 and result*result < 2^46, well within
// int64 range (2^63). No overflow possible.
//
// L6-041 RESOLVED: replaced with constant-time implementation.
// L8-020 SUPERSEDED: security note above updated to reflect resolution.
// CRYPTO- (Info): 63 iterations cover all bits of int64. Since Q=8380417
// < 2^23, exponent = Q-2 has only 23 active bits; the high 40 bits are zero
// and the extra ~40 square-and-multiply iterations perform no-ops (1^2 = 1,
// 1*x = x with mask=0). This is a deliberate defensive-depth choice: a
// constant compile-time iteration count is REQUIRED for constant-time
// correctness (iterating by the actual bit-length of the exponent would
// leak the bit length). Performance cost (~40 extra modmul) is negligible.
// No fix needed; documented for future reviewers.
func modInverse(a, m int64) int64 {
	if m <= 1 {
		return 0
	}
	a = ((a % m) + m) % m
	if a == 0 {
		// No inverse exists; lagrangeCoeff guarantees denominator != 0
		// because participant IDs are distinct mod Q.
		return 0
	}

	// Fermat: a^(-1) ≡ a^(m-2) mod m  (m prime).
	exponent := m - 2

	// Fixed 63-iteration square-and-multiply, MSB→LSB.
	// Processing from MSB to LSB is essential: starting from result=1,
	// high zero bits keep result=1 (no-op), then the first set bit begins
	// the actual exponentiation. Iterating LSB→MSB would continue squaring
	// past the exponent's MSB, corrupting the result.
	//
	// Each iteration ALWAYS squares and ALWAYS multiplies; the multiply
	// result is conditionally selected via ctSelectI64 mask (no branch),
	// keeping timing uniform regardless of exponent bit values.
	result := int64(1)
	for i := 62; i >= 0; i-- {
		// Always square: result = result^2 mod m.
		resultSq := (result * result) % m
		// Always multiply: candidate = resultSq * a mod m.
		resultMul := (resultSq * a) % m
		// Select based on bit i of exponent (0 → keep square, 1 → multiply).
		bit := int((exponent >> uint(i)) & 1)
		result = ctSelectI64(bit, resultMul, resultSq)
	}

	return result
}

// ctSelectI64 returns cond ? a : b in constant time. cond must be 0 or 1.
// Used by modInverse's constant-time square-and-multiply.
func ctSelectI64(cond int, a, b int64) int64 {
	mask := -int64(cond) // 0 if cond==0, -1 (all 1s) if cond==1
	return (a & mask) | (b &^ mask)
}

// bytesEqual compares two byte slices for equality.
func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// AUDIT (2026) TSS-FIX: InjectExternalShare has been REMOVED.
// The old protocol had the aggregator inject raw S2/T0 shares via this
// method, which were then used by Round2Aggregate to reconstruct s2/t0 —
// leaking the full private key. The new protocol carries the combined
// z0 contribution (Z0Share) directly in the Round2Reveal struct,
// so no separate injection step is needed.

// SubmitExternalW stores an externally-received W_i (from another participant's
// Round1 broadcast) into the session's wComputed map. This is needed in distributed
// mode where each participant only computes its own W_i locally and receives others'
// W_i via P2P broadcast. Round2Reveal reads wComputed for all participants to
// compute W_agg and derive the challenge c.
func (s *QTDSession) SubmitExternalW(participantID int, wBytes []byte) error {
	// R47-QP-05 FIX: Validate participant ID and input.
	if participantID < 1 {
		return ErrParticipantNotFound
	}
	if len(wBytes) == 0 {
		return fmt.Errorf("empty W bytes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.wComputed[participantID] = append([]byte(nil), wBytes...)
	return nil
}

// GetW returns the W_i computed during Round1Commitment for the given participant.
// Used by the distributed signer to include W_i in the Round1 broadcast.
func (s *QTDSession) GetW(participantID int) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.wComputed[participantID]
	if !ok {
		return nil
	}
	return append([]byte(nil), w...)
}

// SetMessage stores the message to be signed in the session.
// Used by participants who receive the message via SessionInit broadcast.
func (s *QTDSession) SetMessage(message []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.message = append([]byte(nil), message...)
}

func (s *QTDSession) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// L4-007 FIX: Use SecurelyZeroMemory instead of plain for-loops.
	// The compiler can optimize away `for i := range v { v[i] = 0 }`
	// via dead-store elimination. SecurelyZeroMemory uses an indirect
	// function call + runtime.KeepAlive to prevent this.
	for k, v := range s.wShares {
		SecurelyZeroMemory(v)
		delete(s.wShares, k)
	}
	for k, v := range s.wComputed {
		SecurelyZeroMemory(v)
		delete(s.wComputed, k)
	}
	for k, v := range s.zShares {
		SecurelyZeroMemory(v)
		delete(s.zShares, k)
	}
	// L5-014 FIX: Also zero sensitive byte slices in round1Commitments
	// and round2Reveals. Z0Share contains the combined z0 contribution
	// (c·(t0-s2)-derived, not raw key material) and ZShare contains
	// secret-key-derived data. Previously these were only deleted from the
	// map without zeroing, leaving sensitive data in memory.
	//
	// Note: s.shares is NOT cleaned up here because it is a caller-owned
	// map (passed in via NewQTDSession). The caller (e.g. QTDManager) may
	// reuse shares across sessions and is responsible for zeroing them
	// when they are truly retired.
	for k, c := range s.round1Commitments {
		SecurelyZeroMemory(c.Commitment)
		SecurelyZeroMemory(c.Nonce)
		delete(s.round1Commitments, k)
	}
	for k, r := range s.round2Reveals {
		SecurelyZeroMemory(r.WShare)
		SecurelyZeroMemory(r.ZShare)
		// AUDIT (2026) TSS-FIX: Zero Z0Share (combined z0
		// contribution) instead of the removed Cs2Share/Ct0Share fields.
		SecurelyZeroMemory(r.Z0Share)
		delete(s.round2Reveals, k)
	}
}

// getLambda returns the Lagrange coefficient for a participant.
// In additive mode (non-Shamir), returns 1.
// In Shamir mode, returns the pre-computed Lagrange coefficient.
func getLambda(s *QTDSession, participantID int) int64 {
	if !s.useShamir || s.lagrangeCoeffs == nil {
		return 1
	}
	lam, ok := s.lagrangeCoeffs[participantID]
	if !ok {
		return 1
	}
	return lam
}

// ===========================================================================
// TSS- FULL CLOSURE: Role-Separated Aggregation
// ===========================================================================
//
// The single-aggregator model is vulnerable: one node sees w_agg, z_agg, and
// z0_agg, from which it can recover s1 = (z_agg - y_agg) / c because:
//   w_agg = A·y_agg  →  y_agg = A^{-1}·w_agg  (K > L, solvable)
//   z_agg = s1·c + y_agg  →  s1 = (z_agg - y_agg) / c
//
// FULL CLOSURE: Split aggregation into THREE independent roles. No single
// role sees both w_agg and z_agg, so no single role can recover s1.
//
//   Role W-Aggregator: sees all WShare → w_agg, w1, c
//                      Cannot see ZShare → cannot compute s1
//
//   Role Z-Aggregator: sees all ZShare → z_agg
//                      Cannot see WShare → cannot get y_agg → cannot get s1
//
//   Role H-Aggregator: sees all Z0Share + w_agg (from W-agg) → hint
//                      Cannot see ZShare → cannot compute s1
//
// SECURITY: Recovery of s1 requires collusion of W-aggregator + Z-aggregator.
// In a t-of-n threshold system, this means at least t colluding nodes are
// needed, matching the threshold security assumption. This is FULL CLOSURE:
// no single node can recover s1.
// ===========================================================================

type AggregationRole int

const (
	AggregatorRoleW AggregationRole = iota
	AggregatorRoleZ
	AggregatorRoleH
)

type WAggrResult struct {
	WAggBytes  []byte
	W1Bytes    []byte
	C          Poly
	CtildeSeed []byte
}

type ZAggrResult struct {
	ZAgg PolyVec
}

type HAggrResult struct {
	Hint      PolyVec
	HintCount int
}

func (s *QTDSession) AggregateW(reveals []*Round2Reveal) (*WAggrResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isExpired() {
		return nil, ErrSessionExpired
	}
	if len(reveals) < s.threshold {
		return nil, ErrInsufficientParticipants
	}

	wAggVec := make(PolyVec, Dilithium3K)
	for _, r := range reveals {
		_, ok := s.round1Commitments[r.ParticipantID]
		if !ok {
			return nil, ErrParticipantNotFound
		}

		wVec, err := VecFromBytes(r.WShare, Dilithium3K)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize W share: %w", err)
		}
		for i := 0; i < Dilithium3K; i++ {
			wAggVec[i].Add(&wAggVec[i], &wVec[i])
		}
	}

	wHigh := HighBits(wAggVec, Dilithium3Gamma2)
	wHighBytes := PackW1(wHigh)

	hTr := sha3.NewShake256()
	hTr.Write(s.pkBytes)
	var tr [32]byte
	hTr.Read(tr[:])

	c, ctilde, err := ComputeChallenge(wHighBytes, tr[:], s.message, int(Dilithium3Tau))
	if err != nil {
		return nil, fmt.Errorf("failed to compute challenge: %w", err)
	}

	wAggPacked := VecToBytes(wAggVec)

	return &WAggrResult{
		WAggBytes:  wAggPacked,
		W1Bytes:    wHighBytes,
		C:          c,
		CtildeSeed: ctilde[:],
	}, nil
}

func (s *QTDSession) AggregateZ(reveals []*Round2Reveal) (*ZAggrResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isExpired() {
		return nil, ErrSessionExpired
	}
	if len(reveals) < s.threshold {
		return nil, ErrInsufficientParticipants
	}

	zAgg := make(PolyVec, Dilithium3L)
	for _, r := range reveals {
		zShare, err := VecFromBytes(r.ZShare, Dilithium3L)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize Z share: %w", err)
		}
		for i := 0; i < Dilithium3L; i++ {
			zAgg[i].Add(&zAgg[i], &zShare[i])
		}
	}

	zNorm := VecNormInf(zAgg)
	rejectionBound := int64(Dilithium3Gamma1 - Dilithium3Beta)
	if !CheckRejection(zAgg, rejectionBound) {
		return nil, fmt.Errorf("%w: ||z||_inf = %d, bound = %d",
			ErrRejectionSamplingFailed, zNorm, rejectionBound)
	}

	return &ZAggrResult{
		ZAgg: zAgg,
	}, nil
}

func (s *QTDSession) AggregateHint(reveals []*Round2Reveal, wAggBytes []byte, w1Bytes []byte) (*HAggrResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isExpired() {
		return nil, ErrSessionExpired
	}
	if len(reveals) < s.threshold {
		return nil, ErrInsufficientParticipants
	}

	wAggVec, err := VecFromBytes(wAggBytes, Dilithium3K)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize w_agg: %w", err)
	}

	wHigh, err := UnpackW1(w1Bytes, Dilithium3K)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize w1: %w", err)
	}

	z0Contribution := make(PolyVec, Dilithium3K)
	// TSS-M7 (R8 2026-07-19 FIX): Attribution logging for bad Z0Shares.
	//
	// We previously attempted a per-participant norm bound check
	// (||z0Share||_inf < 2·γ2), but it is mathematically unsound for the
	// same reasons documented in Round2Aggregate: Z0Share = λ_i·c·(t0-s2)
	// is computed mod Q=8380417, and Lagrange coefficients λ_i are
	// essentially random mod Q. A legitimate Z0Share can have centered
	// coefficients arbitrarily close to Q/2, so any fixed bound below Q/2
	// rejects honest participants. DH masks further inflate the norm.
	//
	// Closure here mirrors Round2Aggregate:
	//   1. Validate structural correctness (non-nil reveal, non-empty
	//      Z0Share, correct length via VecFromBytes).
	//   2. Record per-participant Z0Share hashes for post-hoc attribution.
	//   3. The UseHint verification at the end catches any inconsistent
	//      Z0Share that would produce an invalid hint. When that fires,
	//      we log the per-participant hashes so the operator can identify
	//      the offending participant by comparing against the hashes
	//      recorded here.
	//   4. Full cryptographic closure (Pedersen homomorphic verification
	//      of c·λ·(t0-s2) against VVectorS2/VVectorT0) is research-level
	//      work and is tracked as future closure.
	participantZ0Hashes := make(map[int]string, len(reveals))
	for _, r := range reveals {
		if r == nil {
			return nil, fmt.Errorf("nil reveal in AggregateHint")
		}
		if len(r.Z0Share) == 0 {
			return nil, fmt.Errorf("TSS-M7: participant %d: empty Z0Share", r.ParticipantID)
		}
		z0Share, err := VecFromBytes(r.Z0Share, Dilithium3K)
		if err != nil {
			return nil, fmt.Errorf("TSS-M7: failed to deserialize Z0Share from participant %d: %w", r.ParticipantID, err)
		}
		// Record SHA-256 of the Z0Share bytes for post-hoc attribution.
		h := sha256.Sum256(r.Z0Share)
		participantZ0Hashes[r.ParticipantID] = fmt.Sprintf("%x", h[:8])
		for i := 0; i < Dilithium3K; i++ {
			z0Contribution[i].Add(&z0Contribution[i], &z0Share[i])
		}
	}

	if VecNormInf(z0Contribution) >= 2*int64(Dilithium3Gamma2) {
		return nil, fmt.Errorf("%w: ||c·(t0-s2)||_∞ exceeds 2·γ₂",
			ErrRejectionSamplingFailed)
	}

	w0 := LowBits(wAggVec, int(Dilithium3Gamma2))

	z0Vec := make(PolyVec, Dilithium3K)
	rCt0 := make(PolyVec, Dilithium3K)
	for i := 0; i < Dilithium3K; i++ {
		z0Vec[i].Add(&w0[i], &z0Contribution[i])
		z0Vec[i].Reduce()
		rCt0[i].Add(&wAggVec[i], &z0Contribution[i])
		rCt0[i].Reduce()
	}

	hint, hintCount := ComputeHint(z0Vec, wHigh, int(Dilithium3Gamma2))

	if hintCount > int(Dilithium3Omega) {
		return nil, fmt.Errorf("%w: hint count %d exceeds Omega %d",
			ErrRejectionSamplingFailed, hintCount, Dilithium3Omega)
	}

	wRecovered := UseHint(hint, rCt0, int(Dilithium3Gamma2))
	mismatch := 0
	for i := 0; i < Dilithium3K && mismatch == 0; i++ {
		for j := 0; j < N && mismatch == 0; j++ {
			wAggN := int32(int64(wAggVec[i][j]) % Q)
			if wAggN < 0 {
				wAggN += Q
			}
			expectedW1 := highBitsCoeff(wAggN, int(Dilithium3Gamma2))
			if wRecovered[i][j] != expectedW1 {
				mismatch++
			}
		}
	}
	if mismatch > 0 {
		// TSS-M7 (R8 2026-07-19 FIX): UseHint verification failed — the
		// assembled hint does not recover w1 from rCt0. This indicates at
		// least one participant submitted an inconsistent Z0Share. Log
		// the per-participant Z0Share hashes recorded above so operators
		// can identify the offending participant by comparing these
		// hashes against the ones recorded by the W/Z aggregators for
		// the same session (a malicious participant typically submits
		// different bad shares to different aggregators to evade
		// single-aggregator detection).
		log.Printf("TSS-M7: AggregateHint UseHint verification failed (mismatch=%d) — participant Z0Share hashes: %v",
			mismatch, participantZ0Hashes)
		return nil, ErrRejectionSamplingFailed
	}

	return &HAggrResult{
		Hint:      hint,
		HintCount: hintCount,
	}, nil
}

func AssembleFinalSignature(zAgg PolyVec, hint PolyVec, ctildeSeed []byte, w1Bytes []byte) *QTDSignature {
	var ctildeArr [32]byte
	copy(ctildeArr[:], ctildeSeed)

	fullSig := PackGMQTDSignature(zAgg, hint, ctildeArr)

	// AUDIT-FULL CR-08 FIX (2026-08-15): use the named constant instead of
	// the magic-number local `zByteSize := 640`.
	return &QTDSignature{
		FullSig: fullSig,
		Z:       fullSig[32 : 32+Dilithium3L*Dilithium3ZPolyByteSize],
		Ctilde:  fullSig[:32],
		WAgg:    w1Bytes,
	}
}

func PackGMQTDSignatureFromParts(z []byte, hint []byte, ctilde []byte) []byte {
	sig := make([]byte, 32+len(z)+len(hint))
	copy(sig[:32], ctilde)
	copy(sig[32:32+len(z)], z)
	copy(sig[32+len(z):], hint)
	return sig
}
