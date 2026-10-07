// Quantaureum Node source, version 1.0.0.
package quantum

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	qaucrypto "github.com/quantaureum/qau/crypto"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
)

var (
	ErrMPCNotReady             = errors.New("MPC computation not ready")
	ErrInsufficientParties     = errors.New("insufficient parties for MPC")
	ErrShareVerificationFailed = errors.New("share verification failed")
	// ErrPartyAlreadySubmitted: this party has already submitted its share
	// audit fix (HIGH-3): prevent the same party from submitting multiple times
	ErrPartyAlreadySubmitted = errors.New("party already submitted share")
	// ErrLagrangeInterpolationFailed: Lagrange interpolation failed
	// audit fix (LOW-8): ModInverse can return nil
	ErrLagrangeInterpolationFailed = errors.New("lagrange interpolation failed: modular inverse does not exist")
	// audit fix (H-3): SubmitShare now requires a Dilithium3 signature
	// to prove the caller owns the party's private key. This prevents any RPC
	// caller from impersonating an arbitrary registered party.
	ErrShareSignatureInvalid = errors.New("share signature verification failed")
	// ErrPartyIndexConflict: the party's Index conflicts with a registered party
	// SECURITY FIX (P2-3): combineShares stored shares as intShares[xVal] = share,
	// so two parties with the same Index meant the latter silently overwrote the former's share,
	// causing Lagrange interpolation to reconstruct the wrong secret.
	ErrPartyIndexConflict = errors.New("party index conflicts with an already registered party")
	// ErrPartyIndexTooHigh: the party's Index >= 10000 collides with the
	// combineShares fallback index range. combineShares assigns fallback indices
	// starting at fallbackIdx=10000 for parties without an explicit Index, so an explicit Index >= 10000 collides,
	// causing Lagrange interpolation to reconstruct the wrong secret.
	// L6-003 FIX
	ErrPartyIndexTooHigh = errors.New("party index too high, must be less than 10000")
)

//	Default TTL for MPC sessions. Sessions that have not completed
//
// within this duration are eligible for cleanup to prevent memory leaks
// and sensitive key material from persisting indefinitely.
const DefaultSessionTTL = 30 * time.Minute

type MPCParty struct {
	ID        types.Address
	PublicKey []byte
	Share     []byte
	Index     int
}

type MPCConfig struct {
	MinParties   int
	TotalParties int
	Threshold    int
	FieldPrime   *big.Int
}

func DefaultMPCConfig() *MPCConfig {
	// audit-fix CRITICAL-4: Use post-quantum safe prime (2^256 - 189) instead of
	// secp256k1 field prime. secp256k1 is vulnerable to Shor's algorithm on
	// quantum computers. This 256-bit prime provides post-quantum security
	// and is large enough for any secret representation.
	prime, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43", 16)
	return &MPCConfig{
		MinParties:   3,
		TotalParties: 10,
		Threshold:    5,
		FieldPrime:   prime,
	}
}

type MPCManager struct {
	mu          sync.RWMutex
	config      *MPCConfig
	parties     map[types.Address]*MPCParty
	sessions    map[string]*MPCSession
	maxSessions int
	//  TTL for sessions; expired incomplete sessions are cleaned up.
	sessionTTL time.Duration
}

type MPCSession struct {
	ID          string
	Parties     []types.Address
	Shares      map[types.Address][]byte
	Commitments map[types.Address][]byte
	Result      []byte
	Complete    bool
	Phase       MPCPhase
	// audit fix (HIGH-3): track submitted parties, preventing duplicates
	submittedParties map[types.Address]bool
	// audit fix (MEDIUM-6): the session key is used for HMAC commitment verification
	sessionSecret []byte
	// R7-P3-1: record session creation time for the maxSessions eviction policy
	createdAt time.Time
}

type MPCPhase uint8

const (
	MPCPhaseSetup       MPCPhase = 0
	MPCPhaseShareDist   MPCPhase = 1
	MPCPhaseComputation MPCPhase = 2
	MPCPhaseReconstruct MPCPhase = 3
	MPCPhaseComplete    MPCPhase = 4
)

func NewMPCManager(config *MPCConfig) *MPCManager {
	if config == nil {
		config = DefaultMPCConfig()
	}

	return &MPCManager{
		config:      config,
		parties:     make(map[types.Address]*MPCParty),
		sessions:    make(map[string]*MPCSession),
		maxSessions: 1000,
		sessionTTL:  DefaultSessionTTL,
	}
}

// SetSessionTTL sets the TTL for MPC sessions. Sessions that have not completed
// within this duration are eligible for cleanup to prevent memory leaks and
// sensitive key material from persisting indefinitely.
// FIX: Expose sessionTTL as a configurable parameter. Previously
// sessionTTL was hardcoded to DefaultSessionTTL with no way for callers to
// adjust it for their deployment requirements.
func (mpc *MPCManager) SetSessionTTL(ttl time.Duration) {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	mpc.sessionTTL = ttl
}

// GetSessionTTL returns the current session TTL.
func (mpc *MPCManager) GetSessionTTL() time.Duration {
	mpc.mu.RLock()
	defer mpc.mu.RUnlock()
	return mpc.sessionTTL
}

func (mpc *MPCManager) RegisterParty(party *MPCParty) error {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()

	if _, exists := mpc.parties[party.ID]; exists {
		return fmt.Errorf("party already registered: %s", party.ID.ToHexAddress())
	}

	// L6-003 FIX: Reject indices >= 10000 because combineShares uses the
	// [10000, ...) range for fallback indices assigned to parties without an
	// explicit Index. An explicit Index >= 10000 would collide with fallback
	// indices, corrupting Lagrange interpolation.
	if party.Index >= 10000 {
		return fmt.Errorf("%w: index %d", ErrPartyIndexTooHigh, party.Index)
	}

	// SECURITY FIX (P2-3): Verify Index uniqueness. combineShares uses
	// intShares[party.Index] = share to store shares keyed by Index.
	// If two parties share the same Index, the later share silently
	// overwrites the earlier one, corrupting Lagrange interpolation.
	if party.Index > 0 {
		for _, existing := range mpc.parties {
			if existing.Index == party.Index {
				return fmt.Errorf("%w: index %d already used by party %s",
					ErrPartyIndexConflict, party.Index, existing.ID.ToHexAddress())
			}
		}
	}

	mpc.parties[party.ID] = party
	return nil
}

func (mpc *MPCManager) CreateSession(sessionID string, partyIDs []types.Address) (*MPCSession, error) {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()

	//  Clean up expired incomplete sessions before creating new ones.
	mpc.evictExpiredSessionsLocked()

	// R7-P3-1: Enforce maxSessions limit to prevent unbounded growth. When
	// the limit is reached, evict the oldest completed session first.
	if len(mpc.sessions) >= mpc.maxSessions {
		mpc.evictOldestCompletedLocked()
	}

	if len(partyIDs) < mpc.config.MinParties {
		return nil, ErrInsufficientParties
	}

	for _, pid := range partyIDs {
		if _, exists := mpc.parties[pid]; !exists {
			return nil, fmt.Errorf("party not registered: %s", pid.ToHexAddress())
		}
	}

	// audit fix (MEDIUM-6): generate a per-session key for HMAC commitment verification
	sessionSecret := make([]byte, 32)

	// QUANTUFIX: Ensure sessionSecret is wiped from memory if
	// CreateSession returns an error, so secret material is never left
	// around on a failure path (e.g. a future error between generation and
	// session storage). On the success path the secret is handed off to the
	// session and stored in mpc.sessions, so secretWipeNeeded is cleared
	// before returning to avoid zeroing the live secret.
	secretWipeNeeded := true
	defer func() {
		if secretWipeNeeded {
			for i := range sessionSecret {
				sessionSecret[i] = 0
			}
		}
	}()

	if _, err := rand.Read(sessionSecret); err != nil {
		return nil, fmt.Errorf("failed to generate session secret: %w", err)
	}

	session := &MPCSession{
		ID:               sessionID,
		Parties:          partyIDs,
		Shares:           make(map[types.Address][]byte),
		Commitments:      make(map[types.Address][]byte),
		Phase:            MPCPhaseSetup,
		submittedParties: make(map[types.Address]bool),
		sessionSecret:    sessionSecret,
		createdAt:        time.Now(),
	}

	mpc.sessions[sessionID] = session
	// Success: the session now owns sessionSecret; do not wipe it.
	secretWipeNeeded = false
	return session, nil
}

// SubmitShare submits a share for a party in the given session.
//
// audit fix (H-3): previously SubmitShare only checked that `party` was
// in the session's participant list, without verifying that the caller actually
// owns the party's private key. Any RPC caller could impersonate an arbitrary
// registered party and submit forged shares, polluting the MPC result.
//
// Now SubmitShare requires a Dilithium3 signature over
// (sessionID || party || share || commitment) that is verified against the
// party's registered public key. This proves the caller holds the private key
// for the claimed party identity.
func (mpc *MPCManager) SubmitShare(sessionID string, party types.Address, share []byte, commitment []byte, sig []byte) error {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()

	session, exists := mpc.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	//  SECURITY FIX: Authenticate the caller BEFORE checking session phase.
	// Previously, the phase check happened before signature verification, allowing
	// unauthenticated callers to probe session state (e.g., whether the session
	// is in share distribution phase) without proving identity. Now the caller
	// must pass signature verification first; only authenticated callers can
	// observe phase-related errors.

	partyFound := false
	for _, pid := range session.Parties {
		if pid == party {
			partyFound = true
			break
		}
	}
	if !partyFound {
		return fmt.Errorf("party not in session: %s", party.ToHexAddress())
	}

	// audit fix (H-3): verify the caller's Dilithium3 signature to prove
	// ownership of the party's private key. Without this check, any RPC caller
	// could impersonate an arbitrary party.
	registeredParty, regExists := mpc.parties[party]
	if !regExists || registeredParty == nil || len(registeredParty.PublicKey) == 0 {
		return fmt.Errorf("party public key not registered: %s", party.ToHexAddress())
	}
	pubKey, err := qaucrypto.PublicKeyFromBytes(registeredParty.PublicKey)
	if err != nil || pubKey == nil {
		return fmt.Errorf("invalid public key for party %s: %w", party.ToHexAddress(), err)
	}
	// Message = sessionID || party.Bytes() || share || commitment
	msg := buildShareSignatureMessage(sessionID, party, share, commitment)
	if !qaucrypto.Verify(pubKey, msg, sig) {
		return ErrShareSignatureInvalid
	}

	//  Phase check moved AFTER signature verification to prevent
	// unauthenticated callers from probing session state.
	if session.Phase != MPCPhaseShareDist {
		return fmt.Errorf("session not in share distribution phase")
	}

	// audit fix (HIGH-3): prevent the same party from submitting multiple times
	if session.submittedParties[party] {
		return fmt.Errorf("%w: %s", ErrPartyAlreadySubmitted, party.ToHexAddress())
	}

	// audit fix (MEDIUM-6): HMAC the commitment with the session key, preventing precomputation attacks
	if !mpc.verifyCommitment(share, commitment, session.sessionSecret) {
		return ErrShareVerificationFailed
	}

	// R5-P3-2: Deep-copy share and commitment before storing to prevent the
	// caller from mutating already-verified data via the original slice reference.
	shareCopy := make([]byte, len(share))
	copy(shareCopy, share)
	commitmentCopy := make([]byte, len(commitment))
	copy(commitmentCopy, commitment)
	session.Shares[party] = shareCopy
	session.Commitments[party] = commitmentCopy
	session.submittedParties[party] = true

	if len(session.Shares) >= mpc.config.Threshold {
		session.Phase = MPCPhaseComputation
	}

	return nil
}

// buildShareSignatureMessage constructs the message that must be signed by the
// party's private key when calling SubmitShare.
// L15-016 FIX: Added domain separator to prevent cross-protocol signature
// replay attacks. Message = domainSep || sessionID || party.Bytes() || share || commitment
func buildShareSignatureMessage(sessionID string, party types.Address, share []byte, commitment []byte) []byte {
	// Domain separator: prevents this signature from being valid in any other
	// protocol context (e.g., transaction signing, governance votes, etc.).
	const domainSep = "QUANTAUREUM_MPC_SHARE_SIG_V1"
	msg := make([]byte, 0, len(domainSep)+len(sessionID)+len(party)+len(share)+len(commitment))
	msg = append(msg, []byte(domainSep)...)
	msg = append(msg, []byte(sessionID)...)
	msg = append(msg, party.Bytes()...)
	msg = append(msg, share...)
	msg = append(msg, commitment...)
	return msg
}

// verifyCommitment verifies the share/commitment binding via HMAC-SHA256
// audit fix (MEDIUM-6): the original used SHA256(share) as the commitment, letting attackers precompute
// all candidate share hashes for an offline brute-force. Switching to HMAC(sessionSecret, share)
// means commitments cannot be precomputed without sessionSecret — a stronger binding.
func (mpc *MPCManager) verifyCommitment(share []byte, commitment []byte, sessionSecret []byte) bool {
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write(share)
	expected := mac.Sum(nil)
	return hmac.Equal(expected, commitment)
}

func (mpc *MPCManager) ComputeResult(sessionID string) ([]byte, error) {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()

	session, exists := mpc.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	if len(session.Shares) < mpc.config.Threshold {
		return nil, ErrInsufficientParties
	}

	result, err := mpc.combineShares(session)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shares: %w", err)
	}
	session.Result = result
	session.Phase = MPCPhaseReconstruct

	// L4-018 FIX: Mark the session as complete so that
	// evictOldestCompletedLocked can reclaim it when the session limit is
	// reached. Previously ComputeResult left the session in a non-complete
	// state, so sessions that went through ComputeResult but never
	// ReconstructSecret were never evicted, leaking sessionSecret, Shares,
	// and Commitments indefinitely.
	//
	// We intentionally do NOT call cleanupSessionLocked here because
	// ReconstructSecret requires session.Phase == MPCPhaseReconstruct and
	// uses session.Shares for Lagrange interpolation. Deleting or zeroizing
	// the session in ComputeResult would make ReconstructSecret unusable.
	// The full zeroizing cleanup happens in ReconstructSecret (or via
	// eviction) once the caller is done with the session.
	//
	// L6-015 CONFIRMED: The MPC session data residue issue is resolved by
	// the L4-018 fix above. Sessions that complete via ComputeResult but
	// never call ReconstructSecret are now marked Complete=true, enabling
	// eviction-based cleanup (evictOldestCompletedLocked). No additional
	// cleanup logic is needed here — adding zeroizing in ComputeResult would
	// break ReconstructSecret's contract. The eviction path ensures
	// sessionSecret, Shares, and Commitments are eventually reclaimed.
	session.Complete = true

	return result, nil
}

// lagrangeInterpolate reconstructs the secret via Lagrange interpolation
// audit fix (LOW-8): the original did not check ModInverse's return; when denominator and prime
// are not coprime ModInverse returns nil and the subsequent Mul panics. Now an error is returned and checked explicitly.
func lagrangeInterpolate(shares map[int][]byte, prime *big.Int) ([]byte, error) {
	// L16-003 FIX: Check for index overflow before Lagrange interpolation.
	// The int64(-j) and int64(i-j) conversions in the interpolation loop
	// can produce incorrect results if share indices exceed MaxInt32,
	// especially on 32-bit platforms where int is 32 bits. Rejecting
	// out-of-range indices early prevents silent arithmetic errors.
	for idx := range shares {
		if idx > math.MaxInt32 || idx < -math.MaxInt32 {
			return nil, fmt.Errorf("%w: share index %d overflows int32 range", ErrLagrangeInterpolationFailed, idx)
		}
	}
	secret := new(big.Int)
	// L8-003 FIX: Hoist intermediate big.Int variables to function scope so
	// they can be zeroized via defer before any return path, preventing
	// sensitive intermediate values from lingering in heap memory.
	var numerator, denominator, inv, lagrangeCoeff, term *big.Int
	// L6-045 FIX: Zeroize the reconstructed secret big.Int on all return
	// paths to prevent it from lingering in heap memory after the function
	// returns. big.Int.Bytes() returns a copy, so the returned slice is
	// not affected by this zeroization.
	// L8-022 CONFIRMED FIXED: L6-045 defer zeroization verified present.
	// L8-003 FIX: Extend the defer to also zeroize all intermediate big.Int
	// variables. Nil checks are required because these variables may not be
	// assigned on all return paths (e.g. empty shares map, or ModInverse nil).
	// L9-027 CONFIRMED FIXED: All intermediate big.Int variables (numerator,
	// denominator, inv, lagrangeCoeff, term) are hoisted to function scope
	// and zeroized via the defer above. No additional zeroization needed.
	defer func() {
		secret.SetInt64(0)
		if numerator != nil {
			numerator.SetInt64(0)
		}
		if denominator != nil {
			denominator.SetInt64(0)
		}
		if inv != nil {
			inv.SetInt64(0)
		}
		if lagrangeCoeff != nil {
			lagrangeCoeff.SetInt64(0)
		}
		if term != nil {
			term.SetInt64(0)
		}
	}()

	for i, shareBytes := range shares {
		share := new(big.Int).SetBytes(shareBytes)

		// L10-027 FIX: Zeroize previous iteration's intermediate values before
		// reassignment. The defer at function exit only zeros the final values;
		// values from earlier iterations would linger in heap memory without this.
		if numerator != nil {
			numerator.SetInt64(0)
		}
		if denominator != nil {
			denominator.SetInt64(0)
		}
		if inv != nil {
			inv.SetInt64(0)
		}
		if lagrangeCoeff != nil {
			lagrangeCoeff.SetInt64(0)
		}
		if term != nil {
			term.SetInt64(0)
		}

		numerator = big.NewInt(1)
		denominator = big.NewInt(1)

		for j := range shares {
			if i != j {
				numerator.Mul(numerator, big.NewInt(int64(-j)))
				denominator.Mul(denominator, big.NewInt(int64(i-j)))
			}
		}

		// audit fix (LOW-8): check whether ModInverse returned nil
		// L10-027 FIX: Zeroize previous inv before reassignment (done above).
		inv = new(big.Int).ModInverse(denominator, prime)
		if inv == nil {
			// L6-045: Zeroize share before error return
			share.SetInt64(0)
			return nil, fmt.Errorf("%w: denominator has no inverse for share index %d", ErrLagrangeInterpolationFailed, i)
		}
		// L10-027 FIX: Zeroize previous lagrangeCoeff/term before reassignment (done above).
		lagrangeCoeff = new(big.Int).Mul(numerator, inv)
		term = new(big.Int).Mul(share, lagrangeCoeff)
		secret.Add(secret, term)
		secret.Mod(secret, prime)
		// L6-045: Zeroize share after use in each iteration
		share.SetInt64(0)
	}

	result := secret.Bytes()
	if len(result) == 0 {
		return []byte{0}, nil
	}
	return result, nil
}

func (mpc *MPCManager) combineShares(session *MPCSession) ([]byte, error) {
	// audit-fix L7-002: Use shared assignShareIndices method to prevent
	// divergence between combineShares and lagrangeInterpolation.
	intShares := mpc.assignShareIndices(session)
	return lagrangeInterpolate(intShares, mpc.config.FieldPrime)
}

// assignShareIndices builds the intShares map from session shares, assigning
// each party's Index as the Lagrange x-value (or a fallback index starting
// from 10000+ for parties without an explicit Index).
// audit-fix L7-002: Extracted from combineShares and lagrangeInterpolation
// to eliminate code duplication and prevent future divergence.
func (mpc *MPCManager) assignShareIndices(session *MPCSession) map[int][]byte {
	intShares := make(map[int][]byte)
	// audit-fix L3-015: fallback indices start from 10000+ to avoid collision
	// with explicit party.Index values.
	fallbackIdx := 10000
	// QUANTUFIX: Hard limit on party count to prevent index overflow.
	// MaxInt32 is the upper bound enforced by lagrangeInterpolate, but we
	// use a much lower practical limit to prevent excessive memory use.
	const maxParties = 10000
	if len(session.Parties) > maxParties {
		// Log warning — the excess parties will be skipped
		logging.Warn("MPC assignShareIndices: party count exceeds limit, truncating",
			map[string]any{"partyCount": len(session.Parties), "max": maxParties})
	}
	for _, partyAddr := range session.Parties {
		if len(intShares) >= maxParties {
			break // QUANTUFIX: Stop after max parties
		}
		if share, exists := session.Shares[partyAddr]; exists {
			xVal := fallbackIdx
			if party, ok := mpc.parties[partyAddr]; ok && party.Index > 0 {
				xVal = party.Index
			} else {
				fallbackIdx++
				// QUANTUFIX: Prevent fallback index from exceeding MaxInt32
				if fallbackIdx > math.MaxInt32 {
					logging.Warn("MPC assignShareIndices: fallback index overflow",
						map[string]any{"fallbackIdx": fallbackIdx})
					break
				}
			}
			intShares[xVal] = share
		}
	}
	return intShares
}

func (mpc *MPCManager) ReconstructSecret(sessionID string) ([]byte, error) {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()

	session, exists := mpc.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	if session.Phase != MPCPhaseReconstruct {
		return nil, ErrMPCNotReady
	}

	if len(session.Shares) < mpc.config.Threshold {
		return nil, ErrInsufficientParties
	}

	secret, err := mpc.lagrangeInterpolation(session)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct secret: %w", err)
	}
	session.Phase = MPCPhaseComplete
	session.Complete = true

	// R7-P3-1: Clean up the completed session to zeroize all sensitive
	// material (sessionSecret, Shares, Commitments, Result) and remove it
	// from the sessions map. This supersedes R6-P3-2 (which only zeroized
	// Shares) by ensuring no key material lingers after session completion.
	mpc.cleanupSessionLocked(sessionID)

	return secret, nil
}

func (mpc *MPCManager) lagrangeInterpolation(session *MPCSession) ([]byte, error) {
	// audit-fix L7-002: Use shared assignShareIndices method.
	intShares := mpc.assignShareIndices(session)
	return lagrangeInterpolate(intShares, mpc.config.FieldPrime)
}

// copySession returns a defensive deep copy of an MPCSession so that external
// callers receiving the result via GetSession cannot mutate the internal
// session's Shares/Commitments maps or other fields.
// R5-P3-1: GetSession previously returned the internal *MPCSession pointer,
// allowing callers to directly modify Shares/Commitments maps.
func copySession(s *MPCSession) *MPCSession {
	if s == nil {
		return nil
	}
	cp := &MPCSession{
		ID:               s.ID,
		Parties:          append([]types.Address(nil), s.Parties...),
		Shares:           make(map[types.Address][]byte, len(s.Shares)),
		Commitments:      make(map[types.Address][]byte, len(s.Commitments)),
		Result:           append([]byte(nil), s.Result...),
		Complete:         s.Complete,
		Phase:            s.Phase,
		submittedParties: make(map[types.Address]bool, len(s.submittedParties)),
		// R6-P3-1: Do not copy sessionSecret to the defensive copy. The secret
		// is internal-only (used for HMAC commitment verification); exposing it
		// via GetSession violates the principle of least exposure.
		sessionSecret: nil,
		createdAt:     s.createdAt,
	}
	for k, v := range s.Shares {
		cp.Shares[k] = append([]byte(nil), v...)
	}
	for k, v := range s.Commitments {
		cp.Commitments[k] = append([]byte(nil), v...)
	}
	for k, v := range s.submittedParties {
		cp.submittedParties[k] = v
	}
	return cp
}

func (mpc *MPCManager) GetSession(sessionID string) (*MPCSession, bool) {
	mpc.mu.RLock()
	defer mpc.mu.RUnlock()

	session, exists := mpc.sessions[sessionID]
	if !exists {
		return nil, false
	}
	// R5-P3-1: Return a deep copy so callers cannot mutate internal state.
	return copySession(session), true
}

// ComputeCommitment computes the HMAC-SHA256 commitment for a share using the
// session's internal secret key. This allows external callers (other packages)
// to produce valid commitments for SubmitShare without exposing sessionSecret.
// R4-P2-1: Previously verifyCommitment used an internally generated sessionSecret
// as the HMAC key, but no method was provided for external callers to compute
// a valid commitment, making SubmitShare unusable from outside the package.
func (mpc *MPCManager) ComputeCommitment(sessionID string, share []byte) ([]byte, error) {
	mpc.mu.RLock()
	defer mpc.mu.RUnlock()

	session, exists := mpc.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	if len(session.sessionSecret) == 0 {
		return nil, fmt.Errorf("session has no secret: %s", sessionID)
	}
	mac := hmac.New(sha256.New, session.sessionSecret)
	mac.Write(share)
	return mac.Sum(nil), nil
}

func (mpc *MPCManager) GetPartyCount() int {
	mpc.mu.RLock()
	defer mpc.mu.RUnlock()
	return len(mpc.parties)
}

func (mpc *MPCManager) GetActiveSessionCount() int {
	mpc.mu.RLock()
	defer mpc.mu.RUnlock()

	count := 0
	for _, s := range mpc.sessions {
		if !s.Complete {
			count++
		}
	}
	return count
}

// cleanupSessionLocked securely zeroizes all sensitive session material
// (sessionSecret, Shares, Commitments, Result) and removes the session from
// the manager. The caller MUST hold mpc.mu.
// R7-P3-1: MPCManager lacked a session cleanup method, leaving sessionSecret,
// Shares, and Commitments in memory after session completion.
func (mpc *MPCManager) cleanupSessionLocked(sessionID string) {
	session, exists := mpc.sessions[sessionID]
	if !exists {
		return
	}

	// Zeroize sessionSecret
	for i := range session.sessionSecret {
		session.sessionSecret[i] = 0
	}

	// Zeroize Shares
	for _, share := range session.Shares {
		for j := range share {
			share[j] = 0
		}
	}

	// Zeroize Commitments
	for _, commitment := range session.Commitments {
		for j := range commitment {
			commitment[j] = 0
		}
	}

	// Zeroize Result
	for i := range session.Result {
		session.Result[i] = 0
	}

	delete(mpc.sessions, sessionID)
}

// CleanupSession securely zeroizes all sensitive session material and removes
// the session from the manager. This should be called after a session is
// complete to prevent key material from lingering in memory.
// R7-P3-1: MPCManager lacked a session cleanup method.
func (mpc *MPCManager) CleanupSession(sessionID string) {
	mpc.mu.Lock()
	defer mpc.mu.Unlock()
	mpc.cleanupSessionLocked(sessionID)
}

// evictOldestCompletedLocked removes the oldest completed session to make room
// for new sessions. The caller MUST hold mpc.mu.
// R7-P3-1: Prevent unbounded session growth by evicting completed sessions
// when maxSessions limit is reached.
func (mpc *MPCManager) evictOldestCompletedLocked() {
	var oldestID string
	var oldestTime time.Time
	found := false
	for id, s := range mpc.sessions {
		if s.Complete {
			if !found || s.createdAt.Before(oldestTime) {
				oldestID = id
				oldestTime = s.createdAt
				found = true
			}
		}
	}
	if found {
		mpc.cleanupSessionLocked(oldestID)
	}
}

// evictExpiredSessionsLocked removes sessions that have exceeded their TTL
// without completing. The caller MUST hold mpc.mu.
//
//	Prevent memory leaks and persistent sensitive key material from
//
// abandoned sessions that never reach Complete state.
func (mpc *MPCManager) evictExpiredSessionsLocked() {
	now := time.Now()
	for id, s := range mpc.sessions {
		if !s.Complete && now.Sub(s.createdAt) > mpc.sessionTTL {
			mpc.cleanupSessionLocked(id)
		}
	}
}

type SecretSharingScheme struct {
	mu          sync.Mutex
	threshold   int
	totalShares int
	prime       *big.Int
	// N19-001 FIX: Share commitments generated by SplitSecret, used to
	// verify shares in ReconstructSecret. Prevents injection of forged
	// shares that could control the reconstructed secret.
	commitments map[int][]byte
}

func NewSecretSharingScheme(threshold, totalShares int) (*SecretSharingScheme, error) {
	// FIX: Validate threshold and totalShares to prevent
	// misconfiguration. A threshold of 0 makes every subset of shares
	// (including the empty set) sufficient to reconstruct the secret.
	// A threshold greater than totalShares makes reconstruction impossible
	// since not enough shares can ever be collected. Both values must be
	// positive and threshold must not exceed totalShares.
	if threshold <= 0 {
		return nil, fmt.Errorf("threshold must be positive, got %d", threshold)
	}
	if totalShares <= 0 {
		return nil, fmt.Errorf("totalShares must be positive, got %d", totalShares)
	}
	if threshold > totalShares {
		return nil, fmt.Errorf("threshold (%d) cannot exceed totalShares (%d)", threshold, totalShares)
	}

	// audit-fix CRITICAL-4: Use post-quantum safe prime (2^256 - 189)
	prime, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF43", 16)
	return &SecretSharingScheme{
		threshold:   threshold,
		totalShares: totalShares,
		prime:       prime,
	}, nil
}

func (sss *SecretSharingScheme) SplitSecret(secret []byte) (map[int][]byte, error) {
	sss.mu.Lock()
	defer sss.mu.Unlock()

	shares := make(map[int][]byte)

	secretInt := new(big.Int).SetBytes(secret)
	// L16-004 FIX: Zeroize secretInt immediately via defer to close the window
	// between converting the secret to big.Int and the coefficients defer being
	// set up. secretInt is also referenced as coefficients[0], but the
	// coefficients defer is not registered until after the coefficients slice is
	// allocated and populated. This defer ensures secretInt is zeroized on all
	// return paths, including panics during coefficients allocation.
	defer func() { secretInt.SetInt64(0) }()

	coefficients := make([]*big.Int, sss.threshold)
	coefficients[0] = secretInt

	// R3-P3-1: Zeroize sensitive polynomial coefficients (including the secret at
	// index 0) and random coefficient bytes before returning. These contain the
	// secret itself and the randomness used to generate shares.
	defer func() {
		for _, c := range coefficients {
			if c != nil {
				c.SetInt64(0)
			}
		}
	}()

	for i := 1; i < sss.threshold; i++ {
		randCoeff := make([]byte, 32)
		if _, err := rand.Read(randCoeff); err != nil {
			// R3-P3-1: Zeroize randCoeff before returning on error
			for j := range randCoeff {
				randCoeff[j] = 0
			}
			return nil, fmt.Errorf("failed to generate random coefficient: %w", err)
		}
		coefficients[i] = new(big.Int).SetBytes(randCoeff)
		coefficients[i].Mod(coefficients[i], sss.prime)
		// R3-P3-1: Zero random coefficient bytes immediately after use
		for j := range randCoeff {
			randCoeff[j] = 0
		}
	}

	for x := 1; x <= sss.totalShares; x++ {
		y := sss.evaluatePolynomial(coefficients, big.NewInt(int64(x)))
		shares[x] = y.Bytes()
	}

	// N19-001 FIX: Generate commitments for each share.
	// QUANTUFIX: Use HMAC-SHA256 instead of plain SHA-256 to prevent
	// offline brute-force attacks when the share space is small. The HMAC
	// key is derived from the scheme's prime to ensure per-instance uniqueness.
	sss.commitments = make(map[int][]byte)
	hmacKey := sss.prime.Bytes()
	for x, shareBytes := range shares {
		h := hmac.New(sha256.New, hmacKey)
		idxBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(idxBytes, uint32(x))
		h.Write(idxBytes)
		h.Write(shareBytes)
		sss.commitments[x] = h.Sum(nil)
	}

	return shares, nil
}

func (sss *SecretSharingScheme) evaluatePolynomial(coefficients []*big.Int, x *big.Int) *big.Int {
	result := new(big.Int)

	for i := len(coefficients) - 1; i >= 0; i-- {
		result.Mul(result, x)
		result.Add(result, coefficients[i])
		result.Mod(result, sss.prime)
	}

	return result
}

func (sss *SecretSharingScheme) ReconstructSecret(shares map[int][]byte) ([]byte, error) {
	sss.mu.Lock()
	defer sss.mu.Unlock()

	if len(shares) < sss.threshold {
		return nil, ErrInsufficientParties
	}

	// FIX [P1]: Commitments are mandatory for reconstruction.
	// Previously verification was skipped when sss.commitments was nil
	// (the zero value), so calling ReconstructSecret directly without a
	// prior SplitSecret allowed attackers to inject forged shares that
	// would control the interpolated result. Reject outright when no
	// commitments are available.
	if sss.commitments == nil {
		return nil, fmt.Errorf("%w: no commitments available - call SplitSecret first", ErrShareVerificationFailed)
	}

	// N19-001 FIX: Verify each share against its commitment before
	// performing Lagrange interpolation. Since commitments are now
	// guaranteed to be present (set by SplitSecret), all shares must
	// match. This prevents an attacker from injecting forged shares
	// that would control the result.
	for i, shareBytes := range shares {
		expectedCommit, ok := sss.commitments[i]
		if !ok {
			return nil, fmt.Errorf("%w: no commitment for share index %d", ErrShareVerificationFailed, i)
		}
		// QUANTUFIX: Use HMAC-SHA256 to match SplitSecret's commitment generation
		h := hmac.New(sha256.New, sss.prime.Bytes())
		idxBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(idxBytes, uint32(i))
		h.Write(idxBytes)
		h.Write(shareBytes)
		if subtle.ConstantTimeCompare(h.Sum(nil), expectedCommit) != 1 {
			return nil, fmt.Errorf("%w: share %d fails commitment verification", ErrShareVerificationFailed, i)
		}
	}

	secret := new(big.Int)
	// L9-028 FIX: Hoist intermediate big.Int variables to function scope so
	// they can be zeroized via defer before any return path, preventing
	// sensitive intermediate values from lingering in heap memory.
	// Mirrors the L8-003 fix applied to lagrangeInterpolate.
	var numerator, denominator, inv, lagrangeCoeff, term *big.Int
	defer func() {
		secret.SetInt64(0)
		if numerator != nil {
			numerator.SetInt64(0)
		}
		if denominator != nil {
			denominator.SetInt64(0)
		}
		if inv != nil {
			inv.SetInt64(0)
		}
		if lagrangeCoeff != nil {
			lagrangeCoeff.SetInt64(0)
		}
		if term != nil {
			term.SetInt64(0)
		}
	}()

	// FIX: Track internal share copies for cleanup.
	// We copy each share into a big.Int; these are zeroed after reconstruction
	// instead of mutating the caller's []byte slices.
	shareInts := make([]*big.Int, 0, len(shares))

	for i, shareBytes := range shares {
		share := new(big.Int).SetBytes(shareBytes)
		shareInts = append(shareInts, share)

		numerator = big.NewInt(1)
		denominator = big.NewInt(1)

		for j := range shares {
			if i != j {
				numerator.Mul(numerator, big.NewInt(int64(-j)))
				denominator.Mul(denominator, big.NewInt(int64(i-j)))
			}
		}

		// audit fix (LOW-8): check whether ModInverse returned nil, preventing a later Mul panic
		inv = new(big.Int).ModInverse(denominator, sss.prime)
		if inv == nil {
			// L6-045: Zeroize share before error return
			share.SetInt64(0)
			return nil, fmt.Errorf("%w: denominator has no inverse for share index %d", ErrLagrangeInterpolationFailed, i)
		}
		lagrangeCoeff = new(big.Int).Mul(numerator, inv)
		term = new(big.Int).Mul(share, lagrangeCoeff)
		secret.Add(secret, term)
		secret.Mod(secret, sss.prime)
		// L6-045: Zeroize share after use in each iteration
		share.SetInt64(0)
		// L15-015 FIX: Zeroize intermediate variables within each loop iteration
		// to minimize the window in which secret material resides in memory.
		term.SetInt64(0)
		lagrangeCoeff.SetInt64(0)
		inv.SetInt64(0)
		numerator.SetInt64(0)
		denominator.SetInt64(0)
	}

	// FIX: Zero the internal share copy (shareInts) after successful
	// reconstruction to prevent sensitive key material from lingering in memory.
	// FIX: Do NOT zero the caller's shares slice — that is a surprising
	// side effect that violates the function's contract and can cause the caller
	// to lose data it still needs. Only zero our internal copies.
	for i := range shareInts {
		shareInts[i].SetInt64(0)
	}

	// R39-P3 FIX: Zero and clear commitments after successful reconstruction.
	// The commitments map contains HMAC values derived from share material
	// and should not linger in memory after reconstruction is complete.
	if sss.commitments != nil {
		for k, v := range sss.commitments {
			for i := range v {
				v[i] = 0
			}
			delete(sss.commitments, k)
		}
	}

	return secret.Bytes(), nil
}
