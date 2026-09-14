// Quantaureum Node source, version 1.0.0.
package tss

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/quantaureum/qau/wallet/tss/qtd"
)

// This file implements the distributed TSS signing coordinator.
//
// In distributed mode, each validator holds only ONE key share (its own).
// The signing protocol requires network exchange of protocol data:
//
//   Round 1: Each participant computes commitment locally, broadcasts it.
//   Round 2: Each participant computes reveal locally, sends to aggregator.
//   Aggregate: Aggregator collects all reveals, produces final signature.
//
// The key challenge is that Round2Aggregate needs S2Share and T0Share from
// all participants. In distributed mode, each participant includes weighted
// S2 and T0 components in their Round2 reveal so the aggregator can
// reconstruct the aggregate without holding other participants' shares.
//
// Security:
//   - ScShare (private key material) is sent ONLY via encrypted P2P to the aggregator
//   - S2Share and T0Share are also private (they are key shares) and sent encrypted
//   - WShare and ZShare are public and can be broadcast

var (
	ErrDistributedSessionNotFound = errors.New("tss: distributed session not found")
	ErrDistributedSessionTimeout  = errors.New("tss: distributed session timed out")
	ErrInsufficientReveals        = errors.New("tss: insufficient reveals for aggregation")
	ErrNotAggregator              = errors.New("tss: this node is not the aggregator for this session")
)

// sessionRoundTimeout returns the deadline window for distributed signing
// sessions (used for both session creation and the round1 expiry check).
//
// CR-11 FIX (audit 2026-08-14): Previously a hardcoded 30 * time.Second at
// both DistributedSession construction sites, and the deadline was never
// enforced on the round1 submission path — a commitment arriving after the
// deadline was still accepted (the only enforcement was the external
// CleanExpiredSessions sweep). The window is now configurable via the
// QAU_TSS_SESSION_TIMEOUT_SECONDS environment variable; the default of 30
// seconds preserves existing behavior. Invalid (non-numeric or <= 0) values
// fall back to the default.
func sessionRoundTimeout() time.Duration {
	if v := os.Getenv("QAU_TSS_SESSION_TIMEOUT_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 30 * time.Second
}

// maxEncodedShareSize is the maximum allowed size (in bytes) for any single
// share field (wShare, zShare, scShare, s2Share, t0Share) transmitted over the
// wire. Legitimate Dilithium3 shares are well under this limit (a few KB);
// larger values indicate malformed or malicious input and are rejected to
// prevent memory-exhaustion attacks against the encode/decode paths.
// QP-04/QP-05/QP-06 FIX.
const maxEncodedShareSize = 16384

// DistributedSession tracks a single distributed signing session.
type DistributedSession struct {
	mu sync.Mutex

	SessionID      [32]byte
	Message        []byte
	ParticipantIDs []int
	Threshold      int

	// Round 1 state
	round1Commitments map[int]*qtd.Round1Commitment // participantID → commitment
	round1Done        bool

	// Round 2 state
	round2Reveals map[int]*qtd.Round2Reveal // participantID → reveal
	round2Done    bool

	// The underlying QTD session (created by the aggregator for local computation)
	qtdSession *qtd.QTDSession

	// Timing
	createdAt time.Time
	deadline  time.Time
}

// DistributedSigner coordinates multi-party TSS signing over the network.
// It is used by the node layer to orchestrate Round1/Round2/Aggregate
// across validator nodes.
type DistributedSigner struct {
	mu       sync.RWMutex
	manager  *TSSManager
	sessions map[[32]byte]*DistributedSession
}

// NewDistributedSigner creates a new distributed signer wrapping the given TSSManager.
func NewDistributedSigner(manager *TSSManager) *DistributedSigner {
	return &DistributedSigner{
		manager:  manager,
		sessions: make(map[[32]byte]*DistributedSession),
	}
}

// InitiateSession is called by the aggregator to start a new distributed signing session.
// It creates the underlying QTD session locally and returns the session ID.
// The aggregator must then broadcast the session init to all participants.
//
// TSS-R9-CRIT-01 (2026-07-19) FIX: Previously this method called the DEPRECATED
// CreateSigningSession, which loaded ALL participant shares into a single
// in-memory session held by the aggregator. If the aggregator node is later
// compromised, an attacker can exfiltrate every share and reconstruct the
// full private key via Shamir/Lagrange interpolation — defeating t-of-n
// threshold security even when the operator believes they are running
// distributed TSS.
//
// The fix uses CreateParticipantSession, which loads ONLY the aggregator's
// own key share into the local QTD session. Other participants' shares are
// never present on this node; their W_i commitments arrive via the normal
// Round1 P2P exchange (SubmitRound1Commitment + SubmitRound1W). This
// preserves threshold security: compromising the aggregator leaks only ONE
// share, not all of them.
//
// The aggregator's myParticipantID MUST be supplied by the caller (the
// node layer resolves it from the validator index via getMyParticipantID).
// An invalid myParticipantID (< 1) is rejected up front to surface caller
// bugs rather than silently producing an unusable session.
func (ds *DistributedSigner) InitiateSession(message []byte, participantIDs []int, myParticipantID int) ([32]byte, error) {
	if myParticipantID < 1 {
		return [32]byte{}, fmt.Errorf("tss: InitiateSession: invalid myParticipantID %d (must be >= 1)", myParticipantID)
	}
	if !isParticipantInList(myParticipantID, participantIDs) {
		return [32]byte{}, fmt.Errorf("tss: InitiateSession: myParticipantID %d is not in participantIDs %v", myParticipantID, participantIDs)
	}

	// TSS-R9-CRIT-01 FIX: Use CreateParticipantSession (loads ONLY the local
	// aggregator share) instead of the deprecated CreateSigningSession
	// (which loaded ALL shares, defeating t-of-n threshold security).
	initiatedAt := time.Now().UnixNano()
	sessionKey, err := ds.manager.CreateParticipantSession(message, participantIDs, myParticipantID, initiatedAt)
	if err != nil {
		return [32]byte{}, fmt.Errorf("create participant session: %w", err)
	}

	ds.manager.mu.RLock()
	qtdSession := ds.manager.activeSessions[sessionKey]
	ds.manager.mu.RUnlock()

	if qtdSession == nil {
		return [32]byte{}, fmt.Errorf("failed to get QTD session")
	}

	// Generate session ID
	// R43-QP-002 FIX: Include full participant ID list (not just count) to
	// prevent session ID collisions between different participant sets with
	// the same count. Also avoid append(message, ...) which can mutate the
	// caller's backing array.
	h := sha256.New()
	h.Write(message)
	var idBuf [4]byte
	binary.BigEndian.PutUint32(idBuf[:], uint32(len(participantIDs)))
	h.Write(idBuf[:])
	for _, pid := range participantIDs {
		binary.BigEndian.PutUint32(idBuf[:], uint32(pid))
		h.Write(idBuf[:])
	}
	var sessionID [32]byte
	copy(sessionID[:], h.Sum(nil))

	session := &DistributedSession{
		SessionID:         sessionID,
		Message:           append([]byte(nil), message...),
		ParticipantIDs:    append([]int(nil), participantIDs...),
		Threshold:         ds.manager.Threshold(),
		round1Commitments: make(map[int]*qtd.Round1Commitment),
		round2Reveals:     make(map[int]*qtd.Round2Reveal),
		qtdSession:        qtdSession,
		createdAt:         time.Now(),
		deadline:          time.Now().Add(sessionRoundTimeout()),
	}

	ds.mu.Lock()
	ds.sessions[sessionID] = session
	ds.mu.Unlock()

	// Clean up the session key mapping in TSSManager (we'll manage it ourselves)
	ds.manager.CleanSession(sessionKey)

	return sessionID, nil
}

// ComputeRound1Commitment is called by a participant to compute its Round1 commitment.
// Returns the commitment and the W_i bytes (for inclusion in the P2P broadcast).
func (ds *DistributedSigner) ComputeRound1Commitment(sessionID [32]byte, participantID int) (*qtd.Round1Commitment, []byte, error) {
	ds.mu.RLock()
	session, ok := ds.sessions[sessionID]
	ds.mu.RUnlock()
	if !ok {
		return nil, nil, ErrDistributedSessionNotFound
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.qtdSession == nil {
		return nil, nil, fmt.Errorf("no QTD session for this participant")
	}

	commitment, err := session.qtdSession.Round1Commitment(participantID)
	if err != nil {
		return nil, nil, fmt.Errorf("round1 commitment: %w", err)
	}

	// Retrieve W_i computed during Round1Commitment
	wBytes := session.qtdSession.GetW(participantID)

	return commitment, wBytes, nil
}

// SubmitRound1Commitment is called when a participant receives a Round1 commitment
// from another participant. The aggregator collects all commitments.
func (ds *DistributedSigner) SubmitRound1Commitment(sessionID [32]byte, commitment *qtd.Round1Commitment) error {
	ds.mu.RLock()
	session, ok := ds.sessions[sessionID]
	ds.mu.RUnlock()
	if !ok {
		return ErrDistributedSessionNotFound
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	// R48-QP-01 FIX: Validate participant ID and check for duplicates.
	if commitment == nil {
		return fmt.Errorf("nil commitment")
	}
	if commitment.ParticipantID < 1 {
		return fmt.Errorf("invalid participant ID: %d", commitment.ParticipantID)
	}
	if _, exists := session.round1Commitments[commitment.ParticipantID]; exists {
		return fmt.Errorf("duplicate round1 commitment for participant %d", commitment.ParticipantID)
	}

	// CR-11 FIX (audit 2026-08-14): Enforce the session deadline on the
	// round1 submission path. Previously the deadline was only consulted
	// by the external CleanExpiredSessions sweep — a commitment arriving
	// after the deadline was still accepted here and could complete
	// round1/round2 on a session the rest of the network had already
	// abandoned. Rejecting late submissions bounds the round1 wait to the
	// configured window (QAU_TSS_SESSION_TIMEOUT_SECONDS, default 30s).
	if time.Now().After(session.deadline) {
		return fmt.Errorf("%w: session %x round1 deadline passed", ErrDistributedSessionTimeout, sessionID)
	}

	if session.round1Done {
		// R46-QP-03 FIX: Return an error instead of nil so the caller knows
		// its commitment was discarded. This prevents replays and network
		// duplication from being silently swallowed.
		return fmt.Errorf("round 1 already complete for session %x", sessionID)
	}

	session.round1Commitments[commitment.ParticipantID] = commitment

	// Check if we have enough commitments
	// R48-QP-09 FIX: Use == instead of >= for exact threshold match.
	// Using >= is not a bug here (duplicate check prevents overflow), but ==
	// is more precise: round1Done should be set exactly when the last needed
	// commitment arrives, not on any surplus.
	if len(session.round1Commitments) == len(session.ParticipantIDs) {
		// Verify all commitments (only if we have a QTD session — aggregator side)
		if session.qtdSession != nil {
			commitments := make([]*qtd.Round1Commitment, 0, len(session.round1Commitments))
			for _, c := range session.round1Commitments {
				commitments = append(commitments, c)
			}
			if err := session.qtdSession.Round1Verify(commitments); err != nil {
				return fmt.Errorf("round1 verify: %w", err)
			}
		}
		session.round1Done = true
	}

	return nil
}

// SubmitRound1W stores another participant's W_i into the QTD session.
// Called by participants when they receive a Round1 broadcast containing W_i.
func (ds *DistributedSigner) SubmitRound1W(sessionID [32]byte, participantID int, wBytes []byte) error {
	ds.mu.RLock()
	session, ok := ds.sessions[sessionID]
	ds.mu.RUnlock()
	if !ok {
		return ErrDistributedSessionNotFound
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	// QP-06 FIX: Verify the participant is part of this session before
	// accepting their W_i. Without this check, a non-participant could
	// inject a malicious W_i into the QTD session, corrupting the signing.
	if !isParticipantInList(participantID, session.ParticipantIDs) {
		return fmt.Errorf("participant %d is not part of this session", participantID)
	}

	if session.qtdSession != nil {
		if err := session.qtdSession.SubmitExternalW(participantID, wBytes); err != nil {
			return fmt.Errorf("submit external W: %w", err)
		}
	}
	return nil
}

// InitiateParticipantSession is called by a non-aggregator participant when it
// receives a SessionInit broadcast. It creates a local QTD session containing
// only the participant's own share. The participantID must be this node's share ID.
//
// TSS-M8 (R8 2026-07-19 FIX): initiatedAt is the aggregator's authoritative
// Unix-nano timestamp (extracted from the SessionInit payload). When non-zero,
// it is used for both DistributedSession.createdAt/deadline AND the inner
// qtdSession's createdAt (via CreateParticipantSession), so the session
// expires at the same wall-clock instant across all participants regardless of
// per-node clock skew. When zero (legacy payload or pre-TSS-M8 aggregator),
// the participant falls back to its local time.Now().
func (ds *DistributedSigner) InitiateParticipantSession(sessionID [32]byte, message []byte, participantIDs []int, myParticipantID int, initiatedAt int64) error {
	sessionKey, err := ds.manager.CreateParticipantSession(message, participantIDs, myParticipantID, initiatedAt)
	if err != nil {
		return fmt.Errorf("create participant session: %w", err)
	}

	ds.manager.mu.RLock()
	qtdSession := ds.manager.activeSessions[sessionKey]
	ds.manager.mu.RUnlock()

	if qtdSession == nil {
		return fmt.Errorf("failed to get QTD session for participant %d", myParticipantID)
	}

	ds.manager.CleanSession(sessionKey)

	// TSS-M8: Use the aggregator's authoritative timestamp when available.
	createdAt := time.Now()
	if initiatedAt > 0 {
		createdAt = time.Unix(0, initiatedAt)
	}

	session := &DistributedSession{
		SessionID:         sessionID,
		Message:           append([]byte(nil), message...),
		ParticipantIDs:    append([]int(nil), participantIDs...),
		Threshold:         ds.manager.Threshold(),
		round1Commitments: make(map[int]*qtd.Round1Commitment),
		round2Reveals:     make(map[int]*qtd.Round2Reveal),
		qtdSession:        qtdSession,
		createdAt:         createdAt,
		deadline:          createdAt.Add(sessionRoundTimeout()),
	}

	ds.mu.Lock()
	ds.sessions[sessionID] = session
	ds.mu.Unlock()

	return nil
}

// IsRound1Complete returns true if all Round1 commitments have been received and verified.
func (ds *DistributedSigner) IsRound1Complete(sessionID [32]byte) bool {
	ds.mu.RLock()
	session, ok := ds.sessions[sessionID]
	ds.mu.RUnlock()
	if !ok {
		return false
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.round1Done
}

// ComputeRound2Reveal is called by a participant to compute its Round2 reveal.
// The returned reveal contains:
//   - Public part (WShare, ZShare, Nonce) — can be sent to aggregator via any channel
//   - Private part (ScShare) — MUST be sent via encrypted P2P only
//
// The S2 and T0 weighted shares are also included for the aggregator.
func (ds *DistributedSigner) ComputeRound2Reveal(sessionID [32]byte, participantID int) (*qtd.Round2Reveal, error) {
	ds.mu.RLock()
	session, ok := ds.sessions[sessionID]
	ds.mu.RUnlock()
	if !ok {
		return nil, ErrDistributedSessionNotFound
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if !session.round1Done {
		return nil, fmt.Errorf("round1 not complete")
	}

	if session.qtdSession == nil {
		return nil, fmt.Errorf("no QTD session (not the aggregator)")
	}

	reveal, err := session.qtdSession.Round2Reveal(participantID)
	if err != nil {
		return nil, fmt.Errorf("round2 reveal: %w", err)
	}

	return reveal, nil
}

// isParticipantInList reports whether pid is present in the participants slice.
func isParticipantInList(pid int, participants []int) bool {
	for _, p := range participants {
		if p == pid {
			return true
		}
	}
	return false
}

// SubmitRound2Reveal is called when the aggregator receives a Round2 reveal
// from a participant. The aggregator collects all reveals for final aggregation.
func (ds *DistributedSigner) SubmitRound2Reveal(sessionID [32]byte, reveal *qtd.Round2Reveal) error {
	ds.mu.RLock()
	session, ok := ds.sessions[sessionID]
	ds.mu.RUnlock()
	if !ok {
		return ErrDistributedSessionNotFound
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.round2Done {
		// R47-QP-03 FIX: Return an error instead of nil so the caller knows
		// its reveal was discarded (same fix as SubmitRound1Commitment).
		return fmt.Errorf("round 2 already complete for session %x", sessionID)
	}

	// R47-QP-10 FIX: Validate participant ID before storing.
	if reveal == nil || reveal.ParticipantID < 1 {
		return fmt.Errorf("invalid reveal or participant ID")
	}
	// QP-03 FIX: Verify the participant is part of this session before
	// storing the reveal. Without this check, reveals from non-participants
	// would be accepted and could corrupt the threshold aggregation.
	if !isParticipantInList(reveal.ParticipantID, session.ParticipantIDs) {
		return fmt.Errorf("participant %d is not part of this session", reveal.ParticipantID)
	}
	// QP-07 FIX: If a reveal already exists for this participant (e.g. a
	// retransmitted or duplicate submission), zeroize the previous z0
	// contribution (Z0Share) — secret-derived private material —
	// before it is replaced. Otherwise the old backing arrays would linger
	// unreferenced in memory, defeating the zeroization done in
	// zeroSessionSecrets/CleanSession.
	// AUDIT (2026) TSS-FIX: Replaced Cs2Share/Ct0Share zeroization
	// with Z0Share zeroization (the struct field changed).
	if old, exists := session.round2Reveals[reveal.ParticipantID]; exists && old != nil {
		if old.Z0Share != nil {
			for i := range old.Z0Share {
				old.Z0Share[i] = 0
			}
		}
	}
	session.round2Reveals[reveal.ParticipantID] = reveal

	// Check if we have enough reveals (threshold)
	if len(session.round2Reveals) >= session.Threshold {
		session.round2Done = true
	}

	return nil
}

// IsRound2Complete returns true if enough Round2 reveals have been received (>= threshold).
func (ds *DistributedSigner) IsRound2Complete(sessionID [32]byte) bool {
	ds.mu.RLock()
	session, ok := ds.sessions[sessionID]
	ds.mu.RUnlock()
	if !ok {
		return false
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.round2Done
}

// AttachZ0Contribution attaches the combined z0 contribution (Z0Share) and
// ZShare to an existing Round2 reveal. Called by the aggregator when it
// receives the encrypted private part after the public part has already been
// stored.
//
// AUDIT (2026) TSS-FIX: This replaces the old AttachMaskedContributions
// which accepted separate cs2Share/ct0Share. The new method accepts a SINGLE
// combined z0Share = λ_i·c·(t0_i - s2_i) which cannot be decomposed by the
// aggregator into c·s2 and c·t0 separately. The aggregator never sees raw
// s2_i/t0_i shares OR the individual masked contributions.
// R2-HIGH-07: ZShare is delivered via the private channel and attached here.
func (ds *DistributedSigner) AttachZ0Contribution(sessionID [32]byte, participantID int, z0Share, zShare []byte) error {
	// R50-QP-02 FIX: Validate share sizes before processing.
	const maxShareSize = 16384 // 16KB — well above any legitimate share size
	if len(z0Share) > maxShareSize {
		return fmt.Errorf("z0Share too large: %d bytes (max %d)", len(z0Share), maxShareSize)
	}
	if len(zShare) > maxShareSize {
		return fmt.Errorf("zShare too large: %d bytes (max %d)", len(zShare), maxShareSize)
	}

	ds.mu.RLock()
	session, ok := ds.sessions[sessionID]
	ds.mu.RUnlock()
	if !ok {
		return ErrDistributedSessionNotFound
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	reveal, exists := session.round2Reveals[participantID]
	if !exists {
		return fmt.Errorf("no public reveal for participant %d", participantID)
	}

	// AUDIT (2026) TSS-FIX: Attach the combined z0 contribution
	// instead of separate cs2Share/ct0Share. Z0Share cannot be decomposed
	// by the aggregator, preventing full-key-recovery.
	reveal.Z0Share = z0Share
	// R2-HIGH-07: Attach ZShare from the private encrypted channel.
	if len(zShare) > 0 {
		reveal.ZShare = zShare
	}

	return nil
}

// AggregateSignature is called by the aggregator to produce the final signature
// from all collected Round2 reveals.
//
// TSS-R9-CRIT-02 (2026-07-19) FIX: Previously this method called the legacy
// single-aggregator Round2Aggregate, which is HARD-BLOCKED when role
// separation is enforced (auto-enabled for n >= 3 by NewGMQTDSession /
// NewQTDSession via DeriveRoleAssignment). For n >= 3 the call therefore
// returned ErrRoleSeparationRequired, breaking distributed TSS signing
// entirely in any non-trivial validator set.
//
// The fix uses the role-separated aggregation primitives
//
//	AggregateW → AggregateZ → AggregateHint → AssembleFinalSignature
//
// instead of the disabled Round2Aggregate. This produces a byte-identical
// signature to the legacy path (the underlying math is the same — the
// split is purely a structural decoupling so no single caller obtains
// w_agg, z_agg, and z0_agg in one method frame).
//
// Residual risk (documented): because all three calls are still issued by
// the same aggregator process, the aggregator momentarily holds all three
// aggregates in memory. True cross-node role separation (W-agg, Z-agg, and
// H-agg performed by DIFFERENT validators) is a deeper architectural change
// tracked under TSS- "full closure" and is out of R9 scope. The
// immediate fix removes the hard-block and uses the supported API.
func (ds *DistributedSigner) AggregateSignature(sessionID [32]byte) ([]byte, error) {
	ds.mu.RLock()
	session, ok := ds.sessions[sessionID]
	ds.mu.RUnlock()
	if !ok {
		return nil, ErrDistributedSessionNotFound
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if !session.round2Done {
		return nil, ErrInsufficientReveals
	}

	if session.qtdSession == nil {
		return nil, fmt.Errorf("no QTD session for aggregation")
	}

	// Collect reveals
	reveals := make([]*qtd.Round2Reveal, 0, len(session.round2Reveals))
	for _, r := range session.round2Reveals {
		reveals = append(reveals, r)
	}

	// TSS-R9-CRIT-02 FIX: Use the role-separated W/Z/H aggregation path
	// (supported, non-deprecated) instead of Round2Aggregate (hard-blocked
	// when role separation is enforced, which is the default for n >= 3).
	wResult, err := session.qtdSession.AggregateW(reveals)
	if err != nil {
		return nil, fmt.Errorf("QTD aggregate W failed: %w", err)
	}
	zResult, err := session.qtdSession.AggregateZ(reveals)
	if err != nil {
		return nil, fmt.Errorf("QTD aggregate Z failed: %w", err)
	}
	hResult, err := session.qtdSession.AggregateHint(reveals, wResult.WAggBytes, wResult.W1Bytes)
	if err != nil {
		return nil, fmt.Errorf("QTD aggregate Hint failed: %w", err)
	}

	qtdSig := qtd.AssembleFinalSignature(zResult.ZAgg, hResult.Hint, wResult.CtildeSeed, wResult.W1Bytes)
	if qtdSig == nil {
		return nil, fmt.Errorf("QTD assemble final signature returned nil")
	}
	return qtdSig.FullSig, nil
}

// CleanSession removes a completed or expired session.
// R48-QP-06 FIX: Zero commitments and reveals before deletion.
func (ds *DistributedSigner) CleanSession(sessionID [32]byte) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	session, ok := ds.sessions[sessionID]
	if ok {
		zeroSessionSecrets(session)
	}
	delete(ds.sessions, sessionID)
}

// zeroSessionSecrets zeroes all sensitive material in a DistributedSession.
// R49-QP-01 FIX: Extracted from CleanSession so CleanExpiredSessions can reuse it.
func zeroSessionSecrets(session *DistributedSession) {
	if session == nil {
		return
	}
	// Zero commitments
	for _, c := range session.round1Commitments {
		if c != nil {
			if c.Commitment != nil {
				for i := range c.Commitment {
					c.Commitment[i] = 0
				}
			}
			if c.Nonce != nil {
				for i := range c.Nonce {
					c.Nonce[i] = 0
				}
			}
		}
	}
	// Zero reveals
	for _, r := range session.round2Reveals {
		if r != nil {
			if r.WShare != nil {
				for i := range r.WShare {
					r.WShare[i] = 0
				}
			}
			if r.ZShare != nil {
				for i := range r.ZShare {
					r.ZShare[i] = 0
				}
			}
			// AUDIT (2026) TSS-FIX: Zeroize the combined z0
			// contribution (Z0Share) instead of the old Cs2Share/Ct0Share.
			// While Z0Share is a combined contribution (not raw key shares),
			// zeroing it prevents leaking the signing transcript before the
			// signature is finalized.
			if r.Z0Share != nil {
				for i := range r.Z0Share {
					r.Z0Share[i] = 0
				}
			}
			if r.Nonce != nil {
				for i := range r.Nonce {
					r.Nonce[i] = 0
				}
			}
		}
	}
	if session.qtdSession != nil {
		session.qtdSession.Cleanup()
	}
}

// CleanExpiredSessions removes sessions that have exceeded their deadline.
// R49-QP-01 FIX: Now zeroizes secrets before deletion, consistent with CleanSession.
func (ds *DistributedSigner) CleanExpiredSessions() {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	for id, session := range ds.sessions {
		if time.Now().After(session.deadline) {
			zeroSessionSecrets(session)
			delete(ds.sessions, id)
		}
	}
}

// GetSession returns the distributed session for inspection (e.g., to check state).
func (ds *DistributedSigner) GetSession(sessionID [32]byte) (*DistributedSession, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	session, ok := ds.sessions[sessionID]
	return session, ok
}

// EncodeRound1Commitment serializes a Round1 commitment + W_i for P2P transmission.
// Format: SessionID(32) + ParticipantID(4) + Commitment(32) + Nonce(16) + WShareLen(4) + WShare
// WShare is included so that each participant can compute W_agg = Σ W_i independently,
// which is needed to derive the challenge c in Round2Reveal.
// QP-04 FIX: Validate wShare size before encoding to prevent oversized/malformed
// shares from being transmitted and to bound the allocated buffer.
func EncodeRound1Commitment(sessionID [32]byte, c *qtd.Round1Commitment, wShare []byte) ([]byte, error) {
	if len(wShare) > maxEncodedShareSize {
		return nil, fmt.Errorf("wShare too large: %d bytes (max %d)", len(wShare), maxEncodedShareSize)
	}
	headerSize := 32 + 4 + 32 + 16 // 84
	buf := make([]byte, headerSize+4+len(wShare))
	copy(buf[0:32], sessionID[:])
	binary.BigEndian.PutUint32(buf[32:36], uint32(c.ParticipantID))
	copy(buf[36:68], c.Commitment)
	copy(buf[68:84], c.Nonce)
	binary.BigEndian.PutUint32(buf[84:88], uint32(len(wShare)))
	copy(buf[88:88+len(wShare)], wShare)
	return buf, nil
}

// DecodeRound1Commitment deserializes a Round1 commitment + W_i from P2P transmission.
func DecodeRound1Commitment(data []byte) (sessionID [32]byte, c *qtd.Round1Commitment, wShare []byte, err error) {
	if len(data) < 88 {
		return [32]byte{}, nil, nil, fmt.Errorf("invalid round1 commitment size: %d", len(data))
	}
	copy(sessionID[:], data[0:32])
	c = &qtd.Round1Commitment{
		ParticipantID: int(binary.BigEndian.Uint32(data[32:36])),
		Commitment:    append([]byte(nil), data[36:68]...),
		Nonce:         append([]byte(nil), data[68:84]...),
	}
	wLen := int(binary.BigEndian.Uint32(data[84:88]))
	// QP-05 FIX: Bound the decoded wLen before using it to allocate or slice.
	// Without this, a malicious peer could send a huge length field to force
	// an oversized allocation or trigger an integer-overflow-adjacent path.
	if wLen > maxEncodedShareSize {
		return [32]byte{}, nil, nil, fmt.Errorf("wShare length exceeds maximum: %d (max %d)", wLen, maxEncodedShareSize)
	}
	if len(data) < 88+wLen {
		return [32]byte{}, nil, nil, fmt.Errorf("invalid wShare length: %d", wLen)
	}
	wShare = append([]byte(nil), data[88:88+wLen]...)
	return sessionID, c, wShare, nil
}

// EncodeRound2Reveal serializes a Round2 reveal for P2P transmission.
// The public part (WShare + ZShare + Nonce) is sent as MsgTypeTSSRound2Reveal.
// The private part (ScShare + ZShare + S2/T0) is sent separately as
// MsgTypeTSSRound2Private (encrypted).
//
// R2-HIGH-07 / TSS-FIX: ZShare (z_i = lambda_i*s1_i*c + y_i) is NO
// LONGER included in the public broadcast. Broadcasting z_i before rejection
// sampling leaks rejected transcripts that bias toward s1_i, enabling key
// recovery over many signatures. ZShare is now sent only via the encrypted
// private channel to the aggregator. If rejection sampling fails, the z_i
// values are discarded and never revealed publicly.
//
// Public message format:
//
//	SessionID(32) + ParticipantID(4) + WShare(4608) + Nonce(16) = 4660 bytes
func EncodeRound2RevealPublic(sessionID [32]byte, r *qtd.Round2Reveal) []byte {
	wLen := qtd.Dilithium3K * qtd.N * 3
	nonceLen := 16
	total := 32 + 4 + wLen + nonceLen

	buf := make([]byte, total)
	copy(buf[0:32], sessionID[:])
	binary.BigEndian.PutUint32(buf[32:36], uint32(r.ParticipantID))
	copy(buf[36:36+wLen], r.WShare)
	copy(buf[36+wLen:36+wLen+nonceLen], r.Nonce)
	return buf
}

// DecodeRound2RevealPublic deserializes the public part of a Round2 reveal.
// ZShare is NOT included in the public encoding (R2-HIGH-07 fix); it is
// delivered via the encrypted private channel instead.
func DecodeRound2RevealPublic(data []byte) (sessionID [32]byte, r *qtd.Round2Reveal, err error) {
	wLen := qtd.Dilithium3K * qtd.N * 3
	nonceLen := 16
	expected := 32 + 4 + wLen + nonceLen

	if len(data) < expected {
		return [32]byte{}, nil, fmt.Errorf("invalid round2 reveal size: %d, expected >= %d", len(data), expected)
	}

	copy(sessionID[:], data[0:32])
	r = &qtd.Round2Reveal{
		ParticipantID: int(binary.BigEndian.Uint32(data[32:36])),
		WShare:        append([]byte(nil), data[36:36+wLen]...),
		ZShare:        nil, // delivered via private channel (R2-HIGH-07)
		Nonce:         append([]byte(nil), data[36+wLen:36+wLen+nonceLen]...),
	}
	return sessionID, r, nil
}

// EncodeRound2RevealPrivate serializes the private ZShare + combined Z0Share
// for encrypted P2P transmission.
// Format: SessionID(32) + ParticipantID(4) + ZShareLen(4) + ZShare +
//
//	Z0ShareLen(4) + Z0Share
//
// AUDIT (2026) TSS-FIX: The old format transmitted Cs2Share and
// Ct0Share SEPARATELY (λ_i·c·s2_i and λ_i·c·t0_i), which allowed the
// aggregator to recover the full private key via NTT inversion. The new
// format transmits a SINGLE combined Z0Share (λ_i·c·(t0_i - s2_i)) which
// the aggregator CANNOT decompose into c·s2 and c·t0 separately.
// R2-HIGH-07: ZShare is included in the private (encrypted) channel
// instead of the public broadcast, preventing leakage of rejected transcripts.
// QP-02 FIX: Size validation for zShare, z0Share (max
// maxEncodedShareSize bytes each) to reject oversized shares before serialization.
//
// AUDIT (2026) TSS-FIX: The wire format now carries an 8-byte
// Unix-nano timestamp between ParticipantID and ZShareLen. The aggregator
// validates the timestamp against a ±5min acceptance window AND enforces
// per-(session,participant) strict monotonic increase, closing the
// per-message replay gap that previously relied only on B-3/B-4 binding.
// The timestamp is taken from the sender's local clock; clock skew across
// validators is bounded by the ±5min window (well above any realistic NTP
// drift). The format is NOT backward-compatible — distributed TSS is
// hard-blocked in production, so all nodes must upgrade together.
//
// Wire format:
//
//	SessionID(32) + ParticipantID(4) + Timestamp(8) + ZShareLen(4) + ZShare
//	  + Z0ShareLen(4) + Z0Share
func EncodeRound2RevealPrivate(sessionID [32]byte, participantID int, timestamp int64, zShare, z0Share []byte) ([]byte, error) {
	if len(zShare) > maxEncodedShareSize {
		return nil, fmt.Errorf("zShare too large: %d bytes (max %d)", len(zShare), maxEncodedShareSize)
	}
	if len(z0Share) > maxEncodedShareSize {
		return nil, fmt.Errorf("z0Share too large: %d bytes (max %d)", len(z0Share), maxEncodedShareSize)
	}
	buf := make([]byte, 32+4+8+4+len(zShare)+4+len(z0Share))
	copy(buf[0:32], sessionID[:])
	binary.BigEndian.PutUint32(buf[32:36], uint32(participantID))
	binary.BigEndian.PutUint64(buf[36:44], uint64(timestamp))
	binary.BigEndian.PutUint32(buf[44:48], uint32(len(zShare)))
	copy(buf[48:48+len(zShare)], zShare)
	off := 48 + len(zShare)
	binary.BigEndian.PutUint32(buf[off:off+4], uint32(len(z0Share)))
	copy(buf[off+4:off+4+len(z0Share)], z0Share)
	return buf, nil
}

// DecodeRound2RevealPrivate deserializes the private ZShare + combined Z0Share.
// AUDIT (2026) TSS-FIX: Returns z0Share (combined z0 contribution)
// instead of the old cs2Share/ct0Share (separate masked contributions that
// enabled full-key-recovery via NTT inversion).
// AUDIT (2026) TSS-FIX: Also returns the embedded timestamp for
// the caller to validate freshness (window + monotonic increase).
func DecodeRound2RevealPrivate(data []byte) (sessionID [32]byte, participantID int, timestamp int64, zShare, z0Share []byte, err error) {
	if len(data) < 48 {
		return [32]byte{}, 0, 0, nil, nil, fmt.Errorf("invalid private reveal size: %d", len(data))
	}
	copy(sessionID[:], data[0:32])
	participantID = int(binary.BigEndian.Uint32(data[32:36]))
	timestamp = int64(binary.BigEndian.Uint64(data[36:44]))
	zLen := int(binary.BigEndian.Uint32(data[44:48]))
	// QP-06 FIX: Bound each decoded share length to prevent memory exhaustion
	// from a malicious peer sending an oversized length field.
	if zLen > maxEncodedShareSize {
		return [32]byte{}, 0, 0, nil, nil, fmt.Errorf("zShare length exceeds maximum: %d (max %d)", zLen, maxEncodedShareSize)
	}
	if len(data) < 48+zLen+4 {
		return [32]byte{}, 0, 0, nil, nil, fmt.Errorf("invalid zShare length: %d", zLen)
	}
	zShare = append([]byte(nil), data[48:48+zLen]...)
	off := 48 + zLen
	if len(data) < off+4 {
		return [32]byte{}, 0, 0, nil, nil, fmt.Errorf("missing z0Share length")
	}
	z0Len := int(binary.BigEndian.Uint32(data[off : off+4]))
	if z0Len > maxEncodedShareSize {
		return [32]byte{}, 0, 0, nil, nil, fmt.Errorf("z0Share length exceeds maximum: %d (max %d)", z0Len, maxEncodedShareSize)
	}
	if len(data) < off+4+z0Len {
		return [32]byte{}, 0, 0, nil, nil, fmt.Errorf("invalid z0Share length: %d", z0Len)
	}
	z0Share = append([]byte(nil), data[off+4:off+4+z0Len]...)
	return sessionID, participantID, timestamp, zShare, z0Share, nil
}

// EncodeSessionInit serializes a session initialization message for broadcast.
//
// AUDIT (2026) TSS-FIX: The previous wire format included only
// sha256(message) (32 bytes) — NOT the message itself. Participants therefore
// reconstructed `message = sha256(actual_message)` and used that 32-byte hash
// as the signed message when computing the Dilithium3 challenge. The
// aggregator, however, used the full original message bytes. This caused
// challenge mismatches between participants and the aggregator, forcing the
// distributed signing path to silently fall back to local signing — i.e. the
// threshold/distributed property was never actually exercised.
//
// New wire format (forward-compatible — old payloads are rejected by the
// length check in DecodeSessionInit because they lack the MessageLen field):
//
//	SessionID(32) + MessageHash(32) + MessageLen(4) + Message(MessageLen)
//	  + ParticipantCount(4) + ParticipantIDs(4*N) + InitiatedAt(8)
//
// The MessageHash is retained as an integrity checksum so the receiver can
// detect in-transit corruption independently of the length-prefix check.
//
// TSS-M8 (R8 2026-07-19 FIX): InitiatedAt is the aggregator's authoritative
// Unix-nano timestamp for this session, sourced from the proposer's clock
// at session-creation time. Participants MUST use this value (when non-zero)
// instead of their local time.Now() when setting createdAt/deadline on both
// the outer DistributedSession and the inner qtd.QTDSession. This decouples
// session lifetime from per-node clock skew: even if a participant's NTP
// feed is off by minutes, its session expires at the same wall-clock
// instant as every other participant's. The field is authenticated by the
// existing B-5 aggregator-signature check (handleTSSSessionInit verifies
// the sender is the current block proposer), so a non-proposer cannot
// inject a forged timestamp to extend or shorten the session window.
//
// Backward compatibility: the trailing 8 bytes are OPTIONAL. A legacy
// payload without them parses successfully and DecodeSessionInit returns
// initiatedAt=0, which the caller treats as "no authoritative timestamp
// available — fall back to local time.Now()".
func EncodeSessionInit(sessionID [32]byte, message []byte, participantIDs []int, initiatedAt int64) []byte {
	msgHash := sha256.Sum256(message)
	msgLen := uint32(len(message))
	buf := make([]byte, 32+32+4+int(msgLen)+4+4*len(participantIDs)+8)
	copy(buf[0:32], sessionID[:])
	copy(buf[32:64], msgHash[:])
	binary.BigEndian.PutUint32(buf[64:68], msgLen)
	copy(buf[68:68+int(msgLen)], message)
	off := 68 + int(msgLen)
	binary.BigEndian.PutUint32(buf[off:off+4], uint32(len(participantIDs)))
	off += 4
	for i, pid := range participantIDs {
		binary.BigEndian.PutUint32(buf[off+4*i:off+4*i+4], uint32(pid))
	}
	off += 4 * len(participantIDs)
	// TSS-M8: Append authoritative aggregator timestamp (Unix nano).
	binary.BigEndian.PutUint64(buf[off:off+8], uint64(initiatedAt))
	return buf
}

// DecodeSessionInit deserializes a session initialization message produced by
// EncodeSessionInit. Returns the session ID, the FULL original message bytes
// (verified against the in-band SHA-256 checksum), the participant ID list,
// and the aggregator's authoritative Unix-nano timestamp (TSS-M8).
//
// AUDIT (2026) TSS-FIX: Previously this returned the 32-byte
// sha256(message) as `message`, causing the participant's QTD session to use
// the hash — not the original message — when computing the Dilithium3
// challenge. The aggregator's session used the original message, so the two
// sides computed different challenges and distributed signing silently fell
// back to local signing. Now the full message bytes are transmitted and the
// receiver verifies them against the in-band hash before use.
//
// TSS-M8 (R8 2026-07-19 FIX): Returns the authoritative aggregator timestamp
// (initiatedAt). A returned value of 0 means "no timestamp in payload"
// (legacy encoder or stripped relay); callers MUST treat 0 as "fall back to
// local time.Now()" rather than as the Unix epoch.
func DecodeSessionInit(data []byte) (sessionID [32]byte, message []byte, participantIDs []int, initiatedAt int64, err error) {
	// Minimum payload: SessionID(32) + MessageHash(32) + MessageLen(4)
	//                  + ParticipantCount(4)  (with zero-length message)
	const minSize = 32 + 32 + 4 + 4
	if len(data) < minSize {
		return [32]byte{}, nil, nil, 0, fmt.Errorf("invalid session init size: %d (min %d)", len(data), minSize)
	}
	copy(sessionID[:], data[0:32])
	expectedHash := make([]byte, 32)
	copy(expectedHash, data[32:64])
	msgLen := binary.BigEndian.Uint32(data[64:68])

	// TSS- / DoS hardening: bound the declared message length. The
	// legitimate use case is signing block hashes (32 bytes) or short
	// challenge strings; anything beyond 1 MiB is malformed or hostile.
	const maxSessionInitMessageLen = 1 << 20 // 1 MiB
	if msgLen > maxSessionInitMessageLen {
		return [32]byte{}, nil, nil, 0, fmt.Errorf("message length exceeds maximum: %d (max %d)", msgLen, maxSessionInitMessageLen)
	}

	msgEnd := 68 + int(msgLen)
	if len(data) < msgEnd {
		return [32]byte{}, nil, nil, 0, fmt.Errorf("truncated message: declared %d bytes, only %d available", msgLen, len(data)-68)
	}
	message = make([]byte, msgLen)
	copy(message, data[68:msgEnd])

	// Verify the in-band SHA-256 checksum to detect in-transit corruption
	// (or a malformed/hostile payload with mismatched hash and bytes).
	actualHash := sha256.Sum256(message)
	if subtle.ConstantTimeCompare(actualHash[:], expectedHash) != 1 {
		return [32]byte{}, nil, nil, 0, fmt.Errorf("session init message hash mismatch — corrupted or tampered payload")
	}

	off := msgEnd
	if len(data) < off+4 {
		return [32]byte{}, nil, nil, 0, fmt.Errorf("missing participant count field")
	}
	count := int(binary.BigEndian.Uint32(data[off : off+4]))
	off += 4
	// QP-01 FIX: Bound the participant count to prevent memory exhaustion
	// from a malicious oversized count field. A legitimate QPOS validator
	// set is far smaller than this; anything larger is malformed or hostile.
	const maxSessionInitParticipants = 1000
	if count > maxSessionInitParticipants {
		return [32]byte{}, nil, nil, 0, fmt.Errorf("participant count exceeds maximum: %d (max %d)", count, maxSessionInitParticipants)
	}
	if len(data) < off+4*count {
		return [32]byte{}, nil, nil, 0, fmt.Errorf("invalid participant count: %d (need %d bytes, have %d)", count, 4*count, len(data)-off)
	}
	participantIDs = make([]int, count)
	for i := 0; i < count; i++ {
		participantIDs[i] = int(binary.BigEndian.Uint32(data[off+4*i : off+4*i+4]))
	}
	off += 4 * count

	// TSS-M8 (R8 2026-07-19 FIX): Parse the optional trailing 8-byte
	// InitiatedAt timestamp. Two valid length classes:
	//   - Exactly off bytes: legacy payload (pre-TSS-M8) — no timestamp.
	//   - Exactly off+8 bytes: TSS-M8 payload — parse the timestamp.
	// Any other trailing length is malformed; reject rather than silently
	// ignoring trailing junk that could mask a relay-truncation attack.
	switch len(data) - off {
	case 0:
		// Legacy payload — fall back to local time.Now() at the caller.
		initiatedAt = 0
	case 8:
		initiatedAt = int64(binary.BigEndian.Uint64(data[off : off+8]))
	default:
		return [32]byte{}, nil, nil, 0, fmt.Errorf("invalid trailing length: %d bytes after participant IDs (expected 0 or 8)", len(data)-off)
	}
	return sessionID, message, participantIDs, initiatedAt, nil
}

// EncodeSignature serializes the final signature for broadcast.
// Format: SessionID(32) + Signature(variable)
func EncodeSignature(sessionID [32]byte, signature []byte) []byte {
	buf := make([]byte, 32+len(signature))
	copy(buf[0:32], sessionID[:])
	copy(buf[32:], signature)
	return buf
}

// DecodeSignature deserializes a final signature.
func DecodeSignature(data []byte) (sessionID [32]byte, signature []byte, err error) {
	if len(data) < 33 {
		return [32]byte{}, nil, fmt.Errorf("invalid signature message size: %d", len(data))
	}
	copy(sessionID[:], data[0:32])
	signature = append([]byte(nil), data[32:]...)
	return sessionID, signature, nil
}
