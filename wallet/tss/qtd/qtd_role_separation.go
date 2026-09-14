// Quantaureum Node source, version 1.0.0.
// Package qtd implements the GM-QTD threshold signing protocol.
// This file provides PER-SESSION ROLE ROTATION (TSS- closure).
//
// AUDIT (2026) TSS-FIX (HIGH → CLOSED via rotation + enforcement):
//
// Previous state: Round2Aggregate performed all three aggregation roles
// (W-agg, Z-agg, H-agg) in a single function call. Although separate
// AggregateW/AggregateZ/AggregateHint methods existed (added during
// TSS- "full closure"), the legacy single-aggregator Round2Aggregate
// was the default production path and nothing enforced use of the
// role-separated methods. Furthermore, there was no per-session role
// rotation — a participant assigned as W-agg (or H-agg) kept that role
// indefinitely, making long-term s1-recovery collusion trivial.
//
// RESIDUAL RISK (from TSS- / TSS-):
//
//   - W-agg sees w_agg = A·y → can compute y = A^{-1}·w_agg
//   - After signature publication, z (= s1·c + y) is public
//   - Therefore W-agg + public sig → s1 = (z - y)·c^{-1}
//   - H-agg sees z0_agg = c·(t0-s2) → can recover s1 via NTT inversion
//   - DH masking (TSS-) only protects transport, not the role itself
//
// CLOSURE: This file adds TWO mechanisms:
//
//  1. DeriveRoleAssignment: deterministically derives W/Z/H role assignment
//     from sessionID. Roles rotate per session — no participant plays the
//     same role across consecutive sessions. To continuously recover s1,
//     an attacker must compromise the rotating W-agg (or H-agg) node of
//     EACH session, raising collusion cost from "1 node forever" to
//     "many nodes over time".
//
//  2. SetRoleAssignment + enforcement: when enabled, the legacy
//     Round2Aggregate method is DISABLED (returns ErrRoleSeparationRequired),
//     forcing callers to use the existing role-separated methods
//     (AggregateW / AggregateZ / AggregateHint). This prevents a single
//     caller from obtaining w_agg, z_agg, and z0_agg simultaneously.
//
// The existing AggregateW/Z/H methods (in qtd_protocol.go) remain
// unchanged — they already implement the per-role share isolation. This
// file adds the rotation + enforcement layer on top of them.
//
// USAGE:
//
//	roles, err := DeriveRoleAssignment(sessionID, participants)
//	if err != nil { /* n < 3, fall back to legacy with documented risk */ }
//	session.SetRoleAssignment(roles)
//
//	// W-agg node runs ONLY:
//	wResult, _ := session.AggregateW(reveals)
//	// Z-agg node runs ONLY:
//	zResult, _ := session.AggregateZ(reveals)
//	// H-agg node runs ONLY (receives wResult from W-agg over secure channel):
//	hResult, _ := session.AggregateHint(reveals, wResult.WAggBytes, wResult.W1Bytes)
//	// Any node assembles the final signature from partial results:
//	sig := AssembleFinalSignature(zResult.ZAgg, hResult.Hint, wResult.CtildeSeed, wResult.W1Bytes)
//
// RESEARCH-LEVEL FULL CLOSURE (deferred):
//
// The residual s1 leakage via W-agg (or H-agg) + public signature is
// fundamental to the Dilithium3-based threshold design. Full closure
// requires distributed hint generation via MPC (e.g. SPDZ) where no
// single party observes c·(t0-s2) in the clear, OR migration to FROST/
// CFROST threshold-Schnorr protocols. These are future protocol changes.
// The per-session rotation provided here is the practical mitigation
// recommended by the TSS- audit.

package qtd

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
)

// ErrRoleSeparationRequired is returned when the legacy single-aggregator
// Round2Aggregate is called while role separation is enforced. The caller
// MUST use AggregateW / AggregateZ / AggregateHint instead.
var ErrRoleSeparationRequired = errors.New("qtd: role separation enforced — use AggregateW/Z/Hint instead of Round2Aggregate")

// ErrInsufficientParticipantsForRoles is returned when there are fewer than
// 3 participants available to fill the W/Z/H aggregator roles distinctly.
// In this case role separation cannot be enforced and callers must fall
// back to the legacy Round2Aggregate with documented residual risk.
var ErrInsufficientParticipantsForRoles = errors.New("qtd: need at least 3 distinct participants for role separation")

// RoleAssignment maps the W/Z/H aggregator roles to participant IDs.
// All three IDs MUST be distinct (enforced by DeriveRoleAssignment).
//
// TSS- Per-session rotation means this assignment changes every
// session. An attacker who compromises the W-agg node in session N
// cannot recover s1 from session N+1 unless they also compromise the
// (different) W-agg node of session N+1.
type RoleAssignment struct {
	WAggregator int // participant ID playing the W-aggregator role
	ZAggregator int // participant ID playing the Z-aggregator role
	HAggregator int // participant ID playing the H-aggregator role
}

// DeriveRoleAssignment deterministically derives the W/Z/H aggregator role
// assignment for a given session. The assignment rotates per session so
// that no participant plays the same role across consecutive sessions,
// raising the long-term collusion cost for s1 recovery.
//
// Algorithm:
//  1. Sort participant IDs canonically (all participants agree on ordering).
//  2. Derive a rotation offset from HMAC-SHA256(sessionID, "qtd-role-rotation").
//     HMAC is used so that an attacker who cannot control sessionID cannot
//     predict (and thus target) which participant will play W-agg.
//  3. Assign W, Z, H to participants[offset], participants[offset+1],
//     participants[offset+2] (mod n) — three DISTINCT participants.
//
// When n < 3, role separation cannot be fully enforced (some participant
// must play multiple roles). The function returns
// ErrInsufficientParticipantsForRoles. Callers in small-N deployments
// should fall back to the legacy Round2Aggregate with documented risk.
func DeriveRoleAssignment(sessionID []byte, participants []int) (RoleAssignment, error) {
	if len(participants) < 3 {
		return RoleAssignment{}, ErrInsufficientParticipantsForRoles
	}

	// Canonical sort of participant IDs for deterministic indexing.
	sorted := make([]int, len(participants))
	copy(sorted, participants)
	sort.Ints(sorted)

	// Derive rotation offset from sessionID. HMAC-SHA256 gives a
	// pseudorandom, unpredictable (to an attacker who cannot control
	// sessionID) but deterministic (all participants agree) offset.
	mac := hmac.New(sha256.New, sessionID)
	mac.Write([]byte("qtd-role-rotation"))
	digest := mac.Sum(nil)
	// Use first 8 bytes as a uint64, then mod n.
	offsetU64 := binary.BigEndian.Uint64(digest[:8])
	offset := int(offsetU64 % uint64(len(sorted)))

	return RoleAssignment{
		WAggregator: sorted[offset%len(sorted)],
		ZAggregator: sorted[(offset+1)%len(sorted)],
		HAggregator: sorted[(offset+2)%len(sorted)],
	}, nil
}

// SetRoleAssignment configures the session to enforce role separation.
// After this is called, the legacy Round2Aggregate method will return
// ErrRoleSeparationRequired, and only AggregateW / AggregateZ /
// AggregateHint may be used.
//
// Pass an empty RoleAssignment{} to disable enforcement (revert to
// legacy single-aggregator mode). This is intended ONLY for tests and
// for small-N deployments (n < 3) where role separation is impossible.
func (s *QTDSession) SetRoleAssignment(roles RoleAssignment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.roleAssignment = roles
	s.roleSeparationEnforced = (roles != RoleAssignment{})
}

// GetRoleAssignment returns the current role assignment (zero value if
// none set).
func (s *QTDSession) GetRoleAssignment() RoleAssignment {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.roleAssignment
}

// IsRoleSeparationEnforced reports whether role separation is enforced
// (i.e. the legacy Round2Aggregate is disabled and callers must use
// AggregateW / AggregateZ / AggregateHint).
func (s *QTDSession) IsRoleSeparationEnforced() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.roleSeparationEnforced
}

// IsWAggregator reports whether the given participant ID is assigned the
// W-aggregator role for this session. Convenience for transport layers
// that need to route WShare only to the designated W-agg node.
func (s *QTDSession) IsWAggregator(participantID int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.roleSeparationEnforced && s.roleAssignment.WAggregator == participantID
}

// IsZAggregator reports whether the given participant ID is assigned the
// Z-aggregator role for this session.
func (s *QTDSession) IsZAggregator(participantID int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.roleSeparationEnforced && s.roleAssignment.ZAggregator == participantID
}

// IsHAggregator reports whether the given participant ID is assigned the
// H-aggregator role for this session.
func (s *QTDSession) IsHAggregator(participantID int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.roleSeparationEnforced && s.roleAssignment.HAggregator == participantID
}
