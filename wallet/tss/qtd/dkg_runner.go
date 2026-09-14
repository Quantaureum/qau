// Quantaureum Node source, version 1.0.0.
package qtd

import "errors"

// ============================================================================
// TSS-R7-01 (2026-07-17) — DistributedDKGRunner interface (P2P DKG placeholder)
//
// AUDIT FINDING (TSS-R7-01, Critical): GenerateDKGDistributed executes all
// participants' sampling, aggregation, and Shamir splitting in a single
// process. The function returns []*QTDShare containing ALL participants'
// shares, so the calling host (TSSManager) effectively acts as a trusted
// dealer — it can Lagrange-interpolate the full private key s1 from the
// shares it holds. The code's own CAVEAT admits this: "we simulate this in
// a single process for integration with the existing TSSManager API".
//
// ARCHITECTURAL CLOSURE PATH (not yet implemented):
//
//   1. Each participant i runs Round1 sample s1_i/s2_i LOCALLY (in their own
//      process), broadcasts a Pedersen commitment C_i = commit(s1_i, s2_i),
//      and privately sends the masked contribution A·s1_i + s2_i to a
//      coordinator (or broadcasts it; A·s1_i + s2_i alone does not reveal
//      s1_i/s2_i thanks to lattice hardness).
//   2. After all commitments are collected, each participant opens their
//      commitment. The coordinator aggregates t = Σ (A·s1_i + s2_i) and
//      Power2Round-splits into (t0, t1). The public key is rho + packed t1.
//   3. Each participant Shamir-splits their s1_i, s2_i, t0_i (over GF(Q))
//      and privately sends one share of each to every other participant.
//   4. Each participant finalizes by collecting threshold shares from
//      others, yielding their own (s1_share, s2_share, t0_share) WITHOUT
//      ever seeing any other participant's full s1_i/s2_i/t0_i.
//
// In this protocol, NO single process ever holds the aggregated s1, s2, t0
// in plaintext — only the per-participant shards. The TSSManager on each
// validator node holds only ITS OWN share, not all shares.
//
// This file defines the integration interface for that future P2P DKG.
// The actual P2P transport (gossipsub rounds, signed messages, replay
// protection) is NOT YET IMPLEMENTED. Until it is, callers must use
// GenerateDKGDistributedSimulated, which documents the trusted-dealer
// caveat honestly.
//
// NOTE: This interface is intentionally distinct from
// consensus.DistributedDKGRunner (provinces.go). The consensus-level runner
// is a high-level epoch-keyed abstraction used by the executive chamber.
// This qtd-level runner is the low-level multi-round protocol that the
// consensus runner (implemented in node/) will internally invoke.
// ============================================================================

// ErrDistributedDKGNotImplemented is returned by the default (placeholder)
// DistributedDKGRunner implementation. Production code MUST inject a real
// P2P runner via SetDistributedDKGRunner; the placeholder exists only so
// that callers fail-closed with a clear error rather than silently falling
// back to the simulated single-process path.
var ErrDistributedDKGNotImplemented = errors.New(
	"distributed DKG runner not injected: real P2P DKG transport is not yet " +
		"implemented; until then, callers must use GenerateDKGDistributedSimulated " +
		"and acknowledge the trusted-dealer caveat (TSS-R7-01)")

// Round1CommitmentMessage is the broadcast payload of DKG Round 1.
//
// R43-VSS: Commitment is no longer a SHA256 digest of (s1_i ‖ s2_i) that is
// later opened in plaintext. Instead it is a Pedersen VSS commitment set
// (Feldman variant with hiding) that commits to EVERY Shamir coefficient of
// the s1_i/s2_i split polynomials WITHOUT revealing them. Each participant
// therefore distributes Shamir shares of their secret in Round 2 and the
// recipient verifies the received share against this commitment set, so no
// single participant ever sees another participant's full s1_i/s2_i.
//
// Commitment set wire format:
//
//	[4B s1PolyCount uint32 LE][4B s2PolyCount uint32 LE][4B threshold uint32 LE]
//	[32B sessionID]
//	[48B BLS12-381 G1 Pedersen commitment point] × ((s1PolyCount+s2PolyCount)·N·threshold)
//
// Points are ordered [poly][coeff][j] (j = Shamir coefficient index, j=0 is the
// secret). A commitment C_{p,c,j} = g^{coeff}·h^{blind} binds coefficient j of
// the Shamir polynomial for (poly p, coeff c) while hiding it (random blind).
type Round1CommitmentMessage struct {
	ParticipantID int
	// Commitment is the Pedersen VSS commitment set described above. The
	// opening (the split polynomials and blinds) is kept private and never
	// transmitted in plaintext.
	Commitment []byte
	// PubContribution is A·s1_i + s2_i in packed form — the public
	// contribution to t = Σ (A·s1_i + s2_i). This is safe to broadcast
	// because recovering s1_i from A·s1_i is the SIS problem (lattice-hard).
	PubContribution []byte
}

// Round1OpenMessage is the Round 2 distribution of a participant's Shamir
// shares of s1_i/s2_i/t0_i plus the blind shares needed to verify them
// against the Round 1 Pedersen VSS commitment set.
//
// R43-VSS: The old CommitmentOpening field (which sent the full s1_i ‖ s2_i
// in plaintext to every participant, letting any single participant recover
// s1 = Σ s1_i) has been removed. The recipient now verifies the received
// secret share against the sender's commitment set using the accompanying
// blind share; it can never recover the sender's full secret.
type Round1OpenMessage struct {
	ParticipantID int
	// S1ShareShares is a map from recipient participant ID to that
	// recipient's Shamir share of the sender's s1_i. Each share is a
	// packed PolyVec over GF(Q). The coordinator (or each recipient)
	// aggregates threshold shares to compute their own s1_share.
	S1ShareShares map[int][]byte
	// S2ShareShares is analogous to S1ShareShares but for s2_i.
	S2ShareShares map[int][]byte
	// T0ShareShares is analogous to S1ShareShares but for t0_i. t0 is
	// public (derivable from the aggregated t), so it needs no hiding and
	// carries no blind share.
	T0ShareShares map[int][]byte
	// S1BlindShares is a map from recipient participant ID to that
	// recipient's Pedersen blind share for s1. Per (poly, coeff) entry it
	// holds the blind polynomial evaluated at the recipient's x coordinate
	// (32 bytes, big-endian mod curve order). Used together with
	// S1ShareShares to verify against the Round 1 commitment set.
	S1BlindShares map[int][]byte
	// S2BlindShares is analogous to S1BlindShares but for s2_i.
	S2BlindShares map[int][]byte
}

// Round2AckMessage acknowledges receipt of Round 2 share-shares and
// attests that they are consistent with the Round 1 commitment.
type Round2AckMessage struct {
	ParticipantID int
	// FromParticipant is the sender of the shares being acknowledged.
	FromParticipant int
	// Verified is true if the recipient verified that the shares they
	// received match the sender's Round 1 commitment. If any participant
	// reports Verified=false, the DKG round is aborted.
	Verified bool
}

// DKGResult is the output of a successful distributed DKG round.
// Each participant receives their OWN share — NOT all shares.
type DKGResult struct {
	// GroupPublicKey is the Dilithium3 group public key (rho + packed t1).
	// All participants receive the same value.
	GroupPublicKey *QTDPublicKey
	// MyShare is THIS participant's QTDShare. Each participant receives a
	// DIFFERENT share — the defining property of distributed DKG.
	MyShare *QTDShare
}

// DistributedDKGRunner is the integration interface for real multi-round
// P2P distributed DKG. Implementations live in node/ (the integration layer)
// and wrap a P2P transport (gossipsub or direct peer-to-peer messages).
//
// Protocol phases (minimum 3 communication rounds):
//
//  1. InitiateRound1 — local sampling of (s1_i, s2_i), Pedersen commitment,
//     and broadcast of Round1CommitmentMessage to all participants.
//  2. SubmitCommitment — receive another participant's Round1CommitmentMessage.
//  3. VerifyCommitment — verify the Pedersen commitment is well-formed.
//  4. InitiateRound2 — open the commitment and distribute Shamir shares of
//     s1_i/s2_i/t0_i to each recipient (Round1OpenMessage).
//  5. SubmitShare — receive another participant's Round1OpenMessage and
//     extract the share destined for THIS participant.
//  6. Finalize — aggregate received shares into MyShare and verify against
//     the group public key.
//
// SECURITY INVARIANTS implementations MUST uphold:
//
//   - The full s1_i, s2_i, t0_i NEVER leave the originating participant's
//     process. Only Shamir SHARES of them traverse the network.
//   - CombinedSeed in the resulting QTDPublicKey MUST be nil.
//   - threshold >= 2 is enforced (a 1-of-n DKG defeats the threshold goal).
//   - All P2P messages are sender-authenticated (dilithium3-signed) and
//     replay-protected (epoch + sessionID binding).
//
// Until a real implementation is injected, callers MUST use
// GenerateDKGDistributedSimulated and acknowledge the trusted-dealer caveat.
type DistributedDKGRunner interface {
	// InitiateRound1 starts the DKG protocol. The participant samples
	// s1_i/s2_i locally, computes A·s1_i + s2_i, builds a Pedersen
	// commitment, and returns the Round1CommitmentMessage to broadcast.
	//
	// The threshold and totalParticipants are agreed out-of-band
	// (typically from the consensus-layer validator set for the epoch).
	InitiateRound1(participantID, threshold, totalParticipants int) (*Round1CommitmentMessage, error)

	// SubmitCommitment ingests a Round1CommitmentMessage from another
	// participant. The runner stores it pending Round 2 opening.
	SubmitCommitment(msg *Round1CommitmentMessage) error

	// VerifyCommitment verifies the Pedersen commitment is well-formed
	// (correct length, valid group elements, etc.). Does NOT verify the
	// opening — that happens after InitiateRound2.
	VerifyCommitment(msg *Round1CommitmentMessage) error

	// InitiateRound2 opens THIS participant's Round 1 commitment and
	// distributes Shamir shares of s1_i/s2_i/t0_i to each recipient.
	// Returns the Round1OpenMessage to send to each recipient (the map
	// is keyed by recipient participant ID).
	InitiateRound2() (map[int]*Round1OpenMessage, error)

	// SubmitShare ingests a Round1OpenMessage from another participant
	// and extracts the Shamir share destined for THIS participant. The
	// share is verified against the sender's Round 1 commitment.
	SubmitShare(msg *Round1OpenMessage) error

	// Finalize aggregates received shares into MyShare, derives the
	// group public key from all participants' PubContribution values,
	// and returns the DKGResult. Returns an error if any required
	// participant's share is missing or fails verification.
	Finalize() (*DKGResult, error)

	// IsPlaceholder reports whether this runner is the default noop
	// placeholder (qtd.DefaultDistributedDKGRunner) rather than a real
	// P2P DKG implementation. Real implementations MUST return false.
	//
	// TSS-M10 (R8 2026-07-19 FIX): Used by TSSManager.HasDistributedDKGRunner
	// to honor its documented contract — "Returns false for both nil and
	// the noop placeholder runner". Without this method, HasDistributedDKGRunner
	// only checked nil, so a caller who injected DefaultDistributedDKGRunner()
	// (the placeholder) would pass the runtime guard even though no real
	// P2P transport is in place, defeating the fail-closed guarantee.
	IsPlaceholder() bool
}

// noopDistributedDKGRunner is the default placeholder implementation.
// It rejects every call with ErrDistributedDKGNotImplemented so that
// callers fail-closed instead of silently using the simulated path.
type noopDistributedDKGRunner struct{}

func (noopDistributedDKGRunner) InitiateRound1(int, int, int) (*Round1CommitmentMessage, error) {
	return nil, ErrDistributedDKGNotImplemented
}
func (noopDistributedDKGRunner) SubmitCommitment(*Round1CommitmentMessage) error {
	return ErrDistributedDKGNotImplemented
}
func (noopDistributedDKGRunner) VerifyCommitment(*Round1CommitmentMessage) error {
	return ErrDistributedDKGNotImplemented
}
func (noopDistributedDKGRunner) InitiateRound2() (map[int]*Round1OpenMessage, error) {
	return nil, ErrDistributedDKGNotImplemented
}
func (noopDistributedDKGRunner) SubmitShare(*Round1OpenMessage) error {
	return ErrDistributedDKGNotImplemented
}
func (noopDistributedDKGRunner) Finalize() (*DKGResult, error) {
	return nil, ErrDistributedDKGNotImplemented
}

// IsPlaceholder implements DistributedDKGRunner. The noop placeholder
// returns true so that TSSManager.HasDistributedDKGRunner correctly reports
// the absence of a real P2P DKG runner (TSS-M10, R8 2026-07-19 FIX).
func (noopDistributedDKGRunner) IsPlaceholder() bool {
	return true
}

// DefaultDistributedDKGRunner returns the placeholder runner. All methods
// return ErrDistributedDKGNotImplemented. Production code MUST inject a
// real runner (e.g., via node/tss_distributed.go) before mainnet activation.
func DefaultDistributedDKGRunner() DistributedDKGRunner {
	return noopDistributedDKGRunner{}
}
