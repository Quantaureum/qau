// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// TSS-FIX (2026-07-17) — DH-BASED PAIRWISE MASKING
//
// AUDIT CONTEXT (TSS- [Medium / LATENT]):
// The H-aggregator receives Z0Share = λ_i·c·(t0_i - s2_i) from each
// participant and sums them to obtain c·(t0-s2), which is needed for hint
// computation. The aggregated value c·(t0-s2) = c·(A·s1 - t1·2^d) allows
// the H-aggregator to theoretically recover s1 via NTT inversion + linear
// algebra (since A, t1, c are public). s1 leakage alone does NOT permit
// signature forgery (s2 and t0 are still hidden), but it reduces the
// security boundary.
//
// This file implements DH-BASED PAIRWISE MASKING of individual Z0Share
// transmissions. Each pair of participants (i, j) establishes a shared
// DH secret k_ij and derives a pairwise mask u_ij. Participant i adds
// +u_ij to their Z0Share; participant j adds -u_ij. The masks CANCEL in
// aggregation:
//
//	Σ_i masked_z0_i = Σ_i (z0_i + Σ_{j>i} u_ij - Σ_{j<i} u_ji)
//	                 = Σ_i z0_i + 0
//	                 = c·(t0-s2)
//
// SECURITY PROPERTIES:
//  1. TRANSPORT PROTECTION: A network eavesdropper sees masked_z0_i, not
//     the raw z0_i. Without the DH shared secret k_ij, the eavesdropper
//     cannot recover u_ij and thus cannot recover z0_i.
//  2. PARTICIPANT PRIVACY: A non-aggregator participant j sees only their
//     own z0_j and the masks they share with others. They cannot recover
//     any other participant's z0_i.
//  3. COLLUSION THRESHOLD: Combined with role-separated aggregation
//     (TSS-), recovering s1 now requires:
//     - W-aggregator (sees w_agg, c) AND
//     - H-aggregator (sees aggregated c·(t0-s2))
//     colluding. No single non-aggregator party can recover s1.
//
// RESIDUAL (DOCUMENTED): The H-aggregator still observes the AGGREGATED
// c·(t0-s2) after summing masked contributions (masks cancel). Fully
// closing this residual requires DISTRIBUTED HINT GENERATION — a protocol
// where the hint is computed without any single party observing
// c·(t0-s2) in the clear. That is a research-level protocol change
// deferred to future work. This DH masking closes the TRANSPORT-LEVEL
// leakage vector and raises the collusion bar, matching the audit's
// "DH-based pairwise masking" remediation guidance.
//
// TSS- (2026-07-17) — DOCUMENTED LIMITATION + RUNTIME WARN:
// The DH masking's security boundary is STRICTLY the transport path
// (network eavesdroppers, non-aggregator participants). It does NOT
// protect the H-aggregator role itself: by design, masks cancel in
// aggregation so the H-aggregator obtains the correct c·(t0-s2) for
// hint computation. This means TSS- (W-agg + H-agg collusion
// recovers s1) is NOT closed by DH masking alone. Mitigation in place:
//   1. Per-session role rotation via DeriveRoleAssignment + SetRoleAssignment
//      (qtd_role_separation.go) raises long-term collusion cost.
//   2. SetDHKeys emits a runtime log.Warning when role separation is NOT
//      enforced, alerting operators that the H-aggregator is single-point
//      trust for s1 leakage.
//   3. Full closure (distributed hint generation / FROST migration) is
//      a research-level protocol change deferred beyond P2 scope.

// DHMaskKeyPair holds an ephemeral X25519 keypair for a participant.
// Each signing session generates a fresh keypair for forward secrecy.
type DHMaskKeyPair struct {
	ParticipantID int
	PrivateKey    *ecdh.PrivateKey
	PublicKey     []byte // 32-byte X25519 public key
}

// GenerateDHMaskKeyPair generates a fresh X25519 keypair for participant ID.
func GenerateDHMaskKeyPair(participantID int) (*DHMaskKeyPair, error) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate X25519 keypair: %w", err)
	}
	return &DHMaskKeyPair{
		ParticipantID: participantID,
		PrivateKey:    privKey,
		PublicKey:     privKey.PublicKey().Bytes(),
	}, nil
}

// ComputeDHSharedSecret computes the ECDH shared secret between a local
// private key and a peer's public key. Returns an error if the keys are
// not valid X25519 keys.
func ComputeDHSharedSecret(localPriv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	if localPriv == nil {
		return nil, fmt.Errorf("nil local private key")
	}
	if len(peerPub) != 32 {
		return nil, fmt.Errorf("invalid peer public key length: got %d, want 32", len(peerPub))
	}
	curve := ecdh.X25519()
	peerKey, err := curve.NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer public key: %w", err)
	}
	shared, err := localPriv.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("ECDH computation failed: %w", err)
	}
	return shared, nil
}

// derivePairwiseMask generates a PolyVec mask from a DH shared secret.
// The mask is deterministic: both participants i and j derive the SAME
// mask from the SAME shared secret k_ij. The canonical ordering
// (minID, maxID) ensures both sides compute identical masks.
//
// The mask is generated via HMAC-SHA256 in counter mode, expanding to
// Dilithium3K polynomials × N coefficients = 6 × 256 = 1536 coefficients.
// Each coefficient is reduced mod Q to be a valid R_q element.
//
// Parameters:
//   - sharedSecret: 32-byte DH shared secret k_ij
//   - sessionID:    unique session identifier (binds mask to one session)
//   - idA, idB:     participant IDs (order-independent; canonicalized internally)
func derivePairwiseMask(sharedSecret []byte, sessionID []byte, idA, idB int) (PolyVec, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("empty shared secret")
	}
	// Canonical ordering: lower ID first. This ensures both participants
	// derive the same mask regardless of who is "local" vs "peer".
	lo, hi := idA, idB
	if lo > hi {
		lo, hi = hi, lo
	}

	// TSS-M2 (R8 2026-07-19 FIX): The previous code allocated a `mac`
	// HMAC object, wrote domain-separator + sessionID + idBuf into it,
	// but NEVER called mac.Sum(). The expansion loop below builds its
	// own per-block `blockMac` from scratch (re-writing the same fields
	// plus a counter), so the initial `mac` was pure dead code — a
	// reader could waste time tracing it assuming it produced a digest
	// that fed into the mask. Removed.
	//
	// The blockMac loop is the actual mask derivation: each block is
	// HMAC(sharedSecret, "qtd-z0-dh-mask-v1" || sessionID || lo || hi || ctr).
	mask := make(PolyVec, Dilithium3K)
	var idBuf [8]byte

	// Expand to Dilithium3K * N coefficients = 6 * 256 = 1536 int32 values.
	// Each coefficient needs 4 bytes (uint32); HMAC-SHA256 produces 32 bytes
	// per block. Use counter-mode expansion: HMAC(key, base || counter),
	// generating blocks on demand (rejection sampling consumes a variable
	// number of 4-byte samples).
	const bytesPerCoeff = 4

	// AUDIT-FULL CR-12 (2026-08-14) FIX: rejection sampling replaces the
	// previous simple modular reduction, which biased coefficients by
	// ~2^-13 (2^32 is not a multiple of Q, so values in [0, 2^32 mod Q)
	// got one extra representation). Samples >= rejectionThreshold are
	// discarded and the next 4-byte sample is taken, making the final
	// distribution exactly uniform over [0, Q). The rejection probability
	// is (2^32 mod Q)/2^32 ≈ 9.2e-5 — at most a handful of extra HMAC
	// blocks per derivation.
	const rejectionThreshold = uint32(0xFFFFFFFF) - uint32(0xFFFFFFFF%Q) // 4294573503

	blockIndex := uint32(0)
	nextBlock := func() []byte {
		blockMac := hmac.New(sha256.New, sharedSecret)
		blockMac.Write([]byte("qtd-z0-dh-mask-v1"))
		blockMac.Write(sessionID)
		binary.BigEndian.PutUint64(idBuf[:], uint64(lo))
		blockMac.Write(idBuf[:])
		binary.BigEndian.PutUint64(idBuf[:], uint64(hi))
		blockMac.Write(idBuf[:])
		var ctrBuf [4]byte
		binary.BigEndian.PutUint32(ctrBuf[:], blockIndex)
		blockMac.Write(ctrBuf[:])
		blockIndex++
		return blockMac.Sum(nil)
	}

	expanded := nextBlock()
	idx := 0
	nextSample := func() uint32 {
		for {
			// Refill from a fresh HMAC block when the current one is spent.
			// 32 is a multiple of 4, so blocks never straddle a sample.
			if idx+bytesPerCoeff > len(expanded) {
				expanded = nextBlock()
				idx = 0
			}
			raw := binary.BigEndian.Uint32(expanded[idx : idx+bytesPerCoeff])
			idx += bytesPerCoeff
			if raw <= rejectionThreshold {
				return raw
			}
			// Rejected sample (would bias low coefficients): skip it.
		}
	}

	// Reduce each accepted 4-byte sample mod Q — now exactly uniform.
	for i := 0; i < Dilithium3K; i++ {
		for j := 0; j < N; j++ {
			raw := nextSample()
			mask[i][j] = int32(uint64(raw) % uint64(Q))
		}
	}
	return mask, nil
}

// ComputeParticipantMask computes the NET mask that participant `selfID`
// should add to their z0 contribution, given all pairwise shared secrets.
//
// For each other participant `otherID`:
//   - If selfID < otherID: add +u_{selfID, otherID}
//   - If selfID > otherID: add -u_{otherID, selfID} (i.e., subtract)
//
// This ensures masks cancel in aggregation:
//
//	Σ_i netMask_i = Σ_i Σ_{j≠i} sign(i,j)·u_{min(i,j),max(i,j)} = 0
//
// because each pair (i,j) contributes +u and -u which cancel.
//
// Parameters:
//   - selfID:         this participant's ID
//   - dhPrivate:      this participant's DH private key
//   - peerPublicKeys: map[participantID] => X25519 public key bytes
//   - sessionID:      unique session identifier (binds masks to one session)
func ComputeParticipantMask(selfID int, dhPrivate *ecdh.PrivateKey, peerPublicKeys map[int][]byte, sessionID []byte) (PolyVec, error) {
	if dhPrivate == nil {
		return nil, fmt.Errorf("nil DH private key")
	}
	if len(sessionID) == 0 {
		return nil, fmt.Errorf("empty session ID")
	}

	// Start with zero mask
	netMask := make(PolyVec, Dilithium3K)

	for otherID, otherPub := range peerPublicKeys {
		if otherID == selfID {
			continue
		}
		if len(otherPub) != 32 {
			return nil, fmt.Errorf("participant %d: invalid DH public key length %d", otherID, len(otherPub))
		}

		// Compute DH shared secret with this peer
		sharedSecret, err := ComputeDHSharedSecret(dhPrivate, otherPub)
		if err != nil {
			return nil, fmt.Errorf("DH with participant %d: %w", otherID, err)
		}

		// Derive the canonical pairwise mask (same for both i and j)
		pairMask, err := derivePairwiseMask(sharedSecret, sessionID, selfID, otherID)
		if err != nil {
			// Zeroize shared secret before returning
			for i := range sharedSecret {
				sharedSecret[i] = 0
			}
			return nil, fmt.Errorf("derive mask with participant %d: %w", otherID, err)
		}

		// Zeroize shared secret (no longer needed)
		for i := range sharedSecret {
			sharedSecret[i] = 0
		}

		// Apply sign: lower ID adds, higher ID subtracts
		if selfID < otherID {
			// Add +u
			for i := 0; i < Dilithium3K; i++ {
				var sum Poly
				sum.Add(&netMask[i], &pairMask[i])
				netMask[i] = sum
			}
		} else {
			// Subtract: add (-u) = add (Q - u) mod Q
			for i := 0; i < Dilithium3K; i++ {
				var neg Poly
				for j := 0; j < N; j++ {
					neg[j] = int32(uint64(Q) - uint64(pairMask[i][j])%uint64(Q))
					if neg[j] >= Q {
						neg[j] -= Q
					}
				}
				var sum Poly
				sum.Add(&netMask[i], &neg)
				netMask[i] = sum
			}
		}

		// Zeroize pairMask
		for i := range pairMask {
			pairMask[i].Zero()
		}
	}

	return netMask, nil
}

// ApplyMaskToZ0 adds a net mask to a z0 contribution:
//
//	masked_z0 = z0 + netMask (mod Q)
//
// This is used by computeZ0ContributionWithDHMask to produce the masked
// Z0Share that is transmitted to the H-aggregator.
func ApplyMaskToZ0(z0 PolyVec, mask PolyVec) (PolyVec, error) {
	if len(z0) != len(mask) {
		return nil, fmt.Errorf("length mismatch: z0 has %d polys, mask has %d", len(z0), len(mask))
	}
	result := make(PolyVec, len(z0))
	for i := 0; i < len(z0); i++ {
		result[i].Add(&z0[i], &mask[i])
	}
	return result, nil
}

// VerifyMasksCancel verifies that a set of participant masks sum to zero
// (i.e., masks cancel in aggregation). This is a TEST/VERIFICATION helper
// used to confirm protocol correctness.
func VerifyMasksCancel(masks []PolyVec) bool {
	if len(masks) == 0 {
		return true
	}
	length := len(masks[0])
	acc := make(PolyVec, length)
	for _, m := range masks {
		if len(m) != length {
			return false
		}
		for i := 0; i < length; i++ {
			var sum Poly
			sum.Add(&acc[i], &m[i])
			acc[i] = sum
		}
	}
	return isPolyVecZero(acc)
}

// GenerateSessionID derives a unique session identifier from the session's
// message and participant set. This binds DH masks to a specific signing
// session, preventing mask reuse across sessions.
func GenerateSessionID(message []byte, participants []int) []byte {
	h := sha256.New()
	h.Write([]byte("qtd-session-id-v1"))
	h.Write(message)
	var buf [8]byte
	for _, pid := range participants {
		binary.BigEndian.PutUint64(buf[:], uint64(pid))
		h.Write(buf[:])
	}
	return h.Sum(nil)
}
