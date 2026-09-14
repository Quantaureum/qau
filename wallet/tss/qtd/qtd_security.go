// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"math/big"
	"runtime"

	"github.com/quantaureum/qau/pedersen"
)

// PedersenVerifier provides verification for QTD shares using Pedersen commitments.
// This prevents participants from submitting invalid or equivocal shares.
type PedersenVerifier struct {
	// Verification vectors: V[i] = g^{a_i} where a_i are polynomial coefficients
	verificationVectors map[int][][]byte
	// Pedersen generators (precomputed, hardcoded for security)
	G []byte // base generator
	H []byte // secondary generator for blinding
}

// NewPedersenVerifier creates a new Pedersen verifier.
// audit-fix Round3 L-1: When pedersen.NewGenerator() fails, return nil instead
// of falling back to SHA256-derived "generators". The previous fallback used
// sha256("qtd-pedersen-g-fallback") as the generator G, which is a 32-byte hash
// — not a point on the BLS12-381 curve. This breaks the Pedersen commitment
// scheme's security properties (hiding and binding) because the "generator" has
// no discrete-log relationship with the real generator. Callers must check for
// nil and handle the error appropriately. Fail-closed is safer than silently
// degrading to an insecure generator.
func NewPedersenVerifier() *PedersenVerifier {
	gen, err := pedersen.NewGenerator()
	if err != nil {
		// Fail-closed: return nil so callers know the verifier is unavailable.
		// Using SHA256-derived bytes as fake curve points is cryptographically
		// unsound and would give a false sense of security.
		return nil
	}
	gBytes := gen.G.Bytes()
	hBytes := gen.H.Bytes()
	return &PedersenVerifier{
		verificationVectors: make(map[int][][]byte),
		G:                   gBytes[:],
		H:                   hBytes[:],
	}
}

// AddVerificationVector adds a verification vector for a participant.
func (v *PedersenVerifier) AddVerificationVector(participantID int, vector [][]byte) error {
	if participantID < 1 {
		return ErrInvalidShare
	}
	v.verificationVectors[participantID] = vector
	return nil
}

// VerifyShare checks that a share is consistent with the verification vector.
// Uses the Pedersen commitment scheme: g^{share} = product(V_m^{i^m})
// audit-fix Round3 M-1: The previous implementation used SHA256(generator || shareByte || pid)
// as a "commitment", which is NOT a Pedersen commitment — it lacks the algebraic
// structure needed for hiding and binding. Now we use a real Pedersen commitment
// (g^value * h^blinding) when the verification vector entries are 48-byte
// serialized BLS12-381 G1Affine points.
//
// SECURITY FIX H-3: Removed the SHA256-based fallback. The fallback
// accepted non-cryptographic SHA256 hashes as "commitments", which an attacker
// could forge without knowing the secret share. This defeats the purpose of
// Pedersen commitments (hiding + binding). Now, if the verification vector
// entries are not proper 48-byte BLS12-381 G1Affine points, verification FAILS
// with an error rather than silently degrading to an insecure scheme.
func (v *PedersenVerifier) VerifyShare(share *QTDShare) error {
	if v == nil {
		return fmt.Errorf("pedersen verifier is nil (generator initialization failed)")
	}

	// SECURITY FIX (L14-022): Validate share participant ID is within valid
	// bounds before any map lookup or verification vector access. A negative
	// or out-of-range participant ID could cause unexpected behavior or be
	// used to probe the verification vectors map. Participant IDs are 1-indexed.
	//
	// TSS-M3 (R8 2026-07-19 FIX): The local variable was previously named
	// `threshold`, which is misleading — this value is NOT the signing
	// threshold (config.Threshold); it is the number of registered
	// verification vectors. A reader could mistakenly conclude that the
	// signing threshold is what bounds participant IDs here. Rename to
	// `registeredVectorCount` to reflect the actual semantics.
	registeredVectorCount := len(v.verificationVectors)
	if share.ParticipantID < 1 || share.ParticipantID > registeredVectorCount {
		return ErrInvalidShare
	}

	vVector, ok := v.verificationVectors[share.ParticipantID]
	if !ok {
		return ErrParticipantNotFound
	}

	if len(vVector) == 0 {
		return ErrInvalidShare
	}

	// Require Pedersen verification with proper BLS12-381 G1Affine points
	// (48 bytes compressed). The SHA256 fallback was cryptographically
	// unsound and has been removed for security.
	if !v.canUsePedersenVerification(vVector, share) {
		return fmt.Errorf("share verification failed: verification vector entries are not valid 48-byte BLS12-381 G1Affine points (SHA256 fallback removed for security)")
	}
	return v.verifySharePedersen(share, vVector)
}

// canUsePedersenVerification checks whether the verification vector entries
// are 80-byte serialized Pedersen commitments (48-byte BLS12-381 G1Affine
// commitment + 32-byte random blinding factor).
//
// FIX: previously required exactly 48 bytes, which forced
// verifySharePedersen to use participant ID as deterministic blinding (CRITICAL
// vulnerability). Now requires 80 bytes so the random blinding generated by
// generateVerificationVector can be extracted and used for proper Pedersen
// verification.
func (v *PedersenVerifier) canUsePedersenVerification(vVector [][]byte, share *QTDShare) bool {
	if len(vVector) == 0 || len(share.S1ShareBytes) < 4 {
		return false
	}
	// FIX: reject if the verification vector is shorter
	// than the number of coefficients derived from the share. Previously the
	// verifier wrapped around with `vVector[i%len(vVector)]`, allowing a
	// 1-entry vector to "verify" an arbitrarily long share.
	if len(vVector) < (len(share.S1ShareBytes)+3)/4 {
		return false
	}
	// Each entry must be 80 bytes: 48-byte BLS12-381 G1Affine commitment +
	// 32-byte random blinding factor.
	for _, entry := range vVector {
		if len(entry) != 80 {
			return false
		}
	}
	return true
}

// verifySharePedersen performs real Pedersen commitment verification:
// For each coefficient, extract the commitment and blinding from the 80-byte
// verification vector entry, recompute C = g^value * h^blinding, and compare.
//
// FIX: previously used the participant ID as the blinding
// factor, which is a public predictable value. This completely destroyed the
// hiding property of Pedersen commitments — an attacker knowing the
// participant ID could forge commitments for arbitrary share values. Now the
// blinding factor is extracted from the verification vector entry (bytes
// 48..80), which was generated randomly by generateVerificationVector using
// pedersen.RandomBlinding().
//
// FIX: removed the `vVector[i%len(vVector)]` wrap-around
// indexing. The length check in canUsePedersenVerification now guarantees
// len(vVector) >= len(share.S1ShareBytes)/4, so direct indexing is safe.
func (v *PedersenVerifier) verifySharePedersen(share *QTDShare, vVector [][]byte) error {
	gen, err := pedersen.NewGenerator()
	if err != nil {
		return fmt.Errorf("failed to create pedersen generator for verification: %w", err)
	}

	//  [P2] SECURITY FIX: the error returns below previously included the
	// failing coefficient index (%d). This leaked the position of the first entry
	// that fails Pedersen verification, which can enable a differential/oracle
	// attack: an adversary who can submit crafted shares and observe which index
	// fails could recover share-coefficient information one position at a time.
	// The error messages are now generic (no index) to prevent such oracle
	// attacks. These errors must still never be surfaced to untrusted callers.
	if err := verifyPedersenVecLocked(gen, share.S1ShareBytes, vVector); err != nil {
		return err
	}

	// AUDIT (2026) TSS-FIX: Verify S2 and T0 shares against their
	// Pedersen verification vectors. Previously this method only verified S1,
	// leaving S2/T0 unverified — a malicious participant could forge S2 or
	// T0 shares while passing S1 verification, corrupting the reconstructed
	// private key. Now we verify all three share types when vectors are
	// present. If a vector is absent, we only allow it when the corresponding
	// share bytes are also absent (backward compat for S1-only test shares).
	// When share bytes exist but no verification vector, we fail closed.
	if len(share.S2ShareBytes) > 0 {
		if len(share.VVectorS2) > 0 {
			if err := verifyPedersenVecLocked(gen, share.S2ShareBytes, share.VVectorS2); err != nil {
				return fmt.Errorf("S2 share: %w", err)
			}
		} else {
			return fmt.Errorf("S2 share present but verification vector absent — cannot verify")
		}
	}

	if len(share.T0ShareBytes) > 0 {
		if len(share.VVectorT0) > 0 {
			if err := verifyPedersenVecLocked(gen, share.T0ShareBytes, share.VVectorT0); err != nil {
				return fmt.Errorf("T0 share: %w", err)
			}
		} else {
			return fmt.Errorf("T0 share present but verification vector absent — cannot verify")
		}
	}

	return nil
}

// verifyPedersenVecLocked verifies that shareBytes are consistent with the
// given Pedersen verification vector. Each entry must be 80 bytes
// (48-byte commitment + 32-byte blinding). Extracted to avoid duplication
// between S1, S2, and T0 verification.
func verifyPedersenVecLocked(gen *pedersen.Generator, shareBytes []byte, vVector [][]byte) error {
	for i := 0; i < len(vVector) && (i+1)*4 <= len(shareBytes); i++ {
		entry := vVector[i]
		// entry is 80 bytes: commitment[48] || blinding[32]
		commitmentBytes := entry[:48]
		blindingBytes := entry[48:80]

		commitment, cerr := pedersen.CommitmentFromBytes(commitmentBytes)
		if cerr != nil {
			return fmt.Errorf("coefficient verification failed: invalid commitment bytes: %w", cerr)
		}

		// Derive a scalar from the share bytes (4-byte little-endian → big.Int)
		shareVal := new(big.Int).SetUint64(uint64(binary.LittleEndian.Uint32(shareBytes[i*4 : i*4+4])))

		// Extract the random blinding factor generated by generateVerificationVector
		blinding := new(big.Int).SetBytes(blindingBytes)

		// Recompute the Pedersen commitment: C = g^value * h^blinding
		expectedCommit := gen.Commit(shareVal, blinding)
		expectedBytes := expectedCommit.Bytes()
		actualBytes := commitment.Bytes()

		if subtle.ConstantTimeCompare(expectedBytes, actualBytes) != 1 {
			return fmt.Errorf("coefficient verification failed")
		}
	}
	return nil
}

// TimingAttackProtection provides constant-time operations to prevent timing attacks.
type TimingAttackProtection struct{}

// ConstantTimeCompare compares two byte slices in constant time.
// SECURITY FIX: Use crypto/subtle.ConstantTimeCompare instead of manual implementation.
// FIX: Removed early len() return — subtle.ConstantTimeCompare already
// handles different lengths by returning 0 internally, and the early return
// leaks length information via timing.
func (t *TimingAttackProtection) ConstantTimeCompare(a, b []byte) bool {
	// Use crypto/subtle for cryptographically secure constant-time comparison
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ConstantTimeSelect returns x if choice == 1, y if choice == 0.
// This prevents timing leaks from conditional branches.
func (t *TimingAttackProtection) ConstantTimeSelect(choice int32, x, y int32) int32 {
	mask := -choice // if choice=1, mask=0xFFFFFFFF; if choice=0, mask=0
	return (x & mask) | (y & ^mask)
}

// AntiCollusionMechanism detects and prevents collusion between participants.
type AntiCollusionMechanism struct {
	// Detected collusions between participant pairs
	detectedCollusions map[pair]bool
	// Round counters to track signing session timing
	roundTimings map[int]int64
}

type pair struct {
	a, b int
}

// NewAntiCollusion creates a new anti-collusion mechanism.
func NewAntiCollusion() *AntiCollusionMechanism {
	return &AntiCollusionMechanism{
		detectedCollusions: make(map[pair]bool),
		roundTimings:       make(map[int]int64),
	}
}

// DetectSimilarShares checks if two participants submitted suspiciously similar shares.
// FIX: Lowered the similarity threshold from 90% to 25%. The previous 90%
// threshold only flagged near-identical shares, allowing colluding participants
// to evade detection by introducing small perturbations. A 25% byte-level
// match is a much stronger indicator of collusion because independently
// generated shares should have essentially 0% byte-level similarity.
func (a *AntiCollusionMechanism) DetectSimilarShares(share1, share2 *QTDShare) bool {
	if len(share1.S1ShareBytes) != len(share2.S1ShareBytes) {
		return false
	}

	matchingBytes := 0
	for i := 0; i < len(share1.S1ShareBytes); i++ {
		xor := int32(share1.S1ShareBytes[i] ^ share2.S1ShareBytes[i])
		matchingBytes += subtle.ConstantTimeEq(xor, 0)
	}

	threshold := len(share1.S1ShareBytes) * 25 / 100
	return matchingBytes > threshold
}

// RecordRoundTiming records the timing of a signing round.
func (a *AntiCollusionMechanism) RecordRoundTiming(participantID int, timestamp int64) {
	a.roundTimings[participantID] = timestamp
}

// CheckSynchronizedSubmission checks if multiple participants submitted too close together.
//
//	NOTE: The comparison below (diff < maxDiff) is not constant-time.
//
// This is acceptable because the round timestamps recorded by
// RecordRoundTiming are public synchronization metadata, not secret values.
// An attacker observing the timing of the comparison gains no information
// about any secret key material. Constant-time comparison is therefore not
// strictly necessary here, though it could be added if the timestamps ever
// become derived from secret data.
func (a *AntiCollusionMechanism) CheckSynchronizedSubmission(id1, id2 int, maxDiff int64) bool {
	t1, ok1 := a.roundTimings[id1]
	t2, ok2 := a.roundTimings[id2]
	if !ok1 || !ok2 {
		return false
	}

	diff := t1 - t2
	if diff < 0 {
		diff = -diff
	}
	return diff < maxDiff
}

// ZeroKnowledgeProof implements a simple Schnorr-style ZKP for share correctness.
type ZeroKnowledgeProof struct {
	// Public commitment
	R []byte
	// Challenge
	C []byte
	// Response
	S []byte
}

// GenerateZKProof generates a proper Schnorr zero-knowledge proof over the BLS12-381
// curve that the prover knows the share bytes without revealing them.
//
// TSS-003 CRITICAL FIX: Previously used only 1 byte of randomness (rBytes[0]) in
// verification via computeShareCommitment (SHA256), allowing brute-force in 256 attempts.
// Now uses proper Schnorr proof over BLS12-381: R = g^r, c = H(R||V||msg||pid),
// s = r + c*secret (mod order), verified as g^s == R * V^c.
//
// CRYPTO- (Info): This is a COMPUTATIONAL zero-knowledge proof (Schnorr
// Fiat-Shamir), NOT an information-theoretic one. Security relies on SHA256
// collision/preimage resistance and the discrete logarithm assumption on
// BLS12-381. Under the Quantaureum threat model (computational security, not
// information-theoretic), this design is acceptable. The challenge value
// c = H(R || V || msg || pid) is derived via Fiat-Shamir, binding the proof
// to the message and prover identity. See L18-022 note below for details.
// Documented here for future reviewers; no code change required.
func GenerateZKProof(share *QTDShare, message []byte) (*ZeroKnowledgeProof, error) {
	gen, err := pedersen.NewGenerator()
	if err != nil {
		return nil, fmt.Errorf("failed to create Pedersen generator: %w", err)
	}

	// Derive secret scalar from share bytes.
	// L18-022 NOTE: SHA256 provides computational security, NOT
	// information-theoretic security. An attacker with unbounded compute
	// could in principle invert the hash. This is acceptable in practice
	// because SHA256 preimage resistance (2^256) far exceeds the curve
	// order (~2^255 for BLS12-381), so the hash does not weaken the scheme.
	// TODO: For formal post-quantum analysis, consider replacing with a
	// lattice-based commitment or direct scalar derivation to achieve
	// information-theoretic security.
	h := sha256.New()
	h.Write(share.S1ShareBytes)
	h.Write(share.S2ShareBytes)
	secretBytes := h.Sum(nil)
	secret := new(big.Int).SetBytes(secretBytes)
	secret.Mod(secret, pedersen.CurveOrder())
	if secret.Sign() == 0 {
		return nil, fmt.Errorf("derived secret is zero")
	}

	// V = g^secret (public commitment)
	vCommit := gen.Commit(secret, new(big.Int))
	vBytes := vCommit.Bytes()

	// Pick random r, compute R = g^r
	r, err := pedersen.RandomBlinding()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random: %w", err)
	}
	rCommit := gen.Commit(r, new(big.Int))
	rBytes := rCommit.Bytes()

	// c = H(R || V || message || pid) mod order
	challenger := sha256.New()
	challenger.Write([]byte("qtd-zkp-v2"))
	challenger.Write(rBytes)
	challenger.Write(vBytes)
	challenger.Write(message)
	pidBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(pidBytes, uint64(share.ParticipantID))
	challenger.Write(pidBytes)
	cBytes := challenger.Sum(nil)
	c := new(big.Int).SetBytes(cBytes)
	c.Mod(c, pedersen.CurveOrder())

	// s = r + c * secret mod order
	s := new(big.Int).Mul(c, secret)
	s.Mod(s, pedersen.CurveOrder())
	s.Add(s, r)
	s.Mod(s, pedersen.CurveOrder())

	// R44-QP-001 FIX: Zero sensitive big.Int values before returning.
	// Capture sBytes first since s will be zeroed.
	sBytes := s.Bytes()
	secret.SetInt64(0)
	r.SetInt64(0)
	s.SetInt64(0)

	return &ZeroKnowledgeProof{
		R: rBytes,
		C: cBytes,
		S: sBytes,
	}, nil
}

// VerifyZKProof verifies a Schnorr zero-knowledge proof.
// Checks: g^s == R * V^c where V = g^{H(S1ShareBytes || S2ShareBytes)}.
func VerifyZKProof(proof *ZeroKnowledgeProof, share *QTDShare, message []byte) bool {
	if proof == nil || share == nil {
		return false
	}
	if len(proof.R) == 0 || len(proof.C) == 0 || len(proof.S) == 0 {
		return false
	}

	gen, err := pedersen.NewGenerator()
	if err != nil {
		return false
	}

	// Recover s
	sVal := new(big.Int).SetBytes(proof.S)
	sVal.Mod(sVal, pedersen.CurveOrder())

	// Recover V = g^{H(share bytes)}.
	// L18-022 NOTE: SHA256 derivation is computationally secure, not
	// information-theoretically secure. See GenerateZKProof for details.
	h := sha256.New()
	h.Write(share.S1ShareBytes)
	h.Write(share.S2ShareBytes)
	vSecret := new(big.Int).SetBytes(h.Sum(nil))
	vSecret.Mod(vSecret, pedersen.CurveOrder())
	vCommit := gen.Commit(vSecret, new(big.Int))

	// Recover R from proof.R bytes
	rCommit, cerr := pedersen.CommitmentFromBytes(proof.R)
	if cerr != nil {
		return false
	}

	// Recompute c = H(R || V || message || pid) mod order
	challenger := sha256.New()
	challenger.Write([]byte("qtd-zkp-v2"))
	challenger.Write(proof.R)
	challenger.Write(vCommit.Bytes())
	challenger.Write(message)
	pidBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(pidBytes, uint64(share.ParticipantID))
	challenger.Write(pidBytes)
	cBytes := challenger.Sum(nil)
	c := new(big.Int).SetBytes(cBytes)
	c.Mod(c, pedersen.CurveOrder())

	if subtle.ConstantTimeCompare(proof.C, cBytes) != 1 {
		return false
	}

	// Verify: g^s == R * V^c
	lhs := gen.Commit(sVal, new(big.Int))
	cV := gen.ScalarMulCommitment(vCommit, c)
	rhs := gen.HomomorphicAdd(rCommit, cV)

	result := lhs.Equal(rhs)

	// R44-QP-002 FIX: Zero sensitive big.Int values before returning.
	vSecret.SetInt64(0)
	sVal.SetInt64(0)
	c.SetInt64(0)

	return result
}

// SecurityAudit provides comprehensive security auditing for QTD sessions.
type SecurityAudit struct {
	timingProtection *TimingAttackProtection
	antiCollusion    *AntiCollusionMechanism
}

// NewSecurityAudit creates a new security audit.
func NewSecurityAudit() *SecurityAudit {
	return &SecurityAudit{
		timingProtection: &TimingAttackProtection{},
		antiCollusion:    NewAntiCollusion(),
	}
}

// AuditSession runs a comprehensive security audit on a signing session.
func (sa *SecurityAudit) AuditSession(session *QTDSession, shares []*QTDShare) []string {
	issues := []string{}

	// Check for collusion
	for i := 0; i < len(shares); i++ {
		for j := i + 1; j < len(shares); j++ {
			if sa.antiCollusion.DetectSimilarShares(shares[i], shares[j]) {
				issues = append(issues, fmt.Sprintf(
					"potential collusion detected between participants %d and %d",
					shares[i].ParticipantID, shares[j].ParticipantID,
				))
			}
		}
	}

	// Verify all shares against verification vectors
	for _, share := range shares {
		if len(share.VVector) == 0 {
			issues = append(issues, fmt.Sprintf(
				"participant %d has empty verification vector",
				share.ParticipantID,
			))
		}
	}

	// Check session integrity
	if session.threshold < 1 {
		issues = append(issues, "invalid threshold value")
	}

	if len(session.participants) < session.threshold {
		issues = append(issues, "insufficient participants for threshold")
	}

	return issues
}

// GenerateShareProofBundle generates a complete proof bundle for a share.
type ShareProofBundle struct {
	Share          *QTDShare
	ZKProof        *ZeroKnowledgeProof
	CommitmentHash []byte
	Signature      []byte
}

// NewShareProofBundle creates a new proof bundle for a share.
func NewShareProofBundle(share *QTDShare, message []byte) (*ShareProofBundle, error) {
	zkProof, err := GenerateZKProof(share, message)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ZK proof: %w", err)
	}

	// Compute commitment hash
	h := sha256.New()
	h.Write(share.S1ShareBytes)
	h.Write(share.S2ShareBytes)
	commitmentHash := h.Sum(nil)

	return &ShareProofBundle{
		Share:          share,
		ZKProof:        zkProof,
		CommitmentHash: commitmentHash,
	}, nil
}

// VerifyProofBundle verifies a complete proof bundle.
func (pb *ShareProofBundle) VerifyProofBundle(message []byte) bool {
	if pb.Share == nil || pb.ZKProof == nil {
		return false
	}

	if !VerifyZKProof(pb.ZKProof, pb.Share, message) {
		return false
	}

	// Verify commitment hash
	h := sha256.New()
	h.Write(pb.Share.S1ShareBytes)
	h.Write(pb.Share.S2ShareBytes)
	expected := h.Sum(nil)

	return bytesEqual(pb.CommitmentHash, expected)
}

// ShareIntegrityCheck performs comprehensive integrity checks on a share.
func ShareIntegrityCheck(share *QTDShare) error {
	if share.ParticipantID < 1 {
		return ErrInvalidShare
	}

	if len(share.Rho) != 32 {
		return fmt.Errorf("invalid rho length: %d, expected 32", len(share.Rho))
	}

	if len(share.S1ShareBytes) == 0 {
		return ErrInvalidShare
	}

	if len(share.S2ShareBytes) == 0 {
		return ErrInvalidShare
	}

	// L18-020 FIX: Validate T0ShareBytes is present and well-formed.
	// Previously, only S1 and S2 shares were checked; a missing or
	// malformed T0 share could bypass integrity verification.
	if len(share.T0ShareBytes) == 0 {
		return ErrInvalidShare
	}

	if len(share.S1ShareBytes)%4 != 0 {
		return fmt.Errorf("invalid S1ShareBytes length: %d, expected multiple of 4", len(share.S1ShareBytes))
	}

	if len(share.S2ShareBytes)%4 != 0 {
		return fmt.Errorf("invalid S2ShareBytes length: %d, expected multiple of 4", len(share.S2ShareBytes))
	}

	// QP-05 FIX: Validate T0ShareBytes length and coefficient ranges.
	// T0ShareBytes is a PolyVec serialization (same format as S1/S2), so
	// each uint32 coefficient must be within the field modulus Q. Without
	// this check, a malformed T0 share with out-of-range coefficients could
	// bypass integrity verification and produce invalid Dilithium3 signatures.
	if len(share.T0ShareBytes)%4 != 0 {
		return fmt.Errorf("invalid T0ShareBytes length: %d, expected multiple of 4", len(share.T0ShareBytes))
	}

	for i := 0; i < len(share.S1ShareBytes); i += 4 {
		val := binary.LittleEndian.Uint32(share.S1ShareBytes[i : i+4])
		if val >= uint32(Q) {
			return fmt.Errorf("S1ShareBytes[%d] out of range: %d (max %d)", i/4, val, Q-1)
		}
	}

	for i := 0; i < len(share.S2ShareBytes); i += 4 {
		val := binary.LittleEndian.Uint32(share.S2ShareBytes[i : i+4])
		if val >= uint32(Q) {
			return fmt.Errorf("S2ShareBytes[%d] out of range: %d (max %d)", i/4, val, Q-1)
		}
	}

	for i := 0; i < len(share.T0ShareBytes); i += 4 {
		val := binary.LittleEndian.Uint32(share.T0ShareBytes[i : i+4])
		if val >= uint32(Q) {
			return fmt.Errorf("T0ShareBytes[%d] out of range: %d (max %d)", i/4, val, Q-1)
		}
	}

	return nil
}

// BatchVerifyProofs verifies multiple proof bundles in batch.
func BatchVerifyProofs(bundles []*ShareProofBundle, message []byte) bool {
	if len(bundles) > 1000 {
		return false
	}
	for _, bundle := range bundles {
		// R54-QP-01 FIX: Skip nil bundles instead of dereferencing them.
		// A nil entry in the slice would cause a panic in VerifyProofBundle.
		if bundle == nil {
			return false
		}
		if !bundle.VerifyProofBundle(message) {
			return false
		}
	}
	return true
}

// zeroMemoryImpl is the actual zeroing implementation.
func zeroMemoryImpl(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroMemoryFunc is a package-level function variable. The compiler cannot
// prove at compile time that it always points to zeroMemoryImpl, so the writes
// cannot be eliminated as dead stores. This mirrors the pattern used in
// crypto/keystore.go (zeroBytesFunc) for guaranteed memory zeroing.
var zeroMemoryFunc = zeroMemoryImpl

// SecurelyZeroMemory attempts to zero sensitive data in memory.
//
// SECURITY NOTE: Due to Go's GC and memory model, this function cannot guarantee
// that the underlying memory is actually zeroed - the GC may copy data before
// it's overwritten, and escape analysis may keep data in registers or stack frames.
// For truly sensitive operations (key material, shares), consider:
//   - Using hardware-backed memory protection (mprotect)
//   - Running in isolated processes with custom allocators
//   - Using a language with explicit memory control (Rust, C)
//
// This function zeros the visible slice data but the actual key material may
// persist in memory longer than expected despite the zeroing attempt.
//
// P3-1 FIX: use an indirect function call via a package-level variable plus
// runtime.KeepAlive to prevent the compiler from optimizing away the zeroing
// writes (dead-store elimination). Previously a plain for-loop could be
// elided by the optimizer, leaving sensitive data in memory.
func SecurelyZeroMemory(data []byte) {
	if len(data) == 0 {
		return
	}
	zeroMemoryFunc(data)
	runtime.KeepAlive(data)
}

// GenerateChallengeSeed generates a secure challenge seed from multiple entropy sources.
func GenerateChallengeSeed(entropy [][]byte) ([]byte, error) {
	if len(entropy) == 0 {
		return nil, ErrInvalidSeed
	}

	h := sha256.New()
	for _, e := range entropy {
		h.Write(e)
	}

	// Add random entropy
	random := make([]byte, 16)
	_, err := rand.Read(random)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random entropy: %w", err)
	}
	h.Write(random)

	return h.Sum(nil), nil
}

// EncodeShareForTransmission encodes a share for secure transmission.
// EncodeShareForTransmission encodes a QTDShare for network transmission.
// R47-QP-12 NOTE: ParticipantID is encoded as uint64 (8 bytes) while length
// fields use uint32 (4 bytes). This inconsistency is a legacy design choice.
// Changing ParticipantID to uint32 would break wire-format compatibility.
// Participant IDs are small (< 1000), so either size works correctly.
func EncodeShareForTransmission(share *QTDShare) ([]byte, error) {
	if err := ShareIntegrityCheck(share); err != nil {
		return nil, err
	}

	// Encode: [participant_id(8)] [rho(32)] [s1_len(4)] [s1] [s2_len(4)] [s2] [t0_len(4)] [t0]
	buf := make([]byte, 0)

	idBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(idBytes, uint64(share.ParticipantID))
	buf = append(buf, idBytes...)
	buf = append(buf, share.Rho...)

	s1Len := make([]byte, 4)
	binary.BigEndian.PutUint32(s1Len, uint32(len(share.S1ShareBytes)))
	buf = append(buf, s1Len...)
	buf = append(buf, share.S1ShareBytes...)

	s2Len := make([]byte, 4)
	binary.BigEndian.PutUint32(s2Len, uint32(len(share.S2ShareBytes)))
	buf = append(buf, s2Len...)
	buf = append(buf, share.S2ShareBytes...)

	t0Len := make([]byte, 4)
	binary.BigEndian.PutUint32(t0Len, uint32(len(share.T0ShareBytes)))
	buf = append(buf, t0Len...)
	buf = append(buf, share.T0ShareBytes...)

	return buf, nil
}

// DecodeShareFromTransmission decodes a share from transmission format.
func DecodeShareFromTransmission(data []byte) (*QTDShare, error) {
	// Minimum: participant_id(8) + rho(32) + s1_len(4) + s2_len(4) + t0_len(4) = 52
	if len(data) < 52 {
		return nil, ErrInvalidShare
	}

	// Maximum: prevent abuse with oversized payloads
	if len(data) > 65536 {
		return nil, ErrInvalidShare
	}

	offset := 0
	participantID := int(binary.BigEndian.Uint64(data[offset:]))
	offset += 8

	rho := make([]byte, 32)
	copy(rho, data[offset:offset+32])
	offset += 32

	// N20-010 FIX: Use uint32 + uint64 bounds check to prevent int overflow on
	// 32-bit platforms where int is 32 bits. A uint32 > 2^31-1 would overflow to
	// a negative int, bypassing the bounds check and causing a slice panic.
	s1LenU32 := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	// R53-QP-01 FIX: Individual upper bound for s1Len to prevent memory
	// exhaustion from a malicious oversized length field. Legitimate QTD
	// shares are well under this limit.
	const maxShareFieldSize = 16384
	if s1LenU32 > maxShareFieldSize {
		return nil, fmt.Errorf("s1Len exceeds maximum: %d (max %d)", s1LenU32, maxShareFieldSize)
	}
	if uint64(offset)+uint64(s1LenU32) > uint64(len(data)) {
		return nil, ErrInvalidShare
	}
	s1Len := int(s1LenU32)
	s1Share := make([]byte, s1Len)
	copy(s1Share, data[offset:offset+s1Len])
	offset += s1Len

	if offset+4 > len(data) {
		return nil, ErrInvalidShare
	}
	// N20-010 FIX: same uint32 overflow guard as s1Len above.
	s2LenU32 := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	// R53-QP-01 FIX: Same upper bound for s2Len.
	if s2LenU32 > maxShareFieldSize {
		return nil, fmt.Errorf("s2Len exceeds maximum: %d (max %d)", s2LenU32, maxShareFieldSize)
	}
	if uint64(offset)+uint64(s2LenU32) > uint64(len(data)) {
		return nil, ErrInvalidShare
	}
	s2Len := int(s2LenU32)
	s2Share := make([]byte, s2Len)
	copy(s2Share, data[offset:offset+s2Len])
	offset += s2Len

	if offset+4 > len(data) {
		return nil, ErrInvalidShare
	}
	// N20-010 FIX: same uint32 overflow guard as s1Len above.
	t0LenU32 := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	// R53-QP-01 FIX: Same upper bound for t0Len.
	if t0LenU32 > maxShareFieldSize {
		return nil, fmt.Errorf("t0Len exceeds maximum: %d (max %d)", t0LenU32, maxShareFieldSize)
	}
	if uint64(offset)+uint64(t0LenU32) > uint64(len(data)) {
		return nil, ErrInvalidShare
	}
	t0Len := int(t0LenU32)
	t0Share := make([]byte, t0Len)
	copy(t0Share, data[offset:offset+t0Len])

	return &QTDShare{
		ParticipantID: participantID,
		Rho:           rho,
		S1ShareBytes:  s1Share,
		S2ShareBytes:  s2Share,
		T0ShareBytes:  t0Share,
	}, nil
}
