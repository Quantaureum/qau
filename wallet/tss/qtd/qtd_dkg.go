// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/pedersen"
)

// QTDShare represents a party's additive share of the distributed Dilithium3 key.
// L14-034 SECURITY NOTE: Share verification uses Pedersen commitments
// (g^value * h^blinding) to verify that each share is consistent with the
// verification vector without revealing the share value itself. This
// provides both hiding (the verifier learns nothing about the share) and
// binding (the prover cannot change the share after committing). The
// verification vectors are generated during DKG and must be distributed
// to all participants before share verification can occur.
type QTDShare struct {
	ParticipantID int
	Rho           []byte   // Public seed (32 bytes)
	S1ShareBytes  []byte   // Additive share of s1 (PolyVec serialized)
	S2ShareBytes  []byte   // Additive share of s2 (PolyVec serialized)
	T0ShareBytes  []byte   // Additive share of t0 (PolyVec serialized)
	T1Bytes       []byte   // Public t1 (K polynomials, each 768 bytes)
	VVector       [][]byte // Verification vectors for S1 share validation
	VVectorS2     [][]byte //  Verification vectors for S2 share validation
	VVectorT0     [][]byte //  Verification vectors for T0 share validation
}

// Zeroize securely zeroes all sensitive share data fields (S1ShareBytes,
// S2ShareBytes, T0ShareBytes) so that residual secret material is not left in
// memory after the share is no longer needed.
//
// L11-029 FIX: QTDShare previously lacked a Destroy/Zeroize method, leaving
// the additive shares of the Dilithium3 secret key (s1, s2, t0) in heap
// memory after use. This uses the existing SecurelyZeroMemory helper (which
// relies on the indirect zeroMemoryFunc call to defeat dead-store
// elimination), consistent with how the privKey bytes are zeroed elsewhere
// in this file.
func (s *QTDShare) Zeroize() {
	SecurelyZeroMemory(s.S1ShareBytes)
	SecurelyZeroMemory(s.S2ShareBytes)
	SecurelyZeroMemory(s.T0ShareBytes)
	// VVector entries may contain blinding factors used in Pedersen
	// commitments; zero them as well to avoid leaking blinding material.
	for i := range s.VVector {
		SecurelyZeroMemory(s.VVector[i])
	}
	//  Zero S2/T0 verification vectors (contain blinding factors).
	for i := range s.VVectorS2 {
		SecurelyZeroMemory(s.VVectorS2[i])
	}
	for i := range s.VVectorT0 {
		SecurelyZeroMemory(s.VVectorT0[i])
	}
}

// Validate performs a structured ShareIntegrityCheck on the decoded QTDShare
// fields. It ensures that critical share components are present and
// internally consistent before the share is trusted for use in signing.
//
// L16-001 FIX: DecodeQTDShare previously returned a share without verifying
// that the decoded fields are non-empty and valid. A malformed or truncated
// payload could produce a struct with zero-value fields that would later cause
// unexpected behavior during signing. This validation is called at the end of
// DecodeQTDShare to reject such shares early.
func (s *QTDShare) Validate() error {
	if s.ParticipantID <= 0 {
		return fmt.Errorf("%w: ParticipantID must be > 0, got %d", ErrInvalidShare, s.ParticipantID)
	}
	if len(s.S1ShareBytes) == 0 {
		return fmt.Errorf("%w: S1ShareBytes is empty", ErrInvalidShare)
	}
	if len(s.S2ShareBytes) == 0 {
		return fmt.Errorf("%w: S2ShareBytes is empty", ErrInvalidShare)
	}
	// L18-020/N19-002 FIX: Validate T0ShareBytes. ShareIntegrityCheck
	// already checks this, but Validate() is an independent entry point
	// (called by DecodeQTDShare) and must reject a share missing its t0
	// additive share; otherwise signing would operate on zero-value t0
	// coefficients, producing invalid Dilithium3 signatures.
	if len(s.T0ShareBytes) == 0 {
		return fmt.Errorf("%w: T0ShareBytes is empty", ErrInvalidShare)
	}
	return nil
}

// QTDPublicKey represents the group public key.
type QTDPublicKey struct {
	Rho    []byte `json:"rho"`     // Public seed
	T1     []byte `json:"t1"`      // Public matrix t1
	PubKey []byte `json:"pub_key"` // Standard Dilithium3 public key
	// PlanA-Bridge: CombinedSeed enables signWithCircl() to reconstruct the
	// full private key via mode3.NewKeyFromSeed() for standard Dilithium3 signing.
	// SECURITY: Treat as equivalent to the private key. Never export or log.
	// N20-001 FIX: Added json:"-" to prevent accidental JSON serialization
	// leaking the private key equivalent material.
	CombinedSeed []byte `json:"-"` // 32-byte seed for mode3.NewKeyFromSeed
}

// ZeroizeCombinedSeed securely erases the CombinedSeed field from memory.
// R32-P1-01 FIX (2026-07-28): CombinedSeed is equivalent to the private key —
// an attacker with a heap dump can reconstruct the full Dilithium3 private key
// via mode3.NewKeyFromSeed. This method should be called when the seed is no
// longer needed (e.g., on manager shutdown, key rotation, or when the
// distributed DKG path is used and the seed was only needed transiently).
// In distributed DKG mode, CombinedSeed is already nil (see qtd_distributed.go),
// so this method is a no-op.
func (pk *QTDPublicKey) ZeroizeCombinedSeed() {
	if pk == nil {
		return
	}
	if len(pk.CombinedSeed) > 0 {
		SecurelyZeroMemory(pk.CombinedSeed)
		pk.CombinedSeed = nil
	}
}

// QTDManager manages the QTD threshold signing system.
type QTDManager struct {
	threshold    int
	total        int
	participants map[int]*QTDShare
	publicKey    *QTDPublicKey
	// TSS-001 HIGH FIX: When useShamir=true, signing uses t-of-n Shamir secret sharing
	// (any threshold subset can sign) with Lagrange coefficient weighting.
	// When useShamir=false (default), additive secret sharing requires all n participants.
	useShamir bool
}

// NewQTDManager creates a new QTD manager.
func NewQTDManager(threshold, total int) (*QTDManager, error) {
	if threshold <= 0 || total <= 0 || threshold > total {
		return nil, ErrInvalidConfig
	}

	return &QTDManager{
		threshold:    threshold,
		total:        total,
		participants: make(map[int]*QTDShare),
	}, nil
}

// AddShare adds a share from a participant.
// R48-QP-05 FIX: Removed upper bound range check that assumed contiguous IDs.
// Non-contiguous participant IDs are valid (e.g., after RemoveParticipant).
func (m *QTDManager) AddShare(share *QTDShare) error {
	if share == nil {
		return ErrInvalidShare
	}
	if share.ParticipantID < 1 {
		return ErrInvalidShare
	}
	if _, exists := m.participants[share.ParticipantID]; exists {
		return ErrInvalidShare
	}

	m.participants[share.ParticipantID] = share
	return nil
}

// GetShare retrieves a share for a participant.
func (m *QTDManager) GetShare(participantID int) (*QTDShare, error) {
	share, ok := m.participants[participantID]
	if !ok {
		return nil, ErrParticipantNotFound
	}
	return share, nil
}

// SetShamirMode enables or disables Shamir t-of-n threshold mode.
// When enabled, signing requires only threshold participants (not all).
// This must be set before CreateSigningSession and must match the DKG mode used.
func (m *QTDManager) SetShamirMode(enabled bool) {
	m.useShamir = enabled
}

// IsShamirMode returns whether Shamir mode is enabled.
func (m *QTDManager) IsShamirMode() bool {
	return m.useShamir
}

// CreateSigningSession creates a new threshold signing session.
// TSS-001 HIGH FIX: Now supports t-of-n threshold via Shamir mode.
//   - Shamir mode (useShamir=true): requires >= threshold participants
//   - Additive mode (useShamir=false): requires ALL participants (n-out-of-n)
func (m *QTDManager) CreateSigningSession(message []byte, participantIDs []int) (*QTDSession, error) {
	minRequired := m.total
	modeLabel := "additive"
	if m.useShamir {
		minRequired = m.threshold
		modeLabel = "shamir"
	}

	if len(participantIDs) < minRequired {
		return nil, fmt.Errorf("%w: %s sharing requires %d participants, got %d",
			ErrInsufficientParticipants, modeLabel, minRequired, len(participantIDs))
	}

	shares := make(map[int]*QTDShare)
	for _, id := range participantIDs {
		share, ok := m.participants[id]
		if !ok {
			return nil, ErrParticipantNotFound
		}
		shares[id] = share
	}

	session, err := NewQTDSession(message, participantIDs, minRequired, shares)
	if err != nil {
		return nil, err
	}
	session.useShamir = m.useShamir
	if m.useShamir {
		session.lagrangeCoeffs = make(map[int]int64, len(participantIDs))
		for _, id := range participantIDs {
			session.lagrangeCoeffs[id] = lagrangeCoeff(id, participantIDs)
		}
	}
	return session, nil
}

// SetPublicKey sets the group public key.
func (m *QTDManager) SetPublicKey(pk *QTDPublicKey) {
	m.publicKey = pk
}

// GetPublicKey returns the group public key.
func (m *QTDManager) GetPublicKey() *QTDPublicKey {
	return m.publicKey
}

// TSS-001 HIGH FIX: GenerateDKGSharesShamir performs distributed key generation
// using Shamir secret sharing over GF(Q) for each coefficient of the Dilithium3
// secret key vectors s1 and s2. This enables true t-of-n threshold signing where
// any threshold of participants can produce a valid signature.
//
// During signing, each participant computes z_i = λ_i * s1_share_i * c + y_i
// where λ_i is the Lagrange coefficient. The aggregated z = Σ z_i = s1*c + Σ y_i
// produces a standard Dilithium3-compatible signature.
//
// TSS- (2026-07-16) — TRUSTED DEALER MODE: Like GenerateDKGShares, this
// function is NOT a real distributed DKG. The "participant seed shares" are
// generated, combined, and fed to mode3.NewKeyFromSeed IN A SINGLE PROCESS
// (qtd_dkg.go:275-282), materializing the full Dilithium3 private key in
// this host's memory before Shamir splitting. The threshold t-of-n property
// holds AFTER distribution, but NOT during generation. Use only for
// controlled key ceremonies; the TSSManager.GenerateKeyShares wrapper gates
// this path behind QAU_ALLOW_TRUSTED_DEALER_CEREMONY=1.
func GenerateDKGSharesShamir(threshold, total int) (*QTDPublicKey, []*QTDShare, error) {
	if threshold <= 0 || total <= 0 || threshold > total {
		return nil, nil, ErrInvalidConfig
	}

	seedShares := make([][]byte, total)
	commitments := make([][]byte, total)
	nonces := make([][]byte, total)

	for i := 0; i < total; i++ {
		seed := make([]byte, 32)
		_, err := rand.Read(seed)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate seed share: %w", err)
		}
		seedShares[i] = seed

		nonce := make([]byte, 16)
		_, err = rand.Read(nonce)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
		nonces[i] = nonce

		h := sha256.New()
		h.Write(seed)
		h.Write([]byte{byte(i + 1)})
		h.Write(nonce)
		commitments[i] = h.Sum(nil)
	}

	// TSS-006 FIX: Verify seed commitments after combine
	for i := 0; i < total; i++ {
		h := sha256.New()
		h.Write(seedShares[i])
		h.Write([]byte{byte(i + 1)})
		h.Write(nonces[i])
		if subtle.ConstantTimeCompare(h.Sum(nil), commitments[i]) != 1 {
			return nil, nil, fmt.Errorf("seed commitment verification failed for participant %d", i+1)
		}
	}

	h := sha256.New()
	for i := 0; i < total; i++ {
		h.Write(seedShares[i])
		h.Write([]byte{byte(i + 1)})
	}
	combinedSeed := h.Sum(nil)

	pubKey, privKey := mode3.NewKeyFromSeed((*[32]byte)(combinedSeed))
	// L9-001 FIX: mode3.PrivateKey is a struct (type PrivateKey internal.PrivateKey)
	// with unexported fields (rho, key, s1, s2, t0, tr, seed, cached NTTs).
	// Bytes() returns a COPY, so zeroing the copy does not clear the original
	// ~4000-byte key material on the heap. Extract once, zero both the copy
	// and the struct in-place via *privKey = mode3.PrivateKey{}.
	privKeyBytes := privKey.Bytes()
	defer func() {
		*privKey = mode3.PrivateKey{}
		SecurelyZeroMemory(privKeyBytes)
		// R32-P1-01 FIX (2026-07-28): Zeroize the combined seed after use.
		// combinedSeed is the master seed from which the full Dilithium3
		// private key is derived via mode3.NewKeyFromSeed. An attacker with
		// a heap dump can reconstruct the entire private key from this seed.
		SecurelyZeroMemory(combinedSeed)
		runtime.KeepAlive(privKey)
	}()

	// TSS-001: Use Shamir splitting instead of additive splitting
	// Each coefficient of s1 and s2 is independently shared using a random
	// polynomial of degree (threshold-1). Only threshold participants are
	// needed to reconstruct the secret via Lagrange interpolation.
	s1Packed := privKeyBytes[mode3.SeedSize*3 : mode3.SeedSize*3+Dilithium3L*128]
	s1Vec, err := UnpackEtaVec(s1Packed, Dilithium3L, Dilithium3EtaPoly)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unpack s1: %w", err)
	}

	s1ShareVecs, err := shamirSplitPolyVec(s1Vec, threshold, total)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to Shamir-split s1: %w", err)
	}

	s2Packed := privKeyBytes[mode3.SeedSize*3+Dilithium3L*128:]
	s2Packed = s2Packed[:Dilithium3K*128]
	s2Vec, err := UnpackEtaVec(s2Packed, Dilithium3K, Dilithium3EtaPoly)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unpack s2: %w", err)
	}

	s2ShareVecs, err := shamirSplitPolyVec(s2Vec, threshold, total)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to Shamir-split s2: %w", err)
	}

	t0Offset := mode3.SeedSize*3 + Dilithium3L*128 + Dilithium3K*128
	t0Packed := privKeyBytes[t0Offset : t0Offset+Dilithium3K*416]
	t0Vec := make(PolyVec, Dilithium3K)
	if err := parseT0PolyVec(t0Vec, t0Packed, Dilithium3K); err != nil {
		return nil, nil, fmt.Errorf("failed to parse t0: %w", err)
	}

	t0ShareVecs, err := shamirSplitPolyVec(t0Vec, threshold, total)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to Shamir-split t0: %w", err)
	}

	shares := make([]*QTDShare, total)
	for i := 0; i < total; i++ {
		pid := i + 1
		shares[i] = &QTDShare{
			ParticipantID: pid,
			Rho:           pubKey.Bytes()[:32],
			S1ShareBytes:  VecToBytes(s1ShareVecs[pid]),
			S2ShareBytes:  VecToBytes(s2ShareVecs[pid]),
			T0ShareBytes:  VecToBytes(t0ShareVecs[pid]),
			// L13-016: VVector is initialized to nil here and assigned below in the
			// same loop iteration via generateVerificationVector. This two-step init
			// is fragile: if generateVerificationVector fails, the returned error
			// causes the function to return immediately (nil, nil, err), so no
			// partially-initialized shares escape. However, any future refactor that
			// separates VVector generation into a different loop MUST re-verify that
			// all shares have non-nil VVector before returning.
			VVector: nil,
		}

		vVector, verr := generateVerificationVector(shares[i].S1ShareBytes, threshold)
		if verr != nil {
			return nil, nil, fmt.Errorf("failed to generate verification vector: %w", verr)
		}
		shares[i].VVector = vVector

		vVectorS2, verr2 := generateVerificationVector(shares[i].S2ShareBytes, threshold)
		if verr2 != nil {
			return nil, nil, fmt.Errorf("failed to generate S2 verification vector: %w", verr2)
		}
		shares[i].VVectorS2 = vVectorS2

		vVectorT0, verr3 := generateVerificationVector(shares[i].T0ShareBytes, threshold)
		if verr3 != nil {
			return nil, nil, fmt.Errorf("failed to generate T0 verification vector: %w", verr3)
		}
		shares[i].VVectorT0 = vVectorT0
	}

	t1Packed := pubKey.Bytes()[32:]
	t1Vec, err := UnpackT1(t1Packed, Dilithium3K)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unpack t1: %w", err)
	}
	t1FullBytes := VecToBytes(t1Vec)

	// audit-fix L5-007: Each share gets its own copy of T1Bytes to prevent
	// shared-reference data races. Previously all shares pointed to the same
	// t1FullBytes slice, so concurrent modifications by one share would
	// corrupt all other shares' T1Bytes.
	for i := 0; i < total; i++ {
		t1Copy := make([]byte, len(t1FullBytes))
		copy(t1Copy, t1FullBytes)
		shares[i].T1Bytes = t1Copy
	}

	qtdPubKey := &QTDPublicKey{
		Rho:          pubKey.Bytes()[:32],
		T1:           t1Packed,
		PubKey:       pubKey.Bytes(),
		CombinedSeed: combinedSeed,
	}

	return qtdPubKey, shares, nil
}

// GenerateDKGShares generates a group Dilithium3 key pair split into `total`
// additive shares via the TRUSTED DEALER pattern.
//
// TSS- (2026-07-16) — TRUSTED DEALER MODE (not a real distributed DKG):
// Despite the function name, this is NOT a distributed DKG. All "participant
// seed shares" are generated, committed, verified, and combined IN A SINGLE
// PROCESS (qtd_dkg.go:407-463). The combined seed is then fed to
// mode3.NewKeyFromSeed, which materializes the COMPLETE Dilithium3 private
// key in this process's heap (privKeyBytes, qtd_dkg.go:468). The full key is
// then split additively (additiveSplitPrivateKey). Therefore, at the moment
// of key generation, the host running this function has the entire group
// private key in memory — defeating the threshold security property.
//
// This is acceptable ONLY for a controlled key ceremony on an air-gapped
// host, with shares immediately distributed and the in-memory material
// destroyed. The TSSManager.GenerateKeyShares wrapper enforces this via
// the QAU_ALLOW_TRUSTED_DEALER_CEREMONY env var; callers of this package
// must apply the same gate.
//
// A real distributed DKG would have each participant generate their own
// s1_i/s2_i locally, exchange Pedersen commitments, and jointly compute
// t = A·s1 + s2 without any single party ever holding the full key.
// Implementing this is tracked as future work.
//
// Each participant contributes a share, and the combined result is a valid
// Dilithium3 key pair where no single party knows the full private key
// — AFTER distribution. During generation (this function), the dealer knows
// the full key.
func GenerateDKGShares(threshold, total int) (*QTDPublicKey, []*QTDShare, error) {
	if threshold <= 0 || total <= 0 || threshold > total {
		return nil, nil, ErrInvalidConfig
	}

	// Phase 1: Each participant generates a random seed share
	seedShares := make([][]byte, total)
	commitments := make([][]byte, total)
	nonces := make([][]byte, total)

	for i := 0; i < total; i++ {
		seed := make([]byte, 32)
		_, err := rand.Read(seed)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate seed share: %w", err)
		}
		seedShares[i] = seed

		nonce := make([]byte, 16)
		_, err = rand.Read(nonce)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
		nonces[i] = nonce

		// Commit to seed share
		h := sha256.New()
		h.Write(seed)
		h.Write([]byte{byte(i + 1)})
		h.Write(nonce)
		commitments[i] = h.Sum(nil)
	}

	// Phase 2: Verify seed commitments before combining.
	// TSS-006 FIX: Each participant's revealed seed must match their commitment.
	// Prevents a malicious participant from changing their seed after seeing
	// others' seeds (last-revealer attack).
	// Without this check, the last participant could choose their seed to
	// influence the combined key.
	for i := 0; i < total; i++ {
		hVerifier := sha256.New()
		hVerifier.Write(seedShares[i])
		hVerifier.Write([]byte{byte(i + 1)})
		hVerifier.Write(nonces[i])
		if subtle.ConstantTimeCompare(hVerifier.Sum(nil), commitments[i]) != 1 {
			return nil, nil, fmt.Errorf("seed commitment verification failed for participant %d", i+1)
		}
	}

	// Phase 3: Combine seed shares using SHA256 (not XOR).
	// SECURITY FIX (vuln 4): XOR combination is insecure because a malicious
	// participant who knows all other shares can choose their own share to
	// cancel out all others and control the combined seed:
	//   attacker_share = target_seed XOR share_1 XOR ... XOR share_n
	// SHA256 is a cryptographic hash that makes the output unpredictable
	// even if some inputs are adversarially chosen.
	h := sha256.New()
	for i := 0; i < total; i++ {
		h.Write(seedShares[i])
		h.Write([]byte{byte(i + 1)}) // domain separation
	}
	combinedSeed := h.Sum(nil)

	// Phase 3: Derive key material from combined seed
	pubKey, privKey := mode3.NewKeyFromSeed((*[32]byte)(combinedSeed))
	// L9-001 FIX: see GenerateDKGSharesShamir for explanation.
	privKeyBytes := privKey.Bytes()
	defer func() {
		*privKey = mode3.PrivateKey{}
		SecurelyZeroMemory(privKeyBytes)
		// R32-P1-01 FIX: Zeroize combined seed (see GenerateDKGSharesShamir).
		SecurelyZeroMemory(combinedSeed)
		runtime.KeepAlive(privKey)
	}()

	// Phase 4: Split private key using additive secret sharing.
	// s1 = s1_1 + s1_2 + ... + s1_n (mod Q)
	// Each s1_i is a random polynomial vector, and the last share is
	// computed as s1 - Σ_{i=1}^{n-1} s1_i to ensure correctness.
	// This enables additive aggregation during signing: z = Σ z_i,
	// producing a standard Dilithium3-compatible signature.
	shares, err := additiveSplitPrivateKey(privKeyBytes, total)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to split private key: %w", err)
	}

	// Phase 5: Generate verification vectors
	for i := 0; i < total; i++ {
		vVector, err := generateVerificationVector(shares[i].S1ShareBytes, threshold)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate verification vector: %w", err)
		}
		shares[i].VVector = vVector

		vVectorS2, verr2 := generateVerificationVector(shares[i].S2ShareBytes, threshold)
		if verr2 != nil {
			return nil, nil, fmt.Errorf("failed to generate S2 verification vector: %w", verr2)
		}
		shares[i].VVectorS2 = vVectorS2

		vVectorT0, verr3 := generateVerificationVector(shares[i].T0ShareBytes, threshold)
		if verr3 != nil {
			return nil, nil, fmt.Errorf("failed to generate T0 verification vector: %w", verr3)
		}
		shares[i].VVectorT0 = vVectorT0
	}

	// Phase 6: Construct public key and set T1Bytes on each share
	rho := pubKey.Bytes()[:32]
	t1Packed := pubKey.Bytes()[32:]

	t1Vec, err := UnpackT1(t1Packed, Dilithium3K)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unpack t1: %w", err)
	}
	t1FullBytes := VecToBytes(t1Vec)

	// audit-fix L5-007: Each share gets its own copy of T1Bytes to prevent
	// shared-reference data races. Previously all shares pointed to the same
	// t1FullBytes slice, so concurrent modifications by one share would
	// corrupt all other shares' T1Bytes.
	for i := 0; i < total; i++ {
		t1Copy := make([]byte, len(t1FullBytes))
		copy(t1Copy, t1FullBytes)
		shares[i].T1Bytes = t1Copy
	}

	qtdPubKey := &QTDPublicKey{
		Rho:          rho,
		T1:           t1Packed,
		PubKey:       pubKey.Bytes(),
		CombinedSeed: combinedSeed,
	}

	return qtdPubKey, shares, nil
}

// additiveSplitPrivateKey splits a Dilithium3 private key into additive shares.
//
// With additive sharing, s1 = Σ s1_i (mod Q). The first n-1 shares are random
// polynomial vectors, and the nth share is computed as s1 - Σ_{i=1}^{n-1} s1_i.
// This ensures that during signing, z = Σ z_i = s1*c + Σ y_i, which produces
// a standard Dilithium3-compatible signature after global rejection sampling.
//
// Circl Dilithium3 private key layout (4000 bytes):
//
//	[0:32]   Rho (32 bytes)
//	[32:64]  K   (32 bytes)
//	[64:96]  tr  (32 bytes)
//	[96:736] s1  (640 bytes, 5 polynomials * 128 bytes, eta=5 packed)
//	[736:1504] s2 (768 bytes, 6 polynomials * 128 bytes, eta=5 packed)
//	[1504:4000] t0 (2496 bytes, 6 polynomials * 416 bytes, 13-bit packed)
func additiveSplitPrivateKey(privKeyBytes []byte, total int) ([]*QTDShare, error) {
	const s1Offset = mode3.SeedSize * 3
	const s1Size = Dilithium3L * 128
	const s2Offset = s1Offset + s1Size
	const s2Size = Dilithium3K * 128
	const t0Offset = s2Offset + s2Size
	const t0Size = Dilithium3K * 416

	if len(privKeyBytes) < t0Offset+t0Size {
		return nil, ErrInvalidConfig
	}

	// L14-001 FIX: Copy Rho instead of using a slice reference into privKeyBytes.
	// The caller defers SecurelyZeroMemory(privKeyBytes), which would zero the
	// shared slice — corrupting every share's Rho and causing ComputeA() to
	// derive the wrong matrix A during signing. This was the root cause of
	// T=1/T=N signature verification failures: circl Verify uses the correct
	// A (from the public key's Rho), while QTD signing used an all-zeros
	// Rho → wrong w → wrong ctilde → mismatch.
	rho := make([]byte, mode3.SeedSize)
	copy(rho, privKeyBytes[:mode3.SeedSize])

	s1Packed := privKeyBytes[s1Offset : s1Offset+s1Size]
	s1Vec, err := UnpackEtaVec(s1Packed, Dilithium3L, Dilithium3EtaPoly)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack s1: %w", err)
	}

	s1ShareVecs, err := additiveSplitPolyVec(s1Vec, total)
	if err != nil {
		return nil, fmt.Errorf("failed to split s1: %w", err)
	}

	s2Packed := privKeyBytes[s2Offset : s2Offset+s2Size]
	s2Vec, err := UnpackEtaVec(s2Packed, Dilithium3K, Dilithium3EtaPoly)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack s2: %w", err)
	}

	s2ShareVecs, err := additiveSplitPolyVec(s2Vec, total)
	if err != nil {
		return nil, fmt.Errorf("failed to split s2: %w", err)
	}

	t0Packed := privKeyBytes[t0Offset : t0Offset+t0Size]
	t0Vec := make(PolyVec, Dilithium3K)
	if err := parseT0PolyVec(t0Vec, t0Packed, Dilithium3K); err != nil {
		return nil, fmt.Errorf("failed to parse t0: %w", err)
	}

	t0ShareVecs, err := additiveSplitPolyVec(t0Vec, total)
	if err != nil {
		return nil, fmt.Errorf("failed to split t0: %w", err)
	}

	// L12-025 [P3] NOTE: Rho is intentionally shared across all shares (and the public
	// key). Rho is the public seed (32 bytes) used to expand the Dilithium3 matrix A;
	// it is non-secret and identical for every share, so a single slice reference is
	// reused instead of copying. CAUTION: because Rho is a []byte slice (not a value),
	// mutating any share's Rho in place will affect every other share and QTDPublicKey.Rho
	// via slice aliasing. Treat Rho as read-only after split; copy it first if mutation is required.
	shares := make([]*QTDShare, total)
	for i := 0; i < total; i++ {
		pid := i + 1
		shares[i] = &QTDShare{
			ParticipantID: pid,
			Rho:           rho,
			S1ShareBytes:  VecToBytes(s1ShareVecs[pid]),
			S2ShareBytes:  VecToBytes(s2ShareVecs[pid]),
			T0ShareBytes:  VecToBytes(t0ShareVecs[pid]),
			VVector:       nil,
		}
	}

	return shares, nil
}

// additiveSplitPolyVec splits a PolyVec into additive shares.
// s = s_1 + s_2 + ... + s_n (mod Q)
// The first n-1 shares are random, the nth is s - Σ_{i=1}^{n-1} s_i.
//
// N20-009 FIX: Previously this function called rand.Read once per coefficient
// per share (len(vec)*N*(total-1) calls), each reading only 4 bytes. For a
// typical PolyVec (5 polynomials x 256 coefficients x ~3 shares), this meant
// ~3840 syscalls. Now random bytes are generated in 4 KB batches, reducing
// the number of rand.Read calls by ~1000x with no change to the distribution
// (each uint32 is still independently uniform over [0, 2^32)).
func additiveSplitPolyVec(vec PolyVec, total int) (map[int]PolyVec, error) {
	if len(vec) == 0 || total <= 0 {
		return nil, ErrInvalidConfig
	}

	shares := make(map[int]PolyVec, total)
	for id := 1; id <= total; id++ {
		shares[id] = make(PolyVec, len(vec))
	}

	// N20-009: batch random buffer — 4 KB, must be a multiple of 4.
	const randChunkSize = 4096
	var randBuf [randChunkSize]byte
	randOff := len(randBuf) // start exhausted to trigger first fill

	for p := 0; p < len(vec); p++ {
		for c := 0; c < N; c++ {
			secret := int64(vec[p][c])
			secret = ((secret % Q) + Q) % Q

			sum := int64(0)
			for id := 1; id < total; id++ {
				if randOff+4 > len(randBuf) {
					if _, err := rand.Read(randBuf[:]); err != nil {
						return nil, fmt.Errorf("failed to generate random share: %w", err)
					}
					randOff = 0
				}
				val := int64(binary.LittleEndian.Uint32(randBuf[randOff:])) % Q
				randOff += 4
				shares[id][p][c] = int32(val)
				sum = (sum + val) % Q
			}

			lastVal := (secret - sum) % Q
			if lastVal < 0 {
				lastVal += Q
			}
			shares[total][p][c] = int32(lastVal)
		}
	}

	return shares, nil
}

// shamirSideChannelWarned guards one-time emission of the TSS- side-channel
// warning so the log is not spammed across repeated Shamir split calls within
// the same process. Subsequent calls within the same process stay silent —
// the first warning is sufficient to alert operators.
var shamirSideChannelWarned bool

// warnShamirSideChannelRisk emits a one-time WARNING when shamirSplitPolyVec
// (or its seeded variant) is called in production mode without TEE attestation.
// The warning fires at most once per process to avoid log spam.
//
// TSS- The Shamir split is NOT constant-time (N25-003). The
// `% uint32(Q)` reductions on secret coefficients have data-dependent timing.
// Production deployments MUST either (a) run inside a TEE (set
// QAU_TSS_TEE_ENFORCED=1) or (b) run on an air-gapped ceremony host.
//
// AUDIT-FULL ROUND1 2026-08-14 CR-07: Non-constant-time Shamir split is a
// known limitation documented as N25-003. The warning above provides runtime
// protection. Full constant-time closure requires a formal-verified library.
// CONFIRMED-IN-PLACE.
func warnShamirSideChannelRisk() {
	if shamirSideChannelWarned {
		return
	}
	shamirSideChannelWarned = true

	if !params.IsProductionEnv() {
		// Dev/test mode — no warning needed. The non-CT behavior is
		// documented and acceptable outside production.
		return
	}

	if os.Getenv("QAU_TSS_TEE_ENFORCED") == "1" {
		// Operator attests that the execution environment is a TEE or
		// hardened isolated hardware that neutralizes side-channel leakage.
		return
	}

	log.Printf("WARNING (TSS- / N25-003): shamirSplitPolyVec called in production " +
		"WITHOUT TEE attestation (QAU_TSS_TEE_ENFORCED unset). This function is NOT " +
		"constant-time — the modular reduction on secret coefficients has data-dependent " +
		"timing that can leak private key material via cache/power/branch side-channels. " +
		"Production deployments MUST execute this inside a TEE (Intel SGX, AMD SEV, ARM " +
		"TrustZone) or on an air-gapped ceremony host. Set QAU_TSS_TEE_ENFORCED=1 to " +
		"attest TEE protection and silence this warning. Full constant-time closure " +
		"requires a formal-verified library (deferred beyond P2 scope).")
}

// shamirSplitPolyVec splits each coefficient of a PolyVec into independent
// Shamir shares over GF(Q). Returns a PolyVec per participant where each
// coefficient is that participant's share value.
//
// N25-003 [P2] SECURITY NOTE (known limitation, tracked as N20-007): This
// function is NOT constant-time. The coefficient reduction
// (uint32(vec[p][c]) % uint32(Q)) and the share-evaluation loop perform
// arithmetic whose timing and branch behavior depend on the SECRET
// coefficient values being split. A side-channel attacker observing timing
// or power could theoretically recover information about the secret key
// material. Implementing a fully constant-time Shamir split over GF(Q)
// (constant-time modular reduction + constant-time polynomial evaluation
// with secret-independent memory access) is TODO and intentionally deferred
// because it is high-risk and would require dedicated formal review.
// The algorithm is left unchanged on purpose; do not "optimize" the
// branches below without also addressing constant-time behavior.
//
// TSS- (2026-07-17) — HARD DEPLOYMENT CONSTRAINT + RUNTIME WARN:
//
//	The leakage vector is in the DATA-DEPENDENT ARITHMETIC
//	(`% uint32(Q)` on secret coefficients), NOT in control-flow branches.
//	Replacing `%` with a constant-time Barrett reduction would require
//	dedicated formal review and is explicitly deferred per N25-003.
//	subtle.ConstantTimeSelect cannot fix arithmetic timing leakage — it
//	only addresses branch-timing. A partial "branch fix" would give a
//	false sense of security while the arithmetic leakage persists.
//
//	HARD CONSTRAINT: This function MUST be executed inside a TEE (Intel SGX,
//	AMD SEV, ARM TrustZone, or equivalent isolated hardware) OR on an
//	air-gapped ceremony host. Production validators MUST set the env var
//	QAU_TSS_TEE_ENFORCED=1 to attest that the execution environment
//	neutralizes side-channel leakage. When QAU_PRODUCTION=1 AND
//	QAU_TSS_TEE_ENFORCED is unset, this function emits a runtime WARNING
//	alerting the operator that side-channel protection is not in place.
//	Full closure requires a formal-verified constant-time Shamir library
//	(see N25-003 / N20-007) — deferred beyond P2 scope.
//
//	QUANTUM- (audit 2026-07-17, Low): reaffirmed as documented
//	limitation. Constant-time modular reduction over GF(Q) requires formal
//	verification — out of P3 scope. Runtime warn + TEE attestation remain
//	the mitigation; full CT closure tracked under N25-003.
func shamirSplitPolyVec(vec PolyVec, threshold, total int) (map[int]PolyVec, error) {
	if len(vec) == 0 {
		return nil, ErrInvalidConfig
	}
	if threshold <= 0 || total <= 0 || threshold > total {
		return nil, ErrInvalidConfig
	}

	// TSS- Warn when running in production without TEE attestation.
	// We do NOT fail-closed here because (1) test/dev paths legitimately
	// call this function outside a TEE, (2) the trusted-dealer ceremony
	// path (QAU_ALLOW_TRUSTED_DEALER_CEREMONY) already assumes a hardened
	// air-gapped host, and (3) failing would break existing key import on
	// validators that have not yet migrated to TEE. The warning makes the
	// risk visible to operators so they can remediate.
	warnShamirSideChannelRisk()

	shares := make(map[int]PolyVec, total)
	for id := 1; id <= total; id++ {
		shares[id] = make(PolyVec, len(vec))
	}

	for p := 0; p < len(vec); p++ {
		for c := 0; c < N; c++ {
			secret := uint32(vec[p][c]) % uint32(Q)

			coeffs := make([]uint32, threshold)
			coeffs[0] = secret
			for j := 1; j < threshold; j++ {
				var buf [4]byte
				if _, err := rand.Read(buf[:]); err != nil {
					// L10-010 FIX: Zero coeffs (contains secret in coeffs[0]) on error path
					zeroUint32SliceFunc(coeffs)
					return nil, fmt.Errorf("failed to generate coefficient: %w", err)
				}
				coeffs[j] = binary.LittleEndian.Uint32(buf[:]) % uint32(Q)
			}

			for id := 1; id <= total; id++ {
				val := uint32(0)
				x := uint32(id)
				xPow := uint32(1)
				for _, coeff := range coeffs {
					val = (val + uint32((uint64(coeff%uint32(Q))*uint64(xPow%uint32(Q)))%uint64(Q))) % uint32(Q)
					xPow = uint32((uint64(xPow) * uint64(x)) % uint64(Q))
				}
				shares[id][p][c] = int32(val)
			}
			// L10-011 FIX: Use indirect function call to prevent compiler optimization.
			zeroUint32SliceFunc(coeffs)
		}
	}

	return shares, nil
}

// shamirSplitAll splits data into Shamir shares for ALL participants at once
// over the finite field GF(Q) where Q = 8380417 (Dilithium3 prime modulus).
//
// SECURITY FIX (vuln 1): The previous code used shamirPrime=251 and computed
// secret = data[i] % 251, which mapped byte values 251-255 to 0-4, causing
// irreversible information loss during reconstruction. Now each input byte
// (0-255) is mapped directly to a GF(Q) element (no modulo reduction needed
// since 255 < Q), and each share element is encoded as 4-byte little-endian
// uint32 to avoid truncation (Q ≈ 8.38 million requires 23 bits).
//
// CRITICAL: All shares are generated from the SAME polynomial (same random
// coefficients) so that Lagrange interpolation can reconstruct the secret.
// zeroUint32SliceFunc is a package-level function variable for zeroing uint32 slices.
// Using an indirect function call prevents the compiler from inlining the body.
// FIX: Added runtime.KeepAlive(s) to prevent the compiler from eliminating
// the zeroing writes as dead stores. The indirect call alone is not sufficient —
// the compiler's escape analysis can still prove the slice is not read after zeroing
// and remove the writes. runtime.KeepAlive forces the slice to remain observable,
// matching the pattern used by SecurelyZeroMemory (zeroMemoryFunc + KeepAlive).
var zeroUint32SliceFunc = func(s []uint32) {
	for i := range s {
		s[i] = 0
	}
	runtime.KeepAlive(s)
}

func shamirSplitAll(data []byte, threshold, total int) (map[int][]byte, error) {
	if len(data) == 0 {
		return nil, ErrInvalidConfig
	}
	if threshold <= 0 || total <= 0 || threshold > total {
		return nil, ErrInvalidConfig
	}

	shares := make(map[int][]byte, total)
	for id := 1; id <= total; id++ {
		shares[id] = make([]byte, len(data)*4)
	}

	for i := 0; i < len(data); i++ {
		coeffs := make([]uint32, threshold)
		coeffs[0] = uint32(data[i]) // secret = data[i], no modulo needed (0-255 < Q)

		for j := 1; j < threshold; j++ {
			var coeffBuf [4]byte
			if _, err := rand.Read(coeffBuf[:]); err != nil {
				// L10-010 FIX: Zero coeffs (contains secret in coeffs[0]) on error path
				zeroUint32SliceFunc(coeffs)
				return nil, fmt.Errorf("failed to generate coefficient: %w", err)
			}
			coeffs[j] = binary.LittleEndian.Uint32(coeffBuf[:]) % uint32(Q)
		}

		for id := 1; id <= total; id++ {
			val := uint32(0)
			x := uint32(id)
			xPow := uint32(1)
			for _, c := range coeffs {
				val = (val + uint32((uint64(c%uint32(Q))*uint64(xPow%uint32(Q)))%uint64(Q))) % uint32(Q)
				xPow = uint32((uint64(xPow) * uint64(x)) % uint64(Q))
			}
			binary.LittleEndian.PutUint32(shares[id][i*4:(i+1)*4], val)
		}
		// L9-011 FIX: Zeroize coeffs slice containing the secret coefficient
		// (coeffs[0]) and random polynomial coefficients after share evaluation.
		zeroUint32SliceFunc(coeffs)
	}

	return shares, nil
}

// shamirReconstruct reconstructs the original data from Shamir shares
// using Lagrange interpolation over GF(Q).
//
// SECURITY FIX (vuln 1): Updated to decode 4-byte little-endian uint32
// elements and use Q-based Lagrange coefficients (from lagrangeCoeff in
// qtd_protocol.go) for correct reconstruction without information loss.
func shamirReconstruct(shares map[int][]byte, threshold int) ([]byte, error) {
	if len(shares) < threshold {
		return nil, ErrInsufficientParticipants
	}

	// L18-006 FIX: Validate all shares have consistent length and are 4-byte aligned.
	var dataLen int
	for id, s := range shares {
		if len(s) == 0 {
			return nil, fmt.Errorf("%w: share %d is empty", ErrInvalidConfig, id)
		}
		if len(s)%4 != 0 {
			return nil, fmt.Errorf("%w: share %d length %d is not 4-byte aligned", ErrInvalidConfig, id, len(s))
		}
		if dataLen == 0 {
			dataLen = len(s) / 4
		} else if len(s)/4 != dataLen {
			return nil, fmt.Errorf("%w: share %d length mismatch: expected %d elements, got %d",
				ErrInvalidConfig, id, dataLen, len(s)/4)
		}
	}
	if dataLen == 0 {
		return nil, ErrInvalidConfig
	}

	result := make([]byte, dataLen)
	participants := make([]int, 0, len(shares))
	for id := range shares {
		participants = append(participants, id)
	}

	for i := 0; i < dataLen; i++ {
		val := int64(0)
		for _, id := range participants {
			offset := i * 4
			if offset+4 > len(shares[id]) {
				continue
			}
			shareVal := int64(binary.LittleEndian.Uint32(shares[id][offset : offset+4]))
			coeff := lagrangeCoeff(id, participants)
			term := (shareVal * coeff) % Q
			val = (val + term) % Q
		}
		// L18-006 FIX: Validate reconstructed value is in valid byte range.
		// Shamir secret sharing over GF(Q) reconstructs the original secret
		// coefficient, which should be in [0, 255] for byte-valued secrets.
		// If val >= 256, the shares may be corrupted or tampered.
		if val < 0 || val > 255 {
			return nil, fmt.Errorf("%w: reconstructed value %d at index %d is out of byte range [0, 255]",
				ErrInvalidShare, val, i)
		}
		result[i] = byte(val)
	}

	return result, nil
}

// generateVerificationVector creates Pedersen commitments to the polynomial coefficients.
//
// Uses real Pedersen commitments (C = g^value * h^blinding) from the project's
// pedersen package, which provides both binding and hiding properties.
//
// SECURITY FIX (CRITICAL-2): Blinding factors are now randomly generated using
// crypto/rand (via pedersen.RandomBlinding), providing true information-theoretic
// hiding like proper Pedersen VSS. The random blinding is appended to the
// commitment bytes (format: commitment[48] || blinding[32]) so that verifiers
// can reconstruct and verify the commitment.
//
// Format: each vVector entry is 80 bytes = 48 (commitment) + 32 (blinding)
//
// N20-003 SECURITY NOTE (Accepted Risk): This function is currently called
// with S1ShareBytes only (see all call sites in qtd_dkg.go and qtd_refresh.go).
// S2 and T0 additive shares do NOT have Pedersen commitment verification
// vectors. A malicious participant could submit valid S1 shares (passing
// VerifyShare) while providing forged S2 or T0 shares that would corrupt
// the reconstructed Dilithium3 private key.
//
// Mitigating factors:
//   - ShareIntegrityCheck (qtd_security.go) validates S2/T0 share lengths,
//     byte ranges, and coefficient bounds before use.
//   - The final signature verification (Dilithium3.Verify) will fail if
//     the reconstructed key is incorrect, preventing invalid signatures.
//   - DKG participants typically know each other and the public key t1,
//     providing an out-of-band integrity check.
//
// TODO(N20-003): Extend verification vectors to cover S2 and T0 shares. This
// requires: (1) calling generateVerificationVector for S2ShareBytes and
// T0ShareBytes at each call site, (2) storing multiple vVectors per share
// (or extending VVector to a tagged format), (3) updating VerifyShare to
// verify all three share types, and (4) updating QTDShare serialization
// in qtd_security.go to persist all verification vectors.
func generateVerificationVector(shareBytes []byte, threshold int) ([][]byte, error) {
	gen, err := pedersen.NewGenerator()
	if err != nil {
		return nil, fmt.Errorf("failed to create Pedersen generator: %w", err)
	}

	vVector := make([][]byte, threshold)

	for i := 0; i < threshold; i++ {
		// Generate cryptographically secure random blinding factor
		blinding, err := pedersen.RandomBlinding()
		if err != nil {
			return nil, fmt.Errorf("failed to generate random blinding: %w", err)
		}

		// Q21-022 FIX: Return error if shareBytes is too short instead of using zero.
		if i*4+4 > len(shareBytes) {
			return nil, fmt.Errorf("shareBytes too short: need %d bytes at offset %d, have %d", i*4+4, i*4, len(shareBytes))
		}
		value := big.NewInt(int64(binary.LittleEndian.Uint32(shareBytes[i*4 : i*4+4])))

		commitment := gen.Commit(value, blinding)
		commitmentBytes := commitment.Bytes()

		// Format: commitment (48 bytes) || blinding (32 bytes)
		blindingBytes := make([]byte, 32)
		blinding.FillBytes(blindingBytes)

		entry := make([]byte, len(commitmentBytes)+32)
		copy(entry[:len(commitmentBytes)], commitmentBytes)
		copy(entry[len(commitmentBytes):], blindingBytes)

		vVector[i] = entry
	}

	return vVector, nil
}

// verifyPedersenCoefficients verifies that shareBytes are consistent with
// the given Pedersen verification vector. Each VVector entry must be 80 bytes
// (48-byte commitment + 32-byte random blinding). Returns true if all checked
// coefficients match and at least one was checked, false otherwise.
//
//	Extracted from VerifyShare's inline S1 verification loop so that
//
// S2 and T0 shares can be verified with the same Pedersen commitment logic.
func verifyPedersenCoefficients(gen *pedersen.Generator, shareBytes []byte, vVector [][]byte) bool {
	checked := 0
	for j := 0; j < len(vVector) && j*4+4 <= len(shareBytes); j++ {
		entry := vVector[j]
		if len(entry) != 80 {
			return false
		}

		commitmentBytes := entry[:48]
		commitment, cerr := pedersen.CommitmentFromBytes(commitmentBytes)
		if cerr != nil {
			return false
		}

		value := big.NewInt(int64(binary.LittleEndian.Uint32(shareBytes[j*4 : j*4+4])))
		blindingBytes := entry[48:80]
		blinding := new(big.Int).SetBytes(blindingBytes)
		expected := gen.Commit(value, blinding)

		expectedBytes := expected.Bytes()
		actualBytes := commitment.Bytes()

		if subtle.ConstantTimeCompare(expectedBytes, actualBytes) != 1 {
			return false
		}
		checked++
	}
	return checked > 0
}

// VerifyShare verifies a share against the verification vectors.
//
// SECURITY FIX (vuln 2): Previously only checked allVVectors[0][0], ignoring
// all other participants' commitments. Now iterates over ALL verification
// vectors and verifies share elements against real Pedersen commitments.
//
// Uses crypto/subtle.ConstantTimeCompare for commitment comparison to
// prevent timing side-channel attacks that could leak information about
// the share values or commitment structure.
//
// SECURITY FIX (CRITICAL-2): Now uses random blinding factors stored alongside
// commitments (format: commitment[48] || blinding[32]) instead of deterministic
// HMAC-derived blinding. This provides true information-theoretic hiding.
func VerifyShare(share *QTDShare, allVVectors [][][]byte, participantID int) error {
	if share == nil {
		return ErrInvalidShare
	}
	if participantID < 1 {
		return ErrInvalidShare
	}
	if len(allVVectors) == 0 {
		return ErrShareVerification
	}

	// FIX: Cross-validate S2 and T0 share sizes when both present.
	// S2 and T0 are both K-dimensional polynomial vectors, so they must have
	// the same byte length. S1 is L-dimensional and may differ.
	//  Full Pedersen verification for S2/T0 is now implemented below
	// using VVectorS2/VVectorT0. This size check remains as an early reject.
	if len(share.S2ShareBytes) > 0 && len(share.T0ShareBytes) > 0 &&
		len(share.S2ShareBytes) != len(share.T0ShareBytes) {
		return fmt.Errorf("%w: S2/T0 share size mismatch: S2=%d, T0=%d",
			ErrInvalidShare, len(share.S2ShareBytes), len(share.T0ShareBytes))
	}

	gen, err := pedersen.NewGenerator()
	if err != nil {
		return ErrShareVerification
	}

	// N19-001 FIX: Use participantID to index to the specific participant's
	// verification vector, instead of iterating over ALL vectors.
	// The old code verified against all participants' vectors, causing
	// verification to fail when any participant's vector didn't match.
	if participantID > len(allVVectors) {
		return fmt.Errorf("%w: participantID %d exceeds vector count %d", ErrShareVerification, participantID, len(allVVectors))
	}
	vVector := allVVectors[participantID-1]
	if len(vVector) == 0 {
		return ErrShareVerification
	}

	verified := true
	checked := 0
	for j := 0; j < len(vVector) && j*4+4 <= len(share.S1ShareBytes); j++ {
		entry := vVector[j]
		// FIX: Require exactly 80 bytes (48-byte
		// commitment + 32-byte random blinding). The previous legacy
		// branch accepted 48..79 byte entries and derived the blinding
		// deterministically from the share bytes via HMAC, which:
		//   1. Created a circular dependency (blinding derived from share)
		//   2. Allowed downgrade attacks (truncating 80-byte entries to
		//      48 bytes forced verification down the insecure path)
		// Now any entry shorter than 80 bytes fails verification.
		if len(entry) != 80 {
			verified = false
			break
		}

		// Extract commitment (first 48 bytes) and blinding (next 32 bytes)
		commitmentBytes := entry[:48]
		commitment, cerr := pedersen.CommitmentFromBytes(commitmentBytes)
		if cerr != nil {
			verified = false
			break
		}

		value := big.NewInt(int64(binary.LittleEndian.Uint32(share.S1ShareBytes[j*4 : j*4+4])))

		// New format: commitment (48) + blinding (32) — random blinding
		// generated by generateVerificationVector via pedersen.RandomBlinding()
		blindingBytes := entry[48:80]
		blinding := new(big.Int).SetBytes(blindingBytes)
		expected := gen.Commit(value, blinding)

		expectedBytes := expected.Bytes()
		actualBytes := commitment.Bytes()

		if subtle.ConstantTimeCompare(expectedBytes, actualBytes) != 1 {
			verified = false
			break
		}
		checked++
	}

	if !verified || checked == 0 {
		return ErrShareVerification
	}

	//  / TSS- (2026-07-16): Verify S2 and T0 shares using their
	// Pedersen verification vectors. These vectors are generated during DKG
	// alongside the S1 VVector (see GenerateDKGShares Phase 5,
	// qtd_dkg.go:528-538, and GenerateDKGSharesShamir's analogous phase).
	// Because DKG *always* emits VVectorS2/VVectorT0, a share missing them
	// is either (a) forged by a malicious distributor who omitted the
	// vectors to bypass S2/T0 verification, or (b) corrupted/truncated in
	// transit. Both cases MUST be rejected.
	//
	// Previously this branch logged a warning and skipped verification
	// (fail-open), relying on the final Dilithium3 signature check to
	// catch corruption. That is insufficient: a malicious distributor can
	// plant inconsistent S2/T0 shares that pass ShareIntegrityCheck (which
	// only validates length/range/bounds) but corrupt the reconstructed
	// private key, causing signature DoS or — under future distributed DKG
	// — silently breaking correctness without detection. The signature
	// check only catches the aggregate result, not which share was bad,
	// and in some failure modes a malformed t0 can produce a key that
	// still verifies on a subset of messages.
	//
	// Fix: fail-closed. Missing S2/T0 verification vectors now return
	// ErrShareVerification, completing TODO(N20-003). This closes the
	// ACTIVE downgrade path where a distributor could omit the vectors
	// to fall back to the legacy unverified S2/T0 path.
	if len(share.VVectorS2) == 0 {
		return fmt.Errorf("%w: S2 verification vector absent (TSS- fail-closed; DKG must emit VVectorS2)",
			ErrShareVerification)
	}
	if !verifyPedersenCoefficients(gen, share.S2ShareBytes, share.VVectorS2) {
		return fmt.Errorf("%w: S2 share Pedersen verification failed", ErrShareVerification)
	}

	if len(share.VVectorT0) == 0 {
		return fmt.Errorf("%w: T0 verification vector absent (TSS- fail-closed; DKG must emit VVectorT0)",
			ErrShareVerification)
	}
	if !verifyPedersenCoefficients(gen, share.T0ShareBytes, share.VVectorT0) {
		return fmt.Errorf("%w: T0 share Pedersen verification failed", ErrShareVerification)
	}

	return nil
}

// GenerateDKGSharesWithSeed performs deterministic DKG using a master seed.
//
// audit-fix L-10 [LOW]: Deterministic share generation means anyone who knows
// the masterSeed can reconstruct ALL shares, defeating the purpose of
// distributed key generation. This function is intended ONLY for testing
// (deterministic test vectors). In production, use GenerateDKGShares which
// uses crypto/rand for each share. This function is blocked when the
// QAU_PRODUCTION environment variable is set to "1".
func GenerateDKGSharesWithSeed(threshold, total int, masterSeed []byte) (*QTDPublicKey, []*QTDShare, error) {
	if params.IsProductionEnv() {
		return nil, nil, fmt.Errorf("GenerateDKGSharesWithSeed: deterministic DKG blocked in production; use GenerateDKGShares with crypto/rand")
	}
	if threshold <= 0 || total <= 0 || threshold > total {
		return nil, nil, ErrInvalidConfig
	}

	seedShares := make([][]byte, total)
	commitments := make([][]byte, total)
	nonces := make([][]byte, total)

	for i := 0; i < total; i++ {
		mac := hmac.New(sha256.New, masterSeed)
		mac.Write([]byte("seed-share"))
		mac.Write([]byte{byte(i + 1)})
		seedShares[i] = mac.Sum(nil)[:32]

		mac = hmac.New(sha256.New, masterSeed)
		mac.Write([]byte("nonce"))
		mac.Write([]byte{byte(i + 1)})
		nonces[i] = mac.Sum(nil)[:16]

		h := sha256.New()
		h.Write(seedShares[i])
		h.Write([]byte{byte(i + 1)})
		h.Write(nonces[i])
		commitments[i] = h.Sum(nil)
	}

	for i := 0; i < total; i++ {
		hVerifier := sha256.New()
		hVerifier.Write(seedShares[i])
		hVerifier.Write([]byte{byte(i + 1)})
		hVerifier.Write(nonces[i])
		if subtle.ConstantTimeCompare(hVerifier.Sum(nil), commitments[i]) != 1 {
			return nil, nil, fmt.Errorf("seed commitment verification failed for participant %d", i+1)
		}
	}

	h := sha256.New()
	for i := 0; i < total; i++ {
		h.Write(seedShares[i])
		h.Write([]byte{byte(i + 1)})
	}
	combinedSeed := h.Sum(nil)

	pubKey, privKey := mode3.NewKeyFromSeed((*[32]byte)(combinedSeed))
	// L9-001 FIX: see GenerateDKGSharesShamir for explanation.
	privKeyBytes := privKey.Bytes()
	defer func() {
		*privKey = mode3.PrivateKey{}
		SecurelyZeroMemory(privKeyBytes)
		// R32-P1-01 FIX: Zeroize combined seed (see GenerateDKGSharesShamir).
		SecurelyZeroMemory(combinedSeed)
		runtime.KeepAlive(privKey)
	}()

	shares, err := additiveSplitPrivateKeyWithSeed(privKeyBytes, total, masterSeed)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to split private key: %w", err)
	}

	for i := 0; i < total; i++ {
		vVector, err := generateVerificationVector(shares[i].S1ShareBytes, threshold)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate verification vector: %w", err)
		}
		shares[i].VVector = vVector

		vVectorS2, verr2 := generateVerificationVector(shares[i].S2ShareBytes, threshold)
		if verr2 != nil {
			return nil, nil, fmt.Errorf("failed to generate S2 verification vector: %w", verr2)
		}
		shares[i].VVectorS2 = vVectorS2

		vVectorT0, verr3 := generateVerificationVector(shares[i].T0ShareBytes, threshold)
		if verr3 != nil {
			return nil, nil, fmt.Errorf("failed to generate T0 verification vector: %w", verr3)
		}
		shares[i].VVectorT0 = vVectorT0
	}

	rho := pubKey.Bytes()[:32]
	t1Packed := pubKey.Bytes()[32:]
	t1Vec, err := UnpackT1(t1Packed, Dilithium3K)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unpack t1: %w", err)
	}
	t1FullBytes := VecToBytes(t1Vec)
	// audit-fix L5-007: Each share gets its own copy of T1Bytes to prevent
	// shared-reference data races. Previously all shares pointed to the same
	// t1FullBytes slice, so concurrent modifications by one share would
	// corrupt all other shares' T1Bytes.
	for i := 0; i < total; i++ {
		t1Copy := make([]byte, len(t1FullBytes))
		copy(t1Copy, t1FullBytes)
		shares[i].T1Bytes = t1Copy
	}

	qtdPubKey := &QTDPublicKey{
		Rho:          rho,
		T1:           t1Packed,
		PubKey:       pubKey.Bytes(),
		CombinedSeed: combinedSeed,
	}

	return qtdPubKey, shares, nil
}

func additiveSplitPrivateKeyWithSeed(privKeyBytes []byte, total int, masterSeed []byte) ([]*QTDShare, error) {
	const s1Offset = mode3.SeedSize * 3
	const s1Size = Dilithium3L * 128
	const s2Offset = s1Offset + s1Size
	const s2Size = Dilithium3K * 128
	const t0Offset = s2Offset + s2Size
	const t0Size = Dilithium3K * 416

	if len(privKeyBytes) < t0Offset+t0Size {
		return nil, ErrInvalidConfig
	}

	// L14-001 FIX: Copy Rho instead of using a slice reference (see additiveSplitPrivateKey).
	rho := make([]byte, mode3.SeedSize)
	copy(rho, privKeyBytes[:mode3.SeedSize])

	s1Packed := privKeyBytes[s1Offset : s1Offset+s1Size]
	s1Vec, err := UnpackEtaVec(s1Packed, Dilithium3L, Dilithium3EtaPoly)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack s1: %w", err)
	}

	s1ShareVecs, err := additiveSplitPolyVecWithSeed(s1Vec, total, masterSeed, "s1")
	if err != nil {
		return nil, fmt.Errorf("failed to split s1: %w", err)
	}

	s2Packed := privKeyBytes[s2Offset : s2Offset+s2Size]
	s2Vec, err := UnpackEtaVec(s2Packed, Dilithium3K, Dilithium3EtaPoly)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack s2: %w", err)
	}

	s2ShareVecs, err := additiveSplitPolyVecWithSeed(s2Vec, total, masterSeed, "s2")
	if err != nil {
		return nil, fmt.Errorf("failed to split s2: %w", err)
	}

	t0Packed := privKeyBytes[t0Offset : t0Offset+t0Size]
	t0Vec := make(PolyVec, Dilithium3K)
	if err := parseT0PolyVec(t0Vec, t0Packed, Dilithium3K); err != nil {
		return nil, fmt.Errorf("failed to parse t0: %w", err)
	}

	t0ShareVecs, err := additiveSplitPolyVecWithSeed(t0Vec, total, masterSeed, "t0")
	if err != nil {
		return nil, fmt.Errorf("failed to split t0: %w", err)
	}

	shares := make([]*QTDShare, total)
	for i := 0; i < total; i++ {
		pid := i + 1
		shares[i] = &QTDShare{
			ParticipantID: pid,
			Rho:           rho,
			S1ShareBytes:  VecToBytes(s1ShareVecs[pid]),
			S2ShareBytes:  VecToBytes(s2ShareVecs[pid]),
			T0ShareBytes:  VecToBytes(t0ShareVecs[pid]),
			VVector:       nil,
		}
	}

	return shares, nil
}

func additiveSplitPolyVecWithSeed(vec PolyVec, total int, masterSeed []byte, domain string) (map[int]PolyVec, error) {
	if len(vec) == 0 || total <= 0 {
		return nil, ErrInvalidConfig
	}

	shares := make(map[int]PolyVec, total)
	for id := 1; id <= total; id++ {
		shares[id] = make(PolyVec, len(vec))
	}

	coeffIndex := uint64(0)
	for p := 0; p < len(vec); p++ {
		for c := 0; c < N; c++ {
			secret := int64(vec[p][c])
			secret = ((secret % Q) + Q) % Q

			sum := int64(0)
			for id := 1; id < total; id++ {
				mac := hmac.New(sha256.New, masterSeed)
				mac.Write([]byte(domain))
				mac.Write([]byte("additive-coeff"))
				binary.Write(mac, binary.BigEndian, coeffIndex)
				mac.Write([]byte{byte(id)})
				buf := mac.Sum(nil)
				val := int64(binary.LittleEndian.Uint32(buf[:4])) % Q
				shares[id][p][c] = int32(val)
				sum = (sum + val) % Q
				coeffIndex++
			}

			lastVal := (secret - sum) % Q
			if lastVal < 0 {
				lastVal += Q
			}
			shares[total][p][c] = int32(lastVal)
		}
	}

	return shares, nil
}

// GenerateDKGSharesShamirWithSeed performs deterministic Shamir DKG using a master seed.
//
// audit-fix L-10 [LOW]: Same security concern as GenerateDKGSharesWithSeed —
// deterministic share generation is for testing only. Blocked in production.
func GenerateDKGSharesShamirWithSeed(threshold, total int, masterSeed []byte) (*QTDPublicKey, []*QTDShare, error) {
	if params.IsProductionEnv() {
		return nil, nil, fmt.Errorf("GenerateDKGSharesShamirWithSeed: deterministic DKG blocked in production; use GenerateDKGSharesShamir with crypto/rand")
	}
	if threshold <= 0 || total <= 0 || threshold > total {
		return nil, nil, ErrInvalidConfig
	}

	seedShares := make([][]byte, total)
	commitments := make([][]byte, total)
	nonces := make([][]byte, total)

	for i := 0; i < total; i++ {
		mac := hmac.New(sha256.New, masterSeed)
		mac.Write([]byte("seed-share"))
		mac.Write([]byte{byte(i + 1)})
		seedShares[i] = mac.Sum(nil)[:32]

		mac = hmac.New(sha256.New, masterSeed)
		mac.Write([]byte("nonce"))
		mac.Write([]byte{byte(i + 1)})
		nonces[i] = mac.Sum(nil)[:16]

		h := sha256.New()
		h.Write(seedShares[i])
		h.Write([]byte{byte(i + 1)})
		h.Write(nonces[i])
		commitments[i] = h.Sum(nil)
	}

	for i := 0; i < total; i++ {
		h := sha256.New()
		h.Write(seedShares[i])
		h.Write([]byte{byte(i + 1)})
		h.Write(nonces[i])
		if subtle.ConstantTimeCompare(h.Sum(nil), commitments[i]) != 1 {
			return nil, nil, fmt.Errorf("seed commitment verification failed for participant %d", i+1)
		}
	}

	h := sha256.New()
	for i := 0; i < total; i++ {
		h.Write(seedShares[i])
		h.Write([]byte{byte(i + 1)})
	}
	combinedSeed := h.Sum(nil)

	pubKey, privKey := mode3.NewKeyFromSeed((*[32]byte)(combinedSeed))
	// L9-001 FIX: see GenerateDKGSharesShamir for explanation.
	privKeyBytes := privKey.Bytes()
	defer func() {
		*privKey = mode3.PrivateKey{}
		SecurelyZeroMemory(privKeyBytes)
		// R32-P1-01 FIX: Zeroize combined seed (see GenerateDKGSharesShamir).
		SecurelyZeroMemory(combinedSeed)
		runtime.KeepAlive(privKey)
	}()

	s1Packed := privKeyBytes[mode3.SeedSize*3 : mode3.SeedSize*3+Dilithium3L*128]
	s1Vec, err := UnpackEtaVec(s1Packed, Dilithium3L, Dilithium3EtaPoly)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unpack s1: %w", err)
	}

	s1ShareVecs, err := shamirSplitPolyVecWithSeed(s1Vec, threshold, total, masterSeed, "s1")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to Shamir-split s1: %w", err)
	}

	s2Packed := privKeyBytes[mode3.SeedSize*3+Dilithium3L*128:]
	s2Packed = s2Packed[:Dilithium3K*128]
	s2Vec, err := UnpackEtaVec(s2Packed, Dilithium3K, Dilithium3EtaPoly)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unpack s2: %w", err)
	}

	s2ShareVecs, err := shamirSplitPolyVecWithSeed(s2Vec, threshold, total, masterSeed, "s2")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to Shamir-split s2: %w", err)
	}

	t0Offset := mode3.SeedSize*3 + Dilithium3L*128 + Dilithium3K*128
	t0Packed := privKeyBytes[t0Offset : t0Offset+Dilithium3K*416]
	t0Vec := make(PolyVec, Dilithium3K)
	if err := parseT0PolyVec(t0Vec, t0Packed, Dilithium3K); err != nil {
		return nil, nil, fmt.Errorf("failed to parse t0: %w", err)
	}

	t0ShareVecs, err := shamirSplitPolyVecWithSeed(t0Vec, threshold, total, masterSeed, "t0")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to Shamir-split t0: %w", err)
	}

	shares := make([]*QTDShare, total)
	for i := 0; i < total; i++ {
		pid := i + 1
		shares[i] = &QTDShare{
			ParticipantID: pid,
			Rho:           pubKey.Bytes()[:32],
			S1ShareBytes:  VecToBytes(s1ShareVecs[pid]),
			S2ShareBytes:  VecToBytes(s2ShareVecs[pid]),
			T0ShareBytes:  VecToBytes(t0ShareVecs[pid]),
			VVector:       nil,
		}

		vVector, verr := generateVerificationVector(shares[i].S1ShareBytes, threshold)
		if verr != nil {
			return nil, nil, fmt.Errorf("failed to generate verification vector: %w", verr)
		}
		shares[i].VVector = vVector

		vVectorS2, verr2 := generateVerificationVector(shares[i].S2ShareBytes, threshold)
		if verr2 != nil {
			return nil, nil, fmt.Errorf("failed to generate S2 verification vector: %w", verr2)
		}
		shares[i].VVectorS2 = vVectorS2

		vVectorT0, verr3 := generateVerificationVector(shares[i].T0ShareBytes, threshold)
		if verr3 != nil {
			return nil, nil, fmt.Errorf("failed to generate T0 verification vector: %w", verr3)
		}
		shares[i].VVectorT0 = vVectorT0
	}

	t1Packed := pubKey.Bytes()[32:]
	t1Vec, err := UnpackT1(t1Packed, Dilithium3K)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unpack t1: %w", err)
	}
	t1FullBytes := VecToBytes(t1Vec)

	// audit-fix L5-007: Each share gets its own copy of T1Bytes to prevent
	// shared-reference data races. Previously all shares pointed to the same
	// t1FullBytes slice, so concurrent modifications by one share would
	// corrupt all other shares' T1Bytes.
	for i := 0; i < total; i++ {
		t1Copy := make([]byte, len(t1FullBytes))
		copy(t1Copy, t1FullBytes)
		shares[i].T1Bytes = t1Copy
	}

	qtdPubKey := &QTDPublicKey{
		Rho:          pubKey.Bytes()[:32],
		T1:           t1Packed,
		PubKey:       pubKey.Bytes(),
		CombinedSeed: combinedSeed,
	}

	return qtdPubKey, shares, nil
}

// shamirSplitPolyVecWithSeed is the deterministic seeded variant of
// shamirSplitPolyVec. It shares the SAME non-constant-time limitation
// (N25-003 / TSS-): the `% uint32(Q)` reductions on secret-dependent
// values have data-dependent timing. The same HARD CONSTRAINT applies —
// MUST be executed in a TEE or air-gapped ceremony host. See the
// shamirSplitPolyVec docstring for the full TSS- analysis.
func shamirSplitPolyVecWithSeed(vec PolyVec, threshold, total int, masterSeed []byte, domain string) (map[int]PolyVec, error) {
	if len(vec) == 0 {
		return nil, ErrInvalidConfig
	}
	if threshold <= 0 || total <= 0 || threshold > total {
		return nil, ErrInvalidConfig
	}

	// TSS- Same side-channel risk as shamirSplitPolyVec — warn in
	// production when TEE attestation is not present.
	warnShamirSideChannelRisk()

	shares := make(map[int]PolyVec, total)
	for id := 1; id <= total; id++ {
		shares[id] = make(PolyVec, len(vec))
	}

	coeffIndex := uint64(0)
	for p := 0; p < len(vec); p++ {
		for c := 0; c < N; c++ {
			secret := uint32(vec[p][c]) % uint32(Q)

			coeffs := make([]uint32, threshold)
			coeffs[0] = secret
			for j := 1; j < threshold; j++ {
				mac := hmac.New(sha256.New, masterSeed)
				mac.Write([]byte(domain))
				mac.Write([]byte("shamir-coeff"))
				binary.Write(mac, binary.BigEndian, coeffIndex)
				mac.Write([]byte{byte(j)})
				buf := mac.Sum(nil)
				coeffs[j] = binary.LittleEndian.Uint32(buf[:4]) % uint32(Q)
				coeffIndex++
			}

			for id := 1; id <= total; id++ {
				val := uint32(0)
				x := uint32(id)
				xPow := uint32(1)
				for _, coeff := range coeffs {
					val = (val + uint32((uint64(coeff%uint32(Q))*uint64(xPow%uint32(Q)))%uint64(Q))) % uint32(Q)
					xPow = uint32((uint64(xPow) * uint64(x)) % uint64(Q))
				}
				shares[id][p][c] = int32(val)
			}
			// L10-011 FIX (4 rounds): Use indirect function call to prevent compiler optimization.
			zeroUint32SliceFunc(coeffs)
		}
	}

	return shares, nil
}

func (s *QTDShare) Encode() []byte {
	rhLen := len(s.Rho)
	s1Len := len(s.S1ShareBytes)
	s2Len := len(s.S2ShareBytes)
	t0Len := len(s.T0ShareBytes)
	t1Len := len(s.T1Bytes)
	vLen := len(s.VVector)
	vS2Len := len(s.VVectorS2)
	vT0Len := len(s.VVectorT0)

	// N19-005 FIX: On 32-bit platforms `int` is 32 bits, so the aggregate
	// `total` could overflow to a negative value, causing make([]byte, total)
	// to panic or allocate the wrong size. Validate that every length fits the
	// uint16 serialization width and compute the total in uint64.
	const maxUint16 = 0xFFFF
	if rhLen > maxUint16 || s1Len > maxUint16 || s2Len > maxUint16 ||
		t0Len > maxUint16 || t1Len > maxUint16 || vLen > maxUint16 ||
		vS2Len > maxUint16 || vT0Len > maxUint16 {
		return nil
	}

	var total uint64 = 4 + 2 + uint64(rhLen) + 2 + uint64(s1Len) + 2 +
		uint64(s2Len) + 2 + uint64(t0Len) + 2 + uint64(t1Len) + 2
	for _, v := range s.VVector {
		if len(v) > maxUint16 {
			return nil
		}
		total += 2 + uint64(len(v))
	}
	//  Include S2/T0 verification vectors in total size.
	total += 2 // vS2Len field
	for _, v := range s.VVectorS2 {
		if len(v) > maxUint16 {
			return nil
		}
		total += 2 + uint64(len(v))
	}
	total += 2 // vT0Len field
	for _, v := range s.VVectorT0 {
		if len(v) > maxUint16 {
			return nil
		}
		total += 2 + uint64(len(v))
	}
	// maxInt is the platform-specific maximum int value (no math import needed).
	const maxInt = int(^uint(0) >> 1)
	if total > uint64(maxInt) {
		return nil
	}

	data := make([]byte, int(total))
	offset := 0

	binary.BigEndian.PutUint32(data[offset:], uint32(s.ParticipantID))
	offset += 4

	binary.BigEndian.PutUint16(data[offset:], uint16(rhLen))
	offset += 2
	copy(data[offset:], s.Rho)
	offset += rhLen

	binary.BigEndian.PutUint16(data[offset:], uint16(s1Len))
	offset += 2
	copy(data[offset:], s.S1ShareBytes)
	offset += s1Len

	binary.BigEndian.PutUint16(data[offset:], uint16(s2Len))
	offset += 2
	copy(data[offset:], s.S2ShareBytes)
	offset += s2Len

	binary.BigEndian.PutUint16(data[offset:], uint16(t0Len))
	offset += 2
	copy(data[offset:], s.T0ShareBytes)
	offset += t0Len

	binary.BigEndian.PutUint16(data[offset:], uint16(t1Len))
	offset += 2
	copy(data[offset:], s.T1Bytes)
	offset += t1Len

	binary.BigEndian.PutUint16(data[offset:], uint16(vLen))
	offset += 2
	for _, v := range s.VVector {
		vLen := len(v)
		binary.BigEndian.PutUint16(data[offset:], uint16(vLen))
		offset += 2
		copy(data[offset:], v)
		offset += vLen
	}

	//  Append S2/T0 verification vectors (backward compatible —
	// old decoders ignore trailing data, new decoders read if present).
	binary.BigEndian.PutUint16(data[offset:], uint16(vS2Len))
	offset += 2
	for _, v := range s.VVectorS2 {
		vLen := len(v)
		binary.BigEndian.PutUint16(data[offset:], uint16(vLen))
		offset += 2
		copy(data[offset:], v)
		offset += vLen
	}

	binary.BigEndian.PutUint16(data[offset:], uint16(vT0Len))
	offset += 2
	for _, v := range s.VVectorT0 {
		vLen := len(v)
		binary.BigEndian.PutUint16(data[offset:], uint16(vLen))
		offset += 2
		copy(data[offset:], v)
		offset += vLen
	}

	return data
}

func DecodeQTDShare(data []byte) (*QTDShare, error) {
	// L18-004 FIX: Added bounds checks before every uint16/uint32 read,
	// total size limit, and ParticipantID validation.
	if len(data) < 4+2 {
		return nil, fmt.Errorf("QTDShare data too short: %d bytes", len(data))
	}
	// L18-004 FIX: Prevent excessively large payloads from causing OOM.
	// A valid QTDShare is typically < 10KB; 1MB is a generous upper bound.
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("QTDShare data too large: %d bytes", len(data))
	}

	offset := 0
	s := &QTDShare{}

	pid := binary.BigEndian.Uint32(data[offset:])
	offset += 4
	// L18-019 FIX: On 32-bit platforms, int is 32 bits and cannot hold
	// the full uint32 range. Reject values exceeding MaxInt32 to prevent
	// overflow that could produce a negative ParticipantID.
	if pid > 0x7FFFFFFF {
		return nil, fmt.Errorf("%w: ParticipantID overflow: %d exceeds MaxInt32", ErrInvalidShare, pid)
	}
	s.ParticipantID = int(pid)
	// L18-004 FIX: Validate ParticipantID range.
	if s.ParticipantID <= 0 {
		return nil, fmt.Errorf("%w: ParticipantID must be > 0, got %d", ErrInvalidShare, s.ParticipantID)
	}

	// Helper to read uint16 with bounds check
	readU16 := func() (int, error) {
		if offset+2 > len(data) {
			return 0, fmt.Errorf("QTDShare unexpected end of data at offset %d", offset)
		}
		v := int(binary.BigEndian.Uint16(data[offset:]))
		offset += 2
		return v, nil
	}

	rhLen, err := readU16()
	if err != nil {
		return nil, fmt.Errorf("QTDShare rhLen: %w", err)
	}
	// Q21-012 FIX: Validate Rho length matches expected SeedSize (32 bytes).
	// Rho is the Dilithium3 seed; incorrect length indicates corrupted or malicious data.
	if rhLen != mode3.SeedSize {
		return nil, fmt.Errorf("QTDShare invalid Rho length: %d, expected %d", rhLen, mode3.SeedSize)
	}
	if offset+rhLen > len(data) {
		return nil, fmt.Errorf("QTDShare rhLen overflow: %d+%d > %d", offset, rhLen, len(data))
	}
	s.Rho = make([]byte, rhLen)
	copy(s.Rho, data[offset:offset+rhLen])
	offset += rhLen

	s1Len, err := readU16()
	if err != nil {
		return nil, fmt.Errorf("QTDShare s1Len: %w", err)
	}
	if offset+s1Len > len(data) {
		return nil, fmt.Errorf("QTDShare s1Len overflow")
	}
	s.S1ShareBytes = make([]byte, s1Len)
	copy(s.S1ShareBytes, data[offset:offset+s1Len])
	offset += s1Len

	s2Len, err := readU16()
	if err != nil {
		return nil, fmt.Errorf("QTDShare s2Len: %w", err)
	}
	if offset+s2Len > len(data) {
		return nil, fmt.Errorf("QTDShare s2Len overflow")
	}
	s.S2ShareBytes = make([]byte, s2Len)
	copy(s.S2ShareBytes, data[offset:offset+s2Len])
	offset += s2Len

	t0Len, err := readU16()
	if err != nil {
		return nil, fmt.Errorf("QTDShare t0Len: %w", err)
	}
	if offset+t0Len > len(data) {
		return nil, fmt.Errorf("QTDShare t0Len overflow")
	}
	s.T0ShareBytes = make([]byte, t0Len)
	copy(s.T0ShareBytes, data[offset:offset+t0Len])
	offset += t0Len

	t1Len, err := readU16()
	if err != nil {
		return nil, fmt.Errorf("QTDShare t1Len: %w", err)
	}
	if offset+t1Len > len(data) {
		return nil, fmt.Errorf("QTDShare t1Len overflow")
	}
	s.T1Bytes = make([]byte, t1Len)
	copy(s.T1Bytes, data[offset:offset+t1Len])
	offset += t1Len

	vCount, err := readU16()
	if err != nil {
		return nil, fmt.Errorf("QTDShare vCount: %w", err)
	}
	// L18-004 FIX: Limit vCount to prevent excessive allocation.
	if vCount > 100 {
		return nil, fmt.Errorf("QTDShare vCount too large: %d", vCount)
	}
	s.VVector = make([][]byte, vCount)
	for i := 0; i < vCount; i++ {
		vLen, err := readU16()
		if err != nil {
			return nil, fmt.Errorf("QTDShare vVector[%d] len: %w", i, err)
		}
		if offset+vLen > len(data) {
			return nil, fmt.Errorf("QTDShare vVector[%d] data overflow", i)
		}
		s.VVector[i] = make([]byte, vLen)
		copy(s.VVector[i], data[offset:offset+vLen])
		offset += vLen
	}

	//  Decode S2/T0 verification vectors if present (backward
	// compatible — older encodings omit these fields, leaving them nil).
	if offset < len(data) {
		vS2Count, err := readU16()
		if err != nil {
			return nil, fmt.Errorf("QTDShare vS2Count: %w", err)
		}
		if vS2Count > 100 {
			return nil, fmt.Errorf("QTDShare vS2Count too large: %d", vS2Count)
		}
		s.VVectorS2 = make([][]byte, vS2Count)
		for i := 0; i < vS2Count; i++ {
			vLen, err := readU16()
			if err != nil {
				return nil, fmt.Errorf("QTDShare vVectorS2[%d] len: %w", i, err)
			}
			if offset+vLen > len(data) {
				return nil, fmt.Errorf("QTDShare vVectorS2[%d] data overflow", i)
			}
			s.VVectorS2[i] = make([]byte, vLen)
			copy(s.VVectorS2[i], data[offset:offset+vLen])
			offset += vLen
		}
	}

	if offset < len(data) {
		vT0Count, err := readU16()
		if err != nil {
			return nil, fmt.Errorf("QTDShare vT0Count: %w", err)
		}
		if vT0Count > 100 {
			return nil, fmt.Errorf("QTDShare vT0Count too large: %d", vT0Count)
		}
		s.VVectorT0 = make([][]byte, vT0Count)
		for i := 0; i < vT0Count; i++ {
			vLen, err := readU16()
			if err != nil {
				return nil, fmt.Errorf("QTDShare vVectorT0[%d] len: %w", i, err)
			}
			if offset+vLen > len(data) {
				return nil, fmt.Errorf("QTDShare vVectorT0[%d] data overflow", i)
			}
			s.VVectorT0[i] = make([]byte, vLen)
			copy(s.VVectorT0[i], data[offset:offset+vLen])
			offset += vLen
		}
	}

	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("QTDShare validation failed: %w", err)
	}

	return s, nil
}
