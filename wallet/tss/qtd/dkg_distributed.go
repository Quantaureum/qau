// Quantaureum Node source, version 1.0.0.
package qtd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/quantaureum/qau/pedersen"
	"golang.org/x/crypto/sha3"
)

// ============================================================================
// TSS-R7-01 closure (2026-08-21) — real GM-QTD distributed DKG runner.
//
// R43-VSS (2026-08-22): replaced the legacy SHA256 commitment + plaintext
// CommitmentOpening with Pedersen VSS (Feldman variant). Each participant
// publishes Pedersen VSS commitments for every Shamir polynomial coefficient
// (g^coeff · h^blind) in Round1, then distributes blind shares (blind
// polynomial evaluations) in Round2 so receivers can run VSS verification
// without ever revealing any participant's full s1_i/s2_i. See
// qtd/dkg_runner.go for the wire format.
//
// State machine: idle → round1 → round2 → done. All methods hold the mutex;
// out-of-order, duplicate, or cross-session messages are rejected.
// ============================================================================

// DKG error sentinels (alongside ErrDistributedDKGNotImplemented).
var (
	// ErrDKGWrongSession — message sessionID does not match this runner.
	ErrDKGWrongSession = errors.New("dkg: message belongs to a different session")
	// ErrDKGDuplicateCommitment — same participant submitted Round1 commitment twice.
	ErrDKGDuplicateCommitment = errors.New("dkg: duplicate commitment from participant")
	// ErrDKGInvalidThreshold — threshold < 2 or exceeds total.
	ErrDKGInvalidThreshold = errors.New("dkg: invalid threshold (must satisfy 2 <= threshold <= total)")
	// ErrDKGIncompleteRound — current round is missing some participant messages.
	ErrDKGIncompleteRound = errors.New("dkg: round is incomplete (missing participant messages)")
	// ErrDKGInvalidState — call order violates idle→round1→round2→done state machine.
	ErrDKGInvalidState = errors.New("dkg: invalid state for this operation")
	// ErrDKGUnknownParticipant — participant ID out of range or not recognized.
	ErrDKGUnknownParticipant = errors.New("dkg: unknown or out-of-range participant ID")
	// ErrDKGMissingShare — open message lacks the share destined for this participant.
	ErrDKGMissingShare = errors.New("dkg: message is missing the share destined for this participant")
	// ErrDKGShareMismatch — share does not match deterministic recomputation (tampered).
	ErrDKGShareMismatch = errors.New("dkg: share does not match deterministic recomputation (tampered)")
)

const (
	dkgStateIdle = iota
	dkgStateRound1
	dkgStateRound2
	dkgStateDone
)

// Domain separator for deterministic t0 splitting (t0 is publicly derivable, no need to hide it).
const (
	dkgSplitDomain = "QTD-DKG-SPLIT-v1"
	dkgDomainT0    = 3
)

// realDistributedDKGRunner is a transport-agnostic implementation of DistributedDKGRunner.
type realDistributedDKGRunner struct {
	mu        sync.Mutex
	sessionID []byte
	rho       [32]byte

	state     int
	pid       int
	threshold int
	total     int

	// Local secrets (sampled in Round1, Zeroize'd immediately after Round2 splitting).
	s1 PolyVec
	s2 PolyVec

	// Messages received in Round1.
	commitments map[int][]byte
	pubContribs map[int][]byte

	// Shares received in Round2 addressed to this participant (summed at Final, then Zeroize'd).
	s1Shares map[int]PolyVec
	s2Shares map[int]PolyVec
	t0Shares map[int]PolyVec

	// R43-VSS: Feldman VSS blind-polynomial store and Pedersen generator.
	feldmanStore *feldmanBlindStore
	pedersenGen  *pedersen.Generator
}

// NewRealDistributedDKGRunner constructs a real distributed DKG runner.
// sessionID and rho must be agreed upon by all participants before the
// session begins; the runner validates every message against sessionID.
func NewRealDistributedDKGRunner(sessionID []byte, rho [32]byte) DistributedDKGRunner {
	return &realDistributedDKGRunner{
		sessionID:   append([]byte(nil), sessionID...),
		rho:         rho,
		state:       dkgStateIdle,
		commitments: make(map[int][]byte),
		pubContribs: make(map[int][]byte),
		s1Shares:    make(map[int]PolyVec),
		s2Shares:    make(map[int]PolyVec),
		t0Shares:    make(map[int]PolyVec),
	}
}

// dkgDeterministicSplitT0 deterministically Shamir-splits t0 into degree-(threshold-1) shares.
// t0 is publicly derivable, so it needs no hiding. Polynomial coefficients are expanded deterministically via SHAKE256.
// x coordinates are participant IDs 1..total, consistent with the shamirSplitPolyVec convention.
func dkgDeterministicSplitT0(secret PolyVec, threshold, total int, sessionID []byte, pid int) (map[int]PolyVec, error) {
	if threshold < 2 || threshold > total || total <= 0 {
		return nil, ErrDKGInvalidThreshold
	}
	xof := sha3.NewShake256()
	xof.Write([]byte(dkgSplitDomain))
	xof.Write([]byte{dkgDomainT0})
	xof.Write(sessionID)
	var pidBuf [4]byte
	binary.LittleEndian.PutUint32(pidBuf[:], uint32(pid))
	xof.Write(pidBuf[:])
	xof.Write(VecToBytes(secret))

	shares := make(map[int]PolyVec, total)
	for id := 1; id <= total; id++ {
		shares[id] = make(PolyVec, len(secret))
	}

	var coeffBuf [4]byte
	for p := range secret {
		for c := 0; c < N; c++ {
			coeffs := make([]uint32, threshold)
			coeffs[0] = uint32(secret[p][c]) % uint32(Q)
			for j := 1; j < threshold; j++ {
				if _, err := xof.Read(coeffBuf[:]); err != nil {
					zeroUint32SliceFunc(coeffs)
					return nil, fmt.Errorf("dkg: deterministic coefficient expansion: %w", err)
				}
				coeffs[j] = binary.LittleEndian.Uint32(coeffBuf[:]) % uint32(Q)
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
			zeroUint32SliceFunc(coeffs)
		}
	}
	return shares, nil
}

// computeTFromContributions aggregates all participants' PubContribution to obtain
// t = Σ (A·s1_i + s2_i), then Power2Round yields (t1, t0). t is publicly derivable.
func computeTFromContributions(pubContribs map[int][]byte, total int) (t1 PolyVec, t0 PolyVec, err error) {
	if len(pubContribs) != total {
		return nil, nil, ErrDKGIncompleteRound
	}
	tVec := make(PolyVec, Dilithium3K)
	for pid := 1; pid <= total; pid++ {
		contrib, cerr := VecFromBytes(pubContribs[pid], Dilithium3K)
		if cerr != nil {
			return nil, nil, fmt.Errorf("dkg: decode PubContribution from pid %d: %w", pid, cerr)
		}
		for j := range tVec {
			tVec[j].Add(&tVec[j], &contrib[j])
		}
	}
	for i := range tVec {
		tVec[i].Reduce()
	}
	t1 = make(PolyVec, Dilithium3K)
	t0 = make(PolyVec, Dilithium3K)
	for i := range tVec {
		Power2RoundPoly(&t0[i], &t1[i], &tVec[i])
	}
	for i := range t0 {
		t0[i].Reduce() // normalize Q+t0 into [0, Q-1]; equivalent mod Q
	}
	for i := range tVec {
		zeroPolyFunc(&tVec[i])
	}
	return t1, t0, nil
}

// zeroizePolyVec clears a sensitive polynomial vector.
func zeroizePolyVec(v PolyVec) {
	for i := range v {
		zeroPolyFunc(&v[i])
	}
}

// InitiateRound1 samples local (s1_i, s2_i), computes the PubContribution and the
// Pedersen VSS commitment set (Feldman variant).
func (r *realDistributedDKGRunner) InitiateRound1(participantID, threshold, totalParticipants int) (*Round1CommitmentMessage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.state != dkgStateIdle {
		return nil, ErrDKGInvalidState
	}
	if threshold < 2 || threshold > totalParticipants || totalParticipants <= 0 {
		return nil, fmt.Errorf("%w (threshold=%d total=%d)", ErrDKGInvalidThreshold, threshold, totalParticipants)
	}
	if participantID < 1 || participantID > totalParticipants {
		return nil, ErrDKGUnknownParticipant
	}

	s1, err := sampleSmallPolyVec(Dilithium3L, Dilithium3EtaPoly)
	if err != nil {
		return nil, fmt.Errorf("dkg: sample s1: %w", err)
	}
	s2, err := sampleSmallPolyVec(Dilithium3K, Dilithium3EtaPoly)
	if err != nil {
		zeroizePolyVec(s1)
		return nil, fmt.Errorf("dkg: sample s2: %w", err)
	}

	aMat, err := ComputeA(r.rho[:], Dilithium3K, Dilithium3L)
	if err != nil {
		zeroizePolyVec(s1)
		zeroizePolyVec(s2)
		return nil, fmt.Errorf("dkg: ComputeA: %w", err)
	}
	w := ComputeW(aMat, s1)
	for i := range w {
		w[i].Add(&w[i], &s2[i])
		w[i].Reduce()
	}
	pubContrib := VecToBytes(w)
	zeroizePolyVec(w)

	// R43-VSS: generate the Pedersen VSS commitment set instead of the SHA256 commitment
	gen, err := pedersen.NewGenerator()
	if err != nil {
		zeroizePolyVec(s1)
		zeroizePolyVec(s2)
		return nil, fmt.Errorf("dkg: pedersen generator: %w", err)
	}
	commitSet, store, err := generateFeldmanCommitmentSet(s1, s2, threshold, r.sessionID, gen)
	if err != nil {
		zeroizePolyVec(s1)
		zeroizePolyVec(s2)
		return nil, fmt.Errorf("dkg: feldman commitment set: %w", err)
	}

	r.pid = participantID
	r.threshold = threshold
	r.total = totalParticipants
	r.s1 = s1
	r.s2 = s2
	r.pedersenGen = gen
	r.feldmanStore = store
	r.state = dkgStateRound1

	return &Round1CommitmentMessage{
		ParticipantID:   participantID,
		Commitment:      commitSet,
		PubContribution: pubContrib,
	}, nil
}

// checkCommitmentWellFormed validates the structural legality of a Round1 message.
func (r *realDistributedDKGRunner) checkCommitmentWellFormed(msg *Round1CommitmentMessage) error {
	if msg == nil {
		return fmt.Errorf("%w: nil commitment message", ErrDKGUnknownParticipant)
	}
	if msg.ParticipantID < 1 || msg.ParticipantID > r.total {
		return fmt.Errorf("%w: pid=%d", ErrDKGUnknownParticipant, msg.ParticipantID)
	}
	if err := validateFeldmanCommitmentSet(msg.Commitment, r.sessionID, Dilithium3L, Dilithium3K, r.threshold); err != nil {
		return err
	}
	if len(msg.PubContribution) != Dilithium3K*N*3 {
		return fmt.Errorf("dkg: PubContribution length %d, want %d", len(msg.PubContribution), Dilithium3K*N*3)
	}
	if _, err := VecFromBytes(msg.PubContribution, Dilithium3K); err != nil {
		return fmt.Errorf("dkg: PubContribution undecodable: %w", err)
	}
	return nil
}

// SubmitCommitment accepts a Round1 commitment. One's own message must also
// travel the same path (self-delivery), keeping the state machine symmetric.
func (r *realDistributedDKGRunner) SubmitCommitment(msg *Round1CommitmentMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.state != dkgStateRound1 {
		return ErrDKGInvalidState
	}
	if err := r.checkCommitmentWellFormed(msg); err != nil {
		return err
	}
	if _, dup := r.commitments[msg.ParticipantID]; dup {
		return fmt.Errorf("%w: pid=%d", ErrDKGDuplicateCommitment, msg.ParticipantID)
	}
	r.commitments[msg.ParticipantID] = append([]byte(nil), msg.Commitment...)
	r.pubContribs[msg.ParticipantID] = append([]byte(nil), msg.PubContribution...)
	return nil
}

// VerifyCommitment validates the structural legality of a commitment (without verifying the opening).
func (r *realDistributedDKGRunner) VerifyCommitment(msg *Round1CommitmentMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != dkgStateRound1 && r.state != dkgStateRound2 {
		return ErrDKGInvalidState
	}
	return r.checkCommitmentWellFormed(msg)
}

// InitiateRound2 distributes random Shamir shares of s1_i/s2_i + Pedersen blind shares,
// plus deterministic shares of t0. t0 convention: only the pid==1 participant splits the real t0; the others split
// the zero vector (t0 is publicly derivable; no extra leakage).
func (r *realDistributedDKGRunner) InitiateRound2() (map[int]*Round1OpenMessage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.state != dkgStateRound1 {
		return nil, ErrDKGInvalidState
	}
	if len(r.commitments) != r.total {
		return nil, fmt.Errorf("%w: have %d/%d commitments", ErrDKGIncompleteRound, len(r.commitments), r.total)
	}

	// s1/s2 are split with the polynomial coefficients stored by Feldman, ensuring consistency with the commitment set
	s1Shares, err := feldmanSplitPolyVec(r.feldmanStore.s1Polys, Dilithium3L, r.threshold, r.total)
	if err != nil {
		return nil, fmt.Errorf("dkg: feldman split s1: %w", err)
	}
	s2Shares, err := feldmanSplitPolyVec(r.feldmanStore.s2Polys, Dilithium3K, r.threshold, r.total)
	if err != nil {
		return nil, fmt.Errorf("dkg: feldman split s2: %w", err)
	}

	// compute the s1/s2 blind shares (for Pedersen VSS verification)
	s1BlindShares, s2BlindShares, err := computeFeldmanBlindShares(r.feldmanStore, r.total)
	if err != nil {
		return nil, fmt.Errorf("dkg: blind shares: %w", err)
	}

	// t0 contribution: pid==1 uses the real t0, the rest use the zero vector (deterministic split, publicly verifiable)
	var t0Secret PolyVec
	if r.pid == 1 {
		_, t0, terr := computeTFromContributions(r.pubContribs, r.total)
		if terr != nil {
			return nil, fmt.Errorf("dkg: compute t0: %w", terr)
		}
		t0Secret = t0
	} else {
		t0Secret = make(PolyVec, Dilithium3K)
	}
	t0Shares, err := dkgDeterministicSplitT0(t0Secret, r.threshold, r.total, r.sessionID, r.pid)
	if err != nil {
		if r.pid == 1 {
			zeroizePolyVec(t0Secret)
		}
		return nil, fmt.Errorf("dkg: split t0: %w", err)
	}
	if r.pid == 1 {
		zeroizePolyVec(t0Secret)
	}

	msgs := make(map[int]*Round1OpenMessage, r.total)
	for recipient := 1; recipient <= r.total; recipient++ {
		msgs[recipient] = &Round1OpenMessage{
			ParticipantID: r.pid,
			S1ShareShares: map[int][]byte{recipient: vecToBytesFull(s1Shares[recipient])},
			S2ShareShares: map[int][]byte{recipient: vecToBytesFull(s2Shares[recipient])},
			T0ShareShares: map[int][]byte{recipient: VecToBytes(t0Shares[recipient])},
			S1BlindShares: map[int][]byte{recipient: s1BlindShares[recipient]},
			S2BlindShares: map[int][]byte{recipient: s2BlindShares[recipient]},
		}
		zeroizePolyVec(s1Shares[recipient])
		zeroizePolyVec(s2Shares[recipient])
		zeroizePolyVec(t0Shares[recipient])
	}

	// local secrets are no longer needed; clear immediately
	zeroizePolyVec(r.s1)
	zeroizePolyVec(r.s2)
	r.s1 = nil
	r.s2 = nil

	// Feldman VSS blind polynomial storage is no longer needed
	zeroizeFeldmanStore(r.feldmanStore)
	r.feldmanStore = nil
	r.pedersenGen = nil

	r.state = dkgStateRound2
	return msgs, nil
}

// SubmitShare receives sender s's open message: verifies the share with Pedersen VSS,
// deterministically recomputes t0 for comparison, then stages it. Self-delivery follows the same path.
func (r *realDistributedDKGRunner) SubmitShare(msg *Round1OpenMessage) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.state != dkgStateRound2 {
		return ErrDKGInvalidState
	}
	if msg == nil || msg.ParticipantID < 1 || msg.ParticipantID > r.total {
		return ErrDKGUnknownParticipant
	}
	sender := msg.ParticipantID
	if _, dup := r.s1Shares[sender]; dup {
		return fmt.Errorf("%w: share from pid=%d", ErrDKGDuplicateCommitment, sender)
	}
	storedCommit, ok := r.commitments[sender]
	if !ok {
		return fmt.Errorf("%w: share from pid=%d without prior round1 commitment", ErrDKGInvalidState, sender)
	}

	if msg.S1ShareShares == nil || msg.S2ShareShares == nil || msg.T0ShareShares == nil {
		return fmt.Errorf("%w: nil share maps from pid=%d", ErrDKGMissingShare, sender)
	}
	if msg.S1BlindShares == nil || msg.S2BlindShares == nil {
		return fmt.Errorf("%w: nil blind share maps from pid=%d", ErrDKGMissingShare, sender)
	}
	gotS1, ok := msg.S1ShareShares[r.pid]
	if !ok {
		return fmt.Errorf("%w: s1 from pid=%d", ErrDKGMissingShare, sender)
	}
	gotS2, ok := msg.S2ShareShares[r.pid]
	if !ok {
		return fmt.Errorf("%w: s2 from pid=%d", ErrDKGMissingShare, sender)
	}
	gotT0, ok := msg.T0ShareShares[r.pid]
	if !ok {
		return fmt.Errorf("%w: t0 from pid=%d", ErrDKGMissingShare, sender)
	}
	gotS1Blind, ok := msg.S1BlindShares[r.pid]
	if !ok {
		return fmt.Errorf("%w: s1 blind from pid=%d", ErrDKGMissingShare, sender)
	}
	gotS2Blind, ok := msg.S2BlindShares[r.pid]
	if !ok {
		return fmt.Errorf("%w: s2 blind from pid=%d", ErrDKGMissingShare, sender)
	}

	// R43-VSS: verify the s1/s2 shares with Pedersen VSS
	gen, err := pedersen.NewGenerator()
	if err != nil {
		return fmt.Errorf("dkg: pedersen generator: %w", err)
	}
	if err := verifyFeldmanShare(storedCommit, gotS1, gotS1Blind, true, r.pid, r.threshold, Dilithium3L, Dilithium3K, gen); err != nil {
		return fmt.Errorf("dkg: s1 VSS from pid=%d: %w", sender, err)
	}
	if err := verifyFeldmanShare(storedCommit, gotS2, gotS2Blind, false, r.pid, r.threshold, Dilithium3L, Dilithium3K, gen); err != nil {
		return fmt.Errorf("dkg: s2 VSS from pid=%d: %w", sender, err)
	}

	// t0 deterministic recomputation and comparison
	var t0Secret PolyVec
	if sender == 1 {
		_, t0, terr := computeTFromContributions(r.pubContribs, r.total)
		if terr != nil {
			return terr
		}
		t0Secret = t0
	} else {
		t0Secret = make(PolyVec, Dilithium3K)
	}
	expT0, err := dkgDeterministicSplitT0(t0Secret, r.threshold, r.total, r.sessionID, sender)
	if err != nil {
		if sender == 1 {
			zeroizePolyVec(t0Secret)
		}
		return err
	}
	if sender == 1 {
		zeroizePolyVec(t0Secret)
	}
	if !bytes.Equal(gotT0, VecToBytes(expT0[r.pid])) {
		zeroizePolyVec(expT0[r.pid])
		return fmt.Errorf("%w: t0 sender pid=%d recipient pid=%d", ErrDKGShareMismatch, sender, r.pid)
	}

	// stage the shares: s1/s2 are full integer evaluations; after VSS verification they are stored reduced mod Q
	myS1Full, err := vecFromBytesFull(gotS1, Dilithium3L)
	if err != nil {
		return fmt.Errorf("dkg: decode s1 share from pid=%d: %w", sender, err)
	}
	myS2Full, err := vecFromBytesFull(gotS2, Dilithium3K)
	if err != nil {
		zeroizePolyVec(myS1Full)
		return fmt.Errorf("dkg: decode s2 share from pid=%d: %w", sender, err)
	}
	myS1 := reduceFullShareToQ(myS1Full)
	myS2 := reduceFullShareToQ(myS2Full)
	zeroizePolyVec(myS1Full)
	zeroizePolyVec(myS2Full)
	myT0 := make(PolyVec, Dilithium3K)
	copy(myT0, expT0[r.pid])
	zeroizePolyVec(expT0[r.pid])

	r.s1Shares[sender] = myS1
	r.s2Shares[sender] = myS2
	r.t0Shares[sender] = myT0
	return nil
}

// Finalize aggregates all shares into this participant's global share and builds the group public key and QTDShare.
func (r *realDistributedDKGRunner) Finalize() (*DKGResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.state != dkgStateRound2 {
		return nil, ErrDKGInvalidState
	}
	if len(r.s1Shares) != r.total {
		return nil, fmt.Errorf("%w: have %d/%d shares", ErrDKGIncompleteRound, len(r.s1Shares), r.total)
	}

	// coefficient-wise summation: at the same x coordinate, the sum of degree-(t-1) polynomials is still a legal Shamir share.
	s1Share := make(PolyVec, Dilithium3L)
	s2Share := make(PolyVec, Dilithium3K)
	t0Share := make(PolyVec, Dilithium3K)
	for sender := 1; sender <= r.total; sender++ {
		for j := range s1Share {
			s1Share[j].Add(&s1Share[j], &r.s1Shares[sender][j])
		}
		for j := range s2Share {
			s2Share[j].Add(&s2Share[j], &r.s2Shares[sender][j])
		}
		for j := range t0Share {
			t0Share[j].Add(&t0Share[j], &r.t0Shares[sender][j])
		}
		zeroizePolyVec(r.s1Shares[sender])
		zeroizePolyVec(r.s2Shares[sender])
		zeroizePolyVec(r.t0Shares[sender])
		delete(r.s1Shares, sender)
		delete(r.s2Shares, sender)
		delete(r.t0Shares, sender)
	}

	// t = Σ PubContribution → Power2Round → t1 → public key
	t1Vec, t0Check, err := computeTFromContributions(r.pubContribs, r.total)
	if err != nil {
		return nil, err
	}
	_ = t0Check
	zeroizePolyVec(t0Check)

	t1Packed := PackT1Vec(t1Vec)
	for i := range t1Vec {
		zeroPolyFunc(&t1Vec[i])
	}
	if len(t1Packed) != Dilithium3K*320 {
		return nil, fmt.Errorf("dkg: t1 packed size mismatch: %d", len(t1Packed))
	}
	var pkBuf [mode3.PublicKeySize]byte
	copy(pkBuf[:32], r.rho[:])
	copy(pkBuf[32:], t1Packed)
	var pubKey mode3.PublicKey
	pubKey.Unpack(&pkBuf)

	share := &QTDShare{
		ParticipantID: r.pid,
		Rho:           append([]byte(nil), r.rho[:]...),
		S1ShareBytes:  VecToBytes(s1Share),
		S2ShareBytes:  VecToBytes(s2Share),
		T0ShareBytes:  VecToBytes(t0Share),
	}
	zeroizePolyVec(s1Share)
	zeroizePolyVec(s2Share)
	zeroizePolyVec(t0Share)

	vVector, verr := generateVerificationVector(share.S1ShareBytes, r.threshold)
	if verr != nil {
		share.Zeroize()
		return nil, fmt.Errorf("dkg: VVector s1: %w", verr)
	}
	share.VVector = vVector
	vVectorS2, verr := generateVerificationVector(share.S2ShareBytes, r.threshold)
	if verr != nil {
		share.Zeroize()
		return nil, fmt.Errorf("dkg: VVector s2: %w", verr)
	}
	share.VVectorS2 = vVectorS2
	vVectorT0, verr := generateVerificationVector(share.T0ShareBytes, r.threshold)
	if verr != nil {
		share.Zeroize()
		return nil, fmt.Errorf("dkg: VVector t0: %w", verr)
	}
	share.VVectorT0 = vVectorT0
	share.T1Bytes = append([]byte(nil), t1Packed...)

	r.state = dkgStateDone
	return &DKGResult{
		GroupPublicKey: &QTDPublicKey{
			Rho:          append([]byte(nil), r.rho[:]...),
			T1:           append([]byte(nil), t1Packed...),
			PubKey:       append([]byte(nil), pubKey.Bytes()...),
			CombinedSeed: nil,
		},
		MyShare: share,
	}, nil
}

// IsPlaceholder implements DistributedDKGRunner: the real implementation must return false.
func (r *realDistributedDKGRunner) IsPlaceholder() bool { return false }
