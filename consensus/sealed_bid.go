// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

const (
	SealedBidNonceSize     = 32
	MaxSealedBidsPerSlot   = 1024
	SealedBidCommitTimeout = 4 * time.Second
	SealedBidRevealTimeout = 4 * time.Second
	// L20-001 FIX: Slot-based deadline constants for deterministic phase
	// transitions. These replace wall-clock time (time.Now) to prevent block
	// proposers from manipulating perceived time to gain unfair election advantage.
	SealedBidCommitSlots = 4 // commit phase lasts 4 slots
	SealedBidRevealSlots = 4 // reveal phase lasts 4 slots
)

var (
	// MinSealedBidAmount is the minimum bid for commit-reveal (1 QAU = 10^18 base units).
	// L11-007 FIX: prevents dust/griefing bids that cost nothing to commit.
	MinSealedBidAmount = big.NewInt(1e18)

	// DefaultSlashAmount is the default slash penalty in base units (1000 QAU).
	// L11-007 FIX: was 1000 (raw value, effectively 0 QAU), now 1000 * 1e18 = 1000 QAU.
	DefaultSlashAmount = new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
)

var (
	ErrSealedBidInvalidPhase     = errors.New("sealedbid: invalid phase for this operation")
	ErrSealedBidAlreadyCommitted = errors.New("sealedbid: validator already committed")
	ErrSealedBidNotCommitted     = errors.New("sealedbid: validator has not committed")
	ErrSealedBidAlreadyRevealed  = errors.New("sealedbid: validator already revealed")
	ErrSealedBidInvalidCommit    = errors.New("sealedbid: invalid commit")
	ErrSealedBidInvalidReveal    = errors.New("sealedbid: invalid reveal")
	ErrSealedBidSlotExpired      = errors.New("sealedbid: slot expired")
	ErrSealedBidCommitMismatch   = errors.New("sealedbid: reveal does not match commitment hash")
	ErrSealedBidTooManyBids      = errors.New("sealedbid: too many bids for this slot")
	ErrSealedBidRevealTimeout    = errors.New("sealedbid: reveal phase timed out")
	ErrSealedBidNilKey           = errors.New("sealedbid: nil private key")
	ErrSealedBidVRFVerifyFailed  = errors.New("sealedbid: VRF proof verification failed")
	ErrSealedBidInsufficientBid  = errors.New("sealedbid: bid amount below minimum (1 QAU)")
)

type SealedBidPhase uint8

const (
	SealedBidPhaseCommit SealedBidPhase = iota
	SealedBidPhaseReveal
	SealedBidPhaseComplete
	SealedBidPhaseExpired
)

func (p SealedBidPhase) String() string {
	switch p {
	case SealedBidPhaseCommit:
		return "COMMIT"
	case SealedBidPhaseReveal:
		return "REVEAL"
	case SealedBidPhaseComplete:
		return "COMPLETE"
	case SealedBidPhaseExpired:
		return "EXPIRED"
	default:
		return "UNKNOWN"
	}
}

type SealedBidCommit struct {
	ValidatorAddr  types.Address
	CommitmentHash [32]byte
	BidAmount      *big.Int // L11-007: minimum 1 QAU (10^18 base units)
	Slot           uint64
	Timestamp      time.Time
}

type SealedBidReveal struct {
	ValidatorAddr types.Address
	VRFProof      *PQVRFProof
	VRFOutput     *PQVRFOutput
	Nonce         [SealedBidNonceSize]byte
	Slot          uint64
	Timestamp     time.Time
}

type SealedBidResult struct {
	Slot           uint64
	SelectedAddr   types.Address
	SelectedOutput *PQVRFOutput
	RevealedAddrs  []types.Address
	SlashedAddrs   []types.Address
	Phase          SealedBidPhase
}

type SealedBidLottery struct {
	mu sync.RWMutex

	slot  uint64
	phase SealedBidPhase

	commits map[types.Address]*SealedBidCommit
	reveals map[types.Address]*SealedBidReveal

	commitDeadline time.Time
	revealDeadline time.Time

	// L20-001 FIX: Slot-based deadlines for deterministic phase transitions.
	// When currentSlot > 0, updatePhaseLocked uses slot comparison instead of
	// wall-clock time, preventing block proposers from manipulating time.
	currentSlot        uint64
	commitDeadlineSlot uint64
	revealDeadlineSlot uint64

	slashAmount *big.Int
}

func NewSealedBidLottery(slot uint64) *SealedBidLottery {
	// L20-001 FIX: Use deterministic slot-based deadlines instead of time.Now().
	// Block proposers can manipulate perceived wall-clock time, but slot/height
	// progression is deterministic and verifiable on-chain. Callers must use
	// SetCurrentSlot() to advance phase transitions deterministically.
	return &SealedBidLottery{
		slot:               slot,
		phase:              SealedBidPhaseCommit,
		commits:            make(map[types.Address]*SealedBidCommit),
		reveals:            make(map[types.Address]*SealedBidReveal),
		commitDeadlineSlot: slot + SealedBidCommitSlots,
		revealDeadlineSlot: slot + SealedBidCommitSlots + SealedBidRevealSlots,
		slashAmount:        new(big.Int).Set(DefaultSlashAmount),
	}
}

// NewSealedBidLotteryWithTimeouts creates a SealedBidLottery with slot-based
// deadlines derived from the given time durations (converted to slot counts).
//
// R33 P2-20 FIX (2026-07-28): Previously this constructor set wall-clock
// deadlines using time.Now(), which could be manipulated by block proposers
// to gain unfair election advantage. Now it ONLY sets slot-based deadlines
// (commitDeadlineSlot/revealDeadlineSlot). Callers MUST use SetCurrentSlot()
// to drive phase transitions deterministically.
//
// The commitTimeout and revealTimeout parameters are retained for backward
// compatibility but are used ONLY to derive slot-based deadline offsets
// (assuming 12-second slot time). They are NOT used to set wall-clock deadlines.
//
// Deprecated: Use NewSealedBidLottery(slot) instead, which uses the default
// SealedBidCommitSlots/SealedBidRevealSlots constants directly.
func NewSealedBidLotteryWithTimeouts(slot uint64, commitTimeout, revealTimeout time.Duration) *SealedBidLottery {
	// R33 P2-20 FIX: Convert time durations to slot counts (12s per slot).
	// This avoids using time.Now() entirely. Slot-based deadlines are
	// deterministic and cannot be manipulated by block proposers.
	commitSlots := uint64(commitTimeout / (12 * time.Second))
	if commitSlots == 0 {
		commitSlots = SealedBidCommitSlots
	}
	revealSlots := uint64(revealTimeout / (12 * time.Second))
	if revealSlots == 0 {
		revealSlots = SealedBidRevealSlots
	}
	return &SealedBidLottery{
		slot:    slot,
		phase:   SealedBidPhaseCommit,
		commits: make(map[types.Address]*SealedBidCommit),
		reveals: make(map[types.Address]*SealedBidReveal),
		// R33 P2-20 FIX: commitDeadline/revealDeadline left as zero values.
		// Phase transitions are driven by SetCurrentSlot() only.
		commitDeadlineSlot: slot + commitSlots,
		revealDeadlineSlot: slot + commitSlots + revealSlots,
		slashAmount:        new(big.Int).Set(DefaultSlashAmount),
	}
}

func (sbl *SealedBidLottery) Slot() uint64 {
	sbl.mu.RLock()
	defer sbl.mu.RUnlock()
	return sbl.slot
}

func (sbl *SealedBidLottery) Phase() SealedBidPhase {
	sbl.mu.Lock()
	defer sbl.mu.Unlock()
	sbl.updatePhaseLocked()
	return sbl.phase
}

func (sbl *SealedBidLottery) updatePhaseLocked() {
	// L20-001 FIX: Use deterministic slot-based phase transitions when
	// currentSlot is set (via SetCurrentSlot). This prevents block proposers
	// from manipulating wall-clock time to gain unfair election advantage.
	if sbl.currentSlot > 0 {
		if sbl.phase == SealedBidPhaseCommit && sbl.currentSlot >= sbl.commitDeadlineSlot {
			sbl.phase = SealedBidPhaseReveal
		}
		if sbl.phase == SealedBidPhaseReveal && sbl.currentSlot >= sbl.revealDeadlineSlot {
			sbl.phase = SealedBidPhaseExpired
		}
		return
	}
	// R33 P2-20 FIX (2026-07-28): Removed wall-clock time-based fallback.
	// Previously, when currentSlot == 0, the lottery fell back to wall-clock
	// time (time.Now) for phase transitions, which could be manipulated by
	// block proposers. Now, phase transitions are ONLY driven by
	// SetCurrentSlot(). Callers that don't drive SetCurrentSlot must use
	// explicit phase transitions (TransitionToReveal) or accept that the
	// lottery stays in its current phase.
	//
	// In production mode (QAU_PRODUCTION=1), log an error to alert operators
	// that SetCurrentSlot has not been called. In dev/test mode, log a
	// warning. The phase remains pinned — no automatic transition.
	if params.IsProductionEnv() {
		log.Printf("ERROR: SealedBidLottery.updatePhaseLocked: currentSlot is 0 in production mode — phase transitions require SetCurrentSlot (slot=%d, phase=%s)", sbl.slot, sbl.phase)
		return
	}
	// Dev/test mode: log a warning but do NOT transition. Tests that need
	// phase transitions should use SetCurrentSlot or TransitionToReveal.
	log.Printf("WARNING: SealedBidLottery.updatePhaseLocked: currentSlot is 0 — use SetCurrentSlot or TransitionToReveal for phase transitions (slot=%d, phase=%s)", sbl.slot, sbl.phase)
}

func CreateSealedBidCommitment(
	validatorAddr types.Address,
	vrfOutput *PQVRFOutput,
	blockTime ...int64,
) (*SealedBidCommit, [SealedBidNonceSize]byte, error) {
	if vrfOutput == nil {
		return nil, [SealedBidNonceSize]byte{}, ErrSealedBidInvalidCommit
	}

	var nonce [SealedBidNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, [SealedBidNonceSize]byte{}, fmt.Errorf("sealedbid: nonce generation failed: %w", err)
	}

	commitmentHash := ComputeSealedBidCommitmentHash(validatorAddr, vrfOutput, nonce)

	// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
	var ts time.Time
	if len(blockTime) > 0 {
		ts = time.Unix(blockTime[0], 0)
	} else {
		ts = time.Now()
	}

	commit := &SealedBidCommit{
		ValidatorAddr:  validatorAddr,
		CommitmentHash: commitmentHash,
		BidAmount:      new(big.Int).Set(MinSealedBidAmount),
		Slot:           0,
		Timestamp:      ts,
	}

	return commit, nonce, nil
}

func ComputeSealedBidCommitmentHash(addr types.Address, output *PQVRFOutput, nonce [SealedBidNonceSize]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("QUANTAUREUM_SEALED_BID_V1"))
	h.Write(addr[:])
	h.Write(output.Value[:])
	h.Write(nonce[:])
	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

func (sbl *SealedBidLottery) SubmitCommit(commit *SealedBidCommit) error {
	sbl.mu.Lock()
	defer sbl.mu.Unlock()

	sbl.updatePhaseLocked()

	if sbl.phase != SealedBidPhaseCommit {
		return ErrSealedBidInvalidPhase
	}

	// L7-013 FIX: Reject commits with an empty validator address. A zero
	// address would collide on the commits map key and let a nil validator
	// participate in the sealed-bid lottery.
	var zeroAddr types.Address
	if commit.ValidatorAddr == zeroAddr {
		return fmt.Errorf("validator address must not be empty")
	}

	if _, exists := sbl.commits[commit.ValidatorAddr]; exists {
		return ErrSealedBidAlreadyCommitted
	}

	if len(sbl.commits) >= MaxSealedBidsPerSlot {
		return ErrSealedBidTooManyBids
	}

	// SECURITY (audit P4-): Validate commitment hash is not empty/zero
	// to prevent trivial commits that don't bind to any reveal value.
	var zeroHash [32]byte
	if commit.CommitmentHash == zeroHash {
		return fmt.Errorf("commitment hash must not be zero")
	}

	// L11-007 FIX: enforce minimum bid amount (>= 1 QAU) to prevent
	// dust/griefing commits that cost nothing to place.
	if commit.BidAmount == nil || commit.BidAmount.Cmp(MinSealedBidAmount) < 0 {
		return ErrSealedBidInsufficientBid
	}

	commit.Slot = sbl.slot
	sbl.commits[commit.ValidatorAddr] = commit
	return nil
}

// ErrSealedBidVRFVerifyRequired is returned when SubmitReveal is called without
// VRF proof verification. Callers must use SubmitRevealWithVRFVerify instead.
// AUDIT (2026) CRND-05: SubmitReveal previously did not verify the VRF
// proof, allowing an attacker to submit a forged VRFOutput (e.g., all zeros)
// that always wins the lottery (Finalize picks the lowest output). The
// commitment hash only binds (addr, output, nonce), not the validity of the
// VRF proof. Fail-closed: reject all calls to SubmitReveal.
var ErrSealedBidVRFVerifyRequired = errors.New("sealedbid: VRF proof verification required; use SubmitRevealWithVRFVerify")

func (sbl *SealedBidLottery) SubmitReveal(reveal *SealedBidReveal) error {
	// AUDIT (2026) CRND-05: Fail-closed. SubmitReveal does not verify the
	// VRF proof, so a caller could submit a forged VRFOutput (e.g., all zeros)
	// to always win the lottery. Callers must use SubmitRevealWithVRFVerify,
	// which verifies the VRF proof before accepting the reveal.
	return ErrSealedBidVRFVerifyRequired
}

// submitRevealInternal is the internal reveal submission logic that assumes
// VRF verification has already been performed by the caller.
func (sbl *SealedBidLottery) submitRevealInternal(reveal *SealedBidReveal) error {
	sbl.mu.Lock()
	defer sbl.mu.Unlock()

	sbl.updatePhaseLocked()

	// SECURITY (audit P4-): Validate reveal has required fields
	if reveal.VRFProof == nil || reveal.VRFOutput == nil {
		return fmt.Errorf("reveal must include VRF proof and output")
	}

	if sbl.phase != SealedBidPhaseReveal && sbl.phase != SealedBidPhaseCommit {
		return ErrSealedBidInvalidPhase
	}

	commit, exists := sbl.commits[reveal.ValidatorAddr]
	if !exists {
		return ErrSealedBidNotCommitted
	}

	if _, exists := sbl.reveals[reveal.ValidatorAddr]; exists {
		return ErrSealedBidAlreadyRevealed
	}

	expectedHash := ComputeSealedBidCommitmentHash(reveal.ValidatorAddr, reveal.VRFOutput, reveal.Nonce)
	if subtle.ConstantTimeCompare(expectedHash[:], commit.CommitmentHash[:]) != 1 {
		return ErrSealedBidCommitMismatch
	}

	reveal.Slot = sbl.slot
	sbl.reveals[reveal.ValidatorAddr] = reveal
	return nil
}

func (sbl *SealedBidLottery) SubmitRevealWithVRFVerify(
	reveal *SealedBidReveal,
	publicKey *crypto.PublicKey,
	vrfInput []byte,
) error {
	if err := PQVRFVerify(publicKey, vrfInput, reveal.VRFProof, reveal.VRFOutput); err != nil {
		return fmt.Errorf("%w: %v", ErrSealedBidVRFVerifyFailed, err)
	}

	return sbl.submitRevealInternal(reveal)
}

func (sbl *SealedBidLottery) TransitionToReveal() {
	sbl.mu.Lock()
	defer sbl.mu.Unlock()
	if sbl.phase == SealedBidPhaseCommit {
		sbl.phase = SealedBidPhaseReveal
	}
}

func (sbl *SealedBidLottery) Finalize() *SealedBidResult {
	sbl.mu.Lock()
	defer sbl.mu.Unlock()

	// CONS-FIX: Phase guard — Finalize must only be called during
	// Reveal or Expired phase. Without this check, an attacker could call
	// Finalize during the Commit phase (before other validators reveal),
	// winning the lottery as the sole revealer. Combined with CONS-
	// (no minimum reveal threshold), this lets an attacker always win by
	// committing+revealing immediately while others are still in commit phase.
	sbl.updatePhaseLocked()
	if sbl.phase != SealedBidPhaseReveal && sbl.phase != SealedBidPhaseExpired {
		return nil
	}

	// CONS-FIX: Minimum reveal threshold. Require at least
	// ceil(commitCount * 2/3) reveals before Finalize can complete.
	// Without this, an attacker (legitimate validator) can commit+reveal
	// while other committers are still in the commit phase or have not yet
	// revealed, winning as the sole revealer. When the threshold is not met,
	// return nil so the caller can trigger a re-run (re-lottery) instead of
	// accepting an unrepresentative winner. The threshold scales with the
	// number of committers, so a single-validator lottery still finalizes
	// (ceil(1*2/3) = 1) while multi-validator lotteries require a 2/3
	// supermajority of reveals.
	commitCount := len(sbl.commits)
	if commitCount == 0 {
		return nil
	}
	minReveals := (commitCount * 2) / 3
	if (commitCount*2)%3 != 0 {
		minReveals++
	}
	if len(sbl.reveals) < minReveals {
		return nil
	}

	sbl.phase = SealedBidPhaseComplete

	result := &SealedBidResult{
		Slot:  sbl.slot,
		Phase: SealedBidPhaseComplete,
	}

	var lowestOutput *PQVRFOutput
	var selectedAddr types.Address

	for addr, reveal := range sbl.reveals {
		result.RevealedAddrs = append(result.RevealedAddrs, addr)

		if lowestOutput == nil {
			lowestOutput = reveal.VRFOutput
			selectedAddr = addr
			continue
		}

		cmp := compareVRFOutput(reveal.VRFOutput, lowestOutput)
		// CONS-FIX: Deterministic tiebreaker — when VRF outputs are equal,
		// select the address with the smallest byte representation. Without this,
		// map iteration order would determine the winner, causing consensus splits.
		if cmp < 0 || (cmp == 0 && bytes.Compare(addr[:], selectedAddr[:]) < 0) {
			lowestOutput = reveal.VRFOutput
			selectedAddr = addr
		}
	}

	for addr := range sbl.commits {
		if _, revealed := sbl.reveals[addr]; !revealed {
			result.SlashedAddrs = append(result.SlashedAddrs, addr)
		}
	}

	// CONS-FIX: Sort RevealedAddrs and SlashedAddrs deterministically
	// (by address bytes) so that all nodes produce identical serialization.
	// Map iteration order is randomized; without sorting, the same set of
	// reveals/slashes could serialize to different hashes on different nodes.
	sort.Slice(result.RevealedAddrs, func(i, j int) bool {
		return bytes.Compare(result.RevealedAddrs[i][:], result.RevealedAddrs[j][:]) < 0
	})
	sort.Slice(result.SlashedAddrs, func(i, j int) bool {
		return bytes.Compare(result.SlashedAddrs[i][:], result.SlashedAddrs[j][:]) < 0
	})

	if lowestOutput != nil {
		result.SelectedAddr = selectedAddr
		result.SelectedOutput = lowestOutput
	}

	return result
}

func (sbl *SealedBidLottery) GetSlashedValidators() []types.Address {
	sbl.mu.RLock()
	defer sbl.mu.RUnlock()

	var slashed []types.Address
	for addr := range sbl.commits {
		if _, revealed := sbl.reveals[addr]; !revealed {
			slashed = append(slashed, addr)
		}
	}
	return slashed
}

// audit-remediation: reviewed 2026-09-11 — sealed-bid auction accessor; not validator stake.
func (sbl *SealedBidLottery) SlashAmount() *big.Int {
	sbl.mu.RLock()
	defer sbl.mu.RUnlock()
	if sbl.slashAmount == nil {
		return nil
	}
	return new(big.Int).Set(sbl.slashAmount)
}

// audit-remediation: reviewed 2026-09-11 — sealed-bid auction config; not validator stake.
func (sbl *SealedBidLottery) SetSlashAmount(amount *big.Int) {
	sbl.mu.Lock()
	defer sbl.mu.Unlock()
	if amount == nil {
		sbl.slashAmount = nil
		return
	}
	sbl.slashAmount = new(big.Int).Set(amount)
}

func (sbl *SealedBidLottery) CommitCount() int {
	sbl.mu.RLock()
	defer sbl.mu.RUnlock()
	return len(sbl.commits)
}

func (sbl *SealedBidLottery) RevealCount() int {
	sbl.mu.RLock()
	defer sbl.mu.RUnlock()
	return len(sbl.reveals)
}

func (sbl *SealedBidLottery) GetCommit(addr types.Address) (*SealedBidCommit, bool) {
	sbl.mu.RLock()
	defer sbl.mu.RUnlock()
	c, ok := sbl.commits[addr]
	return c, ok
}

func (sbl *SealedBidLottery) GetReveal(addr types.Address) (*SealedBidReveal, bool) {
	sbl.mu.RLock()
	defer sbl.mu.RUnlock()
	r, ok := sbl.reveals[addr]
	return r, ok
}

func (sbl *SealedBidLottery) CommitDeadline() time.Time {
	sbl.mu.RLock()
	defer sbl.mu.RUnlock()
	return sbl.commitDeadline
}

func (sbl *SealedBidLottery) RevealDeadline() time.Time {
	sbl.mu.RLock()
	defer sbl.mu.RUnlock()
	return sbl.revealDeadline
}

// SetCurrentSlot updates the current block height/slot for deterministic phase
// transitions. L20-001 FIX: replaces wall-clock time with slot-based progression
// that cannot be manipulated by block proposers. Must be called by the consensus
// layer as each slot/height advances.
func (sbl *SealedBidLottery) SetCurrentSlot(slot uint64) {
	sbl.mu.Lock()
	defer sbl.mu.Unlock()
	sbl.currentSlot = slot
	sbl.updatePhaseLocked()
}

// CurrentSlot returns the current slot used for phase transitions.
func (sbl *SealedBidLottery) CurrentSlot() uint64 {
	sbl.mu.RLock()
	defer sbl.mu.RUnlock()
	return sbl.currentSlot
}

func compareVRFOutput(a, b *PQVRFOutput) int {
	for i := 0; i < PQVRFOutputSize; i++ {
		if a.Value[i] < b.Value[i] {
			return -1
		}
		if a.Value[i] > b.Value[i] {
			return 1
		}
	}
	return 0
}
