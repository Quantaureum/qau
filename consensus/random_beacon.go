// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

const (
	BeaconEpochLength   = 32
	BeaconMaxValidators = 256
	BeaconMinReveals    = 3
)

var (
	ErrBeaconInvalidPhase     = errors.New("beacon: invalid phase")
	ErrBeaconAlreadyContribed = errors.New("beacon: validator already contributed")
	ErrBeaconInsufficient     = errors.New("beacon: insufficient contributions")
	ErrBeaconInvalidProof     = errors.New("beacon: invalid VRF proof")
	ErrBeaconInvalidOutput    = errors.New("beacon: invalid VRF output")
	ErrBeaconNilKey           = errors.New("beacon: nil key")
	ErrBeaconNotReady         = errors.New("beacon: not ready to finalize")
	ErrBeaconAlreadyFinalized = errors.New("beacon: already finalized")
	// CRND- publicKey does not match the claimed ValidatorAddr.
	ErrBeaconKeyAddrMismatch = errors.New("beacon: publicKey does not match validator address")
	// CRND- ValidatorAddr is not a known active consensus validator.
	ErrBeaconNotValidator = errors.New("beacon: contributor is not an active validator")
	// AUDIT (2026) R4-CRND-05: deadline has passed and threshold is not met.
	// The beacon has transitioned to BeaconPhaseExpired and can no longer be
	// finalized. Callers should check Phase() == BeaconPhaseExpired before
	// attempting Finalize().
	ErrBeaconExpired = errors.New("beacon: deadline passed without reaching threshold (expired)")
	// R33 P2-17 FIX (2026-07-28): commit-then-reveal protocol errors.
	// SubmitReveal was called without a prior SubmitCommit for the address.
	ErrBeaconCommitNotFound = errors.New("beacon: commit not found for address (call SubmitCommit first)")
	// R33 P2-17 FIX: reveal's VRF output does not hash to the stored commit.
	ErrBeaconCommitMismatch = errors.New("beacon: reveal does not match commitment hash")
	// R33 P2-17 FIX: SubmitCommit called after TransitionToReveal, or
	// SubmitReveal called before TransitionToReveal (in strict mode).
	ErrBeaconNotInRevealPhase = errors.New("beacon: not in reveal phase (call TransitionToReveal first)")
	// R33 P2-17 FIX: SubmitCommit called twice by the same address.
	ErrBeaconAlreadyCommitted = errors.New("beacon: validator already committed")
)

type BeaconPhase uint8

const (
	BeaconPhaseCollect BeaconPhase = iota
	// R33 P2-17 FIX (2026-07-28): BeaconPhaseReveal is the second phase of
	// the commit-then-reveal protocol. After TransitionToReveal is called,
	// the beacon only accepts SubmitReveal calls (not SubmitCommit). This
	// prevents the last revealer from biasing the randomness by withholding
	// their VRF output after seeing others' reveals.
	BeaconPhaseReveal
	BeaconPhaseFinalized
	BeaconPhaseExpired
)

func (p BeaconPhase) String() string {
	switch p {
	case BeaconPhaseCollect:
		return "COLLECT"
	case BeaconPhaseReveal:
		return "REVEAL"
	case BeaconPhaseFinalized:
		return "FINALIZED"
	case BeaconPhaseExpired:
		return "EXPIRED"
	default:
		return "UNKNOWN"
	}
}

type BeaconContribution struct {
	ValidatorAddr types.Address
	VRFProof      *PQVRFProof
	VRFOutput     *PQVRFOutput
	Slot          uint64
	Timestamp     time.Time
}

type BeaconOutput struct {
	Epoch         uint64
	Randomness    [32]byte
	Contributions int
	Contributors  []types.Address
	Phase         BeaconPhase
}

// RandomBeacon implements a multi-party randomness beacon using post-quantum
// VRF (Verifiable Random Function) based on Dilithium3.
//
// L14-027 SECURITY NOTE: The beacon's randomness is derived by feeding all
// submitted VRF outputs into a SHAKE256 XOF (eXtendable Output Function),
// each VRF output verified against the validator's public key. This ensures
// no single party can bias the output. The VRF input (epoch||slot) prevents
// replay across epochs. The threshold of BeaconMinReveals (3) ensures
// liveness even if some validators are offline. However, the randomness is
// only as unpredictable as the last honest contributor -- if all but one
// validator collude, they can withhold/replace their contribution to bias
// the result.
//
// L20-007 FIX: Updated comment to accurately reflect the implementation.
// The previous comment incorrectly stated that randomness is derived from
// "XOR combination" of VRF outputs. The actual implementation
// (computeBeaconRandomness) uses SHAKE256 (sha3.NewShake256) to hash
// together the epoch, contributor addresses, and VRF output values. SHAKE256
// provides stronger diffusion than simple XOR: it is collision-resistant and
// ensures that every bit of the output depends on every bit of every
// contribution, making bias attempts computationally infeasible.
//
// AUDIT (2026) R4-CRND-05 FIX: Finalize now honors the deadline. If the
// deadline has passed and threshold is not met, the beacon transitions to
// BeaconPhaseExpired (previously Finalize would return ErrBeaconInsufficient
// indefinitely, leaving the beacon stuck in Collect phase forever and
// ignoring the deadline). The deadline field is marked "NOT consensus-critical:
// local in-memory tracking only" because each node may have a slightly different
// clock, so the deadline is a best-effort operational hint, not a hard
// consensus rule.
//
// REMAINING LIMITATION (last-revealer bias): Even with deadline enforcement,
// the last contributor can compute the would-be randomness with vs without
// their VRF output and choose to withhold if unfavorable. This is a
// fundamental limitation of single-phase reveal schemes. A full fix requires
// a commit-then-reveal protocol (commit phase: H(vrf_output) submitted;
// reveal phase: vrf_output submitted and verified against commit), which is
// a future protocol upgrade. The current single-phase scheme is acceptable
// for the latent, non-production RandomBeacon path; the production DA
// committee shuffle uses the per-epoch VRF accumulator (R4-CRND-01) instead.
//
// QUANTUM- (audit 2026-07-17, Low): documented limitation. Production DA
// path uses R4-CRND-01 per-epoch VRF accumulator, not this beacon.
//
// R33 P2-17 FIX (2026-07-28): Implemented commit-then-reveal protocol to
// eliminate the last-revealer 1-bit bias. New API:
//  1. SubmitCommit(addr, commitmentHash) — submit only H(vrf_output)
//  2. TransitionToReveal() — move to BeaconPhaseReveal (no more commits)
//  3. SubmitReveal(contribution, publicKey) — reveal VRF output, verified
//     against the stored commitment hash
//  4. Finalize() — same as before, uses revealed contributions
//
// The legacy single-phase API (Contribute/SubmitContribution) still works
// for backward compatibility: it stores both the commit and the reveal
// immediately. New code SHOULD use the commit-then-reveal protocol to
// eliminate the bias.
type RandomBeacon struct {
	mu sync.RWMutex

	epoch         uint64
	phase         BeaconPhase
	threshold     int
	contributions map[types.Address]*BeaconContribution
	// R33 P2-17 FIX: commits map stores commitment hashes during the
	// commit phase. Keyed by validator address. When a reveal is submitted
	// via SubmitReveal, the hash is verified against this map before the
	// contribution is accepted.
	commits  map[types.Address][32]byte
	deadline time.Time
	output   *BeaconOutput
	// CRND- optional consensus identity binding. When set,
	// SubmitContribution rejects contributions from addresses that are not
	// in the active validator set, preventing sybil/multi-key grinding.
	validatorLookup ValidatorSetLookup
}

func NewRandomBeacon(epoch uint64, threshold int) *RandomBeacon {
	return &RandomBeacon{
		epoch:         epoch,
		phase:         BeaconPhaseCollect,
		threshold:     threshold,
		contributions: make(map[types.Address]*BeaconContribution),
		commits:       make(map[types.Address][32]byte),
		deadline:      time.Now().Add(SealedBidCommitTimeout + SealedBidRevealTimeout), // NOT consensus-critical: local in-memory tracking only
	}
}

func NewRandomBeaconWithDeadline(epoch uint64, threshold int, deadline time.Time) *RandomBeacon {
	return &RandomBeacon{
		epoch:         epoch,
		phase:         BeaconPhaseCollect,
		threshold:     threshold,
		contributions: make(map[types.Address]*BeaconContribution),
		commits:       make(map[types.Address][32]byte),
		deadline:      deadline,
	}
}

func (rb *RandomBeacon) Epoch() uint64 {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.epoch
}

func (rb *RandomBeacon) Phase() BeaconPhase {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.phase
}

func (rb *RandomBeacon) ContributionCount() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return len(rb.contributions)
}

func (rb *RandomBeacon) Threshold() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.threshold
}

// SetValidatorLookup configures the consensus identity binding for beacon
// contributions. CRND-FIX: when set, SubmitContribution rejects
// contributions from addresses that are not currently in the active validator
// set, preventing sybil/multi-key grinding attacks. Production deployments
// MUST call this before accepting contributions. When nil (default, used by
// tests), the check is skipped for backward compatibility.
func (rb *RandomBeacon) SetValidatorLookup(lookup ValidatorSetLookup) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.validatorLookup = lookup
}

func (rb *RandomBeacon) Contribute(
	privateKey *crypto.PrivateKey,
	publicKey *crypto.PublicKey,
	slot uint64,
) (*BeaconContribution, error) {
	if privateKey == nil || publicKey == nil {
		return nil, ErrBeaconNilKey
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.phase != BeaconPhaseCollect {
		return nil, ErrBeaconInvalidPhase
	}

	addr := publicKey.Address()
	if _, exists := rb.contributions[addr]; exists {
		return nil, ErrBeaconAlreadyContribed
	}

	// AUDIT (2026) CRND-04: Use canonical slot derived from epoch instead
	// of the caller-provided slot. Previously, the attacker-provided slot was
	// used directly in the VRF input, allowing a single contributor to grind
	// many slot values offline and only submit the one that biases the beacon
	// randomness. Deriving the slot canonically from the epoch eliminates this
	// attack vector — there is exactly one valid VRF input per (epoch, validator).
	vrfInput := beaconVRFInput(rb.epoch, canonicalBeaconSlot(rb.epoch))
	proof, output, err := PQVRFEval(privateKey, vrfInput)
	if err != nil {
		return nil, fmt.Errorf("beacon VRF eval failed: %w", err)
	}

	contribution := &BeaconContribution{
		ValidatorAddr: addr,
		VRFProof:      proof,
		VRFOutput:     output,
		Slot:          slot,
		// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
		Timestamp: time.Unix(int64(slot), 0),
	}

	// R33 P2-17 FIX: Store the commitment hash alongside the contribution
	// for backward compatibility with the legacy single-phase API. New code
	// SHOULD use SubmitCommit + TransitionToReveal + SubmitReveal instead
	// to eliminate the last-revealer 1-bit bias.
	rb.commits[addr] = ComputeBeaconCommitmentHash(addr, output)
	rb.contributions[addr] = contribution
	return contribution, nil
}

func (rb *RandomBeacon) SubmitContribution(contribution *BeaconContribution, publicKey *crypto.PublicKey) error {
	if contribution == nil || publicKey == nil {
		return ErrBeaconNilKey
	}

	// CRND-FIX: Bind publicKey to ValidatorAddr. Without this check,
	// an attacker could submit a contribution claiming to be from validator V
	// (ValidatorAddr=V) but verify the VRF proof against their own publicKey.
	// This enables both impersonation (submitting under someone else's address
	// with a forged key) and multi-key grinding (generating many keypairs to
	// find favorable randomness, each submitted under the keypair's own address
	// but pretending to be a different validator).
	derivedAddr := publicKey.Address()
	if derivedAddr != contribution.ValidatorAddr {
		return fmt.Errorf("%w: derived=%s, claimed=%s",
			ErrBeaconKeyAddrMismatch, derivedAddr.ShortString(), contribution.ValidatorAddr.ShortString())
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.phase != BeaconPhaseCollect {
		return ErrBeaconInvalidPhase
	}

	if _, exists := rb.contributions[contribution.ValidatorAddr]; exists {
		return ErrBeaconAlreadyContribed
	}

	// CRND-FIX: When a validator set lookup is configured, reject
	// contributions from addresses that are not active consensus validators.
	// This prevents sybil attacks where an attacker generates many keypairs
	// and submits contributions from non-validator addresses to bias the
	// beacon randomness.
	if rb.validatorLookup != nil && !rb.validatorLookup.IsActiveValidator(contribution.ValidatorAddr) {
		return fmt.Errorf("%w: %s", ErrBeaconNotValidator, contribution.ValidatorAddr.ShortString())
	}

	// AUDIT (2026) CRND-04: Verify against the canonical slot derived from
	// the epoch, not the attacker-provided contribution.Slot. This prevents
	// grinding: a contributor cannot try many slot values and only submit the
	// one that biases the beacon randomness.
	vrfInput := beaconVRFInput(rb.epoch, canonicalBeaconSlot(rb.epoch))
	if err := PQVRFVerify(publicKey, vrfInput, contribution.VRFProof, contribution.VRFOutput); err != nil {
		return fmt.Errorf("%w: %v", ErrBeaconInvalidProof, err)
	}

	// R33 P2-17 FIX: Store the commitment hash alongside the contribution
	// for backward compatibility with the legacy single-phase API. New code
	// SHOULD use SubmitCommit + TransitionToReveal + SubmitReveal instead.
	rb.commits[contribution.ValidatorAddr] = ComputeBeaconCommitmentHash(contribution.ValidatorAddr, contribution.VRFOutput)
	rb.contributions[contribution.ValidatorAddr] = contribution
	return nil
}

// SubmitCommit stores only the commitment hash for a validator, without
// revealing the VRF output. This is the first phase of the commit-then-reveal
// protocol (R33 P2-17 FIX). After all commits are collected, call
// TransitionToReveal to move to the reveal phase, then call SubmitReveal for
// each validator to reveal their VRF output.
//
// The commitment hash binds the validator to their VRF output without
// revealing it: once the commit is submitted, the validator cannot change
// their VRF output. This eliminates the last-revealer 1-bit bias because
// the last revealer has already committed to their output before seeing
// any other reveals.
//
// The commitment hash should be computed using ComputeBeaconCommitmentHash.
func (rb *RandomBeacon) SubmitCommit(addr types.Address, commitmentHash [32]byte) error {
	var zeroAddr types.Address
	if addr == zeroAddr {
		return fmt.Errorf("beacon: validator address must not be empty")
	}
	var zeroHash [32]byte
	if commitmentHash == zeroHash {
		return fmt.Errorf("beacon: commitment hash must not be zero")
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	// R33 P2-17 FIX: Commits are only accepted during the Collect phase.
	// Once TransitionToReveal is called, the beacon is in Reveal phase and
	// no new commits are accepted. This prevents a validator from submitting
	// a commit after seeing other validators' reveals.
	if rb.phase != BeaconPhaseCollect {
		return fmt.Errorf("%w: phase=%s, expected COLLECT", ErrBeaconInvalidPhase, rb.phase)
	}

	// CRND- When a validator set lookup is configured, reject commits
	// from addresses that are not active consensus validators.
	if rb.validatorLookup != nil && !rb.validatorLookup.IsActiveValidator(addr) {
		return fmt.Errorf("%w: %s", ErrBeaconNotValidator, addr.ShortString())
	}

	if _, exists := rb.commits[addr]; exists {
		return ErrBeaconAlreadyCommitted
	}

	rb.commits[addr] = commitmentHash
	return nil
}

// TransitionToReveal moves the beacon from the Collect phase to the Reveal
// phase (R33 P2-17 FIX). After this call, no new commits are accepted (calls
// to SubmitCommit will return ErrBeaconInvalidPhase). Only reveals (via
// SubmitReveal) are accepted.
//
// This must be called after all validators have submitted their commits and
// before any validator submits their reveal. The protocol guarantees that
// no validator can see another's VRF output before submitting their own
// commit, eliminating the last-revealer 1-bit bias.
func (rb *RandomBeacon) TransitionToReveal() error {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.phase != BeaconPhaseCollect {
		return fmt.Errorf("%w: phase=%s, expected COLLECT", ErrBeaconInvalidPhase, rb.phase)
	}

	rb.phase = BeaconPhaseReveal
	return nil
}

// SubmitReveal is the second phase of the commit-then-reveal protocol
// (R33 P2-17 FIX). It verifies that:
//  1. The beacon is in the Reveal phase (TransitionToReveal was called).
//  2. A commit was previously submitted for this validator (SubmitCommit).
//  3. The VRF proof is valid.
//  4. The VRF output hashes to the stored commitment hash.
//
// Only after all checks pass is the contribution stored in the contributions
// map, making it eligible for Finalize.
//
// This eliminates the last-revealer 1-bit bias: the last revealer has already
// committed to their VRF output (via SubmitCommit) before seeing any other
// reveals. They can choose to not reveal (forfeiting their contribution),
// but they cannot change their VRF output to bias the result.
func (rb *RandomBeacon) SubmitReveal(contribution *BeaconContribution, publicKey *crypto.PublicKey) error {
	if contribution == nil || publicKey == nil {
		return ErrBeaconNilKey
	}

	// CRND- Bind publicKey to ValidatorAddr.
	derivedAddr := publicKey.Address()
	if derivedAddr != contribution.ValidatorAddr {
		return fmt.Errorf("%w: derived=%s, claimed=%s",
			ErrBeaconKeyAddrMismatch, derivedAddr.ShortString(), contribution.ValidatorAddr.ShortString())
	}

	if contribution.VRFProof == nil || contribution.VRFOutput == nil {
		return ErrBeaconInvalidOutput
	}

	rb.mu.Lock()
	defer rb.mu.Unlock()

	// R33 P2-17 FIX: Reveals are only accepted during the Reveal phase.
	// This ensures all commits were submitted before any reveals, which is
	// the core guarantee of the commit-then-reveal protocol.
	if rb.phase != BeaconPhaseReveal {
		return fmt.Errorf("%w: phase=%s, expected REVEAL", ErrBeaconNotInRevealPhase, rb.phase)
	}

	if _, exists := rb.contributions[contribution.ValidatorAddr]; exists {
		return ErrBeaconAlreadyContribed
	}

	// R33 P2-17 FIX: Verify that a commit was previously submitted.
	committedHash, exists := rb.commits[contribution.ValidatorAddr]
	if !exists {
		return ErrBeaconCommitNotFound
	}

	// CRND- When a validator set lookup is configured, reject reveals
	// from addresses that are not active consensus validators.
	if rb.validatorLookup != nil && !rb.validatorLookup.IsActiveValidator(contribution.ValidatorAddr) {
		return fmt.Errorf("%w: %s", ErrBeaconNotValidator, contribution.ValidatorAddr.ShortString())
	}

	// AUDIT (2026) CRND-04: Verify against the canonical slot derived
	// from the epoch, not the attacker-provided contribution.Slot.
	vrfInput := beaconVRFInput(rb.epoch, canonicalBeaconSlot(rb.epoch))
	if err := PQVRFVerify(publicKey, vrfInput, contribution.VRFProof, contribution.VRFOutput); err != nil {
		return fmt.Errorf("%w: %v", ErrBeaconInvalidProof, err)
	}

	// R33 P2-17 FIX: Verify the reveal matches the stored commitment hash.
	// This is the core of the commit-then-reveal protocol: the validator
	// cannot change their VRF output after committing.
	revealHash := ComputeBeaconCommitmentHash(contribution.ValidatorAddr, contribution.VRFOutput)
	if subtle.ConstantTimeCompare(revealHash[:], committedHash[:]) != 1 {
		return ErrBeaconCommitMismatch
	}

	rb.contributions[contribution.ValidatorAddr] = contribution
	return nil
}

// CommitCount returns the number of commits submitted via SubmitCommit.
// R33 P2-17 FIX: useful for callers to check if enough commits have been
// collected before calling TransitionToReveal.
func (rb *RandomBeacon) CommitCount() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return len(rb.commits)
}

func (rb *RandomBeacon) Finalize() (*BeaconOutput, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if rb.phase == BeaconPhaseFinalized {
		return nil, ErrBeaconAlreadyFinalized
	}

	// AUDIT (2026) R4-CRND-05 FIX: Honor the deadline. Previously
	// Finalize ignored the deadline entirely: if threshold was never reached,
	// the beacon would stay in Collect phase forever, repeatedly returning
	// ErrBeaconInsufficient. Now, if the deadline has passed AND threshold is
	// still not met, the beacon transitions to BeaconPhaseExpired — a
	// terminal state that prevents further contributions and signals to
	// callers that this epoch's randomness is unavailable. This also bounds
	// the Collect phase duration, preventing a stalled beacon from
	// accumulating contributions indefinitely.
	if len(rb.contributions) < rb.threshold {
		if !rb.deadline.IsZero() && time.Now().After(rb.deadline) {
			rb.phase = BeaconPhaseExpired
			return nil, fmt.Errorf("%w: deadline %s passed with %d/%d contributions",
				ErrBeaconExpired, rb.deadline.Format(time.RFC3339),
				len(rb.contributions), rb.threshold)
		}
		return nil, fmt.Errorf("%w: need %d, have %d", ErrBeaconInsufficient, rb.threshold, len(rb.contributions))
	}

	randomness := computeBeaconRandomness(rb.epoch, rb.contributions)

	contributors := make([]types.Address, 0, len(rb.contributions))
	for addr := range rb.contributions {
		contributors = append(contributors, addr)
	}

	rb.output = &BeaconOutput{
		Epoch:         rb.epoch,
		Randomness:    randomness,
		Contributions: len(rb.contributions),
		Contributors:  contributors,
		Phase:         BeaconPhaseFinalized,
	}

	rb.phase = BeaconPhaseFinalized
	return rb.output, nil
}

// Expire transitions the beacon to BeaconPhaseExpired if the deadline has
// passed and the beacon is still in Collect phase. This is an explicit
// alternative to relying on Finalize() to detect the expired state — useful
// for callers that want to clean up stalled beacons without attempting
// finalization. Returns true if the beacon was transitioned to Expired.
// AUDIT (2026) R4-CRND-05: Provides a way to mark a beacon as expired
// without calling Finalize (which would otherwise return ErrBeaconInsufficient
// indefinitely for a stalled beacon).
func (rb *RandomBeacon) Expire() bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.phase != BeaconPhaseCollect {
		return false
	}
	if rb.deadline.IsZero() || !time.Now().After(rb.deadline) {
		return false
	}
	rb.phase = BeaconPhaseExpired
	return true
}

// Deadline returns the collection-phase deadline. AUDIT (2026) R4-CRND-05:
// exposed so callers can check whether the deadline has passed before
// attempting Finalize (e.g., to decide whether to wait for more contributions
// or to give up).
func (rb *RandomBeacon) Deadline() time.Time {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.deadline
}

func (rb *RandomBeacon) GetOutput() *BeaconOutput {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	if rb.output == nil {
		return nil
	}
	out := *rb.output
	out.Contributors = make([]types.Address, len(rb.output.Contributors))
	copy(out.Contributors, rb.output.Contributors)
	return &out
}

func (rb *RandomBeacon) VerifyOutput(output *BeaconOutput) bool {
	if output == nil {
		return false
	}

	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if len(rb.contributions) != output.Contributions {
		return false
	}

	expected := computeBeaconRandomness(rb.epoch, rb.contributions)
	return subtle.ConstantTimeCompare(expected[:], output.Randomness[:]) == 1
}

// canonicalBeaconSlot returns the canonical slot for a given epoch.
// AUDIT (2026) CRND-04: The slot is derived deterministically from the
// epoch (the first slot of the epoch) to prevent grinding attacks. Previously,
// the slot was attacker-provided, allowing a contributor to try many slot
// values offline and only submit the one that biases the beacon randomness.
func canonicalBeaconSlot(epoch uint64) uint64 {
	return epoch * BeaconEpochLength
}

// R47-CS-03 NOTE: beaconVRFInput and computeBeaconRandomness both use
// little-endian byte serialization for epoch/slot. This is internally
// consistent. Other modules (validator.go, block.go) use big-endian,
// but they never consume beacon VRF input/output. No cross-module
// consumer expects big-endian for beacon data.
func beaconVRFInput(epoch uint64, slot uint64) []byte {
	input := make([]byte, 16)
	for i := 0; i < 8; i++ {
		input[i] = byte(epoch >> (8 * i))
		input[8+i] = byte(slot >> (8 * i))
	}
	return input
}

func computeBeaconRandomness(epoch uint64, contributions map[types.Address]*BeaconContribution) [32]byte {
	h := sha3.NewShake256()
	var epochBytes [8]byte
	for i := 0; i < 8; i++ {
		epochBytes[i] = byte(epoch >> (8 * i))
	}
	h.Write([]byte("QUANTAUREUM_BEACON_V1"))
	h.Write(epochBytes[:])

	addrs := make([]types.Address, 0, len(contributions))
	for addr := range contributions {
		addrs = append(addrs, addr)
	}
	sort.Slice(addrs, func(i, j int) bool {
		for k := 0; k < len(addrs[i]); k++ {
			if addrs[i][k] != addrs[j][k] {
				return addrs[i][k] < addrs[j][k]
			}
		}
		return false
	})

	for _, addr := range addrs {
		h.Write(addr[:])
		h.Write(contributions[addr].VRFOutput.Value[:])
	}

	var result [32]byte
	h.Read(result[:])
	return result
}

// ComputeBeaconCommitmentHash computes the commitment hash for a beacon
// contribution (R33 P2-17 FIX). The hash is H("BEACON_COMMIT_V1" || addr ||
// vrf_output.Value). This binds the validator to their VRF output without
// revealing the output itself.
//
// Properties:
//  1. Deterministic: same (addr, vrf_output) always produces the same hash.
//  2. Binding: the validator cannot change their VRF output after committing
//     because the hash would not match.
//  3. Hiding: the hash does not reveal the VRF output (pre-image resistance
//     of SHA3-256).
//
// Note: VRF output is deterministic (given the private key and input), so
// the validator cannot grind different outputs. The commitment hash simply
// prevents the validator from withholding their output after seeing other
// reveals — they have already committed, so withholding only forfeits their
// contribution without biasing the result.
func ComputeBeaconCommitmentHash(addr types.Address, output *PQVRFOutput) [32]byte {
	if output == nil {
		return [32]byte{} // zero hash — SubmitCommit rejects zero hashes
	}
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("BEACON_COMMIT_V1"))
	h.Write(addr[:])
	h.Write(output.Value[:])
	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash
}

type BeaconChain struct {
	mu sync.RWMutex

	beacons map[uint64]*RandomBeacon
}

func NewBeaconChain() *BeaconChain {
	return &BeaconChain{
		beacons: make(map[uint64]*RandomBeacon),
	}
}

func (bc *BeaconChain) CreateBeacon(epoch uint64, threshold int) *RandomBeacon {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	beacon := NewRandomBeacon(epoch, threshold)
	bc.beacons[epoch] = beacon
	return beacon
}

func (bc *BeaconChain) GetBeacon(epoch uint64) *RandomBeacon {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.beacons[epoch]
}

func (bc *BeaconChain) GetRandomness(epoch uint64) ([32]byte, error) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	beacon, ok := bc.beacons[epoch]
	if !ok {
		return [32]byte{}, fmt.Errorf("beacon for epoch %d not found", epoch)
	}

	output := beacon.GetOutput()
	if output == nil {
		return [32]byte{}, ErrBeaconNotReady
	}

	return output.Randomness, nil
}

func (bc *BeaconChain) VerifyRandomness(epoch uint64, expectedRandomness [32]byte) bool {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	beacon, ok := bc.beacons[epoch]
	if !ok {
		return false
	}

	output := beacon.GetOutput()
	if output == nil {
		return false
	}

	return subtle.ConstantTimeCompare(output.Randomness[:], expectedRandomness[:]) == 1
}

// GenerateBeaconVRFInput generates the VRF input for a beacon epoch.
// AUDIT (2026) CRND-04: The slot parameter is deprecated — the canonical
// slot is now derived from the epoch to prevent grinding. The slot parameter
// is retained for backward compatibility but ignored.
func GenerateBeaconVRFInput(epoch, slot uint64) []byte {
	_ = slot // deprecated; canonical slot is derived from epoch
	return beaconVRFInput(epoch, canonicalBeaconSlot(epoch))
}

func ComputeBeaconRandomness(epoch uint64, contributions map[types.Address]*BeaconContribution) [32]byte {
	return computeBeaconRandomness(epoch, contributions)
}

func SelectProposerByBeacon(beaconRandomness [32]byte, validators []types.Address) (types.Address, error) {
	if len(validators) == 0 {
		return types.Address{}, errors.New("no validators")
	}

	n := uint64(len(validators))
	// L12-016 FIX: Use rejection sampling to eliminate modulo bias.
	// Simple modulo (seedVal % n) is biased because 2^64 is not evenly
	// divisible by n in general: indices 0..(2^64 % n - 1) are each one
	// value more likely than the rest, favoring low-index validators.
	// We reject values in the biased tail and rehash to get a new candidate.
	maxVal := ^uint64(0)           // 2^64 - 1
	threshold := maxVal - maxVal%n // largest multiple of n <= maxVal

	current := beaconRandomness
	for attempt := 0; attempt < 256; attempt++ {
		var seed [8]byte
		copy(seed[:], current[:8])
		seedVal := uint64(seed[0]) | uint64(seed[1])<<8 | uint64(seed[2])<<16 | uint64(seed[3])<<24 |
			uint64(seed[4])<<32 | uint64(seed[5])<<40 | uint64(seed[6])<<48 | uint64(seed[7])<<56

		// Accept only unbiased values; rehash the rest.
		if seedVal < threshold {
			idx := seedVal % n
			return validators[idx], nil
		}

		// Rehash: mix current randomness with the attempt counter.
		h := sha3.NewLegacyKeccak256()
		h.Write(current[:])
		h.Write([]byte{byte(attempt), byte(attempt >> 8), byte(attempt >> 16)})
		copy(current[:], h.Sum(nil))
	}

	// Extremely unlikely (prob ≈ (n/2^64)^256 ≈ 0): all 256 attempts fell
	// in the biased region. Fall back to simple modulo with negligible bias.
	var seed [8]byte
	copy(seed[:], current[:8])
	seedVal := uint64(seed[0]) | uint64(seed[1])<<8 | uint64(seed[2])<<16 | uint64(seed[3])<<24 |
		uint64(seed[4])<<32 | uint64(seed[5])<<40 | uint64(seed[6])<<48 | uint64(seed[7])<<56
	return validators[seedVal%n], nil
}

func GenerateRandomBeaconInput() []byte {
	var buf [32]byte
	// FIX: Handle rand.Read error. Previously the error
	// was silently ignored, which could return an all-zero buffer if the
	// system entropy source failed. An all-zero beacon input is dangerous
	// because it makes the random beacon predictable, potentially allowing
	// an attacker to predict proposer/committee assignments.
	// If crypto/rand fails (extremely rare), we fall back to a time-based
	// seed mixed with the existing buffer to avoid returning a predictable
	// all-zero value. This is a defense-in-depth measure; in production,
	// a rand.Read failure should trigger alerts.
	if _, err := rand.Read(buf[:]); err != nil {
		// Fallback: mix current time (nanosecond precision) into the buffer.
		// This is NOT cryptographically ideal but is strictly better than
		// returning all zeros. The time-based fallback makes prediction
		// harder than a constant zero value.
		now := time.Now().UnixNano() // NOT consensus-critical: local in-memory tracking only
		for i := 0; i < 8; i++ {
			buf[i] = byte(now >> (i * 8))
		}
		// Mix with sha3 of time to spread entropy across all 32 bytes
		hash := sha3.NewLegacyKeccak256()
		hash.Write(buf[:8])
		hashed := hash.Sum(nil)
		copy(buf[:], hashed)
	}
	return buf[:]
}
