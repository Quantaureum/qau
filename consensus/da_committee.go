// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"sync"

	"github.com/quantaureum/qau/encoding"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

var daCommitteeLogger = logging.Global()

const (
	DACommitteeSize          = 512
	DACommitteeSubnetCount   = 32
	DACommitteeValidatorsPer = 16
	DACommitteeEpochLength   = 256
	DAAttestationThreshold   = 0.6667
	// DAMaxTransitionSignatures bounds the number of individual validator
	// signatures concatenated in transition (multi-sig) mode. P0-3 (2026-07-14):
	// When no QTD threshold signer is configured, BuildAggregateAttestation
	// refuses to produce an aggregate with more than this many signatures —
	// larger committees MUST use QTD threshold aggregation instead, otherwise
	// verification time and on-chain footprint grow linearly with committee
	// size. DoD requires ≤ 64 in transition mode.
	DAMaxTransitionSignatures = 64
	// DAMaxAttestationsPerSlot bounds the number of attestations accepted
	// per slot by SubmitAttestation. P1-8 (2026-07-14): Without this cap, a
	// malicious peer could flood the collector with attestations for bogus
	// ValidatorIndex values (even though each is individually verified, the
	// storage and aggregation cost is unbounded). The cap equals the
	// committee size — once every committee member has attested, further
	// submissions for the same slot are redundant and rejected. When
	// committeeSize is set via SetCommitteeSize, this provides a hard upper
	// bound on memory per slot: O(committeeSize) attestations, not O(infinity).
	DAMaxAttestationsPerSlot = DACommitteeSize
	// DAMaxTrackedAttestSlots caps the number of DISTINCT slots the
	// collector tracks. AUDIT ROUND-6 2026-08-17 FIX: attestations are
	// keyed by slot and CleanupOldSlots only removes PAST slots — a
	// committee member with a valid signature key could submit verified
	// attestations for arbitrarily distant FUTURE slots (slot = now + 10^9),
	// each creating a per-slot map entry that never ages out, growing
	// memory without bound. New slots are rejected once this cap is hit.
	DAMaxTrackedAttestSlots = 1024
	// DAMaxFutureAttestSlots bounds how far ahead of the observed current
	// slot a tracked slot may lie before CleanupOldSlots drops it (),
	// mirroring the MEV auction's MaxFutureSlotAhead hardening ().
	DAMaxFutureAttestSlots = 1024
)

// DACommitteeConfig configures the DA committee manager.
// P0-5 (2026-07-13): Previously DACommitteeSize was a compile-time constant
// with no way to disable the committee. Small networks (testnet/devnet) with
// fewer than 512 validators would always fail committee computation. This
// struct allows runtime configuration: when Enabled=false, the committee
// manager short-circuits GetCommittee/IsDACommitteeAvailable to return
// disabled-state errors/false, allowing the rest of the DA subsystem to
// operate in a "DA not enforced" mode without spurious errors.
type DACommitteeConfig struct {
	// Enabled controls whether the DA committee is active. When false,
	// GetCommittee returns ErrDACommitteeDisabled and IsDACommitteeAvailable
	// returns false. Mainnet should set this to true; testnet/devnet may
	// set this to false during early operation.
	Enabled bool
	// Size is the committee size. Defaults to DACommitteeSize if zero.
	Size int
}

// ErrDACommitteeDisabled is returned when the DA committee is explicitly
// disabled via configuration (DACommitteeConfig.Enabled=false).
var ErrDACommitteeDisabled = fmt.Errorf("DA committee disabled by configuration")

type DACommitteeMember struct {
	ValidatorIndex int
	Address        types.Address
	SubnetID       int
}

type DACommittee struct {
	Epoch   uint64
	Members []DACommitteeMember
	Subnets [DACommitteeSubnetCount][]DACommitteeMember
	mu      sync.RWMutex
}

type DACommitteeManager struct {
	committees    map[uint64]*DACommittee
	mu            sync.RWMutex
	getValidators func() []*ValidatorInfo
	getRandao     func(epoch uint64) types.Hash
	// P1-12 (2026-07-14): VRF-based random beacon for shuffle seed. When
	// set, the beacon's VRF randomness takes priority over the RANDAO mix
	// as the shuffle seed. Falls back to getRandao when the beacon is not
	// finalized for the epoch.
	beaconChain *BeaconChain
	// P0-5 (2026-07-13): Runtime-configurable committee size and enabled flag.
	// When config.Enabled=false, GetCommittee returns ErrDACommitteeDisabled
	// and IsDACommitteeAvailable returns false without touching the validator
	// set. When config.Size > 0, it overrides the DACommitteeSize constant.
	config DACommitteeConfig
}

type indexedValidator struct {
	index int
	info  *ValidatorInfo
}

func NewDACommitteeManager(
	getValidators func() []*ValidatorInfo,
	getRandao func(epoch uint64) types.Hash,
) *DACommitteeManager {
	return &DACommitteeManager{
		committees:    make(map[uint64]*DACommittee),
		getValidators: getValidators,
		getRandao:     getRandao,
		// P0-5: Default to enabled with the standard committee size. Callers
		// can override via SetConfig() (e.g., testnet sets Enabled=false).
		config: DACommitteeConfig{Enabled: true, Size: DACommitteeSize},
	}
}

// SetConfig updates the DA committee configuration at runtime.
// P0-5 (2026-07-13): Allows node operators to disable the committee or
// adjust its size without recompiling. When Enabled=false, cached committees
// are cleared so that subsequent GetCommittee calls return disabled errors
// instead of stale results.
func (m *DACommitteeManager) SetConfig(cfg DACommitteeConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = cfg
	if !cfg.Enabled {
		// Clear cached committees so GetCommittee doesn't return stale data.
		cleared := len(m.committees)
		m.committees = make(map[uint64]*DACommittee)
		// P3-2 (2026-07-15): Log committee disable for lifecycle traceability.
		daCommitteeLogger.Infof("[da] committee disabled via SetConfig (cleared %d cached epochs)", cleared)
	}
}

// SetBeaconChain injects the VRF-based random beacon chain. When set,
// the DA committee shuffle seed is derived from the beacon's VRF output
// (post-quantum PQVRF based on Dilithium3) instead of the simple RANDAO
// XOR mix. This provides stronger unpredictability guarantees: the VRF
// output is verifiable and non-biasable by a single party.
// P1-12 (2026-07-14).
//
// DA- (2026-07-16): This method is currently NOT called from the
// node startup path (node.go). The DA committee shuffle seed is instead
// derived from the finalized epoch's VRF accumulator (Tier 1) or the
// previous epoch's accumulator (Tier 2), which eliminates block-withholding
// grinding by using immutable, finalized entropy. The beacon chain path
// remains as a future extension point for when a full commit-reveal
// protocol is implemented (the current RandomBeacon has its own
// last-revealer bias — see random_beacon.go:111-119). Until then, this
// hook is intentionally unwired and the getShuffleSeedLocked beacon
// branch is unreachable in production.
func (m *DACommitteeManager) SetBeaconChain(bc *BeaconChain) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.beaconChain = bc
}

// effectiveSize returns the configured committee size, falling back to the
// DACommitteeSize constant when config.Size is not positive.
//
// P2-10 FIX (2026-07-15): This method reads m.config.Size which is written by
// SetConfig under m.mu.Lock. Callers MUST hold m.mu (read or write) to avoid
// a data race. The public IsDACommitteeAvailable method now acquires RLock
// before calling this.
func (m *DACommitteeManager) effectiveSize() int {
	if m.config.Size > 0 {
		return m.config.Size
	}
	return DACommitteeSize
}

// getShuffleSeed returns the seed for the committee shuffle. P1-12 (2026-07-14):
// When a VRF-based BeaconChain is configured and finalized for the epoch,
// its randomness is used as the seed — this is post-quantum secure (PQVRF
// based on Dilithium3) and non-biasable by any single party. When the beacon
// is not available (nil, not created, or not yet finalized), falls back to
// the RANDAO mix from QPOS. This ensures liveness during startup and when
// insufficient beacon contributions are received.
//
// This method acquires m.mu.RLock internally. Callers already holding m.mu
// (read or write) MUST use getShuffleSeedLocked instead to avoid re-entrant
// lock deadlock.
func (m *DACommitteeManager) getShuffleSeed(epoch uint64) types.Hash {
	m.mu.RLock()
	bc := m.beaconChain
	m.mu.RUnlock()
	return m.getShuffleSeedLocked(epoch, bc)
}

// getShuffleSeedLocked is the lock-free inner implementation. The caller MUST
// hold at least m.mu.RLock (or m.mu.Lock). P1-12 (2026-07-14): split from
// getShuffleSeed to fix re-entrant RLock deadlock when called from
// computeCommittee (which holds m.mu.Lock — Go's sync.RWMutex blocks readers
// while a writer holds the lock, so re-acquiring RLock from the same goroutine
// deadlocks).
func (m *DACommitteeManager) getShuffleSeedLocked(epoch uint64, bc *BeaconChain) types.Hash {
	if bc != nil {
		randomness, err := bc.GetRandomness(epoch)
		if err == nil {
			return types.BytesToHash(randomness[:])
		}
	}
	return m.getRandao(epoch)
}

func (m *DACommitteeManager) GetCommittee(epoch uint64) (*DACommittee, error) {
	// P0-5: Short-circuit when the committee is explicitly disabled.
	// P2-10 FIX (2026-07-15): Read m.config.Enabled under RLock to avoid
	// data race with SetConfig (which writes under Lock).
	m.mu.RLock()
	enabled := m.config.Enabled
	committee, exists := m.committees[epoch]
	m.mu.RUnlock()

	if !enabled {
		return nil, ErrDACommitteeDisabled
	}

	if exists {
		return committee, nil
	}

	committee, err := m.computeCommittee(epoch)
	if err != nil {
		// R54-CS-01 FIX: Return the error instead of nil, nil. Returning
		// nil, nil causes callers to proceed with a nil committee, leading
		// to nil pointer dereference or incorrect empty-committee behavior.
		return nil, fmt.Errorf("failed to compute DA committee for epoch %d: %w", epoch, err)
	}
	return committee, nil
}

func (m *DACommitteeManager) IsDACommitteeAvailable() bool {
	// P0-5: When explicitly disabled, report unavailable without touching
	// the validator set.
	// P2-10 FIX (2026-07-15): Read m.config under RLock to avoid data race
	// with SetConfig. effectiveSize() also reads m.config.Size, so it must
	// be called under the lock.
	m.mu.RLock()
	enabled := m.config.Enabled
	size := m.effectiveSize()
	m.mu.RUnlock()

	if !enabled {
		return false
	}
	validators := m.getValidators()
	activeCount := 0
	for _, v := range validators {
		if v.Active {
			activeCount++
		}
	}
	return activeCount >= size
}

func (m *DACommitteeManager) computeCommittee(epoch uint64) (*DACommittee, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if committee, exists := m.committees[epoch]; exists {
		return committee, nil
	}

	validators := m.getValidators()
	if len(validators) == 0 {
		return nil, fmt.Errorf("no validators available")
	}

	activeValidators := make([]indexedValidator, 0, len(validators))
	for i, v := range validators {
		if v.Active {
			activeValidators = append(activeValidators, indexedValidator{index: i, info: v})
		}
	}

	// P0-5: Use the runtime-configurable effective size instead of the
	// DACommitteeSize constant directly.
	requiredSize := m.effectiveSize()
	if len(activeValidators) < requiredSize {
		daCommitteeLogger.Infof("DA committee unavailable: active validators %d < required %d. This is normal for small networks; DA committee will activate automatically when validator count reaches the threshold", len(activeValidators), requiredSize)
		return nil, fmt.Errorf("insufficient active validators: %d < %d", len(activeValidators), requiredSize)
	}

	// P1-12 (2026-07-14): Use VRF-based beacon randomness as the shuffle
	// seed when available; falls back to RANDAO mix otherwise. We hold
	// m.mu.Lock here, so use getShuffleSeedLocked (not getShuffleSeed,
	// which would deadlock re-acquiring m.mu.RLock).
	seed := m.getShuffleSeedLocked(epoch, m.beaconChain)

	shuffled := make([]indexedValidator, len(activeValidators))
	copy(shuffled, activeValidators)
	shuffleIndexedValidators(shuffled, seed)

	committee := &DACommittee{
		Epoch:   epoch,
		Members: make([]DACommitteeMember, requiredSize),
	}

	for i := 0; i < requiredSize; i++ {
		subnetID := i % DACommitteeSubnetCount
		committee.Members[i] = DACommitteeMember{
			ValidatorIndex: shuffled[i].index,
			Address:        shuffled[i].info.Address,
			SubnetID:       subnetID,
		}
		committee.Subnets[subnetID] = append(committee.Subnets[subnetID], committee.Members[i])
	}

	m.committees[epoch] = committee

	m.cleanupOldCommittees(epoch)

	// P3-2 (2026-07-15): Log committee switch for lifecycle traceability.
	// This fires once per epoch when a new committee is computed (not on
	// every GetCommittee call, which returns the cached committee).
	daCommitteeLogger.Infof("[da] committee computed: epoch=%d members=%d subnets=%d", epoch, len(committee.Members), DACommitteeSubnetCount)

	return committee, nil
}

func (m *DACommitteeManager) cleanupOldCommittees(currentEpoch uint64) {
	for epoch := range m.committees {
		if epoch+4 < currentEpoch {
			delete(m.committees, epoch)
		}
	}
}

func (m *DACommitteeManager) IsInCommittee(epoch uint64, validatorIndex int) (bool, int) {
	committee, err := m.GetCommittee(epoch)
	if err != nil {
		return false, -1
	}

	committee.mu.RLock()
	defer committee.mu.RUnlock()

	for _, member := range committee.Members {
		if member.ValidatorIndex == validatorIndex {
			return true, member.SubnetID
		}
	}
	return false, -1
}

func (m *DACommitteeManager) GetSubnetMembers(epoch uint64, subnetID int) ([]DACommitteeMember, error) {
	committee, err := m.GetCommittee(epoch)
	if err != nil {
		return nil, err
	}

	committee.mu.RLock()
	defer committee.mu.RUnlock()

	if subnetID < 0 || subnetID >= DACommitteeSubnetCount {
		return nil, fmt.Errorf("invalid subnet ID: %d", subnetID)
	}

	members := make([]DACommitteeMember, len(committee.Subnets[subnetID]))
	copy(members, committee.Subnets[subnetID])
	return members, nil
}

// shuffleIndexedValidators shuffles validators using a Fisher-Yates shuffle with
// a SHA3-based PRNG. The seed comes from getShuffleSeed: when a VRF-based
// BeaconChain is configured and finalized, the seed is the beacon's PQVRF
// output (post-quantum secure, non-biasable). Otherwise, the RANDAO mix from
// QPOS is used as a fallback. P1-12 (2026-07-14): VRF integration.
func shuffleIndexedValidators(validators []indexedValidator, seed types.Hash) {
	n := len(validators)
	if n <= 1 {
		return
	}

	rng := newShuffleRNG(seed)

	for i := n - 1; i > 0; i-- {
		j := rng.nextInt(i + 1)
		validators[i], validators[j] = validators[j], validators[i]
	}
}

// shuffleRNG implements a SHA3-based deterministic random number generator.
// The seed comes from getShuffleSeed: VRF beacon randomness (primary) or
// RANDAO mix (fallback). P1-12 (2026-07-14): VRF integration.
type shuffleRNG struct {
	state [32]byte
}

func newShuffleRNG(seed types.Hash) *shuffleRNG {
	// Mix seed with a domain separator to prevent cross-protocol collisions
	h := sha3.New256()
	h.Write([]byte("QuantaureumDACommitteeShuffleV1"))
	h.Write(seed[:])
	rng := &shuffleRNG{}
	hash := h.Sum(nil)
	copy(rng.state[:], hash)
	return rng
}

func (r *shuffleRNG) nextInt(max int) int {
	if max <= 1 {
		return 0
	}
	maxU64 := uint64(max)
	rejectThreshold := (math.MaxUint64 / maxU64) * maxU64
	for {
		h := sha3.New256()
		h.Write(r.state[:])
		hash := h.Sum(nil)
		copy(r.state[:], hash)
		val := binary.BigEndian.Uint64(hash[:8])
		if val < rejectThreshold {
			return int(val % maxU64)
		}
	}
}

type DAAttestationCollector struct {
	attestations  map[uint64]map[int]*encoding.DASAttestation
	mu            sync.RWMutex
	retention     encoding.DASRetentionConfig
	committeeSize int // AUDIT (2026) GOV-04: bounded validator index range
	// AUDIT (2026) GOV-04: Signature + committee membership verifier.
	// Fail-closed: if nil, all attestations are rejected. This prevents an
	// attacker from forging attestations with arbitrary ValidatorIndex and
	// Available=true to inflate the aggregate availability count.
	attestationVerifier DAAttestationVerifier
	// P0-3 (2026-07-14): Optional QTD threshold signer. When non-nil AND
	// IsThresholdMode() returns true, BuildAggregateAttestation aggregates
	// partial signatures into a single threshold signature (Signatures has
	// length 1, ThresholdAggregated=true). When nil or not in threshold mode,
	// transition multi-sig mode is used (concatenated signatures, ≤ 64).
	thresholdSigner ThresholdKeySigner
	// P3-1 (2026-07-15): Optional DA metrics for observability. When non-nil,
	// SubmitAttestation increments verifier_rejections_total and
	// attestation_cap_rejections_total counters on the corresponding rejection
	// paths. Nil-safe: all metric helper methods early-return on nil receiver.
	metrics *DAMetrics
}

// DAAttestationVerifier verifies the signature and committee membership of a
// DA attestation. The implementation should:
//  1. Look up the validator by ValidatorIndex
//  2. Verify the Signature against the attestation Hash() using the validator's public key
//  3. Verify the validator is in the DA committee for the slot's epoch
//
// AUDIT (2026) GOV-04: Without this verification, SubmitAttestation
// accepted any attestation with a valid index range, allowing forged
// attestations to inflate aggregate availability.
type DAAttestationVerifier func(attestation *encoding.DASAttestation) error

func NewDAAttestationCollector() *DAAttestationCollector {
	return &DAAttestationCollector{
		attestations:  make(map[uint64]map[int]*encoding.DASAttestation),
		retention:     encoding.DefaultDASRetentionConfig(),
		committeeSize: 0, // fail-closed: must be set via SetCommitteeSize
	}
}

// SetRetentionConfig updates the retention configuration.
// DA- (2026-07-16): Rejects invalid configurations (those violating
// the Blob >= Session >= Attest > Decay invariants) and keeps the previous
// config — fail-closed against accidental availability regression.
func (c *DAAttestationCollector) SetRetentionConfig(cfg encoding.DASRetentionConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := cfg.Validate(); err != nil {
		daCommitteeLogger.Warnf("[da] DA- rejecting invalid retention config from DAAttestationCollector.SetRetentionConfig: %v (keeping previous config)", err)
		return
	}
	c.retention = cfg
}

// SetCommitteeSize sets the expected committee size for validator index
// validation. AUDIT (2026) GOV-04: Without this, SubmitAttestation
// accepted any ValidatorIndex, allowing an attacker to forge attestations
// with arbitrary indices to inflate the aggregate availability count.
// Fail-closed: if committeeSize is 0 (not set), all submissions are rejected.
func (c *DAAttestationCollector) SetCommitteeSize(size int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.committeeSize = size
}

// SetAttestationVerifier sets the signature + committee membership verifier.
// AUDIT (2026) GOV-04: Without this, SubmitAttestation did not verify
// the attestation signature or committee membership, allowing an attacker
// to forge attestations with arbitrary Available=true to inflate the
// aggregate availability count.
// Fail-closed: if nil (not set), all submissions are rejected.
func (c *DAAttestationCollector) SetAttestationVerifier(v DAAttestationVerifier) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attestationVerifier = v
}

// SetThresholdSigner injects the QTD threshold signer used to aggregate
// partial DAS attestation signatures into a single threshold signature.
// P0-3 (2026-07-14): When non-nil and IsThresholdMode()=true,
// BuildAggregateAttestation switches from transition multi-sig (≤ 64
// concatenated signatures) to QTD threshold aggregation (1 signature).
//
// SECURITY: The injected signer MUST verify each DASAttestation.Signature
// as a valid partial signature over the canonical threshold message
// (see thresholdMessageForSlot) BEFORE accepting it via SubmitAttestation.
// The SetAttestationVerifier callback is the right place to enforce this.
//
// Passing nil disables QTD mode and reverts to transition multi-sig mode.
func (c *DAAttestationCollector) SetThresholdSigner(s ThresholdKeySigner) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.thresholdSigner = s
}

// SetDAMetrics injects the DA metrics collector. P3-1 (2026-07-15).
// When set, SubmitAttestation increments the verifier_rejections_total and
// attestation_cap_rejections_total counters on the corresponding rejection
// paths. Passing nil disables metric recording (existing tests that don't
// set metrics continue to work — all DAMetrics methods are nil-safe).
func (c *DAAttestationCollector) SetDAMetrics(m *DAMetrics) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metrics = m
}

// thresholdMessageForSlot returns the canonical message that all validators
// sign in QTD threshold mode. P0-3 (2026-07-14): Each validator's
// DASAttestation.Signature is a partial signature over THIS message (not
// over DASAttestation.Hash, which differs per validator due to varying
// SampleCount/SuccessCount). Using a common message is what allows the
// partial signatures to be aggregated by AggregatePartialSignatures.
//
// The message binds:
//   - slot:           which slot the attestation is for
//   - blob commitments: which blobs are being attested
//   - "QauDASAttestV1": domain separator preventing cross-protocol reuse
func thresholdMessageForSlot(slot uint64, commitments []encoding.KZGCommitment) []byte {
	h := sha3.New256()
	h.Write([]byte("QauDASAttestV1"))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], slot)
	h.Write(buf[:])
	for _, c := range commitments {
		h.Write(c[:])
	}
	return h.Sum(nil)
}

func (c *DAAttestationCollector) SubmitAttestation(attestation *encoding.DASAttestation) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// AUDIT (2026) GOV-04: Fail-closed — reject all attestations when
	// committee size is not configured. Previously, any ValidatorIndex was
	// accepted, allowing forged attestations to inflate availability.
	if c.committeeSize <= 0 {
		return fmt.Errorf("committee size not configured; cannot accept attestations")
	}
	if attestation.ValidatorIndex < 0 || attestation.ValidatorIndex >= c.committeeSize {
		return fmt.Errorf("validator index %d out of range [0, %d)", attestation.ValidatorIndex, c.committeeSize)
	}

	// AUDIT (2026) GOV-04: Fail-closed — reject all attestations when
	// the signature verifier is not configured. Without signature verification,
	// an attacker can forge attestations with any ValidatorIndex and
	// Available=true to inflate the aggregate availability count.
	if c.attestationVerifier == nil {
		c.metrics.IncVerifierRejections()
		daCommitteeLogger.Warnf("[da] attestation rejected (verifier not configured): slot=%d validatorIndex=%d", attestation.Slot, attestation.ValidatorIndex)
		return fmt.Errorf("attestation verifier not configured; cannot accept attestations")
	}
	if err := c.attestationVerifier(attestation); err != nil {
		c.metrics.IncVerifierRejections()
		daCommitteeLogger.Warnf("[da] attestation rejected (verifier failed): slot=%d validatorIndex=%d err=%v", attestation.Slot, attestation.ValidatorIndex, err)
		return fmt.Errorf("attestation verification failed: %w", err)
	}

	slotAttestations, exists := c.attestations[attestation.Slot]
	if !exists {
		// AUDIT ROUND-6 2026-08-17 FIX: cap the number of distinct
		// tracked slots (see DAMaxTrackedAttestSlots). Existing slots keep
		// accepting up to the per-slot cap; only OPENING a new slot is
		// gated, so a full window of live slots is unaffected.
		if len(c.attestations) >= DAMaxTrackedAttestSlots {
			c.metrics.IncAttestationCapRejections()
			daCommitteeLogger.Warnf("[da] attestation rejected (tracked-slot cap reached): slot=%d current=%d cap=%d (audit )", attestation.Slot, len(c.attestations), DAMaxTrackedAttestSlots)
			return fmt.Errorf("tracked attestation slot cap reached: %d/%d (audit )", len(c.attestations), DAMaxTrackedAttestSlots)
		}
		slotAttestations = make(map[int]*encoding.DASAttestation)
		c.attestations[attestation.Slot] = slotAttestations
	}

	// P1-8 (2026-07-14): Enforce per-slot attestation cap to prevent memory
	// DoS. The cap is the smaller of DAMaxAttestationsPerSlot and the
	// configured committee size — once every committee member has attested,
	// further submissions are redundant. Submissions that would exceed the
	// cap are rejected with an error so the caller knows to stop retrying.
	// Re-submissions from the same validator (overwriting an existing entry)
	// are allowed and do not count against the cap.
	cap := DAMaxAttestationsPerSlot
	if c.committeeSize > 0 && c.committeeSize < cap {
		cap = c.committeeSize
	}
	if _, existing := slotAttestations[attestation.ValidatorIndex]; !existing {
		if len(slotAttestations) >= cap {
			c.metrics.IncAttestationCapRejections()
			daCommitteeLogger.Warnf("[da] attestation rejected (cap reached): slot=%d validatorIndex=%d current=%d cap=%d", attestation.Slot, attestation.ValidatorIndex, len(slotAttestations), cap)
			return fmt.Errorf("attestation cap reached for slot %d: %d/%d", attestation.Slot, len(slotAttestations), cap)
		}
	}

	slotAttestations[attestation.ValidatorIndex] = attestation
	return nil
}

func (c *DAAttestationCollector) GetAttestations(slot uint64) []*encoding.DASAttestation {
	c.mu.RLock()
	defer c.mu.RUnlock()

	slotAttestations, exists := c.attestations[slot]
	if !exists {
		return nil
	}

	result := make([]*encoding.DASAttestation, 0, len(slotAttestations))
	for _, att := range slotAttestations {
		result = append(result, att)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].ValidatorIndex < result[j].ValidatorIndex
	})

	return result
}

// BuildAggregateAttestation produces the aggregate DA attestation for a slot.
// P0-3 (2026-07-14): Two aggregation modes:
//
//  1. QTD threshold mode (preferred): when thresholdSigner != nil and
//     IsThresholdMode()=true, partial signatures from "Available" attestations
//     are aggregated into a single threshold signature via
//     AggregatePartialSignatures. Result: Signatures has length 1,
//     ThresholdAggregated=true. Verification uses the group public key over
//     thresholdMessageForSlot(slot, commitments).
//
//  2. Transition multi-sig mode (fallback): when no threshold signer is
//     configured, individual signatures are concatenated. To keep on-chain
//     footprint and verification time bounded, this mode REFUSES to produce
//     an aggregate with more than DAMaxTransitionSignatures signatures —
//     larger committees MUST enable QTD. Result: Signatures has length ≤ 64,
//     ThresholdAggregated=false.
//
// In both modes, ValidatorBits and AvailableCount/TotalCount are populated
// identically so that IsSufficient() works uniformly.
func (c *DAAttestationCollector) BuildAggregateAttestation(slot uint64, commitments []encoding.KZGCommitment) *encoding.DASAggregateAttestation {
	attestations := c.GetAttestations(slot)
	if len(attestations) == 0 {
		return nil
	}

	// DA- (2026-07-16): Verify each attestation's BlobCommitments
	// matches the expected aggregate set. Without this, an attacker could
	// submit an attestation with a different commitment set (but same
	// BlobCommitment[0]) and have it counted toward the aggregate, breaking
	// the binding between the DA proof and the actual committed data.
	//
	// Fail-closed: if commitments is non-empty AND any attestation's
	// BlobCommitments differs from it, refuse to produce an aggregate.
	// This prevents an attacker from poisoning the aggregate with
	// mismatched attestations. When commitments is nil (e.g., quorum-only
	// checks via GetAggregateAttestation), the binding check is skipped —
	// the caller is responsible for re-checking with the real set.
	if len(commitments) > 0 {
		for _, att := range attestations {
			// DA-FIX (2026-07-17): In production mode, reject legacy
			// attestations whose BlobCommitments is empty. Legacy attestations
			// only bind to commitments[0] via the BlobCommitment field (32-byte
			// truncated form), so they can be reused across commitment sets
			// that share the same first commitment — weakening the DA proof
			// binding. The legacy fallback path in attestationCommitmentsMatch
			// remains available for dev/test networks, but mainnet must
			// require the full BlobCommitments trailing block.
			if params.IsProductionEnv() && len(att.BlobCommitments) == 0 {
				daCommitteeLogger.Errorf(
					"[da] DA- legacy attestation (empty BlobCommitments) rejected in production mode for slot %d validator %d — full commitment set required",
					slot, att.ValidatorIndex,
				)
				return nil
			}
			if !attestationCommitmentsMatch(att, commitments) {
				daCommitteeLogger.Errorf(
					"[da] DA- attestation commitment mismatch for slot %d validator %d — refusing to aggregate (attestation BlobCommitments does not match expected set)",
					slot, att.ValidatorIndex,
				)
				return nil
			}
		}
	}

	aggregate := &encoding.DASAggregateAttestation{
		Slot:            slot,
		BlobCommitments: commitments,
		// DA- (2026-07-17): Populate CommitteeSize so IsSufficient
		// can enforce the absolute attestation floor (TotalCount ≥
		// ceil(2/3 · CommitteeSize)). Without this, IsSufficient
		// fail-closed returns false, refusing to produce a sufficient
		// aggregate. The collector's committeeSize is set via
		// SetCommitteeSize (fail-closed: 0 until set).
		CommitteeSize: c.committeeSize,
	}

	availableCount := 0
	for _, att := range attestations {
		if att.Available {
			availableCount++
		}
	}
	aggregate.AvailableCount = availableCount
	aggregate.TotalCount = len(attestations)

	bitsLen := (len(attestations) + 7) / 8
	aggregate.ValidatorBits = make([]byte, bitsLen)
	for i, att := range attestations {
		if att.Available {
			byteIdx := i / 8
			bitIdx := i % 8
			aggregate.ValidatorBits[byteIdx] |= 1 << bitIdx
		}
	}

	// Read the threshold signer under the lock to avoid TOCTOU.
	c.mu.RLock()
	signer := c.thresholdSigner
	c.mu.RUnlock()

	useThreshold := signer != nil && signer.IsThresholdMode()
	if useThreshold {
		// QTD threshold mode: collect partial sigs from Available attestations.
		sealers := make([]int, 0, availableCount)
		partialSigs := make(map[int][]byte, availableCount)
		for _, att := range attestations {
			if !att.Available {
				continue
			}
			sealers = append(sealers, att.ValidatorIndex)
			partialSigs[att.ValidatorIndex] = att.Signature
		}
		if len(sealers) == 0 {
			// No available attesters — nothing to aggregate. P1-7 (2026-07-14):
			// IsSufficient()=false here, so return nil rather than an empty
			// aggregate that callers might mistake for a valid (but empty)
			// aggregate.
			return nil
		}
		msg := thresholdMessageForSlot(slot, commitments)
		aggSig, err := signer.AggregatePartialSignatures(sealers, partialSigs, msg)
		if err != nil {
			// Aggregation failed (e.g., insufficient partial sigs, malformed
			// sigs, DKG not ready). Log and fall back to multi-sig mode if
			// the count fits within the transition limit; otherwise refuse
			// to produce an unbounded aggregate.
			daCommitteeLogger.Errorf("QTD aggregation failed for slot %d: %v", slot, err)
			if len(attestations) > DAMaxTransitionSignatures {
				return nil
			}
			for _, att := range attestations {
				aggregate.Signatures = append(aggregate.Signatures, att.Signature)
			}
			// P1-7: fallback aggregate must also pass IsSufficient.
			if !aggregate.IsSufficient() {
				return nil
			}
			return aggregate
		}
		aggregate.Signatures = [][]byte{aggSig}
		aggregate.ThresholdAggregated = true
		// P1-7: even successful QTD aggregation must pass IsSufficient — the
		// threshold signature proves the available attesters signed, but if
		// AvailableCount/TotalCount < 0.6667 the block is still not DA-safe.
		if !aggregate.IsSufficient() {
			return nil
		}
		return aggregate
	}

	// Transition multi-sig mode: enforce ≤ DAMaxTransitionSignatures bound.
	if len(attestations) > DAMaxTransitionSignatures {
		daCommitteeLogger.Errorf(
			"transition mode: %d attestations for slot %d exceed limit %d; enable QTD threshold mode",
			len(attestations), slot, DAMaxTransitionSignatures,
		)
		return nil
	}
	for _, att := range attestations {
		aggregate.Signatures = append(aggregate.Signatures, att.Signature)
	}
	// P1-7 (2026-07-14): Do not return an aggregate that fails the
	// sufficiency check. Callers rely on a non-nil return meaning "this
	// aggregate is valid and the block is DA-available". Returning an
	// insufficient aggregate would let BlockValidator/consensus mis-treat
	// an unavailable block as available. The 0-attester case is already
	// handled above (returns empty aggregate); here we handle the case
	// where attestations exist but AvailableCount/TotalCount < 0.6667.
	if !aggregate.IsSufficient() {
		return nil
	}
	return aggregate
}

func (c *DAAttestationCollector) CleanupOldSlots(currentSlot uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	retentionSlots := c.retention.AttestRetentionSlots
	for slot := range c.attestations {
		// AUDIT ROUND-6 2026-08-17 FIX: also drop FAR-FUTURE slots.
		// Previously only stale past slots were pruned, so entries for
		// arbitrarily distant future slots — which never become "old" —
		// accumulated forever. Attestations more than DAMaxFutureAttestSlots
		// ahead of the observed current slot cannot participate in any
		// aggregation this process will perform and are dropped here.
		if slot+retentionSlots < currentSlot || slot > currentSlot+DAMaxFutureAttestSlots {
			delete(c.attestations, slot)
		}
	}
}

// attestationCommitmentsMatch checks whether the attestation's BlobCommitments
// field is consistent with the expected aggregate set. DA- (2026-07-16).
//
// Matching rules:
//   - If att.BlobCommitments is non-empty: it must equal `expected` exactly
//     (same length, same entries in the same order).
//   - If att.BlobCommitments is empty (legacy attestation without the
//     trailing block): fall back to comparing att.BlobCommitment (legacy
//     single-commitment field, 32 bytes) against the truncated form of
//     expected[0] (KZGCommitment, 48 bytes → last 32 bytes via
//     types.BytesToHash). This preserves backward compatibility with
//     attestations produced by old binaries that only set BlobCommitment.
//     If `expected` is empty, the legacy attestation is accepted only if
//     att.BlobCommitment is the zero hash (i.e., the attester had no
//     commitments).
//
// DA- (2026-07-17): `expected` is now []encoding.KZGCommitment (48
// bytes each) instead of []types.Hash. The legacy fallback compares
// att.BlobCommitment against types.BytesToHash(expected[0][:]). NOTE:
// types.BytesToHash takes the LAST 32 bytes of a >32-byte input (i.e.,
// bytes 16..47 of the 48-byte commitment), not the first 32 bytes. This
// derivation is identical to BuildDAAttestation's
// `types.BytesToHash(commitments[0][:])`, so the two sites stay consistent.
//
// This function is intentionally pure (no side effects, no I/O) so it can
// be unit-tested in isolation.
func attestationCommitmentsMatch(att *encoding.DASAttestation, expected []encoding.KZGCommitment) bool {
	if att == nil {
		return false
	}
	if len(att.BlobCommitments) > 0 {
		if len(att.BlobCommitments) != len(expected) {
			return false
		}
		for i := range att.BlobCommitments {
			if att.BlobCommitments[i] != expected[i] { // #nosec G602 -- lengths verified equal above
				return false
			}
		}
		return true
	}
	// Legacy attestation (no BlobCommitments trailing block): fall back to
	// the single BlobCommitment field (32 bytes). Compare against
	// types.BytesToHash(expected[0][:]) — the LAST 32 bytes of the 48-byte
	// commitment (DA- truncated form, consistent with BuildDAAttestation).
	if len(expected) == 0 {
		return att.BlobCommitment == (types.Hash{})
	}
	if len(expected) > 0 {
		expectedLegacy := types.BytesToHash(expected[0][:])
		if att.BlobCommitment != expectedLegacy {
			return false
		}
	}
	return true
}

type DASubnetManager struct {
	subnets     [DACommitteeSubnetCount]*DASubnet
	mu          sync.RWMutex
	blobStorage BlobStorageProvider
}

type BlobStorageProvider interface {
	GetCell(slot uint64, blobIndex, row, col int) (*encoding.Cell, *encoding.KZGCommitment, error)
	HasBlob(slot uint64, blobIndex int) bool
}

type DASubnet struct {
	ID      int
	columns []int
	mu      sync.RWMutex
}

func NewDASubnetManager(storage BlobStorageProvider) *DASubnetManager {
	m := &DASubnetManager{
		blobStorage: storage,
	}
	for i := 0; i < DACommitteeSubnetCount; i++ {
		m.subnets[i] = &DASubnet{
			ID:      i,
			columns: make([]int, 0),
		}
	}
	return m
}

func (m *DASubnetManager) AssignColumns(subnetID int, blobCount int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if subnetID < 0 || subnetID >= DACommitteeSubnetCount {
		return
	}

	subnet := m.subnets[subnetID]
	subnet.mu.Lock()
	defer subnet.mu.Unlock()

	subnet.columns = subnet.columns[:0]

	colsPerSubnet := (blobCount * 2) / DACommitteeSubnetCount
	if colsPerSubnet < 1 {
		colsPerSubnet = 1
	}

	startCol := subnetID * colsPerSubnet
	for col := startCol; col < startCol+colsPerSubnet && col < blobCount*2; col++ {
		subnet.columns = append(subnet.columns, col)
	}
}

func (m *DASubnetManager) GetSubnetColumns(subnetID int) []int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if subnetID < 0 || subnetID >= DACommitteeSubnetCount {
		return nil
	}

	subnet := m.subnets[subnetID]
	subnet.mu.RLock()
	defer subnet.mu.RUnlock()

	cols := make([]int, len(subnet.columns))
	copy(cols, subnet.columns)
	return cols
}

func (m *DASubnetManager) SampleSubnet(subnetID int, slot uint64, blobCount int) ([]encoding.DASSampleResponse, error) {
	columns := m.GetSubnetColumns(subnetID)
	if len(columns) == 0 {
		return nil, fmt.Errorf("no columns assigned to subnet %d", subnetID)
	}

	samplesPerColumn := 4
	totalSamples := len(columns) * samplesPerColumn

	responses := make([]encoding.DASSampleResponse, 0, totalSamples)

	for _, col := range columns {
		for s := 0; s < samplesPerColumn; s++ {
			blobIndex := col / 2
			// DA- (2026-07-17): Skip out-of-range samples instead of
			// clamping to blobCount-1. The previous clamp folded all
			// out-of-range columns onto the last blob, causing severe
			// over-sampling of blobCount-1 and zero coverage of the intended
			// blob when subnet column assignment drifted from blobCount
			// (e.g., blobCount shrank after assignment, or AssignColumns
			// was called with a stale blobCount). Skipping preserves the
			// uniform distribution over valid (blobIndex, col) pairs and
			// avoids the statistical bias that undermined DAS availability
			// detection. The DAS availability decision is then based on the
			// samples that did land on valid cells.
			if blobIndex >= blobCount {
				continue
			}
			// Defensive: blobCount <= 0 would make blobIndex (col/2) trivially
			// >= blobCount and be skipped above, but guard explicitly to avoid
			// passing a negative blobIndex to GetCell if blobCount is 0 and
			// the branch above is ever reordered.
			if blobIndex < 0 {
				continue
			}

			row := randomInt(encoding.CellsPerBlobExtended)

			cell, _, err := m.blobStorage.GetCell(slot, blobIndex, row, col)
			if err != nil {
				continue
			}

			responses = append(responses, encoding.DASSampleResponse{
				Slot:      slot,
				BlobIndex: blobIndex,
				CellRow:   row,
				CellCol:   col,
				Cell:      *cell,
			})
		}
	}

	return responses, nil
}

func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// audit-fix LOW: use project logger instead of fmt.Printf for consistent logging
		daCommitteeLogger.Errorf("crypto/rand.Read failed in randomInt: %v", err)
		return 0
	}
	return int(binary.BigEndian.Uint64(b) % uint64(max))
}
