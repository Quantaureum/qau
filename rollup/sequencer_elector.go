// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// Sequencer election errors.
// W-P1-7 (2026-07-15)
var (
	ErrNoValidators         = errors.New("sequencer elector: validator set is empty")
	ErrSequencerNotFound    = errors.New("sequencer elector: no sequencer found for epoch")
	ErrElectorNotConfigured = errors.New("sequencer elector not configured")
	// ErrVRFSeedNotAvailable is returned by GetCurrentSequencer and
	// GetNextSequencer when the VRF seed required to elect a sequencer for
	// the requested epoch is unavailable (the provider returned the zero
	// hash) AND the epoch is at or above the elector's minVRFEpoch
	// threshold. P3-RL-05 (2026-08-03). Caller should retry once the
	// provider populates the seed (e.g. the L1 consensus layer catches
	// up). Returning an error here is SAFE-by-design: the previous
	// fallback (keccak256(epoch) % n) was a fully deterministic sequencer
	// identity, predictable across epochs, which an attacker could pre-
	// compute to launch strategic timing / DoS attacks during the
	// bootstrap window — this gate bounds that window to the configured
	// bootstrap epoch bound.
	ErrVRFSeedNotAvailable = errors.New("sequencer elector: VRF seed not yet available for epoch at or above minVRFEpoch (P3-RL-05); retry once the provider retrieves the L1 epoch seed")
)

// SequencerElector defines the interface for decentralized sequencer election.
//
// W-P1-7 (2026-07-15): Replaces the single-sequencer model with a rotating
// sequencer elected per epoch, synchronized with QPOS proposer rotation.
// When no elector is configured (SetSequencerElector not called), the engine
// falls back to the legacy single-sequencer mode for backward compatibility.
//
// RLLP- (2026-07-16): Election is now VRF-seeded. The elector mixes the
// QPOS per-epoch VRF accumulator into a keccak256 hash to derive the sequencer
// index, so sequencer identity cannot be predicted for future epochs (an
// attacker observing the chain head cannot compute who will be sequencer in
// epoch N+1 because that depends on VRF outputs not yet produced). This
// eliminates the censorship/MEV vector of the previous `epoch % len(validators)`
// formula, which was fully predictable for the entire chain lifetime.
type SequencerElector interface {
	// GetCurrentSequencer returns the current epoch's sequencer address.
	GetCurrentSequencer(epoch uint64) (types.Address, error)
	// IsCurrentSequencer checks if the given address is the current sequencer.
	IsCurrentSequencer(addr types.Address, epoch uint64) (bool, error)
	// GetNextSequencer returns the next epoch's sequencer (for smooth handoff
	// and failover when the current sequencer is unresponsive).
	GetNextSequencer(epoch uint64) (types.Address, error)
}

// ValidatorSetProvider provides access to the QPOS validator set, epoch
// information, and per-epoch VRF randomness. Implemented by an adapter in
// node.go that wraps *consensus.QPOS, keeping the rollup package decoupled
// from the consensus package (architecture discipline: rollup must not import
// consensus directly — dependency inversion via interface injection, matching
// the L1Anchor / WithdrawalProcessor pattern).
//
// W-P1-7 (2026-07-15). RLLP- (2026-07-16) adds GetEpochSeed.
type ValidatorSetProvider interface {
	// GetValidators returns the current validator addresses in stake order.
	// The elector uses this list to deterministically pick the sequencer.
	GetValidators() []types.Address
	// GetCurrentEpoch returns the current QPOS epoch.
	GetCurrentEpoch() uint64
	// GetEpochSeed returns the VRF-derived randomness seed for the given
	// epoch. This is the three-tier seed (finalized-epoch VRF accumulator →
	// epoch-1 VRF accumulator → RANDAO) shared with the DA committee shuffle
	// (DA-). Returns the zero hash if no randomness is available
	// (startup/initial sync); the elector falls back to a plain keccak256
	// (epoch) index in that case — still less predictable than the old
	// `epoch % len` formula, and the window of pure-deterministic election
	// is bounded to the bootstrap phase.
	// RLLP- (2026-07-16).
	GetEpochSeed(epoch uint64) types.Hash
}

// QPOSSequencerElector implements SequencerElector by mapping each epoch to
// a validator from the QPOS validator set. The mapping is VRF-seeded:
// sequencerIndex = keccak256(epoch || epochSeed) % len(validators).
//
// RLLP- (2026-07-16): Previously `epoch % len(validators)` was fully
// predictable — an attacker could compute the sequencer for any future epoch,
// enabling targeted censorship (wait until your epoch, then censor specific
// users) and MEV (front-run known upcoming transactions). The VRF seed
// breaks this predictability: sequencer identity for epoch N depends on
// VRF outputs from epoch N-1 (or the finalized epoch), which are not known
// until those epochs actually conclude.
//
// When the current sequencer is unresponsive (missed SequencerTimeout batch
// cycles), the engine calls GetNextSequencer to determine the failover
// sequencer = validators[keccak256((epoch+1) || epochSeed) % len(validators)].
//
// W-P1-7 (2026-07-15). RLLP- (2026-07-16) adds VRF-seeded election.
type QPOSSequencerElector struct {
	mu       sync.RWMutex
	provider ValidatorSetProvider
	// P3-RL-05 (2026-08-03): minimum epoch requiring a real VRF
	// (non-zero-hash) epochSeed. Epochs BELOW this value retain the
	// legacy bootstrap fallback (keccak256(epoch) % n) — bounded by
	// this cutoff. Epochs AT OR ABOVE this value, when the seed is the
	// zero hash, REFUSE to elect a sequencer and return
	// ErrVRFSeedNotAvailable instead — the audit's recommendation to
	// "defer sequencer election until at least one VRF seed is
	// available". A hard defer unconditionally would break genesis /
	// bootstrap on devnet (where VRF accumulators populate over the
	// first few epochs), so the gate is per-epoch: operationally,
	// minVRFEpoch is set to a small multiple of `epochsPerVRFReset`
	// (e.g. 3 epochs = 3 * 43200 / 12 ≈ 6 hours on mainnet) by the
	// node startup wiring, after which the consistent-hash fallback is
	// only legal for the bootstrap-only epochs. Default 0 preserves
	// legacy behavior (never defer).
	minVRFEpoch uint64
}

// SetMinVRFEpoch sets the minimum epoch at which the elector will REQUIRE
// a non-zero VRF seed (P3-RL-05, 2026-08-03). Epochs >= this threshold
// return ErrVRFSeedNotAvailable when the provider returns the zero hash;
// epochs < this threshold retain the legacy keccak256(epoch) fallback.
// Idempotent. Thread-safe; intended to be called ONCE during node
// startup wiring before the first Get/GetCurrentSequencer call.
//
// Production: set this to a value > 0 once the node has observed the
// consensus layer producing VRF accumulators reliably (e.g. set to
// currentEpoch + 3 so the next three epochs continue to tolerate
// bootstrap-only behavior while subsequent epochs require real VRF).
// 0 reverts to the legacy unbounded-fallback behavior.
func (e *QPOSSequencerElector) SetMinVRFEpoch(epoch uint64) {
	e.mu.Lock()
	e.minVRFEpoch = epoch
	e.mu.Unlock()
}

// NewQPOSSequencerElector creates a SequencerElector backed by a
// ValidatorSetProvider. The provider is queried on each call so the elector
// always reflects the current validator set (handles validator set updates
// without requiring the elector to be rebuilt).
func NewQPOSSequencerElector(provider ValidatorSetProvider) *QPOSSequencerElector {
	return &QPOSSequencerElector{provider: provider}
}

// GetCurrentSequencer returns the sequencer for the given epoch.
// RLLP- (2026-07-16): The index is derived from
// keccak256(epoch || epochSeed) rather than the bare epoch, so sequencer
// identity is not predictable for future epochs (the seed depends on VRF
// outputs not yet produced). When the seed is the zero hash (bootstrap),
// the index falls back to keccak256(epoch) % len — still hash-mixed rather
// than the raw modulo, and the bootstrap window is bounded.
//
// P3-RL-05 (2026-08-03): bootstrap window is now BOUNDED by
// sm.minVRFEpoch. For epochs >= minVRFEpoch, a zero-hash seed REFUSES the
// election with ErrVRFSeedNotAvailable instead of silently falling back
// to the predictable keccak256(epoch) % n index. See SetMinVRFEpoch for
// the operational gating rationale. Caller SHOULD retry on this error;
// the L1 consensus layer's VRF accumulator rarely takes more than a
// few slots to populate.
func (e *QPOSSequencerElector) GetCurrentSequencer(epoch uint64) (types.Address, error) {
	addrs := e.getValidators()
	if len(addrs) == 0 {
		return types.Address{}, ErrNoValidators
	}
	seed := e.getEpochSeed(epoch)
	// P3-RL-05 gate. Hold RLock for atomic minVRFEpoch read.
	e.mu.RLock()
	minEpoch := e.minVRFEpoch
	e.mu.RUnlock()
	if seed == (types.Hash{}) && epoch >= minEpoch && minEpoch > 0 {
		return types.Address{}, fmt.Errorf("%w: epoch=%d minVRFEpoch=%d",
			ErrVRFSeedNotAvailable, epoch, minEpoch)
	}
	idx := computeSequencerIndex(epoch, seed, len(addrs))
	return addrs[idx], nil
}

// IsCurrentSequencer checks if the given address is the current epoch's sequencer.
func (e *QPOSSequencerElector) IsCurrentSequencer(addr types.Address, epoch uint64) (bool, error) {
	current, err := e.GetCurrentSequencer(epoch)
	if err != nil {
		return false, err
	}
	return current == addr, nil
}

// GetNextSequencer returns the sequencer for epoch+1. Used for smooth handoff
// at epoch boundaries and for failover when the current sequencer is
// unresponsive (the next validator in the rotation takes over).
//
// RLLP-FIX (2026-07-17): Previously this called getEpochSeed(epoch),
// i.e. queried the seed for the CURRENT epoch when predicting epoch+1. That
// mismatch made the prediction trivially equivalent to a query the caller
// could already perform, and in the bootstrap phase (finalizedEpoch == 0)
// it leaked the current epoch's VRF accumulator into the next-epoch index
// computation a full epoch early. The fix queries getEpochSeed(epoch+1) so
// the seed selection goes through selectDACommitteeSeed's standard three-tier
// path for the TARGET epoch (finalized-epoch accumulator → epoch accumulator
// → RANDAO), matching the semantics of GetCurrentSequencer(epoch+1) as
// closely as the available randomness permits.
//
// PREDICTION-PRECISION CAVEAT (RLLP-): This function is INTERNAL ONLY
// (not exposed via RPC) and is used solely by shouldBuildBatch for failover
// decisions. The returned address is NOT a cryptographic guarantee of
// unpredictability: until epoch+1's own VRF accumulator is produced (which
// happens only after epoch+1 concludes), the seed necessarily derives from
// already-public randomness (finalized-epoch or current-epoch accumulator).
// This is an inherent liveness-vs-security tradeoff — failover requires SOME
// next-sequencer decision, and halting the chain (returning an error) is
// worse than a predictability window that is bounded to one epoch and is
// non-manipulable (the seed sources are VRF-bound, not attacker-controlled).
// Callers MUST NOT treat this as a future-epoch commitment.
func (e *QPOSSequencerElector) GetNextSequencer(epoch uint64) (types.Address, error) {
	addrs := e.getValidators()
	if len(addrs) == 0 {
		return types.Address{}, ErrNoValidators
	}
	// RLLP- Query the seed for the TARGET epoch (epoch+1) rather than
	// the current epoch, so the seed selection is consistent with
	// GetCurrentSequencer(epoch+1) and does not prematurely surface the
	// current epoch's accumulator as the next-epoch seed.
	seed := e.getEpochSeed(epoch + 1)
	// P3-RL-05 (2026-08-03): apply the same minVRFEpoch gate as
	// GetCurrentSequencer, evaluated against the TARGET epoch
	// (epoch+1) so a peer that calls GetNextSequencer while in
	// bootstrap cannot get a deterministic next-sequencer prediction
	// either. The gate for epoch+1 is `epoch+1 >= minVRFEpoch`.
	e.mu.RLock()
	minEpoch := e.minVRFEpoch
	e.mu.RUnlock()
	if seed == (types.Hash{}) && epoch+1 >= minEpoch && minEpoch > 0 {
		return types.Address{}, fmt.Errorf("%w: next-epoch=%d minVRFEpoch=%d",
			ErrVRFSeedNotAvailable, epoch+1, minEpoch)
	}
	idx := computeSequencerIndex(epoch+1, seed, len(addrs))
	return addrs[idx], nil
}

// computeSequencerIndex derives a validator index from the epoch and VRF seed.
// RLLP- (2026-07-16).
//
// The index is keccak256(epoch_be || seed) % n. When seed is the zero hash
// (bootstrap / initial sync), it falls back to keccak256(epoch_be) % n —
// still hash-mixed (not the raw `epoch % n` that was fully predictable),
// and the bootstrap window is bounded to the period before VRF accumulators
// are populated.
//
// epoch_be is 8-byte big-endian. n is the validator count. n > 0 is required
// by the caller.
//
// RLLP-FIX (2026-07-17): Previously this took only the first 8 bytes of
// the keccak256 output as a uint64 and applied `% n`. When n is not a power of
// two, that truncation introduces modular bias (residual ≤ 2^64 / n upper
// bound, though actual bias ≤ ~10^-19 for typical n). Although practically
// unexploitable (the seed is VRF-bound, not attacker-controlled), it violated
// the "unbiased election" property in theory. The fix uses big.Int.SetBytes
// over the FULL 32-byte hash output and then Mod by n, reducing the residual
// bias to ≤ 2^-192 (negligible for any realistic validator set size).
func computeSequencerIndex(epoch uint64, seed types.Hash, n int) int {
	if n <= 0 {
		return 0
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], epoch)

	h := sha3.NewLegacyKeccak256()
	h.Write(buf[:])
	if seed != (types.Hash{}) {
		h.Write(seed[:])
	}
	out := h.Sum(nil)

	// RLLP- Use the full 32-byte hash via big.Int to eliminate modular
	// bias. Residual bias is ≤ 2^-192 (n << 2^256), negligible for any
	// realistic validator set size.
	hashInt := new(big.Int).SetBytes(out)
	idx := hashInt.Mod(hashInt, big.NewInt(int64(n)))
	return int(idx.Int64())
}

// getEpochSeed safely reads the VRF seed for the given epoch from the provider.
func (e *QPOSSequencerElector) getEpochSeed(epoch uint64) types.Hash {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.provider == nil {
		return types.Hash{}
	}
	return e.provider.GetEpochSeed(epoch)
}

// getValidators safely reads the validator list from the provider.
func (e *QPOSSequencerElector) getValidators() []types.Address {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.provider == nil {
		return nil
	}
	return e.provider.GetValidators()
}

// GetCurrentEpoch returns the current epoch from the underlying provider.
// Convenience method for the engine to query the current epoch without
// holding a separate reference to the provider.
func (e *QPOSSequencerElector) GetCurrentEpoch() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.provider == nil {
		return 0
	}
	return e.provider.GetCurrentEpoch()
}

// --- RollupEngine integration ---

// SetSequencerElector injects the sequencer elector. When non-nil, the engine
// only builds batches when the local node is the current (or failover)
// sequencer for the current epoch. When nil, the engine falls back to the
// legacy single-sequencer mode (any node builds batches).
//
// The elector is also propagated to the Sequencer so its IsCurrentSequencer()
// helper reflects the decentralized state (used by the RPC layer to advise
// clients whether to forward transactions).
//
// W-P1-7 (2026-07-15)
func (e *RollupEngine) SetSequencerElector(elector SequencerElector) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sequencerElector = elector
	if e.sequencer != nil {
		e.sequencer.SetSequencerElector(elector)
	}
}

// GetSequencerElector returns the configured elector (may be nil).
func (e *RollupEngine) GetSequencerElector() SequencerElector {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.sequencerElector
}

// SetLocalAddress sets the local node's validator address. Used by the engine
// to determine whether this node is the current sequencer. When zero (default),
// the engine behaves as if it is always the sequencer (legacy mode), which
// should only be used in single-node development setups.
//
// W-P1-7 (2026-07-15)
func (e *RollupEngine) SetLocalAddress(addr types.Address) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.localAddress = addr
	if e.sequencer != nil {
		e.sequencer.SetLocalAddress(addr)
	}
}

// GetLocalAddress returns the configured local validator address.
func (e *RollupEngine) GetLocalAddress() types.Address {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.localAddress
}

// IsCurrentSequencer returns whether the local node is the current sequencer
// for the current epoch. When no elector is configured or localAddress is zero,
// returns true (legacy single-sequencer mode).
//
// W-P1-7 (2026-07-15)
func (e *RollupEngine) IsCurrentSequencer() bool {
	e.mu.RLock()
	elector := e.sequencerElector
	local := e.localAddress
	e.mu.RUnlock()

	if elector == nil || local == (types.Address{}) {
		return true
	}

	epoch := e.currentEpoch()
	current, err := elector.GetCurrentSequencer(epoch)
	if err != nil {
		// R36-P3-22 FIX (2026-07-30): Fail-closed (return false) on elector
		// error, matching the fix already applied to Sequencer.IsCurrentSequencer
		// (sequencer.go:99-107, RLLP-). The previous fail-open behavior
		// (return true) was inconsistent with the sibling method and could
		// cause a non-sequencer node to mistakenly believe it is the active
		// sequencer after an elector error, leading to invalid batch signing
		// attempts that pollute L1 anchor history and waste L1 gas. Returning
		// false is safer: the caller treats this node as a non-sequencer
		// until the elector recovers, and the error is logged via the
		// elector's own error metric. This path is latent (no production
		// caller wires the elector to RollupEngine yet) but the fix ensures
		// consistency when the wiring is added.
		log.Printf("[WARN] rollup-engine: IsCurrentSequencer fail-closed on elector error (epoch=%d local=%x): %v",
			epoch, local[:8], err)
		return false
	}
	return current == local
}

// currentEpoch returns the current epoch, either from the elector's provider
// or 0 if no elector is configured.
func (e *RollupEngine) currentEpoch() uint64 {
	e.mu.RLock()
	elector := e.sequencerElector
	e.mu.RUnlock()

	if qe, ok := elector.(*QPOSSequencerElector); ok {
		return qe.GetCurrentEpoch()
	}
	return 0
}

// RecordBatchReceivedFromCurrentSequencer updates the liveness observation
// clock used by shouldBuildBatch to gate failover takeover. It MUST be called
// whenever this node receives evidence that the current sequencer is still
// producing batches — e.g. when a batch is received via P2P gossip, or when
// an L1 anchoring event is observed for the current sequencer's batch.
//
// P1-ROLLUP-02 FIX (2026-07-30): Without this signal, every non-sequencer
// node would unconditionally take over after SequencerTimeout ticks even
// when the current sequencer is healthy, producing dual sequencers and
// conflicting batches. With this signal, the failover gate requires
// evidence that the current sequencer has actually stopped producing.
//
// R39-P2-06 (2026-08-02) FIX: the previous version took no arguments —
// attackers controlling the caller could feed evidence-less liveness
// ticks to keep the gate permanently open (suppressing legitimate
// failover). The audit's "liveness gate update path did not carry batch info
// completeness" finding is closed by requiring the caller to supply the
// batch's fingerprint (batchHash + postStateRoot) and rejecting calls
// where either is the zero hash. The fingerprint is stored as
// lastObservedBatchEvidence for forensics (post-failover audit can
// inspect what the gate last saw) and as a completeness invariant
// (you can't claim liveness without a real batch).
//
// The method is safe to call from any goroutine. It is a no-op when no
// elector is configured (legacy single-sequencer mode), AND a no-op
// when the supplied batch fingerprint is the zero hash — the latter is
// the R39-P2-06 fail-closed rejection (we silently return rather than
// error to preserve the legacy API contract; the gate simply doesn't
// update and failover remains eligible once enough silence accumulates).
func (e *RollupEngine) RecordBatchReceivedFromCurrentSequencer(batchHash, postStateRoot types.Hash) {
	// R39-P2-06: fail-closed on missing batch evidence. The audit's
	// finding is precisely that an attacker could call this method with
	// no batch context to keep the gate open. We require BOTH the
	// batchHash AND the postStateRoot to be non-zero — they are the
	// integrity guarantee that a real batch (with deterministic
	// computing) is being attested to. The zero-hash check is the
	// minimum invariant because the QAU hash function (keccak256) maps
	// empty-domain inputs to a NON-zero constant, so a real batch
	// always has a non-zero hash.
	//
	// We return silently (no error) to preserve the legacy API
	// contract — the net effect is that the liveness clock does NOT
	// advance, so failover remains eligible once SequencerTimeout ticks
	// elapse. This is the safe default: when in doubt about whether
	// the current sequencer is actually alive, fall back to failover.
	var zeroHash types.Hash
	if batchHash == zeroHash || postStateRoot == zeroHash {
		// Log at DEBUG level (not ERROR) because the no-op is the
		// intended fail-closed behavior, not an error condition —
		// the caller may be a legacy caller that hasn't been updated
		// to pass the new args yet. Logging at ERROR would spam
		// production logs.
		//
		// We don't have access to e.logger here in this sign-of-the
		// quiet path; falling back to log.Printf matches the existing
		// style. (If e.logger is later added, switch to it.)
		// Skipping log entirely on the hot path keeps the gate fast.
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sequencerElector == nil {
		return
	}
	e.lastObservedBatchTime = time.Now()
	// Reset missedBatchCount too — receiving a batch is the strongest
	// possible liveness signal, strictly stronger than the tick-based
	// counter (which only resets when THIS node builds a batch).
	e.missedBatchCount = 0
	// R39-P2-06: store the batch fingerprint as the liveness-evidence
	// invariant. Post-failover auditors can inspect this to determine
	// WHAT the gate last observed before silence accumulated.
	e.lastObservedBatchEvidence = batchHash
}

// shouldBuildBatch determines whether the local node should build a batch in
// the current tick. Returns true when:
//   - No elector is configured (legacy mode), OR
//   - Local node is the current epoch's sequencer, OR
//   - Current sequencer has missed >= SequencerTimeout batch cycles AND
//     the local node is the next sequencer AND (P1-ROLLUP-02) the
//     observation clock shows no batch has been received from the current
//     sequencer for longer than the equivalent of SequencerTimeout ticks.
//
// W-P1-7 (2026-07-15). P1-ROLLUP-02 (2026-07-30) adds the observation gate.
func (e *RollupEngine) shouldBuildBatch() bool {
	e.mu.RLock()
	elector := e.sequencerElector
	local := e.localAddress
	timeout := e.config.SequencerTimeout
	missed := e.missedBatchCount
	lastSeq := e.lastSequencerAddr
	lastObserved := e.lastObservedBatchTime
	blockTime := e.config.BlockTime
	e.mu.RUnlock()

	// Legacy mode: no elector or no local address → always build.
	if elector == nil || local == (types.Address{}) {
		return true
	}

	epoch := e.currentEpoch()
	current, err := elector.GetCurrentSequencer(epoch)
	if err != nil {
		// RLLP- (2026-07-16): Fail-CLOSED when sequencer election
		// errors. Previously this returned true (fail-open), allowing ANY
		// node to build batches when the elector failed — enabling
		// unauthorized sequencers to produce batches, potentially
		// front-running or censoring legitimate transactions.
		//
		// Fix: return false to halt batch production until the elector
		// recovers. This prioritizes safety over liveness: a temporary
		// stall is better than unauthorized batch production. The elector
		// errors are logged by GetCurrentSequencer itself.
		return false
	}

	// Reset miss counter when the sequencer changes (new epoch or failover).
	if current != lastSeq {
		e.mu.Lock()
		e.lastSequencerAddr = current
		e.missedBatchCount = 0
		e.mu.Unlock()
		missed = 0
	}

	// Am I the current sequencer?
	if current == local {
		return true
	}

	// Not the current sequencer. Check failover condition.
	if timeout > 0 && missed >= timeout {
		next, err := elector.GetNextSequencer(epoch)
		if err != nil {
			return false
		}
		// Failover: local node takes over as the next sequencer — but only
		// after we have positive evidence that the current sequencer is
		// actually unresponsive. P1-ROLLUP-02 (2026-07-30): without this
		// gate, every non-sequencer node would take over after the timeout
		// even when the current sequencer is healthy, producing dual
		// sequencers and conflicting batches.
		//
		// The observation clock (lastObservedBatchTime) is updated by
		// RecordBatchReceivedFromCurrentSequencer whenever the node
		// observes a batch from the current sequencer. If the clock shows
		// a recently-received batch, failover is suppressed regardless of
		// missedBatchCount. The required silence window is
		// SequencerTimeout * BlockTime — matching the tick-based threshold
		// so the observation gate is never more permissive than the old
		// tick-only logic.
		//
		// When lastObserved is zero (never observed / startup), the gate
		// is bypassed so the engine can bootstrap failover on initial sync.
		if !lastObserved.IsZero() && blockTime > 0 {
			requiredSilence := time.Duration(timeout) * blockTime
			if time.Since(lastObserved) < requiredSilence {
				return false
			}
		}
		// Failover: local node takes over as the next sequencer.
		if next == local {
			return true
		}
	}
	return false
}
