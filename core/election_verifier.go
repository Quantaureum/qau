// Quantaureum Node source, version 1.0.0.
package core

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/types"
)

// ErrProposerScheduleNotReady is returned by VerifyProposer when QPOS
// reports the per-epoch shuffle was computed under the cold-start
// fallback (VRF accumulator for epoch-2 still empty). The caller in
// core/block_validator.go treats this as "trust canonical-chain
// ProposerAddr, do not fail the block" — see R45-PoA-FIX.
var ErrProposerScheduleNotReady = errors.New("proposer schedule not ready: VRF accumulator for epoch-2 not yet populated (cold-start)")

// QPOSElectionVerifier is a production-grade implementation of
// ProposerElectionVerifier that delegates proposer verification to the QPOS
// consensus engine.
//
// audit fix (H-7) [CRITICAL]: ValidateBlock requires an election
// verifier to confirm that each block's proposer was legitimately elected via
// QPOS. This implementation wraps *consensus.QPOS and uses
// GetProposerForSlot(slot) to determine the expected proposer, then compares
// it against the block's ProposerAddr.
//
// Usage: During node initialization, create a QPOSElectionVerifier with the
// node's QPOS instance and register it via BlockValidator.SetElectionVerifier.
//
//	bv := core.NewBlockValidator(chainID, maxGasLimit)
//	bv.SetElectionVerifier(core.NewQPOSElectionVerifier(qpos))
//
// Thread safety: QPOSElectionVerifier is safe for concurrent use because it
// only reads from *consensus.QPOS, whose methods (GetProposerForSlot) are
// thread-safe. R61's reject-counter state is guarded by the embedded mu lock.
type QPOSElectionVerifier struct {
	qpos *consensus.QPOS
	// R58-ELEC-TRUST (2026-08-18): when true, VerifyProposer never
	// independently derives the proposer schedule — it always returns
	// ErrProposerScheduleNotReady so the caller trusts the canonical-chain
	// ProposerAddr. This is geth's post-merge model: a non-producing node
	// (RPC/wallet gateway, verify-only observer) does NOT re-derive the
	// beacon proposer, it simply follows the canonical chain. Its local VRF
	// accumulator can legitimately diverge (R45-SYNC-TRUST-FIX), and
	// forcing strict verification would stall block import forever. Only
	// active sealers (nodes that produce blocks) keep strict independent
	// verification — they are the ones whose identity is pinned by stake.
	// node.go sets this for non-sealer nodes; QAU_TRUST_CANONICAL_PROPOSER
	// env remains as a manual override for sealer hosts that opt in.
	trustCanonical bool

	// R61-ELEC-DIVERGE-HEAL (2026-08-18): persistent-reject heal path.
	// A sealer node keeps strict proposer verification (R58-ELEC-TRUST sets
	// trustCanonical=false for sealers). If its LOCAL per-epoch VRF
	// accumulator diverges from the canonical chain — e.g. because the R52
	// / R58-VRF-PERSIST replay either was skipped or loaded a stale
	// persisted checkpoint that no longer matches the canonical value —
	// VerifyProposer will return a "proposer mismatch" error for EVERY
	// canonical block at that epoch, indefinitely. Because the rejection
	// happens in ValidateBlock BEFORE ProcessBlock writes the block, the
	// SetEpochVRFAccumulator call that would repair the local accumulator
	// NEVER RUNS — the sealer is permanently deadlocked at the old chain
	// tip ("proposer mismatch: expected X, got Y" forever).
	//
	// A stale local accumulator can disagree with the canonical value while
	// peers continue to accept canonical blocks. The canonical signature still
	// identifies the proposer, so persistent rejection of the same slot and
	// epoch is evidence that only the local accumulator is polluted.
	//
	// R61 heal: count REJECTIONS for the SAME canonical block; once the
	// same (slot, epoch) is rejected more than `healThreshold` times we
	// treat the local accumulator as polluted and return
	// ErrProposerScheduleNotReady so the caller (block_validator.go
	// ValidateBlock, non-sync path) trusts the canonical ProposerAddr and
	// lets ProcessBlock proceed — its subsequent SetEpochVRFAccumulator
	// overwrites the polluted per-epoch entry with the authoritative
	// on-chain value, repairing the sealer in place. The reject counting
	// keys on (slot, epoch) — not (height, slot, epoch) — because the same
	// stale acc[epoch-2] would poison every block in epoch, and we only
	// want to fire the heal once per polluted epoch. A counter refreshes
	// whenever a different (slot, epoch) is seen (forward progress).
	//
	// Safety: this is the post-merge EL view — ValidateBlock has already
	// verified the ProposerAddr's signature over the block hash (see
	// verifyBlockSignature), so "trust canonical ProposerAddr" only means
	// "accept that the signed block producer is who the signature claims",
	// not "accept any block". The awaited heal is read-only consensus
	// state; no state rollback, no fork choice change, just letting the
	// sealer keep importing canonical blocks while its accumulator
	// catches up. A malicious sealer that forged a block + signature would
	// be detected by other sealers (which keep strict verification); at
	// worst, the divergent sealer accepts ONE block that honest peers
	// already accepted. Then SetEpochVRFAccumulator realigns it to the
	// canonical schedule.
	mu            sync.Mutex
	rejectSlot    uint64
	rejectEpoch   uint64
	rejectCount   int
	healedEpochs  map[uint64]bool
	healThreshold int
}

// SetHealThreshold overrides the default persistent-reject threshold.
// 0 keeps the default (defaultHealThreshold). For tests this lets the heal
// fire deterministically without waiting for 8 rejections. Negative or zero
// reset leaves the default in place.
const defaultHealThreshold = 8

// NewQPOSElectionVerifier creates a production-grade election verifier backed
// by the given QPOS consensus engine. The qpos must be non-nil and have a
// configured validator set; otherwise VerifyProposer returns an error for
// every call (fail-closed).
func NewQPOSElectionVerifier(qpos *consensus.QPOS) *QPOSElectionVerifier {
	return &QPOSElectionVerifier{
		qpos:          qpos,
		healedEpochs:  make(map[uint64]bool),
		healThreshold: defaultHealThreshold,
	}
}

// SetHealThreshold overrides the R61 persistent-reject heal threshold. Zero
// or negative values restore the default (defaultHealThreshold). For tests,
// a value of 1 makes the heal fire on the first reject so the operator can
// deterministically exercise the canonical-trust path without waiting for
// defaultHealThreshold rejections in the wild.
func (v *QPOSElectionVerifier) SetHealThreshold(n int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if n <= 0 {
		v.healThreshold = defaultHealThreshold
	} else {
		v.healThreshold = n
	}
}

// SetTrustCanonicalProposer configures whether this verifier skips
// independent proposer derivation and trusts the canonical-chain ProposerAddr
// (R58-ELEC-TRUST). Intended for non-producing nodes; see field comment.
func (v *QPOSElectionVerifier) SetTrustCanonicalProposer(b bool) {
	v.trustCanonical = b
}

// IsEpochHealed reports whether the R61 persistent-reject heal has fired for
// the given epoch — meaning this node's local VRF accumulator/shuffle for that
// epoch was diagnosed as diverged from the canonical chain and the verifier
// now trusts the canonical ProposerAddr for it.
//
// R88-E (2026-08-30): consumed by node.BlockProducer.isProposerForSlot to
// STAND DOWN from proposing for the healed epoch: the same polluted
// accumulator that made the validator-side verification reject canonical
// blocks would make the producer-side schedule elect a proposer that exists
// nowhere in the canonical chain — every block produced from it is fork
// garbage that deepens the divergence. Standing down costs at most the rest of
// one epoch of liveness for this node; its peers keep the chain live, and
// the producer resumes on the next epoch (whose accumulator is repaired by
// then via the SetEpochVRFAccumulator that follows the healed import).
func (v *QPOSElectionVerifier) IsEpochHealed(epoch uint64) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.healedEpochs != nil && v.healedEpochs[epoch]
}

// VerifyProposer checks that proposer is the legitimate elected proposer for
// the given slot and epoch by querying the QPOS consensus engine.
//
// Returns nil if the proposer matches the QPOS-elected proposer for the slot.
// Returns an error if:
//   - qpos is nil (verifier not configured)
//   - QPOS returns an error (no validator set, internal error)
//   - The elected proposer's address does not match `proposer`
func (v *QPOSElectionVerifier) VerifyProposer(proposer types.Address, slot, epoch uint64) error {
	if v.qpos == nil {
		return fmt.Errorf("QPOSElectionVerifier: qpos engine not configured")
	}

	// R45-PoA-FIX (2026-08-12): Surface cold-start via a sentinel error
	// instead of silently comparing against a poison shuffle. The caller
	// (core/block_validator.go ValidateBlock) inspects the sentinel and
	// treats it as "schedule unverified due to local cold-start; trust the
	// canonical-chain ProposerAddr and let sync/VRF-accumulator replay
	// catch up" rather than failing the block as invalid. Without this,
	// a restarting sealer that has not yet replayed the canonical chain
	// far enough to repopulate epochVRFAccumulator[epoch-2] would
	// compute a wrong proposer (keccak(epoch) seed instead of
	// keccak(epoch||acc[epoch-2])) and reject every canonical block at
	// heights >= the cold-start epoch — permanently deadlocking the
	// sealer at the old fork tip ("proposer mismatch: expected X, got Y").
	//
	// R45-ACC-LOOKUP-FIX (2026-08-12): The original version gate-checked
	// `IsProposerScheduleReadyForSlot(slot)` (cold-start flag map). That
	// flag is only set INSIDE GetProposerForSlot the FIRST time it sees
	// acc[srcEpoch]==zero. So the gate would PASS on the first rejecting
	// call (flag still empty) → VerifyProposer computed a wrong expected
	// proposer from a partial seed → block was rejected as "expected X got
	// Y" (NOT as ErrProposerScheduleNotReady) → ValidateBlock went down
	// the wrong branch and failed the block. A node with a partially rebuilt
	// accumulator can therefore reject every canonical block for an epoch that
	// its rebuild has not reached yet.
	//
	// FIX: check the accumulator directly. Return
	// ErrProposerScheduleNotReady when acc[epoch-2] is missing, NOT
	// when IsProposerScheduleReadyForSlot says cold. The cold-start flag
	// on the qpos struct is a SEPARATE safety knob (mainly for
	// IsProposerScheduleReadyForSlot consumers in BlockProducer);
	// VerifyProposer must use the ground truth (acc availability).
	//
	// This is also correct for the sealer side: when the sealer has a
	// real accumulator (from R52 rebuild or SetEpochVRFAccumulator),
	// VerifyProposer proceeds to compare elected vs canonical and either
	// accepts (match) or rejects (NON cold-start mismatch = real fork,
	// real consensus violation).
	//
	// R45-SYNC-TRUST-FIX (2026-08-13): The above "either accept match OR
	// reject mismatch" assumption is unsafe for a non-sealer peer
	// node that received its entire chain from remote sync (all blocks
	// signed by remote sealers). Such a node's R52 rebuild populates
	// epochVRFAccumulator from block.Header.VRFAccumulator values that
	// were set by the REMOTE sealer at compute time. If two peer nodes
	// diverge before reaching canonical (e.g. the WARMUP-EXPAND-FIX
	// period where multiple sealers produced parallel fork blocks at
	// the same epoch with DIFFERENT VRF outputs), each node's R52
	// rebuild loads its OWN accumulator trajectory. For a node whose
	// rebuild picked a different trajectory than the canonical sealer
	// chain has, acc[epoch-2] is non-zero but WRONG → VerifyProposer
	// returns the regular mismatch error → block is rejected → node
	// never syncs past that epoch.
	//
	// Best-effort fix: when QAU_TRUST_CANONICAL_PROPOSER env var is set
	// to "1", bypass the acc[epoch-2]==zero gate and ALWAYS return
	// ErrProposerScheduleNotReady → ValidateBlock trusts the canonical
	// ProposerAddr unconditionally. This allows a wallet/RPC node to
	// fully follow the canonical chain without independently
	// reproducing the VRF schedule. The sealer (which signs blocks)
	// never sets this env; sealers always verify independently.
	//
	// Safety: this env is only for non-sealer nodes (RPC wallet
	// gateways) — overriding proposer identity == skipping PoA
	// verification at the local node. The remote signer's canonical
	// identity is still verified by signature recover on
	// block.Header.ProposerAddr.sig over block hash, which is done
	// earlier in ValidateBlock (the verifyBlockSignature path).
	// Setting this env only accepts blocks whose ProposerAddr is
	// whoever the remote sealer set it to; if the remote sealer is
	// malicious and signs a block with a fake ProposerAddr, this trust
	// mode would accept it. Acceptable for testnet/early mainnet; for
	// hostile environments set up proper peers-only trust (TODO R46).
	// R58-ELEC-TRUST (2026-08-18): non-producing nodes (SetTrustCanonicalProposer
	// wired by node.go) skip independent proposer derivation entirely — same
	// path as the manual QAU_TRUST_CANONICAL_PROPOSER env override. This is
	// geth's post-merge behavior: the execution layer does not re-derive the
	// beacon proposer, it follows the canonical chain from the consensus layer.
	if v.trustCanonical || os.Getenv("QAU_TRUST_CANONICAL_PROPOSER") == "1" {
		return ErrProposerScheduleNotReady
	}

	if epoch >= 2 {
		if v.qpos.GetEpochVRFAccumulator(epoch-2) == (types.Hash{}) {
			return ErrProposerScheduleNotReady
		}
	}
	// R45-PoA-FIX FOLLOW-UP (2026-08-13): epoch < 2 must PROCEED to real
	// verification, not trust canonical blindly. The epoch-0/1 shuffle seed
	// derives from the genesis root registered at node startup
	// (SetGenesisRoot) and never depends on the epoch-2 accumulator, so it
	// can never be cold-start — this matches QPOS.IsProposerScheduleReadyForEpoch
	// ("epoch < 2: always uses the genesis root, never cold-start"). The
	// previous hotfix returned ErrProposerScheduleNotReady here too, which
	// made VerifyProposer a permanent no-op for the first two epochs and
	// broke the R38-P1-08 deep-fix contract (matching proposers must count
	// as PASS). Sync-mode callers stay fail-open: any VerifyProposer error
	// still falls back to the conservative skip, so a node genuinely missing
	// its genesis root cannot deadlock on epoch-0/1 blocks.

	expected, err := v.qpos.GetProposerForSlot(slot)
	if err != nil {
		return fmt.Errorf("failed to determine elected proposer for slot %d epoch %d: %w",
			slot, epoch, err)
	}
	if expected == nil {
		return fmt.Errorf("no proposer elected for slot %d epoch %d", slot, epoch)
	}

	if expected.Address != proposer {
		// R61-ELEC-DIVERGE-HEAL (2026-08-18): persistent-reject heal path.
		// A sealer node whose local per-epoch VRF accumulator diverged
		// from the canonical chain (R45-SYNC-TRUST-FIX scenario where the
		// accumulator IS present but WRONG — e.g. due to a stale R58-VRF-
		// PERSIST checkpoint that no longer matches the canonical chain)
		// would return this "proposer mismatch" error for every block at
		// this epoch, indefinitely. ValidateBlock rejects the block
		// BEFORE ProcessBlock calls SetEpochVRFAccumulator, so the local
		// accumulator is never repaired. The sealer is stuck forever.
		//
		// Heal: track consecutive rejections for the same (slot, epoch).
		// We key by (slot, epoch) rather than (height, slot, epoch) so
		// that a polluted acc[epoch-2] — which affects every block in
		// the epoch — still trips the heal after the EARLIEST rejected
		// block, not after every block at one specific height appears
		// `healThreshold` times. Once the threshold is crossed for THIS
		// epoch we mark the epoch "healed" and return
		// ErrProposerScheduleNotReady so the caller trusts the canonical
		// ProposerAddr, lets ProcessBlock run, and the subsequent
		// SetEpochVRFAccumulator overwrites the polluted per-epoch entry
		// with the authoritative on-chain value — repairing the sealer
		// in place. Switching to a different (slot, epoch) means the
		// previous heal worked AND the sealer advanced, so we reset the
		// counter for the new (slot, epoch) — only ONE epoch is healed
		// per divergence scene. Already-healed epochs short-circuit
		// straight to ErrProposerScheduleNotReady without re-counting,
		// so a re-divergence at a later block of an already-healed epoch
		// is handled by the existing SetEpochVRFAccumulator repair.
		//
		// The `healedEpochs` set lives for the verifier's lifetime (no
		// reset) — that's correct: an epoch healed once stays healed; the
		// live accumulator has been repaired and won't diverge again for
		// that epoch unless an explicit fork rollback re-pollutes it
		// (which is the R40 FINALITY sync's job, not this hot path).
		threshold := defaultHealThreshold
		if v.healThreshold > 0 {
			threshold = v.healThreshold
		}
		v.mu.Lock()
		if v.healedEpochs != nil && v.healedEpochs[epoch] {
			v.mu.Unlock()
			return ErrProposerScheduleNotReady
		}
		if v.rejectSlot != slot || v.rejectEpoch != epoch {
			v.rejectSlot = slot
			v.rejectEpoch = epoch
			v.rejectCount = 0
		}
		v.rejectCount++
		shouldHeal := v.rejectCount >= threshold
		if shouldHeal {
			healed := v.healedEpochs
			if healed != nil {
				healed[epoch] = true
			}
		}
		v.mu.Unlock()

		if shouldHeal {
			// Trust the canonical-chain ProposerAddr this time. The caller
			// (block_validator.go ValidateBlock) inspects
			// ErrProposerScheduleNotReady and trusts the canonical proposer;
			// ProcessBlock's SetEpochVRFAccumulator then overwrites the
			// polluted local accumulator, and subsequent blocks at this
			// epoch can be verified normally (their first verify will find
			// the repaired acc and PASS).
			return ErrProposerScheduleNotReady
		}
		return fmt.Errorf("proposer mismatch: expected %x, got %x (slot %d epoch %d, rejectCount=%d, healThreshold=%d)",
			expected.Address[:4], proposer[:4], slot, epoch, v.rejectCount, threshold)
	}

	return nil
}
