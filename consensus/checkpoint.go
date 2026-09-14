// Quantaureum Node source, version 1.0.0.
// Package consensus implements the QPOS consensus mechanism for Quantaureum.
// This file implements checkpoint mechanism for Long-Range attack protection.
// Checkpoints provide weak subjectivity and prevent historical chain rewrites.
package consensus

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// Checkpoint errors
var (
	ErrCheckpointNotFound     = errors.New("checkpoint not found")
	ErrCheckpointTooOld       = errors.New("checkpoint is too old")
	ErrCheckpointInvalid      = errors.New("invalid checkpoint")
	ErrCheckpointConflict     = errors.New("checkpoint conflicts with existing")
	ErrInsufficientSignatures = errors.New("insufficient checkpoint signatures")
	ErrWeakSubjectivity       = errors.New("weak subjectivity period exceeded")
	ErrValidatorNotActive     = errors.New("validator is not active") // audit-fix CR-1: Added for consistency
)

// CheckpointConfig holds checkpoint configuration
type CheckpointConfig struct {
	// CheckpointInterval is the number of blocks between checkpoints
	CheckpointInterval uint64
	// MinSignatures is minimum signatures required for a valid checkpoint
	MinSignatures int
	// WeakSubjectivityPeriod is max blocks a node can be offline before needing trusted checkpoint
	WeakSubjectivityPeriod uint64
	// CheckpointRetention is how many checkpoints to keep
	CheckpointRetention int
}

// DefaultCheckpointConfig returns default checkpoint configuration.
// FIX: MinSignatures is a FALLBACK used only when validatorMgr is
// nil or returns 0 active validators. In production, ComputeMinSignatures()
// dynamically computes ceil(activeValidators * 2/3) and takes precedence.
// The fallback value of 4 assumes 6 validators (ceil(6*2/3)=4).
// Callers should call SetMinSignatures() or use ComputeMinSignatures()
// instead of relying on this static default.
func DefaultCheckpointConfig() *CheckpointConfig {
	return &CheckpointConfig{
		CheckpointInterval: 1000, // Checkpoint every 1000 blocks
		MinSignatures:      4,    // ceil(6*2/3)=4 for the 6 deployed validators
		// Genesis defines 6 validators, all deployed and active.
		// With 6 validators and Casper FFG's 2/3 requirement,
		// ceil(6*2/3)=4 signatures are needed.
		// ComputeMinSignatures() at runtime also uses ActiveValidatorCount.
		WeakSubjectivityPeriod: 50000, // ~1 week at 12s blocks
		CheckpointRetention:    100,   // Keep last 100 checkpoints
	}
}

// SetMinSignatures allows runtime configuration of the minimum signatures
// required for checkpoint finality. This should be called after the validator
// set is known, replacing the static default from DefaultCheckpointConfig.
// FIX: Provides a way to override the hardcoded fallback.
func (c *CheckpointConfig) SetMinSignatures(n int) {
	if n > 0 {
		c.MinSignatures = n
	}
}

// Checkpoint represents a finalized checkpoint
type Checkpoint struct {
	// Height is the block height of this checkpoint
	Height uint64
	// BlockHash is the hash of the checkpoint block
	BlockHash types.Hash
	// StateRoot is the state root at this checkpoint
	StateRoot types.Hash
	// Timestamp is when the checkpoint was created
	Timestamp int64
	// Signatures from validators who signed this checkpoint
	Signatures []*CheckpointSignature
	// TotalStake is the total stake of signers
	TotalStake *big.Int
	// Epoch is the checkpoint epoch number
	Epoch uint64
}

// CheckpointSignature represents a validator's signature on a checkpoint
type CheckpointSignature struct {
	ValidatorAddr types.Address
	Signature     []byte
	Stake         *big.Int
}

// Hash computes the checkpoint hash (for signing).
// audit-fix NEW-7: validates Timestamp is non-negative before casting to uint64
// to prevent silent wraparound that would produce a different hash.
// H-17 FIX: Add explicit length validation for BlockHash and StateRoot.
func (c *Checkpoint) Hash() types.Hash {
	// H-17 FIX: Validate hash lengths before copying
	if len(c.BlockHash) != types.HashLength || len(c.StateRoot) != types.HashLength {
		// Return zero hash if lengths are invalid - this will cause signature verification to fail
		return types.Hash{}
	}
	data := make([]byte, 8+32+32+8+8)
	binary.BigEndian.PutUint64(data[0:8], c.Height)
	copy(data[8:40], c.BlockHash[:])
	copy(data[40:72], c.StateRoot[:])
	// audit-fix NEW-7: clamp negative timestamp to 0 to avoid uint64 wraparound
	ts := c.Timestamp
	if ts < 0 {
		ts = 0
	}
	binary.BigEndian.PutUint64(data[72:80], uint64(ts)) // #nosec G115 -- ts is clamped to >=0 above (line 92-94)
	binary.BigEndian.PutUint64(data[80:88], c.Epoch)

	h := sha3.Sum256(data)
	return types.BytesToHash(h[:])
}

// Verify verifies all signatures on the checkpoint.
// audit-fix  tracks actually-verified count to prevent bypass via unknown validators.
// audit-fix NEW-8: enforces minSignatures threshold. Callers should pass the
// configured MinSignatures from CheckpointConfig to prevent acceptance of
// checkpoints with fewer valid signatures than the security policy requires.
//
// R33 P3-11 FIX (2026-07-28): Added structured security logging at each
// signature-verification failure path using the centralized crypto.Reason*
// constants so SIEM/log-analysis tools can grep for a single canonical
// vocabulary across all verification paths (crypto.Verify, VerifyAggregate,
// Checkpoint.Verify, etc.). Previously a checkpoint signature failure only
// returned a generic ErrCheckpointInvalid with no machine-readable reason.
func (c *Checkpoint) Verify(validatorMgr *ValidatorManager, minSignatures ...int) error {
	if len(c.Signatures) == 0 {
		return ErrInsufficientSignatures
	}

	// L10-001 FIX: Use dynamic threshold based on validator count when available.
	// L11-006 FIX: When no explicit threshold is passed and validatorMgr is
	// available, compute the threshold dynamically based on the current
	// validator set size. The hardcoded DefaultCheckpointConfig.MinSignatures
	// (4) is correct for 6 validators (ceil(6*2/3)=4). Using the dynamic
	// ceil(N*2/3) formula matches CheckpointManager.ComputeMinSignatures()
	// and supports any validator set size.
	// AUDIT-FULL ROUND1 2026-08-14 CS-04: requiredSigs uses ActiveValidatorCount()
	// which counts validators rather than stake weight. This is by design for the
	// current QPOS implementation where all validators have equal voting weight
	// per the BFT committee model. If stake-weighted voting is introduced in a
	// future upgrade, this function must be updated to compute a stake-weighted
	// threshold. CONFIRMED-IN-PLACE.
	requiredSigs := DefaultCheckpointConfig().MinSignatures
	if len(minSignatures) > 0 && minSignatures[0] > 0 {
		requiredSigs = minSignatures[0]
	} else if validatorMgr != nil {
		// No explicit threshold passed: derive from live validator set.
		count := validatorMgr.ActiveValidatorCount()
		if count > 0 {
			// ceil(count * 2 / 3) = (count*2 + 2) / 3
			requiredSigs = (count*2 + 2) / 3
		}
	}

	checkpointHash := c.Hash()
	verifiedCount := 0
	// audit-fix CS-04: accumulate verified signer weight from the
	// authoritative ValidatorManager (NOT from sig.Stake, which on a
	// Checkpoint coming over the p2p wire can be attacker-controlled).
	// The numeric count check below stays as a lower bound for backward
	// compatibility with the original behavior, but it is augmented by a
	// Casper FFG "2/3 of total stake" weight gate identical to the one
	// enforced in CheckpointManager.FinalizeCheckpoint. Without this, a
	// checkpoint carrying N validators each with low stake could pass the
	// N-th count gate even if their combined stake is well below 2/3 of the
	// network total — a count-vs-stake inconsistency CS-04 calls out.
	verifiedStake := new(big.Int)

	// CON-CP-01 FIX (deep-audit 2026-07-12): fail closed if validator keys cannot
	// be resolved, and count each validator AT MOST ONCE. The loop below
	// dereferences validatorMgr (nil here would panic), and without dedup a
	// checkpoint bundling ONE validator's valid signature repeated requiredSigs
	// times would pass — defeating the 2/3 DISTINCT-validator threshold.
	if validatorMgr == nil {
		return ErrInsufficientSignatures
	}
	seen := make(map[types.Address]bool, len(c.Signatures))

	for _, sig := range c.Signatures {
		if seen[sig.ValidatorAddr] {
			continue // already counted this validator; do not double-count
		}
		pubKey, err := validatorMgr.GetPublicKey(sig.ValidatorAddr)
		if err != nil {
			continue // Skip unknown validators
		}
		// R25-H1 FIX: Defensive nil check to prevent panic if GetPublicKey returns (nil, nil)
		if pubKey == nil {
			continue // Skip if no public key available
		}

		if !crypto.Verify(pubKey, checkpointHash[:], sig.Signature) {
			// R33 P3-11 FIX: crypto.Verify already emits a structured log
			// (with category=SECURITY and reason=ReasonVerificationFailed or
			// related) for the specific inner failure. Here we annotate the
			// returned error so callers that only inspect the error (not the
			// logs) can still identify the failure reason programmatically.
			qposAdvLogger.Warn("Checkpoint signature verification failed", map[string]any{
				"category":       "SECURITY",
				"reason":         crypto.ReasonVerificationFailed,
				"checkpoint_h":   c.Height,
				"validator_addr": sig.ValidatorAddr.ToHexAddress(),
				"sig_len":        len(sig.Signature),
			})
			return fmt.Errorf("%w: %s", ErrCheckpointInvalid, crypto.ReasonVerificationFailed)
		}
		seen[sig.ValidatorAddr] = true
		verifiedCount++
		// CS-04: accumulate the AUTHORITATIVE stake from the validator manager
		// (do NOT trust sig.Stake for an externally-supplied checkpoint). If the
		// validator lookup fails, contribute zero stake; this keeps the weight
		// gate strict — unknown validators cannot help reach 2/3.
		if vInfo, vErr := validatorMgr.GetValidator(sig.ValidatorAddr); vErr == nil && vInfo != nil && vInfo.Stake != nil && vInfo.Stake.Sign() > 0 {
			verifiedStake.Add(verifiedStake, vInfo.Stake)
		}
	}

	// audit-fix  + NEW-8: reject checkpoint if verified signatures are
	// below the required minimum. This prevents forged checkpoints with
	// signatures from non-existent validators being silently accepted.
	if verifiedCount < requiredSigs {
		qposAdvLogger.Warn("Checkpoint insufficient distinct signatures", map[string]any{
			"category":     "SECURITY",
			"reason":       "insufficient_signatures",
			"checkpoint_h": c.Height,
			"verified":     verifiedCount,
			"required":     requiredSigs,
		})
		return ErrInsufficientSignatures
	}

	// audit-fix CS-04: enforce stake-weighted 2/3 majority to keep
	// Checkpoint.Verify aligned with CheckpointManager.FinalizeCheckpoint.
	// When the validator manager can supply a positive network total stake,
	// the verified signers MUST also reach 2/3 of it (Casper FFG accountable
	// safety). When the network total stake is unavailable or zero (e.g.
	// bootstrap before any stakes are registered), the count gate above still
	// applies as a fallback, preserving the original behavior for callers
	// that rely on Verify during early startup — so the public Verify API
	// signature is unchanged.
	if count := validatorMgr.ActiveValidatorCount(); count > 0 {
		networkTotalStake := validatorMgr.GetTotalStake()
		if networkTotalStake != nil && networkTotalStake.Sign() > 0 {
			if verifiedStake.Sign() <= 0 {
				return ErrInsufficientSignatures
			}
			lhs := new(big.Int).Mul(verifiedStake, big.NewInt(3))
			rhs := new(big.Int).Mul(networkTotalStake, big.NewInt(2))
			if lhs.Cmp(rhs) < 0 {
				qposAdvLogger.Warn("Checkpoint below 2/3 stake majority", map[string]any{
					"category":     "SECURITY",
					"reason":       "insufficient_stake_weight",
					"checkpoint_h": c.Height,
					"verified":     verifiedCount,
					"required":     requiredSigs,
				})
				return ErrInsufficientSignatures
			}
		}
	}

	return nil
}

// CheckpointManager manages checkpoints for long-range attack protection
type CheckpointManager struct {
	mu sync.RWMutex

	config       *CheckpointConfig
	validatorMgr *ValidatorManager

	// Checkpoints indexed by height
	checkpoints map[uint64]*Checkpoint

	// Latest finalized checkpoint
	latestCheckpoint *Checkpoint

	// Trusted checkpoint (from external source for weak subjectivity)
	trustedCheckpoint *Checkpoint

	// Pending checkpoint being collected
	pendingCheckpoint *PendingCheckpoint
}

// PendingCheckpoint represents a checkpoint being collected
type PendingCheckpoint struct {
	Height     uint64
	BlockHash  types.Hash
	StateRoot  types.Hash
	Timestamp  int64
	Epoch      uint64
	Signatures map[types.Address]*CheckpointSignature
}

// NewCheckpointManager creates a new checkpoint manager
func NewCheckpointManager(config *CheckpointConfig, validatorMgr *ValidatorManager) *CheckpointManager {
	if config == nil {
		config = DefaultCheckpointConfig()
	}

	return &CheckpointManager{
		config:       config,
		validatorMgr: validatorMgr,
		checkpoints:  make(map[uint64]*Checkpoint),
	}
}

// Config returns the checkpoint configuration
func (cm *CheckpointManager) Config() *CheckpointConfig {
	return cm.config
}

// ComputeMinSignatures dynamically computes the minimum signatures required
// based on the current validator set size. Uses ceil(N*2/3) formula.
// L10-001 FIX: MinSignatures was hardcoded to 4, which is correct for 6 validators
// but would be wrong if the validator set changes. This method computes the
// threshold dynamically: ceil(activeValidators * 2 / 3).
// Falls back to config.MinSignatures if validator manager is unavailable.
func (cm *CheckpointManager) ComputeMinSignatures() int {
	if cm.validatorMgr == nil {
		return cm.config.MinSignatures
	}
	count := cm.validatorMgr.ActiveValidatorCount()
	if count == 0 {
		return cm.config.MinSignatures
	}
	// ceil(count * 2 / 3) = (count*2 + 2) / 3 using integer arithmetic
	return (count*2 + 2) / 3
}

// SetTrustedCheckpoint sets a trusted checkpoint for weak subjectivity
// This should be called when syncing from scratch with a trusted source
func (cm *CheckpointManager) SetTrustedCheckpoint(cp *Checkpoint) error {
	if cp == nil {
		return ErrCheckpointInvalid
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// CON-CP-02 FIX (deep-audit 2026-07-12): count DISTINCT signers, not raw
	// signature entries, so a checkpoint padded with duplicate/garbage signatures
	// cannot pass this weak-subjectivity gate. When the validator set is
	// available, also cryptographically verify the checkpoint (the trust anchor
	// must be authentic); during initial bootstrap the set may be empty, in which
	// case the distinct-count gate still applies.
	distinct := make(map[types.Address]bool, len(cp.Signatures))
	for _, sig := range cp.Signatures {
		distinct[sig.ValidatorAddr] = true
	}
	if len(distinct) < cm.ComputeMinSignatures() {
		return ErrInsufficientSignatures
	}
	if cm.validatorMgr != nil && cm.validatorMgr.ActiveValidatorCount() > 0 {
		if err := cp.Verify(cm.validatorMgr); err != nil {
			return err
		}
	}

	cm.trustedCheckpoint = cp
	cm.checkpoints[cp.Height] = cp

	if cm.latestCheckpoint == nil || cp.Height > cm.latestCheckpoint.Height {
		cm.latestCheckpoint = cp
	}

	return nil
}

// ShouldCreateCheckpoint returns true if a checkpoint should be created at this height
func (cm *CheckpointManager) ShouldCreateCheckpoint(height uint64) bool {
	return height > 0 && height%cm.config.CheckpointInterval == 0
}

// StartCheckpoint starts collecting signatures for a new checkpoint
func (cm *CheckpointManager) StartCheckpoint(height uint64, blockHash, stateRoot types.Hash) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Check if checkpoint already exists
	if _, exists := cm.checkpoints[height]; exists {
		return ErrCheckpointConflict
	}

	epoch := height / cm.config.CheckpointInterval

	cm.pendingCheckpoint = &PendingCheckpoint{
		Height:    height,
		BlockHash: blockHash,
		StateRoot: stateRoot,
		// R43-CS-003 FIX: Use int64(height) as deterministic timestamp instead
		// of time.Now().Unix() to ensure all nodes agree on checkpoint timestamps.
		Timestamp:  int64(height),
		Epoch:      epoch,
		Signatures: make(map[types.Address]*CheckpointSignature),
	}

	return nil
}

// AddCheckpointSignature adds a validator's signature to the pending checkpoint
func (cm *CheckpointManager) AddCheckpointSignature(
	validatorAddr types.Address,
	signature []byte,
	height uint64,
	blockHash types.Hash,
) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.pendingCheckpoint == nil {
		return ErrCheckpointNotFound
	}

	// Verify height and hash match
	if cm.pendingCheckpoint.Height != height || cm.pendingCheckpoint.BlockHash != blockHash {
		return ErrCheckpointConflict
	}

	// Get validator info
	validator, err := cm.validatorMgr.GetValidator(validatorAddr)
	if err != nil {
		return err
	}

	// audit-fix CR-1: Check validator is active before accepting signature
	// Inactive validators should not participate in consensus
	if !validator.Active {
		return ErrValidatorNotActive
	}

	// Verify signature
	cp := &Checkpoint{
		Height:    cm.pendingCheckpoint.Height,
		BlockHash: cm.pendingCheckpoint.BlockHash,
		StateRoot: cm.pendingCheckpoint.StateRoot,
		Timestamp: cm.pendingCheckpoint.Timestamp,
		Epoch:     cm.pendingCheckpoint.Epoch,
	}

	pubKey, err := cm.validatorMgr.GetPublicKey(validatorAddr)
	if err != nil {
		return err
	}

	cpHash := cp.Hash()
	if !crypto.Verify(pubKey, cpHash[:], signature) {
		return ErrCheckpointInvalid
	}

	// Add signature
	// AUDIT (2026) CONS- CONFIRMED: stakeCopy is NOT dead code —
	// it is stored as CheckpointSignature.Stake below. CheckpointSignature.Stake
	// is *big.Int (no uint64 truncation), so the historical " saturating
	// conversion" comment was inaccurate; the deep copy simply prevents the
	// caller from mutating validator.Stake through the stored reference.
	stakeCopy := new(big.Int).Set(validator.Stake)

	// R25-CR-2 FIX: Deep copy signature before storing to prevent caller
	// modification from corrupting internal checkpoint state.
	sigCopy := make([]byte, len(signature))
	copy(sigCopy, signature)
	cm.pendingCheckpoint.Signatures[validatorAddr] = &CheckpointSignature{
		ValidatorAddr: validatorAddr,
		Signature:     sigCopy,
		Stake:         stakeCopy,
	}

	return nil
}

// FinalizeCheckpoint finalizes the pending checkpoint if it has enough signatures
func (cm *CheckpointManager) FinalizeCheckpoint() (*Checkpoint, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.pendingCheckpoint == nil {
		return nil, ErrCheckpointNotFound
	}

	// Check minimum signatures
	if len(cm.pendingCheckpoint.Signatures) < cm.ComputeMinSignatures() {
		return nil, ErrInsufficientSignatures
	}

	// Create finalized checkpoint
	signatures := make([]*CheckpointSignature, 0, len(cm.pendingCheckpoint.Signatures))
	totalStake := new(big.Int)

	// HIGH FIX: Track unique signers to prevent duplicate signature stake calculation
	seenSigners := make(map[types.Address]bool)
	for validatorAddr, sig := range cm.pendingCheckpoint.Signatures {
		// Skip if we've already counted this validator's stake
		if seenSigners[validatorAddr] {
			continue
		}
		seenSigners[validatorAddr] = true
		signatures = append(signatures, sig)
		totalStake.Add(totalStake, sig.Stake)
	}

	// audit-fix  verify signer weight exceeds 2/3 majority
	networkTotalStake := cm.validatorMgr.GetTotalStake()
	// audit-fix CRIT-2: reject if totalStake or networkTotalStake is 0
	// to prevent bypass when both are 0 (0*3 <= 0*2 is incorrectly true)
	// Also reject negative stake values as they indicate corruption
	if totalStake.Sign() <= 0 || networkTotalStake.Sign() <= 0 {
		return nil, errors.New("checkpoint weight below 2/3 majority: invalid stake")
	}
	// R35-P2-CONS-03 FIX (2026-07-29): Use >= instead of > to match Casper FFG
	// "at least 2/3" semantics, consistent with VoteSet.HasQuorum (voting.go:816)
	// which accepts 3*weight >= 2*total. The previous strict-greater-than
	// (`3*signerStake > 2*totalNetworkStake`) rejected the exact 2/3 boundary
	// case where signerStake == (2/3)*totalNetworkStake — for example, with 3
	// validators each holding equal stake, exactly 2 validators signing (2/3
	// exactly) would be rejected, making checkpoint finalization unreachable
	// in the symmetric-stake mainnet configuration. The off-by-one also
	// diverged from VoteSet.HasQuorum, so a block could reach quorum in the
	// BFT vote set but fail checkpoint finalization at the exact 2/3 boundary,
	// splitting consensus.
	lhs := new(big.Int).Mul(totalStake, big.NewInt(3))
	rhs := new(big.Int).Mul(networkTotalStake, big.NewInt(2))
	if lhs.Cmp(rhs) < 0 {
		return nil, errors.New("checkpoint weight below 2/3 majority")
	}

	checkpoint := &Checkpoint{
		Height:     cm.pendingCheckpoint.Height,
		BlockHash:  cm.pendingCheckpoint.BlockHash,
		StateRoot:  cm.pendingCheckpoint.StateRoot,
		Timestamp:  cm.pendingCheckpoint.Timestamp,
		Epoch:      cm.pendingCheckpoint.Epoch,
		Signatures: signatures,
		TotalStake: totalStake,
	}

	// Store checkpoint
	cm.checkpoints[checkpoint.Height] = checkpoint
	cm.latestCheckpoint = checkpoint
	cm.pendingCheckpoint = nil

	// Prune old checkpoints
	cm.pruneOldCheckpoints()

	return checkpoint, nil
}

// GetCheckpoint returns a deep copy of a checkpoint by height.
// audit-fix NEW-22: return deep copy to prevent callers from mutating internal state.
func (cm *CheckpointManager) GetCheckpoint(height uint64) (*Checkpoint, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	cp, exists := cm.checkpoints[height]
	if !exists {
		return nil, ErrCheckpointNotFound
	}

	return deepCopyCheckpoint(cp), nil
}

// GetLatestCheckpoint returns a deep copy of the latest finalized checkpoint.
// audit-fix NEW-22: return deep copy to prevent callers from mutating internal state.
func (cm *CheckpointManager) GetLatestCheckpoint() *Checkpoint {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return deepCopyCheckpoint(cm.latestCheckpoint)
}

// GetTrustedCheckpoint returns a deep copy of the trusted checkpoint.
// audit-fix NEW-22: return deep copy to prevent callers from mutating internal state.
func (cm *CheckpointManager) GetTrustedCheckpoint() *Checkpoint {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	return deepCopyCheckpoint(cm.trustedCheckpoint)
}

// ValidateChainAgainstCheckpoints validates that a chain respects all checkpoints
func (cm *CheckpointManager) ValidateChainAgainstCheckpoints(
	getBlockHash func(height uint64) (types.Hash, error),
) error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	for height, cp := range cm.checkpoints {
		blockHash, err := getBlockHash(height)
		if err != nil {
			continue // Block not yet synced
		}

		if blockHash != cp.BlockHash {
			return ErrCheckpointConflict
		}
	}

	return nil
}

// CheckWeakSubjectivity checks if the node is within weak subjectivity period
// Returns error if the node has been offline too long and needs a trusted checkpoint.
//
// R33 P3-05 FIX (2026-07-28): This function returns nil (allow sync) when
// cm.latestCheckpoint == nil. That means a fresh-syncing node has NO weak
// subjectivity protection until it observes its first finalized checkpoint
// from peers. The residual risk is mitigated by:
//  1. A startup warning in node.initSyncer() that logs when no trusted
//     checkpoint is configured (so operators are reminded to set one).
//  2. The CheckpointManager's ValidateChainAgainstCheckpoints() guard,
//     which rejects any chain whose blocks conflict with a known
//     finalized checkpoint (prevents shallow-history fabrication once
//     a checkpoint IS observed).
//  3. Production deployments SHOULD set a trusted checkpoint out-of-band
//     via qau_setTrustedCheckpoint RPC before starting sync from scratch.
//
// A future enhancement could fetch a trusted checkpoint from a well-known
// HTTPS endpoint or from peers via a MsgTypeCheckpointReq/Resp exchange
// (the message type is already scaffolded in p2p/message_validator.go).
func (cm *CheckpointManager) CheckWeakSubjectivity(currentHeight uint64) error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.checkWeakSubjectivityLocked(currentHeight)
}

// checkWeakSubjectivityLocked is the lock-free internal implementation.
// MUST be called while cm.mu is already held (read or write).
func (cm *CheckpointManager) checkWeakSubjectivityLocked(currentHeight uint64) error {
	if cm.latestCheckpoint == nil {
		// No checkpoint yet, allow sync
		return nil
	}

	// Check if we're within weak subjectivity period
	if currentHeight > cm.latestCheckpoint.Height+cm.config.WeakSubjectivityPeriod {
		// Node has been offline too long
		if cm.trustedCheckpoint == nil ||
			cm.trustedCheckpoint.Height < currentHeight-cm.config.WeakSubjectivityPeriod {
			return ErrWeakSubjectivity
		}
	}

	return nil
}

// IsCheckpointHeight returns true if the given height is a checkpoint height
func (cm *CheckpointManager) IsCheckpointHeight(height uint64) bool {
	return height > 0 && height%cm.config.CheckpointInterval == 0
}

// GetCheckpointEpoch returns the epoch number for a given height
func (cm *CheckpointManager) GetCheckpointEpoch(height uint64) uint64 {
	return height / cm.config.CheckpointInterval
}

// pruneOldCheckpoints removes checkpoints beyond retention limit
func (cm *CheckpointManager) pruneOldCheckpoints() {
	if len(cm.checkpoints) <= cm.config.CheckpointRetention {
		return
	}

	// Find minimum height to keep
	var heights []uint64
	for h := range cm.checkpoints {
		heights = append(heights, h)
	}

	// Sort heights (simple bubble sort for small list)
	for i := 0; i < len(heights)-1; i++ {
		for j := 0; j < len(heights)-i-1; j++ {
			if heights[j] > heights[j+1] {
				heights[j], heights[j+1] = heights[j+1], heights[j]
			}
		}
	}

	// Remove oldest checkpoints
	toRemove := len(heights) - cm.config.CheckpointRetention
	for i := 0; i < toRemove; i++ {
		// Don't remove trusted checkpoint
		if cm.trustedCheckpoint != nil && heights[i] == cm.trustedCheckpoint.Height {
			continue
		}
		delete(cm.checkpoints, heights[i])
	}
}

// GetAllCheckpoints returns deep copies of all stored checkpoints.
// audit-fix NEW-22: return deep copies to prevent callers from mutating internal state.
func (cm *CheckpointManager) GetAllCheckpoints() []*Checkpoint {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make([]*Checkpoint, 0, len(cm.checkpoints))
	for _, cp := range cm.checkpoints {
		result = append(result, deepCopyCheckpoint(cp))
	}

	return result
}

// deepCopyCheckpoint returns a deep copy of a Checkpoint.
// audit-fix NEW-22: prevents callers from mutating internal consensus state.
func deepCopyCheckpoint(cp *Checkpoint) *Checkpoint {
	if cp == nil {
		return nil
	}
	result := &Checkpoint{
		Height:     cp.Height,
		BlockHash:  cp.BlockHash,
		StateRoot:  cp.StateRoot,
		Timestamp:  cp.Timestamp,
		TotalStake: new(big.Int).Set(cp.TotalStake),
		Epoch:      cp.Epoch,
	}
	if cp.Signatures != nil {
		result.Signatures = make([]*CheckpointSignature, len(cp.Signatures))
		for i, sig := range cp.Signatures {
			sigCopy := &CheckpointSignature{
				ValidatorAddr: sig.ValidatorAddr,
				Stake:         new(big.Int).Set(sig.Stake),
			}
			if sig.Signature != nil {
				sigCopy.Signature = make([]byte, len(sig.Signature))
				copy(sigCopy.Signature, sig.Signature)
			}
			result.Signatures[i] = sigCopy
		}
	}
	return result
}

// CheckpointStats returns statistics about checkpoints
type CheckpointStats struct {
	TotalCheckpoints   int
	LatestHeight       uint64
	LatestEpoch        uint64
	TrustedHeight      uint64
	PendingSignatures  int
	WeakSubjectivityOK bool
}

// GetStats returns checkpoint statistics
func (cm *CheckpointManager) GetStats(currentHeight uint64) *CheckpointStats {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	stats := &CheckpointStats{
		TotalCheckpoints: len(cm.checkpoints),
	}

	if cm.latestCheckpoint != nil {
		stats.LatestHeight = cm.latestCheckpoint.Height
		stats.LatestEpoch = cm.latestCheckpoint.Epoch
	}

	if cm.trustedCheckpoint != nil {
		stats.TrustedHeight = cm.trustedCheckpoint.Height
	}

	if cm.pendingCheckpoint != nil {
		stats.PendingSignatures = len(cm.pendingCheckpoint.Signatures)
	}

	// Check weak subjectivity (use internal method to avoid re-acquiring RLock)
	stats.WeakSubjectivityOK = cm.checkWeakSubjectivityLocked(currentHeight) == nil

	return stats
}
