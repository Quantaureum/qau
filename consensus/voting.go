// Quantaureum Node source, version 1.0.0.
// Package consensus implements the QPOS consensus mechanism for Quantaureum.
// This file implements vote collection and verification for block finalization.
// Optimized for high-throughput voting with BLS signature aggregation support.
package consensus

import (
	"bytes"
	"container/heap"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

var (
	// ErrInvalidVote is returned when a vote is invalid
	ErrInvalidVote = errors.New("invalid vote")

	// ErrDuplicateVote is returned when a validator votes twice
	ErrDuplicateVote = errors.New("duplicate vote from validator")

	// ErrVoteFromNonValidator is returned when vote is from non-validator
	ErrVoteFromNonValidator = errors.New("vote from non-validator")

	// ErrInvalidVoteSignature is returned when vote signature is invalid
	ErrInvalidVoteSignature = errors.New("invalid vote signature")

	// ErrBlockMismatch is returned when vote is for different block
	ErrBlockMismatch = errors.New("vote is for different block")

	// ErrQuorumNotReached is returned when quorum is not reached
	ErrQuorumNotReached = errors.New("quorum not reached")

	// ErrVoteTimeout is returned when vote collection times out
	ErrVoteTimeout = errors.New("vote collection timeout")

	// ErrInvalidAggregatedSignature is returned when aggregated signature is invalid
	ErrInvalidAggregatedSignature = errors.New("invalid aggregated signature")

	// ErrDoubleSign is returned when double-signing is detected
	ErrDoubleSign = errors.New("double-signing detected")

	// ErrValidatorBlacklisted is returned when vote is from a blacklisted validator
	// P1-T5 (2026-07-14): MinistryDefense blacklist enforcement in VotingManager.
	ErrValidatorBlacklisted = errors.New("validator is blacklisted by MinistryDefense")

	// voteDomainSeparator is used to separate vote signatures
	voteDomainSeparator = []byte("QUANTAUREUM_VOTE_V2")

	// votingSystemCaller is the system caller address for voting operations
	// CRITICAL FIX: Pre-registered system caller for evidence submission
	votingSystemCaller     types.Address
	votingSystemCallerOnce sync.Once
)

// getVotingSystemCaller returns the system caller address for voting operations.
// CRITICAL FIX: This address is registered as a system caller and used for all
// evidence submissions from the VotingManager.
func getVotingSystemCaller() types.Address {
	votingSystemCallerOnce.Do(func() {
		// Generate deterministic address from voting domain
		data := []byte("voting-system-caller-v1")
		hash := sha3.Sum256(data)
		votingSystemCaller = types.BytesToAddress(hash[12:])

		// Register as system caller (idempotent, safe to call multiple times)
		RegisterSystemCaller(votingSystemCaller)
	})
	return votingSystemCaller
}

// GetVotingSystemCaller is the exported version of getVotingSystemCaller.
// P1-T7 (2026-07-14): Used by the node layer to obtain a system caller for
// ministry operations (e.g., MinistryWorks.RegisterBridge/RecordCrossChainTx).
func GetVotingSystemCaller() types.Address {
	return getVotingSystemCaller()
}

var (
	// DefaultVoteTimeout is the default timeout for vote collection (2 seconds per requirement 5.1)
	DefaultVoteTimeout = 2 * time.Second

	// QuorumThresholdNumerator is the numerator for quorum threshold (2/3)
	QuorumThresholdNumerator = big.NewInt(2)

	// QuorumThresholdDenominator is the denominator for quorum threshold (2/3)
	QuorumThresholdDenominator = big.NewInt(3)
)

// VoteType represents the type of vote
type VoteType uint8

const (
	// VoteTypePrevote is a prevote in the consensus
	VoteTypePrevote VoteType = iota
	// VoteTypePrecommit is a precommit in the consensus
	VoteTypePrecommit
	// VoteTypeAttestation is an attestation in the consensus
	VoteTypeAttestation
)

// Vote represents a validator's vote for a block
type Vote struct {
	Type          VoteType
	Height        uint64
	Round         uint32
	BlockHash     types.Hash
	ValidatorAddr types.Address
	Signature     []byte
	// R41-H1 FIX: Add epoch fields for proper Casper FFG surround vote verification.
	// These fields are only set for attestation votes (VoteTypeAttestation).
	// For attestation votes, SourceEpoch < TargetEpoch must hold.
	// For precommit votes these are 0 (precommits don't use epoch-based surround detection).
	SourceEpoch uint64
	TargetEpoch uint64
	// CONS-R9-001/002/004 (2026-07-19) FIX: Carry the source/target block
	// roots so slashing verification can attest that the voted-on roots
	// are actually the canonical (or conflicting) ones. Previously
	// voteToAttestation dropped Root entirely, so a slashing proof could
	// be constructed with attacker-chosen Roots that don't correspond to
	// any real chain history — defeating Casper FFG accountable safety.
	//
	// These are ONLY set for attestation votes. Zero-value (Hash{})
	// means "not yet populated" — slashing verification MUST reject votes
	// with zero Root to prevent the old bypass.
	SourceRoot types.Hash
	TargetRoot types.Hash
	// CONS-R9-001/002/004 (2026-07-19) FIX: Carry the attestation-specific
	// fields so that Vote.SignedMessage() can reproduce the exact byte
	// layout of QPOS.attestationSigningData / buildAttestationMessage. The
	// attestation signature in att.Signature is computed over that layout
	// (domain || networkID || slot || keyVersion || beaconBlockRoot ||
	// sourceEpoch || sourceRoot || targetEpoch || targetRoot ||
	// validatorIndex). Without these fields, attestationToVote(att) →
	// vote.Verify(pubKey) would always fail because VoteMessage() used a
	// different (Root-less, KeyVersion-less, ValidatorIndex-less) layout.
	// Slashing evidence MUST be verifiable against the real attestation
	// signature, so we mirror the full attestation signed payload here.
	KeyVersion     uint64
	ValidatorIndex int
}

// deepCopyVote creates a deep copy of a Vote to prevent external mutation
// from corrupting evidence stored in SlashingEvidence.
// deepCopyVote returns a deep copy of a Vote.
// C-14 FIX: Vote pointers must be deep copied to prevent corruption
// if the original vote in voteHistory is modified.
func deepCopyVote(v *Vote) *Vote {
	if v == nil {
		return nil
	}
	sigCopy := make([]byte, len(v.Signature))
	copy(sigCopy, v.Signature)
	return &Vote{
		Type:           v.Type,
		Height:         v.Height,
		Round:          v.Round,
		BlockHash:      v.BlockHash,
		ValidatorAddr:  v.ValidatorAddr,
		Signature:      sigCopy,
		SourceEpoch:    v.SourceEpoch,    // R41-H1 FIX
		TargetEpoch:    v.TargetEpoch,    // R41-H1 FIX
		SourceRoot:     v.SourceRoot,     // CONS-R9-001/002/004 FIX
		TargetRoot:     v.TargetRoot,     // CONS-R9-001/002/004 FIX
		KeyVersion:     v.KeyVersion,     // CONS-R9-001/002/004 FIX
		ValidatorIndex: v.ValidatorIndex, // CONS-R9-001/002/004 FIX
	}
}

// VoteMessage returns the message to be signed for a vote.
// audit-fix H-1: includes network ID to prevent cross-chain replay attacks,
// matching the attestation signing pattern in attestationSigningData().
func (v *Vote) VoteMessage() []byte {
	// R41-H1 FIX: Include SourceEpoch and TargetEpoch in the signed message.
	// C21-003 FIX: Include ValidatorAddr in the signed message to bind the
	// signature to the claiming validator. Format: domainSep || networkID ||
	// type || sourceEpoch || targetEpoch || height || round || blockHash || validatorAddr
	msg := make([]byte, len(voteDomainSeparator)+8+1+8+8+8+4+types.HashLength+types.AddressLength)
	copy(msg, voteDomainSeparator)
	offset := len(voteDomainSeparator)

	// Network ID (prevents testnet votes replaying on mainnet)
	networkID := GetAttestationNetworkID()
	msg[offset] = byte(networkID >> 56)
	msg[offset+1] = byte(networkID >> 48) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+2] = byte(networkID >> 40) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+3] = byte(networkID >> 32) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+4] = byte(networkID >> 24) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+5] = byte(networkID >> 16) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+6] = byte(networkID >> 8)  // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+7] = byte(networkID)       // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 8

	msg[offset] = byte(v.Type)
	offset++

	// R41-H1 FIX: SourceEpoch (big-endian) — 0 for precommit votes
	msg[offset] = byte(v.SourceEpoch >> 56)
	msg[offset+1] = byte(v.SourceEpoch >> 48) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+2] = byte(v.SourceEpoch >> 40) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+3] = byte(v.SourceEpoch >> 32) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+4] = byte(v.SourceEpoch >> 24) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+5] = byte(v.SourceEpoch >> 16) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+6] = byte(v.SourceEpoch >> 8)  // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+7] = byte(v.SourceEpoch)       // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 8

	// R41-H1 FIX: TargetEpoch (big-endian) — 0 for precommit votes
	msg[offset] = byte(v.TargetEpoch >> 56)
	msg[offset+1] = byte(v.TargetEpoch >> 48) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+2] = byte(v.TargetEpoch >> 40) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+3] = byte(v.TargetEpoch >> 32) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+4] = byte(v.TargetEpoch >> 24) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+5] = byte(v.TargetEpoch >> 16) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+6] = byte(v.TargetEpoch >> 8)  // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+7] = byte(v.TargetEpoch)       // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 8

	// Height (big-endian)
	msg[offset] = byte(v.Height >> 56)
	msg[offset+1] = byte(v.Height >> 48) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+2] = byte(v.Height >> 40) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+3] = byte(v.Height >> 32) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+4] = byte(v.Height >> 24) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+5] = byte(v.Height >> 16) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+6] = byte(v.Height >> 8)  // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+7] = byte(v.Height)       // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 8

	// Round (big-endian)
	msg[offset] = byte(v.Round >> 24)
	msg[offset+1] = byte(v.Round >> 16) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+2] = byte(v.Round >> 8)  // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	msg[offset+3] = byte(v.Round)       // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	offset += 4

	copy(msg[offset:], v.BlockHash[:])
	offset += types.HashLength

	// C21-003 FIX: ValidatorAddr binds the signature to the claiming validator.
	copy(msg[offset:], v.ValidatorAddr[:])

	return msg
}

// Hash returns the hash of the vote
func (v *Vote) Hash() types.Hash {
	return sha3.Sum256(v.VoteMessage())
}

// SignedMessage returns the byte payload that is actually signed/verified
// for this vote. The layout depends on the vote type:
//
//   - VoteTypeAttestation: mirrors QPOS.attestationSigningData /
//     buildAttestationMessage exactly (domain || networkID || slot ||
//     keyVersion || beaconBlockRoot || sourceEpoch || sourceRoot ||
//     targetEpoch || targetRoot || validatorIndex). This is required so
//     that a Vote produced by attestationToVote(att) — whose Signature
//     field is the attestation's signature — verifies correctly under
//     Verify(pubKey). Before CONS-R9-001/002/004 this path used
//     VoteMessage() (Root-less, KeyVersion-less, ValidatorIndex-less),
//     so every attestation-derived slashing vote failed signature
//     verification, silently disabling slashing enforcement.
//
//   - Other types (VoteTypePrevote / VoteTypePrecommit): use the legacy
//     VoteMessage() layout (domain || networkID || type || sourceEpoch ||
//     targetEpoch || height || round || blockHash || validatorAddr).
//
// This MUST stay byte-for-byte in sync with buildAttestationMessage for
// attestation votes; if the two diverge, signature verification breaks.
func (v *Vote) SignedMessage() []byte {
	if v == nil {
		return nil
	}
	if v.Type == VoteTypeAttestation {
		att := v.toAttestationForSigning()
		return buildAttestationMessage(att)
	}
	return v.VoteMessage()
}

// toAttestationForSigning reconstructs an Attestation carrying the fields
// needed to reproduce the attestation signature payload. It is internal
// to SignedMessage and MUST NOT be used for state-affecting operations.
func (v *Vote) toAttestationForSigning() *Attestation {
	return &Attestation{
		Slot:            v.Height,
		BeaconBlockRoot: v.BlockHash,
		Source: AttestationCheckpoint{
			Epoch: v.SourceEpoch,
			Root:  v.SourceRoot,
		},
		Target: AttestationCheckpoint{
			Epoch: v.TargetEpoch,
			Root:  v.TargetRoot,
		},
		ValidatorIndex: v.ValidatorIndex,
		Signature:      v.Signature,
		KeyVersion:     v.KeyVersion,
	}
}

// Sign signs the vote with the given private key
func (v *Vote) Sign(privateKey *crypto.PrivateKey) error {
	if privateKey == nil {
		return ErrNilPrivateKey
	}

	msg := v.SignedMessage()
	sig, err := privateKey.Sign(msg)
	if err != nil {
		return err
	}

	v.Signature = sig
	return nil
}

// Verify verifies the vote signature with the given public key
func (v *Vote) Verify(publicKey *crypto.PublicKey) bool {
	if publicKey == nil || len(v.Signature) == 0 {
		return false
	}

	msg := v.SignedMessage()
	return publicKey.Verify(msg, v.Signature)
}

// VoteCollector collects and validates votes for a specific block
type VoteCollector struct {
	mu           sync.RWMutex
	height       uint64
	round        uint32
	blockHash    types.Hash
	votes        map[types.Address]*Vote
	validatorMgr *ValidatorManager
	totalStake   *big.Int
	votedStake   *big.Int
	// R14-MED (2026-07-21): Optional DoubleSignDetector for cross-block
	// equivocation detection. When set via SetDoubleSignDetector, AddVote
	// forwards every accepted vote to the detector so that a validator
	// voting for DIFFERENT blocks at the same (height, round) is caught
	// and slashing evidence is generated.
	//
	// This is defense-in-depth: the production caller (FinalityTracker.
	// FinalizeBlock) already has its own double-sign detection at the
	// higher level via ft.voteHistory. The detector here protects future
	// callers that might use VoteCollector directly without the
	// FinalityTracker wrapper. nil means no detector → existing behavior
	// (no cross-block detection at this layer).
	doubleSignDetector *DoubleSignDetector
	// R30-IMPLEMENT (2026-07-27): Optional SlashingManager for submitting
	// double-sign evidence detected by doubleSignDetector. When set via
	// SetSlashingManager, AddVote forwards detected evidence to the
	// SlashingManager for penalty enforcement. nil means evidence is
	// queued in evidenceQueue (graceful degradation until a manager is
	// attached). Mirrors VotingManager.SetSlashingManager's drain pattern.
	slashingManager *SlashingManager
	// R30-IMPLEMENT (2026-07-27): Evidence queue for pending evidence when
	// slashingManager is unavailable. Drained by SetSlashingManager.
	// Bounded to MaxEvidenceQueue to prevent unbounded memory growth.
	evidenceQueue []*SlashingEvidence
}

// NewVoteCollector creates a new vote collector for a block
func NewVoteCollector(height uint64, round uint32, blockHash types.Hash, validatorMgr *ValidatorManager) *VoteCollector {
	return &VoteCollector{
		height:       height,
		round:        round,
		blockHash:    blockHash,
		votes:        make(map[types.Address]*Vote),
		validatorMgr: validatorMgr,
		totalStake:   validatorMgr.TotalStake(),
		votedStake:   big.NewInt(0),
	}
}

// SetDoubleSignDetector attaches a DoubleSignDetector to this VoteCollector.
// When set, AddVote will forward accepted votes to the detector for cross-block
// equivocation detection. Passing nil disables the detector (default state).
// R14-MED (2026-07-21): defense-in-depth so VoteCollector-based paths that
// bypass FinalityTracker still generate slashing evidence on double-sign.
func (vc *VoteCollector) SetDoubleSignDetector(d *DoubleSignDetector) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	vc.doubleSignDetector = d
}

// SetSlashingManager attaches a SlashingManager to this VoteCollector and
// drains any pending evidence that was queued before the manager was available.
//
// R30-IMPLEMENT (2026-07-27): Implements the test contract in
// cons_r15_l01_l03_test.go:29,33. Without this setter, the direct
// VoteCollector path detects double-sign (via doubleSignDetector) but never
// penalizes the offender — evidence is queued but never submitted.
//
// Mirrors VotingManager.SetSlashingManager's drain pattern (voting.go:798):
// set field → drain queue → submit each evidence to the SlashingManager.
// Submission happens OUTSIDE vc.mu to avoid potential lock-ordering issues
// with SlashingManager.SubmitEvidence (which acquires its own lock and may
// call back into ValidatorManager).
// audit-remediation: reviewed 2026-09-11 — wiring setter called once by the
// node assembler; not a stake-mutation surface. SubmitEvidence re-validates
// evidence and enforces penalty bounds independently.
func (vc *VoteCollector) SetSlashingManager(sm *SlashingManager) {
	vc.mu.Lock()
	vc.slashingManager = sm
	queued := vc.evidenceQueue
	vc.evidenceQueue = make([]*SlashingEvidence, 0)
	vc.mu.Unlock()

	if sm != nil && len(queued) > 0 {
		caller := getVotingSystemCaller()
		for _, evidence := range queued {
			// R34-CONS-P0-003 FIX: Pass evidence.Timestamp as blockTime for
			// deterministic slashing. Queued evidence already has Timestamp set;
			// using it prevents time.Now() fallback which causes jailUntil
			// divergence across nodes.
			var bt int64
			if evidence.Timestamp > 0 {
				bt = evidence.Timestamp
			}
			if _, err := sm.SubmitEvidence(evidence, caller, bt); err != nil {
				slashingLogger.Warnf("VoteCollector: failed to submit queued evidence to SlashingManager: %v", err)
			}
		}
		slashingLogger.Infof("VoteCollector: drained %d queued slashing evidence items after SetSlashingManager", len(queued))
	}
}

// queueEvidenceLocked adds evidence to the pending queue when slashingManager
// is unavailable. Caller MUST hold vc.mu (write) before calling this.
// R30-IMPLEMENT (2026-07-27): Mirrors VotingManager.queueEvidenceLocked.
func (vc *VoteCollector) queueEvidenceLocked(evidence *SlashingEvidence) {
	if evidence == nil {
		return
	}
	if len(vc.evidenceQueue) >= MaxEvidenceQueue {
		// Drop oldest evidence (FIFO) to bound memory.
		vc.evidenceQueue[0] = nil
		vc.evidenceQueue = vc.evidenceQueue[1:]
	}
	vc.evidenceQueue = append(vc.evidenceQueue, evidence)
}

// AddVote adds a vote to the collector
// CRITICAL FIX: Moved signature verification INSIDE the lock to prevent TOCTOU race condition
// Previously, validator info was retrieved and verified outside the lock, allowing
// a validator to be deactivated between verification and recording.
//
// R30-IMPLEMENT (2026-07-27): When DoubleSignDetector returns ErrDoubleSign,
// AddVote now submits evidence to slashingManager (if attached) and returns
// ErrDoubleSign to the caller. Previously the evidence was only logged and
// the caller saw nil — so the offender was never penalized through the
// VoteCollector path. The test contract in cons_r15_l01_l03_test.go:50
// requires AddVote to return ErrDoubleSign and SetSlashingManager to drive
// PermanentlySlashed=true.
func (vc *VoteCollector) AddVote(vote *Vote) error {
	if vote == nil {
		return ErrInvalidVote
	}

	// Verify vote is for correct block
	if vote.Height != vc.height || vote.Round != vc.round {
		return ErrBlockMismatch
	}
	if vote.BlockHash != vc.blockHash {
		return ErrBlockMismatch
	}

	// SECURITY FIX (L14-019): Early duplicate vote check BEFORE expensive
	// Dilithium signature verification. Without this, an attacker could spam
	// duplicate votes to force expensive crypto verification on each one,
	// causing a DoS. The duplicate check is repeated inside the write lock
	// below for race-safety; this early read-lock check just rejects the
	// common case without performing any crypto operations.
	vc.mu.RLock()
	_, alreadyVoted := vc.votes[vote.ValidatorAddr]
	vc.mu.RUnlock()
	if alreadyVoted {
		return ErrDuplicateVote
	}

	// CONS-R12-005 (2026-07-20) FIX: TOCTOU race window.
	//
	// Previously GetValidator + vote.Verify ran OUTSIDE vc.mu, then the
	// in-lock re-validation re-checked Active/PermanentlySlashed but did NOT
	// re-verify the signature. This created a race window where:
	//   1. Validator V is active with pubkey K1
	//   2. vote.Verify(K1) succeeds outside the lock
	//   3. V's key is rotated to K2 (or V is slashed/deactivated)
	//   4. The in-lock re-check passes because the read of Active/Slashed
	//      happens to land on a memory/visibility state where V is still
	//      active (Go memory model does not guarantee cross-goroutine
	//      visibility ordering without synchronization)
	//   5. V's vote is counted even though the signature was made for K1
	//      but V's current pubkey is K2
	//
	// Fix: fetch the validator's public key INSIDE the lock, then verify the
	// signature INSIDE the same lock using that just-fetched key. This
	// guarantees the verified key is identical to the key used for the
	// in-lock status check — the TOCTOU window is closed.
	//
	// Performance note: vc.mu is a per-block lock (VoteCollector is created
	// per block), not a global lock, so holding it during Dilithium3
	// verification does NOT serialize votes across different blocks.
	// Dilithium3 Verify is ~1ms, well within the 2s DefaultVoteTimeout.
	vc.mu.Lock()
	defer vc.mu.Unlock()

	// Re-check duplicate inside write lock (early RLock check was racy).
	if _, exists := vc.votes[vote.ValidatorAddr]; exists {
		return ErrDuplicateVote
	}

	// Fetch validator info INSIDE the lock. This is the authoritative
	// snapshot of the validator's state at the time the vote is recorded.
	validatorInfo, err := vc.validatorMgr.GetValidator(vote.ValidatorAddr)
	if err != nil {
		return ErrVoteFromNonValidator
	}
	if !validatorInfo.Active {
		return ErrVoteFromNonValidator
	}
	// CRITICAL FIX: Reject votes from permanently slashed validators.
	// SlashManager already marked them, but AddVote was not checking.
	if validatorInfo.PermanentlySlashed {
		return ErrValidatorSlashed
	}

	// Verify signature INSIDE the lock using the just-fetched public key.
	// This closes the TOCTOU window: the key used for verification is the
	// same key that the in-lock status check used, so it cannot be stale
	// by the time the vote is recorded.
	if !vote.Verify(validatorInfo.PublicKey) {
		return ErrInvalidVoteSignature
	}

	// R25-CR-1 FIX: Deep copy vote before storing to prevent external mutation
	// from corrupting evidence stored in SlashingEvidence.
	voteCopy := deepCopyVote(vote)

	// R14-MED (2026-07-21): Forward accepted vote to DoubleSignDetector if
	// configured. This catches cross-block equivocation (same validator
	// voting for DIFFERENT blocks at the same height/round) at the
	// VoteCollector layer, generating slashing evidence even when the
	// caller doesn't have its own higher-level detection (FinalityTracker
	// does, but other/future callers might not). We use the deep copy
	// (voteCopy) so the detector stores an immutable snapshot.
	//
	// R30-IMPLEMENT (2026-07-27): When the detector returns ErrDoubleSign,
	// we now (1) submit the evidence to slashingManager if attached
	// (otherwise queue it for later submission via SetSlashingManager),
	// and (2) return ErrDoubleSign to the caller. Previously the evidence
	// was only logged and the caller saw nil — so the offender was never
	// penalized through the VoteCollector path.
	//
	// CONS-R15-002 (2026-07-27): The detector check now runs BEFORE storing
	// the vote. Previously the vote was stored and stake counted BEFORE the
	// detector ran, so an equivocating vote was counted toward quorum even
	// when ErrDoubleSign was returned. Now the detector runs first; on
	// ErrDoubleSign we return early WITHOUT storing the vote or counting
	// its stake. This prevents tainted stake from helping reach finality.
	//
	// Submission to SlashingManager happens while holding vc.mu. This is
	// safe because SlashingManager.SubmitEvidence acquires its own lock
	// (sm.mu) and does NOT call back into VoteCollector — the only
	// lock-ordering concern is sm.mu → vm.mu (ValidatorManager), which is
	// the existing pattern used by VotingManager.recordAttestationVote
	// (see voting.go:918). VoteCollector does not participate in that
	// ordering, so holding vc.mu during SubmitEvidence is safe.
	//
	// R36-P3-9 NOTE (2026-07-30): WIRING GAP. The double-sign detection
	// branch below (vc.doubleSignDetector != nil) is currently dead code
	// in production. SetDoubleSignDetector is only invoked from unit
	// tests; production callers (FinalityTracker.AddFinalizationVotes at
	// finality.go:204, VotingManager.recordAttestationVote) construct
	// VoteCollector via NewVoteCollector without wiring the detector.
	// FinalityTracker relies on its own voteHistory-based detection
	// (finality.go:215-229) instead, which catches same-(height,round)
	// equivocation but does NOT cover the broader cross-block patterns
	// the detector would catch. This is defense-in-depth — the existing
	// paths still penalize equivocation, but the VoteCollector-side
	// detector remains an unused safety net until production wiring is
	// added in a future release.
	var pendingEvidence *SlashingEvidence
	var pendingSlashingMgr *SlashingManager
	if vc.doubleSignDetector != nil {
		ev, dsErr := vc.doubleSignDetector.CheckAndRecordVote(voteCopy)
		if dsErr != nil {
			if dsErr == ErrDoubleSign {
				// P3-LOG-01 FIX (R30, 2026-07-27): Use slashingLogger (module=consensus,
				// category=SECURITY) so SIEM can collect this double-sign event.
				slashingLogger.Error("VoteCollector: double-sign detected by detector",
					map[string]any{
						"validator": vote.ValidatorAddr.String(),
						"height":    vote.Height,
						"round":     vote.Round,
						"blockHash": vote.BlockHash.String(),
						"detection": "cross-block equivocation",
					})
				// R30-IMPLEMENT: Capture evidence for submission.
				// If slashingManager is set, submit synchronously; otherwise queue.
				if vc.slashingManager != nil && ev != nil {
					pendingEvidence = ev
					pendingSlashingMgr = vc.slashingManager
				} else if ev != nil {
					vc.queueEvidenceLocked(ev)
					// R30-IMPLEMENT: Set pendingEvidence so the post-block
					// check returns ErrDoubleSign to the caller. Without this,
					// the caller would see nil and not know equivocation was
					// detected — the offender would go unpenalized through the
					// VoteCollector path until SetSlashingManager is called.
					pendingEvidence = ev
				}
			}
			// For ErrDuplicateVote (same vote already recorded), no log —
			// this is expected when FinalityTracker also forwards the same
			// vote to its own detector path.
		}
	}

	// R30-IMPLEMENT: Submit evidence to SlashingManager (synchronously while
	// holding vc.mu — see safety note above). On failure, re-queue so
	// SetSlashingManager drain or a future retry can pick it up.
	// CONS-R15-002: Return ErrDoubleSign WITHOUT storing the vote — the
	// equivocating vote must NOT be counted toward quorum.
	if pendingEvidence != nil && pendingSlashingMgr != nil {
		// R34-CONS-P0-003 FIX: Pass evidence.Timestamp as blockTime for
		// deterministic slashing. The evidence Timestamp was set by
		// CheckAndRecordVote using consensus-derived time when available.
		var bt int64
		if pendingEvidence.Timestamp > 0 {
			bt = pendingEvidence.Timestamp
		}
		if _, submitErr := pendingSlashingMgr.SubmitEvidence(pendingEvidence, getVotingSystemCaller(), bt); submitErr != nil {
			vc.queueEvidenceLocked(pendingEvidence)
			slashingLogger.Warnf("VoteCollector: SubmitEvidence failed, evidence re-queued: %v", submitErr)
		}
		return ErrDoubleSign
	}

	if pendingEvidence != nil {
		// Evidence was queued (no slashingManager) — still return ErrDoubleSign
		// so the caller is informed of the equivocation.
		return ErrDoubleSign
	}

	// CONS-R15-002: Only store the vote if double-sign was NOT detected.
	// This is the critical fix: the equivocating vote must not be counted
	// toward quorum or stored in the votes map.
	vc.votes[vote.ValidatorAddr] = voteCopy
	vc.votedStake.Add(vc.votedStake, validatorInfo.Stake)

	return nil
}

// HasQuorum returns true if at least 2/3 of stake has voted
func (vc *VoteCollector) HasQuorum() bool {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	// CONS-R8-002 (R8 2026-07-19 FIX): Use >= instead of > to match the
	// Casper FFG requirement of "at least 2/3" (≥ ceil(2/3)). The previous
	// strict-greater-than comparison required > 2/3, which for small
	// validator sets (e.g. N=3 mainnet) made quorum unreachable: with
	// N=3, 3*voted > 2*3 = 6 requires voted > 2 → voted >= 3 (100%),
	// while Casper FFG only requires 2/3 (i.e. voted >= 2). This caused
	// the voting system to reject valid quorums that the finality system
	// accepted, producing consensus splits. The integer form 3*voted >=
	// 2*total is mathematically equivalent to voted >= ceil(2*total/3),
	// which is the correct Casper FFG threshold.
	//
	// Edge case: when totalStake == 0 (no validators registered), the
	// comparison 0 >= 0 would incorrectly return true. A validator set
	// with zero stake cannot reach consensus — there is nobody to vote.
	// Guard against this degenerate case explicitly. This also preserves
	// the behavior expected by tests that rely on FinalizeBlock returning
	// ErrInsufficientVotes when called with an empty validator set.
	if vc.totalStake.Sign() == 0 {
		return false
	}
	threshold := new(big.Int).Mul(vc.totalStake, big.NewInt(2))
	voted := new(big.Int).Mul(vc.votedStake, big.NewInt(3))

	return voted.Cmp(threshold) >= 0
}

// VoteCount returns the number of votes collected
func (vc *VoteCollector) VoteCount() int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return len(vc.votes)
}

// VotedStake returns the total stake that has voted
func (vc *VoteCollector) VotedStake() *big.Int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return new(big.Int).Set(vc.votedStake)
}

// TotalStake returns the total stake of all validators
// R47-CS-09 FIX: Acquire RLock for consistency with VotedStake().
func (vc *VoteCollector) TotalStake() *big.Int {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	return new(big.Int).Set(vc.totalStake)
}

// GetVotes returns all collected votes.
// audit-fix NEW-23: returns deep copies to prevent callers from mutating
// internal Signature byte slices shared with consensus state.
func (vc *VoteCollector) GetVotes() []*Vote {
	vc.mu.RLock()
	defer vc.mu.RUnlock()

	votes := make([]*Vote, 0, len(vc.votes))
	for _, v := range vc.votes {
		votes = append(votes, deepCopyVote(v))
	}
	return votes
}

// HasVoted returns true if the validator has already voted
func (vc *VoteCollector) HasVoted(addr types.Address) bool {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	_, exists := vc.votes[addr]
	return exists
}

// VoteSet represents a collection of votes for a specific height and round
type VoteSet struct {
	mu                 sync.RWMutex
	height             uint64
	round              uint32
	blockHash          types.Hash
	votes              map[types.Address]*Vote
	aggregated         *AggregatedSignature
	weight             *big.Int
	threshold          *big.Int // 2/3 total stake
	doubleSignDetector *DoubleSignDetector
}

// AggregatedSignature represents a BLS aggregated signature
type AggregatedSignature struct {
	Signature []byte          // Aggregated BLS signature
	Bitmap    []byte          // Bitmap indicating which validators signed
	Signers   []types.Address // List of signers for verification
}

// NewVoteSet creates a new vote set for a specific height and round
func NewVoteSet(height uint64, round uint32, blockHash types.Hash, totalStake *big.Int, dsDetector *DoubleSignDetector) *VoteSet {
	// CONS-R8-002 (R8 2026-07-19 FIX): Compute threshold as
	// ceil(2*totalStake/3) (round up) instead of floor. Combined with
	// HasQuorum's >= comparison, this gives the correct Casper FFG
	// "at least 2/3" semantics. For N=3: ceil(2*3/3) = 2, so weight
	// >= 2 reaches quorum (matches 3*voted >= 2*total). For N=6:
	// ceil(2*6/3) = 4, weight >= 4 reaches quorum.
	threshold := new(big.Int).Mul(totalStake, QuorumThresholdNumerator)
	threshold.Div(threshold, QuorumThresholdDenominator)
	// Add 1 when there is a remainder (i.e. 2*totalStake not divisible by 3)
	// to round up to the ceiling.
	product := new(big.Int).Mul(totalStake, QuorumThresholdNumerator)
	remainder := new(big.Int).Mod(product, QuorumThresholdDenominator)
	if remainder.Sign() != 0 {
		threshold.Add(threshold, big.NewInt(1))
	}

	return &VoteSet{
		height:             height,
		round:              round,
		blockHash:          blockHash,
		votes:              make(map[types.Address]*Vote),
		weight:             big.NewInt(0),
		threshold:          threshold,
		doubleSignDetector: dsDetector,
	}
}

// AddVote adds a vote to the vote set
// audit-fix R5-1: validates vote.BlockHash matches the VoteSet's target block
// to prevent votes for different blocks from being mixed into one quorum tally.
func (vs *VoteSet) AddVote(vote *Vote, stake *big.Int) error {
	if vote == nil {
		return ErrInvalidVote
	}

	vs.mu.Lock()
	defer vs.mu.Unlock()

	// audit-fix R5-1: reject votes targeting a different block.
	// Without this check, votes for block A and block B at the same
	// (height, round) would be mixed together, inflating quorum weight
	// and potentially finalizing a block without a true 2/3 majority.
	if vote.BlockHash != vs.blockHash {
		return ErrBlockMismatch
	}

	// Check for duplicate
	if _, exists := vs.votes[vote.ValidatorAddr]; exists {
		return ErrDuplicateVote
	}

	// CRITICAL FIX: Check for double-signing before recording vote
	if vs.doubleSignDetector != nil {
		if _, err := vs.doubleSignDetector.CheckAndRecordVote(vote); err != nil {
			return err
		}
	}

	// Add vote and update weight
	// R35-P0-04/P2-CONS-01 FIX: Deep copy the vote before storing to prevent
	// the caller (or another goroutine sharing the *Vote pointer) from
	// mutating the Signature backing array after AddVote returns. This
	// complements the DoubleSignDetector deep-copy fix (P0-04).
	vs.votes[vote.ValidatorAddr] = deepCopyVote(vote)
	vs.weight.Add(vs.weight, stake)

	return nil
}

// HasQuorum returns true if the vote set has reached quorum
func (vs *VoteSet) HasQuorum() bool {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	// CONS-R8-002 (R8 2026-07-19 FIX): Use >= to match Casper FFG "at
	// least 2/3" semantics. Combined with the ceil threshold in
	// NewVoteSet, this is equivalent to 3*weight >= 2*total. The previous
	// strict-greater-than required > 2/3, which made quorum unreachable
	// for N=3 mainnet (needed 3/3 votes) while finality accepted 2/3,
	// splitting consensus.
	//
	// Edge case: a threshold of 0 (created with zero total stake) must
	// NOT count as quorum. 0 >= 0 is true, but a vote set with no backing
	// stake cannot constitute consensus. Guard explicitly.
	if vs.threshold.Sign() == 0 {
		return false
	}
	return vs.weight.Cmp(vs.threshold) >= 0
}

// GetWeight returns the current voting weight
func (vs *VoteSet) GetWeight() *big.Int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	return new(big.Int).Set(vs.weight)
}

// GetVotes returns all votes in the set.
// audit-fix NEW-23: returns deep copies to prevent callers from mutating
// internal Signature byte slices shared with consensus state.
func (vs *VoteSet) GetVotes() []*Vote {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	votes := make([]*Vote, 0, len(vs.votes))
	for _, v := range vs.votes {
		votes = append(votes, deepCopyVote(v))
	}
	return votes
}

// SetAggregatedSignature sets the aggregated signature for this vote set
func (vs *VoteSet) SetAggregatedSignature(agg *AggregatedSignature) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	vs.aggregated = agg
}

// GetAggregatedSignature returns the aggregated signature
func (vs *VoteSet) GetAggregatedSignature() *AggregatedSignature {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	return vs.aggregated
}

// VotingManager manages vote collection and finality for multiple heights
//
// DATA FLOW (vote history synchronization):
// Three data stores track overlapping vote/attestation data:
//  1. VotingManager.voteSets — Vote-level authoritative source (quorum tracking)
//  2. DoubleSignDetector.voteHistory — Double-sign detection index (fed by VoteSet.AddVote)
//  3. QPOS.validatorAttestations — Attestation-level authoritative source (slashing detection)
//
// Synchronization rules:
//   - ProcessAttestation accepts → writes validatorAttestations + calls recordAttestationVote()
//   - VotingManager.AddVote accepts → writes voteSets/DoubleSignDetector + calls qpos.syncVoteToAttestations()
//   - This ensures all three stores stay consistent without merging data structures.
type VotingManager struct {
	mu         sync.RWMutex
	validators *ValidatorManager
	// audit-fix R9-1: index VoteSets by (height, round, blockHash) so that
	// votes for competing blocks at the same round are tracked independently.
	// Previously a single VoteSet per (height, round) was locked to the first
	// vote's BlockHash, allowing one malicious validator to "poison" a round
	// and prevent quorum for the legitimate block.
	voteSets           map[uint64]map[uint32]map[types.Hash]*VoteSet // height -> round -> blockHash -> VoteSet
	finalized          map[uint64]types.Hash                         // height -> finalized block hash
	timeout            time.Duration
	blsAggregator      *BLSAggregator
	doubleSignDetector *DoubleSignDetector
	slashingManager    *SlashingManager
	// CRITICAL FIX: Evidence queue for when slashingManager is unavailable
	evidenceQueue []*SlashingEvidence
	// qpos is a back-reference for syncing votes to QPOS.validatorAttestations.
	// Set via SetQPOS after both objects are constructed.
	qpos *QPOS
	// P1-T5 (2026-07-14): Optional blacklist check from MinistryDefense.
	// When set, AddVote rejects votes from blacklisted validators.
	blacklistCheck func(int, ...int64) bool
}

// NewVotingManager creates a new voting manager
func NewVotingManager(validators *ValidatorManager) *VotingManager {
	return &VotingManager{
		validators:         validators,
		voteSets:           make(map[uint64]map[uint32]map[types.Hash]*VoteSet),
		finalized:          make(map[uint64]types.Hash),
		timeout:            DefaultVoteTimeout,
		blsAggregator:      NewBLSAggregator(),
		doubleSignDetector: NewDoubleSignDetector(),
		evidenceQueue:      make([]*SlashingEvidence, 0), // CRITICAL FIX: initialize evidence queue
	}
}

// SetQPOS sets the back-reference to QPOS for syncing votes to validatorAttestations.
// DATA FLOW: When VotingManager.AddVote accepts a vote, it calls qpos.syncVoteToAttestations()
// to keep QPOS.validatorAttestations in sync with voteSets.
func (vm *VotingManager) SetQPOS(q *QPOS) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.qpos = q
}

// SetSlashingManager sets the slashing manager and drains any pending evidence
// that was queued before the slashing manager was available.
//
// P0-4 (2026-07-13): Without this setter, vm.slashingManager is always nil,
// and double-sign evidence detected by DoubleSignDetector is queued but never
// submitted to SlashingManager — effectively lost. This method mirrors
// QPOS.SetSlashingManager's drain pattern.
// audit-remediation: reviewed 2026-09-11 — wiring setter called once by the
// node assembler; not a stake-mutation surface. SubmitEvidence re-validates
// evidence and enforces penalty bounds independently.
func (vm *VotingManager) SetSlashingManager(sm *SlashingManager) {
	vm.mu.Lock()
	vm.slashingManager = sm
	queued := vm.evidenceQueue
	vm.evidenceQueue = make([]*SlashingEvidence, 0)
	vm.mu.Unlock()

	if sm != nil && len(queued) > 0 {
		caller := getVotingSystemCaller()
		for _, evidence := range queued {
			// R34-CONS-P0-003 FIX: Pass evidence.Timestamp as blockTime for
			// deterministic slashing. Queued evidence already has Timestamp set;
			// using it prevents time.Now() fallback which causes jailUntil
			// divergence across nodes.
			var bt int64
			if evidence.Timestamp > 0 {
				bt = evidence.Timestamp
			}
			if _, err := sm.SubmitEvidence(evidence, caller, bt); err != nil {
				qposAdvLogger.Warnf("VotingManager: failed to submit queued evidence to SlashingManager: %v", err)
			}
		}
		qposAdvLogger.Infof("VotingManager: drained %d queued slashing evidence items after SetSlashingManager", len(queued))
	}
}

// SetBlacklistCheck sets the MinistryDefense blacklist check function.
// P1-T5 (2026-07-14): When set, AddVote rejects votes from blacklisted
// validators before signature verification, saving expensive Dilithium
// crypto operations and enforcing governance decisions.
func (vm *VotingManager) SetBlacklistCheck(fn func(int, ...int64) bool) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.blacklistCheck = fn
}

// isBlacklisted checks if a validator address is on the MinistryDefense blacklist.
// P1-T5 (2026-07-14): Reads blacklistCheck and qpos ref under vm.mu.RLock,
// then releases the lock before calling qpos.GetValidatorSet() to avoid
// AB-BA deadlock with q.mu → vm.mu ordering in qpos_finality.go.
func (vm *VotingManager) isBlacklisted(addr types.Address, height uint64) bool {
	vm.mu.RLock()
	check := vm.blacklistCheck
	qposRef := vm.qpos
	vm.mu.RUnlock()

	if check == nil || qposRef == nil {
		return false
	}

	vs := qposRef.GetValidatorSet()
	if vs == nil {
		return false
	}
	idx := vs.GetValidatorIndex(addr)
	if idx < 0 {
		return false
	}

	// Use height as slot for deterministic block time (height == slot in this chain).
	blockTime := GetSlotStartTime(height).Unix()
	return check(idx, blockTime)
}

func (vm *VotingManager) syncFinalityFromQPOS(justifiedEpoch, finalizedEpoch uint64, justifiedRoot, finalizedRoot types.Hash) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if finalizedEpoch > 0 && finalizedRoot != (types.Hash{}) {
		height := EpochStartSlot(finalizedEpoch) + SlotsPerEpoch - 1
		vm.finalized[height] = finalizedRoot
	}
}

// recordAttestationVote records a vote derived from an accepted attestation.
// Called by QPOS.ProcessAttestation after the attestation passes all validation
// (including signature verification), so this method skips crypto verification
// to avoid redundant expensive Dilithium operations.
// DATA FLOW: ProcessAttestation → validatorAttestations (already written) → recordAttestationVote → voteSets + DoubleSignDetector
func (vm *VotingManager) recordAttestationVote(vote *Vote, stake *big.Int) error {
	// R7-P3 FIX: recover prevents a panic in vote recording from crashing the
	// node. This method runs as a goroutine (go vm.recordAttestationVote) from
	// ProcessAttestation's defer, so a panic here would be unrecoverable without this.
	defer func() {
		if r := recover(); r != nil {
			qposAdvLogger.Errorf("panic in recordAttestationVote: %v", r)
		}
	}()
	if vote == nil {
		return nil
	}

	vm.mu.Lock()

	if _, exists := vm.voteSets[vote.Height]; !exists {
		vm.voteSets[vote.Height] = make(map[uint32]map[types.Hash]*VoteSet)
	}
	if _, exists := vm.voteSets[vote.Height][vote.Round]; !exists {
		vm.voteSets[vote.Height][vote.Round] = make(map[types.Hash]*VoteSet)
	}
	if _, exists := vm.voteSets[vote.Height][vote.Round][vote.BlockHash]; !exists {
		totalStake := vm.validators.TotalStake()
		vm.voteSets[vote.Height][vote.Round][vote.BlockHash] = NewVoteSet(
			vote.Height, vote.Round, vote.BlockHash, totalStake, vm.doubleSignDetector,
		)
	}

	voteSet := vm.voteSets[vote.Height][vote.Round][vote.BlockHash]
	// AUDIT (2026) HIGH-03: Capture double-sign evidence BEFORE releasing vm.mu.
	// SubmitEvidence acquires q.mu (via GetValidatorSet); calling it while holding
	// vm.mu creates AB-BA deadlock with the q.mu→vm.mu order in
	// syncFinalityFromQPOS. Submit OUTSIDE the lock.
	var pendingEvidence *SlashingEvidence
	var slashingMgr *SlashingManager
	if err := voteSet.AddVote(vote, stake); err != nil {
		if errors.Is(err, ErrDoubleSign) {
			pendingEvidence = vm.doubleSignDetector.GetLatestEvidence()
			slashingMgr = vm.slashingManager
		}
	}
	// Capture qpos reference before releasing vm.mu for blockTime lookup.
	qposRef := vm.qpos
	vm.mu.Unlock()

	// Submit evidence OUTSIDE vm.mu to break AB-BA deadlock with q.mu.
	if pendingEvidence != nil {
		if slashingMgr == nil {
			vm.queueEvidence(pendingEvidence)
			return nil
		}
		// R34-CONS-P0-003 FIX: Pass deterministic blockTime for SubmitEvidence.
		// Use qposRef.GetLastKnownBlockTime() when available, otherwise fall back
		// to pendingEvidence.Timestamp (set by DoubleSignDetector). Prevents
		// non-deterministic jailUntil divergence across nodes.
		var submitBlockTime int64
		if qposRef != nil {
			submitBlockTime = qposRef.GetLastKnownBlockTime()
		}
		if submitBlockTime == 0 && pendingEvidence.Timestamp > 0 {
			submitBlockTime = pendingEvidence.Timestamp
		}
		if _, submitErr := slashingMgr.SubmitEvidence(pendingEvidence, getVotingSystemCaller(), submitBlockTime); submitErr != nil {
			vm.queueEvidence(pendingEvidence)
		}
	}
	return nil
}

// SetTimeout sets the vote collection timeout
func (vm *VotingManager) SetTimeout(timeout time.Duration) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	// audit-fix MEDIUM: validate timeout to prevent misconfiguration.
	// A zero or negative timeout would cause time.NewTimer to panic or
	// fire immediately, disrupting consensus vote collection.
	if timeout <= 0 {
		// Fall back to default instead of accepting invalid value
		vm.timeout = DefaultVoteTimeout
		return
	}
	vm.timeout = timeout
}

// queueEvidence adds evidence to the queue when slashingManager is unavailable.
// CRITICAL FIX: Prevents evidence loss when slashingManager is not initialized.
func (vm *VotingManager) queueEvidence(evidence *SlashingEvidence) {
	if evidence == nil {
		return
	}
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.queueEvidenceLocked(evidence)
}

// queueEvidenceLocked queues evidence WITHOUT acquiring the lock.
// Caller MUST hold vm.mu before calling this.
// SECURITY FIX (R4-P0-1): queueEvidence acquires vm.mu.Lock(), but it was
// called from recordAttestationVote and AddVote which already hold vm.mu.
// Go's sync.Mutex is not reentrant, causing permanent self-deadlock.
func (vm *VotingManager) queueEvidenceLocked(evidence *SlashingEvidence) {
	if evidence == nil {
		return
	}
	// Limit queue size to prevent unbounded memory growth
	if len(vm.evidenceQueue) >= MaxEvidenceQueue {
		// P3-3: Alert on queue overflow — evidence is being dropped.
		qposAdvLogger.Errorf("VotingManager evidence queue overflow (%d entries, max %d) — oldest evidence dropped, validator=%s reason=%s",
			len(vm.evidenceQueue), MaxEvidenceQueue, evidence.ValidatorAddr.String(), evidence.Reason)
		vm.evidenceQueue[0] = nil
		vm.evidenceQueue = vm.evidenceQueue[1:]
	}
	vm.evidenceQueue = append(vm.evidenceQueue, evidence)

	// P3-3: Warn when queue is > 80% full (approaching overflow).
	if len(vm.evidenceQueue) >= MaxEvidenceQueue*4/5 {
		qposAdvLogger.Warnf("VotingManager evidence queue at %d/%d (%.0f%% capacity) — SlashingManager may be slow",
			len(vm.evidenceQueue), MaxEvidenceQueue, float64(len(vm.evidenceQueue))/float64(MaxEvidenceQueue)*100)
	}
}

// GetQueuedEvidence returns and clears the queued evidence.
// Call this after slashingManager is initialized to submit pending evidence.
func (vm *VotingManager) GetQueuedEvidence() []*SlashingEvidence {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	queue := vm.evidenceQueue
	vm.evidenceQueue = make([]*SlashingEvidence, 0)
	return queue
}

// AddVote adds a vote and returns true if quorum is reached.
// R26-H1 FIX: Signature verified outside lock to avoid holding mutex
// during expensive Dilithium crypto. Validator status re-checked inside lock.
// DATA FLOW: On success, syncs the vote to QPOS.validatorAttestations (if qpos is set)
// to keep the Attestation-level data source consistent.
//
// CONS-R9-M TOCTOU FIX (2026-07-19): Previously, the PublicKey used for
// signature verification (outside the lock) was NOT re-checked inside the
// lock. If the validator's PublicKey was rotated between the outside-lock
// GetValidator call and the inside-lock re-check, the signature had been
// verified against a STALE key — accepting a vote signed with an old key
// as if it were signed with the current key. Now: capture the bytes of the
// PublicKey used for verification, and inside the lock compare against the
// current PublicKey. If they differ, re-verify the signature against the
// current key (rejecting if verification fails). This closes the TOCTOU
// without re-doing the expensive Dilithium verification on the common path
// (key rotation is rare, so the fast path is just a byte comparison).
func (vm *VotingManager) AddVote(vote *Vote) (bool, error) {
	if vote == nil {
		return false, ErrInvalidVote
	}

	// Verify signature OUTSIDE lock to avoid holding lock during expensive Dilithium crypto.
	validatorInfo, err := vm.validators.GetValidator(vote.ValidatorAddr)
	if err != nil {
		return false, ErrVoteFromNonValidator
	}
	if !validatorInfo.Active {
		return false, ErrVoteFromNonValidator
	}
	// CRITICAL FIX: Reject votes from permanently slashed validators.
	if validatorInfo.PermanentlySlashed {
		return false, ErrValidatorSlashed
	}

	// P1-T5 (2026-07-14): Reject votes from MinistryDefense-blacklisted validators.
	// Checked before signature verification to save expensive Dilithium crypto.
	if vm.isBlacklisted(vote.ValidatorAddr, vote.Height) {
		return false, ErrValidatorBlacklisted
	}

	if !vote.Verify(validatorInfo.PublicKey) {
		return false, ErrInvalidVoteSignature
	}

	// CONS-R9-M FIX: Capture the PublicKey bytes used for signature
	// verification so we can detect key rotation inside the lock.
	verifiedPubKeyBytes := validatorInfo.PublicKey.Bytes()

	vm.mu.Lock()

	// Re-validate validator status inside lock to prevent TOCTOU after crypto ops.
	validatorInfo, err = vm.validators.GetValidator(vote.ValidatorAddr)
	if err != nil || !validatorInfo.Active {
		vm.mu.Unlock()
		return false, ErrVoteFromNonValidator
	}
	// Re-check slashed status inside lock
	if validatorInfo.PermanentlySlashed {
		vm.mu.Unlock()
		return false, ErrValidatorSlashed
	}
	// CONS-R9-M FIX: Detect PublicKey rotation between the outside-lock
	// signature verification and the inside-lock re-check. If the
	// PublicKey changed, the signature was verified against a STALE key
	// and may no longer be valid for the current key. Re-verify against
	// the current key (the expensive Dilithium path runs only on key
	// rotation, which is rare). If re-verification fails, reject the vote.
	currentPubKeyBytes := validatorInfo.PublicKey.Bytes()
	if !bytes.Equal(currentPubKeyBytes, verifiedPubKeyBytes) {
		// Key was rotated between the outside-lock check and the inside-lock
		// check. The signature was verified against the OLD key. Re-verify
		// against the CURRENT key while holding the lock (safe — we are
		// already inside vm.mu and vote.Verify does not acquire any other
		// lock that would create a deadlock).
		if !vote.Verify(validatorInfo.PublicKey) {
			vm.mu.Unlock()
			return false, ErrInvalidVoteSignature
		}
	}
	// P1-T5 NOTE: Blacklist is NOT re-checked inside vm.mu because
	// isBlacklisted calls qpos.GetValidatorSet() (acquires q.mu.RLock),
	// and qpos_finality.go acquires vm.mu while holding q.mu — re-checking
	// here would create an AB-BA deadlock. The blacklist is time-based
	// (not transaction-state-based), so TOCTOU risk is negligible.

	// audit-fix R9-1: get or create vote set for this height/round/blockHash.
	// Each distinct block hash gets its own VoteSet so that a malicious
	// validator voting for a fake block cannot prevent quorum for the real one.
	if _, exists := vm.voteSets[vote.Height]; !exists {
		vm.voteSets[vote.Height] = make(map[uint32]map[types.Hash]*VoteSet)
	}

	if _, exists := vm.voteSets[vote.Height][vote.Round]; !exists {
		vm.voteSets[vote.Height][vote.Round] = make(map[types.Hash]*VoteSet)
	}

	if _, exists := vm.voteSets[vote.Height][vote.Round][vote.BlockHash]; !exists {
		totalStake := vm.validators.TotalStake()
		vm.voteSets[vote.Height][vote.Round][vote.BlockHash] = NewVoteSet(
			vote.Height, vote.Round, vote.BlockHash, totalStake, vm.doubleSignDetector,
		)
	}

	voteSet := vm.voteSets[vote.Height][vote.Round][vote.BlockHash]
	// AUDIT (2026) HIGH-03: Capture double-sign evidence BEFORE releasing vm.mu.
	// SubmitEvidence acquires q.mu (via GetValidatorSet); calling it while
	// holding vm.mu creates AB-BA deadlock with the q.mu→vm.mu order in
	// syncFinalityFromQPOS. Submit OUTSIDE the lock.
	var pendingEvidence *SlashingEvidence
	var slashingMgr *SlashingManager
	var addVoteErr error
	if err := voteSet.AddVote(vote, validatorInfo.Stake); err != nil {
		addVoteErr = err
		if errors.Is(err, ErrDoubleSign) {
			pendingEvidence = vm.doubleSignDetector.GetLatestEvidence()
			slashingMgr = vm.slashingManager
		}
	}

	quorumReached := false
	if addVoteErr == nil {
		quorumReached = voteSet.HasQuorum()
	}

	// Capture qpos reference before releasing vm.mu
	qposRef := vm.qpos

	vm.mu.Unlock()

	// Submit evidence OUTSIDE vm.mu to break AB-BA deadlock with q.mu.
	if pendingEvidence != nil {
		if slashingMgr == nil {
			vm.queueEvidence(pendingEvidence)
			return false, fmt.Errorf("%w: slashingManager not initialized, evidence queued, vote blocked", ErrDoubleSign)
		}
		// R34-CONS-P0-003 FIX: Pass deterministic blockTime for SubmitEvidence.
		// Use qposRef.GetLastKnownBlockTime() when available, otherwise fall back
		// to pendingEvidence.Timestamp (set by DoubleSignDetector). Prevents
		// non-deterministic jailUntil divergence across nodes.
		var submitBlockTime int64
		if qposRef != nil {
			submitBlockTime = qposRef.GetLastKnownBlockTime()
		}
		if submitBlockTime == 0 && pendingEvidence.Timestamp > 0 {
			submitBlockTime = pendingEvidence.Timestamp
		}
		if _, submitErr := slashingMgr.SubmitEvidence(pendingEvidence, getVotingSystemCaller(), submitBlockTime); submitErr != nil {
			vm.queueEvidence(pendingEvidence)
			return false, fmt.Errorf("failed to submit double-sign evidence (queued, vote blocked): %w", submitErr)
		}
	}

	if addVoteErr != nil {
		return false, addVoteErr
	}

	// DATA FLOW SYNC: Sync accepted vote to QPOS.validatorAttestations.
	// This must happen AFTER releasing vm.mu to avoid deadlock:
	// ProcessAttestation holds q.mu → calls recordAttestationVote (acquires vm.mu)
	// AddVote holds vm.mu → calls syncVoteToAttestations (acquires q.mu)
	// Releasing vm.mu first breaks the potential cycle.
	if qposRef != nil && vote.Type == VoteTypeAttestation {
		validatorIndex := vm.findValidatorIndex(vote.ValidatorAddr)
		if validatorIndex >= 0 {
			qposRef.syncVoteToAttestations(vote, validatorIndex)
		}
	}

	return quorumReached, nil
}

// findValidatorIndex finds the validator index for a given address.
// Returns -1 if not found. Used for syncing votes to QPOS.validatorAttestations.
func (vm *VotingManager) findValidatorIndex(addr types.Address) int {
	if vm.qpos == nil {
		return -1
	}
	vm.qpos.mu.RLock()
	defer vm.qpos.mu.RUnlock()
	validators := vm.qpos.validators.Validators()
	for i, v := range validators {
		if v.Address == addr {
			return i
		}
	}
	return -1
}

// HasQuorum checks if quorum is reached for a specific height and round.
// audit-fix R9-1: checks ALL block-specific VoteSets at that round.
func (vm *VotingManager) HasQuorum(height uint64, round uint32) bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if rounds, exists := vm.voteSets[height]; exists {
		if blockSets, exists := rounds[round]; exists {
			for _, voteSet := range blockSets {
				if voteSet.HasQuorum() {
					return true
				}
			}
		}
	}
	return false
}

// Finalize marks a block as finalized
// audit-fix HIGH: Added rollback protection — reject finalizing blocks at heights
// below an already-finalized height. Without this check, an attacker who can call
// Finalize could mark an older block as finalized, potentially causing chain reorgs
// and double-spend attacks. Also rejects empty block hashes.
func (vm *VotingManager) Finalize(height uint64, blockHash types.Hash) error {
	// audit-fix HIGH: Reject empty block hash — finalizing an empty hash would
	// corrupt consensus state and allow trivial finalization of non-existent blocks.
	if blockHash == (types.Hash{}) {
		return fmt.Errorf("cannot finalize empty block hash at height %d", height)
	}

	vm.mu.Lock()

	if _, exists := vm.finalized[height]; exists {
		vm.mu.Unlock()
		return ErrAlreadyFinalized
	}

	// audit-fix HIGH: Rollback protection — find the highest finalized height
	// and reject finalization at a lower height. This prevents an attacker from
	// finalizing an older block to override the canonical chain.
	for finalizedHeight := range vm.finalized {
		if finalizedHeight > height {
			vm.mu.Unlock()
			return fmt.Errorf("%w: cannot finalize height %d, already finalized at higher height %d",
				ErrAlreadyFinalized, height, finalizedHeight)
		}
	}

	vm.finalized[height] = blockHash
	vm.mu.Unlock()

	// CONS-R10-003 (2026-07-19) FIX: Removed the
	// `qposRef.syncFinalityFromVM(height, blockHash)` call. The
	// VotingManager is NOT an authoritative finality source — it is a
	// vote-aggregation layer. QPOS.tryUpdateFinality (driven by
	// ProcessAttestation, which enforces Casper FFG 2/3 supermajority) is
	// the sole authoritative finality path, and it propagates state DOWN
	// to the VotingManager via syncFinalityFromQPOS. Permitting the
	// reverse direction (VM → QPOS) created a second finality path that
	// bypassed the 2/3 weight check, violating accountable safety.
	//
	// VotingManager.Finalize now only updates the local `finalized` map
	// (used by IsFinalized/GetFinalizedHash queries). It must not be used
	// as a production finality trigger — callers should rely on the
	// canonical attestation path instead. The method is retained only for
	// backward compatibility with existing tests and external read-only
	// finality queries; it has no production caller.
	return nil
}

// IsFinalized checks if a height is finalized
func (vm *VotingManager) IsFinalized(height uint64) bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	_, exists := vm.finalized[height]
	return exists
}

// GetFinalizedHash returns the finalized block hash for a height
func (vm *VotingManager) GetFinalizedHash(height uint64) (types.Hash, bool) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	hash, exists := vm.finalized[height]
	return hash, exists
}

// GetVoteSet returns the vote set for a specific height and round.
// audit-fix R9-1: returns the VoteSet that reached quorum, or the one with
// the highest accumulated weight if no quorum yet.
func (vm *VotingManager) GetVoteSet(height uint64, round uint32) *VoteSet {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if rounds, exists := vm.voteSets[height]; exists {
		if blockSets, exists := rounds[round]; exists {
			var best *VoteSet
			for _, vs := range blockSets {
				if vs.HasQuorum() {
					return vs
				}
				if best == nil || vs.GetWeight().Cmp(best.GetWeight()) > 0 {
					best = vs
				}
			}
			return best
		}
	}
	return nil
}

// AggregateSignatures aggregates all signatures in a vote set using BLS
// R26-H2 FIX: Get votes inside lock to prevent concurrent modification.
// Previously, lock was released before GetVotes() call, allowing race with AddVote.
func (vm *VotingManager) AggregateSignatures(height uint64, round uint32) (*AggregatedSignature, error) {
	vm.mu.RLock()
	var voteSet *VoteSet
	if rounds, exists := vm.voteSets[height]; exists {
		if blockSets, exists := rounds[round]; exists {
			for _, vs := range blockSets {
				if vs.HasQuorum() {
					voteSet = vs
					break
				}
			}
		}
	}

	if voteSet == nil {
		vm.mu.RUnlock()
		return nil, ErrInvalidVote
	}

	// R26-H2 FIX: Get votes while holding lock to prevent concurrent modification
	votes := voteSet.GetVotes()
	if len(votes) == 0 {
		vm.mu.RUnlock()
		return nil, ErrInvalidVote
	}

	// Collect signatures and signers while still holding lock
	signatures := make([][]byte, len(votes))
	signers := make([]types.Address, len(votes))

	for i, vote := range votes {
		signatures[i] = vote.Signature
		signers[i] = vote.ValidatorAddr
	}
	vm.mu.RUnlock()

	// AUDIT (2026) CRND-08: Look up public keys and compute the vote
	// message so the aggregate commitment can bind to them. All votes in a
	// vote set share the same blockHash/height/round, so we derive the message
	// from the first vote.
	publicKeys := make([]*crypto.PublicKey, len(signers))
	for i, signer := range signers {
		pubKey, err := vm.validators.GetPublicKey(signer)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key for signer %s: %w", signer.String(), err)
		}
		publicKeys[i] = pubKey
	}
	message := votes[0].VoteMessage()

	// Aggregate using BLS (no lock needed - using copied data)
	aggregatedSig, err := vm.blsAggregator.Aggregate(signatures, publicKeys, message)
	if err != nil {
		return nil, err
	}

	// Create bitmap
	bitmap := vm.createSignerBitmap(signers)

	agg := &AggregatedSignature{
		Signature: aggregatedSig,
		Bitmap:    bitmap,
		Signers:   signers,
	}

	// Store aggregated signature
	voteSet.SetAggregatedSignature(agg)

	return agg, nil
}

// createSignerBitmap creates a bitmap indicating which validators signed
func (vm *VotingManager) createSignerBitmap(signers []types.Address) []byte {
	// Get all active validators
	validators := vm.validators.GetActiveValidators()

	// Create bitmap (1 bit per validator)
	bitmapSize := (len(validators) + 7) / 8
	bitmap := make([]byte, bitmapSize)

	// Create address to index map
	addrToIdx := make(map[types.Address]int)
	for i, v := range validators {
		addrToIdx[v.Address] = i
	}

	// Set bits for signers
	for _, signer := range signers {
		if idx, exists := addrToIdx[signer]; exists {
			byteIdx := idx / 8
			bitIdx := uint(idx % 8) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
			bitmap[byteIdx] |= (1 << bitIdx)
		}
	}

	return bitmap
}

// VerifyAggregatedSignature verifies an aggregated signature
func (vm *VotingManager) VerifyAggregatedSignature(height uint64, round uint32, blockHash types.Hash, agg *AggregatedSignature) bool {
	if agg == nil || len(agg.Signature) == 0 {
		return false
	}

	// Collect public keys for signers
	publicKeys := make([]*crypto.PublicKey, 0, len(agg.Signers))
	for _, signer := range agg.Signers {
		pubKey, err := vm.validators.GetPublicKey(signer)
		if err != nil {
			return false
		}
		publicKeys = append(publicKeys, pubKey)
	}

	// Create the message that was signed
	vote := &Vote{
		Type:      VoteTypePrecommit,
		Height:    height,
		Round:     round,
		BlockHash: blockHash,
	}
	message := vote.VoteMessage()

	// Verify aggregated signature
	return vm.blsAggregator.VerifyAggregate(publicKeys, message, agg.Signature)
}

// CollectVotesWithTimeout collects votes until quorum or timeout
func (vm *VotingManager) CollectVotesWithTimeout(height uint64, round uint32, voteChan <-chan *Vote) (bool, error) {
	// audit-fix MEDIUM: read timeout under mutex to prevent data race with SetTimeout.
	// Previously vm.timeout was read without holding the lock, causing a data race
	// if SetTimeout was called concurrently.
	vm.mu.RLock()
	timeout := vm.timeout
	vm.mu.RUnlock()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case vote := <-voteChan:
			if vote == nil {
				continue
			}
			quorumReached, err := vm.AddVote(vote)
			if err != nil {
				// Log error but continue collecting
				continue
			}
			if quorumReached {
				return true, nil
			}
		case <-timer.C:
			// Check if we have quorum before returning timeout
			if vm.HasQuorum(height, round) {
				return true, nil
			}
			return false, ErrVoteTimeout
		}
	}
}

// PruneOldVotes removes vote sets and finalized entries older than the given height
func (vm *VotingManager) PruneOldVotes(keepAbove uint64) int {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	pruned := 0
	for height := range vm.voteSets {
		if height < keepAbove {
			delete(vm.voteSets, height)
			pruned++
		}
	}

	// audit-fix R9-L3: prune finalized map to prevent unbounded memory growth.
	for height := range vm.finalized {
		if height < keepAbove {
			delete(vm.finalized, height)
		}
	}

	return pruned
}

// GetVotingStats returns statistics about voting
func (vm *VotingManager) GetVotingStats(height uint64, round uint32) *VotingStats {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	stats := &VotingStats{
		Height:     height,
		Round:      round,
		TotalStake: vm.validators.TotalStake(),
		VotedStake: big.NewInt(0),
		VoteCount:  0,
		HasQuorum:  false,
	}

	// audit-fix R9-1: find the best VoteSet (quorum or highest weight) among
	// competing blocks at this (height, round).
	if rounds, exists := vm.voteSets[height]; exists {
		if blockSets, exists := rounds[round]; exists {
			var best *VoteSet
			for _, vs := range blockSets {
				if vs.HasQuorum() {
					best = vs
					break
				}
				if best == nil || vs.GetWeight().Cmp(best.GetWeight()) > 0 {
					best = vs
				}
			}
			if best != nil {
				stats.VotedStake = best.GetWeight()
				// audit-fix R4-M1: access votes count through VoteSet lock to
				// prevent data race with concurrent AddVote.
				best.mu.RLock()
				stats.VoteCount = len(best.votes)
				best.mu.RUnlock()
				stats.HasQuorum = best.HasQuorum()
			}
		}
	}

	return stats
}

// VotingStats contains statistics about voting progress
type VotingStats struct {
	Height     uint64
	Round      uint32
	TotalStake *big.Int
	VotedStake *big.Int
	VoteCount  int
	HasQuorum  bool
}

// audit-fix NEW-2: maximum entries in DoubleSignDetector.voteHistory to prevent
// unbounded memory growth under sustained double-sign attack.
const maxDoubleSignVoteHistory = 100000

// audit-fix R3-1: maximum evidence entries in DoubleSignDetector to prevent
// unbounded memory growth from accumulated double-sign evidence.
// P0-NEW-2 FIX: Reduced from 10000 to 1000, evict 50% instead of 10%
// to prevent memory exhaustion attacks where attacker floods with evidence
// faster than legitimate evidence can be processed.
const maxDoubleSignEvidence = 1000

// DoubleSignDetector detects and generates slashing evidence for double-signing
type DoubleSignDetector struct {
	mu          sync.RWMutex
	voteHistory map[types.Address]map[uint64]map[uint32]*Vote // addr -> height -> round -> vote
	voteCount   int                                           // audit-fix NEW-2: track total entries for cap enforcement
	evidence    []*SlashingEvidence
}

// NewDoubleSignDetector creates a new double-sign detector
func NewDoubleSignDetector() *DoubleSignDetector {
	return &DoubleSignDetector{
		voteHistory: make(map[types.Address]map[uint64]map[uint32]*Vote),
		evidence:    make([]*SlashingEvidence, 0),
	}
}

// CheckAndRecordVote checks for double-signing and records the vote.
// If double-signing is detected, it generates slashing evidence.
// slashing evidence generation implemented
// R4-C1 FIX (2026-07-06): Added variadic blockTime for deterministic evidence timestamp.
func (d *DoubleSignDetector) CheckAndRecordVote(vote *Vote, blockTime ...int64) (*SlashingEvidence, error) {
	if vote == nil {
		return nil, ErrInvalidVote
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	addr := vote.ValidatorAddr
	height := vote.Height
	round := vote.Round

	// Initialize maps if needed
	if _, exists := d.voteHistory[addr]; !exists {
		d.voteHistory[addr] = make(map[uint64]map[uint32]*Vote)
	}
	if _, exists := d.voteHistory[addr][height]; !exists {
		d.voteHistory[addr][height] = make(map[uint32]*Vote)
	}

	// Check for existing vote at same height/round
	if existingVote, exists := d.voteHistory[addr][height][round]; exists {
		// Check if it's a different block hash (double-signing)
		if existingVote.BlockHash != vote.BlockHash {
			// Generate slashing evidence
			// C-5 FIX: Deep copy votes to prevent evidence corruption
			// R4-C1 FIX: Use deterministic blockTime when available for evidence timestamp
			//
			// R36-P3-11 NOTE (2026-07-30): When blockTime is not provided
			// (the VoteCollector.CheckAndRecordVote path that has no
			// consensus-derived time), evTimestamp falls back to
			// wall-clock time.Now().UTC().Unix(). Two nodes independently
			// observing the same double-sign will therefore record
			// different Timestamp values. This does NOT affect consensus
			// safety: Timestamp is metadata used for log ordering and
			// evidence TTL (ClearEvidenceOlderThan), not for slashing
			// conviction (which keys on (ValidatorAddr, Height, Round)).
			// The FinalityTracker path (finality.go:226-228) supplies
			// deterministic blockTime, so production evidence uses
			// consensus time. The wall-clock fallback only affects the
			// detector's test-only direct-invocation path.
			var evTimestamp int64
			if len(blockTime) > 0 && blockTime[0] > 0 {
				evTimestamp = blockTime[0]
			} else {
				evTimestamp = time.Now().UTC().Unix()
			}
			evidence := &SlashingEvidence{
				Reason:        SlashingReasonDoubleSigning,
				ValidatorAddr: addr,
				Height:        height,
				Vote1:         deepCopyVote(existingVote),
				Vote2:         deepCopyVote(vote),
				Timestamp:     evTimestamp,
			}
			d.evidence = append(d.evidence, evidence)
			// audit-fix R3-1: cap evidence slice to prevent unbounded growth
			// P0-NEW-2 FIX: Changed eviction from 10% to 50% to prevent memory exhaustion
			if len(d.evidence) > maxDoubleSignEvidence {
				evictCount := maxDoubleSignEvidence / 2 // evict 50% instead of 10%
				d.evidence = d.evidence[evictCount:]
			}
			return evidence, ErrDoubleSign
		}
		// Same vote, no issue
		return nil, ErrDuplicateVote
	}

	// Record the vote
	// R35-P0-04 FIX: Use deepCopyVote instead of shallow struct copy.
	// The previous "Fix 3" optimization assumed the caller's Signature
	// slice was already an independent copy, but this is NOT guaranteed:
	//   - VoteSet.AddVote (voting.go:802) stores the original *Vote pointer
	//     directly, so the same Vote can be passed to CheckAndRecordVote
	//     while another goroutine mutates vote.Signature.
	//   - Concurrent modification of the shared Signature backing array
	//     corrupts stored slashing evidence, blocking conviction.
	// Deep copy is cheap relative to the slashing path and prevents the
	// corruption attack vector described in P0-04.
	voteCopy := deepCopyVote(vote)
	d.voteHistory[addr][height][round] = voteCopy
	d.voteCount++

	// audit-fix NEW-2: cap total entries to prevent unbounded memory growth
	if d.voteCount > maxDoubleSignVoteHistory {
		d.pruneOldestLocked(d.voteCount - maxDoubleSignVoteHistory*9/10)
	}

	return nil, nil
}

// deepCopySlashingEvidence returns a deep copy of a SlashingEvidence.
// P3 FIX: prevents callers from mutating stored evidence via Vote pointers.
// audit-remediation: reviewed 2026-09-11 — read-only copy helper; no stake
// mutation, no authorization surface (in-memory evidence records only).
func deepCopySlashingEvidence(ev *SlashingEvidence) *SlashingEvidence {
	if ev == nil {
		return nil
	}
	return &SlashingEvidence{
		Reason:        ev.Reason,
		ValidatorAddr: ev.ValidatorAddr,
		Height:        ev.Height,
		Vote1:         deepCopyVote(ev.Vote1),
		Vote2:         deepCopyVote(ev.Vote2),
		MissedBlocks:  ev.MissedBlocks,
		Timestamp:     ev.Timestamp,
	}
}

// GetEvidence returns all collected slashing evidence.
// P3 FIX: returns deep copies to prevent callers from mutating stored evidence.
func (d *DoubleSignDetector) GetEvidence() []*SlashingEvidence {
	d.mu.RLock()
	defer d.mu.RUnlock()

	result := make([]*SlashingEvidence, len(d.evidence))
	for i, ev := range d.evidence {
		result[i] = deepCopySlashingEvidence(ev)
	}
	return result
}

// GetLatestEvidence returns the most recently detected evidence.
//
// R36-P3-10 FIX (2026-07-30): Return a deep copy, mirroring the P3-09 fix
// applied to GetEvidence. The previous implementation returned the internal
// pointer, so a caller that mutated the returned evidence would corrupt the
// detector's stored evidence (and future GetLatestEvidence / GetEvidence
// calls). The deep copy is cheap relative to the slashing path and removes
// the aliasing foot-gun.
func (d *DoubleSignDetector) GetLatestEvidence() *SlashingEvidence {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if len(d.evidence) == 0 {
		return nil
	}
	return deepCopySlashingEvidence(d.evidence[len(d.evidence)-1])
}

// GetEvidenceForValidator returns slashing evidence for a specific validator.
//
// R37-P3-24 FIX (2026-07-31): Return deep copies instead of internal pointers.
// Previously, callers could mutate the returned evidence and corrupt the
// detector's stored state, leading to silent data corruption and inconsistent
// slashing decisions. The deep copy is cheap relative to the slashing path
// and removes the aliasing foot-gun, matching the fix applied to
// GetEvidence / GetLatestEvidence.
func (d *DoubleSignDetector) GetEvidenceForValidator(addr types.Address) []*SlashingEvidence {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var result []*SlashingEvidence
	for _, ev := range d.evidence {
		if ev.ValidatorAddr == addr {
			result = append(result, deepCopySlashingEvidence(ev))
		}
	}
	return result
}

// ClearEvidenceOlderThan removes evidence older than the given time
func (d *DoubleSignDetector) ClearEvidenceOlderThan(cutoff time.Time) int {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoffUnix := cutoff.Unix()
	var remaining []*SlashingEvidence
	removed := 0
	for _, ev := range d.evidence {
		if ev.Timestamp > cutoffUnix {
			remaining = append(remaining, ev)
		} else {
			removed++
		}
	}
	d.evidence = remaining
	return removed
}

// pruneOldestLocked evicts the N lowest-height entries from voteHistory.
// MUST be called while d.mu is held.
// audit-fix NEW-2: prevents unbounded memory growth.
// HIGH FIX: Optimized from O(n^2) to O(n log n) using heap for efficient pruning.
func (d *DoubleSignDetector) pruneOldestLocked(n int) {
	if n <= 0 {
		return
	}

	// Create min-heap prioritized by height (oldest first)
	h := &voteHeap{}
	for addr, heights := range d.voteHistory {
		for hgt, rounds := range heights {
			for r := range rounds {
				heap.Push(h, voteEntry{addr: addr, height: hgt, round: r})
			}
		}
	}

	// Pop and delete N oldest entries
	for n > 0 && h.Len() > 0 {
		val := heap.Pop(h)
		entry, ok := val.(voteEntry)
		if !ok {
			continue
		}
		addr, hgt, rnd := entry.addr, entry.height, entry.round

		// Verify entry still exists (may have been deleted via other paths)
		if heights, exists := d.voteHistory[addr]; exists {
			if rounds, exists := heights[hgt]; exists {
				if _, exists := rounds[rnd]; exists {
					delete(d.voteHistory[addr][hgt], rnd)
					d.voteCount--
					n--

					// Clean up empty maps
					if len(d.voteHistory[addr][hgt]) == 0 {
						delete(d.voteHistory[addr], hgt)
					}
					if len(d.voteHistory[addr]) == 0 {
						delete(d.voteHistory, addr)
					}
				}
			}
		}
	}
}

// voteEntry represents a single vote in the heap for pruning
type voteEntry struct {
	addr   types.Address
	height uint64
	round  uint32
}

// voteHeap implements heap.Interface for efficient pruning
type voteHeap []voteEntry

func (h voteHeap) Len() int { return len(h) }
func (h voteHeap) Less(i, j int) bool {
	if h[i].height != h[j].height {
		return h[i].height < h[j].height
	}
	return h[i].round < h[j].round
}
func (h voteHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *voteHeap) Push(x any) {
	v, ok := x.(voteEntry)
	if ok {
		*h = append(*h, v)
	}
}
func (h *voteHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// PruneVoteHistory removes vote history older than the given height
func (d *DoubleSignDetector) PruneVoteHistory(keepAbove uint64) int {
	d.mu.Lock()
	defer d.mu.Unlock()

	pruned := 0
	for addr, heights := range d.voteHistory {
		for height, rounds := range heights {
			if height < keepAbove {
				// audit-fix R3-2: decrement voteCount by actual votes removed
				d.voteCount -= len(rounds)
				delete(d.voteHistory[addr], height)
				pruned++
			}
		}
		// Clean up empty address entries
		if len(d.voteHistory[addr]) == 0 {
			delete(d.voteHistory, addr)
		}
	}
	return pruned
}
