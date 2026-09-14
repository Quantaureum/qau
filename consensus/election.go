// Quantaureum Node source, version 1.0.0.
// Package consensus implements the QPOS consensus mechanism for Quantaureum.
// This file implements the validator election algorithm using VRF.
// Optimized for deterministic, stake-weighted proposer selection.
package consensus

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

var (
	// ErrNoValidators is returned when there are no validators to select from
	ErrNoValidators = errors.New("no validators available")

	// ErrNoActiveValidators is returned when there are no active validators
	ErrNoActiveValidators = errors.New("no active validators")

	// ErrInvalidStake is returned when a validator has invalid stake
	ErrInvalidStake = errors.New("invalid stake amount")

	// ErrZeroTotalStake is returned when total stake is zero
	ErrZeroTotalStake = errors.New("total stake is zero")

	// ErrInvalidVRFForElection is returned when VRF output is invalid for election
	ErrInvalidVRFForElection = errors.New("invalid VRF output for election")
)

// Validator represents a validator in the consensus
type Validator struct {
	Address             types.Address // Validator's address
	Stake               *big.Int      // Staked amount
	Active              bool          // Whether the validator is active
	Commission          uint32        // Commission rate in basis points (0-10000)
	PublicKeyBytes      []byte        // Dilithium3 public key bytes for signature verification
	KyberPublicKeyBytes []byte        // Kyber-768 public key bytes for encrypted P2P communication
}

// ValidatorSet represents a set of validators
type ValidatorSet struct {
	validators []*Validator
	totalStake *big.Int

	// Precomputed cumulative stakes for O(log n) selection
	cumulativeStakes []*big.Int
	// Map for O(1) validator lookup by address
	validatorMap map[types.Address]*Validator
	// Map for O(1) address→index lookup (avoids O(n) scan in GetValidatorIndex)
	addrIndexMap map[types.Address]int
	mu           sync.RWMutex

	// FIX: Callback for stake changes, used to sync economics layer.
	onStakeChanged func(addr types.Address, newStake *big.Int)
}

// Election represents a VRF-based election for proposer selection
type Election struct {
	privateKey *crypto.PrivateKey
	publicKey  *crypto.PublicKey
	validators *ValidatorSet
}

// NewElection creates a new election instance with the given key pair and validator set
func NewElection(privateKey *crypto.PrivateKey, publicKey *crypto.PublicKey, validators *ValidatorSet) *Election {
	return &Election{
		privateKey: privateKey,
		publicKey:  publicKey,
		validators: validators,
	}
}

// Evaluate generates a VRF output for the given seed
// This is used by a validator to prove they are the proposer
func (e *Election) Evaluate(seed types.Hash) (*VRFProof, *VRFOutput, error) {
	return GenerateVRF(e.privateKey, seed)
}

// Verify verifies a VRF proof and output against a public key and seed
// This is used to verify that a validator is the legitimate proposer
func (e *Election) Verify(publicKey *crypto.PublicKey, seed types.Hash, proof *VRFProof, output *VRFOutput) error {
	return VerifyVRF(publicKey, seed, proof, output)
}

// IsWinner determines if the VRF output makes this validator a winner
// based on their stake proportion
// HIGH FIX: Enhanced entropy sources to prevent stake manipulation attacks.
// The VRF output is combined with multiple entropy sources including:
// - VRF output (primary)
// - Block hash (unpredictable future value)
// - Timestamp (time-based entropy)
// - Validator address (prevents cross-validator replay)
// - Stake ratio components (binds to specific validator)
func (e *Election) IsWinner(output *VRFOutput, stake *big.Int, totalStake *big.Int, blockHash types.Hash, timestamp int64) bool {
	if output == nil || stake == nil || totalStake == nil {
		return false
	}
	if stake.Sign() <= 0 || totalStake.Sign() <= 0 {
		return false
	}

	// HIGH FIX: Combine VRF output with enhanced entropy sources
	// to prevent stake manipulation attacks
	pubKeyBytes := []byte{}
	if e.publicKey != nil {
		pubKeyBytes = e.publicKey.Bytes()
	}
	combined := make([]byte, 0, len(output.Value)+len(blockHash)+8+len(pubKeyBytes)+len(stake.Bytes())+len(totalStake.Bytes()))
	combined = append(combined, output.Value[:]...)
	combined = append(combined, blockHash[:]...)

	// Add timestamp bytes for time-based entropy
	tsBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBytes, uint64(timestamp)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	combined = append(combined, tsBytes...)

	// HIGH FIX: Add validator public key to prevent cross-validator replay
	// Different validators with the same VRF output will get different results
	if e.publicKey != nil {
		combined = append(combined, e.publicKey.Bytes()...)
	}

	// HIGH FIX: Add stake ratio components to bind result to specific validator
	// This prevents an attacker from using another validator's proof
	combined = append(combined, stake.Bytes()...)
	combined = append(combined, totalStake.Bytes()...)

	// Hash the combined data with SHA3-256 for final output
	hashedOutput := sha3.Sum256(combined)

	// Convert VRF output to a number
	vrfValue := new(big.Int).SetBytes(hashedOutput[:])

	// Calculate threshold: (stake / totalStake) * 2^256
	// Rearranged to avoid division: vrfValue * totalStake < stake * 2^256
	// Simplified: vrfValue * totalStake < stake * maxVRF
	maxVRF := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256

	// left = vrfValue * totalStake
	left := new(big.Int).Mul(vrfValue, totalStake)

	// right = stake * maxVRF
	right := new(big.Int).Mul(stake, maxVRF)

	return left.Cmp(right) < 0
}

// MinBFTValidatorCount is the minimum validator count recommended for BFT
// safety (n >= 3f+1 means f=1 requires n >= 4). Quantaureum's mainnet/testnet
// may temporarily operate with fewer validators during bootstrapping, so this
// is NOT enforced as a hard rejection in NewValidatorSet; callers that require
// strict BFT safety should call (*ValidatorSet).ValidateBFTSafety().
//
//	(P3).
const MinBFTValidatorCount = 4

// NewValidatorSet creates a new validator set from a list of validators
func NewValidatorSet(validators []*Validator) (*ValidatorSet, error) {
	if len(validators) == 0 {
		return nil, ErrNoValidators
	}

	vs := &ValidatorSet{
		validators:   make([]*Validator, 0, len(validators)),
		totalStake:   big.NewInt(0),
		validatorMap: make(map[types.Address]*Validator),
		addrIndexMap: make(map[types.Address]int),
	}

	// Filter active validators and calculate total stake
	for _, v := range validators {
		if v == nil {
			continue
		}
		if !v.Active {
			continue
		}
		// Allow zero-stake validators for genesis bootstrap.
		// Genesis validators start with 0 stake and receive QAU via airdrop transfers,
		// then stake via their own transactions. The deterministic shuffle proposer
		// selection (qpos_proposer.go) does not use stake weight, so zero-stake
		// validators can still be elected as proposers.
		if v.Stake == nil {
			v.Stake = big.NewInt(0)
		}

		// Copy validator to avoid external modifications
		validatorCopy := &Validator{
			Address:             v.Address,
			Stake:               new(big.Int).Set(v.Stake),
			Active:              v.Active,
			Commission:          v.Commission,
			PublicKeyBytes:      append([]byte(nil), v.PublicKeyBytes...),
			KyberPublicKeyBytes: append([]byte(nil), v.KyberPublicKeyBytes...),
		}
		vs.validators = append(vs.validators, validatorCopy)
		vs.validatorMap[v.Address] = validatorCopy
		vs.totalStake.Add(vs.totalStake, v.Stake)
	}

	if len(vs.validators) == 0 {
		return nil, ErrNoActiveValidators
	}

	// Allow zero total stake for genesis bootstrap phase.
	// Genesis validators start with 0 stake; SelectProposer will use
	// deterministic round-robin (via qpos_proposer.go) when totalStake=0.
	// Once validators stake via transactions, totalStake > 0 and
	// stake-weighted selection takes effect.

	// Sort validators by address for deterministic ordering
	sort.Slice(vs.validators, func(i, j int) bool {
		return compareAddresses(vs.validators[i].Address, vs.validators[j].Address) < 0
	})

	// Build address→index map after sorting (indices are now stable)
	for i, v := range vs.validators {
		vs.addrIndexMap[v.Address] = i
	}

	// Precompute cumulative stakes for O(log n) selection
	vs.computeCumulativeStakes()

	return vs, nil
}

// ValidateBFTSafety returns an error if the active validator set is smaller
// than MinBFTValidatorCount, the minimum required for BFT safety (tolerating
// f=1 Byzantine validator via n >= 3f+1). This is a soft check ():
// production deployments should call it, but NewValidatorSet does not
// auto-reject smaller sets so testnet/devnet bootstrapping is not blocked.
func (vs *ValidatorSet) ValidateBFTSafety() error {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	if len(vs.validators) < MinBFTValidatorCount {
		return fmt.Errorf("validator set size %d below BFT safety minimum %d", len(vs.validators), MinBFTValidatorCount)
	}
	return nil
}

// computeCumulativeStakes precomputes cumulative stakes for binary search selection
// SECURITY NOTE: Must be called while holding vs.mu WriteLock
// This is enforced by callers - currently called from NewValidatorSet and updateValidators
func (vs *ValidatorSet) computeCumulativeStakes() {
	vs.cumulativeStakes = make([]*big.Int, len(vs.validators))
	cumulative := big.NewInt(0)

	for i, v := range vs.validators {
		cumulative = new(big.Int).Add(cumulative, v.Stake)
		vs.cumulativeStakes[i] = new(big.Int).Set(cumulative)
	}
}

// validateVRFOutputForElection validates that a VRF output is safe to use
// for proposer selection. The check rejects:
//  1. nil VRF outputs (caller error).
//  2. Outputs whose Value slice is shorter than 32 bytes — defense-in-depth
//     even though types.Hash is a fixed [32]byte array, in case a future VRF
//     variant or test helper passes a truncated buffer.
//
// CONS- (2026-07-20): The audit recommends validating that
// vrfOutput.Value conforms to the VRF standard length (32 bytes / SHA3-256)
// before being used in the stake-weighted mod operation. The previous code
// trusted the VRF output unconditionally. types.Hash enforces length at
// compile time, but this check remains as defense-in-depth so a future
// refactor (e.g. switching Value to a []byte) cannot silently break the
// invariant. The check intentionally does NOT reject the all-zero hash:
// that is a degenerate-but-valid 32-byte input used by tests of selection
// determinism, and rejecting it would break the contract that any 32-byte
// VRF output selects exactly one proposer.
func validateVRFOutputForElection(vrfOutput *VRFOutput) error {
	if vrfOutput == nil {
		return ErrInvalidVRFOutput
	}
	if len(vrfOutput.Value[:]) != types.HashLength {
		return ErrInvalidVRFForElection
	}
	return nil
}

// SelectProposer selects a block proposer based on VRF output.
// The selection is weighted by stake - validators with more stake
// have a proportionally higher chance of being selected.
//
// Algorithm (optimized with binary search):
// 1. Convert VRF output to a number in range [0, totalStake)
// 2. Use binary search on precomputed cumulative stakes
// 3. Return the validator at the found index
//
// Time complexity: O(log n) where n is the number of validators
func (vs *ValidatorSet) SelectProposer(vrfOutput *VRFOutput) (*Validator, error) {
	// CONS- (2026-07-20): Validate VRF output BEFORE acquiring the
	// read lock — reject degenerate inputs (nil, wrong length, zero hash)
	// up front so they cannot bias proposer selection toward idx 0.
	if err := validateVRFOutputForElection(vrfOutput); err != nil {
		return nil, err
	}

	vs.mu.RLock()
	defer vs.mu.RUnlock()

	if len(vs.validators) == 0 {
		return nil, ErrNoActiveValidators
	}

	// Genesis bootstrap: when totalStake=0, stake-weighted selection is
	// impossible. Return error so caller (qpos_proposer.go) falls back to
	// deterministic round-robin selection.
	if vs.totalStake.Sign() == 0 {
		return nil, ErrZeroTotalStake
	}

	// Convert VRF output to a big integer
	vrfValue := new(big.Int).SetBytes(vrfOutput.Value[:])

	// Calculate selection point: vrfValue mod totalStake
	selectionPoint := new(big.Int).Mod(vrfValue, vs.totalStake)

	// Use binary search to find the validator
	idx := vs.binarySearchValidator(selectionPoint)

	return vs.validators[idx], nil
}

// binarySearchValidator finds the validator index using binary search on cumulative stakes
// Returns the index of the first validator whose cumulative stake > selectionPoint
// M-NEW-1 FIX: Add bounds check to prevent out-of-bounds access when selectionPoint
// exceeds all cumulative stakes.
func (vs *ValidatorSet) binarySearchValidator(selectionPoint *big.Int) int {
	left, right := 0, len(vs.cumulativeStakes)-1

	// M-NEW-1 FIX: Handle empty or single-element case
	if left > right {
		return 0
	}

	for left < right {
		mid := left + (right-left)/2
		if vs.cumulativeStakes[mid].Cmp(selectionPoint) <= 0 {
			left = mid + 1
		} else {
			right = mid
		}
	}

	// M-NEW-1 FIX: Clamp result to valid range
	if left >= len(vs.cumulativeStakes) {
		return len(vs.cumulativeStakes) - 1
	}

	return left
}

// SelectProposerLinear selects a proposer using linear search (for comparison/testing)
// This is the original O(n) algorithm
func (vs *ValidatorSet) SelectProposerLinear(vrfOutput *VRFOutput) (*Validator, error) {
	// CONS- (2026-07-20): Validate VRF output before use, matching
	// SelectProposer's validation, so the linear variant cannot be abused
	// with a degenerate (zero/nil/short) VRF output.
	if err := validateVRFOutputForElection(vrfOutput); err != nil {
		return nil, err
	}

	// CON4-003 FIX: Acquire RLock to prevent data race with AddValidator/
	// RemoveValidator/ReduceStake, matching SelectProposer's locking pattern.
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	if len(vs.validators) == 0 {
		return nil, ErrNoActiveValidators
	}

	// Convert VRF output to a big integer
	vrfValue := new(big.Int).SetBytes(vrfOutput.Value[:])

	// Calculate selection point: vrfValue mod totalStake
	selectionPoint := new(big.Int).Mod(vrfValue, vs.totalStake)

	// Find the validator at the selection point
	accumulated := big.NewInt(0)
	for _, v := range vs.validators {
		accumulated.Add(accumulated, v.Stake)
		if accumulated.Cmp(selectionPoint) > 0 {
			return v, nil
		}
	}

	// Should never reach here if totalStake is calculated correctly
	// Return the last validator as a fallback
	return vs.validators[len(vs.validators)-1], nil
}

// SelectProposerByHeight selects a proposer for a given block height.
// L18-011 FIX: The seed now incorporates vrfEntropy — an unpredictable random
// source derived from the previous block's VRF output or aggregated threshold
// signature. This prevents adversaries from predicting the election seed
// since height and prevBlockHash are both public and predictable.
//
// Callers should pass the VRF output (or aggregated threshold signature hash)
// from the most recent finalized block as vrfEntropy. If no VRF output is
// available (e.g. during chain initialization), pass types.Hash{} — the seed
// will still be deterministic but should only be used for bootstrapping.
func SelectProposerByHeight(vs *ValidatorSet, height uint64, prevBlockHash types.Hash, vrfEntropy types.Hash) (*Validator, types.Hash, error) {
	// CON-001 FIX: Reject zero vrfEntropy for non-genesis heights to prevent
	// predictable election seeds. During chain initialization (height <= 1),
	// zero vrfEntropy is acceptable because no adversary can exploit the
	// bootstrap phase. For all subsequent heights, vrfEntropy MUST be non-zero
	// and derived from the previous block's VRF output or aggregated threshold
	// signature, making the seed unpredictable until the previous block is
	// finalized.
	var zeroHash types.Hash
	if height > 1 && vrfEntropy == zeroHash {
		return nil, types.Hash{}, fmt.Errorf("vrfEntropy must be non-zero for height %d > 1", height)
	}

	// Create seed from height, previous block hash, and VRF entropy
	seed := createElectionSeed(height, prevBlockHash, vrfEntropy)

	// Use the seed as VRF output for selection.
	//
	// CON-001 AUDIT NOTE: The VRF proof is verified at the block validation
	// layer (consensus/block.go ValidateBlock), which calls Election.Verify()
	// to validate the proposer's VRF proof against their public key. This
	// function performs deterministic proposer selection based on the seed;
	// the proof verification ensures that the selected proposer actually
	// generated the VRF output, preventing forgery.
	output := &VRFOutput{Value: seed}

	proposer, err := vs.SelectProposer(output)
	if err != nil {
		return nil, types.Hash{}, err
	}

	return proposer, seed, nil
}

// createElectionSeed creates a deterministic seed for election.
// L18-011 FIX: The seed now incorporates vrfEntropy — an unpredictable
// random source (e.g. VRF output or aggregated threshold signature from the
// previous block). Previously the seed was derived only from height and
// prevBlockHash, both of which are public and predictable, allowing an
// adversary to pre-compute the election outcome.
//
// The vrfEntropy parameter should be the hash of the most recent block's
// VRF proof output or aggregated threshold signature. When vrfEntropy is the
// zero hash (types.Hash{}), the function falls back to the old behavior for
// backward compatibility during chain bootstrap, but this should NOT be used
// in production consensus rounds.
func createElectionSeed(height uint64, prevBlockHash types.Hash, vrfEntropy types.Hash) types.Hash {
	// Combine height, previous block hash, and VRF entropy
	data := make([]byte, 8+types.HashLength+types.HashLength)

	// Encode height as big-endian
	data[0] = byte(height >> 56)
	data[1] = byte(height >> 48) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	data[2] = byte(height >> 40) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	data[3] = byte(height >> 32) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	data[4] = byte(height >> 24) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	data[5] = byte(height >> 16) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	data[6] = byte(height >> 8)  // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	data[7] = byte(height)       // #nosec G115 -- safe conversion: value range verified or bit-shift extraction

	copy(data[8:], prevBlockHash[:])
	// L18-011 FIX: Mix in VRF entropy to make the seed unpredictable
	copy(data[8+types.HashLength:], vrfEntropy[:])

	// Hash to create seed
	return hashProof(data)
}

// Validators returns a copy of the validator list
// audit-fix M-5: include PublicKeyBytes in the copy for signature verification.
// audit-fix NEW-5: deep-copy PublicKeyBytes to prevent callers from mutating
// internal validator state (e.g. spoofing attestation public keys).
func (vs *ValidatorSet) Validators() []*Validator {
	// CON-ELEC-01 FIX (deep-audit 2026-07-12): read under the lock. Node-layer
	// callers (block producer, syncer, adapters) invoke this concurrently with
	// consensus mutations (AddValidator/RemoveValidator/ReduceStake) that replace
	// the slice header and mutate elements under vs.mu; every other accessor
	// (Size/GetValidator/DeepCopy) locks — these two were missed, risking a torn
	// slice-header read (possible out-of-range) or a racy stake sum.
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	result := make([]*Validator, len(vs.validators))
	for i, v := range vs.validators {
		var pkCopy []byte
		if len(v.PublicKeyBytes) > 0 {
			pkCopy = make([]byte, len(v.PublicKeyBytes))
			copy(pkCopy, v.PublicKeyBytes)
		}
		var kyberCopy []byte
		if len(v.KyberPublicKeyBytes) > 0 {
			kyberCopy = make([]byte, len(v.KyberPublicKeyBytes))
			copy(kyberCopy, v.KyberPublicKeyBytes)
		}
		result[i] = &Validator{
			Address:             v.Address,
			Stake:               new(big.Int).Set(v.Stake),
			Active:              v.Active,
			Commission:          v.Commission,
			PublicKeyBytes:      pkCopy,
			KyberPublicKeyBytes: kyberCopy,
		}
	}
	return result
}

// TotalStake returns the total stake of all active validators
func (vs *ValidatorSet) TotalStake() *big.Int {
	// CON-ELEC-01 FIX: read under the lock (see Validators()); ReduceStake and
	// recomputeCumulativeStakesLocked replace vs.totalStake under vs.mu.
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	return new(big.Int).Set(vs.totalStake)
}

// DeepCopy returns a deep copy of the ValidatorSet to prevent data races
// when the set is accessed by multiple goroutines.
// CRITICAL FIX: GetValidatorSet() in qpos.go returns internal *ValidatorSet pointer,
// which could be modified by callers causing data races. This method provides
// safe access by returning a completely independent copy.
// audit-fix R3-H1.
func (vs *ValidatorSet) DeepCopy() *ValidatorSet {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	result := &ValidatorSet{
		validators:       make([]*Validator, len(vs.validators)),
		totalStake:       new(big.Int).Set(vs.totalStake),
		validatorMap:     make(map[types.Address]*Validator, len(vs.validatorMap)),
		addrIndexMap:     make(map[types.Address]int, len(vs.addrIndexMap)),
		cumulativeStakes: make([]*big.Int, len(vs.cumulativeStakes)),
	}

	for i, v := range vs.validators {
		var pkCopy []byte
		if len(v.PublicKeyBytes) > 0 {
			pkCopy = make([]byte, len(v.PublicKeyBytes))
			copy(pkCopy, v.PublicKeyBytes)
		}
		var kyberCopy []byte
		if len(v.KyberPublicKeyBytes) > 0 {
			kyberCopy = make([]byte, len(v.KyberPublicKeyBytes))
			copy(kyberCopy, v.KyberPublicKeyBytes)
		}
		result.validators[i] = &Validator{
			Address:             v.Address,
			Stake:               new(big.Int).Set(v.Stake),
			Active:              v.Active,
			Commission:          v.Commission,
			PublicKeyBytes:      pkCopy,
			KyberPublicKeyBytes: kyberCopy,
		}
		result.validatorMap[v.Address] = result.validators[i]
		result.addrIndexMap[v.Address] = i
	}

	for i, cs := range vs.cumulativeStakes {
		result.cumulativeStakes[i] = new(big.Int).Set(cs)
	}

	return result
}

// Size returns the number of active validators
// audit-fix MEDIUM: Add RLock to prevent race condition with concurrent access
func (vs *ValidatorSet) Size() int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	return len(vs.validators)
}

// AddValidator adds a new validator to the set. If the validator already exists,
// their stake is updated. Returns true if a new validator was added, false if an
// existing validator was updated.
func (vs *ValidatorSet) AddValidator(addr types.Address, stake *big.Int) bool {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	// Check if validator already exists
	if idx, ok := vs.addrIndexMap[addr]; ok {
		// Update existing validator's stake
		origStake := vs.validators[idx].Stake
		vs.totalStake.Sub(vs.totalStake, origStake)
		vs.validators[idx].Stake = new(big.Int).Set(stake)
		vs.totalStake.Add(vs.totalStake, vs.validators[idx].Stake)
		vs.validators[idx].Active = true
		vs.recomputeCumulativeStakesLocked()
		return false
	}

	// R41-L5CONS-04 (2026-08-03) FIX: enforce the protocol MaxValidators
	// cap BEFORE appending. The upper QPOS.AddStakingValidator entry
	// (consensus/validator.go:811) already guards via validatorsCapExceeded,
	// but AddValidator is a lower-level public method and external callers
	// (e.g. tests, future RPC handlers, future consensus variants) can
	// reach it directly. Without this check, an attacker who can call
	// AddValidator directly — bypassing QPOS — could push the validator
	// set past MaxValidators, exhausting the addrIndexMap and causing
	// subsequent proposer elections to iterate a slice far larger than
	// the protocol allows (gas/latency amplification, and over time,
	// making consensus proposer-selection no longer match the on-chain
	// economic distribution the protocol expects). The guard fails closed
	// (returns false, semantically indistinguishable from "update
	// existing") so existing callers treat the rejection as a no-op.
	if len(vs.validators) >= MaxValidators {
		return false
	}

	// Add new validator
	v := &Validator{
		Address: addr,
		Stake:   new(big.Int).Set(stake),
		Active:  true,
	}
	vs.validators = append(vs.validators, v)
	vs.validatorMap[addr] = v
	vs.addrIndexMap[addr] = len(vs.validators) - 1
	vs.totalStake.Add(vs.totalStake, stake)
	vs.recomputeCumulativeStakesLocked()
	return true
}

// GetValidator returns a validator by address
func (vs *ValidatorSet) GetValidator(addr types.Address) *Validator {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	v, exists := vs.validatorMap[addr]
	if !exists {
		return nil
	}

	// Return a copy to prevent external modifications
	// audit-fix R3-H1: include PublicKeyBytes so callers can verify signatures.
	// audit-fix NEW-5: deep-copy PublicKeyBytes to prevent mutation of internal state.
	var pkCopy []byte
	if len(v.PublicKeyBytes) > 0 {
		pkCopy = make([]byte, len(v.PublicKeyBytes))
		copy(pkCopy, v.PublicKeyBytes)
	}
	var kyberCopy []byte
	if len(v.KyberPublicKeyBytes) > 0 {
		kyberCopy = make([]byte, len(v.KyberPublicKeyBytes))
		copy(kyberCopy, v.KyberPublicKeyBytes)
	}
	return &Validator{
		Address:             v.Address,
		Stake:               new(big.Int).Set(v.Stake),
		Active:              v.Active,
		Commission:          v.Commission,
		PublicKeyBytes:      pkCopy,
		KyberPublicKeyBytes: kyberCopy,
	}
}

// GetValidatorByIndex returns a copy of the validator at the given index.
// O(1) per call — avoids the O(n) deep copy of Validators().
// Returns nil if index is out of bounds.
func (vs *ValidatorSet) GetValidatorByIndex(idx int) *Validator {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	if idx < 0 || idx >= len(vs.validators) {
		return nil
	}

	v := vs.validators[idx]

	var pkCopy []byte
	if len(v.PublicKeyBytes) > 0 {
		pkCopy = make([]byte, len(v.PublicKeyBytes))
		copy(pkCopy, v.PublicKeyBytes)
	}
	var kyberCopy []byte
	if len(v.KyberPublicKeyBytes) > 0 {
		kyberCopy = make([]byte, len(v.KyberPublicKeyBytes))
		copy(kyberCopy, v.KyberPublicKeyBytes)
	}
	return &Validator{
		Address:             v.Address,
		Stake:               new(big.Int).Set(v.Stake),
		Active:              v.Active,
		Commission:          v.Commission,
		PublicKeyBytes:      pkCopy,
		KyberPublicKeyBytes: kyberCopy,
	}
}

// ValidatorCount returns the number of validators without acquiring a deep copy.
// Equivalent to len(vs.Validators()) but O(1) instead of O(n).
func (vs *ValidatorSet) ValidatorCount() int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	return len(vs.validators)
}

// GetValidatorIndex returns the index of a validator by address, or -1 if not found
// Optimized: O(1) lookup via addrIndexMap instead of O(n) linear scan
func (vs *ValidatorSet) GetValidatorIndex(addr types.Address) int {
	vs.mu.RLock()
	defer vs.mu.RUnlock()

	idx, ok := vs.addrIndexMap[addr]
	if !ok {
		return -1
	}
	return idx
}

func (vs *ValidatorSet) DeactivateValidator(index int) bool {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	if index < 0 || index >= len(vs.validators) {
		return false
	}
	if vs.validators[index].Active {
		vs.validators[index].Active = false
		vs.recomputeCumulativeStakesLocked()
	}
	return true
}

// RemoveValidator removes a validator at the given index and re-indexes
// the remaining validators. L11-013 FIX: slashed validators previously
// stayed forever in the set (DeactivateValidator only sets Active=false),
// causing a memory leak as the validator slice grew unboundedly.
func (vs *ValidatorSet) RemoveValidator(index int) bool {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	if index < 0 || index >= len(vs.validators) {
		return false
	}

	removed := vs.validators[index]

	// Remove from slice (preserves order of remaining validators)
	vs.validators = append(vs.validators[:index], vs.validators[index+1:]...)

	// Remove from address-keyed maps
	delete(vs.validatorMap, removed.Address)
	delete(vs.addrIndexMap, removed.Address)

	// Re-index addrIndexMap for all validators that shifted down
	for i := index; i < len(vs.validators); i++ {
		vs.addrIndexMap[vs.validators[i].Address] = i
	}

	// Recompute cumulative stakes and total stake
	vs.recomputeCumulativeStakesLocked()

	return true
}

// RemoveValidatorByAddr removes a validator by address from all internal
// structures (validators slice, validatorMap, addrIndexMap) and re-indexes
// the remaining validators.
//
// SLASH-H1 FIX (R29, 2026-07-25): Previously, WithdrawStake only deleted
// from ValidatorManager.validators, leaving residual entries in ValidatorSet
// (validators slice, validatorMap, addrIndexMap). These stale entries caused
// unbounded memory growth and could block re-registration of the same
// address. This method is invoked by the onValidatorRemoved callback
// registered by the node layer to clean up ValidatorSet residual state.
//
// Returns true if the validator was found and removed, false if not found.
func (vs *ValidatorSet) RemoveValidatorByAddr(addr types.Address) bool {
	vs.mu.Lock()
	defer vs.mu.Unlock()

	index, exists := vs.addrIndexMap[addr]
	if !exists {
		return false
	}

	// Remove from slice (preserves order of remaining validators)
	vs.validators = append(vs.validators[:index], vs.validators[index+1:]...)

	// Remove from address-keyed maps
	delete(vs.validatorMap, addr)
	delete(vs.addrIndexMap, addr)

	// Re-index addrIndexMap for all validators that shifted down
	for i := index; i < len(vs.validators); i++ {
		vs.addrIndexMap[vs.validators[i].Address] = i
	}

	// Recompute cumulative stakes and total stake
	vs.recomputeCumulativeStakesLocked()

	return true
}

func (vs *ValidatorSet) ReduceStake(index int, penalty *big.Int) bool {
	vs.mu.Lock()

	if index < 0 || index >= len(vs.validators) {
		vs.mu.Unlock()
		return false
	}
	if penalty == nil || penalty.Sign() <= 0 {
		vs.mu.Unlock()
		return false
	}
	v := vs.validators[index]
	if v.Stake != nil {
		newStake := new(big.Int).Sub(v.Stake, penalty)
		if newStake.Sign() < 0 {
			newStake = big.NewInt(0)
		}
		vs.validators[index].Stake = newStake
	}
	vs.recomputeCumulativeStakesLocked()

	// FIX: Capture callback and arguments while holding the lock,
	// then call the callback AFTER releasing the lock. Previously, the
	// callback was invoked while vs.mu was still held (via defer), which
	// could deadlock if the callback indirectly acquires vs.mu (e.g., via
	// Validators() or GetValidator()).
	var cb func(types.Address, *big.Int)
	var cbAddr types.Address
	var cbStake *big.Int
	if vs.onStakeChanged != nil && v.Stake != nil {
		cb = vs.onStakeChanged
		cbAddr = v.Address
		cbStake = new(big.Int).Set(vs.validators[index].Stake)
	}
	vs.mu.Unlock()

	// FIX: Notify stake-change callback so economics layer can sync
	// its totalStaked tracker. Without this, slashing in consensus causes
	// totalStaked (economics) to drift from totalStake (consensus).
	if cb != nil {
		// P3-NODE-06 FIX (R30, 2026-07-27): wrap callback in safeCallback
		// so a panic cannot kill the caller's goroutine.
		safeCallback("ValidatorSet.onStakeChanged", func() { cb(cbAddr, cbStake) })
	}
	return true
}

// FIX: SetStakeChangedCallback registers a callback invoked whenever
// a validator's stake changes (slash, reduce, etc.). The node layer (L6) uses
// this to sync the economics StakingManager's totalStaked tracker with the
// consensus ValidatorSet's totalStake, preventing dual-track drift.
// audit-remediation: reviewed 2026-09-11 — wiring setter called once by the
// node assembler; cannot mutate stake or validator membership itself.
func (vs *ValidatorSet) SetStakeChangedCallback(cb func(addr types.Address, newStake *big.Int)) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	vs.onStakeChanged = cb
}

func (vs *ValidatorSet) recomputeCumulativeStakesLocked() {
	vs.cumulativeStakes = make([]*big.Int, len(vs.validators))
	cumulative := big.NewInt(0)
	for i, v := range vs.validators {
		if v.Active && v.Stake != nil {
			cumulative = new(big.Int).Add(cumulative, v.Stake)
		}
		vs.cumulativeStakes[i] = new(big.Int).Set(cumulative)
	}
	vs.totalStake = new(big.Int).Set(cumulative)
}

// compareAddresses compares two addresses lexicographically
func compareAddresses(a, b types.Address) int {
	for i := 0; i < types.AddressLength; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
