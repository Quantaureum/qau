// Quantaureum Node source, version 1.0.0.
// Package consensus implements security enhancements for QPOS consensus.
// This file adds authorization checks, stake consistency validation, and slashing parameter validation.
package consensus

import (
	"crypto/subtle"
	"errors"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/types"
)

// Security-related errors
var (
	ErrUnauthorizedOperation = errors.New("unauthorized operation")
	ErrStakeInconsistency    = errors.New("stake consistency check failed")
	ErrInvalidSlashingParams = errors.New("invalid slashing parameters")
	ErrExcessivePenalty      = errors.New("penalty exceeds validator stake")
	ErrPenaltyOutOfBounds    = errors.New("penalty percentage out of bounds")
	ErrInvalidCaller         = errors.New("invalid caller address")
)

// SlashingConfig defines slashing parameters
type SlashingConfig struct {
	// MinPenaltyPercent is the minimum penalty percentage (basis points)
	MinPenaltyPercent uint32
	// MaxPenaltyPercent is the maximum penalty percentage (basis points)
	MaxPenaltyPercent uint32
	// DoubleVotePenalty is the penalty for double voting (basis points)
	DoubleVotePenalty uint32
	// SurroundVotePenalty is the penalty for surround voting (basis points)
	SurroundVotePenalty uint32
	// InactivityPenalty is the penalty for inactivity (basis points per epoch)
	InactivityPenalty uint32
	// R30-IMPLEMENT (2026-07-27): SLASH-H2 — DowntimePenalty is the penalty
	// for downtime (basis points). Distinct from InactivityPenalty to avoid
	// the 10x penalty discrepancy between QPOS.SlashValidator (which uses
	// SlashingValidator.CalculatePenalty) and SlashingManager.slashLocked
	// (which uses its own DowntimePenalty). Default 100 bp = 1%.
	DowntimePenalty uint32
}

// ValidateSlashingConfig validates a SlashingConfig for internal consistency.
// audit-fix M-1: extracted so both DefaultSlashingConfig and NewSlashingValidator
// can validate without panicking.
func ValidateSlashingConfig(config *SlashingConfig) error {
	if config.MinPenaltyPercent > config.MaxPenaltyPercent {
		return errors.New("invalid slashing config: min penalty exceeds max")
	}
	if config.DoubleVotePenalty > config.MaxPenaltyPercent {
		return errors.New("invalid slashing config: double vote penalty exceeds max")
	}
	if config.SurroundVotePenalty > config.MaxPenaltyPercent {
		return errors.New("invalid slashing config: surround vote penalty exceeds max")
	}
	// MEDIUM FIX: Validate InactivityPenalty parameter
	// Inactivity penalty should be reasonable (1-1000 basis points per epoch)
	if config.InactivityPenalty == 0 {
		return errors.New("invalid slashing config: inactivity penalty cannot be zero")
	}
	if config.InactivityPenalty > 1000 {
		return errors.New("invalid slashing config: inactivity penalty exceeds 1000 basis points (10%)")
	}
	// R30-IMPLEMENT (2026-07-27): SLASH-H2 — Validate DowntimePenalty.
	// Downtime is a distinct offense from inactivity (10x more severe by
	// default: 100 bp vs 10 bp). Must be non-zero (otherwise downtime
	// slashes silently become free) and <= MaxPenaltyPercent (otherwise
	// the penalty exceeds the configured ceiling).
	if config.DowntimePenalty == 0 {
		return errors.New("invalid slashing config: downtime penalty cannot be zero")
	}
	if config.DowntimePenalty > config.MaxPenaltyPercent {
		return errors.New("invalid slashing config: downtime penalty exceeds max")
	}
	return nil
}

// DefaultSlashingConfig returns the default slashing configuration.
// audit-fix M-1: returns error instead of panicking on invalid config.
// SECURITY: This is a pure configuration function - it does NOT perform any slashing
// or stake modifications. It only returns immutable default values.
// SECURITY FIX (audit S-2): DoubleVotePenalty was 3300 (33%), now 10000 (100%) to
// align with Casper FFG standard. SurroundVotePenalty also raised to 10000 (100%).
// audit-remediation: reviewed 2026-09-11 — pure config constructor; returns immutable defaults, performs no slashing.
func DefaultSlashingConfig() (*SlashingConfig, error) {
	config := &SlashingConfig{
		MinPenaltyPercent:   100,   // 1%
		MaxPenaltyPercent:   10000, // 100%
		DoubleVotePenalty:   10000, // 100% — Casper FFG standard for double voting
		SurroundVotePenalty: 10000, // 100% — Casper FFG standard for surround voting
		InactivityPenalty:   10,    // 0.1% per epoch
		// R30-IMPLEMENT (2026-07-27): SLASH-H2 — DowntimePenalty=100 bp (1%).
		// 10x InactivityPenalty (10 bp = 0.1%) to match SlashingManager's
		// DowntimePenalty rate, ensuring both slash paths (QPOS.SlashValidator
		// and SlashingManager.slashLocked) produce identical penalties for
		// the same downtime offense.
		DowntimePenalty: 100, // 1% — 10x inactivity penalty
	}
	if err := ValidateSlashingConfig(config); err != nil {
		return nil, err
	}
	return config, nil
}

// AuthorizedCallers tracks addresses authorized to perform sensitive operations
type AuthorizedCallers struct {
	mu      sync.RWMutex
	callers map[types.Address]bool
	// Governance address for multi-sig operations
	governance    types.Address
	governanceSet bool // audit-fix R9-1: track if governance was explicitly set
}

// NewAuthorizedCallers creates a new authorized callers tracker
func NewAuthorizedCallers() *AuthorizedCallers {
	return &AuthorizedCallers{
		callers: make(map[types.Address]bool),
	}
}

// AddCaller adds an authorized caller
func (ac *AuthorizedCallers) AddCaller(addr types.Address) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.callers[addr] = true
}

// RemoveCaller removes an authorized caller
func (ac *AuthorizedCallers) RemoveCaller(addr types.Address) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	delete(ac.callers, addr)
}

// IsAuthorized checks if an address is authorized
func (ac *AuthorizedCallers) IsAuthorized(addr types.Address) bool {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	return ac.callers[addr]
}

// SetGovernance sets the governance address
func (ac *AuthorizedCallers) SetGovernance(addr types.Address) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.governance = addr
	ac.governanceSet = true // audit-fix R9-1: mark as explicitly configured
}

// IsGovernance checks if an address is the governance address
// audit-fix R9-1: requires governance to be explicitly set via SetGovernance
// to prevent zero-address bypass when governance was never configured.
func (ac *AuthorizedCallers) IsGovernance(addr types.Address) bool {
	ac.mu.RLock()
	defer ac.mu.RUnlock()
	// audit-fix L-2: constant-time comparison to prevent timing side-channel
	return ac.governanceSet && subtle.ConstantTimeCompare(ac.governance[:], addr[:]) == 1
}

// StakeConsistencyChecker validates stake consistency
type StakeConsistencyChecker struct {
	mu sync.RWMutex
}

// NewStakeConsistencyChecker creates a new stake consistency checker
func NewStakeConsistencyChecker() *StakeConsistencyChecker {
	return &StakeConsistencyChecker{}
}

// VerifyTotalStake verifies that the sum of individual stakes equals total stake
func (scc *StakeConsistencyChecker) VerifyTotalStake(validators []*Validator, expectedTotal *big.Int) error {
	scc.mu.RLock()
	defer scc.mu.RUnlock()

	calculatedTotal := big.NewInt(0)
	for _, v := range validators {
		// audit-fix LOW: only count active validators, matching calculateTotalStake
		// semantics. Inactive validators must not contribute to the total stake.
		if v.Active && v.Stake != nil {
			calculatedTotal.Add(calculatedTotal, v.Stake)
		}
	}

	if calculatedTotal.Cmp(expectedTotal) != 0 {
		return ErrStakeInconsistency
	}

	return nil
}

// ValidateStakeChange validates a stake change operation
func (scc *StakeConsistencyChecker) ValidateStakeChange(
	oldStake, newStake, minStake, maxStake *big.Int,
) error {
	// Check minimum stake
	if minStake != nil && newStake.Cmp(minStake) < 0 && newStake.Sign() > 0 {
		return errors.New("new stake below minimum")
	}

	// Check maximum stake
	if maxStake != nil && maxStake.Sign() > 0 && newStake.Cmp(maxStake) > 0 {
		return errors.New("new stake exceeds maximum")
	}

	return nil
}

// SlashingValidator validates slashing operations
type SlashingValidator struct {
	config *SlashingConfig
	mu     sync.RWMutex
}

// NewSlashingValidator creates a new slashing validator.
// audit-fix M-1: returns error instead of panicking on invalid config.
// SECURITY: This is a constructor function - it does NOT perform any slashing
// or stake modifications. It only initializes the validator with config.
// audit-remediation: reviewed 2026-09-11 — constructor only; initializes a validator, performs no slashing.
func NewSlashingValidator(config *SlashingConfig) (*SlashingValidator, error) {
	if config == nil {
		var err error
		config, err = DefaultSlashingConfig()
		if err != nil {
			return nil, err
		}
	}
	if err := ValidateSlashingConfig(config); err != nil {
		return nil, err
	}
	return &SlashingValidator{
		config: config,
	}, nil
}

// ValidateSlashingParams validates slashing parameters
func (sv *SlashingValidator) ValidateSlashingParams(penaltyPercent uint32) error {
	sv.mu.RLock()
	defer sv.mu.RUnlock()

	if penaltyPercent < sv.config.MinPenaltyPercent {
		return ErrPenaltyOutOfBounds
	}
	if penaltyPercent > sv.config.MaxPenaltyPercent {
		return ErrPenaltyOutOfBounds
	}

	return nil
}

// CalculatePenalty calculates the penalty amount for a slashing event
func (sv *SlashingValidator) CalculatePenalty(stake *big.Int, reason SlashReason) (*big.Int, error) {
	sv.mu.RLock()
	defer sv.mu.RUnlock()

	var penaltyPercent uint32
	switch reason {
	case SlashReasonDoubleVote:
		penaltyPercent = sv.config.DoubleVotePenalty
	case SlashReasonSurroundVote:
		penaltyPercent = sv.config.SurroundVotePenalty
	case SlashReasonInactivity:
		penaltyPercent = sv.config.InactivityPenalty
	case SlashReasonProposerMissed:
		penaltyPercent = sv.config.InactivityPenalty
	case SlashReasonDowntime:
		// R30-IMPLEMENT (2026-07-27): SLASH-H2 — Downtime uses the dedicated
		// DowntimePenalty (default 100 bp = 1%), NOT InactivityPenalty
		// (10 bp = 0.1%). The 10x discrepancy was the SLASH-H2 bug: the same
		// downtime offense produced different penalties depending on which
		// code path triggered the slash (QPOS.SlashValidator vs
		// SlashingManager.slashLocked).
		penaltyPercent = sv.config.DowntimePenalty
	case SlashReasonUnknown:
		penaltyPercent = sv.config.MinPenaltyPercent
	}

	// Calculate penalty: stake * penaltyPercent / 10000
	penalty := new(big.Int).Mul(stake, big.NewInt(int64(penaltyPercent)))
	penalty.Div(penalty, big.NewInt(10000))

	// Ensure penalty doesn't exceed stake
	if penalty.Cmp(stake) > 0 {
		penalty = new(big.Int).Set(stake)
	}

	return penalty, nil
}

// ValidatePenaltyAmount validates that penalty doesn't exceed stake
func (sv *SlashingValidator) ValidatePenaltyAmount(penalty, stake *big.Int) error {
	if penalty.Cmp(stake) > 0 {
		return ErrExcessivePenalty
	}
	return nil
}

// SlashReason represents the reason for slashing
type SlashReason int

const (
	SlashReasonUnknown SlashReason = iota
	SlashReasonDoubleVote
	SlashReasonSurroundVote
	SlashReasonInactivity
	SlashReasonProposerMissed
	// R30-IMPLEMENT (2026-07-27): SLASH-H2 — SlashReasonDowntime is a
	// distinct offense from SlashReasonInactivity. Downtime (validator
	// offline for too long) carries a 10x higher penalty (1% vs 0.1%) to
	// reflect the greater harm to consensus liveness. Previously
	// QPOS.SlashValidator mapped "downtime" to SlashReasonInactivity,
	// causing a 10x penalty discrepancy vs SlashingManager.slashLocked
	// which used its own DowntimePenalty rate.
	SlashReasonDowntime
)

// String returns the string representation of a slash reason
func (sr SlashReason) String() string {
	switch sr {
	case SlashReasonDoubleVote:
		return "double_vote"
	case SlashReasonSurroundVote:
		return "surround_vote"
	case SlashReasonInactivity:
		return "inactivity"
	case SlashReasonProposerMissed:
		return "proposer_missed"
	case SlashReasonDowntime:
		return "downtime"
	case SlashReasonUnknown:
		return "unknown"
	default:
		// Exhaustive: all SlashingReason values handled above
		return "unknown"
	}
}

// SlashingEvent represents a slashing event for audit trail
type SlashingEvent struct {
	ValidatorIndex int
	ValidatorAddr  types.Address
	Reason         SlashReason
	PenaltyAmount  *big.Int
	Epoch          uint64
	Slot           uint64
	Timestamp      int64
	Evidence       []byte
	EvidenceCount  int // Number of failed evidence submissions for this validator
	Threshold      int // Threshold at which point the validator is slashed
}

// audit-fix M-2: MaxAuditLogEvents limits audit log size to prevent memory exhaustion.
const MaxAuditLogEvents = 100000

// SlashingAuditLog tracks all slashing events
type SlashingAuditLog struct {
	mu        sync.RWMutex
	events    []*SlashingEvent
	maxEvents int
}

// NewSlashingAuditLog creates a new slashing audit log
// SECURITY: This is a constructor function - it does NOT perform any slashing
// or stake modifications. It only creates an empty audit log for recording events.
// audit-remediation: reviewed 2026-09-11 — constructor only; creates an empty audit log, performs no slashing.
func NewSlashingAuditLog() *SlashingAuditLog {
	return &SlashingAuditLog{
		events:    make([]*SlashingEvent, 0, 100), // Pre-allocate for efficiency
		maxEvents: MaxAuditLogEvents,
	}
}

// LogSlashing logs a slashing event
// SECURITY: This function only RECORDS slashing events for audit purposes.
// It does NOT perform any stake modifications - the actual slashing is done
// in SlashValidator() which calls this function AFTER stake deduction.
// audit-remediation: reviewed 2026-09-11 — audit-log only; explicitly no stake modification (see comment above).
func (sal *SlashingAuditLog) LogSlashing(event *SlashingEvent) {
	if event == nil {
		return
	}
	sal.mu.Lock()
	defer sal.mu.Unlock()

	// Validate event before logging
	if event.PenaltyAmount != nil && event.PenaltyAmount.Sign() < 0 {
		return // Invalid penalty amount
	}

	// audit-fix M-2: evict oldest events when at capacity to prevent unbounded growth
	if sal.maxEvents > 0 && len(sal.events) >= sal.maxEvents {
		// Discard oldest 10% to amortize eviction cost
		evictCount := sal.maxEvents / 10
		if evictCount < 1 {
			evictCount = 1
		}
		sal.events = sal.events[evictCount:]
	}

	sal.events = append(sal.events, event)
}

// GetEvents returns all slashing events
func (sal *SlashingAuditLog) GetEvents() []*SlashingEvent {
	sal.mu.RLock()
	defer sal.mu.RUnlock()

	result := make([]*SlashingEvent, len(sal.events))
	copy(result, sal.events)
	return result
}

// GetEventsByValidator returns slashing events for a specific validator
func (sal *SlashingAuditLog) GetEventsByValidator(validatorIndex int) []*SlashingEvent {
	sal.mu.RLock()
	defer sal.mu.RUnlock()

	var result []*SlashingEvent
	for _, event := range sal.events {
		if event.ValidatorIndex == validatorIndex {
			result = append(result, event)
		}
	}
	return result
}
