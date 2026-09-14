// Quantaureum Node source, version 1.0.0.
package economics

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

var (
	ErrClaimTooFrequent = errors.New("claim too frequent, minimum interval not met")
	ErrMaxParticipants  = errors.New("program has reached max participants")
	// SECURITY FIX (P2-5): DeFiIncentiveManager previously reused error variables
	// from the staking module (ErrValidatorAlreadyExists, ErrInsufficientStake,
	// ErrStakeNotFound), which was misleading and could mask real staking errors.
	// These dedicated errors provide accurate semantic meaning.
	ErrProgramAlreadyExists = errors.New("incentive program already exists")
	ErrProgramNotFound      = errors.New("incentive program not found or not active")
	ErrInsufficientBudget   = errors.New("insufficient budget for reward")

	// R38-P1-13 FIX (2026-08-01): fail-closed errors. Previously CreateProgram
	// and ClaimReward used `len(map) > 0 && !map[k]` / `verifier != nil &&
	// !verifier(...)` guards, which silently skipped authorization when no
	// creators / no verifier was configured. That fail-open posture let any
	// address create programs and Sybil-claim rewards. The manager is now
	// fail-closed by default: an empty creators set or a nil verifier REJECTS
	// the call. Tests / one-shot allocation flows that intentionally want the
	// permissive posture must call AllowAllCreators() / AllowAllClaims().
	ErrUnauthorizedCreator = errors.New("creator not authorized: no creator is in the allow-list (fail-closed)")
	ErrCreatorNotInList    = errors.New("creator not in the authorizedCreators set (fail-closed)")
	ErrNoActionVerifier    = errors.New("no action verifier configured (fail-closed)")
	ErrActionNotVerified   = errors.New("incentivised action not verified for claimant")
)

type IncentiveType uint8

const (
	IncentiveTypeLiquidityProvision      IncentiveType = 0
	IncentiveTypeTradingVolume           IncentiveType = 1
	IncentiveTypeProtocolUsage           IncentiveType = 2
	IncentiveTypeGovernanceParticipation IncentiveType = 3
	IncentiveTypeDeveloperGrant          IncentiveType = 4
)

type IncentiveProgram struct {
	ID              string
	Name            string
	Type            IncentiveType
	TotalBudget     *big.Int
	RemainingBudget *big.Int
	RewardPerAction *big.Int
	StartBlock      uint64
	EndBlock        uint64
	MaxParticipants uint64
	Active          bool
	CreatedAt       int64
	// R37-FIX P2-ECON-05 (2026-07-30): Creator is the address that proposes
	// the program. When authorizedCreators is configured, CreateProgram
	// verifies Creator is in the authorized set.
	Creator types.Address
}

type IncentiveClaim struct {
	ProgramID   string
	Claimant    types.Address
	Amount      *big.Int
	BlockHeight uint64
	Timestamp   int64
	ActionType  string
	ActionData  []byte
}

type DeFiIncentiveManager struct {
	mu               sync.RWMutex
	programs         map[string]*IncentiveProgram
	claims           map[types.Address][]*IncentiveClaim
	totalDistributed *big.Int
	budgetSource     *big.Int
	lastClaimTime    map[types.Address]time.Time
	// programParticipants tracks unique claimants per program to enforce MaxParticipants.
	programParticipants map[string]map[types.Address]bool

	// R37-FIX P2-ECON-05 (2026-07-30): authorizedCreators gates CreateProgram.
	// When non-empty, only addresses in this map may create programs.
	authorizedCreators map[types.Address]bool

	// R37-FIX P2-ECON-05 (2026-07-30): actionVerifier gates ClaimReward.
	// When set, each claim must pass verification that the incentivised
	// action actually occurred (e.g. a liquidity deposit, a trade, etc.).
	actionVerifier func(programID string, claimant types.Address, blockHeight uint64) bool

	// R38-P1-13 FIX (2026-08-01): fail-closed authorization switches.
	//
	// allowAllCreators: when false (default), CreateProgram REJECTS any creator
	//   that is not in authorizedCreators. This is the secure default: an empty
	//   authorizedCreators set means "no one may create programs" rather than
	//   "anyone may create programs" (the previous fail-open behavior).
	//   Callers that intentionally want the permissive posture (unit tests,
	//   one-shot genesis allocation) must opt-in via AllowAllCreators().
	//
	// allowAllClaims: when false (default), ClaimReward REJECTS the claim when
	//   actionVerifier is nil (no Sybil check configured). Callers that
	//   intentionally want permissive claiming (e.g. unit tests that exercise
	//   pure accounting logic) must opt-in via AllowAllClaims().
	//
	// Rationale: production RPC `qau_claimDeFiIncentives` already verifies the
	// claimant's signature before calling, but that does not stop Sybil attacks
	// (a fresh signed address can still drain rewards). The fail-closed default
	// here forces the integration layer to consciously wire a verifier.
	allowAllCreators bool
	allowAllClaims   bool

	// R37-P3-43 FIX (2026-07-31): lastCleanupHeight records the block height
	// at which the last cleanup ran. Prevents cleanup on every ClaimReward call.
	lastCleanupHeight uint64
	// cleanupInterval is the number of blocks between automatic cleanups.
	cleanupInterval uint64
}

func NewDeFiIncentiveManager(initialBudget *big.Int) *DeFiIncentiveManager {
	return &DeFiIncentiveManager{
		programs:            make(map[string]*IncentiveProgram),
		claims:              make(map[types.Address][]*IncentiveClaim),
		totalDistributed:    new(big.Int),
		budgetSource:        new(big.Int).Set(initialBudget),
		lastClaimTime:       make(map[types.Address]time.Time),
		programParticipants: make(map[string]map[types.Address]bool),
		authorizedCreators:  make(map[types.Address]bool),
		cleanupInterval:     10000, // ~2.7 days at 12s block time
	}
}

// SetAuthorizedCreator adds an address to the set of creators allowed to call
// CreateProgram. R37 P2-ECON-05. When the set is empty, CreateProgram is
// unrestricted (backward-compatible for tests); in production the node layer
// should populate this before accepting external calls.
func (dim *DeFiIncentiveManager) SetAuthorizedCreator(addr types.Address) {
	dim.mu.Lock()
	defer dim.mu.Unlock()
	dim.authorizedCreators[addr] = true
}

// SetActionVerifier installs a callback that ClaimReward invokes to verify
// the claimant has actually performed the incentivised action. R37 P2-ECON-05.
func (dim *DeFiIncentiveManager) SetActionVerifier(fn func(programID string, claimant types.Address, blockHeight uint64) bool) {
	dim.mu.Lock()
	defer dim.mu.Unlock()
	dim.actionVerifier = fn
}

// AllowAllCreators opts the manager INTO a permissive creator posture.
//
// R38-P1-13 (2026-08-01): by default the manager is fail-closed — an empty
// authorizedCreators set REJECTS CreateProgram. This method reverts that
// behavior to "anyone may create a program". It is intended ONLY for:
//   - unit tests that exercise pure accounting logic without caring about
//     creator authorization, and
//   - one-shot genesis allocation flows that run before the authorized set
//     is wired up.
//
// SECURITY WARNING: do NOT call this from production request paths. If you
// reach for it, you almost certainly want SetAuthorizedCreator(addr) instead.
// Production nodes must populate authorizedCreators before accepting external
// CreateProgram calls, otherwise anyone can mint incentive programs.
func (dim *DeFiIncentiveManager) AllowAllCreators() {
	dim.mu.Lock()
	defer dim.mu.Unlock()
	dim.allowAllCreators = true
}

// AllowAllClaims opts the manager INTO a permissive claim posture.
//
// R38-P1-13 (2026-08-01): by default the manager is fail-closed — a nil
// actionVerifier REJECTS ClaimReward (no Sybil protection configured). This
// method reverts that behavior to "any signed claimant may claim". It is
// intended ONLY for unit tests that exercise pure accounting logic.
//
// SECURITY WARNING: do NOT call this from production request paths. Sybil
// attacks would drain the reward pool: a fresh signed address has no
// qualifying action but IssuedReward is paid out anyway. Production nodes
// must install an actionVerifier via SetActionVerifier before exposing
// ClaimReward to external callers.
func (dim *DeFiIncentiveManager) AllowAllClaims() {
	dim.mu.Lock()
	defer dim.mu.Unlock()
	dim.allowAllClaims = true
}

// CS-01 FIX: Added variadic blockTime parameter for deterministic timestamps.
// When provided, blockTime[0] is used for the program's CreatedAt timestamp
// instead of time.Now().Unix(), ensuring consensus-critical timestamps are
// deterministic across nodes.
func (dim *DeFiIncentiveManager) CreateProgram(program *IncentiveProgram, blockTime ...int64) error {
	dim.mu.Lock()
	defer dim.mu.Unlock()

	// R38-P1-13 FIX (2026-08-01): fail-closed creator authorization.
	//
	// Previously: `if len(dim.authorizedCreators) > 0 && !dim.authorizedCreators[...]`
	// This short-circuited when authorizedCreators was EMPTY, accepting ANY
	// creator — a fail-open posture. An attacker who wiped the allow-list
	// (or simply started from a fresh manager before the node wired it up)
	// could mint arbitrary incentive programs and drain budgetSource.
	//
	// Now: the empty allow-list REJECTS. Only allowAllCreators=true (set via
	// AllowAllCreators(), used by tests / one-shot allocation) bypasses the
	// check. Specific address-match failures get a distinct error so callers
	// can distinguish "no one is authorized" from "you specifically are not".
	if !dim.allowAllCreators {
		if len(dim.authorizedCreators) == 0 {
			return ErrUnauthorizedCreator
		}
		if !dim.authorizedCreators[program.Creator] {
			return fmt.Errorf("%w: address %s", ErrCreatorNotInList, program.Creator.ToHexAddress())
		}
	}

	if _, exists := dim.programs[program.ID]; exists {
		return ErrProgramAlreadyExists
	}

	if program.TotalBudget.Cmp(dim.budgetSource) > 0 {
		return ErrInsufficientBudget
	}

	dim.budgetSource.Sub(dim.budgetSource, program.TotalBudget)
	program.RemainingBudget = new(big.Int).Set(program.TotalBudget)
	// CS-01 FIX: Use deterministic blockTime for CreatedAt when provided;
	// fall back to time.Now() for non-consensus callers.
	if len(blockTime) > 0 {
		program.CreatedAt = blockTime[0]
	} else {
		program.CreatedAt = time.Now().Unix()
	}
	program.Active = true

	dim.programs[program.ID] = program
	return nil
}

// CS-04 FIX: Added variadic blockTime parameter for deterministic timestamps.
// When provided, blockTime[0] is used for the claim's audit Timestamp instead
// of time.Now().Unix(), ensuring consensus-critical timestamps are deterministic.
// The rate-limiting logic still uses time.Now() — it is NOT consensus-critical
// (local spam protection only; each node applies it independently).
func (dim *DeFiIncentiveManager) ClaimReward(programID string, claimant types.Address, blockHeight uint64, blockTime ...int64) (*IncentiveClaim, error) {
	dim.mu.Lock()
	defer dim.mu.Unlock()

	// R37-P3-43 FIX (2026-07-31): Trigger periodic cleanup of expired
	// program data to prevent unbounded memory growth. Only runs when
	// blockHeight exceeds lastCleanupHeight + cleanupInterval.
	if dim.cleanupInterval > 0 && blockHeight > dim.lastCleanupHeight+dim.cleanupInterval {
		dim.cleanupExpiredProgramsLocked(blockHeight)
		dim.lastCleanupHeight = blockHeight
	}

	program, exists := dim.programs[programID]
	if !exists {
		return nil, ErrProgramNotFound
	}

	if !program.Active {
		return nil, ErrProgramNotFound
	}

	if blockHeight < program.StartBlock || blockHeight > program.EndBlock {
		return nil, ErrProgramNotFound
	}

	// R38-P1-13 FIX (2026-08-01): fail-closed action verification.
	//
	// Previously: `if dim.actionVerifier != nil && !dim.actionVerifier(...)`
	// This short-circuited when actionVerifier was nil (the default), accepting
	// ANY claim — a Sybil-style fail-open posture. A fresh address with no
	// qualifying activity could drain rewards.
	//
	// Now: a nil verifier REJECTS. Only allowAllClaims=true (set via
	// AllowAllClaims(), used by tests) bypasses verification. Production
	// must install a verifier via SetActionVerifier before exposing claims.
	//
	// Note: this check runs AFTER the program lookup / active / block-range
	// checks, so callers that hit a non-existent program still get
	// ErrProgramNotFound (preserving existing test assertions).
	if !dim.allowAllClaims {
		if dim.actionVerifier == nil {
			return nil, ErrNoActionVerifier
		}
		if !dim.actionVerifier(programID, claimant, blockHeight) {
			return nil, ErrActionNotVerified
		}
	}

	// FIX: nil check for RewardPerAction before using it in Cmp/Set.
	// A nil RewardPerAction would panic on Cmp() and produce incorrect behavior
	// on Set(). Return an error instead of crashing.
	if program.RewardPerAction == nil {
		return nil, errors.New("reward per action is not configured for this program")
	}

	if program.RemainingBudget.Cmp(program.RewardPerAction) < 0 {
		return nil, ErrInsufficientBudget
	}

	// audit-fix: enforce MaxParticipants. A value of 0 means unlimited.
	// New claimants are rejected once the cap is reached; returning claimants
	// are still allowed to claim again.
	if program.MaxParticipants > 0 {
		participants, ok := dim.programParticipants[programID]
		if !ok {
			participants = make(map[types.Address]bool)
			dim.programParticipants[programID] = participants
		}
		if !participants[claimant] && uint64(len(participants)) >= program.MaxParticipants {
			return nil, ErrMaxParticipants
		}
	}

	// NOTE: Rate limiting uses time.Now() and is NOT consensus-critical.
	// It is a local protection against claim spam; each node applies it
	// independently and it does not affect on-chain state.
	const minClaimInterval = 1 * time.Hour
	if lastTime, exists := dim.lastClaimTime[claimant]; exists {
		if time.Since(lastTime) < minClaimInterval {
			return nil, ErrClaimTooFrequent
		}
	}

	// CS-04 FIX: Use deterministic blockTime for the audit timestamp when
	// provided; fall back to time.Now() for non-consensus callers.
	var claimTimestamp int64
	if len(blockTime) > 0 {
		claimTimestamp = blockTime[0]
	} else {
		claimTimestamp = time.Now().Unix()
	}

	claim := &IncentiveClaim{
		ProgramID:   programID,
		Claimant:    claimant,
		Amount:      new(big.Int).Set(program.RewardPerAction),
		BlockHeight: blockHeight,
		Timestamp:   claimTimestamp,
	}

	program.RemainingBudget.Sub(program.RemainingBudget, claim.Amount)
	dim.totalDistributed.Add(dim.totalDistributed, claim.Amount)
	dim.claims[claimant] = append(dim.claims[claimant], claim)
	// NOTE: lastClaimTime uses time.Now() for local rate limiting only;
	// NOT consensus-critical (see rate-limit check above).
	dim.lastClaimTime[claimant] = time.Now()

	// Register the claimant as a program participant (first claim only).
	if program.MaxParticipants > 0 {
		if participants := dim.programParticipants[programID]; participants != nil {
			participants[claimant] = true
		}
	}

	return claim, nil
}

// cleanupExpiredProgramsLocked removes data for programs that have ended.
// MUST be called with dim.mu held.
// R37-P3-43 FIX (2026-07-31): prevents unbounded memory growth from
// claims/lastClaimTime/programParticipants maps that were previously
// never cleaned.
func (dim *DeFiIncentiveManager) cleanupExpiredProgramsLocked(currentBlock uint64) {
	for programID, program := range dim.programs {
		// Keep active programs and programs that haven't ended yet.
		if program.Active || currentBlock <= program.EndBlock {
			continue
		}
		// Clean up participants for this program.
		delete(dim.programParticipants, programID)
		// Clean up claims referencing this program (compact per claimant).
		for claimant, claimList := range dim.claims {
			var remaining []*IncentiveClaim
			for _, c := range claimList {
				if c.ProgramID != programID {
					remaining = append(remaining, c)
				}
			}
			if len(remaining) == 0 {
				delete(dim.claims, claimant)
			} else {
				dim.claims[claimant] = remaining
			}
		}
		// Remove the program itself.
		delete(dim.programs, programID)
	}

	// Clean up lastClaimTime entries for claimants with no remaining claims.
	for claimant := range dim.lastClaimTime {
		if _, hasClaims := dim.claims[claimant]; !hasClaims {
			delete(dim.lastClaimTime, claimant)
		}
	}
}

// deepCopy returns a deep copy of the IncentiveProgram so callers cannot
// mutate the internal state through the returned pointer.
func (p *IncentiveProgram) deepCopy() *IncentiveProgram {
	if p == nil {
		return nil
	}
	return &IncentiveProgram{
		ID:              p.ID,
		Name:            p.Name,
		Type:            p.Type,
		TotalBudget:     cloneBigInt(p.TotalBudget),
		RemainingBudget: cloneBigInt(p.RemainingBudget),
		RewardPerAction: cloneBigInt(p.RewardPerAction),
		StartBlock:      p.StartBlock,
		EndBlock:        p.EndBlock,
		MaxParticipants: p.MaxParticipants,
		Active:          p.Active,
		CreatedAt:       p.CreatedAt,
	}
}

// cloneBigInt returns a copy of v, or a new zero if v is nil.
func cloneBigInt(v *big.Int) *big.Int {
	if v == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(v)
}

func (dim *DeFiIncentiveManager) GetProgram(programID string) (*IncentiveProgram, bool) {
	dim.mu.RLock()
	defer dim.mu.RUnlock()

	program, exists := dim.programs[programID]
	return program.deepCopy(), exists
}

func (dim *DeFiIncentiveManager) ListActivePrograms() []*IncentiveProgram {
	dim.mu.RLock()
	defer dim.mu.RUnlock()

	var active []*IncentiveProgram
	for _, program := range dim.programs {
		if program.Active {
			active = append(active, program.deepCopy())
		}
	}
	return active
}

func (dim *DeFiIncentiveManager) GetClaimsByUser(claimant types.Address) []*IncentiveClaim {
	dim.mu.RLock()
	defer dim.mu.RUnlock()

	claims := dim.claims[claimant]
	result := make([]*IncentiveClaim, len(claims))
	copy(result, claims)
	return result
}

func (dim *DeFiIncentiveManager) GetTotalDistributed() *big.Int {
	dim.mu.RLock()
	defer dim.mu.RUnlock()
	return new(big.Int).Set(dim.totalDistributed)
}

func (dim *DeFiIncentiveManager) GetRemainingBudget() *big.Int {
	dim.mu.RLock()
	defer dim.mu.RUnlock()
	return new(big.Int).Set(dim.budgetSource)
}

func (dim *DeFiIncentiveManager) DeactivateProgram(programID string) error {
	dim.mu.Lock()
	defer dim.mu.Unlock()

	program, exists := dim.programs[programID]
	if !exists {
		return ErrProgramNotFound
	}

	program.Active = false

	if program.RemainingBudget.Sign() > 0 {
		dim.budgetSource.Add(dim.budgetSource, program.RemainingBudget)
		program.RemainingBudget.SetInt64(0)
	}

	return nil
}

func (dim *DeFiIncentiveManager) AddBudget(amount *big.Int) {
	dim.mu.Lock()
	defer dim.mu.Unlock()
	dim.budgetSource.Add(dim.budgetSource, amount)
}

func (dim *DeFiIncentiveManager) GetProgramStats(programID string) (participants uint64, distributed *big.Int, remaining *big.Int) {
	dim.mu.RLock()
	defer dim.mu.RUnlock()

	program, exists := dim.programs[programID]
	if !exists {
		return 0, new(big.Int), new(big.Int)
	}

	participantSet := make(map[types.Address]bool)
	for addr, claims := range dim.claims {
		for _, claim := range claims {
			if claim.ProgramID == programID {
				participantSet[addr] = true
				break
			}
		}
	}

	return uint64(len(participantSet)), new(big.Int).Sub(program.TotalBudget, program.RemainingBudget), new(big.Int).Set(program.RemainingBudget)
}
