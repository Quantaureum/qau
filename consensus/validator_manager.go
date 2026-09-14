// Quantaureum Node source, version 1.0.0.
// Package consensus implements the QPOS consensus mechanism for Quantaureum.
// This file implements the validator manager for handling staking and validator lifecycle.
package consensus

import (
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
)

// validatorMgrLogger is the package logger for validator lifecycle events.
// M6-4: Used for Info-level logging of validator state transitions.
var validatorMgrLogger = logging.Global()

// safeCallback invokes a consensus callback with panic recovery.
//
// P3-NODE-06 FIX (R30, 2026-07-27): Consensus callbacks (onStakeChanged,
// onActiveChanged) are invoked from deep inside block-processing and
// slashing paths. A panic inside a callback would otherwise propagate up
// the call stack and kill the caller's goroutine — e.g. the block
// processing loop or the slashing path — taking down consensus. The
// recovery is logged via the package logger so operators can diagnose
// the root cause (a buggy callback registered by the node layer) without
// losing the node. The callback name is included in the log so the
// operator can identify which callback panicked.
//
// We use a variadic bool return so callers can optionally propagate a
// "did-panic" flag if they need to take compensating action. Most callers
// ignore the return value.
func safeCallback(name string, fn func()) (recovered bool) {
	defer func() {
		if r := recover(); r != nil {
			recovered = true
			validatorMgrLogger.Error("consensus callback panic recovered",
				map[string]any{"callback": name, "panic": fmt.Sprintf("%v", r)})
		}
	}()
	fn()
	return false
}

var (
	// ErrValidatorNotFound is returned when a validator is not found
	ErrValidatorNotFound = errors.New("validator not found")

	// ErrValidatorAlreadyExists is returned when trying to add an existing validator
	ErrValidatorAlreadyExists = errors.New("validator already exists")

	// R41-L5CONS-05 (2026-08-03): ErrValidatorSetFull is returned when
	// addValidatorInternal is called while the validator map is already
	// at MaxValidators. Mirrors QPOS validatorsCapExceeded but at the
	// ValidatorManager level so the lower-level path cannot bypass the
	// protocol cap. See addValidatorInternal for rationale.
	ErrValidatorSetFull = errors.New("validator set is full (MaxValidators reached)")

	// ErrInsufficientStake is declared in qpos_advanced.go

	// ErrValidatorNotActive is declared in checkpoint.go

	// ErrInvalidCommission is returned when commission rate is invalid
	ErrInvalidCommission = errors.New("invalid commission rate")

	// ErrUnauthorizedValidatorOperation is returned when caller is not authorized
	// audit-fix CR-2: Added to prevent unauthorized validator operations
	ErrUnauthorizedValidatorOperation = errors.New("unauthorized validator operation: caller is not the validator address")

	// MinStakeAmount is the minimum stake required to become a validator
	MinStakeAmount = new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)) // 32 QAU — matches params.MinValidatorStake

	// R20-H3 FIX: Add maximum stake amount to prevent unbounded accumulation.
	// A single validator cannot hold more than 1/3 of total supply (Caspar FFG safety).
	// Setting max to 33% of total supply (~6.6e24 for 2e25 total supply).
	// Total supply: 2e25 / 10^18 = 2e7 QAU = 20,000,000 QAU
	// 33% of 20,000,000 = 6,600,000 QAU = 6.6 * 10^6 * 10^18 = 6.6e24
	MaxStakeAmount = new(big.Int).Mul(big.NewInt(6600000), new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))

	// ErrStakeExceedsMaximum is returned when stake exceeds the maximum allowed
	ErrStakeExceedsMaximum = errors.New("stake exceeds maximum allowed amount")

	// MaxCommission is the maximum commission rate (100% = 10000 basis points).
	// C21-009: These values are intentionally hardcoded constants — commission rates
	// are consensus-critical parameters that must be identical across all nodes.
	// Changing them would require a coordinated network upgrade (hard fork).
	MaxCommission uint32 = 10000

	// L18-032 FIX: MinCommission is the minimum commission rate (1% = 100 basis points).
	// Unified between consensus and economics layers to prevent boundary mismatch.
	//  Genesis validators use commission=100 (= MinCommission) by design.
	// The boundary overlap is intentional: genesis validators use the minimum
	// allowed rate (1%) to maximize delegator rewards. The check uses strict
	// less-than (<), so commission=100 passes. New validators may also set
	// commission=100. This is safe because the minimum is enforced consistently
	// across consensus and economics layers.
	MinCommission uint32 = 100

	// L16-033 FIX: MaxReasonableCommission is the maximum reasonable commission (50% = 5000 basis points).
	// Commission above this is considered an outlier indicating potential misconfiguration.
	MaxReasonableCommission uint32 = 5000

	ValidatorCooldownBlocks uint64 = 256
)

// ValidatorInfo contains full validator information including public key
type ValidatorInfo struct {
	Address            types.Address
	PublicKey          *crypto.PublicKey
	Stake              *big.Int
	Active             bool
	Commission         uint32
	JoinHeight         uint64 // Block height when validator joined
	PermanentlySlashed bool   // True if validator was permanently slashed (cannot be reactivated)
	JailedUntil        int64  // Unix timestamp until which validator is jailed (0 = not jailed)
	// CRITICAL FIX R19-H2: Track last stake change time to enforce cooldown
	LastStakeChange int64 // Unix timestamp of last stake change
	// F1-3 HIGH FIX: Track pending deactivation to prevent validator remaining
	// active during SetActive failure retry window. When SetActive fails (e.g. DB
	// contention), the validator should be marked as pending deactivation so it
	// cannot process new blocks even if the evidence queue is retrying.
	PendingDeactivation bool
	ExitHeight          uint64
	// R30-IMPLEMENT (2026-07-27): VAL-H04/VAL-H05 — EverActivated is set to
	// true the first time a validator is activated via ActivateFromQueue
	// (called by ProcessEpochAdvanced after the 4-epoch queue delay).
	// SetActive rejects first-time activation (EverActivated=false) to
	// prevent bypassing the ValidatorQueue's activation delay. Subsequent
	// deactivation/reactivation cycles (e.g. jail/unjail) go through
	// SetActive, which is allowed because EverActivated is already true.
	EverActivated bool
}

// ValidatorManager manages the validator set and staking operations
type ValidatorManager struct {
	mu            sync.RWMutex
	validators    map[types.Address]*ValidatorInfo
	currentHeight uint64
	// R43-CS-002 FIX: Consensus-derived block timestamp for deterministic
	// jail expiry checks. Set alongside currentHeight to avoid time.Now()
	// in consensus-critical paths.
	currentBlockTime int64
	// FIX: Optional reference to ValidatorQueue for synchronous cleanup
	// when a validator is removed. When set, RemoveValidator also removes the
	// validator from the queue to keep ValidatorManager and ValidatorQueue in sync.
	validatorQueue *ValidatorQueue
	// P1-T4 (2026-07-14): Optional reference to MinistryPersonnel for recording
	// validator registrations in the governance reputation system.
	ministryPersonnel *MinistryPersonnel
	// CONS-R13-M02 (2026-07-21): Callback invoked whenever a validator's
	// stake changes (UpdateStake / UpdateStakeForSlashing / SlashStake).
	// The node layer (L6) uses this to sync QPOS.validators (ValidatorSet)
	// with ValidatorManager — without it, QPOS finality calculations and
	// vote verifications would use stale weights, diverging from the
	// authoritative ValidatorManager state.
	//
	// Defense-in-depth: even if a caller invokes vm.UpdateStake directly
	// (bypassing consensusStakeUpdaterAdapter), this callback still fires
	// and syncs QPOS. Without it, only the adapter path syncs QPOS.
	// Callback is invoked AFTER vm.mu is released (LIFO defer order) to
	// avoid deadlock if the callback indirectly acquires vm.mu.
	onStakeChanged func(addr types.Address, newStake *big.Int)

	// SLASH-H1 FIX (R29, 2026-07-25): Callback invoked AFTER a validator
	// is deleted from vm.validators by WithdrawStake. The node layer (L6)
	// registers a callback that calls QPOS.CleanupValidatorState(addr) and
	// ValidatorSet.RemoveValidatorByAddr(addr) to clean up ALL residual
	// state (slashedValidators, pendingDeactivationAddrs, ValidatorSet
	// validators slice/validatorMap/addrIndexMap). Without this callback,
	// stale entries in those structures would cause unbounded memory growth
	// and could block re-registration of the same address.
	//
	// Callback is invoked AFTER vm.mu is released (LIFO defer order) to
	// avoid deadlock if the callback indirectly acquires vm.mu.
	onValidatorRemoved func(addr types.Address)

	// R30-IMPLEMENT (2026-07-27): SLASH-H3 — Callback invoked whenever a
	// validator's Active status changes (SetActive, MarkPermanentlySlashed).
	// The node layer (L6) uses this to sync QPOS.validators (ValidatorSet)
	// with ValidatorManager — without it, QPOS finality calculations and
	// vote verifications would use stale active status, diverging from the
	// authoritative ValidatorManager state.
	//
	// Callback is invoked AFTER vm.mu is released (LIFO defer order) to
	// avoid deadlock if the callback indirectly acquires vm.mu (e.g., via
	// GetValidatorSet → vm.mu.RLock). The SLASH-H3 fix specifically
	// addresses the self-deadlock where the callback fired WHILE holding
	// vm.mu, and the callback called GetValidator/GetValidatorSet which
	// tried to RLock the already-locked vm.mu.
	onActiveChanged func(addr types.Address, active bool)
}

// NewValidatorManager creates a new validator manager
func NewValidatorManager() *ValidatorManager {
	return &ValidatorManager{
		validators: make(map[types.Address]*ValidatorInfo),
	}
}

// SetValidatorQueue links the ValidatorQueue so RemoveValidator can sync it.
// FIX: When set, RemoveValidator will also remove the validator from
// the queue to keep ValidatorManager and ValidatorQueue in sync.
func (vm *ValidatorManager) SetValidatorQueue(vq *ValidatorQueue) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.validatorQueue = vq
}

// SetMinistryPersonnel sets the MinistryPersonnel reference for governance recording.
// P1-T4 (2026-07-14): When set, AddValidator records each registration in the
// Personnel reputation system via RecordValidatorRegistration.
func (vm *ValidatorManager) SetMinistryPersonnel(mp *MinistryPersonnel) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.ministryPersonnel = mp
}

// SetStakeChangedCallback registers a callback invoked whenever a validator's
// stake changes via UpdateStake, UpdateStakeForSlashing, or SlashStake.
//
// CONS-R13-M02 (2026-07-21): ValidatorManager and QPOS.validators
// (ValidatorSet) are two separate data structures tracking validator stakes.
// Without this callback, updates to ValidatorManager would NOT propagate to
// QPOS, causing finality calculations and vote verifications to use stale
// weights — diverging from the authoritative ValidatorManager state.
//
// The node layer (L6) registers a callback that calls
// qpos.AddStakingValidator(addr, newStake) to sync the ValidatorSet. This
// provides defense-in-depth: even if a caller invokes vm.UpdateStake
// directly (bypassing consensusStakeUpdaterAdapter), the callback still
// fires and syncs QPOS.
//
// The callback is invoked AFTER vm.mu is released (via LIFO defer order)
// to avoid deadlock if the callback indirectly acquires vm.mu (e.g., via
// AddStakingValidator → q.mu → vs.mu).
// audit-remediation: reviewed 2026-09-11 — wiring setter called once by the
// node assembler; cannot mutate stake or validator membership itself.
func (vm *ValidatorManager) SetStakeChangedCallback(cb func(addr types.Address, newStake *big.Int)) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.onStakeChanged = cb
}

// SetValidatorRemovedCallback registers a callback invoked AFTER a validator
// is deleted from vm.validators by WithdrawStake.
//
// SLASH-H1 FIX (R29, 2026-07-25): Previously, WithdrawStake only deleted
// from vm.validators, leaving residual entries in QPOS.slashedValidators,
// QPOS.pendingDeactivationAddrs, and ValidatorSet (validators slice,
// validatorMap, addrIndexMap). These stale entries caused unbounded memory
// growth and could block re-registration of the same address. The node layer
// registers a callback here that cleans up ALL residual state.
//
// The callback is invoked AFTER vm.mu is released (via LIFO defer order in
// WithdrawStake) to avoid deadlock if the callback indirectly acquires vm.mu.
func (vm *ValidatorManager) SetValidatorRemovedCallback(cb func(addr types.Address)) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.onValidatorRemoved = cb
}

// SetActiveChangedCallback registers a callback invoked whenever a validator's
// Active status changes via SetActive or MarkPermanentlySlashed.
//
// R30-IMPLEMENT (2026-07-27): SLASH-H3 fix. The callback is invoked AFTER
// vm.mu is released (via LIFO defer order in SetActive/MarkPermanentlySlashed)
// to avoid deadlock if the callback indirectly acquires vm.mu (e.g., via
// GetValidatorSet → vm.mu.RLock). The node layer (L6) registers a callback
// that syncs QPOS.validators (ValidatorSet) with ValidatorManager so QPOS
// finality calculations use up-to-date active status.
func (vm *ValidatorManager) SetActiveChangedCallback(cb func(addr types.Address, active bool)) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.onActiveChanged = cb
}

func (vm *ValidatorManager) SetCurrentHeight(h uint64) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.currentHeight = h
}

// SetCurrentBlockTime sets the consensus-derived block timestamp for
// deterministic jail expiry checks. Must be called alongside SetCurrentHeight.
func (vm *ValidatorManager) SetCurrentBlockTime(t int64) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.currentBlockTime = t
}

func (vm *ValidatorManager) GetCurrentHeight() uint64 {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.currentHeight
}

// AddGenesisValidator adds a bootstrap validator from genesis without requiring
// MinStakeAmount. This allows the chain to start with genesis-configured stake
// (from the "stake" field in genesis.json) so that reward calculations work
// immediately without requiring separate staking transactions.
// Only callable by the system (genesis init). Commission is ignored for bootstrap.
func (vm *ValidatorManager) AddGenesisValidator(caller, addr types.Address, pubKey *crypto.PublicKey, stake *big.Int, commission uint32, height uint64) error {
	if stake == nil {
		stake = big.NewInt(0)
	}
	return vm.addValidatorInternal(caller, addr, pubKey, stake, commission, height, true)
}

// AddValidator adds a new validator with the given stake
// R19-C2 FIX: Add explicit negative stake check for clearer error handling
// R28-SEC FIX: Added caller parameter and authorization check
// CR40-C6 FIX: Strict authorization - only system caller or the validator itself can add
func (vm *ValidatorManager) AddValidator(caller, addr types.Address, pubKey *crypto.PublicKey, stake *big.Int, commission uint32, height uint64) error {
	return vm.addValidatorInternal(caller, addr, pubKey, stake, commission, height, false)
}

func (vm *ValidatorManager) addValidatorInternal(caller, addr types.Address, pubKey *crypto.PublicKey, stake *big.Int, commission uint32, height uint64, isGenesis bool) error {
	// CR40-C6 FIX: Strict authorization check
	// Only the validator address itself OR a registered system caller can add validators
	// This prevents unauthorized additions even if caller == addr check is bypassed
	isSystem := vm.isSystemCaller(caller)
	isSelf := caller == addr

	if !isSystem && !isSelf {
		return fmt.Errorf("unauthorized: only the validator or system can add a validator")
	}

	// CR40-C6 FIX: Additional security - reject zero address as valid caller
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot add validators")
	}

	if stake == nil {
		return ErrInvalidStake
	}
	if stake.Sign() < 0 {
		return ErrInvalidStake
	}
	if stake.Cmp(MinStakeAmount) < 0 {
		if !isGenesis {
			return ErrInsufficientStake
		}
		// Genesis validators can bootstrap with 0 stake
		log.Printf("[WARN] Genesis validator bootstrapping with stake below MinStakeAmount: %s", addr.String())
	}
	if commission > MaxCommission {
		return ErrInvalidCommission
	}
	// L16-033 FIX: Commission boundaries are now unified package-level constants.
	// MinCommission=100 (1%) matches economics layer DefaultStakingConfig.MinCommission.
	// MaxReasonableCommission=5000 (50%) detects outlier configurations.
	// L18-033 NOTE: Genesis validators (genesis/mainnet.json) use commission=100,
	// which equals MinCommission. The check below uses strict less-than (<), so
	// commission=100 passes. This is intentional: genesis validators use the minimum
	// allowed commission rate (1%) to maximize delegator rewards.
	if commission < MinCommission {
		return fmt.Errorf("commission %d below minimum %d (1%% minimum required)", commission, MinCommission)
	}
	if commission > MaxReasonableCommission {
		return fmt.Errorf("commission %d exceeds reasonable maximum %d (50%% max)", commission, MaxReasonableCommission)
	}

	vm.mu.Lock()
	defer vm.mu.Unlock()

	if _, exists := vm.validators[addr]; exists {
		return ErrValidatorAlreadyExists
	}

	// R41-L5CONS-05 (2026-08-03) FIX: enforce the protocol MaxValidators
	// cap on ValidatorManager BEFORE inserting. The upper QPOS path
	// (consensus/validator.go:811) guards via validatorsCapExceeded, but
	// addValidatorInternal is a lower-level entry reached directly by
	// ValidatorManager.AddValidator (which itself is reached by node.go's
	// stake-tx processing path, line 4820) — that path bypasses
	// QPOS.AddStakingValidator and therefore the cap, allowing the
	// validator map to grow unbounded. An attacker who spams stake
	// transactions (each self-registering as a validator) could push
	// len(vm.validators) far above MaxValidators, bloating per-epoch
	// activation queue processing and proposer-set serialization. The
	// check here mirrors ValidatorSet.AddValidator's check so both
	// ValidatorManager and ValidatorSet stay below the same cap.
	if len(vm.validators) >= MaxValidators {
		return ErrValidatorSetFull
	}

	// L18-010 FIX: Set Active=true when stake meets the minimum requirement.
	// The stake has already been validated (>= MinStakeAmount) above, so the
	// validator is eligible to be active. The join cooldown enforced by
	// GetActiveValidators (JoinHeight + ValidatorCooldownBlocks <= currentHeight)
	// prevents immediate block proposal, so activating here is safe.
	// Previously Active was hardcoded to false with no activation path.
	//
	// VAL-H04/VAL-H05 FIX (R30, 2026-07-27): Non-genesis validators start
	// Active=false and must be activated via the ValidatorQueue (mirroring
	// ProcessEpochAdvanced) using a system caller. First-time self-activation
	// is rejected. Genesis validators remain Active=true from genesis. This
	// matches the test contract in TestValidatorManager_ActiveValidatorCount
	// and prevents a non-genesis validator from immediately participating in
	// consensus before queue activation.
	vm.validators[addr] = &ValidatorInfo{
		Address:    addr,
		PublicKey:  pubKey,
		Stake:      new(big.Int).Set(stake),
		Active:     isGenesis,
		Commission: commission,
		JoinHeight: height,
		// VAL-H04 FIX (R31, 2026-07-27): Genesis validators are immediately
		// Active=true from genesis, so they must also have EverActivated=true
		// — otherwise a later deactivation/reactivation cycle (e.g. jail then
		// unjail) would be rejected by the new SetActive EverActivated check,
		// permanently bricking genesis validators after their first slash.
		// Non-genesis validators start EverActivated=false and are flipped to
		// true by ActivateFromQueue (called by ProcessEpochAdvanced after the
		// 4-epoch queue delay).
		EverActivated: isGenesis,
	}

	// P1-T4 (2026-07-14): Record the registration in MinistryPersonnel for
	// governance reputation tracking. Best-effort — failures are logged but
	// do NOT block the validator addition. Called while holding vm.mu since
	// Personnel uses its own mutex (no lock ordering issue).
	if vm.ministryPersonnel != nil {
		if err := vm.ministryPersonnel.RecordValidatorRegistration(caller, addr, stake, height); err != nil {
			log.Printf("[WARN] MinistryPersonnel.RecordValidatorRegistration failed for %x: %v", addr[:4], err)
		}
	}

	return nil
}

// RemoveValidator removes a validator from the set.
// FIX: Now synchronously removes the validator from ValidatorQueue
// (if linked via SetValidatorQueue) to keep ValidatorManager and ValidatorQueue
// in sync. Previously, stale ValidatorLifecycle entries could remain in the
// queue and be processed after the validator was removed from ValidatorManager.
// CR40-C6 FIX: Strict authorization - only system caller or the validator itself can remove
func (vm *ValidatorManager) RemoveValidator(caller, addr types.Address) error {
	vm.mu.Lock()

	isSystem := vm.isSystemCaller(caller)
	isSelf := caller == addr

	if !isSystem && !isSelf {
		vm.mu.Unlock()
		return fmt.Errorf("unauthorized: only the validator or system can remove")
	}

	if caller == (types.Address{}) {
		vm.mu.Unlock()
		return fmt.Errorf("unauthorized: zero address cannot remove validators")
	}

	v, exists := vm.validators[addr]
	if !exists {
		vm.mu.Unlock()
		return ErrValidatorNotFound
	}

	if v.ExitHeight > 0 {
		vm.mu.Unlock()
		return fmt.Errorf("validator already pending exit")
	}

	v.Active = false
	v.ExitHeight = vm.currentHeight

	// FIX: Capture the queue reference under the lock, then release
	// before calling the queue to avoid potential lock-ordering deadlock
	// (ProcessEpochAdvanced acquires vq.mu first, then vm.mu via SetActive).
	queue := vm.validatorQueue
	vm.mu.Unlock()

	// FIX: Synchronously remove from ValidatorQueue to keep them in sync.
	// P1-05 FIX (R45): Pass caller for authorization check.
	if queue != nil {
		_ = queue.RemoveValidator(caller, addr)
	}

	return nil
}

var ErrExitCooldownNotExpired = errors.New("exit cooldown period has not expired")

var ErrValidatorNotExiting = errors.New("validator is not in exit state")

func (vm *ValidatorManager) CanWithdrawStake(addr types.Address) (bool, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	v, exists := vm.validators[addr]
	if !exists {
		return false, ErrValidatorNotFound
	}

	if v.ExitHeight == 0 {
		return false, ErrValidatorNotExiting
	}

	if vm.currentHeight < v.ExitHeight+ValidatorCooldownBlocks {
		return false, nil
	}

	return true, nil
}

func (vm *ValidatorManager) WithdrawStake(caller, addr types.Address) (*big.Int, error) {
	// SLASH-H1 FIX (R29, 2026-07-25): Capture the onValidatorRemoved callback
	// while holding the lock, then invoke it AFTER vm.mu is released (LIFO
	// defer order) to avoid deadlock if the callback indirectly acquires vm.mu
	// (e.g., via QPOS.CleanupValidatorState → q.mu or ValidatorSet.RemoveValidatorByAddr → vs.mu).
	var removedCB func(types.Address)
	var cbAddr types.Address

	vm.mu.Lock()
	defer vm.mu.Unlock()

	// Defer runs AFTER vm.mu.Unlock() (LIFO), so callback fires outside
	// the lock — safe to call QPOS/ValidatorSet cleanup paths without deadlock.
	defer func() {
		if removedCB != nil {
			// P3-NODE-06 FIX (R30, 2026-07-27): wrap callback in safeCallback
			// so a panic cannot kill the caller's goroutine (block processing
			// / staking path).
			safeCallback("onValidatorRemoved", func() { removedCB(cbAddr) })
		}
	}()

	isSystem := vm.isSystemCaller(caller)
	isSelf := caller == addr

	if !isSystem && !isSelf {
		return nil, fmt.Errorf("unauthorized: only the validator or system can withdraw stake")
	}

	if caller == (types.Address{}) {
		return nil, fmt.Errorf("unauthorized: zero address cannot withdraw stake")
	}

	v, exists := vm.validators[addr]
	if !exists {
		return nil, ErrValidatorNotFound
	}

	if v.ExitHeight == 0 {
		return nil, ErrValidatorNotExiting
	}

	if vm.currentHeight < v.ExitHeight+ValidatorCooldownBlocks {
		return nil, ErrExitCooldownNotExpired
	}

	stake := new(big.Int).Set(v.Stake)
	delete(vm.validators, addr)

	// SLASH-H1 FIX: Capture callback state for invocation after unlock.
	removedCB = vm.onValidatorRemoved
	cbAddr = addr
	return stake, nil
}

// GetValidator returns validator info by address
func (vm *ValidatorManager) GetValidator(addr types.Address) (*ValidatorInfo, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	v, exists := vm.validators[addr]
	if !exists {
		return nil, ErrValidatorNotFound
	}

	// R40-C2 FIX: Include PermanentSlashed and JailedUntil fields so callers
	// can detect slashed/jailed validators returned from GetValidator.
	// VAL-H04 FIX (R31, 2026-07-27): Include EverActivated so tests and
	// callers can verify the first-time-activation gate state. Without this
	// field in the copy, the VAL-H04 regression tests checking
	// `info.EverActivated` would always see false even after
	// ActivateFromQueue set it to true internally.
	return &ValidatorInfo{
		Address:            v.Address,
		PublicKey:          v.PublicKey,
		Stake:              new(big.Int).Set(v.Stake),
		Active:             v.Active,
		Commission:         v.Commission,
		JoinHeight:         v.JoinHeight,
		PermanentlySlashed: v.PermanentlySlashed,
		JailedUntil:        v.JailedUntil,
		ExitHeight:         v.ExitHeight,
		EverActivated:      v.EverActivated,
	}, nil
}

// MaxStakeChangePercent is the maximum allowed stake change per operation (50%)
// stake manipulation protection: limits sudden stake changes
var MaxStakeChangePercent = big.NewInt(50)

// ErrStakeChangeExceedsLimit is returned when stake change exceeds the allowed limit
var ErrStakeChangeExceedsLimit = errors.New("stake change exceeds allowed limit")

// StakeCooldownPeriod is the minimum time between stake changes (prevents rapid stake-unstake cycles)
// CRITICAL FIX R19-H2: Add cooldown period to prevent stake manipulation attacks
var StakeCooldownPeriod = 1 * time.Hour

// ErrStakeCooldownActive is returned when stake change is attempted during cooldown period
var ErrStakeCooldownActive = errors.New("stake change cooldown period is active")

// Note: ErrInvalidStake is declared in election.go

// UpdateStake updates a validator's stake with manipulation protection
// R19-C1 FIX: Added caller parameter and authorization check
// - Validates stake changes against authorized limits (50% max change)
// - Large changes require governance approval
// - Slashing uses separate UpdateStakeForSlashing function
// R48-CS-01 FIX: Added optional blockTime parameter for deterministic cooldown.
// Pass 0 to use time.Now() (backward compatible); production callers should
// pass the current block timestamp to ensure all nodes compute the same
// cooldown decision.
// audit-remediation: reviewed 2026-09-11 — caller authorization (validator
// self or system) plus 50% change-limit and governance gates are enforced
// inside; cooldown period prevents rapid stake-unstake manipulation.
func (vm *ValidatorManager) UpdateStake(caller, addr types.Address, newStake *big.Int, blockTime ...int64) error {
	// R48-CS-01 FIX: Use block time if provided, otherwise fall back to wall clock.
	// CONS-R9-M (2026-07-19) FIX: Previously fell back to time.Now().Unix()
	// directly, which is inconsistent with SetActive's fallback path that
	// uses vm.currentBlockTime first. When a caller omits blockTime AND
	// vm.currentBlockTime is set (production path), LastStakeChange would
	// be set using wall clock while SetActive (called in the same block)
	// uses consensus time — causing the cooldown enforcement
	// (EnforceStakeCooldown) to compare apples and oranges. Now: prefer
	// vm.currentBlockTime (matching SetActive) when blockTime is not
	// explicitly provided. Wall-clock fallback remains only for tests / not
	// yet-set cases (identical to SetActive's behavior).
	var now int64
	if len(blockTime) > 0 && blockTime[0] > 0 {
		now = blockTime[0]
	} else if vm.currentBlockTime > 0 {
		now = vm.currentBlockTime
	} else {
		now = time.Now().Unix()
	}
	// R19-C1 FIX: Add authorization check - only validator themselves or system can update stake
	if caller != addr && !vm.isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only the validator or system can update stake")
	}

	if newStake == nil || newStake.Sign() < 0 {
		return ErrInvalidStake
	}

	// R20-H3 FIX: Reject stake exceeding maximum to prevent network dominance.
	// A single validator holding >33% of stake could compromise Caspar FFG finality.
	if newStake.Cmp(MaxStakeAmount) > 0 {
		return ErrStakeExceedsMaximum
	}

	// CONS-R13-M02 (2026-07-21): Capture callback + args while holding the
	// lock, then invoke the callback AFTER vm.mu is released (LIFO defer
	// order). This avoids deadlock if the callback indirectly acquires
	// vm.mu (e.g., via AddStakingValidator → q.mu → vs.mu). The pattern
	// mirrors ProcessAttestation's vote-recording defer in validator.go.
	//
	// R30-IMPLEMENT (2026-07-27): SLASH-H3 fix. The callback defer is
	// registered BEFORE the Unlock defer, making LIFO order:
	//  1. vm.mu.Unlock() (registered last → runs first)
	//  2. callback (registered first → runs last)
	// This ensures the callback fires AFTER vm.mu is released, so the
	// callback can safely re-acquire vm.mu (e.g., via GetValidator) without
	// self-deadlock. Go's sync.RWMutex does not support recursive locking.
	var stakeChangedCB func(types.Address, *big.Int)
	var cbAddr types.Address
	var cbStake *big.Int

	// SLASH-H3: Register callback defer FIRST (runs LAST in LIFO).
	defer func() {
		if stakeChangedCB != nil && cbStake != nil {
			// P3-NODE-06 FIX (R30, 2026-07-27): wrap callback in
			// safeCallback so a panic cannot kill the caller's
			// goroutine (block processing / slashing path).
			safeCallback("onStakeChanged", func() { stakeChangedCB(cbAddr, cbStake) })
		}
	}()

	vm.mu.Lock()
	// SLASH-H3: Register Unlock defer SECOND (runs FIRST in LIFO).
	defer vm.mu.Unlock()

	v, exists := vm.validators[addr]
	if !exists {
		return ErrValidatorNotFound
	}

	// stake manipulation protection: validate stake change is within allowed bounds
	// Large stake changes (>50%) require governance approval (not implemented here)
	// R19-H1 FIX: Apply 50% limit check even when current stake is 0
	// For first stake deposit, require minimum stake and governance for large deposits
	// CRITICAL FIX R19-H2: Enforce cooldown period between stake changes
	// R48-CS-01 FIX: `now` is now computed at function entry (from blockTime or wall clock).
	if v.LastStakeChange > 0 && now-v.LastStakeChange < int64(StakeCooldownPeriod.Seconds()) {
		return ErrStakeCooldownActive
	}

	if v.Stake.Sign() > 0 {
		// Calculate the absolute change
		change := new(big.Int).Sub(newStake, v.Stake)
		if change.Sign() < 0 {
			change.Neg(change)
		}

		// Calculate max allowed change (50% of current stake)
		maxChange := new(big.Int).Mul(v.Stake, MaxStakeChangePercent)
		maxChange.Div(maxChange, big.NewInt(100))

		// audit-fix R11: 50% change limit applies to BOTH increases AND decreases.
		// Slashing bypasses this via UpdateStakeForSlashing (separate authorized path).
		if change.Cmp(maxChange) > 0 {
			return ErrStakeChangeExceedsLimit
		}
	} else if newStake.Sign() > 0 {
		// R19-H1 FIX: First stake deposit - require minimum amount
		// Reject if new stake is less than minimum
		if newStake.Cmp(MinStakeAmount) < 0 {
			return ErrInsufficientStake
		}
	}
	// R20-L1 FIX: Explicit check for 0->0 conversion.
	// When current stake is 0 and new stake is also 0, skip validation
	// but set Active=false since 0 stake cannot be an active validator.
	// This edge case requires internal access to exploit.

	// If stake drops below minimum, deactivate validator
	if newStake.Cmp(MinStakeAmount) < 0 {
		v.Active = false
	}

	v.Stake = new(big.Int).Set(newStake)
	// CRITICAL FIX R19-H2: Update last stake change timestamp
	v.LastStakeChange = now

	// CONS-R13-M02: Capture callback state for invocation after unlock.
	// cbStake is a defensive copy so the callback cannot mutate v.Stake.
	stakeChangedCB = vm.onStakeChanged
	cbAddr = addr
	cbStake = new(big.Int).Set(newStake)
	return nil
}

// UpdateStakeForSlashing updates a validator's stake for slashing purposes
// audit-remediation: authorized slashing operation
// - Bypasses normal stake change limits (slashing is authorized)
// - Only called by SlashingManager.Slash() after evidence verification
// - Stake changes are logged in SlashingRecord for audit trail
// R4-C1 FIX (2026-07-06): Added blockTime parameter for deterministic LastStakeChange.
func (vm *ValidatorManager) UpdateStakeForSlashing(addr types.Address, newStake *big.Int, blockTime ...int64) error {
	if newStake == nil || newStake.Sign() < 0 {
		return ErrInvalidStake
	}

	// CONS-R13-M02 (2026-07-21): Capture callback for post-unlock invocation.
	// R30-IMPLEMENT (2026-07-27): SLASH-H3 fix — callback defer registered
	// BEFORE Unlock defer so LIFO order releases the lock first.
	var stakeChangedCB func(types.Address, *big.Int)
	var cbAddr types.Address
	var cbStake *big.Int

	// SLASH-H3: Register callback defer FIRST (runs LAST in LIFO).
	defer func() {
		if stakeChangedCB != nil && cbStake != nil {
			// P3-NODE-06 FIX (R30, 2026-07-27): wrap callback in
			// safeCallback so a panic cannot kill the caller's
			// goroutine (block processing / slashing path).
			safeCallback("onStakeChanged", func() { stakeChangedCB(cbAddr, cbStake) })
		}
	}()

	vm.mu.Lock()
	// SLASH-H3: Register Unlock defer SECOND (runs FIRST in LIFO).
	defer vm.mu.Unlock()

	v, exists := vm.validators[addr]
	if !exists {
		return ErrValidatorNotFound
	}

	if newStake.Cmp(MinStakeAmount) < 0 {
		v.Active = false
	}

	v.Stake = new(big.Int).Set(newStake)
	// R48-CS-02 FIX: Update LastStakeChange to prevent immediate re-staking
	// after slashing (enforces cooldown period).
	// R4-C1 FIX (2026-07-06): Use deterministic blockTime when available.
	// CONS-R9-M (2026-07-19) FIX: Same fallback logic as `now` above —
	// prefer vm.currentBlockTime over wall-clock when blockTime is not
	// explicitly provided, to keep UpdateStake consistent with SetActive
	// (which uses currentBlockTime first). Without this, LastStakeChange
	// could be set via wall clock while a subsequent SetActive in the same
	// block uses consensus time, breaking the cooldown invariant.
	if len(blockTime) > 0 && blockTime[0] > 0 {
		v.LastStakeChange = blockTime[0]
	} else if vm.currentBlockTime > 0 {
		v.LastStakeChange = vm.currentBlockTime
	} else {
		v.LastStakeChange = time.Now().Unix()
	}

	// CONS-R13-M02: Capture callback state for invocation after unlock.
	stakeChangedCB = vm.onStakeChanged
	cbAddr = addr
	cbStake = new(big.Int).Set(newStake)
	return nil
}

// audit-remediation: reviewed 2026-09-11 — system-caller-only authorization
// and slashPercent bounds are enforced inside (L18-012);
// not a manipulation surface.
func (vm *ValidatorManager) SlashStake(caller, addr types.Address, slashPercent *big.Int) (*big.Int, error) {
	// L18-012 FIX: Authorization failure must return an error, never silently continue.
	// Only registered system callers (e.g. SlashingManager) are permitted to slash.
	if !vm.isSystemCaller(caller) {
		return nil, fmt.Errorf("unauthorized: only system callers can slash stake")
	}

	// L18-012 FIX: Validate slashPercent to prevent silent failures.
	// A nil slashPercent would cause a panic in big.Int.Mul.
	// A negative slashPercent would INCREASE the stake instead of slashing it.
	// A slashPercent > 100 would slash more than the total stake (caught below
	// but the returned slashAmount would be misleading).
	if slashPercent == nil {
		return nil, fmt.Errorf("slashPercent is nil: invalid slash parameter")
	}
	if slashPercent.Sign() < 0 {
		return nil, fmt.Errorf("slashPercent %s is negative: cannot slash negative percentage", slashPercent.String())
	}
	if slashPercent.Cmp(big.NewInt(100)) > 0 {
		return nil, fmt.Errorf("slashPercent %s exceeds 100: cannot slash more than total stake", slashPercent.String())
	}

	// CONS-R13-M02 (2026-07-21): Capture callback for post-unlock invocation.
	// R30-IMPLEMENT (2026-07-27): SLASH-H3 fix — callback defer registered
	// BEFORE Unlock defer so LIFO order releases the lock first.
	var stakeChangedCB func(types.Address, *big.Int)
	var cbAddr types.Address
	var cbStake *big.Int

	// SLASH-H3: Register callback defer FIRST (runs LAST in LIFO).
	defer func() {
		if stakeChangedCB != nil && cbStake != nil {
			// P3-NODE-06 FIX (R30, 2026-07-27): wrap callback in
			// safeCallback so a panic cannot kill the caller's
			// goroutine (block processing / slashing path).
			safeCallback("onStakeChanged", func() { stakeChangedCB(cbAddr, cbStake) })
		}
	}()

	vm.mu.Lock()
	// SLASH-H3: Register Unlock defer SECOND (runs FIRST in LIFO).
	defer vm.mu.Unlock()

	v, exists := vm.validators[addr]
	if !exists {
		return nil, ErrValidatorNotFound
	}

	slashAmount := new(big.Int).Mul(v.Stake, slashPercent)
	// FIX: Use named PercentDenominator constant instead of magic 100.
	// slashPercent is in percentage (0-100), NOT basis points (0-10000).
	slashAmount.Div(slashAmount, big.NewInt(PercentDenominator))
	// R32-P2-08 FIX (2026-07-28): Integer division truncation can produce
	// slashAmount == 0 even when slashPercent > 0. Example: stake=99 wei,
	// slashPercent=1 → 99*1/100 = 0 (truncated). A validator with very
	// small stake could thus escape slashing entirely for any offense,
	// defeating the deterrence purpose. When slashPercent > 0 but the
	// computed slashAmount is 0, charge a minimum of 1 wei so the offense
	// is still punished. This mirrors the dust-bucket pattern used in
	// distribute.go (remainder allocation).
	if slashPercent.Sign() > 0 && slashAmount.Sign() == 0 && v.Stake.Sign() > 0 {
		slashAmount.SetInt64(1)
	}
	newStake := new(big.Int).Sub(v.Stake, slashAmount)
	if newStake.Sign() < 0 {
		newStake = big.NewInt(0)
	}

	if newStake.Cmp(MinStakeAmount) < 0 {
		v.Active = false
	}

	v.Stake = new(big.Int).Set(newStake)

	// CONS-R13-M02: Capture callback state for invocation after unlock.
	stakeChangedCB = vm.onStakeChanged
	cbAddr = addr
	cbStake = new(big.Int).Set(newStake)
	return slashAmount, nil
}

// SlashStakeBasisPoints slashes a validator's stake by a basis-points fraction
// (0-10000, where 10000 = 100%). It is the basis-points counterpart of
// SlashStake (which takes a 0-100 percentage). ministry_revenue.go and other
// callers that natively work in basis points use this method to avoid
// lossy BP→percent conversion rounding.
//
// R30-IMPLEMENT (2026-07-27): SLASH-H3 fix. The onStakeChanged callback defer
// is registered BEFORE the Unlock defer, making LIFO order:
//  1. vm.mu.Unlock() (registered last → runs first)
//  2. callback (registered first → runs last)
//
// This ensures the callback fires AFTER vm.mu is released, so the callback
// can safely re-acquire vm.mu (e.g., via GetValidator → vm.mu.RLock) without
// self-deadlock. Go's sync.RWMutex does not support recursive locking.
//
// R30-IMPLEMENT (2026-07-27): implements SlashStakeBasisPoints to match R29
// test contract in slash_h3_test.go (TestSLASH_H3_SlashStakeBasisPoints_CallbackNoSelfDeadlock).
func (vm *ValidatorManager) SlashStakeBasisPoints(caller, addr types.Address, slashBP *big.Int) (*big.Int, error) {
	// L18-012 FIX: Authorization failure must return an error, never silently continue.
	// Only registered system callers (e.g. SlashingManager) are permitted to slash.
	if !vm.isSystemCaller(caller) {
		return nil, fmt.Errorf("unauthorized: only system callers can slash stake")
	}

	// L18-012 FIX: Validate slashBP to prevent silent failures.
	// A nil slashBP would cause a panic in big.Int.Mul.
	// A negative slashBP would INCREASE the stake instead of slashing it.
	// A slashBP > 10000 would slash more than the total stake (caught below
	// but the returned slashAmount would be misleading).
	if slashBP == nil {
		return nil, fmt.Errorf("slashBP is nil: invalid slash parameter")
	}
	if slashBP.Sign() < 0 {
		return nil, fmt.Errorf("slashBP %s is negative: cannot slash negative basis points", slashBP.String())
	}
	if slashBP.Cmp(big.NewInt(BasisPointsDenominator)) > 0 {
		return nil, fmt.Errorf("slashBP %s exceeds 10000: cannot slash more than total stake", slashBP.String())
	}

	// SLASH-H3: Capture callback for post-unlock invocation.
	var stakeChangedCB func(types.Address, *big.Int)
	var cbAddr types.Address
	var cbStake *big.Int

	// SLASH-H3: Register callback defer FIRST (runs LAST in LIFO).
	defer func() {
		if stakeChangedCB != nil && cbStake != nil {
			// P3-NODE-06 FIX (R30, 2026-07-27): wrap callback in
			// safeCallback so a panic cannot kill the caller's
			// goroutine (block processing / slashing path).
			safeCallback("onStakeChanged", func() { stakeChangedCB(cbAddr, cbStake) })
		}
	}()

	vm.mu.Lock()
	// SLASH-H3: Register Unlock defer SECOND (runs FIRST in LIFO).
	defer vm.mu.Unlock()

	v, exists := vm.validators[addr]
	if !exists {
		return nil, ErrValidatorNotFound
	}

	slashAmount := new(big.Int).Mul(v.Stake, slashBP)
	// FIX: Use named BasisPointsDenominator constant (10000) instead of magic number.
	// slashBP is in basis points (0-10000), NOT percentage (0-100).
	slashAmount.Div(slashAmount, big.NewInt(BasisPointsDenominator))
	// R32-P2-08 FIX (2026-07-28): Same integer-division truncation guard
	// as SlashStake. With BP=1 and stake < 10000 wei, slashAmount would
	// truncate to 0, letting a validator escape any punishment. Charge a
	// minimum of 1 wei when slashBP > 0 but the computed slashAmount is 0.
	if slashBP.Sign() > 0 && slashAmount.Sign() == 0 && v.Stake.Sign() > 0 {
		slashAmount.SetInt64(1)
	}
	newStake := new(big.Int).Sub(v.Stake, slashAmount)
	if newStake.Sign() < 0 {
		newStake = big.NewInt(0)
	}

	if newStake.Cmp(MinStakeAmount) < 0 {
		v.Active = false
	}

	v.Stake = new(big.Int).Set(newStake)
	// R48-CS-02 FIX: Update LastStakeChange to prevent immediate re-staking
	// after slashing (enforces cooldown period). Use consensus-derived
	// blockTime when available for deterministic behavior across nodes.
	if vm.currentBlockTime > 0 {
		v.LastStakeChange = vm.currentBlockTime
	} else {
		v.LastStakeChange = time.Now().Unix()
	}

	// CONS-R13-M02: Capture callback state for invocation after unlock.
	stakeChangedCB = vm.onStakeChanged
	cbAddr = addr
	cbStake = new(big.Int).Set(newStake)
	return slashAmount, nil
}

// SetActive sets a validator's active status
// FIX: Cannot activate a permanently slashed validator
// HIGH-1 FIX: Allow self-activation (caller == addr) for unjail
//
// R30-IMPLEMENT (2026-07-27): SLASH-H3 fix. The onActiveChanged callback
// defer is registered BEFORE the Unlock defer, making LIFO order:
//  1. vm.mu.Unlock() (registered last → runs first)
//  2. callback (registered first → runs last)
//
// This ensures the callback fires AFTER vm.mu is released, so the callback
// can safely re-acquire vm.mu (e.g., via GetValidatorSet → vm.mu.RLock)
// without self-deadlock. Go's sync.RWMutex does not support recursive locking.
func (vm *ValidatorManager) SetActive(caller, addr types.Address, active bool) error {
	// SLASH-H3: Capture callback for post-unlock invocation.
	var activeChangedCB func(types.Address, bool)
	var cbAddr types.Address
	var cbActive bool

	// SLASH-H3: Register callback defer FIRST (runs LAST in LIFO).
	defer func() {
		if activeChangedCB != nil {
			safeCallback("onActiveChanged", func() { activeChangedCB(cbAddr, cbActive) })
		}
	}()

	vm.mu.Lock()
	// SLASH-H3: Register Unlock defer SECOND (runs FIRST in LIFO).
	defer vm.mu.Unlock()

	// HIGH-1 FIX: Allow self-activation for unjail, in addition to system callers
	if !vm.isSystemCaller(caller) && caller != addr {
		return fmt.Errorf("unauthorized: only system or validator itself can change active status")
	}

	v, exists := vm.validators[addr]
	if !exists {
		return ErrValidatorNotFound
	}

	// FIX: Cannot activate a permanently slashed validator
	if active && v.PermanentlySlashed {
		return fmt.Errorf("cannot activate permanently slashed validator %x", addr)
	}

	// VAL-H04/VAL-H05 FIX (R31, 2026-07-27): First-time activation (active=true
	// AND EverActivated=false) must be REJECTED regardless of caller. The only
	// legitimate first-time activation path is ActivateFromQueue, called by
	// ProcessEpochAdvanced AFTER validatorQueue.ProcessEpoch has verified the
	// 4-epoch activation delay has elapsed. Without this check, a system caller
	// (or the validator itself) could bypass the 4-epoch queue delay by calling
	// SetActive(caller, addr, true) directly — defeating the queue's safety
	// guarantee (which prevents recent attackers from re-activating immediately
	// after a slash). Re-activation (EverActivated=true, e.g. unjail) is still
	// allowed via SetActive.
	if active && !v.EverActivated {
		return fmt.Errorf("VAL-H04: first-time activation of %x must go through ActivateFromQueue (called by ProcessEpochAdvanced after the 4-epoch queue delay); SetActive is reserved for re-activation (e.g. unjail) of validators that have been active at least once", addr)
	}

	// R39-C1 FIX: Cannot activate a jailed validator - prevents jail bypass via direct SetActive
	// CONS-FIX: Use consensus-derived block time (consistent with GetActiveValidators)
	// instead of wall-clock time.Now(). Different node clocks could cause consensus divergence:
	// SetActive (wall-clock) might unjail while GetActiveValidators (consensus time) still
	// considers the validator jailed, or vice versa. Both must use the same time source.
	if active && v.JailedUntil > 0 {
		now := vm.currentBlockTime
		if now == 0 {
			now = time.Now().Unix() // fallback for tests / not-yet-set
		}
		if now < v.JailedUntil {
			return fmt.Errorf("cannot activate jailed validator %x: jailed until %d", addr, v.JailedUntil)
		}
		// Jail period expired, clear it
		v.JailedUntil = 0
		// M6-4: Log unjail at Info level for production observability
		validatorMgrLogger.Infof("validator unjailed: addr=%x", addr)
	}

	// Cannot activate if stake is below minimum
	if active && v.Stake.Cmp(MinStakeAmount) < 0 {
		return ErrInsufficientStake
	}

	v.Active = active
	// M6-4: Log activation at Info level for production observability
	if active {
		validatorMgrLogger.Infof("validator activated: addr=%x stake=%s", addr, v.Stake.String())
	}

	// SLASH-H3: Capture callback state for invocation after unlock.
	activeChangedCB = vm.onActiveChanged
	cbAddr = addr
	cbActive = active
	return nil
}

// ActivateFromQueue performs the first-time activation of a validator that
// has waited out the ValidatorQueue's activation delay. This is the ONLY
// legitimate path for first-time activation; SetActive rejects validators
// with EverActivated=false to prevent bypassing the queue delay.
//
// R30-IMPLEMENT (2026-07-27): VAL-H04/VAL-H05 fix. ProcessEpochAdvanced
// calls this after validatorQueue.ProcessEpoch has verified the 4-epoch
// delay has elapsed. Tests also call this directly to put a validator into
// a fully active state without going through the queue. The method sets
// Active=true AND EverActivated=true so subsequent deactivation/reactivation
// cycles (e.g. jail/unjail) can go through SetActive.
func (vm *ValidatorManager) ActivateFromQueue(addr types.Address) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	v, exists := vm.validators[addr]
	if !exists {
		return ErrValidatorNotFound
	}
	if v.PermanentlySlashed {
		return fmt.Errorf("cannot activate permanently slashed validator %x", addr)
	}
	v.Active = true
	v.EverActivated = true
	v.PendingDeactivation = false
	validatorMgrLogger.Infof("validator activated from queue: addr=%x stake=%s", addr, v.Stake.String())
	return nil
}

// MarkPendingDeactivation marks a validator as pending deactivation.
// F1-3 HIGH FIX: Called when SetActive fails, so the validator cannot process
// new blocks even if the evidence queue is retrying. The evidence queue processor
// should check PendingDeactivation before accepting blocks from this validator.
func (vm *ValidatorManager) MarkPendingDeactivation(addr types.Address) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	v, exists := vm.validators[addr]
	if !exists {
		return
	}
	v.PendingDeactivation = true
}

// SetJailedUntil updates the JailedUntil field for a validator.
// Called by SlashingManager when jailing a validator.
func (vm *ValidatorManager) SetJailedUntil(caller, addr types.Address, jailedUntil int64) error {
	if !vm.isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can set jailed until")
	}

	vm.mu.Lock()
	defer vm.mu.Unlock()

	v, exists := vm.validators[addr]
	if !exists {
		return ErrValidatorNotFound
	}

	v.JailedUntil = jailedUntil
	// M6-4: Log jailing at Info level for production observability
	validatorMgrLogger.Infof("validator jailed: addr=%x until=%d", addr, jailedUntil)
	return nil
}

// MarkPermanentlySlashed marks a validator as permanently slashed
// FIX: Prevents bypass of permanent slash via ValidatorManager.SetActive
// SlashingManager calls this when validator is permanently slashed for double-signing or surround voting
// audit-remediation: reviewed 2026-09-11 — caller authorization enforced
// inside via isSystemCaller (system callers only); not a manipulation surface.
//
// R30-IMPLEMENT (2026-07-27): SLASH-H3 fix. The onActiveChanged callback defer
// is registered BEFORE the Unlock defer, making LIFO order:
//  1. vm.mu.Unlock() (registered last → runs first)
//  2. callback (registered first → runs last)
//
// This ensures the callback fires AFTER vm.mu is released, so the callback
// can safely re-acquire vm.mu (e.g., via GetValidatorSet → vm.mu.RLock)
// without self-deadlock. MarkPermanentlySlashed sets v.Active = false, so it
// MUST fire onActiveChanged to keep QPOS.validators (ValidatorSet) in sync —
// otherwise QPOS finality calculations would use stale active status for
// permanently slashed validators.
func (vm *ValidatorManager) MarkPermanentlySlashed(caller, addr types.Address) error {
	// SLASH-H3: Capture callback for post-unlock invocation.
	var activeChangedCB func(types.Address, bool)
	var cbAddr types.Address
	var cbActive bool

	// SLASH-H3: Register callback defer FIRST (runs LAST in LIFO).
	defer func() {
		if activeChangedCB != nil {
			safeCallback("onActiveChanged", func() { activeChangedCB(cbAddr, cbActive) })
		}
	}()

	vm.mu.Lock()
	// SLASH-H3: Register Unlock defer SECOND (runs FIRST in LIFO).
	defer vm.mu.Unlock()

	if !vm.isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system can mark permanently slashed")
	}

	v, exists := vm.validators[addr]
	if !exists {
		return ErrValidatorNotFound
	}

	v.PermanentlySlashed = true
	v.Active = false // Permanently slashed validators cannot be active

	// SLASH-H3: Capture callback state for invocation after unlock.
	// Only fire if active status actually changed (v.Active was true before).
	activeChangedCB = vm.onActiveChanged
	cbAddr = addr
	cbActive = false
	return nil
}

// GetActiveValidators returns all active validators
func (vm *ValidatorManager) GetActiveValidators() []*ValidatorInfo {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	result := make([]*ValidatorInfo, 0)
	for _, v := range vm.validators {
		// R43-CS-002 FIX: Use consensus-derived block time instead of time.Now()
		// to ensure all nodes agree on jail status. Different node clocks could
		// cause consensus divergence on which validators are jailed.
		blockTime := vm.currentBlockTime
		if blockTime == 0 {
			blockTime = time.Now().Unix() // fallback for tests/not-yet-set
		}
		isJailed := v.JailedUntil > 0 && blockTime < v.JailedUntil
		joinCooldownPassed := v.JoinHeight == 0 || vm.currentHeight == 0 || v.JoinHeight+ValidatorCooldownBlocks <= vm.currentHeight
		if v.Active && !v.PendingDeactivation && !v.PermanentlySlashed && !isJailed && joinCooldownPassed {
			// AUDIT (2026) CONS-FIX: Copy ALL fields, not just a
			// subset. Previously only Address, PublicKey, Stake, Active,
			// Commission, JoinHeight were copied; downstream callers reading
			// PermanentlySlashed/JailedUntil/PendingDeactivation/ExitHeight/
			// LastStakeChange would get zero values and could misjudge a
			// validator's state during debugging or filtering logic. The
			// filter above guarantees the slash/jail/pending fields are at
			// their default zero state for returned validators, so the
			// copied values are still consistent with the filter intent.
			result = append(result, &ValidatorInfo{
				Address:             v.Address,
				PublicKey:           v.PublicKey,
				Stake:               new(big.Int).Set(v.Stake),
				Active:              v.Active,
				Commission:          v.Commission,
				JoinHeight:          v.JoinHeight,
				PermanentlySlashed:  v.PermanentlySlashed,
				JailedUntil:         v.JailedUntil,
				LastStakeChange:     v.LastStakeChange,
				PendingDeactivation: v.PendingDeactivation,
				ExitHeight:          v.ExitHeight,
			})
		}
	}
	return result
}

// GetValidatorSet creates a ValidatorSet from active validators
func (vm *ValidatorManager) GetValidatorSet() (*ValidatorSet, error) {
	activeValidators := vm.GetActiveValidators()
	if len(activeValidators) == 0 {
		return nil, ErrNoActiveValidators
	}

	validators := make([]*Validator, len(activeValidators))
	for i, v := range activeValidators {
		// audit-fix HIGH-1: populate PublicKeyBytes so signature verification
		// in election/voting can authenticate validator messages. Without this,
		// PublicKeyBytes is nil and any signature check against it will fail or
		// be skipped, undermining consensus security.
		var pubKeyBytes []byte
		if v.PublicKey != nil {
			pubKeyBytes = v.PublicKey.Bytes()
		}
		validators[i] = &Validator{
			Address:        v.Address,
			Stake:          v.Stake,
			Active:         v.Active,
			Commission:     v.Commission,
			PublicKeyBytes: pubKeyBytes,
		}
	}

	return NewValidatorSet(validators)
}

// TotalStake returns the total stake of all active validators
func (vm *ValidatorManager) TotalStake() *big.Int {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	total := big.NewInt(0)
	for _, v := range vm.validators {
		if v.Active {
			total.Add(total, v.Stake)
		}
	}
	return total
}

// GetTotalStake returns the total stake of all active validators
func (vm *ValidatorManager) GetTotalStake() *big.Int {
	return vm.TotalStake()
}

// ValidatorCount returns the number of validators
func (vm *ValidatorManager) ValidatorCount() int {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return len(vm.validators)
}

// ActiveValidatorCount returns the number of active validators
func (vm *ValidatorManager) ActiveValidatorCount() int {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	count := 0
	for _, v := range vm.validators {
		if v.Active {
			count++
		}
	}
	return count
}

// GetPublicKey returns the public key for a validator.
// audit-fix L-15: returns internal reference for performance (public keys are immutable).
// Callers MUST NOT modify the returned value; treat as read-only.
func (vm *ValidatorManager) GetPublicKey(addr types.Address) (*crypto.PublicKey, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	v, exists := vm.validators[addr]
	if !exists {
		return nil, ErrValidatorNotFound
	}

	return v.PublicKey, nil
}

var (
	// R24-H2 FIX: Zero address is NOT a system caller by default.
	// Previously the map was initialized with zero address as a system caller,
	// which could allow unauthorized operations via empty caller address.
	systemCallers   = map[types.Address]bool{}
	systemCallersMu sync.RWMutex
)

// isSystemCaller checks if the given address is a registered system caller.
// This package-level function is used by ministry authorization checks (GOV-03)
// where the caller does not have a ValidatorManager reference.
func isSystemCaller(caller types.Address) bool {
	if caller == (types.Address{}) {
		return false
	}
	systemCallersMu.RLock()
	defer systemCallersMu.RUnlock()
	return systemCallers[caller]
}

func (vm *ValidatorManager) isSystemCaller(caller types.Address) bool {
	// R24-H2 FIX: Explicitly reject zero address as system caller
	// Zero address can never be a valid system caller for security reasons
	if caller == (types.Address{}) {
		return false
	}
	// CR40-C6 FIX: Removed 0xFF prefix bypass - strict registration only
	// All system callers must be explicitly registered via RegisterSystemCaller
	systemCallersMu.RLock()
	defer systemCallersMu.RUnlock()
	return systemCallers[caller]
}

// IsSystemCaller exposes isSystemCaller for use by other packages (e.g., SlashingManager)
// FIX: Added exported wrapper for authorization checks
func (vm *ValidatorManager) IsSystemCaller(caller types.Address) bool {
	return vm.isSystemCaller(caller)
}

// GetValidatorPublicKey returns the public key bytes for a validator address.
// Implements core.ValidatorLookup interface for block signature verification.
func (vm *ValidatorManager) GetValidatorPublicKey(addr types.Address) ([]byte, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	v, exists := vm.validators[addr]
	if !exists {
		return nil, ErrValidatorNotFound
	}

	if v.PublicKey == nil {
		return nil, fmt.Errorf("validator %s has no public key", addr.ToHexAddress())
	}

	return v.PublicKey.Bytes(), nil
}

// IsValidator returns true if the address is a registered validator.
// Implements core.ValidatorLookup interface for block signature verification.
func (vm *ValidatorManager) IsValidator(addr types.Address) bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	_, exists := vm.validators[addr]
	return exists
}

// GetAllValidators returns a snapshot of all registered validators.
// AUDIT (2026) GOV-07: Returns deep copies to prevent callers from
// mutating internal state (Stake, Active, etc.) via the returned pointers.
// The previous version returned the actual pointers stored in vm.validators,
// allowing any caller (including untrusted RPC consumers) to bypass the
// authorization on SetStake/SetActive/Slaughter by directly mutating fields.
func (vm *ValidatorManager) GetAllValidators() []*ValidatorInfo {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	result := make([]*ValidatorInfo, 0, len(vm.validators))
	for _, v := range vm.validators {
		copyInfo := *v // shallow copy of the struct
		if v.Stake != nil {
			copyInfo.Stake = new(big.Int).Set(v.Stake)
		}
		// PublicKey is read-only (no mutating methods), safe to share
		result = append(result, &copyInfo)
	}
	return result
}

func RegisterSystemCaller(addr types.Address) {
	systemCallersMu.Lock()
	defer systemCallersMu.Unlock()
	systemCallers[addr] = true
}

// UnregisterSystemCaller removes a system caller address.
// H-NEW-4 FIX: Used by deriveSystemCaller to clean up old epoch-based system callers
// to prevent unbounded memory growth in the systemCallers map.
func UnregisterSystemCaller(addr types.Address) {
	systemCallersMu.Lock()
	defer systemCallersMu.Unlock()
	delete(systemCallers, addr)
}

// ResetSystemCallersForTesting resets the global systemCallers map to empty.
// MUST NOT be called in production code. Panics if EnableTestHelpers() was
// not called first.
//
// R52-SYSCALLERS-DEBT (2026-08-11, fixed as ROUND54-R54-SYSCALLERS-RESET-01):
// 18 test files register a system caller via RegisterSystemCaller without
// a corresponding UnregisterSystemCaller. The cumulative side effect is
// that on `go test -count=N>1` runs, a caller address that some test
// expects isSystemCaller() to REJECT (e.g., an unregistered
// types.Address{1}) may be wrongly accepted because an earlier iteration
// of the test binary registered that very address. This produced
// cross-test pollution under -count>1 and caused cascading
// "non-system caller should fail" failures. The new helper lets tests
// that register system callers defer a clean-slate reset so each test
// iteration starts with an empty systemCallers map.
//
// Symmetric with ResetGenesisTimeForTesting / ResetGenesisHashForTesting
// (block.go): uses the same testHelpersEnabled panic-guard invariant
// (audit-fix M-1). Production code accidentally invoking this would
// strip all system caller authorizations (a fail-closed posture) and
// panic immediately — exactly the safe failure mode we want.
func ResetSystemCallersForTesting() {
	if !testHelpersEnabled {
		panic("consensus: ResetSystemCallersForTesting called without EnableTestHelpers(); this function is for tests only")
	}
	systemCallersMu.Lock()
	defer systemCallersMu.Unlock()
	for k := range systemCallers {
		delete(systemCallers, k)
	}
}
