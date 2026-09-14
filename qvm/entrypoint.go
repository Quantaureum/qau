// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

const (
	EntryPointAddressHex = "0x000000000000000000000000000000000000756e69717565"

	MinStakeValue   = 1000000000000000000
	MinUnstakeDelay = 86400
	DepositGasCost  = 21000
	WithdrawGasCost = 21000
	StakeGasCost    = 21000
	UnstakeGasCost  = 21000
)

var (
	EntryPointAddress, _ = types.ParseHexAddress(EntryPointAddressHex)

	ErrValidationFailed    = fmt.Errorf("user op validation failed")
	ErrExecutionFailed     = fmt.Errorf("user op execution failed")
	ErrPaymasterFailed     = fmt.Errorf("paymaster validation failed")
	ErrInsufficientDeposit = fmt.Errorf("insufficient deposit")
	ErrStakeTooLow         = fmt.Errorf("stake too low")
	ErrUnstakeDelay        = fmt.Errorf("unstake delay not met")
	ErrAlreadyStaked       = fmt.Errorf("already staked")
	ErrNotStaked           = fmt.Errorf("not staked")
	ErrSenderNotContract   = fmt.Errorf("sender is not a contract")
	// QVM-M01 (R8 2026-07-19) FIX: Fail-closed error returned by
	// UnlockStake / WithdrawStake when no deterministic block timestamp has
	// been injected via SetBlockTime. Without this, wall-clock differences
	// across validators could cause WithdrawTime to differ by 1 second →
	// consensus fork on the same UserOperation.
	ErrEntryPointBlockTimeNotSet = fmt.Errorf("entrypoint: block time not set; executor must inject deterministic block timestamp via SetBlockTime before unstake/withdraw operations")
)

type DepositInfo struct {
	Deposit         *big.Int
	Staked          bool
	Stake           *big.Int
	UnstakeDelaySec uint64
	WithdrawTime    uint64
	// V21-017 FIX: Record where withdrawn funds should be sent.
	WithdrawAddress types.Address
}

type StakeInfo struct {
	Stake           *big.Int
	UnstakeDelaySec uint64
}

type EntryPoint struct {
	mu       sync.RWMutex
	executor *Executor
	deposits map[types.Address]*DepositInfo
	stakes   map[types.Address]*StakeInfo
	// R46-QV-01: Track withdrawn balances so WithdrawTo credits the target.
	balances map[types.Address]*big.Int
	// FIX: paymasters maps paymaster address → Paymaster interface.
	// Previously the EntryPoint never called ValidatePaymasterUserOp, allowing any
	// user to set an arbitrary Paymaster address and drain that paymaster's deposit.
	paymasters map[types.Address]Paymaster
	// QVM-M01 (R8 2026-07-19) FIX: Deterministic block timestamp injected by
	// HandleOps via SetBlockTime. Replaces time.Now().Unix() in UnlockStake /
	// WithdrawStake so all validators compute identical WithdrawTime and reach
	// identical unstake-delay decisions. Zero means "not set" → fail-closed.
	blockTime uint64
}

func NewEntryPoint(executor *Executor) *EntryPoint {
	return &EntryPoint{
		executor:   executor,
		deposits:   make(map[types.Address]*DepositInfo),
		stakes:     make(map[types.Address]*StakeInfo),
		balances:   make(map[types.Address]*big.Int),
		paymasters: make(map[types.Address]Paymaster),
	}
}

// RegisterPaymaster associates a Paymaster implementation with an address.
// FIX: required so that handleSingleOp can call
// ValidatePaymasterUserOp before executing the user operation.
func (ep *EntryPoint) RegisterPaymaster(addr types.Address, pm Paymaster) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.paymasters[addr] = pm
}

// UnregisterPaymaster removes a Paymaster association.
func (ep *EntryPoint) UnregisterPaymaster(addr types.Address) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	delete(ep.paymasters, addr)
}

// SetBlockTime injects the deterministic block timestamp (unix seconds) used
// for unstake-delay / withdraw-expiry decisions.
//
// QVM-M01 / R8-NEW-01 (R8 2026-07-19) FIX: The executor must call this with
// the current block's timestamp before HandleOps runs so that UnlockStake /
// WithdrawStake use block time instead of time.Now().Unix(). Without this,
// wall-clock differences across validators could cause WithdrawTime to differ
// by 1 second (straddling a unix-second boundary) → the same UserOperation
// succeeds on one validator and fails on another → consensus fork.
//
// A value of 0 clears the injected time and reverts to fail-closed behavior
// (UnlockStake / WithdrawStake return ErrEntryPointBlockTimeNotSet).
func (ep *EntryPoint) SetBlockTime(t uint64) {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.blockTime = t
}

// currentTime returns the deterministic block timestamp. Caller MUST hold
// ep.mu (either RLock or Lock). Returns ErrEntryPointBlockTimeNotSet when no
// block time has been injected (fail-closed).
func (ep *EntryPoint) currentTime() (uint64, error) {
	if ep.blockTime == 0 {
		return 0, ErrEntryPointBlockTimeNotSet
	}
	return ep.blockTime, nil
}

func (ep *EntryPoint) GetDepositInfo(account types.Address) *DepositInfo {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	info, ok := ep.deposits[account]
	if !ok || info == nil {
		return &DepositInfo{Deposit: big.NewInt(0)}
	}
	return info
}

func (ep *EntryPoint) BalanceOf(account types.Address) *big.Int {
	return new(big.Int).Set(ep.GetDepositInfo(account).Deposit)
}

func (ep *EntryPoint) DepositTo(account types.Address, amount *big.Int) error {
	if amount.Sign() <= 0 {
		return fmt.Errorf("deposit amount must be positive")
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	info, ok := ep.deposits[account]
	if !ok {
		info = &DepositInfo{Deposit: big.NewInt(0)}
	}
	info.Deposit = new(big.Int).Add(info.Deposit, amount)
	ep.deposits[account] = info
	return nil
}

// QVM-FIX: WithdrawTo now takes a StateDB parameter and actually moves
// the funds on-chain by calling stateDB.SetBalance on the withdrawAddress.
// Previously WithdrawTo only updated the in-memory `ep.balances` map — the
// amount was deducted from the sender's deposit but never credited to the
// withdrawAddress's chain balance, permanently locking the funds inside the
// EntryPoint contract. The in-memory balances map is still maintained so
// existing BalanceOf-style queries remain consistent.
func (ep *EntryPoint) WithdrawTo(account types.Address, withdrawAddress types.Address, amount *big.Int, stateDB StateDB) error {
	if stateDB == nil {
		return fmt.Errorf("WithdrawTo requires a non-nil StateDB")
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	info, ok := ep.deposits[account]
	if !ok || info.Deposit.Cmp(amount) < 0 {
		return ErrInsufficientDeposit
	}
	info.Deposit = new(big.Int).Sub(info.Deposit, amount)
	ep.deposits[account] = info
	// R46-QV-01 FIX: Credit the withdrawn amount to the withdrawAddress.
	// Previously the amount was deducted but never sent anywhere, effectively
	// burning the funds instead of withdrawing them.
	if ep.balances == nil {
		ep.balances = make(map[types.Address]*big.Int)
	}
	if ep.balances[withdrawAddress] == nil {
		ep.balances[withdrawAddress] = new(big.Int)
	}
	ep.balances[withdrawAddress].Add(ep.balances[withdrawAddress], amount)

	// QVM-FIX: Actually move the funds on-chain. Without this, the
	// amount was deducted from the deposit but never credited to the
	// withdrawAddress's chain balance — funds were permanently locked
	// inside the EntryPoint contract.
	wdAddr := Address(withdrawAddress)
	currentBalance := stateDB.GetBalance(wdAddr)
	stateDB.SetBalance(wdAddr, new(big.Int).Add(currentBalance, amount))
	return nil
}

func (ep *EntryPoint) AddStake(account types.Address, unstakeDelaySec uint64, amount *big.Int) error {
	if amount.Cmp(big.NewInt(MinStakeValue)) < 0 {
		return ErrStakeTooLow
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	info, ok := ep.deposits[account]
	if !ok {
		info = &DepositInfo{Deposit: big.NewInt(0)}
	}
	if info.Staked {
		return ErrAlreadyStaked
	}
	if info.Deposit.Cmp(amount) < 0 {
		return ErrInsufficientDeposit
	}
	info.Deposit = new(big.Int).Sub(info.Deposit, amount)
	info.Staked = true
	info.Stake = new(big.Int).Set(amount)
	info.UnstakeDelaySec = unstakeDelaySec
	ep.deposits[account] = info
	ep.stakes[account] = &StakeInfo{
		Stake:           new(big.Int).Set(amount),
		UnstakeDelaySec: unstakeDelaySec,
	}
	return nil
}

// UnlockStake starts the unstake delay timer for the account's stake.
//
// FIX: previously UnlockStake immediately returned the
// stake to the deposit and cleared Staked/WithdrawTime. This made
// WithdrawStake unreachable (it requires Staked=true and WithdrawTime>0),
// permanently locking funds. Now follows EIP-4337 semantics: UnlockStake
// only starts the unstake delay timer (WithdrawTime = now + UnstakeDelaySec).
// The actual fund release happens in WithdrawStake after the delay.
func (ep *EntryPoint) UnlockStake(account types.Address) error {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	info, ok := ep.deposits[account]
	if !ok || !info.Staked {
		return ErrNotStaked
	}
	// QVM-M01 / R8-NEW-01 (R8 2026-07-19) FIX: Use deterministic block
	// timestamp instead of time.Now().Unix() so all validators compute
	// identical WithdrawTime. Fail-closed when no block time injected.
	now, err := ep.currentTime()
	if err != nil {
		return err
	}
	if info.UnstakeDelaySec == 0 {
		// No delay configured — allow immediate withdrawal
		info.WithdrawTime = now
	} else {
		info.WithdrawTime = now + info.UnstakeDelaySec
	}
	ep.deposits[account] = info
	return nil
}

// WithdrawStake withdraws staked funds back to the deposit after the unstake
// delay has passed.
//
// FIX: previously used `withdrawAddress` as the lookup key
// for ep.deposits, but AddStake stores under `account`. This meant:
//   - Users could never withdraw their own stake (wrong key → not found)
//   - Or worse, a user could withdraw someone else's stake by passing that
//     address as withdrawAddress
//
// Now uses `account` (the staker) as the lookup key, and `withdrawAddress`
// is reserved for the caller to route the released funds.
//
// FIX: now checks `now >= WithdrawTime` instead of
// `WithdrawTime == 0`, and moves stake back to deposit (matching EIP-4337).
func (ep *EntryPoint) WithdrawStake(account types.Address, withdrawAddress types.Address, amount *big.Int) error {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	info, ok := ep.deposits[account]
	if !ok || info == nil {
		return fmt.Errorf("deposit info not available")
	}
	if !info.Staked {
		return ErrNotStaked
	}
	if info.WithdrawTime == 0 {
		return ErrUnstakeDelay
	}
	// QVM-M01 / R8-NEW-01 (R8 2026-07-19) FIX: Use deterministic block
	// timestamp instead of time.Now().Unix() so all validators reach identical
	// unstake-delay decisions. Fail-closed when no block time injected.
	now, err := ep.currentTime()
	if err != nil {
		return err
	}
	if now < info.WithdrawTime {
		return ErrUnstakeDelay
	}
	if info.Stake.Cmp(amount) < 0 {
		return ErrInsufficientDeposit
	}
	// Modify a copy to avoid mutating shared state while preserving the
	// original pointer for other concurrent readers that hold RLock.
	updated := *info
	updated.Stake = new(big.Int).Sub(info.Stake, amount)
	updated.Deposit = new(big.Int).Add(info.Deposit, amount)
	if updated.Stake.Sign() == 0 {
		updated.Staked = false
		updated.WithdrawTime = 0
	}
	ep.deposits[account] = &updated

	// Update stakes map
	if updated.Stake.Sign() == 0 {
		delete(ep.stakes, account)
	} else {
		ep.stakes[account] = &StakeInfo{
			Stake:           new(big.Int).Set(updated.Stake),
			UnstakeDelaySec: updated.UnstakeDelaySec,
		}
	}

	// V21-017 FIX: Record the withdrawAddress so callers know where to route funds.
	// Previously withdrawAddress was silently discarded, making it impossible to
	// verify where withdrawn funds should be sent.
	updated.WithdrawAddress = withdrawAddress
	ep.deposits[account] = &updated
	return nil
}

// GetStakeInfo returns the stake information for an account.
//
// FIX: previously accessed the ep.stakes map without holding
// the read lock, causing a data race when other goroutines modify the map
// concurrently (Go runtime detects this and panics). Also returned the
// internal *StakeInfo pointer, allowing callers to mutate internal state.
// Now uses RLock and returns a defensive copy.
func (ep *EntryPoint) GetStakeInfo(account types.Address) *StakeInfo {
	ep.mu.RLock()
	defer ep.mu.RUnlock()
	s, ok := ep.stakes[account]
	if !ok || s == nil {
		return &StakeInfo{Stake: big.NewInt(0)}
	}
	// Return a copy to prevent callers from mutating internal state
	return &StakeInfo{
		Stake:           new(big.Int).Set(s.Stake),
		UnstakeDelaySec: s.UnstakeDelaySec,
	}
}

func (ep *EntryPoint) HandleOps(bundle *encoding.UserOpBundle, stateDB StateDB, blockCtx *BlockContext) ([]*ExecutionResult, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}

	// QVM-M01 / R8-NEW-01 (R8 2026-07-19) FIX: Inject the deterministic block
	// timestamp from the block context so that UnlockStake / WithdrawStake (and
	// any other time-sensitive op) use block time instead of time.Now().Unix().
	// Without this, wall-clock differences across validators could cause the
	// same UserOperation to succeed on one validator and fail on another,
	// resulting in a consensus fork.
	ep.SetBlockTime(uint64(blockCtx.Timestamp))

	results := make([]*ExecutionResult, len(bundle.UserOps))
	gasUsed := uint64(0)

	for i, uo := range bundle.UserOps {
		if gasUsed >= blockCtx.GasLimit {
			return results, fmt.Errorf("block gas limit exceeded at user op %d", i)
		}

		result := ep.handleSingleOp(uo, stateDB, blockCtx, bundle)
		results[i] = result
		// QVM-Low (R9 2026-07-19) FIX: Guard against uint64 overflow in
		// accumulated gas accounting. Without this, an attacker who somehow
		// crafted a bundle with many UserOps each reporting near-MaxUint64
		// gas usage could wrap gasUsed back to a small number and bypass
		// the blockCtx.GasLimit check on the next iteration. In practice
		// the per-UserOp gas is bounded by handleSingleOp's own gas
		// accounting, but the cap below is cheap and prevents a silent
		// overflow if that bound is ever loosened.
		newGas := gasUsed + result.GasUsed
		if newGas < gasUsed {
			// Overflow — saturate at blockCtx.GasLimit so the next
			// iteration's `>= blockCtx.GasLimit` check trips and aborts
			// the bundle, rather than wrapping to a small value.
			newGas = blockCtx.GasLimit
		}
		gasUsed = newGas

		if result.Err != nil {
			return results, result.Err
		}
	}

	return results, nil
}

func (ep *EntryPoint) handleSingleOp(uo *encoding.UserOperation, stateDB StateDB, blockCtx *BlockContext, bundle *encoding.UserOpBundle) *ExecutionResult {
	senderAddr := Address(uo.Sender)

	if len(stateDB.GetCode(senderAddr)) == 0 && len(uo.InitCode) == 0 {
		return &ExecutionResult{
			Err:     ErrSenderNotContract,
			GasUsed: uo.PreVerificationGas,
		}
	}

	if len(uo.InitCode) > 0 {
		initResult := ep.executeInitCode(uo, stateDB, blockCtx)
		if initResult.Err != nil {
			return initResult
		}
	}

	validationResult := ep.validateUserOp(uo, stateDB, blockCtx, bundle)
	if validationResult.Err != nil {
		return validationResult
	}

	// FIX: Validate paymaster sponsorship before execution.
	// Previously the EntryPoint skipped ValidatePaymasterUserOp entirely, so any
	// user could set uo.Paymaster to an arbitrary address with deposit and drain
	// it. Now we require a registered Paymaster and call its validation method.
	if uo.Paymaster != nil {
		paymasterAddr := *uo.Paymaster
		ep.mu.RLock()
		pm, pmExists := ep.paymasters[paymasterAddr]
		ep.mu.RUnlock()
		if !pmExists {
			return &ExecutionResult{
				Err:     fmt.Errorf("%w: paymaster %s not registered", ErrPaymasterFailed, paymasterAddr.ToHexAddress()),
				GasUsed: validationResult.GasUsed,
			}
		}
		// Compute the max cost the paymaster could be charged.
		effectiveGasPrice := uo.EffectiveGasPrice(blockCtx.BaseFee)
		// R36-P2-QVMP-02 FIX: Check for uint64 overflow. Without this, an
		// attacker can set CallGasLimit near 2^63 so the wrapped sum is
		// small, bypassing the maxCost pre-check and draining the
		// paymaster deposit for a fraction of the real gas cost.
		maxGas := uo.CallGasLimit + uo.VerificationGasLimit
		if maxGas < uo.CallGasLimit || maxGas < uo.VerificationGasLimit {
			return &ExecutionResult{
				Err:     fmt.Errorf("%w: gas limit overflow", ErrPaymasterFailed),
				GasUsed: validationResult.GasUsed,
			}
		}
		maxGas += uo.PreVerificationGas
		if maxGas < uo.PreVerificationGas {
			return &ExecutionResult{
				Err:     fmt.Errorf("%w: gas limit overflow", ErrPaymasterFailed),
				GasUsed: validationResult.GasUsed,
			}
		}
		maxCost := new(big.Int).Mul(new(big.Int).SetUint64(maxGas), effectiveGasPrice)
		userOpHash := uo.Hash(bundle.EntryPoint, bundle.ChainID)
		pmResult, err := pm.ValidatePaymasterUserOp(uo, userOpHash, maxCost, stateDB)
		if err != nil {
			return &ExecutionResult{
				Err:     fmt.Errorf("%w: %v", ErrPaymasterFailed, err),
				GasUsed: validationResult.GasUsed,
			}
		}
		if pmResult != nil && !pmResult.Valid {
			return &ExecutionResult{
				Err:     fmt.Errorf("%w: %v", ErrPaymasterFailed, pmResult.ValidationError),
				GasUsed: validationResult.GasUsed,
			}
		}
	}

	execResult := ep.executeUserOp(uo, stateDB, blockCtx, bundle)
	if execResult.Err != nil {
		return execResult
	}

	// audit-fix C-3: chargeFees now returns error when balance insufficient
	if feeErr := ep.chargeFees(uo, stateDB, blockCtx, bundle); feeErr != nil {
		return &ExecutionResult{
			Err:     fmt.Errorf("%w: %v", ErrExecutionFailed, feeErr),
			GasUsed: execResult.GasUsed,
		}
	}

	totalGas := uo.PreVerificationGas + validationResult.GasUsed + execResult.GasUsed
	return &ExecutionResult{
		ReturnData: execResult.ReturnData,
		GasUsed:    totalGas,
		Logs:       execResult.Logs,
	}
}

func (ep *EntryPoint) executeInitCode(uo *encoding.UserOperation, stateDB StateDB, blockCtx *BlockContext) *ExecutionResult {
	senderAddr := Address(uo.Sender)
	initGas := uo.VerificationGasLimit / 2
	if initGas > uo.CallGasLimit {
		initGas = uo.CallGasLimit
	}

	result, _ := ep.executor.Create(
		stateDB,
		senderAddr,
		uo.InitCode,
		initGas,
		big.NewInt(0),
		blockCtx,
		0,
	)

	if result.Err != nil {
		return &ExecutionResult{
			Err:     fmt.Errorf("init code execution failed: %w", result.Err),
			GasUsed: initGas,
		}
	}

	return &ExecutionResult{GasUsed: result.GasUsed}
}

func (ep *EntryPoint) validateUserOp(uo *encoding.UserOperation, stateDB StateDB, blockCtx *BlockContext, bundle *encoding.UserOpBundle) *ExecutionResult {
	senderAddr := Address(uo.Sender)
	entryAddr := Address(EntryPointAddress)

	validateCallData := buildValidateUserOpCall(uo, bundle)

	result := ep.executor.CallWithRollback(
		stateDB,
		entryAddr,
		senderAddr,
		validateCallData,
		uo.VerificationGasLimit,
		big.NewInt(0),
		blockCtx,
		false,
		0,
	)

	if result.Err != nil {
		return &ExecutionResult{
			Err:     fmt.Errorf("%w: %v", ErrValidationFailed, result.Err),
			GasUsed: result.GasUsed,
		}
	}

	return &ExecutionResult{GasUsed: result.GasUsed}
}

func (ep *EntryPoint) executeUserOp(uo *encoding.UserOperation, stateDB StateDB, blockCtx *BlockContext, bundle *encoding.UserOpBundle) *ExecutionResult {
	senderAddr := Address(uo.Sender)
	entryAddr := Address(EntryPointAddress)

	result := ep.executor.CallWithRollback(
		stateDB,
		entryAddr,
		senderAddr,
		uo.CallData,
		uo.CallGasLimit,
		big.NewInt(0),
		blockCtx,
		false,
		0,
	)

	if result.Err != nil {
		return &ExecutionResult{
			Err:     fmt.Errorf("%w: %v", ErrExecutionFailed, result.Err),
			GasUsed: result.GasUsed,
		}
	}

	return result
}

// audit-fix C-3: chargeFees now returns error when neither paymaster nor sender
// has sufficient balance. Previously it silently failed, allowing free execution.
//
// FIX: Guard against uint64 overflow in totalGas calculation.
// CallGasLimit + VerificationGasLimit + PreVerificationGas could overflow uint64
// if a malicious UserOperation sets extremely large values, causing totalFee to
// wrap to a small number and allowing free execution.
func (ep *EntryPoint) chargeFees(uo *encoding.UserOperation, stateDB StateDB, blockCtx *BlockContext, bundle *encoding.UserOpBundle) error {
	effectiveGasPrice := uo.EffectiveGasPrice(blockCtx.BaseFee)
	// Use big.Int to avoid uint64 overflow when summing gas components.
	totalGasBig := new(big.Int).SetUint64(uo.CallGasLimit)
	totalGasBig.Add(totalGasBig, new(big.Int).SetUint64(uo.VerificationGasLimit))
	totalGasBig.Add(totalGasBig, new(big.Int).SetUint64(uo.PreVerificationGas))
	// Reject absurdly large gas totals (cap at 2^63 to stay well within int64).
	if totalGasBig.BitLen() > 63 {
		return fmt.Errorf("total gas overflow: %s", totalGasBig.String())
	}
	totalFee := new(big.Int).Mul(totalGasBig, effectiveGasPrice)

	ep.mu.Lock()
	defer ep.mu.Unlock()

	if uo.Paymaster != nil {
		paymasterAddr := *uo.Paymaster
		// QVM-R8-NEW-02 (R8 2026-07-19) FIX (defensive depth): Verify the
		// paymaster is registered in ep.paymasters. handleSingleOp already
		// checks this before execution, but chargeFees is also reachable as
		// an internal helper and should not silently deduct deposit from an
		// address that merely happens to have a DepositInfo entry but is not
		// a registered paymaster. Without this check, a future code path
		// could bypass the handleSingleOp pre-check and use any address with
		// deposit as a paymaster.
		if _, pmExists := ep.paymasters[paymasterAddr]; !pmExists {
			return fmt.Errorf("%w: paymaster %s not registered",
				ErrPaymasterFailed, paymasterAddr.ToHexAddress())
		}
		paymasterDeposit, ok := ep.deposits[paymasterAddr]
		if !ok {
			paymasterDeposit = &DepositInfo{Deposit: big.NewInt(0)}
		}
		if paymasterDeposit.Deposit.Cmp(totalFee) >= 0 {
			paymasterDeposit.Deposit = new(big.Int).Sub(paymasterDeposit.Deposit, totalFee)
			ep.deposits[paymasterAddr] = paymasterDeposit
			return nil
		}
		// QVM-FIX: Reject fallthrough to sender when paymaster is set
		// but insufficient. Previously this fell through to charge sender the
		// full fee, which bypasses paymaster's MaxTotalCost limit (validated in
		// ValidatePaymasterUserOp). An attacker could observe paymaster deposit
		// and craft a UserOp whose totalFee just exceeds the deposit, forcing
		// the sender to pay full cost outside paymaster's cost cap. EIP-4337
		// semantics: when a paymaster is specified, it must cover the full fee.
		return fmt.Errorf("paymaster %s insufficient deposit: need %s, has %s",
			paymasterAddr, totalFee.String(), paymasterDeposit.Deposit.String())
	}

	senderDeposit, ok := ep.deposits[uo.Sender]
	if !ok {
		senderDeposit = &DepositInfo{Deposit: big.NewInt(0)}
	}
	if senderDeposit.Deposit.Cmp(totalFee) >= 0 {
		senderDeposit.Deposit = new(big.Int).Sub(senderDeposit.Deposit, totalFee)
		ep.deposits[uo.Sender] = senderDeposit
		return nil
	}

	// audit-fix C-3: Return error instead of silently failing
	return fmt.Errorf("insufficient deposit for fees: need %s, paymaster has %s, sender has %s",
		totalFee.String(),
		func() string {
			if uo.Paymaster != nil {
				if d, ok := ep.deposits[types.Address(Address(*uo.Paymaster))]; ok {
					return d.Deposit.String()
				}
			}
			return "0"
		}(),
		senderDeposit.Deposit.String())
}

func buildValidateUserOpCall(uo *encoding.UserOperation, bundle *encoding.UserOpBundle) []byte {
	selector := [4]byte{0x3a, 0x87, 0x1c, 0xd2}
	callData := make([]byte, 4)
	copy(callData, selector[:])

	uoHash := uo.Hash(bundle.EntryPoint, bundle.ChainID)
	callData = append(callData, uoHash[:]...)

	nonceBytes := make([]byte, 32)
	nonceBytes[24] = byte(uo.Nonce >> 56)
	nonceBytes[25] = byte(uo.Nonce >> 48)
	nonceBytes[26] = byte(uo.Nonce >> 40)
	nonceBytes[27] = byte(uo.Nonce >> 32)
	nonceBytes[28] = byte(uo.Nonce >> 24)
	nonceBytes[29] = byte(uo.Nonce >> 16)
	nonceBytes[30] = byte(uo.Nonce >> 8)
	nonceBytes[31] = byte(uo.Nonce)
	callData = append(callData, nonceBytes...)

	return callData
}

// SimulateValidation simulates UserOperation validation without making persistent state changes.
// SECURITY: Uses snapshot/revert pattern - any state modifications during simulation are reverted.
// This is a read-only simulation that cannot be used for replay attacks because:
//  1. All state changes are reverted on return
//  2. Validation results are not stored
//  3. Each call starts from a clean snapshot
//
// The caller should implement rate limiting if this is called frequently from untrusted sources.
func (ep *EntryPoint) SimulateValidation(uo *encoding.UserOperation, stateDB StateDB, blockCtx *BlockContext, bundle *encoding.UserOpBundle) (*UserOpValidationResult, error) {
	if err := uo.Validate(); err != nil {
		return nil, err
	}

	snapshot := stateDB.Snapshot()
	defer stateDB.RevertToSnapshot(snapshot)

	validationResult := ep.validateUserOp(uo, stateDB, blockCtx, bundle)

	prefund := uo.RequiredPrefund()
	senderDeposit := ep.GetDepositInfo(uo.Sender)

	return &UserOpValidationResult{
		Valid:           validationResult.Err == nil,
		ValidationGas:   validationResult.GasUsed,
		RequiredPrefund: prefund,
		SenderDeposit:   senderDeposit.Deposit,
		ValidationError: validationResult.Err,
	}, nil
}

type UserOpValidationResult struct {
	Valid           bool
	ValidationGas   uint64
	RequiredPrefund *big.Int
	SenderDeposit   *big.Int
	ValidationError error
}

// GetNonce queries the EntryPoint contract for the per-key nonce of `sender`.
//
// QVM-M01 (R9 2026-07-19) FIX: Previously this method constructed a hardcoded
// BlockContext{BlockNumber:0, Timestamp:0, GasLimit:1000000} and used it to
// invoke ep.executor.Call on the EntryPoint contract. This is inconsistent
// with HandleOps / SimulateValidation, both of which receive the actual
// block context from the caller. A zero Timestamp is especially dangerous
// because any time-dependent opcode (e.g. TIMESTAMP, or a contract that
// derives time from BLOCKNUMBER) would compute a different result here than
// in the actual UserOperation execution path → a sender could pass
// SimulateValidation but fail HandleOps (or vice versa), producing consensus
// divergence across validators.
//
// The fix requires the caller to pass the real BlockContext. A nil blockCtx
// is rejected (fail-closed) to prevent silent fallback to a zeroed context.
func (ep *EntryPoint) GetNonce(sender types.Address, key uint64, stateDB StateDB, blockCtx *BlockContext) (uint64, error) {
	if blockCtx == nil {
		return 0, fmt.Errorf("entrypoint: GetNonce requires a non-nil block context")
	}

	senderAddr := Address(sender)
	entryAddr := Address(EntryPointAddress)

	selector := [4]byte{0x35, 0x5e, 0x7f, 0x8d}
	callData := make([]byte, 4)
	copy(callData, selector[:])

	keyBytes := make([]byte, 32)
	keyBytes[24] = byte(key >> 56)
	keyBytes[25] = byte(key >> 48)
	keyBytes[26] = byte(key >> 40)
	keyBytes[27] = byte(key >> 32)
	keyBytes[28] = byte(key >> 24)
	keyBytes[29] = byte(key >> 16)
	keyBytes[30] = byte(key >> 8)
	keyBytes[31] = byte(key)
	callData = append(callData, keyBytes...)

	result := ep.executor.Call(
		stateDB,
		entryAddr,
		senderAddr,
		callData,
		100000,
		big.NewInt(0),
		blockCtx,
		0,
	)

	if result.Err != nil {
		return 0, result.Err
	}

	if len(result.ReturnData) < 32 {
		return 0, fmt.Errorf("invalid nonce return data")
	}

	nonce := uint64(0)
	for i := 24; i < 32; i++ {
		nonce = (nonce << 8) | uint64(result.ReturnData[i])
	}
	return nonce, nil
}
