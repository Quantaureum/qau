// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"errors"
	"math"
	"math/big"
	"sync"
)

// Gas constants
const (
	// Base costs
	GasZero     uint64 = 0
	GasBase     uint64 = 2
	GasVeryLow  uint64 = 3
	GasLow      uint64 = 5
	GasMid      uint64 = 8
	GasHigh     uint64 = 10
	GasJump     uint64 = 8
	GasJumpDest uint64 = 1

	// Memory costs
	GasMemory uint64 = 3
	GasCopy   uint64 = 3

	// Storage costs - Cold/Warm differentiation (EIP-2929)
	GasSLoad       uint64 = 100   // Warm storage read
	GasSLoadCold   uint64 = 2100  // Cold storage read
	GasSStore      uint64 = 100   // Warm storage write base
	GasSStoreSet   uint64 = 20000 // Storage set (zero to non-zero)
	GasSStoreReset uint64 = 2900  // Storage reset (non-zero to non-zero)
	GasSStoreClear uint64 = 4800  // Refund for clearing storage

	// Access list costs (EIP-2930)
	GasAccessListAddress uint64 = 2400 // Cost per address in access list
	GasAccessListSlot    uint64 = 1900 // Cost per storage slot in access list
	GasColdAccountAccess uint64 = 2600 // Cold account access
	GasWarmAccountAccess uint64 = 100  // Warm account access
	GasColdSLoad         uint64 = 2100 // Cold SLOAD
	GasWarmSLoad         uint64 = 100  // Warm SLOAD

	// Call costs
	GasCall           uint64 = 100
	GasCallCold       uint64 = 2600
	GasCallValue      uint64 = 9000
	GasCallNewAccount uint64 = 25000
	GasCallStipend    uint64 = 2300

	// Create costs
	GasCreate      uint64 = 32000
	GasCreate2     uint64 = 32000
	GasCodeDeposit uint64 = 200 // Per byte
	// R32-P1-09 FIX (2026-07-28): EIP-3860 CreateDataGas — 2 gas per 32-byte
	// word of initcode. Charged in addition to GasCreate/GasCreate2 to prevent
	// underpriced deployment of oversized initcode (DoS vector). Previously
	// only enforced in opCreateGeneric (interpreter path); the public
	// Executor.Create / Create2 APIs bypassed this cost, allowing direct
	// callers (e.g. EntryPoint.executeInitCode) to deploy arbitrarily large
	// contracts without paying the EIP-3860 surcharge.
	GasCreateData uint64 = 2 // Per 32-byte word of initcode (EIP-3860)

	// Log costs
	GasLog      uint64 = 375
	GasLogTopic uint64 = 375
	GasLogData  uint64 = 8 // Per byte

	// Crypto costs
	GasSHA3     uint64 = 30
	GasSHA3Word uint64 = 6 // Per word

	// Post-quantum crypto costs (Kyber-768 KEM)
	GasKyberKeyGen uint64 = 50000
	GasKyberEncaps uint64 = 25000
	GasKyberDecaps uint64 = 25000

	// Transaction costs
	GasTxCreate      uint64 = 53000
	GasTxCall        uint64 = 21000
	GasTxDataZero    uint64 = 4
	GasTxDataNonZero uint64 = 16

	// EXP costs
	GasExp     uint64 = 10
	GasExpByte uint64 = 50 // Per byte of exponent

	// Balance costs
	GasBalance     uint64 = 100
	GasBalanceCold uint64 = 2600

	// Memory costs
	GasMemoryCopy uint64 = 3

	// Block operations
	GasBlockHash uint64 = 20 // BLOCKHASH opcode gas cost (Ethereum mainnet)

	// Self destruct
	GasSelfDestruct           uint64 = 5000
	GasSelfDestructNewAccount uint64 = 25000
)

// Gas errors
var (
	ErrOutOfGas      = errors.New("out of gas")
	ErrGasOverflow   = errors.New("gas overflow")
	ErrGasEstimation = errors.New("gas estimation failed")
)

// audit-fix C-3: CRITICAL - safe gas arithmetic to prevent silent uint64 overflow attacks
// These functions detect overflow and return error instead of silently wrapping to 0

// SafeAddGas safely adds two gas values, returning an error on overflow.
// Silent overflow in gas accounting is a CRITICAL vulnerability:
// overflow to 0 bypasses gas cost enforcement entirely.
func SafeAddGas(a, b uint64) (uint64, error) {
	if a > math.MaxUint64-b {
		return 0, ErrGasOverflow
	}
	return a + b, nil
}

// SafeMulGas safely multiplies two gas values, returning an error on overflow.
// Example: GasMemory * MemSize must not silently overflow.
func SafeMulGas(a, b uint64) (uint64, error) {
	if a > 0 && b > math.MaxUint64/a {
		return 0, ErrGasOverflow
	}
	return a * b, nil
}

// SafeSubGas safely subtracts b from a, returning an error on underflow.
// P3-QVM-GASSAFE FIX (R30, 2026-07-27): Added for completeness of the safe
// gas arithmetic suite (SafeAddGas/SafeMulGas/SafeSubGas). Underflow in gas
// subtraction would wrap to a huge value, bypassing gas accounting.
// Example: BalanceCold - Balance must not silently underflow if a future
// gas table misconfiguration swaps the order.
func SafeSubGas(a, b uint64) (uint64, error) {
	if a < b {
		return 0, ErrGasOverflow
	}
	return a - b, nil
}

// SafeAddGasTuple safely adds three gas values, useful for cumulative calculations.
// Returns error if any addition overflows.
func SafeAddGasTuple(a, b, c uint64) (uint64, error) {
	tmp, err := SafeAddGas(a, b)
	if err != nil {
		return 0, err
	}
	return SafeAddGas(tmp, c)
}

// AccessList tracks warm addresses and storage slots for gas calculation.
// Implements EIP-2929 and EIP-2930 access list functionality.
type AccessList struct {
	addresses map[Address]struct{}
	slots     map[Address]map[Hash]struct{}
	mu        sync.RWMutex
}

// NewAccessList creates a new access list.
func NewAccessList() *AccessList {
	return &AccessList{
		addresses: make(map[Address]struct{}),
		slots:     make(map[Address]map[Hash]struct{}),
	}
}

// AddAddress adds an address to the access list (marks as warm).
func (al *AccessList) AddAddress(addr Address) bool {
	al.mu.Lock()
	defer al.mu.Unlock()

	if _, exists := al.addresses[addr]; exists {
		return false // Already warm
	}
	al.addresses[addr] = struct{}{}
	return true // Was cold, now warm
}

// AddSlot adds a storage slot to the access list (marks as warm).
// EIP-2930 semantics: the address is also added if not already present.
// addrWasCold returns true only on the first call for a given address,
// slotWasCold returns true only on the first call for a given (addr, slot) pair.
func (al *AccessList) AddSlot(addr Address, slot Hash) (addrWasCold, slotWasCold bool) {
	al.mu.Lock()
	defer al.mu.Unlock()

	// Check if address was cold — must be done BEFORE any map modification.
	// This ensures correct per-call coldness reporting: on a second AddSlot
	// call with the same address but different slot, addrWasCold=false is
	// correct (address was already warm from the first call).
	if _, exists := al.addresses[addr]; !exists {
		addrWasCold = true
		// Add address to access list (mark as warm) on first access.
		al.addresses[addr] = struct{}{}
	}

	// Check if slot was cold — done before adding.
	if al.slots[addr] == nil {
		al.slots[addr] = make(map[Hash]struct{})
	}
	if _, exists := al.slots[addr][slot]; !exists {
		slotWasCold = true
		al.slots[addr][slot] = struct{}{}
	}

	return addrWasCold, slotWasCold
}

// IsAddressWarm checks if an address is in the access list (warm).
func (al *AccessList) IsAddressWarm(addr Address) bool {
	al.mu.RLock()
	defer al.mu.RUnlock()
	_, exists := al.addresses[addr]
	return exists
}

// IsSlotWarm checks if a storage slot is in the access list (warm).
func (al *AccessList) IsSlotWarm(addr Address, slot Hash) bool {
	al.mu.RLock()
	defer al.mu.RUnlock()
	if slots, exists := al.slots[addr]; exists {
		_, slotExists := slots[slot]
		return slotExists
	}
	return false
}

// Copy creates a deep copy of the access list.
func (al *AccessList) Copy() *AccessList {
	al.mu.RLock()
	defer al.mu.RUnlock()

	newAL := NewAccessList()
	for addr := range al.addresses {
		newAL.addresses[addr] = struct{}{}
	}
	for addr, slots := range al.slots {
		newAL.slots[addr] = make(map[Hash]struct{})
		for slot := range slots {
			newAL.slots[addr][slot] = struct{}{}
		}
	}
	return newAL
}

// Clear resets the access list.
func (al *AccessList) Clear() {
	al.mu.Lock()
	defer al.mu.Unlock()
	al.addresses = make(map[Address]struct{})
	al.slots = make(map[Address]map[Hash]struct{})
}

// AddressCount returns the number of addresses in the access list.
func (al *AccessList) AddressCount() int {
	al.mu.RLock()
	defer al.mu.RUnlock()
	return len(al.addresses)
}

// SlotCount returns the total number of slots in the access list.
func (al *AccessList) SlotCount() int {
	al.mu.RLock()
	defer al.mu.RUnlock()
	count := 0
	for _, slots := range al.slots {
		count += len(slots)
	}
	return count
}

// GasMeter tracks gas consumption during execution.
// NOTE: No mutex needed — EVM execution is single-threaded; one contract
// execution never accesses the GasMeter concurrently. The mutex was removed
// to eliminate ~20ns overhead per operation on the hot path (every opcode
// calls Consume gas).
//
// P3-V3 AUDIT NOTE (NOT safe for concurrent/parallel use): GasMeter is
// single-threaded by design and MUST NOT be shared across goroutines. The
// parallel executor (qvm/parallel) does NOT share a GasMeter between
// transactions — each parallel transaction gets its own isolated GasMeter
// (and its own MVMemory snapshot), so there is no cross-tx contention. If you
// ever introduce shared gas accounting, you MUST add synchronization here;
// as-is, concurrent calls to Consume/Refund/Used would race on the `used`/
// `refund` uint64 fields.
type GasMeter struct {
	limit      uint64      // Gas limit
	used       uint64      // Gas used
	refund     uint64      // Gas refund
	accessList *AccessList // Access list for cold/warm tracking
}

// NewGasMeter creates a new gas meter with the given limit.
func NewGasMeter(limit uint64) *GasMeter {
	return &GasMeter{
		limit:      limit,
		used:       0,
		refund:     0,
		accessList: NewAccessList(),
	}
}

// NewGasMeterWithAccessList creates a gas meter with a pre-populated access list.
func NewGasMeterWithAccessList(limit uint64, al *AccessList) *GasMeter {
	if al == nil {
		al = NewAccessList()
	}
	return &GasMeter{
		limit:      limit,
		used:       0,
		refund:     0,
		accessList: al,
	}
}

// Consume consumes the specified amount of gas.
// Explicit overflow checks prevent silent uint64 wraparound.
func (g *GasMeter) Consume(amount uint64) error {
	// Explicit overflow check: used + amount overflows uint64
	newUsed := g.used + amount
	if newUsed < g.used {
		return ErrGasOverflow
	}

	// Check if consumption would exceed limit
	if newUsed > g.limit {
		// Set to limit (not used + amount) and return out-of-gas error
		g.used = g.limit
		return ErrOutOfGas
	}

	g.used = newUsed
	return nil
}

// ConsumeWithRefund consumes gas and tracks potential refund.
// SECURITY (audit P2-R3-12): Use same overflow pattern as Consume for consistency.
func (g *GasMeter) ConsumeWithRefund(amount, refund uint64) error {
	// Explicit overflow check: used + amount overflows uint64 (same as Consume)
	newUsed := g.used + amount
	if newUsed < g.used {
		return ErrGasOverflow
	}

	if newUsed > g.limit {
		g.used = g.limit
		return ErrOutOfGas
	}

	g.used = newUsed

	// Check refund overflow
	if g.refund+refund < g.refund {
		// Refund overflow - cap at max uint64
		g.refund = ^uint64(0)
	} else {
		g.refund += refund
	}

	return nil
}

// Refund adds to the refund counter.
func (g *GasMeter) Refund(amount uint64) {
	// Check overflow
	if g.refund+amount < g.refund {
		// Cap at max uint64
		g.refund = ^uint64(0)
	} else {
		g.refund += amount
	}
}

// Return credits unused gas back to the meter (e.g. after a sub-call completes).
// audit-fix R3-F11: without this, gas allocated to sub-calls was never deducted
// from the parent, making sub-call computation effectively free.
func (g *GasMeter) Return(amount uint64) {
	// Return unused gas from a sub-call back to the parent's meter.
	// This reduces g.used by the amount being returned.
	// The cap is that we cannot return more than we consumed (g.used),
	// NOT limited by remaining (limit - used), because we are reducing
	// used, not adding to remaining.
	capped := amount
	if capped > g.used {
		capped = g.used
	}

	g.used -= capped
}

// Used returns the amount of gas used.
func (g *GasMeter) Used() uint64 {
	return g.used
}

// Remaining returns the amount of gas remaining.
func (g *GasMeter) Remaining() uint64 {
	if g.used >= g.limit {
		return 0
	}
	return g.limit - g.used
}

// Limit returns the gas limit.
func (g *GasMeter) Limit() uint64 {
	return g.limit
}

// RefundAmount returns the refund amount (capped at used/5).
func (g *GasMeter) RefundAmount() uint64 {
	// EIP-3529: refund is capped at 1/5 of gas used
	if g.used == 0 {
		return 0
	}

	maxRefund := g.used / 5
	if g.refund > maxRefund {
		return maxRefund
	}
	return g.refund
}

// FinalUsed returns the final gas used after refunds.
func (g *GasMeter) FinalUsed() uint64 {
	// Get capped refund amount
	var maxRefund uint64
	if g.used > 0 {
		maxRefund = g.used / 5
	}

	var actualRefund uint64
	if g.refund > maxRefund {
		actualRefund = maxRefund
	} else {
		actualRefund = g.refund
	}

	// Explicit underflow check
	if actualRefund > g.used {
		return g.used
	}

	return g.used - actualRefund
}

// Clone creates a copy of the gas meter.
func (g *GasMeter) Clone() *GasMeter {
	return &GasMeter{
		limit:      g.limit,
		used:       g.used,
		refund:     g.refund,
		accessList: g.accessList.Copy(),
	}
}

// Reset resets the gas meter with a new limit.
func (g *GasMeter) Reset(limit uint64) {
	g.limit = limit
	g.used = 0
	g.refund = 0
	g.accessList.Clear()
}

// AccessList returns the access list.
func (g *GasMeter) AccessList() *AccessList {
	return g.accessList
}

// ConsumeSLoad consumes gas for SLOAD operation with cold/warm differentiation.
func (g *GasMeter) ConsumeSLoad(addr Address, slot Hash) error {
	var cost uint64
	if g.accessList.IsSlotWarm(addr, slot) {
		cost = GasWarmSLoad
	} else {
		cost = GasColdSLoad
		g.accessList.AddSlot(addr, slot)
	}
	return g.Consume(cost)
}

// ConsumeSStore consumes gas for SSTORE operation with cold/warm differentiation.
func (g *GasMeter) ConsumeSStore(addr Address, slot Hash, currentValue, newValue Hash) (uint64, error) {
	var cost uint64
	var refundAmount uint64

	// Cold access cost
	_, slotWasCold := g.accessList.AddSlot(addr, slot)
	if slotWasCold {
		cost += GasColdSLoad
	}

	// Calculate storage cost based on value changes
	isZeroCurrent := currentValue == Hash{}
	isZeroNew := newValue == Hash{}

	if isZeroCurrent && !isZeroNew {
		// Zero to non-zero: set
		cost += GasSStoreSet
	} else if !isZeroCurrent && isZeroNew {
		// Non-zero to zero: clear (with refund)
		cost += GasSStoreReset
		refundAmount = GasSStoreClear
	} else if !isZeroCurrent && !isZeroNew {
		// Non-zero to non-zero: reset
		cost += GasSStoreReset
	} else {
		// Zero to zero: no-op
		cost += GasSStore
	}

	if err := g.Consume(cost); err != nil {
		return 0, err
	}

	if refundAmount > 0 {
		g.Refund(refundAmount)
	}

	return cost, nil
}

// ConsumeAccountAccess consumes gas for account access with cold/warm differentiation.
func (g *GasMeter) ConsumeAccountAccess(addr Address) error {
	var cost uint64
	if g.accessList.IsAddressWarm(addr) {
		cost = GasWarmAccountAccess
	} else {
		cost = GasColdAccountAccess
		g.accessList.AddAddress(addr)
	}
	return g.Consume(cost)
}

// ConsumeCall consumes gas for CALL operation with cold/warm differentiation.
func (g *GasMeter) ConsumeCall(addr Address, hasValue, isNewAccount bool) (uint64, error) {
	var cost uint64

	// Cold/warm account access
	if g.accessList.IsAddressWarm(addr) {
		cost = GasWarmAccountAccess
	} else {
		cost = GasColdAccountAccess
		g.accessList.AddAddress(addr)
	}

	// Value transfer cost
	if hasValue {
		cost += GasCallValue
	}

	// New account cost
	if isNewAccount && hasValue {
		cost += GasCallNewAccount
	}

	if err := g.Consume(cost); err != nil {
		return 0, err
	}

	return cost, nil
}

// PreloadAccessList preloads addresses and slots from a transaction access list.
// This is used for EIP-2930 access list transactions.
func (g *GasMeter) PreloadAccessList(addresses []Address, slots map[Address][]Hash) uint64 {
	var cost uint64

	for _, addr := range addresses {
		if g.accessList.AddAddress(addr) {
			if cost+GasAccessListAddress < cost {
				return math.MaxUint64
			}
			cost += GasAccessListAddress
		}
	}

	for addr, slotList := range slots {
		for _, slot := range slotList {
			_, slotWasCold := g.accessList.AddSlot(addr, slot)
			if slotWasCold {
				if cost+GasAccessListSlot < cost {
					return math.MaxUint64
				}
				cost += GasAccessListSlot
			}
		}
	}

	return cost
}

// GasTable contains gas costs for different operations.
type GasTable struct {
	// Storage access costs
	SLoad       uint64
	SLoadCold   uint64
	SStore      uint64
	SStoreSet   uint64
	SStoreReset uint64
	SStoreClear uint64

	// Call costs
	Call           uint64
	CallCold       uint64
	CallValue      uint64
	CallNewAccount uint64

	// Balance costs
	Balance     uint64
	BalanceCold uint64

	// Create costs
	Create      uint64
	Create2     uint64
	CodeDeposit uint64

	// Log costs
	Log      uint64
	LogTopic uint64
	LogData  uint64

	// Crypto costs
	SHA3     uint64
	SHA3Word uint64

	// EXP costs
	Exp     uint64
	ExpByte uint64
}

// DefaultGasTable returns the default gas table.
func DefaultGasTable() *GasTable {
	return &GasTable{
		SLoad:          GasSLoad,
		SLoadCold:      GasSLoadCold,
		SStore:         GasSStore,
		SStoreSet:      GasSStoreSet,
		SStoreReset:    GasSStoreReset,
		SStoreClear:    GasSStoreClear,
		Call:           GasCall,
		CallCold:       GasCallCold,
		CallValue:      GasCallValue,
		CallNewAccount: GasCallNewAccount,
		Balance:        GasBalance,
		BalanceCold:    GasBalanceCold,
		Create:         GasCreate,
		Create2:        GasCreate2,
		CodeDeposit:    GasCodeDeposit,
		Log:            GasLog,
		LogTopic:       GasLogTopic,
		LogData:        GasLogData,
		SHA3:           GasSHA3,
		SHA3Word:       GasSHA3Word,
		Exp:            GasExp,
		ExpByte:        GasExpByte,
	}
}

// CalculateCallGas calculates the gas cost for a CALL operation.
// MEDIUM FIX: Added comprehensive bounds checking for extreme gas values
// to prevent overflow/underflow and ensure consistent behavior.
func CalculateCallGas(gasTable *GasTable, availableGas, requestedGas uint64, hasValue, isNewAccount, isCold bool) (uint64, uint64) {
	// MEDIUM FIX: Validate gas table is not nil
	if gasTable == nil {
		return 0, 0
	}

	// MEDIUM FIX: Define maximum safe gas values to prevent overflow
	const maxSafeGas uint64 = ^uint64(0) >> 1 // Max int64 value as safe upper bound

	// Base cost
	cost := gasTable.Call
	if isCold {
		cost = gasTable.CallCold
	}

	// Value transfer cost
	if hasValue {
		// MEDIUM FIX: Check for overflow before adding
		if cost > maxSafeGas-gasTable.CallValue {
			return maxSafeGas, 0
		}
		cost += gasTable.CallValue
	}

	// New account cost
	if isNewAccount && hasValue {
		// MEDIUM FIX: Check for overflow before adding
		if cost > maxSafeGas-gasTable.CallNewAccount {
			return maxSafeGas, 0
		}
		cost += gasTable.CallNewAccount
	}

	// MEDIUM FIX: Cap cost at maximum safe value
	if cost > maxSafeGas {
		cost = maxSafeGas
	}

	// Calculate gas to send to callee
	// Use 63/64 rule
	// audit-fix R2-M2: explicit underflow guard instead of relying on unsigned wrap detection
	// R24-C6 FIX: Explicit check when availableGas <= cost to prevent underflow
	var gasToSend uint64
	if availableGas <= cost {
		// Not enough gas to cover the cost, send nothing to callee
		// This prevents potential gasToSend underflow issues
		return cost, 0
	}
	gasToSend = availableGas - cost

	// MEDIUM FIX: Validate gasToSend is within safe bounds
	if gasToSend > maxSafeGas {
		gasToSend = maxSafeGas
	}

	// R24-C6 FIX: When gasToSend is very small, maxGas computation could have issues
	// With 63/64 rule: maxGas = gasToSend - gasToSend/64 = (63/64) * gasToSend
	// For gasToSend = 1: maxGas = 1 - 0 = 1 (integer division floors)
	// For gasToSend = 63: maxGas = 63 - 0 = 63
	// For gasToSend = 64: maxGas = 64 - 1 = 63
	maxGas := gasToSend - gasToSend/64

	// MEDIUM FIX: Ensure maxGas doesn't exceed safe bounds
	if maxGas > maxSafeGas {
		maxGas = maxSafeGas
	}

	// MEDIUM FIX: Validate requestedGas doesn't overflow when compared to maxGas
	if requestedGas > maxGas {
		requestedGas = maxGas
	}

	// Add stipend for value transfers
	if hasValue {
		// MEDIUM FIX: Check for overflow before adding stipend
		if requestedGas > maxSafeGas-GasCallStipend {
			requestedGas = maxSafeGas
		} else {
			requestedGas += GasCallStipend
		}
	}

	// Final safety check: ensure returned values are within bounds
	if cost > maxSafeGas {
		cost = maxSafeGas
	}
	if requestedGas > maxSafeGas {
		requestedGas = maxSafeGas
	}

	return cost, requestedGas
}

// GasEstimator provides gas estimation functionality.
// HIGH FIX: Added mutex for thread-safe concurrent access
type GasEstimator struct {
	mu       sync.Mutex
	gasTable *GasTable
}

// NewGasEstimator creates a new gas estimator.
func NewGasEstimator() *GasEstimator {
	return &GasEstimator{
		gasTable: DefaultGasTable(),
	}
}

// EstimateGas estimates the gas required for a transaction.
// It performs a binary search to find the minimum gas that allows execution.
// HIGH FIX: Acquire lock for thread-safe execution
func (ge *GasEstimator) EstimateGas(
	executor interface {
		Execute(ctx *ExecutionContext, stateDB StateDB) *ExecutionResult
	},
	ctx *ExecutionContext,
	stateDB StateDB,
	lo, hi uint64,
) (uint64, error) {
	// HIGH FIX: Lock to prevent concurrent state access during estimation
	ge.mu.Lock()
	defer ge.mu.Unlock()

	// CRIT-2 FIX: Calculate intrinsic gas including data costs
	// Previously just used GasTxCall (21000) as minimum, missing data costs
	isCreate := len(ctx.Code) > 0 && ctx.Input == nil
	intrinsicGas := EstimateIntrinsicGas(ctx.Input, isCreate, nil)

	// Ensure we have a valid range
	if lo < intrinsicGas {
		lo = intrinsicGas
	}
	if hi == 0 {
		hi = ctx.GasLimit
	}
	if hi < lo {
		hi = lo
	}

	// First, try with high gas to see if execution succeeds at all
	testCtx := *ctx
	testCtx.Gas = hi

	snapshot := stateDB.Snapshot()
	result := executor.Execute(&testCtx, stateDB)
	stateDB.RevertToSnapshot(snapshot)

	if result.Err != nil && result.Err != ErrExecutionReverted {
		return 0, result.Err
	}

	// If execution reverted, return the gas used
	if result.Reverted {
		return result.GasUsed, ErrExecutionReverted
	}

	// Binary search for minimum gas
	// SECURITY (audit P3-R3-06): Use overflow-safe midpoint calculation
	for lo+1 < hi {
		mid := lo + (hi-lo)/2

		testCtx.Gas = mid
		snapshot = stateDB.Snapshot()
		result = executor.Execute(&testCtx, stateDB)
		stateDB.RevertToSnapshot(snapshot)

		if result.Err == ErrOutOfGas {
			lo = mid
		} else if result.Err != nil && result.Err != ErrExecutionReverted {
			return 0, result.Err
		} else {
			hi = mid
		}
	}

	var estimated uint64
	// L19-009 FIX: Add 10% safety margin to the binary search result.
	// The overflow check (estimated < hi) guards against uint64 wraparound
	// when hi is near MaxUint64. In practice hi is bounded by ctx.GasLimit
	// which is always a reasonable value, so the overflow branch is defensive.
	estimated = hi + hi/10
	if estimated < hi || estimated > ctx.GasLimit {
		estimated = ctx.GasLimit
	}

	return estimated, nil
}

// EstimateIntrinsicGas calculates the intrinsic gas for a transaction.
func EstimateIntrinsicGas(data []byte, isCreate bool, accessList *AccessList) uint64 {
	var gas uint64

	// Base transaction cost
	if isCreate {
		gas = GasTxCreate
	} else {
		gas = GasTxCall
	}

	// Data cost
	for _, b := range data {
		var cost uint64
		if b == 0 {
			cost = GasTxDataZero
		} else {
			cost = GasTxDataNonZero
		}
		if gas+cost < gas {
			return math.MaxUint64
		}
		gas += cost
	}

	if accessList != nil {
		addrCost := uint64(accessList.AddressCount()) * GasAccessListAddress // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		if gas+addrCost < gas {
			return math.MaxUint64
		}
		gas += addrCost
		slotCost := uint64(accessList.SlotCount()) * GasAccessListSlot // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
		if gas+slotCost < gas {
			return math.MaxUint64
		}
		gas += slotCost
	}

	return gas
}

// GasSnapshot captures the state of a GasMeter for rollback.
type GasSnapshot struct {
	used       uint64
	refund     uint64
	accessList *AccessList
}

// Snapshot creates a snapshot of the current gas state.
func (g *GasMeter) Snapshot() *GasSnapshot {
	return &GasSnapshot{
		used:       g.used,
		refund:     g.refund,
		accessList: g.accessList.Copy(),
	}
}

// Revert restores the gas meter to a previous snapshot.
func (g *GasMeter) Revert(snapshot *GasSnapshot) {
	g.used = snapshot.used
	g.refund = snapshot.refund
	g.accessList = snapshot.accessList
}

// CalculateMemoryGas calculates the gas cost for memory expansion.
// audit-fix MED-3: Added overflow protection for quadratic memory cost calculation.
// SECURITY (audit P1-R3-05): Replaced unreliable `newCost < currentCost` check
// with proper safe arithmetic that detects overflow at each multiplication and
// addition step. The previous check only detected overflow that wrapped around
// to a smaller value, missing wraps to a larger but still incorrect value.
func CalculateMemoryGas(currentSize, newSize uint64) uint64 {
	if newSize <= currentSize {
		return 0
	}

	// Cap newSize to prevent overflow in words^2 calculation.
	const maxSafeMemorySize = 32 * 1024 * 1024 // 32 MB
	if newSize > maxSafeMemorySize {
		return math.MaxUint64 // Effectively prevents allocation by exceeding any gas limit
	}

	// Memory cost = 3 * words + words^2 / 512
	currentWords := (currentSize + 31) / 32
	newWords := (newSize + 31) / 32

	// SECURITY (audit P1-R3-05): Check for overflow in words*words.
	// words*words overflows uint64 when words > 2^32.
	if currentWords > 1<<32 || newWords > 1<<32 {
		return math.MaxUint64
	}

	// Calculate linear and quadratic costs separately with overflow checks
	currentLinear := currentWords * GasMemory
	newLinear := newWords * GasMemory
	currentQuadratic := (currentWords * currentWords) / 512
	newQuadratic := (newWords * newWords) / 512

	// Check for overflow in linear + quadratic addition
	if currentLinear > math.MaxUint64-currentQuadratic {
		return math.MaxUint64
	}
	if newLinear > math.MaxUint64-newQuadratic {
		return math.MaxUint64
	}

	currentCost := currentLinear + currentQuadratic
	newCost := newLinear + newQuadratic

	// Final underflow check (shouldn't happen with correct arithmetic)
	if newCost < currentCost {
		return math.MaxUint64 // Overflow — return max to guarantee OOG
	}

	return newCost - currentCost
}

// CalculateCopyGas calculates the gas cost for memory copy operations.
func CalculateCopyGas(size uint64) uint64 {
	// R54-QV-03 FIX: Use safe addition for size+31 to prevent overflow
	// when size is near uint64 max. Without this, (size+31) wraps to a
	// small value, bypassing the gas charging for huge copies.
	if size > math.MaxUint64-31 {
		return math.MaxUint64
	}
	words := (size + 31) / 32
	if GasCopy != 0 && words > math.MaxUint64/GasCopy {
		return math.MaxUint64
	}
	return words * GasCopy
}

// CalculateExpGas calculates the gas cost for EXP operation.
func CalculateExpGas(exponentBytes int) uint64 {
	// R6-QV-005 FIX: Add overflow check for GasExp + exponentBytes*GasExpByte.
	// Without this, a malicious contract could craft an exponent that causes
	// uint64 overflow, resulting in undercharged gas.
	expByteGas, err := SafeMulGas(uint64(exponentBytes), GasExpByte)
	if err != nil {
		return math.MaxUint64
	}
	total, err := SafeAddGas(GasExp, expByteGas)
	if err != nil {
		return math.MaxUint64
	}
	return total
}

// CalculateSHA3Gas calculates the gas cost for SHA3/KECCAK256 operation.
func CalculateSHA3Gas(size uint64) uint64 {
	// R54-QV-03 FIX: Use safe addition for size+31 to prevent overflow
	// when size is near uint64 max. Without this, (size+31) wraps to a
	// small value, bypassing the gas charging for huge SHA3 operations.
	if size > math.MaxUint64-31 {
		return math.MaxUint64
	}
	words := (size + 31) / 32
	if GasSHA3Word != 0 && words > math.MaxUint64/GasSHA3Word {
		return math.MaxUint64
	}
	if GasSHA3 > math.MaxUint64-words*GasSHA3Word {
		return math.MaxUint64
	}
	return GasSHA3 + words*GasSHA3Word
}

// CalculateLogGas calculates the gas cost for LOG operation.
func CalculateLogGas(topicCount int, dataSize uint64) uint64 {
	topicCost := uint64(topicCount) * GasLogTopic                            // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	if GasLogTopic != 0 && uint64(topicCount) > math.MaxUint64/GasLogTopic { //nolint:gosec,G115
		return math.MaxUint64
	}
	dataCost := dataSize * GasLogData
	if GasLogData != 0 && dataSize > math.MaxUint64/GasLogData {
		return math.MaxUint64
	}
	if GasLog > math.MaxUint64-topicCost-dataCost {
		return math.MaxUint64
	}
	return GasLog + topicCost + dataCost
}

// maxGasCostBits is the maximum number of bits allowed in a gas cost result.
// Any result exceeding 256 bits is treated as overflow, as it would not fit
// in a 256-bit VM word and indicates an unreasonable gas/price combination.
const maxGasCostBits = 256

// CalculateGasCost computes gas * price using big.Int arithmetic with an
// overflow check. SECURITY FIX (L14-018): Previously, gas * price could
// silently overflow when using fixed-size integer types, allowing an attacker
// to craft transactions where the actual gas cost was far less than expected
// (or wrapped to a small value), bypassing balance checks.
// Using big.Int.Mul prevents silent overflow — the result is exact — and
// the overflow check rejects results that exceed 256 bits (the VM word size),
// which would indicate an unreasonable or malicious gas/price combination.
func CalculateGasCost(gas uint64, price *big.Int) (*big.Int, error) {
	if price == nil {
		return big.NewInt(0), errors.New("gas price cannot be nil")
	}
	if price.Sign() < 0 {
		return big.NewInt(0), errors.New("gas price cannot be negative")
	}
	result := new(big.Int).Mul(new(big.Int).SetUint64(gas), price)
	if result.BitLen() > maxGasCostBits {
		return nil, ErrGasOverflow
	}
	return result, nil
}
