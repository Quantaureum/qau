// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"fmt"
	"math"
	"math/big"
)

// Arithmetic operations - ADDMOD and MULMOD

func (i *Interpreter) opAddMod(env *Environment) error {
	a, err := env.stack.PopBigInt()
	if err != nil {
		return err
	}
	b, err := env.stack.PopBigInt()
	if err != nil {
		return err
	}
	n, err := env.stack.PopBigInt()
	if err != nil {
		return err
	}

	var result *big.Int
	if n.Sign() == 0 {
		result = new(big.Int)
	} else {
		result = new(big.Int).Add(a, b)
		result.Mod(result, n)
	}

	return env.stack.PushBigInt(result)
}

func (i *Interpreter) opMulMod(env *Environment) error {
	a, err := env.stack.PopBigInt()
	if err != nil {
		return err
	}
	b, err := env.stack.PopBigInt()
	if err != nil {
		return err
	}
	n, err := env.stack.PopBigInt()
	if err != nil {
		return err
	}

	var result *big.Int
	if n.Sign() == 0 {
		result = new(big.Int)
	} else {
		result = new(big.Int).Mul(a, b)
		result.Mod(result, n)
	}

	return env.stack.PushBigInt(result)
}

// Comparison operations - SLT and SGT (signed comparisons)

func (i *Interpreter) opSlt(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Fast path: both fit in uint64 and both are positive (high bit clear)
	// SECURITY (audit P0-): Word is big-endian. For isUint64 values, the
	// value occupies bytes [24..31], so the sign bit is at value[24] (bit 63).
	// Previous checks on value[0] (always 0 for isUint64) or value[31] were wrong.
	if isUint64(a) && isUint64(b) && a[24] < 0x80 && b[24] < 0x80 {
		if int64(a.ToUint64()) < int64(b.ToUint64()) {
			return env.stack.PushUint64(1)
		}
		return env.stack.PushUint64(0)
	}

	// Slow path: big.Int
	ab := a.ToBigInt()
	bb := b.ToBigInt()

	// Convert to signed integers
	aSigned := toSigned(ab)
	bSigned := toSigned(bb)

	if aSigned.Cmp(bSigned) < 0 {
		return env.stack.PushUint64(1)
	}
	return env.stack.PushUint64(0)
}

func (i *Interpreter) opSgt(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Fast path: both fit in uint64 and both are positive (high bit clear)
	// SECURITY (audit P0-): Word is big-endian, sign bit at value[24].
	if isUint64(a) && isUint64(b) && a[24] < 0x80 && b[24] < 0x80 {
		if int64(a.ToUint64()) > int64(b.ToUint64()) {
			return env.stack.PushUint64(1)
		}
		return env.stack.PushUint64(0)
	}

	// Slow path: big.Int
	ab := a.ToBigInt()
	bb := b.ToBigInt()

	// Convert to signed integers
	aSigned := toSigned(ab)
	bSigned := toSigned(bb)

	if aSigned.Cmp(bSigned) > 0 {
		return env.stack.PushUint64(1)
	}
	return env.stack.PushUint64(0)
}

// toSigned converts an unsigned 256-bit integer to a signed one
func toSigned(x *big.Int) *big.Int {
	// If the high bit is set, treat as negative
	if x.Bit(255) == 1 {
		// result = x - 2^256
		result := new(big.Int).Sub(x, bigMaxUint256Plus1)
		return result
	}
	return new(big.Int).Set(x)
}

// fromSigned converts a signed big.Int back to two's complement unsigned 256-bit.
func fromSigned(v *big.Int) *big.Int {
	if v.Sign() < 0 {
		result := new(big.Int).Add(v, bigMaxUint256Plus1)
		return result
	}
	return new(big.Int).Set(v)
}

// Bitwise operations - SHL, SHR, SAR, BYTE

func (i *Interpreter) opShl(env *Environment) error {
	shiftWord, err := env.stack.Pop()
	if err != nil {
		return err
	}
	value, err := env.stack.Pop()
	if err != nil {
		return err
	}

	shift := shiftWord.ToUint64()

	// Fast path: shift < 64 and value fits in uint64
	// SECURITY (audit P0-): Must check that left shift won't overflow uint64.
	// If value has bits in the high shift positions, the result exceeds uint64
	// and must use the big.Int slow path to avoid silent truncation.
	// QVM-SHIFT-01 FIX (deep-audit 2026-07-12): also require the SHIFT operand
	// itself to fit in uint64. shiftWord.ToUint64() collapses to the low 64 bits,
	// so a shift of e.g. 2^64+3 would yield shift=3 and wrongly enter the fast
	// path, computing value<<3 instead of the EVM-correct 0 (any shift >= 256 is
	// 0). isUint64(shiftWord) routes such operands to the slow path.
	if isUint64(shiftWord) && shift < 64 && isUint64(value) {
		v := value.ToUint64()
		if shift > 0 && v>>(64-shift) != 0 {
			// Overflow: high bits would be lost, use slow path
		} else {
			return env.stack.Push(NewWordFromUint64(v << shift))
		}
	}

	// Slow path: big.Int
	shiftBig := shiftWord.ToBigInt()
	valueBig := value.ToBigInt()

	var result *big.Int
	if shiftBig.Cmp(big.NewInt(256)) >= 0 {
		result = new(big.Int)
	} else {
		result = new(big.Int).Lsh(valueBig, uint(shiftBig.Uint64()))
		result.And(result, maxUint256)
	}

	return env.stack.PushBigInt(result)
}

func (i *Interpreter) opShr(env *Environment) error {
	shiftWord, err := env.stack.Pop()
	if err != nil {
		return err
	}
	value, err := env.stack.Pop()
	if err != nil {
		return err
	}

	shift := shiftWord.ToUint64()

	// Fast path: shift < 64 and value fits in uint64
	// QVM-SHIFT-01 FIX (deep-audit 2026-07-12): require the shift operand itself
	// to fit in uint64 so a large shift (e.g. 2^64+3) whose low bits are < 64 is
	// not mistaken for a small shift; EVM defines any shift >= 256 as 0.
	if isUint64(shiftWord) && shift < 64 && isUint64(value) {
		return env.stack.Push(NewWordFromUint64(value.ToUint64() >> shift))
	}

	// Slow path: big.Int
	shiftBig := shiftWord.ToBigInt()
	valueBig := value.ToBigInt()

	var result *big.Int
	if shiftBig.Cmp(big.NewInt(256)) >= 0 {
		result = new(big.Int)
	} else {
		result = new(big.Int).Rsh(valueBig, uint(shiftBig.Uint64()))
	}

	return env.stack.PushBigInt(result)
}

func (i *Interpreter) opSar(env *Environment) error {
	shiftWord, err := env.stack.Pop()
	if err != nil {
		return err
	}
	value, err := env.stack.Pop()
	if err != nil {
		return err
	}

	shift := shiftWord.ToUint64()

	// Fast path: shift < 64, value fits in uint64, and value is positive (high bit clear)
	// SECURITY (audit P0-): Word is big-endian. For isUint64 values, the
	// value occupies bytes [24..31], so the sign bit (bit 63) is at value[24].
	// Previous fix (P1-) incorrectly used value[31] and wrongly stated
	// Word is little-endian. value[31] is the LOWEST byte, not the sign byte.
	// QVM-SHIFT-01 FIX (deep-audit 2026-07-12): require the shift operand to fit
	// in uint64 so a large shift is not collapsed into the fast path.
	if isUint64(shiftWord) && shift < 64 && isUint64(value) && value[24] < 0x80 {
		v := int64(value.ToUint64())
		return env.stack.Push(NewWordFromUint64(uint64(v >> shift)))
	}

	// Slow path: big.Int
	shiftBig := shiftWord.ToBigInt()
	valueBig := value.ToBigInt()

	valueSigned := toSigned(valueBig)
	var result *big.Int
	if shiftBig.Cmp(big.NewInt(256)) >= 0 {
		if valueSigned.Sign() >= 0 {
			result = new(big.Int)
		} else {
			result = big.NewInt(-1)
		}
	} else {
		result = new(big.Int).Rsh(valueSigned, uint(shiftBig.Uint64()))
	}

	result.And(result, maxUint256)
	return env.stack.PushBigInt(result)
}

func (i *Interpreter) opByte(env *Environment) error {
	index, err := env.stack.Pop()
	if err != nil {
		return err
	}
	value, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Direct Word access — no big.Int needed
	// FIX: EVM BYTE semantics are idx=0 → MSB, idx=31 → LSB.
	// Word is big-endian (w[0]=MSB, w[31]=LSB), so value[idx] directly.
	// Previously value[31-idx] inverted the result vs the EVM standard.
	// QVM-SHIFT-01 FIX (deep-audit 2026-07-12): the index is a full 256-bit word.
	// index.ToUint64() collapses to the low 64 bits, so an index like 2^64+5 would
	// pass idx<32 and return value[5] instead of the EVM-correct 0. Require the
	// index operand to fit in uint64 before the range check.
	if !isUint64(index) {
		return env.stack.PushUint64(0)
	}
	idx := index.ToUint64()
	if idx >= 32 {
		return env.stack.PushUint64(0)
	}
	return env.stack.PushUint64(uint64(value[idx])) // #nosec G602 -- value is Word[32]; idx<32 checked above
}

// Memory operations - MCOPY

func (i *Interpreter) opMCopy(env *Environment) error {
	dest, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	src, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	size, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	if size == 0 {
		return nil
	}

	// R25-H10 FIX: Use safe addition to detect overflow properly
	// The previous check `dest > dest+size` doesn't work when dest+size overflows
	if dest > math.MaxUint64-size || src > math.MaxUint64-size {
		return fmt.Errorf("MCOPY offset overflow")
	}

	expansionCost := MemoryExpansionCost(env.memory.Size(), max(dest+size, src+size))
	// R54-QV-01 FIX: Use SafeAddGas for size+31 to prevent overflow when
	// size is near uint64 max. Without this, (size+31) wraps to a small
	// value, bypassing gas charging for huge copies.
	mcopyWords, mcopyErr := SafeAddGas(size, 31)
	if mcopyErr != nil {
		return fmt.Errorf("size overflow in MCOPY gas calculation")
	}
	mcopyWords /= 32
	copyCost, mcopyErr := SafeMulGas(mcopyWords, GasMemoryCopy)
	if mcopyErr != nil {
		return fmt.Errorf("copy gas overflow in MCOPY")
	}
	// FIX: Use SafeAddGas to prevent overflow in gas calculation.
	// Without this, if expansionCost is near MaxUint64, the addition wraps
	// around to a small value, allowing MCOPY to execute for free.
	totalCost, gerr := SafeAddGas(expansionCost, copyCost)
	if gerr != nil {
		return fmt.Errorf("MCOPY gas cost overflow")
	}
	if err := env.gas.Consume(totalCost); err != nil {
		return err
	}

	// Copy data
	data, err := env.memory.Get(src, size)
	if err != nil {
		return err
	}

	return env.memory.Set(dest, data)
}

// Call operations - CALLCODE

func (i *Interpreter) opCallCode(env *Environment) error {
	// Pop arguments from stack.
	// FIX: Verified CALLCODE's stack pop order matches CALL exactly.
	// EVM order (gas on top): gas, addr, value, argsOffset, argsSize, retOffset, retSize
	// QVM order (retSize on top): outSize, outOffset, inSize, inOffset, value, addr, gas
	// The EVMCompatible flag selects the correct pop order. Both CALL and CALLCODE
	// use identical pop sequences — the only difference is execution context
	// (CALLCODE runs target code in caller's storage context).
	var outSizeWord, outOffsetWord, inSizeWord, inOffsetWord, valueWord, addrWord, gasWord Word
	var err error
	if env.ctx.EVMCompatible {
		gasWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		addrWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		valueWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		outOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		outSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
	} else {
		outSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		outOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inSizeWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		inOffsetWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		valueWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		addrWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
		gasWord, err = env.stack.Pop()
		if err != nil {
			return err
		}
	}

	// Convert to values
	gas := gasWord.ToUint64()
	var addr Address
	copy(addr[:], addrWord[12:])
	value := valueWord.ToBigInt()
	inOffset := inOffsetWord.ToUint64()
	inSize := inSizeWord.ToUint64()
	outOffset := outOffsetWord.ToUint64()
	outSize := outSizeWord.ToUint64()

	// L10-020: Prevent calls to the zero address (0x0), a reserved address.
	// AUDIT-FULL H-4 (2026-08-14): now gas-aware via the shared helper.
	var zeroAddr Address
	if addr == zeroAddr {
		return rejectZeroAddrCall(env, gas, inOffset, inSize, outOffset, outSize)
	}

	if env.ctx.ReadOnly && value.Sign() > 0 {
		return ErrWriteProtection
	}

	// Calculate gas for the call using the standard CalculateCallGas function
	// which correctly applies 63/64 rule after deducting fixed costs
	hasValue := value.Sign() > 0
	isNewAccount := !env.stateDB.Exist(addr)
	isCold := !env.stateDB.AddressInAccessList(addr)

	// SECURITY FIX (RISK-008): Pre-calculate memory expansion costs before
	// computing callGas, consistent with opCall/opStaticCall/opDelegateCall fix.
	var memExpansionCost uint64
	if inSize > 0 {
		if inOffset+inSize < inOffset {
			return ErrMemoryOverflow
		}
		memExpansionCost += MemoryExpansionCost(env.memory.Size(), inOffset+inSize)
	}
	if outSize > 0 {
		if outOffset+outSize < outOffset {
			return ErrMemoryOverflow
		}
		outExpansion := MemoryExpansionCost(env.memory.Size(), outOffset+outSize)
		if outExpansion > memExpansionCost {
			memExpansionCost = outExpansion
		}
	}

	availableAfterFixed := env.gas.Remaining()
	if availableAfterFixed < memExpansionCost {
		return ErrOutOfGas
	}
	availableAfterFixed -= memExpansionCost

	// R6-P3 FIX: Add reentrancy guard gas for CALLCODE, consistent with opCall/opAuthCall.
	// CALLCODE executes external code in the current contract's storage context,
	// making reentrancy attacks potentially MORE dangerous than CALL.
	// FIX: Use env.ctx.Address() (caller address) instead of addr (target).
	// CALLCODE executes in the CALLER's storage context, so reentrancy tracking
	// must check whether the CALLER is already active on the call stack. Using
	// the target address (addr) misses A→B(CALLCODE)→A reentrancy entirely.
	// This mirrors the JIT path fix from  (compiler.go:2758).
	//
	// QVM-R13-HIGH-001 (2026-07-21) FIX: Add IncrementReentryCount +
	// defer DecrementReentryCount, mirroring opCall/opStaticCall/opDelegateCall
	// (call.go:265-278, 666-676, 960-970) and the JIT path (jit_adapter.go:847-855).
	// Without this, CALLCODE only charged the 2300-gas reentrancy disincentive
	// but never incremented the per-address counter — so MaxReentriesPerAddress
	// could be bypassed via A→B(CALLCODE)→A→B(CALLCODE)… chains.
	reentrancyGuardGas := uint64(0)
	targetHasCode := len(env.stateDB.GetCode(addr)) > 0
	reentryIncremented := false
	if targetHasCode && env.callDepth >= 1 && env.IsAddressActive(env.ctx.Address) {
		// AUDIT (2026) QVFIX: Hard-block after MaxReentriesPerAddress
		// reentries to the same address within one transaction. The 2300 gas
		// penalty below remains as the per-reentry economic disincentive.
		if !env.IncrementReentryCount(env.ctx.Address) {
			return env.stack.PushUint64(0)
		}
		reentryIncremented = true
		// QVM- (2026-07-20) FIX: Decrement the reentry counter when
		// this CALLCODE frame returns (success, revert, or error). See opCall
		// for full rationale.
		defer func() {
			if reentryIncremented {
				env.DecrementReentryCount(env.ctx.Address)
			}
		}()
		reentrancyGuardGas = 2300
		if availableAfterFixed < reentrancyGuardGas {
			return env.stack.PushUint64(0)
		}
		availableAfterFixed -= reentrancyGuardGas
	}

	callCost, callGas := CalculateCallGas(env.gasTable, availableAfterFixed, gas, hasValue, isNewAccount, isCold)

	// AUDIT-FULL QV-07 (2026-08-14): Verify callCost does not exceed available
	// gas before consuming, mirroring the  fix in opCall (and QV-06 in
	// opStaticCall). CalculateCallGas may return math.MaxUint64 on overflow;
	// without this check Consume() would fail with a confusing "out of gas"
	// instead of a clean revert-style failure.
	if callCost > availableAfterFixed {
		return env.stack.PushUint64(0)
	}

	if err := env.gas.Consume(callCost); err != nil {
		return err
	}

	env.stateDB.AddAddressToAccessList(addr)

	// audit-fix QVM-MEM-1: Consume memory expansion gas ONCE (same fix as opCall).
	// The memExpansionCost was already subtracted from availableAfterFixed above
	// to compute callGas correctly, so we must consume exactly that amount here.
	if memExpansionCost > 0 {
		if err := env.gas.Consume(memExpansionCost); err != nil {
			return err
		}
	}

	// R6-P3 FIX: Consume reentrancy guard gas after memory expansion, before callGas.
	if reentrancyGuardGas > 0 {
		if err := env.gas.Consume(reentrancyGuardGas); err != nil {
			return env.stack.PushUint64(0)
		}
	}

	// Read input data from memory
	input, err := env.memory.Get(inOffset, inSize)
	if err != nil {
		return err
	}

	// FIX: Check balance for value transfer (consistent with opCall).
	// CALLCODE transfers value from caller to target, per EVM Yellow Paper.
	if hasValue {
		balance := env.stateDB.GetBalance(env.ctx.Address)
		if balance.Cmp(value) < 0 {
			return env.stack.PushUint64(0)
		}
	}

	// R31-P2 FIX (2026-07-28): Reorder to match opCall — increment
	// callDepth and check MaxCallDepth BEFORE taking Snapshot or
	// transferring value. Previously Snapshot was taken first (line 565),
	// then callDepth was incremented and checked — if MaxCallDepth was
	// exceeded, the snapshot was taken and immediately reverted (wasteful
	// and inconsistent with opCall which checks depth before Snapshot).
	// opCall order: callDepth++ → MaxCallDepth check → PushActiveAddress → Snapshot
	// opCallCode now uses the same order.
	env.callDepth++
	defer func() {
		env.callDepth--
	}()

	// Check depth — use env.callDepth for consistency with CALL/STATICCALL/DELEGATECALL
	// SECURITY FIX (audit P3): Changed from callCtx.Depth to env.callDepth
	// SECURITY FIX (R2 P1-1): Removed duplicate env.callDepth++ that was
	// previously at this location (QVM-H3). The increment above already
	// tracks the depth — this second increment caused callDepth to increase
	// by 2 per CALLCODE, effectively halving MaxCallDepth.
	// FIX: Use >= (not >) for consistency with opCall, opStaticCall,
	// opDelegateCall, and executor.go which all check ctx.Depth >= MaxCallDepth.
	if env.callDepth >= MaxCallDepth {
		return env.stack.PushUint64(0)
	}

	// R6-P3 FIX: CALLCODE now has reentrancy guard gas (2300) consistent with opCall.
	// The guard gas is consumed above, before the callGas. The PushActiveAddress
	// below provides cross-contract reentrancy detection.
	// R24-C8 FIX: Check if push succeeded - fail call if max depth exceeded
	savedActiveLen := len(env.activeAddresses)
	// R41-C-C1 FIX: PushActiveAddress may have grown the slice before failing
	// (when len was exactly MaxActiveCallDepth-1, append succeeds then return false).
	// Restore to savedActiveLen before returning.
	// R39-P3 FIX: Push env.ctx.Address (caller) to match the reentrancy guard
	// check at line 467 which uses env.ctx.Address. CALLCODE executes in the
	// CALLER's storage context, so active-address tracking must use the caller.
	if !env.PushActiveAddress(env.ctx.Address) {
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		return env.stack.PushUint64(0)
	}

	// Take snapshot for potential revert (after depth check, before value
	// transfer so revert undoes it). This matches opCall's ordering where
	// Snapshot is taken after MaxCallDepth and PushActiveAddress checks.
	snapshot := env.stateDB.Snapshot()

	// FIX: CALLCODE transfers value from caller to target address,
	// consistent with EVM Yellow Paper and JIT path ( fix).
	// The snapshot above ensures the transfer is reverted on failure/revert.
	//
	// AUDIT (2026) R4-QVFIX: Previously, value was transferred from
	// env.ctx.Address (caller) to addr (code source). This permanently lost
	// the funds because CALLCODE executes the target's code in the CALLER's
	// storage context — the target address (addr) has no way to return the
	// funds (its code was never executed in its own context). Now value is
	// transferred from the caller to ITSELF (env.ctx.Address → env.ctx.Address),
	// making the balance transfer a no-op while preserving CALLVALUE semantics
	// (the called code still sees a non-zero Value field in its execution
	// context). This matches the intent of CALLCODE: execute external code
	// with the caller's state, including the caller's balance.
	//
	// R32-P0-1 FIX (2026-07-28): The previous "no-op" implementation was
	// actually a minting bug. It captured callerBalance=B once, then:
	//   SetBalance(B - v)   // balance is now B - v
	//   SetBalance(B + v)   // uses ORIGINAL B, so balance becomes B + v
	// Net effect: balance increased by v out of thin air. An attacker could
	// repeatedly CALLCODE(self, value) to mint unlimited QAU.
	//
	// CALLCODE semantics: the called code runs in the CALLER's storage
	// context, so a self-to-self value transfer is genuinely a no-op.
	// The Value field in callCtx (set below) is what CALLVALUE reads —
	// it does NOT depend on an actual balance transfer. Therefore the
	// correct fix is to perform NO balance mutation at all.
	if hasValue {
		// Intentionally empty: self→self transfer is a no-op.
		// CALLVALUE still returns `value` via callCtx.Value below.
		_ = value
	}

	// Create call context
	// CALLCODE uses the current contract address as storage context (env.ctx.Address)
	// but the target contract address (addr) for code.
	callCtx := &ExecutionContext{
		Origin:        env.ctx.Origin,   // R6-P2 FIX: was missing, ORIGIN opcode returned zero
		GasPrice:      env.ctx.GasPrice, // R6-P2 FIX: was missing, GASPRICE opcode returned zero
		Address:       env.ctx.Address,  // Storage context remains the same
		Caller:        env.ctx.Address,  // Caller is the current contract
		Value:         value,
		BlockNumber:   env.ctx.BlockNumber,
		Timestamp:     env.ctx.Timestamp,
		Coinbase:      env.ctx.Coinbase,
		GasLimit:      env.ctx.GasLimit,
		ChainID:       env.ctx.ChainID,
		BaseFee:       env.ctx.BaseFee,           // QVM- propagate BASEFEE opcode value
		BlobBaseFee:   env.ctx.BlobBaseFee,       // QVM- propagate BLOBBASEFEE opcode value
		PrevRandao:    env.ctx.PrevRandao,        // QVM- propagate PREVRANDAO opcode value
		Code:          env.stateDB.GetCode(addr), // Use target's code
		Input:         input,
		Gas:           callGas,
		Depth:         env.ctx.Depth + 1,
		ReadOnly:      env.ctx.ReadOnly,
		EVMCompatible: isEVMTranslatedCode(env.stateDB.GetCode(addr)), // R7-QV-001 FIX: Detect EVM-translated code dynamically
		ParentEnv:     env,                                            // audit-fix CRIT-REENTRY: pass current env for reentrancy tracking
	}

	// Deduct call gas
	//  [P2] FIX: use slice restoration (env.activeAddresses[:savedActiveLen])
	// instead of PopActiveAddress(), matching the pattern used by opCall in
	// call.go and every other restore point in this function. PopActiveAddress()
	// only pops the top entry and is inconsistent with the savedActiveLen guard
	// captured before PushActiveAddress (which may have grown the slice).
	if err := env.gas.Consume(callGas); err != nil {
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		env.stateDB.RevertToSnapshot(snapshot)
		return env.stack.PushUint64(0)
	}

	// Check if the target is a precompiled contract.
	// CALLCODE to a precompiled contract executes the precompiled logic
	// in the caller's storage context. Value transfer already occurred above;
	// RevertToSnapshot on failure undoes it.
	// QVM-R10-H2 / R37-P1-QVM-02 FIX (2026-07-30): pass the INHERITED
	// read-only flag instead of a hardcoded false. CALLCODE inside a
	// STATICCALL chain runs under the static guarantee (ReadOnly
	// propagates via ctx), so stateful precompiles must stay rejected.
	if executed, success, err := i.executePrecompiled(env, addr, input, callGas, outOffset, outSize, env.ctx.ReadOnly); executed {
		// R5-P3-2 FIX: Use the success return value instead of Peek-ing the stack.
		if !success {
			env.stateDB.RevertToSnapshot(snapshot)
		}
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		return err
	}

	// Execute call
	result := i.Execute(callCtx, env.stateDB)

	// Return unused gas
	if result.GasUsed < callGas {
		env.gas.Return(callGas - result.GasUsed)
	}

	// Handle result
	if result.Err != nil && !result.Reverted {
		// CRIT-1 FIX: Restore activeAddresses BEFORE state revert
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		env.stateDB.RevertToSnapshot(snapshot)
		env.returnData = nil
		return env.stack.PushUint64(0)
	}

	if result.Reverted {
		// CRIT-1 FIX: Restore activeAddresses on revert as well
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		env.stateDB.RevertToSnapshot(snapshot)
	}

	// Store return data
	env.returnData = result.ReturnData

	// Copy return data to memory
	if outSize > 0 && len(result.ReturnData) > 0 {
		copySize := outSize
		if uint64(len(result.ReturnData)) < copySize {
			copySize = uint64(len(result.ReturnData))
		}
		if err := env.memory.Set(outOffset, result.ReturnData[:copySize]); err != nil {
			env.activeAddresses = env.activeAddresses[:savedActiveLen]
			return err
		}
	}

	// Add logs
	// L8-004 FIX: Do not propagate logs from a reverted sub-call. When the
	// sub-call reverts, its state changes (including emitted logs) are
	// rolled back via RevertToSnapshot, so propagating them to the parent
	// would create inconsistent state (matching the L5-003 fix pattern
	// applied to opCall in call.go).
	if !result.Reverted {
		env.logs = append(env.logs, result.Logs...)
	}

	// R40-CRIT-2 FIX: Cleanup activeAddresses on normal return path
	// (matching opCall CR40-C4 FIX pattern)
	env.activeAddresses = env.activeAddresses[:savedActiveLen]

	// Push success/failure
	if result.Err != nil {
		return env.stack.PushUint64(0)
	}
	return env.stack.PushUint64(1)
}

func (i *Interpreter) opSelfDestruct(env *Environment) error {
	// P2-1 FIX: Reject self-destruct in read-only context (STATICCALL).
	// SELFDESTRUCT modifies state (transfers balance, marks account destroyed),
	// so it must not execute under STATICCALL.
	if env.ctx.ReadOnly {
		return ErrWriteProtection
	}

	// Pop beneficiary address from stack
	beneficiaryWord, err := env.stack.Pop()
	if err != nil {
		return err
	}

	var beneficiary Address
	copy(beneficiary[:], beneficiaryWord[12:])

	// Check if contract has already self-destructed.
	//
	// QVM-R10-M2 (2026-07-19) FIX: EIP-6780 same-tx re-creation support.
	// The stateDB's HasSelfDestructed flag remains set after a contract is
	// self-destructed and then RE-CREATED at the same address within the
	// same tx. To allow the re-created contract to self-destruct again
	// (EIP-6780 permits this — it's a fresh creation), we consult the
	// env.selfDestructCleared set BEFORE applying the no-op early return.
	// If the address is in selfDestructCleared, we treat the
	// HasSelfDestructed flag as logically cleared and proceed with the
	// self-destruct (which will set the flag again and re-mark the account).
	if env.stateDB.HasSelfDestructed(env.ctx.Address) {
		cleared := false
		// Traverse to the root env that owns the selfDestructCleared map
		// (same pattern as IncrementReentryCount traversing to root for
		// reentryCounts).
		root := env
		for root.parentEnv != nil {
			root = root.parentEnv
		}
		if root.selfDestructCleared != nil {
			cleared = root.selfDestructCleared[env.ctx.Address]
		}
		if !cleared {
			// Already self-destructed - this is a no-op in EVM
			env.stopped = true
			return nil
		}
		// Logical clear: remove from cleared set so a third self-destruct
		// on the same address (in the same tx) is correctly treated as
		// a duplicate (no-op), matching EIP-6780's "one self-destruct per
		// creation" semantics.
		delete(root.selfDestructCleared, env.ctx.Address)
	}

	// R40-C-H2 FIX: EIP-6780 self-destruct semantics.
	// A contract can only self-destruct if it was created in the same transaction.
	// Contracts created in prior transactions cannot self-destruct under EIP-6780.
	// Check txCreatedContracts: if map is nil or contract not in map, reject.
	if env.txCreatedContracts != nil && !env.txCreatedContracts[env.ctx.Address] {
		// EIP-6780: contract was NOT created in this tx — self-destruct is a no-op
		// (this is the new behavior; pre-Shanghai chains would still execute)
		env.stopped = true
		return nil
	}

	// audit-fix QVM-H3 + P1-2: Reentrancy check for SELFDESTRUCT removed.
	// The previous check (callDepth >= 1 && IsAddressActive) was always true
	// after callDepth++, blocking legitimate SELFDESTRUCT when a contract is
	// called from another contract. In EVM, SELFDESTRUCT is allowed at any
	// call depth. The env.selfDestructed flag (checked above) already prevents
	// double self-destruct. Reentrancy protection is not needed because
	// SELFDESTRUCT does not invoke external code.
	// R9-QV-004 FIX: SELFDESTRUCT does not make a sub-call, so it should not
	// increment callDepth or check PushActiveAddress. In EVM, SELFDESTRUCT is
	// allowed at any call depth. The previous code could erroneously fail at
	// max call depth. We still add the self-address to activeAddresses for
	// reentrancy detection, but without failing on max depth.
	// QVM-FIX: Track whether push succeeded and only pop when we did —
	// otherwise PopActiveAddress would underflow the activeAddresses slice (or
	// pop a sibling frame's entry) when SELFDESTRUCT runs at >=1024 active depth.
	pushed := env.PushActiveAddress(env.ctx.Address)
	if pushed {
		defer env.PopActiveAddress()
	}

	// Calculate gas cost
	gasCost := GasSelfDestruct
	isNewAccount := !env.stateDB.Exist(beneficiary)

	// R47-H-H1 FIX: EIP-6780 self-destruct gas — only charge GasSelfDestructNewAccount
	// when sending value to an account that genuinely didn't exist before this transaction.
	// Previously used !Empty(beneficiary) which incorrectly added surcharge for pre-existing
	// empty accounts. EIP-6780 requires: if value > 0 and beneficiary is a new account,
	// add GasSelfDestructNewAccount. For existing accounts (including empty ones),
	// no extra gas is charged — the value transfer is already covered by GasSelfDestruct.
	//
	// P3-QVM-GASSAFE FIX (R30, 2026-07-27): Use SafeAddGas instead of `+=`
	// for defense-in-depth. GasSelfDestruct (5000) + GasSelfDestructNewAccount
	// (25000) = 30000 cannot overflow uint64, but using the safe function
	// keeps this consistent with the rest of the gas calculation paths and
	// protects against future constant changes.
	balance := env.stateDB.GetBalance(env.ctx.Address)
	if isNewAccount && balance.Sign() > 0 {
		var addErr error
		gasCost, addErr = SafeAddGas(gasCost, GasSelfDestructNewAccount)
		if addErr != nil {
			return ErrGasOverflow
		}
	}

	if err := env.gas.Consume(gasCost); err != nil {
		return err
	}

	// Transfer all balance to beneficiary
	balance = env.stateDB.GetBalance(env.ctx.Address)
	if balance.Sign() > 0 {
		env.stateDB.SetBalance(env.ctx.Address, big.NewInt(0))
		beneficiaryBalance := env.stateDB.GetBalance(beneficiary)
		env.stateDB.SetBalance(beneficiary, new(big.Int).Add(beneficiaryBalance, balance))
	}

	// Mark contract as self-destructed
	env.stateDB.SelfDestruct(env.ctx.Address)

	// Set the beneficiary for later processing (after transaction completes)
	env.selfDestructed = true
	env.selfDestructBeneficiary = beneficiary

	// Stop execution
	env.stopped = true

	return nil
}

// Context operations

// opOrigin returns the transaction sender address
func (i *Interpreter) opOrigin(env *Environment) error {
	return env.stack.Push(NewWord(env.ctx.Origin[:]))
}

// opCallDataCopy copies call data to memory
func (i *Interpreter) opCallDataCopy(env *Environment) error {
	dest, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	offset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	size, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	if size == 0 {
		return nil
	}

	if dest > math.MaxUint64-size || offset > math.MaxUint64-size {
		return fmt.Errorf("CALLDATACOPY offset overflow")
	}

	// R40-M12 FIX: Memory expansion should only be based on dest+size (the
	// destination in memory), not max(dest+size, offset+size). The offset+size
	// refers to the source in calldata which does not affect memory growth.
	// Using max() overcharges gas when offset > dest.
	expansionCost := MemoryExpansionCost(env.memory.Size(), dest+size)
	// R40-H7 FIX: Charge per-word copy gas (GasCopy=3 per 32-byte word).
	// CALLDATACOPY previously only charged memory expansion but not the
	// per-word copy cost, underpricing large data copies.
	// R53-QV-01 FIX: Use SafeAddGas for size+31 to prevent overflow when
	// size is near uint64 max. Without this, (size+31) wraps to a small
	// value, bypassing gas charging for huge copies.
	words, err := SafeAddGas(size, 31)
	if err != nil {
		return fmt.Errorf("size overflow in CALLDATACOPY gas calculation")
	}
	words /= 32
	copyGas, err := SafeMulGas(GasCopy, words)
	if err != nil {
		return fmt.Errorf("copy gas overflow in CALLDATACOPY")
	}
	// FIX: Use SafeAddGas to prevent overflow in gas calculation.
	totalCopyCost, gerr := SafeAddGas(expansionCost, copyGas)
	if gerr != nil {
		return fmt.Errorf("gas cost overflow")
	}
	if err := env.gas.Consume(totalCopyCost); err != nil {
		return err
	}

	// Get call data
	data := make([]byte, size)
	inputLen := uint64(len(env.ctx.Input))
	if offset < inputLen {
		end := offset + size
		if end > inputLen {
			end = inputLen
		}
		copy(data, env.ctx.Input[offset:end])
	}

	return env.memory.Set(dest, data)
}

// opReturnDataCopy copies return data from the last call to memory.
// R40-C-C1 FIX: EIP-211 (Byzantium) — required for Solidity CREATE/call
// return value handling. Without this, contracts using RETURNDATASIZE and
// RETURNDATACOPY will fail with INVALID OPCODE.
func (i *Interpreter) opReturnDataCopy(env *Environment) error {
	dest, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	offset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	size, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	if size == 0 {
		return nil
	}

	// R39-H2/H3 SECURITY FIX: Safe boundary check — prevent panic on offset > len(data).
	returnDataLen := uint64(len(env.returnData))
	if dest > math.MaxUint64-size || offset > math.MaxUint64-size {
		return fmt.Errorf("RETURNDATACOPY offset overflow")
	}

	// EIP-211: RETURNDATACOPY must fail if offset+size exceeds return data length.
	// Previously, out-of-bounds reads silently returned zero data, which is incorrect.
	if offset+size > returnDataLen {
		return fmt.Errorf("RETURNDATACOPY out of bounds: offset=%d size=%d returnDataLen=%d", offset, size, returnDataLen)
	}

	// R40-M12 FIX: Memory expansion should only be based on dest+size (the
	// destination in memory), not max(dest+size, offset+size). The offset+size
	// refers to the source in returnData which does not affect memory growth.
	// Using max() overcharges gas when offset > dest.
	expansionCost := MemoryExpansionCost(env.memory.Size(), dest+size)
	// R40-H7 FIX: Charge per-word copy gas (GasCopy=3 per 32-byte word).
	// RETURNDATACOPY previously only charged memory expansion but not the
	// per-word copy cost, underpricing large data copies.
	// R53-QV-01 FIX: Use SafeAddGas for size+31 to prevent overflow when
	// size is near uint64 max. Without this, (size+31) wraps to a small
	// value, bypassing gas charging for huge copies.
	rdWords, err := SafeAddGas(size, 31)
	if err != nil {
		return fmt.Errorf("size overflow in RETURNDATACOPY gas calculation")
	}
	rdWords /= 32
	rdCopyGas, err := SafeMulGas(GasCopy, rdWords)
	if err != nil {
		return fmt.Errorf("copy gas overflow in RETURNDATACOPY")
	}
	// FIX: Use SafeAddGas to prevent overflow in gas calculation.
	totalCopyCost, gerr := SafeAddGas(expansionCost, rdCopyGas)
	if gerr != nil {
		return fmt.Errorf("gas cost overflow")
	}
	if err := env.gas.Consume(totalCopyCost); err != nil {
		return err
	}

	data := make([]byte, size)
	copy(data, env.returnData[offset:offset+size])

	return env.memory.Set(dest, data)
}

// opCodeSize returns the size of the contract code
func (i *Interpreter) opCodeSize(env *Environment) error {
	// EVM COMPATIBILITY: During contract creation, use OriginalCode length
	// so CODESIZE matches the original (untranslated) bytecode size.
	codeLen := len(env.ctx.Code)
	if env.ctx.OriginalCode != nil {
		codeLen = len(env.ctx.OriginalCode)
	}
	return env.stack.PushUint64(uint64(codeLen))
}

// opCodeCopy copies code to memory
func (i *Interpreter) opCodeCopy(env *Environment) error {
	dest, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	offset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	size, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	if size == 0 {
		return nil
	}

	if dest > math.MaxUint64-size || offset > math.MaxUint64-size {
		return fmt.Errorf("CODECOPY offset overflow")
	}

	// R40-M12 FIX: Memory expansion should only be based on dest+size (the
	// destination in memory), not max(dest+size, offset+size). The offset+size
	// refers to the source in code which does not affect memory growth.
	// Using max() overcharges gas when offset > dest.
	expansionCost := MemoryExpansionCost(env.memory.Size(), dest+size)
	// R40-H7 FIX: Charge per-word copy gas (GasCopy=3 per 32-byte word).
	// CODECOPY previously only charged memory expansion but not the
	// per-word copy cost, underpricing large data copies.
	// R47-QV-02 FIX: Guard against size+31 wraparound and copyGas overflow.
	if size > math.MaxUint64-31 {
		return fmt.Errorf("CODECOPY size overflow")
	}
	words := (size + 31) / 32
	// P3-QVM-GASSAFE FIX (R30, 2026-07-27): Replaced manual overflow check
	// + direct `*` with SafeMulGas for consistency with the audit-fix C-3
	// safe gas arithmetic pattern. SafeMulGas performs the same
	// `a > 0 && b > MaxUint64/a` check internally.
	copyGas, copyErr := SafeMulGas(GasCopy, words)
	if copyErr != nil {
		return fmt.Errorf("CODECOPY copy gas overflow")
	}
	// FIX: Use SafeAddGas to prevent overflow in gas calculation.
	totalCopyCost, gerr := SafeAddGas(expansionCost, copyGas)
	if gerr != nil {
		return fmt.Errorf("gas cost overflow")
	}
	if err := env.gas.Consume(totalCopyCost); err != nil {
		return err
	}

	// Get code
	// EVM COMPATIBILITY: During contract creation, Code is translated but constructor
	// args at the end of Code are corrupted by the translator. Use OriginalCode
	// (untranslated) if available, so CODECOPY returns correct data.
	sourceCode := env.ctx.Code
	if env.ctx.OriginalCode != nil {
		sourceCode = env.ctx.OriginalCode
	}
	code := make([]byte, size)
	codeLen := uint64(len(sourceCode))
	if offset < codeLen {
		end := offset + size
		if end > codeLen {
			end = codeLen
		}
		copy(code, sourceCode[offset:end])
	}

	return env.memory.Set(dest, code)
}

// opGasPrice returns the gas price
func (i *Interpreter) opGasPrice(env *Environment) error {
	return env.stack.Push(NewWordFromBigInt(env.ctx.GasPrice))
}

// opGasLimit returns the block gas limit
func (i *Interpreter) opGasLimit(env *Environment) error {
	return env.stack.PushUint64(env.ctx.GasLimit)
}

// opBlockHash returns the hash of a block number
// FIX C-4: Implement proper BLOCKHASH using real block hashes from Environment
func (i *Interpreter) opBlockHash(env *Environment) error {
	// R40-L3 FIX: Removed internal gas.Consume(GasBlockHash) call.
	// The opcodeInfoTable already charges GasCost: 20 for BLOCKHASH in the
	// run() loop before executeOp() is called. Having an additional Consume()
	// here double-charges gas (20 from the table + 20 here = 40 total).
	// Only one charge of 20 gas is correct per the EVM yellow paper.

	blockNum, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	// Get the current block number
	currentBlock := env.ctx.BlockNumber

	// BLOCKHASH should only work for the most recent 256 blocks
	if blockNum >= currentBlock || currentBlock-blockNum > 256 {
		// Return zero hash for blocks outside the accessible range
		zeroHash := Hash{}
		return env.stack.Push(NewWord(zeroHash[:]))
	}

	// Use the environment's getBlockHash function
	hash := env.getBlockHash(blockNum)
	return env.stack.Push(NewWord(hash[:]))
}

// opCoinbase returns the block proposer's address
func (i *Interpreter) opCoinbase(env *Environment) error {
	return env.stack.Push(NewWord(env.ctx.Coinbase[:]))
}

// opSelfBalance returns the balance of the current contract
func (i *Interpreter) opSelfBalance(env *Environment) error {
	balance := env.stateDB.GetBalance(env.ctx.Address)
	return env.stack.Push(NewWordFromBigInt(balance))
}

// Create operations

// SECURITY (audit P4-6): CREATE/CREATE2 initEnv depth tracking.
// R35-P3 FIX (2026-07-29): The original TODO ("Ensure depth tracking
// matches across all CREATE variants") is now resolved. Both opCreate
// and opCreate2 delegate to opCreateGeneric (below), which initializes
// initEnv.callDepth from initCtx.Depth (R35-P0-01 fix at line 1468).
// Because there is a single CREATE code path, depth tracking is
// consistent across both variants by construction.
func (i *Interpreter) opCreate(env *Environment) error {
	return i.opCreateGeneric(env, false)
}

func (i *Interpreter) opCreate2(env *Environment) error {
	return i.opCreateGeneric(env, true)
}

func (i *Interpreter) opCreateGeneric(env *Environment, isCreate2 bool) error {
	if env.ctx.ReadOnly {
		return ErrWriteProtection
	}

	// Pop value, offset, size from stack
	value, err := env.stack.PopBigInt()
	if err != nil {
		return err
	}
	offset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	size, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	var salt Hash
	if isCreate2 {
		//  NOTE (P3): The CREATE2 salt is popped from the stack and copied
		// into a local `salt` Hash. It is never written to memory, so there is no
		// memory region to zero out. The local variable goes out of scope when
		// opCreateGeneric returns and the stack word that held it will be
		// overwritten by subsequent stack operations, so residual exposure is low
		// risk. No explicit zeroing is required here.
		saltWord, err := env.stack.Pop()
		if err != nil {
			return err
		}
		copy(salt[:], saltWord[:])
	}

	// FIX: EIP-3860 -- enforce a maximum initcode size before memory
	// expansion. Without this bound a caller could supply arbitrarily large
	// initcode, forcing the VM to allocate/copy huge memory regions and hash
	// gigabytes of data (CREATE2), a DoS vector. Reuses the package-level
	// MaxInitCodeSize constant (49152 = 2*MaxCodeSize, matching EIP-3860)
	// already enforced by the bytecode validator.
	if size > MaxInitCodeSize {
		return ErrInitCodeSizeExceeded
	}

	// QVM- (2026-07-20) FIX: EVM atomicity — compute gas BEFORE touching memory.
	// Previously env.memory.Get(offset, size) was called here, which expands memory
	// (m.expand). If gas.Consume below later failed (insufficient gas), memory had
	// already been mutated, violating EVM atomicity expectations. Callers that
	// catch ErrOutOfGas and revert state would still see memory growth leaking
	// into the rollback snapshot. The fix computes gas using the (known) `size`
	// operand — len(initCode) is always == size for memory.Get — and only touches
	// memory AFTER gas is successfully charged.
	//
	// Calculate gas
	gasCost := GasCreate
	if isCreate2 {
		gasCost = GasCreate2
	}

	// Add gas for memory expansion
	gasMemory, err := calculateMemoryGas(env, offset, size)
	if err != nil {
		return err
	}
	// FIX: Use SafeAddGas for all cumulative gas additions to prevent overflow.
	gasCost, err = SafeAddGas(gasCost, gasMemory)
	if err != nil {
		return fmt.Errorf("create gas overflow: memory expansion")
	}

	// R41-H3 FIX: EIP-3860 — charge 200 gas per byte of initcode beyond 32 bytes.
	// Prevents underpriced deployment of large contracts (DoS vector).
	// R47-H-H2 FIX: Applied to BOTH CREATE and CREATE2. EIP-3860 applies to both;
	// previously only CREATE2 was charged, allowing CREATE to deploy arbitrarily large
	// initcode at underpriced gas (DoS vector for CREATE deployments).
	// QVM- use `size` directly (== len(memory.Get result)) so gas can be
	// computed without touching memory.
	if size > 32 {
		eip3860Cost, merr := SafeMulGas(size-32, 200)
		if merr != nil {
			return fmt.Errorf("create gas overflow: EIP-3860 initcode cost")
		}
		gasCost, err = SafeAddGas(gasCost, eip3860Cost)
		if err != nil {
			return fmt.Errorf("create gas overflow: EIP-3860")
		}
	}

	// P3-2 FIX: EIP-1014 — CREATE2 charges hash cost: 6 * ceil(initCode_size / 32).
	// The JIT compiler charges this cost but the interpreter did not, allowing
	// CREATE2 deployments to bypass the keccak256 hashing gas surcharge (DoS vector).
	// R8-P4 FIX: Guard against integer overflow when size is near MaxUint64.
	if isCreate2 && size > 0 {
		if size > math.MaxUint64-31 {
			return ErrMemoryOverflow
		}
		hashCost, merr := SafeMulGas((size+31)/32, 6)
		if merr != nil {
			return fmt.Errorf("create gas overflow: CREATE2 hash cost")
		}
		gasCost, err = SafeAddGas(gasCost, hashCost)
		if err != nil {
			return fmt.Errorf("create gas overflow: CREATE2 hash")
		}
	}

	if err := env.gas.Consume(gasCost); err != nil {
		return err
	}

	// QVM- NOW safe to expand memory — gas has been charged in full.
	initCode, err := env.memory.Get(offset, size)
	if err != nil {
		return err
	}

	// Take a snapshot before making any changes
	snapshot := env.stateDB.Snapshot()

	// FIX: Use env.ctx.Address (the current contract executing CREATE)
	// instead of env.ctx.Caller (who called this contract). In EVM, the CREATE
	// opcode derives the new contract address from the CURRENT contract's address
	// and nonce, not from the caller's. The value transfer also comes from the
	// current contract's balance. Previous code used env.ctx.Caller, which would
	// derive the address from the wrong account and deduct value from the wrong
	// balance — a critical correctness bug for nested contract deployments.
	creator := env.ctx.Address

	// Calculate contract address
	var contractAddr Address
	if isCreate2 {
		contractAddr = Create2Address(creator, salt, initCode)
	} else {
		nonce := env.stateDB.GetNonce(creator)
		contractAddr = CreateAddress(creator, nonce)
	}

	// Check for address collision.
	//
	// QVM-R10-M2 (2026-07-19) FIX: EIP-6780 alignment for same-tx re-creation.
	// Under EIP-6780, when a contract created in tx T self-destructs within
	// the same tx, the slot is considered "free" for re-creation within that
	// tx. The previous collision check (`GetCodeSize > 0 || GetNonce > 0`)
	// would reject this re-creation when the stateDB implementation leaves
	// the nonce non-zero after SelfDestruct (which most implementations do —
	// only the code is cleared, the account remains until end-of-tx for
	// refund/accounting purposes). This produced an edge-case behavior
	// divergence from EIP-6780: a contract could self-destruct in the
	// same tx but the slot could not be re-used, even though EIP-6780
	// explicitly permits re-creation.
	//
	// The fix: if the target address has been marked as self-destructed IN
	// THIS TX (via txCreatedContracts && stateDB.HasSelfDestructed), the
	// collision check is relaxed to only reject when the code is non-empty
	// (nonce is allowed to be > 0). This matches geth's EIP-6780 behavior.
	// We still reject re-creation when the address has non-empty code —
	// that would be a genuine collision (the contract is still alive).
	//
	// Edge cases correctly handled:
	//   - No prior creation at addr: GetCodeSize=0, GetNonce=0 → allow (matches old behavior)
	//   - Existing contract at addr (not self-destructed this tx): GetCodeSize>0 → reject
	//   - Contract created + self-destructed this tx: HasSelfDestructed=true → allow re-creation
	//   - Previously self-destructed in DIFFERENT tx: HasSelfDestructed=false (state was
	//     cleared at end of that tx) → falls through to standard collision check
	hasSelfDestructedThisTx := env.txCreatedContracts != nil &&
		env.txCreatedContracts[contractAddr] &&
		env.stateDB.HasSelfDestructed(contractAddr)
	if hasSelfDestructedThisTx {
		// EIP-6780: slot is free for re-creation. Only reject if code is
		// somehow still present (shouldn't happen, but defensive).
		if env.stateDB.GetCodeSize(contractAddr) > 0 {
			env.stateDB.RevertToSnapshot(snapshot)
			return env.stack.Push(AddressToWord(Address{}))
		}
		// QVM-R10-M2: Mark the address as logically cleared in the tx-scoped
		// selfDestructCleared set. opSelfDestruct consults this set before
		// applying the HasSelfDestructed early-return no-op, allowing the
		// re-created contract to self-destruct again (EIP-6780 permits this
		// since it's a fresh creation). The stateDB's HasSelfDestructed flag
		// is NOT cleared (stateDB implementations don't expose a Clear
		// method); we layer the logical clear on top via this env-scoped set.
		root := env
		for root.parentEnv != nil {
			root = root.parentEnv
		}
		if root.selfDestructCleared == nil {
			root.selfDestructCleared = make(map[Address]bool)
		}
		root.selfDestructCleared[contractAddr] = true
		// Also remove the entry from txCreatedContracts so the next
		// SELFDESTRUCT doesn't bypass the EIP-6780 check via the stale
		// "created in this tx" flag. The new creation below will re-add it.
		delete(env.txCreatedContracts, contractAddr)
	} else if env.stateDB.GetCodeSize(contractAddr) > 0 || env.stateDB.GetNonce(contractAddr) > 0 {
		env.stateDB.RevertToSnapshot(snapshot)
		return env.stack.Push(AddressToWord(Address{}))
	}

	// CRITICAL FIX: Check for nonce overflow before incrementing
	// math.MaxUint64 nonce would overflow on CREATE, causing panic
	creatorNonce := env.stateDB.GetNonce(creator)
	if creatorNonce == ^uint64(0) {
		env.stateDB.RevertToSnapshot(snapshot)
		return env.stack.Push(AddressToWord(Address{}))
	}

	// Increment creator nonce
	env.stateDB.SetNonce(creator, creatorNonce+1)

	// R37-P3-21 FIX (2026-07-31): EIP-161 — a newly created contract account
	// starts with nonce 1 (matches go-ethereum create()). Previously the
	// contract account nonce stayed 0, so a nested CREATE computing the same
	// address during init execution would bypass the GetNonce>0 collision
	// check, and the account was considered "empty" (nonce=0, balance=0,
	// no code) and could be pruned. Placed after the snapshot above so any
	// later failure reverts it via RevertToSnapshot.
	env.stateDB.SetNonce(contractAddr, 1)

	// Transfer value if any
	if value.Sign() > 0 {
		creatorBalance := env.stateDB.GetBalance(creator)
		if creatorBalance.Cmp(value) < 0 {
			env.stateDB.RevertToSnapshot(snapshot)
			return env.stack.Push(AddressToWord(Address{}))
		}
		env.stateDB.SetBalance(creator, new(big.Int).Sub(creatorBalance, value))
		env.stateDB.SetBalance(contractAddr, new(big.Int).Add(env.stateDB.GetBalance(contractAddr), value))
	}

	// V21-001/V21-002 FIX: Translate EVM bytecode for init code execution.
	// The contract address was already calculated above using the ORIGINAL
	// initCode (important for CREATE2 address determinism). Now translate
	// the init code for execution, mirroring executor.go's pattern.
	execInitCode := initCode
	evmCompatible := false
	if len(initCode) > 0 && IsEVMBytecode(initCode) {
		translated, err := TranslateEVMBytecode(initCode)
		if err == nil {
			execInitCode = translated
			evmCompatible = true
		}
	}

	// Create execution context for init code
	// R30-P3 FIX: Document initCode translation consistency:
	// - Code: translated QVM bytecode (for execution by interpreter)
	// - Input: original EVM bytecode (CALLDATA in constructor returns original)
	// - OriginalCode: original EVM bytecode (CODECOPY returns original, not translated)
	// - Contract address was calculated above using ORIGINAL initCode (CREATE2 determinism)
	initCtx := &ExecutionContext{
		Origin:   env.ctx.Origin,
		GasPrice: env.ctx.GasPrice,
		// R40-H13 FIX: Use env.ctx.Address (the current contract) as the Caller
		// for the new contract's init code. In EVM, when contract A calls CREATE,
		// the new contract's msg.sender should be A (env.ctx.Address), not A's
		// caller (env.ctx.Caller). Previously this incorrectly propagated the
		// grandparent caller, breaking msg.sender semantics in constructors.
		Caller:        env.ctx.Address,
		Address:       contractAddr,
		Value:         value,
		BlockNumber:   env.ctx.BlockNumber,
		Timestamp:     env.ctx.Timestamp,
		Coinbase:      env.ctx.Coinbase,
		GasLimit:      env.ctx.GasLimit,
		ChainID:       env.ctx.ChainID,
		BaseFee:       env.ctx.BaseFee,     // QVM- propagate BASEFEE opcode value
		BlobBaseFee:   env.ctx.BlobBaseFee, // QVM- propagate BLOBBASEFEE opcode value
		PrevRandao:    env.ctx.PrevRandao,  // QVM- propagate PREVRANDAO opcode value
		Code:          execInitCode,
		Input:         initCode,
		OriginalCode:  initCode,
		Gas:           env.gas.Remaining() - env.gas.Remaining()/64,
		Depth:         env.ctx.Depth + 1,
		ReadOnly:      false,
		ParentEnv:     env,
		EVMCompatible: evmCompatible,
	}

	// Create new environment for init code execution
	initEnv := &Environment{
		ctx:         initCtx,
		stateDB:     env.stateDB,
		stack:       NewStack(),
		memory:      NewMemory(),
		gas:         NewGasMeter(initCtx.Gas),
		gasTable:    i.gasTable,
		precompiled: env.precompiled,
		pc:          0,
		jumpDests:   i.analyzeJumpDests(execInitCode),
		logs:        make([]*Log, 0),
		returnData:  nil,
		blockHashes: env.blockHashes,
		// R35-P0-01 FIX: Initialize callDepth from initCtx.Depth so that
		// reentrancy protection (callDepth >= 1) works correctly inside
		// constructor init code. Previously callDepth defaulted to 0, which
		// disabled reentrancy protection entirely during CREATE/CREATE2 —
		// a DAO-style reentrancy attack could be performed from a
		// constructor callback with no gas penalty (2300 reentrancy surcharge)
		// and no hard cap (MaxReentriesPerAddress=10). The parent env's
		// callDepth is incremented separately at line 1554 below; this
		// initialization ensures the child env inherits the correct depth.
		callDepth: uint64(initCtx.Depth),
		// AUDIT (2026) QVFIX: Share transient storage (EIP-1153)
		// from the parent environment. Transient storage is per-transaction
		// and must be shared across the entire call tree, including CREATE
		// init code. Without this, TLOAD in a constructor cannot read
		// transient storage set by the deploying contract, and TSTORE in a
		// constructor is lost when init completes — breaking reentrancy
		// locks and other cross-frame transient state. The Execute path
		// (qvm.go:220-222) already shares this via ctx.ParentEnv; this CREATE
		// path creates initEnv directly and must share explicitly.
		transientStorage: env.transientStorage,
		// AUDIT (2026) QVFIX: Share reentry counts so the cap
		// applies across the entire transaction including CREATE init code.
		reentryCounts: env.reentryCounts,
		// R40-C-H1 FIX: Link to parent env so IsAddressActive can traverse
		// the full call chain during init code execution. This enables
		// detection of factory pattern CREATE→callback→re-entry attacks
		// where init code calls back into the deploying contract.
		parentEnv: env,
	}

	if len(env.activeAddresses) > 0 {
		initEnv.activeAddresses = make([]Address, len(env.activeAddresses))
		copy(initEnv.activeAddresses, env.activeAddresses)
	}

	// R40-C-H2 FIX: Copy txCreatedContracts to initEnv so nested CREATE
	// operations can also mark contracts as created in this transaction.
	// The map is shared by reference so updates in initEnv are visible to parent.
	// QVM-FIX: Ensure the map is initialized BEFORE sharing with initEnv.
	// Previously the map was lazily created at line ~1445 only on the parent env
	// AFTER initEnv had already been built with a nil map (line ~1335 skipped
	// sharing when env.txCreatedContracts == nil). The lazy-created map was
	// therefore NOT shared with initEnv — init code SELFDESTRUCT (EIP-6780)
	// could not see the freshly-created contract, and any nested CREATE inside
	// init code would silently drop its own txCreatedContracts updates.
	// Initializing here makes the parent and init code share the same map.
	if env.txCreatedContracts == nil {
		env.txCreatedContracts = make(map[Address]bool)
	}
	initEnv.txCreatedContracts = env.txCreatedContracts

	// R35-P2-QVM-02 FIX (2026-07-29): Move callDepth++ + MaxCallDepth check
	// BEFORE PushActiveAddress, matching opCall/opCallCode/opDelegateCall/
	// opStaticCall ordering. Previously PushActiveAddress was called first,
	// then gas.Consume, then callDepth++ — so a depth-exceeded CREATE would
	// push the address into activeAddresses (and consume gas) before being
	// rejected. This is inconsistent with CALL (which checks depth first)
	// and could leave activeAddresses in a stale state on depth failure.
	env.callDepth++
	defer func() { env.callDepth-- }()
	if env.callDepth >= MaxCallDepth {
		if env.tracer != nil {
			env.tracer.CaptureExit(nil, 0, ErrDepthExceeded)
		}
		env.stateDB.RevertToSnapshot(snapshot)
		return env.stack.Push(AddressToWord(Address{}))
	}

	// Execute init code
	// R39-M1 FIX: Push contract address for reentrancy protection during constructor
	// R49-C-C1 FIX: Check return value - if max active call depth exceeded,
	// revert and return zero address. Previously the return value was ignored,
	// which could allow the init code to execute without the contract being
	// in activeAddresses, breaking reentrancy protection.
	if !initEnv.PushActiveAddress(contractAddr) {
		env.stateDB.RevertToSnapshot(snapshot)
		return env.stack.Push(AddressToWord(Address{}))
	}

	// P1-1 FIX: Consume the full gas allocated to the child upfront (matching CALL pattern).
	// Previously, the parent never consumed initCtx.Gas but Return() credited back
	// the unused portion — giving the parent free gas (net gain = initCtx.Gas - childGasUsed).
	// Now we Consume first, then Return the unused portion, so net deduction = childGasUsed.
	if err := env.gas.Consume(initCtx.Gas); err != nil {
		env.stateDB.RevertToSnapshot(snapshot)
		return env.stack.Push(AddressToWord(Address{}))
	}

	if env.tracer != nil {
		createOp := CREATE
		if isCreate2 {
			createOp = CREATE2
		}
		env.tracer.CaptureEnter(createOp, env.ctx.Address, contractAddr, initCode, initCtx.Gas, value)
	}
	// QVM-P0-01 FIX (R31, 2026-07-27): Capture run() return value and
	// synchronize initEnv fields. Previously `i.run(initEnv)` was called
	// for its side effects and the return value (*ExecutionResult) was
	// discarded. When run() recovered from a panic (nil pointer, stack
	// overflow, out-of-bounds in init code), it set result.Reverted=true
	// and result.Err on the RETURN VALUE only — it did NOT touch
	// initEnv.reverted or initEnv.err. The subsequent check at line ~1536
	// (`if initEnv.err != nil || initEnv.reverted`) therefore evaluated
	// to false, and execution fell through to treat nil/garbage returnData
	// as deployed code. This caused: nonce incremented + value transferred
	// but no contract deployed, then nil stored as code → state pollution
	// and permanent fund lock. Attackers can craft panic-triggering init
	// code at will. Fix: capture the result, and if it indicates panic/
	// revert/error, propagate to initEnv.reverted/err/returnData BEFORE
	// the post-run check. Tracked by QVM-P0-01.
	//
	// QVM-P0-02 FIX (R31, 2026-07-27): Depth check + callDepth tracking
	// was MOVED to before PushActiveAddress by R35-P2-QVM-02 (see above).
	// The original comment is preserved for history: opCall/opCallCode/
	// opDelegateCall/opStaticCall all increment env.callDepth and check
	// MaxCallDepth before invoking the callee. opCreateGeneric was missing
	// both; QVM-P0-02 added them, and R35-P2-QVM-02 moved them earlier for
	// ordering consistency with CALL (depth check → PushActiveAddress → gas).
	// R38-P1-07 FIX: Snapshot the parent environment's transient storage before
	// running the constructor. The constructor shares env.transientStorage
	// (line 1495), so TSTORE in init code mutates the parent's map directly.
	// If CREATE fails, RevertToSnapshot only rolls back StateDB's transient
	// storage — NOT the QVM Environment's map. Without this snapshot/restore,
	// a failed constructor's TSTORE would persist into the parent frame,
	// breaking EIP-1153 semantics (transient storage must not survive a
	// reverted frame).
	transientSnapshot := copyTransientStorage(env.transientStorage)

	createResult := i.run(initEnv)
	// QVM-P0-01: Synchronize initEnv fields from createResult so the
	// post-run checks below work correctly even when run() recovered
	// from a panic (which sets result.Reverted/Err but not env fields).
	if createResult != nil {
		if createResult.Err != nil && initEnv.err == nil {
			initEnv.err = createResult.Err
		}
		if createResult.Reverted {
			initEnv.reverted = true
		}
		// QVM-P0-01: Ensure returnData is consistent with the result.
		// On panic, createResult.ReturnData is nil — propagate that so
		// we don't store stale/garbage data as deployed code.
		if initEnv.reverted || initEnv.err != nil {
			initEnv.returnData = createResult.ReturnData
		}
	}
	if env.tracer != nil {
		env.tracer.CaptureExit(initEnv.returnData, initEnv.gas.Used(), initEnv.err)
	}

	// Calculate gas used by child execution
	childGasUsed := initEnv.gas.Used()

	// The remaining gas from the child is initCtx.Gas - childGasUsed
	// This unused gas should be returned to the parent's available gas pool.
	// R40-L1 FIX: Use Return() instead of Refund(). Refund() adds to a separate
	// refund counter (for SSTORE-style refunds capped at 20% per EIP-3529),
	// while Return() credits gas back to the caller's available gas pool.
	// Using Refund() here meant unused CREATE gas was not actually returned
	// to the caller, causing callers to lose gas on successful CREATE calls.
	// CRITICAL FIX: Check for underflow before computing return
	// If childGasUsed > initCtx.Gas (due to bug), subtraction would underflow
	if childGasUsed < initCtx.Gas {
		childGasRemaining := initCtx.Gas - childGasUsed
		env.gas.Return(childGasRemaining)
	}

	// Check if execution failed or reverted
	if initEnv.err != nil || initEnv.reverted {
		env.stateDB.RevertToSnapshot(snapshot)
		// R38-P1-07 FIX: Restore the parent environment's transient storage
		// to undo any TSTORE performed by the failed constructor.
		env.transientStorage = transientSnapshot
		return env.stack.Push(AddressToWord(Address{}))
	}

	// Get deployed code
	deployedCode := initEnv.returnData

	// R38-P1-07 FIX (deployment-failure path): Every branch from here on
	// runs AFTER the constructor executed successfully (the err/reverted
	// branch above already returned). The constructor therefore already
	// TSTOREd into env.transientStorage (initEnv.transientStorage shares the
	// parent map, line 1495). Per EIP-1153 a failed CREATE frame must NOT
	// leave transient writes behind, so each deployment-failure branch must
	// restore transientSnapshot in addition to reverting the StateDB.
	//
	// Check code size limit
	if len(deployedCode) > MaxCodeSize {
		env.stateDB.RevertToSnapshot(snapshot)
		env.transientStorage = transientSnapshot
		return env.stack.Push(AddressToWord(Address{}))
	}

	// Charge for code storage
	if len(deployedCode) > 0 {
		// FIX: Use SafeMulGas to prevent uint64 overflow.
		// Without this, a very large deployedCode could cause the multiplication
		// to wrap around to a small value, allowing gas bypass.
		codeDepositCost, derr := SafeMulGas(uint64(len(deployedCode)), GasCodeDeposit)
		if derr != nil {
			env.stateDB.RevertToSnapshot(snapshot)
			env.transientStorage = transientSnapshot
			return env.stack.Push(AddressToWord(Address{}))
		}
		if err := env.gas.Consume(codeDepositCost); err != nil {
			env.stateDB.RevertToSnapshot(snapshot)
			env.transientStorage = transientSnapshot
			return env.stack.Push(AddressToWord(Address{}))
		}
	}

	// Store the code
	// V21-002 FIX: Translate deployed runtime code if it's EVM bytecode.
	// R9-QV-003 FIX: If translation fails, revert instead of silently storing
	// un-translatable EVM bytecode (which would be misinterpreted as QVM ops).
	if len(deployedCode) > 0 && IsEVMBytecode(deployedCode) {
		translatedRuntime, terr := TranslateEVMBytecode(deployedCode)
		if terr != nil {
			env.stateDB.RevertToSnapshot(snapshot)
			env.transientStorage = transientSnapshot
			return env.stack.Push(AddressToWord(Address{}))
		}
		deployedCode = translatedRuntime
	}
	// R9-QV-002 FIX: Validate deployed code (EIP-3541: reject 0xEF prefix).
	// The Executor-level Create calls BytecodeValidator.ValidateDeployedCode,
	// but opCreateGeneric (opcode-level CREATE) did not. Since Interpreter has
	// no validator field, we do the critical EIP-3541 check inline.
	if len(deployedCode) > 0 && deployedCode[0] == 0xEF {
		env.stateDB.RevertToSnapshot(snapshot)
		env.transientStorage = transientSnapshot
		return env.stack.Push(AddressToWord(Address{}))
	}
	env.stateDB.SetCode(contractAddr, deployedCode)

	// R40-C-H2 FIX: Mark contract as created in this transaction.
	// Under EIP-6780 (active post-Shanghai), a contract can only self-destruct
	// if it was created in the same transaction. This prevents contracts from
	// being destroyed after the tx that created them.
	// QVM- env.txCreatedContracts is guaranteed non-nil here (initialized
	// above before sharing with initEnv), so we write directly. The same map is
	// shared with initEnv, so any nested CREATE/SELFDESTRUCT sees this entry.
	env.txCreatedContracts[contractAddr] = true

	// R37-FIX P2-QVM-01 (2026-07-30): Propagate constructor logs to the
	// parent environment on successful deployment. Every revert path above
	// already returned before this point, so reaching here means the
	// deployment succeeded — matching the !result.Reverted guard used by
	// opCall/opCallCode/opAuthCall (L5-003 pattern). Without this, events
	// emitted by the constructor of a factory-deployed contract were
	// silently dropped from the receipt's logs/logBloom, breaking
	// indexers, wallets, and bridge listeners.
	if createResult != nil {
		env.logs = append(env.logs, createResult.Logs...)
	}

	// Push contract address on success
	return env.stack.Push(AddressToWord(contractAddr))
}

// copyTransientStorage returns a deep copy of the QVM Environment's transient
// storage map. Used by opCreateGeneric to snapshot transient storage before
// constructor execution so it can be restored if CREATE/CREATE2 fails.
// R38-P1-07: Without this, a failed constructor's TSTORE would persist into
// the parent frame, violating EIP-1153 revert semantics.
func copyTransientStorage(ts map[Address]map[Hash]Hash) map[Address]map[Hash]Hash {
	if ts == nil {
		return nil
	}
	cp := make(map[Address]map[Hash]Hash, len(ts))
	for addr, slots := range ts {
		cpSlots := make(map[Hash]Hash, len(slots))
		for k, v := range slots {
			cpSlots[k] = v
		}
		cp[addr] = cpSlots
	}
	return cp
}

// calculateMemoryGas calculates the gas required for memory expansion
func calculateMemoryGas(env *Environment, offset, size uint64) (uint64, error) {
	if size == 0 {
		return 0, nil
	}
	// FIX: Check for uint64 overflow in offset+size.
	// Without this, a large offset+size could wrap around to a small value,
	// bypassing memory expansion gas charges.
	if offset > math.MaxUint64-size {
		return 0, fmt.Errorf("memory offset+size overflow")
	}
	// Memory expansion cost
	requiredBytes := offset + size
	oldSize := env.memory.Size()
	if requiredBytes <= oldSize {
		return 0, nil
	}
	// Calculate cost for expansion
	gas := MemoryExpansionCost(oldSize, requiredBytes)
	return gas, nil
}

// AddressToWord converts an Address to a Word for stack push
func AddressToWord(addr Address) Word {
	var word Word
	copy(word[:], addr[:])
	return word
}

// Log operations

func (i *Interpreter) opLog0(env *Environment) error {
	return i.opLog(env, 0)
}

func (i *Interpreter) opLog1(env *Environment) error {
	return i.opLog(env, 1)
}

func (i *Interpreter) opLog2(env *Environment) error {
	return i.opLog(env, 2)
}

func (i *Interpreter) opLog3(env *Environment) error {
	return i.opLog(env, 3)
}

func (i *Interpreter) opLog4(env *Environment) error {
	return i.opLog(env, 4)
}

func (i *Interpreter) opLog(env *Environment, numTopics int) error {
	// P3-1 FIX: Reject LOG in read-only context (STATICCALL).
	// LOG emits events which are state changes observable outside the EVM,
	// so it must not execute under STATICCALL.
	if env.ctx.ReadOnly {
		return ErrWriteProtection
	}

	offset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	size, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	// R40-H5 FIX: Charge memory expansion gas before reading memory.
	// LOG opcodes read (offset, size) from memory but previously did not
	// account for memory expansion costs, allowing free memory growth.
	//
	// QVM-M04 (R8 2026-07-19 FIX): Compute the dynamic gas (topic + data
	// cost) and verify it for overflow BEFORE consuming memory expansion
	// gas. Previously the overflow check at the bottom ran AFTER
	// env.gas.Consume(expansionCost) — if the check failed (returning an
	// error), memory expansion gas had already been charged and the
	// caller would see a revert with partial gas consumption, breaking
	// the all-or-nothing gas accounting expectation for a single opcode.
	// Computing dynamicGas first and validating overflow up front lets
	// the failure path exit with zero gas consumed.
	//
	// P3-QVM-GASSAFE FIX (R30, 2026-07-27): Replaced direct `*` and `+`
	// operators with SafeMulGas/SafeAddGas for consistency with the
	// audit-fix C-3 safe gas arithmetic pattern. The previous "multiply
	// then check" pattern (topicGas/GasLogTopic != numTopics) works but
	// is fragile and inconsistent with the rest of the codebase. The
	// safe functions perform the check inside, returning ErrGasOverflow
	// on wrap. Behavior is identical for valid inputs.
	topicGas, topicErr := SafeMulGas(GasLogTopic, uint64(numTopics)) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction
	if topicErr != nil {
		return fmt.Errorf("gas overflow in LOG operation (topic cost)")
	}
	dataGas, dataErr := SafeMulGas(GasLogData, size)
	if dataErr != nil {
		return fmt.Errorf("gas overflow in LOG operation (data cost)")
	}
	dynamicGas, dynErr := SafeAddGas(topicGas, dataGas)
	if dynErr != nil {
		return fmt.Errorf("gas overflow in LOG operation (total)")
	}

	if size > 0 {
		if offset > math.MaxUint64-size {
			return fmt.Errorf("LOG offset overflow")
		}
		expansionCost := MemoryExpansionCost(env.memory.Size(), offset+size)
		if err := env.gas.Consume(expansionCost); err != nil {
			return err
		}
	}

	// Get log data
	data, err := env.memory.Get(offset, size)
	if err != nil {
		return err
	}

	// Get topics
	topics := make([]Hash, numTopics)
	for j := 0; j < numTopics; j++ {
		topic, err := env.stack.Pop()
		if err != nil {
			return err
		}
		copy(topics[j][:], topic[:])
	}

	// QVFIX: Dynamic gas for LOG only charges topic+data costs.
	// The static base cost (GasLog=375) is already charged by the main run() loop
	// via opcodeInfoTable[LOG0..LOG4].GasCost. Charging GasLog again here would
	// double-charge the base cost. dynamicGas was already computed and
	// overflow-checked above (QVM-M04).
	if dynamicGas > 0 {
		if err := env.gas.Consume(dynamicGas); err != nil {
			return err
		}
	}

	// Add log
	env.logs = append(env.logs, &Log{
		Address: env.ctx.Address,
		Topics:  topics,
		Data:    data,
	})

	return nil
}
