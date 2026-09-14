// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"

	"github.com/quantaureum/qau/crypto"
)

// Stack operations

func (i *Interpreter) opPush(env *Environment, op OpCode) error {
	size := op.PushSize()
	if size == 0 {
		return ErrInvalidOpcode
	}

	// Read immediate data
	start := env.pc
	end := start + uint64(size) // #nosec G115 -- safe conversion: value range verified or bit-shift extraction

	code := env.ctx.Code
	// P3-V5 AUDIT NOTE (boundary check present): Clamp `end` to len(code) so a
	// PUSH whose immediate bytes extend past the end of code does NOT read out
	// of bounds. When the immediate is truncated (end > len(code)) the missing
	// bytes are zero-padded below, matching EVM semantics. This is the sole
	// guard against malformed/short bytecode and is intentionally applied here
	// (not in PushSize) so every PUSH variant benefits from it.
	if end > uint64(len(code)) {
		end = uint64(len(code))
	}

	var data []byte
	if start < uint64(len(code)) {
		data = code[start:end]
	}

	// Pad with zeros if needed
	if len(data) < size {
		padded := make([]byte, size)
		copy(padded[size-len(data):], data)
		data = padded
	}

	env.pc = end
	return env.stack.Push(NewWord(data))
}

// Arithmetic operations

// isUint64 checks if a Word fits in uint64 (top 24 bytes are zero).
// This is the fast path check that avoids big.Int allocation.
//
// L18-037 FIX: Replaced unsafe.Pointer with portable binary.BigEndian
// reads. The previous implementation used unsafe.Pointer to cast the
// first 24 bytes of Word to [3]uint64, which has alignment and
// portability risks on non-64-bit platforms (e.g., older ARM with
// strict alignment requirements). binary.BigEndian.Uint64 is safe on
// all architectures, and the Go compiler optimizes it to a single
// load instruction on platforms that support unaligned access (amd64,
// arm64), so there is no performance regression on 64-bit platforms.
func isUint64(w Word) bool {
	return binary.BigEndian.Uint64(w[0:8]) == 0 &&
		binary.BigEndian.Uint64(w[8:16]) == 0 &&
		binary.BigEndian.Uint64(w[16:24]) == 0
}

func (i *Interpreter) opAdd(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Fast path: both operands fit in uint64
	if isUint64(a) && isUint64(b) {
		av := a.ToUint64()
		bv := b.ToUint64()
		// FIX: Check for uint64 overflow before using fast path.
		// If the sum overflows uint64, fall through to big.Int slow path
		// to produce the correct 256-bit result.
		sum := av + bv
		if sum >= av {
			return env.stack.Push(NewWordFromUint64(sum))
		}
		// Overflow detected, fall through to big.Int path
	}

	// Slow path: big.Int
	ab := a.ToBigInt()
	bb := b.ToBigInt()
	result := new(big.Int).Add(ab, bb)
	result.And(result, maxUint256)
	return env.stack.PushBigInt(result)
}

func (i *Interpreter) opSub(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Fast path: both operands fit in uint64 and a >= b
	if isUint64(a) && isUint64(b) {
		av := a.ToUint64()
		bv := b.ToUint64()
		if av >= bv {
			return env.stack.Push(NewWordFromUint64(av - bv))
		}
		// a < b: result = 2^64 + (av - bv) which won't fit in uint64, fall through
	}

	// Slow path: big.Int
	ab := a.ToBigInt()
	bb := b.ToBigInt()
	result := new(big.Int).Sub(ab, bb)
	if result.Sign() < 0 {
		result.Add(result, bigMaxUint256Plus1)
	}
	result.And(result, maxUint256)
	return env.stack.PushBigInt(result)
}

func (i *Interpreter) opMul(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Fast path: both operands fit in uint64 and no overflow
	if isUint64(a) && isUint64(b) {
		av := a.ToUint64()
		bv := b.ToUint64()
		// Check for overflow: if both are small enough, result fits in uint64
		if av == 0 || bv == 0 {
			return env.stack.Push(NewWordFromUint64(0))
		}
		if av <= math.MaxUint64/bv {
			return env.stack.Push(NewWordFromUint64(av * bv))
		}
		// Overflow: fall through to big.Int
	}

	// Slow path: big.Int
	ab := a.ToBigInt()
	bb := b.ToBigInt()
	result := new(big.Int).Mul(ab, bb)
	result.And(result, maxUint256)
	return env.stack.PushBigInt(result)
}

func (i *Interpreter) opDiv(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Fast path: both fit in uint64
	if isUint64(a) && isUint64(b) {
		bv := b.ToUint64()
		if bv == 0 {
			return env.stack.Push(NewWordFromUint64(0))
		}
		return env.stack.Push(NewWordFromUint64(a.ToUint64() / bv))
	}

	// Slow path: big.Int
	ab := a.ToBigInt()
	bb := b.ToBigInt()
	if bb.Sign() == 0 {
		return env.stack.Push(NewWordFromUint64(0))
	}
	result := new(big.Int).Div(ab, bb)
	return env.stack.PushBigInt(result)
}

func (i *Interpreter) opMod(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Fast path: both fit in uint64
	if isUint64(a) && isUint64(b) {
		bv := b.ToUint64()
		if bv == 0 {
			return env.stack.Push(NewWordFromUint64(0))
		}
		return env.stack.Push(NewWordFromUint64(a.ToUint64() % bv))
	}

	// Slow path: big.Int
	ab := a.ToBigInt()
	bb := b.ToBigInt()
	if bb.Sign() == 0 {
		return env.stack.Push(NewWordFromUint64(0))
	}
	result := new(big.Int).Mod(ab, bb)
	return env.stack.PushBigInt(result)
}

func (i *Interpreter) opExp(env *Environment) error {
	base, err := env.stack.PopBigInt()
	if err != nil {
		return err
	}
	exp, err := env.stack.PopBigInt()
	if err != nil {
		return err
	}

	// Calculate dynamic gas cost
	expBytes := (exp.BitLen() + 7) / 8
	//  guard against uint64 overflow when computing the dynamic gas
	// (uint64(expBytes) * GasExpByte). expBytes is bounded by the 256-bit Word
	// size in practice, but check explicitly to prevent a silent wraparound if
	// that bound ever changes.
	// R47-QV-04 FIX: Removed dead `expBytes < 0` check (expBytes is always
	// non-negative since exp.BitLen() >= 0). Only the overflow check remains.
	//
	// P3-QVM-GASSAFE FIX (R30, 2026-07-27): Replaced manual overflow check
	// + direct `*` with SafeMulGas for consistency with the audit-fix C-3
	// safe gas arithmetic pattern. SafeMulGas performs the same
	// `a > 0 && b > MaxUint64/a` check internally and returns ErrGasOverflow
	// on wrap.
	dynamicGas, gasErr := SafeMulGas(uint64(expBytes), GasExpByte) // #nosec G115 -- guarded by SafeMulGas internally
	if gasErr != nil {
		return ErrGasOverflow
	}
	if err := env.gas.Consume(dynamicGas); err != nil {
		return err
	}

	result := new(big.Int).Exp(base, exp, bigMaxUint256Plus1)

	return env.stack.PushBigInt(result)
}

// Comparison operations

func (i *Interpreter) opLt(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Fast path: both fit in uint64
	if isUint64(a) && isUint64(b) {
		if a.ToUint64() < b.ToUint64() {
			return env.stack.PushUint64(1)
		}
		return env.stack.PushUint64(0)
	}

	// Slow path: big.Int
	if a.ToBigInt().Cmp(b.ToBigInt()) < 0 {
		return env.stack.PushUint64(1)
	}
	return env.stack.PushUint64(0)
}

func (i *Interpreter) opGt(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Fast path: both fit in uint64
	if isUint64(a) && isUint64(b) {
		if a.ToUint64() > b.ToUint64() {
			return env.stack.PushUint64(1)
		}
		return env.stack.PushUint64(0)
	}

	// Slow path: big.Int
	if a.ToBigInt().Cmp(b.ToBigInt()) > 0 {
		return env.stack.PushUint64(1)
	}
	return env.stack.PushUint64(0)
}

func (i *Interpreter) opEq(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	if a == b {
		return env.stack.PushUint64(1)
	}
	return env.stack.PushUint64(0)
}

func (i *Interpreter) opIsZero(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}

	if a.IsZero() {
		return env.stack.PushUint64(1)
	}
	return env.stack.PushUint64(0)
}

// Bitwise operations

func (i *Interpreter) opAnd(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Direct Word-level AND — no big.Int needed
	var result Word
	for k := 0; k < WordSize; k++ {
		result[k] = a[k] & b[k]
	}
	return env.stack.Push(result)
}

func (i *Interpreter) opOr(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Direct Word-level OR — no big.Int needed
	var result Word
	for k := 0; k < WordSize; k++ {
		result[k] = a[k] | b[k]
	}
	return env.stack.Push(result)
}

func (i *Interpreter) opXor(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Direct Word-level XOR — no big.Int needed
	var result Word
	for k := 0; k < WordSize; k++ {
		result[k] = a[k] ^ b[k]
	}
	return env.stack.Push(result)
}

func (i *Interpreter) opNot(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Direct Word-level NOT — no big.Int needed
	var result Word
	for k := 0; k < WordSize; k++ {
		result[k] = ^a[k]
	}
	return env.stack.Push(result)
}

// Memory operations

func (i *Interpreter) opMLoad(env *Environment) error {
	offset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	// Calculate memory expansion cost with overflow check
	newSize := offset + 32
	if newSize < offset {
		return ErrMemoryOverflow
	}
	expansionCost := MemoryExpansionCost(env.memory.Size(), newSize)
	if err := env.gas.Consume(expansionCost); err != nil {
		return err
	}

	// Use GetPtr for zero-copy read — MLOAD only reads, never modifies memory
	data, err := env.memory.GetPtr(offset, 32)
	if err != nil {
		return err
	}

	return env.stack.Push(NewWord(data))
}

func (i *Interpreter) opMStore(env *Environment) error {
	offset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	value, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Calculate memory expansion cost with overflow check
	newSize := offset + 32
	if newSize < offset {
		return ErrMemoryOverflow
	}
	expansionCost := MemoryExpansionCost(env.memory.Size(), newSize)
	if err := env.gas.Consume(expansionCost); err != nil {
		return err
	}

	return env.memory.Set32(offset, value)
}

func (i *Interpreter) opMStore8(env *Environment) error {
	offset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	value, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// Calculate memory expansion cost with overflow check
	newSize := offset + 1
	if newSize < offset {
		return ErrMemoryOverflow
	}
	expansionCost := MemoryExpansionCost(env.memory.Size(), newSize)
	if err := env.gas.Consume(expansionCost); err != nil {
		return err
	}

	return env.memory.SetByte(offset, value[31])
}

// Storage operations

func (i *Interpreter) opSLoad(env *Environment) error {
	keyWord, err := env.stack.Pop()
	if err != nil {
		return err
	}

	var key Hash
	copy(key[:], keyWord[:])

	// Check access list for cold/warm access
	// FIX: Charge differential (GasColdSLoad - GasWarmSLoad) for cold access.
	// The base gas (GasWarmSLoad = 100) is already consumed in run() via
	// opcodeInfoTable, so we only add the difference here. Previously charging
	// the full GasColdSLoad (2100) on top of base (100) resulted in 2200 total,
	// but EIP-2929 specifies cold SLOAD should be 2100 total.
	_, slotOk := env.stateDB.SlotInAccessList(env.ctx.Address, key)
	if !slotOk {
		extraCost := GasColdSLoad - GasWarmSLoad
		if err := env.gas.Consume(extraCost); err != nil {
			return err
		}
		env.stateDB.AddSlotToAccessList(env.ctx.Address, key)
	}

	value := env.stateDB.GetState(env.ctx.Address, key)
	return env.stack.Push(NewWord(value[:]))
}

// committedStateReader is an optional StateDB capability that returns the
// storage value committed at the start of the transaction (i.e. before any
// in-transaction dirty writes). It is used by opSStore for EIP-3529 gas
// refund calculation. StateDB implementations that cannot supply the
// committed value simply omit this method; opSStore then falls back to a
// conservative no-refund policy (QVM-FIX) to prevent SSTORE_CLEAR
// refund abuse via same-tx 0 -> X -> 0 cycles.
type committedStateReader interface {
	GetCommittedState(addr Address, key Hash) Hash
}

func (i *Interpreter) opSStore(env *Environment) error {
	if env.ctx.ReadOnly {
		return ErrWriteProtection
	}

	keyWord, err := env.stack.Pop()
	if err != nil {
		return err
	}
	valueWord, err := env.stack.Pop()
	if err != nil {
		return err
	}

	var key, value Hash
	copy(key[:], keyWord[:])
	copy(value[:], valueWord[:])

	// audit-fix HIGH-1: Charge cold access cost for first-time SSTORE (EIP-2929).
	// Use StateDB for consistent access list tracking with SLoad.
	// FIX: Charge differential (GasColdSLoad - GasWarmSLoad) for cold access.
	// The base gas (GasWarmSLoad = 100) is already consumed in run() via
	// opcodeInfoTable, so we only add the difference here. Previously charging
	// the full GasColdSLoad (2100) on top of base (100) resulted in 2200 total,
	// but EIP-2929 specifies cold SSTORE access should be 2100 total.
	if _, slotOk := env.stateDB.SlotInAccessList(env.ctx.Address, key); !slotOk {
		extraCost := GasColdSLoad - GasWarmSLoad
		if err := env.gas.Consume(extraCost); err != nil {
			return err
		}
		env.stateDB.AddSlotToAccessList(env.ctx.Address, key)
	}

	// Get current (live) storage value.
	current := env.stateDB.GetState(env.ctx.Address, key)

	// EIP-3529 compliance: the SSTORE gas refund must be computed against the
	// ORIGINAL storage value (committed at the start of the transaction), not
	// just the current value. A slot created (0 -> X) and then cleared (X -> 0)
	// within the same transaction has a net zero effect and must NOT receive an
	// SSTORE_CLEAR refund; otherwise the transaction is subsidized via a bogus
	// refund (gas refund exploit).
	//
	// QVM-FIX: committedStateReader is optional. If the underlying
	// StateDB cannot supply the committed value, we use a conservative
	// no-refund policy (original treated as zero-equivalent sentinel
	// `originalKnown=false`) — refusing the refund rather than falling back to
	// the live `current` value, which would silently re-enable the abuse.
	var original Hash
	originalKnown := false
	if cr, ok := env.stateDB.(committedStateReader); ok {
		original = cr.GetCommittedState(env.ctx.Address, key)
		originalKnown = true
	}

	// Calculate gas cost based on current, new, and original values.
	//
	// QVM-R13-MED-002 (2026-07-21) FIX: Implement full EIP-2200 net gas
	// metering with EIP-3529 refund restrictions. Previously only a three-
	// state check was performed (current == new, current == 0, new == 0),
	// which ignored the "dirty slot" case — where the slot has already
	// been modified earlier in this transaction (current != original).
	// Per EIP-2200, dirty writes cost only SLOAD (100) because the
	// original transition was already charged when the slot was first
	// modified. The previous code charged SSTORE_RESET (2900) for every
	// subsequent SSTORE to the same dirty slot, diverging from EIP-2200
	// and from Geth — a gas accounting bug that over-charged contracts
	// which write to the same slot multiple times in a single tx.
	//
	// Refund matrix under EIP-2200 + EIP-3529:
	//   1. current == new                       → cost SLoad,  refund 0
	//   2. clean slot, 0 -> Y                   → cost Set,   refund 0
	//   3. clean slot, X -> 0 (original != 0)   → cost Reset, refund Clear
	//   4. clean slot, X -> Y                   → cost Reset, refund 0
	//   5. dirty slot, original == 0, X -> 0   → cost SLoad, refund 0  (EIP-3529 removes refund)
	//   6. dirty slot, original == 0, X -> Y   → cost SLoad, refund 0
	//   7. dirty slot, original != 0, X -> 0   → cost SLoad, refund Clear (net effect: clear)
	//   8. dirty slot, original != 0, X -> Y   → cost SLoad, refund 0
	//
	// When originalKnown is false (StateDB does not implement
	// committedStateReader), we cannot detect dirty slots and conservatively
	// fall through to the three-state logic with no refund (QVM-).
	var gasCost uint64
	if current == value {
		// Case 1: No change.
		gasCost = env.gasTable.SLoad
	} else if originalKnown && current != original {
		// Dirty slot: already modified earlier in this transaction.
		gasCost = env.gasTable.SLoad
		// Issue SSTORE_CLEAR refund only when the net effect is a genuine
		// clear (original != 0 and new value == 0). The 0 -> X -> 0 cycle
		// (original == 0) is explicitly excluded by EIP-3529.
		if original != (Hash{}) && value == (Hash{}) {
			env.gas.Refund(env.gasTable.SStoreClear)
		}
	} else if current == (Hash{}) {
		// Case 2: Clean slot, 0 -> non-zero (set).
		gasCost = env.gasTable.SStoreSet
	} else if value == (Hash{}) {
		// Case 3: Clean slot, non-zero -> zero (clear with refund).
		gasCost = env.gasTable.SStoreReset
		// EIP-3529: only refund when genuinely clearing pre-existing storage
		// (original != 0). Clearing a slot created earlier in this same
		// transaction (original == 0) yields no refund.
		// QVM- When committed value is unknown (StateDB does not
		// implement committedStateReader), do NOT issue a refund — the
		// fallback to `current` would refund same-tx 0 -> X -> 0 cycles.
		if originalKnown && original != (Hash{}) {
			env.gas.Refund(env.gasTable.SStoreClear)
		}
	} else {
		// Case 4: Clean slot, non-zero -> non-zero (reset).
		gasCost = env.gasTable.SStoreReset
	}

	if err := env.gas.Consume(gasCost); err != nil {
		return err
	}

	env.stateDB.SetState(env.ctx.Address, key, value)
	return nil
}

// Context operations

func (i *Interpreter) opAddress(env *Environment) error {
	var word Word
	copy(word[12:], env.ctx.Address[:])
	return env.stack.Push(word)
}

func (i *Interpreter) opBalance(env *Environment) error {
	addrWord, err := env.stack.Pop()
	if err != nil {
		return err
	}

	var addr Address
	copy(addr[:], addrWord[12:])

	// Check access list
	if !env.stateDB.AddressInAccessList(addr) {
		// P3-QVM-GASSAFE FIX (R30, 2026-07-27): Use SafeSubGas instead of
		// direct `-` for defense-in-depth. BalanceCold (2600) > Balance
		// (100) so the subtraction is safe today, but SafeSubGas protects
		// against future gas table misconfigurations that could swap the
		// order and cause silent underflow.
		coldSurcharge, subErr := SafeSubGas(env.gasTable.BalanceCold, env.gasTable.Balance)
		if subErr != nil {
			return subErr
		}
		if err := env.gas.Consume(coldSurcharge); err != nil {
			return err
		}
		env.stateDB.AddAddressToAccessList(addr)
	}

	balance := env.stateDB.GetBalance(addr)
	return env.stack.PushBigInt(balance)
}

func (i *Interpreter) opCaller(env *Environment) error {
	var word Word
	copy(word[12:], env.ctx.Caller[:])
	return env.stack.Push(word)
}

func (i *Interpreter) opCallValue(env *Environment) error {
	return env.stack.PushBigInt(env.ctx.Value)
}

func (i *Interpreter) opCallDataLoad(env *Environment) error {
	offset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	data := env.ctx.Input
	var word Word

	if offset < uint64(len(data)) {
		//  Guard against offset+32 overflow. If offset is within 32
		// of math.MaxUint64, the addition would wrap around to a small value
		// and produce an incorrect slice boundary. Clamp end to the data
		// length in that case.
		var end uint64
		if offset > math.MaxUint64-32 {
			end = uint64(len(data))
		} else {
			end = offset + 32
			if end > uint64(len(data)) {
				end = uint64(len(data))
			}
		}
		copy(word[:], data[offset:end])
	}

	return env.stack.Push(word)
}

// Return operations

func (i *Interpreter) opReturn(env *Environment) error {
	offset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	size, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	// Calculate memory expansion cost with overflow check
	if size > 0 {
		newSize := offset + size
		if newSize < offset {
			return ErrMemoryOverflow
		}
		expansionCost := MemoryExpansionCost(env.memory.Size(), newSize)
		if err := env.gas.Consume(expansionCost); err != nil {
			return err
		}
	}

	// Get return data
	if size > 0 {
		data, err := env.memory.Get(offset, size)
		if err != nil {
			return err
		}
		env.returnData = data
	}

	env.stopped = true
	return nil
}

func (i *Interpreter) opRevert(env *Environment) error {
	offset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	size, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	// Calculate memory expansion cost with overflow check
	if size > 0 {
		newSize := offset + size
		if newSize < offset {
			return ErrMemoryOverflow
		}
		expansionCost := MemoryExpansionCost(env.memory.Size(), newSize)
		if err := env.gas.Consume(expansionCost); err != nil {
			return err
		}
	}

	// Get return data
	if size > 0 {
		data, err := env.memory.Get(offset, size)
		if err != nil {
			return err
		}
		env.returnData = data
	}

	env.stopped = true
	env.reverted = true
	env.err = ErrExecutionReverted
	return nil
}

// Constants for big.Int operations
var (
	maxUint256 = func() *big.Int {
		max := new(big.Int)
		max.SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
		return max
	}()

	bigMaxUint256Plus1 = func() *big.Int {
		max := new(big.Int)
		max.SetString("10000000000000000000000000000000000000000000000000000000000000000", 16)
		return max
	}()
)

// Crypto operations

func (i *Interpreter) opSHA3(env *Environment) error {
	offset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	size, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	// Calculate memory expansion cost with overflow check
	newSize := offset + size
	if newSize < offset {
		return ErrMemoryOverflow
	}
	expansionCost := MemoryExpansionCost(env.memory.Size(), newSize)
	if err := env.gas.Consume(expansionCost); err != nil {
		return err
	}

	// audit-fix R2-H2: charge per-word dynamic gas for SHA3
	// FIX: Use SafeMulGas to prevent overflow in words * GasSHA3Word
	// R54-QV-02 FIX: Use SafeAddGas for size+31 to prevent overflow when
	// size is near uint64 max. Without this, (size+31) wraps to a small
	// value, bypassing gas charging for huge SHA3 operations.
	sha3Words, sha3Err := SafeAddGas(size, 31)
	if sha3Err != nil {
		return fmt.Errorf("size overflow in SHA3 gas calculation")
	}
	sha3Words /= 32
	gasCost, err := SafeMulGas(sha3Words, GasSHA3Word)
	if err != nil {
		return err
	}
	if err := env.gas.Consume(gasCost); err != nil {
		return err
	}

	// Get data from memory
	data, err := env.memory.Get(offset, size)
	if err != nil {
		return err
	}

	// Calculate SHA3-256 hash
	hash := keccak256(data) // Note: SHA3 in EVM is actually Keccak-256

	return env.stack.Push(NewWord(hash[:]))
}

// Post-Quantum Crypto operations

// KyberKeyGen generates a Kyber-768 key pair and stores them in memory
// Stack: [] -> [pubKeyOffset, privKeyOffset]
//
// AUDIT (2026) CRIT-03: DISABLED. crypto.GenerateKyberKeyPair() uses
// crypto/rand (via circl's rand.Reader), making the output non-deterministic.
// Each node would get a different key pair → state-root divergence → chain
// halt. A single transaction calling this opcode could stop the entire network.
// To re-enable: derive all randomness from a consensus seed (block/tx entropy)
// instead of crypto/rand.
func (i *Interpreter) opKyberKeyGen(env *Environment) error {
	return ErrNonDeterministicOpcode
}

// KyberEncaps encapsulates a shared key using the given public key
// Stack: [pubKeyOffset] -> [sharedKeyOffset, ciphertextOffset]
//
// AUDIT (2026) CRIT-03: DISABLED. GenerateKyberKeyPair()+Exchange() uses
// crypto/rand for the ephemeral key, making ciphertext/sharedKey non-deterministic.
// Each node would get different values → state-root divergence → chain halt.
func (i *Interpreter) opKyberEncaps(env *Environment) error {
	return ErrNonDeterministicOpcode
}

// KyberDecaps decapsulates a shared key from ciphertext using the given private key
// Stack: [privKeyOffset, ciphertextOffset] -> [sharedKeyOffset]
func (i *Interpreter) opKyberDecaps(env *Environment) error {
	ciphertextOffset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	// Get private key offset from stack
	privOffset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	// AUDIT (2026) R4-QVFIX: Charge memory expansion gas for the
	// READ side (privBytes + ciphertext). The previous code only charged
	// memory expansion gas for the OUTPUT (sharedKey), allowing a caller
	// to force ~32MB memory allocation for the 25000 base gas cost of
	// KYBER_DECAPS. This was the only enabled opcode that read memory
	// without charging MemoryExpansionCost.
	// Compute the highest memory offset that will be accessed.
	readEndPriv := privOffset + uint64(crypto.KyberPrivateKeySize)
	if readEndPriv < privOffset {
		return ErrMemoryOverflow
	}
	readEndCipher := ciphertextOffset + uint64(crypto.KyberCiphertextSize)
	if readEndCipher < ciphertextOffset {
		return ErrMemoryOverflow
	}
	maxReadEnd := readEndPriv
	if readEndCipher > maxReadEnd {
		maxReadEnd = readEndCipher
	}
	readExpansionCost := MemoryExpansionCost(env.memory.Size(), maxReadEnd)
	if err := env.gas.Consume(readExpansionCost); err != nil {
		return err
	}

	// Read private key from memory
	privBytes, err := env.memory.Get(privOffset, crypto.KyberPrivateKeySize)
	if err != nil {
		return err
	}

	// Read ciphertext from memory
	ciphertext, err := env.memory.Get(ciphertextOffset, crypto.KyberCiphertextSize)
	if err != nil {
		return err
	}

	// Convert to KyberPrivateKey
	privKey, err := crypto.KyberPrivateKeyFromBytes(privBytes)
	if err != nil {
		return err
	}

	// Decapsulate to get shared key
	sharedKey, err := privKey.Decapsulate(ciphertext)
	if err != nil {
		return err
	}

	// HIGH-008 FIX: Zero privBytes in-place immediately after key construction.
	// The key object now owns the sensitive data; local copy is no longer needed.
	for i := range privBytes {
		privBytes[i] = 0
	}

	// Calculate memory offset for shared key
	memSize := env.memory.Size()
	sharedKeyOffset := memSize

	// audit-fix HIGH-OVERFLOW: Prevent uint64 overflow in PQC memory offset calculation
	if sharedKeyOffset > math.MaxUint64-uint64(len(sharedKey)) {
		return ErrOutOfGas
	}

	// Calculate memory expansion cost
	newSize := sharedKeyOffset + uint64(len(sharedKey))
	expansionCost := MemoryExpansionCost(env.memory.Size(), newSize)
	if err := env.gas.Consume(expansionCost); err != nil {
		return err
	}

	// Store shared key in memory
	if err := env.memory.Set(sharedKeyOffset, sharedKey); err != nil {
		return err
	}

	// HIGH-008 FIX: Zero shared key from local variable after copying to memory.
	// Also zero the private key from memory (key material is no longer needed).
	for i := range sharedKey {
		sharedKey[i] = 0
	}
	// Zero the private key from memory as it is no longer needed
	if err := env.memory.ZeroRange(privOffset, crypto.KyberPrivateKeySize); err != nil {
		return err
	}

	// Push shared key offset to stack
	return env.stack.PushUint64(sharedKeyOffset)
}

// opKyberZeroKey implements the KYBER_ZERO_KEY opcode (0x8E).
// SECURITY (audit P1-02): Zeroizes PQC key material from memory after use.
// Stack: pop size (top), pop offset (next).
// Gas: 3.
func (i *Interpreter) opKyberZeroKey(env *Environment) error {
	size, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	offset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	if size == 0 {
		return nil
	}

	// QVM-GAS-01 FIX (deep-audit 2026-07-12): charge memory-expansion and
	// per-word gas BEFORE zeroing. Previously only the 3-gas base cost was
	// charged while ZeroRange expands and zeroes up to 32MB, so a JUMP loop of
	// `PUSH size=0x2000000; PUSH 0; KYBER_ZERO_KEY` re-zeroed 32MB for ~20 gas
	// per iteration — CPU/memory exhaustion.
	if offset > math.MaxUint64-size {
		return ErrOutOfGas
	}
	newSize := offset + size
	expansionCost := MemoryExpansionCost(env.memory.Size(), newSize)
	total, addErr := SafeAddGas(expansionCost, CalculateCopyGas(size))
	if addErr != nil {
		return ErrOutOfGas
	}
	if err := env.gas.Consume(total); err != nil {
		return err
	}

	return env.memory.ZeroRange(offset, size)
}
