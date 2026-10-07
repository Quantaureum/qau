// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"

	"github.com/quantaureum/qau/qvm/secp256k1"
	"golang.org/x/crypto/sha3"
)

// opSignExtend implements the SIGNEXTEND opcode (EVM 0x0B).
// Stack: pop k (byte index), pop x (value), push sign-extended result.
// If bit 7 of byte k of x is 1, fill higher bytes with 0xFF; otherwise fill with 0x00.
func (i *Interpreter) opSignExtend(env *Environment) error {
	kWord, err := env.stack.Pop()
	if err != nil {
		return err
	}
	x, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// QVM-SHIFT-01 FIX (deep-audit 2026-07-12): k is a full 256-bit operand.
	// Collapsing it with ToUint64 would let a large k (e.g. 2^64+5) whose low
	// bits are < 31 wrongly sign-extend at an inner byte instead of returning x
	// unchanged. Any k that doesn't fit in uint64 is >= 31, so x is already fully
	// sign-extended.
	if !isUint64(kWord) {
		return env.stack.Push(x)
	}
	k := kWord.ToUint64()

	// If k >= 31, the value is already fully sign-extended (no bytes to fill)
	if k >= 31 {
		return env.stack.Push(x)
	}

	// Byte index from the most significant byte (big-endian in Word)
	// Word[0] is the most significant byte, Word[31] is the least significant.
	// Byte k means the (k+1)-th least significant byte, i.e., Word[31-k].
	byteIdx := 31 - k
	signBit := x[byteIdx] & 0x80

	var result Word
	copy(result[:], x[:])

	if signBit != 0 {
		// Fill bytes above byteIdx with 0xFF
		for j := 0; j < int(byteIdx); j++ {
			result[j] = 0xFF
		}
	} else {
		// Fill bytes above byteIdx with 0x00
		for j := 0; j < int(byteIdx); j++ {
			result[j] = 0x00
		}
	}

	return env.stack.Push(result)
}

// opExtCodeSize implements the EXTCODESIZE opcode (EVM 0x3B).
// Stack: pop address, push code size.
// Gas: 100 warm, 2600 cold (EIP-2929).
func (i *Interpreter) opExtCodeSize(env *Environment) error {
	addrWord, err := env.stack.Pop()
	if err != nil {
		return err
	}

	var addr Address
	copy(addr[:], addrWord[12:])

	// EIP-2929: charge cold access differential if address is not in access list
	if !env.stateDB.AddressInAccessList(addr) {
		// P3-QVM-GASSAFE FIX (R30, 2026-07-27): Use SafeSubGas for the cold
		// access surcharge. GasColdAccountAccess (2600) > GasWarmAccountAccess
		// (100) so this is safe today; SafeSubGas guards against future
		// constant changes that could invert the relationship.
		extraCost, subErr := SafeSubGas(GasColdAccountAccess, GasWarmAccountAccess)
		if subErr != nil {
			return subErr
		}
		if err := env.gas.Consume(extraCost); err != nil {
			return err
		}
		env.stateDB.AddAddressToAccessList(addr)
	}

	size := env.stateDB.GetCodeSize(addr)
	return env.stack.PushUint64(uint64(size))
}

// opExtCodeCopy implements the EXTCODECOPY opcode (EVM 0x3C).
// Stack: pop address, destOffset, offset, size.
// Gas: 3 base + dynamic (memory expansion + copy cost + cold access).
func (i *Interpreter) opExtCodeCopy(env *Environment) error {
	addrWord, err := env.stack.Pop()
	if err != nil {
		return err
	}
	destOffset, err := env.stack.PopUint64()
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

	var addr Address
	copy(addr[:], addrWord[12:])

	// EIP-2929: charge cold access differential if address is not in access list
	if !env.stateDB.AddressInAccessList(addr) {
		// P3-QVM-GASSAFE FIX (R30, 2026-07-27): Use SafeSubGas (see opExtCodeSize).
		extraCost, subErr := SafeSubGas(GasColdAccountAccess, GasWarmAccountAccess)
		if subErr != nil {
			return subErr
		}
		if err := env.gas.Consume(extraCost); err != nil {
			return err
		}
		env.stateDB.AddAddressToAccessList(addr)
	}

	if size == 0 {
		return nil
	}

	// R47-QV-03 NOTE: The offset overflow check is technically redundant
	// because the code copy bounds-checks against len(code) downstream.
	// Kept for defense-in-depth: prevents overflow in destOffset+size and
	// offset+size arithmetic before memory allocation.
	if destOffset > math.MaxUint64-size || offset > math.MaxUint64-size {
		return fmt.Errorf("EXTCODECOPY offset overflow")
	}

	// Memory expansion cost
	expansionCost := MemoryExpansionCost(env.memory.Size(), destOffset+size)
	// Per-word copy gas
	// R47-QV-01 FIX: Guard against size+31 wraparound and copyGas overflow.
	if size > math.MaxUint64-31 {
		return fmt.Errorf("EXTCODECOPY size overflow")
	}
	words := (size + 31) / 32
	if words > math.MaxUint64/GasCopy {
		return fmt.Errorf("EXTCODECOPY copy gas overflow")
	}
	// R48-QV-02 FIX: Use SafeMulGas instead of native multiplication
	// for consistency with opCodeCopy (operations_missing.go).
	copyGas, gerr := SafeMulGas(words, GasCopy)
	if gerr != nil {
		return fmt.Errorf("EXTCODECOPY copy gas overflow")
	}
	// QV-01 FIX (R45): Use SafeAddGas to prevent overflow in gas calculation,
	// consistent with opCodeCopy (operations_missing.go:925).
	totalCopyCost, gerr := SafeAddGas(expansionCost, copyGas)
	if gerr != nil {
		return fmt.Errorf("gas cost overflow")
	}
	if err := env.gas.Consume(totalCopyCost); err != nil {
		return err
	}

	// Get code from stateDB
	code := env.stateDB.GetCode(addr)

	// Copy code to memory, padding with zeros
	data := make([]byte, size)
	codeLen := uint64(len(code))
	if offset < codeLen {
		end := offset + size
		if end > codeLen {
			end = codeLen
		}
		copy(data, code[offset:end])
	}

	return env.memory.Set(destOffset, data)
}

// opExtCodeHash implements the EXTCODEHASH opcode (EVM 0x3F, EIP-1052).
// Stack: pop address, push code hash.
// Gas: 100 warm, 2600 cold (EIP-2929).
// Returns: 0 for non-existent accounts, keccak256("") for empty accounts,
// keccak256(code) for accounts with code.
func (i *Interpreter) opExtCodeHash(env *Environment) error {
	addrWord, err := env.stack.Pop()
	if err != nil {
		return err
	}

	var addr Address
	copy(addr[:], addrWord[12:])

	// EIP-2929: charge cold access differential if address is not in access list
	if !env.stateDB.AddressInAccessList(addr) {
		// P3-QVM-GASSAFE FIX (R30, 2026-07-27): Use SafeSubGas (see opExtCodeSize).
		extraCost, subErr := SafeSubGas(GasColdAccountAccess, GasWarmAccountAccess)
		if subErr != nil {
			return subErr
		}
		if err := env.gas.Consume(extraCost); err != nil {
			return err
		}
		env.stateDB.AddAddressToAccessList(addr)
	}

	// Non-existent account returns 0
	if !env.stateDB.Exist(addr) {
		return env.stack.Push(NewWordFromUint64(0))
	}

	hash := env.stateDB.GetCodeHash(addr)
	return env.stack.Push(NewWord(hash[:]))
}

// opPrevRandao implements the PREVRANDAO opcode (EVM 0x44, EIP-4399).
// Stack: push prevrandao value (32 bytes).
// Gas: 2.
func (i *Interpreter) opPrevRandao(env *Environment) error {
	return env.stack.Push(NewWord(env.ctx.PrevRandao[:]))
}

// opBlobHash implements the BLOBHASH opcode (EVM 0x49, EIP-4844).
// Stack: pop index, push blob hash.
// Gas: 2.
// Returns zero hash if index is out of range.
func (i *Interpreter) opBlobHash(env *Environment) error {
	index, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	if env.ctx.BlobHashes == nil || index >= uint64(len(env.ctx.BlobHashes)) {
		return env.stack.Push(NewWordFromUint64(0))
	}

	return env.stack.Push(NewWord(env.ctx.BlobHashes[index][:]))
}

// opBlobBaseFee implements the BLOBBASEFEE opcode (EVM 0x4A, EIP-7516).
// Stack: push blob base fee.
// Gas: 2.
func (i *Interpreter) opBlobBaseFee(env *Environment) error {
	return env.stack.PushUint64(env.ctx.BlobBaseFee)
}

// opBaseFee implements the BASEFEE opcode (EVM 0x48, EIP-3198).
// Stack: push base fee per gas of the current block.
// Gas: 2.
func (i *Interpreter) opBaseFee(env *Environment) error {
	return env.stack.PushUint64(env.ctx.BaseFee)
}

// opSDiv implements the SDIV opcode (EVM 0x05) — signed integer division.
// Both operands are interpreted as two's complement signed 256-bit integers.
// Stack: pop a, pop b, push a/b (signed). Division by zero returns 0.
func (i *Interpreter) opSDiv(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// If b == 0, result is 0
	if b.IsZero() {
		return env.stack.Push(NewWordFromUint64(0))
	}

	ab := a.ToBigInt()
	bb := b.ToBigInt()

	// Convert from two's complement to signed
	as := toSigned(ab)
	bs := toSigned(bb)

	// Special case: -2^255 / -1 overflows, return -2^255
	// QV-01 FIX: minInt was -2^256 (Neg of 2^256), which is outside the
	// range of toSigned ([-2^255, 2^255-1]), making this branch dead code.
	// The correct minimum for a 256-bit signed integer is -2^255.
	minInt := new(big.Int).Lsh(big.NewInt(1), 255)
	minInt.Neg(minInt)
	if as.Cmp(minInt) == 0 && bs.Cmp(big.NewInt(-1)) == 0 {
		// Result is minInt which in two's complement is 0x8000...0000
		var result Word
		result[0] = 0x80
		return env.stack.Push(result)
	}

	result := new(big.Int).Quo(as, bs)
	return env.stack.PushBigInt(fromSigned(result))
}

// opSMod implements the SMOD opcode (EVM 0x07) — signed modulo.
// Both operands are interpreted as two's complement signed 256-bit integers.
// Stack: pop a, pop b, push a%b (signed). Modulo by zero returns 0.
// The result has the same sign as the dividend (a).
func (i *Interpreter) opSMod(env *Environment) error {
	a, err := env.stack.Pop()
	if err != nil {
		return err
	}
	b, err := env.stack.Pop()
	if err != nil {
		return err
	}

	// If b == 0, result is 0
	if b.IsZero() {
		return env.stack.Push(NewWordFromUint64(0))
	}

	ab := a.ToBigInt()
	bb := b.ToBigInt()

	as := toSigned(ab)
	bs := toSigned(bb)

	result := new(big.Int).Rem(as, bs)
	return env.stack.PushBigInt(fromSigned(result))
}

// opTLoad implements the TLOAD opcode (EIP-1153).
// Stack: pop key, push transient storage value.
// Gas: 100.
func (i *Interpreter) opTLoad(env *Environment) error {
	keyWord, err := env.stack.Pop()
	if err != nil {
		return err
	}

	var key Hash
	copy(key[:], keyWord[:])

	addr := env.ctx.Address

	// Look up in transient storage
	if env.transientStorage == nil {
		return env.stack.Push(NewWordFromUint64(0))
	}

	if slots, ok := env.transientStorage[addr]; ok {
		if val, ok := slots[key]; ok {
			return env.stack.Push(NewWord(val[:]))
		}
	}

	return env.stack.Push(NewWordFromUint64(0))
}

// opTStore implements the TSTORE opcode (EIP-1153).
// Stack: pop key, pop value, store to transient storage.
// Gas: 100.
// Fails if in read-only (static call) mode.
func (i *Interpreter) opTStore(env *Environment) error {
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

	addr := env.ctx.Address

	if env.transientStorage == nil {
		env.transientStorage = make(map[Address]map[Hash]Hash)
	}

	if env.transientStorage[addr] == nil {
		env.transientStorage[addr] = make(map[Hash]Hash)
	}

	env.transientStorage[addr][key] = value
	return nil
}

// opAuth implements the AUTH opcode (EIP-7702).
// Stack input: authority (20-byte address), offset (memory offset of message), length (message length)
// Stack output: authorized address (20-byte, left-padded to 32 bytes) or 0 on failure
//
// AUTH verifies an ECDSA signature over a message that commits to:
//   - chainID, nonce, address of the executing contract
//   - the delegation designations
//
// The message is read from memory at [offset:offset+length] and must contain:
//   - yParity (1 byte): 0 or 1 (recovery ID)
//   - r (32 bytes): signature r value
//   - s (32 bytes): signature s value
//   - commit (remaining bytes): the commitment data
//
// On success, sets env.authorizedAddress = authority and pushes authority.
// On failure, sets env.authorizedAddress = nil and pushes 0.
func (i *Interpreter) opAuth(env *Environment) error {
	authority, err := env.stack.Pop()
	if err != nil {
		return err
	}
	offset, err := env.stack.PopUint64()
	if err != nil {
		return err
	}
	length, err := env.stack.PopUint64()
	if err != nil {
		return err
	}

	// R37-INFO FIX (2026-07-31): AUTH verifies a secp256k1 ECDSA signature —
	// a quantum-vulnerable authorization path on a quantum-safe (Dilithium3)
	// chain. The path is disabled by default (fail-closed) and must be
	// explicitly enabled via EnableECDSAAuth (test/dev only; the
	// Executor-level gate hard-blocks production). When disabled, refuse
	// authorization and push 0 — identical to any other AUTH failure, so
	// contracts degrade gracefully. Checked after the stack pops so the
	// stack semantics match the enabled failure paths.
	if !i.ecdsaAuthEnabled {
		env.authorizedAddress = nil
		return env.stack.Push(Word{})
	}

	// Consume base gas for AUTH.
	// R37-FIX P2-QVM-02 (2026-07-30): Raised from 100 to 3000. AUTH performs a
	// full secp256k1 ECDSA public-key recovery in recoverSignerAddress — the
	// same work as the ECRECOVER precompile, which is priced at 3000 gas
	// (precompiled/contracts.go). At 100 gas an attacker could pack thousands
	// of AUTH ops into one transaction and burn validator CPU at ~1/30 of the
	// fair price, inflating block execution time (DoS).
	if err := env.gas.Consume(3000); err != nil {
		return err
	}

	// R9-QV-001 FIX: Charge memory expansion gas before reading from memory,
	// consistent with opSHA3 and other memory-accessing opcodes. Without this,
	// an attacker could use AUTH to expand memory for free (memory DoS).
	if length > 0 {
		newSize := offset + length
		if newSize < offset {
			return ErrMemoryOverflow
		}
		expansionCost := MemoryExpansionCost(env.memory.Size(), newSize)
		if err := env.gas.Consume(expansionCost); err != nil {
			return err
		}
	}

	// Extract authority address (rightmost 20 bytes of the 32-byte word)
	var authorityAddr Address
	copy(authorityAddr[:], authority[12:32])

	// Validate authority is not zero address
	if authorityAddr == (Address{}) {
		env.authorizedAddress = nil
		return env.stack.Push(Word{})
	}

	// R37-P1-QVM-03 FIX (2026-07-30): AUTH is stateful — a successful
	// authorization consumes the authority's account nonce (below). It
	// must therefore refuse to run in a read-only (STATICCALL) context,
	// otherwise the nonce write would bypass static write protection.
	if env.ctx.ReadOnly {
		env.authorizedAddress = nil
		return env.stack.Push(Word{})
	}

	// Read message from memory
	msgBytes, err := env.memory.Get(offset, length)
	if err != nil || len(msgBytes) < 65 {
		// Need at least yParity (1) + r (32) + s (32) = 65 bytes
		env.authorizedAddress = nil
		return env.stack.Push(Word{})
	}
	// R30-P3 FIX: Zero signature buffer on exit to prevent lingering key material.
	// memory.Get returns a copy, so zeroing is safe and won't affect VM memory.
	defer func() {
		for i := range msgBytes {
			msgBytes[i] = 0
		}
	}()

	yParity := msgBytes[0]
	rBytes := msgBytes[1:33]
	sBytes := msgBytes[33:65]
	commit := msgBytes[65:]

	// R9-QV-005 FIX: Validate commit format per EIP-7702. The commit should
	// contain chain_id (32 bytes) + nonce (32 bytes) + address (20 bytes) = 84
	// bytes minimum. Reject malformed commit data early.
	// R36-P1-QVFIX: Reject empty commit (previously passed through,
	// making the signed message a constant keccak256(0x05) that can be
	// replayed by anyone). Also bind commit to chainID and contract
	// address to prevent cross-chain/cross-contract replay.
	const minCommitSize = 84
	if len(commit) < minCommitSize {
		env.authorizedAddress = nil
		return env.stack.Push(Word{})
	}

	// Parse commit: chain_id (32 bytes, big-endian, right-aligned) +
	// nonce (32 bytes) + address (20 bytes).
	commitChainID := binary.BigEndian.Uint64(commit[24:32])
	var commitAddr Address
	copy(commitAddr[:], commit[64:84])

	// Verify chainID binding to prevent cross-chain replay
	if commitChainID != env.ctx.ChainID {
		env.authorizedAddress = nil
		return env.stack.Push(Word{})
	}

	// Verify contract address binding to prevent cross-contract replay
	if commitAddr != env.ctx.Address {
		env.authorizedAddress = nil
		return env.stack.Push(Word{})
	}

	// R37-P1-QVM-03 FIX (2026-07-30): Bind the commit nonce to the
	// authority's CURRENT account nonce. Without this, the signed message
	// keccak256(0x05‖commit) is constant for a given commit — a single
	// observed AUTH signature (mempool/calldata are public) becomes a
	// permanent bearer token that anyone can replay in any later tx to
	// AUTHCALL-impersonate the authority. Requiring nonce equality and
	// consuming the nonce on success makes every signature single-use.
	commitNonce := new(big.Int).SetBytes(commit[32:64])
	if !commitNonce.IsUint64() {
		env.authorizedAddress = nil
		return env.stack.Push(Word{})
	}
	authorityNonce := env.stateDB.GetNonce(authorityAddr)
	if commitNonce.Uint64() != authorityNonce {
		env.authorizedAddress = nil
		return env.stack.Push(Word{})
	}

	// Construct the signed message: keccak256(MAGIC || commit)
	// EIP-7702 uses 0x05 as the MAGIC prefix
	magic := byte(0x05)
	preimage := make([]byte, 0, 1+len(commit))
	preimage = append(preimage, magic)
	preimage = append(preimage, commit...)

	// Hash the preimage using keccak256
	msgHash := keccak256Hash(preimage)

	// Recover the public key from the signature
	recoveredAddr, err := recoverSignerAddress(msgHash, yParity, rBytes, sBytes)
	if err != nil {
		env.authorizedAddress = nil
		return env.stack.Push(Word{})
	}

	// Verify the recovered address matches the claimed authority
	if recoveredAddr != authorityAddr {
		env.authorizedAddress = nil
		return env.stack.Push(Word{})
	}

	// R37-P1-QVM-03: Consume the nonce so this exact signature can never
	// be replayed. Placed AFTER all checks so failed authorizations do not
	// burn the authority's nonce (griefing). The write is covered by the
	// enclosing call's stateDB snapshot, so a later REVERT rolls it back.
	env.stateDB.SetNonce(authorityAddr, authorityNonce+1)

	// Authorization successful
	env.authorizedAddress = &authorityAddr

	// Push the authorized address (left-padded to 32 bytes)
	var result Word
	copy(result[12:32], authorityAddr[:])
	return env.stack.Push(result)
}

// opAuthCall implements the AUTHCALL opcode (EIP-7702).
// Stack input: same as CALL (gas, addr, value, argsOffset, argsSize, retOffset, retSize)
// Stack output: success (1 or 0)
//
// AUTHCALL is like CALL but uses the authorized address as the caller instead of
// the current contract address. If no AUTH has been successfully executed
// (authorizedAddress is nil), AUTHCALL behaves like a normal CALL, using
// env.ctx.Address as the caller.
//
//	Rewritten to follow the opCall pattern for consistency:
//	 - EVM-compatible stack pop order
//	 - Zero address check (L10-020)
//	 - Reentrancy guard gas (R5-P3-3)
//	 - Precompiled contract detection
//	 - Depth check using >= ()
//	 - EVMCompatible flag in call context
//	 - L5-003 log propagation guard
func (i *Interpreter) opAuthCall(env *Environment) error {
	// Pop arguments from stack (same order as CALL)
	// EVM order (gas on top): gas, addr, value, argsOffset, argsSize, retOffset, retSize
	// QVM order (retSize on top): outSize, outOffset, inSize, inOffset, value, addr, gas
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

	// Determine effective caller: authorized address if set, otherwise current
	// contract (behaves like normal CALL when no AUTH has been executed).
	var effectiveCaller Address
	if env.authorizedAddress != nil {
		effectiveCaller = *env.authorizedAddress
	} else {
		effectiveCaller = env.ctx.Address
	}

	// Check write protection for value transfer
	if env.ctx.ReadOnly && value.Sign() > 0 {
		return ErrWriteProtection
	}

	// Calculate gas cost
	hasValue := value.Sign() > 0
	isNewAccount := !env.stateDB.Exist(addr)
	isCold := !env.stateDB.AddressInAccessList(addr)

	// Calculate memory expansion costs BEFORE calculating call gas,
	// so that callGas is computed from the gas remaining after ALL fixed costs.
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

	// Reentrancy guard gas (consistent with opCall/opStaticCall/opDelegateCall/opCallCode).
	// R33 QVM-01 FIX (2026-07-28): Add IncrementReentryCount + defer
	// DecrementReentryCount, mirroring opCall/opStaticCall/opDelegateCall/opCallCode.
	// Without this, AUTHCALL bypasses the MaxReentriesPerAddress hard cap,
	// allowing unlimited reentrancy to the same address within one transaction.
	reentrancyGuardGas := uint64(0)
	targetHasCode := len(env.stateDB.GetCode(addr)) > 0
	reentryIncremented := false
	if targetHasCode && env.callDepth >= 1 && env.IsAddressActive(addr) {
		if !env.IncrementReentryCount(addr) {
			return env.stack.PushUint64(0)
		}
		reentryIncremented = true
		defer func() {
			if reentryIncremented {
				env.DecrementReentryCount(addr)
			}
		}()
		reentrancyGuardGas = 2300
		if availableAfterFixed < reentrancyGuardGas {
			return env.stack.PushUint64(0)
		}
		availableAfterFixed -= reentrancyGuardGas
	}

	callCost, callGas := CalculateCallGas(
		env.gasTable,
		availableAfterFixed,
		gas,
		hasValue,
		isNewAccount,
		isCold,
	)

	// QV-02 FIX (R45): Verify callCost does not exceed available gas before
	// consuming, consistent with opCall (call.go:239-245 FIX).
	// CalculateCallGas may return math.MaxUint64 on overflow.
	if callCost > availableAfterFixed {
		return env.stack.PushUint64(0)
	}

	if err := env.gas.Consume(callCost); err != nil {
		return err
	}

	// Add to access list
	env.stateDB.AddAddressToAccessList(addr)

	// Consume memory expansion gas ONCE based on the maximum memory size needed.
	if memExpansionCost > 0 {
		if err := env.gas.Consume(memExpansionCost); err != nil {
			return err
		}
	}

	// Consume reentrancy guard gas after memory expansion, before callGas.
	if reentrancyGuardGas > 0 {
		if err := env.gas.Consume(reentrancyGuardGas); err != nil {
			return env.stack.PushUint64(0)
		}
	}

	// Get input data
	var input []byte
	if inSize > 0 {
		input, err = env.memory.Get(inOffset, inSize)
		if err != nil {
			return err
		}
	}

	// Check balance for value transfer (from effectiveCaller)
	// R31-P3 FIX: Save balance to avoid redundant GetBalance call during transfer.
	var callerBalance *big.Int
	if hasValue {
		callerBalance = env.stateDB.GetBalance(effectiveCaller)
		if callerBalance.Cmp(value) < 0 {
			return env.stack.PushUint64(0)
		}
	}

	// Create call context.
	// Key difference from CALL: when authority is set, use authorizedAddress as Caller.
	callCtx := &ExecutionContext{
		Origin:        env.ctx.Origin,
		GasPrice:      env.ctx.GasPrice,
		Caller:        effectiveCaller,
		Address:       addr,
		Value:         value,
		BlockNumber:   env.ctx.BlockNumber,
		Timestamp:     env.ctx.Timestamp,
		Coinbase:      env.ctx.Coinbase,
		GasLimit:      env.ctx.GasLimit,
		ChainID:       env.ctx.ChainID,
		BaseFee:       env.ctx.BaseFee,     // QVM- propagate BASEFEE opcode value
		BlobBaseFee:   env.ctx.BlobBaseFee, // QVM- propagate BLOBBASEFEE opcode value
		PrevRandao:    env.ctx.PrevRandao,  // QVM- propagate PREVRANDAO opcode value
		Code:          env.stateDB.GetCode(addr),
		Input:         input,
		Gas:           callGas,
		Depth:         env.ctx.Depth + 1,
		ReadOnly:      env.ctx.ReadOnly,
		EVMCompatible: isEVMTranslatedCode(env.stateDB.GetCode(addr)), // R7-QV-001 FIX: Detect EVM-translated code dynamically
		ParentEnv:     env,
	}

	// Unified depth tracking.
	env.callDepth++
	defer func() {
		env.callDepth--
	}()

	// FIX: Use >= (not >) for consistency with opCall and executor.go.
	if env.callDepth >= MaxCallDepth {
		return env.stack.PushUint64(0)
	}

	// Save activeAddresses length for proper restore on all exit paths.
	savedActiveLen := len(env.activeAddresses)

	// PushActiveAddress may have partially grown the slice before failing,
	// so we must restore to savedActiveLen to prevent stack corruption.
	if !env.PushActiveAddress(addr) {
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		return env.stack.PushUint64(0)
	}

	// Snapshot BEFORE value transfer so that revert undoes both the transfer
	// and the sub-call's state changes.
	snapshot := env.stateDB.Snapshot()

	// Transfer value (from effectiveCaller to addr)
	// R31-P3 FIX: Reuse callerBalance from the earlier check to avoid redundant read.
	if hasValue {
		env.stateDB.SetBalance(effectiveCaller, new(big.Int).Sub(callerBalance, value))
		calleeBalance := env.stateDB.GetBalance(addr)
		env.stateDB.SetBalance(addr, new(big.Int).Add(calleeBalance, value))
	}

	// Deduct callGas from parent BEFORE the sub-call.
	if err := env.gas.Consume(callGas); err != nil {
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		// Roll back value transfer on OOG.
		env.stateDB.RevertToSnapshot(snapshot)
		return env.stack.PushUint64(0)
	}

	// Check if the target is a precompiled contract.
	// QVM-R10-H2 / R37-P1-QVM-02 FIX (2026-07-30): pass the INHERITED
	// read-only flag instead of a hardcoded false. AUTHCALL inside a
	// STATICCALL chain runs under the static guarantee (ReadOnly
	// propagates via ctx), so stateful precompiles must stay rejected.
	if executed, success, err := i.executePrecompiled(env, addr, input, callGas, outOffset, outSize, env.ctx.ReadOnly); executed {
		if !success {
			env.stateDB.RevertToSnapshot(snapshot)
		}
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		return err
	}

	// Execute call
	if env.tracer != nil {
		env.tracer.CaptureEnter(AUTHCALL, effectiveCaller, addr, input, callGas, value)
	}
	result := i.Execute(callCtx, env.stateDB)
	if env.tracer != nil {
		env.tracer.CaptureExit(result.ReturnData, result.GasUsed, result.Err)
	}

	// Return unused gas from sub-call to parent.
	if result.GasUsed < callGas {
		env.gas.Return(callGas - result.GasUsed)
	}

	// Handle result
	if result.Err != nil && !result.Reverted {
		env.activeAddresses = env.activeAddresses[:savedActiveLen]
		env.stateDB.RevertToSnapshot(snapshot)
		env.returnData = nil
		return env.stack.PushUint64(0)
	}

	if result.Reverted {
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

	// Add logs (L5-003: only from non-reverted sub-calls to prevent log injection).
	if !result.Reverted {
		env.logs = append(env.logs, result.Logs...)
	}

	// Cleanup activeAddresses on normal return path.
	env.activeAddresses = env.activeAddresses[:savedActiveLen]

	// Push success/failure
	if result.Err != nil {
		return env.stack.PushUint64(0)
	}
	return env.stack.PushUint64(1)
}

// keccak256Hash computes the Keccak-256 hash of the input.
func keccak256Hash(data []byte) Hash {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var hash Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

// recoverSignerAddress recovers the Ethereum address from a signature.
// yParity: 0 or 1 (v - 27)
// r, s: signature components (32 bytes each)
// Returns the recovered 20-byte address.
func recoverSignerAddress(msgHash Hash, yParity byte, rBytes, sBytes []byte) (Address, error) {
	// Convert to big.Int
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	// Validate s is in lower half of curve order (EIP-2)
	secp256k1N := new(big.Int).SetBytes([]byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
	})
	halfN := new(big.Int).Rsh(secp256k1N, 1)
	if s.Cmp(halfN) > 0 {
		return Address{}, fmt.Errorf("AUTH: s value too high")
	}
	if r.Cmp(secp256k1N) >= 0 || s.Cmp(secp256k1N) >= 0 {
		return Address{}, fmt.Errorf("AUTH: signature values out of range")
	}
	// L17-003 FIX: Reject r=0 or s=0. Standard ECDSA requires 1 <= r,s <= N-1.
	// s=0 causes u2*R = point at infinity, recovering an incorrect public key
	// (Q = u1*G) instead of failing. r=0 has no valid modular inverse.
	if r.Sign() == 0 || s.Sign() == 0 {
		return Address{}, fmt.Errorf("AUTH: r or s is zero")
	}

	// Convert yParity to recovery ID
	v := uint(yParity)
	if v > 1 {
		return Address{}, fmt.Errorf("AUTH: invalid yParity %d", yParity)
	}

	// Recover public key using secp256k1
	curve := secp256k1Curve()

	// Compute the point R from r and recovery ID
	ry, err := decompressPoint(r, v, curve)
	if err != nil {
		return Address{}, err
	}

	// Compute r^-1 mod N
	rInv := new(big.Int).ModInverse(r, secp256k1N)
	if rInv == nil {
		return Address{}, fmt.Errorf("AUTH: failed to compute r^-1")
	}

	// u1 = -hash * r^-1 mod N
	z := new(big.Int).SetBytes(msgHash[:])
	u1 := new(big.Int).Neg(z)
	u1.Mul(u1, rInv)
	u1.Mod(u1, secp256k1N)

	// u2 = s * r^-1 mod N
	u2 := new(big.Int).Mul(s, rInv)
	u2.Mod(u2, secp256k1N)

	// Q = u1*G + u2*R
	u1Gx, u1Gy := curve.ScalarBaseMult(u1.Bytes())
	u2Rx, u2Ry := curve.ScalarMult(r, ry, u2.Bytes())

	// Check for nil results from curve operations (can happen with Go's internal validation)
	if u1Gx == nil || u1Gy == nil || u2Rx == nil || u2Ry == nil {
		return Address{}, fmt.Errorf("AUTH: curve operation failed")
	}

	qx, qy := curve.Add(u1Gx, u1Gy, u2Rx, u2Ry)

	if qx == nil || qy == nil || !curve.IsOnCurve(qx, qy) {
		return Address{}, fmt.Errorf("AUTH: recovered point not on curve")
	}

	// Convert to uncompressed public key (65 bytes: 0x04 || x || y)
	pubKey := make([]byte, 65)
	pubKey[0] = 4
	qx.FillBytes(pubKey[1:33])
	qy.FillBytes(pubKey[33:65])

	// Derive address: keccak256(pubKey[1:])[12:]
	addrHash := keccak256Hash(pubKey[1:])
	var addr Address
	copy(addr[:], addrHash[12:])

	return addr, nil
}

// secp256k1Curve returns the secp256k1 elliptic curve.
// Uses the same curve parameters as the ecrecover precompile.
//
// R37-FIX (2026-07-30): Go 1.26 removed the generic CurveParams point
// operations (they now panic unconditionally), breaking ECDSA recovery
// for the AUTH opcode. Delegate to the self-contained Jacobian-coordinate
// implementation in qvm/secp256k1, shared with the ecrecover precompile.
func secp256k1Curve() elliptic.Curve {
	return secp256k1.Shared()
}

// decompressPoint recovers the y coordinate from x and a parity bit.
func decompressPoint(x *big.Int, parity uint, curve elliptic.Curve) (*big.Int, error) {
	params := curve.Params()
	x3 := new(big.Int).Exp(x, big.NewInt(3), params.P)
	y2 := new(big.Int).Add(x3, params.B)
	y2.Mod(y2, params.P)

	exp := new(big.Int).Add(params.P, big.NewInt(1))
	exp.Div(exp, big.NewInt(4))
	y := new(big.Int).Exp(y2, exp, params.P)

	if new(big.Int).Exp(y, big.NewInt(2), params.P).Cmp(y2) != 0 {
		return nil, fmt.Errorf("AUTH: point not on curve")
	}

	if y.Bit(0) != parity {
		y.Sub(params.P, y)
	}

	return y, nil
}
