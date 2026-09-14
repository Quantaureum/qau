// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"fmt"
	"math"
	"math/big"

	"github.com/quantaureum/qau/qvm/jit"
)

func wordToJIT(w Word) jit.Word   { return jit.Word(w) }
func wordFromJIT(w jit.Word) Word { return Word(w) }

func hashToJIT(h Hash) jit.Hash   { return jit.Hash(h) }
func hashFromJIT(h jit.Hash) Hash { return Hash(h) }

func addrToJIT(a Address) jit.Address   { return jit.Address(a) }
func addrFromJIT(a jit.Address) Address { return Address(a) }

type jitStackAdapter struct {
	s *Stack
}

func (a *jitStackAdapter) Push(w jit.Word) error {
	return a.s.Push(wordFromJIT(w))
}

func (a *jitStackAdapter) Pop() (jit.Word, error) {
	w, err := a.s.Pop()
	return wordToJIT(w), err
}

func (a *jitStackAdapter) PopUint64() (uint64, error) {
	return a.s.PopUint64()
}

func (a *jitStackAdapter) PopBigInt() (*big.Int, error) {
	return a.s.PopBigInt()
}

func (a *jitStackAdapter) PushUint64(v uint64) error {
	return a.s.PushUint64(v)
}

func (a *jitStackAdapter) PushBigInt(v *big.Int) error {
	return a.s.PushBigInt(v)
}

func (a *jitStackAdapter) Dup(n int) error {
	return a.s.Dup(n)
}

func (a *jitStackAdapter) Swap(n int) error {
	return a.s.Swap(n)
}

func (a *jitStackAdapter) Len() int {
	return a.s.Len()
}

type jitMemoryAdapter struct {
	m *Memory
}

func (a *jitMemoryAdapter) Load(offset, size uint64) []byte {
	data, err := a.m.Get(offset, size)
	if err != nil {
		return nil
	}
	return data
}

func (a *jitMemoryAdapter) Store(offset uint64, data []byte) error {
	return a.m.Set(offset, data)
}

func (a *jitMemoryAdapter) Len() uint64 {
	return a.m.Size()
}

type jitGasAdapter struct {
	g *GasMeter
}

func (a *jitGasAdapter) Available() uint64 {
	return a.g.Remaining()
}

func (a *jitGasAdapter) Consume(amount uint64) error {
	return a.g.Consume(amount)
}

func (a *jitGasAdapter) FinalUsed() uint64 {
	return a.g.FinalUsed()
}

func (a *jitGasAdapter) RefundAmount() uint64 {
	return a.g.RefundAmount()
}

// FIX: Return refunds unused gas (e.g. after a sub-call)
func (a *jitGasAdapter) Return(amount uint64) {
	a.g.Return(amount)
}

// FIX: Refund adds gas refunds (e.g. storage-clearing SSTORE)
func (a *jitGasAdapter) Refund(amount uint64) {
	a.g.Refund(amount)
}

type jitContextAdapter struct {
	ctx *ExecutionContext
}

func (a *jitContextAdapter) Origin() jit.Address   { return addrToJIT(a.ctx.Origin) }
func (a *jitContextAdapter) GasPrice() *big.Int    { return a.ctx.GasPrice }
func (a *jitContextAdapter) Caller() jit.Address   { return addrToJIT(a.ctx.Caller) }
func (a *jitContextAdapter) Address() jit.Address  { return addrToJIT(a.ctx.Address) }
func (a *jitContextAdapter) Value() *big.Int       { return a.ctx.Value }
func (a *jitContextAdapter) BlockNumber() uint64   { return a.ctx.BlockNumber }
func (a *jitContextAdapter) Timestamp() int64      { return a.ctx.Timestamp }
func (a *jitContextAdapter) Coinbase() jit.Address { return addrToJIT(a.ctx.Coinbase) }
func (a *jitContextAdapter) GasLimit() uint64      { return a.ctx.GasLimit }
func (a *jitContextAdapter) ChainID() uint64       { return a.ctx.ChainID }
func (a *jitContextAdapter) Code() []byte          { return a.ctx.Code }
func (a *jitContextAdapter) Input() []byte         { return a.ctx.Input }
func (a *jitContextAdapter) Depth() int            { return a.ctx.Depth }

// FIX: new context methods to support PREVRANDAO/BLOBHASH/BASEFEE/BLOBBASEFEE
func (a *jitContextAdapter) PrevRandao() jit.Hash { return hashToJIT(a.ctx.PrevRandao) }
func (a *jitContextAdapter) BlobHashes() []jit.Hash {
	hashes := make([]jit.Hash, len(a.ctx.BlobHashes))
	for i, h := range a.ctx.BlobHashes {
		hashes[i] = hashToJIT(h)
	}
	return hashes
}
func (a *jitContextAdapter) BaseFee() uint64     { return a.ctx.BaseFee }
func (a *jitContextAdapter) BlobBaseFee() uint64 { return a.ctx.BlobBaseFee }

type jitStateAdapter struct {
	db StateDB
}

func (a *jitStateAdapter) GetBalance(addr jit.Address) *big.Int {
	return a.db.GetBalance(addrFromJIT(addr))
}

func (a *jitStateAdapter) SetBalance(addr jit.Address, balance *big.Int) {
	a.db.SetBalance(addrFromJIT(addr), balance)
}

func (a *jitStateAdapter) GetNonce(addr jit.Address) uint64 {
	return a.db.GetNonce(addrFromJIT(addr))
}

func (a *jitStateAdapter) SetNonce(addr jit.Address, nonce uint64) {
	a.db.SetNonce(addrFromJIT(addr), nonce)
}

func (a *jitStateAdapter) GetCode(addr jit.Address) []byte {
	return a.db.GetCode(addrFromJIT(addr))
}

func (a *jitStateAdapter) SetCode(addr jit.Address, code []byte) {
	a.db.SetCode(addrFromJIT(addr), code)
}

func (a *jitStateAdapter) GetCodeHash(addr jit.Address) jit.Hash {
	return hashToJIT(a.db.GetCodeHash(addrFromJIT(addr)))
}

func (a *jitStateAdapter) GetCodeSize(addr jit.Address) int {
	return a.db.GetCodeSize(addrFromJIT(addr))
}

func (a *jitStateAdapter) GetState(addr jit.Address, key jit.Hash) jit.Hash {
	return hashToJIT(a.db.GetState(addrFromJIT(addr), hashFromJIT(key)))
}

func (a *jitStateAdapter) SetState(addr jit.Address, key, value jit.Hash) {
	a.db.SetState(addrFromJIT(addr), hashFromJIT(key), hashFromJIT(value))
}

func (a *jitStateAdapter) Exist(addr jit.Address) bool {
	return a.db.Exist(addrFromJIT(addr))
}

func (a *jitStateAdapter) Empty(addr jit.Address) bool {
	return a.db.Empty(addrFromJIT(addr))
}

func (a *jitStateAdapter) Snapshot() int {
	return a.db.Snapshot()
}

func (a *jitStateAdapter) RevertToSnapshot(id int) {
	a.db.RevertToSnapshot(id)
}

func (a *jitStateAdapter) SelfDestruct(addr jit.Address) {
	a.db.SelfDestruct(addrFromJIT(addr))
}

func (a *jitStateAdapter) HasSelfDestructed(addr jit.Address) bool {
	return a.db.HasSelfDestructed(addrFromJIT(addr))
}

func (a *jitStateAdapter) AddAddressToAccessList(addr jit.Address) {
	a.db.AddAddressToAccessList(addrFromJIT(addr))
}

func (a *jitStateAdapter) AddSlotToAccessList(addr jit.Address, slot jit.Hash) {
	a.db.AddSlotToAccessList(addrFromJIT(addr), hashFromJIT(slot))
}

func (a *jitStateAdapter) AddressInAccessList(addr jit.Address) bool {
	return a.db.AddressInAccessList(addrFromJIT(addr))
}

func (a *jitStateAdapter) SlotInAccessList(addr jit.Address, slot jit.Hash) (bool, bool) {
	return a.db.SlotInAccessList(addrFromJIT(addr), hashFromJIT(slot))
}

// GetCommittedState returns the storage value committed at the start of the
// transaction (EIP-3529). If the wrapped StateDB supports committed reads it
// delegates; otherwise it falls back to the current live value (GetState).
// R7 P0-4 FIX (QVM-, 2026-07-17): Required for JIT SSTORE refund to
// match the interpreter path — without this, the JIT makeSStoreOp cannot
// detect slots created earlier in the same transaction and would issue a
// bogus GasSStoreClear refund, causing a consensus-splitting gasUsed diff.
func (a *jitStateAdapter) GetCommittedState(addr jit.Address, key jit.Hash) jit.Hash {
	qAddr := addrFromJIT(addr)
	qKey := hashFromJIT(key)
	if cr, ok := a.db.(committedStateReader); ok {
		return hashToJIT(cr.GetCommittedState(qAddr, qKey))
	}
	return hashToJIT(a.db.GetState(qAddr, qKey))
}

type jitEnvAdapter struct {
	env            *Environment
	interpreter    *Interpreter
	stackAdapter   *jitStackAdapter
	memAdapter     *jitMemoryAdapter
	gasAdapter     *jitGasAdapter
	ctxAdapter     *jitContextAdapter
	stateAdapter   *jitStateAdapter
	lastReturnData []byte
}

func newJITEnvAdapter(env *Environment, interpreter *Interpreter) *jitEnvAdapter {
	return &jitEnvAdapter{
		env:          env,
		interpreter:  interpreter,
		stackAdapter: &jitStackAdapter{s: env.stack},
		memAdapter:   &jitMemoryAdapter{m: env.memory},
		gasAdapter:   &jitGasAdapter{g: env.gas},
		ctxAdapter:   &jitContextAdapter{ctx: env.ctx},
		stateAdapter: &jitStateAdapter{db: env.stateDB},
	}
}

func (a *jitEnvAdapter) Stack() jit.VMStack   { return a.stackAdapter }
func (a *jitEnvAdapter) Memory() jit.VMMemory { return a.memAdapter }
func (a *jitEnvAdapter) Gas() jit.VMGas       { return a.gasAdapter }
func (a *jitEnvAdapter) Ctx() jit.VMContext   { return a.ctxAdapter }
func (a *jitEnvAdapter) StateDB() jit.VMState { return a.stateAdapter }

func (a *jitEnvAdapter) Stopped() bool     { return a.env.stopped }
func (a *jitEnvAdapter) SetStopped(v bool) { a.env.stopped = v }

func (a *jitEnvAdapter) GetBlockHash(blockNum uint64) jit.Hash {
	return hashToJIT(a.env.getBlockHash(blockNum))
}

func (a *jitEnvAdapter) AddLog(log *jit.Log) {
	if log == nil {
		return
	}
	topics := make([]Hash, len(log.Topics))
	for i, t := range log.Topics {
		topics[i] = hashFromJIT(t)
	}
	a.env.logs = append(a.env.logs, &Log{
		Address: addrFromJIT(log.Address),
		Topics:  topics,
		Data:    log.Data,
	})
}

func (a *jitEnvAdapter) SetReturnData(data []byte)  { a.env.returnData = data }
func (a *jitEnvAdapter) ReturnData() []byte         { return a.env.returnData }
func (a *jitEnvAdapter) SetReverted(v bool)         { a.env.reverted = v }
func (a *jitEnvAdapter) SetErr(err error)           { a.env.err = err }
func (a *jitEnvAdapter) Err() error                 { return a.env.err }
func (a *jitEnvAdapter) PC() uint64                 { return a.env.pc }
func (a *jitEnvAdapter) SetPC(pc uint64)            { a.env.pc = pc }
func (a *jitEnvAdapter) JumpDests() map[uint64]bool { return a.env.jumpDests }

// FIX: expose the ReadOnly flag so JIT write ops can check it
func (a *jitEnvAdapter) ReadOnly() bool { return a.env.ctx.ReadOnly }

// FIX: Expose reentrancy state to the JIT compiler so it can charge
// the 2300 reentrancy guard gas BEFORE the 63/64 rule.
func (a *jitEnvAdapter) IsAddressActive(addr jit.Address) bool {
	return a.env.IsAddressActive(addrFromJIT(addr))
}

func (a *jitEnvAdapter) CallDepth() int {
	return int(a.env.callDepth)
}

// FIX: transient storage (EIP-1153) for TLOAD/TSTORE
// Transient storage lives in the Environment, is not persisted, and clears at end of tx.
func (a *jitEnvAdapter) GetTransientState(addr jit.Address, key jit.Hash) jit.Hash {
	qAddr := addrFromJIT(addr)
	qKey := hashFromJIT(key)
	if a.env.transientStorage == nil {
		return jit.Hash{}
	}
	if slots, ok := a.env.transientStorage[qAddr]; ok {
		if val, ok := slots[qKey]; ok {
			return hashToJIT(val)
		}
	}
	return jit.Hash{}
}

func (a *jitEnvAdapter) SetTransientState(addr jit.Address, key, value jit.Hash) {
	qAddr := addrFromJIT(addr)
	qKey := hashFromJIT(key)
	qVal := hashFromJIT(value)
	if a.env.transientStorage == nil {
		a.env.transientStorage = make(map[Address]map[Hash]Hash)
	}
	if a.env.transientStorage[qAddr] == nil {
		a.env.transientStorage[qAddr] = make(map[Hash]Hash)
	}
	a.env.transientStorage[qAddr][qKey] = qVal
}

// --- Call operations delegated to the interpreter ---

func (a *jitEnvAdapter) Call(caller jit.Address, addr jit.Address, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error) {
	qCaller := addrFromJIT(caller)
	qAddr := addrFromJIT(addr)

	// V21-006 FIX: Check call depth before proceeding (matches opCall in call.go)
	if a.env.callDepth >= MaxCallDepth {
		return nil, gas, fmt.Errorf("max call depth exceeded")
	}

	// FIX: Use IsAddressActive() to traverse full parent env chain,
	// matching the interpreter path's reentrancy detection.
	// FIX: Add callDepth >= 1 condition. Without this, the first call
	// from a contract (depth 1) would see the callee in activeAddresses (added
	// by PushActiveAddress at depth 0) and incorrectly charge 2300 gas penalty.
	// The interpreter path checks this condition; JIT must match.
	// FIX: The 2300 reentrancy guard gas is now charged in the JIT
	// compiler's MicroOp (compiler.go) BEFORE the 63/64 rule, matching the
	// interpreter path. Previously it was charged here AFTER the 63/64 split.
	// The gas charge is removed from here to avoid double-charging.

	// V21-005 FIX: Transfer value before execution (matches opCall in call.go)
	// FIX: Verified that a.env.ctx.Address is the CORRECT source for
	// value transfer in CALL semantics. For CALL, value is transferred FROM
	// the current contract (the caller) TO the callee. a.env.ctx.Address is
	// the current contract's address, which IS the caller in a CALL context.
	// This is NOT the original tx sender (Origin) — it's the contract that
	// executed the CALL opcode. Using Origin here would be incorrect.
	snapshot := a.env.stateDB.Snapshot()
	if value != nil && value.Sign() > 0 {
		callerBalance := a.env.stateDB.GetBalance(a.env.ctx.Address)
		if callerBalance.Cmp(value) < 0 {
			return nil, gas, fmt.Errorf("insufficient balance for value transfer")
		}
		a.env.stateDB.SetBalance(a.env.ctx.Address, new(big.Int).Sub(callerBalance, value))
		calleeBalance := a.env.stateDB.GetBalance(qAddr)
		a.env.stateDB.SetBalance(qAddr, new(big.Int).Add(calleeBalance, value))
	}

	callCtx := &ExecutionContext{
		Origin:      a.env.ctx.Origin,
		GasPrice:    a.env.ctx.GasPrice,
		Caller:      qCaller,
		Address:     qAddr,
		Value:       value,
		BlockNumber: a.env.ctx.BlockNumber,
		Timestamp:   a.env.ctx.Timestamp,
		Coinbase:    a.env.ctx.Coinbase,
		GasLimit:    a.env.ctx.GasLimit,
		ChainID:     a.env.ctx.ChainID,
		BaseFee:     a.env.ctx.BaseFee,     // QVM- propagate BASEFEE opcode value
		BlobBaseFee: a.env.ctx.BlobBaseFee, // QVM- propagate BLOBBASEFEE opcode value
		PrevRandao:  a.env.ctx.PrevRandao,  // QVM- propagate PREVRANDAO opcode value
		Code:        a.env.stateDB.GetCode(qAddr),
		Input:       input,
		Gas:         gas,
		Depth:       a.env.ctx.Depth + 1,
		ParentEnv:   a.env,
		// AUDIT H-9: propagate EVMCompatible flag so EVM-translated callees
		// keep EVM stack semantics in JIT sub-calls, mirroring the
		// interpreter's opCall behavior (operations_missing.go).
		EVMCompatible: isEVMTranslatedCode(a.env.stateDB.GetCode(qAddr)),
	}

	// V21-006 FIX: Increment call depth and track active address
	a.env.callDepth++
	savedActiveLen := len(a.env.activeAddresses)
	// R32-P3-6 FIX: Use PushActiveAddress to enforce MaxActiveCallDepth (1024).
	// Direct append bypassed the depth limit, allowing unbounded active address growth.
	if !a.env.PushActiveAddress(qAddr) {
		a.env.activeAddresses = a.env.activeAddresses[:savedActiveLen]
		a.env.callDepth--
		// QV-02 FIX: Revert the value-transfer snapshot so any funds moved
		// before this point are rolled back. Without this, the balance
		// transfer above would persist, losing the caller's funds.
		a.env.stateDB.RevertToSnapshot(snapshot)
		return nil, gas, fmt.Errorf("max active call depth exceeded")
	}
	defer func() {
		a.env.callDepth--
		a.env.activeAddresses = a.env.activeAddresses[:savedActiveLen]
	}()

	result := a.interpreter.Execute(callCtx, a.env.stateDB)
	a.lastReturnData = result.ReturnData

	// V21-005 FIX: Revert value transfer on error
	if result.Err != nil {
		a.env.stateDB.RevertToSnapshot(snapshot)
	}

	var err error
	if result.Err != nil {
		err = result.Err
	}
	return result.ReturnData, result.GasUsed, err
}

func (a *jitEnvAdapter) CallCode(caller jit.Address, addr jit.Address, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error) {
	qCaller := addrFromJIT(caller)
	qAddr := addrFromJIT(addr)

	// FIX: Add call depth check (was completely missing)
	if a.env.callDepth >= MaxCallDepth {
		return nil, gas, fmt.Errorf("max call depth exceeded")
	}

	// FIX: Reentrancy check using full parent chain traversal
	// FIX: Add callDepth >= 1 condition (see Call method for explanation).
	// FIX: Reentrancy guard gas now charged in JIT compiler (see Call).

	// FIX: Value transfer and state snapshot/revert (was missing)
	snapshot := a.env.stateDB.Snapshot()
	if value != nil && value.Sign() > 0 {
		callerBalance := a.env.stateDB.GetBalance(a.env.ctx.Address)
		if callerBalance.Cmp(value) < 0 {
			return nil, gas, fmt.Errorf("insufficient balance for value transfer")
		}
		// R35-P3 FIX (2026-07-29): Removed redundant double SetBalance.
		// CALLCODE executes the target's code in the CALLER's storage
		// context, so a self→self (env.ctx.Address → env.ctx.Address)
		// value transfer is genuinely a no-op. The previous code did:
		//   SetBalance(B - v)   // balance = B - v
		//   SetBalance(B + v)   // uses ORIGINAL B, so balance = B + v
		// which was a minting bug (net +v out of thin air), matching
		// the interpreter path's pre-R32-P0-1 bug. The Value field in
		// callCtx (set below) is what CALLVALUE reads — it does NOT
		// depend on an actual balance mutation. Aligned with the
		// interpreter path's R32-P0-1 fix (operations_missing.go:637-641),
		// which performs NO balance mutation for CALLCODE hasValue.
		// Intentionally empty: self→self transfer is a no-op.
	}

	callCtx := &ExecutionContext{
		Origin:      a.env.ctx.Origin,
		GasPrice:    a.env.ctx.GasPrice,
		Caller:      qCaller,
		Address:     a.env.ctx.Address, // Storage context remains the same
		Value:       value,
		BlockNumber: a.env.ctx.BlockNumber,
		Timestamp:   a.env.ctx.Timestamp,
		Coinbase:    a.env.ctx.Coinbase,
		GasLimit:    a.env.ctx.GasLimit,
		ChainID:     a.env.ctx.ChainID,
		BaseFee:     a.env.ctx.BaseFee,            // QVM- propagate BASEFEE opcode value
		BlobBaseFee: a.env.ctx.BlobBaseFee,        // QVM- propagate BLOBBASEFEE opcode value
		PrevRandao:  a.env.ctx.PrevRandao,         // QVM- propagate PREVRANDAO opcode value
		Code:        a.env.stateDB.GetCode(qAddr), // Use target's code
		Input:       input,
		Gas:         gas,
		Depth:       a.env.ctx.Depth + 1,
		ParentEnv:   a.env,
		// AUDIT H-9: propagate EVMCompatible (see Call).
		EVMCompatible: isEVMTranslatedCode(a.env.stateDB.GetCode(qAddr)),
	}

	// FIX: Track active address and call depth
	a.env.callDepth++
	savedActiveLen := len(a.env.activeAddresses)
	// R32-P3-6 FIX: Use PushActiveAddress to enforce MaxActiveCallDepth.
	if !a.env.PushActiveAddress(qAddr) {
		a.env.activeAddresses = a.env.activeAddresses[:savedActiveLen]
		a.env.callDepth--
		return nil, gas, fmt.Errorf("max active call depth exceeded")
	}
	defer func() {
		a.env.callDepth--
		a.env.activeAddresses = a.env.activeAddresses[:savedActiveLen]
	}()

	result := a.interpreter.Execute(callCtx, a.env.stateDB)
	a.lastReturnData = result.ReturnData

	// FIX: Revert value transfer on error
	if result.Err != nil {
		a.env.stateDB.RevertToSnapshot(snapshot)
	}

	var err error
	if result.Err != nil {
		err = result.Err
	}
	return result.ReturnData, result.GasUsed, err
}

func (a *jitEnvAdapter) DelegateCall(caller jit.Address, addr jit.Address, input []byte, gas uint64) ([]byte, uint64, error) {
	qCaller := addrFromJIT(caller)
	qAddr := addrFromJIT(addr)

	// FIX: Add call depth check (was completely missing)
	if a.env.callDepth >= MaxCallDepth {
		return nil, gas, fmt.Errorf("max call depth exceeded")
	}

	// FIX: Reentrancy check for DELEGATECALL.
	// FIX: Add callDepth >= 1 condition (see Call method for explanation).
	// FIX: DELEGATECALL runs in the caller's storage context, so reentrancy
	// is detected via ctx.Address (the current contract), NOT the target address.
	// The interpreter path (opDelegateCall) also uses ctx.Address for this check.
	// Using qAddr (target) was incorrect — it would miss reentrant calls to the
	// current contract and falsely flag legitimate calls to an already-active target.
	// FIX: Reentrancy guard gas now charged in JIT compiler (see Call).

	callCtx := &ExecutionContext{
		Origin:      a.env.ctx.Origin,
		GasPrice:    a.env.ctx.GasPrice,
		Caller:      qCaller,           // Keep original caller
		Address:     a.env.ctx.Address, // Keep current address (storage context)
		Value:       a.env.ctx.Value,   // Keep original value
		BlockNumber: a.env.ctx.BlockNumber,
		Timestamp:   a.env.ctx.Timestamp,
		Coinbase:    a.env.ctx.Coinbase,
		GasLimit:    a.env.ctx.GasLimit,
		ChainID:     a.env.ctx.ChainID,
		BaseFee:     a.env.ctx.BaseFee,            // QVM- propagate BASEFEE opcode value
		BlobBaseFee: a.env.ctx.BlobBaseFee,        // QVM- propagate BLOBBASEFEE opcode value
		PrevRandao:  a.env.ctx.PrevRandao,         // QVM- propagate PREVRANDAO opcode value
		Code:        a.env.stateDB.GetCode(qAddr), // Use target's code
		Input:       input,
		Gas:         gas,
		Depth:       a.env.ctx.Depth + 1,
		ParentEnv:   a.env,
		// AUDIT H-9: propagate EVMCompatible (see Call).
		EVMCompatible: isEVMTranslatedCode(a.env.stateDB.GetCode(qAddr)),
	}

	// FIX: Track active address and call depth
	a.env.callDepth++
	savedActiveLen := len(a.env.activeAddresses)
	// R32-P3-6 FIX: Use PushActiveAddress to enforce MaxActiveCallDepth.
	// FIX: For DELEGATECALL, push the CURRENT contract's address
	// (a.env.ctx.Address), not the target's (qAddr). DELEGATECALL preserves
	// the caller's storage context, so reentrancy detection must track the
	// address whose storage is actually being modified. Pushing qAddr would
	// miss reentrancy through DELEGATECALL back to the current contract.
	if !a.env.PushActiveAddress(a.env.ctx.Address) {
		a.env.activeAddresses = a.env.activeAddresses[:savedActiveLen]
		a.env.callDepth--
		return nil, gas, fmt.Errorf("max active call depth exceeded")
	}
	defer func() {
		a.env.callDepth--
		a.env.activeAddresses = a.env.activeAddresses[:savedActiveLen]
	}()

	// QVM-FIX: Take snapshot before execution so sub-call failures can
	// be rolled back. DELEGATECALL executes the target's code in the caller's
	// storage context, so any state modifications made by the sub-call before
	// it REVERTs must be undone. Without this, a malicious contract could
	// pollute the caller's storage via DELEGATECALL to a contract that REVERTs
	// partway through, bypassing reentrancy locks or authorization checks.
	snapshot := a.env.stateDB.Snapshot()

	result := a.interpreter.Execute(callCtx, a.env.stateDB)
	a.lastReturnData = result.ReturnData

	// QVM-FIX: Roll back state on error, matching Call's behavior.
	if result.Err != nil {
		a.env.stateDB.RevertToSnapshot(snapshot)
	}

	var err error
	if result.Err != nil {
		err = result.Err
	}
	return result.ReturnData, result.GasUsed, err
}

func (a *jitEnvAdapter) StaticCall(caller jit.Address, addr jit.Address, input []byte, gas uint64) ([]byte, uint64, error) {
	qCaller := addrFromJIT(caller)
	qAddr := addrFromJIT(addr)

	// FIX: Add call depth check (was missing)
	if a.env.callDepth >= MaxCallDepth {
		return nil, gas, fmt.Errorf("max call depth exceeded")
	}

	// FIX: Reentrancy check using full parent chain traversal
	// FIX: Add callDepth >= 1 condition (see Call method for explanation).
	// FIX: Reentrancy guard gas now charged in JIT compiler (see Call).

	callCtx := &ExecutionContext{
		Origin:      a.env.ctx.Origin,
		GasPrice:    a.env.ctx.GasPrice,
		Caller:      qCaller,
		Address:     qAddr,
		Value:       big.NewInt(0),
		BlockNumber: a.env.ctx.BlockNumber,
		Timestamp:   a.env.ctx.Timestamp,
		Coinbase:    a.env.ctx.Coinbase,
		GasLimit:    a.env.ctx.GasLimit,
		ChainID:     a.env.ctx.ChainID,
		BaseFee:     a.env.ctx.BaseFee,     // QVM- propagate BASEFEE opcode value
		BlobBaseFee: a.env.ctx.BlobBaseFee, // QVM- propagate BLOBBASEFEE opcode value
		PrevRandao:  a.env.ctx.PrevRandao,  // QVM- propagate PREVRANDAO opcode value
		Code:        a.env.stateDB.GetCode(qAddr),
		Input:       input,
		Gas:         gas,
		Depth:       a.env.ctx.Depth + 1,
		ReadOnly:    true, //  ReadOnly is already set, confirmed correct
		ParentEnv:   a.env,
		// AUDIT H-9: propagate EVMCompatible (see Call).
		EVMCompatible: isEVMTranslatedCode(a.env.stateDB.GetCode(qAddr)),
	}

	// FIX: Track active address and call depth
	a.env.callDepth++
	savedActiveLen := len(a.env.activeAddresses)
	// R32-P3-6 FIX: Use PushActiveAddress to enforce MaxActiveCallDepth.
	if !a.env.PushActiveAddress(qAddr) {
		a.env.activeAddresses = a.env.activeAddresses[:savedActiveLen]
		a.env.callDepth--
		return nil, gas, fmt.Errorf("max active call depth exceeded")
	}
	defer func() {
		a.env.callDepth--
		a.env.activeAddresses = a.env.activeAddresses[:savedActiveLen]
	}()

	// QVM-FIX: Take snapshot before execution so sub-call failures can
	// be rolled back. Although STATICCALL sets ReadOnly=true (which should
	// prevent writes), a JIT compiler bug could theoretically allow a write
	// to slip through the ReadOnly check. The snapshot + revert pattern is
	// a defense-in-depth measure matching Call/DelegateCall behavior.
	snapshot := a.env.stateDB.Snapshot()

	result := a.interpreter.Execute(callCtx, a.env.stateDB)
	a.lastReturnData = result.ReturnData

	// QVM-FIX: Roll back state on error, matching Call's behavior.
	if result.Err != nil {
		a.env.stateDB.RevertToSnapshot(snapshot)
	}

	var err error
	if result.Err != nil {
		err = result.Err
	}
	return result.ReturnData, result.GasUsed, err
}

func (a *jitEnvAdapter) Create(caller jit.Address, input []byte, gas uint64, value *big.Int, salt *jit.Hash) ([]byte, jit.Address, uint64, error) {
	qCaller := addrFromJIT(caller)

	// FIX: Add call depth check (was missing, consistent with Call/CallCode).
	if a.env.callDepth >= MaxCallDepth {
		return nil, jit.Address{}, gas, fmt.Errorf("max call depth exceeded")
	}

	// FIX: Check ReadOnly — CREATE in read-only mode is prohibited.
	if a.env.ctx.ReadOnly {
		return nil, jit.Address{}, gas, ErrWriteProtection
	}

	// FIX: EIP-3860 — enforce maximum initcode size.
	// Without this bound a caller could supply arbitrarily large initcode,
	// forcing the VM to allocate/copy huge memory regions (DoS vector).
	if len(input) > MaxInitCodeSize {
		return nil, jit.Address{}, gas, ErrInitCodeSizeExceeded
	}

	// FIX: EIP-3860 — charge 200 gas per byte of initcode beyond 32 bytes.
	// Prevents underpriced deployment of large contracts.
	if uint64(len(input)) > 32 {
		eip3860Cost, err := SafeMulGas(uint64(len(input)-32), 200)
		if err != nil {
			return nil, jit.Address{}, gas, fmt.Errorf("create gas overflow: EIP-3860 initcode cost")
		}
		if err := a.env.gas.Consume(eip3860Cost); err != nil {
			return nil, jit.Address{}, gas, err
		}
	}

	// FIX: CREATE2 hash cost — 6 gas per 32-byte word of initcode.
	if salt != nil && len(input) > 0 {
		initCodeSize := uint64(len(input))
		if initCodeSize > math.MaxUint64-31 {
			return nil, jit.Address{}, gas, ErrMemoryOverflow
		}
		hashCost, err := SafeMulGas((initCodeSize+31)/32, 6)
		if err != nil {
			return nil, jit.Address{}, gas, fmt.Errorf("create gas overflow: CREATE2 hash cost")
		}
		if err := a.env.gas.Consume(hashCost); err != nil {
			return nil, jit.Address{}, gas, err
		}
	}

	// Calculate contract address BEFORE value transfer so we can credit
	// the new account. FIX: Use current nonce for address calculation
	// (consistent with interpreter opCreateGeneric). The nonce is incremented
	// AFTER address calculation, BEFORE execution.
	var contractAddr Address
	if salt != nil {
		contractAddr = Create2Address(qCaller, hashFromJIT(*salt), input)
	} else {
		nonce := a.env.stateDB.GetNonce(qCaller)
		contractAddr = CreateAddress(qCaller, nonce)
	}

	// FIX: Value transfer with balance check and snapshot/revert.
	// QVM-P1-01 FIX (R31, 2026-07-27): The previous implementation only
	// SUBTRACTED value from the caller (SetBalance(qCaller, ...-value)) but
	// never ADDED it to the new contract account. This one-sided transfer
	// permanently burned the QAU — the caller lost funds and the contract
	// started with a zero balance, breaking every constructor that reads
	// msg.value / address(this).balance. The interpreter path
	// (opCreateGeneric line 1378-1379) correctly does both halves via
	// AddBalance on the contract account; mirror that here.
	snapshot := a.env.stateDB.Snapshot()
	if value != nil && value.Sign() > 0 {
		callerBalance := a.env.stateDB.GetBalance(qCaller)
		if callerBalance.Cmp(value) < 0 {
			return nil, jit.Address{}, gas, fmt.Errorf("insufficient balance for value transfer")
		}
		a.env.stateDB.SetBalance(qCaller, new(big.Int).Sub(callerBalance, value))
		// QVM-P1-01: Credit the new contract account with the transferred
		// value. GetBalance(contractAddr) returns 0 for a fresh account
		// (the collision check below guarantees it doesn't exist yet), so
		// we can use AddBalance semantics. Use SetBalance for symmetry with
		// the caller debit above and to avoid relying on StateDB.AddBalance
		// presence (some StateDB implementations only expose SetBalance).
		contractBalance := a.env.stateDB.GetBalance(contractAddr)
		a.env.stateDB.SetBalance(contractAddr, new(big.Int).Add(contractBalance, value))
	}

	// FIX: Check for address collision — account already exists if it has
	// code, a nonce, or was previously created. Matches interpreter opCreateGeneric.
	//
	// AUDIT-FULL C-4 FIX (2026-08-14): EIP-6780 same-tx re-creation parity
	// with the interpreter path (QVM-R10-M2 in operations_missing.go
	// opCreateGeneric). Under EIP-6780, a contract created in tx T that
	// self-destructs within the same tx frees its address slot for
	// re-creation in that tx. The previous JIT check rejected this
	// unconditionally (`Exist || GetCodeSize > 0 || GetNonce > 0`), while
	// the interpreter relaxed the nonce condition for same-tx-destructed
	// addresses — a consensus divergence: the same CREATE would succeed
	// under the interpreter and fail under the JIT.
	hasSelfDestructedThisTx := a.env.txCreatedContracts != nil &&
		a.env.txCreatedContracts[contractAddr] &&
		a.env.stateDB.HasSelfDestructed(contractAddr)
	if hasSelfDestructedThisTx {
		// EIP-6780: slot is free for re-creation. Only reject if code is
		// somehow still present (defensive, mirrors interpreter).
		if a.env.stateDB.GetCodeSize(contractAddr) > 0 {
			a.env.stateDB.RevertToSnapshot(snapshot)
			return nil, jit.Address{}, gas, ErrContractAddressCollision
		}
		// Mirror the interpreter: mark the address as logically cleared in
		// the tx-scoped selfDestructCleared set so a subsequent
		// SELFDESTRUCT on the re-created contract is not treated as a
		// no-op, and drop the stale "created in this tx" flag.
		root := a.env
		for root.parentEnv != nil {
			root = root.parentEnv
		}
		if root.selfDestructCleared == nil {
			root.selfDestructCleared = make(map[Address]bool)
		}
		root.selfDestructCleared[contractAddr] = true
		delete(a.env.txCreatedContracts, contractAddr)
	} else if a.env.stateDB.Exist(contractAddr) || a.env.stateDB.GetCodeSize(contractAddr) > 0 || a.env.stateDB.GetNonce(contractAddr) > 0 {
		a.env.stateDB.RevertToSnapshot(snapshot)
		return nil, jit.Address{}, gas, ErrContractAddressCollision
	}

	// FIX: Check for nonce overflow before incrementing.
	// math.MaxUint64 nonce would overflow on CREATE, causing panic.
	callerNonce := a.env.stateDB.GetNonce(qCaller)
	if callerNonce == ^uint64(0) {
		a.env.stateDB.RevertToSnapshot(snapshot)
		return nil, jit.Address{}, gas, fmt.Errorf("nonce overflow")
	}

	// FIX: Increment caller nonce after address calculation.
	// Without this, multiple CREATE calls from the same caller produce the
	// same contract address, causing deployment collisions.
	a.env.stateDB.SetNonce(qCaller, callerNonce+1)

	// FIX: Add reentrancy protection matching interpreter path
	// (opCreateGeneric line 1253). PushActiveAddress(contractAddr) ensures
	// that if the constructor's init code calls back into the deploying
	// contract, the reentrancy is detected. Without this, a malicious
	// constructor could reenter the caller undetected via the JIT path.
	a.env.callDepth++
	savedActiveLen := len(a.env.activeAddresses)
	if !a.env.PushActiveAddress(contractAddr) {
		a.env.activeAddresses = a.env.activeAddresses[:savedActiveLen]
		a.env.callDepth--
		a.env.stateDB.RevertToSnapshot(snapshot)
		return nil, jit.Address{}, gas, fmt.Errorf("max active call depth exceeded")
	}
	defer func() {
		a.env.callDepth--
		a.env.activeAddresses = a.env.activeAddresses[:savedActiveLen]
	}()

	callCtx := &ExecutionContext{
		Origin:      a.env.ctx.Origin,
		GasPrice:    a.env.ctx.GasPrice,
		Caller:      qCaller,
		Address:     contractAddr,
		Value:       value,
		BlockNumber: a.env.ctx.BlockNumber,
		Timestamp:   a.env.ctx.Timestamp,
		Coinbase:    a.env.ctx.Coinbase,
		GasLimit:    a.env.ctx.GasLimit,
		ChainID:     a.env.ctx.ChainID,
		BaseFee:     a.env.ctx.BaseFee,     // QVM- propagate BASEFEE opcode value
		BlobBaseFee: a.env.ctx.BlobBaseFee, // QVM- propagate BLOBBASEFEE opcode value
		PrevRandao:  a.env.ctx.PrevRandao,  // QVM- propagate PREVRANDAO opcode value
		Code:        input,                 // init code
		Input:       nil,
		Gas:         gas,
		Depth:       a.env.ctx.Depth + 1,
		ParentEnv:   a.env,
	}

	result := a.interpreter.Execute(callCtx, a.env.stateDB)

	// R31-P4 FIX: Store return data for RETURNDATASIZE/RETURNDATACOPY opcodes.
	// This must be set BEFORE the revert check so that even on failure the
	// caller can inspect the revert reason via RETURNDATA.
	a.lastReturnData = result.ReturnData

	// QVM-P1-02 FIX (R31, 2026-07-27): The previous implementation only
	// checked result.Err and reverted, but NEVER deployed the code via
	// SetCode — even on successful execution the contract had no code.
	// It also missed the Reverted flag, MaxCodeSize (EIP-170), EIP-3541
	// (no 0xEF prefix), code-deposit gas charge, and EVM→QVM translation.
	// The interpreter path (opCreateGeneric line 1589-1649) does all of
	// these; mirror that here.
	//
	// Failure / revert path: roll back the snapshot (undoes value transfer,
	// nonce increment, and any state changes the constructor made).
	if result.Err != nil || result.Reverted {
		a.env.stateDB.RevertToSnapshot(snapshot)
		var err error
		if result.Err != nil {
			err = result.Err
		} else {
			err = ErrExecutionReverted
		}
		return result.ReturnData, addrToJIT(contractAddr), result.GasUsed, err
	}

	// Success path: deploy the runtime code returned by the constructor.
	deployedCode := result.ReturnData

	// EIP-170: MaxCodeSize check (24576 bytes). Without this a constructor
	// could deploy arbitrarily large code, bloating state.
	if len(deployedCode) > MaxCodeSize {
		a.env.stateDB.RevertToSnapshot(snapshot)
		return result.ReturnData, addrToJIT(contractAddr), result.GasUsed, ErrMaxCodeSizeExceeded
	}

	// Charge code-deposit gas (200 gas per byte). Without this deployment
	// would be underpriced, allowing state bloat DoS.
	if len(deployedCode) > 0 {
		codeDepositCost, derr := SafeMulGas(uint64(len(deployedCode)), GasCodeDeposit)
		if derr != nil {
			a.env.stateDB.RevertToSnapshot(snapshot)
			return result.ReturnData, addrToJIT(contractAddr), result.GasUsed, fmt.Errorf("code deposit gas overflow: %w", derr)
		}
		if err := a.env.gas.Consume(codeDepositCost); err != nil {
			a.env.stateDB.RevertToSnapshot(snapshot)
			return result.ReturnData, addrToJIT(contractAddr), result.GasUsed, err
		}
	}

	// EVM→QVM bytecode translation (matches interpreter line 1624).
	// If the deployed code is EVM bytecode, translate it to QVM ops so the
	// QVM interpreter can execute it on subsequent calls.
	if len(deployedCode) > 0 && IsEVMBytecode(deployedCode) {
		translatedRuntime, terr := TranslateEVMBytecode(deployedCode)
		if terr != nil {
			a.env.stateDB.RevertToSnapshot(snapshot)
			return result.ReturnData, addrToJIT(contractAddr), result.GasUsed, fmt.Errorf("evm bytecode translation failed: %w", terr)
		}
		deployedCode = translatedRuntime
	}

	// EIP-3541: deployed code must not start with 0xEF (would be confused
	// with the EOF prefix reserved by EIP-3670).
	if len(deployedCode) > 0 && deployedCode[0] == 0xEF {
		a.env.stateDB.RevertToSnapshot(snapshot)
		return result.ReturnData, addrToJIT(contractAddr), result.GasUsed, ErrInvalidCodePrefix
	}

	// Commit the runtime code to state (this is the deployment).
	a.env.stateDB.SetCode(contractAddr, deployedCode)

	// EIP-6780 (R40-C-H2): mark the contract as created in this transaction
	// so SELFDESTRUCT can only destroy it within the same tx. The JIT path
	// shares the parent env's txCreatedContracts map (initialized in
	// executor.go:374 for nested calls), so this write is visible to nested
	// CREATE/SELFDESTRUCT.
	if a.env.txCreatedContracts != nil {
		a.env.txCreatedContracts[contractAddr] = true
	}

	return result.ReturnData, addrToJIT(contractAddr), result.GasUsed, nil
}

// AuthCall implements the AUTHCALL opcode (EIP-7702) for the JIT adapter.
// FIX: Previously this method was missing from the JIT adapter. The JIT
// compiler's makeAuthCallOp() returns ErrInvalidOpcode to trigger fallback to
// the interpreter. This method is provided for completeness and future use —
// if the JIT compiler is updated to call the adapter for AUTHCALL, this method
// ensures proper security checks (depth, reentrancy, value transfer).
//
// AUTHCALL is like CALL but uses the authorized address as the caller.
// If no AUTH has been executed (authorizedAddress is nil), it behaves like CALL.
func (a *jitEnvAdapter) AuthCall(caller jit.Address, addr jit.Address, input []byte, gas uint64, value *big.Int) ([]byte, uint64, error) {
	qCaller := addrFromJIT(caller)
	qAddr := addrFromJIT(addr)

	// Depth check (consistent with Call/CallCode/Create)
	if a.env.callDepth >= MaxCallDepth {
		return nil, gas, fmt.Errorf("max call depth exceeded")
	}

	// Reentrancy check using full parent chain traversal
	// FIX: Add callDepth >= 1 condition (see Call method for explanation).
	// FIX: Add targetHasCode check matching interpreter path (opcodes_extended.go:587-588).
	// EOA calls (target has no code) must not be charged the reentrancy guard gas.
	// FIX: Reentrancy guard gas (2300) is charged BEFORE the 63/64 rule
	// subtraction, matching the interpreter's opAuthCall path. This ensures the
	// guard gas is always paid when reentrancy is detected, regardless of the
	// gas forwarded to the callee. Previously the JIT compiler path charged it
	// after 63/64 subtraction, potentially allowing reentrancy when gas was low.
	targetHasCode := len(a.env.stateDB.GetCode(qAddr)) > 0
	reentryIncremented := false
	if targetHasCode && a.env.callDepth >= 1 && a.env.IsAddressActive(qAddr) {
		// AUDIT (2026) QVFIX: Hard-block after MaxReentriesPerAddress.
		if !a.env.IncrementReentryCount(qAddr) {
			return nil, gas, fmt.Errorf("reentrancy cap exceeded for %x", qAddr)
		}
		reentryIncremented = true
		// QVM- (2026-07-20) FIX: Decrement on return to prevent
		// permanent counter saturation within a transaction.
		defer func() {
			if reentryIncremented {
				a.env.DecrementReentryCount(qAddr)
			}
		}()
		if err := a.env.gas.Consume(2300); err != nil {
			return nil, gas, err
		}
	}

	// FIX: Apply 63/64 gas rule — retain 1/64 of available gas for the
	// caller to prevent depth-1 reentrancy from consuming all gas.
	available := a.env.gas.Remaining()
	maxGas := available - available/64
	if gas > maxGas {
		gas = maxGas
	}

	// Value transfer with snapshot/revert
	snapshot := a.env.stateDB.Snapshot()
	if value != nil && value.Sign() > 0 {
		callerBalance := a.env.stateDB.GetBalance(qCaller)
		if callerBalance.Cmp(value) < 0 {
			return nil, gas, fmt.Errorf("insufficient balance for value transfer")
		}
		a.env.stateDB.SetBalance(qCaller, new(big.Int).Sub(callerBalance, value))
		calleeBalance := a.env.stateDB.GetBalance(qAddr)
		a.env.stateDB.SetBalance(qAddr, new(big.Int).Add(calleeBalance, value))
	}

	// Determine effective caller: authorized address if set, otherwise current
	var effectiveCaller Address = qCaller
	if a.env.authorizedAddress != nil {
		effectiveCaller = *a.env.authorizedAddress
	}

	callCtx := &ExecutionContext{
		Origin:      a.env.ctx.Origin,
		GasPrice:    a.env.ctx.GasPrice,
		Caller:      effectiveCaller,
		Address:     qAddr,
		Value:       value,
		BlockNumber: a.env.ctx.BlockNumber,
		Timestamp:   a.env.ctx.Timestamp,
		Coinbase:    a.env.ctx.Coinbase,
		GasLimit:    a.env.ctx.GasLimit,
		ChainID:     a.env.ctx.ChainID,
		BaseFee:     a.env.ctx.BaseFee,     // QVM- propagate BASEFEE opcode value
		BlobBaseFee: a.env.ctx.BlobBaseFee, // QVM- propagate BLOBBASEFEE opcode value
		PrevRandao:  a.env.ctx.PrevRandao,  // QVM- propagate PREVRANDAO opcode value
		Code:        a.env.stateDB.GetCode(qAddr),
		Input:       input,
		Gas:         gas,
		Depth:       a.env.ctx.Depth + 1,
		ParentEnv:   a.env,
		// AUDIT H-9: propagate EVMCompatible (see Call).
		EVMCompatible: isEVMTranslatedCode(a.env.stateDB.GetCode(qAddr)),
	}

	result := a.interpreter.Execute(callCtx, a.env.stateDB)

	if result.Err != nil {
		a.env.stateDB.RevertToSnapshot(snapshot)
	}

	a.lastReturnData = result.ReturnData
	return result.ReturnData, result.GasUsed, result.Err
}

func (a *jitEnvAdapter) LastReturnData() []byte {
	return a.lastReturnData
}

func (a *jitEnvAdapter) SelfDestruct(addr jit.Address) {
	a.env.stateDB.SelfDestruct(addrFromJIT(addr))
}
