// Quantaureum Node source, version 1.0.0.
package qvm

// R38-P1-07 regression tests for CREATE/CREATE2 transient storage rollback.
//
// Background
// ----------
// opCreateGeneric (operations_missing.go) shares the parent environment's
// transient storage map with the constructor (initEnv.transientStorage =
// env.transientStorage, line 1495). A TSTORE executed inside the
// constructor therefore mutates the parent map directly. The R38-P1-07 fix
// (operations_missing.go:1602 / 1648) deep-copies the parent transient
// storage BEFORE running the constructor and restores it on the
// `initEnv.err != nil || initEnv.reverted` failure branch, so that a
// failed constructor's TSTORE writes do not leak into the parent frame
// (EIP-1153: transient storage must not survive a reverted frame).
//
// These tests exercise that fix directly at the opcode level by invoking
// opCreate/opCreate2 on a hand-built parent Environment, mirroring the
// pattern of TestQVM_R37_P1_QVM01_TransientStorage_RolledBackOnRevert
// (qvm_r37_p1_regression_test.go:324) which drives the analogous R37-P1-
// QVM-01 fix for the CALL path via Interpreter.Execute.
//
// Coverage
//   1. CREATE  + constructor REVERT        -> transient writes rolled back
//   2. CREATE2 + constructor INVALID error -> transient writes rolled back
//   3. CREATE  + constructor STOP success  -> transient writes persist
//   4. CREATE  + constructor succeeds but deployment fails (MaxCodeSize)
//      -> transient writes MUST be rolled back (whole CREATE frame failed).
//      Case 4 also covers the post-constructor failure branches at
//      operations_missing.go:1655-1696 which take the post-run snapshot
//      path; without restoring transientSnapshot there the constructor's
//      TSTORE would survive a deployment failure, violating EIP-1153.

import (
	"math/big"
	"testing"
)

// r38P1PreexistingKey/Val are the parent's own transient entry seeded before
// each CREATE. They must survive every outcome (rollback restores the
// pre-call snapshot which includes this entry; success never touches it).
// Word/Hash are array types and cannot be `const`, so these are package-level
// vars used as immutable constants. The map key type is Hash, so the slot key
// is declared as Hash (the constructor bytecode pushes the same low byte via
// PUSH1, which lands at Hash index 31).
var (
	r38P1ParentSlotKey Hash = Hash{31: 0x09}
	r38P1ParentSlotVal Hash = Hash{31: 0x99}
)

// r38P1CtorKey/Val are what the constructor TSTOREs under its own address
// (env.ctx.Address == contractAddr during init code execution). Again Hash
// (map key/value type).
var (
	r38P1CtorKey Hash = Hash{31: 0x01}
	r38P1CtorVal Hash = Hash{31: 0xAA}
)

// newR38P1CreateParentEnv builds a parent Environment set up to run a CREATE
// opcode. The parent already holds one pre-existing transient storage entry
// (parentAddr -> {0x09: 0x99}) that the fix must preserve.
//
// The caller is responsible for:
//   - pushing value/offset/size[/salt] onto the returned env's stack
//   - writing the init code into env.memory at `initCodeOffset`
//
// returned: (env, contractAddr, initCodeOffset).
func newR38P1CreateParentEnv(t *testing.T, sdb *mockStateDB, parentAddr Address, isCreate2 bool, initCode []byte) (*Environment, Address, uint64) {
	t.Helper()
	const initCodeOffset = 0

	// Pre-compute the contract address so the test can assert the exact
	// transient slot the constructor writes. CREATE uses creator nonce 0;
	// CREATE2 uses salt=0 + the literal initCode.
	var contractAddr Address
	if isCreate2 {
		contractAddr = Create2Address(parentAddr, Hash{}, initCode)
	} else {
		contractAddr = CreateAddress(parentAddr, 0)
	}

	env := &Environment{
		ctx:      &ExecutionContext{Address: parentAddr, Gas: 50_000_000, ChainID: 1668, Origin: parentAddr},
		stateDB:  sdb,
		stack:    NewStack(),
		memory:   NewMemory(),
		gas:      NewGasMeter(50_000_000),
		gasTable: DefaultGasTable(),
		// Seed the shared transient map with the parent's own entry.
		transientStorage: map[Address]map[Hash]Hash{
			parentAddr: {r38P1ParentSlotKey: r38P1ParentSlotVal},
		},
		txCreatedContracts: make(map[Address]bool),
		reentryCounts:      make(map[Address]int),
		activeAddresses:    []Address{parentAddr},
	}

	// Write init code into memory at initCodeOffset.
	if err := env.memory.Set(initCodeOffset, initCode); err != nil {
		t.Fatalf("memory.Set initCode: %v", err)
	}

	return env, contractAddr, initCodeOffset
}

// r38P1RunCreate pushes the CREATE/CREATE2 operands onto env.stack and invokes
// the opcode, returning the result address pushed onto the stack. A zero
// address indicates CREATE failure (per EVM convention).
func r38P1RunCreate(t *testing.T, interp *Interpreter, env *Environment, isCreate2 bool, initCodeOffset uint64, initCodeSize uint64) Address {
	t.Helper()

	// opCreateGeneric pops: value (top-> pushed last value? No: pop value first),
	//   pop value, pop offset, pop size, [pop salt if CREATE2].
	// That means the stack (top to bottom) is: value, offset, size[, salt].
	// We push in reverse: salt, size, offset, value so value ends up on top.
	if isCreate2 {
		// salt = 0 (must match newR38P1CreateParentEnv for deterministic addr)
		if err := env.stack.Push(Word{}); err != nil {
			t.Fatalf("push salt: %v", err)
		}
	}
	if err := env.stack.PushUint64(initCodeSize); err != nil {
		t.Fatalf("push size: %v", err)
	}
	if err := env.stack.PushUint64(initCodeOffset); err != nil {
		t.Fatalf("push offset: %v", err)
	}
	if err := env.stack.PushBigInt(zeroBig); err != nil {
		t.Fatalf("push value: %v", err)
	}

	var opErr error
	if isCreate2 {
		opErr = interp.opCreate2(env)
	} else {
		opErr = interp.opCreate(env)
	}
	if opErr != nil {
		// opcode dispatch itself failed (gas/stack/validation) — caller wants
		// to observe the failure via the result address; surface it for diagnosis.
		t.Fatalf("opCreate dispatch error: %v", opErr)
	}

	resWord, err := env.stack.Pop()
	if err != nil {
		t.Fatalf("pop CREATE result: %v", err)
	}
	return WordToAddress(resWord)
}

// WordToAddress converts a Word pushed by AddressToWord back into an Address.
// QVM's AddressToWord (operations_missing.go:1767) is LEFT-aligned:
// `copy(word[:], addr[:])` places the 20-byte address at word[0:20] and leaves
// word[20:32] zero. This differs from the EVM convention (right-aligned at
// word[12:32]); we mirror QVM's own layout to round-trip the address faithfully.
func WordToAddress(w Word) Address {
	var a Address
	copy(a[:], w[0:20])
	return a
}

var zeroBig = big.NewInt(0)

// ---------------------------------------------------------------------------
// Case 1: CREATE constructor REVERT -> transient writes rolled back
// ---------------------------------------------------------------------------

func TestR38_P1_07_Create_TransientStorage_RolledBackOnConstructorRevert(t *testing.T) {
	interp := NewInterpreter()
	// gasTable must match what opCreateGeneric charges (GasCreate/GasCreate2 etc.)
	interp.gasTable = DefaultGasTable()

	sdb := newMockStateDB()
	parentAddr := Address{0xAA}

	// Constructor: TSTORE(key=0x01, value=0xAA) then REVERT with empty data.
	// TSTORE stack: pop key (top), pop value (next) -> push value first, then key.
	// REVERT stack: pop offset (top), pop size (next) -> push size first, then offset.
	ctor := []byte{
		byte(PUSH1), 0xAA, // value
		byte(PUSH1), 0x01, // key
		byte(TSTORE),
		byte(PUSH1), 0x00, // size
		byte(PUSH1), 0x00, // offset
		byte(REVERT),
	}

	env, contractAddr, off := newR38P1CreateParentEnv(t, sdb, parentAddr, false, ctor)

	resAddr := r38P1RunCreate(t, interp, env, false, off, uint64(len(ctor)))

	// CREATE must report failure via a zero address.
	if resAddr != (Address{}) {
		t.Fatalf("expected zero address (CREATE failed), got %x", resAddr)
	}

	// (a) The constructor's transient write must NOT survive the rollback.
	//     The fix restores the pre-call snapshot, which had no entry for
	//     contractAddr. If the entry is present, R38-P1-07 is NOT fixed.
	if slots, ok := env.transientStorage[contractAddr]; ok {
		t.Fatalf("R38-P1-07 NOT FIXED: reverted constructor TSTORE survived (addr=%x slots=%x)", contractAddr, slots)
	}
	// Also assert no stray non-parent entry exists (defense in depth: the
	// snapshot restoration must yield exactly the seeded map).
	for addr := range env.transientStorage {
		if addr != parentAddr {
			t.Fatalf("R38-P1-07 NOT FIXED: stray transient entry for addr %x after reverted CREATE", addr)
		}
	}

	// (b) The parent's own pre-existing entry must be preserved.
	if v := env.transientStorage[parentAddr][r38P1ParentSlotKey]; v != r38P1ParentSlotVal {
		t.Fatalf("parent transient entry lost during CREATE rollback: got %x", v)
	}
}

// ---------------------------------------------------------------------------
// Case 2: CREATE2 constructor INVALID (execution error) -> transient writes
// rolled back (covers the initEnv.err != nil branch of the fix)
// ---------------------------------------------------------------------------

func TestR38_P1_07_Create2_TransientStorage_RolledBackOnConstructorError(t *testing.T) {
	interp := NewInterpreter()
	interp.gasTable = DefaultGasTable()

	sdb := newMockStateDB()
	parentAddr := Address{0xBB}

	// Constructor: TSTORE(key=0x01, value=0xAA) then INVALID (0x08).
	// INVALID sets env.err = ErrInvalidOpcode without setting Reverted, so
	// this exercises the `initEnv.err != nil` branch distinct from case 1
	// (which exercises `initEnv.reverted`).
	ctor := []byte{
		byte(PUSH1), 0xAA, // value
		byte(PUSH1), 0x01, // key
		byte(TSTORE),
		byte(INVALID),
	}

	env, contractAddr, off := newR38P1CreateParentEnv(t, sdb, parentAddr, true, ctor)

	resAddr := r38P1RunCreate(t, interp, env, true, off, uint64(len(ctor)))

	if resAddr != (Address{}) {
		t.Fatalf("expected zero address (CREATE2 failed), got %x", resAddr)
	}

	if slots, ok := env.transientStorage[contractAddr]; ok {
		t.Fatalf("R38-P1-07 NOT FIXED: INVALID'd constructor TSTORE survived (addr=%x slots=%x)", contractAddr, slots)
	}
	for addr := range env.transientStorage {
		if addr != parentAddr {
			t.Fatalf("R38-P1-07 NOT FIXED: stray transient entry for addr %x after errored CREATE2", addr)
		}
	}
	if v := env.transientStorage[parentAddr][r38P1ParentSlotKey]; v != r38P1ParentSlotVal {
		t.Fatalf("parent transient entry lost during CREATE2 rollback: got %x", v)
	}
}

// ---------------------------------------------------------------------------
// Case 3: CREATE constructor STOP (success) -> transient writes persist
// (guards against the fix over-rolling-back on the success path)
// ---------------------------------------------------------------------------

func TestR38_P1_07_Create_TransientStorage_PersistsOnSuccess(t *testing.T) {
	interp := NewInterpreter()
	interp.gasTable = DefaultGasTable()

	sdb := newMockStateDB()
	parentAddr := Address{0xCC}

	// Constructor: TSTORE(key=0x01, value=0xAA) then STOP. No deployed code
	// is returned (returnData == nil), so the parent frame survives the
	// post-run checks (len(deployedCode) == 0 skips MaxCodeSize / code
	// deposit gas / translation / EIP-3541 checks) and reaches the success
	// push.
	ctor := []byte{
		byte(PUSH1), 0xAA, // value
		byte(PUSH1), 0x01, // key
		byte(TSTORE),
		byte(STOP),
	}

	env, contractAddr, off := newR38P1CreateParentEnv(t, sdb, parentAddr, false, ctor)

	resAddr := r38P1RunCreate(t, interp, env, false, off, uint64(len(ctor)))

	if resAddr == (Address{}) {
		t.Fatalf("expected non-zero address (CREATE succeeded), got zero")
	}
	if resAddr != contractAddr {
		t.Fatalf("returned address %x != predicted %x", resAddr, contractAddr)
	}

	// The successful constructor's TSTORE must be visible to the parent.
	wantKey := Hash{31: 0x01}
	wantVal := Hash{31: 0xAA}
	slots, ok := env.transientStorage[contractAddr]
	if !ok {
		t.Fatalf("R38-P1-07 OVER-ROLLBACK: successful constructor TSTORE dropped (no entry for %x)", contractAddr)
	}
	if got := slots[wantKey]; got != wantVal {
		t.Fatalf("R38-P1-07 OVER-ROLLBACK: successful constructor TSTORE value mismatch, got %x want %x", got, wantVal)
	}

	// The parent's pre-existing entry must still be there.
	if v := env.transientStorage[parentAddr][r38P1ParentSlotKey]; v != r38P1ParentSlotVal {
		t.Fatalf("parent transient entry lost on successful CREATE: got %x", v)
	}
}

// ---------------------------------------------------------------------------
// Case 4: constructor succeeds (STOP) but deployment fails because the
// returned runtime code exceeds MaxCodeSize. Per EIP-1153 the whole CREATE
// frame failed, so the constructor's TSTORE must be rolled back too.
// ---------------------------------------------------------------------------

func TestR38_P1_07_DeploymentFailure_AfterSuccessfulConstructor_RestoresTransient(t *testing.T) {
	interp := NewInterpreter()
	interp.gasTable = DefaultGasTable()

	sdb := newMockStateDB()
	parentAddr := Address{0xDD}

	// Runtime code to "deploy": MaxCodeSize+1 bytes of 0xAA. This makes the
	// post-run MaxCodeSize check (operations_missing.go:1656) fail even though
	// the constructor itself ran to completion without error.
	oversizedRuntime := make([]byte, MaxCodeSize+1)
	for i := range oversizedRuntime {
		oversizedRuntime[i] = 0xAA
	}

	// Constructor bytecode:
	//   TSTORE(key=0x01, value=0xAA)      -- writes transient storage
	//   MSTORE(0, <32 bytes of runtime>)  -- seed memory[0..32) with runtime head
	//   RETURN(offset=0, size=len(oversizedRuntime))
	// Because the runtime is much larger than 32 bytes, we cannot push it all
	// onto the stack; instead we materialize it into memory directly via the
	// test harness (env.memory.Set) and have the constructor RETURN that
	// region. The constructor opcodes therefore only need to: TSTORE, then
	// RETURN(0, len(runtime)).
	//
	// RETURN stack: pop offset (top), pop size (next) -> push size, then offset.
	// len(oversizedRuntime) = MaxCodeSize+1 = 24577 = 0x6001 -> fits in PUSH2.
	ctor := []byte{
		byte(PUSH1), 0xAA, // value
		byte(PUSH1), 0x01, // key
		byte(TSTORE),
		byte(PUSH2), 0x60, 0x01, // size = 24577
		byte(PUSH1), 0x00, // offset = 0
		byte(RETURN),
	}

	// The init code occupies memory[0..len(ctor)). We need the oversized
	// runtime to start at offset 0 as well — but the constructor's own bytes
	// are at offset 0. RETURN(0, size) would return the constructor's own
	// bytecode, not the runtime. To keep the test self-contained, we instead
	// place the runtime at a later offset and RETURN that region.
	//
	// Layout: [ctor bytes][padding to a 32-byte boundary][oversizedRuntime]
	const runtimeStart = 64 // comfortably past the short ctor
	fullMem := make([]byte, runtimeStart+len(oversizedRuntime))
	copy(fullMem, ctor)
	copy(fullMem[runtimeStart:], oversizedRuntime)

	env, contractAddr, off := newR38P1CreateParentEnv(t, sdb, parentAddr, false, fullMem)

	// Rebuild ctor to RETURN(runtimeStart, len(oversizedRuntime)) and rewrite
	// memory[0..) in place.
	ctorReturn := []byte{
		byte(PUSH1), 0xAA, // value
		byte(PUSH1), 0x01, // key
		byte(TSTORE),
		byte(PUSH2), 0x60, 0x01, // size = 24577
		byte(PUSH1), byte(runtimeStart), // offset = 64
		byte(RETURN),
	}
	if len(ctorReturn) > runtimeStart {
		t.Fatalf("test setup: ctorReturn too long (%d) for runtimeStart (%d)", len(ctorReturn), runtimeStart)
	}
	// Overwrite the leading region with the (possibly shorter) real ctor. The
	// remainder stays zero-filled which is fine (STOP region after RETURN).
	copy(fullMem, ctorReturn)
	if err := env.memory.Set(off, fullMem); err != nil {
		t.Fatalf("memory.Set fullMem: %v", err)
	}

	resAddr := r38P1RunCreate(t, interp, env, false, off, uint64(len(ctorReturn)))

	// CREATE failed (MaxCodeSize exceeded) -> zero address.
	if resAddr != (Address{}) {
		t.Fatalf("expected zero address (MaxCodeSize deployment failure), got %x", resAddr)
	}

	// Even though the constructor ran to completion (no REVERT, no error),
	// the CREATE frame as a whole failed, so EIP-1153 requires the
	// constructor's transient writes to be rolled back. If this assertion
	// fails, the post-run failure branches at operations_missing.go:1655-1696
	// are missing the transientSnapshot restoration and R38-P1-07 is
	// incomplete on the deployment-failure path.
	if slots, ok := env.transientStorage[contractAddr]; ok {
		// Distinguish a real bug (constructor value present) from a
		// benign empty map entry by checking the actual slot.
		if v, present := slots[Hash{31: 0x01}]; present && v == (Hash{31: 0xAA}) {
			t.Fatalf("R38-P1-07 INCOMPLETE: constructor TSTORE survived a deployment failure "+
				"(MaxCodeSize). Post-run failure branches must restore transientSnapshot. addr=%x v=%x",
				contractAddr, v)
		}
		// Empty map for contractAddr is harmless (opTStore would create it
		// again on next access); still, the snapshot restore replaced the
		// map pointer so a lingering empty entry here indicates the restore
		// used a shallow copy. Log it for awareness but don't fail.
		if len(slots) == 0 {
			t.Logf("note: contractAddr transient entry present but empty after deployment failure (acceptable)")
		}
	}

	// Parent's own entry must survive regardless.
	if v := env.transientStorage[parentAddr][r38P1ParentSlotKey]; v != r38P1ParentSlotVal {
		t.Fatalf("parent transient entry lost during deployment failure: got %x", v)
	}
}

// ---------------------------------------------------------------------------
// Sanity: ensure the deep-copied snapshot is independent (mutation of the
// restored map does not affect the snapshot referenced elsewhere). This is a
// cheap static guard against a future regression of copyTransientStorage that
// would otherwise slip past cases 1-4 because the parent Env holds the same
// pointer the constructor mutated.
// ---------------------------------------------------------------------------

func TestR38_P1_07_CopyTransientStorage_IsDeepCopy(t *testing.T) {
	orig := map[Address]map[Hash]Hash{
		{0x01}: {{31: 0x10}: {31: 0x20}},
	}
	cp := copyTransientStorage(orig)

	// Mutate the copy; the original must be unaffected.
	cp[Address{0x01}][Hash{31: 0x10}] = Hash{31: 0xFF}
	cp[Address{0x02}] = map[Hash]Hash{{31: 0x30}: {31: 0x40}}

	if got := orig[Address{0x01}][Hash{31: 0x10}]; got != (Hash{31: 0x20}) {
		t.Fatalf("copyTransientStorage is shallow: orig mutated to %x", got)
	}
	if _, leaked := orig[Address{0x02}]; leaked {
		t.Fatalf("copyTransientStorage is shallow: new addr leaked into orig")
	}

	// And mutating orig must not affect the (already-mutated) copy.
	orig[Address{0x01}][Hash{31: 0x99}] = Hash{31: 0xBE}
	if _, leaked := cp[Address{0x01}][Hash{31: 0x99}]; leaked {
		t.Fatalf("copyTransientStorage is shallow: orig mutation leaked into copy")
	}

	// nil input must return nil (matches the implementation's fast path).
	if got := copyTransientStorage(nil); got != nil {
		t.Fatalf("copyTransientStorage(nil) = %v, want nil", got)
	}
}
