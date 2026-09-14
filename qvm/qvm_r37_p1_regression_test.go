// Quantaureum Node source, version 1.0.0.
// R37 P1 QVM regression tests (2026-07-30).
//   - P1-QVM-03: AUTH commit nonce must bind to the authority's account
//     nonce and be consumed on success (anti-replay). AUTH must also refuse
//     read-only (STATICCALL) contexts because it is now stateful.
//   - P1-QVM-01: EIP-1153 transient storage must roll back when a sub-call
//     REVERTs or errors; successful sub-call writes must persist.
//   - P1-QVM-02: CALL/DELEGATECALL/CALLCODE/AUTHCALL must forward the
//     inherited ReadOnly flag to the precompiled dispatcher so stateful
//     precompiles stay rejected under a static-call guarantee.
package qvm

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qvm/precompiled"
	"github.com/quantaureum/qau/types"
)

// ---------------------------------------------------------------------------
// P1-QVM-03 helpers
// ---------------------------------------------------------------------------

// authTestKey holds a secp256k1 key pair and its derived QVM address.
type authTestKey struct {
	priv *ecdsa.PrivateKey
	addr Address
}

// newAuthTestKey generates a random secp256k1 key using the interpreter's own
// curve implementation so signatures verify through recoverSignerAddress.
func newAuthTestKey(t *testing.T) *authTestKey {
	t.Helper()
	curve := secp256k1Curve()
	n := curve.Params().N
	d, err := rand.Int(rand.Reader, n)
	if err != nil {
		t.Fatalf("rand.Int: %v", err)
	}
	if d.Sign() == 0 {
		t.Fatal("zero private key")
	}
	qx, qy := curve.ScalarBaseMult(d.Bytes())
	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: qx, Y: qy},
		D:         d,
	}
	// Address derivation must match recoverSignerAddress: keccak(x32||y32)[12:]
	pub := make([]byte, 64)
	qx.FillBytes(pub[:32])
	qy.FillBytes(pub[32:])
	h := keccak256Hash(pub)
	var addr Address
	copy(addr[:], h[12:])
	return &authTestKey{priv: priv, addr: addr}
}

// buildAuthEnv returns an Environment loaded with a signed AUTH message and
// the operand stack prepared for opAuth (length, offset, authority pushed).
// The commit is chainID(32) || nonce(32) || contractAddr(20), matching the
// layout opAuth parses.
func buildAuthEnv(t *testing.T, key *authTestKey, sdb *mockStateDB, contractAddr Address, chainID, nonce uint64, readOnly bool) *Environment {
	t.Helper()
	commit := make([]byte, 84)
	binary.BigEndian.PutUint64(commit[24:32], chainID)
	binary.BigEndian.PutUint64(commit[56:64], nonce)
	copy(commit[64:84], contractAddr[:])

	preimage := append([]byte{0x05}, commit...)
	msgHash := keccak256Hash(preimage)

	r, s, err := ecdsa.Sign(rand.Reader, key.priv, msgHash[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	// Normalize s to the lower half (EIP-2) as recoverSignerAddress requires.
	n := secp256k1Curve().Params().N
	halfN := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if s.Cmp(halfN) > 0 {
		s.Sub(n, s)
	}
	rBytes := r.FillBytes(make([]byte, 32))
	sBytes := s.FillBytes(make([]byte, 32))

	// Determine the recovery parity that maps back to the key's address.
	yParity := byte(255)
	for v := byte(0); v <= 1; v++ {
		addr, err := recoverSignerAddress(msgHash, v, rBytes, sBytes)
		if err == nil && addr == key.addr {
			yParity = v
			break
		}
	}
	if yParity > 1 {
		t.Fatal("could not determine yParity for AUTH signature")
	}

	msgData := make([]byte, 0, 1+32+32+len(commit))
	msgData = append(msgData, yParity)
	msgData = append(msgData, rBytes...)
	msgData = append(msgData, sBytes...)
	msgData = append(msgData, commit...)

	env := &Environment{
		ctx: &ExecutionContext{
			Address:  contractAddr,
			ChainID:  chainID,
			ReadOnly: readOnly,
			Gas:      100000,
		},
		stateDB:  sdb,
		stack:    NewStack(),
		memory:   NewMemory(),
		gas:      NewGasMeter(100000),
		gasTable: DefaultGasTable(),
	}
	if err := env.memory.Set(0, msgData); err != nil {
		t.Fatalf("memory.Set: %v", err)
	}
	// opAuth pops authority, then offset, then length — push in reverse.
	if err := env.stack.PushUint64(uint64(len(msgData))); err != nil {
		t.Fatalf("push length: %v", err)
	}
	if err := env.stack.PushUint64(0); err != nil {
		t.Fatalf("push offset: %v", err)
	}
	var authWord Word
	copy(authWord[12:32], key.addr[:])
	if err := env.stack.Push(authWord); err != nil {
		t.Fatalf("push authority: %v", err)
	}
	return env
}

// TestQVM_R37_P1_QVM03_AUTH_NonceConsumedAndReplayRejected verifies that a
// correctly bound AUTH authorization succeeds, consumes the authority nonce,
// and that replaying the SAME signature afterwards fails.
func TestQVM_R37_P1_QVM03_AUTH_NonceConsumedAndReplayRejected(t *testing.T) {
	interp := NewInterpreter()
	// R37-INFO: AUTH is fail-closed by default (quantum-vulnerable ECDSA
	// path); explicitly enable it for this authorization-logic test.
	interp.EnableECDSAAuth()
	sdb := newMockStateDB()
	key := newAuthTestKey(t)
	contractAddr := Address{0x42}
	const chainID = uint64(1668)

	// Authority starts at nonce 0; commit binds nonce 0.
	env := buildAuthEnv(t, key, sdb, contractAddr, chainID, 0, false)
	if err := interp.opAuth(env); err != nil {
		t.Fatalf("opAuth: %v", err)
	}
	res, err := env.stack.Pop()
	if err != nil {
		t.Fatalf("pop result: %v", err)
	}
	var wantWord Word
	copy(wantWord[12:32], key.addr[:])
	if res != wantWord {
		t.Fatal("AUTH with valid nonce-bound signature should push the authority address")
	}
	if env.authorizedAddress == nil || *env.authorizedAddress != key.addr {
		t.Fatal("authorizedAddress not set after successful AUTH")
	}
	if got := sdb.GetNonce(key.addr); got != 1 {
		t.Fatalf("authority nonce should be consumed (1), got %d", got)
	}

	// Replay: the SAME signature commits nonce 0, but the authority nonce is
	// now 1 — authorization MUST fail.
	env2 := buildAuthEnv(t, key, sdb, contractAddr, chainID, 0, false)
	if err := interp.opAuth(env2); err != nil {
		t.Fatalf("opAuth replay: %v", err)
	}
	res2, err := env2.stack.Pop()
	if err != nil {
		t.Fatalf("pop replay result: %v", err)
	}
	if res2 != (Word{}) {
		t.Fatal("replayed AUTH signature must be rejected (nonce already consumed)")
	}
	if env2.authorizedAddress != nil {
		t.Fatal("authorizedAddress must stay nil on replay")
	}
	if got := sdb.GetNonce(key.addr); got != 1 {
		t.Fatalf("failed authorization must not burn nonce, got %d", got)
	}
}

// TestQVM_R37_P1_QVM03_AUTH_WrongNonceRejected verifies that a signature
// committing a stale/future nonce is rejected and does not mutate state.
func TestQVM_R37_P1_QVM03_AUTH_WrongNonceRejected(t *testing.T) {
	interp := NewInterpreter()
	// R37-INFO: AUTH is fail-closed by default; enable for this test.
	interp.EnableECDSAAuth()
	sdb := newMockStateDB()
	key := newAuthTestKey(t)
	contractAddr := Address{0x42}
	const chainID = uint64(1668)

	// Authority's on-chain nonce is 7 but the commit binds nonce 0.
	sdb.SetNonce(key.addr, 7)
	env := buildAuthEnv(t, key, sdb, contractAddr, chainID, 0, false)
	if err := interp.opAuth(env); err != nil {
		t.Fatalf("opAuth: %v", err)
	}
	res, err := env.stack.Pop()
	if err != nil {
		t.Fatalf("pop result: %v", err)
	}
	if res != (Word{}) {
		t.Fatal("AUTH with mismatched commit nonce must be rejected")
	}
	if got := sdb.GetNonce(key.addr); got != 7 {
		t.Fatalf("rejected AUTH must not change nonce, got %d want 7", got)
	}
}

// TestQVM_R37_P1_QVM03_AUTH_ReadOnlyRejected verifies AUTH refuses static
// contexts: a successful authorization consumes nonce, which is a state
// write that must not happen under a STATICCALL guarantee.
func TestQVM_R37_P1_QVM03_AUTH_ReadOnlyRejected(t *testing.T) {
	interp := NewInterpreter()
	// R37-INFO: AUTH is fail-closed by default; enable for this test.
	interp.EnableECDSAAuth()
	sdb := newMockStateDB()
	key := newAuthTestKey(t)
	contractAddr := Address{0x42}
	const chainID = uint64(1668)

	env := buildAuthEnv(t, key, sdb, contractAddr, chainID, 0, true /* readOnly */)
	if err := interp.opAuth(env); err != nil {
		t.Fatalf("opAuth: %v", err)
	}
	res, err := env.stack.Pop()
	if err != nil {
		t.Fatalf("pop result: %v", err)
	}
	if res != (Word{}) {
		t.Fatal("AUTH in a read-only context must be rejected")
	}
	if got := sdb.GetNonce(key.addr); got != 0 {
		t.Fatalf("read-only AUTH must not write nonce, got %d", got)
	}
}

// TestQVM_R37_INFO_AUTH_FailClosedByDefault verifies the R37-INFO fix:
// with the ECDSA path disabled (the default), opAuth must refuse even a
// perfectly valid authorization — pushing 0, leaving authorizedAddress nil
// and the authority nonce untouched — because secp256k1 is a
// quantum-vulnerable authorization path on a quantum-safe chain.
func TestQVM_R37_INFO_AUTH_FailClosedByDefault(t *testing.T) {
	interp := NewInterpreter() // ecdsaAuthEnabled defaults to false
	sdb := newMockStateDB()
	key := newAuthTestKey(t)
	contractAddr := Address{0x42}
	const chainID = uint64(1668)

	env := buildAuthEnv(t, key, sdb, contractAddr, chainID, 0, false)
	if err := interp.opAuth(env); err != nil {
		t.Fatalf("opAuth: %v", err)
	}
	res, err := env.stack.Pop()
	if err != nil {
		t.Fatalf("pop result: %v", err)
	}
	if res != (Word{}) {
		t.Fatal("AUTH must fail closed (push 0) when the ECDSA path is disabled")
	}
	if env.authorizedAddress != nil {
		t.Fatal("authorizedAddress must stay nil when the ECDSA path is disabled")
	}
	if got := sdb.GetNonce(key.addr); got != 0 {
		t.Fatalf("disabled AUTH must not consume nonce, got %d", got)
	}

	// After explicit enablement, the same authorization must succeed.
	interp.EnableECDSAAuth()
	env2 := buildAuthEnv(t, key, sdb, contractAddr, chainID, 0, false)
	if err := interp.opAuth(env2); err != nil {
		t.Fatalf("opAuth after enable: %v", err)
	}
	res2, err := env2.stack.Pop()
	if err != nil {
		t.Fatalf("pop result after enable: %v", err)
	}
	var wantWord Word
	copy(wantWord[12:32], key.addr[:])
	if res2 != wantWord {
		t.Fatal("AUTH must succeed after EnableECDSAAuth")
	}
}

// ---------------------------------------------------------------------------
// P1-QVM-01 transient storage rollback
// ---------------------------------------------------------------------------

// newParentEnvForTS builds a parent Environment holding a shared transient
// storage map with one pre-existing entry.
func newParentEnvForTS(sdb *mockStateDB, parentAddr Address) *Environment {
	return &Environment{
		ctx:       &ExecutionContext{Address: parentAddr, Gas: 1000000, ChainID: 1668},
		stateDB:   sdb,
		stack:     NewStack(),
		memory:    NewMemory(),
		gas:       NewGasMeter(1000000),
		gasTable:  DefaultGasTable(),
		callDepth: 0,
		transientStorage: map[Address]map[Hash]Hash{
			parentAddr: {{0x09}: {0x99}},
		},
		txCreatedContracts: make(map[Address]bool),
		reentryCounts:      make(map[Address]int),
		activeAddresses:    []Address{parentAddr},
	}
}

// TestQVM_R37_P1_QVM01_TransientStorage_RolledBackOnRevert verifies that a
// sub-call's TSTORE writes are discarded when the sub-call REVERTs, while
// pre-existing parent entries survive.
func TestQVM_R37_P1_QVM01_TransientStorage_RolledBackOnRevert(t *testing.T) {
	interp := NewInterpreter()
	sdb := newMockStateDB()
	parentAddr := Address{0xAA}
	childAddr := Address{0xBB}

	parentEnv := newParentEnvForTS(sdb, parentAddr)

	// Child: TSTORE(key=0x01, value=0xAA) then REVERT.
	childCode := []byte{
		byte(PUSH1), 0xAA, // value
		byte(PUSH1), 0x01, // key
		byte(TSTORE),
		byte(PUSH1), 0x00, // offset
		byte(PUSH1), 0x00, // size
		byte(REVERT),
	}
	childCtx := &ExecutionContext{
		Code:      childCode,
		Address:   childAddr,
		Caller:    parentAddr,
		Gas:       100000,
		ChainID:   1668,
		ParentEnv: parentEnv,
	}
	result := interp.Execute(childCtx, sdb)
	if result == nil || !result.Reverted {
		t.Fatalf("expected child to revert, got %+v", result)
	}

	// The child's TSTORE write must NOT survive the revert. Assert the whole
	// childAddr entry is gone — the rollback restores the pre-call snapshot,
	// which had no entry for childAddr. (TSTORE keys are big-endian Words;
	// PUSH1 0x01 lands at index 31, so checking Hash{0x01} would be a
	// vacuous assertion.)
	if _, ok := parentEnv.transientStorage[childAddr]; ok {
		t.Fatalf("P1-QVM-01 NOT FIXED: reverted sub-call TSTORE survived (slots=%x)", parentEnv.transientStorage[childAddr])
	}
	// The parent's own pre-existing entry must be preserved.
	if v := parentEnv.transientStorage[parentAddr][Hash{0x09}]; v != (Hash{0x99}) {
		t.Fatalf("parent transient entry lost during rollback: got %x", v)
	}
}

// TestQVM_R37_P1_QVM01_TransientStorage_PersistsOnSuccess verifies the fix
// does NOT over-roll-back: a successful sub-call's TSTORE writes persist
// (EIP-1153 transient storage is shared for the whole transaction).
func TestQVM_R37_P1_QVM01_TransientStorage_PersistsOnSuccess(t *testing.T) {
	interp := NewInterpreter()
	sdb := newMockStateDB()
	parentAddr := Address{0xAA}
	childAddr := Address{0xBB}

	parentEnv := newParentEnvForTS(sdb, parentAddr)

	// Child: TSTORE(key=0x02, value=0xBB) then STOP.
	childCode := []byte{
		byte(PUSH1), 0xBB, // value
		byte(PUSH1), 0x02, // key
		byte(TSTORE),
		byte(STOP),
	}
	childCtx := &ExecutionContext{
		Code:      childCode,
		Address:   childAddr,
		Caller:    parentAddr,
		Gas:       100000,
		ChainID:   1668,
		ParentEnv: parentEnv,
	}
	result := interp.Execute(childCtx, sdb)
	if result == nil || result.Err != nil || result.Reverted {
		t.Fatalf("expected child success, got %+v", result)
	}

	// TSTORE keys/values are big-endian Words: PUSH1 0x02/0xBB land at
	// index 31 of the 32-byte Hash.
	wantKey := Hash{31: 0x02}
	wantVal := Hash{31: 0xBB}
	if v := parentEnv.transientStorage[childAddr][wantKey]; v != wantVal {
		t.Fatalf("successful sub-call TSTORE must persist, got %x", v)
	}
}

// ---------------------------------------------------------------------------
// P1-QVM-02 stateful precompile under inherited static context
// ---------------------------------------------------------------------------

// statefulStubPrecompile is a stateful precompile that records whether it ran.
type statefulStubPrecompile struct {
	addr types.Address
	ran  *bool
}

func (s *statefulStubPrecompile) Address() types.Address           { return s.addr }
func (s *statefulStubPrecompile) RequiredGas(input []byte) uint64  { return 0 }
func (s *statefulStubPrecompile) IsStateful() bool                 { return true }
func (s *statefulStubPrecompile) Run(input []byte) ([]byte, error) { *s.ran = true; return nil, nil }

// buildCallPrecompileCode returns bytecode that CALLs `target` with no value
// and no input, stores the CALL result word at memory[0], and returns it.
func buildCallPrecompileCode(target byte) []byte {
	return []byte{
		byte(PUSH1), 0x00, // outSize
		byte(PUSH1), 0x00, // outOffset
		byte(PUSH1), 0x00, // inSize
		byte(PUSH1), 0x00, // inOffset
		byte(PUSH1), 0x00, // value
		byte(PUSH1), target, // addr
		byte(PUSH2), 0xFF, 0xFF, // gas
		byte(CALL),
		byte(PUSH1), 0x00, // MSTORE offset
		byte(MSTORE),
		byte(PUSH1), 0x20, // RETURN size
		byte(PUSH1), 0x00, // RETURN offset
		byte(RETURN),
	}
}

// TestQVM_R37_P1_QVM02_NestedCallUnderStatic_RejectsStatefulPrecompile
// verifies that a CALL issued from a frame executing under an inherited
// read-only (STATICCALL) context cannot reach a stateful precompile.
// Before the fix the four call opcodes hardcoded static=false and the
// precompile executed, bypassing STATICCALL write protection.
func TestQVM_R37_P1_QVM02_NestedCallUnderStatic_RejectsStatefulPrecompile(t *testing.T) {
	ran := false
	stub := &statefulStubPrecompile{
		addr: types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66},
		ran:  &ran,
	}

	interp := NewInterpreter()
	interp.precompiled = precompiled.NewRegistry()
	interp.precompiled.Register(stub)

	sdb := newMockStateDB()
	callerAddr := Address{0xAA}
	code := buildCallPrecompileCode(0x66)

	ctx := &ExecutionContext{
		Code:     code,
		Address:  callerAddr,
		Caller:   Address{0x01},
		Origin:   Address{0x01},
		Gas:      1000000,
		ChainID:  1668,
		ReadOnly: true, // inherited from a STATICCALL ancestor
		// The bytecode pushes CALL args with gas on top (EVM convention);
		// without EVMCompatible the QVM pop order reads addr as 0 and the
		// CALL short-circuits before ever reaching the precompile check.
		EVMCompatible: true,
	}
	result := interp.Execute(ctx, sdb)
	if result == nil || result.Err != nil {
		t.Fatalf("execution failed: %+v", result)
	}
	if ran {
		t.Fatal("P1-QVM-02 NOT FIXED: stateful precompile executed under static context")
	}
	if len(result.ReturnData) != 32 || result.ReturnData[31] != 0 {
		t.Fatalf("CALL to stateful precompile under static context must return 0, got %x", result.ReturnData)
	}
}

// TestQVM_R37_P1_QVM02_NestedCallNonStatic_AllowsStatefulPrecompile is the
// control case: the same CALL in a writable context reaches the precompile.
func TestQVM_R37_P1_QVM02_NestedCallNonStatic_AllowsStatefulPrecompile(t *testing.T) {
	ran := false
	stub := &statefulStubPrecompile{
		addr: types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66},
		ran:  &ran,
	}

	interp := NewInterpreter()
	interp.precompiled = precompiled.NewRegistry()
	interp.precompiled.Register(stub)

	sdb := newMockStateDB()
	callerAddr := Address{0xAA}
	code := buildCallPrecompileCode(0x66)

	ctx := &ExecutionContext{
		Code:          code,
		Address:       callerAddr,
		Caller:        Address{0x01},
		Origin:        Address{0x01},
		Gas:           1000000,
		ChainID:       1668,
		ReadOnly:      false,
		EVMCompatible: true, // match EVM push order (gas on top)
	}
	result := interp.Execute(ctx, sdb)
	if result == nil || result.Err != nil {
		t.Fatalf("execution failed: %+v", result)
	}
	if !ran {
		t.Fatal("stateful precompile should execute in a writable context")
	}
	if len(result.ReturnData) != 32 || result.ReturnData[31] != 1 {
		t.Fatalf("CALL to precompile in writable context must return 1, got %x", result.ReturnData)
	}
}
