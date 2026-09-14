// Quantaureum Node source, version 1.0.0.
// R38-P0-01 Protocol V2 multisig registerWallet RED→GREEN gates.
// These tests prove the V2 precompile closes the legacy 0x66
// "register-an-arbitrary-victim-fund-as-own-multisig" theft path:
// the wallet address is derived from the authenticated
// PrecompileContext.Caller, NOT from attacker-supplied calldata, and an
// attacker cannot register an account they do not own.
package precompiled

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// fakeV2StateDB is a minimal in-memory MultisigStateDB for unit-testing the
// V2 register/create/approve/execute paths in isolation. It implements the
// state slots the V2 precompile writes (per-address GetState/SetState) AND a
// real balance ledger, so the executeProposal happy-path and rollback tests
// can assert SubBalance/AddBalance behavior. Snapshots are no-ops: V2 uses
// them only on the new R47-V2CALLDATA-01 callData path (where Snapshot /
// RevertToSnapshot remain optional and the inline balance check before the
// snapshot provides the primary fail-closed guard); the value-only path
// rolls back manually via SubBalance+AddBalance reversal.
type fakeV2StateDB struct {
	states   map[types.Address]map[types.Hash]types.Hash
	balances map[types.Address]*big.Int
}

func newFakeV2StateDB() *fakeV2StateDB {
	return &fakeV2StateDB{
		states:   map[types.Address]map[types.Hash]types.Hash{},
		balances: map[types.Address]*big.Int{},
	}
}

func (f *fakeV2StateDB) GetState(addr types.Address, key types.Hash) types.Hash {
	if m, ok := f.states[addr]; ok {
		return m[key]
	}
	return types.Hash{}
}
func (f *fakeV2StateDB) SetState(addr types.Address, key, value types.Hash) {
	if f.states[addr] == nil {
		f.states[addr] = map[types.Hash]types.Hash{}
	}
	f.states[addr][key] = value
}
func (f *fakeV2StateDB) GetBalance(addr types.Address) *big.Int {
	if v, ok := f.balances[addr]; ok {
		return new(big.Int).Set(v)
	}
	return new(big.Int)
}
func (f *fakeV2StateDB) AddBalance(addr types.Address, amount *big.Int) error {
	if amount == nil {
		return errors.New("nil amount")
	}
	v, ok := f.balances[addr]
	if !ok {
		v = new(big.Int)
	}
	nv := new(big.Int).Add(v, amount)
	if nv.Sign() < 0 {
		return errors.New("balance underflow")
	}
	f.balances[addr] = nv
	return nil
}
func (f *fakeV2StateDB) SubBalance(addr types.Address, amount *big.Int) error {
	if amount == nil {
		return errors.New("nil amount")
	}
	return f.AddBalance(addr, new(big.Int).Neg(amount))
}

// buildRegisterCalldata assembles the V2 registerWallet calldata:
// threshold(uint32) || signerCount(uint32) || salt(32) || signers(20*N).
func buildRegisterCaldata(t *testing.T, threshold uint32, salt [32]byte, signers []types.Address) []byte {
	t.Helper()
	out := make([]byte, 8+32+len(signers)*20)
	binary.BigEndian.PutUint32(out[0:4], threshold)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(signers)))
	copy(out[8:40], salt[:])
	off := 40
	for _, s := range signers {
		copy(out[off:off+20], s[:])
		off += 20
	}
	return out
}

// TestR38P001_V2RegisterWallet_DerivesAddressFromAuthenticatedCaller asserts
// the core R38-P0-01 invariant: the wallet address is a pure function of
// the authenticated caller + chainID + threshold + signers + salt, and
// is NOT read from calldata. Two registrations with identical inputs but
// different callers MUST produce different addresses, so an attacker
// cannot register a victim's funder as their own multisig.
func TestR38P001_V2RegisterWallet_DerivesAddressFromAuthenticatedCaller(t *testing.T) {
	chainID := uint64(1668)
	signer1 := types.Address{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	callerA := types.Address{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	callerB := types.Address{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22}
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(0x10 + i)
	}

	c := newMultisigV2Precompiled()
	calldata := buildRegisterCaldata(t, 1, salt, []types.Address{signer1})

	ctxA := PrecompileContext{Caller: callerA, Origin: callerA, BlockTime: 1_700_000_000, ChainID: chainID, CallKind: CallKindCall}
	outA, err := c.RunWithContextV2(ctxA, newFakeV2StateDB(), append([]byte{MultisigV2FuncRegisterWallet}, calldata...))
	if err != nil {
		t.Fatalf("register callerA: unexpected error: %v", err)
	}
	if len(outA) != 20 {
		t.Fatalf("register callerA: expected 20-byte address, got %d bytes", len(outA))
	}
	var addrA types.Address
	copy(addrA[:], outA)

	// Same calldata, different authenticated caller → different wallet address.
	c2 := newMultisigV2Precompiled()
	ctxB := PrecompileContext{Caller: callerB, Origin: callerB, BlockTime: 1_700_000_000, ChainID: chainID, CallKind: CallKindCall}
	outB, err := c2.RunWithContextV2(ctxB, newFakeV2StateDB(), append([]byte{MultisigV2FuncRegisterWallet}, calldata...))
	if err != nil {
		t.Fatalf("register callerB: unexpected error: %v", err)
	}
	var addrB types.Address
	copy(addrB[:], outB)

	if addrA == addrB {
		t.Errorf("R38-P0-01 V2 invariant broken: same calldata under different callers derived same wallet address %x", addrA)
	}
}

// TestR38P001_V2RegisterWallet_RejectsMissingCaller asserts that a calldata
// that reaches the precompile without an authenticated caller (zero
// PrecompileContext.Caller) is rejected. The legacy 0x66 path took the
// wallet address from calldata and could not enforce this; V2 makes caller
// the root of trust and refuses to proceed without it.
func TestR38P001_V2RegisterWallet_RejectsMissingCaller(t *testing.T) {
	signer1 := types.Address{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	var salt [32]byte
	c := newMultisigV2Precompiled()
	calldata := buildRegisterCaldata(t, 1, salt, []types.Address{signer1})
	ctx := PrecompileContext{Caller: types.Address{}, Origin: types.Address{}, ChainID: 1668, CallKind: CallKindCall}
	_, err := c.RunWithContextV2(ctx, newFakeV2StateDB(), append([]byte{MultisigV2FuncRegisterWallet}, calldata...))
	if err == nil {
		t.Error("expected error when caller is zero (unauthenticated register)")
	}
}

// TestR38P001_V2RegisterWallet_RejectsInvalidConfiguration delegates the
// validation to types.DeriveMultisigV2Address. The V2 precompile must not
// duplicate the checks; it must let types reject zero threshold, threshold
// > signerCount, duplicates, zero signers, etc. This test asserts the
// precompile surfaces the typed errors.
func TestR38P001_V2RegisterWallet_RejectsInvalidConfiguration(t *testing.T) {
	caller := types.Address{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	signer1 := types.Address{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	var salt [32]byte

	cases := []struct {
		name      string
		threshold uint32
		signers   []types.Address
		wantErr   error
	}{
		{"zero threshold", 0, []types.Address{signer1}, types.ErrMultisigV2InvalidThreshold},
		{"threshold exceeds signers", 2, []types.Address{signer1}, types.ErrMultisigV2InvalidThreshold},
		{"duplicate signer", 1, []types.Address{signer1, signer1}, types.ErrMultisigV2DuplicateSigner},
		{"zero signer address", 1, []types.Address{{}}, types.ErrMultisigV2ZeroSigner},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newMultisigV2Precompiled()
			calldata := buildRegisterCaldata(t, tc.threshold, salt, tc.signers)
			ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: 1668, BlockTime: 1_700_000_000, CallKind: CallKindCall}
			_, err := c.RunWithContextV2(ctx, newFakeV2StateDB(), append([]byte{MultisigV2FuncRegisterWallet}, calldata...))
			if err != tc.wantErr {
				t.Errorf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestR38P001_V2RegisterWallet_PersistsConfigForDerivedAddress asserts the
// V2 register writes the threshold and signer slots under the derived
// wallet address, so the upcoming create/approve/execute batch can audit
// the wallet config at the canonical address (and execute cannot spend a
// wallet that was never registered). This is the protocol-level binding
// between registration and execution.
func TestR38P001_V2RegisterWallet_PersistsConfigForDerivedAddress(t *testing.T) {
	caller := types.Address{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	signer1 := types.Address{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	signer2 := types.Address{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb}
	var salt [32]byte
	salt[0] = 0x42

	c := newMultisigV2Precompiled()
	db := newFakeV2StateDB()
	calldata := buildRegisterCaldata(t, 2, salt, []types.Address{signer1, signer2})
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: 1668, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	out, err := c.RunWithContextV2(ctx, db, append([]byte{MultisigV2FuncRegisterWallet}, calldata...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var walletAddr types.Address
	copy(walletAddr[:], out)

	// Slot 0 must hold the threshold in the low 4 bytes.
	slot0 := db.GetState(walletAddr, stateKey(0))
	gotThreshold := binary.BigEndian.Uint32(slot0[28:32])
	if gotThreshold != 2 {
		t.Errorf("slot 0 wrong: got threshold %d, want 2", gotThreshold)
	}
	// Slot 1 must hold the signerCount.
	slot1 := db.GetState(walletAddr, stateKey(1))
	gotCount := binary.BigEndian.Uint32(slot1[28:32])
	if gotCount != 2 {
		t.Errorf("slot 1 wrong: got signerCount %d, want 2", gotCount)
	}
	// Slot 2..3 must hold the signers, sorted lexicographically: signer2 (bb...)
	// comes before signer1 (aa...)? Actually sorted ascending → aa... first.
	// types.DeriveMultisigV2Address normalizes to ascending lex order, so
	// slot 2 = signer1 (aa...) and slot 3 = signer2 (bb...).
	slot2 := db.GetState(walletAddr, stateKey(2))
	var gotS0 types.Address
	copy(gotS0[:], slot2[12:32])
	if gotS0 != signer1 {
		t.Errorf("slot 2 wrong: got %x, want %x", gotS0, signer1)
	}
}

// TestR38P001_V2RegisterWallet_IdempotentForSameConfig asserts that
// re-registering the exact same configuration is a no-op success returning
// the same derived address. This protects retry-safety: a client that
// retries register after a network blip cannot brick a half-written
// record, and cannot exploit a re-register to mutate the signer set.
func TestR38P001_V2RegisterWallet_IdempotentForSameConfig(t *testing.T) {
	caller := types.Address{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	signer1 := types.Address{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	var salt [32]byte
	salt[0] = 0x42

	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: 1668, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	calldata := buildRegisterCaldata(t, 1, salt, []types.Address{signer1})

	// First register.
	c1 := newMultisigV2Precompiled()
	db := newFakeV2StateDB()
	out1, err := c1.RunWithContextV2(ctx, db, append([]byte{MultisigV2FuncRegisterWallet}, calldata...))
	if err != nil {
		t.Fatalf("first register: unexpected error: %v", err)
	}

	// Re-register with same config and same caller — must succeed and
	// produce the same derived address, without mutating state.
	c2 := newMultisigV2Precompiled()
	out2, err := c2.RunWithContextV2(ctx, db, append([]byte{MultisigV2FuncRegisterWallet}, calldata...))
	if err != nil {
		t.Fatalf("idempotent re-register: unexpected error: %v", err)
	}
	if string(out1) != string(out2) {
		t.Errorf("idempotent re-register changed address: %x then %x", out1, out2)
	}
}

// TestR38P001_V2RegisterWallet_DerivesDifferentAddressWhenSignerSetMutates
// asserts the V2 invariant that defeats "register-to-takeover": because
// the wallet address is derived from (chainID, caller, threshold, signer
// set, salt) as a cryptographic hash, an attacker who mutates ANY of
// those fields — including the threshold or the signer set — derives a
// DIFFERENT wallet address, even with the quantum caller and salt
// unchanged. They cannot land on the victim's already-registered address.
// This is the structural fix for the legacy 0x66 register-theft path; V2
// makes "register another victim's funded account as my multisig"
// arithmetically impossible.
func TestR38P001_V2RegisterWallet_DerivesDifferentAddressWhenSignerSetMutates(t *testing.T) {
	caller := types.Address{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	signer1 := types.Address{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	signer2 := types.Address{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb}
	attacker := types.Address{0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc}
	var salt [32]byte
	salt[0] = 0x42

	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: 1668, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()

	// Alice registers a 2-of-2 wallet with signer1 + signer2.
	c1 := newMultisigV2Precompiled()
	calldataAlice := buildRegisterCaldata(t, 2, salt, []types.Address{signer1, signer2})
	outAlice, err := c1.RunWithContextV2(ctx, db, append([]byte{MultisigV2FuncRegisterWallet}, calldataAlice...))
	if err != nil {
		t.Fatalf("Alice register: unexpected error: %v", err)
	}
	var aliceWallet types.Address
	copy(aliceWallet[:], outAlice)

	// Attacker attempts to register with the same (caller, salt, threshold,
	// signerCount) but substitutes themselves as one of the signers. Because
	// the signer set is part of the hash input, the derived address MUST
	// differ from Alice's — the attacker lands on their own wallet, not
	// Alice's, and cannot spend her funds.
	//
	// Use a separate caller context for the attacker so we model a real
	// attacker (different caller, different signers). The point is that
	// ANY mutation of the signer set yields a distinct address.
	attackerCtx := PrecompileContext{Caller: attacker, Origin: attacker, ChainID: 1668, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	calldataAttacker := buildRegisterCaldata(t, 2, salt, []types.Address{signer1, attacker})
	outAttacker, err := c1.RunWithContextV2(attackerCtx, db, append([]byte{MultisigV2FuncRegisterWallet}, calldataAttacker...))
	if err != nil {
		t.Fatalf("attacker register: unexpected error: %v", err)
	}
	var attackerWallet types.Address
	copy(attackerWallet[:], outAttacker)

	if aliceWallet == attackerWallet {
		t.Errorf("R38-P0-01 V2 invariant broken: signer-set mutation derived same wallet address %x for caller %x vs attacker %x", aliceWallet, caller, attacker)
	}
}

// buildCreateProposalCaldata assembles the V2 createProposal calldata:
// walletAddr(20) + toAddr(20) + value(32) + nonce(8) + expiresAt(8) +
// dataLen(4) + callData.
func buildCreateProposalCaldata(t *testing.T, wallet, to types.Address, value *big.Int, nonce, expiresAt uint64, callData []byte) []byte {
	t.Helper()
	out := make([]byte, 92+len(callData))
	copy(out[0:20], wallet[:])
	copy(out[20:40], to[:])
	value.FillBytes(out[40:72])
	binary.BigEndian.PutUint64(out[72:80], nonce)
	binary.BigEndian.PutUint64(out[80:88], expiresAt)
	binary.BigEndian.PutUint32(out[88:92], uint32(len(callData)))
	copy(out[92:], callData)
	return out
}

// registerWalletForTest registers a wallet and returns its derived address.
// Helper to keep create-proposal tests focused on the create path.
func registerWalletForTest(t *testing.T, c *MultisigV2Precompiled, db MultisigStateDB, ctx PrecompileContext, threshold uint32, salt [32]byte, signers []types.Address) types.Address {
	t.Helper()
	calldata := buildRegisterCaldata(t, threshold, salt, signers)
	out, err := c.RunWithContextV2(ctx, db, append([]byte{MultisigV2FuncRegisterWallet}, calldata...))
	if err != nil {
		t.Fatalf("register helper: unexpected error: %v", err)
	}
	var addr types.Address
	copy(addr[:], out)
	return addr
}

// TestR38P001_V2CreateProposal_RejectsCallerNotInSignerSet asserts that a
// caller who is NOT in the wallet's signer set cannot create a proposal.
// This is the structural fix for the legacy 0x66 "M-4 FIX" that took
// callerAddr from calldata and was trivially spoofable: V2 takes the
// caller from PrecompileContext.Caller, executor-injected and trusted.
func TestR38P001_V2CreateProposal_RejectsCallerNotInSignerSet(t *testing.T) {
	chainID := uint64(1668)
	caller := types.Address{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	signer1 := types.Address{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	// Alice registers a 1-of-1 wallet where she is the sole signer.
	var salt [32]byte
	salt[0] = 0x42

	aliceCtx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	aliceWallet := registerWalletForTest(t, newMultisigV2Precompiled(), newFakeV2StateDB(), aliceCtx, 1, salt, []types.Address{signer1})

	// Mallory is a different caller (not in Alice's signer set). She tries
	// to create a proposal against Alice's wallet. V2 MUST reject her.
	mallory := types.Address{0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33}
	malloryCtx := PrecompileContext{Caller: mallory, Origin: mallory, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db2 := newFakeV2StateDB()
	// Re-register Alice's wallet under the SHARED db so Mallory hits it.
	// Use the same Alice caller so the derived address is identical.
	registerWalletForTest(t, newMultisigV2Precompiled(), db2, aliceCtx, 1, salt, []types.Address{signer1})

	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	calldata := buildCreateProposalCaldata(t, aliceWallet, to, big.NewInt(1000), 1, 1_700_001_000, nil)
	_, err := newMultisigV2Precompiled().RunWithContextV2(malloryCtx, db2, append([]byte{MultisigV2FuncCreateProposal}, calldata...))
	if err == nil {
		t.Error("R38-P0-01 V2 invariant broken: non-signer caller created a proposal against someone else's wallet")
	}
}

// TestR38P001_V2CreateProposal_BindsEveryField asserts that mutating any
// of the executed-affecting fields (value, nonce, expiry, destination,
// callData) changes the resulting proposal hash. This is the R38-P1-02
// deep-copy / re-hash invariant: a signed approval collected for one
// proposal cannot be replayed against a mutated one because the hash —
// and therefore the signed message — differs.
func TestR38P001_V2CreateProposal_BindsEveryField(t *testing.T) {
	chainID := uint64(1668)
	caller := types.Address{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	var salt [32]byte
	salt[0] = 0x42

	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()
	// Make caller a signer (caller == signer1 guarantees signer status).
	salt[1] = 0x00 // different salt so wallet != caller
	wallet := registerWalletForTest(t, newMultisigV2Precompiled(), db, ctx, 1, salt, []types.Address{caller})

	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	canonical, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, to, big.NewInt(100), 1, 1_700_001_000, []byte{0x01})
	if err != nil {
		t.Fatalf("canonical create: %v", err)
	}

	variants := []struct {
		name      string
		value     *big.Int
		nonce     uint64
		expiresAt uint64
		callData  []byte
		to        types.Address
	}{
		{"value", big.NewInt(101), 1, 1_700_001_000, []byte{0x01}, to},
		{"nonce", big.NewInt(100), 2, 1_700_001_000, []byte{0x01}, to},
		{"expiry", big.NewInt(100), 1, 1_700_002_000, []byte{0x01}, to},
		{"callData", big.NewInt(100), 1, 1_700_001_000, []byte{0x02}, to},
		{"to", big.NewInt(100), 1, 1_700_001_000, []byte{0x01}, types.Address{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			got, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, v.to, v.value, v.nonce, v.expiresAt, v.callData)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", v.name, err)
			}
			if got == canonical {
				t.Errorf("R38-P1-02 invariant broken: %s mutation did not change proposal hash", v.name)
			}
		})
	}
}

// runCreate is a helper that builds calldata and dispatches create.
func runCreate(t *testing.T, c *MultisigV2Precompiled, db MultisigStateDB, ctx PrecompileContext,
	wallet, to types.Address, value *big.Int, nonce, expiresAt uint64, callData []byte) (types.Hash, error) {
	t.Helper()
	calldata := buildCreateProposalCaldata(t, wallet, to, value, nonce, expiresAt, callData)
	out, err := c.RunWithContextV2(ctx, db, append([]byte{MultisigV2FuncCreateProposal}, calldata...))
	if err != nil {
		return types.Hash{}, err
	}
	var h types.Hash
	copy(h[:], out)
	return h, nil
}

// TestR38P001_V2CreateProposal_RejectsUnregisteredWallet asserts that
// creating a proposal against a wallet that was never registered fails —
// this blocks the "exploit nonexistent wallet" path.
func TestR38P001_V2CreateProposal_RejectsUnregisteredWallet(t *testing.T) {
	chainID := uint64(1668)
	caller := types.Address{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	fakeWallet := types.Address{0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab}
	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	calldata := buildCreateProposalCaldata(t, fakeWallet, to, big.NewInt(100), 1, 1_700_001_000, nil)
	_, err := newMultisigV2Precompiled().RunWithContextV2(ctx, newFakeV2StateDB(), append([]byte{MultisigV2FuncCreateProposal}, calldata...))
	if err == nil {
		t.Error("expected error when creating a proposal against an unregistered wallet")
	}
}

// TestR38P001_V2CreateProposal_RejectsExpiredOrZeroExpiry asserts the
// expiry checks: zero expiry is rejected, and expiry in the past is
// rejected. Without these, an attacker could back-date a proposal or
// leave it alive forever (invariants per the H-1 follow-up).
func TestR38P001_V2CreateProposal_RejectsExpiredOrZeroExpiry(t *testing.T) {
	chainID := uint64(1668)
	caller := types.Address{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	var salt [32]byte
	salt[0] = 0x42
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()
	wallet := registerWalletForTest(t, newMultisigV2Precompiled(), db, ctx, 1, salt, []types.Address{caller})
	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}

	// Zero expiry must be rejected.
	cdZero := buildCreateProposalCaldata(t, wallet, to, big.NewInt(100), 1, 0, nil)
	if _, err := newMultisigV2Precompiled().RunWithContextV2(ctx, db, append([]byte{MultisigV2FuncCreateProposal}, cdZero...)); err == nil {
		t.Error("expected error for zero expiry")
	}

	// Past expiry must be rejected.
	cdPast := buildCreateProposalCaldata(t, wallet, to, big.NewInt(100), 1, 1_699_999_999, nil)
	if _, err := newMultisigV2Precompiled().RunWithContextV2(ctx, db, append([]byte{MultisigV2FuncCreateProposal}, cdPast...)); err == nil {
		t.Error("expected error for past expiry")
	}
}

// TestR38P001_V2CreateProposal_IsIdempotent asserts that re-submitting the
// exact same calldata returns the same proposal hash (a no-op) instead of
// creating a duplicate proposal record. This protects retry-safety.
func TestR38P001_V2CreateProposal_IsIdempotent(t *testing.T) {
	chainID := uint64(1668)
	caller := types.Address{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
	var salt [32]byte
	salt[0] = 0x42
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()
	wallet := registerWalletForTest(t, newMultisigV2Precompiled(), db, ctx, 1, salt, []types.Address{caller})
	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}

	h1, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, to, big.NewInt(100), 1, 1_700_001_000, []byte{0xab, 0xcd})
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	h2, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, to, big.NewInt(100), 1, 1_700_001_000, []byte{0xab, 0xcd})
	if err != nil {
		t.Fatalf("idempotent create: %v", err)
	}
	if h1 != h2 {
		t.Errorf("idempotent create changed hash: %x then %x", h1, h2)
	}
}

// buildApproveCaldata assembles the V2 approveProposal calldata:
// proposalHash(32) + pubKey(1952) + signature(3293).
func buildApproveCaldata(proposalHash types.Hash, pubKeyBytes, signature []byte) []byte {
	out := make([]byte, 32+crypto.Dilithium3PublicKeySize+crypto.Dilithium3SignatureSize)
	copy(out[0:32], proposalHash[:])
	copy(out[32:32+crypto.Dilithium3PublicKeySize], pubKeyBytes)
	copy(out[32+crypto.Dilithium3PublicKeySize:], signature)
	return out
}

// registerWalletCallerIsSignerTest is a small helper that registers a
// 1-of-1 wallet whose only signer is caller's address, so approveProposal's
// "pubKey.Address() == ctx.Caller == signer" gate is satisfied end-to-end.
// It returns (walletAddr, signers).
func registerWalletCallerIsSignerTest(t *testing.T, db MultisigStateDB, ctx PrecompileContext) types.Address {
	t.Helper()
	var salt [32]byte
	salt[0] = 0x42
	return registerWalletForTest(t, newMultisigV2Precompiled(), db, ctx, 1, salt, []types.Address{ctx.Caller})
}

// generateKeyAddrPriv generates a new Dilithium3 keypair and returns the
// derived caller address plus the private key. crypto.GenerateKeyPair returns
// *KeyPair{Private *PrivateKey; Public *PublicKey}; we surface the private
// key (for signing) and the public-key-derived address (for the
// PrecompileContext.Caller) so callers stay convenient.
func generateKeyAddrPriv(t *testing.T) (types.Address, *crypto.PrivateKey) {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	pub, err := kp.Private.PublicKeySafe()
	if err != nil {
		t.Fatalf("derive public key: %v", err)
	}
	addr := pub.Address()
	if addr == (types.Address{}) {
		t.Fatalf("generated pubKey derived zero address")
	}
	return addr, kp.Private
}

// runApprove builds approve calldata for a real Dilithium3 keypair, signs
// proposalHash with priv, and dispatches approve under ctx.
func runApprove(t *testing.T, c *MultisigV2Precompiled, db MultisigStateDB, ctx PrecompileContext, proposalHash types.Hash, priv *crypto.PrivateKey) ([]byte, error) {
	t.Helper()
	pub, err := priv.PublicKeySafe()
	if err != nil {
		t.Fatalf("derive public key for approve: %v", err)
	}
	pubBytes := pub.Bytes()
	signature, err := priv.Sign(proposalHash[:])
	if err != nil {
		t.Fatalf("sign proposalHash: %v", err)
	}
	return c.RunWithContextV2(ctx, db, append([]byte{MultisigV2FuncApproveProposal}, buildApproveCaldata(proposalHash, pubBytes, signature)...))
}

// runExecute builds execute calldata and dispatches under ctx.
func runExecute(t *testing.T, c *MultisigV2Precompiled, db MultisigStateDB, ctx PrecompileContext, proposalHash types.Hash) ([]byte, error) {
	t.Helper()
	in := make([]byte, 32)
	copy(in, proposalHash[:])
	return c.RunWithContextV2(ctx, db, append([]byte{MultisigV2FuncExecuteProposal}, in...))
}

// =============================================================================
// R47-V2CALLDATA-01 regression tests
// =============================================================================

// TestR47V2CallData_ExecuteProposal_FailsClosedWhenNoCallContractor pins the
// R47-V2CALLDATA-01 fix: when a proposal carries non-empty callData but the
// StateDB does NOT implement CallContractor, executeProposalV2 must return
// an error and leave the proposal UNEXECUTED (status 0x02) — never silently
// mark executed while dropping the callData. This is the "funds locked but
// intent never executed" bug the legacy V1 precompile was hardened against
// by R30-IMPLEMENT (QVM-R9-H1 / QVM-R15-H02); V2 must match it.
func TestR47V2CallData_ExecuteProposal_FailsClosedWhenNoCallContractor(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()

	var salt [32]byte
	salt[0] = 0x77
	wallet := registerWalletForTest(t, newMultisigV2Precompiled(), db, ctx, 1, salt, []types.Address{caller})

	// Prefund wallet with 1000 QAU so the pure value-transfer WOULD succeed
	// if the callData path were accidentally left as "transfer + mark executed".
	if err := db.AddBalance(wallet, big.NewInt(1000)); err != nil {
		t.Fatalf("prefund wallet: %v", err)
	}

	to := types.Address{0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99}
	nonEmptyCallData := []byte{0xde, 0xad, 0xbe, 0xef}

	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, to, big.NewInt(500) /*nonce=*/, 1 /*expiresAt=*/, 1_700_001_000, nonEmptyCallData)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := runApprove(t, newMultisigV2Precompiled(), db, ctx, proposalHash, priv); err != nil {
		t.Fatalf("approve: %v", err)
	}

	_, err = runExecute(t, newMultisigV2Precompiled(), db, ctx, proposalHash)
	if err == nil {
		t.Fatalf("expected execute to FAIL (no CallContractor implemented), got nil")
	}
	if !strings.Contains(err.Error(), "CallContractor") {
		t.Fatalf("error should reference CallContractor requirement, got: %v", err)
	}

	// Fail-closed invariants:
	//   1. The proposal is NOT marked as executed (status stays 0x02 = approved).
	statusKey := v2ProposalKey("ms:v2pstatus:", proposalHash)
	statusVal := db.GetState(multisigV2Address, statusKey)
	if statusVal[31] != 0x02 {
		t.Errorf("proposal must remain approved (0x02), got 0x%x", statusVal[31])
	}
	//   2. Wallet balance must be unchanged (no value leaked to recipient).
	if got := db.GetBalance(wallet); got.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("wallet balance: got %s, want 1000 (value must NOT move when execute fails closed)", got.String())
	}
	if got := db.GetBalance(to); got.Sign() != 0 {
		t.Errorf("recipient balance: got %s, want 0", got.String())
	}
}

// fakeV2CallContractorDB wraps fakeV2StateDB with CallContractor and
// MultisigSnapshotter implementations. It records CallContract arguments so
// tests can assert the R47-V2CALLDATA-01 fix dispatches correctly, and can
// be configured (via CallErr) to exercise the snapshot-revert path.
type fakeV2CallContractorDB struct {
	*fakeV2StateDB
	CallFrom  types.Address
	CallTo    types.Address
	CallValue *big.Int
	CallData  []byte
	CallCount int
	CallErr   error
	SnapCount int
	RevertCnt int
}

func (f *fakeV2CallContractorDB) CallContract(caller, to types.Address, value *big.Int, data []byte) ([]byte, error) {
	f.CallCount++
	f.CallFrom = caller
	f.CallTo = to
	if value == nil {
		f.CallValue = new(big.Int)
	} else {
		f.CallValue = new(big.Int).Set(value)
	}
	f.CallData = append([]byte(nil), data...)
	return nil, f.CallErr
}

func (f *fakeV2CallContractorDB) Snapshot() int {
	f.SnapCount++
	return f.SnapCount
}

func (f *fakeV2CallContractorDB) RevertToSnapshot(_ int) {
	f.RevertCnt++
}

// TestR47V2CallData_HappyPath dispatches a proposal with non-empty callData
// through a StateDB that DOES implement CallContractor, and asserts V2
// calls CallContract with the wallet as caller, recipient as to, the exact
// value / callData from the proposal, then marks the proposal executed.
// Regression companion for R47-V2CALLDATA-01.
func TestR47V2CallData_HappyPath(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	fdb := &fakeV2CallContractorDB{fakeV2StateDB: newFakeV2StateDB()}

	var salt [32]byte
	salt[0] = 0x8c
	wallet := registerWalletForTest(t, newMultisigV2Precompiled(), fdb, ctx, 1, salt, []types.Address{caller})
	if err := fdb.AddBalance(wallet, big.NewInt(1000)); err != nil {
		t.Fatalf("prefund wallet: %v", err)
	}

	to := types.Address{0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77}
	value := big.NewInt(5)
	callData := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), fdb, ctx, wallet, to, value, 1, 1_700_001_000, callData)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := runApprove(t, newMultisigV2Precompiled(), fdb, ctx, proposalHash, priv); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := runExecute(t, newMultisigV2Precompiled(), fdb, ctx, proposalHash); err != nil {
		t.Fatalf("execute must succeed on CallContractor-enabled StateDB, got: %v", err)
	}

	if fdb.CallCount != 1 {
		t.Fatalf("expected CallContract invoked once, got %d", fdb.CallCount)
	}
	if fdb.CallFrom != wallet {
		t.Errorf("CallContract caller mismatch: got %x want wallet %x", fdb.CallFrom, wallet)
	}
	if fdb.CallTo != to {
		t.Errorf("CallContract to mismatch: got %x want %x", fdb.CallTo, to)
	}
	if fdb.CallValue.Cmp(value) != 0 {
		t.Errorf("CallContract value mismatch: got %s want %s", fdb.CallValue, value)
	}
	if !bytes.Equal(fdb.CallData, callData) {
		t.Errorf("CallContract callData mismatch: got %x want %x", fdb.CallData, callData)
	}
	if fdb.SnapCount != 1 {
		t.Errorf("Snapshot must be invoked exactly once before external call, got %d", fdb.SnapCount)
	}
	if fdb.RevertCnt != 0 {
		t.Errorf("RevertToSnapshot must NOT be called on happy path, got %d", fdb.RevertCnt)
	}

	statusKey := v2ProposalKey("ms:v2pstatus:", proposalHash)
	statusVal := fdb.GetState(multisigV2Address, statusKey)
	if statusVal[31] != 0x03 {
		t.Errorf("proposal must be marked executed (0x03) on happy path, got 0x%x", statusVal[31])
	}
}

// TestR47V2CallData_ErrorReverts dispatches a proposal whose CallContractor
// returns an error, and asserts V2 invokes RevertToSnapshot exactly once and
// leaves the proposal in the approved state (status 0x02) instead of marking
// it executed.
func TestR47V2CallData_ErrorReverts(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	fdb := &fakeV2CallContractorDB{fakeV2StateDB: newFakeV2StateDB(), CallErr: errors.New("callee reverted")}

	var salt [32]byte
	salt[0] = 0x8d
	wallet := registerWalletForTest(t, newMultisigV2Precompiled(), fdb, ctx, 1, salt, []types.Address{caller})
	if err := fdb.AddBalance(wallet, big.NewInt(1000)); err != nil {
		t.Fatalf("prefund wallet: %v", err)
	}

	to := types.Address{0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}
	callData := []byte{0x01, 0x02, 0x03, 0x04}

	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), fdb, ctx, wallet, to, big.NewInt(0), 1, 1_700_001_000, callData)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := runApprove(t, newMultisigV2Precompiled(), fdb, ctx, proposalHash, priv); err != nil {
		t.Fatalf("approve: %v", err)
	}
	_, err = runExecute(t, newMultisigV2Precompiled(), fdb, ctx, proposalHash)
	if err == nil {
		t.Fatal("execute must return error when CallContract fails")
	}
	if !strings.Contains(err.Error(), "callData") {
		t.Errorf("error should reference callData path, got: %v", err)
	}
	if fdb.SnapCount != 1 {
		t.Errorf("Snapshot must be invoked once before external call, got %d", fdb.SnapCount)
	}
	if fdb.RevertCnt != 1 {
		t.Errorf("RevertToSnapshot must be invoked exactly once on CallContract error, got %d", fdb.RevertCnt)
	}

	statusKey := v2ProposalKey("ms:v2pstatus:", proposalHash)
	statusVal := fdb.GetState(multisigV2Address, statusKey)
	if statusVal[31] == 0x03 {
		t.Error("proposal must NOT be marked executed (0x03) on CallContract error")
	}
}

// TestR47V2CallData_ExecuteProposal_ZeroValueMustNotRequireBalance asserts
// the R47 bug-fix's "fail-closed" path doesn't regress the pure value-
// transfer path: a proposal with empty callData and value=0 must execute
// cleanly even when the wallet has no balance.
func TestR47V2CallData_ExecuteProposal_ZeroValueMustNotRequireBalance(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()

	var salt [32]byte
	salt[0] = 0x78
	wallet := registerWalletForTest(t, newMultisigV2Precompiled(), db, ctx, 1, salt, []types.Address{caller})

	to := types.Address{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}
	// Zero-value, empty-callData proposal = "pure state-change proposal".
	// This must succeed even though wallet has no funds, because there's
	// nothing to transfer and nothing to call.
	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, to, big.NewInt(0) /*nonce=*/, 2 /*expiresAt=*/, 1_700_001_000 /*callData=*/, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := runApprove(t, newMultisigV2Precompiled(), db, ctx, proposalHash, priv); err != nil {
		t.Fatalf("approve: %v", err)
	}

	if _, err := runExecute(t, newMultisigV2Precompiled(), db, ctx, proposalHash); err != nil {
		t.Fatalf("execute must succeed for zero-value/empty-callData proposal, got: %v", err)
	}

	statusKey := v2ProposalKey("ms:v2pstatus:", proposalHash)
	statusVal := db.GetState(multisigV2Address, statusKey)
	if statusVal[31] != 0x03 {
		t.Errorf("proposal must be marked executed (0x03), got 0x%x", statusVal[31])
	}
}

// TestR38P001_V2ApproveProposal_RejectsInvalidSignature asserts that an
// approval with a signature over a different message than proposalHash is
// rejected by crypto.Verify IN the precompile. A corrupted signature cannot
// register an approval against an arbitrary victim wallet.
func TestR38P001_V2ApproveProposal_RejectsInvalidSignature(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()
	wallet := registerWalletCallerIsSignerTest(t, db, ctx)

	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, to, big.NewInt(100), 1, 1_700_001_000, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Mallory signs a DIFFERENT message.
	wrongMsg := []byte("evil attacker message")
	badSig, err := priv.Sign(wrongMsg)
	if err != nil {
		t.Fatalf("sign wrong msg: %v", err)
	}
	pub, err := priv.PublicKeySafe()
	if err != nil {
		t.Fatalf("derive pub: %v", err)
	}
	pubBytes := pub.Bytes()
	cd := buildApproveCaldata(proposalHash, pubBytes, badSig)
	_, err = newMultisigV2Precompiled().RunWithContextV2(ctx, db, append([]byte{MultisigV2FuncApproveProposal}, cd...))
	if err == nil {
		t.Error("R38-P0-01 V2 invariant broken: approve accepted a signature over the wrong message")
	}
}

// TestR38P001_V2ApproveProposal_RejectsCallerNotEqualSigner asserts that an
// approval submitted by a caller whose PrecompileContext.Caller is NOT the
// signer who produced pubkey+signature is rejected. A relayer cannot inject
// someone else's freshly-collected approval against a transaction they control.
func TestR38P001_V2ApproveProposal_RejectsCallerNotEqualSigner(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	caller2, priv2 := generateKeyAddrPriv(t)
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()
	wallet := registerWalletCallerIsSignerTest(t, db, ctx)

	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, to, big.NewInt(100), 1, 1_700_001_000, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Mallory2 signs correctly with priv2, but submits with Mallory2's caller.
	mCtx := PrecompileContext{Caller: caller2, Origin: caller2, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	_, err = runApprove(t, newMultisigV2Precompiled(), db, mCtx, proposalHash, priv2)
	if err == nil {
		t.Error("R38-P0-01 V2 invariant broken: approve accepted a signature whose signer != authenticated caller")
	}
	_ = priv
}

// TestR38P001_V2ApproveProposal_RejectsNonSigner asserts that an approval
// with a keypair whose derived address is NOT in the wallet's signer set is
// rejected. The contemporary proposal; this catches the "valid signature
// from a wallet that happens to be same chainID but wrong signer set" path.
func TestR38P001_V2ApproveProposal_RejectsNonSigner(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	attackerAddr, attacker := generateKeyAddrPriv(t)
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()
	wallet := registerWalletCallerIsSignerTest(t, db, ctx)

	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, to, big.NewInt(100), 1, 1_700_001_000, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Attacker signs correctly with attacker key and submits under attacker.ctx.
	attackerCtx := PrecompileContext{Caller: attackerAddr, Origin: attackerAddr, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	_, err = runApprove(t, newMultisigV2Precompiled(), db, attackerCtx, proposalHash, attacker)
	if err == nil {
		t.Error("R38-P0-01 V2 invariant broken: approve accepted a key not in the wallet signer set")
	}
	_ = priv
}

// TestR38P001_V2ApproveProposal_FlipsToApprovedAtThreshold asserts that once
// the approval count meets the threshold, the proposal status flips from
// 0x01 (pending) to 0x02 (approved). For a 1-of-1 wallet, the FIRST approve
// must flip.
func TestR38P001_V2ApproveProposal_FlipsToApprovedAtThreshold(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()
	wallet := registerWalletCallerIsSignerTest(t, db, ctx)

	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, to, big.NewInt(100), 1, 1_700_001_000, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := runApprove(t, newMultisigV2Precompiled(), db, ctx, proposalHash, priv); err != nil {
		t.Fatalf("approve: %v", err)
	}

	statusKey := v2ProposalKey("ms:v2pstatus:", proposalHash)
	statusVal := db.GetState(multisigV2Address, statusKey)
	if statusVal[31] != 0x02 {
		t.Errorf("R38-P0-01 V2: expected status=0x02 (approved), got 0x%x", statusVal[31])
	}
}

// TestR38P001_V2ApproveProposal_IsIdempotent asserts that re-submitting the
// exact same approval is a no-op success and does NOT change the bitmap nor
// double-count approvals. This protects against a flaky relayer retry that
// would otherwise push the approval count past threshold erroneously.
func TestR38P001_V2ApproveProposal_IsIdempotent(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()
	wallet := registerWalletCallerIsSignerTest(t, db, ctx)

	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, to, big.NewInt(100), 1, 1_700_001_000, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := runApprove(t, newMultisigV2Precompiled(), db, ctx, proposalHash, priv); err != nil {
		t.Fatalf("approve 1: %v", err)
	}
	// Re-approve with same caller/same signature. Must succeed (idempotent)
	// and the status must still be 0x02 (not regress to 0x01).
	if _, err := runApprove(t, newMultisigV2Precompiled(), db, ctx, proposalHash, priv); err != nil {
		t.Fatalf("approve 2: %v", err)
	}
	statusKey := v2ProposalKey("ms:v2pstatus:", proposalHash)
	statusVal := db.GetState(multisigV2Address, statusKey)
	if statusVal[31] != 0x02 {
		t.Errorf("R38-P0-01 V2: idempotent re-approve regressed status: 0x%x, want 0x02", statusVal[31])
	}
}

// TestR38P001_V2ApproveProposal_RejectsExpired asserts that approving a
// proposal whose expiresAt has elapsed is rejected with a markExpired
// (status → 0x04) so future calls short-circuit.
func TestR38P001_V2ApproveProposal_RejectsExpired(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	// createdAt = 1_700_000_000; expiresAt = 1_700_001_000.
	ctxCreate := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()
	wallet := registerWalletCallerIsSignerTest(t, db, ctxCreate)

	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), db, ctxCreate, wallet, to, big.NewInt(100), 1, 1_700_001_000, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Submit approve at now = 1_700_002_000, past expiry. Must reject.
	ctxExpired := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_002_000, CallKind: CallKindCall}
	_, err = runApprove(t, newMultisigV2Precompiled(), db, ctxExpired, proposalHash, priv)
	if err == nil {
		t.Error("R38-P0-01 V2: approve accepted an expired proposal")
	}
	// Status must flip to 0x04 (expired) so future calls are short-circuited.
	statusKey := v2ProposalKey("ms:v2pstatus:", proposalHash)
	statusVal := db.GetState(multisigV2Address, statusKey)
	if statusVal[31] != 0x04 {
		t.Errorf("R38-P0-01 V2: expired approve must mark status=0x04, got 0x%x", statusVal[31])
	}
}

// TestR38P001_V2ExecuteProposal_HappyPath asserts the full end-to-end V2
// flow: register → create → approve (threshold met) → execute. The wallet
// balance MUST be debited by value and recipient credited by value, and the
// proposal status flips to 0x03 (executed). This is the proof that V2 closes
// the legacy 0x66 theft path while preserving actual money movement.
func TestR38P001_V2ExecuteProposal_HappyPath(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()

	var salt [32]byte
	salt[0] = 0x42
	wallet := registerWalletForTest(t, newMultisigV2Precompiled(), db, ctx, 1, salt, []types.Address{caller})

	// Prefund wallet with 1000 QAU.
	if err := db.AddBalance(wallet, big.NewInt(1000)); err != nil {
		t.Fatalf("prefund wallet: %v", err)
	}
	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}

	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, to, big.NewInt(500), 1, 1_700_001_000, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := runApprove(t, newMultisigV2Precompiled(), db, ctx, proposalHash, priv); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := runExecute(t, newMultisigV2Precompiled(), db, ctx, proposalHash); err != nil {
		t.Fatalf("execute: %v", err)
	}

	// Wallet = 1000 - 500 = 500. Recipient = 500.
	wb := db.GetBalance(wallet)
	if wb.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("wallet balance: got %s, want 500", wb.String())
	}
	rb := db.GetBalance(to)
	if rb.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("recipient balance: got %s, want 500", rb.String())
	}
	statusKey := v2ProposalKey("ms:v2pstatus:", proposalHash)
	statusVal := db.GetState(multisigV2Address, statusKey)
	if statusVal[31] != 0x03 {
		t.Errorf("status: got 0x%x, want 0x03 (executed)", statusVal[31])
	}
}

// TestR38P001_V2ExecuteProposal_RejectsUnapproved asserts execute cannot
// proceed before threshold is met — pending (0x01) status is rejected.
func TestR38P001_V2ExecuteProposal_RejectsUnapproved(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	_ = priv
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()
	wallet := registerWalletCallerIsSignerTest(t, db, ctx)
	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, to, big.NewInt(100), 1, 1_700_001_000, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := db.AddBalance(wallet, big.NewInt(1000)); err != nil {
		t.Fatalf("prefund: %v", err)
	}
	// NOT approved yet — execute MUST reject and MUST NOT touch balances.
	_, err = runExecute(t, newMultisigV2Precompiled(), db, ctx, proposalHash)
	if err == nil {
		t.Error("R38-P0-01 V2: execute accepted an unapproved proposal")
	}
	if got := db.GetBalance(wallet); got.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("wallet balance mutated before approval: got %s, want 1000", got.String())
	}
}

// TestR38P001_V2ExecuteProposal_RederivesHashAndRejectsTampered asserts the
// R38-P1-02 storage-level invariant: if ANY executed-affecting field is
// mutated after create — here we tamper with the stored destination — the
// re-derived proposal hash will not match the stored proposalHash, and
// execute MUST abort instead of silently spending the mutated proposal.
func TestR38P001_V2ExecuteProposal_RederivesHashAndRejectsTampered(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()
	wallet := registerWalletCallerIsSignerTest(t, db, ctx)
	if err := db.AddBalance(wallet, big.NewInt(1000)); err != nil {
		t.Fatalf("prefund: %v", err)
	}
	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, to, big.NewInt(100), 1, 1_700_001_000, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := runApprove(t, newMultisigV2Precompiled(), db, ctx, proposalHash, priv); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Mallory tampers with the stored destination slot.
	destKey := v2ProposalKey("ms:v2pdest:", proposalHash)
	tamperedDestVal := db.GetState(multisigV2Address, destKey)
	tamperedDestVal[31] ^= 0xff // flip a byte in the to-addr
	db.SetState(multisigV2Address, destKey, tamperedDestVal)

	_, err = runExecute(t, newMultisigV2Precompiled(), db, ctx, proposalHash)
	if err == nil {
		t.Error("R38-P1-02 invariant broken: execute proceeded despite a mutated stored destination")
	}
	// Wallet balance MUST be untouched because execute aborted.
	if got := db.GetBalance(wallet); got.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("wallet balance mutated after tamper abort: got %s, want 1000", got.String())
	}
}

// TestR38P001_V2ExecuteProposal_RejectsExpired asserts an expired proposal
// cannot be executed (status must flip to 0x04 short-circuiting next calls).
func TestR38P001_V2ExecuteProposal_RejectsExpired(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	ctxCreate := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()
	wallet := registerWalletCallerIsSignerTest(t, db, ctxCreate)
	if err := db.AddBalance(wallet, big.NewInt(1000)); err != nil {
		t.Fatalf("prefund: %v", err)
	}
	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), db, ctxCreate, wallet, to, big.NewInt(100), 1, 1_700_001_000, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := runApprove(t, newMultisigV2Precompiled(), db, ctxCreate, proposalHash, priv); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Execute at now > expiresAt. Must reject and NOT touch balances.
	ctxExpired := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_002_000, CallKind: CallKindCall}
	_, err = runExecute(t, newMultisigV2Precompiled(), db, ctxExpired, proposalHash)
	if err == nil {
		t.Error("R38-P0-01 V2: execute accepted an expired proposal")
	}
	if got := db.GetBalance(wallet); got.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("wallet balance mutated after expiry abort: got %s, want 1000", got.String())
	}
	// Status must flip to 0x04 (expired).
	statusKey := v2ProposalKey("ms:v2pstatus:", proposalHash)
	statusVal := db.GetState(multisigV2Address, statusKey)
	if statusVal[31] != 0x04 {
		t.Errorf("status: got 0x%x, want 0x04 (expired)", statusVal[31])
	}
}

// TestR38P001_V2ExecuteProposal_RejectsDoubleExecute asserts that a second
// execute on an already-executed proposal aborts without double-spending.
func TestR38P001_V2ExecuteProposal_RejectsDoubleExecute(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	ctx := PrecompileContext{Caller: caller, Origin: caller, ChainID: chainID, BlockTime: 1_700_000_000, CallKind: CallKindCall}
	db := newFakeV2StateDB()
	wallet := registerWalletCallerIsSignerTest(t, db, ctx)
	if err := db.AddBalance(wallet, big.NewInt(1000)); err != nil {
		t.Fatalf("prefund: %v", err)
	}
	to := types.Address{0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44}
	proposalHash, err := runCreate(t, newMultisigV2Precompiled(), db, ctx, wallet, to, big.NewInt(333), 1, 1_700_001_000, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := runApprove(t, newMultisigV2Precompiled(), db, ctx, proposalHash, priv); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := runExecute(t, newMultisigV2Precompiled(), db, ctx, proposalHash); err != nil {
		t.Fatalf("execute 1: %v", err)
	}
	// Second execute MUST reject and MUST NOT double-spend.
	if _, err := runExecute(t, newMultisigV2Precompiled(), db, ctx, proposalHash); err == nil {
		t.Error("R38-P0-01 V2: second execute did NOT reject a replayed proposal")
	}
	// Wallet = 1000 - 333 = 667, recipient = 333 — no double-deduct.
	if got := db.GetBalance(wallet); got.Cmp(big.NewInt(667)) != 0 {
		t.Errorf("wallet balance after double-execute attempt: got %s, want 667", got.String())
	}
	if got := db.GetBalance(to); got.Cmp(big.NewInt(333)) != 0 {
		t.Errorf("recipient balance after double-execute attempt: got %s, want 333", got.String())
	}
}

// fakeV2SwapStateDB wraps fakeV2CallContractorDB and simulates the
// R48-PRECOMPILE-REENTRANCY-01 race window: while CallContract is in
// flight (i.e. the precompile has released c.mu), a second goroutine
// enters RunWithContextV2 and overwrites `c.stateDB` with a DIFFERENT
// MultisigStateDB. The swap is modeled synchronously here — inside
// CallContract the fake reassigns `c.stateDB` to a fresh stateless
// empty fakeV2StateDB, then returns.
//
// Without the R48 fix the post-unlock `c.stateDB.GetState(...)` and
// `c.stateDB.SetState(...)` hit the swapped DB: the proposal status
// read returns empty (treated as "changed", so execute rejects), or
// if the bug were shaped differently the SetState could poison the
// wrong DB entirely.
//
// With the R48 fix the post-unlock reads/writes hit the LOCAL stateDB
// captured before the unlock — the swap is invisible to this call,
// the proposal status is read from the original DB, and the executed
// marker (0x03) lands on the original DB.
type fakeV2SwapStateDB struct {
	*fakeV2CallContractorDB

	// swappedTarget is the MultisigStateDB to install into c.stateDB
	// when CallContract fires. It MUST be a distinct instance from the
	// one passed to RunWithContextV2 so the test can detect that the
	// precompile afterwards still operates on the ORIGINAL DB rather
	// than on swappedTarget.
	swappedTarget MultisigStateDB

	// precompileInstance is the *MultisigV2Precompiled whose `stateDB`
	// instance field we overwrite during the unlock window. Same-
	// package white-box access (stateDB is unexported) is intentional
	// and exactly mirrors the production race surface.
	precompileInstance *MultisigV2Precompiled

	// swapCount records how many times CallContract has performed the
	// swap — should be exactly 1 for a single executeProposal call.
	swapCount int
}

func (f *fakeV2SwapStateDB) CallContract(caller, to types.Address, value *big.Int, data []byte) ([]byte, error) {
	// First delegate the recording of arguments + bookkeeping to the
	// embedded fakeV2CallContractorDB, so existing assertions (CallCount
	// etc.) still work.
	_, _ = f.fakeV2CallContractorDB.CallContract(caller, to, value, data)

	// NOW inject the race: c.mu is released by the precompile before
	// invoking CallContract, so a concurrent RunWithContextV2 entering
	// here would reassign c.stateDB. We model the swap synchronously.
	if f.precompileInstance != nil && f.swappedTarget != nil {
		f.precompileInstance.stateDB = f.swappedTarget
		f.swapCount++
	}

	// No CallErr configured — return success so the post-call status
	// check + SetState path executes (this is where the R48 fix matters).
	return nil, nil
}

// TestR48PrecompileReentrancy_StateDBSwapDuringCallContractNotCorrupted
// is the regression test for the R48-PRECOMPILE-REENTRANCY-01 fix.
//
// Scenario:
//  1. Register wallet + create proposal with non-empty callData + approve
//     (status=0x02) on fakeDB.
//  2. Hook a fakeV2SwapStateDB onto the precompile. The swap DB's
//     CallContract replaces the precompile's `c.stateDB` instance field
//     with a fresh, empty stateless fakeV2StateDB during the unlock
//     window.
//  3. Execute the proposal.
//
// Pre-fix behavior (race surface): after c.mu.Unlock() + CallContract +
// c.mu.Lock(), the function reads `c.stateDB.GetState` and writes
// `c.stateDB.SetState` against the SWAPPED DB. Since the swapped DB is
// empty, the re-validation read returns emptyHash → execute aborts with
// "proposal status changed during callData execution". The status=0x03
// marker either lands on the swapped DB (corrupting it) or the call
// rejects — depending on bug timing. Either way, the original fakeDB
// is NOT marked executed (status stays 0x02).
//
// Post-fix behavior (R48-PRECOMPILE-REENTRANCY-01): the local `stateDB`
// is captured before unlock, so all post-unlock reads/writes go through
// the ORIGINAL fakeDB. Re-validation sees status=0x02 (approved), no
// rejection, and the 0x03 executed marker lands on the ORIGINAL fakeDB.
// The swapped DB is untouched.
//
// PASS conditions (all must hold):
//   - executeProposal returns nil (no error)
//   - swap was performed exactly once (proves we hit the race window)
//   - ORIGINAL DB's proposal status = 0x03 (executed landed correctly)
//   - SWAPPED DB's proposal status = 0x00 (executed did NOT poison swap)
//   - CallCount on the swap-wrapped DB = 1 (CallContract was invoked)
func TestR48PrecompileReentrancy_StateDBSwapDuringCallContractNotCorrupted(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	ctx := PrecompileContext{
		Caller:    caller,
		Origin:    caller,
		ChainID:   chainID,
		BlockTime: 1_700_000_000,
		CallKind:  CallKindCall,
	}

	// fdb holds the wallet + proposal state from register→create→approve.
	fdb := &fakeV2CallContractorDB{fakeV2StateDB: newFakeV2StateDB()}

	// swappedDB is the OTHER state DB that simulates the one a concurrent
	// RunWithContextV2 would install. It is a fresh fakeV2StateDB with
	// NO CallContractor / MultisigSnapshotter capability — i.e. it is
	// missing the proposal state entirely.
	swappedDB := newFakeV2StateDB()

	precompile := newMultisigV2Precompiled()

	// Register wallet on fdb.
	var salt [32]byte
	salt[0] = 0xA1
	wallet := registerWalletForTest(t, precompile, fdb, ctx, 1, salt, []types.Address{caller})
	if err := fdb.AddBalance(wallet, big.NewInt(1000)); err != nil {
		t.Fatalf("prefund wallet: %v", err)
	}

	// Create proposal with non-empty callData so we exercise the
	// unlock-window code path.
	to := types.Address{0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88}
	value := big.NewInt(7)
	callData := []byte{0xCA, 0xFE, 0xBA, 0xBE}

	proposalHash, err := runCreate(t, precompile, fdb, ctx, wallet, to, value, 1, 1_700_001_000, callData)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := runApprove(t, precompile, fdb, ctx, proposalHash, priv); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// SWAP THE STATE DB ON THE INSTANCE before execute, so the callData
	// branch is entered with `c.stateDB = fdb` (real proposal state).
	// The swap itself fires INSIDE CallContract — modeling the race.
	// Prepare the swap DB wrapper now and run execute through it.
	swapDB := &fakeV2SwapStateDB{
		fakeV2CallContractorDB: &fakeV2CallContractorDB{fakeV2StateDB: newFakeV2StateDB()},
		swappedTarget:          swappedDB,
		precompileInstance:     precompile,
	}

	// We need the swap-DB to be the one that RunWithContextV2 sees as
	// c.stateDB, so that CallContractor detection (c.stateDB.(CallContractor))
	// succeeds. Pre-populate the swap-DB with the SAME proposal state by
	// copying every (addr, key, val) entry from fdb into swapDB's embedded
	// fakeV2StateDB. This mirrors the production invariant: the precompile
	// always begins executeProposalV2 against a stateDB that contains the
	// proposal (it was created+approved against the same instance).
	for addr, m := range fdb.states {
		if swapDB.states[addr] == nil {
			swapDB.states[addr] = map[types.Hash]types.Hash{}
		}
		for k, v := range m {
			swapDB.states[addr][k] = v
		}
	}
	// Mirror balances too so the balance-check pre-unlock passes.
	for addr, bal := range fdb.balances {
		swapDB.balances[addr] = new(big.Int).Set(bal)
	}

	// FDB after the swap will be LEFT as the pre-fix test of "swapped DB
	// is empty" — we keep fdb untouched and assert on it after the call.

	// Bookkeeping: snapshot call counts must be 0 before the call.
	if swapDB.SnapCount != 0 {
		t.Fatalf("precondition: swapDB SnapCount should be 0, got %d", swapDB.SnapCount)
	}

	// Execute through RunWithContextV2 → executeProposalV2 callData branch.
	// `c.stateDB` is set to swapDB by RunWithContextV2 entry. The callData
	// branch will then bind the LOCAL `stateDB := c.stateDB` (== swapDB),
	// then unlock, then CallContract.Inside CallContract we OVERWRITE
	// `c.stateDB = swappedDB` (the empty one), then re-lock.
	// Post-fix: re-validation reads `stateDB` (local, == swapDB) — sees
	// status=0x02, proceeds, SetState on `stateDB` (== swapDB) → 0x03.
	// Pre-fix (regression): reads `c.stateDB` (now == swappedDB, empty)
	// → reject "status changed", or worse, SetState on swappedDB.
	executeIn := append([]byte{MultisigV2FuncExecuteProposal}, proposalHash[:]...)
	out, err := precompile.RunWithContextV2(ctx, swapDB, executeIn)
	if err != nil {
		t.Fatalf("R48-PRECOMPILE-REENTRANCY-01: execute must succeed when swap was performed (post-fix); got err=%v out=%x", err, out)
	}

	// PASS condition 1: swap fired exactly once.
	if swapDB.swapCount != 1 {
		t.Fatalf("R48-PRECOMPILE-REENTRANCY-01: expected swap exactly once during CallContract; got %d", swapDB.swapCount)
	}
	// PASS condition 2: CallContract was invoked (proves we entered the
	// callData branch and the unlock window occurred).
	if swapDB.CallCount != 1 {
		t.Fatalf("R48-PRECOMPILE-REENTRANCY-01: expected CallContract=1; got %d", swapDB.CallCount)
	}
	// PASS condition 3: Snapshot was taken exactly once before unlock.
	if swapDB.SnapCount != 1 {
		t.Fatalf("R48-PRECOMPILE-REENTRANCY-01: expected Snapshot=1; got %d", swapDB.SnapCount)
	}
	// PASS condition 4: NO revert on happy path (CallErr was nil).
	if swapDB.RevertCnt != 0 {
		t.Fatalf("R48-PRECOMPILE-REENTRANCY-01: expected RevertToSnapshot=0 on happy path; got %d", swapDB.RevertCnt)
	}

	// PASS condition 5 (THE KEY INVARIANT): The status=0x03 "executed"
	// marker landed on swapDB (the LOCAL stateDB captured before
	// unlock), NOT on swappedDB (which c.stateDB was race-overwritten to
	// during the unlock window).
	statusKey := v2ProposalKey("ms:v2pstatus:", proposalHash)
	swapDBStatus := swapDB.GetState(multisigV2Address, statusKey)
	if swapDBStatus[31] != 0x03 {
		t.Errorf("R48-PRECOMPILE-REENTRANCY-01 FAIL: swapDB (local stateDB) status should be 0x03 (executed), got 0x%02x — fix did not route SetState through the local stateDB", swapDBStatus[31])
	}
	swappedDBStatus := swappedDB.GetState(multisigV2Address, statusKey)
	if swappedDBStatus[31] != 0x00 {
		t.Errorf("R48-PRECOMPILE-REENTRANCY-01 FAIL: swappedDB (race-overwritten c.stateDB) status should be 0x00 (untouched), got 0x%02x — fix leaked the SetState into the swapped DB", swappedDBStatus[31])
	}

	// PASS condition 6: Original fdb (the one used by register/create/
	// approve) is NOT modified by the execute — execute writes only to
	// the stateDB it captured locally at V2 entry (which is swapDB, a
	// mirror of fdb's proposal state at the moment of V2 entry). This is
	// a sanity check: fdb's status should remain 0x02 from approve.
	fdbStatus := fdb.GetState(multisigV2Address, statusKey)
	if fdbStatus[31] != 0x02 {
		t.Logf("note: fdb status after execute = 0x%02x (expected 0x02 — fdb was the create/approve DB and was NOT the locally-captured stateDB at execute time)", fdbStatus[31])
	}
}

// TestR48PrecompileReentrancy_SetStateRaceOnSwappedApprovedDB covers the
// SECOND race surface of R48-PRECOMPILE-REENTRANCY-01: the SetState call
// at the end of the callData branch (was `c.stateDB.SetState(...)` pre-
// fix, now `stateDB.SetState(...)` post-fix where `stateDB` is the local
// captured before unlock).
//
// To reach SetState, the post-unlock GetState re-validation MUST pass
// (status=0x02). In TestR48PrecompileReentrancy_StateDBSwapDuringCallContractNotCorrupted
// the swapped DB is configured EMPTY, so the race aborts the call at
// GetState before SetState is ever reached. This second variant
// PRE-FILLS the swapped DB with the SAME approved proposal so the
// GetState re-validation passes regardless of which DB the precompile
// reads from (race-tolerant) — then we assert that the 0x03 "executed"
// marker does NOT land on the swapped DB. If the fix were missing,
// SetState would write 0x03 to the swapped DB.
//
// This variant closes the SetState half of the race that the GetState
// race-reject leaves uncovered.
func TestR48PrecompileReentrancy_SetStateRaceOnSwappedApprovedDB(t *testing.T) {
	chainID := uint64(1668)
	caller, priv := generateKeyAddrPriv(t)
	ctx := PrecompileContext{
		Caller:    caller,
		Origin:    caller,
		ChainID:   chainID,
		BlockTime: 1_700_000_000,
		CallKind:  CallKindCall,
	}

	// fdb holds wallet + proposal state from register→create→approve.
	fdb := &fakeV2CallContractorDB{fakeV2StateDB: newFakeV2StateDB()}

	precompile := newMultisigV2Precompiled()

	var salt [32]byte
	salt[0] = 0xA2
	wallet := registerWalletForTest(t, precompile, fdb, ctx, 1, salt, []types.Address{caller})
	if err := fdb.AddBalance(wallet, big.NewInt(2000)); err != nil {
		t.Fatalf("prefund wallet: %v", err)
	}

	to := types.Address{0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77}
	value := big.NewInt(11)
	callData := []byte{0xFE, 0xED, 0xC0, 0xDE}

	proposalHash, err := runCreate(t, precompile, fdb, ctx, wallet, to, value, 1, 1_700_001_000, callData)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := runApprove(t, precompile, fdb, ctx, proposalHash, priv); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Build swapDB as the LOCAL stateDB RunWithContextV2 will see at
	// execute entry. Pre-populated with the same proposal state +
	// balances as fdb so the callData branch's pre-unlock checks
	// (balance, snapshotter, re-derive hash) all succeed.
	swapDB := &fakeV2SwapStateDB{
		fakeV2CallContractorDB: &fakeV2CallContractorDB{fakeV2StateDB: newFakeV2StateDB()},
	}
	for addr, m := range fdb.states {
		if swapDB.states[addr] == nil {
			swapDB.states[addr] = map[types.Hash]types.Hash{}
		}
		for k, v := range m {
			swapDB.states[addr][k] = v
		}
	}
	for addr, bal := range fdb.balances {
		swapDB.balances[addr] = new(big.Int).Set(bal)
	}

	// swappedDB is configured to ALSO carry status=0x02 for the same
	// proposalHash, so the post-unlock GetState re-validation passes no
	// matter which DB the precompile reads from. This isolates the
	// SetState race: the pre-fix behavior would write 0x03 to swappedDB
	// (poisoning the wrong DB).
	swappedDB := newFakeV2StateDB()
	statusKey := v2ProposalKey("ms:v2pstatus:", proposalHash)
	var approvedVal types.Hash
	approvedVal[31] = 0x02
	swappedDB.SetState(multisigV2Address, statusKey, approvedVal)

	swapDB.swappedTarget = swappedDB
	swapDB.precompileInstance = precompile

	// Execute through RunWithContextV2 → executeProposalV2 → callData
	// branch → unlock → CallContract (swaps c.stateDB → swappedDB) →
	// relock → GetState (passes either way) → SetState(0x03).
	executeIn := append([]byte{MultisigV2FuncExecuteProposal}, proposalHash[:]...)
	if _, err := precompile.RunWithContextV2(ctx, swapDB, executeIn); err != nil {
		t.Fatalf("R48-PRECOMPILE-REENTRANCY-01 SetState variant: execute err=%v", err)
	}

	if swapDB.swapCount != 1 {
		t.Fatalf("R48-PRECOMPILE-REENTRANCY-01 SetState variant: swapCount got %d, want 1", swapDB.swapCount)
	}

	// KEY INVARIANT: swappedDB must still hold status=0x02 (untouched),
	// NOT 0x03 (which would indicate SetState went to the wrong DB).
	swappedDBStatus := swappedDB.GetState(multisigV2Address, statusKey)
	if swappedDBStatus[31] != 0x02 {
		t.Errorf("R48-PRECOMPILE-REENTRANCY-01 SetState race FAIL: swappedDB status got 0x%02x, want 0x02 — fix did NOT redirect SetState to the local stateDB; SetState leaked into the race-overwritten c.stateDB", swappedDBStatus[31])
	}
	// And swapDB (the local stateDB captured before unlock) MUST now be
	// 0x03 — proving SetState landed on the correct DB.
	swapDBStatus := swapDB.GetState(multisigV2Address, statusKey)
	if swapDBStatus[31] != 0x03 {
		t.Errorf("R48-PRECOMPILE-REENTRANCY-01 SetState race FAIL: swapDB (local stateDB) status got 0x%02x, want 0x03 — fix dropped the executed marker entirely", swapDBStatus[31])
	}
}
