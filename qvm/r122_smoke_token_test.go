// Quantaureum Node source, version 1.0.0.
package qvm

// R122 Step-0 smoke test: deploy the hand-written QASM SmokeToken contract
// and exercise ping/balanceOf/transfer through the real QVM executor.
//
// Validates the three gate items from docs/plans/R122-QSWAP-QASM-AMM.md §3 Step 0:
//  1. keccak256 mapping storage keys (balanceOf per address)
//  2. balance mutation via transfer (caller -, recipient +)
//  3. REVERT rollback on insufficient balance (state unchanged after revert)
//
// The contract hex is assembled from contracts/qasm/smoke_token.qasm via
// `go run ./cmd/qasm assemble contracts/qasm/smoke_token.qasm contracts/qasm/smoke_token.hex`.
// The hex file embeds the runtime code inside init code (CODECOPY pattern),
// same layout as the mainnet-proven LinearVesting contract.

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"
)

// smokeTokenHexPath is the assembled bytecode of smoke_token.qasm.
const smokeTokenHexPath = "../contracts/qasm/smoke_token.hex"

// smokeSelectors — keccak256("...")[0:4], computed with the standard Solidity ABI.
// 0x2e64ce9d ping()
// 0x18160ddd totalSupply()
// 0x70a08231 balanceOf(address)
// 0xa9059cbb transfer(address,uint256)
var (
	selPing     = []byte{0x2e, 0x64, 0xce, 0x9d}
	selSupply   = []byte{0x18, 0x16, 0x0d, 0xdd}
	selBalance  = []byte{0x70, 0xa0, 0x82, 0x31}
	selTransfer = []byte{0xa9, 0x05, 0x9c, 0xbb}
)

// loadSmokeTokenHex reads the assembled init code (0x-prefixed hex file).
func loadSmokeTokenHex(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(smokeTokenHexPath)
	if err != nil {
		t.Skipf("smoke_token.hex not assembled yet (%v); run: go run ./cmd/qasm assemble contracts/qasm/smoke_token.qasm contracts/qasm/smoke_token.hex", err)
	}
	s := strings.TrimSpace(string(raw))
	s = strings.TrimPrefix(s, "0x")
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in %s: %v", smokeTokenHexPath, err)
	}
	return out
}

// deploySmokeToken creates the contract and returns (stateDB, contractAddr).
func deploySmokeToken(t *testing.T, caller Address, initialSupply *big.Int) (*mockStateDB, Address) {
	t.Helper()
	initCode := loadSmokeTokenHex(t)

	db := newMockStateDB()
	db.SetBalance(caller, big.NewInt(1_000_000))
	db.SetNonce(caller, 1) // TxExecutor increments nonce before Create

	exec := NewExecutor()
	blockCtx := &BlockContext{BlockNumber: 1, Timestamp: 1700000000, GasLimit: 20_000_000, ChainID: 1668}
	result, addr := exec.Create(db, caller, initCode, 2_000_000, big.NewInt(0), blockCtx, 0)
	if result.Err != nil {
		t.Fatalf("deploy failed: err=%v gasUsed=%d", result.Err, result.GasUsed)
	}
	if addr == (Address{}) {
		t.Fatal("deploy returned empty address")
	}
	if len(db.GetCode(addr)) == 0 {
		t.Fatal("no runtime code stored at contract address")
	}
	return db, addr
}

// callSmokeToken invokes a function on the deployed contract.
func callSmokeToken(t *testing.T, db *mockStateDB, contract, caller Address, input []byte, gas uint64) []byte {
	t.Helper()
	exec := NewExecutor()
	blockCtx := &BlockContext{BlockNumber: 1, Timestamp: 1700000000, GasLimit: 20_000_000, ChainID: 1668}
	result := exec.Call(db, caller, contract, input, gas, big.NewInt(0), blockCtx, 0)
	t.Logf("call sel=%x err=%v reverted=%v gasUsed=%d retLen=%d ret=%x",
		input[:4], result.Err, result.Reverted, result.GasUsed, len(result.ReturnData), result.ReturnData)
	if result.Err != nil {
		t.Fatalf("call %x failed: err=%v gasUsed=%d", input[:4], result.Err, result.GasUsed)
	}
	return result.ReturnData
}

// callSmokeTokenExpectRevert invokes and expects a revert; returns whether it reverted.
func callSmokeTokenExpectRevert(t *testing.T, db *mockStateDB, contract, caller Address, input []byte, gas uint64) bool {
	t.Helper()
	exec := NewExecutor()
	blockCtx := &BlockContext{BlockNumber: 1, Timestamp: 1700000000, GasLimit: 20_000_000, ChainID: 1668}
	result := exec.Call(db, caller, contract, input, gas, big.NewInt(0), blockCtx, 0)
	return result.Err != nil
}

// padAddressWord left-pads a 20-byte address into a 32-byte ABI word.
func padAddressWord(a Address) []byte {
	out := make([]byte, 32)
	copy(out[12:], a[:])
	return out
}

// TestR122SmokePing verifies ping() returns 42.
func TestR122SmokePing(t *testing.T) {
	caller := Address{0x11}
	db, contract := deploySmokeToken(t, caller, big.NewInt(0))

	ret := callSmokeToken(t, db, contract, caller, selPing, 100_000)
	if len(ret) != 32 || new(big.Int).SetBytes(ret).Int64() != 42 {
		t.Fatalf("ping() = %x, want 42", ret)
	}
}

// TestR122SmokeBalanceOfKey verifies the keccak256 mapping storage key:
// balanceOf reads storage at keccak256(pad(addr) ++ slot2) — the exact
// scheme AMM contracts will reuse for reserves/LP balances.
func TestR122SmokeBalanceOfKey(t *testing.T) {
	owner := Address{0x11}
	alice := Address{0x22}
	db, contract := deploySmokeToken(t, owner, big.NewInt(0))

	// Seed balance directly through the storage key the contract derives.
	// key = keccak256(pad32(alice) ++ pad32(2))
	var buf bytes.Buffer
	buf.Write(padAddressWord(alice))
	buf.Write(big.NewInt(2).FillBytes(make([]byte, 32)))
	key := keccak256HashForTest(t, buf.Bytes())

	db.SetState(contract, key, Hash(big.NewInt(777).FillBytes(make([]byte, 32))))

	input := append(append([]byte{}, selBalance...), padAddressWord(alice)...)
	ret := callSmokeToken(t, db, contract, alice, input, 100_000)
	got := new(big.Int).SetBytes(ret)
	if got.Int64() != 777 {
		t.Fatalf("balanceOf(alice) = %s, want 777", got)
	}

	// Different address -> different key -> zero.
	bob := Address{0x33}
	input = append(append([]byte{}, selBalance...), padAddressWord(bob)...)
	ret = callSmokeToken(t, db, contract, bob, input, 100_000)
	if got = new(big.Int).SetBytes(ret); got.Sign() != 0 {
		t.Fatalf("balanceOf(bob) = %s, want 0", got)
	}
}

// TestR122SmokeTransferFlow verifies transfer moves balances via the mapping:
// caller loses amount, recipient gains amount, and REVERT leaves state intact.
func TestR122SmokeTransferFlow(t *testing.T) {
	owner := Address{0x11}
	alice := Address{0x22}
	bob := Address{0x33}
	db, contract := deploySmokeToken(t, owner, big.NewInt(0))

	// Seed alice with 100 tokens via the storage key.
	seedKey := storageKeyFor(t, alice)
	db.SetState(contract, seedKey, Hash(big.NewInt(100).FillBytes(make([]byte, 32))))

	// transfer(bob, 40)
	var input []byte
	input = append(input, selTransfer...)
	input = append(input, padAddressWord(bob)...)
	input = append(input, big.NewInt(40).FillBytes(make([]byte, 32))...)

	ret := callSmokeToken(t, db, contract, alice, input, 300_000)
	if len(ret) == 0 || new(big.Int).SetBytes(ret).Int64() != 1 {
		t.Fatalf("transfer returned %x, want true", ret)
	}

	// Debug: dump the storage keys the contract derived.
	aliceKey := storageKeyFor(t, alice)
	st := db.GetState(contract, aliceKey)
	t.Logf("aliceKey=%x storage=%x (want 60)", aliceKey, st)
	// Also slot0/1/2 raw
	for i := 0; i < 4; i++ {
		slotKey := Hash{}
		slotKey[31] = byte(i)
		t.Logf("slot%d=%x", i, db.GetState(contract, slotKey))
	}

	// Check balances: alice 60, bob 40.
	input = append(append([]byte{}, selBalance...), padAddressWord(alice)...)
	ret2 := callSmokeToken(t, db, contract, alice, input, 100_000)
	if got := new(big.Int).SetBytes(ret2); got.Int64() != 60 {
		t.Fatalf("alice balance = %s (ret %x), want 60", got, ret2)
	}
	input = append(append([]byte{}, selBalance...), padAddressWord(bob)...)
	if got := new(big.Int).SetBytes(callSmokeToken(t, db, contract, bob, input, 100_000)); got.Int64() != 40 {
		t.Fatalf("bob balance = %s, want 40", got)
	}
}

// TestR122SmokeTransferRevertRollback verifies the insufficient-balance REVERT
// leaves both mappings unchanged (QVM revert must roll back the whole frame's storage).
func TestR122SmokeTransferRevertRollback(t *testing.T) {
	owner := Address{0x11}
	alice := Address{0x22}
	bob := Address{0x33}
	db, contract := deploySmokeToken(t, owner, big.NewInt(0))

	db.SetState(contract, storageKeyFor(t, alice), Hash(big.NewInt(10).FillBytes(make([]byte, 32))))

	// transfer(bob, 999) — exceeds balance -> must revert.
	input := append(append([]byte{}, selTransfer...), padAddressWord(bob)...)
	input = append(input, big.NewInt(999).FillBytes(make([]byte, 32))...)

	if !callSmokeTokenExpectRevert(t, db, contract, alice, input, 300_000) {
		t.Fatal("overdraft transfer should revert")
	}

	// State must be unchanged: alice still 10, bob still 0.
	input = append(append([]byte{}, selBalance...), padAddressWord(alice)...)
	if got := new(big.Int).SetBytes(callSmokeToken(t, db, contract, alice, input, 100_000)); got.Int64() != 10 {
		t.Fatalf("after revert, alice = %s, want 10 (rollback failed!)", got)
	}
	input = append(append([]byte{}, selBalance...), padAddressWord(bob)...)
	if got := new(big.Int).SetBytes(callSmokeToken(t, db, contract, bob, input, 100_000)); got.Sign() != 0 {
		t.Fatalf("after revert, bob = %s, want 0 (rollback failed!)", got)
	}
}

// --- helpers ---

// storageKeyFor computes keccak256(pad32(addr) ++ pad32(2)) — the balanceOf key.
func storageKeyFor(t *testing.T, a Address) Hash {
	t.Helper()
	var buf bytes.Buffer
	buf.Write(padAddressWord(a))
	buf.Write(big.NewInt(2).FillBytes(make([]byte, 32)))
	return keccak256HashForTest(t, buf.Bytes())
}

func keccak256HashForTest(t *testing.T, data []byte) Hash {
	t.Helper()
	h := keccak256(data)
	return h
}
