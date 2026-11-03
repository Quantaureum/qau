// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"bytes"
	"math/big"
	"testing"
)

// R133: vrf_deposit — on-chain billing for the random-number API.
// Drives the assembled contracts/qasm/vrf_deposit.hex through the real QVM executor.
//
// deposit(bytes32 keyHash) payable is a non-refundable SERVICE-FEE payment for
// the API key identified by keyHash (SHA-256 of the key, as a 32-byte word);
// withdraw() is the owner-only sweep of the entire contract balance.
//
// storage: 0=owner 1=totalDeposited 2=deposits[addr] mapping
//   mapping key = keccak256(pad32(addr) ++ pad32(2))
// event Deposit(address,uint256,bytes32):
//   topic0 = keccak256("Deposit(address,uint256,bytes32)")
//   data   = pad32(caller) ++ pad32(amount) ++ pad32(keyHash)

var (
	// keccak256("deposit(bytes32)")[:4] — generated with golang.org/x/crypto/sha3
	// NewLegacyKeccak256 over the ASCII signature (drift-checked in TestVRFCreation).
	vrfSelDeposit = []byte{0xb2, 0x14, 0xfa, 0xa5}
	// keccak256("withdraw()")[:4]
	vrfSelWithdraw = []byte{0x3c, 0xcf, 0xd6, 0x0b}
	// keccak256("Deposit(address,uint256,bytes32)")
	vrfTopicDeposit = Hash{
		0x1a, 0x77, 0x1f, 0xe6, 0x56, 0x01, 0x83, 0x64,
		0xa9, 0x36, 0x9d, 0xa2, 0x19, 0x54, 0xbb, 0x30,
		0x81, 0xcb, 0x08, 0xb0, 0x19, 0x6c, 0x27, 0xe4,
		0x3c, 0xa5, 0x9c, 0x7c, 0xae, 0x87, 0x27, 0x37,
	}
)

// vrfDepositHexPath is the assembled vrf_deposit bytecode (see the qasm source).
const vrfDepositHexPath = "../contracts/qasm/vrf_deposit.hex"

type vrfFixture struct {
	db    *mockStateDB
	exec  *Executor
	ctx   *BlockContext
	owner Address // deployer == contract owner (slot0)
	alice Address
	vd    Address // vrf_deposit contract address
}

func newVrfFixture(t *testing.T) *vrfFixture {
	t.Helper()
	f := &vrfFixture{
		db:    newMockStateDB(),
		exec:  NewExecutor(),
		ctx:   &BlockContext{BlockNumber: 1_000, Timestamp: 1_788_676_000, GasLimit: 20_000_000, ChainID: 1668},
		owner: Address{0x51},
		alice: Address{0x22},
	}
	bal := new(big.Int).Mul(big.NewInt(1_000_000), big.NewInt(1e18))
	f.db.SetBalance(f.owner, bal)
	f.db.SetBalance(f.alice, bal)
	f.db.SetNonce(f.owner, 1)
	res, addr := f.exec.Create(f.db, f.owner, loadContractHex(t, vrfDepositHexPath), 5_000_000, big.NewInt(0), f.ctx, 0)
	if res.Err != nil {
		t.Fatalf("deploy vrf_deposit: %v", res.Err)
	}
	f.vd = addr
	return f
}

// callVrf runs a call against the contract and returns the full result
// (Logs included).
func (f *vrfFixture) callVrf(caller Address, input []byte, value *big.Int, gas uint64) *ExecutionResult {
	return f.exec.Call(f.db, caller, f.vd, input, gas, value, f.ctx, 0)
}

// vrfE18: v × 1e18
func vrfE18(v int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(v), big.NewInt(1e18))
}

// vrfDepositInput builds deposit(bytes32 keyHash) calldata.
func vrfDepositInput(keyHash [32]byte) []byte {
	in := append([]byte{}, vrfSelDeposit...)
	return append(in, keyHash[:]...)
}

// vrfDepositsKey reproduces the contract's slot-2 mapping key:
// keccak256(pad32(addr) ++ pad32(2)).
func vrfDepositsKey(addr Address) Hash {
	var buf [64]byte
	copy(buf[12:], addr[:]) // pad32(addr): 20-byte address left-aligned in word 1 (buf[12:32])
	buf[63] = 2             // pad32(2): word 2
	return keccak256(buf[:])
}

// depositsOf reads deposits[addr] straight from contract storage.
func (f *vrfFixture) depositsOf(addr Address) *big.Int {
	h := f.db.GetState(f.vd, vrfDepositsKey(addr))
	return new(big.Int).SetBytes(h[:])
}

// totalDeposited reads slot1 straight from contract storage.
func (f *vrfFixture) totalDeposited() *big.Int {
	h := f.db.GetState(f.vd, slotKey(1))
	return new(big.Int).SetBytes(h[:])
}

// ============ creation: init code sets owner, counters zero, constants sane ============

func TestVRFCreation(t *testing.T) {
	f := newVrfFixture(t)
	// slot0 = owner = deployer
	h := f.db.GetState(f.vd, slotKey(0))
	var wantOwner Hash
	copy(wantOwner[12:], f.owner[:])
	if h != wantOwner {
		t.Fatalf("owner slot = %x, want %x (deployer)", h, wantOwner)
	}
	// slot1 = totalDeposited = 0
	if got := f.totalDeposited(); got.Sign() != 0 {
		t.Fatalf("totalDeposited = %s, want 0", got)
	}
	// the hardcoded selectors/topic0 are the real keccak256 values of the signatures
	if got := keccak256([]byte("deposit(bytes32)")); !bytes.Equal(got[:4], vrfSelDeposit) {
		t.Fatalf("deposit(bytes32) selector drift: got %x, want %x", got[:4], vrfSelDeposit)
	}
	if got := keccak256([]byte("withdraw()")); !bytes.Equal(got[:4], vrfSelWithdraw) {
		t.Fatalf("withdraw() selector drift: got %x, want %x", got[:4], vrfSelWithdraw)
	}
	if got := keccak256([]byte("Deposit(address,uint256,bytes32)")); got != vrfTopicDeposit {
		t.Fatalf("Deposit topic0 drift: got %x, want %x", got, vrfTopicDeposit)
	}
}

// ============ deposit: accounting, Deposit log layout, accumulation ============

func TestVRFCDepositAccountingAndLogs(t *testing.T) {
	f := newVrfFixture(t)
	var keyHash [32]byte
	keyHash[0], keyHash[1] = 0xab, 0xcd

	res := f.callVrf(f.alice, vrfDepositInput(keyHash), vrfE18(100), 8_000_000)
	if res.Err != nil {
		t.Fatalf("deposit: %v", res.Err)
	}
	if got := f.depositsOf(f.alice); got.Cmp(vrfE18(100)) != 0 {
		t.Fatalf("deposits(alice) = %s, want 100e18", got)
	}
	if got := f.totalDeposited(); got.Cmp(vrfE18(100)) != 0 {
		t.Fatalf("totalDeposited = %s, want 100e18", got)
	}
	// exactly one Deposit log with the full ABI layout
	if len(res.Logs) != 1 {
		t.Fatalf("logs = %d, want 1", len(res.Logs))
	}
	lg := res.Logs[0]
	if lg.Address != f.vd {
		t.Fatalf("log address = %x, want %x", lg.Address, f.vd)
	}
	if len(lg.Topics) != 1 || lg.Topics[0] != vrfTopicDeposit {
		t.Fatalf("log topics = %v, want [Deposit topic0 %x]", lg.Topics, vrfTopicDeposit)
	}
	wantData := padAddressWord(f.alice)
	wantData = append(wantData, vrfE18(100).FillBytes(make([]byte, 32))...)
	wantData = append(wantData, keyHash[:]...)
	if !bytes.Equal(lg.Data, wantData) {
		t.Fatalf("log data = %x, want pad32(caller)++pad32(amount)++pad32(keyHash) = %x", lg.Data, wantData)
	}
	// a second deposit accumulates in both counters and emits again
	res2 := f.callVrf(f.alice, vrfDepositInput(keyHash), vrfE18(50), 8_000_000)
	if res2.Err != nil {
		t.Fatalf("second deposit: %v", res2.Err)
	}
	if got := f.depositsOf(f.alice); got.Cmp(vrfE18(150)) != 0 {
		t.Fatalf("deposits(alice) after second = %s, want 150e18", got)
	}
	if got := f.totalDeposited(); got.Cmp(vrfE18(150)) != 0 {
		t.Fatalf("totalDeposited after second = %s, want 150e18", got)
	}
	if len(res2.Logs) != 1 {
		t.Fatalf("second deposit logs = %d, want 1", len(res2.Logs))
	}
}

// ============ deposit: zero value rejected ============

func TestVRFCDepositZeroValueReverts(t *testing.T) {
	f := newVrfFixture(t)
	var keyHash [32]byte
	if res := f.callVrf(f.alice, vrfDepositInput(keyHash), big.NewInt(0), 8_000_000); res.Err == nil {
		t.Fatal("zero-value deposit should revert")
	}
	if got := f.depositsOf(f.alice); got.Sign() != 0 {
		t.Fatalf("deposits(alice) = %s, want 0 (rollback)", got)
	}
	if got := f.totalDeposited(); got.Sign() != 0 {
		t.Fatalf("totalDeposited = %s, want 0 (rollback)", got)
	}
}

// ============ deposit: malformed calldata / unknown selector rejected ============

func TestVRFCDepositBadCalldataReverts(t *testing.T) {
	f := newVrfFixture(t)
	// selector only (4 bytes): the bare deposit() fallback (zero keyHash) is not allowed
	if res := f.callVrf(f.alice, vrfSelDeposit, vrfE18(1), 8_000_000); res.Err == nil {
		t.Fatal("4-byte deposit calldata should revert")
	}
	// one byte short of 36
	short := vrfDepositInput([32]byte{})
	if res := f.callVrf(f.alice, short[:35], vrfE18(1), 8_000_000); res.Err == nil {
		t.Fatal("35-byte deposit calldata should revert")
	}
	// one byte over 36
	long := append(vrfDepositInput([32]byte{}), 0xee)
	if res := f.callVrf(f.alice, long, vrfE18(1), 8_000_000); res.Err == nil {
		t.Fatal("37-byte deposit calldata should revert")
	}
	// unknown selector
	if res := f.callVrf(f.alice, []byte{0xde, 0xad, 0xbe, 0xef}, vrfE18(1), 8_000_000); res.Err == nil {
		t.Fatal("unknown selector should revert")
	}
	// none of the failed calls left a trace
	if got := f.depositsOf(f.alice); got.Sign() != 0 {
		t.Fatalf("deposits(alice) = %s, want 0 (rollback)", got)
	}
	if got := f.totalDeposited(); got.Sign() != 0 {
		t.Fatalf("totalDeposited = %s, want 0 (rollback)", got)
	}
}

// ============ withdraw: non-owner rejected, state intact ============

func TestVRFCWithdrawNonOwnerReverts(t *testing.T) {
	f := newVrfFixture(t)
	var keyHash [32]byte
	if res := f.callVrf(f.alice, vrfDepositInput(keyHash), vrfE18(100), 8_000_000); res.Err != nil {
		t.Fatalf("deposit: %v", res.Err)
	}
	balBefore := f.db.GetBalance(f.vd)
	if res := f.callVrf(f.alice, vrfSelWithdraw, big.NewInt(0), 8_000_000); res.Err == nil {
		t.Fatal("non-owner withdraw should revert")
	}
	if got := f.db.GetBalance(f.vd); got.Cmp(balBefore) != 0 {
		t.Fatalf("contract balance changed on failed withdraw: %s -> %s", balBefore, got)
	}
	if got := f.depositsOf(f.alice); got.Cmp(vrfE18(100)) != 0 {
		t.Fatalf("deposits(alice) = %s, want 100e18 (intact)", got)
	}
}

// ============ withdraw: owner sweeps the entire balance ============

func TestVRFCWithdrawOwnerSweeps(t *testing.T) {
	f := newVrfFixture(t)
	var keyHash [32]byte
	if res := f.callVrf(f.alice, vrfDepositInput(keyHash), vrfE18(100), 8_000_000); res.Err != nil {
		t.Fatalf("deposit: %v", res.Err)
	}
	ownerBefore := f.db.GetBalance(f.owner)
	if res := f.callVrf(f.owner, vrfSelWithdraw, big.NewInt(0), 8_000_000); res.Err != nil {
		t.Fatalf("owner withdraw: %v", res.Err)
	}
	// the full SELFBALANCE lands on the owner
	delta := new(big.Int).Sub(f.db.GetBalance(f.owner), ownerBefore)
	if delta.Cmp(vrfE18(100)) != 0 {
		t.Fatalf("owner delta = %s, want 100e18 (full sweep)", delta)
	}
	if got := f.db.GetBalance(f.vd); got.Sign() != 0 {
		t.Fatalf("contract balance after sweep = %s, want 0", got)
	}
	// lifetime billing records survive the sweep
	if got := f.depositsOf(f.alice); got.Cmp(vrfE18(100)) != 0 {
		t.Fatalf("deposits(alice) = %s, want 100e18 (lifetime record)", got)
	}
}
