// Quantaureum Node source, version 1.0.0.
package txpool

// LOG PROPAGATION FIX regression test: a contract's LOG0-4 events must reach
// receipt.Logs (and from there StoredReceipt.Logs → eth_getLogs). Uses the
// real vrf_deposit bytecode: deploy, deposit(keyHash) with value, assert the
// Deposit event is on the receipt with the exact topic0 and ABI data layout.

import (
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

// vrf_deposit contract constants (see contracts/qasm/vrf_deposit.qasm header;
// kept in sync by the qvm-level drift test TestVRFCreation).
const (
	vrfSelectorDeposit = "b214faa5"
	vrfTopic0Deposit   = "1a771fe656018364a9369da21954bb3081cb08b0196c27e43ca59c7cae872737"
)

func loadVRFDepositHex(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../contracts/qasm/vrf_deposit.hex")
	if err != nil {
		t.Skipf("vrf_deposit.hex not assembled yet (run: go run ./cmd/qasm assemble contracts/qasm/vrf_deposit.qasm contracts/qasm/vrf_deposit.hex): %v", err)
	}
	codeStr := string(raw)
	codeStr = strings.TrimPrefix(strings.TrimSpace(codeStr), "0x")
	code, err := hex.DecodeString(codeStr)
	if err != nil {
		t.Fatalf("decode vrf_deposit.hex: %v", err)
	}
	return code
}

func padWord(t *testing.T, hexStr string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("decode %q: %v", hexStr, err)
	}
	if len(raw) > 32 {
		t.Fatalf("word too long: %d", len(raw))
	}
	out := make([]byte, 32)
	copy(out[32-len(raw):], raw)
	return out
}

// codeAwareState extends the shared mockState with code storage: the base
// mock's SetCode is a no-op and GetCode always returns nil, which silently
// turned every contract call in txpool tests into a plain transfer.
type codeAwareState struct {
	*mockState
	codes map[types.Address][]byte
}

func newCodeAwareState() *codeAwareState {
	return &codeAwareState{mockState: newMockState(), codes: map[types.Address][]byte{}}
}

func (s *codeAwareState) SetCode(addr types.Address, code []byte) {
	s.codes[addr] = append([]byte(nil), code...)
}

func (s *codeAwareState) GetCode(addr types.Address) []byte {
	return s.codes[addr]
}

func TestExecutorContractLogsReachReceipt(t *testing.T) {
	code := loadVRFDepositHex(t)
	state := newCodeAwareState()
	owner := types.Address{0x11}
	tenQAU := new(big.Int).Mul(big.NewInt(10), big.NewInt(1_000_000_000_000_000_000))
	state.SetBalance(owner, tenQAU)

	executor := NewTxExecutor()
	blockCtx := &BlockContext{
		BlockNumber: 1,
		Timestamp:   time.Now().Unix(),
		GasLimit:    30_000_000,
		ChainID:     1333,
	}

	// Deploy: the executor expects tx.Nonce == state nonce and pre-increments
	// internally, deriving the address as CreateAddress(owner, nonce-1) — so
	// nonce 0 here lands the contract at CreateAddress(owner, 0).
	createTx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeCreate,
		Nonce:    0,
		From:     owner,
		Value:    big.NewInt(0),
		GasLimit: 5_000_000,
		GasPrice: big.NewInt(1),
		Data:     code,
		ChainID:  1333,
	}
	createReceipt := executor.Execute(createTx, state, blockCtx)
	if createReceipt.Status != 1 {
		t.Fatalf("deploy failed: status=%d err=%q", createReceipt.Status, createReceipt.Error)
	}

	// Deposit 1e18 wei with a 32-byte SYNTHETIC keyHash fixture (never a
	// real credential hash — the zero-hit key-scan invariant requires
	// fixtures to be visibly fabricated, matching the qvm-level test).
	keyHash := padWord(t, "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabb")
	sel, _ := hex.DecodeString(vrfSelectorDeposit)
	data := append(append([]byte{}, sel...), keyHash...)
	callTx := &encoding.Transaction{
		Version:  1,
		Type:     encoding.TxTypeContract,
		Nonce:    1,
		From:     owner,
		To:       contractAddrPtr(qvm.CreateAddress(qvm.Address(owner), 0)),
		Value:    big.NewInt(1_000_000_000_000_000_000),
		GasLimit: 5_000_000,
		GasPrice: big.NewInt(1),
		Data:     data,
		ChainID:  1333,
	}
	callReceipt := executor.Execute(callTx, state, blockCtx)
	if callReceipt.Status != 1 {
		t.Fatalf("deposit failed: status=%d err=%q", callReceipt.Status, callReceipt.Error)
	}

	// THE REGRESSION: logs must reach the receipt.
	if len(callReceipt.Logs) == 0 {
		t.Fatal("receipt.Logs is empty — QVM events were dropped at the txpool layer (log propagation regression)")
	}
	wantTopic, _ := hex.DecodeString(vrfTopic0Deposit)
	found := false
	for _, lg := range callReceipt.Logs {
		if lg == nil || len(lg.Topics) == 0 {
			continue
		}
		if lg.Topics[0] != types.Hash(*(*[32]byte)(wantTopic)) {
			continue
		}
		found = true
		wantData := append(append(padWord(t, hex.EncodeToString(owner[:])), padWord(t, "0de0b6b3a7640000")...), keyHash...)
		if string(lg.Data) != string(wantData) {
			t.Errorf("event data mismatch:\n got  %x\n want %x", lg.Data, wantData)
		}
		if lg.Address != types.Address(qvm.CreateAddress(qvm.Address(owner), 0)) {
			t.Errorf("event address = %x, want the contract address", lg.Address)
		}
	}
	if !found {
		t.Fatalf("Deposit topic0 not found among %d receipt log(s)", len(callReceipt.Logs))
	}

	// The deposit must be accounted in contract storage (deposits mapping).
	contract := qvm.CreateAddress(qvm.Address(owner), 0)
	if got := state.GetBalance(types.Address(contract)); got.Cmp(big.NewInt(1_000_000_000_000_000_000)) != 0 {
		t.Errorf("contract balance = %s, want 1e18", got)
	}
}

// contractAddrPtr converts a qvm.Address value into the pointer form the
// encoding.Transaction.To field expects.
func contractAddrPtr(a qvm.Address) *types.Address {
	out := types.Address(a)
	return &out
}
