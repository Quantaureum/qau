// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

type AccessListAPI struct {
	blockReader    BlockReader
	stateReader    StateReader
	contractCaller ContractCaller
	chainInfo      ChainInfo
}

func NewAccessListAPI(blockReader BlockReader, stateReader StateReader, contractCaller ContractCaller, chainInfo ChainInfo) *AccessListAPI {
	return &AccessListAPI{
		blockReader:    blockReader,
		stateReader:    stateReader,
		contractCaller: contractCaller,
		chainInfo:      chainInfo,
	}
}

type AccessListEntry struct {
	Address     string   `json:"address"`
	StorageKeys []string `json:"storageKeys"`
}

type AccessListResult struct {
	AccessList []AccessListEntry `json:"accessList"`
	GasUsed    string            `json:"gasUsed"`
	Error      string            `json:"error,omitempty"`
}

func (api *AccessListAPI) CreateAccessList(args TraceCallArgs, blockNum string) (*AccessListResult, error) {
	// P3-NODE-05 FIX (R30, 2026-07-27): callArgsToMessage now returns
	// an error on gas parse failure — surface it to the caller.
	msg, err := callArgsToMessage(args)
	if err != nil {
		return nil, err
	}

	// R31-P4-6 FIX: Validate gas minimum. A gas value of 0 would cause the
	// execution to fail immediately without producing a meaningful access list.
	// The minimum 21000 matches the cost of a simple transfer (EIP-2025).
	const minAccessListGas uint64 = 21000
	const maxAccessListGas uint64 = 25000000
	if msg.Gas == 0 {
		msg.Gas = maxAccessListGas // default to max if not specified
	}
	if msg.Gas < minAccessListGas {
		return nil, fmt.Errorf("gas %d is below minimum %d for access list creation", msg.Gas, minAccessListGas)
	}
	if msg.Gas > maxAccessListGas {
		msg.Gas = maxAccessListGas
	}

	accessTracer := newAccessListTracer()

	interpreter := qvm.NewInterpreter()
	ctx := &qvm.ExecutionContext{
		Origin:      qvm.Address(msg.From),
		GasPrice:    big.NewInt(0),
		Caller:      qvm.Address(msg.From),
		Address:     qvm.Address(msg.To),
		Value:       msg.Value,
		BlockNumber: 0,
		Timestamp:   0,
		Coinbase:    qvm.Address{},
		GasLimit:    msg.Gas,
		ChainID:     api.chainInfo.ChainID(),
		Code:        api.stateReader.GetCode(msg.To),
		Input:       msg.Data,
		Gas:         msg.Gas,
		Depth:       0,
		ReadOnly:    false,
	}

	stateDB := &accessListStateDB{
		reader: api.stateReader,
		tracer: accessTracer,
	}

	env := &qvm.Environment{}
	env.SetTracer(accessTracer)
	accessTracer.CaptureStart(env, qvm.Address(msg.From), qvm.Address(msg.To), msg.Data, msg.Gas, msg.Value)

	result := interpreter.Execute(ctx, stateDB)

	accessList := accessTracer.buildAccessList()

	gasUsed := uint64(0)
	if result != nil {
		gasUsed = result.GasUsed
	}

	output := &AccessListResult{
		AccessList: accessList,
		GasUsed:    fmt.Sprintf("0x%x", gasUsed),
	}
	if result != nil && result.Err != nil {
		output.Error = result.Err.Error()
	}

	return output, nil
}

// RegisterHandlers registers the eth_createAccessList endpoint.
//
// R22 FIX: The underlying CreateAccessList method uses a custom typed
// signature (TraceCallArgs, string) that the type switch in server.go
// RegisterHandler does not recognize. Without an adapter wrapper the
// handler was silently dropped by the default branch and the method
// returned "method not found". The adapter translates the standard
// JSON-RPC positional params array [callArgs, blockNum] into the typed
// Go arguments.
func (api *AccessListAPI) RegisterHandlers(server *Server) {
	// FIX: eth_createAccessList is a standard read-only JSON-RPC method
	// (EIP-2930). It must NOT be registered as an admin method — doing so
	// breaks tool compatibility (Hardhat/Foundry). Gas cap (25M) and rate
	// limiting already provide sufficient DoS protection.
	server.RegisterHandler("eth_createAccessList", func(ctx context.Context, params json.RawMessage) (any, error) {
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if len(args) < 1 {
			return nil, fmt.Errorf("missing call args parameter")
		}
		var callArgs TraceCallArgs
		if err := json.Unmarshal(args[0], &callArgs); err != nil {
			return nil, fmt.Errorf("invalid call args: %w", err)
		}
		var blockNum string
		if len(args) >= 2 {
			if err := json.Unmarshal(args[1], &blockNum); err != nil {
				return nil, fmt.Errorf("invalid block number: %w", err)
			}
		}
		return api.CreateAccessList(callArgs, blockNum)
	})
}

type accessListTracer struct {
	accessedAddresses map[string]map[string]struct{}
}

func newAccessListTracer() *accessListTracer {
	return &accessListTracer{
		accessedAddresses: make(map[string]map[string]struct{}),
	}
}

func (t *accessListTracer) CaptureStart(env *qvm.Environment, from, to qvm.Address, input []byte, gas uint64, value *big.Int) {
	t.recordAddress(to)
	t.recordAddress(from)
}

func (t *accessListTracer) CaptureState(env *qvm.Environment, pc uint64, op qvm.OpCode, gas, cost uint64, depth int, err error) {
}

func (t *accessListTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {}

func (t *accessListTracer) CaptureEnter(op qvm.OpCode, from, to qvm.Address, input []byte, gas uint64, value *big.Int) {
	t.recordAddress(to)
}

func (t *accessListTracer) CaptureExit(output []byte, gasUsed uint64, err error) {}

func (t *accessListTracer) GetResult() (any, error) {
	return t.buildAccessList(), nil
}

func (t *accessListTracer) recordAddress(addr qvm.Address) {
	addrHex := "0x" + hex.EncodeToString(addr[:])
	if _, ok := t.accessedAddresses[addrHex]; !ok {
		t.accessedAddresses[addrHex] = make(map[string]struct{})
	}
}

func (t *accessListTracer) recordStorage(addr qvm.Address, slot qvm.Hash) {
	addrHex := "0x" + hex.EncodeToString(addr[:])
	slotHex := "0x" + hex.EncodeToString(slot[:])
	if _, ok := t.accessedAddresses[addrHex]; !ok {
		t.accessedAddresses[addrHex] = make(map[string]struct{})
	}
	t.accessedAddresses[addrHex][slotHex] = struct{}{}
}

func (t *accessListTracer) buildAccessList() []AccessListEntry {
	entries := make([]AccessListEntry, 0, len(t.accessedAddresses))
	for addr, slots := range t.accessedAddresses {
		entry := AccessListEntry{
			Address:     addr,
			StorageKeys: make([]string, 0, len(slots)),
		}
		for slot := range slots {
			entry.StorageKeys = append(entry.StorageKeys, slot)
		}
		entries = append(entries, entry)
	}
	return entries
}

type accessListStateDB struct {
	reader StateReader
	tracer *accessListTracer
}

func (s *accessListStateDB) GetBalance(addr qvm.Address) *big.Int {
	s.tracer.recordAddress(addr)
	return s.reader.GetBalance(types.Address(addr))
}

func (s *accessListStateDB) SetBalance(addr qvm.Address, balance *big.Int) {
	s.tracer.recordAddress(addr)
}

func (s *accessListStateDB) GetNonce(addr qvm.Address) uint64 {
	s.tracer.recordAddress(addr)
	return s.reader.GetNonce(types.Address(addr))
}

func (s *accessListStateDB) SetNonce(addr qvm.Address, nonce uint64) {
	s.tracer.recordAddress(addr)
}

func (s *accessListStateDB) GetCode(addr qvm.Address) []byte {
	s.tracer.recordAddress(addr)
	return s.reader.GetCode(types.Address(addr))
}

func (s *accessListStateDB) SetCode(addr qvm.Address, code []byte) {
	s.tracer.recordAddress(addr)
}

func (s *accessListStateDB) GetCodeHash(addr qvm.Address) qvm.Hash {
	s.tracer.recordAddress(addr)
	code := s.reader.GetCode(types.Address(addr))
	if len(code) == 0 {
		return qvm.Hash{}
	}
	var h qvm.Hash
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(code)
	copy(h[:], hasher.Sum(nil))
	return h
}

func (s *accessListStateDB) GetCodeSize(addr qvm.Address) int {
	s.tracer.recordAddress(addr)
	return len(s.reader.GetCode(types.Address(addr)))
}

func (s *accessListStateDB) GetState(addr qvm.Address, key qvm.Hash) qvm.Hash {
	s.tracer.recordAddress(addr)
	s.tracer.recordStorage(addr, key)
	val := s.reader.GetState(types.Address(addr), types.Hash(key))
	return qvm.Hash(val)
}

func (s *accessListStateDB) SetState(addr qvm.Address, key, value qvm.Hash) {
	s.tracer.recordAddress(addr)
	s.tracer.recordStorage(addr, key)
}

func (s *accessListStateDB) Exist(addr qvm.Address) bool {
	s.tracer.recordAddress(addr)
	return s.GetNonce(addr) > 0 || len(s.GetCode(addr)) > 0
}

func (s *accessListStateDB) Empty(addr qvm.Address) bool {
	s.tracer.recordAddress(addr)
	return s.GetNonce(addr) == 0 && s.GetBalance(addr).Sign() == 0 && len(s.GetCode(addr)) == 0
}

func (s *accessListStateDB) Snapshot() int { return 0 }

func (s *accessListStateDB) RevertToSnapshot(id int) {}

func (s *accessListStateDB) SelfDestruct(addr qvm.Address) {
	s.tracer.recordAddress(addr)
}

func (s *accessListStateDB) HasSelfDestructed(addr qvm.Address) bool {
	s.tracer.recordAddress(addr)
	return false
}

func (s *accessListStateDB) AddAddressToAccessList(addr qvm.Address) {
	s.tracer.recordAddress(addr)
}

func (s *accessListStateDB) AddSlotToAccessList(addr qvm.Address, slot qvm.Hash) {
	s.tracer.recordAddress(addr)
	s.tracer.recordStorage(addr, slot)
}

func (s *accessListStateDB) AddressInAccessList(addr qvm.Address) bool {
	return false
}

func (s *accessListStateDB) SlotInAccessList(addr qvm.Address, slot qvm.Hash) (bool, bool) {
	return false, false
}
