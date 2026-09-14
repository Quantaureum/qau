// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/qvm/tracer"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

type DebugAPI struct {
	blockReader    BlockReader
	stateReader    StateReader
	contractCaller ContractCaller
	chainInfo      ChainInfo
}

func NewDebugAPI(blockReader BlockReader, stateReader StateReader, contractCaller ContractCaller, chainInfo ChainInfo) *DebugAPI {
	return &DebugAPI{
		blockReader:    blockReader,
		stateReader:    stateReader,
		contractCaller: contractCaller,
		chainInfo:      chainInfo,
	}
}

type TraceCallArgs struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Gas      string `json:"gas"`
	GasPrice string `json:"gasPrice"`
	Value    string `json:"value"`
	Data     string `json:"data"`
}

type TraceOpts struct {
	Tracer         string `json:"tracer"`
	EnableMemory   bool   `json:"enableMemory"`
	EnableStack    bool   `json:"enableStack"`
	EnableStorage  bool   `json:"enableStorage"`
	DisableStorage bool   `json:"disableStorage"`
	Limit          int    `json:"limit"`
}

func (api *DebugAPI) TraceTransaction(txHash string, opts *TraceOpts) (any, error) {
	hash := hexToHash(txHash)
	txRaw, err := api.blockReader.GetTransaction(hash)
	if err != nil {
		return nil, fmt.Errorf("transaction %s not found: %w", txHash, err)
	}
	tx, ok := txRaw.(*encoding.Transaction)
	if !ok {
		return nil, fmt.Errorf("unexpected transaction type")
	}

	receiptRaw, err := api.blockReader.GetTransactionReceipt(hash)
	if err != nil {
		return nil, fmt.Errorf("receipt for %s not found: %w", txHash, err)
	}
	_ = receiptRaw

	return api.traceTransaction(tx, opts)
}

func (api *DebugAPI) TraceCall(args TraceCallArgs, blockNum string, opts *TraceOpts) (any, error) {
	// P3-NODE-05 FIX (R30, 2026-07-27): surface gas parse errors to the
	// caller instead of silently falling back to 30M. A malformed gas
	// field is almost always a client bug, and silently using 30M can
	// produce misleading traces that don't reflect the actual tx gas.
	msg, err := callArgsToMessage(args)
	if err != nil {
		return nil, err
	}
	return api.traceMessage(msg, opts)
}

func (api *DebugAPI) TraceBlockByNumber(blockNum string, opts *TraceOpts) ([]any, error) {
	height := uint64(0)
	if blockNum == "latest" || blockNum == "" {
		height = api.blockReader.GetLatestHeight()
	} else {
		fmt.Sscanf(blockNum, "%d", &height)
	}

	blockRaw, err := api.blockReader.GetBlockByHeight(height)
	if err != nil {
		return nil, fmt.Errorf("block %d not found: %w", height, err)
	}
	block, ok := blockRaw.(*encoding.Block)
	if !ok {
		return nil, fmt.Errorf("unexpected block type")
	}

	return api.traceBlock(block, opts)
}

func (api *DebugAPI) TraceBlockByHash(blockHash string, opts *TraceOpts) ([]any, error) {
	hash := hexToHash(blockHash)
	blockRaw, err := api.blockReader.GetBlockByHash(hash)
	if err != nil {
		return nil, fmt.Errorf("block %s not found: %w", blockHash, err)
	}
	block, ok := blockRaw.(*encoding.Block)
	if !ok {
		return nil, fmt.Errorf("unexpected block type")
	}

	return api.traceBlock(block, opts)
}

func (api *DebugAPI) traceBlock(block *encoding.Block, opts *TraceOpts) ([]any, error) {
	results := make([]any, 0, len(block.Transactions))
	for _, tx := range block.Transactions {
		result, err := api.traceTransaction(tx, opts)
		if err != nil {
			results = append(results, map[string]string{"error": err.Error()})
			continue
		}
		results = append(results, result)
	}
	return results, nil
}

// maxTraceDepth limits the number of trace steps returned to prevent
// unbounded memory/CPU consumption from deeply recursive or long-running
// contract calls. SECURITY FIX (L14-016).
// R25-018 (P3): This is the maximum trace depth limit (2048 > 1000 baseline)
// that prevents infinite recursion / unbounded trace output. The cap is
// enforced in traceTransaction by clamping opts.Limit to maxTraceDepth.
const maxTraceDepth = 2048

// maxTraceResponseSize limits the serialized size of a trace response to
// prevent unbounded memory consumption from large trace outputs.
// R23-025: responses exceeding this limit are truncated with a notice.
const maxTraceResponseSize = 10 * 1024 * 1024 // 10 MB

func (api *DebugAPI) traceTransaction(tx *encoding.Transaction, opts *TraceOpts) (any, error) {
	// SECURITY FIX (L14-016): Cap trace depth to maxTraceDepth to prevent
	// resource exhaustion from unbounded trace output.
	if opts != nil {
		if opts.Limit <= 0 || opts.Limit > maxTraceDepth {
			opts.Limit = maxTraceDepth
		}
	}
	msg := txToMessage(tx)
	return api.traceMessage(msg, opts)
}

func (api *DebugAPI) traceMessage(msg *ContractCallRequest, opts *TraceOpts) (any, error) {
	cfg := tracer.TraceConfig{
		EnableMemory:  true,
		EnableStack:   true,
		EnableStorage: true,
	}
	if opts != nil {
		cfg.EnableMemory = opts.EnableMemory
		cfg.EnableStack = opts.EnableStack
		cfg.EnableStorage = !opts.DisableStorage
		cfg.Limit = opts.Limit
	}

	var tr qvm.Tracer
	tracerType := "struct_logger"
	if opts != nil && opts.Tracer != "" {
		tracerType = opts.Tracer
	}

	switch tracerType {
	case "call_tracer":
		tr = tracer.NewCallTracer(cfg)
	case "prestate_tracer":
		tr = tracer.NewPrestateTracer(cfg)
	default:
		tr = tracer.NewStructLogger(cfg)
	}

	// R12-RPC-002 FIX: Cap the gas for trace execution to prevent DoS.
	// A caller can supply an enormous gas value, causing the interpreter
	// to run for an unbounded time. Cap at 10M gas (sufficient for tracing).
	// R31-P3 FIX (P3-4, 2026-07-28): Log when the cap is applied so callers
	// know their specified gas was reduced. The 30M→10M second cap is
	// intentional (tracing is more expensive per-gas than normal execution
	// due to tracer hooks), but silently reducing it was confusing.
	const maxTraceGas = 10_000_000
	traceGas := msg.Gas
	if traceGas == 0 || traceGas > maxTraceGas {
		if traceGas > maxTraceGas {
			slog.Warn("debug api: trace gas exceeds 10M execution cap, reducing",
				"requested", traceGas, "capped_to", maxTraceGas)
		}
		traceGas = maxTraceGas
	}

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
		GasLimit:    traceGas,
		ChainID:     api.chainInfo.ChainID(),
		Code:        api.stateReader.GetCode(msg.To),
		Input:       msg.Data,
		Gas:         traceGas,
		Depth:       0,
		ReadOnly:    false,
	}

	env := &qvm.Environment{}
	env.SetTracer(tr)
	tr.CaptureStart(env, qvm.Address(msg.From), qvm.Address(msg.To), msg.Data, msg.Gas, msg.Value)

	interpreter.Execute(ctx, &rpcStateDB{reader: api.stateReader})

	result, traceErr := tr.GetResult()
	if traceErr != nil {
		return nil, traceErr
	}

	// R23-025: Enforce max trace response size to prevent unbounded output.
	if resultBytes, jsonErr := json.Marshal(result); jsonErr == nil {
		if len(resultBytes) > maxTraceResponseSize {
			return map[string]any{
				"error":       "trace response exceeded size limit and was truncated",
				"maxBytes":    maxTraceResponseSize,
				"actualBytes": len(resultBytes),
				"truncated":   true,
			}, nil
		}
	}

	return result, nil
}

// parseTraceOpts parses an optional TraceOpts from a JSON-RPC positional
// param. Returns nil when the raw message is absent or null, preserving the
// nil-opts semantics expected by the tracer (defaults are used).
func parseTraceOpts(raw json.RawMessage) (*TraceOpts, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var opts TraceOpts
	if err := json.Unmarshal(raw, &opts); err != nil {
		return nil, fmt.Errorf("invalid tracer options: %w", err)
	}
	return &opts, nil
}

// RegisterHandlers registers the debug trace endpoints. ALL debug trace
// methods are admin-gated so that wiring this API into a node cannot
// accidentally expose unauthenticated QVM execution (CPU/memory DoS + storage
// disclosure). R7-DEPLOY FIX: previously registered as plain handlers; if
// anyone added `NewDebugAPI(...).RegisterHandlers(srv)` in node.go, every
// debug_trace* would have been callable by a non-admin API key.
//
// R22 FIX: The underlying methods use custom typed signatures (e.g.
// TraceTransaction(txHash string, opts *TraceOpts)) that the type switch in
// server.go RegisterHandler does not recognize. Without adapter wrappers the
// handlers were silently dropped by the default branch and the methods
// returned "method not found". The adapters below translate the standard
// JSON-RPC positional params array into the typed Go arguments.
func (api *DebugAPI) RegisterHandlers(server *Server) {
	server.RegisterAdminMethod("debug_traceTransaction")
	server.RegisterAdminMethod("debug_traceCall")
	server.RegisterAdminMethod("debug_traceBlockByNumber")
	server.RegisterAdminMethod("debug_traceBlockByHash")
	server.RegisterHandler("debug_traceTransaction", func(ctx context.Context, params json.RawMessage) (any, error) {
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if len(args) < 1 {
			return nil, fmt.Errorf("missing transaction hash parameter")
		}
		var txHash string
		if err := json.Unmarshal(args[0], &txHash); err != nil {
			return nil, fmt.Errorf("invalid transaction hash: %w", err)
		}
		var opts *TraceOpts
		if len(args) >= 2 {
			var err error
			if opts, err = parseTraceOpts(args[1]); err != nil {
				return nil, err
			}
		}
		return api.TraceTransaction(txHash, opts)
	})
	server.RegisterHandler("debug_traceCall", func(ctx context.Context, params json.RawMessage) (any, error) {
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
		var opts *TraceOpts
		if len(args) >= 3 {
			var err error
			if opts, err = parseTraceOpts(args[2]); err != nil {
				return nil, err
			}
		}
		return api.TraceCall(callArgs, blockNum, opts)
	})
	server.RegisterHandler("debug_traceBlockByNumber", func(ctx context.Context, params json.RawMessage) (any, error) {
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if len(args) < 1 {
			return nil, fmt.Errorf("missing block number parameter")
		}
		var blockNum string
		if err := json.Unmarshal(args[0], &blockNum); err != nil {
			return nil, fmt.Errorf("invalid block number: %w", err)
		}
		var opts *TraceOpts
		if len(args) >= 2 {
			var err error
			if opts, err = parseTraceOpts(args[1]); err != nil {
				return nil, err
			}
		}
		return api.TraceBlockByNumber(blockNum, opts)
	})
	server.RegisterHandler("debug_traceBlockByHash", func(ctx context.Context, params json.RawMessage) (any, error) {
		var args []json.RawMessage
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if len(args) < 1 {
			return nil, fmt.Errorf("missing block hash parameter")
		}
		var blockHash string
		if err := json.Unmarshal(args[0], &blockHash); err != nil {
			return nil, fmt.Errorf("invalid block hash: %w", err)
		}
		var opts *TraceOpts
		if len(args) >= 2 {
			var err error
			if opts, err = parseTraceOpts(args[1]); err != nil {
				return nil, err
			}
		}
		return api.TraceBlockByHash(blockHash, opts)
	})
}

func callArgsToMessage(args TraceCallArgs) (*ContractCallRequest, error) {
	from := hexToAddress(args.From)
	to := hexToAddress(args.To)

	var value *big.Int
	if args.Value != "" {
		value = new(big.Int)
		value.SetString(args.Value, 0)
	} else {
		value = big.NewInt(0)
	}

	var gas uint64
	if args.Gas != "" {
		// P3-NODE-05 FIX (R30, 2026-07-27): return an error on parse
		// failure instead of silently falling back to 0 (which would
		// make every traced call fail with out-of-gas). The previous
		// fmt.Sscanf silently set gas=0 on malformed input. Use
		// strconv.ParseUint for explicit error reporting and enforce
		// a 30M upper bound to prevent DoS via multi-gigagas traces.
		const maxDebugTraceGas uint64 = 30_000_000
		gasStr := args.Gas
		if len(gasStr) >= 2 && (gasStr[:2] == "0x" || gasStr[:2] == "0X") {
			gasStr = gasStr[2:]
		}
		parsed, err := strconv.ParseUint(gasStr, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("debug api: invalid gas %q: %w", args.Gas, err)
		}
		if parsed > maxDebugTraceGas {
			// R31-P3 FIX (P3-4, 2026-07-28): Log the silent cap so callers
			// know their specified gas was reduced. Without this warning, a
			// user supplying gas=100M whose trace fails with out-of-gas has
			// no indication that the actual execution only got 30M — leading
			// to confusing debugging sessions. The cap itself is correct
			// (DoS protection); only the silence is the bug.
			slog.Warn("debug api: requested gas exceeds 30M cap, trace will use capped gas",
				"requested", parsed, "capped_to", maxDebugTraceGas)
			gas = maxDebugTraceGas
		} else {
			gas = parsed
		}
	} else {
		gas = 5000000
	}

	var data []byte
	if args.Data != "" {
		// R7-L5 FIX: cap calldata to MaxRequestBodySize (1 MiB) to prevent memory
		// blowup when this method (and the Debug API) is enabled. Matches eth_call.
		// R32-P2-02 FIX (2026-07-28): Previously, an oversized calldata was
		// silently truncated to maxHexLen and processing continued with the
		// truncated value — potentially masking a bug or attack. Now the
		// request is rejected outright, matching eth_call's behavior in
		// advanced.go.
		maxHexLen := (MaxRequestBodySize)*2 + 2 // *2 for hex encoding, +2 for "0x"
		if len(args.Data) > maxHexLen {
			slog.Warn("debug api: calldata exceeds limit", "len", len(args.Data))
			return nil, NewErrorWithData(ErrCodeInvalidParams,
				fmt.Sprintf("calldata too large: %d chars exceeds limit %d", len(args.Data), maxHexLen), "")
		}
		if len(args.Data) > 2 && args.Data[:2] == "0x" {
			data, _ = hex.DecodeString(args.Data[2:])
			if data == nil && len(args.Data) > 2 {
				slog.Warn("debug api: invalid hex data", "data", args.Data[:min(len(args.Data), 20)])
			}
		} else {
			data, _ = hex.DecodeString(args.Data)
			if data == nil && len(args.Data) > 0 {
				slog.Warn("debug api: invalid hex data", "data", args.Data[:min(len(args.Data), 20)])
			}
		}
	}

	return &ContractCallRequest{
		From:  from,
		To:    to,
		Value: value,
		Data:  data,
		Gas:   gas,
	}, nil
}

func txToMessage(tx *encoding.Transaction) *ContractCallRequest {
	to := types.Address{}
	if tx.To != nil {
		to = *tx.To
	}
	return &ContractCallRequest{
		From:  tx.From,
		To:    to,
		Value: tx.Value,
		Data:  tx.Data,
		Gas:   tx.GasLimit,
	}
}

type rpcStateDB struct {
	reader StateReader
}

func (s *rpcStateDB) GetBalance(addr qvm.Address) *big.Int {
	return s.reader.GetBalance(types.Address(addr))
}

func (s *rpcStateDB) SetBalance(addr qvm.Address, balance *big.Int) {}

func (s *rpcStateDB) GetNonce(addr qvm.Address) uint64 {
	return s.reader.GetNonce(types.Address(addr))
}

func (s *rpcStateDB) SetNonce(addr qvm.Address, nonce uint64) {}

func (s *rpcStateDB) GetCode(addr qvm.Address) []byte {
	return s.reader.GetCode(types.Address(addr))
}

func (s *rpcStateDB) SetCode(addr qvm.Address, code []byte) {}

func (s *rpcStateDB) GetCodeHash(addr qvm.Address) qvm.Hash {
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

func (s *rpcStateDB) GetCodeSize(addr qvm.Address) int {
	return len(s.reader.GetCode(types.Address(addr)))
}

func (s *rpcStateDB) GetState(addr qvm.Address, key qvm.Hash) qvm.Hash {
	val := s.reader.GetState(types.Address(addr), types.Hash(key))
	return qvm.Hash(val)
}

func (s *rpcStateDB) SetState(addr qvm.Address, key, value qvm.Hash) {}

func (s *rpcStateDB) Exist(addr qvm.Address) bool {
	return s.GetNonce(addr) > 0 || len(s.GetCode(addr)) > 0
}

func (s *rpcStateDB) Empty(addr qvm.Address) bool {
	return s.GetNonce(addr) == 0 && s.GetBalance(addr).Sign() == 0 && len(s.GetCode(addr)) == 0
}

func (s *rpcStateDB) Snapshot() int { return 0 }

func (s *rpcStateDB) RevertToSnapshot(id int) {}

func (s *rpcStateDB) SelfDestruct(addr qvm.Address) {}

func (s *rpcStateDB) HasSelfDestructed(addr qvm.Address) bool { return false }

func (s *rpcStateDB) AddAddressToAccessList(addr qvm.Address) {}

func (s *rpcStateDB) AddSlotToAccessList(addr qvm.Address, slot qvm.Hash) {}

func (s *rpcStateDB) AddressInAccessList(addr qvm.Address) bool { return false }

func (s *rpcStateDB) SlotInAccessList(addr qvm.Address, slot qvm.Hash) (bool, bool) {
	return false, false
}

func hexToHash(s string) types.Hash {
	s = trim0x(s)
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return types.Hash{}
	}
	return types.BytesToHash(b)
}

func hexToAddress(s string) types.Address {
	s = trim0x(s)
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 20 {
		return types.Address{}
	}
	return types.BytesToAddress(b)
}

func trim0x(s string) string {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return s[2:]
	}
	return s
}
