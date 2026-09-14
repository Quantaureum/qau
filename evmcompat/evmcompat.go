// Quantaureum Node source, version 1.0.0.
package evmcompat

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/qvm/precompiled"
	"github.com/quantaureum/qau/types"
)

var (
	ErrIncompatibleOpcode    = errors.New("evmcompat: incompatible opcode")
	ErrUnsupportedPrecompile = errors.New("evmcompat: unsupported precompile")
	ErrGasMismatch           = errors.New("evmcompat: gas calculation mismatch")
)

type EVMVersion int

const (
	EVMVersionLondon EVMVersion = iota
	EVMVersionParis
	EVMVersionShanghai
	EVMVersionCancun
	EVMVersionPrague
)

type CompatibilityLevel int

const (
	CompatLevelBasic CompatibilityLevel = iota
	CompatLevelStandard
	CompatLevelFull
)

type EVMCompatConfig struct {
	EVMVersion         EVMVersion
	CompatibilityLevel CompatibilityLevel
	EnablePrecompiles  bool
	EnableEIP1559      bool
	EnableEIP4844      bool
	EnableEIP7702      bool
	MaxCodeSize        int
	MaxInitCodeSize    int
}

func DefaultEVMCompatConfig() EVMCompatConfig {
	return EVMCompatConfig{
		EVMVersion:         EVMVersionCancun,
		CompatibilityLevel: CompatLevelStandard,
		EnablePrecompiles:  true,
		EnableEIP1559:      true,
		EnableEIP4844:      true,
		EnableEIP7702:      false,
		MaxCodeSize:        24576,
		MaxInitCodeSize:    49152,
	}
}

type OpcodeMapping struct {
	EVMCode    byte
	EVMName    string
	QAUCode    qvm.OpCode
	QAUName    string
	GasCost    uint64
	Compatible bool
}

type EVMCompatLayer struct {
	mu          sync.RWMutex
	config      EVMCompatConfig
	opcodeMap   map[byte]*OpcodeMapping
	qauToEVMMap map[qvm.OpCode]*OpcodeMapping
	precompiles map[types.Address]PrecompileHandler
}

type PrecompileHandler func(input []byte, gas uint64) ([]byte, uint64, error)

func NewEVMCompatLayer(config EVMCompatConfig) *EVMCompatLayer {
	layer := &EVMCompatLayer{
		config:      config,
		opcodeMap:   make(map[byte]*OpcodeMapping),
		qauToEVMMap: make(map[qvm.OpCode]*OpcodeMapping),
		precompiles: make(map[types.Address]PrecompileHandler),
	}

	layer.initOpcodeMappings()
	layer.initPrecompiles()

	return layer
}

func (l *EVMCompatLayer) initOpcodeMappings() {
	mappings := []OpcodeMapping{
		{0x00, "STOP", qvm.STOP, "STOP", 0, true},
		{0x01, "ADD", qvm.ADD, "ADD", 3, true},
		{0x02, "MUL", qvm.MUL, "MUL", 5, true},
		{0x03, "SUB", qvm.SUB, "SUB", 3, true},
		{0x04, "DIV", qvm.DIV, "DIV", 5, true},
		{0x05, "SDIV", qvm.SDIV, "SDIV", 5, true},
		{0x06, "MOD", qvm.MOD, "MOD", 5, true},
		{0x07, "SMOD", qvm.SMOD, "SMOD", 5, true},
		{0x08, "ADDMOD", qvm.ADDMOD, "ADDMOD", 8, true},
		{0x09, "MULMOD", qvm.MULMOD, "MULMOD", 8, true},
		{0x0A, "EXP", qvm.EXP, "EXP", 10, true},
		{0x0B, "SIGNEXTEND", qvm.SIGNEXTEND, "SIGNEXTEND", 5, true},
		{0x10, "LT", qvm.LT, "LT", 3, true},
		{0x11, "GT", qvm.GT, "GT", 3, true},
		{0x12, "SLT", qvm.SLT, "SLT", 3, true},
		{0x13, "SGT", qvm.SGT, "SGT", 3, true},
		{0x14, "EQ", qvm.EQ, "EQ", 3, true},
		{0x15, "ISZERO", qvm.ISZERO, "ISZERO", 3, true},
		{0x16, "AND", qvm.AND, "AND", 3, true},
		{0x17, "OR", qvm.OR, "OR", 3, true},
		{0x18, "XOR", qvm.XOR, "XOR", 3, true},
		{0x19, "NOT", qvm.NOT, "NOT", 3, true},
		{0x1A, "BYTE", qvm.BYTE, "BYTE", 3, true},
		{0x1B, "SHL", qvm.SHL, "SHL", 3, true},
		{0x1C, "SHR", qvm.SHR, "SHR", 3, true},
		{0x1D, "SAR", qvm.SAR, "SAR", 3, true},
		{0x20, "SHA3", qvm.SHA3, "SHA3", 30, true},
		{0x30, "ADDRESS", qvm.ADDRESS, "ADDRESS", 2, true},
		{0x31, "BALANCE", qvm.BALANCE, "BALANCE", 100, true},
		{0x32, "ORIGIN", qvm.ORIGIN, "ORIGIN", 2, true},
		{0x33, "CALLER", qvm.CALLER, "CALLER", 2, true},
		{0x34, "CALLVALUE", qvm.CALLVALUE, "CALLVALUE", 2, true},
		{0x35, "CALLDATALOAD", qvm.CALLDATALOAD, "CALLDATALOAD", 3, true},
		{0x36, "CALLDATASIZE", qvm.CALLDATASIZE, "CALLDATASIZE", 2, true},
		{0x37, "CALLDATACOPY", qvm.CALLDATACOPY, "CALLDATACOPY", 3, true},
		{0x38, "CODESIZE", qvm.CODESIZE, "CODESIZE", 2, true},
		{0x39, "CODECOPY", qvm.CODECOPY, "CODECOPY", 3, true},
		{0x3A, "GASPRICE", qvm.GASPRICE, "GASPRICE", 2, true},
		{0x3B, "EXTCODESIZE", qvm.EXTCODESIZE, "EXTCODESIZE", 100, true},
		{0x3C, "EXTCODECOPY", qvm.EXTCODECOPY, "EXTCODECOPY", 3, true},
		{0x3D, "RETURNDATASIZE", qvm.RETURNDATASIZE, "RETURNDATASIZE", 2, true},
		{0x3E, "RETURNDATACOPY", qvm.RETURNDATACOPY, "RETURNDATACOPY", 3, true},
		{0x3F, "EXTCODEHASH", qvm.EXTCODEHASH, "EXTCODEHASH", 100, true},
		{0x40, "BLOCKHASH", qvm.BLOCKHASH, "BLOCKHASH", 20, true},
		{0x41, "COINBASE", qvm.COINBASE, "COINBASE", 2, true},
		{0x42, "TIMESTAMP", qvm.TIMESTAMP, "TIMESTAMP", 2, true},
		{0x43, "NUMBER", qvm.NUMBER, "NUMBER", 2, true},
		{0x44, "DIFFICULTY", qvm.PREVRANDAO, "PREVRANDAO", 2, true}, // EVM DIFFICULTY maps to QVM PREVRANDAO
		{0x45, "GASLIMIT", qvm.GASLIMIT, "GASLIMIT", 2, true},
		{0x46, "CHAINID", qvm.CHAINID, "CHAINID", 2, true},
		{0x47, "SELFBALANCE", qvm.SELFBALANCE, "SELFBALANCE", 5, true},
		{0x48, "BASEFEE", qvm.BASEFEE, "BASEFEE", 2, true},
		{0x49, "BLOBHASH", qvm.BLOBHASH, "BLOBHASH", 2, true},
		{0x4A, "BLOBBASEFEE", qvm.BLOBBASEFEE, "BLOBBASEFEE", 2, true},
		{0x50, "POP", qvm.POP, "POP", 2, true},
		{0x51, "MLOAD", qvm.MLOAD, "MLOAD", 3, true},
		{0x52, "MSTORE", qvm.MSTORE, "MSTORE", 3, true},
		{0x53, "MSTORE8", qvm.MSTORE8, "MSTORE8", 3, true},
		{0x54, "SLOAD", qvm.SLOAD, "SLOAD", 100, true},
		{0x55, "SSTORE", qvm.SSTORE, "SSTORE", 100, true},
		{0x56, "JUMP", qvm.JUMP, "JUMP", 8, true},
		{0x57, "JUMPI", qvm.JUMPI, "JUMPI", 10, true},
		{0x58, "PC", qvm.PC, "PC", 2, true},
		{0x59, "MSIZE", qvm.MSIZE, "MSIZE", 2, true},
		{0x5A, "GAS", qvm.GAS, "GAS", 2, true},
		{0x5B, "JUMPDEST", qvm.JUMPDEST, "JUMPDEST", 1, true},
		{0x5C, "TLOAD", qvm.TLOAD, "TLOAD", 100, true},
		{0x5D, "TSTORE", qvm.TSTORE, "TSTORE", 100, true},
		{0x5E, "MCOPY", qvm.MCOPY, "MCOPY", 3, true},
		{0x5F, "PUSH0", qvm.PUSH0, "PUSH0", 2, true},
		{0x60, "PUSH1", qvm.PUSH1, "PUSH1", 3, true},
		{0x61, "PUSH2", qvm.PUSH2, "PUSH2", 3, true},
		{0x62, "PUSH3", qvm.PUSH3, "PUSH3", 3, true},
		{0x63, "PUSH4", qvm.PUSH4, "PUSH4", 3, true},
		{0x64, "PUSH5", qvm.PUSH5, "PUSH5", 3, true},
		{0x65, "PUSH6", qvm.PUSH6, "PUSH6", 3, true},
		{0x66, "PUSH7", qvm.PUSH7, "PUSH7", 3, true},
		{0x67, "PUSH8", qvm.PUSH8, "PUSH8", 3, true},
		{0x68, "PUSH9", qvm.PUSH9, "PUSH9", 3, true},
		{0x69, "PUSH10", qvm.PUSH10, "PUSH10", 3, true},
		{0x6A, "PUSH11", qvm.PUSH11, "PUSH11", 3, true},
		{0x6B, "PUSH12", qvm.PUSH12, "PUSH12", 3, true},
		{0x6C, "PUSH13", qvm.PUSH13, "PUSH13", 3, true},
		{0x6D, "PUSH14", qvm.PUSH14, "PUSH14", 3, true},
		{0x6E, "PUSH15", qvm.PUSH15, "PUSH15", 3, true},
		{0x6F, "PUSH16", qvm.PUSH16, "PUSH16", 3, true},
		{0x70, "PUSH17", qvm.PUSH17, "PUSH17", 3, true},
		{0x71, "PUSH18", qvm.PUSH18, "PUSH18", 3, true},
		{0x72, "PUSH19", qvm.PUSH19, "PUSH19", 3, true},
		{0x73, "PUSH20", qvm.PUSH20, "PUSH20", 3, true},
		{0x74, "PUSH21", qvm.PUSH21, "PUSH21", 3, true},
		{0x75, "PUSH22", qvm.PUSH22, "PUSH22", 3, true},
		{0x76, "PUSH23", qvm.PUSH23, "PUSH23", 3, true},
		{0x77, "PUSH24", qvm.PUSH24, "PUSH24", 3, true},
		{0x78, "PUSH25", qvm.PUSH25, "PUSH25", 3, true},
		{0x79, "PUSH26", qvm.PUSH26, "PUSH26", 3, true},
		{0x7A, "PUSH27", qvm.PUSH27, "PUSH27", 3, true},
		{0x7B, "PUSH28", qvm.PUSH28, "PUSH28", 3, true},
		{0x7C, "PUSH29", qvm.PUSH29, "PUSH29", 3, true},
		{0x7D, "PUSH30", qvm.PUSH30, "PUSH30", 3, true},
		{0x7E, "PUSH31", qvm.PUSH31, "PUSH31", 3, true},
		{0x7F, "PUSH32", qvm.PUSH32, "PUSH32", 3, true},
		{0x80, "DUP1", qvm.DUP1, "DUP1", 3, true},
		{0x81, "DUP2", qvm.DUP2, "DUP2", 3, true},
		{0x82, "DUP3", qvm.DUP3, "DUP3", 3, true},
		{0x83, "DUP4", qvm.DUP4, "DUP4", 3, true},
		{0x84, "DUP5", qvm.DUP5, "DUP5", 3, true},
		{0x85, "DUP6", qvm.DUP6, "DUP6", 3, true},
		{0x86, "DUP7", qvm.DUP7, "DUP7", 3, true},
		{0x87, "DUP8", qvm.DUP8, "DUP8", 3, true},
		{0x88, "DUP9", qvm.DUP9, "DUP9", 3, true},
		{0x89, "DUP10", qvm.DUP10, "DUP10", 3, true},
		{0x8A, "DUP11", qvm.DUP11, "DUP11", 3, true},
		{0x8B, "DUP12", qvm.DUP12, "DUP12", 3, true},
		{0x8C, "DUP13", qvm.DUP13, "DUP13", 3, true},
		{0x8D, "DUP14", qvm.DUP14, "DUP14", 3, true},
		{0x8E, "DUP15", qvm.DUP15, "DUP15", 3, true},
		{0x8F, "DUP16", qvm.DUP16, "DUP16", 3, true},
		{0x90, "SWAP1", qvm.SWAP1, "SWAP1", 3, true},
		{0x91, "SWAP2", qvm.SWAP2, "SWAP2", 3, true},
		{0x92, "SWAP3", qvm.SWAP3, "SWAP3", 3, true},
		{0x93, "SWAP4", qvm.SWAP4, "SWAP4", 3, true},
		{0x94, "SWAP5", qvm.SWAP5, "SWAP5", 3, true},
		{0x95, "SWAP6", qvm.SWAP6, "SWAP6", 3, true},
		{0x96, "SWAP7", qvm.SWAP7, "SWAP7", 3, true},
		{0x97, "SWAP8", qvm.SWAP8, "SWAP8", 3, true},
		{0x98, "SWAP9", qvm.SWAP9, "SWAP9", 3, true},
		{0x99, "SWAP10", qvm.SWAP10, "SWAP10", 3, true},
		{0x9A, "SWAP11", qvm.SWAP11, "SWAP11", 3, true},
		{0x9B, "SWAP12", qvm.SWAP12, "SWAP12", 3, true},
		{0x9C, "SWAP13", qvm.SWAP13, "SWAP13", 3, true},
		{0x9D, "SWAP14", qvm.SWAP14, "SWAP14", 3, true},
		{0x9E, "SWAP15", qvm.SWAP15, "SWAP15", 3, true},
		{0x9F, "SWAP16", qvm.SWAP16, "SWAP16", 3, true},
		{0xA0, "LOG0", qvm.LOG0, "LOG0", 375, true},
		{0xA1, "LOG1", qvm.LOG1, "LOG1", 375, true},
		{0xA2, "LOG2", qvm.LOG2, "LOG2", 375, true},
		{0xA3, "LOG3", qvm.LOG3, "LOG3", 375, true},
		{0xA4, "LOG4", qvm.LOG4, "LOG4", 375, true},
		{0xF0, "CREATE", qvm.CREATE, "CREATE", 32000, true},
		{0xF1, "CALL", qvm.CALL, "CALL", 100, true},
		{0xF2, "CALLCODE", qvm.CALLCODE, "CALLCODE", 100, true},
		{0xF3, "RETURN", qvm.RETURN, "RETURN", 0, true},
		{0xF4, "DELEGATECALL", qvm.DELEGATECALL, "DELEGATECALL", 100, true},
		{0xF5, "CREATE2", qvm.CREATE2, "CREATE2", 32000, true},
		{0xF6, "AUTH", qvm.AUTH, "AUTH", 100, true},             // EIP-7702
		{0xF7, "AUTHCALL", qvm.AUTHCALL, "AUTHCALL", 100, true}, // EIP-7702
		{0xFA, "STATICCALL", qvm.STATICCALL, "STATICCALL", 100, true},
		{0xFD, "REVERT", qvm.REVERT, "REVERT", 0, true},
		{0xFE, "INVALID", qvm.INVALID, "INVALID", 0, true},
		{0xFF, "SELFDESTRUCT", qvm.SELFDESTRUCT, "SELFDESTRUCT", 5000, true},
	}

	for i := range mappings {
		m := &mappings[i]
		l.opcodeMap[m.EVMCode] = m
		l.qauToEVMMap[m.QAUCode] = m
	}
}

func (l *EVMCompatLayer) initPrecompiles() {
	// Standard EVM precompiles (0x01-0x09)
	l.precompiles[types.BytesToAddress([]byte{0x01})] = wrapPrecompile(precompiled.NewECRecover())
	l.precompiles[types.BytesToAddress([]byte{0x02})] = wrapPrecompile(precompiled.NewSHA256())
	l.precompiles[types.BytesToAddress([]byte{0x03})] = wrapPrecompile(precompiled.NewRIPEMD160())
	l.precompiles[types.BytesToAddress([]byte{0x04})] = wrapPrecompile(precompiled.NewIdentity())
	l.precompiles[types.BytesToAddress([]byte{0x05})] = wrapPrecompile(precompiled.NewModExp())
	l.precompiles[types.BytesToAddress([]byte{0x06})] = wrapPrecompile(precompiled.NewBN256Add())
	l.precompiles[types.BytesToAddress([]byte{0x07})] = wrapPrecompile(precompiled.NewBN256ScalarMul())
	l.precompiles[types.BytesToAddress([]byte{0x08})] = wrapPrecompile(precompiled.NewBN256Pairing())
	l.precompiles[types.BytesToAddress([]byte{0x09})] = wrapPrecompile(precompiled.NewBlake2F())

	// Cancun-era precompile (0x0A)
	l.precompiles[types.BytesToAddress([]byte{0x0A})] = wrapPrecompile(precompiled.NewKeccak256())

	// Quantum-safe precompiles
	l.precompiles[types.BytesToAddress([]byte{100})] = wrapPrecompile(precompiled.NewDilithiumVerify())
	l.precompiles[types.BytesToAddress([]byte{101})] = wrapPrecompile(precompiled.NewKyberKEM())
}

// wrapPrecompile wraps a precompiled.PrecompiledContract into a PrecompileHandler.
// The handler checks gas sufficiency, calls the real contract, and returns the result.
func wrapPrecompile(c precompiled.PrecompiledContract) PrecompileHandler {
	return func(input []byte, gas uint64) ([]byte, uint64, error) {
		requiredGas := c.RequiredGas(input)
		if gas < requiredGas {
			return nil, 0, errors.New("out of gas")
		}
		result, err := c.Run(input)
		if err != nil {
			return nil, requiredGas, err
		}
		return result, requiredGas, nil
	}
}

func (l *EVMCompatLayer) TranslateOpcode(evmOpcode byte) (qvm.OpCode, uint64, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	mapping, ok := l.opcodeMap[evmOpcode]
	if !ok {
		return 0, 0, ErrIncompatibleOpcode
	}

	if !mapping.Compatible && l.config.CompatibilityLevel >= CompatLevelStandard {
		return 0, 0, ErrIncompatibleOpcode
	}

	return mapping.QAUCode, mapping.GasCost, nil
}

func (l *EVMCompatLayer) TranslateQAUOpcode(qauOpcode qvm.OpCode) (byte, string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	mapping, ok := l.qauToEVMMap[qauOpcode]
	if !ok {
		return 0, "", ErrIncompatibleOpcode
	}

	return mapping.EVMCode, mapping.EVMName, nil
}

func (l *EVMCompatLayer) TranslateBytecode(evmBytecode []byte) ([]byte, []uint64, error) {
	qauBytecode := make([]byte, 0, len(evmBytecode))
	gasCosts := make([]uint64, 0, len(evmBytecode))

	i := 0
	for i < len(evmBytecode) {
		op := evmBytecode[i]

		if op >= 0x60 && op <= 0x7F {
			pushSize := int(op - 0x60 + 1)
			qauOp, gas, err := l.TranslateOpcode(op)
			if err != nil {
				return nil, nil, err
			}
			qauBytecode = append(qauBytecode, byte(qauOp))
			gasCosts = append(gasCosts, gas)

			if i+pushSize < len(evmBytecode) {
				qauBytecode = append(qauBytecode, evmBytecode[i+1:i+1+pushSize]...)
			} else {
				// R11-EVMC-001 FIX: Zero-fill truncated PUSH data instead of
				// silently dropping it. This ensures the translated bytecode
				// has the correct length (opcode + pushSize bytes).
				available := len(evmBytecode) - i - 1
				if available > 0 {
					qauBytecode = append(qauBytecode, evmBytecode[i+1:i+1+available]...)
				}
				for k := available; k < pushSize; k++ {
					qauBytecode = append(qauBytecode, 0x00)
				}
			}
			for range pushSize {
				gasCosts = append(gasCosts, 0)
			}
			i += 1 + pushSize
			continue
		}

		qauOp, gas, err := l.TranslateOpcode(op)
		if err != nil {
			// Unknown/unmapped opcode - return error.
			// The caller (executor.go) handles translation failure by
			// falling back to native QVM execution. Swallowing errors here
			// would silently pass through invalid opcodes, masking real bugs.
			return nil, nil, err
		}
		qauBytecode = append(qauBytecode, byte(qauOp))
		gasCosts = append(gasCosts, gas)
		i++
	}

	return qauBytecode, gasCosts, nil
}

func (l *EVMCompatLayer) TranslateBytecodeToEVM(qauBytecode []byte) ([]byte, error) {
	evmBytecode := make([]byte, 0, len(qauBytecode))

	i := 0
	for i < len(qauBytecode) {
		op := qvm.OpCode(qauBytecode[i])

		if op.IsPush() {
			pushSize := op.PushSize()
			evmOp, _, err := l.TranslateQAUOpcode(op)
			if err != nil {
				return nil, err
			}
			evmBytecode = append(evmBytecode, evmOp)

			if i+pushSize < len(qauBytecode) {
				evmBytecode = append(evmBytecode, qauBytecode[i+1:i+1+pushSize]...)
			}
			i += 1 + pushSize
			continue
		}

		evmOp, _, err := l.TranslateQAUOpcode(op)
		if err != nil {
			return nil, err
		}
		evmBytecode = append(evmBytecode, evmOp)
		i++
	}

	return evmBytecode, nil
}

func (l *EVMCompatLayer) IsPrecompile(addr types.Address) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.precompiles[addr]
	return ok
}

func (l *EVMCompatLayer) ExecutePrecompile(addr types.Address, input []byte, gas uint64) ([]byte, uint64, error) {
	l.mu.RLock()
	handler, ok := l.precompiles[addr]
	l.mu.RUnlock()

	if !ok {
		return nil, 0, ErrUnsupportedPrecompile
	}

	return handler(input, gas)
}

func (l *EVMCompatLayer) ValidateEVMBytecode(bytecode []byte) error {
	// R11-EVMC-003 FIX: Acquire RLock for consistency with other methods
	// that access opcodeMap. Currently map is immutable after init, but
	// this protects against future runtime opcode registration.
	l.mu.RLock()
	defer l.mu.RUnlock()

	if len(bytecode) > l.config.MaxCodeSize {
		return fmt.Errorf("code size exceeds maximum: %d > %d", len(bytecode), l.config.MaxCodeSize)
	}

	i := 0
	for i < len(bytecode) {
		op := bytecode[i]

		if op >= 0x60 && op <= 0x7F {
			pushSize := int(op - 0x60 + 1)
			if i+pushSize >= len(bytecode) {
				return fmt.Errorf("truncated PUSH at position %d", i)
			}
			i += 1 + pushSize
			continue
		}

		if _, ok := l.opcodeMap[op]; !ok {
			return fmt.Errorf("unknown opcode 0x%02X at position %d", op, i)
		}
		i++
	}

	return nil
}

func (l *EVMCompatLayer) GetCompatibilityReport() map[string]any {
	l.mu.RLock()
	defer l.mu.RUnlock()

	totalOpcodes := len(l.opcodeMap)
	compatibleOpcodes := 0
	for _, m := range l.opcodeMap {
		if m.Compatible {
			compatibleOpcodes++
		}
	}

	return map[string]any{
		"evm_version":         l.config.EVMVersion,
		"compatibility_level": l.config.CompatibilityLevel,
		"total_opcodes":       totalOpcodes,
		"compatible_opcodes":  compatibleOpcodes,
		"compatibility_ratio": float64(compatibleOpcodes) / float64(totalOpcodes) * 100,
		"precompile_count":    len(l.precompiles),
		"eip1559_enabled":     l.config.EnableEIP1559,
		"eip4844_enabled":     l.config.EnableEIP4844,
		"eip7702_enabled":     l.config.EnableEIP7702,
		"max_code_size":       l.config.MaxCodeSize,
		"max_init_code_size":  l.config.MaxInitCodeSize,
	}
}

func (l *EVMCompatLayer) ConvertEVMTransaction(evmTx map[string]any) (*encoding.Transaction, error) {
	tx := &encoding.Transaction{
		Version: 1,
		Type:    encoding.TxTypeContract,
	}

	// ECON-H01 FIX (R29, 2026-07-26): Use parseUint64Flexible instead of
	// fmt.Sscanf("%d", ...). Sscanf silently fails on non-decimal input
	// (e.g., "0xff", "garbage"), leaving the field at 0. A malicious caller
	// could supply a hex-formatted nonce that silently became 0, bypassing
	// replay protection — a nonce substitution attack. parseUint64Flexible
	// returns an error on parse failure, forcing the caller to handle it.
	if nonce, ok := evmTx["nonce"].(string); ok {
		v, err := parseUint64Flexible(nonce)
		if err != nil {
			return nil, fmt.Errorf("invalid nonce %q: %w", nonce, err)
		}
		tx.Nonce = v
	}

	// ECON-H01 FIX (R29, 2026-07-26): Same fix for gas limit — Sscanf
	// silently failed on hex input, leaving GasLimit=0 (which the executor
	// would then treat as "intrinsic gas only", allowing underpriced
	// transactions). parseUint64Flexible rejects malformed input.
	if gasLimit, ok := evmTx["gas"].(string); ok {
		v, err := parseUint64Flexible(gasLimit)
		if err != nil {
			return nil, fmt.Errorf("invalid gas %q: %w", gasLimit, err)
		}
		tx.GasLimit = v
	}

	if gasPrice, ok := evmTx["gasPrice"].(string); ok {
		// R11-EVMC-002 FIX: Check SetString return value.
		tx.GasPrice = new(big.Int)
		if _, ok := tx.GasPrice.SetString(strings.TrimPrefix(gasPrice, "0x"), 16); !ok {
			return nil, fmt.Errorf("invalid gasPrice hex: %s", gasPrice)
		}
	}

	if value, ok := evmTx["value"].(string); ok {
		// R11-EVMC-002 FIX: Check SetString return value.
		tx.Value = new(big.Int)
		if _, ok := tx.Value.SetString(strings.TrimPrefix(value, "0x"), 16); !ok {
			return nil, fmt.Errorf("invalid value hex: %s", value)
		}
	}

	if data, ok := evmTx["data"].(string); ok {
		var err error
		tx.Data, err = hex.DecodeString(strings.TrimPrefix(data, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid data: %w", err)
		}
	}

	if to, ok := evmTx["to"].(string); ok && to != "" && to != "0x" {
		addrBytes, err := hex.DecodeString(strings.TrimPrefix(to, "0x"))
		if err != nil {
			return nil, fmt.Errorf("invalid to address: %w", err)
		}
		addr := types.BytesToAddress(addrBytes)
		tx.To = &addr
	}

	return tx, nil
}

// parseUint64Flexible parses a uint64 from a string that may be in decimal
// or hexadecimal form. The accepted formats are:
//
//   - Decimal: "0", "42", "18446744073709551615" (uint64 max)
//   - Hex with prefix: "0xff", "0XFF" (case-insensitive prefix and digits)
//   - Hex without prefix: "ff", "deadbeef" (only if the string contains at
//     least one non-decimal hex digit a-f/A-F; pure-digit strings are parsed
//     as decimal to avoid ambiguity with large decimal values)
//
// Empty or whitespace-only strings return an error. Strings containing
// non-hex characters (e.g., 'g', 'Z', '-') return an error. Overflowing
// values return an error.
//
// ECON-H01 FIX (R29, 2026-07-26): Replaces fmt.Sscanf("%d", ...) which
// silently fails on non-decimal input, leaving the output at 0. That
// silent failure is a nonce substitution attack vector: a malicious
// caller supplies a hex-formatted nonce that silently becomes 0,
// bypassing replay protection. This function forces the caller to handle
// parse errors explicitly.
func parseUint64Flexible(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty input")
	}

	// Strip 0x/0X prefix if present — explicit hex form.
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
		if s == "" {
			return 0, fmt.Errorf("empty hex value after 0x prefix")
		}
		// All characters must be valid hex digits.
		for _, c := range s {
			if !isHexChar(c) {
				return 0, fmt.Errorf("invalid hex character %q in %q", c, s)
			}
		}
		v, err := strconv.ParseUint(s, 16, 64)
		if err != nil {
			return 0, fmt.Errorf("hex parse: %w", err)
		}
		return v, nil
	}

	// No 0x prefix. Determine if it's pure decimal, hex (with at least
	// one non-decimal hex digit), or invalid (contains non-hex chars).
	hasNonDecimalHexChar := false
	for _, c := range s {
		if c >= '0' && c <= '9' {
			continue
		}
		if (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			hasNonDecimalHexChar = true
			continue
		}
		// Invalid character (e.g., 'g', 'Z', '-', '.').
		return 0, fmt.Errorf("invalid character %q in %q", c, s)
	}

	if hasNonDecimalHexChar {
		// Contains a-f/A-F → parse as hex.
		v, err := strconv.ParseUint(s, 16, 64)
		if err != nil {
			return 0, fmt.Errorf("hex parse: %w", err)
		}
		return v, nil
	}

	// Pure decimal digits.
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("decimal parse: %w", err)
	}
	return v, nil
}

// isHexChar returns true if c is a valid hexadecimal digit (0-9, a-f, A-F).
func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
