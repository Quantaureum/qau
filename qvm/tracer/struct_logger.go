// Quantaureum Node source, version 1.0.0.
package tracer

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/qvm"
)

type StructLogger struct {
	cfg        TraceConfig
	logs       []StructLog
	storage    map[string]string
	output     []byte
	err        error
	failed     bool
	gasUsed    uint64
	initialGas uint64
}

func NewStructLogger(cfg TraceConfig) *StructLogger {
	return &StructLogger{
		cfg:     cfg,
		logs:    make([]StructLog, 0),
		storage: make(map[string]string),
	}
}

func (l *StructLogger) CaptureStart(env *qvm.Environment, from, to qvm.Address, input []byte, gas uint64, value *big.Int) {
	l.initialGas = gas
}

func (l *StructLogger) CaptureState(env *qvm.Environment, pc uint64, op qvm.OpCode, gas, cost uint64, depth int, err error) {
	if l.cfg.Limit > 0 && len(l.logs) >= l.cfg.Limit {
		return
	}

	info, valid := op.GetInfo()
	opName := "INVALID"
	if valid {
		opName = info.Name
	}

	log := StructLog{
		Pc:      pc,
		Op:      opName,
		Gas:     gas,
		GasCost: cost,
		Depth:   depth,
		MemSize: int(env.Memory().Size()),
	}

	if l.cfg.EnableMemory {
		log.Memory = l.formatMemory(env)
	}

	if l.cfg.EnableStack {
		log.Stack = l.formatStack(env)
	}

	if l.cfg.EnableStorage && !l.cfg.DisableStorage {
		log.Storage = l.storage
	}

	if err != nil {
		log.Error = err.Error()
	}

	l.logs = append(l.logs, log)
}

func (l *StructLogger) CaptureEnd(output []byte, gasUsed uint64, err error) {
	l.output = output
	l.gasUsed = gasUsed
	if err != nil {
		l.err = err
		l.failed = true
	}
}

func (l *StructLogger) CaptureEnter(op qvm.OpCode, from, to qvm.Address, input []byte, gas uint64, value *big.Int) {
}

func (l *StructLogger) CaptureExit(output []byte, gasUsed uint64, err error) {}

func (l *StructLogger) GetResult() (any, error) {
	returnValue := ""
	if l.output != nil {
		returnValue = "0x" + hex.EncodeToString(l.output)
	}

	return &StructLogRes{
		Failed:      l.failed,
		Gas:         l.gasUsed,
		ReturnValue: returnValue,
		StructLogs:  l.logs,
	}, nil
}

func (l *StructLogger) formatStack(env *qvm.Environment) []string {
	stack := env.Stack()
	result := make([]string, stack.Len())
	for i := 0; i < stack.Len(); i++ {
		word := stack.Data()[i]
		result[i] = "0x" + hex.EncodeToString(word[:])
	}
	return result
}

func (l *StructLogger) formatMemory(env *qvm.Environment) []string {
	mem := env.Memory()
	if mem.Size() == 0 {
		return nil
	}

	data := mem.Data()
	result := make([]string, 0, (len(data)+31)/32)
	for i := 0; i < len(data); i += 32 {
		end := i + 32
		if end > len(data) {
			end = len(data)
		}
		result = append(result, "0x"+hex.EncodeToString(data[i:end]))
	}
	return result
}

func (l *StructLogger) CaptureStorageChange(addr qvm.Address, key, value qvm.Hash) {
	addrHex := "0x" + hex.EncodeToString(addr[:])
	keyHex := "0x" + hex.EncodeToString(key[:])
	valueHex := "0x" + hex.EncodeToString(value[:])
	l.storage[fmt.Sprintf("%s-%s", addrHex, keyHex)] = valueHex
}
