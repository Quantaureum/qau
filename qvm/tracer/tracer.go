// Quantaureum Node source, version 1.0.0.
package tracer

import (
	"math/big"

	"github.com/quantaureum/qau/qvm"
)

type TraceConfig struct {
	EnableMemory     bool
	EnableStack      bool
	EnableStorage    bool
	EnableReturnData bool
	DisableStorage   bool
	Limit            int
}

type StructLog struct {
	Pc         uint64            `json:"pc"`
	Op         string            `json:"op"`
	Gas        uint64            `json:"gas"`
	GasCost    uint64            `json:"gasCost"`
	Memory     []string          `json:"memory,omitempty"`
	MemSize    int               `json:"memSize"`
	Stack      []string          `json:"stack,omitempty"`
	ReturnData string            `json:"returnData,omitempty"`
	Storage    map[string]string `json:"storage,omitempty"`
	Depth      int               `json:"depth"`
	Error      string            `json:"error,omitempty"`
}

type StructLogRes struct {
	Failed      bool        `json:"failed"`
	Gas         uint64      `json:"gas"`
	ReturnValue string      `json:"returnValue"`
	StructLogs  []StructLog `json:"structLogs"`
}

type CallFrame struct {
	Type    string      `json:"type"`
	From    string      `json:"from"`
	To      string      `json:"to"`
	Value   string      `json:"value,omitempty"`
	Gas     uint64      `json:"gas"`
	GasUsed uint64      `json:"gasUsed"`
	Input   string      `json:"input"`
	Output  string      `json:"output,omitempty"`
	Error   string      `json:"error,omitempty"`
	Calls   []CallFrame `json:"calls,omitempty"`
}

type CallTraceResult struct {
	Type    string      `json:"type"`
	From    string      `json:"from"`
	To      string      `json:"to"`
	Value   string      `json:"value,omitempty"`
	Gas     uint64      `json:"gas"`
	GasUsed uint64      `json:"gasUsed"`
	Input   string      `json:"input"`
	Output  string      `json:"output,omitempty"`
	Error   string      `json:"error,omitempty"`
	Calls   []CallFrame `json:"calls,omitempty"`
}

type PreStateResult map[string]AccountState

type AccountState struct {
	Balance string            `json:"balance"`
	Nonce   uint64            `json:"nonce"`
	Code    string            `json:"code,omitempty"`
	Storage map[string]string `json:"storage,omitempty"`
}

type BaseTracer struct{}

func (t *BaseTracer) CaptureStart(env *qvm.Environment, from, to qvm.Address, input []byte, gas uint64, value *big.Int) {
}
func (t *BaseTracer) CaptureState(env *qvm.Environment, pc uint64, op qvm.OpCode, gas, cost uint64, depth int, err error) {
}
func (t *BaseTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {}
func (t *BaseTracer) CaptureEnter(op qvm.OpCode, from, to qvm.Address, input []byte, gas uint64, value *big.Int) {
}
func (t *BaseTracer) CaptureExit(output []byte, gasUsed uint64, err error) {}
func (t *BaseTracer) GetResult() (any, error)                              { return nil, nil }
