// Quantaureum Node source, version 1.0.0.
package tracer

import (
	"encoding/hex"
	"math/big"

	"github.com/quantaureum/qau/qvm"
)

type CallTracer struct {
	cfg       TraceConfig
	callStack []*CallFrame
	root      *CallFrame
	depth     int
}

func NewCallTracer(cfg TraceConfig) *CallTracer {
	return &CallTracer{
		cfg:       cfg,
		callStack: make([]*CallFrame, 0),
	}
}

func (t *CallTracer) CaptureStart(env *qvm.Environment, from, to qvm.Address, input []byte, gas uint64, value *big.Int) {
	t.root = &CallFrame{
		Type:  "CALL",
		From:  "0x" + hex.EncodeToString(from[:]),
		To:    "0x" + hex.EncodeToString(to[:]),
		Gas:   gas,
		Input: "0x" + hex.EncodeToString(input),
		Calls: make([]CallFrame, 0),
	}
	if value != nil && value.Sign() > 0 {
		t.root.Value = "0x" + hex.EncodeToString(value.Bytes())
	}
	t.callStack = append(t.callStack, t.root)
	t.depth = 1
}

func (t *CallTracer) CaptureState(env *qvm.Environment, pc uint64, op qvm.OpCode, gas, cost uint64, depth int, err error) {
}

func (t *CallTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	if t.root != nil {
		t.root.GasUsed = gasUsed
		if output != nil {
			t.root.Output = "0x" + hex.EncodeToString(output)
		}
		if err != nil {
			t.root.Error = err.Error()
		}
	}
}

func (t *CallTracer) CaptureEnter(op qvm.OpCode, from, to qvm.Address, input []byte, gas uint64, value *big.Int) {
	callType := "CALL"
	switch op {
	case qvm.DELEGATECALL:
		callType = "DELEGATECALL"
	case qvm.STATICCALL:
		callType = "STATICCALL"
	case qvm.CREATE:
		callType = "CREATE"
	case qvm.CREATE2:
		callType = "CREATE2"
	}

	frame := &CallFrame{
		Type:  callType,
		From:  "0x" + hex.EncodeToString(from[:]),
		To:    "0x" + hex.EncodeToString(to[:]),
		Gas:   gas,
		Input: "0x" + hex.EncodeToString(input),
		Calls: make([]CallFrame, 0),
	}
	if value != nil && value.Sign() > 0 {
		frame.Value = "0x" + hex.EncodeToString(value.Bytes())
	}

	if len(t.callStack) > 0 {
		parent := t.callStack[len(t.callStack)-1]
		parent.Calls = append(parent.Calls, *frame)
	}

	t.callStack = append(t.callStack, frame)
	t.depth++
}

func (t *CallTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
	if len(t.callStack) > 0 {
		frame := t.callStack[len(t.callStack)-1]
		frame.GasUsed = gasUsed
		if output != nil {
			frame.Output = "0x" + hex.EncodeToString(output)
		}
		if err != nil {
			frame.Error = err.Error()
		}
		t.callStack = t.callStack[:len(t.callStack)-1]
		t.depth--
	}
}

func (t *CallTracer) GetResult() (any, error) {
	if t.root == nil {
		return nil, nil
	}
	return &CallTraceResult{
		Type:    t.root.Type,
		From:    t.root.From,
		To:      t.root.To,
		Value:   t.root.Value,
		Gas:     t.root.Gas,
		GasUsed: t.root.GasUsed,
		Input:   t.root.Input,
		Output:  t.root.Output,
		Error:   t.root.Error,
		Calls:   t.root.Calls,
	}, nil
}
