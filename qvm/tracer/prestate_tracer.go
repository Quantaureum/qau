// Quantaureum Node source, version 1.0.0.
package tracer

import (
	"encoding/hex"
	"math/big"

	"github.com/quantaureum/qau/qvm"
)

type PrestateTracer struct {
	cfg       TraceConfig
	prestate  map[string]AccountState
	poststate map[string]AccountState
	stateDB   qvm.StateDB
}

func NewPrestateTracer(cfg TraceConfig) *PrestateTracer {
	return &PrestateTracer{
		cfg:       cfg,
		prestate:  make(map[string]AccountState),
		poststate: make(map[string]AccountState),
	}
}

func (t *PrestateTracer) CaptureStart(env *qvm.Environment, from, to qvm.Address, input []byte, gas uint64, value *big.Int) {
	t.stateDB = env.StateDB()
	t.captureAccount(from)
	t.captureAccount(to)
}

func (t *PrestateTracer) CaptureState(env *qvm.Environment, pc uint64, op qvm.OpCode, gas, cost uint64, depth int, err error) {
}

func (t *PrestateTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {}

func (t *PrestateTracer) CaptureEnter(op qvm.OpCode, from, to qvm.Address, input []byte, gas uint64, value *big.Int) {
	t.captureAccount(from)
	t.captureAccount(to)
}

func (t *PrestateTracer) CaptureExit(output []byte, gasUsed uint64, err error) {}

func (t *PrestateTracer) GetResult() (any, error) {
	return t.prestate, nil
}

func (t *PrestateTracer) captureAccount(addr qvm.Address) {
	addrHex := "0x" + hex.EncodeToString(addr[:])
	if _, exists := t.prestate[addrHex]; exists {
		return
	}

	state := AccountState{
		Nonce:   t.stateDB.GetNonce(addr),
		Balance: "0x" + hex.EncodeToString(t.stateDB.GetBalance(addr).Bytes()),
	}

	code := t.stateDB.GetCode(addr)
	if len(code) > 0 {
		state.Code = "0x" + hex.EncodeToString(code)
	}

	t.prestate[addrHex] = state
}
