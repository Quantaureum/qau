// Quantaureum Node source, version 1.0.0.
package qvm

import "math/big"

type Tracer interface {
	CaptureStart(env *Environment, from, to Address, input []byte, gas uint64, value *big.Int)
	CaptureState(env *Environment, pc uint64, op OpCode, gas, cost uint64, depth int, err error)
	CaptureEnd(output []byte, gasUsed uint64, err error)
	CaptureEnter(op OpCode, from, to Address, input []byte, gas uint64, value *big.Int)
	CaptureExit(output []byte, gasUsed uint64, err error)
	GetResult() (any, error)
}
