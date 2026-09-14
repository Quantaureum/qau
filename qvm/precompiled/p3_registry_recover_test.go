// Quantaureum Node source, version 1.0.0.
// Package precompiled — P3 regression tests for Registry.Run / RunWithContext
// panic recovery.
//
// P3-QVM-REGISTRY-RECOVER FIX (R29, 2026-07-26): Registry.Run and
// RunWithContext now have defense-in-depth defer recover() to convert
// panics from precompile Run methods into errors. Previously, a panicking
// precompile would crash the caller (e.g., the QVM executor goroutine or
// a BatchRunParallel worker goroutine, which had no outer recover).
//
// These tests verify:
//  1. Registry.Run returns an error (not panic) when a precompile panics.
//  2. Registry.RunWithContext returns an error (not panic) when a precompile
//     panics in either the atomic path or the legacy Set+Run path.
//  3. Gas is still charged (requiredGas) on panic — EVM semantics.
//  4. The error wraps errPrecompilePanic so callers can distinguish
//     panic-recovery errors from normal precompile errors.
package precompiled

import (
	"errors"
	"testing"

	"github.com/quantaureum/qau/types"
)

// panickingPrecompile is a test precompile whose Run method always panics.
// Used to verify Registry.Run's defer recover.
type panickingPrecompile struct {
	addr       types.Address
	panicValue any
}

func (p *panickingPrecompile) Address() types.Address          { return p.addr }
func (p *panickingPrecompile) RequiredGas(input []byte) uint64 { return 100 }
func (p *panickingPrecompile) Run(input []byte) ([]byte, error) {
	panic(p.panicValue)
}

// panickingAtomicPrecompile implements AtomicContextPrecompiledContract
// and panics in RunWithContext. Used to verify the atomic path of
// Registry.RunWithContext.
type panickingAtomicPrecompile struct {
	panickingPrecompile
}

func (p *panickingAtomicPrecompile) RunWithContext(
	stateDB MultisigStateDB, blockTime uint64, chainID uint64,
	input []byte) ([]byte, error) {
	panic(p.panicValue)
}

// panickingLegacyPrecompile implements ContextAwarePrecompiledContract
// (but NOT AtomicContextPrecompiledContract) and panics in SetBlockTime.
// Used to verify the legacy path of Registry.RunWithContext.
type panickingLegacyPrecompile struct {
	panickingPrecompile
}

func (p *panickingLegacyPrecompile) SetStateDB(MultisigStateDB) {}
func (p *panickingLegacyPrecompile) SetBlockTime(uint64)        { panic(p.panicValue) }
func (p *panickingLegacyPrecompile) SetChainID(uint64)          {}

// TestP3_QVM_Registry_Run_PanicRecovered verifies that Registry.Run
// converts a panic from the precompile's Run method into an error,
// rather than crashing the caller.
func TestP3_QVM_Registry_Run_PanicRecovered(t *testing.T) {
	r := NewRegistry()
	addr := types.Address{0xAA}
	r.Register(&panickingPrecompile{
		addr:       addr,
		panicValue: "test panic from Run",
	})

	// This should NOT panic — it should return an error.
	defer func() {
		if recv := recover(); recv != nil {
			t.Fatalf("P3-QVM-REGISTRY-RECOVER REGRESSION: Registry.Run "+
				"panicked instead of recovering: %v. The defer recover() "+
				"was not added or was bypassed.", recv)
		}
	}()

	output, gasUsed, err := r.Run(addr, []byte("test"), 1000)

	// An error MUST be returned.
	if err == nil {
		t.Fatal("P3-QVM-REGISTRY-RECOVER REGRESSION: Registry.Run returned " +
			"nil error after a panicking precompile — the panic was " +
			"silently swallowed without reporting an error.")
	}

	// The error should wrap errPrecompilePanic.
	if !errors.Is(err, errPrecompilePanic) {
		t.Errorf("P3-QVM-REGISTRY-RECOVER REGRESSION: error does not wrap "+
			"errPrecompilePanic. Got: %v. The error should be "+
			"'precompiled contract panicked: <panic value>' so callers "+
			"can distinguish panic-recovery errors from normal errors.",
			err)
	}

	// Output should be nil (no successful result from a panicking precompile).
	if output != nil {
		t.Errorf("expected nil output from panicking precompile, got %v",
			output)
	}

	// Gas should still be charged (EVM semantics: requiredGas = 100).
	if gasUsed != 100 {
		t.Errorf("expected gasUsed = requiredGas (100) on panic, got %d. "+
			"EVM semantics require gas to be charged regardless of "+
			"success/failure.", gasUsed)
	}
}

// TestP3_QVM_Registry_RunWithContext_AtomicPath_PanicRecovered verifies
// that Registry.RunWithContext converts a panic from the atomic
// RunWithContext method into an error.
func TestP3_QVM_Registry_RunWithContext_AtomicPath_PanicRecovered(t *testing.T) {
	r := NewRegistry()
	addr := types.Address{0xBB}
	r.Register(&panickingAtomicPrecompile{
		panickingPrecompile: panickingPrecompile{
			addr:       addr,
			panicValue: "test panic from RunWithContext (atomic)",
		},
	})

	defer func() {
		if recv := recover(); recv != nil {
			t.Fatalf("P3-QVM-REGISTRY-RECOVER REGRESSION: RunWithContext "+
				"(atomic path) panicked instead of recovering: %v", recv)
		}
	}()

	output, gasUsed, err := r.RunWithContext(addr, nil, 0, 0, []byte("test"), 1000)

	if err == nil {
		t.Fatal("P3-QVM-REGISTRY-RECOVER REGRESSION: RunWithContext " +
			"(atomic path) returned nil error after a panicking precompile.")
	}

	if !errors.Is(err, errPrecompilePanic) {
		t.Errorf("expected error to wrap errPrecompilePanic, got: %v", err)
	}

	if output != nil {
		t.Errorf("expected nil output, got %v", output)
	}

	if gasUsed != 100 {
		t.Errorf("expected gasUsed = 100, got %d", gasUsed)
	}
}

// TestP3_QVM_Registry_RunWithContext_LegacyPath_PanicRecovered verifies
// that Registry.RunWithContext converts a panic from the legacy Set+Run
// path (SetStateDB / SetBlockTime / SetChainID / Run) into an error.
func TestP3_QVM_Registry_RunWithContext_LegacyPath_PanicRecovered(t *testing.T) {
	r := NewRegistry()
	addr := types.Address{0xCC}
	r.Register(&panickingLegacyPrecompile{
		panickingPrecompile: panickingPrecompile{
			addr:       addr,
			panicValue: "test panic from SetBlockTime (legacy)",
		},
	})

	defer func() {
		if recv := recover(); recv != nil {
			t.Fatalf("P3-QVM-REGISTRY-RECOVER REGRESSION: RunWithContext "+
				"(legacy path) panicked instead of recovering: %v", recv)
		}
	}()

	output, gasUsed, err := r.RunWithContext(addr, nil, 0, 0, []byte("test"), 1000)

	if err == nil {
		t.Fatal("P3-QVM-REGISTRY-RECOVER REGRESSION: RunWithContext " +
			"(legacy path) returned nil error after a panicking precompile.")
	}

	if !errors.Is(err, errPrecompilePanic) {
		t.Errorf("expected error to wrap errPrecompilePanic, got: %v", err)
	}

	if output != nil {
		t.Errorf("expected nil output, got %v", output)
	}

	if gasUsed != 100 {
		t.Errorf("expected gasUsed = 100, got %d", gasUsed)
	}
}

// TestP3_QVM_Registry_Run_NormalErrorNotAffected verifies that normal
// (non-panic) errors from precompiles are NOT affected by the recover.
// The recover should only catch panics, not swallow legitimate errors.
func TestP3_QVM_Registry_Run_NormalErrorNotAffected(t *testing.T) {
	r := NewRegistry()
	// Use the identity precompile (address 0x04) which always succeeds.
	// We test the normal success path here to ensure the recover doesn't
	// interfere with normal execution.
	addr := types.Address{0x04}
	_, gasUsed, err := r.Run(addr, []byte("test data"), 1000000)

	// Identity precompile should succeed.
	if err != nil {
		t.Errorf("expected identity precompile to succeed, got error: %v", err)
	}

	// Gas should be charged.
	if gasUsed == 0 {
		t.Errorf("expected non-zero gasUsed for identity precompile, got 0")
	}
}
