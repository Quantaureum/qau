// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"fmt"
	"math/big"
	"testing"
)

// TestQVMContractCreate tests contract creation with QVM native opcodes
func TestQVMContractCreate(t *testing.T) {
	callerAddr := Address{0x01}
	executor := NewExecutor()
	stateDB := newMockStateDB()
	stateDB.SetBalance(callerAddr, big.NewInt(1000000))
	// Simulate TxExecutor having already incremented the nonce before calling Create.
	// In production, TxExecutor.Execute increments nonce before calling Create,
	// so the nonce seen by Create is always >= 1.
	stateDB.SetNonce(callerAddr, 1)

	// QVM opcodes: PUSH1=0x10, MSTORE=0x51, RETURN=0x06
	// Simple contract: PUSH1 0x42, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN
	initCode := []byte{0x10, 0x42, 0x10, 0x00, 0x51, 0x10, 0x20, 0x10, 0x00, 0x06}

	t.Logf("Init code: %x", initCode)
	t.Logf("Init code length: %d bytes", len(initCode))

	blockCtx := &BlockContext{
		BlockNumber: 1,
		Timestamp:   1780743509,
		GasLimit:    8000000,
		Coinbase:    Address{0x10},
	}

	result, addr := executor.Create(stateDB, callerAddr, initCode, 1000000, big.NewInt(0), blockCtx, 0)

	fmt.Printf("Error: %v\n", result.Err)
	fmt.Printf("GasUsed: %d\n", result.GasUsed)
	fmt.Printf("ReturnData length: %d\n", len(result.ReturnData))
	if len(result.ReturnData) > 0 {
		fmt.Printf("ReturnData: %x\n", result.ReturnData)
	}
	fmt.Printf("Contract addr: %x\n", addr)
	fmt.Printf("Reverted: %v\n", result.Reverted)

	code := stateDB.GetCode(addr)
	fmt.Printf("Deployed code length: %d\n", len(code))
	if len(code) > 0 {
		fmt.Printf("Deployed code: %x\n", code)
	}

	if result.Err != nil {
		t.Fatalf("contract creation failed: %v", result.Err)
	}
	if len(code) == 0 {
		t.Fatal("no code deployed")
	}
}
