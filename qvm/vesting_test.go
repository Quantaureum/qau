// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"fmt"
	"math/big"
	"os/exec"
	"strings"
	"testing"
)

// The test assembles the public QASM source at runtime. Compiled deployment
// artifacts are intentionally excluded from the repository.
//
// The real QASM contract uses these selectors (defined in linear_vesting.qasm):
//
//	0x86d1a69f = releasable()  — returns current releasable amount (vested - released)
//	0x15e4167e = release()     — transfers releasable QAU to beneficiary, returns 1 on success
//	0x96132521 = released()    — returns total released amount
//
// Storage layout (QASM):
//
//	slot 0: owner
//	slot 1: beneficiary
//	slot 2: start (absolute timestamp)
//	slot 3: cliffEnd (absolute timestamp = start + cliff)
//	slot 4: vestingEnd (absolute timestamp = start + duration)
//	slot 5: totalAmount
//	slot 6: released
func TestLinearVestingContract(t *testing.T) {
	bytecode := assembleLinearVesting(t)

	// Validate the deployed code
	validator := NewBytecodeValidator()
	valResult := validator.ValidateDeployedCode(bytecode)
	if !valResult.Valid {
		t.Fatalf("Deployed code validation failed: %+v", valResult.Errors)
	}

	// Setup
	callerAddr := Address{0x01}
	executor := NewExecutor()
	stateDB := newMockStateDB()
	stateDB.SetBalance(callerAddr, big.NewInt(1000000000))
	stateDB.SetNonce(callerAddr, 1)

	// Constructor args (order: beneficiary, start, cliff, duration, totalAmount)
	startTime := int64(1000000)
	beneficiaryAddr := Address{0x42}
	beneficiary := padAddress(beneficiaryAddr)
	start := padUint64(startTime)
	cliff := padUint64(3600)                                         // 1 hour (relative)
	duration := padUint64(7200)                                      // 2 hours (relative)
	totalAmount := padUint256Big(big.NewInt(1000), big.NewInt(1e18)) // 1000 QAU

	// Build initCode
	initCode := append(bytecode, beneficiary...)
	initCode = append(initCode, start...)
	initCode = append(initCode, cliff...)
	initCode = append(initCode, duration...)
	initCode = append(initCode, totalAmount...)

	// Create contract
	blockCtx := &BlockContext{
		BlockNumber: 1,
		Timestamp:   startTime,
		GasLimit:    8000000,
		Coinbase:    Address{0x10},
	}

	result, contractAddr := executor.Create(stateDB, callerAddr, initCode, 1000000, big.NewInt(0), blockCtx, 0)
	if result.Err != nil {
		t.Fatalf("Contract creation failed: %v", result.Err)
	}
	t.Logf("Contract created at %x, runtime code %d bytes", contractAddr, len(result.ReturnData))

	// Set contract balance so release() can transfer QAU to beneficiary.
	contractBalance := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18)) // 1000 QAU
	stateDB.SetBalance(contractAddr, contractBalance)

	runtimeCode := result.ReturnData

	// Helper: call releasable() at a given timestamp
	// QASM selector 0x86d1a69f = releasable()
	callReleasable := func(timestamp int64) *big.Int {
		ctx := &ExecutionContext{
			Origin: callerAddr, Caller: callerAddr, Address: contractAddr,
			Value: big.NewInt(0), BlockNumber: 1, Timestamp: timestamp,
			GasLimit: 8000000, Gas: 1000000,
			Code: runtimeCode, Input: hexToBytes("86d1a69f"),
			Depth: 0, ReadOnly: false,
		}
		res := executor.Execute(ctx, stateDB)
		if res.Err != nil {
			return nil
		}
		return new(big.Int).SetBytes(res.ReturnData)
	}

	// Helper: call released() at a given timestamp
	// QASM selector 0x96132521 = released()
	callReleased := func(timestamp int64) *big.Int {
		ctx := &ExecutionContext{
			Origin: callerAddr, Caller: callerAddr, Address: contractAddr,
			Value: big.NewInt(0), BlockNumber: 1, Timestamp: timestamp,
			GasLimit: 8000000, Gas: 1000000,
			Code: runtimeCode, Input: hexToBytes("96132521"),
			Depth: 0, ReadOnly: false,
		}
		res := executor.Execute(ctx, stateDB)
		if res.Err != nil {
			return nil
		}
		return new(big.Int).SetBytes(res.ReturnData)
	}

	// Helper: call release() at a given timestamp
	// QASM selector 0x15e4167e = release()
	// Returns 1 on success, reverts on failure
	callRelease := func(timestamp int64) (*big.Int, error) {
		ctx := &ExecutionContext{
			Origin: callerAddr, Caller: callerAddr, Address: contractAddr,
			Value: big.NewInt(0), BlockNumber: 1, Timestamp: timestamp,
			GasLimit: 100000000, Gas: 10000000,
			Code: runtimeCode, Input: hexToBytes("15e4167e"),
			Depth: 0, ReadOnly: false,
		}
		res := executor.Execute(ctx, stateDB)
		if res.Err != nil {
			return nil, res.Err
		}
		return new(big.Int).SetBytes(res.ReturnData), nil
	}

	// ===== Test 1: Before cliff (start + 1800s = 30min, cliff at 1h) =====
	t.Log("=== Test 1: Before cliff (30 min) ===")
	releasable := callReleasable(startTime + 1800)
	if releasable == nil {
		t.Fatal("releasable() before cliff: call failed")
	}
	if releasable.Sign() != 0 {
		t.Fatalf("releasable() before cliff: expected 0, got %s", releasable.String())
	}
	t.Logf("  releasable() = 0 (correct, before cliff)")

	// QASM contract behavior: release() is a no-op (returns 0) when releasable == 0,
	// it does NOT revert. See contracts/linear_vesting.qasm release_noop label.
	ret, err := callRelease(startTime + 1800)
	if err != nil {
		t.Fatalf("release() before cliff: should succeed (no-op) but got error: %v", err)
	}
	if ret.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("release() before cliff: expected 0 (no-op), got %s", ret.String())
	}
	t.Logf("  release() returned 0 (correct, no-op before cliff)")

	// ===== Test 2: After cliff, partially vested (start + 5400s = 1.5h) =====
	t.Log("=== Test 2: After cliff, partially vested (1.5h) ===")
	releasable = callReleasable(startTime + 5400)
	if releasable == nil {
		t.Fatal("releasable() after cliff: call failed")
	}
	// Expected: totalAmount * (time - start) / (vestingEnd - start) = 1000e18 * 5400 / 7200 = 750e18
	expected := new(big.Int).Mul(big.NewInt(750), big.NewInt(1e18))
	if releasable.Cmp(expected) != 0 {
		t.Fatalf("releasable() after cliff: expected %s, got %s", expected.String(), releasable.String())
	}
	t.Logf("  releasable() = %s (correct, 750 QAU)", releasable.String())

	// ===== Test 3: Fully vested (start + 7200s = 2h) =====
	t.Log("=== Test 3: Fully vested (2h) ===")
	releasable = callReleasable(startTime + 7200)
	if releasable == nil {
		t.Fatal("releasable() fully vested: call failed")
	}
	expectedFull := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	if releasable.Cmp(expectedFull) != 0 {
		t.Fatalf("releasable() fully vested: expected %s, got %s", expectedFull.String(), releasable.String())
	}
	t.Logf("  releasable() = %s (correct, 1000 QAU)", releasable.String())

	// ===== Test 4: release() after cliff (1.5h) =====
	t.Log("=== Test 4: release() after cliff (1.5h) ===")
	beneficiaryBalanceBefore := stateDB.GetBalance(beneficiaryAddr)
	released, err := callRelease(startTime + 5400)
	if err != nil {
		t.Fatalf("release() after cliff: should succeed but got error: %v", err)
	}
	// release() returns 1 on success
	if released.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("release() after cliff: expected return 1, got %s", released.String())
	}
	// Check released() storage updated
	releasedAmount := callReleased(startTime + 5400)
	expectedRelease := new(big.Int).Mul(big.NewInt(750), big.NewInt(1e18))
	if releasedAmount == nil || releasedAmount.Cmp(expectedRelease) != 0 {
		t.Fatalf("released() after release: expected %s, got %v", expectedRelease.String(), releasedAmount)
	}
	// Check beneficiary balance increased by 750 QAU
	beneficiaryBalanceAfter := stateDB.GetBalance(beneficiaryAddr)
	expectedBeneficiaryBalance := new(big.Int).Add(beneficiaryBalanceBefore, expectedRelease)
	if beneficiaryBalanceAfter.Cmp(expectedBeneficiaryBalance) != 0 {
		t.Fatalf("beneficiary balance: expected %s, got %s", expectedBeneficiaryBalance.String(), beneficiaryBalanceAfter.String())
	}
	t.Logf("  release() returned 1, released 750 QAU to beneficiary")

	// ===== Test 5: release() again at full vesting (2h) =====
	t.Log("=== Test 5: release() again at full vesting (2h) ===")
	beneficiaryBalanceBefore = stateDB.GetBalance(beneficiaryAddr)
	released2, err := callRelease(startTime + 7200)
	if err != nil {
		t.Fatalf("release() at full vesting: should succeed but got error: %v", err)
	}
	if released2.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("release() at full vesting: expected return 1, got %s", released2.String())
	}
	// Already released 750 QAU, so remaining = 1000 - 750 = 250 QAU
	releasedAmount = callReleased(startTime + 7200)
	expectedTotalReleased := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18))
	if releasedAmount == nil || releasedAmount.Cmp(expectedTotalReleased) != 0 {
		t.Fatalf("released() at full vesting: expected %s, got %v", expectedTotalReleased.String(), releasedAmount)
	}
	// Check beneficiary balance increased by 250 QAU (remaining)
	beneficiaryBalanceAfter = stateDB.GetBalance(beneficiaryAddr)
	expectedRemaining := new(big.Int).Mul(big.NewInt(250), big.NewInt(1e18))
	expectedBeneficiaryBalance = new(big.Int).Add(beneficiaryBalanceBefore, expectedRemaining)
	if beneficiaryBalanceAfter.Cmp(expectedBeneficiaryBalance) != 0 {
		t.Fatalf("beneficiary balance: expected %s, got %s", expectedBeneficiaryBalance.String(), beneficiaryBalanceAfter.String())
	}
	t.Logf("  release() returned 1, released remaining 250 QAU to beneficiary")

	// ===== Test 6: release() when nothing left =====
	// QASM contract behavior: release() is a no-op (returns 0) when releasable == 0.
	t.Log("=== Test 6: release() when fully released ===")
	ret, err = callRelease(startTime + 7200)
	if err != nil {
		t.Fatalf("release() when nothing left: should succeed (no-op) but got error: %v", err)
	}
	if ret.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("release() when nothing left: expected 0 (no-op), got %s", ret.String())
	}
	t.Logf("  release() returned 0 (correct, no-op when nothing left)")

	t.Log("=== ALL TESTS PASSED ===")
}

func assembleLinearVesting(t *testing.T) []byte {
	t.Helper()

	cmd := exec.Command("go", "run", "./cmd/qasm", "assemble", "contracts/linear_vesting.qasm")
	cmd.Dir = ".."
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("failed to assemble linear_vesting.qasm: %v", err)
	}

	bytecodeHex := strings.TrimSpace(string(output))
	bytecodeHex = strings.TrimPrefix(bytecodeHex, "0x")
	bytecode := hexToBytes(bytecodeHex)
	if len(bytecode) == 0 {
		t.Fatal("assembler returned empty bytecode")
	}
	return bytecode
}

func hexToBytes(hexStr string) []byte {
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	result := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		var b byte
		fmt.Sscanf(hexStr[i:i+2], "%02x", &b)
		result[i/2] = b
	}
	return result
}

func padAddress(addr Address) []byte {
	padded := make([]byte, 32)
	copy(padded[12:], addr[:])
	return padded
}

func padUint64(v int64) []byte {
	padded := make([]byte, 32)
	u := uint64(v)
	for i := 7; i >= 0; i-- {
		padded[24+i] = byte(u)
		u >>= 8
	}
	return padded
}

func padUint256Big(a, b *big.Int) []byte {
	bigVal := new(big.Int).Mul(a, b)
	padded := make([]byte, 32)
	bytes := bigVal.Bytes()
	copy(padded[32-len(bytes):], bytes)
	return padded
}
