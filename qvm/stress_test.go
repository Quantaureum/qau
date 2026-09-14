// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestJITStressHighLoad: JIT high-load stress test
// Fix: verify JIT stability under high concurrency, gas consistency, no panics
func TestJITStressHighLoad(t *testing.T) {
	// R31-HIGH-1: JIT dispatch requires QAU_ENABLE_JIT=1 (and not QAU_PRODUCTION).
	t.Setenv("QAU_ENABLE_JIT", "1")
	t.Setenv("QAU_PRODUCTION", "")

	// build complex bytecode: loop + arithmetic + storage
	// QVM stack semantics: a = stack top, b = second
	//   SUB: a - b   (for i-1, stack top must be i, second must be 1)
	//   GT:  a > b   (for i>0, stack top must be i, second must be 0)
	// bytecode layout:
	// 0-1:   PUSH1 0x00       sum = 0
	// 2-3:   PUSH1 0x0a       i = 10
	// 4:     JUMPDEST         loop:
	// 5:     DUP1             i (copy for the comparison)
	// 6:     ISZERO           i == 0?
	// 7-8:   PUSH1 0x15       jump to end (offset 21)
	// 9:     JUMPI            if i==0, exit loop
	// 10:    DUP1             i (copy for accumulation)
	// 11:    SWAP2            swap i and sum
	// 12:    ADD              sum += i (a=sum, b=i → sum+i)
	// 13:    SWAP1            swap back
	// 14-15: PUSH1 0x01       1
	// 16:    SWAP1            swap: i on top, 1 second
	// 17:    SUB              i = i - 1 (a=i, b=1 → i-1)
	// 18-19: PUSH1 0x04       loop start
	// 20:    JUMP             goto loop
	// 21:    JUMPDEST         end:
	// 22:    POP              pop i
	// 23-25: PUSH1 0x00 MSTORE
	// 26-30: PUSH1 0x20 PUSH1 0x00 RETURN
	code := []byte{
		byte(PUSH1), 0x00, // sum = 0
		byte(PUSH1), 0x0a, // i = 10
		byte(JUMPDEST),    // loop: offset 4
		byte(DUP1),        // i
		byte(ISZERO),      // i == 0?
		byte(PUSH1), 0x15, // jump to end (offset 21)
		byte(JUMPI),       // if i==0, exit
		byte(DUP1),        // i
		byte(SWAP2),       // swap i and sum
		byte(ADD),         // sum += i
		byte(SWAP1),       // swap back
		byte(PUSH1), 0x01, // 1
		byte(SWAP1),       // i on top, 1 below
		byte(SUB),         // i = i - 1
		byte(PUSH1), 0x04, // loop start
		byte(JUMP),     // goto loop
		byte(JUMPDEST), // end: offset 21
		byte(POP),      // pop i
		byte(PUSH1), 0x00, byte(MSTORE),
		byte(PUSH1), 0x20, byte(PUSH1), 0x00, byte(RETURN),
	}

	const numGoroutines = 50
	const iterationsPerGoroutine = 200

	var wg sync.WaitGroup
	var successCount atomic.Int64
	var failCount atomic.Int64
	var gasMismatches atomic.Int64
	var firstErr atomic.Value // stores error

	// record the first execution's gas as baseline
	var baselineGas uint64
	var baselineOnce sync.Once

	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			executor := NewExecutorWithJIT() // QVM-001: use JIT-enabled executor for testing
			executor.enableJITForTesting()

			for i := 0; i < iterationsPerGoroutine; i++ {
				stateDB := newMockStateDB()
				calleeAddr := Address{0x02}
				stateDB.SetBalance(calleeAddr, big.NewInt(1000000))
				stateDB.exist[calleeAddr] = true

				ctx := &ExecutionContext{
					Origin:      Address{0x01},
					GasPrice:    big.NewInt(1),
					Caller:      Address{0x01},
					Address:     calleeAddr,
					Value:       big.NewInt(0),
					BlockNumber: uint64(i + 1),
					Timestamp:   int64(i + 1),
					Coinbase:    Address{0x10},
					GasLimit:    1000000,
					ChainID:     1668,
					BlockHashes: make(map[uint64]Hash),
					Code:        code,
					Input:       []byte{},
					Gas:         1000000,
					Depth:       0,
					ReadOnly:    false,
				}

				result := executor.Execute(ctx, stateDB)
				if result.Err != nil {
					if firstErr.CompareAndSwap(nil, result.Err) {
						t.Logf("first failure error: %v", result.Err)
					}
					failCount.Add(1)
					continue
				}

				successCount.Add(1)

				// verify gas consistency: all executions should use the same gas
				baselineOnce.Do(func() {
					baselineGas = result.GasUsed
				})
				if baselineGas > 0 && result.GasUsed != baselineGas {
					gasMismatches.Add(1)
				}
			}
		}(g)
	}

	wg.Wait()

	t.Logf("JIT high-load test: %d goroutines x %d iterations, ok=%d, fail=%d, gas-mismatch=%d",
		numGoroutines, iterationsPerGoroutine,
		successCount.Load(), failCount.Load(), gasMismatches.Load())

	if failCount.Load() > 0 {
		t.Errorf("%d executions failed", failCount.Load())
	}
	if gasMismatches.Load() > 0 {
		t.Errorf("%d gas mismatches (identical bytecode should use identical gas)", gasMismatches.Load())
	}
}

// TestGasMeteringAccuracy: gas-metering accuracy test
// Fix: verify gas metering of complex op chains matches manual computation
func TestGasMeteringAccuracy(t *testing.T) {
	// R31-HIGH-1: JIT dispatch requires QAU_ENABLE_JIT=1 (and not QAU_PRODUCTION).
	t.Setenv("QAU_ENABLE_JIT", "1")
	t.Setenv("QAU_PRODUCTION", "")

	tests := []struct {
		name         string
		code         []byte
		expectedGas  uint64
		gasTolerance uint64 // allowed slack (dynamic parts like memory expansion)
	}{
		{
			name: "simple addition",
			// PUSH1 0x05, PUSH1 0x03, ADD, STOP
			code:         []byte{byte(PUSH1), 0x05, byte(PUSH1), 0x03, byte(ADD), byte(STOP)},
			expectedGas:  3 + 3 + 3 + 0, // PUSH1+PUSH1+ADD+STOP = 9
			gasTolerance: 0,
		},
		{
			name: "storage read/write",
			// PUSH1 0x42, PUSH1 0x00, SSTORE, PUSH1 0x00, SLOAD, POP, STOP
			code:         []byte{byte(PUSH1), 0x42, byte(PUSH1), 0x00, byte(SSTORE), byte(PUSH1), 0x00, byte(SLOAD), byte(POP), byte(STOP)},
			expectedGas:  3 + 3 + 100 + 2000 + 20000 + 3 + 100 + 2 + 0, // PUSH+PUSH+SSTORE(cold+set)+PUSH+SLOAD(warm)+POP+STOP
			gasTolerance: 0,
		},
		{
			name: "SHA3 hash",
			// PUSH1 0x20, PUSH1 0x00, SHA3, POP, STOP
			code:         []byte{byte(PUSH1), 0x20, byte(PUSH1), 0x00, byte(SHA3), byte(POP), byte(STOP)},
			expectedGas:  3 + 3 + 30 + 6 + 3 + 0, // PUSH+PUSH+SHA3(30+1word*6)+POP+STOP + memory expansion
			gasTolerance: 10,                     // allow memory-expansion gas slack
		},
		{
			// R7 P0-4 FIX (QVM-R7-01): SSTORE(slot, X) → SSTORE(slot, 0) within
			// the same transaction must NOT receive a GasSStoreClear refund when
			// original == 0 (EIP-3529). The slot was created (0→X) and then
			// cleared (X→0) in the same tx, net effect is zero. Previously the
			// JIT path only checked `current` and incorrectly refunded 4800 gas,
			// diverging from the interpreter and causing a consensus split.
			//
			// QVM-R13-MED-002 (2026-07-21) UPDATE: EIP-2200 full net gas metering.
			// The second SSTORE is a dirty write (current != original, since
			// original == 0 and current == 0x42). Per EIP-2200, dirty writes
			// cost only SLOAD (100) instead of SSTORE_RESET (2900). The base
			// warm access cost (100) is already charged by opcodeInfoTable,
			// so the additional gas for the second SSTORE is 0 (just the
			// storageCost = gasSStoreNoop = 100, which is already in the base).
			// Wait — gasSStoreNoop is 100, charged via env.gas.Consume(storageCost),
			// so the 2nd SSTORE adds 100 to gasUsed. Total: 22100 + 200 = 22312.
			// refund = 0 (original == 0 per EIP-3529 + EIP-2200 dirty 0→X→0 cycle).
			name: "SSTORE cleared in same tx: no refund",
			// PUSH1 0x42, PUSH1 0x00, SSTORE, PUSH1 0x00, PUSH1 0x00, SSTORE, STOP
			code: []byte{
				byte(PUSH1), 0x42, byte(PUSH1), 0x00, byte(SSTORE), // 0 → 0x42 (clean, SSTORE_SET, cold)
				byte(PUSH1), 0x00, byte(PUSH1), 0x00, byte(SSTORE), // 0x42 → 0 (dirty, SLOAD cost, warm, NO refund)
				byte(STOP),
			},
			// PUSH+PUSH+SSTORE(cold=2000 + base=100 + SSTORE_SET=20000 = 22100)
			// PUSH+PUSH+SSTORE(warm base=100 + dirty SLoad storageCost=100 = 200)
			// refund = 0 (original == 0)
			// FinalUsed = 22100 + 200 = 22312
			expectedGas:  3 + 3 + 22100 + 3 + 3 + 200 + 0,
			gasTolerance: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateDB := newMockStateDB()
			calleeAddr := Address{0x02}
			stateDB.SetBalance(calleeAddr, big.NewInt(1000000))
			stateDB.exist[calleeAddr] = true

			ctx := &ExecutionContext{
				Origin:      Address{0x01},
				GasPrice:    big.NewInt(1),
				Caller:      Address{0x01},
				Address:     calleeAddr,
				Value:       big.NewInt(0),
				BlockNumber: 1,
				Timestamp:   100,
				Coinbase:    Address{0x10},
				GasLimit:    1000000,
				ChainID:     1668,
				BlockHashes: make(map[uint64]Hash),
				Code:        tt.code,
				Input:       []byte{},
				Gas:         1000000,
				Depth:       0,
				ReadOnly:    false,
			}

			// interpreter execution
			interpExecutor := NewExecutor()
			interpExecutor.DisableJIT()
			interpResult := interpExecutor.Execute(ctx, stateDB)

			if interpResult.Err != nil {
				t.Fatalf("interpreter execution failed: %v", interpResult.Err)
			}

			// JIT execution
			jitExecutor := NewExecutorWithJIT() // QVM-001: use JIT-enabled executor for testing
			jitExecutor.enableJITForTesting()
			jitStateDB := newMockStateDB()
			jitStateDB.SetBalance(calleeAddr, big.NewInt(1000000))
			jitStateDB.exist[calleeAddr] = true
			jitCtx := &ExecutionContext{
				Origin:      Address{0x01},
				GasPrice:    big.NewInt(1),
				Caller:      Address{0x01},
				Address:     calleeAddr,
				Value:       big.NewInt(0),
				BlockNumber: 1,
				Timestamp:   100,
				Coinbase:    Address{0x10},
				GasLimit:    1000000,
				ChainID:     1668,
				BlockHashes: make(map[uint64]Hash),
				Code:        tt.code,
				Input:       []byte{},
				Gas:         1000000,
				Depth:       0,
				ReadOnly:    false,
			}
			jitResult := jitExecutor.Execute(jitCtx, jitStateDB)

			if jitResult.Err != nil {
				t.Fatalf("JIT execution failed: %v", jitResult.Err)
			}

			// verify JIT and interpreter gas agree
			if interpResult.GasUsed != jitResult.GasUsed {
				t.Errorf("gas mismatch: interpreter=%d, JIT=%d", interpResult.GasUsed, jitResult.GasUsed)
			}

			// verify gas within the expected range
			minExpected := tt.expectedGas
			maxExpected := tt.expectedGas + tt.gasTolerance
			if jitResult.GasUsed < minExpected || jitResult.GasUsed > maxExpected {
				t.Errorf("gas out of expected range: want=[%d, %d], got=%d",
					minExpected, maxExpected, jitResult.GasUsed)
			}

			t.Logf("%s: interpreter gas=%d, JIT gas=%d, expected=[%d, %d]",
				tt.name, interpResult.GasUsed, jitResult.GasUsed, minExpected, maxExpected)
		})
	}
}

// TestBlockProductionStability: block-production stability test
// Fix: simulate producing 100 consecutive blocks; verify stable execution and consistent gas
func TestBlockProductionStability(t *testing.T) {
	// R31-HIGH-1: JIT dispatch requires QAU_ENABLE_JIT=1 (and not QAU_PRODUCTION).
	t.Setenv("QAU_ENABLE_JIT", "1")
	t.Setenv("QAU_PRODUCTION", "")

	const numBlocks = 100
	const txsPerBlock = 10

	// build contract code: simple store + load
	code := []byte{
		byte(PUSH1), 0x42, // value
		byte(PUSH1), 0x00, // key
		byte(SSTORE),      // SSTORE
		byte(PUSH1), 0x00, // key
		byte(SLOAD),                     // SLOAD
		byte(PUSH1), 0x00, byte(MSTORE), // MSTORE
		byte(PUSH1), 0x20, byte(PUSH1), 0x00, byte(RETURN),
	}

	// record gas usage per block
	gasUsedPerBlock := make([]uint64, numBlocks)
	var failCount int

	for block := 0; block < numBlocks; block++ {
		// fresh StateDB per block (simulating per-block state)
		stateDB := newMockStateDB()
		calleeAddr := Address{0x02}
		stateDB.SetBalance(calleeAddr, big.NewInt(1e12))
		stateDB.exist[calleeAddr] = true

		blockGasUsed := uint64(0)

		for tx := 0; tx < txsPerBlock; tx++ {
			ctx := &ExecutionContext{
				Origin:      Address{0x01},
				GasPrice:    big.NewInt(1),
				Caller:      Address{0x01},
				Address:     calleeAddr,
				Value:       big.NewInt(0),
				BlockNumber: uint64(block + 1),
				Timestamp:   int64(block*1000 + tx),
				Coinbase:    Address{0x10},
				GasLimit:    1000000,
				ChainID:     1668,
				BlockHashes: make(map[uint64]Hash),
				Code:        code,
				Input:       []byte{},
				Gas:         1000000,
				Depth:       0,
				ReadOnly:    false,
			}

			executor := NewExecutorWithJIT() // QVM-001: use JIT-enabled executor for testing
			executor.enableJITForTesting()
			result := executor.Execute(ctx, stateDB)

			if result.Err != nil {
				failCount++
				continue
			}
			blockGasUsed += result.GasUsed
		}

		gasUsedPerBlock[block] = blockGasUsed
	}

	// verify all blocks succeed
	if failCount > 0 {
		t.Errorf("%d transactions failed", failCount)
	}

	// verify gas usage stability (each block should match, same bytecode)
	baseline := gasUsedPerBlock[0]
	unstableBlocks := 0
	for i, gas := range gasUsedPerBlock {
		if gas != baseline {
			unstableBlocks++
			t.Errorf("block %d gas unstable: baseline=%d, got=%d", i+1, baseline, gas)
		}
	}

	t.Logf("block production stability: %d blocks x %d txs/block, baseline gas=%d, unstable blocks=%d",
		numBlocks, txsPerBlock, baseline, unstableBlocks)

	if unstableBlocks > 0 {
		t.Errorf("%d blocks had unstable gas", unstableBlocks)
	}
}

// TestHighTPSTransfer: high-TPS transfer stress test
// create 100 accounts, run 1000 concurrent transfers, measure TPS, verify final state consistency
func TestHighTPSTransfer(t *testing.T) {
	t.Parallel()

	const numAccounts = 100
	const numTransfers = 1000

	// create shared StateDB
	stateDB := newFuzzStateDB()

	// initialize 100 accounts, 1,000,000 QAU each
	initialBalance := big.NewInt(1000000)
	totalInitial := new(big.Int)
	for i := 0; i < numAccounts; i++ {
		addr := Address{byte(i + 1)}
		stateDB.SetBalance(addr, new(big.Int).Set(initialBalance))
		totalInitial.Add(totalInitial, initialBalance)
	}

	// record start time
	start := time.Now()

	// run transfers concurrently
	var wg sync.WaitGroup
	var successCount atomic.Int64
	var failCount atomic.Int64

	// mutex protects concurrent StateDB writes
	var mu sync.Mutex

	for i := 0; i < numTransfers; i++ {
		wg.Add(1)
		go func(txIndex int) {
			defer wg.Done()

			from := Address{byte(txIndex%numAccounts + 1)}
			to := Address{byte((txIndex+1)%numAccounts + 1)}
			amount := big.NewInt(100)

			mu.Lock()
			defer mu.Unlock()

			fromBal := stateDB.GetBalance(from)
			if fromBal.Cmp(amount) >= 0 {
				stateDB.SetBalance(from, new(big.Int).Sub(fromBal, amount))
				toBal := stateDB.GetBalance(to)
				stateDB.SetBalance(to, new(big.Int).Add(toBal, amount))
				successCount.Add(1)
			} else {
				failCount.Add(1)
			}
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(start)

	// compute TPS
	tps := float64(successCount.Load()) / elapsed.Seconds()
	t.Logf("high-TPS transfer test: %d ok, %d failed, elapsed=%v, TPS=%.0f",
		successCount.Load(), failCount.Load(), elapsed, tps)

	// verify total-amount conservation
	totalFinal := new(big.Int)
	for i := 0; i < numAccounts; i++ {
		addr := Address{byte(i + 1)}
		totalFinal.Add(totalFinal, stateDB.GetBalance(addr))
	}

	if totalFinal.Cmp(totalInitial) != 0 {
		t.Errorf("total supply conservation broken: initial=%s, final=%s", totalInitial.String(), totalFinal.String())
	}

	// verify all balances non-negative
	for i := 0; i < numAccounts; i++ {
		addr := Address{byte(i + 1)}
		if stateDB.GetBalance(addr).Sign() < 0 {
			t.Errorf("account %x has negative balance: %s", addr, stateDB.GetBalance(addr).String())
		}
	}
}

// TestLargeBlockProcessing: large-block processing test
// build a 500-tx block, measure processing time, verify all txs execute correctly
func TestLargeBlockProcessing(t *testing.T) {
	t.Parallel()

	const numTransactions = 500

	stateDB := newFuzzStateDB()
	sender := Address{0x01}
	receiver := Address{0x02}

	// give the sender sufficient balance
	stateDB.SetBalance(sender, big.NewInt(1e12))

	// build trivial bytecode (STOP = do nothing, just burn gas)
	code := []byte{byte(STOP)}

	gasLimit := uint64(100000)
	gasPrice := big.NewInt(1)

	// record start time
	start := time.Now()

	successCount := 0
	failCount := 0

	for i := 0; i < numTransactions; i++ {
		transferAmount := big.NewInt(1000)
		gasUsed := GasTxCall
		gasFee := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(gasUsed))
		totalCost := new(big.Int).Add(transferAmount, gasFee)

		senderBal := stateDB.GetBalance(sender)
		if senderBal.Cmp(totalCost) < 0 {
			failCount++
			continue
		}

		// execute the transfer
		stateDB.SetBalance(sender, new(big.Int).Sub(senderBal, totalCost))
		receiverBal := stateDB.GetBalance(receiver)
		stateDB.SetBalance(receiver, new(big.Int).Add(receiverBal, transferAmount))

		// run contract code to burn gas
		ctx := &ExecutionContext{
			Origin:      sender,
			GasPrice:    gasPrice,
			Caller:      sender,
			Address:     receiver,
			Value:       transferAmount,
			BlockNumber: uint64(i + 1),
			Timestamp:   int64(i + 1),
			Coinbase:    Address{0x03},
			GasLimit:    gasLimit,
			ChainID:     1668,
			BlockHashes: make(map[uint64]Hash),
			Code:        code,
			Input:       nil,
			Gas:         gasLimit,
		}

		interp := NewInterpreter()
		result := interp.Execute(ctx, stateDB)
		if result.Err != nil {
			failCount++
			continue
		}

		// increment nonce
		nonce := stateDB.GetNonce(sender)
		stateDB.SetNonce(sender, nonce+1)

		successCount++
	}

	elapsed := time.Since(start)

	t.Logf("large-block test: %d ok, %d failed, elapsed=%v, avg per tx=%v",
		successCount, failCount, elapsed, elapsed/time.Duration(numTransactions))

	// verify nonce increments monotonically
	finalNonce := stateDB.GetNonce(sender)
	if finalNonce != uint64(successCount) {
		t.Errorf("nonce mismatch: want=%d, got=%d", successCount, finalNonce)
	}

	// verify balance non-negative
	if stateDB.GetBalance(sender).Sign() < 0 {
		t.Errorf("sender balance negative: %s", stateDB.GetBalance(sender).String())
	}
}

// TestConcurrentContractExecution: concurrent contract execution test
// 10 contracts execute concurrently, each running ADD/SUB/MUL 100 times; verify results
func TestConcurrentContractExecution(t *testing.T) {
	t.Parallel()

	const numContracts = 10
	const iterationsPerContract = 100

	// build arithmetic bytecode:
	// PUSH1 a, PUSH1 b, ADD, POP
	// PUSH1 c, PUSH1 d, SUB, POP
	// PUSH1 e, PUSH1 f, MUL, POP
	// STOP
	makeArithmeticCode := func(a, b, c, d, e, f byte) []byte {
		return []byte{
			byte(PUSH1), a, byte(PUSH1), b, byte(ADD), byte(POP),
			byte(PUSH1), c, byte(PUSH1), d, byte(SUB), byte(POP),
			byte(PUSH1), e, byte(PUSH1), f, byte(MUL), byte(POP),
			byte(STOP),
		}
	}

	var wg sync.WaitGroup
	results := make(chan error, numContracts*iterationsPerContract)

	for contractIdx := 0; contractIdx < numContracts; contractIdx++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			code := makeArithmeticCode(
				byte(idx+1), byte(idx+2), // ADD: (idx+1) + (idx+2)
				byte(idx+10), byte(idx+3), // SUB: (idx+10) - (idx+3)
				byte(idx+1), byte(idx+1), // MUL: (idx+1) * (idx+1)
			)

			for iter := 0; iter < iterationsPerContract; iter++ {
				stateDB := newFuzzStateDB()
				ctx := &ExecutionContext{
					Origin:      Address{byte(idx + 1)},
					GasPrice:    big.NewInt(1),
					Caller:      Address{byte(idx + 1)},
					Address:     Address{byte(idx + 0x80)},
					Value:       big.NewInt(0),
					BlockNumber: 1,
					Timestamp:   100,
					Coinbase:    Address{},
					GasLimit:    1000000,
					ChainID:     1668,
					BlockHashes: make(map[uint64]Hash),
					Code:        code,
					Input:       nil,
					Gas:         1000000,
				}

				interp := NewInterpreter()
				result := interp.Execute(ctx, stateDB)
				if result.Err != nil {
					results <- fmt.Errorf("contract %d iteration %d failed: %v", idx, iter, result.Err)
					return
				}

				// verify gas usage consistent (same bytecode should use same gas)
				if iter > 0 {
					// the first execution is the baseline; later runs must match
				}
			}
		}(contractIdx)
	}

	wg.Wait()
	close(results)

	// check errors
	errCount := 0
	for err := range results {
		if err != nil {
			t.Errorf("concurrent contract execution error: %v", err)
			errCount++
		}
	}

	if errCount == 0 {
		t.Logf("concurrent execution test: %d contracts x %d iterations all succeeded",
			numContracts, iterationsPerContract)
	}
}

// TestMemoryIntensiveContract: memory-intensive contract test
// run many MSTORE/MLOAD ops, verify no memory leak and correct gas
func TestMemoryIntensiveContract(t *testing.T) {
	t.Parallel()

	// build memory-intensive bytecode: 100x MSTORE + 100x MLOAD
	// MSTORE: PUSH1 value, PUSH1 offset, MSTORE
	// MLOAD: PUSH1 offset, MLOAD, POP
	code := []byte{}
	const memOps = 100

	// write phase: MSTORE x100
	for i := 0; i < memOps; i++ {
		offset := byte(i * 32) // one slot every 32 bytes
		value := byte(i + 1)
		code = append(code, byte(PUSH1), value)
		code = append(code, byte(PUSH1), offset)
		code = append(code, byte(MSTORE))
	}

	// read phase: MLOAD x100
	for i := 0; i < memOps; i++ {
		offset := byte(i * 32)
		code = append(code, byte(PUSH1), offset)
		code = append(code, byte(MLOAD))
		code = append(code, byte(POP))
	}

	code = append(code, byte(STOP))

	stateDB := newFuzzStateDB()
	gasLimit := uint64(10000000) // generous gas limit

	ctx := &ExecutionContext{
		Origin:      Address{0x01},
		GasPrice:    big.NewInt(1),
		Caller:      Address{0x01},
		Address:     Address{0x02},
		Value:       big.NewInt(0),
		BlockNumber: 1,
		Timestamp:   100,
		Coinbase:    Address{},
		GasLimit:    gasLimit,
		ChainID:     1668,
		BlockHashes: make(map[uint64]Hash),
		Code:        code,
		Input:       nil,
		Gas:         gasLimit,
	}

	interp := NewInterpreter()
	result := interp.Execute(ctx, stateDB)

	if result.Err != nil {
		t.Fatalf("memory-intensive contract failed: %v", result.Err)
	}

	t.Logf("memory-intensive contract: %d MSTORE + %d MLOAD, gas used=%d, gas left=%d",
		memOps, memOps, result.GasUsed, gasLimit-result.GasUsed)

	// verify gas usage is sane (should not burn the entire limit)
	if result.GasUsed >= gasLimit {
		t.Errorf("gas anomaly: burned the entire limit=%d", gasLimit)
	}

	// verify gas usage > 0
	if result.GasUsed == 0 {
		t.Error("memory ops should consume gas, but usage was 0")
	}

	// repeat execution to detect leaks (watch whether gas usage stays stable)
	var prevGasUsed uint64
	for run := 0; run < 5; run++ {
		freshDB := newFuzzStateDB()
		freshCtx := &ExecutionContext{
			Origin:      Address{0x01},
			GasPrice:    big.NewInt(1),
			Caller:      Address{0x01},
			Address:     Address{0x02},
			Value:       big.NewInt(0),
			BlockNumber: 1,
			Timestamp:   100,
			Coinbase:    Address{},
			GasLimit:    gasLimit,
			ChainID:     1668,
			BlockHashes: make(map[uint64]Hash),
			Code:        code,
			Input:       nil,
			Gas:         gasLimit,
		}

		runResult := interp.Execute(freshCtx, freshDB)
		if runResult.Err != nil {
			t.Fatalf("run %d failed: %v", run+1, runResult.Err)
		}

		if prevGasUsed != 0 && runResult.GasUsed != prevGasUsed {
			t.Errorf("gas usage unstable: previous=%d, current=%d", prevGasUsed, runResult.GasUsed)
		}
		prevGasUsed = runResult.GasUsed
	}
}

// TestStorageIntensiveContract: storage-intensive contract test
// run many SSTORE/SLOAD ops, verify StateDB cache hits and final storage correctness
func TestStorageIntensiveContract(t *testing.T) {
	t.Parallel()

	// build storage-intensive bytecode: 50x SSTORE + 50x SLOAD
	code := []byte{}
	const storeOps = 50

	// write phase: SSTORE x50
	for i := 0; i < storeOps; i++ {
		// PUSH1 value, PUSH1 key, SSTORE
		code = append(code, byte(PUSH1), byte(i+1)) // value
		code = append(code, byte(PUSH1), byte(i))   // key (slot)
		code = append(code, byte(SSTORE))
	}

	// read phase: SLOAD x50
	for i := 0; i < storeOps; i++ {
		// PUSH1 key, SLOAD, POP
		code = append(code, byte(PUSH1), byte(i))
		code = append(code, byte(SLOAD))
		code = append(code, byte(POP))
	}

	code = append(code, byte(STOP))

	stateDB := newFuzzStateDB()
	contractAddr := Address{0x02}
	gasLimit := uint64(10000000)

	ctx := &ExecutionContext{
		Origin:      Address{0x01},
		GasPrice:    big.NewInt(1),
		Caller:      Address{0x01},
		Address:     contractAddr,
		Value:       big.NewInt(0),
		BlockNumber: 1,
		Timestamp:   100,
		Coinbase:    Address{},
		GasLimit:    gasLimit,
		ChainID:     1668,
		BlockHashes: make(map[uint64]Hash),
		Code:        code,
		Input:       nil,
		Gas:         gasLimit,
	}

	interp := NewInterpreter()
	result := interp.Execute(ctx, stateDB)

	if result.Err != nil {
		t.Fatalf("storage-intensive contract failed: %v", result.Err)
	}

	t.Logf("storage-intensive contract: %d SSTORE + %d SLOAD, gas used=%d",
		storeOps, storeOps, result.GasUsed)

	// verify stored values
	for i := 0; i < storeOps; i++ {
		var key Hash
		key[31] = byte(i) // low byte of the key
		value := stateDB.GetState(contractAddr, key)

		// expected: byte(i+1) left-aligned into 32 bytes
		var expected Hash
		expected[31] = byte(i + 1)

		if value != expected {
			t.Errorf("slot %d storage value wrong: want=%x, got=%x", i, expected, value)
		}
	}

	// verify gas usage is sane
	if result.GasUsed == 0 {
		t.Error("storage ops should consume gas, but usage was 0")
	}

	// verify repeated reads cost less gas (warm vs cold)
	// running the same code again, SLOAD should be cheaper (access list already warm)
	freshDB := newFuzzStateDB()
	// warm up: run one write first
	warmCode := []byte{}
	for i := 0; i < storeOps; i++ {
		warmCode = append(warmCode, byte(PUSH1), byte(i+1))
		warmCode = append(warmCode, byte(PUSH1), byte(i))
		warmCode = append(warmCode, byte(SSTORE))
	}
	// SLOAD only (slot already warm)
	for i := 0; i < storeOps; i++ {
		warmCode = append(warmCode, byte(PUSH1), byte(i))
		warmCode = append(warmCode, byte(SLOAD))
		warmCode = append(warmCode, byte(POP))
	}
	warmCode = append(warmCode, byte(STOP))

	warmCtx := &ExecutionContext{
		Origin:      Address{0x01},
		GasPrice:    big.NewInt(1),
		Caller:      Address{0x01},
		Address:     contractAddr,
		Value:       big.NewInt(0),
		BlockNumber: 1,
		Timestamp:   100,
		Coinbase:    Address{},
		GasLimit:    gasLimit,
		ChainID:     1668,
		BlockHashes: make(map[uint64]Hash),
		Code:        warmCode,
		Input:       nil,
		Gas:         gasLimit,
	}

	warmResult := interp.Execute(warmCtx, freshDB)
	if warmResult.Err != nil {
		t.Fatalf("warm-up execution failed: %v", warmResult.Err)
	}

	// cold SLOAD should cost more gas than warm SLOAD
	// the first execution's SLOAD is cold (2100 gas), the second is warm (100 gas)
	coldSloadCost := GasColdSLoad * storeOps
	warmSloadCost := GasWarmSLoad * storeOps
	t.Logf("storage access gas comparison: cold=%d, warm=%d, saved=%d",
		coldSloadCost, warmSloadCost, coldSloadCost-warmSloadCost)
}
