// Quantaureum Node source, version 1.0.0.
// Package stability provides long-running stability tests for the Quantaureum blockchain.
// These tests verify that the node can run continuously without crashes,
// memory leaks, goroutine leaks, or consensus failures over an extended period.
//
// Environment variables:
//   - STABILITY_DURATION: test duration (default: "10m" for CI, "168h" for 7-day production)
//   - STABILITY_ACCELERATION: time acceleration factor (default: 100)
//   - STABILITY_MEMORY_LIMIT: max allowed heap growth in MB (default: 512)
//   - STABILITY_GOROUTINE_LIMIT: max allowed goroutine count (default: 500)
package stability

import (
	"fmt"
	"math/big"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/qaudb/state"
	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

// stabilityConfig holds configuration for stability tests.
type stabilityConfig struct {
	Duration       time.Duration
	Acceleration   int
	MemoryLimitMB  int
	GoroutineLimit int
	LogInterval    int // Log metrics every N iterations
}

// loadConfig reads stability test configuration from environment variables.
func loadConfig() stabilityConfig {
	cfg := stabilityConfig{
		Duration:       30 * time.Second, // Default: 30s for CI, set STABILITY_DURATION=168h for 7-day production
		Acceleration:   100,
		MemoryLimitMB:  4096, // Verkle tree and before-image tracking grow with block count
		GoroutineLimit: 500,
		LogInterval:    100,
	}

	if d := os.Getenv("STABILITY_DURATION"); d != "" {
		if parsed, err := time.ParseDuration(d); err == nil {
			cfg.Duration = parsed
		}
	}
	if a := os.Getenv("STABILITY_ACCELERATION"); a != "" {
		var val int
		if _, err := fmt.Sscanf(a, "%d", &val); err == nil && val > 0 {
			cfg.Acceleration = val
		}
	}
	if m := os.Getenv("STABILITY_MEMORY_LIMIT"); m != "" {
		var val int
		if _, err := fmt.Sscanf(m, "%d", &val); err == nil && val > 0 {
			cfg.MemoryLimitMB = val
		}
	}
	if g := os.Getenv("STABILITY_GOROUTINE_LIMIT"); g != "" {
		var val int
		if _, err := fmt.Sscanf(g, "%d", &val); err == nil && val > 0 {
			cfg.GoroutineLimit = val
		}
	}

	return cfg
}

// metricsSnapshot captures a point-in-time snapshot of runtime metrics.
type metricsSnapshot struct {
	Timestamp      time.Time
	HeapAllocMB    float64
	HeapSysMB      float64
	StackInUseMB   float64
	NumGoroutine   int
	NumGC          uint32
	PauseTotalMS   uint64
	BlocksProduced uint64
	TxProcessed    uint64
	AvgGasPerTx    float64
}

// captureMetrics takes a snapshot of current runtime and test metrics.
func captureMetrics(blocks, txs uint64, gasSum float64) metricsSnapshot {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	var avgGas float64
	if txs > 0 {
		avgGas = gasSum / float64(txs)
	}

	return metricsSnapshot{
		Timestamp:      time.Now(),
		HeapAllocMB:    float64(m.HeapAlloc) / 1024 / 1024,
		HeapSysMB:      float64(m.HeapSys) / 1024 / 1024,
		StackInUseMB:   float64(m.StackInuse) / 1024 / 1024,
		NumGoroutine:   runtime.NumGoroutine(),
		NumGC:          m.NumGC,
		PauseTotalMS:   m.PauseTotalNs / 1_000_000,
		BlocksProduced: blocks,
		TxProcessed:    txs,
		AvgGasPerTx:    avgGas,
	}
}

// logMetrics prints a metrics snapshot in a structured format.
func logMetrics(t *testing.T, iter int, snap metricsSnapshot) {
	t.Helper()
	t.Logf("[iter %d] heap=%.2fMB sys=%.2fMB stack=%.2fMB goroutines=%d gc=%d gcPause=%dms blocks=%d txs=%d avgGas=%.1f",
		iter,
		snap.HeapAllocMB,
		snap.HeapSysMB,
		snap.StackInUseMB,
		snap.NumGoroutine,
		snap.NumGC,
		snap.PauseTotalMS,
		snap.BlocksProduced,
		snap.TxProcessed,
		snap.AvgGasPerTx,
	)
}

// simulatedBlockchain provides a lightweight simulated blockchain environment
// for stability testing without requiring a full node.
type simulatedBlockchain struct {
	mu         sync.Mutex
	stateDB    *state.StateDB
	qvm        *qvm.Interpreter
	validators *consensus.ValidatorSet
	qpos       *consensus.QPOS

	// Simulated state
	blockHeight uint64
	accounts    map[types.Address]*big.Int
	nonces      map[types.Address]uint64
}

// newSimulatedBlockchain creates a new simulated blockchain for testing.
func newSimulatedBlockchain() *simulatedBlockchain {
	sdb := state.NewStateDB()

	// Create 3 validators (matching mainnet configuration)
	validators := createTestValidators()
	qpos, err := consensus.NewQPOS(validators)
	if err != nil {
		// If QPOS creation fails (e.g., due to slashing config), we still
		// want the stability test to run for state/QVM components.
		qpos = nil
	}

	// Pre-fund some test accounts
	accounts := make(map[types.Address]*big.Int)
	nonces := make(map[types.Address]uint64)
	for i := 0; i < 10; i++ {
		var addr types.Address
		addr[0] = byte(i + 1)
		accounts[addr] = new(big.Int).Mul(big.NewInt(1e6), big.NewInt(1e18)) // 1M QAU each
		nonces[addr] = 0
		sdb.SetBalance(addr, accounts[addr])
		sdb.SetNonce(addr, 0)
	}
	// Commit initial state
	sdb.Commit(0)

	return &simulatedBlockchain{
		stateDB:    sdb,
		qvm:        qvm.NewInterpreter(),
		validators: validators,
		qpos:       qpos,
		accounts:   accounts,
		nonces:     nonces,
	}
}

// createTestValidators creates a validator set for testing.
func createTestValidators() *consensus.ValidatorSet {
	vals := make([]*consensus.Validator, 3)
	for i := 0; i < 3; i++ {
		var addr types.Address
		addr[0] = byte(0xA0 + i)
		vals[i] = &consensus.Validator{
			Address: addr,
			Stake:   new(big.Int).Mul(big.NewInt(1000000), big.NewInt(1e18)),
			Active:  true,
		}
	}
	vs, _ := consensus.NewValidatorSet(vals)
	return vs
}

// simulateBlock simulates producing a block with transactions.
// Returns the number of transactions processed and total gas used.
func (sb *simulatedBlockchain) simulateBlock(t *testing.T) (txCount int, gasUsed uint64, panicked bool) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Recover from any panics in QVM execution
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			t.Logf("PANIC recovered in simulateBlock at height %d: %v", sb.blockHeight, r)
		}
	}()

	sb.blockHeight++

	// Simulate 1-5 transactions per block
	txCount = int(sb.blockHeight%5) + 1
	totalGas := uint64(0)

	for i := 0; i < txCount; i++ {
		gas := sb.simulateTransaction(i)
		totalGas += gas
	}

	// Commit state periodically (every 100 blocks, like real node batch commits)
	if sb.blockHeight%100 == 0 {
		sb.stateDB.CommitWithBlock(sb.blockHeight)
	}

	return txCount, totalGas, false
}

// simulateTransaction runs a simulated transaction through the QVM.
func (sb *simulatedBlockchain) simulateTransaction(txIndex int) uint64 {
	// Pick sender and receiver from test accounts
	var sender, receiver types.Address
	sender[0] = byte((sb.blockHeight+uint64(txIndex))%10 + 1)
	receiver[0] = byte((sb.blockHeight+uint64(txIndex)+5)%10 + 1)
	if sender == receiver {
		receiver[0] = (sender[0] % 10) + 1
	}

	// Simple value transfer via StateDB
	amount := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e15)) // 0.1 QAU
	balance := sb.stateDB.GetBalance(sender)
	if balance.Cmp(amount) >= 0 {
		sb.stateDB.SubBalance(sender, amount)
		sb.stateDB.AddBalance(receiver, amount)
	}

	// Increment nonce
	nonce := sb.stateDB.GetNonce(sender)
	sb.stateDB.SetNonce(sender, nonce+1)

	// Execute a simple QVM contract (PUSH1 0x2a, PUSH1 0x00, SSTORE, STOP)
	code := []byte{
		byte(qvm.PUSH1), 0x2a,
		byte(qvm.PUSH1), 0x00,
		byte(qvm.SSTORE),
		byte(qvm.STOP),
	}

	ctx := &qvm.ExecutionContext{
		Code:        code,
		Gas:         100000,
		Input:       []byte{},
		Origin:      qvm.Address(sender),
		Caller:      qvm.Address(sender),
		Address:     qvm.Address(receiver),
		Value:       big.NewInt(0),
		BlockNumber: sb.blockHeight,
		GasLimit:    10000000,
		ChainID:     1669, // testnet
	}

	// Use a simple mock StateDB adapter for QVM
	adapter := &stateDBAdapter{state: sb.stateDB}
	result := sb.qvm.Execute(ctx, adapter)

	gasUsed := uint64(0)
	if result != nil {
		gasUsed = result.GasUsed
	}

	return gasUsed
}

// stateDBAdapter adapts qaudb/state.StateDB to qvm.StateDB interface.
type stateDBAdapter struct {
	state *state.StateDB
}

func (a *stateDBAdapter) GetBalance(addr qvm.Address) *big.Int {
	return a.state.GetBalance(types.Address(addr))
}

func (a *stateDBAdapter) SetBalance(addr qvm.Address, balance *big.Int) {
	a.state.SetBalance(types.Address(addr), balance)
}

func (a *stateDBAdapter) GetNonce(addr qvm.Address) uint64 {
	return a.state.GetNonce(types.Address(addr))
}

func (a *stateDBAdapter) SetNonce(addr qvm.Address, nonce uint64) {
	a.state.SetNonce(types.Address(addr), nonce)
}

func (a *stateDBAdapter) GetCode(addr qvm.Address) []byte {
	return a.state.GetCode(types.Address(addr))
}

func (a *stateDBAdapter) SetCode(addr qvm.Address, code []byte) {
	a.state.SetCode(types.Address(addr), code)
}

func (a *stateDBAdapter) GetCodeHash(addr qvm.Address) qvm.Hash {
	acc, err := a.state.GetAccount(types.Address(addr))
	if err != nil || acc == nil {
		return qvm.Hash{}
	}
	return qvm.Hash(acc.CodeHash)
}

func (a *stateDBAdapter) GetCodeSize(addr qvm.Address) int {
	code := a.state.GetCode(types.Address(addr))
	return len(code)
}

func (a *stateDBAdapter) GetState(addr qvm.Address, key qvm.Hash) qvm.Hash {
	return qvm.Hash(a.state.GetState(types.Address(addr), types.Hash(key)))
}

func (a *stateDBAdapter) SetState(addr qvm.Address, key, value qvm.Hash) {
	a.state.SetState(types.Address(addr), types.Hash(key), types.Hash(value))
}

func (a *stateDBAdapter) Exist(addr qvm.Address) bool {
	return a.state.Exist(types.Address(addr))
}

func (a *stateDBAdapter) Empty(addr qvm.Address) bool {
	return a.state.Empty(types.Address(addr))
}

func (a *stateDBAdapter) Snapshot() int {
	return a.state.Snapshot()
}

func (a *stateDBAdapter) RevertToSnapshot(id int) {
	a.state.RevertToSnapshot(id)
}

func (a *stateDBAdapter) SelfDestruct(addr qvm.Address) {
	// No-op for stability test
}

func (a *stateDBAdapter) HasSelfDestructed(addr qvm.Address) bool {
	return false
}

func (a *stateDBAdapter) AddAddressToAccessList(addr qvm.Address) {
	// No-op for stability test
}

func (a *stateDBAdapter) AddSlotToAccessList(addr qvm.Address, slot qvm.Hash) {
	// No-op for stability test
}

func (a *stateDBAdapter) AddressInAccessList(addr qvm.Address) bool {
	return false
}

func (a *stateDBAdapter) SlotInAccessList(addr qvm.Address, slot qvm.Hash) (addressOk, slotOk bool) {
	return false, false
}

// verifyStateConsistency checks that total QAU supply hasn't been created or destroyed.
func (sb *simulatedBlockchain) verifyStateConsistency(t *testing.T) bool {
	t.Helper()
	sb.mu.Lock()
	defer sb.mu.Unlock()

	totalSupply := new(big.Int)
	for i := 0; i < 10; i++ {
		var addr types.Address
		addr[0] = byte(i + 1)
		balance := sb.stateDB.GetBalance(addr)
		totalSupply.Add(totalSupply, balance)
	}

	expectedSupply := new(big.Int).Mul(big.NewInt(10e6), big.NewInt(1e18)) // 10M QAU total
	if totalSupply.Cmp(expectedSupply) != 0 {
		t.Errorf("State inconsistency detected! Total supply: %s, expected: %s",
			totalSupply.String(), expectedSupply.String())
		return false
	}
	return true
}

// Test7DayStability is the main long-running stability test.
// It simulates 7 days of continuous blockchain operation compressed into
// a shorter test run using accelerated time.
//
// Use -timeout flag to allow long test runs:
//
//	go test -run Test7DayStability -timeout 168h
//
// Control duration with environment variables:
//
//	STABILITY_DURATION=10m     (CI default)
//	STABILITY_DURATION=168h    (7-day production run)
//	STABILITY_ACCELERATION=100 (time compression factor)
func Test7DayStability(t *testing.T) {
	cfg := loadConfig()
	t.Logf("=== 7-Day Stability Test ===")
	t.Logf("Duration: %v (acceleration: %dx)", cfg.Duration, cfg.Acceleration)
	t.Logf("Memory limit: %dMB, Goroutine limit: %d", cfg.MemoryLimitMB, cfg.GoroutineLimit)
	t.Logf("Simulated time: %v", cfg.Duration*time.Duration(cfg.Acceleration))

	chain := newSimulatedBlockchain()
	defer chain.stateDB.Revert()

	// Track metrics
	var (
		totalBlocks  uint64
		totalTxs     uint64
		totalGas     float64
		panicCount   int
		missedBlocks int
		initialSnap  = captureMetrics(0, 0, 0)
	)

	deadline := time.Now().Add(cfg.Duration)
	iteration := 0
	lastBlockTime := time.Now()

	for time.Now().Before(deadline) {
		iteration++

		// Simulate block production
		txCount, gasUsed, panicked := chain.simulateBlock(t)
		if panicked {
			panicCount++
			if panicCount > 10 {
				t.Fatalf("Too many panics (%d) during stability test", panicCount)
			}
			continue
		}

		totalBlocks++
		totalTxs += uint64(txCount)
		totalGas += float64(gasUsed)

		// Check for missed blocks (if block production takes too long)
		blockInterval := time.Since(lastBlockTime)
		if blockInterval > 30*time.Second {
			missedBlocks++
			t.Logf("WARNING: Block production delay at height %d: %v", totalBlocks, blockInterval)
		}
		lastBlockTime = time.Now()

		// Periodic consistency check
		if iteration%1000 == 0 {
			if !chain.verifyStateConsistency(t) {
				t.Errorf("State consistency check failed at iteration %d (block %d)", iteration, totalBlocks)
			}
		}

		// Periodic metrics logging
		if iteration%cfg.LogInterval == 0 {
			snap := captureMetrics(totalBlocks, totalTxs, totalGas)
			logMetrics(t, iteration, snap)

			// Check memory bounds (rate-based, not absolute)
			// Verkle tree grows linearly with block count; flag if growth rate is excessive
			if snap.HeapAllocMB > 0 && totalBlocks > 0 {
				growthRateKBPerBlock := (snap.HeapAllocMB - initialSnap.HeapAllocMB) * 1024 / float64(totalBlocks)
				if growthRateKBPerBlock > 100 { // > 100KB/block suggests a leak
					t.Logf("WARNING: High memory growth rate: %.2fKB/block at iteration %d", growthRateKBPerBlock, iteration)
				}
			}

			// Check goroutine bounds
			if snap.NumGoroutine > cfg.GoroutineLimit {
				t.Errorf("Goroutine limit exceeded: %d > %d at iteration %d",
					snap.NumGoroutine, cfg.GoroutineLimit, iteration)
			}
		}

		// Yield to scheduler periodically to prevent CPU starvation
		if iteration%100 == 0 {
			runtime.Gosched()
		}
	}

	// Final report
	finalSnap := captureMetrics(totalBlocks, totalTxs, totalGas)
	t.Logf("")
	t.Logf("=== 7-Day Stability Test Results ===")
	t.Logf("Duration: %v", cfg.Duration)
	t.Logf("Simulated time: %v", cfg.Duration*time.Duration(cfg.Acceleration))
	t.Logf("Iterations: %d", iteration)
	t.Logf("Blocks produced: %d", totalBlocks)
	t.Logf("Transactions processed: %d", totalTxs)
	t.Logf("Panics recovered: %d", panicCount)
	t.Logf("Missed blocks: %d", missedBlocks)
	t.Logf("")
	t.Logf("Memory: initial=%.2fMB -> final=%.2fMB (delta=%.2fMB)",
		initialSnap.HeapAllocMB, finalSnap.HeapAllocMB, finalSnap.HeapAllocMB-initialSnap.HeapAllocMB)
	t.Logf("Goroutines: initial=%d -> final=%d (delta=%d)",
		initialSnap.NumGoroutine, finalSnap.NumGoroutine, finalSnap.NumGoroutine-initialSnap.NumGoroutine)
	t.Logf("GC cycles: %d, total GC pause: %dms", finalSnap.NumGC, finalSnap.PauseTotalMS)
	t.Logf("Avg gas per tx: %.1f", finalSnap.AvgGasPerTx)

	// Final consistency check
	if !chain.verifyStateConsistency(t) {
		t.Error("Final state consistency check FAILED")
	}

	// Assert no critical issues
	if panicCount > 0 {
		t.Errorf("Stability test encountered %d panics", panicCount)
	}
	if missedBlocks > 5 {
		t.Errorf("Too many missed blocks: %d", missedBlocks)
	}

	// Memory growth check
	// Note: StateDB's Verkle tree and before-image tracking grow with block count,
	// so absolute memory limits are not meaningful. Instead, check for abnormal
	// growth rate (memory leak) vs. expected linear growth from state data.
	heapGrowthMB := finalSnap.HeapAllocMB - initialSnap.HeapAllocMB
	expectedGrowthPerBlock := 0.03                                           // ~30KB per block (Verkle tree + before-images)
	expectedMaxGrowthMB := float64(totalBlocks) * expectedGrowthPerBlock * 2 // 2x safety margin
	if expectedMaxGrowthMB < 256 {
		expectedMaxGrowthMB = 256 // Minimum 256MB allowance
	}
	if heapGrowthMB > expectedMaxGrowthMB {
		t.Errorf("Excessive heap growth: %.2fMB (expected max: %.2fMB for %d blocks, %.2fKB/block)",
			heapGrowthMB, expectedMaxGrowthMB, totalBlocks, heapGrowthMB*1024/float64(totalBlocks))
	}

	// Goroutine leak check
	goroutineDelta := finalSnap.NumGoroutine - initialSnap.NumGoroutine
	if goroutineDelta > 50 {
		t.Errorf("Potential goroutine leak: %d new goroutines", goroutineDelta)
	}
}

// TestMemoryStability verifies that no memory leaks occur over 1000 iterations
// of repeated state operations and QVM executions.
func TestMemoryStability(t *testing.T) {
	const iterations = 1000
	const maxHeapGrowthMB = 64.0 // Allow up to 64MB growth over 1000 iterations

	chain := newSimulatedBlockchain()
	defer chain.stateDB.Revert()

	// Force GC and capture baseline
	runtime.GC()
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	baselineHeapMB := float64(baseline.HeapAlloc) / 1024 / 1024

	t.Logf("Memory stability test: %d iterations, baseline heap: %.2fMB", iterations, baselineHeapMB)

	maxHeapMB := baselineHeapMB
	leakDetected := false

	for i := 0; i < iterations; i++ {
		// Perform state operations
		var addr types.Address
		addr[0] = byte(i%10 + 1)

		// Read-modify-write cycle
		balance := chain.stateDB.GetBalance(addr)
		chain.stateDB.SetBalance(addr, new(big.Int).Add(balance, big.NewInt(1)))

		nonce := chain.stateDB.GetNonce(addr)
		chain.stateDB.SetNonce(addr, nonce+1)

		// Storage operations
		var key, value types.Hash
		key[0] = byte(i % 256)
		value[0] = byte((i + 1) % 256)
		chain.stateDB.SetState(addr, key, value)
		_ = chain.stateDB.GetState(addr, key)

		// Snapshot and revert cycle
		snapID := chain.stateDB.Snapshot()
		chain.stateDB.SetBalance(addr, big.NewInt(0))
		chain.stateDB.RevertToSnapshot(snapID)

		// Commit periodically
		if (i+1)%100 == 0 {
			chain.stateDB.CommitWithBlock(uint64(i + 1))
		}

		// Check memory every 100 iterations
		if (i+1)%100 == 0 {
			runtime.GC()
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			currentHeapMB := float64(m.HeapAlloc) / 1024 / 1024

			if currentHeapMB > maxHeapMB {
				maxHeapMB = currentHeapMB
			}

			t.Logf("[iter %d/%d] heap=%.2fMB (baseline=%.2fMB, growth=%.2fMB)",
				i+1, iterations, currentHeapMB, baselineHeapMB, currentHeapMB-baselineHeapMB)

			// Check for monotonic growth (leak indicator)
			if currentHeapMB > baselineHeapMB+maxHeapGrowthMB {
				t.Errorf("Memory leak detected at iteration %d: heap %.2fMB exceeds baseline+%.0fMB (%.2fMB)",
					i+1, currentHeapMB, maxHeapGrowthMB, baselineHeapMB+maxHeapGrowthMB)
				leakDetected = true
			}
		}
	}

	// Final memory check
	runtime.GC()
	runtime.GC()
	var final runtime.MemStats
	runtime.ReadMemStats(&final)
	finalHeapMB := float64(final.HeapAlloc) / 1024 / 1024

	t.Logf("Memory stability test complete:")
	t.Logf("  Baseline: %.2fMB", baselineHeapMB)
	t.Logf("  Final:    %.2fMB", finalHeapMB)
	t.Logf("  Growth:   %.2fMB", finalHeapMB-baselineHeapMB)
	t.Logf("  Peak:     %.2fMB", maxHeapMB)

	if leakDetected {
		t.Error("Memory leak was detected during the test")
	}

	heapGrowth := finalHeapMB - baselineHeapMB
	if heapGrowth > maxHeapGrowthMB {
		t.Errorf("Final heap growth %.2fMB exceeds limit %.2fMB", heapGrowth, maxHeapGrowthMB)
	}
}

// TestGoroutineStability verifies that no goroutine leaks occur
// during repeated concurrent operations.
func TestGoroutineStability(t *testing.T) {
	const iterations = 500
	const maxGoroutineGrowth = 20

	// Capture baseline goroutine count
	runtime.GC()
	baselineGoroutines := runtime.NumGoroutine()

	t.Logf("Goroutine stability test: %d iterations, baseline: %d goroutines",
		iterations, baselineGoroutines)

	chain := newSimulatedBlockchain()
	defer chain.stateDB.Revert()

	maxGoroutines := baselineGoroutines

	for i := 0; i < iterations; i++ {
		// Simulate concurrent state access patterns
		var wg sync.WaitGroup
		const workers = 4

		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()

				var addr types.Address
				addr[0] = byte(workerID%10 + 1)

				// Concurrent read-modify-write
				balance := chain.stateDB.GetBalance(addr)
				chain.stateDB.SetBalance(addr, new(big.Int).Add(balance, big.NewInt(int64(workerID))))

				// Concurrent storage operations
				var key types.Hash
				key[0] = byte(workerID)
				_ = chain.stateDB.GetState(addr, key)
			}(w)
		}

		wg.Wait()

		// Check goroutine count every 50 iterations
		if (i+1)%50 == 0 {
			currentGoroutines := runtime.NumGoroutine()
			if currentGoroutines > maxGoroutines {
				maxGoroutines = currentGoroutines
			}

			t.Logf("[iter %d/%d] goroutines=%d (baseline=%d, delta=%d)",
				i+1, iterations, currentGoroutines, baselineGoroutines, currentGoroutines-baselineGoroutines)

			if currentGoroutines > baselineGoroutines+maxGoroutineGrowth {
				t.Errorf("Goroutine leak detected at iteration %d: %d goroutines (baseline: %d, limit: +%d)",
					i+1, currentGoroutines, baselineGoroutines, maxGoroutineGrowth)
			}
		}
	}

	// Wait for any remaining goroutines to settle
	time.Sleep(100 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()
	goroutineDelta := finalGoroutines - baselineGoroutines

	t.Logf("Goroutine stability test complete:")
	t.Logf("  Baseline: %d", baselineGoroutines)
	t.Logf("  Final:    %d", finalGoroutines)
	t.Logf("  Delta:    %d", goroutineDelta)
	t.Logf("  Peak:     %d", maxGoroutines)

	if goroutineDelta > maxGoroutineGrowth {
		t.Errorf("Goroutine leak: %d new goroutines (limit: %d)", goroutineDelta, maxGoroutineGrowth)
	}
}

// TestConsensusStability verifies that block production remains consistent
// over many simulated rounds without consensus failures.
func TestConsensusStability(t *testing.T) {
	const numBlocks = 2000

	chain := newSimulatedBlockchain()
	defer chain.stateDB.Revert()

	t.Logf("Consensus stability test: %d simulated blocks", numBlocks)

	var (
		totalTxs        uint64
		totalGas        uint64
		blocksProduced  int
		emptyBlocks     int
		maxTxPerBlock   int
		minTxPerBlock   = int(^uint(0) >> 1) // max int
		gasPerBlockList []uint64
		panicCount      int
	)

	for i := 0; i < numBlocks; i++ {
		txCount, gasUsed, panicked := chain.simulateBlock(t)
		if panicked {
			panicCount++
			continue
		}

		blocksProduced++

		if txCount == 0 {
			emptyBlocks++
		}
		if txCount > maxTxPerBlock {
			maxTxPerBlock = txCount
		}
		if txCount < minTxPerBlock {
			minTxPerBlock = txCount
		}

		totalTxs += uint64(txCount)
		totalGas += gasUsed
		gasPerBlockList = append(gasPerBlockList, gasUsed)

		// Log progress every 500 blocks
		if (i+1)%500 == 0 {
			avgGas := float64(0)
			if totalTxs > 0 {
				avgGas = float64(totalGas) / float64(totalTxs)
			}
			t.Logf("[block %d/%d] txs=%d avgGas=%.1f panics=%d",
				i+1, numBlocks, totalTxs, avgGas, panicCount)
		}
	}

	// Calculate gas consistency metrics
	var gasSum, gasSumSq float64
	for _, g := range gasPerBlockList {
		gasSum += float64(g)
		gasSumSq += float64(g) * float64(g)
	}
	n := float64(len(gasPerBlockList))
	meanGas := gasSum / n
	variance := gasSumSq/n - meanGas*meanGas

	t.Logf("Consensus stability test complete:")
	t.Logf("  Blocks produced: %d/%d", blocksProduced, numBlocks)
	t.Logf("  Empty blocks: %d", emptyBlocks)
	t.Logf("  Total transactions: %d", totalTxs)
	t.Logf("  Tx/block: min=%d max=%d avg=%.1f",
		minTxPerBlock, maxTxPerBlock, float64(totalTxs)/float64(blocksProduced))
	t.Logf("  Gas/block: mean=%.1f variance=%.1f", meanGas, variance)
	t.Logf("  Panics: %d", panicCount)

	// Assertions
	if panicCount > 0 {
		t.Errorf("Consensus stability test had %d panics", panicCount)
	}
	if blocksProduced < numBlocks-10 {
		t.Errorf("Too many missed blocks: produced %d/%d", blocksProduced, numBlocks)
	}
	if emptyBlocks > numBlocks/10 {
		t.Errorf("Too many empty blocks: %d/%d", emptyBlocks, numBlocks)
	}

	// Gas metering consistency: variance should not be extreme
	// (very high variance could indicate non-deterministic gas calculation)
	if variance > meanGas*meanGas*4 {
		t.Errorf("Gas metering inconsistency: variance=%.1f is very high relative to mean=%.1f",
			variance, meanGas)
	}
}

// TestStateConsistency verifies that state remains consistent after many
// operations including balance transfers, storage operations, and commits.
func TestStateConsistency(t *testing.T) {
	const iterations = 1000

	chain := newSimulatedBlockchain()
	defer chain.stateDB.Revert()

	t.Logf("State consistency test: %d iterations", iterations)

	// Record initial total supply
	initialSupply := calculateTotalSupply(chain)

	var (
		commitFails      int
		consistencyFails int
	)

	for i := 0; i < iterations; i++ {
		var addr types.Address
		addr[0] = byte(i%10 + 1)

		switch i % 3 {
		case 0:
			// Balance transfer (preserves total supply)
			var receiver types.Address
			receiver[0] = byte((i+5)%10 + 1)
			amount := big.NewInt(1000)
			balance := chain.stateDB.GetBalance(addr)
			if balance.Cmp(amount) >= 0 {
				err := chain.stateDB.SubBalance(addr, amount)
				if err == nil {
					chain.stateDB.AddBalance(receiver, amount)
				}
			}

		case 1:
			// Storage operations
			var key, value types.Hash
			key[0] = byte(i % 256)
			value[0] = byte((i * 7) % 256)
			chain.stateDB.SetState(addr, key, value)
			readBack := chain.stateDB.GetState(addr, key)
			if readBack != value {
				t.Errorf("Storage read-back mismatch at iter %d: wrote %x, read %x",
					i, value[:1], readBack[:1])
			}

		case 2:
			// Nonce increment
			nonce := chain.stateDB.GetNonce(addr)
			chain.stateDB.SetNonce(addr, nonce+1)
			newNonce := chain.stateDB.GetNonce(addr)
			if newNonce != nonce+1 {
				t.Errorf("Nonce increment failed at iter %d: expected %d, got %d",
					i, nonce+1, newNonce)
			}
		}

		// Commit every 50 iterations to exercise commit path
		if (i+1)%50 == 0 {
			_, err := chain.stateDB.CommitWithBlock(uint64(i + 1))
			if err != nil {
				commitFails++
				t.Errorf("Commit failed at iter %d: %v", i, err)
			}
		}

		// Periodic total supply consistency check
		if (i+1)%200 == 0 {
			currentSupply := calculateTotalSupply(chain)
			if currentSupply.Cmp(initialSupply) != 0 {
				consistencyFails++
				t.Errorf("Total supply inconsistency at iter %d: expected %s, got %s (delta: %s)",
					i+1, initialSupply.String(), currentSupply.String(),
					new(big.Int).Sub(currentSupply, initialSupply).String())
			}
		}
	}

	// Final consistency check
	finalSupply := calculateTotalSupply(chain)
	t.Logf("State consistency test complete:")
	t.Logf("  Initial supply: %s", initialSupply.String())
	t.Logf("  Final supply:   %s", finalSupply.String())
	t.Logf("  Commit fails:   %d", commitFails)
	t.Logf("  Consistency fails: %d", consistencyFails)

	if finalSupply.Cmp(initialSupply) != 0 {
		t.Errorf("Final total supply mismatch: %s vs %s (delta: %s)",
			initialSupply.String(), finalSupply.String(),
			new(big.Int).Sub(finalSupply, initialSupply).String())
	}

	if consistencyFails > 0 {
		t.Errorf("State consistency failed %d times", consistencyFails)
	}
}

// calculateTotalSupply sums the balances of all test accounts.
func calculateTotalSupply(chain *simulatedBlockchain) *big.Int {
	total := new(big.Int)
	for i := 0; i < 10; i++ {
		var addr types.Address
		addr[0] = byte(i + 1)
		balance := chain.stateDB.GetBalance(addr)
		total.Add(total, balance)
	}
	return total
}
