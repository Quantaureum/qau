// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/quantaureum/qau/qvm/precompiled"
	"github.com/quantaureum/qau/types"
)

// countingStateDB wraps mockStateDB and counts GetState calls. Used by
// QVM-R13-HIGH-002 tests to verify that each RunWithContext invocation reads
// from the stateDB it was called with (no cross-contamination).
type countingStateDB struct {
	*mockStateDB
	mu    sync.Mutex
	count int
}

func newCountingStateDB() *countingStateDB {
	return &countingStateDB{mockStateDB: newMockStateDB()}
}

func (c *countingStateDB) GetState(addr Address, key Hash) Hash {
	c.mu.Lock()
	c.count++
	c.mu.Unlock()
	return c.mockStateDB.GetState(addr, key)
}

func (c *countingStateDB) GetCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// TestQVM_R13_HIGH_002_MultisigImplementsAtomicInterface verifies that the
// multisig precompile implements AtomicContextPrecompiledContract.
//
// QVM-R13-HIGH-002 (2026-07-21): Without this interface, the QVM executor
// would fall back to the legacy injectPrecompileContext + Run sequence, which
// has a TOCTOU race in parallel execution mode.
func TestQVM_R13_HIGH_002_MultisigImplementsAtomicInterface(t *testing.T) {
	registry := precompiled.NewRegistry()
	multisigAddr := types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66}
	pc := registry.Get(multisigAddr)
	if pc == nil {
		t.Fatal("multisig precompile not registered at 0x66")
	}

	if _, ok := pc.(precompiled.AtomicContextPrecompiledContract); !ok {
		t.Fatal("multisig precompile should implement AtomicContextPrecompiledContract")
	}
}

// TestQVM_R13_HIGH_002_RegistryRunWithContext_Multisig verifies that
// Registry.RunWithContext correctly dispatches to the multisig precompile's
// RunWithContext method (atomic path) and produces correct gas accounting.
//
// QVM-R13-HIGH-002 (2026-07-21): This is a behavior parity test — the new
// atomic path must produce identical gas results to the legacy path.
//
// We verify gasUsed and that the call succeeds (no error). We don't verify
// the actual isSigner result because of a pre-existing storage layout
// mismatch in the multisig precompile (BytesToAddress right-aligns but
// registerWallet left-aligns signer storage) — that's a separate bug to fix.
func TestQVM_R13_HIGH_002_RegistryRunWithContext_Multisig(t *testing.T) {
	registry := precompiled.NewRegistry()
	multisigAddr := types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66}

	// Set up a stateDB with a wallet containing one signer.
	sdb := newMockStateDB()
	walletAddr := types.Address{0xAB, 0xCD}
	signerAddr := types.Address{0x11, 0x22, 0x33}
	setupMultisigWalletStorage(sdb, multisigAddr, walletAddr, []types.Address{signerAddr}, 1)

	// Query isSigner(wallet, signer).
	input := make([]byte, 41)
	input[0] = 0x08 // MultisigFuncIsSigner
	copy(input[1:21], walletAddr[:])
	copy(input[21:41], signerAddr[:])

	// Atomic path via Registry.RunWithContext.
	output, gasUsed, err := executePrecompiledAtomic(
		registry, multisigAddr, sdb, 1700000000, 1668, input, 1000000,
	)
	if err != nil {
		t.Fatalf("executePrecompiledAtomic failed: %v", err)
	}
	if gasUsed != 10000 {
		t.Errorf("gasUsed: got %d, want 10000 (MultisigGasQuery)", gasUsed)
	}
	// encodeResult always returns 32 bytes.
	if len(output) != 32 {
		t.Errorf("isSigner output length: got %d, want 32 (encodeResult format)", len(output))
	}
}

// TestQVM_R13_HIGH_002_RegistryRunWithContext_PurePrecompile verifies that
// Registry.RunWithContext works correctly for pure precompiles (sha256) that
// do NOT implement AtomicContextPrecompiledContract or
// ContextAwarePrecompiledContract. The legacy fallback path (plain Run) is
// used for such precompiles.
//
// QVM-R13-HIGH-002 (2026-07-21): The new Registry.RunWithContext must not
// break pure precompiles. sha256 is a representative pure precompile.
func TestQVM_R13_HIGH_002_RegistryRunWithContext_PurePrecompile(t *testing.T) {
	registry := precompiled.NewRegistry()
	sha256Addr := types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
	sdb := newMockStateDB()

	input := []byte("hello world")
	expected := sha256.Sum256(input)

	// Use Registry.RunWithContext with a stateDB wrapper (sha256 doesn't
	// need context, but the wrapper is still passed for API uniformity).
	output, gasUsed, err := executePrecompiledAtomic(
		registry, sha256Addr, sdb, 1700000000, 1668, input, 1000000,
	)
	if err != nil {
		t.Fatalf("executePrecompiledAtomic failed for sha256: %v", err)
	}
	if !bytes.Equal(output, expected[:]) {
		t.Errorf("sha256 output mismatch: got %x, want %x", output, expected[:])
	}
	if gasUsed == 0 {
		t.Error("sha256 should consume non-zero gas")
	}
}

// TestQVM_R13_HIGH_002_ConcurrentRunWithContext_NoCrossContamination is the
// core TOCTOU race regression test. It verifies that under heavy concurrent
// invocations of RunWithContext, each goroutine's RunWithContext invocation
// reads exclusively from its OWN stateDB (no cross-contamination).
//
// QVM-R13-HIGH-002 (2026-07-21): The legacy injectPrecompileContext + Run
// sequence had a race window where goroutine A's SetStateDB could be followed
// by goroutine B's SetStateDB, then goroutine A's Run would execute against
// goroutine B's stateDB.
//
// Test design:
//   - Each goroutine has its own stateDB containing a wallet W with a UNIQUE
//     signerCount N_i (so the expected number of GetState calls per
//     RunWithContext invocation is 1 + N_i: one wallet lookup + N_i signer
//     lookups).
//   - Each goroutine calls RunWithContext(ownStateDB, isSigner) many times.
//   - After each call, verify the per-call GetState count matches 1 + N_i.
//   - If atomicity is broken, the goroutine might see a sibling's stateDB
//     (with a different signerCount), and the GetState count would not match.
//
// We use countingStateDB to track GetState calls per RunWithContext
// invocation. We reset the counter before each RunWithContext call and check
// it after.
//
// Note: This is a probabilistic test — it cannot prove the absence of a
// race, but it will LIKELY catch the race if it exists (with N*M=8000
// invocations spread across 8 goroutines, the race window would be hit many
// times).
func TestQVM_R13_HIGH_002_ConcurrentRunWithContext_NoCrossContamination(t *testing.T) {
	registry := precompiled.NewRegistry()
	multisigAddr := types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66}
	pc := registry.Get(multisigAddr)
	if pc == nil {
		t.Fatal("multisig precompile not registered at 0x66")
	}
	atomicPC, ok := pc.(precompiled.AtomicContextPrecompiledContract)
	if !ok {
		t.Fatal("multisig precompile does not implement AtomicContextPrecompiledContract")
	}

	const numGoroutines = 8
	const iterationsPerGoroutine = 1000

	// Each goroutine has its own stateDB with wallet W containing a UNIQUE
	// signerCount. The expected GetState count per RunWithContext call is
	// 1 (wallet lookup) + N_i (signer lookups, none match due to pre-existing
	// storage layout bug, but the loop still iterates all N_i signers).
	walletAddr := types.Address{0xAB, 0xCD}
	querySigner := types.Address{0xFF, 0xEE, 0xDD} // a signer that doesn't match any stored signer

	type goroutineState struct {
		stateDB             *countingStateDB
		signerCount         uint32
		expectedGetStateCnt int
	}
	states := make([]goroutineState, numGoroutines)
	for i := range states {
		sdb := newCountingStateDB()
		signerCount := uint32(i + 1) // 1, 2, 3, ..., 8
		// Create signerCount signers (none match querySigner).
		signers := make([]types.Address, signerCount)
		for j := uint32(0); j < signerCount; j++ {
			signers[j] = types.Address{0x01, byte(j + 1), 0xBB}
		}
		setupMultisigWalletStorage(sdb.mockStateDB, multisigAddr, walletAddr, signers, signerCount)
		states[i] = goroutineState{
			stateDB:             sdb,
			signerCount:         signerCount,
			expectedGetStateCnt: 1 + int(signerCount),
		}
	}

	// Precompute the isSigner input.
	input := make([]byte, 41)
	input[0] = 0x08 // MultisigFuncIsSigner
	copy(input[1:21], walletAddr[:])
	copy(input[21:41], querySigner[:])

	var failures int64
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {

		go func() {
			defer wg.Done()
			st := states[i]
			adapter := &qvmStateDBAdapter{db: st.stateDB}
			for j := 0; j < iterationsPerGoroutine; j++ {
				// Reset the GetState counter before each RunWithContext call.
				st.stateDB.mu.Lock()
				st.stateDB.count = 0
				st.stateDB.mu.Unlock()

				// Call RunWithContext — should atomically Set + dispatch
				// under a single lock, so all GetState calls during dispatch
				// use THIS goroutine's stateDB.
				_, err := atomicPC.RunWithContext(
					adapter,
					1700000000,
					1668,
					input,
				)
				if err != nil {
					atomic.AddInt64(&failures, 1)
					t.Errorf("goroutine %d iter %d: RunWithContext failed: %v", i, j, err)
					return
				}

				// Verify the per-call GetState count matches the expected
				// count for THIS goroutine's stateDB. If atomicity is broken
				// and the dispatch read from a sibling's stateDB (with a
				// different signerCount), the count would not match.
				gotCount := st.stateDB.GetCount()
				if gotCount != st.expectedGetStateCnt {
					atomic.AddInt64(&failures, 1)
					t.Errorf("goroutine %d iter %d: GetState count = %d, want %d (signerCount=%d) — "+
						"TOCTOU cross-contamination detected",
						i, j, gotCount, st.expectedGetStateCnt, st.signerCount)
					return
				}
			}
		}()
	}
	wg.Wait()

	if failures > 0 {
		t.Fatalf("QVM-R13-HIGH-002: %d cross-contamination failures detected (TOCTOU race)", failures)
	}
}

// setupMultisigWalletStorage populates the stateDB with wallet data so that
// isSigner queries proceed past the wallet-exists check and iterate the
// stored signers.
//
// Storage layout (matches MultisigPrecompiled's walletKey/walletSignerKey):
//   - Slot walletKey(walletAddr) = [0:4]=threshold, [4:8]=signerCount, rest zero
//   - Slot walletSignerKey(walletAddr, i) = signer address bytes
//
// NOTE: registerWallet stores signers left-aligned (copy(sVal[:], signerAddr[:]))
// while isSigner reads them via BytesToAddress (right-aligned). This is a
// pre-existing storage layout mismatch in the multisig precompile that causes
// isSigner to never return true. This is OUT OF SCOPE for QVM-R13-HIGH-002
// (which only fixes the TOCTOU race). The test works around this by checking
// GetState counts rather than isSigner's return value.
func setupMultisigWalletStorage(sdb *mockStateDB, multisigContractAddr, walletAddr types.Address, signers []types.Address, signerCount uint32) {
	// We need to compute the same storage keys the precompile uses.
	// storageKey(prefix, data) = sha256(prefix || data)[:32]
	storageKey := func(prefix string, data []byte) types.Hash {
		h := sha256.New()
		h.Write([]byte(prefix))
		h.Write(data)
		digest := h.Sum(nil)
		var hash types.Hash
		copy(hash[:], digest[:types.HashLength])
		return hash
	}
	walletKey := storageKey("ms:wallet:", walletAddr[:])
	// wData layout: [0:4]=threshold, [4:8]=signerCount, rest zero
	wData := types.Hash{}
	binary.BigEndian.PutUint32(wData[0:4], 1) // threshold = 1
	binary.BigEndian.PutUint32(wData[4:8], signerCount)
	// Convert types.Hash to qvm.Hash and store under the multisig contract address.
	var qMultisigAddr Address
	copy(qMultisigAddr[:], multisigContractAddr[:])
	var qWalletKey Hash
	copy(qWalletKey[:], walletKey[:])
	var qWData Hash
	copy(qWData[:], wData[:])
	sdb.SetState(qMultisigAddr, qWalletKey, qWData)

	// Store each signer (matching registerWallet's left-aligned layout).
	for i, signer := range signers {
		if uint32(i) >= signerCount {
			break
		}
		idxBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(idxBytes, uint32(i))
		data := append(walletAddr[:], idxBytes...)
		signKey := storageKey("ms:wsigner:", data)
		var qSignKey Hash
		copy(qSignKey[:], signKey[:])
		var qSignVal Hash
		copy(qSignVal[:], signer[:])
		sdb.SetState(qMultisigAddr, qSignKey, qSignVal)
	}
}

// TestQVM_R13_HIGH_002_LegacyInjectPathStillWorks verifies that the legacy
// injectPrecompileContext function (used by RPC layer, tests) still works
// for backward compatibility. The QVM executor no longer uses this function,
// but it must remain functional for any code that initializes a precompile
// instance once and then uses it single-threaded.
//
// QVM-R13-HIGH-002 (2026-07-21): This is a backward-compatibility test. The
// new atomic path is preferred, but the legacy path must not regress.
func TestQVM_R13_HIGH_002_LegacyInjectPathStillWorks(t *testing.T) {
	registry := precompiled.NewRegistry()
	multisigAddr := types.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x66}
	pc := registry.Get(multisigAddr)
	if pc == nil {
		t.Fatal("multisig precompile not registered at 0x66")
	}

	// Before injection, Run should fail with "stateDB not set".
	_, err := pc.Run([]byte{0x08}) // MultisigFuncIsSigner with insufficient input
	if err == nil {
		t.Fatal("Run before context injection should fail (stateDB not set or invalid input)")
	}

	// Inject context via legacy path.
	sdb := newMockStateDB()
	injectPrecompileContext(pc, sdb, 1700000000, 1668)

	// After injection, Run should no longer fail with "stateDB not set".
	// It may still fail for other reasons (insufficient input), but NOT with
	// the stateDB error.
	_, err = pc.Run([]byte{0x08})
	if err != nil && err.Error() == "multisig: stateDB not set" {
		t.Errorf("after legacy injection, Run should not fail with 'stateDB not set', got: %v", err)
	}
}

// dummy use to prevent unused import warning if tests are trimmed.
var _ = fmt.Sprintf
var _ = big.NewInt
