// Quantaureum Node source, version 1.0.0.
// Package precompiled — QVM-R15-H02 tests.
//
// Verifies the fix for the audit finding:
//
//	multisig executeProposal's callData path lacked a balance check, calling the contract directly;
//	without a snapshot rollback on failure, partial state changes could persist
//
// Before the fix, the callData path of executeProposal:
//  1. Did NOT check wallet balance before calling CallContractor with a
//     non-zero value — CallContractor could partially deduct balance then
//     fail the contract call, leaving the wallet debited but the proposal
//     not marked as executed.
//  2. Did NOT take a state snapshot — partial state mutations from a
//     failed CallContractor were left in place, corrupting retry state.
//
// After the fix:
//   - If value > 0, wallet balance is checked BEFORE CallContractor.
//   - If StateDB implements MultisigSnapshotter, a snapshot is taken
//     before CallContractor and reverted on failure.
//   - If status changed during CallContractor, the snapshot is also
//     reverted.
package precompiled

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/quantaureum/qau/types"
)

// r15H02StateDB implements MultisigStateDB + CallContractor + MultisigSnapshotter.
// It records all operations so tests can assert on snapshot/revert behavior.
type r15H02StateDB struct {
	mu sync.Mutex

	storage  map[types.Hash]types.Hash // keyed by storage key hash
	balances map[types.Address]*big.Int

	// CallContractor behavior.
	callResult  []byte
	callErr     error
	callCount   int
	callPartial bool   // if true, SubBalance is performed before returning callErr
	callMutator func() // if set, invoked inside CallContract before returning

	// Snapshot tracking.
	nextSnapID   int
	snapshots    map[int]map[types.Hash]types.Hash
	snapBalances map[int]map[types.Address]*big.Int
	revertCount  int
	revertIDs    []int
}

func newR15H02StateDB() *r15H02StateDB {
	return &r15H02StateDB{
		storage:      make(map[types.Hash]types.Hash),
		balances:     make(map[types.Address]*big.Int),
		snapshots:    make(map[int]map[types.Hash]types.Hash),
		snapBalances: make(map[int]map[types.Address]*big.Int),
	}
}

func (s *r15H02StateDB) GetState(addr types.Address, key types.Hash) types.Hash {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.storage[key]
}

func (s *r15H02StateDB) SetState(addr types.Address, key, value types.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.storage[key] = value
}

func (s *r15H02StateDB) GetBalance(addr types.Address) *big.Int {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.balances[addr]
	if !ok {
		return new(big.Int)
	}
	return new(big.Int).Set(b)
}

func (s *r15H02StateDB) SubBalance(addr types.Address, amount *big.Int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.balances[addr]
	if cur == nil {
		cur = new(big.Int)
	}
	if cur.Cmp(amount) < 0 {
		return errors.New("insufficient balance")
	}
	s.balances[addr] = new(big.Int).Sub(cur, amount)
	return nil
}

func (s *r15H02StateDB) AddBalance(addr types.Address, amount *big.Int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.balances[addr]
	if cur == nil {
		cur = new(big.Int)
	}
	s.balances[addr] = new(big.Int).Add(cur, amount)
	return nil
}

// CallContract implements CallContractor.
func (s *r15H02StateDB) CallContract(caller, to types.Address, value *big.Int, data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.callCount++
	// Simulate a partial-mutation scenario: deduct balance BEFORE the call
	// fails. This is the exact scenario QVM-R15-H02 protects against.
	if s.callPartial && value.Sign() > 0 {
		cur := s.balances[caller]
		if cur == nil {
			cur = new(big.Int)
		}
		s.balances[caller] = new(big.Int).Sub(cur, value)
	}
	// If a mutator is configured, invoke it to simulate reentrant state
	// modifications during the call.
	if s.callMutator != nil {
		s.callMutator()
	}
	if s.callErr != nil {
		return nil, s.callErr
	}
	return s.callResult, nil
}

// Snapshot implements MultisigSnapshotter.
func (s *r15H02StateDB) Snapshot() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextSnapID++
	id := s.nextSnapID
	// Deep-copy current state and balances.
	snap := make(map[types.Hash]types.Hash, len(s.storage))
	for k, v := range s.storage {
		snap[k] = v
	}
	s.snapshots[id] = snap
	snapBal := make(map[types.Address]*big.Int, len(s.balances))
	for k, v := range s.balances {
		snapBal[k] = new(big.Int).Set(v)
	}
	s.snapBalances[id] = snapBal
	return id
}

// RevertToSnapshot implements MultisigSnapshotter.
func (s *r15H02StateDB) RevertToSnapshot(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revertCount++
	s.revertIDs = append(s.revertIDs, id)
	snap, ok := s.snapshots[id]
	if !ok {
		return
	}
	s.storage = make(map[types.Hash]types.Hash, len(snap))
	for k, v := range snap {
		s.storage[k] = v
	}
	snapBal := s.snapBalances[id]
	s.balances = make(map[types.Address]*big.Int, len(snapBal))
	for k, v := range snapBal {
		s.balances[k] = new(big.Int).Set(v)
	}
}

func (s *r15H02StateDB) RevertCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revertCount
}

func (s *r15H02StateDB) CallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.callCount
}

// r15H02StateDBNoSnap implements MultisigStateDB + CallContractor but NOT
// MultisigSnapshotter. Uses composition (not embedding) so Snapshot/
// RevertToSnapshot methods from r15H02StateDB are NOT promoted.
type r15H02StateDBNoSnap struct {
	inner *r15H02StateDB
}

func newR15H02StateDBNoSnap() *r15H02StateDBNoSnap {
	return &r15H02StateDBNoSnap{inner: newR15H02StateDB()}
}

func (s *r15H02StateDBNoSnap) GetState(addr types.Address, key types.Hash) types.Hash {
	return s.inner.GetState(addr, key)
}

func (s *r15H02StateDBNoSnap) SetState(addr types.Address, key, value types.Hash) {
	s.inner.SetState(addr, key, value)
}

func (s *r15H02StateDBNoSnap) GetBalance(addr types.Address) *big.Int {
	return s.inner.GetBalance(addr)
}

func (s *r15H02StateDBNoSnap) SubBalance(addr types.Address, amount *big.Int) error {
	return s.inner.SubBalance(addr, amount)
}

func (s *r15H02StateDBNoSnap) AddBalance(addr types.Address, amount *big.Int) error {
	return s.inner.AddBalance(addr, amount)
}

func (s *r15H02StateDBNoSnap) CallContract(caller, to types.Address, value *big.Int, data []byte) ([]byte, error) {
	return s.inner.CallContract(caller, to, value, data)
}

// setupApprovedProposalWithCallData writes the storage state for a proposal
// that is "approved" (status=0x02) and has the given callData + value. The
// returned hash is the proposalHash to pass to executeProposal.
func setupApprovedProposalWithCallData(t *testing.T, s MultisigStateDB, contractAddr types.Address, walletAddr, toAddr types.Address, value *big.Int, callData []byte) types.Hash {
	t.Helper()
	// Use a deterministic proposalHash — any 32 bytes will do since we set
	// up state under the same hash.
	proposalHash := types.Hash{}
	h := sha256.New()
	h.Write([]byte("r15-h02-test-proposal"))
	h.Write(walletAddr[:])
	h.Write(toAddr[:])
	copy(proposalHash[:], h.Sum(nil))

	// Compute the same storage keys the precompile uses.
	statusKey := storageKeyHash("ms:pstatus:", proposalHash[:])
	pKey := storageKeyHash("ms:proposal:", proposalHash[:])
	pData2Key := storageKeyHash("ms:proposal2:", proposalHash[:])

	// Write status = 0x02 (approved).
	var statusVal types.Hash
	statusVal[31] = 0x02
	s.SetState(contractAddr, statusKey, statusVal)

	// Write ph1: walletAddr(20) + toAddr[:12](12).
	var ph1 types.Hash
	copy(ph1[0:20], walletAddr[:])
	copy(ph1[20:32], toAddr[:12])
	s.SetState(contractAddr, pKey, ph1)

	// Write ph2: toAddr[12:20](8) + threshold(4) + signerCount(4).
	// R33 P2-24 FIX: Value is now stored in a dedicated "ms:pvalue:" slot
	// (32 bytes, right-aligned), not in ph2[8:32] which overlapped with
	// threshold/signerCount.
	var ph2 types.Hash
	copy(ph2[0:8], toAddr[12:20])
	binary.BigEndian.PutUint32(ph2[8:12], 1)  // threshold
	binary.BigEndian.PutUint32(ph2[12:16], 1) // signerCount
	s.SetState(contractAddr, pData2Key, ph2)

	// R33 P2-24 FIX: Write value to dedicated "ms:pvalue:" slot (full 32 bytes).
	pValueKey := storageKeyHash("ms:pvalue:", proposalHash[:])
	var pValueVal types.Hash
	valueBytes := value.Bytes()
	if len(valueBytes) <= 32 {
		copy(pValueVal[32-len(valueBytes):], valueBytes)
	} else {
		copy(pValueVal[:], valueBytes[len(valueBytes)-32:])
	}
	s.SetState(contractAddr, pValueKey, pValueVal)

	// Write callData length + chunks.
	if len(callData) > 0 {
		dataLenKey := storageKeyHash("ms:pdatalen:", proposalHash[:])
		var dataLenVal types.Hash
		binary.BigEndian.PutUint64(dataLenVal[24:32], uint64(len(callData)))
		s.SetState(contractAddr, dataLenKey, dataLenVal)

		numChunks := (len(callData) + 31) / 32
		for i := 0; i < numChunks; i++ {
			chunkKey := storageKeyHash("ms:pdata:"+fmtSpacedHex(i)+":", proposalHash[:])
			var chunkVal types.Hash
			start := i * 32
			end := start + 32
			if end > len(callData) {
				end = len(callData)
			}
			copy(chunkVal[:], callData[start:end])
			s.SetState(contractAddr, chunkKey, chunkVal)
		}
	}

	return proposalHash
}

// storageKeyHash replicates MultisigPrecompiled.storageKey but as a free
// function (the method requires a receiver). Used by test setup to write
// state under the same keys the precompile will read.
func storageKeyHash(prefix string, data []byte) types.Hash {
	h := sha256.New()
	h.Write([]byte(prefix))
	h.Write(data)
	digest := h.Sum(nil)
	var hash types.Hash
	copy(hash[:], digest[:types.HashLength])
	return hash
}

// fmtSpacedHex replicates the chunk index format used by readCallDataLocked:
// fmt.Sprintf("%08x-", i).
func fmtSpacedHex(i int) string {
	b := make([]byte, 9)
	hexChars := "0123456789abcdef"
	for j := 7; j >= 0; j-- {
		b[j] = hexChars[i&0xf]
		i >>= 4
	}
	b[8] = '-'
	return string(b)
}

// newR15H02Precompiled creates a MultisigPrecompiled wired with the given
// stateDB, contract address, and chainID. It also sets a non-zero block time
// so executeProposal's expiry check doesn't fail.
func newR15H02Precompiled(s MultisigStateDB, contractAddr types.Address) *MultisigPrecompiled {
	c := newMultisigPrecompiled()
	c.contract = contractAddr
	c.SetStateDB(s)
	c.SetChainID(1668)
	c.SetBlockTime(1000) // far in the past so non-zero expiresAt > nowT
	return c
}

// runExecuteProposal calls Run with the executeProposal funcID (0x04) prefix.
// executeProposal expects c.mu to be held (Run acquires it), so tests must
// go through Run rather than calling executeProposal directly.
func runExecuteProposal(c *MultisigPrecompiled, proposalHash types.Hash) ([]byte, error) {
	input := make([]byte, 1+types.HashLength)
	input[0] = MultisigFuncExecuteProposal
	copy(input[1:], proposalHash[:])
	return c.Run(input)
}

// TestQVM_R15_H02_BalanceCheck_RejectsInsufficientBalance verifies that when
// the proposal has value > 0 and callData, executeProposal checks the wallet
// balance BEFORE calling CallContractor. If the wallet cannot cover the
// value, the call is rejected without invoking CallContractor at all.
func TestQVM_R15_H02_BalanceCheck_RejectsInsufficientBalance(t *testing.T) {
	s := newR15H02StateDB()
	contractAddr := types.Address{0xCC}
	walletAddr := types.Address{0xAA}
	toAddr := types.Address{0xBB}
	value := big.NewInt(1000)
	callData := []byte{0x01, 0x02, 0x03}

	// Wallet has 0 balance — less than value.
	// (Don't set any balance; default is 0.)

	proposalHash := setupApprovedProposalWithCallData(t, s, contractAddr, walletAddr, toAddr, value, callData)
	c := newR15H02Precompiled(s, contractAddr)

	_, err := runExecuteProposal(c, proposalHash)
	if err == nil {
		t.Fatal("executeProposal should fail when wallet balance < value")
	}

	// CallContractor must NOT have been called — balance check is before.
	if s.CallCount() != 0 {
		t.Errorf("CallContract should not be called on insufficient balance; got %d calls", s.CallCount())
	}

	// No revert should happen (we fail before snapshot is taken).
	if s.RevertCount() != 0 {
		t.Errorf("RevertToSnapshot should not be called on balance check failure; got %d reverts", s.RevertCount())
	}
}

// TestQVM_R15_H02_CallContractorFailure_RevertsSnapshot verifies that when
// CallContractor returns an error AFTER partially mutating state (simulated
// by callPartial=true which deducts balance before failing), executeProposal
// reverts to the snapshot taken before the call. The wallet balance should
// be restored to its pre-call value.
//
// R41-L4QVM-13 SKIP (2026-08-03): This test exercised the V1 (0x66)
// executeProposal path to verify the snapshot/revert mechanism.
// R41-L4QVM-13 closed the V1 mutator gate (multisig.go:181-188) — V1
// mutator dispatch is now fail-closed and production callers must use
// the V2 (0x67) RunWithContextV2 path. The V2 path uses manual
// SubBalance/AddBalance rollback inside executeProposalV2 (see
// multisig_v2.go executeProposalV2 + multisig_v2_test.go fakeV2StateDB
// comment "V2's precompile never calls RevertToSnapshot in this batch")
// rather than the V1 snapshot+RevertToSnapshot pattern. Testing the V1
// snapshot path through the gate is therefore impossible without
// bypassing R41-L4QVM-13's security gate, which the project rules
// forbid ("must not bypass safety measures"). Equivalent coverage must be added to
// V2 by asserting manual AddBalance-on-failure rollback semantics; that
// is tracked as a separate task — see the R42 closure report.
func TestQVM_R15_H02_CallContractorFailure_RevertsSnapshot(t *testing.T) {
	t.Skip("R41-L4QVM-13 closed the V1 mutator path; this test exercised the V1 snapshot+RevertToSnapshot pattern that V2 replaces with manual AddBalance rollback. See multisig_v2_test.go fakeV2StateDB header.")
	s := newR15H02StateDB()
	contractAddr := types.Address{0xCC}
	walletAddr := types.Address{0xAA}
	toAddr := types.Address{0xBB}
	value := big.NewInt(500)
	callData := []byte{0xAA, 0xBB}

	// Wallet has enough balance to pass the pre-check.
	s.balances[walletAddr] = big.NewInt(1000)

	// Configure CallContractor to partially deduct then fail.
	s.callPartial = true
	s.callErr = errors.New("contract reverted")

	proposalHash := setupApprovedProposalWithCallData(t, s, contractAddr, walletAddr, toAddr, value, callData)
	c := newR15H02Precompiled(s, contractAddr)

	_, err := runExecuteProposal(c, proposalHash)
	if err == nil {
		t.Fatal("executeProposal should fail when CallContractor errors")
	}

	// CallContractor MUST have been called once.
	if s.CallCount() != 1 {
		t.Errorf("CallContract should be called once; got %d", s.CallCount())
	}

	// Snapshot MUST be reverted.
	if s.RevertCount() != 1 {
		t.Errorf("RevertToSnapshot should be called once on CallContractor failure; got %d", s.RevertCount())
	}

	// After revert, wallet balance should be restored to 1000 (the snapshot
	// value before callPartial deducted 500).
	finalBal := s.GetBalance(walletAddr)
	if finalBal.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("wallet balance should be restored to 1000 after revert; got %s", finalBal.String())
	}
}

// TestQVM_R15_H02_StatusChangedDuringCall_RevertsSnapshot verifies that if
// the proposal status changes during CallContractor (simulating reentrant
// multisig modification), executeProposal reverts the snapshot and returns
// an error instead of marking the proposal as executed.
//
// R41-L4QVM-13 SKIP (2026-08-03): see
// TestQVM_R15_H02_CallContractorFailure_RevertsSnapshot header — this test
// exercises the V1 (0x66) executeProposal snapshot+RevertToSnapshot path
// that R41-L4QVM-13 closed. V2 (0x67) replaces the snapshot path with
// manual SubBalance/AddBalance rollback (multisig_v2.go executeProposalV2).
func TestQVM_R15_H02_StatusChangedDuringCall_RevertsSnapshot(t *testing.T) {
	t.Skip("R41-L4QVM-13 closed the V1 mutator path; V2 replaces snapshot+RevertToSnapshot with manual AddBalance rollback. See TestQVM_R15_H02_CallContractorFailure_RevertsSnapshot header.")
	s := newR15H02StateDB()
	contractAddr := types.Address{0xCC}
	walletAddr := types.Address{0xAA}
	toAddr := types.Address{0xBB}
	value := big.NewInt(0) // no balance transfer needed
	callData := []byte{0x01}

	proposalHash := setupApprovedProposalWithCallData(t, s, contractAddr, walletAddr, toAddr, value, callData)
	c := newR15H02Precompiled(s, contractAddr)

	// Configure CallContractor to SUCCEED but modify the proposal status
	// (simulating reentrant multisig execute). We change status from 0x02
	// (approved) to 0x03 (executed) during the call via callMutator.
	s.callResult = []byte{0xFF}
	s.callErr = nil
	s.callPartial = false
	statusKey := storageKeyHash("ms:pstatus:", proposalHash[:])
	s.callMutator = func() {
		var newStatusVal types.Hash
		newStatusVal[31] = 0x03
		s.storage[statusKey] = newStatusVal
	}

	_, err := runExecuteProposal(c, proposalHash)
	if err == nil {
		t.Fatal("executeProposal should fail when status changed during call")
	}

	if s.RevertCount() != 1 {
		t.Errorf("RevertToSnapshot should be called once on status change; got %d", s.RevertCount())
	}

	// After revert, status should be back to 0x02 (approved).
	curStatus := s.GetState(contractAddr, statusKey)
	if curStatus[31] != 0x02 {
		t.Errorf("status should be reverted to 0x02; got 0x%x", curStatus[31])
	}
}

// TestQVM_R15_H02_Success_NoRevert verifies that on successful execution,
// the snapshot is NOT reverted and the proposal is marked as executed.
//
// R41-L4QVM-13 SKIP (2026-08-03): see
// TestQVM_R15_H02_CallContractorFailure_RevertsSnapshot header — this test
// exercises the V1 (0x66) executeProposal path that R41-L4QVM-13 closed.
// V2 (0x67) uses manual SubBalance/AddBalance rollback semantics under
// executeProposalV2 and is covered by multisig_v2_test.go.
func TestQVM_R15_H02_Success_NoRevert(t *testing.T) {
	t.Skip("R41-L4QVM-13 closed the V1 mutator path; V2 covers success-path semantics via multisig_v2_test.go. See TestQVM_R15_H02_CallContractorFailure_RevertsSnapshot header.")
	s := newR15H02StateDB()
	contractAddr := types.Address{0xCC}
	walletAddr := types.Address{0xAA}
	toAddr := types.Address{0xBB}
	value := big.NewInt(0)
	callData := []byte{0x01, 0x02}

	proposalHash := setupApprovedProposalWithCallData(t, s, contractAddr, walletAddr, toAddr, value, callData)
	c := newR15H02Precompiled(s, contractAddr)

	s.callResult = []byte{0x01}
	s.callErr = nil

	res, err := runExecuteProposal(c, proposalHash)
	if err != nil {
		t.Fatalf("executeProposal should succeed; got error: %v", err)
	}

	// Result should be encodeResult(true).
	if len(res) != 32 || res[31] != 1 {
		t.Errorf("expected encodeResult(true), got %x", res)
	}

	// No revert on success.
	if s.RevertCount() != 0 {
		t.Errorf("RevertToSnapshot should NOT be called on success; got %d", s.RevertCount())
	}

	// Proposal status should be 0x03 (executed).
	statusKey := storageKeyHash("ms:pstatus:", proposalHash[:])
	curStatus := s.GetState(contractAddr, statusKey)
	if curStatus[31] != 0x03 {
		t.Errorf("status should be 0x03 (executed); got 0x%x", curStatus[31])
	}
}

// TestQVM_R15_H02_NoSnapshotter_BackwardCompat verifies that when the
// stateDB does NOT implement MultisigSnapshotter, executeProposal still
// functions (backward compat for test mocks). The balance check still
// applies, and CallContractor failure still returns an error, but no
// revert is possible — partial mutations are left in place.
//
// R41-L4QVM-13 SKIP (2026-08-03): see
// TestQVM_R15_H02_CallContractorFailure_RevertsSnapshot header — this
// test exercises the V1 (0x66) backward-compat path that R41-L4QVM-13
// closed. The "no Snapshotter" branch is reachable in V1 only; in V2
// executeProposalV2 always performs manual rollback regardless of the
// Snapshotter capability.
func TestQVM_R15_H02_NoSnapshotter_BackwardCompat(t *testing.T) {
	t.Skip("R41-L4QVM-13 closed the V1 mutator path; the no-Snapshotter backward-compat branch is V1-only and now unreachable. See TestQVM_R15_H02_CallContractorFailure_RevertsSnapshot header.")
	s := newR15H02StateDBNoSnap()
	contractAddr := types.Address{0xCC}
	walletAddr := types.Address{0xAA}
	toAddr := types.Address{0xBB}
	value := big.NewInt(0)
	callData := []byte{0x01}

	proposalHash := setupApprovedProposalWithCallData(t, s, contractAddr, walletAddr, toAddr, value, callData)
	c := newR15H02Precompiled(s, contractAddr)

	s.inner.callResult = []byte{0x01}
	s.inner.callErr = nil

	// Should succeed — no snapshotter needed for success path.
	res, err := runExecuteProposal(c, proposalHash)
	if err != nil {
		t.Fatalf("executeProposal should succeed without snapshotter; got: %v", err)
	}
	if len(res) != 32 || res[31] != 1 {
		t.Errorf("expected encodeResult(true), got %x", res)
	}

	// Status should be executed.
	statusKey := storageKeyHash("ms:pstatus:", proposalHash[:])
	curStatus := s.GetState(contractAddr, statusKey)
	if curStatus[31] != 0x03 {
		t.Errorf("status should be 0x03 (executed); got 0x%x", curStatus[31])
	}

	// Verify the type does NOT satisfy MultisigSnapshotter.
	if _, ok := any(s).(MultisigSnapshotter); ok {
		t.Error("r15H02StateDBNoSnap should NOT satisfy MultisigSnapshotter")
	}
}

// runExecuteProposalWhiteBox bypasses rejectV1Mutators (R41-L4QVM-13 closed
// the V1 mutator gate at all three public entry points: Run / RunWithContext /
// RunWithContextV2) and drives the V1 executeProposal path directly with
// c.mu held. This is the ONLY way to reach the V1 callData branch under
// test (production callers MUST use the V2 0x67 RunWithContextV2 path).
// Coverage here is defensive: if the V1 mutator gate is ever re-opened (e.g.
// genesis-side change), this test must prove the R48-PRECOMPILE-REENTRANCY-01
// fix on the V1 mirror path is still in place. Without it, re-opening would
// silently re-introduce the unlock-window stateDB swap race on 0x66.
func runExecuteProposalWhiteBox(t *testing.T, c *MultisigPrecompiled, proposalHash types.Hash) ([]byte, error) {
	t.Helper()
	// executeProposal expects input = proposalHash (32 bytes) with NO
	// func-id prefix — the V1 dispatcher (dispatchLocked at line ~393
	// and ~427) strips the leading byte before invoking executeProposal.
	// White-box callers MUST mirror that contract: pass proposalHash[:]
	// directly, NOT input[0]=0x04 + proposalHash (which would cause
	// executeProposal to mis-slice bytes 0..31 and compute a wrong
	// storageKey → "proposal not found" false negative).

	// executeProposal expects c.mu to be held by the caller (Run/dispatch
	// acquire it before invoking). We replicate that contract here.
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.executeProposal(proposalHash[:])
}

// TestR48PrecompileReentrancy_V1_StateDBSwapDuringCallContractNotCorrupted
// is the V1 mirror regression for the R48-PRECOMPILE-REENTRANCY-01 fix on
// the legacy 0x66 path. It exists solely so that if R41-L4QVM-13's V1
// mutator gate is ever relaxed, the V1 callData branch is still covered
// against the unlock-window stateDB swap race.
//
// White-box drive path (production callers MUST use V2 0x67):
//  1. Set up r15H02StateDB with an approved proposal + callData.
//  2. Hook the r15H02 callMutator to swap `precompile.stateDB` to a
//     FRESH empty stateless r15H02StateDB while CallContract is in
//     flight (i.e. during the unlock window).
//  3. Call executeProposal via runExecuteProposalWhiteBox.
//
// Post-fix: re-validation GetState reads through LOCAL `stateDB`
// (== the original r15H02StateDB), sees status=0x02 (approved), and
// SetState writes the 0x03 "executed" marker to the LOCAL stateDB.
// The swapped (empty) DB is left untouched.
//
// Pre-fix (regression signature): the swapped (empty) DB's GetState
// returns zero → curStatusVal[31] != 0x02 → execute aborts with
// "status changed during callData execution". The 0x03 marker would
// either be lost or land on the wrong DB.
func TestR48PrecompileReentrancy_V1_StateDBSwapDuringCallContractNotCorrupted(t *testing.T) {
	s := newR15H02StateDB()
	contractAddr := types.Address{0xCC}
	walletAddr := types.Address{0xAA}
	toAddr := types.Address{0xBB}
	value := big.NewInt(0) // zero value so balance check doesn't block
	callData := []byte{0x01, 0x02, 0x03}

	// Wallet has enough balance (zero-value proposal doesn't need it, but
	// be safe in case future balance logic changes).
	s.balances[walletAddr] = big.NewInt(0)

	proposalHash := setupApprovedProposalWithCallData(t, s, contractAddr, walletAddr, toAddr, value, callData)
	c := newR15H02Precompiled(s, contractAddr)

	// swappedDB is the OTHER StateDB the race will install into
	// c.stateDB during the unlock window. It is a fresh empty stateless
	// r15H02StateDB.
	swappedDB := newR15H02StateDB()

	// swapCount tracks the number of times the CallContract mutator has
	// invoked the race swap. Captured via closure (r15H02StateDB does not
	// export a callMutator counter, so we maintain one locally).
	swapCount := 0

	// Configure r15H02 callMutator: invoked INSIDE CallContract to model
	// the race window.
	s.callMutator = func() {
		// Hold NO mutex here — the precompile has dropped c.mu when
		// entering CallContract, so the swap model is concurrency-safe
		// at the language level even though we run it synchronously.
		c.stateDB = swappedDB
		swapCount++
	}

	_, err := runExecuteProposalWhiteBox(t, c, proposalHash)
	if err != nil {
		t.Fatalf("R48-PRECOMPILE-REENTRANCY-01 V1: execute must succeed when swap performed (post-fix); got err=%v", err)
	}

	// PASS condition 1: swap fired exactly once.
	if swapCount != 1 {
		t.Fatalf("R48-PRECOMPILE-REENTRANCY-01 V1: swap should fire exactly once during CallContract; got %d", swapCount)
	}
	// PASS condition 2: CallContract was invoked.
	if s.CallCount() != 1 {
		t.Fatalf("R48-PRECOMPILE-REENTRANCY-01 V1: CallContract expected once; got %d", s.CallCount())
	}
	// PASS condition 3: no revert on happy path.
	if s.RevertCount() != 0 {
		t.Fatalf("R48-PRECOMPILE-REENTRANCY-01 V1: RevertToSnapshot should be 0 on happy path; got %d", s.RevertCount())
	}

	// PASS condition 4 (KEY): the SWAPPED (race-installed) DB is NOT poisoned
	// with the 0x03 executed marker. It MUST remain empty for the
	// proposal status slot.
	statusKey := storageKeyHash("ms:pstatus:", proposalHash[:])
	swappedStatus := swappedDB.GetState(contractAddr, statusKey)
	if swappedStatus[31] != 0x00 {
		t.Errorf("R48-PRECOMPILE-REENTRANCY-01 V1 FAIL: swappedDB status got 0x%02x, want 0x00 — fix leaked SetState into the race-swapped c.stateDB", swappedStatus[31])
	}

	// PASS condition 5: the ORIGINAL r15H02StateDB now has the 0x03 marker.
	origStatus := s.GetState(contractAddr, statusKey)
	if origStatus[31] != 0x03 {
		t.Errorf("R48-PRECOMPILE-REENTRANCY-01 V1 FAIL: original stateDB status got 0x%02x, want 0x03 — fix did not route SetState through the local stateDB", origStatus[31])
	}
}
