// Quantaureum Node source, version 1.0.0.
// Package state — STATE-R12-002 (2026-07-20) tests.
//
// These tests verify the new native per-tx EIP-2929 access list, EIP-1153
// transient storage, EIP-20 event log accumulation, and EIP-6780 selfdestruct
// support added to StateDB. They cover:
//
//   - Basic API behavior (add/query/idempotency)
//   - Snapshot/RevertToSnapshot integration (per-tx state rolls back)
//   - Commit clears per-tx state (next tx starts clean)
//   - Revert clears per-tx state
//   - Copy deep-copies per-tx state (no aliasing)
//   - FinalizeSelfDestructs balance transfer semantics
//   - SetLogBlockInfo assigns sequential indices
//   - Defensive copying (caller mutation does not corrupt accumulated state)
package state

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// ---------------------------------------------------------------------------
// EIP-2929 access list
// ---------------------------------------------------------------------------

// TestSTATE_R12002_AccessList_BasicAddAndQuery verifies that adding an address
// to the access list marks it warm and AddressInAccessList returns true.
func TestSTATE_R12002_AccessList_BasicAddAndQuery(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01, 0x02, 0x03})

	if s.AddressInAccessList(addr) {
		t.Fatalf("fresh StateDB: addr should be cold (not in access list)")
	}

	s.AddAddressToAccessList(addr)
	if !s.AddressInAccessList(addr) {
		t.Fatalf("after AddAddressToAccessList: addr should be warm")
	}

	// Idempotent: calling again should not change anything.
	s.AddAddressToAccessList(addr)
	if !s.AddressInAccessList(addr) {
		t.Fatalf("after second AddAddressToAccessList: addr should still be warm")
	}
}

// TestSTATE_R12002_AccessList_SlotAddImpliesAddress verifies that adding a
// slot to the access list also marks the containing address warm.
func TestSTATE_R12002_AccessList_SlotAddImpliesAddress(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0xaa})
	slot := types.BytesToHash([]byte{0xbb})

	addrWarm, slotWarm := s.SlotInAccessList(addr, slot)
	if addrWarm || slotWarm {
		t.Fatalf("fresh StateDB: addr and slot should be cold, got (%v, %v)", addrWarm, slotWarm)
	}

	s.AddSlotToAccessList(addr, slot)
	addrWarm, slotWarm = s.SlotInAccessList(addr, slot)
	if !addrWarm {
		t.Fatalf("after AddSlotToAccessList: address should be warm")
	}
	if !slotWarm {
		t.Fatalf("after AddSlotToAccessList: slot should be warm")
	}
}

// TestSTATE_R12002_AccessList_UnknownAddressReturnsCold verifies that
// addresses never added return false from AddressInAccessList.
func TestSTATE_R12002_AccessList_UnknownAddressReturnsCold(t *testing.T) {
	s := NewStateDB()
	addr1 := types.BytesToAddress([]byte{0x01})
	addr2 := types.BytesToAddress([]byte{0x02})

	s.AddAddressToAccessList(addr1)
	if s.AddressInAccessList(addr2) {
		t.Fatalf("addr2 was never added, should be cold")
	}
}

// TestSTATE_R12002_AccessList_SnapshotRevert verifies that the access list
// participates in Snapshot/RevertToSnapshot.
func TestSTATE_R12002_AccessList_SnapshotRevert(t *testing.T) {
	s := NewStateDB()
	addr1 := types.BytesToAddress([]byte{0x01})
	addr2 := types.BytesToAddress([]byte{0x02})

	// Pre-snapshot: add addr1.
	s.AddAddressToAccessList(addr1)
	snap := s.Snapshot()

	// Post-snapshot: add addr2.
	s.AddAddressToAccessList(addr2)
	if !s.AddressInAccessList(addr2) {
		t.Fatalf("before revert: addr2 should be warm")
	}

	// Revert should remove addr2 but keep addr1.
	s.RevertToSnapshot(snap)
	if !s.AddressInAccessList(addr1) {
		t.Fatalf("after revert: addr1 (pre-snapshot) should still be warm")
	}
	if s.AddressInAccessList(addr2) {
		t.Fatalf("after revert: addr2 (post-snapshot) should be cold")
	}
}

// TestSTATE_R12002_AccessList_NestedSnapshotRevert verifies that nested
// snapshots correctly roll back the access list.
func TestSTATE_R12002_AccessList_NestedSnapshotRevert(t *testing.T) {
	s := NewStateDB()
	addr1 := types.BytesToAddress([]byte{0x01})
	addr2 := types.BytesToAddress([]byte{0x02})
	addr3 := types.BytesToAddress([]byte{0x03})

	s.AddAddressToAccessList(addr1)
	snap1 := s.Snapshot()
	s.AddAddressToAccessList(addr2)
	snap2 := s.Snapshot()
	s.AddAddressToAccessList(addr3)

	// Revert to snap2: should remove addr3 but keep addr1, addr2.
	s.RevertToSnapshot(snap2)
	if !s.AddressInAccessList(addr1) || !s.AddressInAccessList(addr2) {
		t.Fatalf("after revert snap2: addr1, addr2 should be warm")
	}
	if s.AddressInAccessList(addr3) {
		t.Fatalf("after revert snap2: addr3 should be cold")
	}

	// Revert to snap1: should remove addr2 (and addr3 already gone).
	s.RevertToSnapshot(snap1)
	if !s.AddressInAccessList(addr1) {
		t.Fatalf("after revert snap1: addr1 should be warm")
	}
	if s.AddressInAccessList(addr2) {
		t.Fatalf("after revert snap1: addr2 should be cold")
	}
}

// TestSTATE_R12002_AccessList_CommitClears verifies that Commit clears the
// access list (it is per-tx by EIP-2929).
func TestSTATE_R12002_AccessList_CommitClears(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})

	s.AddAddressToAccessList(addr)
	if !s.AddressInAccessList(addr) {
		t.Fatalf("before commit: addr should be warm")
	}

	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	if s.AddressInAccessList(addr) {
		t.Fatalf("after commit: addr should be cold (per-tx EIP-2929)")
	}
}

// TestSTATE_R12002_AccessList_RevertClears verifies that Revert clears the
// access list.
func TestSTATE_R12002_AccessList_RevertClears(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})

	s.AddAddressToAccessList(addr)
	s.Revert()

	if s.AddressInAccessList(addr) {
		t.Fatalf("after Revert: addr should be cold")
	}
}

// TestSTATE_R12002_AccessList_CopyPreserves verifies that Copy deep-copies
// the access list so mutations on the copy do not affect the original.
func TestSTATE_R12002_AccessList_CopyPreserves(t *testing.T) {
	s := NewStateDB()
	addr1 := types.BytesToAddress([]byte{0x01})
	addr2 := types.BytesToAddress([]byte{0x02})

	s.AddAddressToAccessList(addr1)
	cp := s.Copy()

	// Mutate the copy — add addr2.
	cp.AddAddressToAccessList(addr2)

	// Original should NOT see addr2.
	if s.AddressInAccessList(addr2) {
		t.Fatalf("original StateDB should not see access list mutation on copy")
	}
	// Original should still see addr1.
	if !s.AddressInAccessList(addr1) {
		t.Fatalf("original StateDB should still see addr1 after copy mutation")
	}
	// Copy should see both.
	if !cp.AddressInAccessList(addr1) || !cp.AddressInAccessList(addr2) {
		t.Fatalf("copy should see addr1 (from original) and addr2 (added after copy)")
	}
}

// ---------------------------------------------------------------------------
// EIP-20 event log accumulation
// ---------------------------------------------------------------------------

// makeTestLog builds a Log with the given address and data for tests.
func makeTestLog(addrByte byte, data []byte) *Log {
	return &Log{
		Address: types.BytesToAddress([]byte{addrByte}),
		Topics:  []types.Hash{types.BytesToHash([]byte{0x01})},
		Data:    data,
	}
}

// TestSTATE_R12002_Logs_AddAndRetrieve verifies that AddLog accumulates logs
// and GetLogs returns them.
func TestSTATE_R12002_Logs_AddAndRetrieve(t *testing.T) {
	s := NewStateDB()
	if logs := s.GetLogs(); len(logs) != 0 {
		t.Fatalf("fresh StateDB should have 0 logs, got %d", len(logs))
	}

	s.AddLog(makeTestLog(0x01, []byte("hello")))
	s.AddLog(makeTestLog(0x02, []byte("world")))

	logs := s.GetLogs()
	if len(logs) != 2 {
		t.Fatalf("expected 2 logs, got %d", len(logs))
	}
	if logs[0].Address != types.BytesToAddress([]byte{0x01}) {
		t.Fatalf("log[0] address mismatch")
	}
	if string(logs[0].Data) != "hello" {
		t.Fatalf("log[0] data mismatch: %s", string(logs[0].Data))
	}
	if logs[1].Address != types.BytesToAddress([]byte{0x02}) {
		t.Fatalf("log[1] address mismatch")
	}
}

// TestSTATE_R12002_Logs_AddLogNilDoesNothing verifies that AddLog(nil) is
// silently ignored rather than appending a nil entry.
func TestSTATE_R12002_Logs_AddLogNilDoesNothing(t *testing.T) {
	s := NewStateDB()
	s.AddLog(nil)
	if logs := s.GetLogs(); len(logs) != 0 {
		t.Fatalf("AddLog(nil) should not append, got %d logs", len(logs))
	}
}

// TestSTATE_R12002_Logs_DefensiveCopy verifies that GetLogs returns a
// defensive copy — mutating the returned slice or its logs does not affect
// the StateDB's accumulated state.
func TestSTATE_R12002_Logs_DefensiveCopy(t *testing.T) {
	s := NewStateDB()
	originalData := []byte("original")
	s.AddLog(makeTestLog(0x01, originalData))

	logs := s.GetLogs()
	// Mutate the returned slice's Data.
	logs[0].Data[0] = 'X'
	// Mutate the slice itself.
	_ = append(logs, makeTestLog(0x99, []byte("extra")))

	// The StateDB's accumulated log should be unchanged.
	again := s.GetLogs()
	if len(again) != 1 {
		t.Fatalf("accumulated logs should still be 1, got %d", len(again))
	}
	if string(again[0].Data) != "original" {
		t.Fatalf("accumulated log data should be unchanged, got %q", string(again[0].Data))
	}
}

// TestSTATE_R12002_Logs_CallerMutationSafe verifies that mutating the Log
// passed to AddLog AFTER AddLog returns does not affect accumulated state.
func TestSTATE_R12002_Logs_CallerMutationSafe(t *testing.T) {
	s := NewStateDB()
	data := []byte("before")
	log := makeTestLog(0x01, data)
	s.AddLog(log)

	// Mutate the original log and its data after AddLog returned.
	log.Address = types.BytesToAddress([]byte{0xff})
	log.Data[0] = 'X'
	log.Topics[0] = types.BytesToHash([]byte{0xff})

	// StateDB's accumulated log should be unchanged.
	got := s.GetLogs()
	if got[0].Address != types.BytesToAddress([]byte{0x01}) {
		t.Fatalf("address should be unchanged: got %x", got[0].Address)
	}
	if string(got[0].Data) != "before" {
		t.Fatalf("data should be unchanged: got %q", string(got[0].Data))
	}
	if got[0].Topics[0] != types.BytesToHash([]byte{0x01}) {
		t.Fatalf("topic should be unchanged: got %x", got[0].Topics[0])
	}
}

// TestSTATE_R12002_Logs_SnapshotRevert verifies that logs participate in
// Snapshot/RevertToSnapshot.
func TestSTATE_R12002_Logs_SnapshotRevert(t *testing.T) {
	s := NewStateDB()
	s.AddLog(makeTestLog(0x01, []byte("first")))
	snap := s.Snapshot()
	s.AddLog(makeTestLog(0x02, []byte("second")))

	if len(s.GetLogs()) != 2 {
		t.Fatalf("before revert: expected 2 logs, got %d", len(s.GetLogs()))
	}

	s.RevertToSnapshot(snap)
	logs := s.GetLogs()
	if len(logs) != 1 {
		t.Fatalf("after revert: expected 1 log, got %d", len(logs))
	}
	if string(logs[0].Data) != "first" {
		t.Fatalf("after revert: log should be 'first', got %q", string(logs[0].Data))
	}
}

// TestSTATE_R12002_Logs_CommitClears verifies that Commit clears logs (they
// are per-tx; the executor extracts them into the receipt before Commit).
func TestSTATE_R12002_Logs_CommitClears(t *testing.T) {
	s := NewStateDB()
	s.AddLog(makeTestLog(0x01, []byte("hello")))
	if len(s.GetLogs()) != 1 {
		t.Fatalf("before commit: expected 1 log, got %d", len(s.GetLogs()))
	}

	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	if len(s.GetLogs()) != 0 {
		t.Fatalf("after commit: expected 0 logs, got %d", len(s.GetLogs()))
	}
}

// TestSTATE_R12002_Logs_RevertClears verifies that Revert clears logs.
func TestSTATE_R12002_Logs_RevertClears(t *testing.T) {
	s := NewStateDB()
	s.AddLog(makeTestLog(0x01, []byte("hello")))
	s.Revert()
	if len(s.GetLogs()) != 0 {
		t.Fatalf("after Revert: expected 0 logs, got %d", len(s.GetLogs()))
	}
}

// TestSTATE_R12002_Logs_SetLogBlockInfo verifies that SetLogBlockInfo
// populates block/tx/index fields and assigns sequential indices.
func TestSTATE_R12002_Logs_SetLogBlockInfo(t *testing.T) {
	s := NewStateDB()
	s.AddLog(makeTestLog(0x01, []byte("a")))
	s.AddLog(makeTestLog(0x02, []byte("b")))
	s.AddLog(makeTestLog(0x03, []byte("c")))

	blockHash := types.BytesToHash([]byte{0xff})
	txHash := types.BytesToHash([]byte{0xee})
	nextIdx := s.SetLogBlockInfo(42, blockHash, txHash, 7, 100)

	if nextIdx != 103 {
		t.Fatalf("expected next index 103, got %d", nextIdx)
	}

	logs := s.GetLogs()
	for i, log := range logs {
		if log.BlockNumber != 42 {
			t.Fatalf("log[%d].BlockNumber = %d, want 42", i, log.BlockNumber)
		}
		if log.BlockHash != blockHash {
			t.Fatalf("log[%d].BlockHash mismatch", i)
		}
		if log.TxHash != txHash {
			t.Fatalf("log[%d].TxHash mismatch", i)
		}
		if log.TxIndex != 7 {
			t.Fatalf("log[%d].TxIndex = %d, want 7", i, log.TxIndex)
		}
		if log.Index != uint(100+i) {
			t.Fatalf("log[%d].Index = %d, want %d", i, log.Index, 100+i)
		}
	}
}

// TestSTATE_R12002_Logs_CopyPreserves verifies that Copy deep-copies logs.
func TestSTATE_R12002_Logs_CopyPreserves(t *testing.T) {
	s := NewStateDB()
	s.AddLog(makeTestLog(0x01, []byte("original")))

	cp := s.Copy()
	// Add another log to the copy.
	cp.AddLog(makeTestLog(0x02, []byte("copy-only")))

	// Original should have 1 log.
	if len(s.GetLogs()) != 1 {
		t.Fatalf("original should have 1 log, got %d", len(s.GetLogs()))
	}
	// Copy should have 2 logs.
	if len(cp.GetLogs()) != 2 {
		t.Fatalf("copy should have 2 logs, got %d", len(cp.GetLogs()))
	}
	// Original data should be unchanged.
	if string(s.GetLogs()[0].Data) != "original" {
		t.Fatalf("original log data should be 'original'")
	}
}

// ---------------------------------------------------------------------------
// EIP-6780 selfdestruct
// ---------------------------------------------------------------------------

// TestSTATE_R12002_SelfDestruct_BasicMark verifies that SelfDestruct marks
// the address and HasSelfDestructed returns true.
func TestSTATE_R12002_SelfDestruct_BasicMark(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})

	if s.HasSelfDestructed(addr) {
		t.Fatalf("fresh StateDB: addr should not be selfdestruct-marked")
	}

	s.SelfDestruct(addr)
	if !s.HasSelfDestructed(addr) {
		t.Fatalf("after SelfDestruct: addr should be marked")
	}
}

// TestSTATE_R12002_SelfDestruct_Idempotent verifies that calling SelfDestruct
// multiple times is idempotent.
func TestSTATE_R12002_SelfDestruct_Idempotent(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})

	s.SelfDestruct(addr)
	s.SelfDestruct(addr)
	s.SelfDestruct(addr)

	if !s.HasSelfDestructed(addr) {
		t.Fatalf("after multiple SelfDestruct calls: should still be marked")
	}
}

// TestSTATE_R12002_SelfDestruct_BeneficiaryRecordsAndRetrieves verifies that
// SelfDestructToBeneficiary records the beneficiary and
// SelfDestructBeneficiary retrieves it.
func TestSTATE_R12002_SelfDestruct_BeneficiaryRecordsAndRetrieves(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})
	ben := types.BytesToAddress([]byte{0x02})

	s.SelfDestructToBeneficiary(addr, ben)

	if !s.HasSelfDestructed(addr) {
		t.Fatalf("after SelfDestructToBeneficiary: addr should be marked")
	}
	got := s.SelfDestructBeneficiary(addr)
	if got != ben {
		t.Fatalf("beneficiary mismatch: got %x, want %x", got, ben)
	}
}

// TestSTATE_R12002_SelfDestruct_FirstCallWins verifies that the first
// SelfDestruct call wins — subsequent calls do not override the beneficiary.
func TestSTATE_R12002_SelfDestruct_FirstCallWins(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})
	ben1 := types.BytesToAddress([]byte{0x02})
	ben2 := types.BytesToAddress([]byte{0x03})

	s.SelfDestructToBeneficiary(addr, ben1)
	// Second call should NOT override.
	s.SelfDestructToBeneficiary(addr, ben2)

	got := s.SelfDestructBeneficiary(addr)
	if got != ben1 {
		t.Fatalf("first-call-wins: beneficiary should be ben1, got %x", got)
	}
}

// TestSTATE_R12002_SelfDestruct_BalanceNotZeroedImmediately verifies EIP-6780
// semantics: after SelfDestruct, the account's balance is NOT immediately
// zeroed — it remains readable until FinalizeSelfDestructs() runs.
func TestSTATE_R12002_SelfDestruct_BalanceNotZeroedImmediately(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})
	ben := types.BytesToAddress([]byte{0x02})

	// Setup: give addr some balance.
	if err := s.AddBalance(addr, big.NewInt(1_000_000)); err != nil {
		t.Fatalf("AddBalance failed: %v", err)
	}

	// SelfDestruct with beneficiary.
	s.SelfDestructToBeneficiary(addr, ben)

	// EIP-6780: balance should NOT be zeroed yet.
	bal := s.GetBalance(addr)
	if bal.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Fatalf("EIP-6780: balance should be unchanged post-SelfDestruct, got %d", bal)
	}
}

// TestSTATE_R12002_SelfDestruct_FinalizeTransfersBalance verifies that
// FinalizeSelfDestructs transfers the balance to the beneficiary.
func TestSTATE_R12002_SelfDestruct_FinalizeTransfersBalance(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})
	ben := types.BytesToAddress([]byte{0x02})

	if err := s.AddBalance(addr, big.NewInt(1_000_000)); err != nil {
		t.Fatalf("AddBalance failed: %v", err)
	}
	s.SelfDestructToBeneficiary(addr, ben)

	count, err := s.FinalizeSelfDestructs()
	if err != nil {
		t.Fatalf("FinalizeSelfDestructs failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 finalized, got %d", count)
	}

	// addr should now have 0 balance.
	if bal := s.GetBalance(addr); bal.Sign() != 0 {
		t.Fatalf("addr balance should be 0 after finalize, got %d", bal)
	}
	// beneficiary should have 1_000_000.
	if bal := s.GetBalance(ben); bal.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Fatalf("beneficiary balance should be 1_000_000, got %d", bal)
	}
	// addr should no longer be marked.
	if s.HasSelfDestructed(addr) {
		t.Fatalf("addr should not be marked after FinalizeSelfDestructs")
	}
}

// TestSTATE_R12002_SelfDestruct_FinalizeZeroBeneficiaryBurnsBalance verifies
// that SelfDestruct() with no beneficiary burns the balance (sent to zero
// address, which is treated as "burn").
func TestSTATE_R12002_SelfDestruct_FinalizeZeroBeneficiaryBurnsBalance(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})

	if err := s.AddBalance(addr, big.NewInt(500_000)); err != nil {
		t.Fatalf("AddBalance failed: %v", err)
	}
	// SelfDestruct with NO beneficiary (default zero address).
	s.SelfDestruct(addr)

	count, err := s.FinalizeSelfDestructs()
	if err != nil {
		t.Fatalf("FinalizeSelfDestructs failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 finalized, got %d", count)
	}
	// Balance should be burned (zeroed, not sent anywhere meaningful).
	if bal := s.GetBalance(addr); bal.Sign() != 0 {
		t.Fatalf("burned addr balance should be 0, got %d", bal)
	}
}

// TestSTATE_R12002_SelfDestruct_SnapshotRevert verifies that selfdestruct
// marks participate in Snapshot/RevertToSnapshot.
func TestSTATE_R12002_SelfDestruct_SnapshotRevert(t *testing.T) {
	s := NewStateDB()
	addr1 := types.BytesToAddress([]byte{0x01})
	addr2 := types.BytesToAddress([]byte{0x02})

	s.SelfDestruct(addr1)
	snap := s.Snapshot()
	s.SelfDestruct(addr2)

	if !s.HasSelfDestructed(addr2) {
		t.Fatalf("before revert: addr2 should be marked")
	}

	s.RevertToSnapshot(snap)
	if !s.HasSelfDestructed(addr1) {
		t.Fatalf("after revert: addr1 (pre-snapshot) should still be marked")
	}
	if s.HasSelfDestructed(addr2) {
		t.Fatalf("after revert: addr2 (post-snapshot) should not be marked")
	}
}

// TestSTATE_R12002_SelfDestruct_CommitClears verifies that Commit clears the
// selfdestruct markers (after FinalizeSelfDestructs has processed them).
func TestSTATE_R12002_SelfDestruct_CommitClears(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})

	s.SelfDestruct(addr)
	if !s.HasSelfDestructed(addr) {
		t.Fatalf("before commit: should be marked")
	}

	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	if s.HasSelfDestructed(addr) {
		t.Fatalf("after commit: should not be marked")
	}
}

// TestSTATE_R12002_SelfDestruct_RevertClears verifies that Revert clears
// selfdestruct markers.
func TestSTATE_R12002_SelfDestruct_RevertClears(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})

	s.SelfDestruct(addr)
	s.Revert()

	if s.HasSelfDestructed(addr) {
		t.Fatalf("after Revert: should not be marked")
	}
}

// TestSTATE_R12002_SelfDestruct_CopyPreserves verifies that Copy deep-copies
// the selfdestruct set.
func TestSTATE_R12002_SelfDestruct_CopyPreserves(t *testing.T) {
	s := NewStateDB()
	addr1 := types.BytesToAddress([]byte{0x01})
	addr2 := types.BytesToAddress([]byte{0x02})

	s.SelfDestruct(addr1)
	cp := s.Copy()
	// Mark addr2 on the copy.
	cp.SelfDestruct(addr2)

	// Original should NOT see addr2.
	if s.HasSelfDestructed(addr2) {
		t.Fatalf("original should not see selfdestruct mutation on copy")
	}
	// Both should see addr1.
	if !s.HasSelfDestructed(addr1) || !cp.HasSelfDestructed(addr1) {
		t.Fatalf("both should see addr1 marked")
	}
	// Copy should see addr2.
	if !cp.HasSelfDestructed(addr2) {
		t.Fatalf("copy should see addr2 marked")
	}
}

// ---------------------------------------------------------------------------
// EIP-1153 transient storage
// ---------------------------------------------------------------------------

// TestSTATE_R12002_Transient_GetSet verifies basic SetTransientState /
// GetTransientState round-trip.
func TestSTATE_R12002_Transient_GetSet(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})
	key := types.BytesToHash([]byte{0xaa})
	val := types.BytesToHash([]byte{0xbb})

	// Unset key returns zero hash.
	got := s.GetTransientState(addr, key)
	if got != (types.Hash{}) {
		t.Fatalf("fresh StateDB: transient state should be zero hash, got %x", got)
	}

	s.SetTransientState(addr, key, val)
	got = s.GetTransientState(addr, key)
	if got != val {
		t.Fatalf("after SetTransientState: got %x, want %x", got, val)
	}
}

// TestSTATE_R12002_Transient_Overwrite verifies that setting the same key
// twice overwrites the value.
func TestSTATE_R12002_Transient_Overwrite(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})
	key := types.BytesToHash([]byte{0xaa})
	val1 := types.BytesToHash([]byte{0xbb})
	val2 := types.BytesToHash([]byte{0xcc})

	s.SetTransientState(addr, key, val1)
	s.SetTransientState(addr, key, val2)

	got := s.GetTransientState(addr, key)
	if got != val2 {
		t.Fatalf("after overwrite: got %x, want %x", got, val2)
	}
}

// TestSTATE_R12002_Transient_SetToZero verifies that explicitly setting a
// key to the zero hash is distinguishable from "never set" via
// GetTransientStateExists.
func TestSTATE_R12002_Transient_SetToZero(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})
	key := types.BytesToHash([]byte{0xaa})

	// Unset: exists=false.
	if s.GetTransientStateExists(addr, key) {
		t.Fatalf("fresh StateDB: key should not exist")
	}

	// Explicitly set to zero hash.
	s.SetTransientState(addr, key, types.Hash{})
	// exists=true (distinguishes set-to-zero from unset).
	if !s.GetTransientStateExists(addr, key) {
		t.Fatalf("after SetTransientState(zero): key should exist")
	}
	// GetTransientState returns zero hash.
	got := s.GetTransientState(addr, key)
	if got != (types.Hash{}) {
		t.Fatalf("got %x, want zero hash", got)
	}
}

// TestSTATE_R12002_Transient_DifferentAddresses verifies that transient
// storage is keyed by (addr, key) — same key at different addresses is
// isolated.
func TestSTATE_R12002_Transient_DifferentAddresses(t *testing.T) {
	s := NewStateDB()
	addr1 := types.BytesToAddress([]byte{0x01})
	addr2 := types.BytesToAddress([]byte{0x02})
	key := types.BytesToHash([]byte{0xaa})
	val1 := types.BytesToHash([]byte{0xbb})
	val2 := types.BytesToHash([]byte{0xcc})

	s.SetTransientState(addr1, key, val1)
	s.SetTransientState(addr2, key, val2)

	if got := s.GetTransientState(addr1, key); got != val1 {
		t.Fatalf("addr1: got %x, want %x", got, val1)
	}
	if got := s.GetTransientState(addr2, key); got != val2 {
		t.Fatalf("addr2: got %x, want %x", got, val2)
	}
}

// TestSTATE_R12002_Transient_SnapshotRevert verifies that transient storage
// participates in Snapshot/RevertToSnapshot.
func TestSTATE_R12002_Transient_SnapshotRevert(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})
	key1 := types.BytesToHash([]byte{0xa1})
	key2 := types.BytesToHash([]byte{0xa2})
	val1 := types.BytesToHash([]byte{0x11})
	val2 := types.BytesToHash([]byte{0x22})

	s.SetTransientState(addr, key1, val1)
	snap := s.Snapshot()
	s.SetTransientState(addr, key2, val2)

	if got := s.GetTransientState(addr, key2); got != val2 {
		t.Fatalf("before revert: key2 should be %x, got %x", val2, got)
	}

	s.RevertToSnapshot(snap)
	// key1 should still be val1.
	if got := s.GetTransientState(addr, key1); got != val1 {
		t.Fatalf("after revert: key1 should be %x, got %x", val1, got)
	}
	// key2 should be zero (was added post-snapshot).
	if got := s.GetTransientState(addr, key2); got != (types.Hash{}) {
		t.Fatalf("after revert: key2 should be zero, got %x", got)
	}
	if s.GetTransientStateExists(addr, key2) {
		t.Fatalf("after revert: key2 should not exist")
	}
}

// TestSTATE_R12002_Transient_CommitClears verifies that Commit clears
// transient storage (it is per-tx by EIP-1153).
func TestSTATE_R12002_Transient_CommitClears(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})
	key := types.BytesToHash([]byte{0xaa})
	val := types.BytesToHash([]byte{0xbb})

	s.SetTransientState(addr, key, val)
	if got := s.GetTransientState(addr, key); got != val {
		t.Fatalf("before commit: got %x, want %x", got, val)
	}

	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	if got := s.GetTransientState(addr, key); got != (types.Hash{}) {
		t.Fatalf("after commit: transient should be zero (per-tx), got %x", got)
	}
}

// TestSTATE_R12002_Transient_RevertClears verifies that Revert clears
// transient storage.
func TestSTATE_R12002_Transient_RevertClears(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})
	key := types.BytesToHash([]byte{0xaa})
	val := types.BytesToHash([]byte{0xbb})

	s.SetTransientState(addr, key, val)
	s.Revert()

	if got := s.GetTransientState(addr, key); got != (types.Hash{}) {
		t.Fatalf("after Revert: transient should be zero, got %x", got)
	}
}

// TestSTATE_R12002_Transient_CopyPreserves verifies that Copy deep-copies
// transient storage.
func TestSTATE_R12002_Transient_CopyPreserves(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})
	key1 := types.BytesToHash([]byte{0xa1})
	val1 := types.BytesToHash([]byte{0x11})
	key2 := types.BytesToHash([]byte{0xa2})
	val2 := types.BytesToHash([]byte{0x22})

	s.SetTransientState(addr, key1, val1)
	cp := s.Copy()
	cp.SetTransientState(addr, key2, val2)

	// Original should not see key2.
	if got := s.GetTransientState(addr, key2); got != (types.Hash{}) {
		t.Fatalf("original should not see copy's key2, got %x", got)
	}
	// Original key1 should still be val1.
	if got := s.GetTransientState(addr, key1); got != val1 {
		t.Fatalf("original key1 should be %x, got %x", val1, got)
	}
	// Copy should see both.
	if got := cp.GetTransientState(addr, key1); got != val1 {
		t.Fatalf("copy key1 should be %x, got %x", val1, got)
	}
	if got := cp.GetTransientState(addr, key2); got != val2 {
		t.Fatalf("copy key2 should be %x, got %x", val2, got)
	}
}

// ---------------------------------------------------------------------------
// Cross-feature: invalid snapshot fallback
// ---------------------------------------------------------------------------

// TestSTATE_R12002_InvalidSnapshotClearsAllTxState verifies that calling
// RevertToSnapshot with an invalid ID falls back to clearing all per-tx
// state (access list, logs, selfdestructs, transient storage).
func TestSTATE_R12002_InvalidSnapshotClearsAllTxState(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})
	key := types.BytesToHash([]byte{0xaa})
	val := types.BytesToHash([]byte{0xbb})

	s.AddAddressToAccessList(addr)
	s.AddLog(makeTestLog(0x01, []byte("log")))
	s.SelfDestruct(addr)
	s.SetTransientState(addr, key, val)

	// Revert to an invalid (negative) snapshot ID.
	s.RevertToSnapshot(-1)

	// All per-tx state should be cleared.
	if s.AddressInAccessList(addr) {
		t.Fatalf("after invalid revert: access list should be empty")
	}
	if len(s.GetLogs()) != 0 {
		t.Fatalf("after invalid revert: logs should be empty")
	}
	if s.HasSelfDestructed(addr) {
		t.Fatalf("after invalid revert: selfdestructs should be empty")
	}
	if got := s.GetTransientState(addr, key); got != (types.Hash{}) {
		t.Fatalf("after invalid revert: transient should be zero, got %x", got)
	}
}

// ---------------------------------------------------------------------------
// Cross-feature: ClearTxState public API
// ---------------------------------------------------------------------------

// TestSTATE_R12002_ClearTxState_PublicAPI verifies that the public ClearTxState
// method clears all four per-tx features.
func TestSTATE_R12002_ClearTxState_PublicAPI(t *testing.T) {
	s := NewStateDB()
	addr := types.BytesToAddress([]byte{0x01})
	key := types.BytesToHash([]byte{0xaa})
	val := types.BytesToHash([]byte{0xbb})

	s.AddAddressToAccessList(addr)
	s.AddLog(makeTestLog(0x01, []byte("log")))
	s.SelfDestruct(addr)
	s.SetTransientState(addr, key, val)

	s.ClearTxState()

	if s.AddressInAccessList(addr) {
		t.Fatalf("after ClearTxState: access list should be empty")
	}
	if len(s.GetLogs()) != 0 {
		t.Fatalf("after ClearTxState: logs should be empty")
	}
	if s.HasSelfDestructed(addr) {
		t.Fatalf("after ClearTxState: selfdestructs should be empty")
	}
	if got := s.GetTransientState(addr, key); got != (types.Hash{}) {
		t.Fatalf("after ClearTxState: transient should be zero, got %x", got)
	}
}

// ---------------------------------------------------------------------------
// Cross-feature: integration with underlying state
// ---------------------------------------------------------------------------

// TestSTATE_R12002_PersistentDB_PreservesAccountStateAfterCommit verifies
// that committing account changes does NOT lose them — even though Commit
// also clears per-tx EIP state. This is a regression test to ensure the
// new clearTxStateLocked() call in Commit does not accidentally clear
// dirtyAccounts/dirtyStorage.
func TestSTATE_R12002_PersistentDB_PreservesAccountStateAfterCommit(t *testing.T) {
	memDB := db.NewMemDB()
	s := NewStateDB(memDB)

	addr := types.BytesToAddress([]byte{0x01})
	if err := s.AddBalance(addr, big.NewInt(1_000_000)); err != nil {
		t.Fatalf("AddBalance failed: %v", err)
	}
	// Also add a log — Commit should clear it but preserve account state.
	s.AddLog(makeTestLog(0x01, []byte("log")))

	if _, err := s.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Re-read account — balance should persist.
	got := s.GetBalance(addr)
	if got.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Fatalf("balance should persist after commit, got %d", got)
	}
	// Log should be cleared.
	if len(s.GetLogs()) != 0 {
		t.Fatalf("logs should be cleared after commit, got %d", len(s.GetLogs()))
	}
}
