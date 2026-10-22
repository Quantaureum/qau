// Quantaureum Node source, version 1.0.0.
package qvmasync

import (
	"math/big"
	"testing"

	"github.com/quantaureum/qau/qvm"
	"github.com/quantaureum/qau/types"
)

// R5-04 (2026-10-21 fifth-round audit) regression tests.
//
// The wrapped StateDB signals "snapshot journal depth exhausted" by returning
// the sentinel -1 from Snapshot() instead of creating a journal entry (see
// qaudb/state.StateDB.Snapshot and STATE-R11-005). The adapter used to book a
// matching access-list entry anyway, storing snapshotIDMap[-1] = index. That
// desynchronised the adapter's stack from the underlying one, and two sentinel
// results in the same frame overwrote each other's mapping, so a later
// RevertToSnapshot/ReleaseSnapshot restored the access lists of the wrong
// frame.

// sentinelStateDB is a minimal qvm.StateDB implementation whose Snapshot()
// mirrors what a real StateDB does when its journal stack fills up.
type sentinelStateDB struct {
	snapshotsTaken int
	maxSnapshots   int
	revertCalls    []int
}

func (s *sentinelStateDB) GetBalance(types.Address) *big.Int  { return big.NewInt(0) }
func (s *sentinelStateDB) SetBalance(types.Address, *big.Int) {}
func (s *sentinelStateDB) GetNonce(types.Address) uint64      { return 0 }
func (s *sentinelStateDB) SetNonce(types.Address, uint64)     {}
func (s *sentinelStateDB) GetCode(types.Address) []byte       { return nil }
func (s *sentinelStateDB) SetCode(types.Address, []byte)      {}
func (s *sentinelStateDB) GetState(types.Address, types.Hash) types.Hash {
	return types.Hash{}
}
func (s *sentinelStateDB) SetState(types.Address, types.Hash, types.Hash) {}

func (s *sentinelStateDB) Snapshot() int {
	if s.snapshotsTaken >= s.maxSnapshots {
		// Depth exhausted: the real StateDB returns -1 and journals nothing.
		return -1
	}
	id := s.snapshotsTaken
	s.snapshotsTaken++
	return id
}

func (s *sentinelStateDB) RevertToSnapshot(id int) {
	s.revertCalls = append(s.revertCalls, id)
	if id >= 0 && id < s.snapshotsTaken {
		s.snapshotsTaken = id
	}
}

func newAdapterWithSentinel(maxSnapshots int) (*StateDBAdapter, *sentinelStateDB) {
	back := &sentinelStateDB{maxSnapshots: maxSnapshots}
	return &StateDBAdapter{StateDB: back}, back
}

// TestR5_04_SentinelSnapshotBooksNothing proves the adapter no longer creates
// a ghost journal entry when the wrapped StateDB refuses to journal one.
func TestR5_04_SentinelSnapshotBooksNothing(t *testing.T) {
	adapter, back := newAdapterWithSentinel(0) // stack already full

	// Give the adapter state worth snapshotting so a ghost entry is meaningful.
	addr := qvm.Address{0x01}
	adapter.AddAddressToAccessList(addr)

	for i := 0; i < 3; i++ {
		if got := adapter.Snapshot(); got != -1 {
			t.Fatalf("Snapshot() #%d = %d, want -1 (the wrapped stack is exhausted)", i+1, got)
		}
	}

	if len(adapter.accessSnapshots) != 0 {
		t.Fatalf("adapter booked %d ghost access-snapshot entries for sentinel ids, want 0",
			len(adapter.accessSnapshots))
	}
	if _, ok := adapter.snapshotIDMap[-1]; ok {
		t.Fatalf("adapter registered snapshotIDMap[-1]; the sentinel must never be mapped")
	}
	if back.snapshotsTaken != 0 {
		t.Fatalf("underlying stack journalled %d entries, want 0", back.snapshotsTaken)
	}
}

// TestR5_04_StacksStaySynchronizedAcrossMixedSnapshots proves the adapter and
// the wrapped StateDB agree on how many frames are live, and that reverting a
// legitimate id restores the matching access list rather than the one a later
// sentinel call registered.
func TestR5_04_StacksStaySynchronizedAcrossMixedSnapshots(t *testing.T) {
	adapter, back := newAdapterWithSentinel(2) // ids 0 and 1 succeed, then sentinel

	addrA := qvm.Address{0x0a}
	idFirst := adapter.Snapshot()
	if idFirst != 0 {
		t.Fatalf("first Snapshot() = %d, want 0", idFirst)
	}
	adapter.AddAddressToAccessList(addrA)

	idSecond := adapter.Snapshot()
	if idSecond != 1 {
		t.Fatalf("second Snapshot() = %d, want 1", idSecond)
	}

	// From here the underlying stack is full: both calls must return -1 and
	// must not shift the adapter's bookkeeping.
	for i := 0; i < 2; i++ {
		if got := adapter.Snapshot(); got != -1 {
			t.Fatalf("exhausted Snapshot() = %d, want -1", got)
		}
	}
	if len(adapter.accessSnapshots) != 2 {
		t.Fatalf("adapter stack length = %d, want 2 (one per journalled frame)", len(adapter.accessSnapshots))
	}
	if back.snapshotsTaken != 2 {
		t.Fatalf("underlying stack depth = %d, want 2", back.snapshotsTaken)
	}

	// Reverting the first frame must roll back the address touched after it.
	adapter.RevertToSnapshot(idFirst)
	if adapter.AddressInAccessList(addrA) {
		t.Fatalf("access list still reports %v warm after reverting to the frame that predates it",
			addrA)
	}
	if len(adapter.accessSnapshots) != 0 {
		t.Fatalf("adapter stack length after revert = %d, want 0 (reverting to id %d pops that frame and everything above it)",
			len(adapter.accessSnapshots), idFirst)
	}
	if _, ok := adapter.snapshotIDMap[idSecond]; ok {
		t.Fatalf("stale mapping for id %d survived the revert", idSecond)
	}
}
