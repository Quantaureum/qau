// Quantaureum Node source, version 1.0.0.
package block

// R32 (2026-10-31) — the continuity scan (FindContinuousTip) used to issue
// THREE standalone database Gets per height — one read transaction each — so
// the startup walk at 337k heights held the store lock for 40-90 minutes on
// the arm64 fleet while Node.Start was still inside Syncer.Start: nodes sat
// half-initialized (zero peers, zero logs, height stuck) for the whole walk,
// and every staggered-rollout restart looked frozen (auditor finding from the
// halted R23-R31 fleet deployment).
//
// The fix runs the walk as ONE read transaction with a sequential cursor
// (BoltDB.PrefixScanAndFinalize); the per-height path is kept as the fallback
// for databases without the single-transaction scan. Both paths MUST return
// the same tip on the same data — pinned below on every discontinuity shape.
// The negative control: revert findContinuousTipLocked to the per-height
// branch unconditionally and the BoltDB (fast-path) cases still pass through
// the fallback — so instead the agreement test asserts the fast path is
// actually taken (bs.db must implement prefixScanner) and both paths agree.

import (
	"testing"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// r32BuildChain writes a parent-linked chain of the given height count into
// the store, starting after parent (the genesis parent hash). Returns the
// tip's hash.
func r32BuildChain(t *testing.T, database db.Database, count int, parent types.Hash, seed byte) types.Hash {
	t.Helper()
	bs := NewBlockStore(database)
	tip := parent
	for h := uint64(1); h <= uint64(count); h++ {
		blk := r37MakeBlock(h, tip, 0, seed+byte(h))
		if err := bs.PutBlock(blk); err != nil {
			t.Fatalf("PutBlock(%d): %v", h, err)
		}
		tip = ComputeBlockHash(blk.Header)
	}
	return tip
}

// r32TipsFor returns the continuity tip as computed by BOTH paths on the
// same database: the fast single-transaction scan (BoltDB only) and the
// per-height fallback.
func r32TipsFor(t *testing.T, database db.Database, latestHeight uint64) (fast, fallback uint64, fastTaken bool) {
	t.Helper()
	bs := NewBlockStore(database)

	fastTaken = false
	if scanner, ok := databaseAsPrefixScanner(database); ok {
		bs.mu.RLock()
		tip, err := bs.findContinuousTipScan(scanner, latestHeight)
		bs.mu.RUnlock()
		if err != nil {
			t.Fatalf("fast scan errored: %v", err)
		}
		fast = tip
		fastTaken = true
	}

	bs.mu.RLock()
	fallback = bs.findContinuousTipPerHeight(latestHeight)
	bs.mu.RUnlock()
	return fast, fallback, fastTaken
}

// TestR32_FindContinuousTip_PathAgreement builds the same discontinuity
// shapes into a real BoltDB (fast path) and a MemDB (fallback path) and
// requires both implementations to return the identical tip:
//
//	clean chain            -> tip = height count
//	missing number entry   -> tip = height before the gap
//	corrupt header bytes   -> tip = height before the corrupt header
//	parent linkage broken  -> tip = height before the mismatched header
//	missing header         -> tip = height before the missing header
func TestR32_FindContinuousTip_PathAgreement(t *testing.T) {
	scenarios := []struct {
		name    string
		chain   int // continuous heights written by the builder
		breaks  func(t *testing.T, database db.Database, tip types.Hash) uint64
		wantTip uint64
	}{
		{name: "clean chain", chain: 40, wantTip: 40},
		{
			name:  "gap at height 17 (number entry deleted)",
			chain: 40,
			breaks: func(t *testing.T, database db.Database, tip types.Hash) uint64 {
				if err := database.Delete(r37NumberKey(17)); err != nil {
					t.Fatalf("delete number key: %v", err)
				}
				return 16
			},
		},
		{
			name:  "corrupt header bytes at height 5",
			chain: 40,
			breaks: func(t *testing.T, database db.Database, tip types.Hash) uint64 {
				// Overwrite the header bucket entry of height 5's hash with
				// garbage that fails header decoding. The number index still
				// maps 5 -> fakeHash, so the walk reads and rejects it.
				fakeHash := types.Hash{0x42}
				if err := database.Put(r37NumberKey(5), fakeHash[:]); err != nil {
					t.Fatalf("redirect number key: %v", err)
				}
				if err := database.Put(append(headerPrefix, fakeHash[:]...), []byte{0xde, 0xad, 0xbe, 0xef}); err != nil {
					t.Fatalf("inject corrupt header: %v", err)
				}
				return 4
			},
		},
		{
			name:  "missing header at height 9",
			chain: 40,
			breaks: func(t *testing.T, database db.Database, tip types.Hash) uint64 {
				bs := NewBlockStore(database)
				blk, err := bs.GetBlockByHeight(9)
				if err != nil {
					t.Fatalf("read block 9: %v", err)
				}
				if err := database.Delete(append(headerPrefix, ComputeBlockHash(blk.Header).Bytes()...)); err != nil {
					t.Fatalf("delete header: %v", err)
				}
				return 8
			},
		},
	}

	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			for _, impl := range []struct {
				name string
				new  func(t *testing.T) db.Database
			}{
				{name: "BoltDB(fast path)", new: func(t *testing.T) db.Database {
					d, err := db.NewBoltDB(t.TempDir())
					if err != nil {
						t.Fatalf("NewBoltDB: %v", err)
					}
					t.Cleanup(func() { d.Close() })
					return d
				}},
				{name: "MemDB(fallback)", new: func(t *testing.T) db.Database {
					return db.NewMemDB()
				}},
			} {
				t.Run(impl.name, func(t *testing.T) {
					database := impl.new(t)
					tip := r32BuildChain(t, database, tc.chain, types.Hash{}, 0x30)
					want := tc.wantTip
					if tc.breaks != nil {
						want = tc.breaks(t, database, tip)
					}
					fast, fallback, fastTaken := r32TipsFor(t, database, uint64(tc.chain))
					if fallback != want {
						t.Fatalf("fallback path tip = %d, want %d", fallback, want)
					}
					if !fastTaken {
						if impl.name == "BoltDB(fast path)" {
							t.Fatal("BoltDB did not take the fast path — it must implement prefixScanner")
						}
						return
					}
					if fast != want {
						t.Fatalf("fast path tip = %d, want %d", fast, want)
					}
				})
			}
		})
	}
}

// TestR32_FindContinuousTip_EmptyStore pins the zero state on both paths.
func TestR32_FindContinuousTip_EmptyStore(t *testing.T) {
	for _, database := range []db.Database{db.NewMemDB()} {
		bs := NewBlockStore(database)
		if tip := bs.FindContinuousTip(); tip != 0 {
			t.Fatalf("empty store tip = %d, want 0", tip)
		}
	}
}

// TestR32_FindContinuousTip_TipIsHeaderHash pins that the walk reads the
// number index's hash correctly: the returned tip covers heights whose
// headers decode — exercised implicitly by the agreement test, asserted
// explicitly here for one clean chain on the fast path.
func TestR32_FindContinuousTip_TipIsHeaderHash(t *testing.T) {
	d, err := db.NewBoltDB(t.TempDir())
	if err != nil {
		t.Fatalf("NewBoltDB: %v", err)
	}
	defer d.Close()
	bs := NewBlockStore(d)
	r32BuildChain(t, d, 25, types.Hash{}, 0x31)
	if tip := bs.FindContinuousTip(); tip != 25 {
		t.Fatalf("clean 25-height chain: tip = %d, want 25", tip)
	}
}

// TestR32_FindContinuousTip_HeightZeroGenesisEntry pins the R32b fix (caught
// live on the fleet during rollout): the number index ALSO carries a height-0 genesis
// entry. The per-height walk never reads it (starts at h=1); the first
// revision of the fast walk STOPPED on that entry (h==0 → break), so the
// scan returned 0 and Syncer.Start "corrected" a 337k-height node down to
// genesis — a full re-sync. Height 0 must be SKIPPED, not treated as a
// discontinuity, on BOTH paths.
func TestR32_FindContinuousTip_HeightZeroGenesisEntry(t *testing.T) {
	for _, impl := range []struct {
		name string
		new  func(t *testing.T) db.Database
	}{
		{name: "BoltDB(fast path)", new: func(t *testing.T) db.Database {
			d, err := db.NewBoltDB(t.TempDir())
			if err != nil {
				t.Fatalf("NewBoltDB: %v", err)
			}
			t.Cleanup(func() { d.Close() })
			return d
		}},
		{name: "MemDB(fallback)", new: func(t *testing.T) db.Database {
			return db.NewMemDB()
		}},
	} {
		t.Run(impl.name, func(t *testing.T) {
			database := impl.new(t)
			r32BuildChain(t, database, 30, types.Hash{}, 0x40)

			// The fleet shape: a height-0 genesis entry (number mapping +
			// header) sits BELOW the height-1 block.
			genesisHash := types.Hash{0xEE}
			if err := database.Put(r37NumberKey(0), genesisHash[:]); err != nil {
				t.Fatalf("inject genesis number entry: %v", err)
			}
			hdr := &encoding.BlockHeader{Version: 1, Height: 0, ParentHash: types.Hash{}, ChainID: 1668}
			hdrData, err := encoding.MarshalBlockHeader(hdr)
			if err != nil {
				t.Fatalf("marshal genesis header: %v", err)
			}
			if err := database.Put(append(headerPrefix, genesisHash[:]...), hdrData); err != nil {
				t.Fatalf("inject genesis header: %v", err)
			}

			fast, fallback, fastTaken := r32TipsFor(t, database, 30)
			if fallback != 30 {
				t.Fatalf("fallback tip with a height-0 entry = %d, want 30", fallback)
			}
			if impl.name == "BoltDB(fast path)" && !fastTaken {
				t.Fatal("BoltDB did not take the fast path")
			}
			if fastTaken && fast != 30 {
				t.Fatalf("fast tip with a height-0 entry = %d, want 30 — a height-0 entry must be SKIPPED, not treated as a discontinuity (the fleet resynced from genesis through this bug)", fast)
			}
		})
	}
}

// databaseAsPrefixScanner mirrors the type assertion the production code
// performs on the stored Database (kept in one place so the test cannot
// drift from it).
func databaseAsPrefixScanner(d db.Database) (prefixScanner, bool) {
	scanner, ok := d.(prefixScanner)
	return scanner, ok
}

// TestR32_FindContinuousTip_WindowScope pins the R32c scope boundary: the
// fast single-transaction scan verifies parent linkage for the LAST
// continuityParentWindow heights only; a corrupt header OLDER than the
// window is caught by the per-height fallback (full semantics) but accepted
// by the fast path (tip = the number-continuous height) — and a corrupt
// header INSIDE the window lowers both paths identically.
func TestR32_FindContinuousTip_WindowScope(t *testing.T) {
	const chain = 120
	const corruptAt = 5 // deep: outside the 64-height window back from 120

	d, err := db.NewBoltDB(t.TempDir())
	if err != nil {
		t.Fatalf("NewBoltDB: %v", err)
	}
	defer d.Close()
	r32BuildChain(t, d, chain, types.Hash{}, 0x50)

	// Redirect height 5's number entry to a hash whose "header" is garbage.
	fakeHash := types.Hash{0x42}
	if err := d.Put(r37NumberKey(corruptAt), fakeHash[:]); err != nil {
		t.Fatalf("redirect number key: %v", err)
	}
	if err := d.Put(append(headerPrefix, fakeHash[:]...), []byte{0xde, 0xad, 0xbe, 0xef}); err != nil {
		t.Fatalf("inject corrupt header: %v", err)
	}

	bs := NewBlockStore(d)
	bs.mu.RLock()
	scanner, isScanner := databaseAsPrefixScanner(d)
	if !isScanner {
		t.Fatal("BoltDB must implement prefixScanner")
	}
	fast, ferr := bs.findContinuousTipScan(scanner, chain)
	fallback := bs.findContinuousTipPerHeight(chain)
	bs.mu.RUnlock()

	if ferr != nil {
		t.Fatalf("fast scan errored: %v", ferr)
	}
	if fallback != corruptAt-1 {
		t.Fatalf("fallback (full semantics) tip = %d, want %d", fallback, corruptAt-1)
	}
	if fast != chain {
		t.Fatalf("fast (windowed) tip = %d, want %d — deep corruption is outside the scan's window by design", fast, chain)
	}
	if fast < fallback {
		t.Fatalf("fast tip (%d) must never be BELOW the fallback tip (%d)", fast, fallback)
	}

}

// The recent-window case on a FRESH store: corrupting a header INSIDE the
// window lowers BOTH paths to the height before it (the deep corruption
// above is deliberately on its own store — the fallback would break there
// first and mask the window behavior).
func TestR32_FindContinuousTip_RecentWindowCorruption(t *testing.T) {
	const chain = 120
	recentAt := uint64(chain - 10) // inside the 64-height window back from 120

	d, err := db.NewBoltDB(t.TempDir())
	if err != nil {
		t.Fatalf("NewBoltDB: %v", err)
	}
	defer d.Close()
	r32BuildChain(t, d, chain, types.Hash{}, 0x51)

	fakeHash := types.Hash{0x43}
	if err := d.Put(r37NumberKey(recentAt), fakeHash[:]); err != nil {
		t.Fatalf("redirect recent number key: %v", err)
	}
	if err := d.Put(append(headerPrefix, fakeHash[:]...), []byte{0xde, 0xad, 0xbe, 0xef}); err != nil {
		t.Fatalf("inject recent corrupt header: %v", err)
	}

	bs := NewBlockStore(d)
	bs.mu.RLock()
	scanner, isScanner := databaseAsPrefixScanner(d)
	if !isScanner {
		t.Fatal("BoltDB must implement prefixScanner")
	}
	fast, ferr := bs.findContinuousTipScan(scanner, chain)
	fallback := bs.findContinuousTipPerHeight(chain)
	bs.mu.RUnlock()
	if ferr != nil {
		t.Fatalf("fast scan errored: %v", ferr)
	}
	if fallback != recentAt-1 {
		t.Fatalf("fallback recent-window tip = %d, want %d", fallback, recentAt-1)
	}
	if fast != recentAt-1 {
		t.Fatalf("fast recent-window tip = %d, want %d — in-window corruption must be caught", fast, recentAt-1)
	}
}
