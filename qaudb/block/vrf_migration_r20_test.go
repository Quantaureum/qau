// Quantaureum Node source, version 1.0.0.
package block

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// TestR20_O_VRFAccumulatorLegacyMigration pins the one-time migration that
// keeps the R111-VRF-FASTBOOT path alive across the "v" → "xvrf:" prefix
// rename: legacy entries are copied to the new prefix, the legacy keys are
// deleted, and the colliding "vote:" keys (same shared keyspace via
// SlashingManager.SetDB) are NEVER picked up.
func TestR20_O_VRFAccumulatorLegacyMigration(t *testing.T) {
	store := NewBlockStore(db.NewMemDB())

	// Write legacy-format accumulators directly under the old prefix.
	writeLegacy := func(epoch uint64, acc types.Hash) {
		var epochKey [8]byte
		binary.BigEndian.PutUint64(epochKey[:], epoch)
		if err := store.db.Put(append([]byte("v"), epochKey[:]...), acc[:]); err != nil {
			t.Fatalf("seed legacy key: %v", err)
		}
	}
	acc1 := types.Hash{0xa1}
	acc2 := types.Hash{0xa2}
	writeLegacy(1, acc1)
	writeLegacy(2, acc2)

	// The colliding "vote:" keys must be ignored by the migration (33 bytes,
	// excluded by the strict 1+8 shape check).
	if err := store.db.Put(append([]byte("vote:"), make([]byte, 28)...), []byte("payload")); err != nil {
		t.Fatalf("seed vote key: %v", err)
	}

	got, err := store.LoadVRFAccumulators()
	if err != nil {
		t.Fatalf("LoadVRFAccumulators failed: %v", err)
	}
	if len(got) != 2 || got[1] != acc1 || got[2] != acc2 {
		t.Fatalf("legacy entries must be migrated: got %v", got)
	}

	// Second load must return the SAME set from the new prefix (idempotent —
	// legacy keys are gone, so the fast path serves them).
	got2, err := store.LoadVRFAccumulators()
	if err != nil {
		t.Fatalf("second LoadVRFAccumulators failed: %v", err)
	}
	if len(got2) != 2 || got2[1] != acc1 || got2[2] != acc2 {
		t.Fatalf("migrated entries must be served from the new prefix: got %v", got2)
	}

	// Legacy keys must have been deleted (migration is a move, not a copy).
	var epochKey [8]byte
	binary.BigEndian.PutUint64(epochKey[:], 1)
	if _, err := store.db.Get(append([]byte("v"), epochKey[:]...)); err == nil {
		t.Fatal("legacy key must be deleted after migration")
	}

	// The vote payload must be untouched (the colliding key was never swept).
	if v, err := store.db.Get(append([]byte("vote:"), make([]byte, 28)...)); err != nil || !bytes.Equal(v, []byte("payload")) {
		t.Fatalf("vote key must be untouched by the migration: %v %q", err, v)
	}

	// New writes go to the new prefix and are served.
	if err := store.PutVRFAccumulator(3, types.Hash{0xa3}); err != nil {
		t.Fatalf("PutVRFAccumulator failed: %v", err)
	}
	got3, err := store.LoadVRFAccumulators()
	if err != nil || got3[3] != (types.Hash{0xa3}) {
		t.Fatalf("new-prefix write must be served: %v %v", got3, err)
	}
}

// TestR20_O_MigrationIgnoresMassiveVoteKeyFlood pins the R21 rollout finding:
// the shared keyspace holds ~1.9M "vote:" keys on a production store, and
// BoltDB.NewIterator truncates at 100K entries. The legacy migration MUST
// scan the narrow "v\x00" prefix (epoch keys have a 0x00 second byte;
// "vote:" keys have 'o') so the vote flood never enters the iteration —
// otherwise the migration fails with ErrIteratorTruncated and the
// R111-FASTBOOT path dies on every restart.
func TestR20_O_MigrationIgnoresMassiveVoteKeyFlood(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds 100K+ keys")
	}
	store := NewBlockStore(db.NewMemDB())

	// 100,001 vote keys — enough to trip the 100K iterator cap if the scan
	// ever walked the wide "v" prefix.
	voteTail := make([]byte, 28)
	for i := 0; i < 100001; i++ {
		binary.BigEndian.PutUint32(voteTail[24:28], uint32(i))
		key := append([]byte("vote:"), voteTail...)
		if err := store.db.Put(key, []byte("v")); err != nil {
			t.Fatalf("seed vote key %d: %v", i, err)
		}
	}

	acc := types.Hash{0xbe, 0xef}
	var epochKey [8]byte
	binary.BigEndian.PutUint64(epochKey[:], 777)
	if err := store.db.Put(append([]byte("v"), epochKey[:]...), acc[:]); err != nil {
		t.Fatalf("seed legacy accumulator: %v", err)
	}

	got, err := store.LoadVRFAccumulators()
	if err != nil {
		t.Fatalf("LoadVRFAccumulators must survive the vote flood: %v", err)
	}
	if got[777] != acc {
		t.Fatalf("legacy accumulator must migrate despite 100K+ vote keys: got %v", got)
	}
}
