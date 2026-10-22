// Quantaureum Node source, version 1.0.0.
package state

import (
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// R8-02 (2026-10-21 eighth-round audit) at the state layer. qaudb/db pins the
// replay order in isolation; this test pins what Promote must leave on disk when
// a replay that genuinely spans several transactions dies partway, because that
// is the only state a node restarts into:
//
//   - the commit-pending marker IS durable, so RecoverConsistency notices on the
//     next startup and rebuilds instead of trusting the disk;
//   - the last-committed height/root anchor is NOT durable, so nothing on disk
//     claims a height whose accounts were never applied;
//   - no transaction that actually reached the disk carried durability metadata,
//     which is the ordering property the two points above depend on.
//
// Before the fix all three were inverted: the buffered metadata keys are prefixed
// with '_' and sort before the data prefixes "a"/"c"/"s", so the FIRST replay
// transaction published the new anchor and cleared the marker; the failure that
// followed then left a database advertising a block whose accounts were only
// partly there — self-consistent as far as the anchor is concerned, which is why
// nothing detects it at startup.

// r802PoisonDB is a database that (a) caps how many ops a batch may accumulate,
// which is how a real base (MaxBatchOps) forces a large replay to span
// transactions, (b) refuses to commit the transaction carrying one poisoned key,
// which is the media fault, and (c) records the key set of every transaction that
// did reach the disk.
type r802PoisonDB struct {
	db.Database
	poison string
	limit  int
	txs    [][]string
}

func (p *r802PoisonDB) NewBatch() db.Batch {
	return &r802PoisonBatch{Batch: p.Database.NewBatch(), owner: p}
}

// transactions returns the key sets that were made durable, in order.
func (p *r802PoisonDB) transactions() [][]string {
	out := make([][]string, 0, len(p.txs))
	for _, tx := range p.txs {
		out = append(out, append([]string(nil), tx...))
	}
	return out
}

type r802PoisonBatch struct {
	db.Batch
	owner *r802PoisonDB
	keys  []string
}

func (b *r802PoisonBatch) Put(key, value []byte) error {
	if b.owner.limit > 0 && len(b.keys) >= b.owner.limit {
		return db.ErrBatchFull
	}
	b.keys = append(b.keys, string(key))
	return b.Batch.Put(key, value)
}

func (b *r802PoisonBatch) Delete(key []byte) error {
	if b.owner.limit > 0 && len(b.keys) >= b.owner.limit {
		return db.ErrBatchFull
	}
	b.keys = append(b.keys, string(key))
	return b.Batch.Delete(key)
}

// commit either makes the accumulated keys durable or refuses the whole set, so
// a poisoned key never lands on its own.
func (b *r802PoisonBatch) commit(action func() error) error {
	for _, k := range b.keys {
		if k == b.owner.poison {
			b.keys = nil
			b.Batch.Reset()
			return errors.New("simulated media failure")
		}
	}
	err := action()
	if err == nil {
		b.owner.txs = append(b.owner.txs, append([]string(nil), b.keys...))
	}
	b.keys = nil
	b.Batch.Reset()
	return err
}

func (b *r802PoisonBatch) Write() error { return b.commit(b.Batch.Write) }
func (b *r802PoisonBatch) Flush() error { return b.commit(b.Batch.Flush) }

func TestR8_02_PromoteNeverAdvertisesAnAnchorItsReplayDidNotApply(t *testing.T) {
	inner := db.NewMemDB()
	alice := types.Address{0xa1}
	bob := types.Address{0xb0}
	// The poisoned account sorts after the first transaction's worth of data, so
	// the replay is guaranteed to have applied part of the block when it dies —
	// the interesting case. An early failure would let even the old key-order
	// replay look harmless.
	poison := types.Address{0xb4}

	base := &r802PoisonDB{Database: inner, poison: string(append(accountPrefix, poison[:]...))}
	live := NewStateDB(base)
	live.SetBalance(alice, big.NewInt(1000))
	if _, err := live.CommitWithBlock(1); err != nil {
		t.Fatalf("baseline CommitWithBlock(1): %v", err)
	}

	build := live.CopyForBuild()
	if build == nil {
		t.Fatal("CopyForBuild returned nil")
	}
	// Six accounts plus the Verkle node writes give the replay more to apply than
	// one transaction holds, which is what makes the ordering observable.
	for i := 0; i < 6; i++ {
		build.SetBalance(types.Address{byte(0xb0 + i)}, big.NewInt(int64(100+i)))
	}
	if _, err := build.CommitWithBlock(2); err != nil {
		t.Fatalf("build copy CommitWithBlock(2): %v", err)
	}

	// Arm the split only now and start recording from here: the baseline commit
	// above ran against an unlimited batch, exactly like a production commit
	// against MaxBatchOps, and its own metadata writes are not what this test is
	// about.
	base.txs = nil
	base.limit = 3

	err := build.Promote()
	if err == nil {
		t.Fatal("Promote succeeded although the replay was supposed to fail — the fixture is not exercising a partial apply")
	}
	if errors.Is(err, ErrStaleBuildState) {
		t.Fatalf("Promote failed on the staleness fence instead of the injected replay fault: %v", err)
	}

	txs := base.transactions()
	if len(txs) == 0 {
		t.Fatal("the replay applied nothing before failing, so this run cannot say anything about ordering; the fixture's data set is too small")
	}
	for i, tx := range txs {
		for _, k := range tx {
			if strings.HasPrefix(k, "_") {
				t.Errorf("transaction %d of %d made durability metadata %q durable while later data of the same replay never landed", i+1, len(txs), k)
			}
		}
	}

	// Detectable: the marker survived, so the next startup knows this disk holds
	// half of a block rather than a committed state.
	if _, err := inner.Get(commitPendingKey); err != nil {
		t.Errorf("the commit-pending marker is not durable after a failed promote replay (Get: %v) — a restarted node would trust a database that holds half of block 2", err)
	}

	// Not advertised: the anchor of a state that was never fully applied.
	if got := persistedCommittedHeight(t, inner); got != 1 {
		t.Errorf("durable last-committed height = %d after the replay failed, want the pre-commit 1 — the anchor was published ahead of the data behind it", got)
	}
	if _, err := diskAccount(t, inner, bob); err != nil {
		t.Errorf("the first buffered account never reached disk (err=%v) — the replay applied nothing, so the ordering assertions above would be vacuous", err)
	}
	if _, err := diskAccount(t, inner, poison); !errors.Is(err, db.ErrKeyNotFound) {
		t.Errorf("the poisoned account reached the database anyway (err=%v)", err)
	}

	// The copy keeps what did not land so the failure is auditable, and it stays
	// provisional so nothing quietly treats it as the live instance.
	if !build.ProvisionalForTesting() {
		t.Error("the copy is not provisional after a failed promote — its later commits would write straight through")
	}
	if keys, _ := build.BufferedDurableWritesForTesting(); keys == 0 {
		t.Error("a failed promote dropped the buffered writes; the un-applied part of the replay is gone")
	}
}
