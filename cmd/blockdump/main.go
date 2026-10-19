// Quantaureum Node source, version 1.0.0.
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"
	"path/filepath"

	bolt "go.etcd.io/bbolt"
	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/qaudb/block"
)

func main() {
	datadir := os.Args[1]
	var height uint64
	fmt.Sscan(os.Args[2], &height)
	// Read-only open: a live qaud owns the writer lock; a second writer
	// open would block 30s and fail. ReadOnly bypasses the lock entirely.
	bdb, err := bolt.Open(filepath.Join(datadir, "blocks", "data.db"), 0600, &bolt.Options{
		ReadOnly: true,
		Timeout:  5 * time.Second,
	})
	if err != nil {
		fmt.Println("open err:", err)
		return
	}
	defer bdb.Close()
	bs := block.NewBlockStore(&roDB{bdb: bdb})
	blk, err := bs.GetBlockByNumber(height)
	if err != nil || blk == nil || blk.Header == nil {
		fmt.Println("get err:", err)
		return
	}
	h := block.ComputeBlockHash(blk.Header)
	fmt.Printf("height=%d hash=%s proposer=%s slot=%d epoch=%d acc=%s txs=%d\n",
		blk.Header.Height, hex.EncodeToString(h[:]), hex.EncodeToString(blk.Header.ProposerAddr[:]),
		blk.Header.Slot, blk.Header.Epoch, hex.EncodeToString(blk.Header.VRFAccumulator[:]), len(blk.Transactions))
}

// roDB adapts a read-only bbolt handle to the db.Database interface expected
// by BlockStore. Reads use the default bucket exactly like BoltDB.Get; all
// mutations fail — this tool must never write.
type roDB struct {
	bdb *bolt.DB
}

func (r *roDB) Get(key []byte) ([]byte, error) {
	var out []byte
	err := r.bdb.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("qaudb"))
		if b == nil {
			return fmt.Errorf("bucket qaudb missing")
		}
		v := b.Get(key)
		if v != nil {
			out = append([]byte(nil), v...)
		}
		return nil
	})
	return out, err
}

func (r *roDB) Has(key []byte) (bool, error) {
	ok, err := r.Get(key)
	return len(ok) > 0, err
}
func (r *roDB) Put(_, _ []byte) error  { return fmt.Errorf("read-only") }
func (r *roDB) Delete(_ []byte) error  { return fmt.Errorf("read-only") }
func (r *roDB) Close() error           { return r.bdb.Close() }
func (r *roDB) NewBatch() db.Batch     { panic("read-only") }
func (r *roDB) NewIterator(prefix []byte, start []byte) db.Iterator { panic("read-only") }
func (r *roDB) NewIteratorWithLimit(prefix []byte, start []byte, limit int) db.Iterator { panic("read-only") }
