// Quantaureum Node source, version 1.0.0.
package node

// Blob Storage bbolt Adapter — P0-9 (2026-07-14)
//
// Bridges encoding.BlobKVStore (defined in the encoding module, which cannot
// depend on bbolt) with qaudb.Database (the bbolt-backed KV store used by the
// node). The adapter is instantiated by node.go and injected into
// encoding.NewPersistentBlobStorage(store).

import (
	"errors"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/qaudb/db"
)

// bboltBlobKVStore adapts qaudb.Database to the encoding.BlobKVStore interface.
// P0-9 (2026-07-14)
type bboltBlobKVStore struct {
	store db.Database
}

// NewBlobKVStore wraps a qaudb.Database so it can be used as an
// encoding.BlobKVStore for PersistentBlobStorage.
// Returns nil if store is nil (caller should fall back to in-memory mode).
// P0-9 (2026-07-14)
func NewBlobKVStore(store db.Database) encoding.BlobKVStore {
	if store == nil {
		return nil
	}
	return &bboltBlobKVStore{store: store}
}

func (a *bboltBlobKVStore) Get(key []byte) ([]byte, error) {
	v, err := a.store.Get(key)
	if err != nil {
		if errors.Is(err, db.ErrKeyNotFound) {
			return nil, encoding.ErrBlobNotFound
		}
		return nil, err
	}
	return v, nil
}

func (a *bboltBlobKVStore) Put(key, value []byte) error {
	return a.store.Put(key, value)
}

func (a *bboltBlobKVStore) Delete(key []byte) error {
	return a.store.Delete(key)
}

func (a *bboltBlobKVStore) Has(key []byte) (bool, error) {
	return a.store.Has(key)
}

// NewIterator delegates to qaudb.Database.NewIterator(prefix, start), which
// already handles prefix filtering natively (bbolt cursor seeks to prefix and
// stops when the prefix is exhausted). The returned qaudb.Iterator is wrapped
// to satisfy encoding.BlobKVIterator (the two interfaces are structurally
// identical).
func (a *bboltBlobKVStore) NewIterator(prefix []byte, start []byte) encoding.BlobKVIterator {
	return &bboltIterator{raw: a.store.NewIterator(prefix, start)}
}

// bboltIterator wraps qaudb.Iterator as encoding.BlobKVIterator.
type bboltIterator struct {
	raw db.Iterator
}

func (it *bboltIterator) Next() bool    { return it.raw.Next() }
func (it *bboltIterator) Key() []byte   { return it.raw.Key() }
func (it *bboltIterator) Value() []byte { return it.raw.Value() }
func (it *bboltIterator) Error() error  { return it.raw.Error() }
func (it *bboltIterator) Release()      { it.raw.Release() }
