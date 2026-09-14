// Quantaureum Node source, version 1.0.0.
package trie

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

type BatchProof struct {
	Proofs     []*VerkleProof
	RootBefore types.Hash
	RootAfter  types.Hash
}

type VerkleStateDB struct {
	mu      sync.RWMutex
	tree    *VerkleTree
	storage map[string]*VerkleTree
	codeDB  map[types.Hash][]byte
	dirty   bool
}

func NewVerkleStateDB() *VerkleStateDB {
	return &VerkleStateDB{
		tree:    NewVerkleTree(MaxTreeDepth),
		storage: make(map[string]*VerkleTree),
		codeDB:  make(map[types.Hash][]byte),
	}
}

func (db *VerkleStateDB) Root() types.Hash {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.tree.Root()
}

func (db *VerkleStateDB) GetAccount(addr types.Address) ([]byte, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := makeAccountKey(addr)
	return db.tree.Get(key)
}

func (db *VerkleStateDB) SetAccount(addr types.Address, data []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	key := makeAccountKey(addr)
	db.dirty = true
	return db.tree.Put(key, data)
}

func (db *VerkleStateDB) DeleteAccount(addr types.Address) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	key := makeAccountKey(addr)
	db.dirty = true

	storageKey := string(addr[:])
	delete(db.storage, storageKey)

	return db.tree.Delete(key)
}

func (db *VerkleStateDB) GetStorage(addr types.Address, slot types.Hash) ([]byte, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	storageKey := string(addr[:])
	storageTree, ok := db.storage[storageKey]
	if !ok {
		return nil, ErrKeyNotFound
	}

	return storageTree.Get(slot[:])
}

func (db *VerkleStateDB) SetStorage(addr types.Address, slot types.Hash, value []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	storageKey := string(addr[:])
	storageTree, ok := db.storage[storageKey]
	if !ok {
		storageTree = NewVerkleTree(MaxTreeDepth)
		db.storage[storageKey] = storageTree
	}

	db.dirty = true
	return storageTree.Put(slot[:], value)
}

func (db *VerkleStateDB) GetStorageRoot(addr types.Address) types.Hash {
	db.mu.RLock()
	defer db.mu.RUnlock()

	storageKey := string(addr[:])
	storageTree, ok := db.storage[storageKey]
	if !ok {
		return types.Hash{}
	}
	return storageTree.Root()
}

func (db *VerkleStateDB) GetCode(codeHash types.Hash) ([]byte, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	code, ok := db.codeDB[codeHash]
	if !ok {
		return nil, fmt.Errorf("code not found")
	}
	copied := make([]byte, len(code))
	copy(copied, code)
	return copied, nil
}

func (db *VerkleStateDB) SetCode(code []byte) types.Hash {
	db.mu.Lock()
	defer db.mu.Unlock()

	return db.setCodeLocked(code)
}

func (db *VerkleStateDB) setCodeLocked(code []byte) types.Hash {
	h := sha3.New256()
	h.Write(code)
	var codeHash types.Hash
	copy(codeHash[:], h.Sum(nil))

	db.codeDB[codeHash] = code
	db.dirty = true
	return codeHash
}

func (db *VerkleStateDB) BatchUpdate(updates []StateUpdate) (*BatchProof, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	rootBefore := db.tree.Root()

	// R33 TRIE-08 FIX (2026-07-28): Snapshot the tree and storage maps
	// before applying updates so we can roll back atomically on partial
	// failure. Previously, if update N failed, updates 1..N-1 were already
	// applied to db.tree / db.storage / db.codeDB, leaving the state DB in
	// a half-applied state. Subsequent reads would see partial updates,
	// and the next Commit would persist them — causing permanent state
	// corruption. Fix: deep-copy the tree and codeDB (storage trees are
	// already deep-copied per-account via the storage map copy below).
	// On failure, restore the snapshots. On success, discard them.
	treeSnapshot := db.tree.Copy()
	codeSnapshot := make(map[types.Hash][]byte, len(db.codeDB))
	for k, v := range db.codeDB {
		codeSnapshot[k] = append([]byte(nil), v...)
	}
	storageSnapshot := make(map[string]*VerkleTree, len(db.storage))
	for k, t := range db.storage {
		storageSnapshot[k] = t.Copy()
	}
	// Track which storage trees were created during this BatchUpdate so
	// we can remove them on rollback (they didn't exist before).
	createdStorageKeys := make(map[string]bool)

	// R35-P2-STATE-03 FIX (2026-07-29): Snapshot db.dirty before applying
	// updates so rollback can restore it. Previously, if setCodeLocked was
	// called during the batch (setting db.dirty=true) and then a later
	// update failed, rollback restored tree/codeDB/storage but left
	// db.dirty=true — even though all the batch's mutations were undone.
	// This caused the next Commit() to flush a tree that was identical to
	// its pre-batch state, wasting I/O. Worse, if the pre-batch dirty flag
	// was false (clean state), the spurious dirty=true after rollback could
	// trigger a flush that wrote nothing but still reset internal tree
	// buffers (Flush resets the dirty flag on child nodes), corrupting
	// the tree's persistence tracking for future writes.
	dirtyBefore := db.dirty

	rollback := func() {
		db.tree = treeSnapshot
		db.codeDB = codeSnapshot
		// Restore storage map: keep original entries, drop newly-created ones.
		newStorage := make(map[string]*VerkleTree, len(storageSnapshot))
		for k, t := range storageSnapshot {
			newStorage[k] = t
		}
		db.storage = newStorage
		// R35-P2-STATE-03 FIX: restore dirty flag to pre-batch value.
		db.dirty = dirtyBefore
	}

	proofs := make([]*VerkleProof, 0, len(updates))

	for _, update := range updates {
		switch update.Type {
		case UpdateAccount:
			key := makeAccountKey(update.Address)
			if update.Value == nil {
				if err := db.tree.Delete(key); err != nil {
					rollback()
					return nil, fmt.Errorf("batch delete account: %w", err)
				}
			} else {
				if err := db.tree.Put(key, update.Value); err != nil {
					rollback()
					return nil, fmt.Errorf("batch set account: %w", err)
				}
			}

			proof, err := db.tree.Prove(key)
			if err != nil {
				rollback()
				return nil, fmt.Errorf("batch prove account: %w", err)
			}
			proofs = append(proofs, proof)

		case UpdateStorage:
			storageKey := string(update.Address[:])
			storageTree, ok := db.storage[storageKey]
			if !ok {
				storageTree = NewVerkleTree(MaxTreeDepth)
				db.storage[storageKey] = storageTree
				createdStorageKeys[storageKey] = true
			}

			if update.Value == nil {
				if err := storageTree.Delete(update.Slot[:]); err != nil {
					rollback()
					return nil, fmt.Errorf("batch delete storage: %w", err)
				}
			} else {
				if err := storageTree.Put(update.Slot[:], update.Value); err != nil {
					rollback()
					return nil, fmt.Errorf("batch set storage: %w", err)
				}
			}

			proof, err := storageTree.Prove(update.Slot[:])
			if err != nil {
				rollback()
				return nil, fmt.Errorf("batch prove storage: %w", err)
			}
			proofs = append(proofs, proof)

		case UpdateCode:
			if update.Value != nil {
				db.setCodeLocked(update.Value)
			}
		}
	}

	db.dirty = true

	return &BatchProof{
		Proofs:     proofs,
		RootBefore: rootBefore,
		RootAfter:  db.tree.Root(),
	}, nil
}

func (db *VerkleStateDB) ProveAccount(addr types.Address) (*VerkleProof, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := makeAccountKey(addr)
	return db.tree.Prove(key)
}

func (db *VerkleStateDB) ProveStorage(addr types.Address, slot types.Hash) (*VerkleProof, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	storageKey := string(addr[:])
	storageTree, ok := db.storage[storageKey]
	if !ok {
		return nil, ErrKeyNotFound
	}

	return storageTree.Prove(slot[:])
}

func (db *VerkleStateDB) VerifyAccountProof(root types.Hash, proof *VerkleProof) bool {
	return VerifyProof(root, proof)
}

func (db *VerkleStateDB) VerifyStorageProof(root types.Hash, proof *VerkleProof) bool {
	return VerifyProof(root, proof)
}

func (db *VerkleStateDB) IsDirty() bool {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.dirty
}

func (db *VerkleStateDB) ClearDirty() {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.dirty = false
}

func (db *VerkleStateDB) Copy() *VerkleStateDB {
	db.mu.RLock()
	defer db.mu.RUnlock()

	newDB := &VerkleStateDB{
		tree:    db.tree.Copy(),
		storage: make(map[string]*VerkleTree, len(db.storage)),
		codeDB:  make(map[types.Hash][]byte, len(db.codeDB)),
		dirty:   db.dirty,
	}

	for k, v := range db.storage {
		newDB.storage[k] = v.Copy()
	}
	for k, v := range db.codeDB {
		copied := make([]byte, len(v))
		copy(copied, v)
		newDB.codeDB[k] = copied
	}

	return newDB
}

func (db *VerkleStateDB) Snapshot() *VerkleStateDB {
	return db.Copy()
}

func (db *VerkleStateDB) RevertTo(snapshot *VerkleStateDB) {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.tree = snapshot.tree.Copy()
	db.storage = make(map[string]*VerkleTree, len(snapshot.storage))
	for k, v := range snapshot.storage {
		db.storage[k] = v.Copy()
	}
	db.codeDB = make(map[types.Hash][]byte, len(snapshot.codeDB))
	for k, v := range snapshot.codeDB {
		copied := make([]byte, len(v))
		copy(copied, v)
		db.codeDB[k] = copied
	}
	db.dirty = snapshot.dirty
}

// Commit returns the current state root and flushes any pending persistence
// writes on the account tree and all per-address storage trees.
//
// STORAGE-P0-02 FIX (R31, 2026-07-27): Previously this method was a no-op
// for persistence — it only returned db.tree.Root() without writing anything
// to disk. If VerkleStateDB is ever wired to a persistentDB (today it is
// in-memory only, but a future change could attach one), the previous
// implementation would silently lose all updates on restart. Now we call
// Flush() on the account tree and every storage tree, returning the first
// error encountered. When no persistentDB is configured (current usage),
// Flush() is a no-op and behavior is unchanged.
// R35-P2-STATE-02 FIX (2026-07-29): Previously this method used RLock, but
// Commit() calls Flush() on the account tree and every storage tree, which
// writes pending state to the persistent database. Flush() is a MUTATION
// operation — using RLock allowed concurrent readers (Get/GetStorage) to
// access the trees mid-flush, causing data races on the tree's internal
// nodes and the persistentDB's write buffers. Changed to Lock (exclusive)
// so no other goroutine can read or write the trees while flush is in progress.
func (db *VerkleStateDB) Commit() (types.Hash, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	// STORAGE-P0-02 FIX: flush pending writes on the account tree first.
	// R37-P3-13 FIX (2026-07-31): cross-tree Flush is NOT atomic — there is
	// no multi-tree transaction, so if the account flush succeeds but a
	// storage flush fails, on-disk state is partially committed. Minimal
	// defense: best-effort flush ALL trees (so on-disk state converges as
	// far as possible), log every failure, and return the FIRST error so
	// the caller knows the committed state is inconsistent and must retry
	// (a retry is safe because Flush retains pending batches on failure).
	var firstErr error
	if err := db.tree.Flush(); err != nil {
		log.Printf("WARN: verkle state commit: account tree flush failed: %v (cross-tree flush is non-atomic; on-disk state may be partially committed)", err)
		firstErr = fmt.Errorf("verkle state commit: account tree flush failed: %w", err)
	}
	// Flush each per-address storage tree. Best-effort: continue past
	// failures (R37-P3-13), record only the first error.
	for addrKey, storageTree := range db.storage {
		if err := storageTree.Flush(); err != nil {
			log.Printf("WARN: verkle state commit: storage tree %s flush failed: %v (cross-tree flush is non-atomic; on-disk state may be partially committed)", addrKey, err)
			if firstErr == nil {
				firstErr = fmt.Errorf("verkle state commit: storage tree %s flush failed: %w", addrKey, err)
			}
		}
	}
	if firstErr != nil {
		return types.Hash{}, firstErr
	}
	return db.tree.Root(), nil
}

func (db *VerkleStateDB) Dump() map[string][]byte {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.dumpLocked()
}

// dumpLocked is the lock-free core of Dump. The caller MUST hold at least
// db.mu.RLock.
//
// R37-FIX P2-STATE-01 (2026-07-30): Extracted from Dump() so that Serialize()
// can dump while already holding RLock. Go's sync.RWMutex does not support
// recursive read locking: if a writer is queued, a second RLock on the same
// goroutine blocks forever while the first RLock is never released — a
// self-deadlock that permanently froze the VerkleStateDB.
func (db *VerkleStateDB) dumpLocked() map[string][]byte {
	result := make(map[string][]byte)

	rawDB := db.tree.GetDB()
	for k, v := range rawDB {
		copied := make([]byte, len(v))
		copy(copied, v)
		result["account:"+k] = copied
	}

	for addrKey, storageTree := range db.storage {
		storageDB := storageTree.GetDB()
		for k, v := range storageDB {
			copied := make([]byte, len(v))
			copy(copied, v)
			result["storage:"+addrKey+":"+k] = copied
		}
	}

	for codeHash, code := range db.codeDB {
		copied := make([]byte, len(code))
		copy(copied, code)
		result["code:"+string(codeHash[:])] = copied
	}

	return result
}

func (db *VerkleStateDB) Import(data map[string][]byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.importLocked(data)
}

func (db *VerkleStateDB) importLocked(data map[string][]byte) error {
	// R37-P3-10 FIX (2026-07-31): replace-style import — clear existing
	// state before loading. The previous merge-style import left stale
	// entries from prior state in place, so importing a partial or
	// tampered dump would silently retain accounts, storage slots, or
	// code that should no longer exist.
	db.tree.dbMu.Lock()
	db.tree.db = make(map[string][]byte)
	db.tree.dbMu.Unlock()
	db.tree.root = types.Hash{}
	db.tree.rootNode = nil
	db.storage = make(map[string]*VerkleTree)
	db.codeDB = make(map[types.Hash][]byte)

	for k, v := range data {
		if len(k) < 8 {
			continue
		}
		prefix := k[:8]
		switch prefix {
		case "account:":
			hashKey := k[8:]
			db.tree.dbMu.Lock()
			db.tree.db[hashKey] = v
			db.tree.dbMu.Unlock()
		case "storage:":
			rest := k[8:]
			sepIdx := bytes.IndexByte([]byte(rest), ':')
			if sepIdx < 0 {
				continue
			}
			addrKey := rest[:sepIdx]
			hashKey := rest[sepIdx+1:]

			storageTree, ok := db.storage[addrKey]
			if !ok {
				storageTree = NewVerkleTree(MaxTreeDepth)
				db.storage[addrKey] = storageTree
			}
			storageTree.dbMu.Lock()
			storageTree.db[hashKey] = v
			storageTree.dbMu.Unlock()
		case "code:":
			hashKey := k[5:]
			// R37-P3-10 FIX (2026-07-31): hashKey must be exactly
			// types.HashLength bytes. A truncated key would silently pad
			// with zeros, mapping to an arbitrary (wrong) codeHash and
			// potentially overwriting legitimate contract code.
			if len(hashKey) != len(types.Hash{}) {
				continue
			}
			var codeHash types.Hash
			copy(codeHash[:], []byte(hashKey))
			db.codeDB[codeHash] = v
		}
	}

	return nil
}

type StateUpdateType int

const (
	UpdateAccount StateUpdateType = iota
	UpdateStorage
	UpdateCode
)

type StateUpdate struct {
	Type    StateUpdateType
	Address types.Address
	Slot    types.Hash
	Value   []byte
}

func makeAccountKey(addr types.Address) []byte {
	key := make([]byte, 32)
	copy(key[12:], addr[:])
	return key
}

func (db *VerkleStateDB) GetNodeCount() int {
	db.mu.RLock()
	defer db.mu.RUnlock()

	db.tree.dbMu.RLock()
	count := len(db.tree.db)
	db.tree.dbMu.RUnlock()

	for _, st := range db.storage {
		st.dbMu.RLock()
		count += len(st.db)
		st.dbMu.RUnlock()
	}
	return count
}

func (db *VerkleStateDB) GetCodeCount() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.codeDB)
}

func (db *VerkleStateDB) IterateAccounts(fn func(addr types.Address, data []byte) bool) error {
	db.mu.RLock()
	defer db.mu.RUnlock()

	db.tree.dbMu.RLock()
	keys := make([]string, 0, len(db.tree.db))
	for hashKey := range db.tree.db {
		keys = append(keys, hashKey)
	}
	db.tree.dbMu.RUnlock()

	for _, hashKey := range keys {
		node := db.tree.getNode(types.BytesToHash([]byte(hashKey)))
		if node == nil {
			continue
		}
		if leaf, ok := node.(*LeafNode); ok {
			if len(leaf.Key) == 32 {
				var addr types.Address
				copy(addr[:], leaf.Key[12:])
				if !fn(addr, leaf.Value) {
					break
				}
			}
		}
	}
	return nil
}

func (db *VerkleStateDB) IterateStorage(addr types.Address, fn func(slot types.Hash, value []byte) bool) error {
	db.mu.RLock()
	defer db.mu.RUnlock()

	storageKey := string(addr[:])
	storageTree, ok := db.storage[storageKey]
	if !ok {
		return nil
	}

	storageTree.dbMu.RLock()
	keys := make([]string, 0, len(storageTree.db))
	for hashKey := range storageTree.db {
		keys = append(keys, hashKey)
	}
	storageTree.dbMu.RUnlock()

	for _, hashKey := range keys {
		node := storageTree.getNode(types.BytesToHash([]byte(hashKey)))
		if node == nil {
			continue
		}
		if leaf, ok := node.(*LeafNode); ok {
			var slot types.Hash
			copy(slot[:], leaf.Key)
			if !fn(slot, leaf.Value) {
				break
			}
		}
	}
	return nil
}

func (db *VerkleStateDB) Serialize() ([]byte, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// R37-FIX P2-STATE-01 (2026-07-30): Use the lock-free dumpLocked() here.
	// Calling Dump() while holding RLock would re-acquire RLock recursively,
	// which self-deadlocks as soon as a writer is queued on the RWMutex.
	dump := db.dumpLocked()

	buf := new(bytes.Buffer)

	rootBytes := db.tree.Root().Bytes()
	buf.Write(rootBytes)

	count := uint32(len(dump))
	if err := binary.Write(buf, binary.BigEndian, count); err != nil {
		return nil, err
	}

	for k, v := range dump {
		keyLen := uint32(len(k))
		valLen := uint32(len(v))
		binary.Write(buf, binary.BigEndian, keyLen)
		buf.Write([]byte(k))
		binary.Write(buf, binary.BigEndian, valLen)
		buf.Write(v)
	}

	return buf.Bytes(), nil
}

const (
	maxDeserializeEntries = 1000000
	maxDeserializeKeyLen  = 1024
	maxDeserializeValLen  = 1 << 24
)

func (db *VerkleStateDB) Deserialize(data []byte) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if len(data) < 32 {
		return fmt.Errorf("data too short for root hash")
	}

	var rootHash types.Hash
	copy(rootHash[:], data[:32])
	data = data[32:]

	buf := bytes.NewReader(data)

	var count uint32
	if err := binary.Read(buf, binary.BigEndian, &count); err != nil {
		return fmt.Errorf("failed to read count: %w", err)
	}
	if count > maxDeserializeEntries {
		return fmt.Errorf("too many entries in serialized data: %d", count)
	}

	dump := make(map[string][]byte, count)

	for i := uint32(0); i < count; i++ {
		var keyLen uint32
		if err := binary.Read(buf, binary.BigEndian, &keyLen); err != nil {
			return fmt.Errorf("failed to read key length: %w", err)
		}
		if keyLen > maxDeserializeKeyLen {
			return fmt.Errorf("key too long in serialized data: %d", keyLen)
		}

		key := make([]byte, keyLen)
		// AUDIT (2026) DATA-06 FIX: Use io.ReadFull instead of buf.Read
		// to prevent silent truncation. Read may return n < len(key) without
		// an error, leaving zero-padded data that corrupts the deserialized
		// state. ReadFull guarantees either a full read or an error.
		if _, err := io.ReadFull(buf, key); err != nil {
			return fmt.Errorf("failed to read key: %w", err)
		}

		var valLen uint32
		if err := binary.Read(buf, binary.BigEndian, &valLen); err != nil {
			return fmt.Errorf("failed to read value length: %w", err)
		}
		if valLen > maxDeserializeValLen {
			return fmt.Errorf("value too long in serialized data: %d", valLen)
		}

		value := make([]byte, valLen)
		// AUDIT (2026) DATA-06 FIX: Use io.ReadFull instead of buf.Read
		// to prevent silent truncation (same fix as for key above).
		if _, err := io.ReadFull(buf, value); err != nil {
			return fmt.Errorf("failed to read value: %w", err)
		}

		dump[string(key)] = value
	}

	if err := db.importLocked(dump); err != nil {
		return err
	}

	// AUDIT (2026) R4-DATA-07 FIX: Verify the embedded root hash against
	// the actual decoded root node. Previously, the root hash from the
	// serialized data (first 32 bytes) was trusted without verification and
	// assigned directly to db.tree.root. An attacker (or bit-flip corruption)
	// could inject any 32-byte value as the root, causing the tree to report
	// a root that doesn't match its actual content — enabling state-root
	// divergence if this path is used for snapshot sync or state export/import.
	//
	// Fix: after importing the flat node data, look up the root node by its
	// claimed hash and verify that the decoded node's hash matches. If the
	// lookup fails or the hash doesn't match, fail-closed with an error.
	if rootHash == (types.Hash{}) {
		// Empty tree: root is zero hash, no root node.
		db.tree.root = rootHash
		db.tree.rootNode = nil
		return nil
	}
	rootNode := db.tree.getNode(rootHash)
	if rootNode == nil {
		return fmt.Errorf("R4-DATA-07: root node not found for claimed root hash %x (data may be truncated or tampered)", rootHash)
	}
	if rootNode.Hash() != rootHash {
		return fmt.Errorf("R4-DATA-07: root hash mismatch — claimed %x but decoded node hash is %x (data may be tampered or corrupted)", rootHash, rootNode.Hash())
	}
	db.tree.root = rootHash
	db.tree.rootNode = rootNode

	return nil
}
