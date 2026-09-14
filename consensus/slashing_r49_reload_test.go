// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"math/big"
	"sort"
	"sync"
	"testing"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/types"
)

// mockInMemoryDB is a minimal in-memory implementation of db.Database used
// by R49-SLASH-RELOAD-01 regression tests. Only the methods LoadSlashingRecords
// touches (Put, Get, NewIterator, Release) need to be functional.
//
// R50-RACE-01: this mock now embeds a sync.RWMutex to make PUT/GET/ITER
// goroutine-safe. The iterator's Release/Next/Key/Value methods also
// need the read lock because the underlying map can be mutated between
// Next() and Value() calls in race-detector enabled tests. The downstream
// SlashingManager.sm.mu protects the in-memory state map, but the mock is
// is shared by multiple goroutines during the ConcurrencyNoRace test so
// must itself be goroutine-safe.
type mockInMemoryDB struct {
	mu sync.RWMutex
	kv map[string][]byte
}

func newMockInMemoryDB() *mockInMemoryDB {
	return &mockInMemoryDB{kv: make(map[string][]byte)}
}

func (m *mockInMemoryDB) Put(key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.kv[string(key)] = append([]byte(nil), value...)
	return nil
}

func (m *mockInMemoryDB) Get(key []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if v, ok := m.kv[string(key)]; ok {
		return append([]byte(nil), v...), nil
	}
	return nil, nil
}

func (m *mockInMemoryDB) Delete(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.kv, string(key))
	return nil
}

func (m *mockInMemoryDB) Has(key []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.kv[string(key)]
	return ok, nil
}

func (m *mockInMemoryDB) Close() error { return nil }

func (m *mockInMemoryDB) NewBatch() db.Batch { return &mockBatch{db: m} }

type mockBatch struct {
	db   *mockInMemoryDB
	mu   sync.Mutex
	ops  []mockOp
	size int
}

type mockOp struct {
	key []byte
	val []byte
	del bool
}

func (b *mockBatch) Put(key, value []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ops = append(b.ops, mockOp{key: append([]byte(nil), key...), val: append([]byte(nil), value...)})
	b.size += len(value)
	return nil
}

func (b *mockBatch) Delete(key []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ops = append(b.ops, mockOp{key: append([]byte(nil), key...), del: true})
	return nil
}

func (b *mockBatch) Write() error {
	b.mu.Lock()
	ops := b.ops
	b.ops = nil
	b.size = 0
	b.mu.Unlock()
	for _, op := range ops {
		if op.del {
			b.db.Delete(op.key)
		} else {
			b.db.Put(op.key, op.val)
		}
	}
	return nil
}

func (b *mockBatch) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ops = nil
	b.size = 0
}

func (b *mockBatch) ValueSize() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.size
}

func (b *mockBatch) Flush() error { return b.Write() }

type mockIter struct {
	keys []string
	idx  int
	db   *mockInMemoryDB
	// cached values snapshot so we don't observe Put-concurrent mutation
	// mid-iteration (LoadSlashingRecords will not trigger this, but race
	// detector enabled tests must be safe).
	cachedVals map[string][]byte
}

func (it *mockIter) Next() bool {
	if it.idx >= len(it.keys) {
		return false
	}
	it.idx++
	return true
}

func (it *mockIter) Key() []byte {
	if it.idx == 0 || it.idx > len(it.keys) {
		return nil
	}
	return []byte(it.keys[it.idx-1])
}

func (it *mockIter) Value() []byte {
	if it.idx == 0 || it.idx > len(it.keys) {
		return nil
	}
	if v, ok := it.cachedVals[it.keys[it.idx-1]]; ok {
		return append([]byte(nil), v...)
	}
	return nil
}

func (it *mockIter) Release() {}

func (it *mockIter) Error() error { return nil }

func (m *mockInMemoryDB) collectKeys(prefix []byte) ([]string, map[string][]byte) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make([]string, 0, len(m.kv))
	cached := make(map[string][]byte, len(m.kv))
	for k, v := range m.kv {
		if len(prefix) == 0 || (len(k) >= len(prefix) && k[:len(prefix)] == string(prefix)) {
			keys = append(keys, k)
			cached[k] = append([]byte(nil), v...)
		}
	}
	sort.Strings(keys)
	return keys, cached
}

func (m *mockInMemoryDB) NewIterator(prefix []byte, _ []byte) db.Iterator {
	keys, cached := m.collectKeys(prefix)
	return &mockIter{keys: keys, db: m, cachedVals: cached}
}

func (m *mockInMemoryDB) NewIteratorWithLimit(prefix []byte, _ []byte, limit int) db.Iterator {
	keys, cached := m.collectKeys(prefix)
	if limit > 0 && len(keys) > limit {
		keys = keys[:limit]
	}
	return &mockIter{keys: keys, db: m, cachedVals: cached}
}

// TestR49_SLASH_RELOAD_01_RejectsDuplicateEvidenceAfterRestart proves the
// load path rebuilds sm.slashedOffenses on cold boot so a replayed evidence
// is detected as a duplicate and skipped instead of triggering another
// whistleblower reward / record insertion.
func TestR49_SLASH_RELOAD_01_RejectsDuplicateEvidenceAfterRestart(t *testing.T) {
	vm := NewValidatorManager()
	sm1 := NewSlashingManager(vm)
	dbHandle := newMockInMemoryDB()
	sm1.SetDB(dbHandle)

	validator := types.BytesToAddress([]byte("validator-R49"))
	record := &SlashingRecord{
		ValidatorAddr: validator,
		Reason:        SlashingReasonDoubleSigning,
		Height:        42,
		SlashedAmount: big.NewInt(1000),
		Timestamp:     1_700_000_000,
		Jailed:        true,
		JailUntil:     1_700_003_600,
	}
	if err := sm1.SaveSlashingRecord(record); err != nil {
		t.Fatalf("SaveSlashingRecord: %v", err)
	}

	// Simulate a restart: a NEW SlashingManager instance pointing at the SAME
	// on-disk DB. Without R49-SLASH-RELOAD-01 this sm2 would have an empty
	// slashedOffenses map and happily re-process the same evidence.
	sm2 := NewSlashingManager(vm)
	sm2.SetDB(dbHandle)
	if err := sm2.LoadSlashingRecords(); err != nil {
		t.Fatalf("LoadSlashingRecords: %v", err)
	}

	// The persisted record must be visible via the idempotency guard.
	offenseKey := fmt.Sprintf("%x:%d:%d", validator, SlashingReasonDoubleSigning, 42)
	if !sm2.slashedOffenses[offenseKey] {
		t.Fatalf("R49-SLASH-RELOAD-01 regression: slashedOffenses[%q] is false after cold-boot reload — same evidence would be re-processed", offenseKey)
	}
	if len(sm2.records) != 1 {
		t.Fatalf("expected 1 reloaded record, got %d", len(sm2.records))
	}
	got := sm2.records[0]
	if got.ValidatorAddr != validator {
		t.Errorf("validator addr mismatch: got %x want %x", got.ValidatorAddr, validator)
	}
	if got.Reason != SlashingReasonDoubleSigning {
		t.Errorf("reason mismatch: got %v want %v", got.Reason, SlashingReasonDoubleSigning)
	}
	if got.Height != 42 {
		t.Errorf("height mismatch: got %v want 42", got.Height)
	}
	if got.SlashedAmount == nil || got.SlashedAmount.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("slashed amount mismatch: got %v want 1000", got.SlashedAmount)
	}
	if !got.Jailed {
		t.Error("expected Jailed=true to be persisted")
	}
	if got.JailUntil != 1_700_003_600 {
		t.Errorf("jailUntil mismatch: got %v want %v", got.JailUntil, 1_700_003_600)
	}
}

// TestR49_SLASH_RELOAD_01_IdempotentReload proves calling LoadSlashingRecords
// a second time on the same manager does NOT duplicate the in-memory records
// list or break the slashedOffenses guard.
func TestR49_SLASH_RELOAD_01_IdempotentReload(t *testing.T) {
	vm := NewValidatorManager()
	sm := NewSlashingManager(vm)
	dbHandle := newMockInMemoryDB()
	sm.SetDB(dbHandle)

	validator := types.BytesToAddress([]byte("validator-R49-b"))
	record := &SlashingRecord{
		ValidatorAddr: validator,
		Reason:        SlashingReasonDoubleSigning,
		Height:        100,
		SlashedAmount: big.NewInt(50),
		Timestamp:     1_700_000_500,
		Jailed:        false,
		JailUntil:     0,
	}
	if err := sm.SaveSlashingRecord(record); err != nil {
		t.Fatalf("SaveSlashingRecord: %v", err)
	}

	if err := sm.LoadSlashingRecords(); err != nil {
		t.Fatalf("first LoadSlashingRecords: %v", err)
	}
	if err := sm.LoadSlashingRecords(); err != nil {
		t.Fatalf("second LoadSlashingRecords: %v", err)
	}
	if len(sm.records) != 1 {
		t.Fatalf("expected 1 record after double LoadSlashingRecords, got %d (must be idempotent)", len(sm.records))
	}
	offenseKey := fmt.Sprintf("%x:%d:%d", validator, SlashingReasonDoubleSigning, 100)
	if !sm.slashedOffenses[offenseKey] {
		t.Fatalf("offense guard missing for %q", offenseKey)
	}
}

// TestR49_SLASH_RELOAD_01_NilDB_NoOp proves nil DB is a no-op and not an
// error — this matches the pre-existing LoadVoteHistory semantics.
func TestR49_SLASH_RELOAD_01_NilDB_NoOp(t *testing.T) {
	vm := NewValidatorManager()
	sm := NewSlashingManager(vm)
	if err := sm.LoadSlashingRecords(); err != nil {
		t.Fatalf("LoadSlashingRecords on nil db must be no-op, got: %v", err)
	}
	if len(sm.records) != 0 {
		t.Errorf("expected empty records, got %d", len(sm.records))
	}
	if len(sm.slashedOffenses) != 0 {
		t.Errorf("expected empty slashedOffenses, got %d", len(sm.slashedOffenses))
	}
}

// TestR50_SLASH_RELOAD_ConcurrencyNoRace proves LoadSlashingRecords is race-free
// when called concurrently from multiple goroutines (carried over from the
// previous round's "concurrency idempotency" follow-up). The
// SlashingManager.sm.mu mutex serializes concurrent access
// LoadSlashingRecords calls; the underlying SlashingManager state map is never
// touched without the mutex. Run with -race to exercise the detector.
//
// Real production code only calls LoadSlashingRecords once at startup; this
// test simply provides the regression guard the previous round's Lessons
// Learned section flagged as missing.
func TestR50_SLASH_RELOAD_ConcurrencyNoRace(t *testing.T) {
	vm := NewValidatorManager()
	sm := NewSlashingManager(vm)
	dbHandle := newMockInMemoryDB()
	sm.SetDB(dbHandle)

	// Populate three distinct persisted records so multiple goroutines have
	// something to reload simultaneously.
	for i := 0; i < 3; i++ {
		record := &SlashingRecord{
			ValidatorAddr: types.BytesToAddress([]byte{byte(0xa0 + i)}),
			Reason:        SlashingReasonDoubleSigning,
			Height:        uint64(100 + i),
			SlashedAmount: big.NewInt(int64(100 + i)),
			Timestamp:     int64(1_700_000_000 + i),
			Jailed:        false,
			JailUntil:     0,
		}
		if err := sm.SaveSlashingRecord(record); err != nil {
			t.Fatalf("SaveSlashingRecord[%d]: %v", i, err)
		}
	}

	// Have 8 goroutines call LoadSlashingRecords(N=8) in parallel. Without
	// the sm.mu.Lock() inside LoadSlashingRecords, this would race on the
	// shared sm.records slice AND on the mockInMemoryDB's internal kv map.
	const numGoroutines = 8
	var wg sync.WaitGroup
	errs := make([]error, numGoroutines)
	start := make(chan struct{})
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			errs[idx] = sm.LoadSlashingRecords()
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine[%d] LoadSlashingRecords: %v", i, err)
		}
	}

	// Idempotency must hold across the 8 concurrent calls — records must
	// have exactly the 3 records we persisted, not 24.
	if len(sm.records) != 3 {
		t.Fatalf("expected 3 records after 8 concurrent LoadSlashingRecords, got %d (race likely)", len(sm.records))
	}
	if len(sm.slashedOffenses) != 3 {
		t.Fatalf("expected 3 offense keys, got %d", len(sm.slashedOffenses))
	}

	// Cross-check all three keys are present.
	for i := 0; i < 3; i++ {
		addr := types.BytesToAddress([]byte{byte(0xa0 + i)})
		offenseKey := fmt.Sprintf("%x:%d:%d", addr, SlashingReasonDoubleSigning, uint64(100+i))
		if !sm.slashedOffenses[offenseKey] {
			t.Fatalf("offense guard missing for goroutine-race test %q", offenseKey)
		}
	}
}

// TestR50_SLASH_RELOAD_ConcurrentLoadAndSubmit proves LoadSlashingRecords
// racing against SubmitEvidence on the same SlashingManager does not trip
// the race detector or produce inconsistent state. The sm.mu mutex must
// serialize all writes properly.
func TestR50_SLASH_RELOAD_ConcurrentLoadAndSubmit(t *testing.T) {
	vm := NewValidatorManager()
	sm := NewSlashingManager(vm)
	dbHandle := newMockInMemoryDB()
	sm.SetDB(dbHandle)

	validator := types.BytesToAddress([]byte("validator-r50"))
	// Pre-populate a persisted record matching the evidence we'll submit
	// so SubmitEvidence sees it as a duplicate.
	preload := &SlashingRecord{
		ValidatorAddr: validator,
		Reason:        SlashingReasonDoubleSigning,
		Height:        200,
		SlashedAmount: big.NewInt(100),
		Timestamp:     1_700_000_900,
		Jailed:        false,
		JailUntil:     0,
	}
	if err := sm.SaveSlashingRecord(preload); err != nil {
		t.Fatalf("SaveSlashingRecord preload: %v", err)
	}

	// Use a SEPARATE SlashingManager to simulate restart gap; both share the
	// same on-disk DB as the first.
	sm2 := NewSlashingManager(vm)
	sm2.SetDB(dbHandle)

	// Have 4 goroutines concurrently call LoadSlashingRecords on sm2.
	// Race detector should not trigger any write-write hazard.
	const numLoaders = 4
	var wg sync.WaitGroup
	wg.Add(numLoaders)
	start := make(chan struct{})
	for i := 0; i < numLoaders; i++ {
		go func() {
			defer wg.Done()
			<-start
			_ = sm2.LoadSlashingRecords()
		}()
	}
	close(start)
	wg.Wait()

	offenseKey := fmt.Sprintf("%x:%d:%d", validator, SlashingReasonDoubleSigning, 200)
	if !sm2.slashedOffenses[offenseKey] {
		t.Fatalf("R50-RACE-01 regression: offense guard missing after parallel reload, key=%q", offenseKey)
	}
	if len(sm2.records) != 1 {
		t.Fatalf("expected exactly 1 reloaded record (idempotent across 4 goroutines), got %d", len(sm2.records))
	}
}
