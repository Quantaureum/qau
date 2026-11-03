// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quantaureum/qau/common/lru"
	"github.com/quantaureum/qau/types"
)

// fakeRandomnessSource is a deterministic RandomnessSource for handler tests.
type fakeRandomnessSource struct {
	finalized   uint64
	hasFinality bool
	records     map[uint64]RandomnessRecord
	unavailable map[uint64]bool // epochs that return a not-available error
	fetches     map[uint64]int  // EpochRandomness call count per epoch
}

func (f *fakeRandomnessSource) LatestFinalizedEpoch() (uint64, bool) {
	return f.finalized, f.hasFinality
}

func (f *fakeRandomnessSource) EpochRandomness(epoch uint64) (RandomnessRecord, error) {
	if f.fetches != nil {
		f.fetches[epoch]++
	}
	if f.unavailable[epoch] {
		return RandomnessRecord{}, &testUnavailableError{}
	}
	rec, ok := f.records[epoch]
	if !ok {
		return RandomnessRecord{}, &testUnavailableError{}
	}
	return rec, nil
}

// testUnavailableError mirrors the adapter's "boundary block not found" error.
type testUnavailableError struct{}

func (e *testUnavailableError) Error() string { return "epoch randomness not available" }

func newFakeRandomnessSource() *fakeRandomnessSource {
	return &fakeRandomnessSource{
		finalized:   10,
		hasFinality: true,
		records: map[uint64]RandomnessRecord{
			10: {
				Epoch:         10,
				Accumulator:   types.Hash{0xaa, 0xbb},
				BoundaryBlock: 10*32 + 31,
				BlockHash:     types.Hash{0x01},
			},
			11: {
				Epoch:         11,
				Accumulator:   types.Hash{0xcc, 0xdd},
				BoundaryBlock: 11*32 + 31,
				BlockHash:     types.Hash{0x02},
			},
		},
		unavailable: map[uint64]bool{99: true},
		fetches:     map[uint64]int{},
	}
}

// TestRandomnessLatestHappyPath verifies qau_randomnessLatest returns the
// finalized epoch's record with finalized=true.
func TestRandomnessLatestHappyPath(t *testing.T) {
	api := NewRandomnessAPI(newFakeRandomnessSource())
	resp, rerr := api.GetLatest(context.Background(), nil)
	if rerr != nil {
		t.Fatalf("unexpected error: %v", rerr)
	}
	m, ok := resp.(map[string]any)
	if !ok {
		t.Fatalf("expected map response, got %T", resp)
	}
	if m["epoch"] != uint64(10) {
		t.Errorf("epoch = %v, want 10", m["epoch"])
	}
	if m["finalized"] != true {
		t.Errorf("finalized = %v, want true", m["finalized"])
	}
	wantRandomness := formatHashHex(types.Hash{0xaa, 0xbb})
	if m["randomness"] != wantRandomness {
		t.Errorf("randomness = %v, want %s", m["randomness"], wantRandomness)
	}
	if m["boundaryBlock"] != formatHex(10*32+31) {
		t.Errorf("boundaryBlock = %v, want %s", m["boundaryBlock"], formatHex(10*32+31))
	}
	if m["blockHash"] != formatHashHex(types.Hash{0x01}) {
		t.Errorf("blockHash = %v", m["blockHash"])
	}
	if m["source"] != "vrf-accumulator" {
		t.Errorf("source = %v, want vrf-accumulator", m["source"])
	}
}

// TestRandomnessLatestNoFinality verifies the pre-finality bootstrap window
// returns -32000 instead of serving an unfinalized value as final.
func TestRandomnessLatestNoFinality(t *testing.T) {
	src := newFakeRandomnessSource()
	src.hasFinality = false
	api := NewRandomnessAPI(src)
	_, rerr := api.GetLatest(context.Background(), nil)
	if rerr == nil {
		t.Fatal("expected error before first finalization, got nil")
	}
	if rerr.Code != -32000 {
		t.Errorf("code = %d, want -32000", rerr.Code)
	}
}

// TestRandomnessNilSource verifies both methods return -32601 when the
// backing source is unavailable (consistent with the optional-subsystem
// APIs like quantum_api.go).
func TestRandomnessNilSource(t *testing.T) {
	api := NewRandomnessAPI(nil)
	if _, rerr := api.GetLatest(context.Background(), nil); rerr == nil || rerr.Code != -32601 {
		t.Errorf("GetLatest: expected -32601, got %v", rerr)
	}
	if _, rerr := api.Get(context.Background(), json.RawMessage(`{"epoch":1}`)); rerr == nil || rerr.Code != -32601 {
		t.Errorf("Get: expected -32601, got %v", rerr)
	}
}

// TestRandomnessGetFinalityFlag verifies qau_randomnessGet marks finalized
// epochs and serves sealed-but-unfinalized epochs with finalized=false.
func TestRandomnessGetFinalityFlag(t *testing.T) {
	api := NewRandomnessAPI(newFakeRandomnessSource())

	// Finalized epoch.
	resp, rerr := api.Get(context.Background(), json.RawMessage(`{"epoch":10}`))
	if rerr != nil {
		t.Fatalf("unexpected error: %v", rerr)
	}
	if m := resp.(map[string]any); m["finalized"] != true {
		t.Errorf("finalized epoch 10: finalized = %v, want true", m["finalized"])
	}

	// Sealed but not yet finalized epoch.
	resp, rerr = api.Get(context.Background(), json.RawMessage(`{"epoch":11}`))
	if rerr != nil {
		t.Fatalf("unexpected error: %v", rerr)
	}
	m := resp.(map[string]any)
	if m["finalized"] != false {
		t.Errorf("pending epoch 11: finalized = %v, want false", m["finalized"])
	}
	if m["randomness"] != formatHashHex(types.Hash{0xcc, 0xdd}) {
		t.Errorf("pending epoch 11: randomness = %v", m["randomness"])
	}

	// Numeric-string epoch form must be accepted too.
	if _, rerr = api.Get(context.Background(), json.RawMessage(`{"epoch":"10"}`)); rerr != nil {
		t.Errorf("string epoch form rejected: %v", rerr)
	}
}

// TestRandomnessGetUnavailable verifies an epoch whose boundary block is not
// on this node returns -32000 with a descriptive message.
func TestRandomnessGetUnavailable(t *testing.T) {
	api := NewRandomnessAPI(newFakeRandomnessSource())
	_, rerr := api.Get(context.Background(), json.RawMessage(`{"epoch":99}`))
	if rerr == nil || rerr.Code != -32000 {
		t.Fatalf("expected -32000, got %v", rerr)
	}
	if !strings.Contains(rerr.Message, "not available") {
		t.Errorf("message = %q, want it to describe unavailability", rerr.Message)
	}
}

// TestRandomnessGetInvalidParams verifies malformed epoch params return
// -32602 (missing, non-numeric, fractional, negative, and uint64 overflow).
func TestRandomnessGetInvalidParams(t *testing.T) {
	api := NewRandomnessAPI(newFakeRandomnessSource())
	cases := []string{
		`{}`,
		`null`,
		`{"epoch":"abc"}`,
		`{"epoch":-1}`,
		`{"epoch":1.5}`,
		`{"epoch":99999999999999999999999}`,
		`{"epoch":[]}`,
	}
	for _, tc := range cases {
		if _, rerr := api.Get(context.Background(), json.RawMessage(tc)); rerr == nil || rerr.Code != -32602 {
			t.Errorf("params %s: expected -32602, got %v", tc, rerr)
		}
	}
}

// TestRandomnessMethodsPublicAndNotAdmin verifies the allowlist and admin
// registration state: both methods must be public (no API key needed) and
// must NOT be admin-gated.
func TestRandomnessMethodsPublicAndNotAdmin(t *testing.T) {
	am := NewAuthManager(DefaultAuthConfig())
	for _, method := range []string{"qau_randomnessLatest", "qau_randomnessGet"} {
		if !am.IsPublicMethod(method) {
			t.Errorf("%s should be in the public allowlist", method)
		}
	}

	srv := NewServer(nil)
	NewRandomnessAPI(nil).RegisterHandlers(srv)
	for _, method := range []string{"qau_randomnessLatest", "qau_randomnessGet"} {
		if _, ok := srv.handlers[method]; !ok {
			t.Errorf("%s handler not registered", method)
		}
		if srv.isAdminMethod(method) {
			t.Errorf("%s must not be an admin method", method)
		}
	}
}

// newRandomnessAPIWithCacheSize is the test seam for cache-size-dependent
// behavior (production uses randomnessCacheSize).
func newRandomnessAPIWithCacheSize(source RandomnessSource, size int) *RandomnessAPI {
	api := NewRandomnessAPI(source)
	api.cache = lru.New[uint64, RandomnessRecord](size)
	return api
}

// TestRandomnessCacheServesFinalizedOnce verifies finalized epochs hit the
// cache: the backing source is consulted exactly once across repeats of
// both qau_randomnessGet and qau_randomnessLatest.
func TestRandomnessCacheServesFinalizedOnce(t *testing.T) {
	src := newFakeRandomnessSource()
	api := newRandomnessAPIWithCacheSize(src, 8)

	for i := 0; i < 3; i++ {
		if _, rerr := api.Get(context.Background(), json.RawMessage(`{"epoch":10}`)); rerr != nil {
			t.Fatalf("Get: %v", rerr)
		}
		if _, rerr := api.GetLatest(context.Background(), nil); rerr != nil {
			t.Fatalf("GetLatest: %v", rerr)
		}
	}
	if got := src.fetches[10]; got != 1 {
		t.Errorf("finalized epoch fetched %d times, want 1 (cache must serve repeats)", got)
	}
}

// TestRandomnessCacheSkipsPending verifies pending epochs are never cached:
// their randomness can still change until finality, so every read must go
// to the source.
func TestRandomnessCacheSkipsPending(t *testing.T) {
	src := newFakeRandomnessSource()
	src.hasFinality = false // epoch 11 pending
	api := newRandomnessAPIWithCacheSize(src, 8)

	for i := 0; i < 3; i++ {
		resp, rerr := api.Get(context.Background(), json.RawMessage(`{"epoch":11}`))
		if rerr != nil {
			t.Fatalf("Get: %v", rerr)
		}
		if m := resp.(map[string]any); m["finalized"] != false {
			t.Fatalf("pending epoch served as finalized")
		}
	}
	if got := src.fetches[11]; got != 3 {
		t.Errorf("pending epoch fetched %d times, want 3 (must not be cached)", got)
	}
}

// TestRandomnessCacheEviction verifies the LRU bound: after capacity is
// exceeded, evicted epochs are re-fetched from the source.
func TestRandomnessCacheEviction(t *testing.T) {
	src := newFakeRandomnessSource()
	for e := uint64(0); e < 5; e++ {
		src.records[e] = RandomnessRecord{Epoch: e, Accumulator: types.Hash{byte(e)}}
	}
	src.finalized = 4
	api := newRandomnessAPIWithCacheSize(src, 2)

	for _, e := range []uint64{0, 1, 2, 3, 4} {
		if _, rerr := api.Get(context.Background(), json.RawMessage(`{"epoch":`+strconv.FormatUint(e, 10)+`}`)); rerr != nil {
			t.Fatalf("Get(%d): %v", e, rerr)
		}
	}
	if api.cache.Len() != 2 {
		t.Errorf("cache Len = %d, want 2 (capacity bound)", api.cache.Len())
	}
	// Epoch 0 was evicted; a re-read must hit the source again.
	if _, rerr := api.Get(context.Background(), json.RawMessage(`{"epoch":0}`)); rerr != nil {
		t.Fatalf("Get(0) after eviction: %v", rerr)
	}
	if got := src.fetches[0]; got != 2 {
		t.Errorf("evicted epoch fetched %d times, want 2", got)
	}
}

// TestRandomnessMetricsObserver verifies the per-method observer sees every
// request with the right method name and failure flag.
func TestRandomnessMetricsObserver(t *testing.T) {
	src := newFakeRandomnessSource()
	api := NewRandomnessAPI(src)
	var mu sync.Mutex
	type observation struct {
		method string
		failed bool
	}
	var seen []observation
	api.SetMetricsObserver(func(method string, _ time.Duration, failed bool) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, observation{method, failed})
	})

	if _, rerr := api.Get(context.Background(), json.RawMessage(`{"epoch":10}`)); rerr != nil {
		t.Fatalf("Get: %v", rerr)
	}
	if _, rerr := api.GetLatest(context.Background(), nil); rerr != nil {
		t.Fatalf("GetLatest: %v", rerr)
	}
	if _, rerr := api.Get(context.Background(), json.RawMessage(`{"epoch":99}`)); rerr == nil {
		t.Fatal("expected error for unavailable epoch")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 {
		t.Fatalf("observer saw %d calls, want 3", len(seen))
	}
	if seen[0].method != "qau_randomnessGet" || seen[0].failed {
		t.Errorf("first observation = %+v, want qau_randomnessGet success", seen[0])
	}
	if seen[1].method != "qau_randomnessLatest" || seen[1].failed {
		t.Errorf("second observation = %+v, want qau_randomnessLatest success", seen[1])
	}
	if seen[2].method != "qau_randomnessGet" || !seen[2].failed {
		t.Errorf("third observation = %+v, want qau_randomnessGet failure", seen[2])
	}
}
