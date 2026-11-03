// Quantaureum Node source, version 1.0.0.
// Package rpc implements the JSON-RPC 2.0 server for Quantaureum.
// This file exposes the per-epoch VRF accumulator — the chain's post-quantum
// verifiable randomness — via read-only RPC methods.
//
// Provenance and honesty note: the randomness served here is the per-epoch
// VRF accumulator recorded on epoch boundary block headers
// (encoding.Header.VRFAccumulator, produced by consensus.ComputeNextVRFAccumulator
// and validated by core on every import). It is NOT a hardware quantum random
// number generator and no such claim is made. Its guarantees are: unbiasability
// through post-quantum VRF outputs folded into every block, finality binding
// (only finalized epochs are irreversible), and public verifiability — any
// client can recompute the accumulator chain from block headers alone. These
// RPC methods only repackage data that is already public on chain.

package rpc

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/quantaureum/qau/common/lru"
	"github.com/quantaureum/qau/metrics"
	"github.com/quantaureum/qau/types"
)

// randomnessCacheSize bounds the finalized-epoch record cache. Finalized
// accumulators are immutable, so entries never go stale; the bound exists to
// cap memory against hostile epoch-range scanning.
const randomnessCacheSize = 1024

// MetricsObserver receives one call per served randomness request. method is
// the RPC method name, latency the handler wall time, failed whether the
// handler returned an error. Implementations must be concurrency-safe; nil
// disables per-method metrics (aggregate metrics still apply).
type MetricsObserver func(method string, latency time.Duration, failed bool)

// RandomnessRecord is one epoch's verifiable randomness as read from the
// canonical chain.
type RandomnessRecord struct {
	// Epoch is the epoch the randomness belongs to.
	Epoch uint64
	// Accumulator is the complete VRF accumulator recorded on the epoch
	// boundary block header. This is the canonical randomness value.
	Accumulator types.Hash
	// BoundaryBlock is the height of the epoch's boundary (last) block, whose
	// header carries Accumulator.
	BoundaryBlock uint64
	// BlockHash is the hash of BoundaryBlock.
	BlockHash types.Hash
}

// RandomnessSource is the narrow read-only interface the randomness RPC needs
// from the node layer. It is implemented by the node package
// (randomnessSourceAdapter) and kept as an interface so this package stays
// decoupled from the concrete block store and consensus state.
type RandomnessSource interface {
	// LatestFinalizedEpoch returns the highest finalized (irreversible) epoch.
	// ok is false before any epoch has been finalized.
	LatestFinalizedEpoch() (uint64, bool)
	// EpochRandomness returns the randomness recorded on the boundary block of
	// the given epoch. An error means the boundary block is not (yet)
	// available on this node.
	EpochRandomness(epoch uint64) (RandomnessRecord, error)
}

// RandomnessAPI exposes per-epoch verifiable randomness via JSON-RPC:
//   - qau_randomnessLatest: randomness of the highest finalized epoch
//   - qau_randomnessGet:    randomness of a specific epoch
type RandomnessAPI struct {
	source  RandomnessSource
	cache   *lru.Cache[uint64, RandomnessRecord]
	observe MetricsObserver
}

// NewRandomnessAPI creates a RandomnessAPI. source may be nil; the methods
// then return -32601, consistent with the other optional subsystem APIs.
func NewRandomnessAPI(source RandomnessSource) *RandomnessAPI {
	return &RandomnessAPI{
		source: source,
		cache:  lru.New[uint64, RandomnessRecord](randomnessCacheSize),
	}
}

// SetMetricsObserver wires an optional per-method metrics observer. Only
// successful finalized-epoch responses are cached; metrics observe every call.
func (api *RandomnessAPI) SetMetricsObserver(fn MetricsObserver) {
	api.observe = fn
}

// RegisterHandlers registers the randomness API handlers on the server.
// Both methods are read-only and are listed in the public allowlist
// (PublicMethods in auth.go).
func (api *RandomnessAPI) RegisterHandlers(server *Server) {
	server.RegisterHandler("qau_randomnessLatest", api.GetLatest)
	server.RegisterHandler("qau_randomnessGet", api.Get)
}

// randomnessResponse is the wire format shared by both methods. epoch is a
// decimal JSON number; boundaryBlock and blockHash are 0x-prefixed hex so
// they interoperate with the eth_* conventions (eth_getBlockByNumber takes
// the hex height, eth_getBlockByHash the hash).
func randomnessResponse(rec RandomnessRecord, finalized bool) map[string]any {
	return map[string]any{
		"epoch":         rec.Epoch,
		"randomness":    formatHashHex(rec.Accumulator),
		"boundaryBlock": formatHex(rec.BoundaryBlock),
		"blockHash":     formatHashHex(rec.BlockHash),
		"finalized":     finalized,
		"source":        "vrf-accumulator",
	}
}

// GetLatest returns the verifiable randomness of the highest finalized epoch.
// RPC: qau_randomnessLatest (public, read-only)
//
// Only finalized epochs are served here: their randomness is irreversible.
// Until the first epoch finalization this returns -32000. The "epoch 0 is
// not treated as finalized" policy mirrors the eth_getBlockByNumber
// "finalized" tag (see GetBlockByNumber).
func (api *RandomnessAPI) GetLatest(ctx context.Context, params json.RawMessage) (any, *Error) {
	started := time.Now()
	resp, rerr := api.getLatest(ctx)
	api.record("qau_randomnessLatest", started, rerr)
	return resp, rerr
}

func (api *RandomnessAPI) getLatest(ctx context.Context) (any, *Error) {
	if api.source == nil {
		return nil, &Error{Code: -32601, Message: "randomness source not available"}
	}
	epoch, ok := api.source.LatestFinalizedEpoch()
	if !ok {
		return nil, &Error{Code: -32000, Message: "no finalized epoch yet"}
	}
	// The finalized epoch is immutable by definition, so the cache fast path
	// always applies here.
	if rec, cached := api.cache.Get(epoch); cached {
		return randomnessResponse(rec, true), nil
	}
	rec, err := api.source.EpochRandomness(epoch)
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}
	api.cache.Put(epoch, rec)
	return randomnessResponse(rec, true), nil
}

// Get returns the verifiable randomness of a specific epoch.
// RPC: qau_randomnessGet (public, read-only)
// Params: {"epoch": <uint64>} — a decimal number or a numeric string.
//
// The response carries finalized=true only when the epoch is finalized; a
// sealed but not-yet-finalized epoch is served with finalized=false and its
// randomness may still change on a reorg until finality. Only finalized
// records enter the cache.
func (api *RandomnessAPI) Get(ctx context.Context, params json.RawMessage) (any, *Error) {
	started := time.Now()
	resp, rerr := api.get(ctx, params)
	api.record("qau_randomnessGet", started, rerr)
	return resp, rerr
}

func (api *RandomnessAPI) get(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.source == nil {
		return nil, &Error{Code: -32601, Message: "randomness source not available"}
	}
	unwrapped, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}
	var req struct {
		Epoch json.Number `json:"epoch"`
	}
	if err := json.Unmarshal(unwrapped, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}
	if req.Epoch == "" {
		return nil, &Error{Code: -32602, Message: "invalid params: epoch is required"}
	}
	epoch, err := strconv.ParseUint(req.Epoch.String(), 10, 64)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: epoch must be a uint64"}
	}
	// Cached entries were only stored once finalized, so a hit is immutable.
	if rec, cached := api.cache.Get(epoch); cached {
		return randomnessResponse(rec, true), nil
	}
	// QR-01 (R2 audit): resolve finality BEFORE taking the record — the same
	// order as getLatest. The previous order (fetch, then check finality)
	// left a race window: the fetch could observe a pre-reorg boundary block
	// while the epoch was still unfinalized, finality could then be observed
	// only after a reorg + re-finalization, and the stale record would be
	// cached forever (cache entries are trusted as immutable). Observing
	// finality first pins the epoch as irreversible before the read, so a
	// record fetched on the finalized path is necessarily the canonical one.
	fe, ok := api.source.LatestFinalizedEpoch()
	if ok && epoch <= fe {
		rec, err := api.source.EpochRandomness(epoch)
		if err != nil {
			return nil, &Error{Code: -32000, Message: err.Error()}
		}
		api.cache.Put(epoch, rec)
		return randomnessResponse(rec, true), nil
	}
	// Not finalized (or finality not yet observed): serve the current record
	// without caching — it may still change on a reorg. Response semantics
	// are unchanged: a sealed-but-unfinalized epoch is served with
	// finalized=false, and an unsealed one still returns -32000.
	rec, err := api.source.EpochRandomness(epoch)
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}
	return randomnessResponse(rec, false), nil
}

// record reports request metrics: the process-wide aggregate (same counters
// the /metrics text endpoint renders) plus the optional per-method observer
// wired by the node (see SetMetricsObserver).
func (api *RandomnessAPI) record(method string, started time.Time, rerr *Error) {
	latency := time.Since(started)
	var err error
	if rerr != nil {
		err = rerr // *Error implements the error interface (server.go).
	}
	metrics.Global().RecordRPCRequest(latency, err)
	if api.observe != nil {
		api.observe(method, latency, rerr != nil)
	}
}
