// Quantaureum Node source, version 1.0.0.
package core

import (
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	logging "github.com/quantaureum/qau/log"
	"github.com/quantaureum/qau/types"
)

type DankshardingEngine struct {
	blobStorage     encoding.BlobStorageBackend
	dasClient       *encoding.DASClient
	networkManager  *encoding.BlobNetworkManager
	committeeMgr    *consensus.DACommitteeManager
	attestCollector *consensus.DAAttestationCollector
	subnetMgr       *consensus.DASubnetManager
	gc              *encoding.BlobGarbageCollector
	config          DankshardingConfig
	warnOnce        sync.Once

	// P1-6 (2026-07-14): P2P bridge functions for DAS sampling.
	// Injected via SetP2PBridge and wired to networkManager in Start().
	// When nil, DAS sampling can only use locally stored cells (no peer
	// requests), which is sufficient for single-node testing but not
	// for production multi-node DA verification.
	peerGetter func(peerID string, msgType uint8, data []byte) ([]byte, error)
	peerList   func() []string

	// P1-10 (2026-07-14): Per-slot sampling result cache. Multiple calls
	// to BuildDAAttestation for the same slot reuse the cached result,
	// avoiding redundant Sample() calls. Each slot entry uses sync.Once
	// to guarantee sampling is performed exactly once per slot.
	sampleCache sync.Map

	// R37-P3-32 FIX (2026-07-31): Serializes the NewSession / FRI-provider
	// / Sample / stats-read sequence on the DASClient. sampleCache is keyed
	// by (slot, commitmentsHash) but DASClient sessions are keyed by slot
	// only, so without this mutex two different commitment sets for the
	// same slot could overwrite each other's session mid-sampling and
	// pollute the cached results.
	sampleSessionMu sync.Mutex

	// P3-1 (2026-07-15): Optional DA metrics for observability. When set,
	// VerifyBlockDAAvailability updates the sampling_confidence gauge on
	// success and increments the sampling_failures_total counter on error.
	// Nil-safe: all DAMetrics helper methods early-return on nil receiver.
	metrics *consensus.DAMetrics

	// R7 P0-6 FIX (DA-, 2026-07-17): Per-slot FRI blob data cache.
	// When UseFRI=true, ProcessBlobsForBlock stores *encoding.FRIDABlobData
	// for each blob here (keyed by slot → []*FRIDABlobData). The DASClient
	// reads from this cache (via friDataProvider) to perform FRI-based cell
	// verification (FRIDAVerifyCell) instead of the hash stub.
	friBlobDataBySlot sync.Map

	// CONS-FIX (2026-07-17): Optional DA attestation signer. When
	// configured, BuildDAAttestation invokes this callback to attach a
	// Dilithium3 signature over attestation.Hash() using the validator's
	// private key. This binds the attestation to its ValidatorIndex so
	// SubmitAttestation's verifier (NewDAAttestationVerifier) can reject
	// forged attestations. When nil, Signature is left empty and the caller
	// is responsible for signing before submission (backward-compatible with
	// existing test helpers like signAndSubmit).
	daAttestationSigner func(att *encoding.DASAttestation) error

	mu sync.RWMutex
}

type DankshardingConfig struct {
	Enabled        bool
	Experimental   bool
	WarningMessage string
	// R7 P0-6 FIX (DA-, 2026-07-17): When true, ProcessBlobsForBlock
	// calls FRIDACommitBlob to compute a post-quantum FRI commitment for
	// each blob (stored in friBlobDataBySlot). DASClient.Sample then uses
	// FRIDAVerifyCell for cell verification when FRI data is locally
	// available. When false (default), the legacy Keccak256 hash stub
	// (KZGCommitmentFromBlob / VerifyCellProof) is used.
	//
	// Mainnet MUST keep Enabled=false (DA- hard protection in
	// Config.Validate + initDanksharding). UseFRI only takes effect on
	// testnet/devnet where danksharding is enabled.
	UseFRI bool
}

// daSampleSlot caches the DAS sampling result for a single slot.
// sync.Once guarantees Sample() is called exactly once per slot,
// even under concurrent access. P1-10 (2026-07-14).
type daSampleSlot struct {
	once   sync.Once
	result daSampleResult
}

type daSampleResult struct {
	available  bool
	confidence float64
	err        error
	// R37-P3-32 FIX (2026-07-31): Sample counters captured atomically with
	// the availability result under sampleSessionMu. BuildDAAttestation
	// reads them from this (slot, commitmentsHash)-keyed entry instead of
	// the slot-only DASClient session map, unifying the key dimensions.
	sampleTotal   int
	sampleSuccess int
}

// daSampleCacheKey is the composite key for sampleCache. Including the
// commitments hash (CONS-FIX) ensures that a fork switch to a
// different blob set for the same slot does not reuse a stale sample
// result computed on the pre-fork blobs.
type daSampleCacheKey struct {
	slot            uint64
	commitmentsHash types.Hash
}

// hashCommitments computes a SHA-256 digest over a commitment slice so it
// can be used as part of the sampleCache key. CONS-FIX.
func hashCommitments(commitments []encoding.KZGCommitment) types.Hash {
	h := sha256.New()
	for i := range commitments {
		h.Write(commitments[i][:])
	}
	var out types.Hash
	copy(out[:], h.Sum(nil))
	return out
}

func NewDankshardingEngine(
	blobStorage encoding.BlobStorageBackend,
	dasClient *encoding.DASClient,
	networkManager *encoding.BlobNetworkManager,
	committeeMgr *consensus.DACommitteeManager,
	attestCollector *consensus.DAAttestationCollector,
	subnetMgr *consensus.DASubnetManager,
	gc *encoding.BlobGarbageCollector,
	config DankshardingConfig,
) *DankshardingEngine {
	// R11-CORE-001 FIX: Validate required dependencies to prevent nil-pointer
	// panics later. blobStorage, dasClient, and attestCollector are used in
	// hot paths without nil guards.
	//
	// R36-P3-12 FIX (2026-07-30): Fail-closed in Start() instead of only
	// warning here. The previous behavior logged a warning and returned a
	// half-constructed engine whose hot paths (ProcessBlobs at line 352
	// calls e.blobStorage.StoreMatrix unconditionally;
	// VerifyBlockDAAvailability at line 405 calls e.dasClient.NewSession
	// unconditionally) would nil-deref on the first block with blobs. We
	// still record the misconfiguration here for visibility, but the
	// actual fail-closed gate is in Start() so existing callers that
	// ignore the constructor's return value (none do, but defensively)
	// still get a clean error instead of a runtime panic. DA is
	// hard-disabled on mainnet (config.Enabled=false) so production is
	// unaffected; this only catches test/dev misconfiguration earlier.
	if blobStorage == nil || dasClient == nil || attestCollector == nil {
		logging.Global().Error("DankshardingEngine created with nil critical dependency (blobStorage/dasClient/attestCollector) — Start() will fail-closed", nil)
	}
	if config.Experimental {
		msg := config.WarningMessage
		if msg == "" {
			msg = "Danksharding is EXPERIMENTAL - not production-ready, use at your own risk"
		}
		logging.Global().Warn(msg, nil)
	}

	return &DankshardingEngine{
		blobStorage:     blobStorage,
		dasClient:       dasClient,
		networkManager:  networkManager,
		committeeMgr:    committeeMgr,
		attestCollector: attestCollector,
		subnetMgr:       subnetMgr,
		gc:              gc,
		config:          config,
	}
}

// SetP2PBridge injects the P2P-backed peer getter and peer list functions.
// P1-6 (2026-07-14): These are wired to the BlobNetworkManager in Start()
// to enable cross-node DAS sampling. The node layer (P1-1) creates these
// closures using p2p.NewDASPeerGetter(host) and p2p.NewDASPeerList(host)
// and injects them here before calling Start().
func (e *DankshardingEngine) SetP2PBridge(
	peerGetter func(peerID string, msgType uint8, data []byte) ([]byte, error),
	peerList func() []string,
) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.peerGetter = peerGetter
	e.peerList = peerList
}

// SetDAMetrics injects the DA metrics collector. P3-1 (2026-07-15).
// When set, VerifyBlockDAAvailability updates the sampling_confidence gauge
// on success and increments the sampling_failures_total counter on error.
// CleanupOldData increments the gc_cycles_total counter on each manual GC.
// The BlobGarbageCollector's ticker callback also increments gc_cycles_total
// on each automatic GC cycle. Passing nil disables metric recording (all
// DAMetrics methods are nil-safe). The same *DAMetrics instance is also
// injected into the DAAttestationCollector via SetDAMetrics so
// SubmitAttestation rejections are recorded.
//
// IMPORTANT: Call SetDAMetrics BEFORE Start() — the GC ticker callback is
// snapshotted at Start() time to avoid a data race.
func (e *DankshardingEngine) SetDAMetrics(m *consensus.DAMetrics) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.metrics = m
	if e.attestCollector != nil {
		e.attestCollector.SetDAMetrics(m)
	}
	// Register the GC callback so automatic ticker-driven GC cycles are
	// counted. Must be done before Start() (the callback is snapshotted).
	if e.gc != nil && m != nil {
		e.gc.SetOnGC(func() {
			m.IncGCCycles()
		})
	}
}

// SetDAAttestationSigner configures the optional DA attestation signer used
// by BuildDAAttestation to attach a Dilithium3 signature over
// attestation.Hash() (CONS-FIX). The signer receives the partially
// built attestation (with all fields except Signature populated) and must
// fill in the Signature field in-place. Returning an error aborts
// BuildDAAttestation with that error. When never called, Signature is left
// empty and callers must sign the attestation themselves before submission
// (backward-compatible with existing test helpers).
func (e *DankshardingEngine) SetDAAttestationSigner(signer func(att *encoding.DASAttestation) error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.daAttestationSigner = signer
}

// GetFRIBlobData returns the cached FRI blob data for a given slot and blob
// index, or nil if not cached. R7 P0-6 FIX (DA-): Used by DASClient
// (via friDataProvider callback) to access locally-cached FRI data for
// FRIDAVerifyCell-based cell verification.
func (e *DankshardingEngine) GetFRIBlobData(slot uint64, blobIndex int) *encoding.FRIDABlobData {
	raw, ok := e.friBlobDataBySlot.Load(slot)
	if !ok {
		return nil
	}
	list, ok := raw.([]*encoding.FRIDABlobData)
	if !ok || blobIndex < 0 || blobIndex >= len(list) {
		return nil
	}
	return list[blobIndex]
}

// CleanupFRIBlobData removes cached FRI data for a slot. Called during
// old data cleanup to prevent unbounded memory growth.
func (e *DankshardingEngine) CleanupFRIBlobData(slot uint64) {
	e.friBlobDataBySlot.Delete(slot)
}

func (e *DankshardingEngine) Start() error {
	// R36-P3-12 FIX (2026-07-30): Fail-closed when critical dependencies
	// are nil. The constructor logs the misconfiguration but still returns
	// a non-nil engine (to preserve the existing constructor signature for
	// backward compatibility with tests and node assembly). Start() is the
	// authoritative gate: if blobStorage/dasClient/attestCollector are nil,
	// the engine cannot safely process blobs or attestations, so we refuse
	// to start. This prevents the hot-path nil deref panics described in
	// the audit (ProcessBlobs line 352, VerifyBlockDAAvailability line 405).
	if e.blobStorage == nil || e.dasClient == nil || e.attestCollector == nil {
		return fmt.Errorf("DankshardingEngine cannot start: nil critical dependency (blobStorage=%v dasClient=%v attestCollector=%v)",
			e.blobStorage == nil, e.dasClient == nil, e.attestCollector == nil)
	}
	if e.gc != nil {
		e.gc.Start()
	}
	// P0-6 FIX (2026-07-13): Wire the DAS client's cell getter to the blob
	// network manager so that sampling can fetch cells from peers. Without
	// this, dasClient.Sample() always fails with "no cell getter configured",
	// making DA availability verification non-functional.
	if e.networkManager != nil && e.dasClient != nil {
		e.dasClient.SetCellGetter(func(slot uint64, blobIndex, row, col int) (*encoding.DASSampleResponse, error) {
			return e.networkManager.RequestCell(slot, blobIndex, row, col)
		})
	}
	// P1-6 (2026-07-14): Register the P2P protocol bridge. Wire the injected
	// peerGetter and peerList to the BlobNetworkManager so that DAS sampling
	// can request cells from peers over the P2P network. Without this, the
	// networkManager's RequestCell always fails with "network not configured",
	// limiting DA verification to locally stored cells only.
	e.mu.RLock()
	peerGetter := e.peerGetter
	peerList := e.peerList
	e.mu.RUnlock()
	if e.networkManager != nil {
		if peerGetter != nil {
			e.networkManager.SetPeerGetter(peerGetter)
		}
		if peerList != nil {
			e.networkManager.SetPeerList(peerList)
		}
	}
	return nil
}

func (e *DankshardingEngine) Stop() {
	if e.gc != nil {
		e.gc.Stop()
	}
}

// Shutdown permanently terminates the engine, canceling any in-flight
// sampling goroutines spawned by DASClient.Sample. Stop() only halts the
// garbage collector and is safe to call on a node that will "restart"
// (continue using the same engine instance, as some tests do to simulate
// a crash/recovery). Shutdown() should be called when the engine will no
// longer be used, to avoid leaking sampling goroutines that would
// otherwise starve the scheduler under heavy parallel test execution.
//
// PRE-FIX (2026-07-17): previously Stop() also canceled the DASClient
// context, which broke tests that stop a node mid-scenario and then
// continue using the same engine (TestP2_9_NodeRestart_NewSlot). The
// goroutine cleanup is now split into Shutdown() so Stop() remains a
// non-destructive halt.
func (e *DankshardingEngine) Shutdown() {
	if e.gc != nil {
		e.gc.Stop()
	}
	if e.dasClient != nil {
		e.dasClient.Stop()
	}
}

func (e *DankshardingEngine) ProcessBlobsForBlock(slot uint64, blobs []encoding.Blob) (*encoding.BlobMatrixExtended, []encoding.KZGCommitment, error) {
	if !e.config.Enabled {
		return nil, nil, nil
	}

	e.warnOnce.Do(func() {
		if e.config.Experimental {
			msg := e.config.WarningMessage
			if msg == "" {
				msg = "Danksharding is EXPERIMENTAL - not production-ready, use at your own risk"
			}
			logging.Global().Warn(msg, nil)
		}
	})

	if len(blobs) == 0 {
		return nil, nil, nil
	}

	// R37-FIX P2-CONS-02 (2026-07-30): Piggyback CleanupOldData on the epoch
	// boundary. ProcessBlobsForBlock is the only per-slot production entry
	// point of the DA subsystem, and CleanupOldData previously had NO
	// production caller — attestCollector.attestations (up to ~1.7MB/slot:
	// 512 Dilithium3 signatures), dasClient sessions, and the sampleCache
	// grew without bound. DA is hard-disabled on mainnet; this bounds
	// memory on testnet/devnet where it is enabled.
	if slot%uint64(consensus.SlotsPerEpoch) == 0 {
		e.CleanupOldData(slot)
	}

	if len(blobs) > encoding.MaxBlobsPerBlock {
		return nil, nil, fmt.Errorf("too many blobs: %d > %d", len(blobs), encoding.MaxBlobsPerBlock)
	}

	commitments := make([]encoding.KZGCommitment, len(blobs))

	// R7 P0-6 FIX (DA-, 2026-07-17): When UseFRI=true, compute a
	// post-quantum FRI commitment (FRIDACommitBlob) for each blob and
	// cache the FRIDABlobData for later cell verification by DASClient.
	// The KZGCommitment is still computed for backward-compatible
	// attestation serialization (DASAttestation.BlobCommitments uses
	// types.Hash derived from KZGCommitment). When UseFRI=false (default),
	// only the legacy Keccak256 hash stub is used — identical to prior
	// behavior.
	var friBlobDataList []*encoding.FRIDABlobData
	if e.config.UseFRI {
		friBlobDataList = make([]*encoding.FRIDABlobData, len(blobs))
		for i, blob := range blobs {
			friData, err := encoding.FRIDACommitBlob(blob[:], encoding.DefaultFRIConfig(16))
			if err != nil {
				return nil, nil, fmt.Errorf("FRI commitment failed for blob %d: %w", i, err)
			}
			friBlobDataList[i] = friData
			commitments[i] = encoding.KZGCommitmentFromBlob(blob)
		}
		// Cache FRI data for this slot so DASClient can access it via
		// the friDataProvider callback (set in VerifyBlockDAAvailability).
		e.friBlobDataBySlot.Store(slot, friBlobDataList)
	} else {
		for i, blob := range blobs {
			commitments[i] = encoding.KZGCommitmentFromBlob(blob)
		}
	}

	matrix, err := encoding.ExtendBlobs2D(blobs)
	if err != nil {
		return nil, nil, fmt.Errorf("erasure coding failed: %w", err)
	}

	for i := range blobs {
		if err := e.blobStorage.StoreMatrix(slot, i, matrix, commitments); err != nil {
			// P3-2 (2026-07-15): Log blob persistence failure.
			logging.Global().Warnf("[da] StoreMatrix failed: slot=%d blobIndex=%d err=%v", slot, i, err)
			return nil, nil, fmt.Errorf("failed to store blob %d: %w", i, err)
		}
	}

	// P0-4 FIX (2026-07-13): Previously only subnet 0 was assigned columns,
	// leaving subnets 1..DACommitteeSubnetCount-1 empty. This caused
	// SampleSubnet to fail for all non-zero subnets, breaking the
	// distributed sampling assumption. Now assign columns to ALL subnets.
	// P1-2 (2026-07-14): Nil guard — subnetMgr is optional (single-node /
	// testing mode may not configure subnets). Skip assignment in that case;
	// DA sampling still works with locally stored cells.
	if e.subnetMgr != nil {
		for i := 0; i < consensus.DACommitteeSubnetCount; i++ {
			e.subnetMgr.AssignColumns(i, len(blobs))
		}
	}

	return &matrix, commitments, nil
}

func (e *DankshardingEngine) VerifyBlockDAAvailability(slot uint64, blobCount int, commitments []encoding.KZGCommitment) (bool, float64, error) {
	if !e.config.Enabled {
		return false, 0, nil
	}

	e.warnOnce.Do(func() {
		if e.config.Experimental {
			msg := e.config.WarningMessage
			if msg == "" {
				msg = "Danksharding is EXPERIMENTAL - not production-ready, use at your own risk"
			}
			logging.Global().Warn(msg, nil)
		}
	})

	// P1-10 (2026-07-14): Cache per-slot sampling result so multiple
	// BuildDAAttestation calls for the same slot only trigger Sample once.
	// sync.Once serializes concurrent callers: the first performs sampling,
	// the rest block until the result is ready, then return the cached value.
	// CONS-FIX: The cache key now includes the commitments hash so
	// that a fork switch to a different blob set for the same slot cannot
	// reuse a stale sample result computed on the pre-fork blobs.
	cacheKey := daSampleCacheKey{
		slot:            slot,
		commitmentsHash: hashCommitments(commitments),
	}
	raw, _ := e.sampleCache.LoadOrStore(cacheKey, &daSampleSlot{})
	entry := raw.(*daSampleSlot)

	entry.once.Do(func() {
		// R37-P3-32 FIX (2026-07-31): DASClient sessions are keyed by slot
		// only, while this cache is keyed by (slot, commitmentsHash). Hold
		// sampleSessionMu across NewSession + Sample + stats read so a
		// concurrent sampling of a different commitment set for the same
		// slot cannot replace the session mid-flight (cache pollution).
		e.sampleSessionMu.Lock()
		defer e.sampleSessionMu.Unlock()
		e.dasClient.NewSession(slot, commitments)
		// R7 P0-6 FIX (DA-): When UseFRI=true, inject a FRI data
		// provider so DASClient.Sample can use FRIDAVerifyCell for
		// post-quantum cell verification when FRI data is locally
		// available. When UseFRI=false, the provider is nil and
		// DASClient falls back to the hash stub (VerifyCellProof).
		if e.config.UseFRI {
			e.dasClient.SetFRIDataProvider(func(blobIdx int) *encoding.FRIDABlobData {
				return e.GetFRIBlobData(slot, blobIdx)
			})
		} else {
			e.dasClient.SetFRIDataProvider(nil)
		}
		available, confidence, err := e.dasClient.Sample(slot, blobCount)
		// R37-P3-32 FIX (2026-07-31): Capture the sample counters here,
		// while the slot session is still guaranteed to belong to THIS
		// commitment set (sampleSessionMu held).
		sampleTotal, sampleSuccess := 0, 0
		if session := e.dasClient.GetSession(slot); session != nil {
			sampleTotal, sampleSuccess = session.GetSampleStats()
		}
		if err != nil {
			entry.result = daSampleResult{false, 0, fmt.Errorf("DAS sampling failed: %w", err), sampleTotal, sampleSuccess}
			// P3-1 (2026-07-15): Record sampling failure metric.
			e.metrics.IncSamplingFailures()
			// P3-2 (2026-07-15): Log sampling failure for lifecycle traceability.
			logging.Global().Warnf("[da] DAS sampling failed: slot=%d blobCount=%d err=%v", slot, blobCount, err)
			return
		}
		entry.result = daSampleResult{available, confidence, nil, sampleTotal, sampleSuccess}
		// P3-1 (2026-07-15): Record sampling confidence metric. Even when
		// available=false, the confidence gauge reflects the actual sampling
		// quality — useful for diagnosing partial-network failures.
		e.metrics.SetSamplingConfidence(confidence)
	})

	return entry.result.available, entry.result.confidence, entry.result.err
}

func (e *DankshardingEngine) BuildDAAttestation(
	slot uint64,
	blobCount int,
	commitments []encoding.KZGCommitment,
	validatorIndex int,
) (*encoding.DASAttestation, error) {
	available, confidence, err := e.VerifyBlockDAAvailability(slot, blobCount, commitments)
	if err != nil {
		return nil, err
	}

	attestation := &encoding.DASAttestation{
		Slot:           slot,
		Available:      available,
		Confidence:     confidence,
		ValidatorIndex: validatorIndex,
	}

	// P0-8 FIX (2026-07-13): Populate SampleCount/SuccessCount from the DAS
	// session. Previously these fields were always 0, making the attestation
	// hash identical across all validators regardless of actual sampling.
	// This also prevented distinguishing "insufficient sampling" from
	// "sampling failure" during aggregate attestation verification.
	// R37-P3-32 FIX (2026-07-31): Read the counters from the sampleCache
	// entry keyed by (slot, commitmentsHash) — the same key dimension as
	// the availability result above — instead of the slot-only DASClient
	// session map, which a different commitment set for the same slot may
	// have overwritten. VerifyBlockDAAvailability populated this entry
	// under sampleSessionMu, so the counters are guaranteed to belong to
	// THIS commitment set.
	cacheKey := daSampleCacheKey{
		slot:            slot,
		commitmentsHash: hashCommitments(commitments),
	}
	if raw, ok := e.sampleCache.Load(cacheKey); ok {
		entry := raw.(*daSampleSlot)
		attestation.SampleCount = entry.result.sampleTotal
		attestation.SuccessCount = entry.result.sampleSuccess
	}

	// DA- (2026-07-16): Bind the FULL commitment set to the attestation.
	// Previously only commitments[0] was stored in BlobCommitment, allowing
	// attestation reuse across distinct commitment sets sharing [0]. Now
	// BlobCommitments carries the full slice and Hash() includes every entry.
	// BlobCommitment (legacy) is still populated for backward-compatible
	// fixed-offset readers (e.g., old decoders, fuzz corpus).
	//
	// DA-FIX (2026-07-17): BlobCommitments is now []KZGCommitment
	// (48 bytes each) instead of []types.Hash (32 bytes). The full 48-byte
	// commitment is preserved, eliminating the 16-byte truncation that
	// enabled cross-set collisions. The legacy BlobCommitment field still
	// stores the truncated 32-byte form for backward-compatible readers.
	if len(commitments) > 0 {
		attestation.BlobCommitment = types.BytesToHash(commitments[0][:])
		attestation.BlobCommitments = make([]encoding.KZGCommitment, len(commitments))
		copy(attestation.BlobCommitments, commitments)
	}

	// CONS-FIX (2026-07-17): Attach a Dilithium3 signature over
	// attestation.Hash() when a signer is configured. This binds the
	// attestation to ValidatorIndex so SubmitAttestation's verifier can
	// reject forged attestations. When no signer is configured, Signature
	// is left empty and the caller must sign before submission (matches the
	// pre-fix behavior used by test helpers like signAndSubmit).
	e.mu.RLock()
	signer := e.daAttestationSigner
	e.mu.RUnlock()
	if signer != nil {
		if err := signer(attestation); err != nil {
			return nil, fmt.Errorf("DA attestation signing failed: %w", err)
		}
	}

	return attestation, nil
}

func (e *DankshardingEngine) BuildAggregateAttestation(slot uint64, commitments []encoding.KZGCommitment) *encoding.DASAggregateAttestation {
	return e.attestCollector.BuildAggregateAttestation(slot, commitments)
}

// GetAggregateAttestation returns the current aggregate attestation for a
// slot without requiring blob commitments. Used by the QPOS DA availability
// checker (P1-4) to verify that enough attestations have been collected.
// Returns nil if no attestations exist for the slot.
func (e *DankshardingEngine) GetAggregateAttestation(slot uint64) *encoding.DASAggregateAttestation {
	return e.attestCollector.BuildAggregateAttestation(slot, nil)
}

func (e *DankshardingEngine) SubmitAttestation(attestation *encoding.DASAttestation) error {
	return e.attestCollector.SubmitAttestation(attestation)
}

func (e *DankshardingEngine) IsInDACommittee(epoch uint64, validatorIndex int) (bool, int) {
	inCommittee, subnetID := e.committeeMgr.IsInCommittee(epoch, validatorIndex)
	return inCommittee, subnetID
}

func (e *DankshardingEngine) GetBlobCommitments(slot uint64) []encoding.KZGCommitment {
	return e.blobStorage.GetCommitments(slot)
}

func (e *DankshardingEngine) GetBlobCount(slot uint64) int {
	return e.blobStorage.GetBlobCount(slot)
}

func (e *DankshardingEngine) CleanupOldData(currentSlot uint64) {
	e.blobStorage.GC(currentSlot)
	// P3-1 (2026-07-15): Count this manual GC cycle. Automatic ticker-driven
	// cycles are counted via the BlobGarbageCollector.onGC callback.
	e.metrics.IncGCCycles()
	e.attestCollector.CleanupOldSlots(currentSlot)
	e.dasClient.CleanupOldSessions(currentSlot)
	// P1-10: Clean old sample cache entries (keep last 100 slots).
	// CONS-FIX: cache key is now daSampleCacheKey; extract slot field.
	e.sampleCache.Range(func(key, value any) bool {
		ck, ok := key.(daSampleCacheKey)
		if !ok {
			return true
		}
		if ck.slot+100 < currentSlot {
			e.sampleCache.Delete(ck)
		}
		return true
	})
	// R37-FIX P2-CONS-03 (2026-07-30): Prune cached FRI blob data. In
	// UseFRI mode every slot stores full FRI commitments + polynomial data
	// (up to MB-scale per blob) in friBlobDataBySlot, and CleanupFRIBlobData
	// had zero callers repository-wide — not even CleanupOldData pruned it.
	// Same 100-slot retention window as the sample cache above.
	e.friBlobDataBySlot.Range(func(key, value any) bool {
		s, ok := key.(uint64)
		if !ok {
			return true
		}
		if s+100 < currentSlot {
			e.friBlobDataBySlot.Delete(s)
		}
		return true
	})
}
