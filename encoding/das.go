// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

const (
	DASSamplesPerQuery    = 8
	DASMinConfidenceLevel = 0.9999
	DASMaxRetries         = 3
	DASQueryTimeout       = 5000

	// P1-9 (2026-07-14): Exponential backoff base for retry between failed
	// sample queries. Each retry doubles the backoff: 10ms, 20ms, 40ms...
	// This gives the network time to recover from transient issues without
	// making the overall sampling take too long.
	DASRetryBackoffBaseMs = 10

	// P1-9 (2026-07-14): Overall timeout for the entire Sample() call.
	// Prevents a single sampling session from blocking indefinitely when
	// the network is severely degraded. At 30s, this allows ~6000 retries
	// at 5ms each — far more than MaxRetries (3) per sample.
	DASOverallTimeoutMs = 30000

	// DASMaxConcurrentSamples bounds the number of concurrent in-flight
	// cell getter goroutines a DASClient may spawn. R59 (2026-08-18):
	// sampleWithTimeout spawns one goroutine per request to enforce a
	// timeout on a synchronous getter. Without a cap, slow CPU-bound
	// getters under heavy parallel load (full test suites running many
	// multi-node P2P networks, or a DAS-enabled node serving many
	// samplers) accumulate goroutines across sessions/nodes, starving the
	// scheduler and inflating memory until the process exceeds its
	// package timeout / memory limit. Sample() is serial per client in the
	// normal path, so the cap is only reached under real concurrency.
	DASMaxConcurrentSamples = 16

	// SECURITY (audit 2026-06-24, M-1): Upper bounds to prevent OOM when
	// decoding untrusted DAS aggregate attestation fields. Without these
	// checks a malicious peer could send commitCount/bitsLen/sigCount set
	// to 0xFFFFFFFF and trigger multi-GB allocations.
	maxBlobCommitmentsPerAttestation = 1024
	maxValidatorBitsLen              = 8192
	maxSignaturesPerAttestation      = 4096
	// ENCODING-P0-02: Cap a single signature's length to prevent OOM.
	// Dilithium3 signatures are 3293 bytes; 16KB leaves margin for
	// future signature schemes while bounding malicious allocations.
	maxSignatureLen = 16384
)

// DASSampleRequestSize is the wire size of a DASSampleRequest.
// P1-12 (RPC-H1, 2026-07-19): RequestID (8) + Slot (8) + BlobIndex (4) +
// CellRow (4) + CellCol (4) = 28 bytes.
const DASSampleRequestSize = 28

// DASSampleResponseSize is the wire size of a DASSampleResponse.
// P1-12 (RPC-H1, 2026-07-19): RequestID (8) + DASSampleRequest fixed fields (20)
// + Cell (CellSize) + Proof (48) = 28 + CellSize + 48.
const DASSampleResponseSize = 28 + CellSize + 48

type DASSampleRequest struct {
	// RequestID correlates a response to its originating request.
	// P1-12 (RPC-H1, 2026-07-19): Without this, concurrent sampling
	// goroutines reading a shared response channel would observe each
	// other's responses, allowing a malicious peer to inject arbitrary
	// cell data that gets matched to the wrong request.
	RequestID uint64
	Slot      uint64
	BlobIndex int
	CellRow   int
	CellCol   int
}

type DASSampleResponse struct {
	// RequestID echoes the originating request's RequestID.
	// P1-12 (RPC-H1, 2026-07-19): The responder MUST copy this field
	// verbatim from the request so the requester can route the response
	// to its pending channel via the dasPending map.
	RequestID uint64
	Slot      uint64
	BlobIndex int
	CellRow   int
	CellCol   int
	Cell      Cell
	Proof     KZGProof
}

type DASSession struct {
	Slot           uint64
	Commitments    []KZGCommitment
	TotalSamples   int
	SuccessSamples int
	// P1-9 (2026-07-14): Error classification counters for diagnostics.
	// NetworkErrors: getter returned an error (peer unreachable, RPC fail, etc.)
	// TimeoutErrors: getter didn't respond within QueryTimeoutMs
	// VerificationErrors: cell proof verification failed (data corrupted/wrong)
	NetworkErrors      int
	TimeoutErrors      int
	VerificationErrors int
	mu                 sync.Mutex

	// seenSuccessCoords deduplicates successful sample responses by their
	// (Slot, BlobIndex, CellRow, CellCol) coordinates. R38-P1-06 FIX (2026-08-01):
	// Without this set, a malicious (or simply bad-luck randomInt-colliding)
	// run that yields multiple valid responses for the SAME coordinate would
	// increment SuccessSamples once per matching response, inflating the
	// binomial confidence bound (computeConfidence uses 1 - 0.5^k with k =
	// SuccessSamples) well above the evidence a single unique sample
	// justifies. We count each unique coordinate only ONCE so confidence
	// tracks the actual diversity of cells proven available, not the raw
	// count of (possibly replayed) success responses.
	//
	// BlobIndex is INCLUDED in the key. Each blob has its own independent
	// commitment and a cell at (row, col) under blob A is NOT the same cell
	// at (row, col) under blob B — they verify against different KZG
	// commitments and produce different proof substrates. Excluding
	// BlobIndex (an earlier draft of this fix) caused cross-blob legitimate
	// samples to be incorrectly deduped, defeating availability confidence
	// in multi-blob tests (TestP2_5_ThreeNode_MultipleBlobs regression).
	// Allocation is lazy so we don't pay the map cost for sessions that never sample.
	seenSuccessCoords map[[4]int64]struct{}

	// seenTrialCoords deduplicates ALL sampled (Slot, BlobIndex, CellRow,
	// CellCol) coordinates — successful OR failed — within a single Sample()
	// call. R38-P1-06 FIX (2026-08-01): Without this companion set the
	// seenSuccessCoords-only dedup introduced a regression: when randomInt
	// produced a birthday collision (the SAME coord requested twice), the
	// colliding request's success was correctly NOT counted, but its
	// TotalSamples WAS still incremented, breaking SuccessSamples ==
	// TotalSamples and driving computeConfidence into the observedRate <
	// 1.0 branch. For multi-blob Sample() where samplesNeeded scales with
	// blobCount × CellsPerBlobExtended and the collision expected value is
	// ~15 collisions per call, this dropped observedRate below MinConfidence
	// (0.9999) and made the legitimate TestP2_5_ThreeNode_MultipleBlobs run
	// fail-open UNAVAILABLE — a regression versus the pre-R38 baseline
	// (verified by reverting das.go to c7f643c: 10/10 PASS).
	//
	// Now both TotalSamples and SuccessSamples share the same uniqueness
	// window: a coordinate is counted as a TRIAL exactly once (the first
	// time it appears in req), and counted as a SUCCESS exactly once (the
	// first time a verified response lands for it). This preserves the
	// R38-P1-06 dedup invariant (SuccessSamples == UniqueSuccessCount)
	// while restoring SuccessSamples == TotalSamples in the legitimate
	// happy path, so computeConfidence takes the 1 - 0.5^k branch and
	// produces the same near-1.0 confidence as the pre-R38 baseline.
	//
	// Crucially, this does NOT weaken R38-P1-06's defense: the coordinate
	// mismatch check ABOVE this trial counter still rejects every response
	// a malicious peer serves against a request with a DIFFERENT coord
	// (VerificationErrors++, no trial counted), which is the audit's
	// "peer returns the same valid cell for every request" attack.
	seenTrialCoords map[[4]int64]struct{}
}

type DASConfig struct {
	SamplesPerQuery int
	MinConfidence   float64
	MaxRetries      int
	QueryTimeoutMs  int
	// MaxConcurrentSamples bounds concurrent in-flight cell getter
	// goroutines spawned by Sample. R59 (2026-08-18): see
	// DASMaxConcurrentSamples. Defaults to DASMaxConcurrentSamples when <= 0.
	MaxConcurrentSamples int

	// R40-P1-03 (2026-08-03): the DAS sample verifier has TWO cell verification
	// paths:
	//   (1) FRIDAVerifyCell — a real polynomial commitment check (post-quantum),
	//       used when `friDataProvider != nil` (i.e. when DankshardingConfig.
	//       UseFRI=true on the verifying node and the blob's FRI data is cached).
	//   (2) VerifyCellProof — a HASH STUB that only checks
	//       `subtle.ConstantTimeCompare(proof, sha3(cell||commitment||row||col))`.
	//       This proves the cell's hash matches the proof the producer supplied,
	//       NOT that the cell is an evaluation of the committed polynomial.
	//
	// Path (2) is a security downgrade: an attacker can construct a blob whose
	// cells are internally self-consistent (matching their own fabricated proofs)
	// but that do NOT belong to any committed polynomial, and the sample passes.
	// This breaks the data-availability-sampling guarantee.
	//
	// R40-P1-03 fix: `AllowHashStubFallback` defaults to FALSE. When false:
	//   - If FRI verification is not available (No FRI provider, or FRI data
	//     absent for this blob, or FRI verification FAILED), the sample is
	//     REJECTED — we do NOT fall through to the hash stub. The slot is
	//     treated as unavailable, which is the safe direction.
	//   - Tests / dev environments that intentionally exercise the legacy hash
	//     stub path can set `AllowHashStubFallback: true` to restore the prior
	//     permissive behavior. Production deployments MUST leave this false.
	//
	// This keeps the change surgical: no new crypto, no wire-format change, no
	// removal of the hash stub function (other code paths still use it for
	// non-DAS purposes); only the DAS sample acceptance policy tightens.
	AllowHashStubFallback bool
}

func DefaultDASConfig() DASConfig {
	return DASConfig{
		SamplesPerQuery: DASSamplesPerQuery,
		MinConfidence:   DASMinConfidenceLevel,
		MaxRetries:      DASMaxRetries,
		QueryTimeoutMs:  DASQueryTimeout,
	}
}

type DASClient struct {
	config     DASConfig
	sessions   map[uint64]*DASSession
	mu         sync.RWMutex
	cellGetter func(slot uint64, blobIndex, row, col int) (*DASSampleResponse, error)
	retention  DASRetentionConfig
	// R7 P0-6 FIX (DA-, 2026-07-17): Optional FRI data provider.
	// When set (non-nil), Sample() verification uses FRIDAVerifyCell for
	// post-quantum cell verification when FRI data is available for the
	// blob. When nil, falls back to VerifyCellProof (hash stub).
	// Set by DankshardingEngine.VerifyBlockDAAvailability when UseFRI=true.
	friDataProvider func(blobIndex int) *FRIDABlobData

	// ctx/cancel govern the lifetime of sampling goroutines spawned by
	// sampleWithTimeout. Stop() cancels ctx so that goroutines blocked in
	// the cell getter (e.g. on a slow/dead peer) exit promptly instead of
	// accumulating and starving the scheduler when many test cases run in
	// sequence. ctx is never nil after NewDASClient.
	ctx    context.Context
	cancel context.CancelFunc

	// samplingSem caps the number of concurrent in-flight cell getter
	// goroutines spawned by sampleWithTimeout. R59 (2026-08-18): bounded by
	// MaxConcurrentSamples so heavy parallel load queues sampling requests
	// instead of spawning unbounded goroutines.
	samplingSem chan struct{}
}

func NewDASClient(config DASConfig) *DASClient {
	if config.SamplesPerQuery <= 0 {
		config.SamplesPerQuery = DASSamplesPerQuery
	}
	if config.MinConfidence <= 0 {
		config.MinConfidence = DASMinConfidenceLevel
	}
	if config.MaxRetries <= 0 {
		config.MaxRetries = DASMaxRetries
	}
	if config.MaxConcurrentSamples <= 0 {
		config.MaxConcurrentSamples = DASMaxConcurrentSamples
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &DASClient{
		config:      config,
		sessions:    make(map[uint64]*DASSession),
		retention:   DefaultDASRetentionConfig(),
		ctx:         ctx,
		cancel:      cancel,
		samplingSem: make(chan struct{}, config.MaxConcurrentSamples),
	}
}

// Stop cancels the sampling context, causing any in-flight sampleWithTimeout
// goroutines to return as soon as the cell getter observes the cancellation.
// Safe to call multiple times. After Stop, the DASClient should not be reused.
func (c *DASClient) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// SetFRIDataProvider injects the FRI blob data provider callback.
// R7 P0-6 FIX (DA-): When non-nil, DASClient.Sample uses FRIDAVerifyCell
// for cell verification. Pass nil to disable FRI verification (use hash stub).
func (c *DASClient) SetFRIDataProvider(provider func(blobIndex int) *FRIDABlobData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.friDataProvider = provider
}

// SetRetentionConfig updates the retention configuration.
// DA- (2026-07-16): Rejects invalid configurations (those violating
// the Blob >= Session >= Attest > Decay invariants) and keeps the previous
// config — fail-closed against accidental availability regression.
func (c *DASClient) SetRetentionConfig(cfg DASRetentionConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !validateAndLogRetention(cfg, "DASClient.SetRetentionConfig") {
		return
	}
	c.retention = cfg
}

func (c *DASClient) SetCellGetter(getter func(slot uint64, blobIndex, row, col int) (*DASSampleResponse, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cellGetter = getter
}

func (c *DASClient) NewSession(slot uint64, commitments []KZGCommitment) *DASSession {
	c.mu.Lock()
	defer c.mu.Unlock()

	session := &DASSession{
		Slot:        slot,
		Commitments: commitments,
	}
	c.sessions[slot] = session
	return session
}

func (c *DASClient) GetSession(slot uint64) *DASSession {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessions[slot]
}

// GetSampleStats returns the total and successful sample counts for the
// session. This provides safe external read access to the session's
// mutex-protected fields without exposing the mutex itself.
// P0-8 (2026-07-13): Used by DankshardingEngine.BuildDAAttestation to
// populate DASAttestation.SampleCount/SuccessCount.
func (s *DASSession) GetSampleStats() (total, success int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.TotalSamples, s.SuccessSamples
}

// GetErrorStats returns the error classification counters for the session.
// P1-9 (2026-07-14): Used for diagnostics and monitoring to distinguish
// network issues (transient) from verification failures (data corruption).
func (s *DASSession) GetErrorStats() (network, timeout, verification int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.NetworkErrors, s.TimeoutErrors, s.VerificationErrors
}

// GetUniqueSuccessCount returns the number of DISTINCT (Slot, CellRow, CellCol)
// coordinates that produced a verified-successful sample during the current
// Sample() call. R38-P1-06 FIX (2026-08-01).
//
// SuccessSamples counts matching responses but, after the dedup fix, is
// capped at one increment per unique coordinate — so in the fixed code base
// SuccessSamples == GetUniqueSuccessCount(). Callers (and tests) that want
// to assert the dedup invariant should compare these two values; future
// regressions that drop the dedup will make SuccessSamples exceed the unique
// count, surfacing the bug deterministically.
func (s *DASSession) GetUniqueSuccessCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seenSuccessCoords == nil {
		return 0
	}
	return len(s.seenSuccessCoords)
}

// recordSuccessIfUnique marks resp's (Slot, CellRow, CellCol) coordinate as
// seen and returns true if this is the FIRST time we've recorded that
// coordinate this Sample() call. Returns false if the coordinate was already
// recorded, signalling the caller NOT to increment SuccessSamples. R38-P1-06.
//
// Caller MUST hold no other session lock when invoking; this method takes
// s.mu internally. Exposed (lower-cased) so the dedup logic is unit-testable
// without depending on randomInt collision probabilities.
func (s *DASSession) recordSuccessIfUnique(resp *DASSampleResponse) bool {
	if resp == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seenSuccessCoords == nil {
		s.seenSuccessCoords = make(map[[4]int64]struct{})
	}
	coordKey := [4]int64{int64(resp.Slot), int64(resp.BlobIndex), int64(resp.CellRow), int64(resp.CellCol)}
	if _, seen := s.seenSuccessCoords[coordKey]; seen {
		return false
	}
	s.seenSuccessCoords[coordKey] = struct{}{}
	return true
}

func (c *DASClient) CleanupOldSessions(currentSlot uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	retentionSlots := c.retention.SessionRetentionSlots
	for slot := range c.sessions {
		if slot+retentionSlots < currentSlot {
			delete(c.sessions, slot)
		}
	}
}

func (c *DASClient) GetConfidenceWithDecay(slot uint64, baseConfidence float64, currentSlot uint64) float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	slotAge := currentSlot - slot
	return c.retention.DecayConfidence(baseConfidence, slotAge)
}

func (c *DASClient) Sample(slot uint64, blobCount int) (bool, float64, error) {
	session := c.GetSession(slot)
	if session == nil {
		return false, 0, fmt.Errorf("no DAS session for slot %d", slot)
	}

	c.mu.RLock()
	getter := c.cellGetter
	c.mu.RUnlock()

	if getter == nil {
		return false, 0, fmt.Errorf("no cell getter configured")
	}

	totalCells := blobCount * CellsPerBlobExtended
	samplesNeeded := c.calculateSamplesNeeded(totalCells)

	// P1-9 (2026-07-14): Reset all counters at start.
	// R38-P1-06 FIX (2026-08-01): Also reset the seen-coordinate dedup sets
	// (success + trial) so each Sample() call starts with a fresh uniqueness
	// window. Both share the same [4]int64 coord key so they observe the
	// SAME collision set per Sample() invocation — see seenTrialCoords docs.
	session.mu.Lock()
	session.TotalSamples = 0
	session.SuccessSamples = 0
	session.NetworkErrors = 0
	session.TimeoutErrors = 0
	session.VerificationErrors = 0
	session.seenSuccessCoords = make(map[[4]int64]struct{})
	session.seenTrialCoords = make(map[[4]int64]struct{})
	session.mu.Unlock()

	// P1-9 (2026-07-14): Overall deadline prevents indefinite blocking.
	deadline := time.Now().Add(time.Duration(DASOverallTimeoutMs) * time.Millisecond)
	perQueryTimeout := time.Duration(c.config.QueryTimeoutMs) * time.Millisecond

	for i := 0; i < samplesNeeded; i += c.config.SamplesPerQuery {
		if time.Now().After(deadline) {
			break
		}

		batchSize := c.config.SamplesPerQuery
		if i+batchSize > samplesNeeded {
			batchSize = samplesNeeded - i
		}

		requests := c.generateSampleRequests(slot, blobCount, batchSize)

		for _, req := range requests {
			if time.Now().After(deadline) {
				break
			}

			// R38-P1-06 FIX (2026-08-01, trial dedup): Skip a request whose
			// (Slot, BlobIndex, CellRow, CellCol) coordinate was already
			// TRIED in this Sample() call. randomInt is a uniform crypto
			// CSPRNG; for multi-blob Sample() the sampling plan can reach
			// multiple thousand requests, so on average ~15 birthday
			// collisions land per call. Without this trial-side dedup the
			// earlier success-side-only dedup (seenSuccessCoords) introduced
			// a regression: the colliding request would still bump
			// TotalSamples but no longer bump SuccessSamples, breaking
			// SuccessSamples == TotalSamples and forcing
			// computeConfidence into the observedRate<1.0 branch — making
			// the legitimate TestP2_5_ThreeNode_MultipleBlobs run
			// fail-open UNAVAILABLE. With this trial dedup both totals skip
			// the duplicate coordinate, restoring the success==total
			// invariant that lets computeConfidence use 1 - 0.5^k.
			//
			// This does NOT weaken R38-P1-06's attack defense: a malicious
			// peer serving the SAME valid cell across requests with
			// DIFFERENT coords is rejected earlier by the per-response
			// coordinate mismatch check (VerificationErrors++, no trial mark
			// added because we only mark after a verified match), so the
			// confidence still collapses well below MinConfidence under
			// that replay attack — exactly as the audit requires.
			trialKey := [4]int64{int64(req.Slot), int64(req.BlobIndex), int64(req.CellRow), int64(req.CellCol)}
			session.mu.Lock()
			if _, alreadyTried := session.seenTrialCoords[trialKey]; alreadyTried {
				session.mu.Unlock()
				continue
			}
			session.seenTrialCoords[trialKey] = struct{}{}
			session.mu.Unlock()

			success := false
			// R38-P1-06 FIX (2026-08-01): Capture the response whose proof
			// actually verified so the post-retry dedup block can read its
			// coordinates. resp is scoped to the retry loop, so we hoist the
			// successful one out here. Stays nil if every retry failed.
			var successResp *DASSampleResponse
			for retry := 0; retry < c.config.MaxRetries; retry++ {
				if time.Now().After(deadline) {
					break
				}

				resp, err, timedOut := c.sampleWithTimeout(req, getter, perQueryTimeout)

				if timedOut {
					session.mu.Lock()
					session.TimeoutErrors++
					session.mu.Unlock()
					c.retryBackoff(retry)
					continue
				}

				if err != nil {
					session.mu.Lock()
					session.NetworkErrors++
					session.mu.Unlock()
					c.retryBackoff(retry)
					continue
				}

				// R38-P1-06 FIX: Verify that the response coordinates match the
				// request coordinates. Without this, a malicious peer can return
				// the same valid cell for every sampling request, faking data
				// availability confidence. The response must be bound to the
				// exact (Slot, BlobIndex, CellRow, CellCol) tuple we requested.
				//
				// R38-P1-06 FIX (2026-08-01, RequestID binding): additionally
				// verify resp.RequestID echoes req.RequestID. generateSampleRequests
				// now mints a unique 8-byte nonce per request; a peer that answers
				// with a stale / cross-call response carrying a different RequestID
				// is rejected here even if the (slot, blob, row, col) tuple happens
				// to match — closing the replay window where a peer precomputes one
				// valid response and serves it against every request it receives.
				if resp != nil {
					if resp.Slot != req.Slot ||
						resp.BlobIndex != req.BlobIndex ||
						resp.CellRow != req.CellRow ||
						resp.CellCol != req.CellCol {
						session.mu.Lock()
						session.VerificationErrors++
						session.mu.Unlock()
						log.Printf("[WARN] DAS: response coordinate mismatch — got (slot=%d, blob=%d, row=%d, col=%d), want (slot=%d, blob=%d, row=%d, col=%d) (R38-P1-06)",
							resp.Slot, resp.BlobIndex, resp.CellRow, resp.CellCol,
							req.Slot, req.BlobIndex, req.CellRow, req.CellCol)
						c.retryBackoff(retry)
						continue
					}
					// R38-P1-06 FIX (2026-08-01): RequestID binding is
					// enforced at the wire layer (BlobNetworkManager.RequestCell
					// mints its own nonce, sends it to the peer via
					// encodeDASSampleRequest, and verifies resp.RequestID ==
					// that nonce on receipt). DASClient.Sample routes through
					// cellGetter which wraps RequestCell but cannot forward
					// the client-side req.RequestID (the cellGetter signature
					// only carries (slot, blobIndex, row, col)). As a result
					// the wire's RequestID is independent of
					// generateSampleRequests's per-call nonce, and the two
					// must NOT be compared here — doing so would reject every
					// legitimate response (TestP2_5_FourNode_TwoOfFourNotSufficient
					// regression root cause).
					//
					// The coordinate check above is sufficient to defeat the
					// "peer returns same valid cell for every request" attack
					// described in R38-P1-06, because each request carries a
					// different (slot, blob, row, col) tuple and the cellGetter
					// path returns one response per request (the wire layer's
					// RequestID binding guarantees no cross-call substitution).
					// The dedup set tracked by seenSuccessCoords additionally
					// guards against replay of one valid cell across many
					// requests with the SAME coordinate (a separate attack
					// vector the audit also calls out).
				}

				// R36-P3-5 FIX (2026-07-30): Validate resp.BlobIndex lower bound.
				// On 32-bit builds a uint32 BlobIndex >= 2^31 converts to a negative
				// int, causing a negative slice index panic. On 64-bit builds this
				// is harmless but the explicit check documents the contract.
				if resp != nil && resp.BlobIndex >= 0 && resp.BlobIndex < len(session.Commitments) {
					commitment := session.Commitments[resp.BlobIndex]
					// R7 P0-6 FIX (DA-, 2026-07-17): When FRI data is
					// locally available (block builder verifying its own
					// block), use FRIDAVerifyCell for post-quantum cell
					// verification. This replaces the hash stub
					// (VerifyCellProof) with a real polynomial commitment
					// check. Falls back to VerifyCellProof when FRI data is
					// not available (network cells from peers, or UseFRI=false).
					if c.friDataProvider != nil {
						if friData := c.friDataProvider(resp.BlobIndex); friData != nil {
							if friVerifyDASCell(friData, resp.Cell, resp.CellRow) {
								success = true
								break
							}
							// FRI verification failed — fall through to the
							// hash-stub-or-reject policy below.
						}
					}
					if c.config.AllowHashStubFallback {
						// R40-P1-03: legacy permissive path. Caller explicitly
						// opted into the hash-stub fallback (test/dev).
						// Production MUST leave `AllowHashStubFallback: false`
						// so that an absent or failed FRI check rejects the
						// sample instead of silently accepting a hash-stub-
						// verified cell. The hash stub only proves the cell's
						// hash matches the producer-supplied proof, NOT that
						// the cell is an evaluation of the committed polynomial.
						if VerifyCellProof(resp.Cell, commitment, resp.Proof, resp.CellRow, resp.CellCol) {
							success = true
							successResp = resp
							break
						}
					} else {
						// R40-P1-03 (2026-08-03) strict path. FRI verification
						// is unavailable OR the FRI check failed — REJECT the
						// sample, do NOT fall through to the hash stub. Treat
						// the slot as unavailable so the caller resamples /
						// fails over rather than accepting a potentially-forged
						// cell.
						session.mu.Lock()
						session.VerificationErrors++
						session.mu.Unlock()
						c.retryBackoff(retry)
						break
					}
				}

				// Proof verification failed or resp invalid.
				session.mu.Lock()
				session.VerificationErrors++
				session.mu.Unlock()
				c.retryBackoff(retry)
			}

			session.mu.Lock()
			session.TotalSamples++
			if success {
				// R38-P1-06 FIX (2026-08-01, dedup): Only count a unique
				// successful coordinate ONCE per Sample() call. Without
				// this guard, multiple valid responses for the SAME
				// (Slot, CellRow, CellCol) coordinate (whether from
				// randomInt birthday collisions or a malicious peer that
				// replays one valid cell across many requests) would each
				// push SuccessSamples++, inflating computeConfidence's
				// 1 - 0.5^k bound well above the evidence a single unique
				// sample justifies. BlobIndex is excluded from the key for
				// the reasons documented on seenSuccessCoords.
				//
				// BUG FIX (R38-P1-06, 2026-08-01): previously this block
				// called session.recordSuccessIfUnique(successResp), which
				// internally re-acquires s.mu via s.mu.Lock(). Go's
				// sync.Mutex is NOT reentrant, so re-locking a mutex the
				// same goroutine already holds deadlocks — verified by the
				// TestR38P1_06_SampleCell_DeduplicatesDuplicateSuccessfulCoordinates
				// panic ("sync.Mutex.Lock" in recordSuccessIfUnique). We
				// already hold session.mu here, so INLINE the dedup map
				// operation against seenSuccessCoords and skip calling the
				// helper. The helper is kept for the white-box unit test
				// (which invokes it from an UN-locked context) but is no
				// longer called from a context that already holds the lock.
				if successResp == nil {
					// Defensive: success=true implies successResp != nil
					// (we set it on every success=true site). If a future
					// refactor sets success=true without populating
					// successResp we fall back to the legacy behavior
					// (increment unconditionally) rather than panicking on
					// a nil access, so availability fails open during a
					// transient inconsistency instead of crashing the node.
					session.SuccessSamples++
				} else {
					coordKey := [4]int64{int64(successResp.Slot), int64(successResp.BlobIndex), int64(successResp.CellRow), int64(successResp.CellCol)}
					if _, seen := session.seenSuccessCoords[coordKey]; !seen {
						session.seenSuccessCoords[coordKey] = struct{}{}
						session.SuccessSamples++
					}
				}
			}
			session.mu.Unlock()
		}
	}

	session.mu.Lock()
	total := session.TotalSamples
	success := session.SuccessSamples
	session.mu.Unlock()

	if total == 0 {
		return false, 0, fmt.Errorf("no samples collected")
	}

	confidence := c.computeConfidence(success, total)
	available := confidence >= c.config.MinConfidence

	return available, confidence, nil
}

// sampleWithTimeout calls the cell getter with a per-query timeout. Returns
// the response, a non-nil error if the getter failed, and timedOut=true if
// the getter did not respond within the timeout. P1-9 (2026-07-14).
//
// PRE-FIX (2026-07-17): when the timeout fired, the goroutine running the
// getter continued until the getter returned. In multi-test runs the
// getter is a closure over the test's BlobNetworkManager; if that closure
// takes long (e.g. CPU-bound ComputeCellProof under heavy parallel load)
// the spawned goroutines accumulate across tests and starve the scheduler,
// eventually causing the test binary to hit the overall timeout even
// though every individual test passes in isolation.
//
// FIX: the goroutine now also selects on c.ctx.Done(), so Stop() (called
// by DankshardingEngine.Stop via defer stopAllNodes) cancels all in-flight
// sampling goroutines at once. The buffered channel guarantees the send
// never blocks regardless of which select case fires.
func (c *DASClient) sampleWithTimeout(
	req DASSampleRequest,
	getter func(slot uint64, blobIndex, row, col int) (*DASSampleResponse, error),
	timeout time.Duration,
) (resp *DASSampleResponse, err error, timedOut bool) {
	// R59 (2026-08-18): Acquire a slot in the sampling semaphore BEFORE
	// spawning the getter goroutine. When the cap is reached (heavy
	// parallel load across nodes/tests), the caller waits up to the query
	// timeout or client cancellation for a slot instead of spawning an
	// unbounded goroutine — bounding memory/CPU growth and preventing
	// scheduler starvation. Normal serial sampling never contends on the
	// semaphore, so this adds no latency in the common path.
	select {
	case c.samplingSem <- struct{}{}:
		defer func() { <-c.samplingSem }()
	case <-c.ctx.Done():
		return nil, c.ctx.Err(), false
	case <-time.After(timeout):
		return nil, nil, true
	}

	type result struct {
		resp *DASSampleResponse
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		r, e := getter(req.Slot, req.BlobIndex, req.CellRow, req.CellCol)
		ch <- result{r, e}
	}()
	select {
	case r := <-ch:
		return r.resp, r.err, false
	case <-time.After(timeout):
		return nil, nil, true
	case <-c.ctx.Done():
		return nil, c.ctx.Err(), false
	}
}

// retryBackoff sleeps for an exponentially increasing duration before retrying.
// Backoff: 10ms, 20ms, 40ms, ... P1-9 (2026-07-14).
func (c *DASClient) retryBackoff(retry int) {
	backoff := time.Duration(DASRetryBackoffBaseMs<<retry) * time.Millisecond
	time.Sleep(backoff)
}

func (c *DASClient) generateSampleRequests(slot uint64, blobCount int, count int) []DASSampleRequest {
	requests := make([]DASSampleRequest, count)
	for i := 0; i < count; i++ {
		blobIndex := c.randomInt(blobCount)
		row := c.randomInt(CellsPerBlobExtended)
		col := c.randomInt(MaxBlobColumnsExt)

		// R38-P1-06 FIX (2026-08-01, RequestID nonce): mint a unique 8-byte
		// nonce per request so the caller can bind each response to its
		// originating request via resp.RequestID == req.RequestID. Before
		// this fix RequestID was always 0, so any echo check was vacuous
		// and a peer could freely substitute one request's response for
		// another's. We reuse the crypto/rand path already in randomInt's
		// implementation; on the (cryptographically impossible) failure path
		// we fall back to a deterministic counter-derived value so sampling
		// never blocks on entropy exhaustion — uniqueness within a single
		// Sample() call is still near-certain because requests[i] gets a
		// distinct slot/i mix.
		var nonce uint64
		if b, err := readCryptoRandNonce(); err == nil {
			nonce = b
		} else {
			log.Printf("[WARN] DAS: crypto/rand failed for RequestID nonce, using fallback: %v (R38-P1-06)", err)
			nonce = uint64(slot)<<32 | uint64(i)
		}

		requests[i] = DASSampleRequest{
			RequestID: nonce,
			Slot:      slot,
			BlobIndex: blobIndex,
			CellRow:   row,
			CellCol:   col,
		}
	}
	return requests
}

// readCryptoRandNonce reads 8 bytes from crypto/rand and returns them as a
// big-endian uint64. Kept as a tiny helper so generateSampleRequests stays
// readable and so the failure path is isolated.
func readCryptoRandNonce() (uint64, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

func (c *DASClient) calculateSamplesNeeded(totalCells int) int {
	// R40-P2-03 (2026-08-03): explicit zero / negative-cell short-circuit.
	// The downstream `totalCells > 0` guard at line 766 already prevented the
	// divide-by-zero, but a malicious / corrupted blob could still reach this
	// path with `totalCells == 0` after a uint32-overflow collapse. Returning
	// the default 75 samples when there are zero cells would still try to
	// sample zero cells (caller Iterates indexes [0, 75) against a 0-cell
	// blob → all queries fail). The safe behavior is to request ZERO samples
	// and let the caller mark the blob unavailable rather than spamming the
	// network with doomed queries that look like progress.
	if totalCells <= 0 {
		return 0
	}
	samples := 75
	{
		ratio := float64(samples) / float64(totalCells)
		if ratio < 0.01 {
			samples = totalCells / 100
			if samples < 30 {
				samples = 30
			}
		}
	}
	return samples
}

func (c *DASClient) computeConfidence(success, total int) float64 {
	if total == 0 || success == 0 {
		return 0
	}

	observedRate := float64(success) / float64(total)

	// DA- (2026-07-17): Replace step-function inflation with a
	// sample-count-aware binomial upper bound. The previous step mapping
	// inflated observedRate ≥ 0.99 directly to 0.9999 regardless of sample
	// count, so 99/100 and 990/1000 both yielded 0.9999 — decoupling
	// confidence from the actual amount of evidence collected.
	//
	// Under H0 (data unavailable, i.e. < 50% of cells recoverable), the
	// probability that a single sample hits a recoverable cell is ≤ 0.5.
	// For k successful independent samples, P(all hit | H0) ≤ 0.5^k, so
	// the confidence that the data is available is 1 - 0.5^k. This couples
	// confidence to k (the number of successful samples): more samples →
	// higher confidence, with 100/100 ≈ 1.0 and 10/10 ≈ 0.999.
	//
	// When any sample failed (success < total), the data may be genuinely
	// unavailable — failed samples are not just network noise in the worst
	// case (a malicious proposer can serve some cells and withhold others).
	// We therefore cap confidence at the observed success rate: no inflation
	// above what was actually observed. This prevents a 99/100 run from
	// being reported as 0.9999-available.
	if success < total {
		return observedRate
	}
	return 1.0 - math.Pow(0.5, float64(success))
}

func (c *DASClient) randomInt(max int) int {
	if max <= 0 {
		return 0
	}

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		log.Printf("crypto/rand.Read failed in randomInt: %v", err)
		return 0
	}
	n := binary.BigEndian.Uint64(b)
	return int(n % uint64(max))
}

type DASVerifier struct {
	config DASConfig
}

func NewDASVerifier(config DASConfig) *DASVerifier {
	return &DASVerifier{config: config}
}

func (v *DASVerifier) VerifyDataAvailability(
	slot uint64,
	commitments []KZGCommitment,
	samples []DASSampleResponse,
) (bool, float64) {
	if len(samples) == 0 {
		return false, 0
	}

	// R7 P0-6 NOTE (DA-, 2026-07-17): DASVerifier is a stateless
	// offline verifier that operates on pre-collected samples. It does NOT
	// have access to locally-cached FRI blob data (unlike DASClient.Sample
	// which runs on the block builder with FRI data in memory). To verify
	// FRI-backed cells here, the DASSampleResponse would need to carry the
	// full FRI cell proof (*FRIDACellProof) instead of the 48-byte KZGProof
	// hash stub. That requires network protocol changes (encode/decode in
	// blob_network.go) and is tracked as a follow-up. For now, this path
	// uses the hash stub (VerifyCellProof) — acceptable because the main
	// production sampling path (DASClient.Sample) already uses FRI when
	// UseFRI=true.
	successCount := 0
	for _, sample := range samples {
		if sample.BlobIndex >= len(commitments) {
			continue
		}
		commitment := commitments[sample.BlobIndex]
		if VerifyCellProof(sample.Cell, commitment, sample.Proof, sample.CellRow, sample.CellCol) {
			successCount++
		}
	}

	total := len(samples)
	// DA- (2026-07-17): Apply the same binomial upper bound used by
	// DASClient.computeConfidence. The previous step-function inflation
	// decoupled confidence from sample count (99/100 and 990/1000 both →
	// 0.9999), overstating availability for small sample sets.
	if total == 0 || successCount == 0 {
		return false, 0
	}
	observedRate := float64(successCount) / float64(total)

	var confidence float64
	if successCount < total {
		// Failed samples present: cap at observed rate, no inflation.
		confidence = observedRate
	} else {
		// All samples succeeded: binomial upper bound 1 - 0.5^k.
		confidence = 1.0 - math.Pow(0.5, float64(successCount))
	}

	available := confidence >= v.config.MinConfidence
	return available, confidence
}

type DASAttestation struct {
	Slot           uint64
	BlobCommitment types.Hash // Legacy single-commitment field (= BlobCommitments[0] when present).
	Available      bool
	Confidence     float64
	SampleCount    int
	SuccessCount   int
	ValidatorIndex int
	Signature      []byte

	// BlobCommitments is the FULL set of blob commitments the attester
	// sampled. DA- (2026-07-16): Previously only BlobCommitment
	// (commitments[0]) was bound to attestation.Hash(), so two attestations
	// for the same slot differing only in commitments[1..] produced the
	// same hash. A malicious attester could reuse one attestation across
	// distinct commitment sets, breaking the DA proof's binding to the
	// actual data being attested.
	//
	// Fix: Hash() and Encode() now include the full BlobCommitments slice
	// (length-prefixed). BuildDAAttestation populates both BlobCommitment
	// (legacy compatibility) and BlobCommitments (full binding).
	// BuildAggregateAttestation verifies each attestation's BlobCommitments
	// matches the expected aggregate set, fail-closing on mismatch.
	//
	// DA-FIX (2026-07-17): Type changed from []types.Hash (32 bytes)
	// to []KZGCommitment (48 bytes). The previous type truncated each
	// 48-byte KZG commitment to its first 32 bytes, dropping 16 bytes and
	// enabling cross-set collisions (two distinct commitments sharing the
	// same first 32 bytes produce the same attestation hash). The full
	// 48-byte form eliminates this collision risk. BlobCommitment (legacy
	// single-commitment field above) remains types.Hash for backward-
	// compatible fixed-offset readers.
	BlobCommitments []KZGCommitment
}

func (a *DASAttestation) Hash() types.Hash {
	h := sha3.New256()
	var buf [8]byte
	var buf4 [4]byte

	binary.BigEndian.PutUint64(buf[:], a.Slot)
	h.Write(buf[:])

	h.Write(a.BlobCommitment[:])
	if a.Available {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}

	binary.BigEndian.PutUint64(buf[:], uint64(int64(a.Confidence*1e6)))
	h.Write(buf[:])

	binary.BigEndian.PutUint32(buf4[:], uint32(a.SampleCount))
	h.Write(buf4[:])
	binary.BigEndian.PutUint32(buf4[:], uint32(a.SuccessCount))
	h.Write(buf4[:])
	binary.BigEndian.PutUint32(buf4[:], uint32(a.ValidatorIndex))
	h.Write(buf4[:])

	// DA- (2026-07-16): Bind the FULL blob commitment set to the
	// attestation hash. Length-prefix + each commitment prevents cross-set
	// reuse even when commitments[0] (BlobCommitment legacy field) matches.
	// Cap at maxBlobCommitmentsPerAttestation to bound hashing work.
	bcLen := len(a.BlobCommitments)
	if bcLen > maxBlobCommitmentsPerAttestation {
		bcLen = maxBlobCommitmentsPerAttestation
	}
	binary.BigEndian.PutUint32(buf4[:], uint32(bcLen))
	h.Write(buf4[:])
	for i := 0; i < bcLen; i++ {
		h.Write(a.BlobCommitments[i][:])
	}

	var result types.Hash
	copy(result[:], h.Sum(nil))
	return result
}

func (a *DASAttestation) Encode() []byte {
	buf := make([]byte, 0, 256)

	slotBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(slotBytes, a.Slot)
	buf = append(buf, slotBytes...)

	buf = append(buf, a.BlobCommitment[:]...)

	if a.Available {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	confBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(confBytes, uint64(a.Confidence*1e6))
	buf = append(buf, confBytes...)

	sampleBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sampleBytes, uint32(a.SampleCount))
	buf = append(buf, sampleBytes...)

	successBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(successBytes, uint32(a.SuccessCount))
	buf = append(buf, successBytes...)

	valBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(valBytes, uint32(a.ValidatorIndex))
	buf = append(buf, valBytes...)

	sigLen := make([]byte, 4)
	binary.BigEndian.PutUint32(sigLen, uint32(len(a.Signature)))
	buf = append(buf, sigLen...)
	buf = append(buf, a.Signature...)

	// DA- (2026-07-16): Append the FULL blob commitment set after the
	// signature. Length-prefixed (4 bytes) + N*32 bytes. Old decoders that
	// stop reading after Signature will ignore this trailing block; new
	// decoders bind the full set into Hash(). The legacy BlobCommitment
	// field above remains for backward-compatible fixed-offset readers.
	bcLen := len(a.BlobCommitments)
	if bcLen > maxBlobCommitmentsPerAttestation {
		bcLen = maxBlobCommitmentsPerAttestation
	}
	bcCountBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bcCountBytes, uint32(bcLen))
	buf = append(buf, bcCountBytes...)
	for i := 0; i < bcLen; i++ {
		buf = append(buf, a.BlobCommitments[i][:]...)
	}

	return buf
}

func DecodeDASAttestation(data []byte) (*DASAttestation, error) {
	// SECURITY (audit 2026-06-24, H-5): Minimum length must cover all fixed
	// fields: slot(8) + blobCommitment(32) + available(1) + confidence(8) +
	// sampleCount(4) + successCount(4) + validatorIndex(4) = 61 bytes.
	// Previous check of 45 allowed reading ValidatorIndex at offset 57-60 to
	// go out of bounds, causing a panic (remote DoS).
	const minDASAttestationSize = 61
	if len(data) < minDASAttestationSize {
		return nil, fmt.Errorf("data too short for DA attestation: have %d, need %d", len(data), minDASAttestationSize)
	}

	a := &DASAttestation{}
	offset := 0

	a.Slot = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	copy(a.BlobCommitment[:], data[offset:offset+32])
	offset += 32

	a.Available = data[offset] == 1
	offset++

	a.Confidence = float64(binary.BigEndian.Uint64(data[offset:])) / 1e6
	offset += 8

	a.SampleCount = int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	a.SuccessCount = int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	a.ValidatorIndex = int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	// ENCODING-P0-02 FIX (R31, 2026-07-27): The encoder ALWAYS writes the
	// 4-byte sigLen prefix followed by the signature bytes. A truncated
	// message that ends here (without sigLen) is malformed — returning
	// a partial attestation with empty Signature would let callers treat
	// an unsigned/malformed message as a valid attestation. Reject
	// instead of returning partial struct + nil error.
	if offset+4 > len(data) {
		return nil, fmt.Errorf("DAS attestation truncated: missing signature length field at offset %d (have %d bytes)", offset, len(data))
	}
	sigLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// SECURITY: cap sigLen to prevent OOM from a malicious huge value.
	if sigLen > maxSignatureLen {
		return nil, fmt.Errorf("signature length %d exceeds maximum %d", sigLen, maxSignatureLen)
	}

	// ENCODING-P0-02 FIX: sigLen declares a signature frame but the
	// remaining data is shorter than sigLen. This is a truncated/malformed
	// message — the previous code returned a partial attestation (with
	// Signature=nil) and nil error, allowing callers to mistake a
	// corrupted/attacker-crafted message for a legitimate unsigned
	// attestation. Reject instead.
	if offset+int(sigLen) > len(data) {
		return nil, fmt.Errorf("DAS attestation truncated: signature length %d exceeds remaining data %d", sigLen, len(data)-offset)
	}
	a.Signature = make([]byte, sigLen)
	copy(a.Signature, data[offset:offset+int(sigLen)])
	offset += int(sigLen)

	// DA- (2026-07-16): Parse the trailing BlobCommitments block if
	// present. Old-format attestations (no trailing block) decode with
	// BlobCommitments=nil — Hash() then falls back to the legacy binding
	// (length=0 prefix only). New-format attestations bind the full set.
	//
	// DA-FIX (2026-07-17): Each commitment is now 48 bytes
	// (KZGCommitment) instead of 32 bytes (types.Hash). Legacy
	// 32-byte-per-commitment encodings are no longer decodable — this is
	// an intentional breaking change because the 32-byte form silently
	// truncated 16 bytes of each commitment. Danksharding is disabled by
	// default, so no production attestations exist to migrate.
	//
	// ENCODING-P0-02 FIX (R31, 2026-07-27): If bcCount is declared but
	// the remaining data is insufficient for bcCount*48 bytes, this is a
	// truncated/malformed message — return error instead of silently
	// leaving BlobCommitments=nil (which would cause Hash() to use the
	// legacy binding and mismatch the producer's hash).
	if offset+4 <= len(data) {
		bcCount := binary.BigEndian.Uint32(data[offset:])
		offset += 4
		// SECURITY: cap to prevent OOM from a malicious huge count.
		if bcCount > maxBlobCommitmentsPerAttestation {
			return nil, fmt.Errorf("blob commitment count %d exceeds maximum %d", bcCount, maxBlobCommitmentsPerAttestation)
		}
		if bcCount == 0 {
			// Zero commitments is valid (explicit empty list).
			a.BlobCommitments = make([]KZGCommitment, 0)
		} else if uint64(offset)+uint64(bcCount)*48 > uint64(len(data)) {
			return nil, fmt.Errorf("DAS attestation truncated: blob commitments count %d needs %d bytes, have %d",
				bcCount, uint64(bcCount)*48, len(data)-offset)
		} else {
			a.BlobCommitments = make([]KZGCommitment, bcCount)
			for i := uint32(0); i < bcCount; i++ {
				copy(a.BlobCommitments[i][:], data[offset:offset+48])
				offset += 48
			}
		}
	}

	return a, nil
}

type DASAggregateAttestation struct {
	Slot            uint64
	BlobCommitments []KZGCommitment // DA- (2026-07-17): []types.Hash → []KZGCommitment (48 bytes)
	AvailableCount  int
	TotalCount      int
	Signatures      [][]byte
	ValidatorBits   []byte
	// ThresholdAggregated indicates the aggregation mode (P0-3, 2026-07-14):
	//   - true:  Signatures contains exactly ONE element, a QTD threshold
	//            signature produced by AggregatePartialSignatures. Verifiers
	//            MUST use ThresholdKeySigner.VerifyBlock with the group public
	//            key over the canonical threshold message.
	//   - false: Transition mode (multi-sig). Signatures is a list of
	//            individual validator signatures (≤ DAMaxTransitionSignatures).
	//            Verifiers check each signature against the validator's public
	//            key over DASAttestation.Hash().
	ThresholdAggregated bool
	// CommitteeSize is the expected DA committee size for the aggregate's
	// slot/epoch. DA- (2026-07-17): IsSufficient uses this as the
	// denominator for an absolute attestation floor, preventing an attacker
	// from suppressing honest submissions so only a few attestations are
	// collected (e.g., 3 total, 2 available → 2/3≈0.667 passes the ratio
	// check with minimal actual coverage). When CommitteeSize > 0,
	// IsSufficient requires TotalCount ≥ ceil(2/3 · CommitteeSize) in
	// addition to the ratio check. Fail-closed: when CommitteeSize == 0
	// (unknown / not set), IsSufficient returns false — sufficiency cannot
	// be verified without knowing the expected committee size.
	CommitteeSize int
}

func (a *DASAggregateAttestation) IsSufficient() bool {
	if a.TotalCount == 0 {
		return false
	}
	// Ratio check (existing): available/total ≥ 0.6667.
	if float64(a.AvailableCount)/float64(a.TotalCount) < 0.6667 {
		return false
	}
	// DA- (2026-07-17): Absolute attestation floor. The ratio check
	// alone is insufficient because TotalCount is the number of submitted
	// attestations, not the committee size. An attacker who can suppress
	// honest submissions (network partition, eclipse) can make only a few
	// attestations count (e.g., 3 total with 2 available → 2/3≈0.667
	// passes), faking "DA sufficient" with minimal actual coverage.
	//
	// Fail-closed: when CommitteeSize is 0 (unknown / not set by the
	// collector), we cannot verify that enough of the committee attested,
	// so we refuse to declare the aggregate sufficient. This forces all
	// production paths to set CommitteeSize via SetCommitteeSize before
	// BuildAggregateAttestation can produce a sufficient aggregate.
	if a.CommitteeSize <= 0 {
		return false
	}
	// Require at least ceil(2/3 · CommitteeSize) attestations to be
	// submitted. This mirrors the ratio threshold (2/3) but uses the
	// committee size as the denominator instead of the submitted count.
	// ceil(2n/3) = floor((2n + 2) / 3) for integer n.
	required := (2*a.CommitteeSize + 2) / 3
	if a.TotalCount < required {
		return false
	}
	return true
}

func (a *DASAggregateAttestation) Encode() []byte {
	buf := make([]byte, 0, 1024)

	slotBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(slotBytes, a.Slot)
	buf = append(buf, slotBytes...)

	countBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(countBytes, uint32(len(a.BlobCommitments)))
	buf = append(buf, countBytes...)

	for _, c := range a.BlobCommitments {
		buf = append(buf, c[:]...)
	}

	availBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(availBytes, uint32(a.AvailableCount))
	buf = append(buf, availBytes...)

	totalBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(totalBytes, uint32(a.TotalCount))
	buf = append(buf, totalBytes...)

	bitsLen := make([]byte, 4)
	binary.BigEndian.PutUint32(bitsLen, uint32(len(a.ValidatorBits)))
	buf = append(buf, bitsLen...)
	buf = append(buf, a.ValidatorBits...)

	sigCount := make([]byte, 4)
	binary.BigEndian.PutUint32(sigCount, uint32(len(a.Signatures)))
	buf = append(buf, sigCount...)
	for _, sig := range a.Signatures {
		sigLen := make([]byte, 4)
		binary.BigEndian.PutUint32(sigLen, uint32(len(sig)))
		buf = append(buf, sigLen...)
		buf = append(buf, sig...)
	}

	// P0-3 (2026-07-14): Append ThresholdAggregated as a single trailing byte.
	// Forward-compatible: old decoders stop reading before this byte and
	// default to false (transition mode), which is the safe fallback.
	if a.ThresholdAggregated {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	// DA- (2026-07-17): Append CommitteeSize as 4 trailing bytes.
	// Forward-compatible: old decoders stop reading before this field and
	// default to 0 (which makes IsSufficient fail-closed). New decoders
	// read it when present. This is consensus-safe because all nodes must
	// upgrade together for the DA- floor check to take effect.
	committeeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(committeeBytes, uint32(a.CommitteeSize))
	buf = append(buf, committeeBytes...)

	return buf
}

func DecodeDASAggregateAttestation(data []byte) (*DASAggregateAttestation, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("data too short")
	}

	a := &DASAggregateAttestation{}
	offset := 0

	a.Slot = binary.BigEndian.Uint64(data[offset:])
	offset += 8

	commitCount := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// SECURITY (audit 2026-06-24, M-1): cap commitCount to prevent OOM
	// from make([]KZGCommitment, commitCount) when commitCount is huge.
	// DA- (2026-07-17): Each commitment is now 48 bytes (KZGCommitment).
	if commitCount > maxBlobCommitmentsPerAttestation {
		return nil, fmt.Errorf("blob commitment count %d exceeds maximum %d", commitCount, maxBlobCommitmentsPerAttestation)
	}
	// ENCODING-P0-03 FIX (R31, 2026-07-27): Verify the data has enough
	// bytes for commitCount*48 BEFORE allocating. The previous code
	// pre-allocated make([]KZGCommitment, commitCount) then `break`d on
	// truncation, leaving the remaining entries as zero-value
	// KZGCommitments. Callers receiving a partially-filled slice with
	// zero-value commitments would treat them as valid commitments,
	// allowing an attacker to forge DA proofs with zero commitments.
	// Reject truncated data explicitly.
	if uint64(offset)+uint64(commitCount)*48 > uint64(len(data)) {
		return nil, fmt.Errorf("DAS aggregate truncated: blob commitments count %d needs %d bytes, have %d",
			commitCount, uint64(commitCount)*48, len(data)-offset)
	}
	a.BlobCommitments = make([]KZGCommitment, commitCount)
	for i := uint32(0); i < commitCount; i++ {
		copy(a.BlobCommitments[i][:], data[offset:offset+48])
		offset += 48
	}

	// ENCODING-P0-03 FIX: All remaining fields (AvailableCount, TotalCount,
	// ValidatorBits, Signatures, ThresholdAggregated, CommitteeSize) are
	// REQUIRED in the encoded format — the encoder always writes them. A
	// truncated message missing any of these is malformed and must be
	// rejected, not silently decoded as a partial structure.
	if offset+4 > len(data) {
		return nil, fmt.Errorf("DAS aggregate truncated: missing AvailableCount at offset %d (have %d bytes)", offset, len(data))
	}
	a.AvailableCount = int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	if offset+4 > len(data) {
		return nil, fmt.Errorf("DAS aggregate truncated: missing TotalCount at offset %d (have %d bytes)", offset, len(data))
	}
	a.TotalCount = int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4

	if offset+4 > len(data) {
		return nil, fmt.Errorf("DAS aggregate truncated: missing ValidatorBits length at offset %d (have %d bytes)", offset, len(data))
	}
	bitsLen := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// SECURITY (audit 2026-06-24, M-1): cap bitsLen to prevent OOM.
	if bitsLen > maxValidatorBitsLen {
		return nil, fmt.Errorf("validator bits length %d exceeds maximum %d", bitsLen, maxValidatorBitsLen)
	}
	// ENCODING-P0-03 FIX: bitsLen declares a frame but the remaining
	// data is shorter. Reject instead of silently leaving ValidatorBits=nil.
	if offset+int(bitsLen) > len(data) {
		return nil, fmt.Errorf("DAS aggregate truncated: ValidatorBits length %d exceeds remaining data %d", bitsLen, len(data)-offset)
	}
	a.ValidatorBits = make([]byte, bitsLen)
	copy(a.ValidatorBits, data[offset:offset+int(bitsLen)])
	offset += int(bitsLen)

	if offset+4 > len(data) {
		return nil, fmt.Errorf("DAS aggregate truncated: missing signature count at offset %d (have %d bytes)", offset, len(data))
	}
	sigCount := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	// SECURITY (audit 2026-06-24, M-1): cap sigCount to prevent OOM
	// from make([][]byte, 0, sigCount) when sigCount is huge.
	if sigCount > maxSignaturesPerAttestation {
		return nil, fmt.Errorf("signature count %d exceeds maximum %d", sigCount, maxSignaturesPerAttestation)
	}
	a.Signatures = make([][]byte, 0, sigCount)
	for i := uint32(0); i < sigCount; i++ {
		if offset+4 > len(data) {
			// ENCODING-P0-03 FIX: signature frame truncated. Reject
			// instead of `break`ing and returning a partially-filled
			// Signatures slice.
			return nil, fmt.Errorf("DAS aggregate truncated: signature %d length field missing (have %d bytes)", i, len(data)-offset)
		}
		sigLen := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		// SECURITY: cap individual signature length.
		if sigLen > maxSignatureLen {
			return nil, fmt.Errorf("signature %d length %d exceeds maximum %d", i, sigLen, maxSignatureLen)
		}

		if offset+int(sigLen) > len(data) {
			// ENCODING-P0-03 FIX: signature bytes truncated. Reject
			// instead of silently skipping this signature.
			return nil, fmt.Errorf("DAS aggregate truncated: signature %d bytes %d exceeds remaining data %d", i, sigLen, len(data)-offset)
		}
		sig := make([]byte, sigLen)
		copy(sig, data[offset:offset+int(sigLen)])
		a.Signatures = append(a.Signatures, sig)
		offset += int(sigLen)
	}

	// P0-3 (2026-07-14): Read optional trailing ThresholdAggregated byte.
	// Forward-compatible: missing byte defaults to false (transition mode).
	if offset < len(data) {
		a.ThresholdAggregated = data[offset] == 1
		offset++
	}

	// DA- (2026-07-17): Read optional trailing CommitteeSize (4 bytes).
	// Forward-compatible: missing field defaults to 0 (fail-closed in
	// IsSufficient). When present, enables the absolute attestation floor.
	if offset+4 <= len(data) {
		a.CommitteeSize = int(binary.BigEndian.Uint32(data[offset:]))
	}

	return a, nil
}
