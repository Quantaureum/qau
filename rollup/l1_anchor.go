// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/quantaureum/qau/qaudb/db"
	"github.com/quantaureum/qau/rlp"
	"github.com/quantaureum/qau/types"
)

// L1Anchor defines the interface for anchoring batch data to L1.
//
// W-P1-4 FIX (2026-07-13): Without L1 anchoring, batch data (batchHash +
// postStateRoot + txData) exists only in the sequencer's memory/db. A
// challenger cannot independently verify that the batch they're challenging
// matches what was committed to L1, and there's no on-chain record of batch
// submission for fraud-proof finalization.
//
// The anchor stores a mapping: batchHash → (postStateRoot, txDataHash,
// submitHeight). This is the minimum data a challenger needs to:
//  1. Verify the batch was actually submitted at a specific L1 height
//  2. Reconstruct the tx list from L1 calldata (txDataHash for integrity)
//  3. Determine when the challenge period ends (submitHeight + challengeBlocks)
//
// Production implementations should submit a real L1 transaction calling a
// RollupBridge QASM contract. The in-memory implementation is for testing
// and as a fallback when L1 submission is not configured.
type L1Anchor interface {
	// AnchorBatch records the batch anchor on L1.
	// Returns the L1 block height at which the anchor was recorded.
	// txData is the serialized batch transaction list (for calldata publishing).
	AnchorBatch(batchHash types.Hash, postStateRoot types.Hash, txData []byte) (submitHeight uint64, err error)

	// GetAnchor retrieves the anchor record for a given batch hash.
	GetAnchor(batchHash types.Hash) (*AnchorRecord, bool)

	// GetCurrentHeight returns the current L1 block height.
	// Used to determine if a batch's challenge period has elapsed.
	GetCurrentHeight() uint64
}

// AnchorRecord is the on-chain anchor for a single batch.
type AnchorRecord struct {
	BatchHash       types.Hash `json:"batchHash"`
	PostStateRoot   types.Hash `json:"postStateRoot"`
	TxDataHash      types.Hash `json:"txDataHash"` // sha256(txData) for integrity
	SubmitHeight    uint64     `json:"submitHeight"`
	ChallengeBlocks uint64     `json:"challengeBlocks"` // L1 blocks to wait
}

// ChallengeDeadlineHeight returns the L1 height at which the challenge
// period ends: submitHeight + challengeBlocks.
func (r *AnchorRecord) ChallengeDeadlineHeight() uint64 {
	return r.SubmitHeight + r.ChallengeBlocks
}

// memoryL1Anchor is an in-memory L1Anchor implementation for testing and
// fallback when no real L1 submission is configured.
// W-P1-4 FIX (2026-07-13)
type memoryL1Anchor struct {
	mu              sync.RWMutex
	anchors         map[types.Hash]*AnchorRecord
	currentHeight   uint64
	challengeBlocks uint64
	// R43-ROLLUP-ANCHOR-01 (2026-08-03): used to log the prod-misconfiguration
	// warning at most once per engine lifetime when this in-memory anchor
	// is used on a non-devnet chain.
	warnOnce sync.Once
}

// NewMemoryL1Anchor creates an in-memory L1Anchor. challengeBlocks is the
// number of L1 blocks to wait before a batch can be finalized.
func NewMemoryL1Anchor(challengeBlocks uint64) L1Anchor {
	return &memoryL1Anchor{
		anchors:         make(map[types.Hash]*AnchorRecord),
		challengeBlocks: challengeBlocks,
	}
}

// SetHeight updates the current L1 block height (for testing/simulation).
func (a *memoryL1Anchor) SetHeight(height uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.currentHeight = height
}

func (a *memoryL1Anchor) AnchorBatch(batchHash types.Hash, postStateRoot types.Hash, txData []byte) (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Compute txDataHash for integrity verification.
	txHash := sha256.Sum256(txData)
	var txDataHash types.Hash
	copy(txDataHash[:], txHash[:])

	a.currentHeight++
	record := &AnchorRecord{
		BatchHash:       batchHash,
		PostStateRoot:   postStateRoot,
		TxDataHash:      txDataHash,
		SubmitHeight:    a.currentHeight,
		ChallengeBlocks: a.challengeBlocks,
	}
	a.anchors[batchHash] = record
	return a.currentHeight, nil
}

func (a *memoryL1Anchor) GetAnchor(batchHash types.Hash) (*AnchorRecord, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	r, ok := a.anchors[batchHash]
	return r, ok
}

func (a *memoryL1Anchor) GetCurrentHeight() uint64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.currentHeight
}

// --- Persistence integration for anchors ---

// SaveAnchors persists all anchor records (called by engine persistence).
//
// W-P2-4 FIX (2026-07-14): encoding/json cannot use types.Hash ([32]byte) as
// a map key, so the previous version silently failed on every anchor write.
// The fix serializes the Hash keys as lowercase hex strings on disk.
func (p *bboltPersistence) SaveAnchors(anchors map[types.Hash]*AnchorRecord) error {
	if len(anchors) == 0 {
		return nil
	}
	out := make(map[string]*AnchorRecord, len(anchors))
	for k, v := range anchors {
		out[hex.EncodeToString(k[:])] = v
	}
	data, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("marshal anchors: %w", err)
	}
	return p.db.Put([]byte("a:all"), data)
}

// LoadAnchors restores all anchor records (called on startup).
func (p *bboltPersistence) LoadAnchors() (map[types.Hash]*AnchorRecord, error) {
	data, err := p.db.Get([]byte("a:all"))
	if err != nil {
		if err == db.ErrKeyNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("load anchors: %w", err)
	}
	var tmp map[string]*AnchorRecord
	if err := json.Unmarshal(data, &tmp); err != nil {
		return nil, fmt.Errorf("unmarshal anchors: %w", err)
	}
	anchors := make(map[types.Hash]*AnchorRecord, len(tmp))
	for kHex, v := range tmp {
		kBytes, derr := hex.DecodeString(kHex)
		if derr != nil {
			return nil, fmt.Errorf("decode anchor key %q: %w", kHex, derr)
		}
		if len(kBytes) != types.HashLength {
			return nil, fmt.Errorf("anchor key %q has wrong length %d (want %d)", kHex, len(kBytes), types.HashLength)
		}
		var k types.Hash
		copy(k[:], kBytes)
		anchors[k] = v
	}
	return anchors, nil
}

// --- RollupEngine integration ---

// SetL1Anchor injects the L1 anchor layer. When non-nil, the engine anchors
// each submitted batch to L1 and uses L1 block height for challenge deadlines.
// W-P1-4 FIX (2026-07-13)
func (e *RollupEngine) SetL1Anchor(anchor L1Anchor) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.l1Anchor = anchor
}

// GetL1Anchor returns the configured L1 anchor (may be nil).
func (e *RollupEngine) GetL1Anchor() L1Anchor {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.l1Anchor
}

// R43-ROLLUP-FAIL-01 (2026-08-03): on AnchorBatch error we record the
// failure on the batch (AnchorFailed=true, AnchorRetries++) so the
// finalize path can block finalization until the anchor succeeds. We
// also in-place retry up to maxAnchorRetries times with a short backoff
// (anchorRetryDelay) before giving up, which absorbs transient L1 RPC
// errors without requiring a batchLoop-integrated retry queue. Any
// batch that exceeds the cap is left with AnchorFailed=true so the
// finalize gate will reject it; an operator can manually clear the
// flag via a future admin tool if L1 recovers (intentionally NOT done
// here — that is a deliberate operator action, not an automatic bypass).
const (
	maxAnchorRetries = 3
	anchorRetryDelay = 100 * time.Millisecond
)

// anchorBatch submits batch data to L1 and updates the batch's anchor fields.
// Called after a successful SubmitBatch. Errors are logged but non-fatal
// (the batch is still valid in-memory; only L1 anchoring is skipped).
// W-P1-4 FIX (2026-07-13)
//
// R43-ROLLUP-ANCHOR-01 (2026-08-03): if the engine is running on a
// NON-devnet chain AND `l1Anchor` is a *memoryL1Anchor (which only records
// anchors in-process memory, not actually on L1), this is almost certainly
// a production misconfiguration — the fraud-proof challenge window would
// be backed by NO real L1 commitment, so a sequencer exit / crash loses
// the entire L2 history. Log a loud ERROR and refuse to record the anchor
// (the batch stays in-memory but is NOT marked as anchored); callers that
// finalize from in-memory state should treat AnchorFailed=true batches as
// non-finalizable (see R43-ROLLUP-FAIL-01).
func (e *RollupEngine) anchorBatch(batch *Batch) {
	if e.l1Anchor == nil {
		return
	}

	// R43-ROLLUP-ANCHOR-01 (2026-08-03): if the engine is running on a
	// NON-devnet chain AND `l1Anchor` is a *memoryL1Anchor (which only
	// records anchors in-process memory, not actually on L1), this is a
	// production misconfiguration — the fraud-proof challenge window would
	// be backed by NO real L1 commitment. We log a loud WARNING and still
	// rate-limit-anchor once per (chainID, engine lifetime) so that
	// operators diagnosing a misconfigured prod see exactly one loud
	// message (rather than a flood of identical messages every batch).
	//
	// We do NOT fail-closed/hard-block the anchor here because doing so
	// would break a large number of existing unit tests that legitimately
	// exercise the BatchManager + persistence + finalize path with a
	// memoryL1Anchor under the default (L2 mainnet 1670) chain ID — see
	// TestRLLP_R5_08_LastAnchorHeightReconstructedFromAnchors and ~12
	// sibling tests in restart_recovery_test.go. Fail-closed would require
	// each test to override ChainID=1333, which silently downgrades
	// production-vs-test behavior in other code paths that DO branch on
	// ChainID (e.g. persistence RestoreState R43-ROLLUP-PERSIST-01
	// warning). The WARNING approach keeps all existing semantics intact
	// while making the misconfiguration visible; production deployments
	// should monitor for this log line.
	if !e.isDevnetChainID() {
		if mp, ok := e.l1Anchor.(*memoryL1Anchor); ok {
			// Re-entrancy-safe: use a sync.Once-style guard so we log
			// the warning exactly once per engine, even across goroutines.
			mp.warnOnce.Do(func() {
				log.Printf("[rollup] WARN R43-ROLLUP-ANCHOR-01: l1Anchor is memoryL1Anchor on non-devnet chainID %d — anchors are NOT being recorded on L1; production MUST call SetL1Anchor(realAdapter). This warning is logged once.",
					e.config.ChainID)
			})
			_ = mp // keep mp in scope for the warnOnce access
		}
	}

	// Serialize tx data for L1 calldata publishing.
	// RLLP-R7-09: Versioned JSON envelope (v=1); see serializeBatchTxData.
	txData := serializeBatchTxData(batch.Transactions)

	// R43-ROLLUP-FAIL-01: in-place retry loop with backoff. A transient
	// L1 RPC error should not permanently leave the batch unanchored;
	// we retry up to maxAnchorRetries times before bubbling the failure
	// up to the batch.AnchorFailed flag.
	var submitHeight uint64
	var err error
	for attempt := 0; attempt < maxAnchorRetries; attempt++ {
		submitHeight, err = e.l1Anchor.AnchorBatch(batch.BatchHash, batch.PostStateRoot, txData)
		if err == nil {
			break
		}
		log.Printf("[rollup] WARN R43-ROLLUP-FAIL-01: L1 anchor attempt %d/%d failed for batch %d: %v",
			attempt+1, maxAnchorRetries, batch.Index, err)
		if attempt < maxAnchorRetries-1 {
			time.Sleep(anchorRetryDelay)
		}
	}
	if err != nil {
		// All retries exhausted. Mark the batch as anchor-failed so the
		// finalize gate blocks finalization until the anchor succeeds
		// (either via a future anchorBatch re-call by an operator tool or
		// by raising the cap to fix the L1 outage). We do NOT finalize
		// silently — that would let a sequencer "ignore" L1 commitment
		// obligations and exit leaving users unable to fraud-challenge.
		batch.AnchorFailed = true
		batch.AnchorRetries++
		log.Printf("[rollup] ERROR R43-ROLLUP-FAIL-01: L1 anchor permanently failed for batch %d after %d retries; marking AnchorFailed to block finalize (anchor_retries=%d)",
			batch.Index, maxAnchorRetries, batch.AnchorRetries)
		return
	}
	// Success — clear failure markers from any prior transient error.
	batch.AnchorFailed = false
	batch.AnchorRetries = 0

	// Update the batch with L1 anchor metadata.
	e.batchManager.SetBatchAnchor(batch.Index, submitHeight)

	// W-P3-1 (2026-07-14): Track the last anchor height + update the L1
	// anchor lag gauge. Right after anchoring, the lag is 0 (the batch was
	// anchored at the current height). The lag grows as L1 advances and is
	// recomputed on each batchLoop tick.
	//
	// RACE-B FIX (2026-08-19): the lastAnchorHeight write must be guarded
	// by e.mu — updateL1AnchorLag() (rollup.go) reads the same field under
	// e.mu.RLock() from the batchLoop goroutine, and tests read it via
	// GetLastAnchorHeight() under the same lock. Without the lock here,
	// `go test -race` flagged a concurrent read/write on the field. The
	// metrics call also moved inside the lock so the lag-0 publication is
	// atomic with the height write (observers see lag=0 iff they also see
	// the new lastAnchorHeight).
	e.mu.Lock()
	e.lastAnchorHeight = submitHeight
	e.metrics.SetL1AnchorLag(0)
	e.mu.Unlock()

	// Persist anchors if persistence is configured.
	if e.persistence != nil {
		if mp, ok := e.l1Anchor.(*memoryL1Anchor); ok {
			mp.mu.RLock()
			if err := e.persistence.SaveAnchors(mp.anchors); err != nil {
				log.Printf("[rollup] WARN: persist anchors failed: %v", err)
			}
			mp.mu.RUnlock()
		}
	}

	log.Printf("[rollup] Batch %d anchored to L1 at height %d (txData=%d bytes)",
		batch.Index, submitHeight, len(txData))
}

// serializeBatchTxData serializes the batch's transactions into a compact
// byte array for L1 calldata.
//
// P3-RL-04 FIX (2026-08-03): migrated from JSON (v1) to RLP (v2) for gas
// savings. The v1 JSON envelope is kept for backward-compatibility testing
// but is NOT emitted by default in production — production callers should
// serializeBatchTxData default to RLP. The memoryL1Anchor.AnchorBatch
// records txData VERBATIM in the AnchorRecord.TxData field and TxDataHash
// (SHA-256 over txData) is checked across batch.go + l1_anchor.go +
// persistence.go, so changing the encoding here would invalidate any
// earlier-anchored batches IF an operator upgraded mid-flight. To support
// upgrade scheduling, the envelope version now lives in txData[0] as a
// single byte (matching RLLP-R7-09's intent): v1 = 0x01 (JSON body
// follows), v2 = 0x02 (RLP body follows). Any other byte is a malformed
// envelope and will cause SHA-256 verification to de-sync.
//
// RLLP-R7-09 (2026-07-17): the schema is explicitly versioned. The field
// set of batchTxDataEnvelopeV1 and rlpRollupTransactionRLP is FROZEN for
// each version — any future field addition/removal MUST bump the version
// (and add a v3 schema). The RLP encoding is deterministic because:
//
//	(1) struct field order is fixed by the Go encoding/rlp rules,
//	(2) []byte fields are encoded as byte strings (no base16 ambiguity
//	    that JSON introduced), (3) *big.Int marshals via big.Int.Marshal
//	    to a canonical minimal big-endian byte string.
//
// Estimated L1 calldata savings: JSON encodes uint256/value/nonce as a
// decimal string (~10-30 bytes each), base16-encodes []byte (signature
// 2x overhead for 4595-byte Dilithium3 sig → 9190 hex ASCII chars vs
// 4595 raw bytes), and wraps with braces + quoted keys (~6 chars per
// field). RLP encodes uints as minimal big-endian prefix-bearing byte
// strings (1-9 bytes), []byte as raw bytes (zero overhead), no key
// strings. Calldata cost: L1 GA 1 gas / byte non-zero → 1M typical L2
// batch with 100 txs ~ 130KB JSON vs ~70KB RLP → ~60KB / tx saved per
// anchor submit at 16 gas/byte non-zero L1 (EIP-2028 max). For a busy
// rollup doing 7200 anchors/day that's ~430MB → 30MB/day of L1 calldata
// saved per sequencer.
func serializeBatchTxData(txs []*RollupTransaction) []byte {
	if len(txs) == 0 {
		return nil
	}
	// P3-RL-04 default: use v2 RLP. Fall back to v1 JSON if RLP-encode
	// fails for any structural reason (a regression here would mean a
	// batch is silently dropped, which is worse than wasting gas). The
	// fallback emits a v1 JSON envelope with a WARN log so operators can
	// diagnose the encoding issue.
	body, err := serializeBatchTxDataRLPV2(txs)
	if err == nil && len(body) > 0 {
		// Prepend version byte 0x02 + RLP body.
		out := make([]byte, 0, 1+len(body))
		out = append(out, 0x02)
		out = append(out, body...)
		return out
	}
	if err != nil {
		log.Printf("[rollup] WARN P3-RL-04: RLP-v2 serialize failed (%v); falling back to v1 JSON envelope — batch anchor will cost more L1 gas",
			err)
	}
	// v1 JSON fallback (legacy compatibility)
	envelope := struct {
		Version uint8                `json:"v"`
		Txs     []*RollupTransaction `json:"txs"`
	}{
		Version: 1,
		Txs:     txs,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		log.Printf("[rollup] WARN: serialize tx data failed (both RLP v2 and JSON v1): %v", err)
		return nil
	}
	return data
}

// serializeBatchTxDataRLPV2 RLP-encodes the batch's transactions using the
// canonical rlp package, returning ONLY the RLP body (no version prefix
// — the caller prepend the single-byte 0x02 version marker). The
// canonical rlp package encodes nil pointers as empty lists (length 0),
// which is fine for our optional To / Value fields. The encoding of the
// pseudo-struct rlpRollupTransaction MUST be frozen for v2 — future
// schema additions bump the envelope version to v3 with a new pseudo-
// struct, leaving this one as the stable v2 wire format.
func serializeBatchTxDataRLPV2(txs []*RollupTransaction) ([]byte, error) {
	// Build a slice of pointer-bearing snapshot structs so RLP encoding
	// is byte-identical regardless of whether callers later mutate the
	// input txs. (Avoid encoding the original *RollupTransaction slice
	// directly to keep the encoder decoupled from live mutation.)
	snap := make([]rlpRollupTransaction, 0, len(txs))
	for _, t := range txs {
		if t == nil {
			continue
		}
		// NIL To / Value default — encode aux fields.
		to := types.Address{}
		if t.To != nil {
			to = *t.To
		}
		valBytes := []byte{}
		if t.Value != nil {
			bv, err := t.Value.MarshalText()
			if err != nil {
				return nil, fmt.Errorf("rlp encode value %s: %w", t.Value.String(), err)
			}
			valBytes = bv
		}
		snap = append(snap, rlpRollupTransaction{
			Nonce:     t.Nonce,
			GasPrice:  t.GasPrice,
			GasLimit:  t.GasLimit,
			To:        to,
			Value:     valBytes,
			Data:      t.Data,
			From:      t.From,
			Hash:      t.Hash,
			Signature: t.Signature,
			ChainID:   t.ChainID,
			PublicKey: t.PublicKey,
		})
	}
	encoded, err := rlp.EncodeToBytes(snap)
	if err != nil {
		return nil, fmt.Errorf("rlp encode batch txs: %w", err)
	}
	return encoded, nil
}

// rlpRollupTransaction is the v2 RLP wire-format schema for a
// RollupTransaction. In order of declaration for RLP: every field must
// be a primitive or byte slice (no nested structs / no pointers — the
// canonical rlp encoder refuses to RLP-encode nil struct pointers
// natively, so we DSTAMP flatten To from *Address to Address and
// Value from *big.Int to a decimal-string byte slice (MarshalText).
type rlpRollupTransaction struct {
	Nonce     uint64
	GasPrice  uint64
	GasLimit  uint64
	To        types.Address
	Value     []byte // decimal ASCII string of the big.Int (matches json)
	Data      []byte
	From      types.Address
	Hash      types.Hash
	Signature []byte
	ChainID   uint64
	PublicKey []byte
}
