// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

type FraudProofVerifier interface {
	HasFraudProof(batchIndex uint64) bool
}

type BatchStatus uint8

const (
	BatchStatusPending    BatchStatus = 0
	BatchStatusSubmitted  BatchStatus = 1
	BatchStatusFinalized  BatchStatus = 2
	BatchStatusChallenged BatchStatus = 3
	BatchStatusRejected   BatchStatus = 4
)

type Batch struct {
	Index             uint64
	PrevStateRoot     types.Hash
	PostStateRoot     types.Hash
	Transactions      []*RollupTransaction
	TxCount           int
	TotalGasUsed      uint64
	Timestamp         int64
	Status            BatchStatus
	BatchHash         types.Hash
	SubmitTxHash      types.Hash
	SubmittedAt       int64
	FinalizedAt       int64
	ChallengeDeadline int64
	// W-P1-4 (2026-07-13): L1 anchor height. When non-zero, the challenge
	// deadline is determined by L1 block height (SubmitHeight +
	// challengeBlocks) instead of wall-clock time. Set by BatchManager.
	SubmitHeight uint64
	// R43-ROLLUP-FAIL-01 (2026-08-03): tracks whether AnchorBatch failed the
	// last time anchorBatch tried, plus how many times it has retried. Used
	// by finalize to BLOCK finalization of batches whose L1 anchor is still
	// pending (a fraud-proof window is only safe once the batch is anchored
	// on L1). Set by anchorBatch on failure; cleared on success. The cap
	// maxAnchorRetries is enforced inside anchorBatch.
	AnchorFailed  bool
	AnchorRetries int
	// AUDIT R4-BRDG-02 (2026-07-15): Root of the dedicated withdrawal Merkle
	// tree for this batch. Each leaf = SHA256(withdrawer || amount || txIndex).
	// Recorded on L1 so the bridge can verify that the calldata amount matches
	// the actual withdrawal committed in the finalized batch — preventing the
	// "valid proof, arbitrary amount" drain attack.
	WithdrawalRoot types.Hash
}

type RollupTransaction struct {
	Nonce     uint64
	GasPrice  uint64
	GasLimit  uint64
	To        *types.Address
	Value     *big.Int
	Data      []byte
	From      types.Address
	Hash      types.Hash
	Signature []byte // AUDIT (2026) HIGH-10: Dilithium3 signature over SigningHash()
	// W-P0-4 FIX (2026-07-13): ChainID binds the transaction to a specific L2
	// chain, preventing cross-chain replay (a signed L2 tx must not be
	// broadcastable to a different L2 chain or to L1). Included in
	// SigningHash() and encodeTxForHash() so the signature covers it.
	ChainID uint64
	// W-P1-1 FIX (2026-07-13): Sender's Dilithium3 public key (1952 bytes).
	// L2 accounts' public keys are NOT stored on L1 (unlike L1 keystore
	// accounts), so the verifier cannot look up the pubkey by address.
	// Instead, the tx carries the pubkey inline, and the verifier checks:
	//   1. pubkey derives to tx.From (crypto.PublicKeyAddressFromBytes)
	//   2. signature verifies against pubkey + signingHash
	// This mirrors the L1 txpool pattern (tx.PublicKey). NOT included in
	// SigningHash — it is verification metadata, like Signature.
	PublicKey []byte
}

type BatchManager struct {
	mu            sync.RWMutex
	config        *RollupConfig
	batches       map[uint64]*Batch
	currentBatch  *Batch
	nextIndex     uint64
	pendingTxs    []*RollupTransaction
	lastStateRoot types.Hash
	fraudProver   FraudProofVerifier
	// W-P1-3 (2026-07-13): Optional persistence layer for batches + meta.
	persistence Persistence
	// W-P1-4 (2026-07-13): L1 anchor metadata. When l1ChallengeBlocks > 0,
	// FinalizeBatch uses L1 block height (l1CurrentHeight) instead of
	// wall-clock time to check the challenge deadline.
	l1CurrentHeight   uint64
	l1ChallengeBlocks uint64
}

func NewBatchManager(config *RollupConfig, genesisStateRoot types.Hash) *BatchManager {
	return &BatchManager{
		config:        config,
		batches:       make(map[uint64]*Batch),
		nextIndex:     0,
		pendingTxs:    make([]*RollupTransaction, 0, config.MaxTxPerBatch),
		lastStateRoot: genesisStateRoot,
	}
}

func (bm *BatchManager) AddTransaction(tx *RollupTransaction) error {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if len(bm.pendingTxs) >= bm.config.MaxTxPerBatch {
		return ErrBatchFull
	}

	txBytes := bm.encodeTxForHash(tx)
	tx.Hash = sha256.Sum256(txBytes)
	bm.pendingTxs = append(bm.pendingTxs, tx)
	return nil
}

func (bm *BatchManager) BuildBatch() (*Batch, error) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	if len(bm.pendingTxs) < bm.config.MinTxPerBatch {
		return nil, ErrInsufficientTxs
	}

	txs := make([]*RollupTransaction, len(bm.pendingTxs))
	copy(txs, bm.pendingTxs)

	batch := &Batch{
		Index:         bm.nextIndex,
		PrevStateRoot: bm.lastStateRoot,
		Transactions:  txs,
		TxCount:       len(txs),
		Timestamp:     time.Now().Unix(),
		Status:        BatchStatusPending,
	}

	batch.BatchHash = bm.computeBatchHash(batch)
	bm.batches[batch.Index] = batch
	bm.currentBatch = batch
	bm.nextIndex++

	bm.pendingTxs = bm.pendingTxs[:0]

	return batch, nil
}

func (bm *BatchManager) SubmitBatch(index uint64, postStateRoot types.Hash, txHash types.Hash) error {
	bm.mu.Lock()

	batch, exists := bm.batches[index]
	if !exists {
		bm.mu.Unlock()
		return ErrBatchNotFound
	}

	if batch.Status != BatchStatusPending {
		bm.mu.Unlock()
		return ErrBatchAlreadySubmitted
	}

	batch.PostStateRoot = postStateRoot
	batch.SubmitTxHash = txHash
	batch.SubmittedAt = time.Now().Unix()
	batch.ChallengeDeadline = batch.SubmittedAt + int64(bm.config.ChallengePeriod.Seconds())
	batch.Status = BatchStatusSubmitted
	bm.lastStateRoot = postStateRoot

	// W-P1-3 (2026-07-13): Persist the updated batch + meta. Done under lock
	// to ensure consistency; unlock before returning.
	var persistErr error
	if bm.persistence != nil {
		if err := bm.persistence.SaveBatch(batch); err != nil {
			persistErr = err
		}
	}
	bm.mu.Unlock()

	if persistErr != nil {
		log.Printf("[rollup] WARN: persist SubmitBatch(%d) failed: %v", index, persistErr)
	}
	return nil
}

func (bm *BatchManager) FinalizeBatch(index uint64) error {
	bm.mu.Lock()

	batch, exists := bm.batches[index]
	if !exists {
		bm.mu.Unlock()
		return ErrBatchNotFound
	}

	if batch.Status != BatchStatusSubmitted {
		bm.mu.Unlock()
		return ErrBatchNotSubmitted
	}

	// AUDIT (2026) RLLP-FIX (CRITICAL): Reject finalization when a
	// valid fraud proof exists for this batch. The previous implementation
	// only checked the challenge deadline, NEVER checking whether a fraud
	// proof had been submitted. This made the challenge period meaningless —
	// a malicious sequencer could submit an invalid batch, wait out the
	// challenge period, and have it auto-finalized regardless of any fraud
	// proof submitted by an honest challenger. This completely bypassed the
	// optimistic rollup security model.
	//
	// Fix: Before finalizing, check if a fraud proof exists. If so, transition
	// the batch to Challenged status (which blocks finalization permanently
	// until the dispute is resolved) and return an error. The batch cannot
	// be finalized while Challenged.
	if bm.fraudProver != nil && bm.fraudProver.HasFraudProof(index) {
		// Auto-transition to Challenged so the batch cannot be silently
		// finalized on a subsequent tick. ChallengeBatch does its own
		// HasFraudProof check, but we call it here to centralize the
		// state transition logic and persistence.
		oldStatus := batch.Status
		batch.Status = BatchStatusChallenged

		// W-P1-3 (2026-07-13): Persist the challenged batch status.
		var challengePersistErr error
		if bm.persistence != nil {
			if err := bm.persistence.SaveBatch(batch); err != nil {
				challengePersistErr = err
			}
		}
		bm.mu.Unlock()

		if challengePersistErr != nil {
			log.Printf("[rollup] WARN: persist ChallengeBatch(%d) during FinalizeBatch failed: %v", index, challengePersistErr)
		}
		log.Printf("[rollup] SECURITY: batch %d has a fraud proof — auto-transitioned from %d to Challenged, finalization blocked (RLLP-)",
			index, oldStatus)
		return ErrBatchChallenged
	}

	// W-P1-4 (2026-07-13): When the batch has an L1 anchor (SubmitHeight > 0),
	// use L1 block height for the challenge deadline check instead of
	// wall-clock time. The caller must set the L1 anchor's current height
	// via SetL1CurrentHeight before calling FinalizeBatch.
	//
	// RLLP- (2026-07-16): When L1 challenge mode is configured
	// (l1ChallengeBlocks > 0) but the batch has NO L1 anchor (SubmitHeight
	// == 0), the batch MUST NOT be finalized. Previously, the code fell
	// back to wall-clock time, which bypasses the L1 height gate — a
	// sequencer could anchor-fail (intentionally or not) and then wait
	// out a shorter wall-clock deadline. Fix-closed: require SubmitHeight
	// > 0 when L1 mode is active. Wall-clock fallback is ONLY allowed
	// when L1 mode is not configured (l1ChallengeBlocks == 0).
	if batch.SubmitHeight > 0 {
		if bm.l1CurrentHeight < batch.SubmitHeight+bm.l1ChallengeBlocks {
			bm.mu.Unlock()
			return ErrChallengePeriodNotOver
		}
	} else if bm.l1ChallengeBlocks > 0 {
		// L1 mode is configured but this batch was never anchored.
		bm.mu.Unlock()
		return fmt.Errorf("RLLP- batch %d has no L1 anchor (SubmitHeight=0) but L1 challenge mode is active (l1ChallengeBlocks=%d): refusing to finalize via wall-clock fallback",
			index, bm.l1ChallengeBlocks)
	} else {
		// Fallback: wall-clock time (no L1 anchor configured).
		if time.Now().Unix() < batch.ChallengeDeadline {
			bm.mu.Unlock()
			return ErrChallengePeriodNotOver
		}
	}

	batch.Status = BatchStatusFinalized
	batch.FinalizedAt = time.Now().Unix()

	// W-P1-3 (2026-07-13): Persist the finalized batch status.
	var persistErr error
	if bm.persistence != nil {
		if err := bm.persistence.SaveBatch(batch); err != nil {
			persistErr = err
		}
	}
	bm.mu.Unlock()

	if persistErr != nil {
		log.Printf("[rollup] WARN: persist FinalizeBatch(%d) failed: %v", index, persistErr)
	}
	return nil
}

func (bm *BatchManager) ChallengeBatch(index uint64) error {
	bm.mu.Lock()

	batch, exists := bm.batches[index]
	if !exists {
		bm.mu.Unlock()
		return ErrBatchNotFound
	}

	if batch.Status != BatchStatusSubmitted {
		bm.mu.Unlock()
		return ErrBatchNotSubmitted
	}

	if bm.fraudProver == nil || !bm.fraudProver.HasFraudProof(index) {
		bm.mu.Unlock()
		return ErrFraudProofInvalid
	}

	batch.Status = BatchStatusChallenged

	// W-P1-3 (2026-07-13): Persist the challenged batch status.
	var persistErr error
	if bm.persistence != nil {
		if err := bm.persistence.SaveBatch(batch); err != nil {
			persistErr = err
		}
	}
	bm.mu.Unlock()

	if persistErr != nil {
		log.Printf("[rollup] WARN: persist ChallengeBatch(%d) failed: %v", index, persistErr)
	}
	return nil
}

// SetPersistence injects the persistence layer for batches + meta.
// W-P1-3 FIX (2026-07-13)
func (bm *BatchManager) SetPersistence(p Persistence) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.persistence = p
}

// PersistMeta flushes nextIndex + lastStateRoot to the persistence layer.
// Called by RollupEngine after each successful batch.
// W-P1-3 FIX (2026-07-13)
func (bm *BatchManager) PersistMeta() error {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	if bm.persistence == nil {
		return nil
	}
	return bm.persistence.SaveBatchMeta(bm.nextIndex, bm.lastStateRoot)
}

// RestoreBatches loads persisted batches into memory. Called once on startup.
// W-P1-3 FIX (2026-07-13)
//
// P1-ROLLUP-03 FIX (2026-07-30): lastStateRoot is now derived from the
// max-index Submitted batch rather than the last batch in iteration order.
// The previous code overwrote lastStateRoot for every Submitted batch in
// the iteration, so the "winner" was whichever batch key sorted last
// lexicographically — e.g. "b:9" > "b:100" — leaving lastStateRoot stuck
// at batch 9's PostStateRoot even when batch 100 was the actual latest.
// This made the next ProcessBatch fail with ErrInvalidStateTransition
// permanently (prevStateRoot mismatch). The fix tracks the max Index among
// Submitted batches and only sets lastStateRoot from that one.
func (bm *BatchManager) RestoreBatches(batches []*Batch) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	var maxSubmittedIndex uint64
	var maxSubmittedRoot types.Hash
	foundSubmitted := false
	for _, b := range batches {
		bm.batches[b.Index] = b
		if b.Index >= bm.nextIndex {
			bm.nextIndex = b.Index + 1
		}
		// Track the max-index Submitted batch for lastStateRoot.
		if b.Status >= BatchStatusSubmitted && b.PostStateRoot != (types.Hash{}) {
			if !foundSubmitted || b.Index > maxSubmittedIndex {
				maxSubmittedIndex = b.Index
				maxSubmittedRoot = b.PostStateRoot
				foundSubmitted = true
			}
		}
	}
	if foundSubmitted {
		bm.lastStateRoot = maxSubmittedRoot
	}
}

// RestoreMeta loads nextIndex + lastStateRoot from persistence. Called once
// on startup, AFTER RestoreBatches (which may update nextIndex from batch data).
// W-P1-3 FIX (2026-07-13)
func (bm *BatchManager) RestoreMeta(nextIndex uint64, lastStateRoot types.Hash) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	if nextIndex > bm.nextIndex {
		bm.nextIndex = nextIndex
	}
	if lastStateRoot != (types.Hash{}) {
		bm.lastStateRoot = lastStateRoot
	}
}

// SetBatchAnchor records the L1 anchor height on the batch. Called by
// RollupEngine.anchorBatch after a successful L1 anchor submission.
// W-P1-4 FIX (2026-07-13)
func (bm *BatchManager) SetBatchAnchor(index uint64, submitHeight uint64) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	if batch, ok := bm.batches[index]; ok {
		batch.SubmitHeight = submitHeight
	}
}

// SetL1CurrentHeight updates the current L1 block height. Called by
// RollupEngine when syncing L1 headers, so FinalizeBatch can check the
// challenge deadline using L1 height.
// W-P1-4 FIX (2026-07-13)
func (bm *BatchManager) SetL1CurrentHeight(height uint64) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.l1CurrentHeight = height
}

// SetL1ChallengeBlocks configures the challenge period in L1 blocks.
// When > 0, FinalizeBatch uses L1 height instead of wall-clock time.
// W-P1-4 FIX (2026-07-13)
func (bm *BatchManager) SetL1ChallengeBlocks(blocks uint64) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.l1ChallengeBlocks = blocks
}

func (bm *BatchManager) SetFraudProver(verifier FraudProofVerifier) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.fraudProver = verifier
}

func (bm *BatchManager) GetBatch(index uint64) (*Batch, error) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	batch, exists := bm.batches[index]
	if !exists {
		return nil, ErrBatchNotFound
	}
	return batch, nil
}

// GetBatchStatus returns a snapshot of the batch's status field under
// bm.mu.RLock. This is the race-safe alternative to GetBatch(...).Status
// for callers that only need to inspect the status: GetBatch returns a
// *Batch pointer (no copy), so reading any field off it outside the RLock
// races with FinalizeBatch / ProcessBatch / SubmitBatch mutating those
// fields under bm.mu.Lock. GetBatchStatus reads the status under the
// RLock and returns it as a value type, so no caller can race on the
// shared *Batch's field anymore.
// ROLLUP-R42-CI-RACE-6 (2026-08-19): introduced to fix the
//
//	Write at batch.go:282  batch.Status = BatchStatusFinalized (FinalizeBatch, under bm.mu.Lock)
//	Read  at rollup_test.go:1762  b.Status == BatchStatusFinalized (test, no lock)
//
// race that was making TestFinalizeLoop_AutoFinalizeWallClock flake.
func (bm *BatchManager) GetBatchStatus(index uint64) (BatchStatus, error) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	batch, exists := bm.batches[index]
	if !exists {
		return 0, ErrBatchNotFound
	}
	return batch.Status, nil
}

// GetBatchSnapshot returns a value-copy of the Batch at index, taken under
// bm.mu.RLock. Like GetBatchStatus, this is the race-safe alternative for
// callers that need to inspect multiple fields (e.g. the test's final
// error formatter reading Status, SubmittedAt, ChallengeDeadline) — the
// shared *Batch returned by GetBatch can mutate under bm.mu.Lock while
// the caller iterates the fields, so we hand back a snapshot value that
// can never race.
// ROLLUP-R42-CI-RACE-6 (2026-08-19): introduced alongside GetBatchStatus
// for the same race documented above.
func (bm *BatchManager) GetBatchSnapshot(index uint64) (Batch, error) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	batch, exists := bm.batches[index]
	if !exists {
		return Batch{}, ErrBatchNotFound
	}
	return *batch, nil
}

// GetSubmittedBatchIndices returns a sorted list of batch indices currently
// in BatchStatusSubmitted state. Used by RollupEngine.finalizeLoop to scan
// for batches whose challenge period may have elapsed.
// W-P1-5 FIX (2026-07-13)
func (bm *BatchManager) GetSubmittedBatchIndices() []uint64 {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	indices := make([]uint64, 0, len(bm.batches))
	for idx, b := range bm.batches {
		if b.Status == BatchStatusSubmitted {
			indices = append(indices, idx)
		}
	}
	// Sort ascending so finalize processing is deterministic.
	sort.Slice(indices, func(i, j int) bool { return indices[i] < indices[j] })
	return indices
}

func (bm *BatchManager) GetCurrentBatch() *Batch {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.currentBatch
}

func (bm *BatchManager) PendingTxCount() int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return len(bm.pendingTxs)
}

func (bm *BatchManager) GetLastStateRoot() types.Hash {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.lastStateRoot
}

func (bm *BatchManager) computeBatchHash(batch *Batch) types.Hash {
	h := sha256.New()
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, batch.Index)
	h.Write(buf)
	h.Write(batch.PrevStateRoot[:])
	binary.BigEndian.PutUint64(buf, uint64(batch.Timestamp))
	h.Write(buf)
	for _, tx := range batch.Transactions {
		h.Write(tx.Hash[:])
	}
	var hash types.Hash
	copy(hash[:], h.Sum(nil))
	return hash
}

func (bm *BatchManager) encodeTxForHash(tx *RollupTransaction) []byte {
	var valueBytes []byte
	if tx.Value != nil {
		valueBytes = tx.Value.Bytes()
	}
	// W-P0-4 FIX: +8 bytes for tx.ChainID at the end of the buffer.
	buf := make([]byte, 8+8+8+20+4+len(valueBytes)+len(tx.Data)+20+8)
	offset := 0
	binary.BigEndian.PutUint64(buf[offset:], tx.Nonce)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], tx.GasPrice)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], tx.GasLimit)
	offset += 8
	if tx.To != nil {
		copy(buf[offset:], tx.To[:])
	}
	offset += 20
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(valueBytes)))
	offset += 4
	copy(buf[offset:], valueBytes)
	offset += len(valueBytes)
	copy(buf[offset:], tx.Data)
	offset += len(tx.Data)
	copy(buf[offset:], tx.From[:])
	offset += 20
	// W-P0-4 FIX: Append ChainID so the batch hash is bound to the L2 chain.
	binary.BigEndian.PutUint64(buf[offset:], tx.ChainID)
	return buf
}

// SigningHash returns the hash that the sender must sign with their Dilithium3
// private key. The signature binds From to the transaction fields, preventing
// unauthorized transfers (AUDIT (2026) HIGH-10).
// The hash covers: From || Nonce || GasPrice || GasLimit || To || Value || Data || ChainID || PublicKey
// (NOT the Signature field itself, to avoid circular dependency).
// W-P0-4 FIX (2026-07-13): ChainID is included to prevent cross-chain replay —
// a signature valid on L2 chain A must not be reusable on L2 chain B or on L1.
//
// RLLP-FIX (2026-07-17): PublicKey is now included in the SigningHash so
// the signature explicitly commits to the public key used for verification.
// Previously the signature did not cover PublicKey — although the address
// derivation check (PublicKey → From) prevented practical exploitation, the
// signature semantics did not bind to a specific public key. This matters if
// public key rotation is ever introduced: without this binding, a signature
// could be "borrowed" by a new public key that derives to the same address.
// COMPATIBILITY: The wallet side (quantaureum-wallet) must update its signing
// flow to set tx.PublicKey BEFORE computing the signing hash.
func (tx *RollupTransaction) SigningHash() types.Hash {
	h := sha256.New()
	h.Write(tx.From[:])
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, tx.Nonce)
	h.Write(buf)
	binary.BigEndian.PutUint64(buf, tx.GasPrice)
	h.Write(buf)
	binary.BigEndian.PutUint64(buf, tx.GasLimit)
	h.Write(buf)
	if tx.To != nil {
		h.Write(tx.To[:])
	}
	if tx.Value != nil {
		vb := tx.Value.Bytes()
		lenBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBuf, uint32(len(vb)))
		h.Write(lenBuf)
		h.Write(vb)
	}
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(tx.Data)))
	h.Write(lenBuf)
	h.Write(tx.Data)
	// W-P0-4 FIX: Bind signature to the L2 ChainID.
	binary.BigEndian.PutUint64(buf, tx.ChainID)
	h.Write(buf)
	// RLLP-FIX: Bind signature to the PublicKey so the signer explicitly
	// commits to the verification key. Length-prefixed for domain separation
	// (consistent with the Data field encoding).
	binary.BigEndian.PutUint32(lenBuf, uint32(len(tx.PublicKey)))
	h.Write(lenBuf)
	h.Write(tx.PublicKey)
	var hash types.Hash
	copy(hash[:], h.Sum(nil))
	return hash
}
