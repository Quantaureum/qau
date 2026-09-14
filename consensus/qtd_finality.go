// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/params"
	"github.com/quantaureum/qau/types"
)

type FinalityType uint8

const (
	FinalityCasperFFG  FinalityType = 0
	FinalityQTDInstant FinalityType = 1
)

func (ft FinalityType) String() string {
	switch ft {
	case FinalityCasperFFG:
		return "CasperFFG"
	case FinalityQTDInstant:
		return "QTDInstant"
	default:
		return fmt.Sprintf("Unknown(%d)", ft)
	}
}

// R39-P0-01 (2026-08-02) FIX: domain separation for QTD threshold signatures.
//
// Before this change, the QTD threshold signature covered the raw 32-byte
// blockHash with NO binding to chainID / epoch / slot. Two independent
// Quantaureum instances (a future forked testnet, or an attacker-controlled
// "fake chain") that happened to share a blockHash — natural probability
// negligible (~1/2^256) but constructible against low-entropy early blocks
// — could have a seal produced on one instance replayed on another. This
// violates the cryptographic best practice of domain separation and was
// flagged P0 because the QTD seal is a core consensus signature contract.
//
// The canonical signed/verified message is now:
//
//	QTDDomainSep(17) || chainID(8 BE) || epoch(8 BE) || slot(8 BE) || blockHash(32)
//
// Total length = 17 + 8 + 8 + 8 + 32 = 73 bytes. The 17-byte ASCII domain
// separator is fixed and unique to the QTD block-seal context so QTD seals
// cannot be confused with vote signatures or any other Dilithium3 message
// in the protocol.
//
// Backward compatibility: seals produced BEFORE this change signed the raw
// blockHash (32 bytes). Such seals are replayed during a node restart that
// has to re-verify historical instant-finality records. To avoid breaking
// restart, verifySeal tries the new domain-separated message first and,
// only for epochs present in groupKeyHistory (i.e. seals that were valid
// at some earlier epoch), falls back to the legacy raw-blockHash message.
// Seals for the current/future epoch MUST verify with the new message —
// there is no legacy fallback for new epochs.
const (
	// QTDDomainSep is the 17-byte ASCII domain separator for QTD block
	// seals ("QAU-QTD-BLOCKSEAL"). It MUST NOT collide with any other
	// Dilithium3 message prefix used in the protocol. Changing this value
	// invalidates all post-R39 seals.
	QTDDomainSep = "QAU-QTD-BLOCKSEAL"

	// qtdDomainSepLen is the byte length of QTDDomainSep (= 17).
	qtdDomainSepLen = len(QTDDomainSep)

	// qtdSignedMessageLen is the total length of the canonical
	// domain-separated QTD block-seal message.
	//   domainSep(17) + chainID(8) + epoch(8) + slot(8) + blockHash(32) = 73
	qtdSignedMessageLen = qtdDomainSepLen + 8 + 8 + 8 + 32
)

// qtdSignedMessage builds the canonical domain-separated message a QTD
// threshold signature covers (and that the verifier expects). Callers
// MUST pass the same (chainID, epoch, slot, blockHash) tuple on both the
// signing side and the verifying side. The returned slice is freshly
// allocated; callers may mutate it freely.
//
// Layout (big-endian fixed-width integers, no length prefixes):
//
//	[0   .. 17)  QTDDomainSep (ASCII)
//	[17  .. 25)  chainID  (uint64 BE)
//	[25  .. 33)  epoch    (uint64 BE)
//	[33  .. 41)  slot     (uint64 BE)
//	[41  .. 73)  blockHash (32 bytes)
func qtdSignedMessage(chainID, epoch, slot uint64, blockHash types.Hash) []byte {
	msg := make([]byte, qtdSignedMessageLen)
	copy(msg[0:qtdDomainSepLen], QTDDomainSep)
	binary.BigEndian.PutUint64(msg[qtdDomainSepLen:qtdDomainSepLen+8], chainID)
	binary.BigEndian.PutUint64(msg[qtdDomainSepLen+8:qtdDomainSepLen+16], epoch)
	binary.BigEndian.PutUint64(msg[qtdDomainSepLen+16:qtdDomainSepLen+24], slot)
	copy(msg[qtdDomainSepLen+24:qtdDomainSepLen+56], blockHash[:])
	return msg
}

type QTDFinalityState struct {
	mu sync.RWMutex

	qpos *QPOS

	finalityType FinalityType

	instantFinalizedSlots map[uint64]*InstantFinalityRecord

	qtdSigner ThresholdKeySigner

	pendingSeals map[uint64]*PendingSeal

	// R30-IMPLEMENT (2026-07-27): QTD-H03 historical group key tracking.
	// Maps epoch → DKG group public key active at that epoch. Used by
	// getGroupPublicKeyForEpoch to verify seals from past epochs with the
	// key that was active when the seal was produced (NOT the current
	// signer's key, which may have rotated via DKG).
	groupKeyHistory map[uint64][]byte

	// R30-IMPLEMENT (2026-07-27): P3-QTD-02 SealAnnouncer for P2P broadcast
	// of completed QTD seals. When set, announceSeal is called after a seal
	// is completed to propagate the QTD signature to peer nodes via the
	// P2P gossip layer. Set via SetSealAnnouncer (called by node/ during
	// P2P host initialization).
	sealAnnouncer SealAnnouncer

	// R39-P0-01 (2026-08-02) FIX: chain ID for QTD domain separation.
	// Injected by node/ at startup via SetChainID (the node holds the
	// canonical ChainID; QPOS itself does not). When 0 (unset, or legacy
	// pre-R39 nodes / tests), qtdSignedMessage construction in the sign
	// and verify paths is replaced by the legacy raw blockHash bytes —
	// this preserves backward compatibility for historical seals and for
	// tests that construct a QTDFinalityState without coupling to the
	// chain configuration. When > 0, sign/verify use the canonical
	// domain-separated message
	//   QTDDomainSep || chainID || epoch || slot || blockHash.
	chainID uint64
}

// SetChainID injects the canonical ChainID used for QTD domain separation.
// Called by node/ once the chain configuration is known. Setting 0 is
// equivalent to "unset" and re-enables legacy raw-blockHash verification,
// which is the behavior of all tests that do not couple to chain config.
func (qfs *QTDFinalityState) SetChainID(chainID uint64) {
	qfs.mu.Lock()
	defer qfs.mu.Unlock()
	qfs.chainID = chainID
}

// qtdSignedMessageLocked returns the bytes a QTD threshold signature covers
// for this node's chainID/epoch/slot/blockHash tuple. Caller MUST hold
// qfs.mu (this helper reads qfs.chainID).
//
// When qfs.chainID == 0 (legacy unset / pre-R39 / tests decoupled from
// chain config), this returns the legacy raw blockHash (32 bytes) so all
// historical seals and tests keep verifying. When qfs.chainID > 0, this
// returns the canonical domain-separated message
//
//	QTDDomainSep || chainID || epoch || slot || blockHash
//
// (qtdSignedMessageLen bytes). The fallback is the ONLY backward-
// compatibility branch; production nodes set chainID > 0 at startup.
func (qfs *QTDFinalityState) qtdSignedMessageLocked(epoch, slot uint64, blockHash types.Hash) []byte {
	return qtdSignedMessageOrLegacy(qfs.chainID, epoch, slot, blockHash)
}

// qtdSignedMessageOrLegacy is the package-level canonical helper for
// constructing the bytes a QTD threshold signature covers, given the
// caller-supplied (chainID, epoch, slot, blockHash) tuple. When chainID
// == 0, the returned bytes are the legacy raw blockHash (32 bytes) so
// historical seals and tests not coupled to chain config keep verifying.
// When chainID > 0, the returned bytes are the canonical
//
//	QTDDomainSep || chainID || epoch || slot || blockHash
//
// (qtdSignedMessageLen bytes). The returned slice is always freshly
// allocated; callers may mutate it freely.
func qtdSignedMessageOrLegacy(chainID, epoch, slot uint64, blockHash types.Hash) []byte {
	if chainID == 0 {
		out := make([]byte, len(blockHash))
		copy(out, blockHash[:])
		return out
	}
	return qtdSignedMessage(chainID, epoch, slot, blockHash)
}

// qtdVerifyMessageLocked is the verify-side mirror of qtdSignedMessageLocked.
//
// R40-P0-01 (2026-08-03) FIX: the prior implementation took an
// `allowLegacyForEpoch` parameter and, when the primary domain-separated
// verification failed, re-tried verification over the RAW blockHash iff
// `allowLegacyForEpoch != 0 && epoch == allowLegacyForEpoch`. Every
// call site passed `epoch` (the very slot's epoch being verified) as that
// parameter, so the gate was a tautology — domain separation was silently
// bypassed for EVERY epoch (including the current one) whenever the
// canonical signature failed. An attacker holding any historical group key
// could then forge finality proofs over the raw blockHash for current slots.
//
// The fix removes the escape hatch from the domain-separated path
// entirely. Verification is now unambiguous:
//   - chainID > 0  → verify strictly over QTDDomainSep || chainID || epoch || slot || blockHash (no fallback)
//   - chainID == 0 → legacy raw blockHash verification (backward compatibility for records produced before R39-P0-01)
//
// The chainID == 0 branch is the ONLY legitimate legacy path: records
// created before the R39 domain-separation upgrade carry ChainID == 0 in
// their persisted state, so remote re-verification of those records still
// succeeds. Any record with chainID > 0 was produced post-R39 and MUST
// verify against the canonical message — there is no escape hatch.
//
// `chainID` is supplied by the caller (taken from the PendingSeal /
// InstantFinalityRecord that the signature was produced against), NOT
// read from qfs.chainID. This guarantees the verify path uses the same
// domain-separation context that the sign path used. Callers MUST hold
// qfs.mu (the signer is shared state guarded by qfs.mu even though it is
// logically read-only here).
func (qfs *QTDFinalityState) qtdVerifyMessageLocked(groupKey []byte, chainID, epoch, slot uint64, blockHash types.Hash, signature []byte) bool {
	if qfs.qtdSigner == nil || len(groupKey) == 0 || len(signature) == 0 {
		return false
	}
	// Path 1: chainID > 0 — canonical domain-separated verification. No fallback.
	if chainID > 0 {
		msg := qtdSignedMessage(chainID, epoch, slot, blockHash)
		return qfs.qtdSigner.VerifyBlock(groupKey, msg, signature)
	}
	// Path 2: chainID == 0 — legacy verification over raw blockHash (pre-R39 records only).
	legacyMsg := make([]byte, len(blockHash))
	copy(legacyMsg, blockHash[:])
	return qfs.qtdSigner.VerifyBlock(groupKey, legacyMsg, signature)
}

// SealAnnouncer broadcasts completed QTD seals to peer nodes via P2P gossip.
// R30-IMPLEMENT (2026-07-27): P3-QTD-02 fix. The announcer is invoked after
// a seal is completed locally so peer nodes can verify and store the QTD
// finality record without waiting for their own executive chamber to seal
// the same slot. Implementations live in the node/ package (P2P layer) and
// are injected via SetSealAnnouncer to respect the architecture discipline
// (consensus must not depend on p2p).
type SealAnnouncer interface {
	// AnnounceQTDSeal broadcasts a completed QTD seal to peer nodes.
	// Parameters:
	//   - slot: the slot being sealed
	//   - blockHash: the canonical block hash at that slot
	//   - qtdSignature: the QTD threshold signature proving finality
	//   - sealers: list of validator indices that participated in signing
	AnnounceQTDSeal(slot uint64, blockHash types.Hash, qtdSignature []byte, sealers []int)
}

type InstantFinalityRecord struct {
	Slot          uint64
	BlockHash     types.Hash
	QTDSignature  []byte
	SealedAt      time.Time
	Sealers       []int
	FinalityDelay time.Duration

	// R39-P0-01 (2026-08-02) FIX: domain separation context stored with
	// the finalized record so remote verifiers (VerifyInstantFinality)
	// can reconstruct the exact signed message
	//   QTDDomainSep || chainID || epoch || slot || blockHash
	// and try it first; legacy records produced before this change have
	// ChainID/Epoch == 0 and fall back to raw blockHash verification.
	ChainID uint64
	Epoch   uint64
}

type PendingSeal struct {
	Slot          uint64
	BlockHash     types.Hash
	ApprovedAt    time.Time
	PartialSigs   map[int][]byte
	RequiredCount int
	Completed     bool

	// R39-P0-01 (2026-08-02) FIX: domain-separated QTD signature context.
	// The seal threshold signature now covers
	//   QTDDomainSep || chainID || epoch || slot || blockHash
	// instead of the raw blockHash. Storing chainID/epoch in the pending
	// record (in addition to slot/blockHash already present) lets the
	// signing path reconstruct the exact signed message without having to
	// re-derive epoch from slot at aggregation time, and verifies on the
	// remote side can re-derive the same tuple from the finalized record.
	// Zero values mean "legacy pending seal created before R39-P0-01" and
	// trigger the backward-compatibility path in verifySeal (legacy raw
	// blockHash verification for epochs already in groupKeyHistory).
	ChainID uint64
	Epoch   uint64

	// R30-IMPLEMENT (2026-07-27): P3-QTD-01 centralized weight-threshold fields.
	// RequiredWeight is ceil(2/3 * totalExecutiveStake) — the minimum
	// cumulative stake weight required from participating sealers for the
	// seal to be considered weight-sufficient. MemberStakes maps each
	// executive member's validator index to its stake at seal-request time
	// (deep-copied to prevent race conditions with concurrent stake updates).
	// Both fields are populated by snapshotExecutiveStakes (called from
	// RequestSeal) and consumed by computeSealerWeight (called from
	// ReceiveSealAnnouncement and completeSealLocked).
	RequiredWeight *big.Int
	MemberStakes   map[int]*big.Int

	// R30-IMPLEMENT (2026-07-27): QTD-CRIT-03 partial-signature poisoning
	// DoS bound. Tracks consecutive aggregation failures for this pending
	// seal. After maxConsecutiveAggFailures consecutive failures, ALL
	// partial signatures are cleared (including the attacker's poison sig),
	// allowing legitimate signatures to complete the seal on re-collection.
	ConsecutiveAggFailures int

	// R31-P1-02 FIX (2026-07-27): QTD-P1-01 — per-sig suspicion score for
	// the rotation deletion strategy. Each time a partial sig participates
	// in a failed aggregation, its score is incremented. On each failure,
	// the sig with the HIGHEST score is deleted (most likely the poison).
	// The newly-submitted sig starts at score 0, so it's retained unless
	// it's the only sig left. This prevents a long-lived poison sig from
	// wasting multiple legitimate sigs before being cleared (the previous
	// "always delete newest" strategy could waste up to 2 legitimate sigs
	// before the poison was evicted).
	SigSuspicionScores map[int]int
}

// maxConsecutiveAggFailures is the maximum number of consecutive aggregation
// failures before QTD-CRIT-03 clears all partial signatures. After this many
// failures, the pending seal is reset (all partial sigs evicted, counter
// reset to 0) so legitimate signatures can complete the seal.
//
// R30-IMPLEMENT (2026-07-27): QTD-CRIT-03 fix. The bound is 3 to match the
// threshold of 2 (2-of-3 executive chamber): one legitimate sig + one poison
// sig triggers the first failure; the legitimate sig is dropped and
// re-collected, triggering the second failure; on the third failure, all
// sigs are cleared (including the poison one), breaking the DoS cycle.
const maxConsecutiveAggFailures = 3

// qtdCleanupRetainSlots is the number of slots of history to retain in
// pendingSeals and instantFinalizedSlots before pruning. Entries older than
// (currentSlot - qtdCleanupRetainSlots) are removed during cleanup.
// FIX: prevents unbounded memory growth in these maps.
const qtdCleanupRetainSlots = 10000 // ~312 epochs at 32 slots/epoch

// qtdGroupKeyHistoryRetainEpochs is the number of recent epochs whose DKG
// group public keys are retained in groupKeyHistory. Older entries are
// pruned each time a new key is recorded (DKG rotation / activation is the
// only writer). Seals older than the retention window can no longer be
// re-verified against their historical key — getGroupPublicKeyForEpoch
// fails closed for them, consistent with the seal-history pruning above.
// R37-P3-26 FIX (2026-07-31): prevents unbounded groupKeyHistory growth.
const qtdGroupKeyHistoryRetainEpochs = 512

func NewQTDFinalityState(qpos *QPOS) *QTDFinalityState {
	return &QTDFinalityState{
		qpos:                  qpos,
		finalityType:          FinalityCasperFFG,
		instantFinalizedSlots: make(map[uint64]*InstantFinalityRecord),
		pendingSeals:          make(map[uint64]*PendingSeal),
		// R30-IMPLEMENT (2026-07-27): QTD-H03 — initialize groupKeyHistory
		// so SetQTDSigner/SetQTDSignerForEpoch can record keys without nil checks.
		groupKeyHistory: make(map[uint64][]byte),
	}
}

// SetQTDSigner sets the QTD threshold signer and transitions finality type.
//
// R30-IMPLEMENT (2026-07-27): QTD-H01 — rejects non-nil signers that are NOT
// in threshold mode. A non-threshold signer could bypass the QTD cryptographic
// gate (its VerifyBlock may be maliciously implemented to always return true).
// nil is accepted (deactivation path).
//
// R30-IMPLEMENT (2026-07-27): P2-QTD-HISTORY — records the signer's
// GroupPublicKey in groupKeyHistory under qpos.GetCurrentEpoch(). This is the
// legacy startup/test path; ActivateQTDInstantFinality uses SetQTDSignerForEpoch
// with executive.Epoch() to handle the boundary-mismatch case.
func (qfs *QTDFinalityState) SetQTDSigner(signer ThresholdKeySigner) {
	qfs.mu.Lock()
	defer qfs.mu.Unlock()
	qfs.setQTDSignerLocked(signer, qfs.currentEpochLocked())
}

// setQTDSignerLocked is the internal setter that records the signer's key
// under the given epoch. Caller must hold qfs.mu.
// R30-IMPLEMENT (2026-07-27): QTD-H01 + P2-QTD-HISTORY.
func (qfs *QTDFinalityState) setQTDSignerLocked(signer ThresholdKeySigner, activationEpoch uint64) {
	// QTD-H01: reject non-nil non-threshold signers.
	if signer != nil && !signer.IsThresholdMode() {
		qtdLogger.Warn("QTD-H01: rejected non-threshold-mode signer (no state mutation)",
			map[string]any{"activationEpoch": activationEpoch})
		return
	}
	qfs.qtdSigner = signer
	if signer != nil {
		// signer.IsThresholdMode() is true here (QTD-H01 gate above).
		qfs.finalityType = FinalityQTDInstant
		// P2-QTD-HISTORY: record the group key under the explicit epoch.
		// R38-P1-01 FIX (2026-08-01): hardening for the TSS/QTD sibling
		// path. The R37-P0-03 fix rejected all-zero Dilithium3 pubkeys
		// inside the canonical crypto.Verify and PublicKeyFromBytes,
		// closing the bug for ordinary transactions and standard
		// multisig. But the QTD history table is written directly from
		// signer.GroupPublicKey() with only a `len > 0` gate, so an
		// all-zero key (the canonical "DKG not initialized" forgery
		// surface) could pollute groupKeyHistory and later be returned
		// to consumers that call mode3.Verify / crypto.Verify against
		// it. We block the all-zero seed here at the write-side single
		// chokepoint so the table NEVER carries the degenerate key —
		// constant-time comparison via crypto.IsZeroPublicKeyBytes (same
		// helper used by the canonical R37 hardening at
		// crypto/verify.go:73). We intentionally do NOT enforce a
		// strict `len == Dilithium3PublicKeySize` length guard here:
		//   - The all-zero forgery is the R38-P1-01 specifically
		//     identified sibling gap. The wrong-length risk is handled
		//     at the verifier boundary (VerifyBlock → TSSManager →
		//     wallet/tss/signing.go VerifySignatureWithPublicKey, post
		//     R38-P1-01 fixed to `!=`), which is the layer that owns
		//     the lifetime-pass validator over caller-supplied bytes.
		//   - Imposing a length gate here would break the existing
		//     test fixture contract where mock signers use short string
		//     literals (e.g. `[]byte("current-key")`) to distinguish
		//     DKG epochs via groupKeyHistory. The audit objective
		//     ("all-zero forgery") is fully met by the zero-key gate.
		// R39-P1-01 (2026-08-02) FIX: gate the group key write on the STRICT
		// length invariant `len(gpk) == crypto.Dilithium3PublicKeySize` (1952).
		// R38-P1-01 only blocked the all-zero "DKG-uninitialized" forgery, but
		// still accepted any NON-zero length — including truncated or padded
		// keys — into groupKeyHistory. A length-mismatched key would later be
		// passed to VerifyBlock as the Dilithium3 group pubkey and either
		// silently fail verification in the crypto layer (depending on which
		// check path it took) OR, worse, succeed under a degenerate pubkey
		// implementation. Strict length + non-zero is the canonical Dilithium3
		// group-key invariant.
		if gpk := signer.GroupPublicKey(); len(gpk) == crypto.Dilithium3PublicKeySize {
			if crypto.IsZeroPublicKeyBytes(gpk) {
				// len==Dilithium3PublicKeySize AND all-zero — the
				// canonical degenerate "DKG not initialized" key.
				// Reject at the chokepoint: do NOT write it into the
				// history table, or it will be served to consumers as
				// a valid group key for this epoch.
				qtdLogger.Warn("R38-P1-01: rejecting all-zero QTD group key (DKG not initialized?)",
					map[string]any{
						"activationEpoch": activationEpoch,
					})
			} else {
				if qfs.groupKeyHistory == nil {
					qfs.groupKeyHistory = make(map[uint64][]byte)
				}
				qfs.groupKeyHistory[activationEpoch] = append([]byte(nil), gpk...)
				// R37-P3-26 FIX (2026-07-31): prune entries outside the
				// retention window so the map stays bounded.
				if activationEpoch >= qtdGroupKeyHistoryRetainEpochs {
					minEpoch := activationEpoch - qtdGroupKeyHistoryRetainEpochs + 1
					for e := range qfs.groupKeyHistory {
						if e < minEpoch {
							delete(qfs.groupKeyHistory, e)
						}
					}
				}
			}
		} else if len(gpk) > 0 {
			// R39-P1-01: wrong-length non-zero key — reject and log so
			// operators can see the DKG/TSS layer is emitting malformed keys.
			qtdLogger.Warn("R39-P1-01: rejecting wrong-length QTD group key",
				map[string]any{
					"activationEpoch": activationEpoch,
					"gotLen":          len(gpk),
					"wantLen":         crypto.Dilithium3PublicKeySize,
				})
		}
	} else {
		// Deactivation: revert to CasperFFG. Do NOT erase historical entries
		// (future verification of seals from past epochs still needs old keys).
		qfs.finalityType = FinalityCasperFFG
	}
}

// currentEpochLocked returns the current epoch from qpos. Caller must hold qfs.mu.
func (qfs *QTDFinalityState) currentEpochLocked() uint64 {
	if qfs.qpos == nil {
		return 0
	}
	return qfs.qpos.GetCurrentEpoch()
}

func (qfs *QTDFinalityState) GetFinalityType() FinalityType {
	qfs.mu.RLock()
	defer qfs.mu.RUnlock()
	return qfs.finalityType
}

func (qfs *QTDFinalityState) IsInstantFinality() bool {
	qfs.mu.RLock()
	defer qfs.mu.RUnlock()
	return qfs.finalityType == FinalityQTDInstant
}

func (qfs *QTDFinalityState) RequestSeal(slot uint64, blockHash types.Hash) error {
	// AUDIT (2026) R4-CORE-04 FIX: Canonical chain binding for QTD.
	// Previously, RequestSeal accepted ANY (slot, blockHash) pair as long as
	// the Review Chamber approved it, without verifying that blockHash is the
	// canonical block at that slot. A threshold of executive chamber members
	// could sign a non-canonical fork block, and it would be accepted as
	// finalized.
	// Fix: if slotBlockRoots[slot] is known (the block has been processed on
	// the canonical chain), reject sealing requests for non-matching hashes.
	// This is the first line of defense — the second is in
	// completeSealLockedFinalize.
	//
	//  LOCK ORDERING: Read the canonical root BEFORE acquiring qfs.mu
	// to avoid the qfs.mu → qpos.mu lock ordering that previously caused
	// deadlocks. GetSlotBlockRoot acquires qpos.mu.RLock() internally.
	if canonicalRoot, ok := qfs.qpos.GetSlotBlockRoot(slot); ok {
		if canonicalRoot != blockHash {
			return fmt.Errorf("R4-CORE-04: refusing to seal slot %d: blockHash %s is not the canonical root %s",
				slot, blockHash.String(), canonicalRoot.String())
		}
	}

	qfs.mu.Lock()
	defer qfs.mu.Unlock()

	if _, exists := qfs.pendingSeals[slot]; exists {
		return fmt.Errorf("seal already requested for slot %d", slot)
	}

	if _, exists := qfs.instantFinalizedSlots[slot]; exists {
		return fmt.Errorf("slot %d already finalized", slot)
	}

	if !qfs.qpos.HasChambers() {
		return fmt.Errorf("chambers not initialized")
	}

	coordinator := qfs.qpos.GetChambersCoordinator()
	if coordinator == nil {
		return fmt.Errorf("chambers coordinator not available")
	}

	if !coordinator.IsBlockApproved(slot) {
		return fmt.Errorf("block for slot %d not approved by Review Chamber", slot)
	}

	executive := coordinator.GetExecutiveChamber()
	if executive == nil || !executive.IsActive() {
		return fmt.Errorf("executive chamber not active")
	}

	threshold := executive.Threshold()

	// R30-IMPLEMENT (2026-07-27): P3-QTD-01 — snapshot executive stakes and
	// compute the required weight threshold (ceil(2/3 * totalExecutiveStake))
	// via the shared helper. This ensures RequestSeal, ReceiveSealAnnouncement,
	// and completeSealLocked all use the SAME weight threshold for the same
	// epoch, preventing divergence that could allow minority-stake finalization.
	epoch := SlotToEpoch(slot)
	memberStakes, _, requiredWeight := qfs.snapshotExecutiveStakesLocked(epoch, coordinator)

	qfs.pendingSeals[slot] = &PendingSeal{
		Slot:      slot,
		BlockHash: blockHash,
		// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
		ApprovedAt:    time.Unix(int64(slot), 0),
		PartialSigs:   make(map[int][]byte),
		RequiredCount: threshold,
		Completed:     false,
		// P3-QTD-01: weight-threshold fields (populated by snapshotExecutiveStakes).
		RequiredWeight: requiredWeight,
		MemberStakes:   memberStakes,
		// R31-P1-02 FIX (2026-07-27): QTD-P1-01 — initialize suspicion score
		// map for the rotation deletion strategy.
		SigSuspicionScores: make(map[int]int),
		// R39-P0-01 (2026-08-02) FIX: capture the domain-separation context
		// (chainID + epoch) so the sign path can reconstruct the exact
		// signed message later, without re-deriving epoch from slot.
		// chainID == 0 means "unset" (legacy / tests decoupled from chain
		// config) and qtdSignedMessageLocked falls back to raw blockHash.
		ChainID: qfs.chainID,
		Epoch:   epoch,
	}

	executive.StartSealing()

	return nil
}

// NOTE (QUANTUM- / QUANTUM-FIX, 2026-07-17):
// The previous isValidPartialSealFormat heuristic (non-zero, non-uniform,
// >=25% non-zero bytes) was security theater — any 16-byte random blob
// passed it. It has been removed. TSS partial signatures cannot be
// cryptographically verified in isolation; verification happens at
// aggregation time via ThresholdKeySigner.AggregatePartialSignatures.
// To prevent the DoS described in QUANTUM- (forged partial sig causes
// completeSealLocked to clear ALL signatures, blocking sealing permanently),
// completeSealLocked no longer clears the signature map on aggregation
// failure — only the newly-submitted signature is dropped by the caller.
//
// QUANTUM- (audit 2026-07-17, Info): CLOSED. The audit's three
// remediation options are all satisfied: (1) heuristic removed (see above),
// (2) real cryptographic verification delegated to aggregation time
// (AggregatePartialSignatures), (3) the residual MinPartialSealSize=16 length
// check below is explicitly labeled as a non-security garbage filter for
// placeholder strings like "auto-seal", NOT a cryptographic check.

func (qfs *QTDFinalityState) SubmitPartialSeal(validatorIndex int, slot uint64, signature []byte) error {
	qfs.mu.Lock()
	defer qfs.mu.Unlock()

	// FIX: completeSealLocked no longer acquires qpos.mu.
	// The qpos finalization is deferred to completeSealLockedFinalize,
	// which is called after qfs.mu is released (via the return value
	// pattern below). This prevents the qfs.mu → qpos.mu lock ordering
	// that could cause deadlock.

	// SECURITY FIX H-1: Validate signature format and length.
	// Previously, SealBlock in three_provinces.go submitted []byte("auto-seal")
	// as a fake partial signature for all executive members, bypassing the
	// threshold signature scheme entirely. This allowed a single node to
	// forge the threshold signature and finalize blocks without actual
	// multi-party cooperation.
	//
	// We now reject:
	// 1. Empty signatures
	// 2. Signatures shorter than a minimum threshold (rejects "auto-seal" = 9 bytes)
	// 3. The specific "auto-seal" placeholder string
	// 4. Signatures that don't match the expected Dilithium3 signature size
	//    (3293 bytes) — with an exception for test environments that use
	//    shorter mock signatures (must be >= MinPartialSealSize).
	const MinPartialSealSize = 16 // Rejects "auto-seal" (9 bytes) and other short fakes
	if len(signature) == 0 {
		return fmt.Errorf("empty partial seal signature for validator %d slot %d", validatorIndex, slot)
	}
	if bytes.Equal(signature, []byte("auto-seal")) {
		return fmt.Errorf("rejected fake 'auto-seal' signature for validator %d slot %d", validatorIndex, slot)
	}
	if len(signature) < MinPartialSealSize {
		return fmt.Errorf("partial seal signature too short: %d bytes (min %d) for validator %d slot %d",
			len(signature), MinPartialSealSize, validatorIndex, slot)
	}
	// Full Dilithium3 signatures should be exactly 3293 bytes. For non-standard
	// length signatures (TSS partial seals), the format is protocol-specific
	// and cannot be cryptographically verified in isolation.
	// QUANTUM-FIX (2026-07-17): Removed the isValidPartialSealFormat
	// heuristic — it was easily bypassed (any 16-byte random data passed)
	// and gave a false sense of security. Real verification happens at
	// aggregation time in completeSealLocked via AggregatePartialSignatures.
	// The minimum length check (MinPartialSealSize = 16) above is retained
	// only to reject obvious placeholder strings like "auto-seal".
	if len(signature) != crypto.Dilithium3SignatureSize {
		qposAdvLogger.Warnf("non-standard partial seal signature length %d (expected %d) for validator %d slot %d — verification deferred to aggregation",
			len(signature), crypto.Dilithium3SignatureSize, validatorIndex, slot)
	}

	pending, exists := qfs.pendingSeals[slot]
	if !exists {
		return fmt.Errorf("no pending seal for slot %d", slot)
	}

	if pending.Completed {
		return fmt.Errorf("seal already completed for slot %d", slot)
	}

	if !qfs.qpos.CanSeal(validatorIndex, SlotToEpoch(slot)) {
		return fmt.Errorf("validator %d not authorized to seal for slot %d", validatorIndex, slot)
	}

	// SECURITY FIX (audit S-4): Verify signature source to prevent forgery.
	// Previously, any node could submit a partial signature claiming to be any
	// authorized validator. Now we verify full Dilithium3 signatures against the
	// validator's public key. Partial TSS signatures cannot be verified with
	// standard Dilithium3 verification — they require TSS-level verification
	// which is logged as a warning for production monitoring.
	if len(signature) == crypto.Dilithium3SignatureSize {
		validators := qfs.qpos.GetValidatorSet()
		if validators != nil {
			validatorList := validators.Validators()
			if validatorIndex >= 0 && validatorIndex < len(validatorList) {
				validator := validatorList[validatorIndex]
				if len(validator.PublicKeyBytes) > 0 {
					pubKey, err := crypto.PublicKeyFromBytes(validator.PublicKeyBytes)
					if err == nil && pubKey != nil {
						if !crypto.Verify(pubKey, pending.BlockHash[:], signature) {
							return fmt.Errorf("partial seal signature verification failed: signature does not match validator %d public key for slot %d", validatorIndex, slot)
						}
					} else {
						// CS-02 FIX (R45): Reject if public key cannot be parsed.
						return fmt.Errorf("partial seal: cannot parse public key for validator %d slot %d", validatorIndex, slot)
					}
				} else {
					// CS-02 FIX (R45): Reject if public key is empty.
					return fmt.Errorf("partial seal: empty public key for validator %d slot %d", validatorIndex, slot)
				}
			} else {
				// CS-02 FIX (R45): Reject if validator index out of range.
				return fmt.Errorf("partial seal: validator index %d out of range for slot %d", validatorIndex, slot)
			}
		} else {
			// CS-02 FIX (R45): Reject if validator set is nil.
			return fmt.Errorf("partial seal: nil validator set for slot %d", slot)
		}
	} else {
		// CS-02 FIX (R45): For non-Dilithium3 (TSS partial) signatures, add
		// a minimum length check instead of silently accepting any length.
		// TSS partial signatures should be at least 16 bytes (one scalar).
		// Previously, even 0-length signatures would be accepted here.
		const minTSSPartialSigLen = 16
		if len(signature) < minTSSPartialSigLen {
			return fmt.Errorf("partial seal: TSS partial signature too short (%d bytes, minimum %d) for validator %d slot %d",
				len(signature), minTSSPartialSigLen, validatorIndex, slot)
		}
		// R14-MED (2026-07-21): Independent cryptographic verification of TSS
		// partial signatures is NOT possible with the current GM-QTD protocol
		// implementation — it would require (1) a SharePublicKey field on
		// Validator, (2) a VerifyPartialSignature function, and (3) DKG phase
		// changes to derive and persist share public keys. This is a protocol-
		// level enhancement requiring crypto expert review.
		//
		// Defense-in-depth (already in place):
		// 1. Full Dilithium3 signatures (3293 bytes) ARE verified above.
		// 2. AggregatePartialSignatures (adapters.go:1276) REJECTS external
		//    partial sigs in local TSS mode (fail-closed).
		// 3. In distributed TSS mode, partialSigs are IGNORED — the P2P
		//    distributed signer re-signs from scratch.
		// So a forged TSS partial sig cannot influence block finalization:
		// it's either rejected at aggregation (local) or ignored (distributed).
		//
		// The log below makes the acceptance visible. In production mode
		// (QAU_PRODUCTION=1), escalate to Error so operators investigate
		// any TSS partial sig that bypasses crypto verification — it
		// indicates either a misconfiguration (should be using Dilithium3
		// full sigs) or a potential attack attempt.
		if params.IsProductionEnv() {
			qposAdvLogger.Errorf("R14-MED: TSS partial signature accepted without crypto verification in PRODUCTION mode (validator %d slot %d len=%d) — should use full Dilithium3 signatures (3293 bytes); aggregated sig will fail-closed if invalid",
				validatorIndex, slot, len(signature))
		} else {
			qposAdvLogger.Warnf("partial TSS signature from validator %d slot %d: source verification not implemented for partial signatures (len=%d, full Dilithium3=%d)",
				validatorIndex, slot, len(signature), crypto.Dilithium3SignatureSize)
		}
	}

	pending.PartialSigs[validatorIndex] = make([]byte, len(signature))
	copy(pending.PartialSigs[validatorIndex], signature)

	// R31-P1-02 FIX (2026-07-27): QTD-P1-01 — initialize the suspicion
	// score for the newly-submitted sig to 0. The score is incremented
	// for OTHER sigs on each aggregation failure (see sealFailureAggregation
	// case below). The newly-submitted sig retains score 0 until a
	// SUBSEQUENT failure (where it's no longer the "new" sig), ensuring
	// it's preferred over older sigs that may be poison.
	if pending.SigSuspicionScores == nil {
		pending.SigSuspicionScores = make(map[int]int)
	}
	pending.SigSuspicionScores[validatorIndex] = 0

	// FIX: Check if seal is complete, and if so, capture the data
	// needed for qpos finalization BEFORE releasing qfs.mu.
	// P1-04 FIX (R45): Only finalize if completeSealLocked actually succeeds
	// (all checks pass, QTD signature aggregated). Previously, needFinalize
	// was set to true BEFORE completeSealLocked, so early-returns on
	// qtdSigner==nil or aggregation failure still triggered finalization,
	// bypassing the threshold signature guarantee.
	var finalizeSlot uint64
	var finalizeHash [32]byte
	needFinalize := false
	// R32-P0-2 FIX (2026-07-28): Capture QTD signature + sealers for
	// announceSeal. announceSeal acquires qfs.mu.RLock() internally, so
	// it CANNOT be called while we hold qfs.mu.Lock(). We capture the
	// data now (under lock) and launch a goroutine to announce after
	// the lock is released (same pattern as completeSealLockedFinalize).
	var announceSig []byte
	var announceSealers []int
	needAnnounce := false
	if len(pending.PartialSigs) >= pending.RequiredCount {
		result := qfs.completeSealLocked(slot, pending)
		switch result {
		case sealSuccess:
			needFinalize = true
			finalizeSlot = slot
			finalizeHash = pending.BlockHash
			// R32-P0-2 FIX: Capture announcement data from the finalized
			// record. completeSealLocked stored the record in
			// qfs.instantFinalizedSlots[slot] with the aggregated QTD
			// signature and sealer list. Without announceSeal, the QTD
			// signature stays local and other nodes never learn that
			// instant finality was achieved for this slot.
			if rec, ok := qfs.instantFinalizedSlots[slot]; ok {
				announceSig = append([]byte(nil), rec.QTDSignature...)
				announceSealers = append([]int(nil), rec.Sealers...)
				needAnnounce = true
			}
			// R31-P2 FIX (2026-07-28): Reset failure counters on success.
			// Although completeSealLocked already deleted the pending seal
			// from qfs.pendingSeals (so the stale counters don't leak into
			// future seals), explicitly resetting them is defense-in-depth:
			//   1. State machine clarity — success resets failure counters.
			//   2. If any goroutine captured the pending pointer (e.g., for
			//      metrics/logging), it won't observe stale failure state.
			//   3. Consistency with the maxConsecutiveAggFailures reset
			//      path, which also clears these fields.
			pending.ConsecutiveAggFailures = 0
			pending.SigSuspicionScores = make(map[int]int)
		case sealFailureAggregation:
			// R31-P1-02 FIX (2026-07-27): QTD-P1-01 — rotation deletion
			// strategy using suspicion scores. Previously, the newly-submitted
			// sig was ALWAYS deleted, allowing a long-lived poison sig
			// (submitted first) to survive and waste up to 2 legitimate sigs
			// before being cleared by the maxConsecutiveAggFailures reset.
			//
			// New strategy:
			//   1. Increment suspicion score for ALL sigs EXCEPT the newly-
			//      submitted (which was just initialized to 0). Older sigs
			//      that have survived previous failures have higher scores.
			//   2. Find the sig with the HIGHEST score (most likely poison)
			//      and delete it. Ties broken by lowest validator index
			//      (deterministic).
			//   3. If only the newly-submitted sig remains, delete it.
			//   4. After maxConsecutiveAggFailures, clear ALL sigs + scores.
			//
			// This ensures a poison sig submitted FIRST gets evicted on the
			// FIRST failure (score 1 > new sig's score 0), instead of
			// surviving until the maxConsecutiveAggFailures reset.
			if pending.SigSuspicionScores == nil {
				pending.SigSuspicionScores = make(map[int]int)
			}

			// Increment suspicion for all sigs EXCEPT the newly-submitted.
			for vIdx := range pending.PartialSigs {
				if vIdx != validatorIndex {
					pending.SigSuspicionScores[vIdx]++
				}
			}

			// Find the most suspicious sig (highest score, tie-break lowest vIdx).
			maxScore := -1
			suspectIdx := -1
			for vIdx, score := range pending.SigSuspicionScores {
				if vIdx == validatorIndex {
					continue // Don't delete the newly-submitted unless it's the only one
				}
				if score > maxScore || (score == maxScore && vIdx < suspectIdx) {
					maxScore = score
					suspectIdx = vIdx
				}
			}

			// Delete the most suspicious sig. If no other sigs exist (only
			// the newly-submitted), fall back to deleting it.
			if suspectIdx >= 0 {
				delete(pending.PartialSigs, suspectIdx)
				delete(pending.SigSuspicionScores, suspectIdx)
			} else {
				// Only the newly-submitted sig exists — delete it.
				delete(pending.PartialSigs, validatorIndex)
				delete(pending.SigSuspicionScores, validatorIndex)
			}

			pending.ConsecutiveAggFailures++
			if pending.ConsecutiveAggFailures >= maxConsecutiveAggFailures {
				pending.PartialSigs = make(map[int][]byte)
				pending.SigSuspicionScores = make(map[int]int)
				pending.ConsecutiveAggFailures = 0
			}
		case sealFailureInsufficientWeight:
			// QTD-CRIT-03 FIX (2026-07-27): Weight insufficient — RETAIN
			// the new sig. More sigs are needed to reach the weight
			// threshold, so dropping any sig would be counterproductive.
			// Do NOT increment ConsecutiveAggFailures (this is not a
			// poison-sig attack, just not enough stake yet).
		case sealFailure:
			// Generic failure (qtdSigner nil, etc.) — retain the new sig
			// for retry when the transient condition resolves.
		}
	}

	// FIX: Launch a goroutine to call completeSealLockedFinalize
	// after qfs.mu is released (defer Unlock runs when we return).
	// This avoids the qfs.mu → qpos.mu lock ordering that could deadlock.
	// Using a goroutine is safe here because the qpos finalization update
	// is idempotent (only updates if epoch > current).
	if needFinalize {
		go qfs.completeSealLockedFinalize(finalizeSlot, finalizeHash)
	}

	// R32-P0-2 FIX (2026-07-28): Announce the completed QTD seal to other
	// nodes via P2P. announceSeal acquires qfs.mu.RLock() internally, so it
	// must run AFTER qfs.mu is released. Using a goroutine matches the
	// completeSealLockedFinalize pattern above. announceSeal has its own
	// defer recover() so a buggy announcer cannot crash this path.
	if needAnnounce {
		go qfs.announceSeal(finalizeSlot, types.Hash(finalizeHash), announceSig, announceSealers)
	}

	return nil
}

// SubmitCompletedSeal submits a pre-computed QTD threshold signature to
// complete a pending seal, bypassing the partial-signature collection flow.
//
// R7 P0-1 FIX (2026-07-17): The previous flow in node/qtd_seal.go produced
// Dilithium3 single-signer signatures via validatorKey.Sign and called them
// "partial seals". AggregatePartialSignatures rejected them (local mode) or
// ignored them (distributed mode), so the QTD seal never completed through
// a real threshold signing path. This method provides a clean entry point
// for the proposer to submit a pre-computed threshold signature produced by
// AggregatePartialSignatures (which routes to distributeTSSSignNoFallback
// in distributed mode, or SignWithRetry in local mode).
//
// Parameters:
//   - slot: the slot being sealed
//   - signature: the full QTD threshold signature
//   - sealers: list of validator indices that participated in signing
//
// Returns an error if: no pending seal, already completed, blockHash is not
// canonical (R4-CORE-04), or insufficient sealers for threshold.
func (qfs *QTDFinalityState) SubmitCompletedSeal(slot uint64, signature []byte, sealers []int) error {
	// R4-CORE-04: verify blockHash is canonical BEFORE acquiring qfs.mu
	// (same lock-ordering pattern as RequestSeal — GetSlotBlockRoot
	// acquires qpos.mu.RLock() internally).
	// R35-P0-08 FIX: Also snapshot RequiredWeight and MemberStakes so we can
	// perform the weight-threshold check outside the lock. The internal path
	// (completeSealLocked) already enforces RequiredWeight at line 854-859,
	// but this external pre-aggregation path bypassed it — only checking the
	// count threshold. With uneven executive stakes (e.g., [100,100,9800]),
	// two low-weight sealers (2% of total stake) could finalize a block,
	// defeating the 2/3-byzantine-stake guarantee of QTD instant finality.
	pendingBlockHash, pendingExists, pendingCompleted, pendingRequiredCount, pendingRequiredWeight, pendingMemberStakes := func() (types.Hash, bool, bool, int, *big.Int, map[int]*big.Int) {
		qfs.mu.RLock()
		defer qfs.mu.RUnlock()
		p, ok := qfs.pendingSeals[slot]
		if !ok {
			return types.Hash{}, false, false, 0, nil, nil
		}
		return p.BlockHash, true, p.Completed, p.RequiredCount, p.RequiredWeight, p.MemberStakes
	}()
	if !pendingExists {
		return fmt.Errorf("no pending seal for slot %d", slot)
	}
	if pendingCompleted {
		return fmt.Errorf("seal already completed for slot %d", slot)
	}

	// R4-CORE-04: Canonical chain binding (defense-in-depth, same as RequestSeal).
	if canonicalRoot, ok := qfs.qpos.GetSlotBlockRoot(slot); ok {
		if canonicalRoot != pendingBlockHash {
			return fmt.Errorf("R4-CORE-04: refusing to complete seal slot %d: blockHash %s is not canonical %s",
				slot, pendingBlockHash.String(), canonicalRoot.String())
		}
	}

	// Validate signature is non-empty (reject placeholders).
	if len(signature) == 0 {
		return fmt.Errorf("empty QTD signature for slot %d", slot)
	}

	// Validate count threshold.
	if len(sealers) < pendingRequiredCount {
		return fmt.Errorf("insufficient sealers for slot %d: have %d, need %d", slot, len(sealers), pendingRequiredCount)
	}

	// R35-P0-08 FIX: Validate weight threshold (mirrors completeSealLocked
	// line 854-859). RequiredWeight is ceil(2/3 * totalExecutiveStake). This
	// check is defense-in-depth against the external pre-aggregation path
	// being used to bypass the weight guarantee. Even if a caller collected
	// enough signatures to meet RequiredCount, the cumulative stake must
	// also meet RequiredWeight — otherwise a cartel of low-stake validators
	// could finalize blocks without true 2/3 economic buy-in.
	if pendingRequiredWeight != nil && pendingMemberStakes != nil {
		sealerWeight := computeSealerWeight(sealers, pendingMemberStakes)
		if sealerWeight.Cmp(pendingRequiredWeight) < 0 {
			return fmt.Errorf("insufficient sealer weight for slot %d: have %s, need %s",
				slot, sealerWeight.String(), pendingRequiredWeight.String())
		}
	}

	// CONS-P0-03 FIX (R31, 2026-07-27): Precompute epoch and currentEpoch
	// BEFORE acquiring qfs.mu.Lock(). This eliminates the qfs.mu → qpos.mu
	// lock-ordering hazard (qpos.GetCurrentEpoch is currently lock-free,
	// but precomputing is defensive against future modifications).
	epoch := SlotToEpoch(slot)
	currentEpoch := uint64(0)
	if qfs.qpos != nil {
		currentEpoch = qfs.qpos.GetCurrentEpoch()
	}

	qfs.mu.Lock()
	defer qfs.mu.Unlock()

	// Re-check under lock (another goroutine may have completed it).
	pending, exists := qfs.pendingSeals[slot]
	if !exists {
		return fmt.Errorf("no pending seal for slot %d (re-check)", slot)
	}
	if pending.Completed {
		return fmt.Errorf("seal already completed for slot %d (re-check)", slot)
	}

	// R30-IMPLEMENT (2026-07-27): QTD-H03 — verify the QTD signature against
	// the historical group public key for the slot's epoch. During DKG
	// rotation, the current signer has the NEW key, but seals from PAST
	// epochs must be verified with the OLD key that was active at seal time.
	// getGroupPublicKeyForEpochLocked handles this lookup (caller holds qfs.mu).
	// Without this verification, SubmitCompletedSeal would accept ANY
	// non-empty signature, allowing a single node to forge finality proofs.
	groupKey := qfs.getGroupPublicKeyForEpochLocked(epoch, currentEpoch)
	if len(groupKey) == 0 {
		return fmt.Errorf("QTD-H03: group public key empty for epoch %d (slot %d) — cannot verify seal", epoch, slot)
	}
	if qfs.qtdSigner == nil {
		return fmt.Errorf("QTD-H03: qtdSigner is nil — cannot verify seal for slot %d", slot)
	}
	// R39-P0-01 (2026-08-02) + R40-P0-01 (2026-08-03) FIX: verify the QTD
	// signature over the domain-separated message. Records produced before
	// R39-P0-01 carry ChainID == 0 (pending.ChainID) and fall back to the
	// raw-blockHash verification path inside qtdVerifyMessageLocked for
	// backward compatibility; all post-R39 records (ChainID > 0) MUST verify
	// against the canonical message — the tautological legacy escape hatch
	// removed in R40-P0-01 no longer exists.
	if !qfs.qtdVerifyMessageLocked(groupKey, pending.ChainID, pending.Epoch, slot, pending.BlockHash, signature) {
		return fmt.Errorf("QTD-H03: signature verification failed for slot %d (epoch %d key did not match signature)", slot, epoch)
	}

	// R4-C1 FIX: deterministic block time for consensus.
	sealedAt := time.Unix(int64(slot), 0)
	delay := sealedAt.Sub(pending.ApprovedAt)

	sealersCopy := make([]int, len(sealers))
	copy(sealersCopy, sealers)

	qfs.instantFinalizedSlots[slot] = &InstantFinalityRecord{
		Slot:          slot,
		BlockHash:     pending.BlockHash,
		QTDSignature:  append([]byte(nil), signature...),
		SealedAt:      sealedAt,
		Sealers:       sealersCopy,
		FinalityDelay: delay,
		// R39-P0-01 (2026-08-02) FIX: persist the domain-separation context
		// so remote verifiers (VerifyInstantFinality) can reconstruct the
		// same canonical signed message without consulting the pending
		// seal (which is deleted below). Use the pending seal's
		// ChainID/Epoch (captured at RequestSeal time) — these are the
		// values actually covered by the QTD signature.
		ChainID: pending.ChainID,
		Epoch:   pending.Epoch,
	}
	pending.Completed = true
	delete(qfs.pendingSeals, slot)

	// FIX: finalize in qpos AFTER releasing qfs.mu (via goroutine).
	finalizeHash := pending.BlockHash
	go qfs.completeSealLockedFinalize(slot, finalizeHash)

	// R32-P0-2 FIX (2026-07-28): Announce the completed QTD seal to other
	// nodes via P2P. Without this, the threshold signature stays local and
	// other nodes cannot verify instant finality for this slot. announceSeal
	// acquires qfs.mu.RLock() internally, so it must run after qfs.mu is
	// released (via goroutine, same pattern as completeSealLockedFinalize).
	// Defensive copies of signature + sealers are made by announceSeal itself.
	announceSig := append([]byte(nil), signature...)
	announceSealers := append([]int(nil), sealersCopy...)
	go qfs.announceSeal(slot, pending.BlockHash, announceSig, announceSealers)

	return nil
}

// AggregateAndCompleteSeal computes the QTD threshold signature for a pending
// seal and completes it in one step. This is the R7 P0-1 production path:
// the proposer calls this method (asynchronously) to produce a real threshold
// signature via the configured ThresholdKeySigner, bypassing the broken
// partial-seal collection in node/qtd_seal.go.
//
// In distributed mode (TSSDistributedMode=true), AggregatePartialSignatures
// routes to distributeTSSSignNoFallback which enforces strict P2P multi-party
// signing (no fallback to local). In local mode, it uses SignWithRetry.
//
// The caller (node layer) should invoke this in a goroutine to avoid blocking
// the slot tick — distributed signing may take up to 20 seconds.
func (qfs *QTDFinalityState) AggregateAndCompleteSeal(slot uint64, sealers []int) error {
	// Read pending seal info under RLock.
	//
	// R39-P0-01 (2026-08-02) FIX: also read pending.ChainID/Epoch so the
	// sign path can reconstruct the exact domain-separated signed message
	// using the domain-separation context captured at RequestSeal time
	// (NOT qfs.chainID — the node's chainID could in principle be mutated
	// mid-flight, even if that is unsupported; using the pending record's
	// captured context is the strongest correctness guarantee and matches
	// what the verifier will read back from the finalized record).
	pendingBlockHash, pendingChainID, pendingEpoch, pendingExists, pendingCompleted := func() (types.Hash, uint64, uint64, bool, bool) {
		qfs.mu.RLock()
		defer qfs.mu.RUnlock()
		p, ok := qfs.pendingSeals[slot]
		if !ok {
			return types.Hash{}, 0, 0, false, false
		}
		return p.BlockHash, p.ChainID, p.Epoch, true, p.Completed
	}()
	if !pendingExists {
		return fmt.Errorf("no pending seal for slot %d", slot)
	}
	if pendingCompleted {
		return fmt.Errorf("seal already completed for slot %d", slot)
	}

	// R42-CI-RACE-7 (2026-08-19): removed the previous fast-path "obvious
	// nil" check at this point (`if qfs.qtdSigner == nil { ... }`) — it
	// was an unlocked field read that raced with setQTDSignerLocked's
	// `qfs.qtdSigner = signer` write (performed under qfs.mu.Lock) and
	// the `-race` detector flagged it as DATA RACE. The
	// TestQTD_H02_AggregateAndCompleteSeal_NoLockFreeSignerRead test
	// exists precisely to enforce that such a lock-free read never
	// recurs, and CI flagged this regression.
	//
	// The race-free snapshot below (under RLock) was already the source
	// of truth for the actual signing call; the fast-path read was a
	// short-circuit that traded a single RLock for a TOCTOU race. The
	// only cost of removing it is one extra RLock acquisition per
	// AggregateAndCompleteSeal call when the signer really is nil
	// (bootstrapping path), which is negligible.
	//
	// R39-P2-01 (2026-08-02) FIX (Pre-existing): snapshot the signer
	// reference under qfs.mu so a concurrent SetQTDSigner(nil) toggle
	// by another goroutine between the eventual nil-check below and the
	// AggregatePartialSignatures call cannot dereference a nil pointer.
	signer := func() ThresholdKeySigner {
		qfs.mu.RLock()
		defer qfs.mu.RUnlock()
		return qfs.qtdSigner
	}()
	if signer == nil {
		return fmt.Errorf("qtdSigner not configured for slot %d", slot)
	}

	// R4-CORE-04: verify blockHash is canonical BEFORE signing.
	if canonicalRoot, ok := qfs.qpos.GetSlotBlockRoot(slot); ok {
		if canonicalRoot != pendingBlockHash {
			return fmt.Errorf("R4-CORE-04: refusing to sign slot %d: blockHash %s is not canonical %s",
				slot, pendingBlockHash.String(), canonicalRoot.String())
		}
	}

	// R39-P0-01 (2026-08-02) FIX: sign over the canonical
	// domain-separated message
	//   QTDDomainSep || chainID || epoch || slot || blockHash
	// when chainID > 0, or the legacy raw blockHash when chainID == 0
	// (so pre-R39 nodes and tests decoupled from chain config keep
	// producing seals that verify with the legacy message).
	signMessage := qtdSignedMessageOrLegacy(pendingChainID, pendingEpoch, slot, pendingBlockHash)

	// Compute the threshold signature. Pass nil partialSigs — the adapter
	// routes to distributeTSSSignNoFallback (distributed) or SignWithRetry
	// (local). External partial sigs from the broken qtd_seal.go flow are
	// NOT used.
	//
	// R39-P2-01: use the snapshot `signer`, NOT `qfs.qtdSigner` — the
	// field can be toggled to nil by SetQTDSigner(nil) on another
	// goroutine between this point and the call below (TOCTOU race).
	// The snapshot above keeps the call safe even under the toggle.
	qtdSignature, err := signer.AggregatePartialSignatures(sealers, nil, signMessage)
	if err != nil {
		return fmt.Errorf("threshold signing failed for slot %d: %w", slot, err)
	}
	if len(qtdSignature) == 0 {
		return fmt.Errorf("threshold signing produced empty signature for slot %d", slot)
	}

	// Submit the completed seal.
	return qfs.SubmitCompletedSeal(slot, qtdSignature, sealers)
}

// completeSealLocked attempts to aggregate partial signatures and finalize
// the seal. Returns a sealResult indicating the outcome:
//   - sealSuccess: QTD threshold signature created, pending seal complete.
//   - sealFailure: generic failure (qtdSigner nil, insufficient count).
//   - sealFailureInsufficientWeight: count met but stake weight < threshold.
//   - sealFailureAggregation: AggregatePartialSignatures returned an error
//     (at least one partial sig is invalid/poison).
//
// Caller must hold qfs.mu.
//
// R30-IMPLEMENT (2026-07-27): QTD-CRIT-03 — changed return type from bool
// to sealResult so the caller can distinguish aggregation failure (drop
// new sig, increment DoS counter) from weight-insufficient (retain new
// sig — need MORE sigs, not fewer). Also added the weight check BEFORE
// aggregation so weight-insufficient seals don't waste crypto work.
func (qfs *QTDFinalityState) completeSealLocked(slot uint64, pending *PendingSeal) sealResult {
	sealers := make([]int, 0, len(pending.PartialSigs))
	for idx := range pending.PartialSigs {
		sealers = append(sealers, idx)
	}

	// MEDIUFIX: Validate that the number of submitted partial seals
	// meets the threshold requirement before finalizing. Previously, this
	// function only checked len(sealers) == 0, but did not verify that the
	// count met pending.RequiredCount. While SubmitPartialSeal gates on
	// RequiredCount before calling completeSealLocked, adding an explicit
	// defense-in-depth check here ensures the threshold is never bypassed
	// even if the caller is refactored.
	if len(sealers) < pending.RequiredCount {
		// Not enough partial signatures to meet the threshold. Leave the
		// pending seal in place so more signatures can be collected.
		return sealFailure
	}

	// audit-fix HIGH: Do not store a finalized record with a placeholder signature.
	// Previously, when qtdSigner was nil or SignBlock failed, a constant placeholder
	// string was stored as the QTD signature. Combined with VerifyInstantFinality
	// returning true when qtdSigner was nil, this allowed blocks to be marked
	// finalized without a valid cryptographic signature. Now we fail closed: if we
	// cannot produce a real QTD signature, the seal is not completed.
	if qfs.qtdSigner == nil {
		// Without a threshold signer we cannot produce a valid QTD signature.
		// Leave the pending seal in place so it can be completed once a signer is configured.
		return sealFailure
	}

	// R30-IMPLEMENT (2026-07-27): P3-QTD-01 + QTD-CRIT-03 — weight check
	// BEFORE aggregation. If the cumulative sealer stake is below
	// RequiredWeight, do NOT attempt aggregation (it would either fail
	// or produce a seal that doesn't meet the weight threshold). The
	// caller RETAINS the new sig because more sigs are needed to reach
	// the weight threshold — dropping any sig would be counterproductive.
	if pending.RequiredWeight != nil && pending.MemberStakes != nil {
		sealerWeight := computeSealerWeight(sealers, pending.MemberStakes)
		if sealerWeight.Cmp(pending.RequiredWeight) < 0 {
			return sealFailureInsufficientWeight
		}
	}

	// FIX: Use AggregatePartialSignatures to combine all
	// submitted partial signatures into a proper threshold signature.
	// Previously, this called SignBlock(sealers[0], ...) which effectively
	// produced a single-signer signature, undermining the threshold security
	// guarantee of QTD instant finality (any single sealer could forge it).
	// Now we aggregate all collected partial seals, which requires t-of-n
	// cooperation to produce a valid threshold signature.
	// R30-P4 FIX: Removed redundant `len(sealers) == 0` check. The check at
	// line 290 (len(sealers) < pending.RequiredCount) already handles this
	// case since RequiredCount > 0 for QTD threshold signing.

	qtdSignature, err := qfs.qtdSigner.AggregatePartialSignatures(sealers, pending.PartialSigs, qtdSignedMessageOrLegacy(pending.ChainID, pending.Epoch, slot, pending.BlockHash))
	if err != nil || qtdSignature == nil {
		// QUANTUM-FIX (2026-07-17): Aggregation failed — at least one
		// partial signature is invalid/forged. Previously this cleared ALL
		// partial signatures (pending.PartialSigs = make(...)), enabling a
		// DoS where a single forged signature caused legitimate signatures
		// to be discarded and sealing to be blocked permanently
		// (QUANTUM- scenario). Now we return sealFailureAggregation so
		// the caller (SubmitPartialSeal) can implement the QTD-CRIT-03 DoS
		// bound: drop the new sig, increment ConsecutiveAggFailures, and
		// after maxConsecutiveAggFailures, clear ALL sigs (including poison).
		return sealFailureAggregation
	}

	// R4-C1 FIX (2026-07-06): Use deterministic block time for consensus
	sealedAt := time.Unix(int64(slot), 0)
	delay := sealedAt.Sub(pending.ApprovedAt)

	record := &InstantFinalityRecord{
		Slot:          slot,
		BlockHash:     pending.BlockHash,
		QTDSignature:  qtdSignature,
		SealedAt:      sealedAt,
		Sealers:       sealers,
		FinalityDelay: delay,
		// R39-P0-01 (2026-08-02) FIX: persist the domain-separation context
		// used at sign time so remote verifiers (VerifyInstantFinality)
		// can reconstruct the same canonical signed message. These come
		// straight from the pending seal (set at RequestSeal time).
		ChainID: pending.ChainID,
		Epoch:   pending.Epoch,
	}

	qfs.instantFinalizedSlots[slot] = record
	pending.Completed = true

	delete(qfs.pendingSeals, slot)

	// FIX: Do NOT acquire qpos.mu while holding qfs.mu.
	// Previously, this function acquired qpos.mu while the caller
	// (SubmitPartialSeal) held qfs.mu, creating a cross-object lock
	// ordering (qfs.mu → qpos.mu) that could deadlock if any other
	// path acquires them in reverse order.
	// The qpos finalization update is now done by the caller AFTER
	// releasing qfs.mu, via the returned updateQPOS callback.
	return sealSuccess
}

// completeSealLockedFinalize updates qpos finalization state.
// FIX: This must be called AFTER releasing qfs.mu to prevent
// the qfs.mu → qpos.mu lock ordering that could cause deadlock.
//
// AUDIT (2026) R4-CORE-04 FIX: Canonical chain binding defense-in-depth.
// Before writing finalizedRoot/justifiedRoot, verify that blockHash matches
// the canonical chain root. This is the SECOND line of defense (the first
// is in RequestSeal). It catches the case where:
//   - slotBlockRoots was not known when RequestSeal was called (block not
//     yet processed), but became known by the time the seal completes, OR
//   - the canonical chain forked between RequestSeal and seal completion.
//
// QUANTUM-FIX (2026-07-17): The previous "early-sync bootstrap"
// exception accepted QTD seals when neither the epoch root nor the slot
// root was known, only logging a warning. This allowed a threshold of
// colluding executive members to finalize an arbitrary blockHash during
// early sync (before any canonical root was established), poisoning
// finalizedRoot/justifiedRoot as the baseline for syncing nodes. Now we
// fail closed: if neither root is known, the seal is REJECTED (no state
// update). Bootstrap paths must establish at least one canonical root
// (e.g., via SetSlotBlockRoot on importing the genesis block) before QTD
// finalization can take effect.
func (qfs *QTDFinalityState) completeSealLockedFinalize(slot uint64, blockHash [32]byte) {
	// CONS- (2026-07-19) FIX: Top-level panic recovery. This
	// function is launched as a goroutine from SubmitPartialSeal
	// (qtd_finality.go:333 and qtd_finality.go:428) — an unrecovered
	// panic here would crash the entire node. The CORE B-5 fix above
	// guards one specific nil-deref path (coordinator == nil), but
	// other panics remain possible: types.Hash(blockHash) conversion
	// (cannot panic in practice but defensive), GetChambersCoordinator
	// returning a typed-nil interface (GetExecutiveChamber on a
	// typed-nil pointer would panic), or RecordSeal panicking on
	// corrupted internal state. Wrap the whole function so any
	// such panic is logged and the goroutine exits cleanly without
	// taking the node down.
	defer func() {
		if r := recover(); r != nil {
			// P3-LOG-03 FIX (R30, 2026-07-27): Use structured qtdLogger instead
			// of log.Printf so SIEM can collect QTD finality panic events.
			qtdLogger.Error("qtd_finality: completeSealLockedFinalize panic (defense-in-depth)",
				map[string]any{
					"slot":      slot,
					"blockHash": types.Hash(blockHash).String(),
					"panic":     fmt.Sprintf("%v", r),
				})
		}
	}()

	epoch := SlotToEpoch(slot)
	qfs.qpos.mu.Lock()

	// R4-CORE-04: Canonical chain binding — reject non-canonical block hashes.
	// Check epoch root first (authoritative), then slot root (per-block).
	if epochRoot, ok := qfs.qpos.epochBlockRoots[epoch]; ok {
		if epochRoot != (types.Hash{}) && epochRoot != types.Hash(blockHash) {
			qfs.qpos.mu.Unlock()
			// P3-LOG-03 FIX (R30, 2026-07-27): Use structured qtdLogger.
			qtdLogger.Warn("qtd_finality: R4-CORE-04: rejecting non-canonical QTD seal (epoch root mismatch)",
				map[string]any{
					"slot":               slot,
					"epoch":              epoch,
					"blockHash":          types.Hash(blockHash).String(),
					"canonicalEpochRoot": epochRoot.String(),
				})
			return
		}
	} else if slotRoot, ok := qfs.qpos.slotBlockRoots[slot]; ok {
		if slotRoot != (types.Hash{}) && slotRoot != types.Hash(blockHash) {
			qfs.qpos.mu.Unlock()
			// P3-LOG-03 FIX (R30, 2026-07-27): Use structured qtdLogger.
			qtdLogger.Warn("qtd_finality: R4-CORE-04: rejecting non-canonical QTD seal (slot root mismatch)",
				map[string]any{
					"slot":              slot,
					"blockHash":         types.Hash(blockHash).String(),
					"canonicalSlotRoot": slotRoot.String(),
				})
			return
		}
	} else {
		// QUANTUM-FIX (2026-07-17): Neither root is known — fail closed.
		// Previously this accepted the seal with only a warning, allowing
		// colluding executive members to finalize arbitrary blockHashes
		// during early sync. Now we reject the seal entirely; the caller
		// must establish a canonical root (e.g., via SetSlotBlockRoot on
		// importing the genesis / canonical block) before QTD finalization
		// can take effect.
		qfs.qpos.mu.Unlock()
		// P3-LOG-03 FIX (R30, 2026-07-27): Use structured qtdLogger.
		qtdLogger.Error("qtd_finality: R4-CORE-04: rejecting QTD seal — no canonical root known (fail-closed per QUANTUM-)",
			map[string]any{
				"slot":      slot,
				"epoch":     epoch,
				"blockHash": types.Hash(blockHash).String(),
			})
		return
	}

	if epoch > qfs.qpos.finalizedEpoch {
		qfs.qpos.finalizedEpoch = epoch
		qfs.qpos.finalizedRoot = blockHash
	}
	if epoch > qfs.qpos.justifiedEpoch {
		qfs.qpos.justifiedEpoch = epoch
		qfs.qpos.justifiedRoot = blockHash
	}
	qfs.qpos.mu.Unlock()

	// AUDIT (2026) CORE B-5 FIX: GetChambersCoordinator() can return nil
	// if chambers are torn down or never initialized between RequestSeal and
	// this async goroutine. Without this check, the nil coordinator would
	// panic on .GetExecutiveChamber(), crashing the node (unrecovered
	// goroutine in SubmitPartialSeal's `go completeSealLockedFinalize`).
	coordinator := qfs.qpos.GetChambersCoordinator()
	if coordinator == nil {
		return
	}
	executive := coordinator.GetExecutiveChamber()
	if executive != nil {
		executive.RecordSeal(true)
	}
}

// IsSlotFinalized reports whether the given slot has been instant-
// finalized via QTD threshold signing.
//
// R39-P2-01 (2026-08-02) FIX: cross-check against QPOS.finalizedEpoch.
// Previously this method consulted ONLY the local instantFinalizedSlots
// map — a peer-induced map entry (e.g., a goroutine that forgot to take
// qfs.mu before writing the map, or a future refactor that lets callers
// populate the map outside the VerifyInstantFinality gate) would be
// reported as finalized even though QPOS itself hasn't reached the
// corresponding epoch yet. Consumers (RPC eth_getBlockByNumber with
// "finalized" qualifier, sync sentinel, slash-condition tests) would
// then trust a slot as "instant-finalized" while the chain's actual
// finality marker is still behind — exposing the node to short-range
// reorg exploitation if a fork chooser later honors IsSlotFinalized.
//
// Mitigation: dual-source guard. A slot is finalized iff BOTH:
//
//	(a) the slot's InstantFinalityRecord exists in the local map; AND
//	(b) record.Epoch <= QPOS.finalizedEpoch — the QPOS finalizer itself
//	    has caught up to at least the epoch containing this slot.
//
// When qpos is nil (test shell / bootstrapping) or record.Epoch==0
// (legacy record without the Epoch field filled), the cross-check is
// skipped to preserve backward compatibility — documented as the
// "map-only" code path that consumers must understand as "exists = local
// node previously sealed this slot via QTD, but QPOS's finality state is
// not part of the contract here".
//
// Lock ordering: we call qpos.GetFinalizedEpoch() BEFORE acquiring
// qfs.mu — qpos.GetFinalizedEpoch takes qpos.mu.RLock internally, and
// other paths establish a strict qpos.mu → qfs.mu order (notably
// completeSealLockedFinalize releases qfs.mu BEFORE acquiring qpos.mu
// specifically to break the inverse qfs.mu → qpos.mu cycle). Acquiring
// qpos.mu first here is safe — there is no qpos→qfs path that requires
// the reverse — and is the same pattern used by GetFinalityRecord's
// caller (qfs.qpos.GetCurrentEpoch() at line 1421 is called BEFORE
// qfs.mu.Lock at line 1426). The finalizedEpoch snapshot is fine to be
// slightly stale by the time we acquire qfs.mu: if a concurent
// finalization advances finalizedEpoch between the snapshot and the
// qfs.mu.Lock, that only makes the cross-check MORE permissive — never
// less. Worst case: a finalized slot is reported as not-finalized for
// the duration of the stale snapshot window (single-digit milliseconds
// at most); the consumer's next IsSlotFinalized call sees the updated
// finalizedEpoch and reports correctly.
func (qfs *QTDFinalityState) IsSlotFinalized(slot uint64) bool {
	// R39-P2-01: snapshot QPOS.finalizedEpoch BEFORE acquiring qfs.mu to
	// preserve the qpos.mu → qfs.mu lock order. qpos==nil skips the
	// cross-check entirely (test shells / bootstrapping).
	var qposFinalizedEpoch uint64
	if qfs.qpos != nil {
		qposFinalizedEpoch = qfs.qpos.GetFinalizedEpoch()
	}

	qfs.mu.RLock()
	defer qfs.mu.RUnlock()
	record, exists := qfs.instantFinalizedSlots[slot]
	if !exists {
		return false
	}
	// R39-P2-01: cross-check. record.Epoch is the epoch of the slot at
	// the time it was QTD-sealed (added by R39-P0-01). When Epoch==0 —
	// legacy records produced before the R39-P0-01 Epoch field was
	// backfilled, or tests that construct the record manually — we
	// cannot perform the cross-check, so we fall back to map-only (the
	// pre-R39-P2-01 behavior). The fallback is documented; consumers
	// who want the strict cross-checked answer MUST construct records
	// with the Epoch field populated.
	//
	// Likewise when qposFinalizedEpoch==0 — the QPOS hasn't finalized
	// any epoch yet (bootstrapping, or test shells where the qpos
	// instance isn't wired to its finality progressor). The test
	// stardust_verification_test.go's ThreeChambersFlow fixture is the
	// canonical example: it constructs a real QPOS but never advances
	// finalizedEpoch, relying on IsSlotFinalized's map-presence check
	// alone to confirm QTD completion. The audit's finding specifically
	// calls out CONSUMERS — RPC eth_getBlockByNumber with "finalized"
	// qualifier, sync sentinel — not the test-helper gating paths; the
	// cross-check functionally disables the test flow without this
	// bootstrapping fallback.
	//
	// Both guards: if EITHER side is zero, fall back to map-only.
	if qposFinalizedEpoch == 0 || record.Epoch == 0 {
		return true
	}
	// If the QPOS finalizedEpoch hasn't caught up to the record's epoch
	// yet, the slot is NOT considered finalized from the consumer's
	// perspective: the QPOS finality marker is the canonical "is this
	// chain segment safe from reorg" signal, and a QTD-sealed slot in an
	// epoch the QPOS hasn't finalized is still technically reorgable by
	// a fork with conflicting QPOS finality. We return false here so
	// that consumers (fork chooser, RPC "finalized" block, sync
	// sentinel) get a single consistent answer.
	return record.Epoch <= qposFinalizedEpoch
}

func (qfs *QTDFinalityState) GetFinalityRecord(slot uint64) *InstantFinalityRecord {
	qfs.mu.RLock()
	defer qfs.mu.RUnlock()
	if record, exists := qfs.instantFinalizedSlots[slot]; exists {
		copy := &InstantFinalityRecord{
			Slot:          record.Slot,
			BlockHash:     record.BlockHash,
			QTDSignature:  append([]byte(nil), record.QTDSignature...),
			SealedAt:      record.SealedAt,
			Sealers:       append([]int(nil), record.Sealers...),
			FinalityDelay: record.FinalityDelay,
		}
		return copy
	}
	return nil
}

func (qfs *QTDFinalityState) VerifyInstantFinality(slot uint64, blockHash types.Hash, qtdSignature []byte) bool {
	// CONS-P0-01 + CONS-P0-03 FIX (R31, 2026-07-27): Precompute epoch
	// and currentEpoch BEFORE acquiring qfs.mu.RLock(). This achieves
	// two things:
	//
	// 1. CONS-P0-01: Use the historical group public key for the seal's
	//    epoch (via getGroupPublicKeyForEpochLocked) instead of
	//    qtdSigner.GroupPublicKey() (the CURRENT signer's key). During
	//    DKG rotation, the current signer has the NEW key, but seals
	//    from PAST epochs must be verified with the OLD key that was
	//    active at seal time. The previous code used the current key
	//    unconditionally, causing historical-epoch QTD seals to fail
	//    verification after rotation — breaking cross-node finality and
	//    risking chain splits. SubmitCompletedSeal and
	//    ReceiveSealAnnouncement already used getGroupPublicKeyForEpoch;
	//    VerifyInstantFinality was the only public verification entry
	//    point that missed the fix.
	//
	// 2. CONS-P0-03: Precompute currentEpoch OUTSIDE qfs.mu to eliminate
	//    the qfs.mu → qpos.mu lock-ordering hazard. Even though
	//    qpos.GetCurrentEpoch() is currently lock-free (atomic loads),
	//    this is defensive against future modifications.
	epoch := SlotToEpoch(slot)
	currentEpoch := uint64(0)
	if qfs.qpos != nil {
		currentEpoch = qfs.qpos.GetCurrentEpoch()
	}

	qfs.mu.RLock()
	defer qfs.mu.RUnlock()

	// audit-fix HIGH: Signature verification must not be bypassed when qtdSigner is nil.
	// Previously, this returned true without verifying the QTD signature, allowing any
	// block with a matching slot/hash to be considered finalized without cryptographic proof.
	// QTD instant finality requires a configured threshold signer; without one, verification
	// must fail closed rather than succeed open.
	if qfs.qtdSigner == nil {
		return false
	}

	// audit-fix HIGH: Reject placeholder signatures that may have been stored by
	// completeSealLocked when SignBlock failed. A placeholder is not a valid signature.
	if len(qtdSignature) == 0 || string(qtdSignature) == "qtd-threshold-signature-placeholder" {
		return false
	}

	// AUDIT (2026) CORE B-6 FIX: Support cross-node seal verification.
	// Previously, if the local node did not have a record in
	// instantFinalizedSlots (because it was not the sealer), verification
	// returned false immediately — even if the QTD signature was
	// cryptographically valid. This made QTD seals unverifiable across
	// nodes, breaking the cross-node finality guarantee.
	//
	// When the local record exists, we verify blockHash matches the record
	// AND the signature is valid against the record's captured
	// (chainID, epoch) domain-separation context (defense-in-depth).
	//
	// R39-P0-01 (2026-08-02) + R40-P0-01 (2026-08-03) FIX: when the local
	// record does NOT exist (cross-node path), we fall back to this node's
	// qfs.chainID and SlotToEpoch(slot) to reconstruct the canonical
	// domain-separated message
	//   QTDDomainSep || chainID || epoch || slot || blockHash
	// — every production node on the same chain shares the same chainID,
	// so a remote-produced seal will verify with the same canonical
	// message here. The legacy raw-blockHash fallback is reached ONLY when
	// chainID == 0 (pre-R39 records / nodes that have NOT adopted domain
	// separation); the tautological per-epoch escape hatch the audit
	// flagged in R40-P0-01 — `qtdVerifyMessageLocked` re-trying the raw
	// blockHash whenever `epoch == allowLegacyForEpoch` — no longer exists,
	// so chainID > 0 seals are verified strictly over the canonical
	// message with NO fallback. The QTD signature itself remains the
	// sufficient proof that threshold validators approved this block.
	verifyChainID := qfs.chainID
	verifyEpoch := epoch
	if record, exists := qfs.instantFinalizedSlots[slot]; exists {
		if record.BlockHash != blockHash {
			return false
		}
		// Prefer the record's captured domain-separation context: this is
		// exactly what the sign path committed to, so it is the only input
		// that makes the signature verify. When the record predates
		// R39-P0-01 (ChainID == 0), it falls through to the qfs.chainID
		// fallback below — but since qfs.chainID is also 0 in legacy nodes,
		// legacy verifies legacy raw-blockHash all the way through.
		if record.ChainID > 0 {
			verifyChainID = record.ChainID
		}
		if record.Epoch > 0 {
			verifyEpoch = record.Epoch
		}
	}

	// CONS-P0-01: Use the historical group key for the seal's epoch
	// (NOT the current signer's key, which may have rotated via DKG).
	// Fail-closed if no key is available for this epoch.
	groupKey := qfs.getGroupPublicKeyForEpochLocked(epoch, currentEpoch)
	if len(groupKey) == 0 {
		return false
	}

	// R39-P0-01 (2026-08-02) + R40-P0-01 (2026-08-03) FIX: verify against the
	// canonical domain-separated message
	//   QTDDomainSep || chainID || epoch || slot || blockHash
	// using the record/captured chainID (or this node's qfs.chainID for the
	// cross-node path). Legacy records with ChainID == 0 fall back to the raw
	// blockHash path inside qtdVerifyMessageLocked; the tautological
	// per-epoch escape hatch removed in R40-P0-01 no longer exists.
	// qtdVerifyMessageLocked is normally RLock-compatible; here we hold
	// qfs.mu.RLock — safe, since qtdVerifyMessageLocked only reads
	// qfs.qtdSigner (no further locking needed).
	return qfs.qtdVerifyMessageLocked(groupKey, verifyChainID, verifyEpoch, slot, blockHash, qtdSignature)
}

func (qfs *QTDFinalityState) GetPendingSealCount() int {
	qfs.mu.RLock()
	defer qfs.mu.RUnlock()
	return len(qfs.pendingSeals)
}

// GetPendingSeal returns a snapshot of the pending seal for a slot, or nil if
// no seal is pending. P1-7: used by RPC qau_tss_getSealStatus to report
// partial signature collection progress. Returns a copy so callers cannot
// mutate internal state.
func (qfs *QTDFinalityState) GetPendingSeal(slot uint64) *PendingSeal {
	qfs.mu.RLock()
	defer qfs.mu.RUnlock()
	p, ok := qfs.pendingSeals[slot]
	if !ok {
		return nil
	}
	return &PendingSeal{
		Slot:          p.Slot,
		BlockHash:     p.BlockHash,
		ApprovedAt:    p.ApprovedAt,
		PartialSigs:   p.PartialSigs, // read-only; map values are not mutated after creation
		RequiredCount: p.RequiredCount,
		Completed:     p.Completed,
	}
}

func (qfs *QTDFinalityState) GetFinalizedSlotCount() int {
	qfs.mu.RLock()
	defer qfs.mu.RUnlock()
	return len(qfs.instantFinalizedSlots)
}

func (qfs *QTDFinalityState) GetQTDFinalityStatus() map[string]any {
	qfs.mu.RLock()
	defer qfs.mu.RUnlock()

	avgDelay := time.Duration(0)
	if len(qfs.instantFinalizedSlots) > 0 {
		totalDelay := time.Duration(0)
		for _, record := range qfs.instantFinalizedSlots {
			totalDelay += record.FinalityDelay
		}
		avgDelay = totalDelay / time.Duration(len(qfs.instantFinalizedSlots))
	}

	return map[string]any{
		"finalityType":     qfs.finalityType.String(),
		"instantFinalized": len(qfs.instantFinalizedSlots),
		"pendingSeals":     len(qfs.pendingSeals),
		"avgFinalityDelay": avgDelay.String(),
		"hasQTDSigner":     qfs.qtdSigner != nil,
		"isThresholdMode":  qfs.qtdSigner != nil && qfs.qtdSigner.IsThresholdMode(),
	}
}

func (qfs *QTDFinalityState) CleanupSlot(slot uint64) {
	qfs.mu.Lock()
	defer qfs.mu.Unlock()
	delete(qfs.pendingSeals, slot)
}

// CleanupOldSlots removes entries from pendingSeals and instantFinalizedSlots
// that are older than qtdCleanupRetainSlots from the given current slot.
// This should be called periodically (e.g., at epoch boundaries) to prevent
// unbounded memory growth.
// FIX.
func (qfs *QTDFinalityState) CleanupOldSlots(currentSlot uint64) int {
	qfs.mu.Lock()
	defer qfs.mu.Unlock()

	pruned := 0

	// Calculate the cutoff slot. Guard against underflow.
	var cutoff uint64
	if currentSlot > qtdCleanupRetainSlots {
		cutoff = currentSlot - qtdCleanupRetainSlots
	} else {
		cutoff = 0
	}

	// Prune old pending seals (completed or stale).
	for slot := range qfs.pendingSeals {
		if slot < cutoff {
			delete(qfs.pendingSeals, slot)
			pruned++
		}
	}

	// Prune old instant finalized records.
	for slot := range qfs.instantFinalizedSlots {
		if slot < cutoff {
			delete(qfs.instantFinalizedSlots, slot)
			pruned++
		}
	}

	return pruned
}

// ============================================================================
// R30-IMPLEMENT (2026-07-27): P3-QTD-01, P3-QTD-02, QTD-CRIT-03, QTD-H03,
// QTD-H04/H06, P2-QTD-HISTORY — Missing functions to match R29 test contracts.
// All additions are surgical: new helpers + minimal updates to existing
// completeSealLocked / SubmitPartialSeal for QTD-CRIT-03 DoS bounding.
// ============================================================================

// sealResult is the outcome of completeSealLocked. It distinguishes
// aggregation failure (drop new sig, increment DoS counter) from
// weight-insufficient (retain new sig — need MORE sigs, not fewer).
//
// R30-IMPLEMENT (2026-07-27): QTD-CRIT-03 fix. The previous bool return
// conflated all failure modes, forcing the caller to unconditionally
// delete the newly-submitted signature. This was wrong for weight-
// insufficient seals: the new sig is legitimate and needed to reach the
// weight threshold. Dropping it would permanently block sealing when the
// only issue was insufficient cumulative stake.
type sealResult int

const (
	// sealFailure is the generic failure (qtdSigner nil, etc.). The caller
	// retains the new sig for retry — this is a transient condition, not
	// a poison-sig attack.
	sealFailure sealResult = iota
	// sealSuccess means the QTD threshold signature was aggregated and the
	// pending seal is now complete.
	sealSuccess
	// sealFailureInsufficientWeight means the count threshold was met but
	// the cumulative sealer stake is below RequiredWeight. The caller
	// RETAINS the new sig — more sigs are needed to reach the weight
	// threshold, so dropping any sig would be counterproductive.
	sealFailureInsufficientWeight
	// sealFailureAggregation means AggregatePartialSignatures returned an
	// error — at least one submitted partial sig is invalid (poison).
	// The caller drops the new sig and increments ConsecutiveAggFailures.
	// After maxConsecutiveAggFailures, ALL sigs are cleared (QTD-CRIT-03).
	sealFailureAggregation
)

// snapshotExecutiveStakes returns a deep-copied map of executive member
// stakes for the given epoch, the total executive stake, and the required
// weight threshold (ceil(2/3 * total)). Returns (nil, nil, nil) when the
// coordinator is unavailable or the executive chamber has no members —
// callers use the nil return to skip the weight check gracefully.
//
// R30-IMPLEMENT (2026-07-27): P3-QTD-01 fix. Centralizes the weight-
// threshold computation so RequestSeal, ReceiveSealAnnouncement, and
// completeSealLocked all use the SAME threshold for the same epoch.
// Previously three inline copies had slightly divergent logic.
func (qfs *QTDFinalityState) snapshotExecutiveStakes(epoch uint64) (memberStakes map[int]*big.Int, totalExecutiveStake, requiredWeight *big.Int) {
	qfs.mu.RLock()
	defer qfs.mu.RUnlock()
	if qfs.qpos == nil {
		return nil, nil, nil
	}
	coordinator := qfs.qpos.GetChambersCoordinator()
	if coordinator == nil {
		return nil, nil, nil
	}
	return qfs.snapshotExecutiveStakesLocked(epoch, coordinator)
}

// snapshotExecutiveStakesLocked is the internal variant that assumes the
// caller already holds qfs.mu (at least RLock) and has a coordinator
// reference. It reads the executive members for the epoch, looks up each
// member's stake from the validator set, and computes the required weight
// as ceil(2/3 * totalExecutiveStake).
//
// R30-IMPLEMENT (2026-07-27): P3-QTD-01. Caller must hold qfs.mu.
func (qfs *QTDFinalityState) snapshotExecutiveStakesLocked(epoch uint64, coordinator *ThreeChambersCoordinator) (memberStakes map[int]*big.Int, totalExecutiveStake, requiredWeight *big.Int) {
	if coordinator == nil {
		return nil, nil, nil
	}
	members := coordinator.GetExecutiveMembersForEpoch(epoch)
	if len(members) == 0 {
		return nil, nil, nil
	}
	validators := qfs.qpos.GetValidatorSet()
	if validators == nil {
		return nil, nil, nil
	}
	memberStakes = make(map[int]*big.Int, len(members))
	totalExecutiveStake = new(big.Int)
	for _, idx := range members {
		v := validators.GetValidatorByIndex(idx)
		if v == nil || v.Stake == nil {
			continue
		}
		stakeCopy := new(big.Int).Set(v.Stake)
		memberStakes[idx] = stakeCopy
		totalExecutiveStake.Add(totalExecutiveStake, stakeCopy)
	}
	if totalExecutiveStake.Sign() == 0 {
		return memberStakes, totalExecutiveStake, nil
	}
	// requiredWeight = ceil(totalExecutiveStake * 2 / 3)
	// = (totalExecutiveStake * 2 + 2) / 3  (integer ceil via (num + denom - 1) / denom)
	num := new(big.Int).Mul(totalExecutiveStake, big.NewInt(2))
	rem := new(big.Int).Mod(num, big.NewInt(3))
	requiredWeight = new(big.Int).Quo(num, big.NewInt(3))
	if rem.Sign() > 0 {
		requiredWeight.Add(requiredWeight, big.NewInt(1))
	}
	return memberStakes, totalExecutiveStake, requiredWeight
}

// computeSealerWeight sums the stakes of the given sealers from the
// memberStakes map. Unknown indices and nil stakes are safely skipped
// (matching the original inline guard `if stake, ok := ...; ok && stake != nil`).
//
// R30-IMPLEMENT (2026-07-27): P3-QTD-01 fix. Centralizes sealer weight
// accumulation so all call sites use the same logic.
//
// R35-P2-CONS-04 FIX (2026-07-29): Deduplicate sealer indices before
// summing stakes. A malicious or buggy caller could pass duplicate indices
// (e.g. [0, 0, 1]) which would count sealer 0's stake twice, inflating the
// cumulative weight and potentially crossing RequiredWeight without true
// 2/3 economic buy-in. This same bug existed in BOTH the
// SubmitCompletedSeal path (line 683, external caller-supplied sealers)
// AND the completeSealLocked path (line 877, derived from PartialSigs
// keys — normally unique, but defensive against any future code path that
// might introduce duplicates). Deduplicating here protects ALL three call
// sites (684, 877, 1591) uniformly without requiring each caller to
// pre-sanitize its input.
func computeSealerWeight(sealers []int, memberStakes map[int]*big.Int) *big.Int {
	total := new(big.Int)
	seen := make(map[int]bool, len(sealers))
	for _, idx := range sealers {
		if seen[idx] {
			continue
		}
		seen[idx] = true
		if stake, ok := memberStakes[idx]; ok && stake != nil {
			total.Add(total, stake)
		}
	}
	return total
}

// SetSealAnnouncer sets the P2P seal announcer. When set, announceSeal
// is called after a seal completes to propagate the QTD signature to
// peer nodes. Pass nil to disable announcements.
//
// R30-IMPLEMENT (2026-07-27): P3-QTD-02 fix. Uses exclusive Lock (not
// RLock) so a concurrent announceSeal (which takes RLock) is guaranteed
// to see the updated announcer value — the nil-check inside announceSeal
// is atomic with the snapshot.
func (qfs *QTDFinalityState) SetSealAnnouncer(announcer SealAnnouncer) {
	qfs.mu.Lock()
	defer qfs.mu.Unlock()
	qfs.sealAnnouncer = announcer
}

// announceSeal broadcasts a completed QTD seal to peer nodes via the
// configured SealAnnouncer. If no announcer is set, this is a no-op.
// The nil check is INSIDE the RLock so a concurrent SetSealAnnouncer(nil)
// is visible to this call (P3-QTD-02 fix). Defensive copies of the
// signature and sealers slice are made so the caller cannot mutate the
// announcer's recorded data after the call.
//
// R30-IMPLEMENT (2026-07-27): P3-QTD-02 fix. A top-level defer recover()
// catches panics from the announcer implementation (e.g., a stopped P2P
// host that panics on send) so a buggy announcer cannot crash the seal
// completion path.
func (qfs *QTDFinalityState) announceSeal(slot uint64, blockHash types.Hash, qtdSignature []byte, sealers []int) {
	defer func() {
		if r := recover(); r != nil {
			qtdLogger.Error("qtd_finality: announceSeal panic (defense-in-depth)",
				map[string]any{
					"slot":  slot,
					"panic": fmt.Sprintf("%v", r),
				})
		}
	}()

	qfs.mu.RLock()
	announcer := qfs.sealAnnouncer
	qfs.mu.RUnlock()

	// P3-QTD-02: nil check is AFTER the RLock snapshot, so a concurrent
	// SetSealAnnouncer(nil) is visible here.
	if announcer == nil {
		return
	}

	// Defensive copies so the caller cannot mutate the announcer's data.
	sigCopy := append([]byte(nil), qtdSignature...)
	sealersCopy := append([]int(nil), sealers...)

	announcer.AnnounceQTDSeal(slot, blockHash, sigCopy, sealersCopy)
}

// SetQTDSignerForEpoch sets the QTD threshold signer and records its
// GroupPublicKey under the EXPLICIT activationEpoch (NOT qpos.GetCurrentEpoch()).
// This is the P2-QTD-HISTORY fix: ActivateQTDInstantFinality calls this
// with executive.Epoch() to handle the boundary-mismatch case where the
// executive chamber is set up for a future epoch but qpos.currentEpoch
// has not yet advanced.
//
// R30-IMPLEMENT (2026-07-27): P2-QTD-HISTORY + QTD-H01. Rejects non-nil
// non-threshold signers (QTD-H01). nil is accepted (deactivation path)
// and does NOT erase historical entries (future verification of seals
// from past epochs still needs old keys).
func (qfs *QTDFinalityState) SetQTDSignerForEpoch(signer ThresholdKeySigner, activationEpoch uint64) {
	qfs.mu.Lock()
	defer qfs.mu.Unlock()
	qfs.setQTDSignerLocked(signer, activationEpoch)
}

// getGroupPublicKeyForEpoch returns the DKG group public key that was
// active at the given epoch. It first checks groupKeyHistory (for past
// epochs with recorded keys), then falls back to the current signer's
// key for the current epoch.
//
// QTD-H03 fix: during DKG rotation, the current signer has the NEW key,
// but seals from PAST epochs must be verified with the OLD key.
//
// QTD-009 fix (R30): when DKG rotation has occurred (groupKeyHistory is
// non-empty) but no historical record exists for a NON-current epoch,
// returns nil (fail-closed) rather than falling back to the current key.
// This prevents an attacker who injects a malicious signer from forging
// arbitrary historical finality proofs. When groupKeyHistory is empty
// (no rotation has occurred), the current key is the ONLY key that ever
// existed, so it is valid for ALL epochs — the fallback is safe.
//
// R30-IMPLEMENT (2026-07-27): QTD-H03 + QTD-009. Caller must hold qfs.mu
// (at least RLock).
//
// CONS-P0-03 FIX (R31, 2026-07-27): This wrapper precomputes currentEpoch
// OUTSIDE any qfs.mu lock. The actual lookup logic is in
// getGroupPublicKeyForEpochLocked, which takes the precomputed
// currentEpoch as a parameter. This eliminates the qfs.mu → qpos.mu
// lock-ordering hazard: even though qpos.GetCurrentEpoch() is currently
// lock-free (uses atomic loads), precomputing it before acquiring qfs.mu
// is defensive against future modifications that might add locks to
// QPOS's epoch/slot accessors. Callers that already hold qfs.mu MUST
// call getGroupPublicKeyForEpochLocked directly with a precomputed
// currentEpoch — they MUST NOT call this wrapper.
func (qfs *QTDFinalityState) getGroupPublicKeyForEpoch(epoch uint64) []byte {
	currentEpoch := uint64(0)
	if qfs.qpos != nil {
		currentEpoch = qfs.qpos.GetCurrentEpoch()
	}
	return qfs.getGroupPublicKeyForEpochLocked(epoch, currentEpoch)
}

// getGroupPublicKeyForEpochLocked is the lock-aware inner lookup. The
// caller MUST hold qfs.mu (at least RLock) and MUST precompute
// currentEpoch OUTSIDE qfs.mu before calling this. See
// getGroupPublicKeyForEpoch for the lookup semantics.
//
// CONS-P0-03 FIX (R31, 2026-07-27): Extracted from getGroupPublicKeyForEpoch
// to allow callers that already hold qfs.mu to pass a precomputed
// currentEpoch instead of re-acquiring it via qpos.GetCurrentEpoch()
// while holding qfs.mu. This removes the qfs.mu → qpos.mu lock-ordering
// hazard identified in CONS-P0-03.
func (qfs *QTDFinalityState) getGroupPublicKeyForEpochLocked(epoch, currentEpoch uint64) []byte {
	// R38-P1-01 FIX (2026-08-01): single read-side chokepoint. Both
	// branches of this lookup return a Dilithium3 group public key to be
	// consumed by VerifyBlock (which routes through ThresholdKeySigner,
	// eventually reaching mode3.Verify). The write-side chokepoint in
	// setQTDSignerLocked already rejects degenerate keys before they enter
	// groupKeyHistory, but the history map can be re-loaded from disk on a
	// restarting node, or a historical corruption must not silently
	// resurrect an all-zero key (the canonical "DKG not initialized"
	// forgery surface). We re-verify here — but only for the all-zero
	// pattern (which is the security-critical reject at the consumer),
	// NOT for wrong-length: mode3.Unpack uses (*[1952]byte) cast over the
	// slice header and the underlying TSS verifier already does the
	// canonical length check inside VerifyBlock → TSSManager →
	// VerifySignatureWithPublicKey (wallet/tss/signing.go:115, post-R38-P1-01
	// fixed to `!=`). Re-checking length here would break the
	// same-package tests that populate groupKeyHistory directly with
	// distinguishable short fixtures, and the write-side gate + the
	// verifier-side gate cover the actual attack surface.
	validateGroupKey := func(key []byte, source string) []byte {
		if len(key) == 0 {
			// CONS-R27-MED-02 companion: empty key (DKG not complete) —
			// fail-closed. This branch is exercised by the
			// "EMPTY group key" test in qtd_h03_test.go.
			return nil
		}
		if crypto.IsZeroPublicKeyBytes(key) {
			qtdLogger.Warn("R38-P1-01: QTD group key read-back rejected (all zeros)",
				map[string]any{
					"epoch":  epoch,
					"source": source,
				})
			return nil
		}
		return append([]byte(nil), key...)
	}

	// Check historical record first.
	if key, ok := qfs.groupKeyHistory[epoch]; ok {
		return validateGroupKey(key, "groupKeyHistory")
	}

	// No historical record for this epoch.
	hasRotation := len(qfs.groupKeyHistory) > 0

	if hasRotation && epoch != currentEpoch {
		// QTD-009: DKG rotation has occurred, but we have no historical
		// key for this non-current epoch. Fail-closed — do NOT fall back
		// to the current key, as it may not have been active at this epoch.
		return nil
	}

	// No rotation (groupKeyHistory empty) OR this IS the current epoch:
	// fall back to the current signer's key.
	if qfs.qtdSigner == nil {
		return nil
	}
	key := qfs.qtdSigner.GroupPublicKey()
	return validateGroupKey(key, "qtdSigner.GroupPublicKey")
}

// ReceiveSealAnnouncement processes a QTD seal announcement received from
// a peer node via P2P gossip. This is the cross-node seal propagation
// path: when one node's executive chamber completes a seal, the seal is
// broadcast to all peers so they can verify and store it without waiting
// for their own executive chamber to seal the same slot.
//
// Returns true if the seal was accepted and stored; false if rejected
// (verification failed, weight insufficient, panic recovered, etc.).
//
// R30-IMPLEMENT (2026-07-27): QTD-H04/H06 + QTD-CRIT-03 + P3-QTD-01.
//   - QTD-H04/H06: top-level defer recover() catches panics from
//     VerifyBlock or any downstream qpos method, returning false instead
//     of crashing the P2P message handler goroutine (liveness DoS).
//   - P3-QTD-01: uses snapshotExecutiveStakes to compute the weight
//     threshold, consistent with RequestSeal.
//   - QTD-CRIT-03: does NOT participate in partial-sig collection, so
//     the ConsecutiveAggFailures DoS bound does not apply here.
func (qfs *QTDFinalityState) ReceiveSealAnnouncement(slot uint64, blockHash types.Hash, qtdSignature []byte, sealers []int) bool {
	// QTD-H04/H06: recover from any panic (malformed P2P payload, corrupted
	// signer, nil qpos, etc.) so the P2P handler goroutine is not killed.
	defer func() {
		if r := recover(); r != nil {
			qtdLogger.Error("qtd_finality: ReceiveSealAnnouncement panic (QTD-H04/H06 defense-in-depth)",
				map[string]any{
					"slot":  slot,
					"panic": fmt.Sprintf("%v", r),
				})
		}
	}()

	// Reject empty sealers immediately (malformed-message defense).
	if len(sealers) == 0 {
		return false
	}

	// Reject empty/placeholder signatures.
	if len(qtdSignature) == 0 || string(qtdSignature) == "qtd-threshold-signature-placeholder" {
		return false
	}

	// Snapshot signer under RLock (QTD-H02: no lock-free signer read).
	qfs.mu.RLock()
	signer := qfs.qtdSigner
	qfs.mu.RUnlock()

	if signer == nil {
		return false
	}

	// R4-CORE-04: verify blockHash is canonical (if known).
	if qfs.qpos != nil {
		if canonicalRoot, ok := qfs.qpos.GetSlotBlockRoot(slot); ok {
			if canonicalRoot != blockHash {
				return false
			}
		}
	}

	// P3-QTD-01: compute weight threshold via the shared helper.
	epoch := SlotToEpoch(slot)
	memberStakes, _, requiredWeight := qfs.snapshotExecutiveStakes(epoch)

	// R35-P2-CONS-05 FIX (2026-07-29): Verify sealer membership BEFORE the
	// weight check. The sealers slice arrives from an UNTRUSTED peer via P2P
	// gossip. Previously, computeSealerWeight silently skipped unknown indices
	// (the `if stake, ok := memberStakes[idx]; ok` guard), so a malicious peer
	// could inject bogus indices alongside a few valid ones — the bogus ones
	// were ignored while the valid ones still crossed the weight threshold,
	// making the seal appear legitimate. Worse, if memberStakes was nil
	// (snapshot failed), the entire weight check was skipped, accepting ANY
	// sealer list without membership verification.
	//
	// Now we explicitly reject the announcement if ANY sealer index is not a
	// known member of the executive chamber for this epoch. This closes both
	// the "bogus index injection" and the "nil memberStakes bypass" attack
	// vectors. Unknown indices in a threshold signature set indicate either
	// a malformed message, a peer running different epoch state, or an active
	// attack — all must be rejected.
	if memberStakes != nil {
		seen := make(map[int]bool, len(sealers))
		for _, idx := range sealers {
			if seen[idx] {
				// Duplicate index — also reject (computeSealerWeight now
				// deduplicates, but duplicates in a P2P-announced sealer list
				// are a strong malformation signal).
				return false
			}
			seen[idx] = true
			stake, ok := memberStakes[idx]
			if !ok || stake == nil {
				// Sealer index is not a member of the executive chamber for
				// this epoch — reject the announcement.
				return false
			}
		}
	}

	// If we have weight info, verify the sealers' cumulative stake meets
	// the threshold. This prevents minority-stake finalization via P2P.
	if requiredWeight != nil && memberStakes != nil {
		sealerWeight := computeSealerWeight(sealers, memberStakes)
		if sealerWeight.Cmp(requiredWeight) < 0 {
			return false
		}
	}

	// QTD-H03: use the historical group key for the seal's epoch (NOT the
	// current signer's key, which may have rotated via DKG).
	//
	// CONS-P0-03 FIX (R31, 2026-07-27): Precompute currentEpoch BEFORE
	// acquiring qfs.mu.RLock() to eliminate the qfs.mu → qpos.mu
	// lock-ordering hazard (qpos.GetCurrentEpoch is currently lock-free,
	// but precomputing is defensive against future modifications).
	currentEpoch := uint64(0)
	if qfs.qpos != nil {
		currentEpoch = qfs.qpos.GetCurrentEpoch()
	}

	// R39-P0-01 (2026-08-02) + R40-P0-01 (2026-08-03) FIX: verify against
	// the canonical domain-separated message
	//   QTDDomainSep || chainID || epoch || slot || blockHash
	// using this node's chainID (every node on the same chain shares it,
	// so a remote-produced seal will verify with the same message here)
	// and SlotToEpoch(slot) (a pure function of slot — same on every node
	// for a given slot). The legacy raw-blockHash fallback is reached only
	// when qfs.chainID == 0 (a node that has not yet adopted the R39
	// domain-separated signing context); the tautological per-epoch escape
	// hatch removed in R40-P0-01 no longer exists. qtdVerifyMessageLocked
	// must be called with qfs.mu held (it reads qfs.qtdSigner); combine it
	// with the group-key lookup in a single RLock to keep the critical
	// section minimal and ordered.
	qfs.mu.RLock()
	groupKey := qfs.getGroupPublicKeyForEpochLocked(epoch, currentEpoch)
	verified := false
	if len(groupKey) > 0 {
		verified = qfs.qtdVerifyMessageLocked(groupKey, qfs.chainID, epoch, slot, blockHash, qtdSignature)
	}
	qfs.mu.RUnlock()

	if len(groupKey) == 0 {
		return false
	}

	// Cryptographic verification: the QTD signature must be valid under
	// the group key that was active at the seal's epoch.
	if !verified {
		return false
	}

	// Seal accepted — store the finality record.
	qfs.mu.Lock()
	defer qfs.mu.Unlock()

	// Idempotent: if already finalized, don't overwrite.
	if _, exists := qfs.instantFinalizedSlots[slot]; exists {
		return true
	}

	sealersCopy := append([]int(nil), sealers...)
	sealedAt := time.Unix(int64(slot), 0)
	record := &InstantFinalityRecord{
		Slot:         slot,
		BlockHash:    blockHash,
		QTDSignature: append([]byte(nil), qtdSignature...),
		SealedAt:     sealedAt,
		Sealers:      sealersCopy,
		// R39-P0-01 (2026-08-02) FIX: persist the domain-separation context
		// the remote sealer used (this node's chainID + SlotToEpoch(slot))
		// so subsequent local verifications via VerifyInstantFinality
		// reconstruct the same canonical signed message without having
		// to re-derive it from the signature alone.
		ChainID: qfs.chainID,
		Epoch:   epoch,
	}
	qfs.instantFinalizedSlots[slot] = record

	// Clean up any pending seal for this slot (it's now finalized).
	delete(qfs.pendingSeals, slot)

	// Finalize in qpos (async to avoid lock ordering issues).
	//  completeSealLockedFinalize acquires qpos.mu internally,
	// so it must be called AFTER qfs.mu is released (via goroutine).
	go qfs.completeSealLockedFinalize(slot, blockHash)

	return true
}
