// Quantaureum Node source, version 1.0.0.
package node

// Fresh-sync bootstrap for the Dilithium3 v1 era (TSS-R3-B-1 R-1 fix).
//
// PROBLEM. Anchor adoption runs POST-apply: onCanonicalBlockImported
// (block_producer.go) calls ObserveAnchoredGroupKey only for blocks that
// already passed ValidateSignature and were applied (node.go's import loops
// invoke it under shouldSwitch). A node syncing from genesis therefore has an
// EMPTY anchor custody exactly when it reaches the first group-signed header:
// the v1 verification branch (core/block_validator.go) finds no key, falls
// through to individual Dilithium3 verification, and the group signature (an
// ordinary 3293-byte mode3 signature over the canonical binding, signed with
// the GROUP key) is rejected. Because adoption is post-apply, the anchor
// carried by that very header is never adopted — a one-way door: the fresh
// node stalls forever at the first group-signed header (observed on the P2-3
// devnet as "invalid block signature" repeating without progress). The
// out-of-band re-root (TSSV1TrustedGroupKey) is deliberately disabled on the
// experimental runtime-DKG networks where this posture is exercised.
//
// FIX — replay the proven GM-QTD bootstrap shape: the epoch's group key rides
// on individually signed headers, so every node can verify the carrier and
// adopt the key post-apply. Two carrier rules, both implemented as gates on
// the v1 proposal session (which is the only thing that turns a header's
// signature into a group signature):
//
//  1. EPOCH-BOUNDARY CARRIER (steady state). The first header of an epoch is
//     always individually signed and always carries the epoch's group key.
//     Reason: at an epoch boundary the observer's custody has no exact entry
//     for the NEW epoch yet (adoption is post-apply), and
//     getGroupPublicKeyForEpochLocked answers the CURRENT (wall-clock) epoch
//     from the live signer only (qtd_finality.go) — a fresh node has no
//     signer, so a group-signed boundary header would be rejected by every
//     node joining in real time, at every epoch, forever. An individually
//     signed boundary is verifiable without any custody; its anchor is
//     adopted post-apply and covers every later header of the epoch through
//     the exact-epoch history hit.
//
//  2. UN-ANCHORED WINDOW (era start). Until this node has observed a
//     canonical block anchoring the ACTIVE ceremony key at an epoch at or
//     after the key's activation, the proposal session is skipped and every
//     produced header carries the anchor. This covers the runtime-DKG case
//     where the ceremony completes mid-epoch: the epoch boundary of the
//     activation epoch was produced BEFORE the key existed, so the first
//     armed block(s) must seed the anchor themselves. The window closes as
//     soon as any armed producer's anchor block is applied (the producer
//     observes its own and peers' blocks through the same import path).
//
// Both gates are additive on top of the existing gates: with the proposal
// layer closed (the default) the session path returns nil before reaching
// them, so flags-off behavior is byte-for-byte unchanged. The seal executor
// is untouched: seals sign the block hash through their own session and never
// depended on the header signature type.
//
// TRUST MODEL (why the anchor cannot become an attack surface).
//
//   - Producer side: an anchor is written only from the node's own ACTIVE
//     ceremony share (tdilithium3ActiveShareIdentityCached), never from a
//     header-supplied or self-fabricated key, and a share superseded by an
//     armed re-key ceremony refuses the identity probe, so a replaced key
//     goes quiet instead of being re-anchored.
//   - Observer side: adoption is ObserveAnchoredGroupKey unchanged. A node
//     that already holds keys never accepts a new key without the chained-
//     adoption rule (same key continues at any later epoch; a rotated key
//     additionally needs maxKnown+1 plus the handoff proof), and R19-F02
//     makes the FIRST anchor for a node holding its own signer match that
//     signer's key — a mismatched or rogue anchor is refused and logged.
//   - Fresh node side: first establishment trusts the canonical chain itself
//     (trust-on-first-use to the first individually signed, election-valid
//     anchor carrier) — exactly the legitimacy source the GM-QTD anchors have
//     always used. A false anchor degrades LIVENESS only: subsequent group
//     signatures verify under the TRUE ceremony key, fail against the false
//     one, and the node stalls fail-closed; no forged header becomes
//     acceptable, because acceptance always requires the signature to verify
//     under the key the node adopted AND the proposer to satisfy the existing
//     election/slot rules. The residual "attacker anchors its own ceremony
//     key" fork capability reduces to the solo-proposer fork that the
//     individual-signature fallback already permits, and cannot forge t-of-n
//     seals.

import (
	"bytes"
	"errors"
	"sync"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
)

// tdilithium3CanonicalAnchorState records the last canonical-block anchor this
// node successfully adopted through its import path. It is the producer-side
// evidence that the active ceremony key is on the canonical chain, and it is
// deliberately distinct from the local custody table: the custody is re-rooted
// locally at ceremony registration, so a non-empty custody says nothing about
// what the CHAIN carries.
type tdilithium3CanonicalAnchorState struct {
	mu    sync.Mutex
	epoch uint64
	key   []byte
}

// anchorState lazily allocates the per-node anchor observation state.
func (n *Node) anchorState() *tdilithium3CanonicalAnchorState {
	n.tdilithium3AnchorMu.Lock()
	defer n.tdilithium3AnchorMu.Unlock()
	if n.tdilithium3AnchorObserved == nil {
		n.tdilithium3AnchorObserved = &tdilithium3CanonicalAnchorState{}
	}
	return n.tdilithium3AnchorObserved
}

// recordTDilithium3CanonicalAnchor stores the anchor of a canonical block whose
// QTDGroupKey ADOPTED (ObserveAnchoredGroupKey returned true). A refused anchor
// — the R19-F02 mismatch and chained-adoption refusals — must never reach here,
// so a rogue anchor cannot flip the producer gate open.
//
// Epoch-monotonic guard (audit round-2 finding 3): import order is not chain
// order. A fork switch or a delayed import can deliver an OLDER same-key
// anchor — ObserveAnchoredGroupKey answers a same-key re-anchor at an older
// epoch with a no-op true — and accepting it would rewind the record below the
// key's activation epoch, re-opening the un-anchored window for a key that is
// already on the chain. Same-epoch re-anchors carry the same key (a
// conflicting key at a recorded epoch is refused by the adoption discipline),
// so skipping them loses nothing; a strictly newer epoch — rotation included —
// advances the record.
func (n *Node) recordTDilithium3CanonicalAnchor(epoch uint64, key []byte) {
	if n == nil || len(key) == 0 {
		return
	}
	state := n.anchorState()
	state.mu.Lock()
	defer state.mu.Unlock()
	if epoch <= state.epoch {
		return
	}
	state.epoch = epoch
	state.key = append([]byte(nil), key...)
}

// tdilithium3V1CanonicalAnchorObserved reports whether a canonical block has
// anchored the given ceremony key (the active share's group key) at an epoch at
// or after that key's activation. It is the un-anchored-window gate of the v1
// proposal session and the v1 anchor overlay: while it is false, headers must
// stay individually signed and carry the anchor themselves.
func (n *Node) tdilithium3V1CanonicalAnchorObserved(activation uint64, key []byte) bool {
	if n == nil || len(key) == 0 {
		return false
	}
	state := n.anchorState()
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.epoch >= activation && bytes.Equal(state.key, key)
}

// tdilithium3V1AnchorArmed reports whether this producer may anchor the v1
// group key on its headers: either the offline ceremony path is armed for the
// header's epoch, or the proposal layer's own gate is open (the experimental
// runtime-DKG posture, where the offline activation config is absent). Both
// arming forms are epoch-gated, so nothing anchors before its activation.
func (n *Node) tdilithium3V1AnchorArmed(epoch uint64) bool {
	if n == nil || n.config == nil {
		return false
	}
	return n.offlineTDilithium3SealingArmed(epoch) || tdilithium3ProposalSigningEnabled(n, epoch)
}

// tdilithium3V1HeaderAnchorKey returns the v1 group public key to embed in the
// header's QTDGroupKey field, or nil when this header must not carry an anchor.
// An error is returned only when the producer is armed but its active-share
// identity is unusable (missing store, superseded share) — the caller logs it
// on the boundary carrier, where the old path warned, and stays quiet
// otherwise.
//
// Carrier rules (see the file comment): the epoch's first block always anchors
// (the boundary carrier), and every produced block anchors while the active
// key is not yet chain-observed (the un-anchored window). The key is the
// ACTIVE ceremony share's group key — the same source the signing sessions
// use, so an anchor and the signatures that follow it can never diverge; a
// superseded share refuses the identity probe and anchors nothing. An existing
// anchor (PopulateStardustFields wrote one through the qfs signer table on the
// experimental path) is left untouched.
func (bp *BlockProducer) tdilithium3V1HeaderAnchorKey(header *encoding.BlockHeader) ([]byte, error) {
	if bp == nil || bp.node == nil || header == nil {
		return nil, nil
	}
	if !bp.node.tdilithium3V1AnchorArmed(header.Epoch) {
		return nil, nil
	}
	activation, key, _, err := bp.node.tdilithium3ActiveShareIdentityCached()
	if err != nil || len(key) == 0 {
		if err == nil {
			err = errTDilithium3V1AnchorIdentityEmpty
		}
		return nil, err
	}
	if consensus.EpochStartSlot(header.Epoch) != header.Slot &&
		bp.node.tdilithium3V1CanonicalAnchorObserved(activation, key) {
		return nil, nil
	}
	return key, nil
}

// errTDilithium3V1AnchorIdentityEmpty reports an armed producer whose share
// store answered without a usable group public key.
var errTDilithium3V1AnchorIdentityEmpty = errors.New("Dilithium3 v1 anchor: active share identity has no group key")
