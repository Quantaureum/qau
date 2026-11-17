// Quantaureum Node source, version 1.0.0.
package consensus

// Group-key rotation handoff (QTD v1 observer legitimacy chain).
//
// The header anchor at an epoch's first block carries the epoch's group key in
// QTDGroupKey. Without proof, adoption would trust a self-certifying field;
// with a rotation on a fixed-committee chain the new key CANNOT be checked
// against the old one unless the old threshold committee endorses the handoff.
// The handoff message is:
//
//	QTDHandoffDomain || chainID || epochNew || keyNew || committeeVersionNew
//
// signed by the epoch-(N) group key (the four signers of the outgoing
// committee run one ordinary v1 session over it at the boundary). An observer
// with the trusted key_N verifies the proof locally and adopts key_{N+1}
// only when it checks out. The first establishment (empty history) is exempt:
// that channel is the offline-ceremony/ops installation that predates this
// observer path.
//
// Skipped-epoch adoption (TSS-R3-B-1, P2-4 posture-r5): when the chain itself
// skipped epoch numbers (no boundary block — and therefore no anchor — for
// the intermediate epochs), a rotation anchor at epoch > N+1 is adopted
// through observeSkippedEpochRotationHandoffLocked: the observation ledger
// proves the intermediates never anchored, and the head key's committee
// threshold-signed the handoff for exactly the target (epoch, key). The
// signature tuple is unchanged — the lane is selected by the observer's own
// custody state, and the proof's verifying key must be the custody head in
// every lane, so no proof is valid across lanes.

import (
	"encoding/binary"
	"fmt"

	qcrypto "github.com/quantaureum/qau/crypto"
)

// QTDHandoffDomain separates the handoff signature message from every other
// QTD v1 signing domain; reuse for any other tuple is a cross-protocol
// signature-reuse risk.
const qtdHandoffDomain = "QAU-TDILITHIUM3-V1-KEY-HANDOFF-V1"

// QTDHandoffMessage builds the message the outgoing committee signs when it
// endorses the next epoch's group key. Deterministic on every node from the
// same inputs.
func QTDHandoffMessage(chainID, epochNew uint64, keyNew []byte, committeeVersion uint64) []byte {
	msg := make([]byte, 0, len(qtdHandoffDomain)+8+8+len(keyNew)+8)
	msg = append(msg, qtdHandoffDomain...)
	msg = binary.BigEndian.AppendUint64(msg, chainID)
	msg = binary.BigEndian.AppendUint64(msg, epochNew)
	msg = append(msg, keyNew...)
	msg = binary.BigEndian.AppendUint64(msg, committeeVersion)
	return msg
}

// VerifyAnchoredGroupKeyProof verifies a boundary anchor's proof against the
// previously established group key: a signature produced by the outgoing
// committee over the handoff message for (epochNew, keyNew). Returns true iff
// `signature` verifies under `prevKey` for that exact tuple.
func VerifyAnchoredGroupKeyProof(prevKey, keyNew []byte, epochNew, chainID, committeeVersion uint64, signature []byte) bool {
	if len(prevKey) != qcrypto.Dilithium3PublicKeySize || len(keyNew) != qcrypto.Dilithium3PublicKeySize {
		return false
	}
	if len(signature) != qcrypto.Dilithium3SignatureSize {
		return false
	}
	msg := QTDHandoffMessage(chainID, epochNew, keyNew, committeeVersion)
	return qcrypto.VerifySignatureForAlgorithm(qcrypto.SignatureAlgorithmDilithium3Legacy, prevKey, msg, nil, signature) == nil
}

// QTDAnchorProofCommitteeVersion is the committee version every anchor proof
// is bound to. CommitteeVersion is not wired today; v1 offline rotations pin
// it to 1, and the runtime-DKG fresh-key ceremonies derive committees with
// version 1 as well (node/tdilithium3_dkg_committee_sampling.go), so the
// signer side and this verifier share one constant.
const QTDAnchorProofCommitteeVersion = uint64(1)

// qtdAnchorProofCommitteeVersion is the internal alias used by the observer
// verification path below.
const qtdAnchorProofCommitteeVersion = QTDAnchorProofCommitteeVersion

// observeAnchoredGroupKeyHandoffLocked is the rotation-lane verifier, called
// with qfs.mu already HELD (observe entry owns the lock). It fails closed on a
// missing or non-matching proof whenever the observer has ANY prior history,
// so a rogue boundary block cannot teach a fresh key it cannot vouch for.
func (qfs *QTDFinalityState) observeAnchoredGroupKeyHandoffLocked(epoch uint64, key, proof []byte) error {
	if len(key) != qcrypto.Dilithium3PublicKeySize {
		return fmt.Errorf("handoff: bad key length %d", len(key))
	}
	prev := qfs.groupKeyHistory
	if len(prev) == 0 {
		// First establishment: the offline-ceremony/ops channel is the trust
		// source; no key_N to verify against, accept without a proof (the
		// ceremony-node shape).
		return nil
	}
	maxKnown := uint64(0)
	for known := range prev {
		if known > maxKnown {
			maxKnown = known
		}
	}
	if epoch != maxKnown+1 {
		return fmt.Errorf("handoff: not a chained rotation (have up to %d, got %d)", maxKnown, epoch)
	}
	if len(proof) == 0 {
		return fmt.Errorf("handoff: rotation anchor missing proof of handoff from epoch %d", maxKnown)
	}
	prevKey := prev[maxKnown]
	if !VerifyAnchoredGroupKeyProof(prevKey, key, epoch, qfs.chainID, qtdAnchorProofCommitteeVersion, proof) {
		return fmt.Errorf("handoff: proof does not verify under epoch-%d key", maxKnown)
	}
	return nil
}

// observeSkippedEpochRotationHandoffLocked is the skipped-epoch rotation lane
// (TSS-R3-B-1, P2-4 posture-r5 observer deadlock). Called with qfs.mu already
// HELD when a rotation anchor lands at epoch > maxKnown+1: the chain produced
// no boundary anchor for every epoch in (maxKnown, epoch) — the experimental
// runtime-DKG posture's clock-driven ceremonies can outpace chain time, so an
// epoch number can pass with no block at all and strict maxKnown+1 chaining
// would refuse this and every later anchor forever.
//
// Two conditions, both mandatory, let the lane adopt the next ACTUAL rotation:
//
//  1. DETERMINISTIC NO-INTERMEDIATE-ANCHOR EVIDENCE. The anchor-observation
//     ledger (anchorObservedEpochs, fed by this same observe entry point for
//     every canonical anchor this node has seen, adopted or refused) must
//     hold no epoch in (maxKnown, epoch). Since maxKnown is by construction
//     the largest adopted epoch, the ledger is the only place an
//     intermediate anchor can be recorded; an observed-but-refused
//     intermediate anchor (e.g. a proposer wrote an anchor with a bad proof)
//     blocks the lane — "intermediate has an anchor" refuses, exactly as the
//     chained discipline would demand the missing proof. The scan is over
//     the ledger set (bounded by qtdAnchorObservationHorizon above the
//     head), never a chain walk, so it is O(ledger) and hot-path safe; the
//     caller refuses skips wider than the horizon outright.
//
//  2. THE CURRENT RECORDED KEY'S HANDOFF PROOF. The same handoff signature
//     the chained lane requires — a threshold signature under
//     groupKeyHistory[maxKnown] (the last key this observer actually trusts)
//     over QTDHandoffMessage(chainID, epoch, key, committeeVersion). The
//     tuple binds the target epoch and the new key, so a proof cannot be
//     replayed across epochs, keys, or chainIDs; the verifying key is the
//     observer's own custody head, so a proof that verifies here is one the
//     already-trusted committee produced. The lane therefore adds no new
//     trust root and does not weaken R19-F02: injecting a key still requires
//     the previous committee's threshold signature, exactly as before.
//
// Production-side obligation (TSS-R3-B-1 Wave F channel): the boundary
// producer signs the handoff with the last ANCHORED committee's shares only
// when the chain skipped the intermediate epochs, so an honestly produced
// skip proof implies the intermediates never anchored on the producer's
// canonical chain. A Byzantine producer cannot forge the threshold
// signature alone, and a committee that signed a handoff for an epoch whose
// intermediates DID anchor would be violating its own protocol — the same
// trust placement as the chained lane.
func (qfs *QTDFinalityState) observeSkippedEpochRotationHandoffLocked(maxKnown, epoch uint64, key, proof []byte) error {
	if len(key) != qcrypto.Dilithium3PublicKeySize {
		return fmt.Errorf("handoff: bad key length %d", len(key))
	}
	if epoch <= maxKnown+1 {
		return fmt.Errorf("handoff: skipped-epoch lane requires epoch beyond %d, got %d", maxKnown+1, epoch)
	}
	if epoch > maxKnown+qtdAnchorObservationHorizon {
		return fmt.Errorf("handoff: skipped-epoch adoption wider than the %d-epoch horizon (have up to %d, got %d)",
			qtdAnchorObservationHorizon, maxKnown, epoch)
	}
	for observed := range qfs.anchorObservedEpochs {
		if observed > maxKnown && observed < epoch {
			return fmt.Errorf("handoff: skipped-epoch adoption refused: epoch %d carries an anchor on the canonical chain", observed)
		}
	}
	if len(proof) == 0 {
		return fmt.Errorf("handoff: skipped-epoch rotation anchor missing proof of handoff from epoch %d", maxKnown)
	}
	prevKey := qfs.groupKeyHistory[maxKnown]
	if !VerifyAnchoredGroupKeyProof(prevKey, key, epoch, qfs.chainID, qtdAnchorProofCommitteeVersion, proof) {
		return fmt.Errorf("handoff: proof does not verify under epoch-%d key", maxKnown)
	}
	return nil
}
