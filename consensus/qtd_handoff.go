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

// anchoredGroupKeyProofLayout is the (epoch, version) header of a
// proof-bearing anchor block. Key bytes come from the anchor field itself.
// CommitteeVersion is not wired today; v1 offline rotations pin it to 1.
const qtdAnchorProofCommitteeVersion = uint64(1)

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
		// source; no key_N to verify against, accept without a proof (S8 shape).
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
