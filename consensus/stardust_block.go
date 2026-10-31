// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"encoding/binary"
	"fmt"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// PopulateStardustFields fills the QTD/stardust fields of a block header.
//
// Finality semantics carried by the header (R23, 2026-10-29):
//
// The header can only carry the FINALITY TYPE (0 = CasperFFG, 1 = QTD
// instant), never the statement "this block is final". Two structural
// reasons:
//
//	L1 — self-reference. The block hash is computed OVER the header, and
//	     the QTD seal is over the block hash. At population time the block
//	     hash does not exist yet, so a field like "Finalized = true" could
//	     not be bound to the hash it claims to finalize; whatever it said
//	     would be excluded from (or self-contradictory with) the very hash
//	     it describes. The header therefore advertises the finality
//	     MECHANISM, and the binding fact is published out of band.
//
//	L2 — hash stability. FinalityType is part of the encoded header and
//	     therefore part of the block hash. Redefining what the field means
//	     (for example "1 = this block is final" instead of "1 = QTD
//	     instant finality is in use") would change the hash of every
//	     block produced by the new code while the old code produces the
//	     old hashes — during a staggered fleet rollout the two node
//	     populations would build different blocks for the same slot and
//	     fork the chain. The R23 canonical-binding fix is therefore
//	     deliberately confined to the reporting layer (the RPCs), which is
//	     version-agnostic and cannot fork the chain.
//
// The QTD signature is copied into the header only when it belongs to THIS
// block: a record whose sealed hash is provably not the slot's canonical
// root is left out, so the header advertises no signature rather than
// another block's (VerifyStardustFinality would reject it anyway).
func PopulateStardustFields(header *encoding.BlockHeader, qpos *QPOS) error {
	if header == nil {
		return fmt.Errorf("nil block header")
	}

	if qpos == nil || !qpos.HasChambers() {
		header.FinalityType = 0
		return nil
	}

	qfs := qpos.GetQTDFinality()
	if qfs != nil && qfs.IsInstantFinality() {
		header.FinalityType = 1

		record := qfs.GetFinalityRecord(header.Slot)
		// R22 (2026-10-29): a record now survives even when its block is not
		// the slot's canonical root (the R19-F08 rollback was reverted — see
		// qtd_finality.go). Never present another block's threshold signature
		// as THIS block's finality proof: copy it only when the slot's
		// canonical root is still unknown (the normal case at production time)
		// or actually equals the recorded hash. A proven-stale record is left
		// out, so the header advertises no signature rather than a mismatched
		// one (VerifyStardustFinality would reject it anyway — fail-closed).
		if record != nil {
			if root, known := qpos.GetSlotBlockRoot(header.Slot); known && root != record.BlockHash {
				record = nil
			}
		}
		if record != nil {
			header.QTDSignature = make([]byte, len(record.QTDSignature))
			copy(header.QTDSignature, record.QTDSignature)

			sealerBytes := make([]byte, len(record.Sealers)*4)
			for i, idx := range record.Sealers {
				binary.LittleEndian.PutUint32(sealerBytes[i*4:], uint32(idx))
			}
			header.ExecutiveSealers = sealerBytes
		}

		// Observer anchor (QTD v1): the first block of an epoch carries the
		// epoch's active group public key, so verify-only consumers can learn
		// it from the chain instead of an out-of-band ceremony artifact.
		// Emitted only when this proposer actually holds the epoch's key.
		if header.Slot == EpochStartSlot(header.Epoch) {
			if key := qfs.getGroupPublicKeyForEpoch(header.Epoch); len(key) > 0 {
				header.QTDGroupKey = append([]byte(nil), key...)
				qtdLogger.Info("QTD group key anchored on epoch boundary block",
					map[string]any{"slot": header.Slot, "epoch": header.Epoch, "keyPrefix": key[:8]})
			}
		}
	} else {

		header.FinalityType = 0
	}
	// Note: on the v1 offline-sealing path the QTD group key arrives through the
	// ceremony's v1 share store (not the legacy qfs signer table), so consensus
	// cannot self-anchor there — the node layer overlays the anchor in block
	// production (see block_producer.populateStardust* call sites).

	coordinator := qpos.GetChambersCoordinator()
	if coordinator != nil {
		review := coordinator.GetReviewChamber()
		if review != nil {
			result := review.GetSlotResult(header.Slot)
			if result != nil {
				data := make([]byte, 0)
				data = binary.LittleEndian.AppendUint64(data, result.Slot)
				data = binary.LittleEndian.AppendUint64(data, uint64(result.CommitteeSize))
				data = binary.LittleEndian.AppendUint64(data, uint64(result.ApproveCount))
				data = binary.LittleEndian.AppendUint64(data, uint64(result.RejectCount))
				if result.ApproveStake != nil {
					data = append(data, result.ApproveStake.Bytes()...)
				}
				if result.RejectStake != nil {
					data = append(data, result.RejectStake.Bytes()...)
				}
				hash := sha3.Sum256(data)
				header.ReviewAttestationRoot = hash
			}
		}
	}

	return nil
}

// VerifyStardustFinality verifies the QTD instant finality seal on a block
// header. The blockHash parameter is the block's own hash (NOT the parent
// hash) — the QTD seal is requested via RequestSeal(slot, blockHash) where
// blockHash is the block's identity, so verification must use the same hash.
//
// AUDIT (2026) CORE-05 FIX: Previously, this function passed
// header.ParentHash to VerifyInstantFinality, which is semantically wrong —
// the QTD seal is over the block's own hash, not its parent's hash. This
// caused verification to always fail (fail-closed) because ParentHash !=
// record.BlockHash. Now the caller provides the correct block hash.
func VerifyStardustFinality(header *encoding.BlockHeader, blockHash types.Hash, qpos *QPOS) bool {
	if header == nil {
		return false
	}

	if header.FinalityType == 0 {
		return true
	}

	if header.FinalityType != 1 {
		return false
	}

	if qpos == nil {
		return false
	}

	if len(header.QTDSignature) == 0 {
		return false
	}

	qfs := qpos.GetQTDFinality()
	if qfs == nil {
		return false
	}

	return qfs.VerifyInstantFinality(header.Slot, blockHash, header.QTDSignature)
}

func IsQTDInstantFinality(header *encoding.BlockHeader) bool {
	if header == nil {
		return false
	}
	return header.FinalityType == 1
}

func GetExecutiveSealers(header *encoding.BlockHeader) []int {
	if header == nil || len(header.ExecutiveSealers) == 0 {
		return nil
	}

	count := len(header.ExecutiveSealers) / 4
	sealers := make([]int, count)
	for i := 0; i < count; i++ {
		sealers[i] = int(binary.LittleEndian.Uint32(header.ExecutiveSealers[i*4:]))
	}
	return sealers
}
