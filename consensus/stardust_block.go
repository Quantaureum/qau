// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"encoding/binary"
	"fmt"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

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
		if record != nil {
			header.QTDSignature = make([]byte, len(record.QTDSignature))
			copy(header.QTDSignature, record.QTDSignature)

			sealerBytes := make([]byte, len(record.Sealers)*4)
			for i, idx := range record.Sealers {
				binary.LittleEndian.PutUint32(sealerBytes[i*4:], uint32(idx))
			}
			header.ExecutiveSealers = sealerBytes
		}
	} else {
		header.FinalityType = 0
	}

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
