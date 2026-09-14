// Quantaureum Node source, version 1.0.0.
package consensus

// QTD Integration Path (R33-023 documentation):
//
// The GM-QTD (Quantum Threshold Signature) protocol enables t-of-n threshold
// signing using Dilithium3 post-quantum keys. The full integration path is:
//
//   wallet/tss/qtd (GM-QTD protocol implementation)
//     → wallet/tss.TSSManager (orchestrates DKG, partial signing, aggregation)
//       → crypto.GMQTD_Sign (low-level signing entry point, L1 crypto layer)
//         → consensus.ThresholdKeySigner (this interface, L5 consensus layer)
//           → QPOS.tssSigner (injected at node startup via node/node.go)
//             → RPC qau_tss_* (exposed via rpc/tss_api.go, L7 service layer)
//
// Key architectural constraints:
//   - crypto (L1) cannot import wallet/tss/qtd (higher layer), so a callback
//     injection pattern is used: SetQTDSingleSigner() registers the real
//     implementation at startup.
//   - The TSSManager is the single orchestrator for all threshold operations.
//   - Block sealing uses AggregatePartialSignatures, NOT SignBlock, to ensure
//     threshold security (multiple validators must participate).
//
// Current integration status (2026-07-14, P0-P4 complete):
//   ✅ crypto.GMQTD_Sign + SetQTDSingleSigner callback injection
//   ✅ consensus.ThresholdKeySigner interface (includes AggregatePartialSignatures)
//   ✅ QPOS.tssSigner field + completeSealLocked using AggregatePartialSignatures
//   ✅ RPC qau_tss_status + qau_tss_getPublicKey
//   ✅ RPC qau_tss_requestSeal + qau_tss_submitPartialSeal + qau_tss_getSealStatus (P1-7)
//   ✅ RPC qau_stardust_getDKGStatus (P1-9, read-only DKG monitoring)
//   ✅ ThreeChambersFlow wired into block_producer slot tick (P1-1~P1-3)
//   ✅ SelectExecutiveForEpoch at epoch boundary (P0-2)
//   ✅ SetSlotBlockRoot on block import/production (P0-3)
//   ✅ FinalityTracker double-sign detection sunk to VotingManager → DoubleSignDetector → SlashingManager (P0-4)
//   ✅ Placeholder "auto-seal" signatures removed from production SealBlock (P0-5)
//   ✅ DKG productionization: TriggerDKG + CheckDKGTimeout + GetDKGStatus (P1-9)
//   ✅ Executive health monitoring: CheckExecutiveHealth (P3-2)
//   ✅ Prometheus metrics: finality_type, instant_finalized_count, pending_seals (P3-6)
//   ✅ P2 test coverage: threshold forge prevention, CORE-03 partition recovery,
//      GOV-05 per-slot root, GOV-06 stake-weighted election, P0-5 dead code (P2)

// ThresholdKeySigner defines the interface for threshold signature operations.
type ThresholdKeySigner interface {
	SignBlock(validatorIndex int, message []byte) ([]byte, error)
	SignVote(validatorIndex int, message []byte) ([]byte, error)
	VerifyBlock(pubKey []byte, message []byte, signature []byte) bool
	VerifyVote(pubKey []byte, message []byte, signature []byte) bool
	GroupPublicKey() []byte
	IsThresholdMode() bool
	// AggregatePartialSignatures combines collected partial signatures from
	// multiple validators into a single threshold signature. This is the
	// correct way to produce a QTD signature — using SignBlock with a single
	// validatorIndex undermines the threshold security guarantee.
	//
	// FIX: Added to prevent completeSealLocked from using
	// sealers[0] as a single signer, which allowed any single sealer to forge
	// the threshold signature.
	//
	// Parameters:
	//   - sealers: list of validator indices that submitted partial signatures
	//   - partialSigs: map from validator index to their partial signature bytes
	//   - message: the message being signed (typically the block hash)
	// Returns:
	//   - the aggregated threshold signature, or an error if aggregation fails
	AggregatePartialSignatures(sealers []int, partialSigs map[int][]byte, message []byte) ([]byte, error)
}
