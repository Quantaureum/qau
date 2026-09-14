// Quantaureum Node source, version 1.0.0.
package node

import (
	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// rollupTxSigVerifier adapts crypto.SigningVerifier to rollup.TxSignatureVerifier.
//
// W-P1-1 FIX (2026-07-13): L2 transactions carry the sender's Dilithium3
// public key inline (RollupTransaction.PublicKey) because L2 accounts' pubkeys
// are not stored on L1. This verifier:
//  1. Checks that pubKey derives to the claimed `from` address
//     (crypto.PublicKeyAddressFromBytes) — prevents pubkey spoofing.
//  2. Calls SigningVerifier.VerifyTransactionSignature(pubKey, msg, sig) —
//     performs the actual Dilithium3 signature verification.
//
// If either check fails, the transaction is rejected. This mirrors the L1
// txpool validator pattern (txpool/validator.go:500-543).
//
// AUDIT-FULL-ROUND1-2026-08-15 P0-01 FIX (2026-08-15): the binding check +
// Dilithium3 verify now delegate to encoding.VerifySingleSigBinding — the
// single-source primitive shared with encoding.VerifyTransactionAuthorization.
// The SigningVerifier's cache still amortizes repeated (pubKey,msg,sig)
// verifications via InvalidSignatureCache fast-path / SignatureCache hit, so
// hitting the helper on cache-miss does not regress the hot path.
type rollupTxSigVerifier struct {
	sv *crypto.SigningVerifier
}

// VerifyTxSignature implements rollup.TxSignatureVerifier.
// Returns true only if pubKey derives to `from` AND the signature is valid.
func (v *rollupTxSigVerifier) VerifyTxSignature(from types.Address, pubKey []byte, msg []byte, sig []byte) bool {
	if v.sv == nil {
		return false
	}
	// Canonical single-source binding+verify (encoding package). The
	// helper performs length + pubKey->from derivation + Dilithium3
	// signature verification. On signature-cache hit, the wrapped
	// SigningVerifier's VerifyTransactionSignature already short-circuits
	// before the underlying crypto.Verify call, so calling the helper's
	// crypto.Verify only happens on cache miss — same cost profile as the
	// previous inline implementation.
	if err := encoding.VerifySingleSigBinding(from, pubKey, msg, sig); err != nil {
		return false
	}
	// The helper already verified the signature; the SigningVerifier call
	// here populates / consumes the signature cache so subsequent
	// verifications of the same (pubKey, msg, sig) are O(1). The cache
	// stores only verified-valid results (CRYPTO-004 anti-poisoning), so
	// re-verifying via VerifyTransactionSignature is purely a cache-write
	// and cannot flip the result of the canonical check above.
	_ = v.sv.VerifyTransactionSignature(pubKey, msg, sig)
	return true
}

// rollupFraudProofSigVerifier adapts crypto.SigningVerifier to rollup.SignatureVerifier.
//
// W-P1-1 FIX (2026-07-13): L2 fraud proofs carry the challenger's Dilithium3
// public key inline (FraudProof.ChallengerPubKey) because L2 challengers'
// pubkeys are not stored on L1. This verifier uses the same two-step check as
// rollupTxSigVerifier: address derivation match + signature verification.
type rollupFraudProofSigVerifier struct {
	sv *crypto.SigningVerifier
}

// VerifyFraudProofSignature implements rollup.SignatureVerifier.
// Returns true only if pubKey derives to `challenger` AND the signature is valid.
func (v *rollupFraudProofSigVerifier) VerifyFraudProofSignature(challenger types.Address, pubKey []byte, msg []byte, sig []byte) bool {
	if v.sv == nil || len(pubKey) == 0 || len(sig) == 0 {
		return false
	}
	derivedAddr := crypto.PublicKeyAddressFromBytes(pubKey)
	if derivedAddr != challenger {
		return false
	}
	if err := v.sv.VerifyTransactionSignature(pubKey, msg, sig); err != nil {
		return false
	}
	return true
}

// qposSequencerAdapter adapts *consensus.QPOS to rollup.ValidatorSetProvider.
//
// W-P1-7 (2026-07-15): Provides the QPOS validator set and current epoch to
// the rollup sequencer elector. This keeps the rollup package decoupled from
// the consensus package (architecture discipline: rollup must not import
// consensus directly — dependency inversion via interface injection, matching
// the rollupTxSigVerifier / rollupFraudProofSigVerifier pattern).
//
// RLLP- (2026-07-16): Also provides the per-epoch VRF seed via
// GetEpochSeed, which uses the same three-tier selection as the DA committee
// shuffle (selectDACommitteeSeed). This breaks the predictability of the
// previous `epoch % len(validators)` sequencer election.
//
// GetValidators returns the active validator addresses in stake order. The
// elector uses keccak256(epoch || epochSeed) % len(validators) to pick the
// sequencer, so sequencer rotation is synchronized with QPOS epoch boundaries
// but no longer predictable for future epochs.
type qposSequencerAdapter struct {
	qpos *consensus.QPOS
}

// GetValidators returns the current validator addresses in stake order.
// Implements rollup.ValidatorSetProvider.
func (a *qposSequencerAdapter) GetValidators() []types.Address {
	if a.qpos == nil {
		return nil
	}
	vs := a.qpos.GetValidatorSet()
	if vs == nil {
		return nil
	}
	validators := vs.Validators()
	addrs := make([]types.Address, 0, len(validators))
	for _, v := range validators {
		if v.Active {
			addrs = append(addrs, v.Address)
		}
	}
	return addrs
}

// GetCurrentEpoch returns the current QPOS epoch.
// Implements rollup.ValidatorSetProvider.
func (a *qposSequencerAdapter) GetCurrentEpoch() uint64 {
	if a.qpos == nil {
		return 0
	}
	return a.qpos.GetCurrentEpoch()
}

// GetEpochSeed returns the VRF-derived randomness seed for the given epoch.
// Implements rollup.ValidatorSetProvider. RLLP- (2026-07-16).
//
// Delegates to selectDACommitteeSeed (the same three-tier selection used by
// the DA committee shuffle — finalized-epoch VRF accumulator → epoch-1 VRF
// accumulator → RANDAO), so sequencer election and DA committee selection
// share a consistent randomness source.
func (a *qposSequencerAdapter) GetEpochSeed(epoch uint64) types.Hash {
	if a.qpos == nil {
		return types.Hash{}
	}
	return selectDACommitteeSeed(a.qpos, epoch)
}
