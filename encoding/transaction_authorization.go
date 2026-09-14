// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
)

// R38-P0-02 (2026-08-01): Canonical Transaction Authorization.
//
// VerifyTransactionAuthorization is the single, canonical replacement for
// the historical split between "dilithium3 tx.SigningHash() verification"
// (for ordinary transactions) and "string-domain staking signature
// verification" (for stake/unstake). Every consensus-reachable code path
// — the block validator's batch signature verifier, the txpool's
// admit/recheck path, and the RPC layer's pre-admit hook — MUST call this
// helper instead of the legacy specialized skips. This eliminates the
// R38-P0-02 "signature scope detach" vulnerability where a relay could
// tamper with tx.To / tx.Value / tx.GasPrice after the staking string
// signature was collected and the mutated tx would still parse as valid
// at the block boundary.
//
// Contract for *Transaction:
//   - Non-nil tx.
//   - tx.PublicKey has exactly crypto.Dilithium3PublicKeySize bytes.
//   - tx.Signature has exactly crypto.Dilithium3SignatureSize bytes.
//   - The public key, when derived, yields an address equal to tx.From.
//   - For ordinary tx: the signature verifies over tx.SigningHash().
//   - For stake/unstake tx: tx.Data decodes as the canonical
//     commission(4 BE) + staking-nonce(len-prefixed u16 BE) layout,
//     tx.To equals the canonical system contract for that type, and the
//     signature verifies over ComputeStakeAuthorizationHash.
//
// The function returns a typed error so callers can classify the failure
// reason ("invalid signature", "tampered recipient", etc.) without
// introspecting strings.

// Sentinels.
var (
	ErrAuthNilTx              = errors.New("verify tx authorization: nil tx")
	ErrAuthNoPublicKey        = errors.New("verify tx authorization: missing public key")
	ErrAuthNoSignature        = errors.New("verify tx authorization: missing signature")
	ErrAuthBadPubKeyLength    = errors.New("verify tx authorization: bad public key length")
	ErrAuthBadSigLength       = errors.New("verify tx authorization: bad signature length")
	ErrAuthPubKeyAddrMismatch = errors.New("verify tx authorization: public key does not derive tx.From")
	ErrAuthInvalidSignature   = errors.New("verify tx authorization: invalid signature")
	ErrAuthUnknownTxType      = errors.New("verify tx authorization: unknown tx type")
	ErrAuthStakeMissingTo     = errors.New("verify tx authorization: stake/unstake requires non-nil tx.To")
	ErrAuthStakeBadRecipient  = errors.New("verify tx authorization: tx.To is not the canonical staking/unstaking contract")
	ErrAuthStakeBadData       = errors.New("verify tx authorization: stake/unstake tx.Data is not the canonical commission(4)+nonce layout")
	// R43-ERR-CHAINID-01: dedicated sentinel for cross-chain replay protection
	// mismatches. Previously DefaultValidator reused ErrAuthUnknownTxType for
	// chain-ID failures, conflating "wrong chain" with "wrong tx type" and
	// hiding the real reason from log introspection. Use this sentinel for
	// the chain-ID branch only so callers (block_validator, txpool, RPC admit
	// hook) can classify cross-chain replay attempts distinctly.
	ErrAuthChainIDMismatch = errors.New("verify tx authorization: tx.ChainID does not match expected chain ID (cross-chain replay protection)")
	// R43-TYPEDISP-01: MultiSig N-of-M verification requires an external
	// signer-pubkey roster (who are the M legitimate signers for this
	// transaction's MultiSigSignerBitmap). The encoding package cannot
	// import the on-chain multi-sig registry (would create a cycle), so
	// the canonical VerifyTransactionAuthorization FAIL-CLOSED on MultiSig
	// txns instead of silently accepting them. Callers that hold the
	// signer roster should use VerifyMultiSigAuthorization(tx, roster)
	// below; the canonical entry point never silently lets MultiSig
	// through. Privacy tx use ZK proofs and remain allow-listed as before.
	ErrAuthMultiSigUnsupported = errors.New("verify tx authorization: MultiSig N-of-M verification requires external signer roster (use VerifyMultiSigAuthorization)")
)

// stakingContractAddress / unstakingContractAddress mirror
// economics.StakingContractAddress / UnstakeContractAddress. Held here
// as constants so the encoding package, which cannot import economics
// (would create a cycle: economics -> encoding/...; encoding -> economics),
// still enforces recipient hard-binding at the sign-verify boundary.
// Economics writes the same byte values via parseContractAddress(0x10, 0x01)
// and parseContractAddress(0x10, 0x02). If either is changed, both must.
var (
	stakingContractAddress      = types.Address{18: 0x10, 19: 0x01}
	unstakingContractAddress    = types.Address{18: 0x10, 19: 0x02}
	validatorKeyRegistryAddress = types.Address{18: 0x10, 19: 0x04} // R131
)

// VerifyTransactionAuthorization checks every consensus-affecting field
// of tx against the supplied Dilithium3 signature. Returns nil only if
// all checks pass.
func VerifyTransactionAuthorization(tx *Transaction) error {
	if tx == nil {
		return ErrAuthNilTx
	}
	if len(tx.PublicKey) == 0 {
		return ErrAuthNoPublicKey
	}
	if len(tx.Signature) == 0 {
		return ErrAuthNoSignature
	}
	if len(tx.PublicKey) != crypto.Dilithium3PublicKeySize {
		return fmt.Errorf("%w: got %d want %d", ErrAuthBadPubKeyLength, len(tx.PublicKey), crypto.Dilithium3PublicKeySize)
	}
	if len(tx.Signature) != crypto.Dilithium3SignatureSize {
		return fmt.Errorf("%w: got %d want %d", ErrAuthBadSigLength, len(tx.Signature), crypto.Dilithium3SignatureSize)
	}

	// Derive the address for the supplied public key and require equality
	// with tx.From. This catches both forged public keys and tx.From
	// tampering after signature.
	pub, err := crypto.PublicKeyFromBytes(tx.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuthPubKeyAddrMismatch, err)
	}
	derivedAddr := pub.Address()
	if derivedAddr != tx.From {
		return ErrAuthPubKeyAddrMismatch
	}

	// Dispatch on tx.Type.
	switch tx.Type {
	case TxTypeTransfer, TxTypeContract, TxTypeCreate,
		TxTypeDynamicFee, TxTypeBlob, TxTypeCommit:
		// R43-TYPEDISP-01 (2026-08-03): DynamicFee and Blob were
		// previously dispatched to `default` which returned
		// ErrAuthUnknownTxType — meaning any well-formed EIP-1559 or
		// EIP-4844 transaction arriving at a P2P / rollup verifier that
		// routed through VerifyTransactionAuthorization was rejected as
		// "unknown", and downstream code often interpreted "unknown" as
		// "skip signature" (the failing fast again became the silent
		// success). SigningHash() already includes MaxFeePerGas,
		// MaxPriorityFeePerGas, MaxFeePerBlobGas, BlobVersionedHashes,
		// and BlobGasUsed (CRYPTO-), so the same single-signature
		// verification path covers them. We lump the five single-sig
		// types together so the canonical entry point covers the full
		// single-sig tx-type enum. MultiSig is handled separately below.
		hash, err := tx.SigningHash()
		if err != nil {
			return fmt.Errorf("%w: signing hash: %v", ErrAuthInvalidSignature, err)
		}
		if !crypto.Verify(pub, hash[:], tx.Signature) {
			return ErrAuthInvalidSignature
		}
		return nil

	case TxTypeStake, TxTypeUnstake:
		// 1) tx.To MUST be the canonical contract for this type.
		if tx.To == nil {
			return ErrAuthStakeMissingTo
		}
		var expectedAddr types.Address
		var authType types.StakeAuthTxType
		if tx.Type == TxTypeStake {
			expectedAddr = stakingContractAddress
			authType = types.StakeAuthTypeStake
		} else {
			expectedAddr = unstakingContractAddress
			authType = types.StakeAuthTypeUnstake
		}
		if *tx.To != expectedAddr {
			return ErrAuthStakeBadRecipient
		}

		// 2) Decode commission + staking nonce from tx.Data.
		// Layout (matches rpc.API.Stake / qau_stake producer):
		//   commission(4 BE) + nonceLen(2 BE) + nonce(nonceLen bytes)
		commission, nonce, ok := decodeStakeAuthData(tx.Data)
		if !ok {
			return ErrAuthStakeBadData
		}

		// 3) Re-derive the canonical auth hash from the canonical
		// fields and verify.
		value := tx.Value
		if value == nil {
			value = new(big.Int)
		}
		hash, err := types.ComputeStakeAuthorizationHash(
			tx.ChainID,
			tx.From,
			*tx.To,
			authType,
			value,
			commission,
			nonce,
		)
		if err != nil {
			return fmt.Errorf("%w: canonical hash: %v", ErrAuthInvalidSignature, err)
		}
		if !crypto.Verify(pub, hash[:], tx.Signature) {
			return ErrAuthInvalidSignature
		}
		return nil

	case TxTypeValidatorKey:
		// R131: validator key-ops (rotate session / bind master / revoke).
		// Auth rules:
		//   1) To MUST be the ValidatorKeyRegistryAddress system sink; the
		//      consensus post-commit hook ignores txs addressed elsewhere.
		//   2) Value MUST be zero — these txs are pure control-plane.
		//   3) Signature is the ordinary Dilithium3 SigningHash verification;
		//      authorization *semantics* (identity vs master) are enforced by
		//      the consensus registry, not here (it needs chain state).
		if tx.To == nil || *tx.To != validatorKeyRegistryAddress {
			return ErrAuthStakeBadRecipient
		}
		if tx.Value != nil && tx.Value.Sign() != 0 {
			return fmt.Errorf("%w: validatorKey tx must carry zero value", ErrAuthStakeBadData)
		}
		hash, err := tx.SigningHash()
		if err != nil {
			return fmt.Errorf("%w: signing hash: %v", ErrAuthInvalidSignature, err)
		}
		if !crypto.Verify(pub, hash[:], tx.Signature) {
			return ErrAuthInvalidSignature
		}
		return nil

	case TxTypePrivacy:
		// Privacy tx use ZK proofs, not Dilithium3 signature verification
		// at the block boundary; they carry no public key usable here.
		return nil

	case TxTypeMultiSig:
		// R43-TYPEDISP-01 (2026-08-03): MultiSig N-of-M verification
		// requires an external signer-pubkey roster that the encoding
		// package cannot import (cycle: encoding <- economics <- ...).
		// The canonical entry point FAIL-CLOSED with a dedicated sentinel
		// so MultiSig txns are NEVER silently accepted as "unknown type".
		// Callers that hold the roster should call the exported
		// VerifyMultiSigAuthorization below; the consensus block
		// validator path is responsible for routing MultiSig to that
		// helper. Privacy tx were already allow-listed above because
		// they use ZK proofs (no key here).
		//
		// We do NOT accept the tx.PublicKey single-sig path here even
		// though SigningHash covers the MultiSig config fields: a single
		// signature over a MultiSig tx is NOT authorization by itself
		// (an attacker could forge a single sig on a 3-of-5 tx); the
		// N-of-M requirement must be checked against the registered
		// signer roster.
		return ErrAuthMultiSigUnsupported

	default:
		return fmt.Errorf("%w: 0x%x", ErrAuthUnknownTxType, byte(tx.Type))
	}
}

// VerifyMultiSigAuthorization verifies an N-of-M Dilithium3 multi-signature
// transaction against an external signer roster. R43-TYPEDISP-01 (2026-08-03).
//
// Behavior:
//   - tx.Type MUST be TxTypeMultiSig; anything else is a caller bug.
//   - signerRoster is the M public keys eligible to sign this tx, in the
//     SAME index order as MultiSigSignerBitmap (bit i = 1 means signer i
//     contributed a signature). The roster is provided by the on-chain
//     multi-sig registry; the encoding package does not own that lookup.
//   - For each bitmap-set bit, the corresponding sig in tx.MultiSigSignatures
//     (in order) MUST verify over tx.SigningHash() using roster[i].
//   - At least tx.MultiSigRequiredSigs signatures MUST be present + valid.
//   - RequiredSigs > TotalSigners is fail-closed (matches encoding.ValidateTx).
//   - Roster nil or shorter than the bitmap-high-bit index is fail-closed.
//
// Returns nil on success, a typed error otherwise. The canonical
// VerifyTransactionAuthorization FAIL-CLOSED on MultiSig tx with
// ErrAuthMultiSigUnsupported; callers MUST route MultiSig txns here.
func VerifyMultiSigAuthorization(tx *Transaction, signerRoster [][]byte) error {
	if tx == nil {
		return ErrAuthNilTx
	}
	if tx.Type != TxTypeMultiSig {
		return fmt.Errorf("%w: VerifyMultiSigAuthorization called on non-MultiSig tx type 0x%x", ErrAuthUnknownTxType, byte(tx.Type))
	}
	if tx.MultiSigRequiredSigs > tx.MultiSigTotalSigners {
		return fmt.Errorf("%w: required_sigs (%d) exceeds total_signers (%d)", ErrAuthInvalidSignature, tx.MultiSigRequiredSigs, tx.MultiSigTotalSigners)
	}
	if len(tx.MultiSigSignatures) < tx.MultiSigRequiredSigs {
		return fmt.Errorf("%w: collected signatures (%d) < required (%d)", ErrAuthInvalidSignature, len(tx.MultiSigSignatures), tx.MultiSigRequiredSigs)
	}
	if signerRoster == nil {
		return fmt.Errorf("%w: nil signer roster", ErrAuthMultiSigUnsupported)
	}
	hash, err := tx.SigningHash()
	if err != nil {
		return fmt.Errorf("%w: signing hash: %v", ErrAuthInvalidSignature, err)
	}
	// Walk the bitmap + signatures together. Each set bit consumes the
	// next signature in MultiSigSignatures; we count valid signatures and
	// require >= MultiSigRequiredSigs at the end.
	validCount := 0
	sigIdx := 0
	for i := 0; i < tx.MultiSigTotalSigners && i < len(signerRoster); i++ {
		bit := (tx.MultiSigSignerBitmap[i/8] >> (uint(i) % 8)) & 1
		if bit == 0 {
			continue
		}
		if sigIdx >= len(tx.MultiSigSignatures) {
			// Bitmap claims more signers than signatures provided —
			// fail-closed.
			return fmt.Errorf("%w: bitmap bit %d set but no signature at index %d", ErrAuthInvalidSignature, i, sigIdx)
		}
		if len(signerRoster[i]) != crypto.Dilithium3PublicKeySize {
			return fmt.Errorf("%w: roster[%d] bad pubkey length %d", ErrAuthBadPubKeyLength, i, len(signerRoster[i]))
		}
		if len(tx.MultiSigSignatures[sigIdx]) != crypto.Dilithium3SignatureSize {
			return fmt.Errorf("%w: sigs[%d] bad signature length %d", ErrAuthBadSigLength, sigIdx, len(tx.MultiSigSignatures[sigIdx]))
		}
		pub, perr := crypto.PublicKeyFromBytes(signerRoster[i])
		if perr != nil {
			return fmt.Errorf("%w: roster[%d] invalid pubkey: %v", ErrAuthPubKeyAddrMismatch, i, perr)
		}
		if !crypto.Verify(pub, hash[:], tx.MultiSigSignatures[sigIdx]) {
			return fmt.Errorf("%w: roster[%d] signature does not verify over SigningHash", ErrAuthInvalidSignature, i)
		}
		validCount++
		sigIdx++
	}
	if validCount < tx.MultiSigRequiredSigs {
		return fmt.Errorf("%w: valid signatures (%d) < required (%d)", ErrAuthInvalidSignature, validCount, tx.MultiSigRequiredSigs)
	}
	return nil
}

// VerifySingleSigBinding is the single-source implementation of the
// "pubkey derives to from AND signature verifies over msg" canonical
// check used by every Dilithium3 single-signature authorization path.
// AUDIT-FULL-ROUND1-2026-08-15 P0-01 FIX (2026-08-15).
//
// Why this helper exists:
//  1. The Round 1 boundary audit found that rollup/sequencer.go
//     re-implemented this exact two-step check inline, separate from
//     encoding.VerifyTransactionAuthorization. That violates the
//     "single signature-verification boundary" invariant (audit lesson
//     1): two implementations can drift, and a future tx-type extension
//     that adds a new binding field could update one path and forget
//     the other.
//  2. The rollup domain cannot call VerifyTransactionAuthorization
//     directly because RollupTransaction has a different field
//     layout / signing-hash domain (sha256 over L2-only fields,
//     ChainID binding) than encoding.Transaction — so the only
//     surgically minimal way to share the binding check is to extract
//     the two-step primitive and have both callers invoke it.
//
// This helper performs ONLY the binding+signature check. It does NOT
// assert tx.Type, ChainID, recipient, or stake-data canonicality —
// those remain the caller's responsibility (VerifyTransactionAuthorization
// keeps those checks; rollup validates tx.ChainID against the L2 config
// before reaching this point).
//
// Inputs:
//   - from:      claimed sender address (already trust-bound to the
//     caller; this helper re-asserts the pubkey derives it).
//   - pubKey:    Dilithium3 public key bytes (length checked here).
//   - msg:       the signing-hash bytes the signature was produced over.
//   - signature: Dilithium3 signature bytes (length checked here).
//
// Returns one of:
//   - nil on success.
//   - ErrAuthNoPublicKey / ErrAuthBadPubKeyLength on bad pubkey.
//   - ErrAuthNoSignature / ErrAuthBadSigLength on bad sig.
//   - ErrAuthPubKeyAddrMismatch when pubKey derives an address != from
//     or when PublicKeyFromBytes rejects the bytes as malformed.
//   - ErrAuthInvalidSignature when the signature does not verify.
//
// This function does not allocate and is safe to call from hot paths.
func VerifySingleSigBinding(from types.Address, pubKey, msg, signature []byte) error {
	if len(pubKey) == 0 {
		return ErrAuthNoPublicKey
	}
	if len(signature) == 0 {
		return ErrAuthNoSignature
	}
	if len(pubKey) != crypto.Dilithium3PublicKeySize {
		return fmt.Errorf("%w: got %d want %d", ErrAuthBadPubKeyLength, len(pubKey), crypto.Dilithium3PublicKeySize)
	}
	if len(signature) != crypto.Dilithium3SignatureSize {
		return fmt.Errorf("%w: got %d want %d", ErrAuthBadSigLength, len(signature), crypto.Dilithium3SignatureSize)
	}
	pub, err := crypto.PublicKeyFromBytes(pubKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuthPubKeyAddrMismatch, err)
	}
	if pub.Address() != from {
		return ErrAuthPubKeyAddrMismatch
	}
	if !crypto.Verify(pub, msg, signature) {
		return ErrAuthInvalidSignature
	}
	return nil
}

// decodeStakeAuthData parses the canonical stake authorization payload
// stored in tx.Data: commission(4 bytes BE) + nonceLen(2 bytes BE) +
// nonce(nonceLen bytes). Returns (commission, nonce, ok). ok is false on
// any truncation; this is how the caller distinguishes "tx.Data does not
// look like a canonical stake auth payload" from any other error.
func decodeStakeAuthData(data []byte) (uint32, string, bool) {
	if len(data) < 4 {
		return 0, "", false
	}
	commission := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	data = data[4:]
	if len(data) < 2 {
		return 0, "", false
	}
	nonceLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < nonceLen {
		return 0, "", false
	}
	if nonceLen > types.StakeV2NonceMaxLen {
		return 0, "", false
	}
	nonce := string(data[:nonceLen])
	return commission, nonce, true
}

// VerifyStakeAuthorizationDigest verifies a Dilithium3 signature over a
// stake/unstake authorization message, given the canonical inputs of
// types.ComputeStakeAuthorizationHash (the same hash that the L1 block
// validator's VerifyTransactionAuthorization re-derives when checking a
// TxTypeStake / TxTypeUnstake encoding.Transaction). R43-RPC-LEGACY-01
// (2026-08-03).
//
// This helper exists so the legacy RPC stake/unstake handlers
// (rpc/api.go Stake / Unstake) can share the EXACT same verification step
// as encoding.VerifyTransactionAuthorization's TxTypeStake branch —
// eliminating the hand-rolled `crypto.Verify(pubKey, canonical[:], sig)`
// duplicate (which was the audit R43-RPC-LEGACY-01 concern: the RPC path
// could drift from canonical if either side added a new field/branch
// without updating the other). Putting the helper in encoding (not types)
// avoids a cycle: types already depends on crypto's error / Address
// helpers transitively, but encoding may import both, so the canonical
// path can be centralized here.
//
// boolean argument + arguments are checked:
//   - chainID != 0 (anti-replay) and matching `from` address binding
//     through `pubKey.DerivedAddress() == from` (the R38-P0-02 signature
//     scope detach fix, applied uniformly to stake/unstake).
//   - non-zero recipient (encoded as the stake/unstake versioned
//     contract address by the caller — the helper does NOT enforce which
//     version byte to use; the caller is responsible for choosing the
//     right recipient per txType).
//   - txType ∈ {StakeAuthTypeStake, StakeAuthTypeUnstake}
//   - value > 0
//
// All of these checks are types.ComputeStakeAuthorizationHash's
// pre-conditions. On any failure, this function returns false (no error
// detail beyond what hash computation returns); callers should inspect
// the hash error to surface a meaningful RPC error. Note: the helper
// does NOT itself enforce the recipient; the encoding path also enforces
// recipient binds to a specific canonical address — but the RPC caller
// has already done so before invoking this helper, duplicating the
// encoding-side check would be over-strict (a hypothetical future RPC
// extension that targets a different version byte of the canonical
// contract should not be re-blocked here).
//
// Returns:
//   - (true, nil) on signature verify success
//   - (false, err) when canonical-hash computation failed (with err)
//   - (false, nil) when pubkey/from binding mismatch OR signature verify
//     returned false (no err — caller treats as "permission denied")
func VerifyStakeAuthorizationDigest(
	chainID uint64,
	from, recipient types.Address,
	txType types.StakeAuthTxType,
	value *big.Int,
	commission uint32,
	nonce string,
	pubKeyBytes, sigBytes []byte,
) (bool, error) {
	if pubKeyBytes == nil || sigBytes == nil {
		return false, nil
	}
	if len(pubKeyBytes) != crypto.Dilithium3PublicKeySize ||
		len(sigBytes) != crypto.Dilithium3SignatureSize {
		return false, nil
	}
	pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return false, nil
	}
	// R38-P0-02: must derive-from binding to the claimed From.
	if pubKey.Address() != from {
		return false, nil
	}
	hash, err := types.ComputeStakeAuthorizationHash(
		chainID, from, recipient, txType, value, commission, nonce,
	)
	if err != nil {
		return false, err
	}
	return crypto.Verify(pubKey, hash[:], sigBytes), nil
}
