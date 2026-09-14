// Quantaureum Node source, version 1.0.0.
package types

import (
	"errors"
	"math/big"
)

// R38-P0-02 (2026-08-01): Canonical Stake Authorization Domain.
//
// Quantaureum V2 unifies the stake/unstake signing domain with the
// transaction-signing domain. The previous scheme signed a string
// "method|chainID|addr|nonce|params" — which did NOT cover tx.To,
// tx.Value, tx.GasLimit, tx.GasPrice, or txType, so a relay could
// tamper with those fields after the signature was collected. The
// canonical hash below binds EVERY consensus-affecting field, so
// any mutation invalidates the signature and the block/tx validator
// rejects the transaction.
//
// The hash is consumed by BOTH:
//   - the client-side signer (cmd/stakevalidator / wallet stake path)
//   - the node-side verification helper VerifyTransactionAuthorization
// which re-derives the same bytes from the proposed tx and compares
// against the supplied Dilithium3 signature over those bytes.
//
// Per the cryptography contract, this hash uses the same Keccak256
// (LegacyKeccak256) as DeriveMultisigV2Address and the rest of the
// V2 identity layer; Dilithium3 is the signing primitive.

const (
	// StakeV2Domain is the canonical domain tag prefix. It is included
	// as the first bytes of the hashed message so that a stake-auth
	// signature can never be reused as a different message type even if
	// the rest of the payload collides with some other domain.
	StakeV2Domain = "QAU_STAKE_AUTH_V2"

	// StakeV2NonceMaxLen bounds the RPC-layer staking nonce (a
	// replay-protection string) so a malicious peer cannot OOM the
	// canonicalization with a 1MB nonce.
	StakeV2NonceMaxLen = 128

	// StakeV2MaxCommission is the upper bound (1e6 = 100%) enforced by
	// the economics layer; re-checking here stops a tampered-commission
	// tx from sneaking in a value outside the legal range after the
	// signature check.
	StakeV2MaxCommission = 1_000_000
)

// Typed errors for stake authorization. Centralized here so the client
// signer and node verifier fail with identical, comparable errors.
var (
	ErrStakeV2ZeroChainID       = errors.New("stake v2 auth: zero chain id")
	ErrStakeV2ZeroFrom          = errors.New("stake v2 auth: zero from address")
	ErrStakeV2ZeroRecipient     = errors.New("stake v2 auth: zero recipient address")
	ErrStakeV2ZeroValue         = errors.New("stake v2 auth: zero value")
	ErrStakeV2NegativeValue     = errors.New("stake v2 auth: negative value")
	ErrStakeV2OversizedValue    = errors.New("stake v2 auth: oversized value")
	ErrStakeV2InvalidTxType     = errors.New("stake v2 auth: invalid tx type (must be stake or unstake)")
	ErrStakeV2InvalidCommission = errors.New("stake v2 auth: invalid commission (must be 0..1e6)")
	ErrStakeV2EmptyNonce        = errors.New("stake v2 auth: empty staking nonce")
	ErrStakeV2OversizedNonce    = errors.New("stake v2 auth: oversized staking nonce")
)

// StakeAuthTxType is the subset of consensus transaction types that
// share the canonical stake-authorization domain. Using a typed enum
// here ensures a stake signature cannot be replayed as an unstake and
// vice-versa — the txType byte is bound into the hash.
type StakeAuthTxType uint8

const (
	StakeAuthTypeStake   StakeAuthTxType = 0x01
	StakeAuthTypeUnstake StakeAuthTxType = 0x02
)

// ComputeStakeAuthorizationHash returns the canonical 32-byte Keccak256
// hash that the staker must sign with Dilithium3 and that the node-side
// VerifyTransactionAuthorization re-derives from the proposed tx to
// compare against the supplied signature.
//
// Field binding (in serialization order, all length-prefixed):
//   - domain tag (length-prefixed, StakeV2Domain)
//   - chainID (uint64 little-endian, 8 bytes fixed)
//   - from address (20 raw bytes, fixed)
//   - recipient address (20 raw bytes, fixed — StakingContractAddress
//     for stake, UnstakeContractAddress for unstake)
//   - txType (1 byte)
//   - value (uint256 big-endian, 32 bytes fixed)
//   - commission (uint32 big-endian, 4 bytes fixed — 0 for unstake)
//   - staking nonce (length-prefixed variable string)
//
// All fields are fixed-width except domain/nonce, which are length-
// prefixed to prevent ambiguity. The hash is canonical, deterministic,
// and has no collision ambiguity regardless of field values.
func ComputeStakeAuthorizationHash(
	chainID uint64,
	from, recipient Address,
	txType StakeAuthTxType,
	value *big.Int,
	commission uint32,
	nonce string,
) (Hash, error) {
	if chainID == 0 {
		return Hash{}, ErrStakeV2ZeroChainID
	}
	if from == (Address{}) {
		return Hash{}, ErrStakeV2ZeroFrom
	}
	if recipient == (Address{}) {
		return Hash{}, ErrStakeV2ZeroRecipient
	}
	if txType != StakeAuthTypeStake && txType != StakeAuthTypeUnstake {
		return Hash{}, ErrStakeV2InvalidTxType
	}
	if value == nil {
		return Hash{}, ErrStakeV2ZeroValue
	}
	if value.Sign() < 0 {
		return Hash{}, ErrStakeV2NegativeValue
	}
	// Bound at 2^256-1 — same as EVM's max uint256; prevents a
	// malicious signer from constructing an oversized value that
	// serializes cleanly for them but overflows the on-chain math.
	maxVal := new(big.Int).Lsh(big.NewInt(1), 256)
	maxVal.Sub(maxVal, big.NewInt(1))
	if value.Cmp(maxVal) > 0 {
		return Hash{}, ErrStakeV2OversizedValue
	}
	if commission > StakeV2MaxCommission {
		return Hash{}, ErrStakeV2InvalidCommission
	}
	if nonce == "" {
		return Hash{}, ErrStakeV2EmptyNonce
	}
	if len(nonce) > StakeV2NonceMaxLen {
		return Hash{}, ErrStakeV2OversizedNonce
	}

	var buf []byte
	// Domain tag — length-prefixed uint16 BE so the parser can skip it
	// unambiguously if we ever extend the format.
	domainBytes := []byte(StakeV2Domain)
	buf = appendU16(buf, uint16(len(domainBytes)))
	buf = append(buf, domainBytes...)

	// chainID — 8 bytes fixed big-endian to match the rest of the
	// V2 identity layer's u64 helper (see multisig_v2.go).
	buf = appendU64(buf, chainID)

	// from — 20 raw bytes fixed.
	buf = append(buf, from[:]...)

	// recipient — 20 raw bytes fixed.
	buf = append(buf, recipient[:]...)

	// txType — 1 byte.
	buf = append(buf, byte(txType))

	// value — uint256 big-endian 32 bytes fixed.
	var valBuf [32]byte
	value.FillBytes(valBuf[:])
	buf = append(buf, valBuf[:]...)

	// commission — uint32 big-endian 4 bytes fixed.
	var commBuf [4]byte
	commBuf[0] = byte(commission >> 24)
	commBuf[1] = byte(commission >> 16)
	commBuf[2] = byte(commission >> 8)
	commBuf[3] = byte(commission)
	buf = append(buf, commBuf[:]...)

	// nonce — length-prefixed uint16 BE + raw bytes.
	nonceBytes := []byte(nonce)
	buf = appendU16(buf, uint16(len(nonceBytes)))
	buf = append(buf, nonceBytes...)

	return Keccak256Hash(buf), nil
}

// appendU16 writes a uint16 in big-endian to buf and returns the
// extended slice. Used for length-prefixes. (appendU32 / appendU64
// are defined in multisig_v2.go and reused here.)
func appendU16(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}
