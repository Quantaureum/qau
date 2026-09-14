// Quantaureum Node source, version 1.0.0.
// Package types defines the Protocol V2 multisig canonical address and
// proposal domains (R38-P0-01). The legacy multisig precompile at address
// 0x66 trusted an attacker-supplied wallet address and caller; Protocol V2
// instead derives the wallet address from the authenticated caller, chain
// ID, threshold, normalized signer set, and a 32-byte salt, so an attacker
// cannot register an arbitrary victim's funded account as their own
// multisig. Proposal hashes bind every field that affects execution so a
// signed approval cannot be replayed against a mutated proposal.
//
// This file is shared by the Go node, the Go wallet, and the TypeScript
// SDK. The encoding uses Go's crypto/sha3 LegacyKeccak256 (Keccak-256, not
// the finalized SHA3-256) with fixed-width big-endian integers. Any change
// here must be mirrored by the TypeScript SDK at
// sdks/sdk/src/multisig/multisig.ts and locked to the same golden vectors.
package types

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
)

// MultisigV2 domain separation strings. The wallet domain covers the
// inputs to DeriveMultisigV2Address; the proposal domain covers the
// inputs to ComputeMultisigV2ProposalHash. They are ASCII bytes with no
// NUL terminator and are prepended verbatim to the hashed payload.
const (
	MultisigV2WalletDomain   = "QAU_MULTISIG_V2"
	MultisigV2ProposalDomain = "QAU_MULTISIG_PROPOSAL_V2"
	// MultisigV2SaltSize is the byte length of the unpredictable salt that
	// differentiates wallets with identical creator/threshold/signer sets.
	MultisigV2SaltSize = 32
	// MaxMultisigV2Signers is the upper bound on the signer set size. It
	// bounds the cost of an address-derivation DoS and matches the SDK.
	MaxMultisigV2Signers = 100
)

var (
	// ErrMultisigV2ZeroChainID is returned when the chain ID is zero; a
	// valid wallet must bind to a real chain so cross-chain registration
	// cannot collide.
	ErrMultisigV2ZeroChainID = errors.New("multisig v2: chain ID must be non-zero")
	// ErrMultisigV2ZeroCreator is returned when the creator address is the
	// zero address; the creator distinguishes wallets and anchors the
	// authenticated caller.
	ErrMultisigV2ZeroCreator = errors.New("multisig v2: creator must be non-zero")
	// ErrMultisigV2InvalidThreshold is returned when the threshold is zero,
	// exceeds the signer count, or exceeds the maximum uint32 range that
	// the fixed-width encoding can represent.
	ErrMultisigV2InvalidThreshold = errors.New("multisig v2: threshold must be in (0, signerCount]")
	// ErrMultisigV2NoSigners is returned when the signer set is empty.
	ErrMultisigV2NoSigners = errors.New("multisig v2: signers must not be empty")
	// ErrMultisigV2TooManySigners is returned when the signer set exceeds
	// MaxMultisigV2Signers.
	ErrMultisigV2TooManySigners = fmt.Errorf("multisig v2: signers must not exceed %d", MaxMultisigV2Signers)
	// ErrMultisigV2DuplicateSigner is returned when the signer set contains
	// the same address more than once. Permutation invariance depends on a
	// normalized set; duplicates would collapse the effective signer set and
	// change the derived address.
	ErrMultisigV2DuplicateSigner = errors.New("multisig v2: signers must not contain duplicates")
	// ErrMultisigV2ZeroSigner is returned when the signer set contains the
	// zero address; a keyless wallet defeats authentication.
	ErrMultisigV2ZeroSigner = errors.New("multisig v2: signer must not be zero")
	// ErrMultisigV2ZeroRecipient is returned when the proposal destination is
	// the zero address; this catches accidental empty calldata references.
	ErrMultisigV2ZeroRecipient = errors.New("multisig v2: destination must not be zero")
	// ErrMultisigV2NegativeValue is returned when the transfer value is
	// negative; the encoding is unsigned 256-bit.
	ErrMultisigV2NegativeValue = errors.New("multisig v2: value must not be negative")
	// ErrMultisigV2OversizedValue is returned when the transfer value does
	// not fit in 32 bytes; the fixed-width proposal encoding cannot
	// represent it without ambiguity.
	ErrMultisigV2OversizedValue = errors.New("multisig v2: value must fit in 256 bits")
)

// NormalizeMultisigV2Signers returns the canonical signer set: sorted,
// deduplicated, with no zero addresses. It accepts raw 20-byte addresses
// and rejects invalid inputs up front so the address derivation never
// operates on untrusted data.
func NormalizeMultisigV2Signers(signers []Address) ([]Address, error) {
	if len(signers) == 0 {
		return nil, ErrMultisigV2NoSigners
	}
	if len(signers) > MaxMultisigV2Signers {
		return nil, ErrMultisigV2TooManySigners
	}
	var zero Address
	seen := make(map[Address]struct{}, len(signers))
	out := make([]Address, 0, len(signers))
	for _, s := range signers {
		if s == zero {
			return nil, ErrMultisigV2ZeroSigner
		}
		if _, dup := seen[s]; dup {
			return nil, ErrMultisigV2DuplicateSigner
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		// Lexicographic byte comparison produces a stable canonical order
		// across implementations (Go and TypeScript Uint8Array.sort both
		// use unsigned comparisons by default, but we seed the raw bytes to
		// avoid surprises).
		for k := 0; k < AddressLength; k++ {
			if out[i][k] != out[j][k] {
				return out[i][k] < out[j][k]
			}
		}
		return false
	})
	return out, nil
}

// DeriveMultisigV2Address returns the canonical multisig wallet address
// derived from chainID, creator, threshold, signers, and salt. The address
// is the last 20 bytes of Keccak256("QAU_MULTISIG_V2" || chainID ||
// creator || threshold || signerCount || sortedSigners || salt), all
// encoded with fixed-width big-endian integers and raw addresses.
//
// Permutation invariance: the signers are normalized before hashing, so any
// permutation of the same signer set derives the same address. Bound
// fields: chain ID, creator, threshold, signer set, and salt are all
// committed before the address is taken, so an attacker cannot cause a
// collision by reordering or omitting any of them.
func DeriveMultisigV2Address(chainID uint64, creator Address, threshold uint32, signers []Address, salt [MultisigV2SaltSize]byte) (Address, error) {
	if chainID == 0 {
		return Address{}, ErrMultisigV2ZeroChainID
	}
	var zero Address
	if creator == zero {
		return Address{}, ErrMultisigV2ZeroCreator
	}
	normalized, err := NormalizeMultisigV2Signers(signers)
	if err != nil {
		return Address{}, err
	}
	if threshold == 0 || uint32(len(normalized)) < threshold {
		return Address{}, ErrMultisigV2InvalidThreshold
	}

	encode := make([]byte, 0, len(MultisigV2WalletDomain)+8+AddressLength+4+4+len(normalized)*AddressLength+MultisigV2SaltSize)
	encode = append(encode, []byte(MultisigV2WalletDomain)...)
	encode = appendU64(encode, chainID)
	encode = append(encode, creator[:]...)
	encode = appendU32(encode, threshold)
	encode = appendU32(encode, uint32(len(normalized)))
	for _, s := range normalized {
		encode = append(encode, s[:]...)
	}
	encode = append(encode, salt[:]...)

	h := Keccak256Hash(encode)
	var addr Address
	copy(addr[:], h[HashLength-AddressLength:])
	return addr, nil
}

// ComputeMultisigV2ProposalHash returns the canonical hash of a multisig
// proposal: Keccak256("QAU_MULTISIG_PROPOSAL_V2" || chainID || wallet ||
// destination || value[32] || nonce || expiry || Keccak256(callData)).
//
// Every field that affects execution is bound to the hash so:
//   - a signed approval cannot be replayed against a proposal whose
//     destination, value, calldata, nonce, or expiry was modified after
//     the approval was collected;
//   - the wallet address binds the proposal to the specific derived wallet,
//     blocking cross-wallet replay;
//   - the chain ID blocks cross-chain replay;
//   - the callData is committed by hash (not by value) to keep the signed
//     payload size independent of calldata length while still preventing
//     any tampering with the executed bytes.
func ComputeMultisigV2ProposalHash(chainID uint64, wallet, destination Address, value *big.Int, callData []byte, nonce, expiry uint64) (Hash, error) {
	if chainID == 0 {
		return Hash{}, ErrMultisigV2ZeroChainID
	}
	var zero Address
	if wallet == zero {
		return Hash{}, ErrMultisigV2ZeroCreator
	}
	if destination == zero {
		return Hash{}, ErrMultisigV2ZeroRecipient
	}
	if value == nil {
		value = new(big.Int)
	}
	if value.Sign() < 0 {
		return Hash{}, ErrMultisigV2NegativeValue
	}
	if value.BitLen() > 256 {
		return Hash{}, ErrMultisigV2OversizedValue
	}

	var valueBytes [32]byte
	value.FillBytes(valueBytes[:])

	callDataHash := Keccak256Hash(callData)

	encode := []byte(MultisigV2ProposalDomain)
	encode = appendU64(encode, chainID)
	encode = append(encode, wallet[:]...)
	encode = append(encode, destination[:]...)
	encode = append(encode, valueBytes[:]...)
	encode = appendU64(encode, nonce)
	encode = appendU64(encode, expiry)
	encode = append(encode, callDataHash[:]...)

	return Keccak256Hash(encode), nil
}

// appendU32 appends a 4-byte big-endian uint32. Fixed width keeps the
// encoding unambiguous across Go and TypeScript implementations and
// prevents variable-length encodings from being misdecoded.
func appendU32(b []byte, v uint32) []byte {
	return append(b,
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v),
	)
}

// appendU64 appends an 8-byte big-endian uint64.
func appendU64(b []byte, v uint64) []byte {
	return append(b,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v),
	)
}
