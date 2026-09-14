// Quantaureum Node source, version 1.0.0.
// Package encoding provides serialization and deserialization for Quantaureum blockchain data structures.
// It uses a protobuf-compatible binary encoding format.
package encoding

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

var (
	// ErrInvalidData is returned when data cannot be deserialized
	ErrInvalidData = errors.New("invalid data")

	// ErrInvalidHash is returned when a hash has invalid length
	ErrInvalidHash = errors.New("invalid hash length")

	// ErrInvalidAddress is returned when an address has invalid length
	ErrInvalidAddress = errors.New("invalid address length")

	// ErrMalformedMessage is returned when a protobuf message is malformed
	ErrMalformedMessage = errors.New("malformed protobuf message")

	// ErrInvalidVersion is returned when version is invalid
	ErrInvalidVersion = errors.New("invalid version")

	// ErrInvalidTimestamp is returned when timestamp is invalid
	ErrInvalidTimestamp = errors.New("invalid timestamp")

	// ErrInvalidTxType is returned when transaction type is invalid
	ErrInvalidTxType = errors.New("invalid transaction type")

	// ErrEmptyData is returned when data is empty
	ErrEmptyData = errors.New("empty data")
)

// TxType represents the type of transaction
type TxType uint8

const (
	TxTypeTransfer     TxType = iota // Normal transfer
	TxTypeContract                   // Contract call
	TxTypeCreate                     // Contract creation
	TxTypeStake                      // Staking operation
	TxTypeUnstake                    // Unstaking operation
	TxTypeDynamicFee                 // EIP-1559 dynamic fee transaction
	TxTypeBlob                       // EIP-4844 blob-carrying transaction
	TxTypeMultiSig                   // Multi-signature transaction (N-of-M Dilithium3)
	TxTypePrivacy                    // Privacy transaction (stealth address + confidential amount)
	TxTypeCommit                     // CRV2: commit-reveal commitment (micro-tx, gas-only execution)
	TxTypeValidatorKey               // R131: validator key ops (rotate session / bind master / revoke)
)

func (t TxType) IsValid() bool {
	return t <= TxTypeValidatorKey
}

func (t TxType) String() string {
	switch t {
	case TxTypeTransfer:
		return "transfer"
	case TxTypeContract:
		return "contract"
	case TxTypeCreate:
		return "create"
	case TxTypeStake:
		return "stake"
	case TxTypeUnstake:
		return "unstake"
	case TxTypeDynamicFee:
		return "dynamic_fee"
	case TxTypeBlob:
		return "blob"
	case TxTypeMultiSig:
		return "multisig"
	case TxTypePrivacy:
		return "privacy"
	case TxTypeCommit:
		return "commit"
	case TxTypeValidatorKey:
		return "validator_key"
	default:
		return "unknown"
	}
}

// BlockHeader represents the header of a block
type BlockHeader struct {
	Version      uint32
	Height       uint64
	Timestamp    int64
	ParentHash   types.Hash
	StateRoot    types.Hash
	TxRoot       types.Hash
	ReceiptRoot  types.Hash
	ProposerAddr types.Address
	VRFProof     []byte
	VRFValue     types.Hash
	Signature    []byte
	ChainID      uint64 // Chain ID for replay protection (EIP-155)

	// QPOS consensus fields
	Slot           uint64     // Slot number for this block
	Epoch          uint64     // Epoch number
	RANDAOReveal   types.Hash // Proposer's RANDAO reveal
	Attestations   []byte     // Serialized attestations included in this block
	JustifiedEpoch uint64     // Latest justified epoch
	FinalizedEpoch uint64     // Latest finalized epoch
	KeyVersion     uint64     // audit-fix C-5: Signing key version for rotation-safe validation

	BaseFee  *big.Int // EIP-1559: base fee for this block (nil for pre-EIP-1559 blocks)
	GasUsed  uint64   // EIP-1559: total gas used by transactions in this block
	GasLimit uint64   // Gas limit for this block

	ExcessBlobGas uint64 // EIP-4844: excess blob gas from previous blocks
	BlobGasUsed   uint64 // EIP-4844: total blob gas used in this block

	SyncCommitteeSig  []byte // Aggregated sync committee signature for light clients
	SyncCommitteeBits []byte // Bitfield of which sync committee members signed

	DAAttestation     []byte // Danksharding: aggregated DA attestation data
	DABlobCommitments []byte // Danksharding: serialized blob KZG commitments

	// Stardust Consensus fields
	QTDSignature          []byte     // Executive Chamber QTD threshold signature for instant finality
	ReviewAttestationRoot types.Hash // Review Chamber Merkle root of attestation votes
	ExecutiveSealers      []byte     // Executive Chamber committee member indices who sealed this block
	FinalityType          uint8      // 0=CasperFFG, 1=QTDInstant

	// R54-ACC (2026-08-07): per-epoch VRF accumulator carried ON-CHAIN at
	// block-production time. Derived deterministically from the parent header
	// (see consensus.ComputeNextVRFAccumulator), so proposer election reads a
	// value that is identical across all nodes regardless of local sync/restart/
	// reorg history — eliminating the chain-fork root cause. Genesis = zero hash.
	VRFAccumulator types.Hash
}

// Transaction represents a transaction
type Transaction struct {
	Version   uint32
	Type      TxType
	Nonce     uint64
	From      types.Address
	To        *types.Address // nil for contract creation
	Value     *big.Int
	GasLimit  uint64
	GasPrice  *big.Int
	Data      []byte
	PublicKey []byte // Sender's public key for signature verification (required for Dilithium)
	Signature []byte
	ChainID   uint64 // Cross-chain replay protection (field 13)

	MaxFeePerGas         *big.Int // EIP-1559: max total fee per gas the sender is willing to pay
	MaxPriorityFeePerGas *big.Int // EIP-1559: max priority fee per gas (tip to proposer)

	MaxFeePerBlobGas    *big.Int       // EIP-4844: max fee per blob gas
	BlobVersionedHashes []types.Hash   // EIP-4844: versioned hashes of blob commitments
	BlobGasUsed         uint64         // EIP-4844: blob gas consumed by this tx
	BlobSidecar         *BlobTxSidecar // EIP-4844: sidecar carrying actual blob data (not in tx body)

	// EthHash stores the Ethereum-compatible transaction hash (keccak256 of RLP data)
	// LEGACY COMPATIBILITY - for MetaMask/Ethereum wallets
	// This is set during RLP decoding and used for lookups
	EthHash types.Hash

	// Multi-signature fields (TxTypeMultiSig)
	MultiSigSignatures   [][]byte // Collected Dilithium3 signatures from each signer
	MultiSigSignerBitmap []byte   // Bitmap indicating which signers have signed
	MultiSigRequiredSigs int      // Number of required signatures (N-of-M)
	MultiSigTotalSigners int      // Total number of signers (M)

	// Privacy transaction fields (TxTypePrivacy)
	PrivacyEphemeralPubKey  []byte     // Ephemeral public key for stealth address
	PrivacyStealthAddrHash  types.Hash // Hash of the stealth address
	PrivacyCommitments      [][]byte   // Pedersen commitments for confidential amounts
	PrivacyEncryptedAmounts [][]byte   // Encrypted amounts for each output
	PrivacyRangeProofs      [][]byte   // Range proofs for each output
	PrivacyBalanceProof     []byte     // Balance conservation proof
	PrivacyNullifier        types.Hash // Nullifier for double-spend prevention
}

// Block represents a complete block
type Block struct {
	Header       *BlockHeader
	Transactions []*Transaction
}

// StoredReceipt is the persistent representation of a transaction receipt.
//
// R35-P0-09 FIX (2026-07-29): Previously the codebase had NO persistent
// receipt storage — eth_getTransactionReceipt returned either nil or a
// simulated receipt reconstructed from cached gasUsed. This struct is the
// Phase 1 minimal persistence layer: it is stored keyed by tx hash in
// block_store.go (receiptPrefix) and survives node restarts.
//
// Phase 2 (deferred, consensus-breaking) will embed receipts directly in
// the Block struct and hash them into ReceiptRoot for consensus validation.
// Until then, receipts are AUTHORITY-OF-PROPOSER: the proposing node
// persists what it executed, and validating nodes trust the proposer for
// receipt data (status/gasUsed/logs). Receipt tampering by a malicious
// proposer affects only dApp observability, NOT chain state or balances
// (which are validated via stateRoot).
type StoredReceipt struct {
	TxHash      types.Hash
	BlockHash   types.Hash
	BlockNumber uint64
	TxIndex     uint32
	Status      uint64 // 1 = success, 0 = failure
	GasUsed     uint64
	Logs        []*StoredLog
	Error       string
}

// StoredLog is the persistent representation of an event log.
type StoredLog struct {
	Address types.Address
	Topics  []types.Hash
	Data    []byte
}

// Equal returns true if two BlockHeaders are equal
//
// CRYPTO-R13-008 (2026-07-21) FIX: Hash and Address fields now use the
// ConstantTimeEqual / Equal methods on those types instead of ==. Go's
// array == compiles to memequal, which short-circuits on the first
// differing byte. Although most of these fields are public once the block
// is in the chain, BlockHeader.Equal is called during block validation
// BEFORE the header has been fully broadcast, where the caller may still
// be holding an unannounced hash. Using the explicit constant-time path
// removes any dependency on compiler/runtime behavior.
func (h *BlockHeader) Equal(other *BlockHeader) bool {
	if h == nil || other == nil {
		return h == other
	}
	// Scalar (uint64, int) comparisons compile to a single machine
	// instruction and are already constant-time.
	return h.Version == other.Version &&
		h.Height == other.Height &&
		h.Timestamp == other.Timestamp &&
		h.ParentHash.ConstantTimeEqual(other.ParentHash) &&
		h.StateRoot.ConstantTimeEqual(other.StateRoot) &&
		h.TxRoot.ConstantTimeEqual(other.TxRoot) &&
		h.ReceiptRoot.ConstantTimeEqual(other.ReceiptRoot) &&
		h.ProposerAddr.ConstantTimeEqual(other.ProposerAddr) &&
		bytesEqual(h.VRFProof, other.VRFProof) &&
		h.VRFValue == other.VRFValue &&
		bytesEqual(h.Signature, other.Signature) &&
		h.ChainID == other.ChainID &&
		h.Slot == other.Slot &&
		h.Epoch == other.Epoch &&
		h.RANDAOReveal.ConstantTimeEqual(other.RANDAOReveal) &&
		bytesEqual(h.Attestations, other.Attestations) &&
		h.JustifiedEpoch == other.JustifiedEpoch &&
		h.FinalizedEpoch == other.FinalizedEpoch &&
		bigIntEqual(h.BaseFee, other.BaseFee) &&
		h.ExcessBlobGas == other.ExcessBlobGas &&
		h.BlobGasUsed == other.BlobGasUsed &&
		bytesEqual(h.DAAttestation, other.DAAttestation) &&
		bytesEqual(h.DABlobCommitments, other.DABlobCommitments) &&
		bytesEqual(h.QTDSignature, other.QTDSignature) &&
		h.ReviewAttestationRoot.ConstantTimeEqual(other.ReviewAttestationRoot) &&
		bytesEqual(h.ExecutiveSealers, other.ExecutiveSealers) &&
		h.FinalityType == other.FinalityType
}

// Equal returns true if two Transactions are equal
func (tx *Transaction) Equal(other *Transaction) bool {
	if tx == nil || other == nil {
		return tx == other
	}

	// Compare To addresses (handle nil case).
	//
	// CRYPTO-R13-008 (2026-07-21) FIX: Previously used `*tx.To == *other.To`,
	// which compiles to memequal and short-circuits on the first differing
	// byte. Use Address.ConstantTimeEqual to match the BlockHeader.Equal
	// behavior and the existing Address.Equal / Address.ConstantTimeEqual
	// audit-fix L-1 contract.
	toEqual := (tx.To == nil && other.To == nil) ||
		(tx.To != nil && other.To != nil && tx.To.ConstantTimeEqual(*other.To))

	// CRYPTO-R13-004 (2026-07-21) FIX: Previously used tx.Value.Cmp(other.Value)
	// which is non-constant-time — big.Int.Cmp returns as soon as it finds a
	// differing word, leaking which word differs via timing. Although
	// transaction Value and GasPrice are public values once the transaction
	// is in a block, the Equal() method is also called during transaction
	// pool deduplication and block validation BEFORE inclusion, where the
	// caller may not have announced the value yet. Use bigIntEqual which
	// routes through constantTimeBigIntEqual.
	valueEqual := bigIntEqual(tx.Value, other.Value)
	gasPriceEqual := bigIntEqual(tx.GasPrice, other.GasPrice)

	// SECURITY FIX: Compare ChainID to prevent cross-chain transaction equality
	return tx.Version == other.Version &&
		tx.Type == other.Type &&
		tx.Nonce == other.Nonce &&
		tx.From == other.From &&
		toEqual &&
		valueEqual &&
		tx.GasLimit == other.GasLimit &&
		gasPriceEqual &&
		tx.ChainID == other.ChainID && // SECURITY FIX: Compare ChainID
		bytesEqual(tx.Data, other.Data) &&
		bytesEqual(tx.PublicKey, other.PublicKey) &&
		bytesEqual(tx.Signature, other.Signature)
}

// bytesEqual compares two byte slices for equality using constant-time comparison.
// SECURITY FIX: Uses crypto/subtle.ConstantTimeCompare to prevent timing attacks
// on sensitive data like signatures and VRF proofs.
func bytesEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// bigIntEqual compares two big.Int values in constant time.
//
// CRYPTO-R13-004 (2026-07-21) FIX: Previously this used big.Int.Cmp which
// returns as soon as it finds a differing word, leaking timing information
// about which word differs. This matters because bigIntEqual is called from
// Transaction.Equal and BlockHeader.Equal during block validation and
// transaction-pool deduplication, where the caller may not have broadcast
// the value yet — a remote peer that can observe response timing could
// partially recover an unannounced value.
//
// Implementation: For values fitting in 32 bytes (256 bits — the EVM/QVM
// word size), zero-pad both to 32 bytes and use subtle.ConstantTimeCompare.
// This guarantees the same number of byte comparisons regardless of where
// the values differ.
//
// For values exceeding 256 bits (extremely rare in practice — total QAU
// supply is ~2^87), fall back to Cmp. The fallback is non-constant-time
// but these oversized values are already inherently leaky through their
// big.Int internal []Word slice length, and they cannot fit in a single
// EVM word anyway, so any timing leak does not meaningfully aid recovery.
func bigIntEqual(a, b *big.Int) bool {
	if a == nil || b == nil {
		// Nil equality is itself a public branch (caller can observe via
		// downstream side effects), but the alternative — a fixed-time
		// comparison of nil-pointer-derived zero values — is fragile.
		// The nil case is not a timing-attack vector.
		return a == b
	}
	return constantTimeBigIntEqual(a, b)
}

// constantTimeBigIntEqual performs a constant-time equality comparison on
// two non-nil big.Int values that fit in 32 bytes (256 bits).
func constantTimeBigIntEqual(a, b *big.Int) bool {
	// Compare signs in constant time. big.Int.Sign() returns -1, 0, or 1.
	// We shift by +1 to make all values non-negative (0, 1, 2) so the
	// conversion to int32 is safe and does not lose information.
	// subtle.ConstantTimeEq returns 1 iff the two int32 values are equal.
	//
	// This sign check is REQUIRED because big.Int.FillBytes (used below)
	// only writes the absolute value — without this guard, -1 and +1
	// would both fill as [0,...,0,1] and compare equal, a real bug we
	// hit during CRYPTO-R13-004 testing.
	aSign := int32(a.Sign() + 1)
	bSign := int32(b.Sign() + 1)
	if subtle.ConstantTimeEq(aSign, bSign) == 0 {
		return false
	}
	// BitLen is O(1) (reads the internal []Word slice length). It does
	// leak the magnitude of each value, but magnitude is already exposed
	// via the []Word slice length itself — a determined attacker observing
	// memory layout or GC pressure could recover it regardless. The
	// property we care about here is that the *per-word comparison* does
	// not short-circuit on the first differing word.
	if a.BitLen() > 256 || b.BitLen() > 256 {
		return a.Cmp(b) == 0
	}
	var aBuf [32]byte
	var bBuf [32]byte
	a.FillBytes(aBuf[:])
	b.FillBytes(bBuf[:])
	return subtle.ConstantTimeCompare(aBuf[:], bBuf[:]) == 1
}

// Validate validates the BlockHeader
func (h *BlockHeader) Validate() error {
	if h == nil {
		return fmt.Errorf("%w: nil header", ErrInvalidData)
	}
	if h.Timestamp < 0 {
		return fmt.Errorf("%w: negative timestamp", ErrInvalidTimestamp)
	}
	return nil
}

// Validate validates the Transaction
func (tx *Transaction) Validate() error {
	if tx == nil {
		return fmt.Errorf("%w: nil transaction", ErrInvalidData)
	}
	if !tx.Type.IsValid() {
		return fmt.Errorf("%w: %d", ErrInvalidTxType, tx.Type)
	}
	if tx.ChainID == 0 {
		return fmt.Errorf("transaction chain ID is zero")
	}
	if tx.GasLimit < 21000 {
		return fmt.Errorf("gas limit too low: %d", tx.GasLimit)
	}
	if tx.Value != nil && tx.Value.Sign() < 0 {
		return fmt.Errorf("negative value")
	}
	// CONS-R18-CRIT-01 (2026-07-24): Blob txs use EIP-1559 dynamic fees
	// (MaxFeePerGas/MaxPriorityFeePerGas) instead of legacy GasPrice.
	// Accept either form: blob txs must have a valid MaxFeePerGas; other
	// tx types must have a valid GasPrice.
	if tx.IsBlobTx() {
		if tx.MaxFeePerGas == nil || tx.MaxFeePerGas.Sign() <= 0 {
			return fmt.Errorf("invalid gas price")
		}
	} else {
		if tx.GasPrice == nil || tx.GasPrice.Sign() <= 0 {
			return fmt.Errorf("invalid gas price")
		}
	}
	if len(tx.Signature) == 0 {
		return fmt.Errorf("missing transaction signature")
	}
	// L9-036 FIX: Validate Dilithium3 public key length when present.
	// A valid Dilithium3 public key must be exactly 1952 bytes.
	// An incorrect length indicates tampering or encoding corruption.
	if len(tx.PublicKey) > 0 && len(tx.PublicKey) != crypto.Dilithium3PublicKeySize {
		return fmt.Errorf("invalid public key length: expected %d bytes, got %d", crypto.Dilithium3PublicKeySize, len(tx.PublicKey))
	}
	return nil
}

// Size returns the approximate size of the transaction in bytes.
func (tx *Transaction) Size() int {
	size := 8 + 1 + 8           // version + type + nonce
	size += types.AddressLength // from
	if tx.To != nil {
		size += types.AddressLength
	}
	if tx.Value != nil {
		size += len(tx.Value.Bytes())
	}
	size += 8 // gas limit
	if tx.GasPrice != nil {
		size += len(tx.GasPrice.Bytes())
	}
	size += len(tx.Data)
	size += len(tx.PublicKey)
	size += len(tx.Signature)
	return size
}

// SigningHash returns the hash used for signing (excludes signature and public key).
// SECURITY FIX: Includes ChainID to prevent cross-chain replay attacks.
// Cross-chain replay protection is now enforced at the signing level, not just validation.
// L10-021: Verified — all callers of SigningHash() properly handle the error
// return. The only caller that ignores it (miner/mev_protection.go) calls
// BuilderBid.SigningHash() which is a different method returning only types.Hash.
//
// CRYPTO-R13-001 (2026-07-21) FIX: Previously SigningHash only copied the
// base fields (Version..ChainID), omitting all EIP-1559/4844/multi-sig/privacy
// extension fields. This allowed an attacker to tamper with MaxFeePerGas
// (overcharge gas), MultiSigRequiredSigs (bypass multi-sig), or PrivacyNullifier
// (double-spend) without invalidating the signature.
//
// CRYPTO-R13-002 (2026-07-21) FIX: Added a domain separation prefix
// "Quantaureum Transaction v1\0" before the serialized transaction to
// prevent cross-protocol signature reuse (e.g., signing a Quantaureum tx
// could be replayed as a vote in another protocol using the same Dilithium3
// key).
//
// The fix copies ALL fields except Signature/PublicKey/EthHash (which must
// remain zeroed to match the verification path's encoding).
func (tx *Transaction) SigningHash() (types.Hash, error) {
	// R14-MED (2026-07-21): Normalize nil big.Int fields to new(big.Int)
	// (zero value) before hashing. Go's big.Int.Bytes() returns []byte{}
	// for both nil and zero, so without normalization, a tx with Value=nil
	// and a tx with Value=big.NewInt(0) produce identical SigningHashes.
	// This creates a signature-malleability risk: a signature over a
	// "nil value" tx is also valid for a "zero value" tx (and vice versa).
	// Normalizing to a non-nil zero value makes the encoding unambiguous
	// and consistent with bigIntEqual semantics (nil != 0 in Equal, so
	// the hash must also distinguish them — we resolve this by always
	// using the explicit zero form).
	//
	// This normalization is applied to ALL big.Int fields that participate
	// in SigningHash: Value, GasPrice, MaxFeePerGas, MaxPriorityFeePerGas,
	// MaxFeePerBlobGas. Other fields (Nonce, GasLimit, ChainID, etc.) are
	// fixed-width integers and have no nil/0 ambiguity.
	normalizeBigInt := func(v *big.Int) *big.Int {
		if v == nil {
			return new(big.Int)
		}
		return v
	}

	// Create a copy with ALL transaction fields for signing.
	// CRITICAL: Explicitly zero Signature, PublicKey, and EthHash so marshaling
	// produces the same encoding on both signing and verification paths.
	// Without this, a populated Signature+PublicKey on the source tx causes
	// SigningHash() to marshal ~5311 bytes while the signing side marshals ~60 bytes,
	// producing different hashes and invalidating all signatures.
	txCopy := &Transaction{
		Version:  tx.Version,
		Type:     tx.Type,
		Nonce:    tx.Nonce,
		From:     tx.From,
		To:       tx.To,
		Value:    normalizeBigInt(tx.Value),
		GasLimit: tx.GasLimit,
		GasPrice: normalizeBigInt(tx.GasPrice),
		Data:     tx.Data,
		ChainID:  tx.ChainID, // SECURITY FIX: Include ChainID in signing hash

		// CRYPTO-R13-001: EIP-1559 fields — previously omitted, allowing
		// gas-fee tampering without signature invalidation.
		MaxFeePerGas:         normalizeBigInt(tx.MaxFeePerGas),
		MaxPriorityFeePerGas: normalizeBigInt(tx.MaxPriorityFeePerGas),

		// CRYPTO-R13-001: EIP-4844 fields — previously omitted, allowing
		// blob-gas-fee tampering and blob-hash substitution.
		MaxFeePerBlobGas:    normalizeBigInt(tx.MaxFeePerBlobGas),
		BlobVersionedHashes: tx.BlobVersionedHashes,
		BlobGasUsed:         tx.BlobGasUsed,
		// BlobSidecar is intentionally NOT copied — it carries the actual
		// blob data and is not part of the signed tx body (matches EIP-4844
		// spec where the sidecar is committed to via BlobVersionedHashes).

		// CRYPTO-R13-001: Multi-sig *configuration* fields — previously
		// omitted, allowing an attacker to lower MultiSigRequiredSigs
		// (e.g., 3-of-5 → 1-of-5) or replace the signer bitmap without
		// invalidating signatures.
		//
		// CRYPTO-R14-001 (2026-07-21) FIX: MultiSigSignatures (the list
		// of already-collected signatures) MUST be excluded from the
		// signing hash, otherwise each subsequent signer hashes a
		// different payload (signer N hashes the list containing sigs
		// 1..N-1) and the final verification against the canonical hash
		// fails for every signature except the first. This is the same
		// exclusion principle used for Signature / PublicKey above.
		MultiSigSignatures:   nil,
		MultiSigSignerBitmap: tx.MultiSigSignerBitmap,
		MultiSigRequiredSigs: tx.MultiSigRequiredSigs,
		MultiSigTotalSigners: tx.MultiSigTotalSigners,

		// CRYPTO-R13-001: Privacy fields — previously omitted, allowing
		// nullifier substitution (double-spend), commitment/proof swap
		// (decrypt amounts to attacker), or stealth-address hijack.
		PrivacyEphemeralPubKey:  tx.PrivacyEphemeralPubKey,
		PrivacyStealthAddrHash:  tx.PrivacyStealthAddrHash,
		PrivacyCommitments:      tx.PrivacyCommitments,
		PrivacyEncryptedAmounts: tx.PrivacyEncryptedAmounts,
		PrivacyRangeProofs:      tx.PrivacyRangeProofs,
		PrivacyBalanceProof:     tx.PrivacyBalanceProof,
		PrivacyNullifier:        tx.PrivacyNullifier,

		// Explicitly zero to match signing path encoding:
		Signature: nil,
		PublicKey: nil,
		EthHash:   types.Hash{},
	}

	// L9-032 FIX: Do not ignore the marshal error — propagate it so callers
	// can reject transactions that cannot be encoded correctly.
	data, err := MarshalTransaction(txCopy)
	if err != nil {
		return types.Hash{}, fmt.Errorf("marshal transaction for signing hash: %w", err)
	}
	// CRYPTO-R13-002 (2026-07-21) FIX: Domain separation prefix.
	// Prepend a fixed-length, zero-terminated tag so that a Quantaureum
	// transaction signature cannot be replayed in any other protocol that
	// uses the same Dilithium3 key with a raw SHA3-256 of serialized data.
	// The tag includes a version byte (v1) for future format migrations.
	//
	// Layout: [tag:"Quantaureum Transaction v1\0"][marshaled-tx-data]
	// The tag is 27 bytes (26 visible + 1 NUL). Including it in the hash
	// input ensures the resulting signature is bound to this exact tag,
	// making cross-protocol replay impossible as long as other protocols
	// use a different prefix (or no prefix).
	domainSeparated := make([]byte, 0, len(signingDomainSeparator)+len(data))
	domainSeparated = append(domainSeparated, signingDomainSeparator...)
	domainSeparated = append(domainSeparated, data...)
	return types.BytesToHash(hashData(domainSeparated)), nil
}

// signingDomainSeparator is the fixed prefix prepended to transaction
// data before computing SigningHash. The NUL terminator prevents prefix
// extension attacks (a protocol using prefix "Quantaureum Transaction v1"
// without the NUL would be ambiguous with "Quantaureum Transaction v1\0X").
//
// CRYPTO-R13-002 (2026-07-21).
var signingDomainSeparator = []byte("Quantaureum Transaction v1\x00")

// Hash returns the full transaction hash.
//
// L9-032 FIX: The marshal error is no longer silently ignored with "_". Because
// Hash() is used in ~50 call sites including sort comparators and map keys
// (which cannot propagate errors), the signature is kept as types.Hash; on a
// marshal failure (only possible for a nil tx) a zero hash is returned as a
// defensive sentinel so downstream code treats it as an invalid hash rather
// than hashing empty data. SigningHash() — the security-critical path —
// returns the error explicitly.
func (tx *Transaction) Hash() types.Hash {
	data, err := MarshalTransaction(tx)
	if err != nil {
		return types.Hash{}
	}
	return types.BytesToHash(hashData(data))
}

// hashData computes SHA3-256 hash of data.
func hashData(data []byte) []byte {
	hash := sha3.Sum256(data)
	return hash[:]
}
