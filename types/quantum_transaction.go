// Quantaureum Node source, version 1.0.0.
// Package types provides quantum transaction types for Quantaureum blockchain.
// This is the NATIVE quantum transaction format using Dilithium3 signatures.
package types

import (
	"bytes"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
	"unsafe"

	logging "github.com/quantaureum/qau/log"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"golang.org/x/crypto/sha3"
)

// CRYPTO- (2026-07-20) compile-time assertion: bool is exactly 1 byte.
// Same invariant as crypto/generate.go's boolToInt32 — needed because Verify()
// below reads the bool's underlying byte via unsafe.Pointer to perform a
// constant-time bool→int conversion without a secret-dependent branch.
var _ [1 - unsafe.Sizeof(true)]byte

const (
	// QuantumSignatureSize is size of a Dilithium3 signature in bytes.
	//  NOTE: This duplicates crypto.Dilithium3SignatureSize (both derive
	// from mode3.SignatureSize). Kept as a separate constant because types/
	// must not import crypto/ (L1 layer discipline — crypto depends on types,
	// not the reverse). Both constants are guaranteed equal by the circl source.
	QuantumSignatureSize = mode3.SignatureSize // 3293 bytes

	// QuantumPublicKeySize is size of a Dilithium3 public key in bytes
	QuantumPublicKeySize = mode3.PublicKeySize // 1952 bytes

	// MaxTransactionDataSize is maximum size of transaction data
	MaxTransactionDataSize = 1024 * 1024 // 1MB

	// MaxGasLimit is the maximum gas limit allowed for a single transaction.
	// H-04 (R8 2026-07-19 FIX): Cap gas limit to prevent resource exhaustion
	// attacks where an attacker submits a transaction with GasLimit = MaxUint64.
	// 30M matches Ethereum's per-block gas limit convention.
	MaxGasLimit = 30_000_000

	// MaxUInt256 is 2^256 - 1, the maximum value representable in 256 bits.
	// R9-C03 (2026-07-19) FIX: All *big.Int Value/GasPrice paths must reject
	// values exceeding this bound. Without this cap, a *big.Int larger than
	// 2^256-1 would be silently truncated by Bytes() (which only returns the
	// absolute-value bytes up to the minimal length), producing a different
	// post-serialization value than the in-memory one — a consensus fork.
	MaxUInt256Bits = 256
)

// Quantum transaction errors
var (
	// ErrTransactionTooLarge is returned when transaction data exceeds maximum size
	ErrTransactionTooLarge = errors.New("transaction data too large")

	// ErrInvalidPublicKey is returned when public key is invalid
	ErrInvalidPublicKey = errors.New("invalid public key")

	// ErrInvalidSignature is returned when signature is invalid
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrNegativeValue is returned when transaction value is negative.
	// H-04 (R8 2026-07-19 FIX): A negative Value would cause the receiver's
	// balance to DECREASE and the sender's balance to INCREASE on execution,
	// i.e. reverse-transfer / mint-out-of-thin-air. big.Int is signed, so
	// without this check an attacker-controlled payload can serialize -10^18.
	ErrNegativeValue = errors.New("transaction value cannot be negative")

	// ErrNegativeGasPrice is returned when gas price is negative.
	// H-04 (R8 2026-07-19 FIX): A negative GasPrice means the miner pays the
	// sender for executing the transaction, which can be abused to drain
	// miner/validator balances or trigger balance underflow in StateDB.
	ErrNegativeGasPrice = errors.New("gas price cannot be negative")

	// ErrGasLimitTooHigh is returned when gas limit exceeds MaxGasLimit.
	// H-04 (R8 2026-07-19 FIX): Cap to prevent resource exhaustion.
	ErrGasLimitTooHigh = errors.New("gas limit exceeds maximum")

	// ErrValueTooLarge is returned when Value or GasPrice exceeds 2^256-1.
	// R9-C03 (2026-07-19) FIX: Prevents serialization truncation that would
	// cause consensus divergence (in-memory value differs from post-serialize
	// value on different nodes).
	ErrValueTooLarge = errors.New("value exceeds 2^256-1")

	// ErrInvalidChainID is returned when chainID is zero.
	// R9-C02 (2026-07-19) FIX: NewQuantumStake previously returned a tx with
	// ChainID=0 that would silently fail Verify() at submission time. Lift
	// this into an explicit construction-time error.
	ErrInvalidChainID = errors.New("chainID must be greater than zero")
)

// validateBigInt256 validates that v is non-negative and fits in 256 bits.
// R9-C03 (2026-07-19) FIX: Centralized check used by all *big.Int fields.
// Returns the corresponding sentinel error on failure, nil on success.
// nil v is treated as valid (zero value) for caller convenience.
func validateBigInt256(v *big.Int, negativeErr error) error {
	if v == nil {
		return nil
	}
	if v.Sign() < 0 {
		return negativeErr
	}
	// BitLen() returns the number of bits required to represent v in binary.
	// 2^256-1 has BitLen=256; 2^256 has BitLen=257. Reject any value whose
	// bit length exceeds 256.
	if v.BitLen() > MaxUInt256Bits {
		return ErrValueTooLarge
	}
	return nil
}

// QuantumSigner is the interface for signing quantum transactions.
// Implemented by *crypto.PrivateKey.
type QuantumSigner interface {
	// Sign signs the message and returns the signature
	Sign(message []byte) ([]byte, error)
	// PublicKeyBytes returns the signer's public key as bytes
	PublicKeyBytes() []byte
}

// TransactionType represents the type of transaction
type TransactionType uint8

const (
	// TransferType is a simple token transfer transaction
	TransferType TransactionType = 0x01

	// ContractCallType is a smart contract call
	ContractCallType TransactionType = 0x02

	// ContractCreationType creates a new smart contract
	ContractCreationType TransactionType = 0x03

	// StakeType is a validator stake transaction
	StakeType TransactionType = 0x04

	// UnstakeType is a validator unstake transaction
	UnstakeType TransactionType = 0x05
)

// IsValid reports whether the transaction type is a known valid value.
func (t TransactionType) IsValid() bool {
	switch t {
	case TransferType, ContractCallType, ContractCreationType, StakeType, UnstakeType:
		return true
	default:
		return false
	}
}

// QuantumTransaction represents a native quantum transaction with Dilithium3 signature
type QuantumTransaction struct {
	// Basic fields
	Type    TransactionType // Transaction type (transfer, contract call, stake, etc.)
	Nonce   uint64          // Sender's transaction counter
	ChainID uint64          // Chain identifier for replay protection

	// Transfer fields
	From  Address  // Sender address (derived from signature)
	To    Address  // Recipient address (nil for contract creation)
	Value *big.Int // Amount in smallest unit (audit-fix H-1: supports full 256-bit range)

	// Contract fields
	Data     []byte // Contract call data or creation bytecode
	GasLimit uint64 // Maximum gas to use
	// R40-M10 FIX: Changed GasPrice from uint64 to *big.Int to match the
	// encoding layer (encoding/transaction.go) which serializes GasPrice as
	// big-endian bytes via EncodeBytesField. Using uint64 here caused a type
	// mismatch: the encoding layer expected *big.Int methods (.Bytes(), .Sign())
	// while this struct stored a plain integer.
	GasPrice *big.Int // Gas price per unit

	// Quantum signature (replaces ECDSA V/R/S)
	Signature []byte // Dilithium3 signature (3293 bytes)
	PublicKey []byte // Sender's Dilithium3 public key (1952 bytes)

	// H-02 (R8 2026-07-19 FIX): Replace sync.Once with mutex+flag to make
	// hash cache reset thread-safe. The previous sync.Once pattern had a
	// data race: Sign() reassigned `tx.hashOnce = sync.Once{}` without
	// holding any lock, while a concurrent Hash() was reading tx.hashOnce
	// to call Do(). Replacing a struct field while another goroutine reads
	// it is a data race (flagged by `go test -race`). The mutex serializes
	// all cache reads (Hash) and writes (Sign reset) so the cache is
	// consistent. Transactions are expected to be hashed frequently and
	// re-signed rarely, so the read-mostly pattern is preserved via
	// double-checked locking (RLock for reads, Lock only for first compute
	// and for Sign reset).
	hashMu  sync.RWMutex
	hash    Hash
	hashSet bool
	hashErr error // R46-H-H1 FIX: track serialization errors so Hash() can surface them
}

// InvalidateHashCache clears the cached hash so the next Hash() call
// recomputes from the current fields.
//
// H-02 / H-03 (R9 2026-07-19) FIX — R8 partial closure completed:
// R8 only reset the cache inside Sign() (under hashMu.Lock). R9 found that
// other mutation paths (DeserializeQuantumTransaction mutating a re-used
// tx, future Setters, or any code that mutates Value/To/From after Hash()
// has been cached) would leave a stale cached hash visible to concurrent
// readers — a correctness bug, not just a race.
//
// This helper centralizes the reset logic so all future mutation entry
// points use the same mutex-guarded, three-field atomic reset. Callers
// MUST NOT hold hashMu when invoking this method — use
// invalidateHashCacheLocked() instead if the lock is already held.
func (tx *QuantumTransaction) InvalidateHashCache() {
	tx.hashMu.Lock()
	tx.invalidateHashCacheLocked()
	tx.hashMu.Unlock()
}

// invalidateHashCacheLocked performs the actual cache reset without
// acquiring hashMu. Caller MUST hold tx.hashMu (write lock).
//
// H-03 (R9 2026-07-19) FIX: This is the true single source of truth for
// the three-field atomic reset. Sign() and any future code that already
// holds the write lock must call this instead of duplicating the reset
// inline — preventing the "constructor X forgot to reset" class of bug
// flagged in R9 H-03.
func (tx *QuantumTransaction) invalidateHashCacheLocked() {
	tx.hash = Hash{}
	tx.hashSet = false
	tx.hashErr = nil
}

// NewQuantumTransfer creates a new transfer transaction
// R58-N8 [MEDIUM] FIX: validate chainID > 0 to prevent transactions that will
// always fail verification (Verify() rejects ChainID == 0). Without this, a
// transaction created with chainID = 0 silently fails at submission with no
// actionable error message.
func NewQuantumTransfer(
	nonce uint64,
	chainID uint64,
	to Address,
	value *big.Int,
) (*QuantumTransaction, error) {
	if chainID == 0 {
		return nil, ErrInvalidChainID
	}
	// H-04 (R8 2026-07-19 FIX) + R9-C03 (2026-07-19): reject negative AND
	// >2^256-1 values via centralized validator.
	if err := validateBigInt256(value, ErrNegativeValue); err != nil {
		return nil, err
	}
	return &QuantumTransaction{
		Type:     TransferType,
		Nonce:    nonce,
		ChainID:  chainID,
		To:       to,
		Value:    value,
		GasLimit: 21000,         // Standard gas for simple transfer
		GasPrice: big.NewInt(1), // R40-M10 FIX: base gas price as *big.Int
		Data:     nil,
	}, nil
}

// NewQuantumContractCall creates a new contract call transaction
// R58-N8 [MEDIUM] FIX: validate chainID > 0 to prevent transactions that will
// always fail verification (Verify() rejects ChainID == 0).
func NewQuantumContractCall(
	nonce uint64,
	chainID uint64,
	to Address,
	value *big.Int,
	data []byte,
	gasLimit uint64,
	gasPrice *big.Int,
) (*QuantumTransaction, error) {
	if chainID == 0 {
		return nil, ErrInvalidChainID
	}
	// H-04 (R8 2026-07-19 FIX) + R9-C03 (2026-07-19): centralized validator.
	if err := validateBigInt256(value, ErrNegativeValue); err != nil {
		return nil, err
	}
	if err := validateBigInt256(gasPrice, ErrNegativeGasPrice); err != nil {
		return nil, err
	}
	if gasLimit > MaxGasLimit {
		return nil, ErrGasLimitTooHigh
	}
	return &QuantumTransaction{
		Type:     ContractCallType,
		Nonce:    nonce,
		ChainID:  chainID,
		To:       to,
		Value:    value,
		Data:     data,
		GasLimit: gasLimit,
		GasPrice: gasPrice,
	}, nil
}

// NewQuantumContractCreation creates a new contract creation transaction
// R58-N8 [MEDIUM] FIX: validate chainID > 0 to prevent transactions that will
// always fail verification (Verify() rejects ChainID == 0).
func NewQuantumContractCreation(
	nonce uint64,
	chainID uint64,
	value *big.Int,
	bytecode []byte,
	gasLimit uint64,
	gasPrice *big.Int,
) (*QuantumTransaction, error) {
	if chainID == 0 {
		return nil, ErrInvalidChainID
	}
	// H-04 (R8 2026-07-19 FIX) + R9-C03 (2026-07-19): centralized validator.
	if err := validateBigInt256(value, ErrNegativeValue); err != nil {
		return nil, err
	}
	if err := validateBigInt256(gasPrice, ErrNegativeGasPrice); err != nil {
		return nil, err
	}
	if gasLimit > MaxGasLimit {
		return nil, ErrGasLimitTooHigh
	}
	return &QuantumTransaction{
		Type:     ContractCreationType,
		Nonce:    nonce,
		ChainID:  chainID,
		To:       Address{}, // Empty for contract creation
		Value:    value,
		Data:     bytecode,
		GasLimit: gasLimit,
		GasPrice: gasPrice,
	}, nil
}

// NewQuantumStake creates a new staking transaction.
//
// R9-C02 (2026-07-19) FIX — R8-H04 partial closure completed:
// R8 only added validation to NewQuantumTransfer/Call/Creation; NewQuantumStake
// was missed. A caller could construct a stake with chainID=0 (would silently
// fail Verify() at submission) or a NEGATIVE amount. Combined with R9-C06
// (big.Int.Bytes() drops the sign bit on serialization), a negative stake
// amount could be serialized → deserialized as a huge positive number,
// effectively minting stake weight out of thin air. This fix returns
// (*QuantumTransaction, error) and validates all invariants up-front.
//
// R9-C03 (2026-07-19): amount must fit in 256 bits to prevent serialization
// truncation. The 2^256-1 cap matches Ethereum's U256 MAX and is enforced
// centrally via validateBigInt256.
func NewQuantumStake(
	nonce uint64,
	chainID uint64,
	validator Address,
	amount *big.Int,
	commission uint32,
) (*QuantumTransaction, error) {
	if chainID == 0 {
		return nil, ErrInvalidChainID
	}
	if err := validateBigInt256(amount, ErrNegativeValue); err != nil {
		return nil, err
	}

	// Encode commission into data
	data := make([]byte, 4)
	data[0] = byte(commission >> 24)
	data[1] = byte(commission >> 16)
	data[2] = byte(commission >> 8)
	data[3] = byte(commission)

	return &QuantumTransaction{
		Type:     StakeType,
		Nonce:    nonce,
		ChainID:  chainID,
		To:       validator,
		Value:    amount,
		Data:     data,
		GasLimit: 100000,        // Stake gas limit
		GasPrice: big.NewInt(1), // R40-M10 FIX: base gas price as *big.Int
	}, nil
}

// Sign signs the transaction using a Dilithium3 private key
func (tx *QuantumTransaction) Sign(signer QuantumSigner) error {
	// Validate transaction data size
	if len(tx.Data) > MaxTransactionDataSize {
		return ErrTransactionTooLarge
	}

	// M-08 FIX (R8 2026-07-19): Compute all signing artifacts into LOCAL
	// variables first, and only commit them to `tx` after every step
	// succeeded. Previously Sign() wrote PublicKey/From to `tx` BEFORE
	// computing the message hash and calling signer.Sign(), so any failure
	// on those paths left `tx` in a half-signed state:
	//   - tx.PublicKey was set (1952 bytes)
	//   - tx.From was set
	//   - tx.Signature was nil (or a STALE signature from a previous Sign)
	//   - tx.hash cache was NOT reset
	//
	// This broke the "all-or-nothing" atomicity of Sign: a caller that
	// ignored the returned error and re-used `tx` (e.g. logged it, retried
	// signing, or serialized it for transmission) could end up with a
	// malformed transaction where From/PublicKey didn't match Signature.
	// In the worst case, an existing Signature from a previous successful
	// Sign would still verify against the NEW PublicKey (if the new signer
	// happened to share the same key bytes), causing the network to accept
	// a transaction whose From didn't actually correspond to the signer
	// that produced the signature.
	//
	// Compute pubKey/from/message/signature into locals; commit at the end.
	pubKey := signer.PublicKeyBytes()
	// H-01 (R8 2026-07-19 FIX): use error-returning variant so that an
	// invalid signer.PublicKeyBytes() (e.g. a malformed stub key from a
	// broken signer implementation) is rejected at signing time rather
	// than silently producing a transaction with From = zero Address.
	// Such a transaction would later be accepted by the network with an
	// unverifiable sender, opening the door to spoofing attacks.
	from, err := AddressFromPublicKeyE(pubKey)
	if err != nil {
		return fmt.Errorf("failed to derive sender address: %w", err)
	}

	// Build a transient view of the transaction with the new pubKey/from
	// for hash computation, WITHOUT mutating `tx`. The hash is over the
	// post-Sign fields (From/PublicKey/Signature-absent), so we need to
	// compute it with the NEW pubKey/from. We avoid a full deep copy by
	// temporarily swapping fields under the hashMu write lock.
	//
	// L-05 (R8 2026-07-19) NOTE: Currently HashForSigning() constructs a
	// tempTx that explicitly excludes From and PublicKey, so the swap has
	// no effect on the computed hash. We retain the swap as defensive
	// coding: if HashForSigning() is ever changed to include From/PublicKey
	// in its tempTx (e.g., to bind the sender into the signature), this
	// code path will already be correct. The swap is mutex-protected and
	// cheap relative to the Dilithium3 sign operation that follows.
	tx.hashMu.Lock()
	prevPubKey := tx.PublicKey
	prevFrom := tx.From
	tx.PublicKey = pubKey
	tx.From = from
	message := tx.HashForSigning()
	// Restore tx to its prior state — we haven't committed the Sign yet.
	// If message computation fails, the caller's `tx` is unchanged.
	tx.PublicKey = prevPubKey
	tx.From = prevFrom
	tx.hashMu.Unlock()

	// audit-fix M-QTX-1: HashForSigning returns nil on serialization failure.
	// Signing a nil message would produce a valid-looking but meaningless signature.
	if message == nil {
		return fmt.Errorf("failed to compute signing hash: serialization error")
	}

	// Sign using Dilithium3
	signature, err := signer.Sign(message)
	if err != nil {
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	// FIX: all signing artifacts computed successfully — commit
	// atomically. The hashMu write lock also serializes the hash cache
	// reset, so concurrent Hash() callers either see the old cached hash
	// (pre-commit) or recompute from the new fields (post-commit).
	tx.hashMu.Lock()
	tx.PublicKey = pubKey
	tx.From = from
	tx.Signature = signature
	// H-02 (R8 2026-07-19 FIX): Reset hash cache under write lock to
	// prevent data race with concurrent Hash() callers. The previous code
	// reassigned `tx.hashOnce = sync.Once{}` without any lock, racing with
	// concurrent Hash() which read tx.hashOnce. Serialize() includes the
	// Signature field, so the cached hash is now stale and must be
	// recomputed on the next Hash() call.
	//
	// H-03 (R9 2026-07-19) FIX: Use the centralized invalidateHashCacheLocked
	// helper (the no-lock variant of InvalidateHashCache). Sign() already
	// holds hashMu.Lock() — calling InvalidateHashCache() here would
	// deadlock. The previous code duplicated the three-field reset inline,
	// which is the "constructor X forgot to reset" anti-pattern that R9
	// H-03 flagged. Centralizing in a single helper eliminates the
	// duplication risk: any future field added to the cache state needs
	// to be reset in exactly one place.
	tx.invalidateHashCacheLocked()
	tx.hashMu.Unlock()
	return nil
}

// Verify verifies the transaction's signature
func (tx *QuantumTransaction) Verify() bool {
	// C-01 (R8 2026-07-19 FIX): Constant-time verification path.
	//
	// PREVIOUS IMPLEMENTATION had multiple early returns (ChainID==0,
	// signature size, public key size, value/gasprice negative, gaslimit
	// oversized, address mismatch, panic, nil message). An attacker
	// measuring response time could fingerprint which validation branch
	// failed — even without learning the signature itself. Distinguishing
	// "wrong size" from "wrong signature" leaks which field the node
	// rejected, a node-version fingerprint usable for targeted attacks.
	//
	// FIX: Collect each check result in a flag, perform all checks (with
	// dummy work to keep CPU time uniform when fields are well-formed),
	// then AND-combine at the end. Early-return is gone, so every
	// rejection takes the same code path through the function.
	//
	// Even though remote timing attacks are typically masked by network
	// jitter, this is defense-in-depth: a future side-channel (cache
	// timing, power analysis on validator HSM, co-tenant cloud VM) could
	// turn this into a real fingerprint. Constant-time here is cheap.
	//
	// NOTE: We log all failure reasons (single combined log entry) so
	// operators still get diagnostic visibility without leaking per-branch
	// timing to attackers.

	// Accumulate validity. Start true; any failed check clears it.
	// All comparisons use constant-time primitives so a compiler cannot
	// short-circuit on the secret result.
	// subtle.ConstantTimeEq/ConstantTimeCompare return int (0 or 1).
	valid := 1 // 1 = valid, 0 = invalid

	// --- Field-level checks (constant-time) ---

	// ChainID == 0 is invalid. ConstantTimeEq returns 1 if equal.
	chainIDZero := subtle.ConstantTimeEq(int32(tx.ChainID), 0) // 1 if zero
	valid &= chainIDZero ^ 1                                   // flip: 1 if non-zero (valid)

	// Signature size check (constant-time length comparison).
	sigSizeOK := subtle.ConstantTimeEq(int32(len(tx.Signature)), int32(QuantumSignatureSize))
	valid &= sigSizeOK

	// Public key size check (constant-time length comparison).
	pubKeySizeOK := subtle.ConstantTimeEq(int32(len(tx.PublicKey)), int32(QuantumPublicKeySize))
	valid &= pubKeySizeOK

	// R37-P0-03 FIX (2026-07-30): Reject all-zero public keys. With t1=0 the
	// Dilithium verification equation degenerates to w' = A·z and
	// mode3.Verify accepts keyless forged signatures (z=0, h=0) for ANY
	// message — empirically verified in the R37 audit. ConstantTimeCompare
	// returns 0 on length mismatch, which folds into the size check above.
	var zeroPubKey [QuantumPublicKeySize]byte
	pubKeyAllZero := subtle.ConstantTimeCompare(tx.PublicKey, zeroPubKey[:]) // 1 if all-zero
	valid &= pubKeyAllZero ^ 1                                               // valid=1 if NOT all-zero

	// H-04 (R8 2026-07-19 FIX): Reject negative Value/GasPrice and oversized
	// GasLimit. Use constant-time sign check.
	//
	// CRYPTO-R10-N06 (2026-07-19) FIX: Previously these were `if tx.Value != nil`
	// branches that skipped the Sign() call entirely when Value/GasPrice was
	// nil — creating a measurable timing difference between "Value is nil" and
	// "Value is non-nil". For uniform timing, we always execute the sign check
	// against a non-nil zero big.Int when the field is nil. Sign() on a zero
	// big.Int returns 0 (not negative), so the check always passes; the work
	// performed is identical to the non-nil case.
	valueForCheck := tx.Value
	if valueForCheck == nil {
		valueForCheck = big.NewInt(0)
	}
	negValue := subtle.ConstantTimeEq(int32(valueForCheck.Sign()), -1)
	valid &= negValue ^ 1 // valid=1 if Value.Sign() != -1

	gasPriceForCheck := tx.GasPrice
	if gasPriceForCheck == nil {
		gasPriceForCheck = big.NewInt(0)
	}
	negGasPrice := subtle.ConstantTimeEq(int32(gasPriceForCheck.Sign()), -1)
	valid &= negGasPrice ^ 1
	// GasLimit > MaxGasLimit — constant-time comparison.
	// ConstantTimeLessOrEq takes int args and returns 1 if a <= b.
	gasLimitOK := subtle.ConstantTimeLessOrEq(int(tx.GasLimit), int(MaxGasLimit))
	valid &= gasLimitOK

	// --- Address check (constant-time) ---
	// Compute expected sender from public key, then constant-time compare.
	// Even when PublicKey is malformed (size check above failed), we still
	// call Sender() so timing is uniform.
	expectedFrom := tx.Sender()
	// Address is a [20]byte. Use ConstantTimeCompare on the bytes.
	addrMatch := subtle.ConstantTimeCompare(expectedFrom[:], tx.From[:])
	valid &= addrMatch

	// --- Public key unpack + signature verify (already wrapped in recover) ---
	// R40-B-C2 FIX: panic recovery. If pubKey unpack fails (malformed),
	// we still run a dummy signature verify with an empty pubKey so the
	// total CPU time is close to the success path.
	var pubKey mode3.PublicKey
	var panicErr error
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicErr = fmt.Errorf("public key unpack panic: %v", r)
			}
		}()
		pubKey.Unpack((*[mode3.PublicKeySize]byte)(tx.PublicKey))
	}()
	if panicErr != nil {
		logging.Global().Error("QuantumTransaction.Verify() public key unpack panic", map[string]any{"error": panicErr.Error()})
		// Constant-time: clear valid without short-circuit.
		valid = 0
	}

	message := tx.HashForSigning()
	// audit-fix M-QTX-1: HashForSigning returns nil on serialization failure.
	// Use a dummy non-nil message if nil to keep the verify call uniform.
	if message == nil {
		logging.Global().Error("QuantumTransaction.Verify() HashForSigning returned nil", map[string]any{"reason": "serialization failed"})
		// Replace with zero-length message so signature verify still runs.
		// Dilithium3.Verify with empty message + invalid signature = deterministic failure.
		message = []byte{}
		valid = 0
	}

	var ok bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicErr = fmt.Errorf("signature verify panic: %v", r)
				ok = false
			}
		}()
		ok = mode3.Verify(&pubKey, message, tx.Signature)
	}()
	if panicErr != nil {
		logging.Global().Error("QuantumTransaction.Verify() signature verify panic", map[string]any{"error": panicErr.Error()})
		valid = 0
	}

	// Final result: valid AND signature verification OK.
	// Constant-time AND.
	// CRYPTO- (2026-07-20) FIX: Previously used `if ok { result = 1 }`
	// which is a secret-dependent branch (ok encodes whether the signature
	// verified, which is secret data). Even though the surrounding code is
	// constant-time, this branch leaks a timing fingerprint distinguishing
	// "signature verified" from "signature rejected". Convert ok to int
	// via subtle.ConstantTimeEq on the bool's byte representation (Go
	// stores bool as 0x00/0x01) — no branch, no crypto package dependency.
	// CR-06 FIX (audit 2026-08-14): Compile-time assertion that a Go bool
	// occupies exactly one byte — the unsafe reinterpretation below reads
	// &ok as *byte. If a future Go runtime ever changed the representation
	// of bool, this assignment fails to compile instead of silently
	// reading wrong/garbage bytes.
	var _ [1]struct{} = [unsafe.Sizeof(ok)]struct{}{}
	result := int(subtle.ConstantTimeEq(int32(*(*byte)(unsafe.Pointer(&ok))), 1))
	finalValid := valid & result
	return finalValid == 1
}

// Sender returns the sender address derived from the public key.
//
// CRYPTO-R10-N01 (2026-07-19) FIX: Make Sender() constant-time to
// preserve the constant-time property of Verify(). Previously, Sender()
// had an early return on len(PublicKey)==0 returning Address{} — this
// leaked a timing fingerprint distinguishing "empty pubkey" from
// "non-empty pubkey" and from "wrong-size pubkey". Since Verify()
// calls Sender() unconditionally (to keep its own timing uniform), the
// leak propagated up to Verify()'s observable timing.
//
// Fix: always run the same amount of work regardless of PublicKey
// length. We copy PublicKey into a fixed-size 1952-byte buffer (zero-
// padded if shorter/empty), always compute SHA3-256 over the full
// buffer, then use constant-time select to zero out the result if the
// input length was not exactly QuantumPublicKeySize. The resulting
// timing is dominated by the fixed-cost SHA3-256 over 1952 bytes,
// which is identical for all inputs.
func (tx *QuantumTransaction) Sender() Address {
	const pkSize = QuantumPublicKeySize
	var buf [pkSize]byte
	// Always copy up to pkSize bytes (no-op if PublicKey is empty/short).
	// The time variance of copy() over <1952 bytes is negligible vs the
	// subsequent SHA3-256 over the full 1952-byte buffer.
	copy(buf[:], tx.PublicKey)
	// Always compute SHA3-256 over the full pkSize buffer.
	hash := sha3.Sum256(buf[:])
	addr := BytesToAddress(hash[HashLength-AddressLength:])
	// Constant-time zero-out when PublicKey length != pkSize.
	// subtle.ConstantTimeEq returns 1 if equal, 0 otherwise.
	lenMatch := subtle.ConstantTimeEq(int32(len(tx.PublicKey)), int32(pkSize))
	var zero Address
	// subtle.ConstantTimeSelect(v, x, y) returns x if v==1, else y.
	// We want: addr[i] if lenMatch==1, else 0.
	for i := 0; i < AddressLength; i++ {
		addr[i] = byte(subtle.ConstantTimeSelect(lenMatch, int(addr[i]), int(zero[i])))
	}
	return addr
}

// IsSigned returns true if transaction is properly signed
//
// CRYPTO- (2026-07-20) FIX: Previously used short-circuit `&&`,
// which is inconsistent with the constant-time property enforced by
// Verify() and Sender(). `IsSigned()` itself is not secret-dependent
// (Signature/PublicKey lengths are public data), but the project's
// coding convention (see crypto/generate.go boolToInt32 + R63-CR-1
// comments) requires all AND/OR composition of equality checks to
// avoid short-circuit evaluation so future refactors cannot accidentally
// introduce timing leaks. We use subtle.ConstantTimeEq for both length
// comparisons and a constant-time AND (a*b for 0/1 values).
func (tx *QuantumTransaction) IsSigned() bool {
	sigMatch := subtle.ConstantTimeEq(int32(len(tx.Signature)), int32(QuantumSignatureSize))
	pubMatch := subtle.ConstantTimeEq(int32(len(tx.PublicKey)), int32(QuantumPublicKeySize))
	// Constant-time AND: both must be 1.
	return (sigMatch & pubMatch) == 1
}

// Hash returns the transaction hash.
// H-02 (R8 2026-07-19 FIX): Thread-safe via RWMutex with double-checked
// locking. RLock allows concurrent reads of the cached hash; only the first
// caller (when hashSet is false) acquires the write lock to compute the
// hash. This replaces the previous sync.Once pattern which had a data race
// when Sign() reassigned tx.hashOnce without holding any lock.
// R46-H-H1 FIX: track serialization errors to prevent silent zero hash return.
func (tx *QuantumTransaction) Hash() Hash {
	// Fast path: read cached hash under RLock.
	tx.hashMu.RLock()
	if tx.hashSet {
		h := tx.hash
		tx.hashMu.RUnlock()
		return h
	}
	// If a previous serialization failed, return zero hash without retrying
	// (serialization errors are deterministic for a given tx state).
	if tx.hashErr != nil {
		tx.hashMu.RUnlock()
		return Hash{}
	}
	tx.hashMu.RUnlock()

	// Slow path: acquire write lock and double-check (another goroutine may
	// have computed the hash between our RUnlock and Lock).
	tx.hashMu.Lock()
	defer tx.hashMu.Unlock()
	if tx.hashSet {
		return tx.hash
	}
	if tx.hashErr != nil {
		return Hash{}
	}
	data, err := tx.Serialize()
	if err != nil {
		tx.hashErr = err
		logging.Error("QuantumTransaction.Hash() serialize failed, returning zero hash", map[string]any{"error": err.Error()})
		return Hash{}
	}
	tx.hash = sha3.Sum256(data)
	tx.hashSet = true
	return tx.hash
}

// quantumTxDomainSeparationTag is the domain separation prefix mixed into
// every HashForSigning digest. It prevents cross-protocol signature reuse:
// without a domain tag, an attacker could theoretically take a valid
// QuantumTransaction signature and replay it as a signature for a different
// message type (e.g., an attestation, a vote, or a bridge operation) that
// happens to serialize to the same byte pattern.
//
// CRYPTO- (2026-07-20) FIX: Previously HashForSigning hashed the
// raw serialized transaction with no domain separation. Now we prefix the
// serialization with a fixed tag so the resulting digest is unambiguously
// bound to "a QuantumTransaction signature", distinct from any other
// signing domain in the protocol.
//
// The tag is ASCII bytes wrapped in a length prefix (4-byte big-endian
// length) to follow the construct:
//
//	digest = SHA3-256( len(tag) || tag || tx_payload )
//
// This matches the standard EIP-712 / RFC 8709 domain-separation pattern
// and avoids length-extension ambiguity across variable-length prefixes.
const quantumTxDomainSeparationTag = "QUANTAUREUM_QUANTUM_TX_V1"

// HashForSigning returns the hash that should be signed
// This excludes the signature fields
func (tx *QuantumTransaction) HashForSigning() []byte {
	// Create a copy without signature and sender-derived fields.
	// From is excluded because it is derived from PublicKey after signing,
	// so it may be zero at signing time.
	tempTx := &QuantumTransaction{
		Type:     tx.Type,
		Nonce:    tx.Nonce,
		ChainID:  tx.ChainID,
		To:       tx.To,
		Value:    tx.Value,
		Data:     tx.Data,
		GasLimit: tx.GasLimit,
		GasPrice: tx.GasPrice,
		// From, Signature, and PublicKey excluded
	}

	// Serialize and hash
	data, err := tempTx.Serialize()
	if err != nil {
		return nil
	}

	// CRYPTO-FIX: Mix a domain separation tag into the digest to
	// prevent cross-protocol signature reuse. The tag is length-prefixed
	// (4-byte big-endian) to avoid ambiguity if the tag itself is ever
	// changed to a variable-length value.
	tag := []byte(quantumTxDomainSeparationTag)
	tagLen := uint32(len(tag))
	lenBytes := []byte{
		byte(tagLen >> 24),
		byte(tagLen >> 16),
		byte(tagLen >> 8),
		byte(tagLen),
	}

	// digest = SHA3-256( len(tag) || tag || tx_payload )
	buffer := make([]byte, 0, 4+len(tag)+len(data))
	buffer = append(buffer, lenBytes...)
	buffer = append(buffer, tag...)
	buffer = append(buffer, data...)

	hash := sha3.Sum256(buffer)
	return hash[:]
}

// Serialize converts the transaction to a byte array
// Uses custom binary format (not RLP!)
func (tx *QuantumTransaction) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write type (1 byte)
	buf.WriteByte(byte(tx.Type))

	// Write nonce (8 bytes, big-endian)
	writeUint64(buf, tx.Nonce)

	// Write chain ID (8 bytes, big-endian)
	writeUint64(buf, tx.ChainID)

	// Write sender address (20 bytes)
	buf.Write(tx.From[:])

	// Write recipient address (20 bytes)
	buf.Write(tx.To[:])

	// Write value as length-prefixed big-endian bytes (audit-fix H-1)
	//
	// R9-C06 (2026-07-19) FIX — sign-bit preservation:
	// big.Int.Bytes() returns the absolute-value bytes (unsigned big-endian),
	// dropping the sign bit. A negative *big.Int would round-trip through
	// Bytes()/SetBytes() as a POSITIVE value, silently minting value.
	// Although constructors and Validate() reject negatives, defense-in-depth
	// requires Serialize() to also refuse negative values at the wire
	// boundary — so a future code path that bypasses construction-time
	// validation (e.g. a deserialized-then-mutated tx) cannot sneak a
	// negative value past the serializer.
	//
	// R9-C03 (2026-07-19) FIX — 256-bit upper bound:
	// Reject values whose BitLen() exceeds 256 to prevent serialization
	// truncation that would cause consensus divergence.
	valueBytes := []byte{}
	if tx.Value != nil {
		if tx.Value.Sign() < 0 {
			return nil, ErrNegativeValue
		}
		if tx.Value.BitLen() > MaxUInt256Bits {
			return nil, ErrValueTooLarge
		}
		valueBytes = tx.Value.Bytes()
	}
	writeUint16(buf, uint16(len(valueBytes)))
	buf.Write(valueBytes)

	// Write data length (4 bytes) + data
	writeUint32(buf, uint32(len(tx.Data)))
	buf.Write(tx.Data)

	// Write gas limit (8 bytes)
	writeUint64(buf, tx.GasLimit)

	// R40-M10 FIX: Write gas price as length-prefixed big-endian bytes (like Value)
	// to match the encoding layer's *big.Int representation. Previously written as
	// a fixed 8-byte uint64 which truncated values exceeding 2^64.
	//
	// R9-C06/C03 (2026-07-19) FIX: Same sign-bit + 256-bit bound as Value above.
	gasPriceBytes := []byte{}
	if tx.GasPrice != nil {
		if tx.GasPrice.Sign() < 0 {
			return nil, ErrNegativeGasPrice
		}
		if tx.GasPrice.BitLen() > MaxUInt256Bits {
			return nil, ErrValueTooLarge
		}
		gasPriceBytes = tx.GasPrice.Bytes()
	}
	writeUint16(buf, uint16(len(gasPriceBytes)))
	buf.Write(gasPriceBytes)

	// Write public key (2 bytes length + 1952 bytes)
	writeUint16(buf, uint16(len(tx.PublicKey)))
	buf.Write(tx.PublicKey)

	// Write signature (2 bytes length + 3293 bytes)
	writeUint16(buf, uint16(len(tx.Signature)))
	buf.Write(tx.Signature)

	return buf.Bytes(), nil
}

// Deserialize reads a transaction from a byte array
func DeserializeQuantumTransaction(data []byte) (*QuantumTransaction, error) {
	if len(data) < 50 { // Minimum size check
		return nil, errors.New("transaction data too short")
	}

	reader := bytes.NewReader(data)
	tx := &QuantumTransaction{}

	// Read type
	typ, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	tx.Type = TransactionType(typ)
	if !tx.Type.IsValid() {
		return nil, fmt.Errorf("invalid transaction type: 0x%02x", typ)
	}

	// Read nonce
	tx.Nonce, err = readUint64(reader)
	if err != nil {
		return nil, err
	}

	// Read chain ID
	tx.ChainID, err = readUint64(reader)
	if err != nil {
		return nil, err
	}

	// Read from address
	// audit-fix R2-M2: use io.ReadFull to prevent short reads
	if _, err := io.ReadFull(reader, tx.From[:]); err != nil {
		return nil, err
	}

	// Read to address
	if _, err := io.ReadFull(reader, tx.To[:]); err != nil {
		return nil, err
	}

	// Read value (length-prefixed big-endian bytes, audit-fix H-1)
	//
	// R9-C03/C06 (2026-07-19) FIX: Cap at 32 bytes (256 bits) and verify
	// post-SetBytes that the value is non-negative. SetBytes never produces
	// a negative *big.Int (it interprets bytes as unsigned), but a future
	// caller could mutate tx.Value post-deserialization — Verify() re-checks
	// to cover that case. The 32-byte cap prevents a malicious payload from
	// advertising a huge length that would allocate gigabytes of memory.
	valueLen, err := readUint16(reader)
	if err != nil {
		return nil, err
	}
	if valueLen > 32 {
		return nil, ErrValueTooLarge
	}
	valueBuf := make([]byte, valueLen)
	if valueLen > 0 {
		if _, err := io.ReadFull(reader, valueBuf); err != nil {
			return nil, err
		}
	}
	tx.Value = new(big.Int).SetBytes(valueBuf)
	if tx.Value.BitLen() > MaxUInt256Bits {
		return nil, ErrValueTooLarge
	}

	// Read data
	dataLen, err := readUint32(reader)
	if err != nil {
		return nil, err
	}
	if dataLen > MaxTransactionDataSize {
		return nil, ErrTransactionTooLarge
	}
	tx.Data = make([]byte, dataLen)
	if _, err := io.ReadFull(reader, tx.Data); err != nil {
		return nil, err
	}

	// Read gas limit
	tx.GasLimit, err = readUint64(reader)
	if err != nil {
		return nil, err
	}

	// R40-M10 FIX: Read gas price as length-prefixed big-endian bytes (like Value)
	// to match the updated *big.Int representation.
	//
	// R9-C03/C06 (2026-07-19) FIX: Same 32-byte cap and BitLen check as Value.
	gasPriceLen, err := readUint16(reader)
	if err != nil {
		return nil, err
	}
	if gasPriceLen > 32 {
		return nil, ErrValueTooLarge
	}
	gasPriceBuf := make([]byte, gasPriceLen)
	if gasPriceLen > 0 {
		if _, err := io.ReadFull(reader, gasPriceBuf); err != nil {
			return nil, err
		}
	}
	tx.GasPrice = new(big.Int).SetBytes(gasPriceBuf)
	if tx.GasPrice.BitLen() > MaxUInt256Bits {
		return nil, ErrValueTooLarge
	}

	// H-04 (R8 2026-07-19 FIX): Reject negative Value/GasPrice and oversized
	// GasLimit immediately after deserialization. big.Int is signed and
	// SetBytes itself never produces negatives, but a malicious or buggy
	// upstream encoder could synthesize a negative big.Int via other paths
	// (e.g. RLP decode → big.Int). Checking here is the cheapest defense.
	// The same invariants are re-checked in Verify() to cover round-trips
	// through in-memory mutation.
	if tx.Value != nil && tx.Value.Sign() < 0 {
		return nil, ErrNegativeValue
	}
	if tx.GasPrice != nil && tx.GasPrice.Sign() < 0 {
		return nil, ErrNegativeGasPrice
	}
	if tx.GasLimit > MaxGasLimit {
		return nil, ErrGasLimitTooHigh
	}

	// audit-fix R2-L3: use readUint16 helper (has io.ReadFull protection)
	pubKeyLen, err := readUint16(reader)
	if err != nil {
		return nil, err
	}
	if int(pubKeyLen) != QuantumPublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	tx.PublicKey = make([]byte, pubKeyLen)
	// audit-fix R2-M2: use io.ReadFull to prevent short reads
	if _, err := io.ReadFull(reader, tx.PublicKey); err != nil {
		return nil, err
	}

	// Derive sender address from public key.
	// H-01 (R8 2026-07-19 FIX): use error-returning variant so that a
	// deserialized transaction with a malformed PublicKey (wrong size) is
	// rejected at deserialization rather than silently accepted with From =
	// zero Address. Previously, an attacker could submit a transaction
	// with a short/garbage PublicKey that passed deserialization but had
	// an unverifiable sender; now the deserialization fails with an
	// explicit error.
	from, err := AddressFromPublicKeyE(tx.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key in transaction: %w", err)
	}
	tx.From = from

	// audit-fix R2-L3: use readUint16 helper (has io.ReadFull protection)
	sigLen, err := readUint16(reader)
	if err != nil {
		return nil, err
	}
	if int(sigLen) != QuantumSignatureSize {
		return nil, ErrInvalidSignature
	}
	tx.Signature = make([]byte, sigLen)
	// audit-fix R2-M2: use io.ReadFull to prevent short reads
	if _, err := io.ReadFull(reader, tx.Signature); err != nil {
		return nil, err
	}

	return tx, nil
}

// Size returns the serialized size of the transaction
func (tx *QuantumTransaction) Size() int {
	valueLen := 0
	if tx.Value != nil {
		valueLen = len(tx.Value.Bytes())
	}
	// R40-M10 FIX: GasPrice size is now variable (length-prefixed *big.Int)
	gasPriceLen := 0
	if tx.GasPrice != nil {
		gasPriceLen = len(tx.GasPrice.Bytes())
	}
	// Type (1) + Nonce (8) + ChainID (8) + From (20) + To (20)
	// + ValueLen (2) + Value (var) + DataLen (4) + Data (var) + GasLimit (8)
	// + GasPriceLen (2) + GasPrice (var)
	// + PubKeyLen (2) + PubKey (1952) + SigLen (2) + Sig (3293)
	return 1 + 8 + 8 + 20 + 20 + 2 + valueLen + 4 + len(tx.Data) + 8 + 2 + gasPriceLen + 2 + QuantumPublicKeySize + 2 + QuantumSignatureSize
}

// Copy creates a deep copy of the transaction
func (tx *QuantumTransaction) Copy() *QuantumTransaction {
	cpy := &QuantumTransaction{
		Type:     tx.Type,
		Nonce:    tx.Nonce,
		ChainID:  tx.ChainID,
		From:     tx.From,
		To:       tx.To,
		GasLimit: tx.GasLimit,
	}

	// R40-M10 FIX: deep-copy GasPrice as *big.Int (was a plain uint64 copy before)
	if tx.GasPrice != nil {
		cpy.GasPrice = new(big.Int).Set(tx.GasPrice)
	}

	if tx.Value != nil {
		cpy.Value = new(big.Int).Set(tx.Value)
	}

	if tx.Data != nil {
		cpy.Data = make([]byte, len(tx.Data))
		copy(cpy.Data, tx.Data)
	}

	if tx.PublicKey != nil {
		cpy.PublicKey = make([]byte, len(tx.PublicKey))
		copy(cpy.PublicKey, tx.PublicKey)
	}

	if tx.Signature != nil {
		cpy.Signature = make([]byte, len(tx.Signature))
		copy(cpy.Signature, tx.Signature)
	}

	return cpy
}

// MarshalJSON converts transaction to JSON for RPC responses
// H-05 (R8 2026-07-19 FIX): Add publicKey field to RPC response.
// Previously, the JSON output omitted the sender's public key, forcing
// clients to fetch it separately (or assume From was correct without
// verification). The publicKey is required for clients to verify the
// signature independently and to derive the sender address — without it,
// the RPC payload is incomplete and consumers cannot perform
// trustless validation.
func (tx *QuantumTransaction) MarshalJSON() ([]byte, error) {
	valueStr := "0"
	if tx.Value != nil {
		valueStr = tx.Value.String()
	}
	// R40-M10 FIX: GasPrice is now *big.Int, serialize as string like Value
	gasPriceStr := "0"
	if tx.GasPrice != nil {
		gasPriceStr = tx.GasPrice.String()
	}
	// M-04 FIX (R8 2026-07-19): use a dedicated hex encoder instead of
	// fmt.Sprintf("0x%x", ...). Behavior is identical for non-nil byte slices,
	// but encoding/hex is the canonical Go stdlib path and makes the intent
	// explicit. The output for nil/empty slices remains "0x" (preserving
	// backwards compatibility with existing wallet/RPC parsers).
	//
	// value/gasPrice intentionally remain DECIMAL strings (not hex) because
	// the wallet already parses them as decimal *big.Int; switching to hex
	// would break wallet compatibility. nonce/gasLimit remain JSON numbers
	// for the same reason.
	return json.Marshal(map[string]any{
		"type":      tx.Type,
		"nonce":     tx.Nonce,
		"chainId":   tx.ChainID,
		"from":      tx.From.String(),
		"to":        tx.To.String(),
		"value":     valueStr,
		"data":      "0x" + hex.EncodeToString(tx.Data),
		"gasLimit":  tx.GasLimit,
		"gasPrice":  gasPriceStr,
		"hash":      tx.Hash().String(),
		"signature": "0x" + hex.EncodeToString(tx.Signature),
		"publicKey": "0x" + hex.EncodeToString(tx.PublicKey),
	})
}

// EncodeRLP implements io.Writer for compatibility (but we don't use RLP)
func (tx *QuantumTransaction) EncodeRLP(w io.Writer) error {
	// This is a NO-OP for quantum transactions
	// RLP is an Ethereum-specific serialization format
	// Quantum transactions use custom binary format
	return errors.New("RLP encoding not supported for quantum transactions")
}

// Helper functions for serialization

func writeUint64(buf *bytes.Buffer, n uint64) {
	buf.WriteByte(byte(n >> 56))
	buf.WriteByte(byte(n >> 48))
	buf.WriteByte(byte(n >> 40))
	buf.WriteByte(byte(n >> 32))
	buf.WriteByte(byte(n >> 24))
	buf.WriteByte(byte(n >> 16))
	buf.WriteByte(byte(n >> 8))
	buf.WriteByte(byte(n))
}

func writeUint32(buf *bytes.Buffer, n uint32) {
	buf.WriteByte(byte(n >> 24))
	buf.WriteByte(byte(n >> 16))
	buf.WriteByte(byte(n >> 8))
	buf.WriteByte(byte(n))
}

func writeUint16(buf *bytes.Buffer, n uint16) {
	buf.WriteByte(byte(n >> 8))
	buf.WriteByte(byte(n))
}

// audit-fix M-3: use io.ReadFull to prevent short reads
func readUint64(r io.Reader) (uint64, error) {
	b := make([]byte, 8)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, err
	}
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 |
		uint64(b[3])<<32 | uint64(b[4])<<24 | uint64(b[5])<<16 |
		uint64(b[6])<<8 | uint64(b[7]), nil
}

func readUint16(r io.Reader) (uint16, error) {
	b := make([]byte, 2)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, err
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

func readUint32(r io.Reader) (uint32, error) {
	b := make([]byte, 4)
	if _, err := io.ReadFull(r, b); err != nil {
		return 0, err
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}
