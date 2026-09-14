// Quantaureum Go SDK source, version 1.0.0.
// Package types provides core blockchain types for the Quantaureum Go SDK.
package types

import (
	"bytes"
	"io"
	"math/big"

	"github.com/quantaureum/qau/sdks/go-sdk/common"
	"github.com/quantaureum/qau/sdks/go-sdk/utils"
)

// Transaction represents a blockchain transaction.
type Transaction struct {
	Nonce    uint64          // Transaction nonce
	GasPrice *big.Int        // Gas price in wei
	Gas      uint64          // Gas limit
	To       *common.Address // Recipient address (nil for contract creation)
	Value    *big.Int        // Value in wei
	Data     []byte          // Transaction data

	// Signature components
	//
	// AUDIT 2026-07-12 KEYS-11 FIX: Dilithium3 produces a single 3293-byte
	// signature that must be stored as raw bytes. Previously the SDK split it
	// into V/R/S *big.Int halves, but big.Int.SetBytes strips leading zero
	// bytes — reassembling R.Bytes()+S.Bytes() can produce a shorter byte
	// sequence that no longer matches the original signature, causing chain
	// verification to fail or mismatch silently. The Signature field below
	// stores the exact bytes; V/R/S is retained only for backward
	// compatibility with RPC responses that still serialize v/r/s separately.
	Signature []byte // Raw Dilithium3 signature (3293 bytes). Preferred over V/R/S.
	V         *big.Int
	R         *big.Int
	S         *big.Int

	// Cached values
	hash *common.Hash
}

// NewTransaction creates a new unsigned transaction.
func NewTransaction(nonce uint64, to *common.Address, value *big.Int, gas uint64, gasPrice *big.Int, data []byte) *Transaction {
	tx := &Transaction{
		Nonce:    nonce,
		To:       to,
		Value:    value,
		Gas:      gas,
		GasPrice: gasPrice,
		Data:     data,
	}

	// Ensure non-nil big.Int values
	if tx.Value == nil {
		tx.Value = new(big.Int)
	}
	if tx.GasPrice == nil {
		tx.GasPrice = new(big.Int)
	}

	return tx
}

// NewContractCreation creates a new contract creation transaction.
func NewContractCreation(nonce uint64, value *big.Int, gas uint64, gasPrice *big.Int, data []byte) *Transaction {
	return NewTransaction(nonce, nil, value, gas, gasPrice, data)
}

// GetNonce returns the transaction nonce.
func (tx *Transaction) GetNonce() uint64 {
	return tx.Nonce
}

// GetGasPrice returns the gas price.
func (tx *Transaction) GetGasPrice() *big.Int {
	if tx.GasPrice == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(tx.GasPrice)
}

// GetGas returns the gas limit.
func (tx *Transaction) GetGas() uint64 {
	return tx.Gas
}

// GetTo returns the recipient address.
func (tx *Transaction) GetTo() *common.Address {
	return tx.To
}

// GetValue returns the transaction value.
func (tx *Transaction) GetValue() *big.Int {
	if tx.Value == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(tx.Value)
}

// GetData returns the transaction data.
func (tx *Transaction) GetData() []byte {
	return tx.Data
}

// IsSigned returns true if the transaction has been signed.
//
// AUDIT 2026-07-12 KEYS-11 FIX: Also consider the transaction signed when the
// raw Signature bytes are present (the preferred representation for
// Dilithium3). V/R/S is checked for backward compatibility with transactions
// parsed from RPC responses that still serialize v/r/s separately.
func (tx *Transaction) IsSigned() bool {
	return len(tx.Signature) > 0 || (tx.V != nil && tx.R != nil && tx.S != nil)
}

// GetV returns the V component of the signature.
func (tx *Transaction) GetV() *big.Int {
	if tx.V == nil {
		return nil
	}
	return new(big.Int).Set(tx.V)
}

// GetR returns the R component of the signature.
func (tx *Transaction) GetR() *big.Int {
	if tx.R == nil {
		return nil
	}
	return new(big.Int).Set(tx.R)
}

// GetS returns the S component of the signature.
func (tx *Transaction) GetS() *big.Int {
	if tx.S == nil {
		return nil
	}
	return new(big.Int).Set(tx.S)
}

// SetSignature sets the V/R/S signature components.
//
// Deprecated for Dilithium3 signatures: prefer SetRawSignature, which stores
// the exact 3293-byte signature without leading-zero stripping. This method
// is retained for backward compatibility with ECDSA-style callers and with
// transactions parsed from RPC responses that serialize v/r/s separately.
func (tx *Transaction) SetSignature(v, r, s *big.Int) {
	tx.V = v
	tx.R = r
	tx.S = s
	tx.hash = nil // Invalidate cached hash
}

// SetRawSignature stores the raw Dilithium3 signature bytes (3293 bytes).
//
// AUDIT 2026-07-12 KEYS-11 FIX: This is the preferred way to attach a
// Dilithium3 signature to a transaction. Unlike SetSignature, it preserves
// the exact byte sequence — including any leading zero bytes — so chain
// verification receives the identical signature that mode3.SignTo produced.
func (tx *Transaction) SetRawSignature(sig []byte) {
	// Copy to avoid aliasing caller-owned slices.
	tx.Signature = make([]byte, len(sig))
	copy(tx.Signature, sig)
	tx.hash = nil // Invalidate cached hash
}

// GetSignature returns the raw Dilithium3 signature bytes, or nil if the
// transaction was signed via V/R/S only.
func (tx *Transaction) GetSignature() []byte {
	if len(tx.Signature) == 0 {
		return nil
	}
	cpy := make([]byte, len(tx.Signature))
	copy(cpy, tx.Signature)
	return cpy
}

// Copy creates a deep copy of the transaction.
func (tx *Transaction) Copy() *Transaction {
	cpy := &Transaction{
		Nonce: tx.Nonce,
		Gas:   tx.Gas,
	}

	if tx.To != nil {
		to := *tx.To
		cpy.To = &to
	}

	if tx.Value != nil {
		cpy.Value = new(big.Int).Set(tx.Value)
	}

	if tx.GasPrice != nil {
		cpy.GasPrice = new(big.Int).Set(tx.GasPrice)
	}

	if tx.Data != nil {
		cpy.Data = make([]byte, len(tx.Data))
		copy(cpy.Data, tx.Data)
	}

	// AUDIT 2026-07-12 KEYS-11 FIX: Deep-copy the raw Signature bytes so the
	// copy is fully independent of the original (a shallow alias would let
	// callers mutate the signature after copying).
	if tx.Signature != nil {
		cpy.Signature = make([]byte, len(tx.Signature))
		copy(cpy.Signature, tx.Signature)
	}

	if tx.V != nil {
		cpy.V = new(big.Int).Set(tx.V)
	}
	if tx.R != nil {
		cpy.R = new(big.Int).Set(tx.R)
	}
	if tx.S != nil {
		cpy.S = new(big.Int).Set(tx.S)
	}

	return cpy
}

// IsContractCreation returns true if this is a contract creation transaction.
func (tx *Transaction) IsContractCreation() bool {
	return tx.To == nil
}

// Hash returns the transaction hash.
// For unsigned transactions, it returns the hash of the unsigned transaction data.
// For signed transactions, it returns the hash including the signature.
func (tx *Transaction) Hash() common.Hash {
	if tx.hash != nil {
		return *tx.hash
	}

	var rlpData []byte
	if tx.IsSigned() {
		rlpData = tx.RLPEncode()
	} else {
		rlpData = tx.RLPEncodeUnsigned()
	}

	hash := utils.Keccak256Hash(rlpData)
	tx.hash = &hash
	return hash
}

// RLPEncode returns the RLP encoding of the signed transaction.
func (tx *Transaction) RLPEncode() []byte {
	var buf bytes.Buffer
	tx.EncodeRLP(&buf)
	return buf.Bytes()
}

// RLPEncodeUnsigned returns the RLP encoding of the unsigned transaction.
func (tx *Transaction) RLPEncodeUnsigned() []byte {
	var buf bytes.Buffer
	tx.encodeUnsignedRLP(&buf)
	return buf.Bytes()
}

// RLPEncodeForSigning returns the RLP encoding for signing with the given chain ID.
// This implements EIP-155 replay protection.
func (tx *Transaction) RLPEncodeForSigning(chainID *big.Int) []byte {
	var buf bytes.Buffer
	tx.encodeForSigningRLP(&buf, chainID)
	return buf.Bytes()
}

// EncodeRLP implements the rlp.Encoder interface.
//
// AUDIT 2026-07-12 KEYS-11 FIX: When the raw Signature bytes are present
// (the preferred Dilithium3 representation), encode them as a single bytes
// field instead of V/R/S. Encoding V/R/S via big.Int.Bytes() would strip
// leading zero bytes from each half and produce a different byte sequence
// than the original 3293-byte signature. Falls back to V/R/S only when the
// raw Signature is absent (e.g. transactions parsed from legacy RPC
// responses that serialize v/r/s separately).
func (tx *Transaction) EncodeRLP(w io.Writer) error {
	var items [][]byte

	items = append(items, encodeUint64(tx.Nonce))
	items = append(items, encodeBigInt(tx.GasPrice))
	items = append(items, encodeUint64(tx.Gas))
	items = append(items, encodeAddress(tx.To))
	items = append(items, encodeBigInt(tx.Value))
	items = append(items, encodeBytes(tx.Data))

	if len(tx.Signature) > 0 {
		// Single-field raw signature (Dilithium3 native form).
		items = append(items, encodeBytes(tx.Signature))
	} else {
		// Legacy V/R/S fallback (lossy for Dilithium3 — see KEYS-11).
		items = append(items, encodeBigInt(tx.V))
		items = append(items, encodeBigInt(tx.R))
		items = append(items, encodeBigInt(tx.S))
	}

	encoded := encodeList(items)
	_, err := w.Write(encoded)
	return err
}

// encodeUnsignedRLP encodes the unsigned transaction fields.
func (tx *Transaction) encodeUnsignedRLP(w io.Writer) error {
	// Encode as: [nonce, gasPrice, gas, to, value, data]
	var items [][]byte

	items = append(items, encodeUint64(tx.Nonce))
	items = append(items, encodeBigInt(tx.GasPrice))
	items = append(items, encodeUint64(tx.Gas))
	items = append(items, encodeAddress(tx.To))
	items = append(items, encodeBigInt(tx.Value))
	items = append(items, encodeBytes(tx.Data))

	encoded := encodeList(items)
	_, err := w.Write(encoded)
	return err
}

// encodeForSigningRLP encodes the transaction for signing with EIP-155.
func (tx *Transaction) encodeForSigningRLP(w io.Writer, chainID *big.Int) error {
	// Encode as: [nonce, gasPrice, gas, to, value, data, chainID, 0, 0]
	var items [][]byte

	items = append(items, encodeUint64(tx.Nonce))
	items = append(items, encodeBigInt(tx.GasPrice))
	items = append(items, encodeUint64(tx.Gas))
	items = append(items, encodeAddress(tx.To))
	items = append(items, encodeBigInt(tx.Value))
	items = append(items, encodeBytes(tx.Data))
	items = append(items, encodeBigInt(chainID))
	items = append(items, encodeUint64(0))
	items = append(items, encodeUint64(0))

	encoded := encodeList(items)
	_, err := w.Write(encoded)
	return err
}

// RLP encoding helper functions

// encodeUint64 encodes a uint64 value to RLP.
func encodeUint64(i uint64) []byte {
	if i == 0 {
		return []byte{0x80}
	}
	if i < 128 {
		return []byte{byte(i)}
	}
	// Encode as big-endian bytes
	b := make([]byte, 8)
	size := putUint64(b, i)
	return encodeBytes(b[:size])
}

// encodeBigInt encodes a big.Int to RLP.
func encodeBigInt(i *big.Int) []byte {
	if i == nil || i.Sign() == 0 {
		return []byte{0x80}
	}
	return encodeBytes(i.Bytes())
}

// encodeAddress encodes an address to RLP.
func encodeAddress(addr *common.Address) []byte {
	if addr == nil {
		return []byte{0x80}
	}
	return encodeBytes(addr.Bytes())
}

// encodeBytes encodes a byte slice to RLP.
func encodeBytes(b []byte) []byte {
	if len(b) == 0 {
		return []byte{0x80}
	}
	if len(b) == 1 && b[0] < 128 {
		return []byte{b[0]}
	}
	return append(encodeStringHeader(len(b)), b...)
}

// encodeStringHeader encodes the header for a string/bytes.
func encodeStringHeader(size int) []byte {
	if size < 56 {
		return []byte{0x80 + byte(size)}
	}
	sizeBytes := putUint64Bytes(uint64(size))
	return append([]byte{0xB7 + byte(len(sizeBytes))}, sizeBytes...)
}

// encodeList encodes a list of RLP-encoded items.
func encodeList(items [][]byte) []byte {
	var content []byte
	for _, item := range items {
		content = append(content, item...)
	}
	return append(encodeListHeader(len(content)), content...)
}

// encodeListHeader encodes the header for a list.
func encodeListHeader(size int) []byte {
	if size < 56 {
		return []byte{0xC0 + byte(size)}
	}
	sizeBytes := putUint64Bytes(uint64(size))
	return append([]byte{0xF7 + byte(len(sizeBytes))}, sizeBytes...)
}

// putUint64 writes i to b in big-endian byte order using minimum bytes.
func putUint64(b []byte, i uint64) int {
	switch {
	case i < (1 << 8):
		b[0] = byte(i)
		return 1
	case i < (1 << 16):
		b[0] = byte(i >> 8)
		b[1] = byte(i)
		return 2
	case i < (1 << 24):
		b[0] = byte(i >> 16)
		b[1] = byte(i >> 8)
		b[2] = byte(i)
		return 3
	case i < (1 << 32):
		b[0] = byte(i >> 24)
		b[1] = byte(i >> 16)
		b[2] = byte(i >> 8)
		b[3] = byte(i)
		return 4
	case i < (1 << 40):
		b[0] = byte(i >> 32)
		b[1] = byte(i >> 24)
		b[2] = byte(i >> 16)
		b[3] = byte(i >> 8)
		b[4] = byte(i)
		return 5
	case i < (1 << 48):
		b[0] = byte(i >> 40)
		b[1] = byte(i >> 32)
		b[2] = byte(i >> 24)
		b[3] = byte(i >> 16)
		b[4] = byte(i >> 8)
		b[5] = byte(i)
		return 6
	case i < (1 << 56):
		b[0] = byte(i >> 48)
		b[1] = byte(i >> 40)
		b[2] = byte(i >> 32)
		b[3] = byte(i >> 24)
		b[4] = byte(i >> 16)
		b[5] = byte(i >> 8)
		b[6] = byte(i)
		return 7
	default:
		b[0] = byte(i >> 56)
		b[1] = byte(i >> 48)
		b[2] = byte(i >> 40)
		b[3] = byte(i >> 32)
		b[4] = byte(i >> 24)
		b[5] = byte(i >> 16)
		b[6] = byte(i >> 8)
		b[7] = byte(i)
		return 8
	}
}

// putUint64Bytes returns the big-endian byte representation of i using minimum bytes.
func putUint64Bytes(i uint64) []byte {
	b := make([]byte, 8)
	size := putUint64(b, i)
	return b[:size]
}
