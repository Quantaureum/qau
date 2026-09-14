// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"fmt"
	"math"
	"math/big"

	"github.com/quantaureum/qau/types"
)

// Transaction field numbers (protobuf compatible)
const (
	fieldTxVersion             = 1
	fieldTxType                = 2
	fieldTxNonce               = 3
	fieldTxFrom                = 4
	fieldTxTo                  = 5
	fieldTxValue               = 6
	fieldTxGasLimit            = 7
	fieldTxGasPrice            = 8
	fieldTxData                = 9
	fieldTxSignature           = 10
	fieldTxPublicKey           = 11
	fieldTxLegacyHash          = 12 // LEGACY COMPATIBILITY: hash field for MetaMask (deprecated naming from Ethereum era)
	fieldTxChainID             = 13 // Cross-chain replay protection
	fieldTxMaxFee              = 14 // EIP-1559: max fee per gas
	fieldTxPriorityFee         = 15 // EIP-1559: max priority fee per gas
	fieldTxMaxFeePerBlobGas    = 16 // EIP-4844: max fee per blob gas
	fieldTxBlobVersionedHashes = 17 // EIP-4844: blob versioned hashes
	fieldTxBlobGasUsed         = 18 // EIP-4844: blob gas used

	// Multi-signature fields
	fieldTxMultiSigSignatures   = 20
	fieldTxMultiSigSignerBitmap = 21
	fieldTxMultiSigRequiredSigs = 22
	fieldTxMultiSigTotalSigners = 23

	// Privacy transaction fields
	fieldTxPrivacyEphemeralPubKey  = 30
	fieldTxPrivacyStealthAddrHash  = 31
	fieldTxPrivacyCommitments      = 32
	fieldTxPrivacyEncryptedAmounts = 33
	fieldTxPrivacyRangeProofs      = 34
	fieldTxPrivacyBalanceProof     = 35
	fieldTxPrivacyNullifier        = 36
)

// maxTransactionSize is the maximum allowed size for a serialized transaction.
// L10-013 FIX: Prevents OOM attacks from oversized transactions.
const maxTransactionSize = 128 * 1024 // 128 KB

// MarshalTransaction serializes a Transaction to bytes using protobuf wire format
func MarshalTransaction(tx *Transaction) ([]byte, error) {
	if tx == nil {
		return nil, fmt.Errorf("%w: nil transaction", ErrInvalidData)
	}

	buf := NewWriteBuffer()

	// Field 1: version (uint32)
	buf.EncodeUint32Field(fieldTxVersion, tx.Version)

	// Field 2: type (enum/uint32)
	buf.EncodeUint32Field(fieldTxType, uint32(tx.Type))

	// Field 3: nonce (uint64)
	buf.EncodeUint64Field(fieldTxNonce, tx.Nonce)

	// Field 4: from (bytes)
	buf.EncodeBytesField(fieldTxFrom, tx.From[:])

	// Field 5: to (bytes) - only if not nil
	if tx.To != nil {
		buf.EncodeBytesField(fieldTxTo, tx.To[:])
	}

	// Field 6: value (bytes) - big.Int encoded as big-endian bytes
	if tx.Value != nil && tx.Value.Sign() != 0 {
		buf.EncodeBytesField(fieldTxValue, tx.Value.Bytes())
	}

	// Field 7: gas_limit (uint64)
	buf.EncodeUint64Field(fieldTxGasLimit, tx.GasLimit)

	// Field 8: gas_price (bytes) - big.Int encoded as big-endian bytes
	if tx.GasPrice != nil && tx.GasPrice.Sign() != 0 {
		buf.EncodeBytesField(fieldTxGasPrice, tx.GasPrice.Bytes())
	}

	// Field 9: data (bytes)
	buf.EncodeBytesField(fieldTxData, tx.Data)

	// Field 10: signature (bytes)
	// R55-SIG FIX: Use EncodeBytesFieldAlways so nil/empty signature is still encoded.
	// This ensures the wire format on the signing side matches the verification side,
	// making the signing hash deterministic regardless of nil/empty state.
	buf.EncodeBytesFieldAlways(fieldTxSignature, tx.Signature)

	// Field 11: public_key (bytes)
	// R55-SIG FIX: Use EncodeBytesFieldAlways so nil/empty public key is still encoded.
	buf.EncodeBytesFieldAlways(fieldTxPublicKey, tx.PublicKey)

	// Field 12: qau_hash (bytes) - LEGACY COMPATIBILITY for MetaMask
	// Only encode if not zero (to save space for non-Ethereum transactions)
	if tx.EthHash != (types.Hash{}) {
		buf.EncodeBytesField(fieldTxLegacyHash, tx.EthHash[:])
	}

	// Field 13: chain_id (uint64) — cross-chain replay protection.
	// R40-M5 FIX: Use EncodeUint64FieldAlways to ensure ChainID is always present
	// in the wire format, even when zero. This prevents the encoding inconsistency
	// where EncodeUint64Field silently skips zero values but UnmarshalTransaction
	// rejects ChainID=0, making round-trip impossible for ChainID=0 transactions.
	buf.EncodeUint64FieldAlways(fieldTxChainID, tx.ChainID)

	if tx.MaxFeePerGas != nil && tx.MaxFeePerGas.Sign() != 0 {
		buf.EncodeBytesField(fieldTxMaxFee, tx.MaxFeePerGas.Bytes())
	}
	if tx.MaxPriorityFeePerGas != nil && tx.MaxPriorityFeePerGas.Sign() != 0 {
		buf.EncodeBytesField(fieldTxPriorityFee, tx.MaxPriorityFeePerGas.Bytes())
	}

	if tx.MaxFeePerBlobGas != nil && tx.MaxFeePerBlobGas.Sign() != 0 {
		buf.EncodeBytesField(fieldTxMaxFeePerBlobGas, tx.MaxFeePerBlobGas.Bytes())
	}
	for _, h := range tx.BlobVersionedHashes {
		buf.EncodeBytesField(fieldTxBlobVersionedHashes, h[:])
	}
	if tx.BlobGasUsed > 0 {
		buf.EncodeUint64Field(fieldTxBlobGasUsed, tx.BlobGasUsed)
	}

	// Multi-signature fields
	if tx.Type == TxTypeMultiSig {
		for _, sig := range tx.MultiSigSignatures {
			buf.EncodeBytesField(fieldTxMultiSigSignatures, sig)
		}
		if len(tx.MultiSigSignerBitmap) > 0 {
			buf.EncodeBytesField(fieldTxMultiSigSignerBitmap, tx.MultiSigSignerBitmap)
		}
		buf.EncodeUint32Field(fieldTxMultiSigRequiredSigs, uint32(tx.MultiSigRequiredSigs))
		buf.EncodeUint32Field(fieldTxMultiSigTotalSigners, uint32(tx.MultiSigTotalSigners))
	}

	// Privacy transaction fields
	if tx.Type == TxTypePrivacy {
		if len(tx.PrivacyEphemeralPubKey) > 0 {
			buf.EncodeBytesField(fieldTxPrivacyEphemeralPubKey, tx.PrivacyEphemeralPubKey)
		}
		if tx.PrivacyStealthAddrHash != (types.Hash{}) {
			buf.EncodeBytesField(fieldTxPrivacyStealthAddrHash, tx.PrivacyStealthAddrHash[:])
		}
		for _, c := range tx.PrivacyCommitments {
			buf.EncodeBytesField(fieldTxPrivacyCommitments, c)
		}
		for _, e := range tx.PrivacyEncryptedAmounts {
			buf.EncodeBytesField(fieldTxPrivacyEncryptedAmounts, e)
		}
		for _, r := range tx.PrivacyRangeProofs {
			buf.EncodeBytesField(fieldTxPrivacyRangeProofs, r)
		}
		if len(tx.PrivacyBalanceProof) > 0 {
			buf.EncodeBytesField(fieldTxPrivacyBalanceProof, tx.PrivacyBalanceProof)
		}
		if tx.PrivacyNullifier != (types.Hash{}) {
			buf.EncodeBytesField(fieldTxPrivacyNullifier, tx.PrivacyNullifier[:])
		}
	}

	return buf.Bytes(), nil
}

// UnmarshalTransaction deserializes a Transaction from bytes
func UnmarshalTransaction(data []byte) (*Transaction, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty data", ErrEmptyData)
	}
	// L10-013 FIX: Enforce maximum transaction size to prevent OOM attacks.
	if len(data) > maxTransactionSize {
		return nil, fmt.Errorf("%w: transaction size %d exceeds maximum %d", ErrMalformedMessage, len(data), maxTransactionSize)
	}

	buf := NewBuffer(data)
	tx := &Transaction{
		Value:    new(big.Int),
		GasPrice: new(big.Int),
	}

	// L18-014 FIX: Track seen fields to detect duplicate non-repeatable fields.
	// Protobuf-style decoding silently overwrites previous values when a field
	// appears multiple times. This can be exploited for transaction malleability.
	// Repeatable fields (which append to slices) are excluded from this check.
	seenFields := make(map[int]bool)

	for buf.Remaining() > 0 {
		fieldNum, wireType, err := buf.DecodeTag()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
		}

		// L18-014 FIX: Reject duplicate non-repeatable fields.
		// These fields legitimately appear multiple times (they append to slices):
		if fieldNum != fieldTxBlobVersionedHashes &&
			fieldNum != fieldTxMultiSigSignatures &&
			fieldNum != fieldTxPrivacyCommitments &&
			fieldNum != fieldTxPrivacyEncryptedAmounts &&
			fieldNum != fieldTxPrivacyRangeProofs {
			if seenFields[fieldNum] {
				return nil, fmt.Errorf("%w: duplicate field %d in transaction", ErrMalformedMessage, fieldNum)
			}
			seenFields[fieldNum] = true
		}

		switch fieldNum {
		case fieldTxVersion:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for version", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// Safe conversion: check for uint32 overflow
			if v > math.MaxUint32 {
				return nil, fmt.Errorf("%w: version value %d exceeds uint32 max", ErrMalformedMessage, v)
			}
			tx.Version = uint32(v)

		case fieldTxType:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for type", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// Safe conversion: check for uint8 overflow (TxType is uint8)
			if v > math.MaxUint8 {
				return nil, fmt.Errorf("%w: type value %d exceeds valid range", ErrMalformedMessage, v)
			}
			tx.Type = TxType(v)
			if !tx.Type.IsValid() {
				return nil, fmt.Errorf("%w: %d", ErrInvalidTxType, tx.Type)
			}

		case fieldTxNonce:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for nonce", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			tx.Nonce = v

		case fieldTxFrom:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for from", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) != types.AddressLength {
				return nil, fmt.Errorf("%w: from must be %d bytes, got %d", ErrInvalidAddress, types.AddressLength, len(data))
			}
			copy(tx.From[:], data)

		case fieldTxTo:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for to", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) != types.AddressLength {
				return nil, fmt.Errorf("%w: to must be %d bytes, got %d", ErrInvalidAddress, types.AddressLength, len(data))
			}
			to := types.Address{}
			copy(to[:], data)
			tx.To = &to

		case fieldTxValue:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for value", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// L10-016/L11-016 FIX: Limit Value to 32 bytes to prevent oversized big.Int.
			if len(data) > 32 {
				return nil, fmt.Errorf("%w: value field exceeds 32 bytes (got %d)", ErrMalformedMessage, len(data))
			}
			tx.Value.SetBytes(data)

		case fieldTxGasLimit:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for gas_limit", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			tx.GasLimit = v

		case fieldTxGasPrice:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for gas_price", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// L12-032 FIX: Check size before SetBytes for defensive programming.
			// L10-016/L11-016 FIX: Limit GasPrice to 32 bytes to prevent oversized big.Int.
			if len(data) > 32 {
				return nil, fmt.Errorf("%w: gas_price field exceeds 32 bytes (got %d)", ErrMalformedMessage, len(data))
			}
			tx.GasPrice.SetBytes(data)

		case fieldTxData:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for data", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// L10-017/L11-017 FIX: Limit Data to 1MB to prevent oversized payload.
			if len(data) > 1024*1024 {
				return nil, fmt.Errorf("%w: data field exceeds 1MB (got %d)", ErrMalformedMessage, len(data))
			}
			tx.Data = data

		case fieldTxSignature:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for signature", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// L10-018/L11-018 FIX: Limit Signature to Dilithium3 size (3293 bytes).
			if len(data) > 3293 {
				return nil, fmt.Errorf("%w: signature field exceeds 3293 bytes (got %d)", ErrMalformedMessage, len(data))
			}
			tx.Signature = data

		case fieldTxPublicKey:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for public_key", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// L10-032/L11-023 FIX: Limit PublicKey to Dilithium3 size (1952 bytes).
			if len(data) > 1952 {
				return nil, fmt.Errorf("%w: public_key field exceeds 1952 bytes (got %d)", ErrMalformedMessage, len(data))
			}
			tx.PublicKey = data

		case fieldTxLegacyHash:
			// LEGACY COMPATIBILITY: Ethereum-compatible tx hash for MetaMask
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for qau_hash", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) == types.HashLength {
				copy(tx.EthHash[:], data)
			}

		case fieldTxChainID:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for chain_id", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// R46-H-H2 FIX: Reject chainId=0 to prevent cross-chain replay.
			// ChainID must be > 0 for replay protection to work.
			if v == 0 {
				return nil, fmt.Errorf("%w: chain_id is zero — replay protection requires a valid chain ID", ErrMalformedMessage)
			}
			tx.ChainID = v

		case fieldTxMaxFee:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for max_fee_per_gas", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// L12-019 FIX: Limit fee fields to 32 bytes to prevent oversized big.Int.
			if len(data) > 32 {
				return nil, fmt.Errorf("%w: max_fee_per_gas field exceeds 32 bytes (got %d)", ErrMalformedMessage, len(data))
			}
			tx.MaxFeePerGas = new(big.Int).SetBytes(data)

		case fieldTxPriorityFee:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for max_priority_fee_per_gas", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// L12-019 FIX: Limit fee fields to 32 bytes to prevent oversized big.Int.
			if len(data) > 32 {
				return nil, fmt.Errorf("%w: max_priority_fee_per_gas field exceeds 32 bytes (got %d)", ErrMalformedMessage, len(data))
			}
			tx.MaxPriorityFeePerGas = new(big.Int).SetBytes(data)

		case fieldTxMaxFeePerBlobGas:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for max_fee_per_blob_gas", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// L12-019 FIX: Limit fee fields to 32 bytes to prevent oversized big.Int.
			if len(data) > 32 {
				return nil, fmt.Errorf("%w: max_fee_per_blob_gas field exceeds 32 bytes (got %d)", ErrMalformedMessage, len(data))
			}
			tx.MaxFeePerBlobGas = new(big.Int).SetBytes(data)

		case fieldTxBlobVersionedHashes:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for blob_versioned_hashes", ErrMalformedMessage)
			}
			// L9-037 FIX: Enforce max blob count to prevent unbounded memory allocation.
			if len(tx.BlobVersionedHashes) >= MaxBlobsPerTransaction {
				return nil, fmt.Errorf("%w: too many blob versioned hashes (%d > max %d)", ErrMalformedMessage, len(tx.BlobVersionedHashes)+1, MaxBlobsPerTransaction)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) != types.HashLength {
				return nil, fmt.Errorf("%w: invalid blob versioned hash length %d", ErrMalformedMessage, len(data))
			}
			var h types.Hash
			copy(h[:], data)
			tx.BlobVersionedHashes = append(tx.BlobVersionedHashes, h)

		case fieldTxBlobGasUsed:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for blob_gas_used", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			tx.BlobGasUsed = v

		// Multi-signature fields
		case fieldTxMultiSigSignatures:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for multisig_signature", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// L10-019 FIX: Limit MultiSigSignatures count to 256.
			if len(tx.MultiSigSignatures) >= 256 {
				return nil, fmt.Errorf("%w: too many multisig signatures (%d > max 256)", ErrMalformedMessage, len(tx.MultiSigSignatures)+1)
			}
			// L12-020 FIX: Limit each individual signature to Dilithium3 size (3293 bytes).
			if len(data) > 3293 {
				return nil, fmt.Errorf("%w: individual signature too large (got %d bytes, max 3293)", ErrMalformedMessage, len(data))
			}
			tx.MultiSigSignatures = append(tx.MultiSigSignatures, data)

		case fieldTxMultiSigSignerBitmap:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for multisig_signer_bitmap", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			tx.MultiSigSignerBitmap = data
			// L10-030/L11-021 FIX: Limit MultiSigSignerBitmap to 32 bytes (256 signers max).
			if len(tx.MultiSigSignerBitmap) > 32 {
				return nil, fmt.Errorf("%w: multisig signer bitmap exceeds 32 bytes (got %d)", ErrMalformedMessage, len(tx.MultiSigSignerBitmap))
			}

		case fieldTxMultiSigRequiredSigs:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for multisig_required_sigs", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if v > math.MaxInt32 {
				return nil, fmt.Errorf("multiSigRequiredSigs too large: %d", v)
			}
			tx.MultiSigRequiredSigs = int(v)

		case fieldTxMultiSigTotalSigners:
			if wireType != WireVarint {
				return nil, fmt.Errorf("%w: invalid wire type for multisig_total_signers", ErrMalformedMessage)
			}
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if v > math.MaxInt32 {
				return nil, fmt.Errorf("multiSigTotalSigners too large: %d", v)
			}
			tx.MultiSigTotalSigners = int(v)

		// Privacy transaction fields
		case fieldTxPrivacyEphemeralPubKey:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for privacy_ephemeral_pubkey", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			tx.PrivacyEphemeralPubKey = data
			// L10-028/L11-019 FIX: Limit PrivacyEphemeralPubKey to Kyber768 size (1184 bytes).
			if len(tx.PrivacyEphemeralPubKey) > 1184 {
				return nil, fmt.Errorf("%w: privacy ephemeral pubkey exceeds 1184 bytes (got %d)", ErrMalformedMessage, len(tx.PrivacyEphemeralPubKey))
			}

		case fieldTxPrivacyStealthAddrHash:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for privacy_stealth_addr_hash", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) == types.HashLength {
				copy(tx.PrivacyStealthAddrHash[:], data)
			}

		case fieldTxPrivacyCommitments:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for privacy_commitment", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// L10-020/L11-009 FIX: Limit PrivacyCommitments count to 64.
			if len(tx.PrivacyCommitments) >= 64 {
				return nil, fmt.Errorf("%w: too many privacy commitments (%d > max 64)", ErrMalformedMessage, len(tx.PrivacyCommitments)+1)
			}
			// L12-021 FIX: Limit each commitment to 48 bytes.
			if len(data) > 48 {
				return nil, fmt.Errorf("%w: privacy commitment exceeds 48 bytes (got %d)", ErrMalformedMessage, len(data))
			}
			tx.PrivacyCommitments = append(tx.PrivacyCommitments, data)

		case fieldTxPrivacyEncryptedAmounts:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for privacy_encrypted_amount", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// L10-020/L11-009 FIX: Limit PrivacyEncryptedAmounts count to 64.
			if len(tx.PrivacyEncryptedAmounts) >= 64 {
				return nil, fmt.Errorf("%w: too many privacy encrypted amounts (%d > max 64)", ErrMalformedMessage, len(tx.PrivacyEncryptedAmounts)+1)
			}
			// L12-021 FIX: Limit each encrypted amount to 68 bytes.
			if len(data) > 68 {
				return nil, fmt.Errorf("%w: privacy encrypted amount exceeds 68 bytes (got %d)", ErrMalformedMessage, len(data))
			}
			tx.PrivacyEncryptedAmounts = append(tx.PrivacyEncryptedAmounts, data)

		case fieldTxPrivacyRangeProofs:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for privacy_range_proof", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			// L10-020/L11-009 FIX: Limit PrivacyRangeProofs count to 64.
			if len(tx.PrivacyRangeProofs) >= 64 {
				return nil, fmt.Errorf("%w: too many privacy range proofs (%d > max 64)", ErrMalformedMessage, len(tx.PrivacyRangeProofs)+1)
			}
			// L12-021 FIX: Limit each range proof to 8192 bytes.
			if len(data) > 8192 {
				return nil, fmt.Errorf("%w: privacy range proof exceeds 8192 bytes (got %d)", ErrMalformedMessage, len(data))
			}
			tx.PrivacyRangeProofs = append(tx.PrivacyRangeProofs, data)

		case fieldTxPrivacyBalanceProof:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for privacy_balance_proof", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			tx.PrivacyBalanceProof = data
			// L10-029/L11-020 FIX: Limit PrivacyBalanceProof to 8192 bytes.
			if len(tx.PrivacyBalanceProof) > 8192 {
				return nil, fmt.Errorf("%w: privacy balance proof exceeds 8192 bytes (got %d)", ErrMalformedMessage, len(tx.PrivacyBalanceProof))
			}

		case fieldTxPrivacyNullifier:
			if wireType != WireBytes {
				return nil, fmt.Errorf("%w: invalid wire type for privacy_nullifier", ErrMalformedMessage)
			}
			data, err := buf.DecodeBytes()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
			if len(data) == types.HashLength {
				copy(tx.PrivacyNullifier[:], data)
			}

		default:
			// Skip unknown fields
			if err := buf.Skip(wireType); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMalformedMessage, err)
			}
		}
	}

	// L10-031/L11-022 FIX: RequiredSigs must not exceed TotalSigners.
	if tx.MultiSigRequiredSigs > tx.MultiSigTotalSigners {
		return nil, fmt.Errorf("%w: required_sigs (%d) exceeds total_signers (%d)", ErrMalformedMessage, tx.MultiSigRequiredSigs, tx.MultiSigTotalSigners)
	}

	return tx, nil
}
