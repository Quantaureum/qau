// Quantaureum Node source, version 1.0.0.
package encoding

import (
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/types"
)

const (
	MaxUserOpVerificationGasLimit = 5000000
	MaxUserOpCallDataSize         = 131072
	MaxUserOpInitCodeSize         = 65536
	MaxUserOpPaymasterDataSize    = 65536
	MaxUserOpSignatureSize        = 4096
	MaxUserOpsPerBundle           = 128
)

type UserOpType uint8

const (
	UserOpTypeDefault UserOpType = iota
)

type UserOperation struct {
	Sender               types.Address
	Nonce                uint64
	InitCode             []byte
	CallData             []byte
	CallGasLimit         uint64
	VerificationGasLimit uint64
	PreVerificationGas   uint64
	MaxFeePerGas         *big.Int
	MaxPriorityFeePerGas *big.Int
	Paymaster            *types.Address
	PaymasterData        []byte
	Signature            []byte
	OpType               UserOpType
}

func (uo *UserOperation) Validate() error {
	if uo.Sender == (types.Address{}) {
		return fmt.Errorf("%w: sender is empty", ErrInvalidData)
	}
	if uo.VerificationGasLimit > MaxUserOpVerificationGasLimit {
		return fmt.Errorf("%w: verification gas limit exceeds max", ErrInvalidData)
	}
	if len(uo.CallData) > MaxUserOpCallDataSize {
		return fmt.Errorf("%w: call data exceeds max size", ErrInvalidData)
	}
	if len(uo.InitCode) > MaxUserOpInitCodeSize {
		return fmt.Errorf("%w: init code exceeds max size", ErrInvalidData)
	}
	if uo.Paymaster != nil && len(uo.PaymasterData) > MaxUserOpPaymasterDataSize {
		return fmt.Errorf("%w: paymaster data exceeds max size", ErrInvalidData)
	}
	if len(uo.Signature) > MaxUserOpSignatureSize {
		return fmt.Errorf("%w: signature exceeds max size", ErrInvalidData)
	}
	if uo.MaxFeePerGas == nil || uo.MaxFeePerGas.Sign() < 0 {
		return fmt.Errorf("%w: max fee per gas is invalid", ErrInvalidData)
	}
	if uo.MaxPriorityFeePerGas == nil || uo.MaxFeePerGas == nil {
		return fmt.Errorf("%w: max priority fee per gas or max fee per gas is nil", ErrInvalidData)
	}
	if uo.MaxPriorityFeePerGas.Sign() < 0 || uo.MaxFeePerGas.Sign() < 0 {
		return fmt.Errorf("%w: max fee per gas is invalid", ErrInvalidData)
	}
	if uo.MaxPriorityFeePerGas.Cmp(uo.MaxFeePerGas) > 0 {
		return fmt.Errorf("%w: priority fee exceeds max fee", ErrInvalidData)
	}
	return nil
}

func (uo *UserOperation) Hash(entryPoint types.Address, chainID uint64) types.Hash {
	return types.BytesToHash(uo.hashBytes(entryPoint, chainID))
}

func (uo *UserOperation) hashBytes(entryPoint types.Address, chainID uint64) []byte {
	buf := NewWriteBuffer()
	buf.EncodeBytesField(1, uo.Sender[:])
	buf.EncodeUint64Field(2, uo.Nonce)
	buf.EncodeBytesField(3, uo.InitCode)
	buf.EncodeBytesField(4, uo.CallData)
	buf.EncodeUint64Field(5, uo.CallGasLimit)
	buf.EncodeUint64Field(6, uo.VerificationGasLimit)
	buf.EncodeUint64Field(7, uo.PreVerificationGas)
	if uo.MaxFeePerGas != nil {
		buf.EncodeBytesField(8, uo.MaxFeePerGas.Bytes())
	}
	if uo.MaxPriorityFeePerGas != nil {
		buf.EncodeBytesField(9, uo.MaxPriorityFeePerGas.Bytes())
	}
	if uo.Paymaster != nil {
		buf.EncodeBytesField(10, uo.Paymaster[:])
	}
	buf.EncodeBytesField(11, uo.PaymasterData)
	buf.EncodeBytesField(12, entryPoint[:])
	buf.EncodeUint64Field(13, chainID)
	return buf.Bytes()
}

func (uo *UserOperation) RequiredPrefund() *big.Int {
	// CRITICAL FIX: Check for uint64 overflow before addition.
	// Three uint64 values added can overflow silently if all are near MaxUint64.
	gasTotal := uo.CallGasLimit + uo.VerificationGasLimit
	if gasTotal < uo.CallGasLimit { // overflow
		return nil
	}
	gasTotal += uo.PreVerificationGas
	if gasTotal < uo.PreVerificationGas { // overflow
		return nil
	}
	maxGasCost := new(big.Int).Mul(new(big.Int).SetUint64(gasTotal), uo.MaxFeePerGas)
	return maxGasCost
}

func (uo *UserOperation) EffectiveGasPrice(baseFee *big.Int) *big.Int {
	priorityFee := uo.MaxPriorityFeePerGas
	maxFee := uo.MaxFeePerGas
	if baseFee == nil {
		return maxFee
	}
	effective := new(big.Int).Add(baseFee, priorityFee)
	if effective.Cmp(maxFee) > 0 {
		return maxFee
	}
	return effective
}

func MarshalUserOperation(uo *UserOperation) ([]byte, error) {
	if uo == nil {
		return nil, fmt.Errorf("%w: nil user operation", ErrInvalidData)
	}
	buf := NewWriteBuffer()
	buf.EncodeBytesField(1, uo.Sender[:])
	buf.EncodeUint64Field(2, uo.Nonce)
	buf.EncodeBytesField(3, uo.InitCode)
	buf.EncodeBytesField(4, uo.CallData)
	buf.EncodeUint64Field(5, uo.CallGasLimit)
	buf.EncodeUint64Field(6, uo.VerificationGasLimit)
	buf.EncodeUint64Field(7, uo.PreVerificationGas)
	if uo.MaxFeePerGas != nil {
		buf.EncodeBytesField(8, uo.MaxFeePerGas.Bytes())
	}
	if uo.MaxPriorityFeePerGas != nil {
		buf.EncodeBytesField(9, uo.MaxPriorityFeePerGas.Bytes())
	}
	if uo.Paymaster != nil {
		buf.EncodeBytesField(10, uo.Paymaster[:])
	}
	buf.EncodeBytesField(11, uo.PaymasterData)
	buf.EncodeBytesField(12, uo.Signature)
	buf.EncodeUint32Field(13, uint32(uo.OpType))
	return buf.Bytes(), nil
}

func UnmarshalUserOperation(data []byte) (*UserOperation, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty data", ErrInvalidData)
	}
	uo := &UserOperation{}
	buf := NewBuffer(data)
	// L20-009 FIX: Track seen fields to detect duplicate non-repeatable fields.
	// All UserOperation fields are non-repeatable; duplicates indicate a
	// malformed or malicious message that could overwrite earlier values.
	seenFields := make(map[int]bool)
	for buf.Remaining() > 0 {
		fieldNum, wireType, err := buf.DecodeTag()
		if err != nil {
			return nil, err
		}
		if seenFields[fieldNum] {
			return nil, fmt.Errorf("%w: duplicate field %d in user operation", ErrMalformedMessage, fieldNum)
		}
		seenFields[fieldNum] = true
		switch fieldNum {
		case 1:
			addr, err := buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			if len(addr) != types.AddressLength {
				return nil, fmt.Errorf("%w: invalid sender address length", ErrInvalidAddress)
			}
			copy(uo.Sender[:], addr)
		case 2:
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, err
			}
			uo.Nonce = v
		case 3:
			uo.InitCode, err = buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			if len(uo.InitCode) > MaxUserOpInitCodeSize {
				return nil, fmt.Errorf("%w: init code exceeds max size", ErrInvalidData)
			}
		case 4:
			uo.CallData, err = buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			if len(uo.CallData) > MaxUserOpCallDataSize {
				return nil, fmt.Errorf("%w: call data exceeds max size", ErrInvalidData)
			}
		case 5:
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, err
			}
			uo.CallGasLimit = v
		case 6:
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, err
			}
			uo.VerificationGasLimit = v
		case 7:
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, err
			}
			uo.PreVerificationGas = v
		case 8:
			val, err := buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			uo.MaxFeePerGas = new(big.Int).SetBytes(val)
		case 9:
			val, err := buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			uo.MaxPriorityFeePerGas = new(big.Int).SetBytes(val)
		case 10:
			addr, err := buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			if len(addr) == types.AddressLength {
				var pm types.Address
				copy(pm[:], addr)
				uo.Paymaster = &pm
			}
		case 11:
			uo.PaymasterData, err = buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			if len(uo.PaymasterData) > MaxUserOpPaymasterDataSize {
				return nil, fmt.Errorf("%w: paymaster data exceeds max size", ErrInvalidData)
			}
		case 12:
			uo.Signature, err = buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
		case 13:
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, err
			}
			uo.OpType = UserOpType(v)
			// SECURITY (audit 2026-06-24, M-2): Validate OpType is within known range
			if uo.OpType != UserOpTypeDefault {
				return nil, fmt.Errorf("invalid UserOpType: %d", v)
			}
		default:
			if err := buf.Skip(wireType); err != nil {
				return nil, err
			}
		}
	}
	return uo, nil
}

type UserOpBundle struct {
	UserOps      []*UserOperation
	EntryPoint   types.Address
	ChainID      uint64
	Beneficiary  types.Address
	BlockNumber  uint64
	BlockBaseFee *big.Int
}

func (b *UserOpBundle) Validate() error {
	if len(b.UserOps) == 0 {
		return fmt.Errorf("%w: empty bundle", ErrInvalidData)
	}
	if len(b.UserOps) > MaxUserOpsPerBundle {
		return fmt.Errorf("%w: bundle exceeds max user ops", ErrInvalidData)
	}
	if b.EntryPoint == (types.Address{}) {
		return fmt.Errorf("%w: entry point is empty", ErrInvalidData)
	}
	for i, uo := range b.UserOps {
		if err := uo.Validate(); err != nil {
			return fmt.Errorf("user op %d: %w", i, err)
		}
	}
	return nil
}

func MarshalUserOpBundle(bundle *UserOpBundle) ([]byte, error) {
	if bundle == nil {
		return nil, fmt.Errorf("%w: nil bundle", ErrInvalidData)
	}
	buf := NewWriteBuffer()
	buf.EncodeBytesField(1, bundle.EntryPoint[:])
	buf.EncodeUint64Field(2, bundle.ChainID)
	buf.EncodeBytesField(3, bundle.Beneficiary[:])
	buf.EncodeUint64Field(4, bundle.BlockNumber)
	if bundle.BlockBaseFee != nil {
		buf.EncodeBytesField(5, bundle.BlockBaseFee.Bytes())
	}
	for _, uo := range bundle.UserOps {
		uoBytes, err := MarshalUserOperation(uo)
		if err != nil {
			return nil, err
		}
		buf.EncodeBytesField(6, uoBytes)
	}
	return buf.Bytes(), nil
}

func UnmarshalUserOpBundle(data []byte) (*UserOpBundle, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty data", ErrInvalidData)
	}
	bundle := &UserOpBundle{}
	buf := NewBuffer(data)
	// L20-010 FIX: Track seen fields to detect duplicate non-repeatable fields.
	// Field 6 (UserOps) is repeatable (one per user op), all other fields
	// are non-repeatable and must not appear more than once.
	seenFields := make(map[int]bool)
	for buf.Remaining() > 0 {
		fieldNum, wireType, err := buf.DecodeTag()
		if err != nil {
			return nil, err
		}
		// Skip duplicate check for repeatable field 6 (UserOps)
		if fieldNum != 6 {
			if seenFields[fieldNum] {
				return nil, fmt.Errorf("%w: duplicate field %d in user op bundle", ErrMalformedMessage, fieldNum)
			}
			seenFields[fieldNum] = true
		}
		switch fieldNum {
		case 1:
			addr, err := buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			if len(addr) != types.AddressLength {
				return nil, fmt.Errorf("%w: invalid entry point address", ErrInvalidAddress)
			}
			copy(bundle.EntryPoint[:], addr)
		case 2:
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, err
			}
			bundle.ChainID = v
		case 3:
			addr, err := buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			if len(addr) == types.AddressLength {
				copy(bundle.Beneficiary[:], addr)
			}
		case 4:
			v, err := buf.DecodeVarint()
			if err != nil {
				return nil, err
			}
			bundle.BlockNumber = v
		case 5:
			val, err := buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			bundle.BlockBaseFee = new(big.Int).SetBytes(val)
		case 6:
			// AUDIT ROUND-7 2026-08-17 FIX: enforce the UserOps count
			// cap AT DECODE TIME, mirroring UnmarshalBlock's maxTxPerBlock
			// pattern. Previously the cap lived only in UserOpBundle.
			// Validate() (consumer side); a 32MB wire budget can still hold
			// hundreds of thousands of minimal user ops, so a crafted bundle
			// forced unbounded []*UserOperation growth and per-op object
			// allocation during decoding before any Validate() could run.
			if len(bundle.UserOps) >= MaxUserOpsPerBundle {
				return nil, fmt.Errorf("%w: bundle exceeds max user ops (%d)", ErrInvalidData, MaxUserOpsPerBundle)
			}
			uoBytes, err := buf.DecodeBytes()
			if err != nil {
				return nil, err
			}
			uo, err := UnmarshalUserOperation(uoBytes)
			if err != nil {
				return nil, err
			}
			bundle.UserOps = append(bundle.UserOps, uo)
		default:
			if err := buf.Skip(wireType); err != nil {
				return nil, err
			}
		}
	}
	return bundle, nil
}
