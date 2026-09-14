// Quantaureum Go SDK source, version 1.0.0.
// Package errors provides custom error types for the Quantaureum Go SDK.
package errors

import (
	"errors"
	"fmt"
)

// Base error variables for common error conditions.
var (
	// ErrInvalidAddress indicates an invalid address format.
	ErrInvalidAddress = errors.New("invalid address")

	// ErrInvalidPrivateKey indicates an invalid private key.
	ErrInvalidPrivateKey = errors.New("invalid private key")

	// ErrInvalidMnemonic indicates an invalid mnemonic phrase.
	ErrInvalidMnemonic = errors.New("invalid mnemonic phrase")

	// ErrInvalidHex indicates an invalid hex string.
	ErrInvalidHex = errors.New("invalid hex string")

	// ErrNilPointer indicates a nil pointer was provided where not allowed.
	ErrNilPointer = errors.New("nil pointer")

	// ErrInvalidSignature indicates an invalid signature.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrConnectionFailed indicates a connection failure.
	ErrConnectionFailed = errors.New("connection failed")

	// ErrTimeout indicates a timeout occurred.
	ErrTimeout = errors.New("timeout")

	// ErrInvalidChainID indicates an invalid chain ID.
	ErrInvalidChainID = errors.New("invalid chain ID")

	// ErrInsufficientFunds indicates insufficient funds for a transaction.
	ErrInsufficientFunds = errors.New("insufficient funds")

	// ErrNonceTooLow indicates the nonce is too low.
	ErrNonceTooLow = errors.New("nonce too low")

	// ErrGasTooLow indicates the gas limit is too low.
	ErrGasTooLow = errors.New("gas too low")

	// ErrTransactionAlreadyKnown indicates the transaction is already in the pool.
	ErrTransactionAlreadyKnown = errors.New("transaction already known")

	// ErrReplacementUnderpriced indicates a replacement transaction has insufficient gas price.
	ErrReplacementUnderpriced = errors.New("replacement transaction underpriced")

	// ErrExecutionReverted indicates the transaction execution was reverted.
	ErrExecutionReverted = errors.New("execution reverted")
)

// RPCError represents an error returned from an RPC call.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Error implements the error interface.
func (e *RPCError) Error() string {
	if e.Data != nil {
		return fmt.Sprintf("rpc error: code=%d, message=%s, data=%v", e.Code, e.Message, e.Data)
	}
	return fmt.Sprintf("rpc error: code=%d, message=%s", e.Code, e.Message)
}

// NewRPCError creates a new RPCError.
func NewRPCError(code int, message string, data any) *RPCError {
	return &RPCError{
		Code:    code,
		Message: message,
		Data:    data,
	}
}

// TransactionError represents an error related to a transaction.
type TransactionError struct {
	TxHash       string `json:"txHash,omitempty"`
	RevertReason string `json:"revertReason,omitempty"`
	Err          error  `json:"-"`
}

// Error implements the error interface.
func (e *TransactionError) Error() string {
	if e.RevertReason != "" {
		return fmt.Sprintf("transaction %s reverted: %s", e.TxHash, e.RevertReason)
	}
	if e.Err != nil {
		return fmt.Sprintf("transaction %s failed: %v", e.TxHash, e.Err)
	}
	return fmt.Sprintf("transaction %s failed", e.TxHash)
}

// Unwrap returns the underlying error.
func (e *TransactionError) Unwrap() error {
	return e.Err
}

// NewTransactionError creates a new TransactionError.
func NewTransactionError(txHash string, revertReason string, err error) *TransactionError {
	return &TransactionError{
		TxHash:       txHash,
		RevertReason: revertReason,
		Err:          err,
	}
}

// ValidationError represents a validation error for input parameters.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Err     error  `json:"-"`
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("validation error: field=%s, message=%s", e.Field, e.Message)
	}
	return fmt.Sprintf("validation error: %s", e.Message)
}

// Unwrap returns the underlying error.
func (e *ValidationError) Unwrap() error {
	return e.Err
}

// NewValidationError creates a new ValidationError.
func NewValidationError(field string, message string) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: message,
	}
}

// NewValidationErrorWithCause creates a new ValidationError with an underlying cause.
func NewValidationErrorWithCause(field string, message string, err error) *ValidationError {
	return &ValidationError{
		Field:   field,
		Message: message,
		Err:     err,
	}
}

// Is checks if the target error matches this error type.
// This enables errors.Is() support.
func (e *RPCError) Is(target error) bool {
	t, ok := target.(*RPCError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// Is checks if the target error matches this error type.
// This enables errors.Is() support.
func (e *TransactionError) Is(target error) bool {
	_, ok := target.(*TransactionError)
	return ok
}

// Is checks if the target error matches this error type.
// This enables errors.Is() support.
func (e *ValidationError) Is(target error) bool {
	t, ok := target.(*ValidationError)
	if !ok {
		return false
	}
	return e.Field == t.Field
}
