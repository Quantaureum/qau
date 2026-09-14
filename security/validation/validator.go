// Quantaureum Node source, version 1.0.0.
// Package validation provides input validation framework for Quantaureum.
// It validates all RPC inputs and P2P messages to prevent malformed data processing.
package validation

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"sync"

	"github.com/quantaureum/qau/types"
)

// Validation errors
var (
	ErrEmptyInput       = errors.New("empty input")
	ErrInvalidFormat    = errors.New("invalid format")
	ErrInvalidLength    = errors.New("invalid length")
	ErrInvalidHex       = errors.New("invalid hex encoding")
	ErrInvalidAddress   = errors.New("invalid address")
	ErrInvalidHash      = errors.New("invalid hash")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrInvalidNonce     = errors.New("invalid nonce")
	ErrInvalidGasLimit  = errors.New("invalid gas limit")
	ErrInvalidGasPrice  = errors.New("invalid gas price")
	ErrInvalidValue     = errors.New("invalid value")
	ErrInvalidData      = errors.New("invalid data")
	ErrInvalidBlockNum  = errors.New("invalid block number")
	ErrInvalidTxType    = errors.New("invalid transaction type")
	ErrInputTooLarge    = errors.New("input too large")
	ErrInvalidJSON      = errors.New("invalid JSON")
	ErrMissingField     = errors.New("missing required field")
	ErrInvalidFieldType = errors.New("invalid field type")
	ErrRejectedInput    = errors.New("input rejected by validation")
)

// Validation limits
const (
	MaxAddressLength   = 42               // 0x + 40 hex chars
	MaxHashLength      = 66               // 0x + 64 hex chars
	MaxDataLength      = 10 * 1024 * 1024 // 10 MB
	MaxSignatureLength = 4096             // R3 FIX (2026-07-06): Tightened from 8192 to 4096. Dilithium3 signatures are ~3293 bytes; 4096 provides ~25% headroom for future algorithm changes while rejecting oversized payloads.
	MaxGasLimit        = 30_000_000
	MaxBatchSize       = 100
	MaxMethodLength    = 128
	MaxParamsSize      = 1 * 1024 * 1024 // 1 MB
)

// ValidationResult contains the result of a validation
type ValidationResult struct {
	Valid   bool
	Error   error
	Field   string
	Details string
}

// Validator provides input validation functionality
type Validator struct {
	mu sync.RWMutex

	// Custom validators
	customValidators map[string]CustomValidator

	// Validation stats
	stats ValidationStats
}

// CustomValidator is a function that validates custom input
type CustomValidator func(input any) *ValidationResult

// ValidationStats tracks validation statistics
type ValidationStats struct {
	TotalValidations      uint64
	SuccessfulValidations uint64
	FailedValidations     uint64
	RejectedInputs        uint64
}

// NewValidator creates a new Validator
func NewValidator() *Validator {
	return &Validator{
		customValidators: make(map[string]CustomValidator),
	}
}

// RegisterCustomValidator registers a custom validator for a specific type
func (v *Validator) RegisterCustomValidator(name string, validator CustomValidator) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.customValidators[name] = validator
}

// Stats returns the validation statistics
func (v *Validator) Stats() ValidationStats {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.stats
}

// recordValidation records a validation result
func (v *Validator) recordValidation(valid bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.stats.TotalValidations++
	if valid {
		v.stats.SuccessfulValidations++
	} else {
		v.stats.FailedValidations++
	}
}

// recordRejection records a rejected input
func (v *Validator) recordRejection() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.stats.RejectedInputs++
}

// ValidateAddress validates an address string
func (v *Validator) ValidateAddress(addr string) *ValidationResult {
	result := validateAddress(addr)
	v.recordValidation(result.Valid)
	return result
}

// ValidateHash validates a hash string
func (v *Validator) ValidateHash(hash string) *ValidationResult {
	result := validateHash(hash)
	v.recordValidation(result.Valid)
	return result
}

// ValidateHexBytes validates hex-encoded bytes
func (v *Validator) ValidateHexBytes(data string, maxLen int) *ValidationResult {
	result := validateHexBytes(data, maxLen)
	v.recordValidation(result.Valid)
	return result
}

// ValidateBlockNumber validates a block number string
func (v *Validator) ValidateBlockNumber(blockNum string) *ValidationResult {
	result := validateBlockNumber(blockNum)
	v.recordValidation(result.Valid)
	return result
}

// ValidateGasLimit validates a gas limit value
func (v *Validator) ValidateGasLimit(gasLimit uint64) *ValidationResult {
	result := validateGasLimit(gasLimit)
	v.recordValidation(result.Valid)
	return result
}

// ValidateGasPrice validates a gas price value
func (v *Validator) ValidateGasPrice(gasPrice *big.Int) *ValidationResult {
	result := validateGasPrice(gasPrice)
	v.recordValidation(result.Valid)
	return result
}

// ValidateValue validates a transfer value
func (v *Validator) ValidateValue(value *big.Int) *ValidationResult {
	result := validateValue(value)
	v.recordValidation(result.Valid)
	return result
}

// ValidateRPCRequest validates a JSON-RPC request
func (v *Validator) ValidateRPCRequest(data []byte) *ValidationResult {
	result := validateRPCRequest(data)
	v.recordValidation(result.Valid)
	if !result.Valid {
		v.recordRejection()
	}
	return result
}

// ValidateRPCParams validates JSON-RPC parameters for a specific method
func (v *Validator) ValidateRPCParams(method string, params json.RawMessage) *ValidationResult {
	result := validateRPCParams(method, params)
	v.recordValidation(result.Valid)
	return result
}

// Standalone validation functions

func validateAddress(addr string) *ValidationResult {
	if addr == "" {
		return &ValidationResult{Valid: false, Error: ErrEmptyInput, Field: "address"}
	}

	// Remove 0x prefix if present
	cleanAddr := strings.TrimPrefix(strings.TrimPrefix(addr, "0x"), "0X")

	// Check length (20 bytes = 40 hex chars)
	if len(cleanAddr) != 40 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidLength,
			Field:   "address",
			Details: fmt.Sprintf("expected 40 hex chars, got %d", len(cleanAddr)),
		}
	}

	// Validate hex encoding
	if _, err := hex.DecodeString(cleanAddr); err != nil {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidHex,
			Field:   "address",
			Details: err.Error(),
		}
	}

	return &ValidationResult{Valid: true}
}

func validateHash(hash string) *ValidationResult {
	if hash == "" {
		return &ValidationResult{Valid: false, Error: ErrEmptyInput, Field: "hash"}
	}

	// Remove 0x prefix if present
	cleanHash := strings.TrimPrefix(strings.TrimPrefix(hash, "0x"), "0X")

	// Check length (32 bytes = 64 hex chars)
	if len(cleanHash) != 64 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidLength,
			Field:   "hash",
			Details: fmt.Sprintf("expected 64 hex chars, got %d", len(cleanHash)),
		}
	}

	// Validate hex encoding
	if _, err := hex.DecodeString(cleanHash); err != nil {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidHex,
			Field:   "hash",
			Details: err.Error(),
		}
	}

	return &ValidationResult{Valid: true}
}

func validateHexBytes(data string, maxLen int) *ValidationResult {
	if data == "" {
		return &ValidationResult{Valid: true} // Empty data is valid
	}

	// Remove 0x prefix if present
	cleanData := strings.TrimPrefix(strings.TrimPrefix(data, "0x"), "0X")

	// Check max length
	if maxLen > 0 && len(cleanData)/2 > maxLen {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInputTooLarge,
			Field:   "data",
			Details: fmt.Sprintf("data exceeds max length of %d bytes", maxLen),
		}
	}

	// Validate hex encoding
	if _, err := hex.DecodeString(cleanData); err != nil {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidHex,
			Field:   "data",
			Details: err.Error(),
		}
	}

	return &ValidationResult{Valid: true}
}

var blockNumberRegex = regexp.MustCompile(`^(latest|pending|earliest|0x[0-9a-fA-F]+)$`)

// audit-fix R5-M2: compile once at package level instead of per-request
var methodNameRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)

func validateBlockNumber(blockNum string) *ValidationResult {
	if blockNum == "" {
		return &ValidationResult{Valid: false, Error: ErrEmptyInput, Field: "blockNumber"}
	}

	if !blockNumberRegex.MatchString(blockNum) {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidBlockNum,
			Field:   "blockNumber",
			Details: "must be 'latest', 'pending', 'earliest', or hex number",
		}
	}

	return &ValidationResult{Valid: true}
}

func validateGasLimit(gasLimit uint64) *ValidationResult {
	if gasLimit == 0 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidGasLimit,
			Field:   "gasLimit",
			Details: "gas limit cannot be zero",
		}
	}

	if gasLimit > MaxGasLimit {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidGasLimit,
			Field:   "gasLimit",
			Details: fmt.Sprintf("gas limit exceeds maximum of %d", MaxGasLimit),
		}
	}

	return &ValidationResult{Valid: true}
}

func validateGasPrice(gasPrice *big.Int) *ValidationResult {
	if gasPrice == nil {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidGasPrice,
			Field:   "gasPrice",
			Details: "gas price cannot be nil",
		}
	}

	if gasPrice.Sign() < 0 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidGasPrice,
			Field:   "gasPrice",
			Details: "gas price cannot be negative",
		}
	}

	return &ValidationResult{Valid: true}
}

func validateValue(value *big.Int) *ValidationResult {
	if value == nil {
		return &ValidationResult{Valid: true} // nil value is valid (means 0)
	}

	if value.Sign() < 0 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidValue,
			Field:   "value",
			Details: "value cannot be negative",
		}
	}

	return &ValidationResult{Valid: true}
}

// RPCRequest represents a JSON-RPC request for validation
type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      any             `json:"id"`
}

func validateRPCRequest(data []byte) *ValidationResult {
	if len(data) == 0 {
		return &ValidationResult{Valid: false, Error: ErrEmptyInput, Field: "request"}
	}

	if len(data) > MaxParamsSize {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInputTooLarge,
			Field:   "request",
			Details: fmt.Sprintf("request exceeds max size of %d bytes", MaxParamsSize),
		}
	}

	var req RPCRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidJSON,
			Field:   "request",
			Details: err.Error(),
		}
	}

	// Validate JSON-RPC version
	if req.JSONRPC != "2.0" {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidFormat,
			Field:   "jsonrpc",
			Details: "must be '2.0'",
		}
	}

	// Validate method
	if req.Method == "" {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMissingField,
			Field:   "method",
			Details: "method is required",
		}
	}

	if len(req.Method) > MaxMethodLength {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInputTooLarge,
			Field:   "method",
			Details: fmt.Sprintf("method name exceeds max length of %d", MaxMethodLength),
		}
	}

	// Validate method name format (alphanumeric with underscores)
	if !methodNameRegex.MatchString(req.Method) {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidFormat,
			Field:   "method",
			Details: "invalid method name format",
		}
	}

	return &ValidationResult{Valid: true}
}

func validateRPCParams(method string, params json.RawMessage) *ValidationResult {
	if len(params) > MaxParamsSize {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInputTooLarge,
			Field:   "params",
			Details: fmt.Sprintf("params exceed max size of %d bytes", MaxParamsSize),
		}
	}

	// Method-specific validation
	switch method {
	case "eth_getBalance", "eth_getTransactionCount", "eth_getCode":
		return validateAddressParams(params)
	case "eth_getStorageAt":
		return validateStorageAtParams(params)
	case "eth_getBlockByHash", "eth_getTransactionByHash", "eth_getTransactionReceipt":
		return validateHashParams(params)
	case "eth_getBlockByNumber":
		return validateBlockNumberParams(params)
	case "eth_sendRawTransaction":
		return validateRawTxParams(params)
	default:
		// Unknown method - basic validation only
		return &ValidationResult{Valid: true}
	}
}

func validateAddressParams(params json.RawMessage) *ValidationResult {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidJSON,
			Field:   "params",
			Details: "expected array of strings",
		}
	}

	if len(args) < 1 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMissingField,
			Field:   "params[0]",
			Details: "address is required",
		}
	}

	return validateAddress(args[0])
}

func validateStorageAtParams(params json.RawMessage) *ValidationResult {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidJSON,
			Field:   "params",
			Details: "expected array of strings",
		}
	}

	if len(args) < 2 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMissingField,
			Field:   "params",
			Details: "address and storage key are required",
		}
	}

	if result := validateAddress(args[0]); !result.Valid {
		result.Field = "params[0]"
		return result
	}

	if result := validateHash(args[1]); !result.Valid {
		result.Field = "params[1]"
		return result
	}

	return &ValidationResult{Valid: true}
}

func validateHashParams(params json.RawMessage) *ValidationResult {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidJSON,
			Field:   "params",
			Details: "expected array",
		}
	}

	if len(args) < 1 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMissingField,
			Field:   "params[0]",
			Details: "hash is required",
		}
	}

	hashStr, ok := args[0].(string)
	if !ok {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidFieldType,
			Field:   "params[0]",
			Details: "expected string",
		}
	}

	return validateHash(hashStr)
}

func validateBlockNumberParams(params json.RawMessage) *ValidationResult {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidJSON,
			Field:   "params",
			Details: "expected array",
		}
	}

	if len(args) < 1 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMissingField,
			Field:   "params[0]",
			Details: "block number is required",
		}
	}

	blockNumStr, ok := args[0].(string)
	if !ok {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidFieldType,
			Field:   "params[0]",
			Details: "expected string",
		}
	}

	return validateBlockNumber(blockNumStr)
}

func validateRawTxParams(params json.RawMessage) *ValidationResult {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrInvalidJSON,
			Field:   "params",
			Details: "expected array of strings",
		}
	}

	if len(args) < 1 {
		return &ValidationResult{
			Valid:   false,
			Error:   ErrMissingField,
			Field:   "params[0]",
			Details: "raw transaction data is required",
		}
	}

	return validateHexBytes(args[0], MaxDataLength)
}

// ParseAddress parses and validates an address string, returning the Address type
func ParseAddress(addr string) (types.Address, error) {
	result := validateAddress(addr)
	if !result.Valid {
		return types.Address{}, result.Error
	}

	cleanAddr := strings.TrimPrefix(strings.TrimPrefix(addr, "0x"), "0X")
	addrBytes, err := hex.DecodeString(cleanAddr)
	if err != nil {
		return types.Address{}, fmt.Errorf("invalid address hex: %w", err)
	}
	return types.BytesToAddress(addrBytes), nil
}

// ParseHash parses and validates a hash string, returning the Hash type
func ParseHash(hash string) (types.Hash, error) {
	result := validateHash(hash)
	if !result.Valid {
		return types.Hash{}, result.Error
	}

	cleanHash := strings.TrimPrefix(strings.TrimPrefix(hash, "0x"), "0X")
	hashBytes, err := hex.DecodeString(cleanHash)
	if err != nil {
		return types.Hash{}, fmt.Errorf("invalid hash hex: %w", err)
	}
	return types.BytesToHash(hashBytes), nil
}

// ParseHexBytes parses and validates hex-encoded bytes
func ParseHexBytes(data string) ([]byte, error) {
	result := validateHexBytes(data, MaxDataLength)
	if !result.Valid {
		return nil, result.Error
	}

	cleanData := strings.TrimPrefix(strings.TrimPrefix(data, "0x"), "0X")
	if cleanData == "" {
		return []byte{}, nil
	}
	return hex.DecodeString(cleanData)
}
