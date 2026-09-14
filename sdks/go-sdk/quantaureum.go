// Quantaureum Go SDK source, version 1.0.0.
// Package quantaureum provides a Go SDK for interacting with the Quantaureum blockchain.
//
// The SDK provides a comprehensive set of tools for:
//   - Connecting to Quantaureum nodes via JSON-RPC
//   - Managing accounts and signing transactions
//   - Interacting with smart contracts
//   - Utility functions for data conversion and validation
//
// Quick Start:
//
//	// Create a client
//	client, err := quantaureum.NewClient("http://localhost:8545")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Create an account
//	account, err := quantaureum.NewAccount()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println("Address:", account.Address().Hex())
//
//	// Get balance
//	balance, err := client.BalanceAt(context.Background(), account.Address(), nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println("Balance:", quantaureum.WeiToEther(balance))
package quantaureum

import (
	"context"
	"math/big"
	"time"

	"github.com/quantaureum/qau/sdks/go-sdk/accounts"
	"github.com/quantaureum/qau/sdks/go-sdk/client"
	"github.com/quantaureum/qau/sdks/go-sdk/common"
	"github.com/quantaureum/qau/sdks/go-sdk/contracts"
	"github.com/quantaureum/qau/sdks/go-sdk/errors"
	"github.com/quantaureum/qau/sdks/go-sdk/types"
	"github.com/quantaureum/qau/sdks/go-sdk/utils"
)

// =============================================================================
// Type Aliases - Common Types
// =============================================================================

// Address represents a 20-byte Ethereum-style address.
type Address = common.Address

// Hash represents a 32-byte Keccak256 hash.
type Hash = common.Hash

// =============================================================================
// Type Aliases - Transaction Types
// =============================================================================

// Transaction represents a blockchain transaction.
type Transaction = types.Transaction

// Block represents a blockchain block.
type Block = types.Block

// Receipt represents a transaction receipt.
type Receipt = types.Receipt

// Log represents an event log entry.
type Log = types.Log

// BlockHeader represents a block header (without transactions).
type BlockHeader = types.BlockHeader

// =============================================================================
// Type Aliases - Client Types
// =============================================================================

// Client represents a connection to a Quantaureum node.
type Client = client.Client

// CallMsg represents a message call.
type CallMsg = client.CallMsg

// FilterQuery represents a filter query for logs.
type FilterQuery = client.FilterQuery

// Subscription represents an event subscription.
type Subscription = client.Subscription

// =============================================================================
// Type Aliases - Account Types
// =============================================================================

// Account represents a blockchain account with a private key and derived address.
type Account = accounts.Account

// =============================================================================
// Type Aliases - Contract Types
// =============================================================================

// ABI represents a contract's Application Binary Interface.
type ABI = contracts.ABI

// BoundContract represents a contract bound to a specific address.
type BoundContract = contracts.BoundContract

// CallOpts represents options for a contract call.
type CallOpts = contracts.CallOpts

// TransactOpts represents options for a contract transaction.
type TransactOpts = contracts.TransactOpts

// Method represents a contract method (function).
type Method = contracts.Method

// Event represents a contract event.
type Event = contracts.Event

// Argument represents a function argument or return value.
type Argument = contracts.Argument

// ContractBackend combines ContractCaller and ContractTransactor.
type ContractBackend = contracts.ContractBackend

// ContractCaller defines the interface for read-only contract calls.
type ContractCaller = contracts.ContractCaller

// ContractTransactor defines the interface for sending transactions.
type ContractTransactor = contracts.ContractTransactor

// =============================================================================
// Type Aliases - Error Types
// =============================================================================

// RPCError represents an error returned from an RPC call.
type RPCError = errors.RPCError

// TransactionError represents an error related to a transaction.
type TransactionError = errors.TransactionError

// ValidationError represents a validation error for input parameters.
type ValidationError = errors.ValidationError

// =============================================================================
// Common Type Constructors
// =============================================================================

// BytesToAddress converts a byte slice to an Address.
func BytesToAddress(b []byte) Address {
	return common.BytesToAddress(b)
}

// HexToAddress converts a hex string to an Address.
func HexToAddress(s string) Address {
	return common.HexToAddress(s)
}

// BytesToHash converts a byte slice to a Hash.
func BytesToHash(b []byte) Hash {
	return common.BytesToHash(b)
}

// HexToHash converts a hex string to a Hash.
func HexToHash(s string) Hash {
	return common.HexToHash(s)
}

// EmptyAddress returns an empty (zero) address.
func EmptyAddress() Address {
	return common.EmptyAddress()
}

// EmptyHash returns an empty (zero) hash.
func EmptyHash() Hash {
	return common.EmptyHash()
}

// =============================================================================
// Client Functions
// =============================================================================

// NewClient creates a new client connected to the given URL.
func NewClient(url string, opts ...ClientOption) (*Client, error) {
	return client.NewClient(url, opts...)
}

// ClientOption is a function that configures a Client.
type ClientOption = client.ClientOption

// WithTimeout returns a ClientOption that sets the default timeout for requests.
func WithTimeout(timeout time.Duration) ClientOption {
	return client.WithTimeout(timeout)
}

// =============================================================================
// Account Functions
// =============================================================================

// NewAccount creates a new account with a randomly generated private key.
func NewAccount() (*Account, error) {
	return accounts.NewAccount()
}

// NewAccountFromPrivateKeyHex creates an account from a hex-encoded private key.
func NewAccountFromPrivateKeyHex(hexKey string) (*Account, error) {
	return accounts.NewAccountFromPrivateKeyHex(hexKey)
}

// NewAccountFromPrivateKeyBytes creates an account from raw private key bytes.
func NewAccountFromPrivateKeyBytes(keyBytes []byte) (*Account, error) {
	return accounts.NewAccountFromPrivateKeyBytes(keyBytes)
}

// NewAccountFromMnemonic creates an account from a mnemonic phrase.
// audit-fix GO-CRIT-2: Changed default derivation path from Ethereum's
// m/44'/60'/0'/0/0 to Quantaureum's registered SLIP-44 path m/44'/1668'/0'/0/0.
// Using coin type 60 meant keys were identical to Ethereum wallets.
func NewAccountFromMnemonic(mnemonic string) (*Account, error) {
	return accounts.NewAccountFromMnemonic(mnemonic)
}

// NewAccountFromMnemonicWithPath creates an account from a mnemonic phrase
// using a custom derivation path.
func NewAccountFromMnemonicWithPath(mnemonic string, path string) (*Account, error) {
	return accounts.NewAccountFromMnemonicWithPath(mnemonic, path)
}

// NewAccountFromMnemonicWithPassword creates an account from a mnemonic phrase
// with a password (passphrase) for additional security.
func NewAccountFromMnemonicWithPassword(mnemonic string, password string) (*Account, error) {
	return accounts.NewAccountFromMnemonicWithPassword(mnemonic, password)
}

// GenerateMnemonic generates a new random mnemonic phrase.
// The bitSize should be 128 (12 words), 160 (15 words), 192 (18 words),
// 224 (21 words), or 256 (24 words).
func GenerateMnemonic(bitSize int) (string, error) {
	return accounts.GenerateMnemonic(bitSize)
}

// GenerateMnemonic12 generates a new 12-word mnemonic phrase.
func GenerateMnemonic12() (string, error) {
	return accounts.GenerateMnemonic12()
}

// GenerateMnemonic24 generates a new 24-word mnemonic phrase.
func GenerateMnemonic24() (string, error) {
	return accounts.GenerateMnemonic24()
}

// ValidateMnemonic checks if a mnemonic phrase is valid.
func ValidateMnemonic(mnemonic string) bool {
	return accounts.ValidateMnemonic(mnemonic)
}

// SignMessage signs a message with the given account.
// The message is prefixed with "\x19Ethereum Signed Message:\n" + len(message)
// before hashing and signing (EIP-191 personal_sign format).
func SignMessage(account *Account, message []byte) ([]byte, error) {
	return account.SignMessage(message)
}

// VerifySignature verifies that a signature was created by the given address.
func VerifySignature(address Address, message []byte, signature []byte) bool {
	return accounts.VerifySignature(address, message, signature)
}

// SignTransaction signs a transaction with the given account.
// The chainID is used for EIP-155 replay protection.
func SignTransaction(account *Account, tx *Transaction, chainID *big.Int) (*Transaction, error) {
	signedTx, err := account.SignTransactionGeneric(tx, chainID)
	if err != nil {
		return nil, err
	}
	return signedTx.(*Transaction), nil
}

// RecoverAddress recovers the signer's address from a hash and signature.
func RecoverAddress(hash []byte, signature []byte) (Address, error) {
	return accounts.RecoverAddress(hash, signature)
}

// RecoverTransactionSigner recovers the signer's address from a signed transaction.
func RecoverTransactionSigner(tx *Transaction, chainID *big.Int) (Address, error) {
	return accounts.RecoverTransactionSigner(tx, chainID)
}

// =============================================================================
// Transaction Functions
// =============================================================================

// NewTransaction creates a new unsigned transaction.
func NewTransaction(nonce uint64, to *Address, value *big.Int, gas uint64, gasPrice *big.Int, data []byte) *Transaction {
	return types.NewTransaction(nonce, to, value, gas, gasPrice, data)
}

// NewContractCreation creates a new contract creation transaction.
func NewContractCreation(nonce uint64, value *big.Int, gas uint64, gasPrice *big.Int, data []byte) *Transaction {
	return types.NewContractCreation(nonce, value, gas, gasPrice, data)
}

// =============================================================================
// Contract Functions
// =============================================================================

// ParseABI parses an ABI from JSON bytes.
func ParseABI(data []byte) (ABI, error) {
	return contracts.ParseABI(data)
}

// JSON parses an ABI from a JSON string.
func JSON(reader string) (ABI, error) {
	return contracts.JSON(reader)
}

// NewBoundContract creates a new bound contract instance.
func NewBoundContract(address Address, abi ABI, backend ContractBackend) *BoundContract {
	return contracts.NewBoundContract(address, abi, backend)
}

// NewBoundContractCaller creates a bound contract for read-only operations.
func NewBoundContractCaller(address Address, abi ABI, caller ContractCaller) *BoundContract {
	return contracts.NewBoundContractCaller(address, abi, caller)
}

// NewBoundContractTransactor creates a bound contract for write operations.
func NewBoundContractTransactor(address Address, abi ABI, transactor ContractTransactor) *BoundContract {
	return contracts.NewBoundContractTransactor(address, abi, transactor)
}

// DeployContract deploys a new contract.
func DeployContract(opts *TransactOpts, abi ABI, bytecode []byte, backend ContractBackend, params ...any) (Address, *Transaction, *BoundContract, error) {
	return contracts.DeployContract(opts, abi, bytecode, backend, params...)
}

// CreateAddress calculates the contract address from sender and nonce.
func CreateAddress(sender Address, nonce uint64) Address {
	return contracts.CreateAddress(sender, nonce)
}

// WaitMined waits for a transaction to be mined.
func WaitMined(ctx context.Context, backend interface {
	TransactionReceipt(ctx context.Context, hash Hash) (*Receipt, error)
}, txHash Hash) (*Receipt, error) {
	return contracts.WaitMined(ctx, backend, txHash)
}

// WaitDeployed waits for a contract deployment transaction to be mined.
func WaitDeployed(ctx context.Context, backend interface {
	TransactionReceipt(ctx context.Context, hash Hash) (*Receipt, error)
}, tx *Transaction) (Address, error) {
	return contracts.WaitDeployed(ctx, backend, tx)
}

// =============================================================================
// Utility Functions - Unit Conversion
// =============================================================================

// ToWei converts an ether string value to wei.
func ToWei(value string, decimals int) (*big.Int, error) {
	return utils.ToWei(value, decimals)
}

// FromWei converts wei to an ether string value.
func FromWei(wei *big.Int, decimals int) string {
	return utils.FromWei(wei, decimals)
}

// ParseUnits is an alias for ToWei for compatibility.
func ParseUnits(value string, decimals int) (*big.Int, error) {
	return utils.ParseUnits(value, decimals)
}

// FormatUnits is an alias for FromWei for compatibility.
func FormatUnits(wei *big.Int, decimals int) string {
	return utils.FormatUnits(wei, decimals)
}

// EtherToWei converts ether string to wei (18 decimals).
func EtherToWei(ether string) (*big.Int, error) {
	return utils.EtherToWei(ether)
}

// WeiToEther converts wei to ether string (18 decimals).
func WeiToEther(wei *big.Int) string {
	return utils.WeiToEther(wei)
}

// GWeiToWei converts gwei string to wei (9 decimals).
func GWeiToWei(gwei string) (*big.Int, error) {
	return utils.GWeiToWei(gwei)
}

// WeiToGWei converts wei to gwei string (9 decimals).
func WeiToGWei(wei *big.Int) string {
	return utils.WeiToGWei(wei)
}

// =============================================================================
// Utility Functions - Hex Conversion
// =============================================================================

// BytesToHex converts a byte slice to a hex string with 0x prefix.
func BytesToHex(b []byte) string {
	return utils.BytesToHex(b)
}

// HexToBytes converts a hex string to a byte slice.
func HexToBytes(s string) ([]byte, error) {
	return utils.HexToBytes(s)
}

// Has0xPrefix checks if a string has the 0x or 0X prefix.
func Has0xPrefix(s string) bool {
	return utils.Has0xPrefix(s)
}

// Add0xPrefix adds the 0x prefix to a hex string if not already present.
func Add0xPrefix(s string) string {
	return utils.Add0xPrefix(s)
}

// Remove0xPrefix removes the 0x or 0X prefix from a hex string if present.
func Remove0xPrefix(s string) string {
	return utils.Remove0xPrefix(s)
}

// IsValidHex checks if a string is a valid hex string.
func IsValidHex(s string) bool {
	return utils.IsValidHex(s)
}

// =============================================================================
// Utility Functions - Hash
// =============================================================================

// Keccak256 calculates the Keccak-256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	return utils.Keccak256(data...)
}

// Keccak256Hash calculates the Keccak-256 hash and returns it as a Hash.
func Keccak256Hash(data ...[]byte) Hash {
	return utils.Keccak256Hash(data...)
}

// Keccak256Hex calculates the Keccak-256 hash and returns it as a hex string.
func Keccak256Hex(data ...[]byte) string {
	return utils.Keccak256Hex(data...)
}

// =============================================================================
// Utility Functions - Address
// =============================================================================

// IsValidAddress checks if a string is a valid Ethereum-style address.
func IsValidAddress(s string) bool {
	return utils.IsValidAddress(s)
}

// ChecksumAddress returns the EIP-55 checksummed version of an address.
func ChecksumAddress(addr string) string {
	return utils.ChecksumAddress(addr)
}

// IsChecksumAddress checks if an address has valid EIP-55 checksum.
func IsChecksumAddress(addr string) bool {
	return utils.IsChecksumAddress(addr)
}

// AddressFromHex converts a hex string to an Address.
func AddressFromHex(s string) Address {
	return utils.AddressFromHex(s)
}

// =============================================================================
// Error Variables
// =============================================================================

var (
	// ErrInvalidAddress indicates an invalid address format.
	ErrInvalidAddress = errors.ErrInvalidAddress

	// ErrInvalidPrivateKey indicates an invalid private key.
	ErrInvalidPrivateKey = errors.ErrInvalidPrivateKey

	// ErrInvalidMnemonic indicates an invalid mnemonic phrase.
	ErrInvalidMnemonic = errors.ErrInvalidMnemonic

	// ErrInvalidHex indicates an invalid hex string.
	ErrInvalidHex = errors.ErrInvalidHex

	// ErrNilPointer indicates a nil pointer was provided where not allowed.
	ErrNilPointer = errors.ErrNilPointer

	// ErrInvalidSignature indicates an invalid signature.
	ErrInvalidSignature = errors.ErrInvalidSignature

	// ErrConnectionFailed indicates a connection failure.
	ErrConnectionFailed = errors.ErrConnectionFailed

	// ErrTimeout indicates a timeout occurred.
	ErrTimeout = errors.ErrTimeout

	// ErrInvalidChainID indicates an invalid chain ID.
	ErrInvalidChainID = errors.ErrInvalidChainID

	// ErrInsufficientFunds indicates insufficient funds for a transaction.
	ErrInsufficientFunds = errors.ErrInsufficientFunds

	// ErrNonceTooLow indicates the nonce is too low.
	ErrNonceTooLow = errors.ErrNonceTooLow

	// ErrGasTooLow indicates the gas limit is too low.
	ErrGasTooLow = errors.ErrGasTooLow

	// ErrTransactionAlreadyKnown indicates the transaction is already in the pool.
	ErrTransactionAlreadyKnown = errors.ErrTransactionAlreadyKnown

	// ErrReplacementUnderpriced indicates a replacement transaction has insufficient gas price.
	ErrReplacementUnderpriced = errors.ErrReplacementUnderpriced

	// ErrExecutionReverted indicates the transaction execution was reverted.
	ErrExecutionReverted = errors.ErrExecutionReverted
)

// =============================================================================
// Error Constructors
// =============================================================================

// NewRPCError creates a new RPCError.
func NewRPCError(code int, message string, data any) *RPCError {
	return errors.NewRPCError(code, message, data)
}

// NewTransactionError creates a new TransactionError.
func NewTransactionError(txHash string, revertReason string, err error) *TransactionError {
	return errors.NewTransactionError(txHash, revertReason, err)
}

// NewValidationError creates a new ValidationError.
func NewValidationError(field string, message string) *ValidationError {
	return errors.NewValidationError(field, message)
}

// =============================================================================
// Constants
// =============================================================================

const (
	// AddressLength is the expected length of an address in bytes.
	AddressLength = common.AddressLength

	// HashLength is the expected length of a hash in bytes.
	HashLength = common.HashLength

	// DefaultDerivationPath is the default BIP-44 derivation path for Quantaureum.
	DefaultDerivationPath = accounts.DefaultDerivationPath
)

// Unit multipliers
var (
	// Wei is the smallest unit (1).
	Wei = utils.Wei

	// GWei is 10^9 wei.
	GWei = utils.GWei

	// Ether is 10^18 wei.
	Ether = utils.Ether
)
