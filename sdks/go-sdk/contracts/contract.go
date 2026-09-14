// Quantaureum Go SDK source, version 1.0.0.
// Package contracts provides smart contract interaction functionality for the Quantaureum Go SDK.
package contracts

import (
	"context"
	"fmt"
	"math/big"

	"github.com/quantaureum/qau/sdks/go-sdk/common"
	"github.com/quantaureum/qau/sdks/go-sdk/errors"
	"github.com/quantaureum/qau/sdks/go-sdk/types"
	"golang.org/x/crypto/sha3"
)

// ContractCaller defines the interface for read-only contract calls.
type ContractCaller interface {
	// Call executes a message call transaction.
	Call(ctx context.Context, msg CallMsg, blockNumber any) ([]byte, error)
	// CodeAt returns the code at the given address.
	CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error)
}

// ContractTransactor defines the interface for sending transactions.
type ContractTransactor interface {
	// PendingNonceAt returns the pending nonce for the given address.
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
	// SuggestGasPrice returns the suggested gas price.
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
	// EstimateGas estimates the gas needed for a transaction.
	EstimateGas(ctx context.Context, msg CallMsg) (uint64, error)
	// SendTransaction sends a signed transaction.
	SendTransaction(ctx context.Context, tx *types.Transaction) (common.Hash, error)
}

// ContractBackend combines ContractCaller and ContractTransactor.
type ContractBackend interface {
	ContractCaller
	ContractTransactor
}

// CallMsg represents a message call.
type CallMsg struct {
	From     common.Address  // Sender address (optional for calls)
	To       *common.Address // Recipient address
	Gas      uint64          // Gas limit
	GasPrice *big.Int        // Gas price
	Value    *big.Int        // Value in wei
	Data     []byte          // Call data
}

// CallOpts represents options for a contract call.
type CallOpts struct {
	Pending     bool            // Whether to use pending state
	From        common.Address  // Sender address (optional)
	BlockNumber *big.Int        // Block number (nil = latest)
	Context     context.Context // Context for the call
}

// TransactOpts represents options for a contract transaction.
type TransactOpts struct {
	From     common.Address                                                       // Sender address
	Nonce    *big.Int                                                             // Nonce (nil = auto)
	Signer   func(common.Address, *types.Transaction) (*types.Transaction, error) // Signer function
	Value    *big.Int                                                             // Value in wei
	GasPrice *big.Int                                                             // Gas price (nil = auto)
	GasLimit uint64                                                               // Gas limit (0 = auto)
	Context  context.Context                                                      // Context for the transaction
	NoSend   bool                                                                 // Don't send, just return signed tx
}

// BoundContract represents a contract bound to a specific address.
type BoundContract struct {
	address    common.Address
	abi        ABI
	caller     ContractCaller
	transactor ContractTransactor
}

// NewBoundContract creates a new bound contract instance.
func NewBoundContract(address common.Address, abi ABI, backend ContractBackend) *BoundContract {
	return &BoundContract{
		address:    address,
		abi:        abi,
		caller:     backend,
		transactor: backend,
	}
}

// NewBoundContractCaller creates a bound contract for read-only operations.
func NewBoundContractCaller(address common.Address, abi ABI, caller ContractCaller) *BoundContract {
	return &BoundContract{
		address: address,
		abi:     abi,
		caller:  caller,
	}
}

// NewBoundContractTransactor creates a bound contract for write operations.
func NewBoundContractTransactor(address common.Address, abi ABI, transactor ContractTransactor) *BoundContract {
	return &BoundContract{
		address:    address,
		abi:        abi,
		transactor: transactor,
	}
}

// Address returns the contract address.
func (c *BoundContract) Address() common.Address {
	return c.address
}

// ABI returns the contract ABI.
func (c *BoundContract) ABI() ABI {
	return c.abi
}

// Call executes a read-only contract method call.
func (c *BoundContract) Call(opts *CallOpts, results *[]any, method string, params ...any) error {
	if c.caller == nil {
		return errors.NewValidationError("caller", "contract caller not set")
	}

	// Pack the method call
	input, err := c.abi.Pack(method, params...)
	if err != nil {
		return fmt.Errorf("failed to pack method call: %w", err)
	}

	// Build call message
	msg := CallMsg{
		To:   &c.address,
		Data: input,
	}

	if opts != nil {
		msg.From = opts.From
	}

	// Determine context
	ctx := context.Background()
	if opts != nil && opts.Context != nil {
		ctx = opts.Context
	}

	// Determine block number
	var blockNumber any
	if opts != nil {
		if opts.Pending {
			blockNumber = "pending"
		} else if opts.BlockNumber != nil {
			blockNumber = opts.BlockNumber
		}
	}

	// Execute call
	output, err := c.caller.Call(ctx, msg, blockNumber)
	if err != nil {
		return fmt.Errorf("contract call failed: %w", err)
	}

	// Unpack results
	if results != nil && len(output) > 0 {
		unpacked, err := c.abi.Unpack(method, output)
		if err != nil {
			return fmt.Errorf("failed to unpack results: %w", err)
		}
		*results = unpacked
	}

	return nil
}

// CallRaw executes a raw contract call and returns the raw output.
func (c *BoundContract) CallRaw(opts *CallOpts, input []byte) ([]byte, error) {
	if c.caller == nil {
		return nil, errors.NewValidationError("caller", "contract caller not set")
	}

	msg := CallMsg{
		To:   &c.address,
		Data: input,
	}

	if opts != nil {
		msg.From = opts.From
	}

	ctx := context.Background()
	if opts != nil && opts.Context != nil {
		ctx = opts.Context
	}

	var blockNumber any
	if opts != nil {
		if opts.Pending {
			blockNumber = "pending"
		} else if opts.BlockNumber != nil {
			blockNumber = opts.BlockNumber
		}
	}

	return c.caller.Call(ctx, msg, blockNumber)
}

// Transact executes a contract method that modifies state.
func (c *BoundContract) Transact(opts *TransactOpts, method string, params ...any) (*types.Transaction, error) {
	if c.transactor == nil {
		return nil, errors.NewValidationError("transactor", "contract transactor not set")
	}

	if opts == nil {
		return nil, errors.NewValidationError("opts", "transaction options required")
	}

	if opts.Signer == nil {
		return nil, errors.NewValidationError("signer", "signer function required")
	}

	// Pack the method call
	input, err := c.abi.Pack(method, params...)
	if err != nil {
		return nil, fmt.Errorf("failed to pack method call: %w", err)
	}

	return c.transactRaw(opts, input)
}

// TransactRaw executes a raw transaction with the given input data.
func (c *BoundContract) TransactRaw(opts *TransactOpts, input []byte) (*types.Transaction, error) {
	if c.transactor == nil {
		return nil, errors.NewValidationError("transactor", "contract transactor not set")
	}

	if opts == nil {
		return nil, errors.NewValidationError("opts", "transaction options required")
	}

	if opts.Signer == nil {
		return nil, errors.NewValidationError("signer", "signer function required")
	}

	return c.transactRaw(opts, input)
}

// transactRaw is the internal implementation for sending transactions.
func (c *BoundContract) transactRaw(opts *TransactOpts, input []byte) (*types.Transaction, error) {
	ctx := context.Background()
	if opts.Context != nil {
		ctx = opts.Context
	}

	// Get nonce
	var nonce uint64
	if opts.Nonce != nil {
		nonce = opts.Nonce.Uint64()
	} else {
		pendingNonce, err := c.transactor.PendingNonceAt(ctx, opts.From)
		if err != nil {
			return nil, fmt.Errorf("failed to get nonce: %w", err)
		}
		nonce = pendingNonce
	}

	// Get gas price
	gasPrice := opts.GasPrice
	if gasPrice == nil {
		suggestedPrice, err := c.transactor.SuggestGasPrice(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get gas price: %w", err)
		}
		gasPrice = suggestedPrice
	}

	// Get gas limit
	gasLimit := opts.GasLimit
	if gasLimit == 0 {
		msg := CallMsg{
			From:     opts.From,
			To:       &c.address,
			GasPrice: gasPrice,
			Value:    opts.Value,
			Data:     input,
		}
		estimated, err := c.transactor.EstimateGas(ctx, msg)
		if err != nil {
			return nil, fmt.Errorf("failed to estimate gas: %w", err)
		}
		// Add 20% buffer to estimated gas
		gasLimit = estimated * 120 / 100
	}

	// Create transaction
	value := opts.Value
	if value == nil {
		value = new(big.Int)
	}

	tx := types.NewTransaction(nonce, &c.address, value, gasLimit, gasPrice, input)

	// Sign transaction
	signedTx, err := opts.Signer(opts.From, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Send transaction (unless NoSend is set)
	if !opts.NoSend {
		_, err = c.transactor.SendTransaction(ctx, signedTx)
		if err != nil {
			return nil, fmt.Errorf("failed to send transaction: %w", err)
		}
	}

	return signedTx, nil
}

// Transfer sends ETH/native tokens to the contract.
func (c *BoundContract) Transfer(opts *TransactOpts) (*types.Transaction, error) {
	if c.transactor == nil {
		return nil, errors.NewValidationError("transactor", "contract transactor not set")
	}

	if opts == nil {
		return nil, errors.NewValidationError("opts", "transaction options required")
	}

	if opts.Signer == nil {
		return nil, errors.NewValidationError("signer", "signer function required")
	}

	return c.transactRaw(opts, nil)
}

// DeployContract deploys a new contract.
func DeployContract(opts *TransactOpts, abi ABI, bytecode []byte, backend ContractBackend, params ...any) (common.Address, *types.Transaction, *BoundContract, error) {
	if opts == nil {
		return common.Address{}, nil, nil, errors.NewValidationError("opts", "transaction options required")
	}

	if opts.Signer == nil {
		return common.Address{}, nil, nil, errors.NewValidationError("signer", "signer function required")
	}

	if len(bytecode) == 0 {
		return common.Address{}, nil, nil, errors.NewValidationError("bytecode", "bytecode cannot be empty")
	}

	// Pack constructor arguments
	var input []byte
	if len(params) > 0 {
		constructorArgs, err := abi.PackConstructor(params...)
		if err != nil {
			return common.Address{}, nil, nil, fmt.Errorf("failed to pack constructor: %w", err)
		}
		input = append(bytecode, constructorArgs...)
	} else {
		input = bytecode
	}

	ctx := context.Background()
	if opts.Context != nil {
		ctx = opts.Context
	}

	// Get nonce
	var nonce uint64
	if opts.Nonce != nil {
		nonce = opts.Nonce.Uint64()
	} else {
		pendingNonce, err := backend.PendingNonceAt(ctx, opts.From)
		if err != nil {
			return common.Address{}, nil, nil, fmt.Errorf("failed to get nonce: %w", err)
		}
		nonce = pendingNonce
	}

	// Get gas price
	gasPrice := opts.GasPrice
	if gasPrice == nil {
		suggestedPrice, err := backend.SuggestGasPrice(ctx)
		if err != nil {
			return common.Address{}, nil, nil, fmt.Errorf("failed to get gas price: %w", err)
		}
		gasPrice = suggestedPrice
	}

	// Get gas limit
	gasLimit := opts.GasLimit
	if gasLimit == 0 {
		msg := CallMsg{
			From:     opts.From,
			GasPrice: gasPrice,
			Value:    opts.Value,
			Data:     input,
		}
		estimated, err := backend.EstimateGas(ctx, msg)
		if err != nil {
			return common.Address{}, nil, nil, fmt.Errorf("failed to estimate gas: %w", err)
		}
		// Add 20% buffer
		gasLimit = estimated * 120 / 100
	}

	// Create contract creation transaction
	value := opts.Value
	if value == nil {
		value = new(big.Int)
	}

	tx := types.NewContractCreation(nonce, value, gasLimit, gasPrice, input)

	// Sign transaction
	signedTx, err := opts.Signer(opts.From, tx)
	if err != nil {
		return common.Address{}, nil, nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Calculate contract address
	contractAddr := CreateAddress(opts.From, nonce)

	// Send transaction (unless NoSend is set)
	if !opts.NoSend {
		_, err = backend.SendTransaction(ctx, signedTx)
		if err != nil {
			return common.Address{}, nil, nil, fmt.Errorf("failed to send transaction: %w", err)
		}
	}

	// Create bound contract
	contract := NewBoundContract(contractAddr, abi, backend)

	return contractAddr, signedTx, contract, nil
}

// CreateAddress calculates the contract address from sender and nonce.
// This follows the CREATE opcode address derivation.
func CreateAddress(sender common.Address, nonce uint64) common.Address {
	// RLP encode [sender, nonce]
	var data []byte

	// Encode sender (20 bytes)
	senderBytes := sender.Bytes()
	data = append(data, byte(0x80+len(senderBytes)))
	data = append(data, senderBytes...)

	// Encode nonce
	if nonce == 0 {
		data = append(data, 0x80)
	} else if nonce < 128 {
		data = append(data, byte(nonce))
	} else {
		nonceBytes := encodeNonceBytes(nonce)
		data = append(data, byte(0x80+len(nonceBytes)))
		data = append(data, nonceBytes...)
	}

	// Create list header
	listLen := len(data)
	var header []byte
	if listLen < 56 {
		header = []byte{byte(0xC0 + listLen)}
	} else {
		lenBytes := encodeNonceBytes(uint64(listLen))
		header = append([]byte{byte(0xF7 + len(lenBytes))}, lenBytes...)
	}

	// Hash the RLP-encoded data
	rlpData := append(header, data...)
	hash := keccak256Hash(rlpData)

	return common.BytesToAddress(hash[12:])
}

// encodeNonceBytes encodes a nonce as big-endian bytes.
func encodeNonceBytes(n uint64) []byte {
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte(n & 0xff)}, buf...)
		n >>= 8
	}
	return buf
}

// keccak256Hash computes the Keccak-256 hash.
func keccak256Hash(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

// WaitMined waits for a transaction to be mined.
// This is a helper function that polls for the transaction receipt.
func WaitMined(ctx context.Context, backend interface {
	TransactionReceipt(ctx context.Context, hash common.Hash) (*types.Receipt, error)
}, txHash common.Hash) (*types.Receipt, error) {
	for {
		receipt, err := backend.TransactionReceipt(ctx, txHash)
		if err == nil && receipt != nil {
			return receipt, nil
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			// Continue polling
		}
	}
}

// WaitDeployed waits for a contract deployment transaction to be mined
// and returns the contract address.
func WaitDeployed(ctx context.Context, backend interface {
	TransactionReceipt(ctx context.Context, hash common.Hash) (*types.Receipt, error)
}, tx *types.Transaction) (common.Address, error) {
	if !tx.IsContractCreation() {
		return common.Address{}, errors.NewValidationError("tx", "not a contract creation transaction")
	}

	receipt, err := WaitMined(ctx, backend, tx.Hash())
	if err != nil {
		return common.Address{}, err
	}

	if receipt.ContractAddress == nil {
		return common.Address{}, errors.NewValidationError("receipt", "contract address not found in receipt")
	}

	return *receipt.ContractAddress, nil
}
