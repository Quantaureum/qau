// Quantaureum Node source, version 1.0.0.
package graphql

import (
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
	"golang.org/x/crypto/sha3"
)

// Errors returned by the resolver.
var (
	ErrBlockNotFound       = errors.New("block not found")
	ErrAccountNotFound     = errors.New("account not found")
	ErrTransactionNotFound = errors.New("transaction not found")
	ErrReceiptNotFound     = errors.New("receipt not found")
	ErrInvalidFilter       = errors.New("invalid filter")
	ErrPaginationLimit     = errors.New("pagination limit exceeded")
)

// Security constants for GraphQL resolver
// #nosec audit-remediation: GraphQL security limits
const (
	// MaxPaginationLimit is the maximum number of items per page
	MaxPaginationLimit = 100

	// DefaultPaginationLimit is the default number of items per page
	DefaultPaginationLimit = 25

	// MaxBlockRange is the maximum block range for queries
	MaxBlockRange = 1000

	// MaxDepthLimit is the maximum query depth
	MaxDepthLimit = 10

	// MaxComplexityLimit is the maximum query complexity
	MaxComplexityLimit = 100

	// R36-P2-RPC-03 FIX: MaxLogsResult caps the number of logs returned by a
	// single Logs resolver query. Without this, a log-heavy contract over the
	// 1000-block range can accumulate hundreds of thousands of *Log objects,
	// exhausting memory/CPU. Truncate and warn when exceeded (unlike the RPC
	// layer which errors) to keep GraphQL responses partial-but-useful.
	MaxLogsResult = 1000
)

// BlockchainReader provides read access to blockchain data.
type BlockchainReader interface {
	// Block retrieval
	GetBlockByNumber(number uint64) (*encoding.Block, error)
	GetBlockByHash(hash types.Hash) (*encoding.Block, error)
	GetLatestBlock() (*encoding.Block, error)
	GetBlockRange(from, to uint64) ([]*encoding.Block, error)

	// Account retrieval
	GetAccount(address types.Address, blockNumber uint64) (*AccountState, error)

	// Transaction retrieval
	GetTransaction(hash types.Hash) (*encoding.Transaction, *TxLocation, error)
	GetTransactionReceipt(hash types.Hash) (*Receipt, error)

	// Chain info
	ChainID() uint64
	GasPrice() *big.Int
	CurrentBlockNumber() uint64
}

// AccountState represents the state of an account at a specific block.
type AccountState struct {
	Address     types.Address
	Balance     *big.Int
	Nonce       uint64
	Code        []byte
	CodeHash    types.Hash
	StorageRoot types.Hash
}

// TxLocation contains the location of a transaction in a block.
type TxLocation struct {
	BlockHash   types.Hash
	BlockNumber uint64
	Index       uint64
}

// Resolver implements GraphQL query resolution.
type Resolver struct {
	chain   BlockchainReader
	chainID uint64
	mu      sync.RWMutex
}

// NewResolver creates a new GraphQL resolver.
func NewResolver(chain BlockchainReader) *Resolver {
	return &Resolver{
		chain:   chain,
		chainID: chain.ChainID(),
	}
}

// Block resolves a block query by number or hash.
func (r *Resolver) Block(number *uint64, hash *types.Hash) (*Block, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var block *encoding.Block
	var err error

	if hash != nil {
		block, err = r.chain.GetBlockByHash(*hash)
	} else if number != nil {
		block, err = r.chain.GetBlockByNumber(*number)
	} else {
		block, err = r.chain.GetLatestBlock()
	}

	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, ErrBlockNotFound
	}

	return r.convertBlock(block), nil
}

// Blocks resolves a blocks query with optional filter.
func (r *Resolver) Blocks(filter *BlockFilter) ([]*Block, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var from, to uint64
	currentBlock := r.chain.CurrentBlockNumber()

	if filter != nil {
		if filter.FromBlock != nil {
			from = *filter.FromBlock
		}
		if filter.ToBlock != nil {
			to = *filter.ToBlock
		} else {
			to = currentBlock
		}
	} else {
		// Default: return last 10 blocks
		to = currentBlock
		if to >= 10 {
			from = to - 9
		}
	}

	if from > to {
		return nil, ErrInvalidFilter
	}

	// Security: enforce MaxBlockRange to prevent DoS via large range queries
	if to-from > MaxBlockRange {
		return nil, fmt.Errorf("%w: block range %d exceeds maximum %d", ErrInvalidFilter, to-from, MaxBlockRange)
	}

	blocks, err := r.chain.GetBlockRange(from, to)
	if err != nil {
		return nil, err
	}

	result := make([]*Block, len(blocks))
	for i, b := range blocks {
		result[i] = r.convertBlock(b)
	}

	return result, nil
}

// LatestBlock resolves the latest block query.
func (r *Resolver) LatestBlock() (*Block, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	block, err := r.chain.GetLatestBlock()
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, ErrBlockNotFound
	}

	return r.convertBlock(block), nil
}

// Account resolves an account query.
func (r *Resolver) Account(address types.Address, blockNumber *uint64) (*Account, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var bn uint64
	if blockNumber != nil {
		bn = *blockNumber
	} else {
		bn = r.chain.CurrentBlockNumber()
	}

	state, err := r.chain.GetAccount(address, bn)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, ErrAccountNotFound
	}

	return r.convertAccount(state), nil
}

// Accounts resolves multiple account queries.
func (r *Resolver) Accounts(addresses []types.Address, blockNumber *uint64) ([]*Account, error) {
	// Security: enforce pagination limit to prevent DoS via large batch queries
	if len(addresses) > MaxPaginationLimit {
		return nil, fmt.Errorf("%w: requested %d addresses exceeds maximum %d", ErrPaginationLimit, len(addresses), MaxPaginationLimit)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	var bn uint64
	if blockNumber != nil {
		bn = *blockNumber
	} else {
		bn = r.chain.CurrentBlockNumber()
	}

	result := make([]*Account, 0, len(addresses))
	for _, addr := range addresses {
		state, err := r.chain.GetAccount(addr, bn)
		if err != nil {
			continue // Skip accounts that can't be found
		}
		if state != nil {
			result = append(result, r.convertAccount(state))
		}
	}

	return result, nil
}

// Transaction resolves a transaction query by hash.
func (r *Resolver) Transaction(hash types.Hash) (*Transaction, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tx, loc, err := r.chain.GetTransaction(hash)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, ErrTransactionNotFound
	}

	return r.convertTransaction(tx, loc), nil
}

// Transactions resolves a transactions query with filter.
func (r *Resolver) Transactions(filter *TransactionFilter) ([]*Transaction, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var from, to uint64
	currentBlock := r.chain.CurrentBlockNumber()

	if filter != nil {
		if filter.FromBlock != nil {
			from = *filter.FromBlock
		}
		if filter.ToBlock != nil {
			to = *filter.ToBlock
		} else {
			to = currentBlock
		}
	} else {
		to = currentBlock
		if to >= 10 {
			from = to - 9
		}
	}

	if from > to {
		return nil, ErrInvalidFilter
	}

	// Security: enforce MaxBlockRange to prevent DoS via large range queries
	if to-from > MaxBlockRange {
		return nil, fmt.Errorf("%w: block range %d exceeds maximum %d", ErrInvalidFilter, to-from, MaxBlockRange)
	}

	blocks, err := r.chain.GetBlockRange(from, to)
	if err != nil {
		return nil, err
	}

	var result []*Transaction
	for _, block := range blocks {
		if block == nil || block.Header == nil {
			continue
		}
		for i, tx := range block.Transactions {
			if !r.matchesTransactionFilter(tx, filter) {
				continue
			}

			idx := uint64(i) //nolint:gosec,G115
			loc := &TxLocation{
				BlockHash:   computeBlockHash(block),
				BlockNumber: block.Header.Height,
				Index:       idx,
			}
			result = append(result, r.convertTransaction(tx, loc))

			// audit-fix P5-M9: Cap result count to prevent memory exhaustion.
			// Even with MaxBlockRange, 1000 blocks * ~200 txs/block = 200K txs
			// could exhaust memory. Stop collecting once we hit the pagination limit.
			if len(result) >= MaxPaginationLimit {
				return result, nil
			}
		}
	}

	return result, nil
}

// matchesTransactionFilter checks if a transaction matches the filter criteria.
func (r *Resolver) matchesTransactionFilter(tx *encoding.Transaction, filter *TransactionFilter) bool {
	if filter == nil {
		return true
	}

	// Filter by from address
	if filter.FromAddress != nil && tx.From != *filter.FromAddress {
		return false
	}

	// Filter by to address
	if filter.ToAddress != nil {
		if tx.To == nil || *tx.To != *filter.ToAddress {
			return false
		}
	}

	// Filter by value range
	if filter.MinValue != nil && tx.Value != nil {
		if tx.Value.Cmp(filter.MinValue) < 0 {
			return false
		}
	}
	if filter.MaxValue != nil && tx.Value != nil {
		if tx.Value.Cmp(filter.MaxValue) > 0 {
			return false
		}
	}

	return true
}

// Receipt resolves a receipt query by transaction hash.
func (r *Resolver) Receipt(hash types.Hash) (*Receipt, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	receipt, err := r.chain.GetTransactionReceipt(hash)
	if err != nil {
		return nil, err
	}
	if receipt == nil {
		return nil, ErrReceiptNotFound
	}

	return receipt, nil
}

// Logs resolves a logs query with filter.
func (r *Resolver) Logs(filter *LogFilter) ([]*Log, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if filter == nil {
		return nil, ErrInvalidFilter
	}

	var from, to uint64
	currentBlock := r.chain.CurrentBlockNumber()

	if filter.FromBlock != nil {
		from = *filter.FromBlock
	}
	if filter.ToBlock != nil {
		to = *filter.ToBlock
	} else {
		to = currentBlock
	}

	if from > to {
		return nil, ErrInvalidFilter
	}

	// Security: enforce MaxBlockRange to prevent DoS via large range queries
	if to-from > MaxBlockRange {
		return nil, fmt.Errorf("%w: block range %d exceeds maximum %d", ErrInvalidFilter, to-from, MaxBlockRange)
	}

	blocks, err := r.chain.GetBlockRange(from, to)
	if err != nil {
		return nil, err
	}

	var result []*Log
	truncated := false
	for _, block := range blocks {
		if block == nil || block.Header == nil {
			continue
		}
		for txIdx, tx := range block.Transactions {
			receipt, err := r.chain.GetTransactionReceipt(tx.Hash())
			if err != nil || receipt == nil {
				continue
			}

			for _, log := range receipt.Logs {
				if r.matchesLogFilter(log, filter) {
					// R36-P2-RPC-03 FIX: stop accumulating once we hit the
					// result cap to bound memory/CPU. Set truncated flag and
					// break out of all loops.
					if len(result) >= MaxLogsResult {
						truncated = true
						break
					}
					logCopy := *log
					logCopy.BlockNumber = block.Header.Height
					logCopy.TxHash = tx.Hash()
					logCopy.TxIndex = uint64(txIdx) //nolint:gosec,G115
					result = append(result, &logCopy)
				}
			}
			if truncated {
				break
			}
		}
		if truncated {
			break
		}
	}
	if truncated {
		log.Printf("[SECURITY] GraphQL Logs resolver truncated result to MaxLogsResult=%d; narrow block range or filter criteria", MaxLogsResult)
	}

	return result, nil
}

// matchesLogFilter checks if a log matches the filter criteria.
func (r *Resolver) matchesLogFilter(log *Log, filter *LogFilter) bool {
	if filter == nil {
		return true
	}

	// Filter by addresses
	if len(filter.Addresses) > 0 {
		found := false
		for _, addr := range filter.Addresses {
			if log.Address == addr {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Filter by topics
	if len(filter.Topics) > 0 {
		for i, topicFilter := range filter.Topics {
			if len(topicFilter) == 0 {
				continue // Wildcard
			}
			if i >= len(log.Topics) {
				return false
			}
			found := false
			for _, topic := range topicFilter {
				if log.Topics[i] == topic {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	return true
}

// ChainID returns the chain ID.
func (r *Resolver) ChainID() uint64 {
	return r.chainID
}

// GasPrice returns the current gas price.
func (r *Resolver) GasPrice() *big.Int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.chain.GasPrice()
}

// BlockNumber returns the current block number.
func (r *Resolver) BlockNumber() uint64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.chain.CurrentBlockNumber()
}

// convertBlock converts an encoding.Block to a GraphQL Block.
func (r *Resolver) convertBlock(block *encoding.Block) *Block {
	if block == nil || block.Header == nil {
		return nil
	}

	txs := make([]*Transaction, len(block.Transactions))
	var gasUsed uint64
	blockHash := computeBlockHash(block)

	for i, tx := range block.Transactions {
		idx := uint64(i) //nolint:gosec,G115
		loc := &TxLocation{
			BlockHash:   blockHash,
			BlockNumber: block.Header.Height,
			Index:       idx,
		}
		txs[i] = r.convertTransaction(tx, loc)

		receipt, err := r.chain.GetTransactionReceipt(tx.Hash())
		if err == nil && receipt != nil {
			gasUsed += receipt.GasUsed
		} else {
			gasUsed += tx.GasLimit
		}
	}

	return &Block{
		Number:       block.Header.Height,
		Hash:         blockHash,
		ParentHash:   block.Header.ParentHash,
		Timestamp:    block.Header.Timestamp,
		StateRoot:    block.Header.StateRoot,
		TxRoot:       block.Header.TxRoot,
		ReceiptRoot:  block.Header.ReceiptRoot,
		Proposer:     block.Header.ProposerAddr,
		Transactions: txs,
		TxCount:      len(block.Transactions),
		GasUsed:      gasUsed,
		GasLimit:     30000000, // Default block gas limit
	}
}

// convertTransaction converts an encoding.Transaction to a GraphQL Transaction.
func (r *Resolver) convertTransaction(tx *encoding.Transaction, loc *TxLocation) *Transaction {
	if tx == nil {
		return nil
	}

	result := &Transaction{
		Hash:     tx.Hash(),
		From:     tx.From,
		To:       tx.To,
		Value:    tx.Value,
		GasLimit: tx.GasLimit,
		GasPrice: tx.GasPrice,
		Nonce:    tx.Nonce,
		Data:     tx.Data,
	}

	if loc != nil {
		result.BlockNumber = &loc.BlockNumber
		result.BlockHash = &loc.BlockHash
		result.Index = &loc.Index
	}

	return result
}

// convertAccount converts an AccountState to a GraphQL Account.
func (r *Resolver) convertAccount(state *AccountState) *Account {
	if state == nil {
		return nil
	}

	return &Account{
		Address:     state.Address,
		Balance:     state.Balance,
		Nonce:       state.Nonce,
		Code:        state.Code,
		CodeHash:    state.CodeHash,
		StorageRoot: state.StorageRoot,
	}
}

// computeBlockHash computes the hash of a block.
func computeBlockHash(block *encoding.Block) types.Hash {
	if block == nil || block.Header == nil {
		return types.Hash{}
	}
	data, err := encoding.MarshalBlockHeader(block.Header)
	if err != nil {
		return types.Hash{}
	}
	return types.BytesToHash(simpleHash(data))
}

// simpleHash computes the SHA3-256 hash of the input data.
// audit-fix L-16: replaced weak XOR hash with cryptographically secure SHA3-256.
func simpleHash(data []byte) []byte {
	h := sha3.Sum256(data)
	return h[:]
}
