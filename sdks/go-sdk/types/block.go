// Quantaureum Go SDK source, version 1.0.0.
// Package types provides core blockchain types for the Quantaureum Go SDK.
package types

import (
	"math/big"

	"github.com/quantaureum/qau/sdks/go-sdk/common"
)

// Block represents a blockchain block.
type Block struct {
	Number          *big.Int       // Block number
	Hash            common.Hash    // Block hash
	ParentHash      common.Hash    // Parent block hash
	Nonce           uint64         // Block nonce
	Miner           common.Address // Miner/validator address
	Difficulty      *big.Int       // Block difficulty
	TotalDifficulty *big.Int       // Total chain difficulty
	ExtraData       []byte         // Extra data field
	Size            uint64         // Block size in bytes
	GasLimit        uint64         // Gas limit
	GasUsed         uint64         // Gas used
	Timestamp       uint64         // Block timestamp (Unix)
	Transactions    []*Transaction // Transactions in the block
	Uncles          []common.Hash  // Uncle block hashes

	// State roots
	StateRoot        common.Hash // State trie root
	TransactionsRoot common.Hash // Transactions trie root
	ReceiptsRoot     common.Hash // Receipts trie root
	LogsBloom        []byte      // Bloom filter for logs
}

// NewBlock creates a new block with the given parameters.
func NewBlock(number *big.Int, hash, parentHash common.Hash, timestamp uint64) *Block {
	return &Block{
		Number:     number,
		Hash:       hash,
		ParentHash: parentHash,
		Timestamp:  timestamp,
	}
}

// GetNumber returns the block number.
func (b *Block) GetNumber() *big.Int {
	if b.Number == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(b.Number)
}

// GetHash returns the block hash.
func (b *Block) GetHash() common.Hash {
	return b.Hash
}

// GetParentHash returns the parent block hash.
func (b *Block) GetParentHash() common.Hash {
	return b.ParentHash
}

// GetTimestamp returns the block timestamp.
func (b *Block) GetTimestamp() uint64 {
	return b.Timestamp
}

// GetGasLimit returns the gas limit.
func (b *Block) GetGasLimit() uint64 {
	return b.GasLimit
}

// GetGasUsed returns the gas used.
func (b *Block) GetGasUsed() uint64 {
	return b.GasUsed
}

// GetMiner returns the miner/validator address.
func (b *Block) GetMiner() common.Address {
	return b.Miner
}

// GetDifficulty returns the block difficulty.
func (b *Block) GetDifficulty() *big.Int {
	if b.Difficulty == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(b.Difficulty)
}

// GetTransactions returns the transactions in the block.
func (b *Block) GetTransactions() []*Transaction {
	return b.Transactions
}

// TransactionCount returns the number of transactions in the block.
func (b *Block) TransactionCount() int {
	return len(b.Transactions)
}

// Transaction returns the transaction at the given index.
func (b *Block) Transaction(index int) *Transaction {
	if index < 0 || index >= len(b.Transactions) {
		return nil
	}
	return b.Transactions[index]
}

// Receipt represents a transaction receipt.
type Receipt struct {
	TxHash            common.Hash     // Transaction hash
	TxIndex           uint            // Transaction index in block
	BlockHash         common.Hash     // Block hash
	BlockNumber       *big.Int        // Block number
	From              common.Address  // Sender address
	To                *common.Address // Recipient address (nil for contract creation)
	CumulativeGasUsed uint64          // Cumulative gas used in block
	GasUsed           uint64          // Gas used by this transaction
	ContractAddress   *common.Address // Contract address (if contract creation)
	Logs              []*Log          // Event logs
	LogsBloom         []byte          // Bloom filter for logs
	Status            uint64          // Transaction status (1 = success, 0 = failure)

	// EIP-2718 fields
	Type uint8 // Transaction type
}

// NewReceipt creates a new receipt with the given parameters.
func NewReceipt(txHash common.Hash, status uint64, gasUsed uint64) *Receipt {
	return &Receipt{
		TxHash:  txHash,
		Status:  status,
		GasUsed: gasUsed,
	}
}

// GetTxHash returns the transaction hash.
func (r *Receipt) GetTxHash() common.Hash {
	return r.TxHash
}

// GetBlockHash returns the block hash.
func (r *Receipt) GetBlockHash() common.Hash {
	return r.BlockHash
}

// GetBlockNumber returns the block number.
func (r *Receipt) GetBlockNumber() *big.Int {
	if r.BlockNumber == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(r.BlockNumber)
}

// GetStatus returns the transaction status.
func (r *Receipt) GetStatus() uint64 {
	return r.Status
}

// IsSuccess returns true if the transaction was successful.
func (r *Receipt) IsSuccess() bool {
	return r.Status == 1
}

// GetGasUsed returns the gas used.
func (r *Receipt) GetGasUsed() uint64 {
	return r.GasUsed
}

// GetContractAddress returns the contract address (if contract creation).
func (r *Receipt) GetContractAddress() *common.Address {
	return r.ContractAddress
}

// GetLogs returns the event logs.
func (r *Receipt) GetLogs() []*Log {
	return r.Logs
}

// LogCount returns the number of logs.
func (r *Receipt) LogCount() int {
	return len(r.Logs)
}

// Log represents an event log entry.
type Log struct {
	Address     common.Address // Contract address that emitted the log
	Topics      []common.Hash  // Indexed event parameters
	Data        []byte         // Non-indexed event parameters
	BlockNumber uint64         // Block number
	TxHash      common.Hash    // Transaction hash
	TxIndex     uint           // Transaction index in block
	BlockHash   common.Hash    // Block hash
	Index       uint           // Log index in block
	Removed     bool           // True if log was removed due to chain reorg
}

// NewLog creates a new log with the given parameters.
func NewLog(address common.Address, topics []common.Hash, data []byte) *Log {
	return &Log{
		Address: address,
		Topics:  topics,
		Data:    data,
	}
}

// GetAddress returns the contract address.
func (l *Log) GetAddress() common.Address {
	return l.Address
}

// GetTopics returns the indexed event parameters.
func (l *Log) GetTopics() []common.Hash {
	return l.Topics
}

// GetData returns the non-indexed event parameters.
func (l *Log) GetData() []byte {
	return l.Data
}

// GetBlockNumber returns the block number.
func (l *Log) GetBlockNumber() uint64 {
	return l.BlockNumber
}

// GetTxHash returns the transaction hash.
func (l *Log) GetTxHash() common.Hash {
	return l.TxHash
}

// GetIndex returns the log index in the block.
func (l *Log) GetIndex() uint {
	return l.Index
}

// IsRemoved returns true if the log was removed due to chain reorg.
func (l *Log) IsRemoved() bool {
	return l.Removed
}

// TopicCount returns the number of topics.
func (l *Log) TopicCount() int {
	return len(l.Topics)
}

// Topic returns the topic at the given index.
func (l *Log) Topic(index int) common.Hash {
	if index < 0 || index >= len(l.Topics) {
		return common.Hash{}
	}
	return l.Topics[index]
}

// BlockHeader represents a block header (without transactions).
type BlockHeader struct {
	Number           *big.Int       // Block number
	Hash             common.Hash    // Block hash
	ParentHash       common.Hash    // Parent block hash
	Nonce            uint64         // Block nonce
	Miner            common.Address // Miner/validator address
	Difficulty       *big.Int       // Block difficulty
	TotalDifficulty  *big.Int       // Total chain difficulty
	ExtraData        []byte         // Extra data field
	Size             uint64         // Block size in bytes
	GasLimit         uint64         // Gas limit
	GasUsed          uint64         // Gas used
	Timestamp        uint64         // Block timestamp (Unix)
	StateRoot        common.Hash    // State trie root
	TransactionsRoot common.Hash    // Transactions trie root
	ReceiptsRoot     common.Hash    // Receipts trie root
	LogsBloom        []byte         // Bloom filter for logs
}

// NewBlockHeader creates a new block header.
func NewBlockHeader(number *big.Int, hash, parentHash common.Hash, timestamp uint64) *BlockHeader {
	return &BlockHeader{
		Number:     number,
		Hash:       hash,
		ParentHash: parentHash,
		Timestamp:  timestamp,
	}
}

// GetNumber returns the block number.
func (h *BlockHeader) GetNumber() *big.Int {
	if h.Number == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(h.Number)
}

// GetHash returns the block hash.
func (h *BlockHeader) GetHash() common.Hash {
	return h.Hash
}

// GetParentHash returns the parent block hash.
func (h *BlockHeader) GetParentHash() common.Hash {
	return h.ParentHash
}

// GetTimestamp returns the block timestamp.
func (h *BlockHeader) GetTimestamp() uint64 {
	return h.Timestamp
}
