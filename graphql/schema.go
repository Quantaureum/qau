// Quantaureum Node source, version 1.0.0.
// Package graphql provides a GraphQL API for querying blockchain data.
package graphql

import (
	"math/big"

	"github.com/quantaureum/qau/types"
)

// Block represents a GraphQL Block type with complete block information.
type Block struct {
	Number       uint64         `json:"number"`
	Hash         types.Hash     `json:"hash"`
	ParentHash   types.Hash     `json:"parentHash"`
	Timestamp    int64          `json:"timestamp"`
	StateRoot    types.Hash     `json:"stateRoot"`
	TxRoot       types.Hash     `json:"txRoot"`
	ReceiptRoot  types.Hash     `json:"receiptRoot"`
	Proposer     types.Address  `json:"proposer"`
	Transactions []*Transaction `json:"transactions"`
	TxCount      int            `json:"txCount"`
	GasUsed      uint64         `json:"gasUsed"`
	GasLimit     uint64         `json:"gasLimit"`
}

// Account represents a GraphQL Account type with account state information.
type Account struct {
	Address     types.Address `json:"address"`
	Balance     *big.Int      `json:"balance"`
	Nonce       uint64        `json:"nonce"`
	Code        []byte        `json:"code"`
	CodeHash    types.Hash    `json:"codeHash"`
	StorageRoot types.Hash    `json:"storageRoot"`
}

// Transaction represents a GraphQL Transaction type with transaction details.
type Transaction struct {
	Hash        types.Hash     `json:"hash"`
	BlockNumber *uint64        `json:"blockNumber"`
	BlockHash   *types.Hash    `json:"blockHash"`
	Index       *uint64        `json:"index"`
	From        types.Address  `json:"from"`
	To          *types.Address `json:"to"`
	Value       *big.Int       `json:"value"`
	GasLimit    uint64         `json:"gasLimit"`
	GasPrice    *big.Int       `json:"gasPrice"`
	GasUsed     *uint64        `json:"gasUsed"`
	Nonce       uint64         `json:"nonce"`
	Data        []byte         `json:"data"`
	Status      *uint64        `json:"status"`
}

// Log represents a log entry from a transaction receipt.
type Log struct {
	Address     types.Address `json:"address"`
	Topics      []types.Hash  `json:"topics"`
	Data        []byte        `json:"data"`
	BlockNumber uint64        `json:"blockNumber"`
	TxHash      types.Hash    `json:"txHash"`
	TxIndex     uint64        `json:"txIndex"`
	LogIndex    uint64        `json:"logIndex"`
}

// Receipt represents a transaction receipt.
type Receipt struct {
	TxHash            types.Hash     `json:"txHash"`
	BlockHash         types.Hash     `json:"blockHash"`
	BlockNumber       uint64         `json:"blockNumber"`
	TxIndex           uint64         `json:"txIndex"`
	From              types.Address  `json:"from"`
	To                *types.Address `json:"to"`
	GasUsed           uint64         `json:"gasUsed"`
	CumulativeGasUsed uint64         `json:"cumulativeGasUsed"`
	Status            uint64         `json:"status"`
	Logs              []*Log         `json:"logs"`
	ContractAddress   *types.Address `json:"contractAddress"`
}

// BlockFilter defines filter criteria for block queries.
type BlockFilter struct {
	FromBlock *uint64 `json:"fromBlock"`
	ToBlock   *uint64 `json:"toBlock"`
}

// TransactionFilter defines filter criteria for transaction queries.
type TransactionFilter struct {
	FromAddress *types.Address `json:"fromAddress"`
	ToAddress   *types.Address `json:"toAddress"`
	FromBlock   *uint64        `json:"fromBlock"`
	ToBlock     *uint64        `json:"toBlock"`
	MinValue    *big.Int       `json:"minValue"`
	MaxValue    *big.Int       `json:"maxValue"`
}

// LogFilter defines filter criteria for log queries.
type LogFilter struct {
	Addresses []types.Address `json:"addresses"`
	Topics    [][]types.Hash  `json:"topics"`
	FromBlock *uint64         `json:"fromBlock"`
	ToBlock   *uint64         `json:"toBlock"`
}

// Query represents the root GraphQL Query type.
type Query struct {
	// Block queries
	Block       func(number *uint64, hash *types.Hash) (*Block, error)
	Blocks      func(filter *BlockFilter) ([]*Block, error)
	LatestBlock func() (*Block, error)

	// Account queries
	Account  func(address types.Address, blockNumber *uint64) (*Account, error)
	Accounts func(addresses []types.Address, blockNumber *uint64) ([]*Account, error)

	// Transaction queries
	Transaction  func(hash types.Hash) (*Transaction, error)
	Transactions func(filter *TransactionFilter) ([]*Transaction, error)

	// Receipt queries
	Receipt func(hash types.Hash) (*Receipt, error)

	// Log queries
	Logs func(filter *LogFilter) ([]*Log, error)

	// Chain info
	ChainID     func() uint64
	GasPrice    func() *big.Int
	BlockNumber func() uint64
}

// Schema represents the GraphQL schema definition.
type Schema struct {
	Query Query
}

// NewSchema creates a new GraphQL schema with the given resolver.
func NewSchema(resolver *Resolver) *Schema {
	return &Schema{
		Query: Query{
			Block:        resolver.Block,
			Blocks:       resolver.Blocks,
			LatestBlock:  resolver.LatestBlock,
			Account:      resolver.Account,
			Accounts:     resolver.Accounts,
			Transaction:  resolver.Transaction,
			Transactions: resolver.Transactions,
			Receipt:      resolver.Receipt,
			Logs:         resolver.Logs,
			ChainID:      resolver.ChainID,
			GasPrice:     resolver.GasPrice,
			BlockNumber:  resolver.BlockNumber,
		},
	}
}

// SchemaDefinition returns the GraphQL schema definition string.
func SchemaDefinition() string {
	return `
type Query {
	block(number: Int, hash: String): Block
	blocks(fromBlock: Int, toBlock: Int): [Block!]!
	latestBlock: Block
	account(address: String!, blockNumber: Int): Account
	accounts(addresses: [String!]!, blockNumber: Int): [Account!]!
	transaction(hash: String!): Transaction
	transactions(filter: TransactionFilter): [Transaction!]!
	receipt(hash: String!): Receipt
	logs(filter: LogFilter!): [Log!]!
	chainId: Int!
	gasPrice: String!
	blockNumber: Int!
}

type Block {
	number: Int!
	hash: String!
	parentHash: String!
	timestamp: Int!
	stateRoot: String!
	txRoot: String!
	receiptRoot: String!
	proposer: String!
	transactions: [Transaction!]!
	txCount: Int!
	gasUsed: Int!
	gasLimit: Int!
}

type Account {
	address: String!
	balance: String!
	nonce: Int!
	code: String
	codeHash: String!
	storageRoot: String!
}

type Transaction {
	hash: String!
	blockNumber: Int
	blockHash: String
	index: Int
	from: String!
	to: String
	value: String!
	gasLimit: Int!
	gasPrice: String!
	gasUsed: Int
	nonce: Int!
	data: String!
	status: Int
}

type Receipt {
	txHash: String!
	blockHash: String!
	blockNumber: Int!
	txIndex: Int!
	from: String!
	to: String
	gasUsed: Int!
	cumulativeGasUsed: Int!
	status: Int!
	logs: [Log!]!
	contractAddress: String
}

type Log {
	address: String!
	topics: [String!]!
	data: String!
	blockNumber: Int!
	txHash: String!
	txIndex: Int!
	logIndex: Int!
}

input TransactionFilter {
	fromAddress: String
	toAddress: String
	fromBlock: Int
	toBlock: Int
	minValue: String
	maxValue: String
}

input LogFilter {
	addresses: [String!]
	topics: [[String!]]
	fromBlock: Int
	toBlock: Int
}
`
}
