// Quantaureum Node source, version 1.0.0.
package miner

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quantaureum/qau/consensus"
	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

// Miner errors
var (
	ErrMinerRunning  = errors.New("miner already running")
	ErrMinerStopped  = errors.New("miner not running")
	ErrNoParentBlock = errors.New("no parent block available")
)

// BlockChain defines the interface for blockchain operations.
type BlockChain interface {
	// CurrentBlock returns the current head block.
	CurrentBlock() *encoding.Block
	// GetBlockByHash returns a block by its hash.
	GetBlockByHash(hash types.Hash) *encoding.Block
	// InsertBlock inserts a new block into the chain.
	InsertBlock(block *encoding.Block) error
}

// Config holds configuration for the Miner.
type Config struct {
	// GasLimit is the maximum gas allowed per block.
	GasLimit uint64
	// BlockTime is the target time between blocks.
	BlockTime time.Duration
	// MaxTxsPerBlock is the maximum transactions per block.
	MaxTxsPerBlock int
}

// DefaultConfig returns default miner configuration.
func DefaultConfig() Config {
	return Config{
		GasLimit:       8000000,
		BlockTime:      12 * time.Second, // audit-fix HIGH-BLOCKTIME: match consensus.SlotDuration
		MaxTxsPerBlock: 1000,
	}
}

// Miner handles block production for the QAU blockchain.
// TransactionExecutor executes transactions and returns results.
// When set on the Miner, it produces real receipts from actual QVM execution
// instead of placeholder receipts (L6-018/L9-003 fix).
type TransactionExecutor interface {
	Execute(tx *encoding.Transaction) (status uint64, gasUsed uint64, logs []Log, err error)
}

// StateRootComputer computes the state root after transaction execution.
// When set on the Miner, it provides the real StateRoot for block finalization
// (L6-022/L9-004 fix).
type StateRootComputer interface {
	ComputeStateRoot() (types.Hash, error)
}

type Miner struct {
	mu sync.RWMutex

	config Config
	chain  BlockChain
	txPool TxPool
	state  StateReader

	worker  *Worker
	builder *BlockBuilder
	sealer  *Sealer
	// audit-fix L6-018/L9-003: When set, produces real receipts from QVM execution.
	txExecutor TransactionExecutor
	// audit-fix L6-022/L9-004: When set, computes real StateRoot after execution.
	stateRootComputer StateRootComputer

	running int32 // atomic
	stopCh  chan struct{}
	doneCh  chan struct{}

	// Event callbacks
	onBlockMined func(*encoding.Block)
}

// New creates a new Miner instance.
func New(config Config, chain BlockChain, txPool TxPool, state StateReader) *Miner {
	if config.GasLimit == 0 {
		config = DefaultConfig()
	}

	workerConfig := WorkerConfig{
		GasLimit:       config.GasLimit,
		MaxTxsPerBlock: config.MaxTxsPerBlock,
	}

	return &Miner{
		config:  config,
		chain:   chain,
		txPool:  txPool,
		state:   state,
		worker:  NewWorker(txPool, state, workerConfig),
		builder: NewBlockBuilder(1),
		sealer:  NewSealer(),
	}
}

// Start starts the miner.
func (m *Miner) Start() error {
	if !atomic.CompareAndSwapInt32(&m.running, 0, 1) {
		return ErrMinerRunning
	}

	m.stopCh = make(chan struct{})
	m.doneCh = make(chan struct{})

	go m.miningLoop()

	return nil
}

// Stop stops the miner.
func (m *Miner) Stop() error {
	if !atomic.CompareAndSwapInt32(&m.running, 1, 0) {
		return ErrMinerStopped
	}

	close(m.stopCh)
	<-m.doneCh

	return nil
}

// IsRunning returns true if the miner is running.
func (m *Miner) IsRunning() bool {
	return atomic.LoadInt32(&m.running) == 1
}

// SetValidator sets the validator account for block signing.
func (m *Miner) SetValidator(validator Signer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sealer.SetValidator(validator)
}

// SetOnBlockMined sets the callback for when a block is mined.
func (m *Miner) SetOnBlockMined(callback func(*encoding.Block)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onBlockMined = callback
}

// SetGasLimit updates the gas limit for new blocks.
func (m *Miner) SetGasLimit(limit uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config.GasLimit = limit
	m.worker.SetGasLimit(limit)
}

// GasLimit returns the current gas limit.
func (m *Miner) GasLimit() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config.GasLimit
}

// miningLoop is the main mining loop.
// FIX: Sync to consensus slot boundaries instead of using a simple ticker.
// This ensures blocks are produced at the correct slot time, preventing slot
// mismatches that cause blocks to be rejected by other nodes.
func (m *Miner) miningLoop() {
	defer close(m.doneCh)

	for {
		//  Calculate time until the next slot boundary.
		// Each slot is 12 seconds (consensus.SlotDuration). We align mining
		// to the start of each slot to prevent slot/time desync.
		now := time.Now()
		gt := consensus.GetGenesisTime()
		if gt == 0 {
			// Genesis not configured, fall back to simple ticker
			select {
			case <-m.stopCh:
				return
			case <-time.After(m.config.BlockTime):
				m.tryMineBlock()
			}
			continue
		}

		// Calculate the current slot and the start time of the next slot
		elapsed := now.Unix() - gt
		if elapsed < 0 {
			// Clock is before genesis time, wait
			select {
			case <-m.stopCh:
				return
			case <-time.After(time.Duration(-elapsed) * time.Second):
				continue
			}
		}

		slotDuration := int64(consensus.SlotDuration.Seconds())
		currentSlot := uint64(elapsed / slotDuration)
		nextSlotStart := gt + (int64(currentSlot)+1)*slotDuration
		sleepDuration := time.Until(time.Unix(nextSlotStart, 0))

		// Clamp sleep duration to reasonable bounds
		if sleepDuration < 0 {
			sleepDuration = 0
		}
		if sleepDuration > m.config.BlockTime {
			sleepDuration = m.config.BlockTime
		}

		select {
		case <-m.stopCh:
			return
		case <-time.After(sleepDuration):
			m.tryMineBlock()
		}
	}
}

// tryMineBlock attempts to mine a new block.
func (m *Miner) tryMineBlock() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get current block as parent
	parent := m.chain.CurrentBlock()
	if parent == nil || parent.Header == nil {
		return
	}

	// Build new block
	block, err := m.buildBlock(parent)
	if err != nil {
		return
	}

	// Insert block into chain
	if err := m.chain.InsertBlock(block); err != nil {
		return
	}

	// Remove committed transactions from pool
	m.worker.RemoveCommittedFromPool()
	m.worker.Reset()

	// Notify callback
	if m.onBlockMined != nil {
		m.onBlockMined(block)
	}
}

// buildBlock builds a new block based on the parent.
// deterministic transaction ordering implemented via worker.SelectTransactions
func (m *Miner) buildBlock(parent *encoding.Block) (*encoding.Block, error) {
	// Get validator address
	// audit-fix I-2: use accessor method instead of direct field access
	var proposer types.Address
	if validator := m.sealer.GetValidator(); validator != nil {
		proposer = validator.Address()
	}

	// Prepare header
	header, err := m.builder.PrepareHeader(parent.Header, proposer)
	if err != nil {
		return nil, err
	}

	// Select transactions
	txs := m.worker.SelectTransactions(m.config.GasLimit)

	// Commit transactions
	if err := m.worker.CommitTransactions(txs); err != nil {
		return nil, err
	}

	// audit-fix L6-018/L9-003/L9-006 (P0): Generate real receipts from
	// transaction execution. If no TransactionExecutor is set, fail-closed
	// to prevent producing blocks with fake placeholder receipts.
	if m.txExecutor == nil {
		return nil, fmt.Errorf("miner: transaction executor not set; cannot produce real receipts (L6-018 fix)")
	}
	receipts := make([]Receipt, len(txs))
	var gasUsed uint64
	for i, tx := range txs {
		status, gasConsumed, logs, err := m.txExecutor.Execute(tx)
		if err != nil {
			// Transaction execution failed - record as failed receipt
			status = 0
			gasConsumed = tx.GasLimit // charge full gas on execution error
		}
		// audit-fix M-11: overflow-safe gas accumulation
		if gasConsumed > ^uint64(0)-gasUsed {
			gasUsed = ^uint64(0)
		} else {
			gasUsed += gasConsumed
		}
		receipts[i] = Receipt{
			TxHash:        tx.Hash(),
			Status:        status,
			GasUsed:       gasConsumed,
			CumulativeGas: gasUsed,
			Logs:          logs,
		}
	}

	// L10-007 FIX (P1): Compute StateRoot BEFORE FinalizeBlock to eliminate
	// the time window where block has ReceiptRoot but no StateRoot.
	// audit-fix L6-022/L9-004 (P0): Compute real StateRoot after transaction
	// execution. If no StateRootComputer is set, fail-closed.
	if m.stateRootComputer == nil {
		return nil, fmt.Errorf("miner: state root computer not set; cannot compute StateRoot (L6-022 fix)")
	}
	stateRoot, err := m.stateRootComputer.ComputeStateRoot()
	if err != nil {
		return nil, fmt.Errorf("miner: failed to compute state root: %w", err)
	}

	// Finalize block (sets TxRoot and ReceiptRoot atomically)
	block, err := m.builder.FinalizeBlock(header, txs, receipts)
	if err != nil {
		return nil, err
	}

	// Set StateRoot immediately after FinalizeBlock (no time window)
	block.Header.StateRoot = stateRoot

	// Seal block with signature
	return m.sealer.SealBlock(block)
}

// MineBlockSync mines a single block synchronously.
// This is useful for testing.
func (m *Miner) MineBlockSync() (*encoding.Block, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	parent := m.chain.CurrentBlock()
	if parent == nil || parent.Header == nil {
		return nil, ErrNoParentBlock
	}

	block, err := m.buildBlock(parent)
	if err != nil {
		return nil, err
	}

	if err := m.chain.InsertBlock(block); err != nil {
		return nil, err
	}

	m.worker.RemoveCommittedFromPool()
	m.worker.Reset()

	return block, nil
}

// PendingBlock returns the current pending block being built.
func (m *Miner) PendingBlock() *encoding.Block {
	m.mu.RLock()
	defer m.mu.RUnlock()

	parent := m.chain.CurrentBlock()
	if parent == nil || parent.Header == nil {
		return nil
	}

	// audit-fix I-2: use accessor method instead of direct field access
	var proposer types.Address
	if validator := m.sealer.GetValidator(); validator != nil {
		proposer = validator.Address()
	}

	header, err := m.builder.PrepareHeader(parent.Header, proposer)
	if err != nil {
		return nil
	}

	txs := m.worker.PendingTransactions()

	return &encoding.Block{
		Header:       header,
		Transactions: txs,
	}
}
