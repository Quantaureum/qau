// Quantaureum Node source, version 1.0.0.
package rollup

import (
	"fmt"
	"math/big"
	"time"

	"github.com/quantaureum/qau/types"
)

const (
	DefaultMaxBatchSize           = 1000
	DefaultMaxBatchBytes          = 128 * 1024
	DefaultBlockTime              = 2 * time.Second
	DefaultChallengePeriod        = 7 * 24 * time.Hour
	DefaultMaxTxPerBatch          = 500
	DefaultMinTxPerBatch          = 1
	DefaultBatchSubmissionTimeout = 10 * time.Minute

	// W-P0-4 FIX (2026-07-13): L1ChainID must point to Quantaureum mainnet
	// (1668), not Ethereum mainnet (1). L2 ChainID (1670) is distinct from
	// all L1 chain IDs (1668/1669/1333) to avoid cross-chain replay.
	// These are also added to the wallet's ALLOWED_CHAIN_IDS in a separate
	// wallet-side change.
	DefaultL1ChainID = 1668
	DefaultL2ChainID = 1670

	// W-P1-5 FIX (2026-07-13): How often finalizeLoop scans Submitted batches
	// for automatic finalization. Kept independent from BlockTime so the
	// finalize scan does not need to fire on every L2 block tick — once per
	// ~30s is enough because the challenge period is on the order of hours
	// or days, not seconds.
	DefaultFinalizeCheckInterval = 30 * time.Second

	// W-P1-7 (2026-07-15): Number of consecutive batch cycles the current
	// sequencer can miss before the next sequencer takes over (failover).
	// At the default 2s block time, 3 cycles = 6s before failover triggers.
	// Set to 0 to disable failover (current sequencer must produce or the
	// chain stalls until the next epoch).
	DefaultSequencerTimeout = 3
)

type RollupConfig struct {
	ChainID                uint64
	MaxBatchSize           int
	MaxBatchBytes          int64
	BlockTime              time.Duration
	ChallengePeriod        time.Duration
	MaxTxPerBatch          int
	MinTxPerBatch          int
	BatchSubmissionTimeout time.Duration
	L1ChainID              uint64
	L1BridgeAddress        types.Address
	// W-P1-6 Phase 4 (2026-07-14): Address of the on-chain QASM L1Bridge
	// contract (deployed from contracts/L1Bridge.qasm). When set, the node
	// can sync finalized state roots to the on-chain contract via
	// EncodeRecordFinalizedBatch. When zero, only the local bboltL1Bridge
	// is used (development mode).
	L1BridgeContractAddress types.Address
	BatchInboxAddress       types.Address
	GenesisStateRoot        types.Hash
	BaseFee                 *big.Int
	GasLimit                uint64
	// W-P1-5 (2026-07-13): Interval at which finalizeLoop scans Submitted
	// batches. Zero means use DefaultFinalizeCheckInterval.
	FinalizeCheckInterval time.Duration
	// W-P1-7 (2026-07-15): Number of consecutive batch cycles the current
	// sequencer can miss before the next sequencer takes over. Zero means
	// use DefaultSequencerTimeout. Only effective when a SequencerElector
	// is configured (SetSequencerElector called).
	SequencerTimeout uint64
	// RLLP- (2026-07-16): L2 bridge address that users send withdrawal
	// transactions to (tx.To == BridgeAddress && tx.Value > 0). When set,
	// processBatchLocked BURNS the withdrawal value from L2 supply (deducts
	// from sender without crediting the bridge account) instead of treating
	// it as a normal transfer. This maintains the L2 supply invariant:
	// every L1 release corresponds 1:1 to an L2 burn, preventing double-
	// spending. When zero (default), withdrawal txs are handled as normal
	// transfers (legacy/development mode — NOT safe for production bridges).
	BridgeAddress types.Address
}

func DefaultRollupConfig() *RollupConfig {
	return &RollupConfig{
		ChainID:                DefaultL2ChainID, // W-P0-4 FIX: 1670, not 42069
		MaxBatchSize:           DefaultMaxBatchSize,
		MaxBatchBytes:          DefaultMaxBatchBytes,
		BlockTime:              DefaultBlockTime,
		ChallengePeriod:        DefaultChallengePeriod,
		MaxTxPerBatch:          DefaultMaxTxPerBatch,
		MinTxPerBatch:          DefaultMinTxPerBatch,
		BatchSubmissionTimeout: DefaultBatchSubmissionTimeout,
		L1ChainID:              DefaultL1ChainID, // W-P0-4 FIX: 1668, not 1
		BaseFee:                big.NewInt(1e9),
		GasLimit:               30_000_000,
		FinalizeCheckInterval:  DefaultFinalizeCheckInterval,
		SequencerTimeout:       DefaultSequencerTimeout,
	}
}

func (c *RollupConfig) Validate() error {
	if c.ChainID == 0 {
		return ErrInvalidChainID
	}
	// W-P0-4 FIX: L2 ChainID must differ from L1 ChainID to prevent
	// cross-chain replay of signed L2 transactions on L1 (and vice versa).
	if c.ChainID == c.L1ChainID {
		return ErrInvalidChainID
	}
	if c.L1ChainID == 0 {
		return ErrInvalidChainID
	}
	if c.MaxBatchSize <= 0 {
		return ErrInvalidBatchSize
	}
	if c.BlockTime <= 0 {
		return ErrInvalidBlockTime
	}
	if c.ChallengePeriod <= 0 {
		return ErrInvalidChallengePeriod
	}
	// RLLP-FIX: Reject ChallengePeriod/BlockTime combinations that
	// would require more than maxStateHistoryEntries in-memory snapshots.
	// Operators needing longer challenge windows must enable disk persistence
	// (W-P1-3) rather than relying on the in-memory ring buffer.
	//
	// Test fast-path exemption: BlockTime < 1s indicates a test configuration
	// using accelerated block times. In that case the ceiling is not enforced
	// (computeStateHistoryEntries still clamps to maxStateHistoryEntries, so
	// memory stays bounded — the test simply won't get full coverage of the
	// challenge window, which is acceptable for unit tests).
	if c.BlockTime >= time.Second {
		needed := int(float64(c.ChallengePeriod)/float64(c.BlockTime)*stateHistorySafetyMargin + 0.999)
		if needed > maxStateHistoryEntries {
			return fmt.Errorf("challenge period %v with block time %v requires %d in-memory snapshots, exceeds max %d — enable Persistence (W-P1-3) or shorten challenge period",
				c.ChallengePeriod, c.BlockTime, needed, maxStateHistoryEntries)
		}
	}
	if c.GasLimit == 0 {
		return ErrInvalidGasLimit
	}
	return nil
}
