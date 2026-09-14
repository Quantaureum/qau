// Quantaureum Node source, version 1.0.0.
// Package params defines the chain configuration parameters for Quantaureum.
package params

import (
	"fmt"
	"math/big"
)

// Chain IDs for different networks
const (
	MainnetChainID = 1668 // Mainnet
	TestnetChainID = 1669 // Testnet
	DevnetChainID  = 1333 // Development network
)

// Network IDs (same as Chain IDs for Quantaureum)
const (
	MainnetNetworkID = MainnetChainID
	TestnetNetworkID = TestnetChainID
	DevnetNetworkID  = DevnetChainID
)

// Block parameters
const (
	BlockGasLimit = 30000000        // Maximum gas per block
	BlockTime     = 12              // audit-fix HIGH-BLOCKTIME: match consensus.SlotDuration (12s)
	BlockReward   = 2e18            // Block reward in wei (2 QAU)
	MaxBlockSize  = 5 * 1024 * 1024 // Maximum block size (5MB)
)

// Transaction parameters
const (
	MinGasPrice      = 1000000000   // Minimum gas price (1 Gwei)
	MaxGasPrice      = 500000000000 // Maximum gas price (500 Gwei)
	TxGas            = 21000        // Gas for a standard transfer
	TxDataZeroGas    = 4            // Gas per zero byte of data
	TxDataNonZeroGas = 16           // Gas per non-zero byte of data
)

// EIP-1559 Dynamic Fee Market parameters
const (
	InitialBaseFee        = 1000000000   // Initial base fee (1 Gwei)
	BaseFeeMaxChangeDenom = 8            // Max base fee change per block (1/8 = 12.5%)
	ElasticityMultiplier  = 2            // Block gas target = GasLimit / ElasticityMultiplier
	MinPriorityFee        = 1000000000   // Minimum priority fee (1 Gwei)
	MaxPriorityFee        = 500000000000 // Maximum priority fee (500 Gwei)
)

// Staking parameters
const (
	MinValidatorStake = 32 // Minimum stake to become validator (QAU) - 32g gold ≈ $2,720
	MinDelegatorStake = 1  // Minimum stake for delegation (QAU) - 1g gold ≈ $85
	UnbondingPeriod   = 21 // Unbonding period in days
	SlashingPenalty   = 10 // Slashing penalty percentage
)

// Consensus parameters
const (
	ValidatorSetSize  = 100 // Maximum number of active validators
	EpochLength       = 32  // Blocks per epoch
	FinalityThreshold = 67  // 2/3 + 1 for BFT finality (percentage)
)

// P2P network parameters
const (
	MaxPeers       = 50   // Maximum number of peers
	DefaultP2PPort = 9000 // Default P2P port
	DefaultRPCPort = 8545 // Default RPC port
	DefaultWSPort  = 8546 // Default WebSocket port
)

// Token parameters
var (
	TotalSupply = new(big.Int).Mul(big.NewInt(20000000), big.NewInt(1e18)) // 20M QAU
	Decimals    = 18
	Symbol      = "QAU"
	Name        = "Quantaureum"
)

// Version info
const (
	VersionMajor = 1
	VersionMinor = 0
	VersionPatch = 0
	VersionMeta  = "stable"
)

// Version returns the version string
func Version() string {
	return fmt.Sprintf("%d.%d.%d-%s", VersionMajor, VersionMinor, VersionPatch, VersionMeta)
}
