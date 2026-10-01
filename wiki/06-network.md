# 06 - L3 Network + Economics Layer — `p2p/` `economics/`

## 6.1 `p2p/` — Quantum-Secure Networking

| File | Key Exports | Responsibility |
|------|---------|------|
| [p2p/host.go](../p2p/host.go) | `Host`, `NewHost`, `Start/Stop`, `Connect` | libp2p host lifecycle |
| [p2p/protocol.go](../p2p/protocol.go) | `Protocol`, `HandleStream` | Peer protocol (handshake/messages) |
| [p2p/message.go](../p2p/message.go) | `Message`, `Encode/Decode` | Network message wrapper |
| [p2p/broadcast.go](../p2p/broadcast.go) | `Broadcast`, `BroadcastTx/Block` | gossipsub broadcast of transactions/blocks |
| [p2p/connpool.go](../p2p/connpool.go) | `ConnPool` | Connection management |
| [p2p/mtls.go](../p2p/mtls.go) | `mTLS` | Mutual TLS encrypted transport |
| [p2p/crypto.go](../p2p/crypto.go) | `Crypto` | Network-layer encryption (incl. quantum keys) |
| [p2p/snap_sync.go](../p2p/snap_sync.go) | `SnapSync` | Snapshot synchronization |
| [p2p/das_protocol.go](../p2p/das_protocol.go) | `DASProtocol` | DA sampling protocol |
| [p2p/ratelimit.go](../p2p/ratelimit.go) | `RateLimit` | Peer rate limiting |
| [p2p/peer_score.go](../p2p/peer_score.go) | `PeerScore` | Peer reputation |
| [p2p/penalty.go](../p2p/penalty.go) | `Penalty` | Penalty mechanism |
| [p2p/bloom.go](../p2p/bloom.go) | `BloomFilter` | Transaction-dedup Bloom filter |
| [p2p/compact_block.go](../p2p/compact_block.go) | `CompactBlock` | Compact blocks (only transmit missing parts) |
| [p2p/compact_tx.go](../p2p/compact_tx.go) | `CompactTx` | Compact transactions |
| [p2p/compress.go](../p2p/compress.go) | `Compress` | Compressed transport |

### 6.1.1 Key Features

- **gossipsub broadcast**: transactions/blocks are propagated over gossipsub topics via `broadcast.go`.
- **mTLS encrypted transport**: `mtls.go` ensures data between peers is encrypted, preventing eavesdropping/tampering.
- **Compact blocks/transactions**: `compact_block.go` / `compact_tx.go` — only transmit the transactions the
  peer is missing, significantly reducing bandwidth (analogous to Bitcoin Compact Blocks).
- **Peer reputation**: `peer_score.go` + `penalty.go` penalize misbehaving nodes.

## 6.2 `economics/` — Staking, Rewards, Governance, DeFi

| File | Key Exports | Responsibility |
|------|---------|------|
| [economics/staking.go](../economics/staking.go) | `StakingManager`, `StakeInfo`, `UnstakeRequest`, `Stake`, `RequestUnstake`, `CompleteUnstake`, `GetStake`, `SetStakingAPY` | Staking (stake/unstake/APY/rewards) |
| [economics/rewards.go](../economics/rewards.go) | `CalculateRewards`, `DistributeRewards` | Block reward distribution |
| [economics/defi.go](../economics/defi.go) | `DeFi`, `LiquidityPool` | DeFi liquidity pools |
| [economics/inflation.go](../economics/inflation.go) | `Inflation`, `ComputeInflation` | Inflation model |
| [economics/gas_fees.go](../economics/gas_fees.go) | `GasFees`, `CalculateBaseFee` | Gas fees (incl. EIP-1559 style) |
| [economics/governance.go](../economics/governance.go) | `GovernanceManager`, `GovernanceConfig`, `Proposal` | Parameter and proposal governance |
| [economics/gas_fees.go](../economics/gas_fees.go) | `GasFeeCollector`, `CalculateBurnRate` | Gas accounting and scheduled fee burn |
| [economics/fee_distribution.go](../economics/fee_distribution.go) | `FeeDistributor`, `FeePool` | Fee split between validators, burn, and network pools |
| [economics/model/model.go](../economics/model/model.go) | Fee and supply model | Economic projections and burn modeling |

### 6.2.1 StakingManager Structure (Schematic)

Defined in [economics/staking.go:319](../economics/staking.go#L319)

```go
type StakingManager struct {
    config   *StakingConfig
    stakes   map[types.Address]*StakeInfo
    unstakes map[types.Address]*UnstakeRequest
    mu       sync.RWMutex
    treasury types.Address
    // ...
}

func NewStakingManager(config *StakingConfig) *StakingManager
func (sm *StakingManager) Stake(addr types.Address, amount *big.Int, commission uint32, blockHeight uint64) error
func (sm *StakingManager) RequestUnstake(addr types.Address, amount *big.Int, blockHeight uint64) error
func (sm *StakingManager) CompleteUnstake(addr types.Address, currentHeight uint64) (*big.Int, error)
func (sm *StakingManager) GetStake(addr types.Address) (*StakeInfo, error)
func (sm *StakingManager) SetStakingAPY(apy int64) error
```

- Accounts participating in staking are constrained by a **system caller** whitelist (from `staking.go:67`).
- Rewards are computed by APY + staking duration via the `computeStakingRewardsECONR11004` function.

### 6.2.2 Economic Constants

| Quantity | Value |
|----|----|
| Minimum stake | configured by `StakingConfig` (default in `DefaultStakingConfig()` [staking.go:265](../economics/staking.go#L265)) |
| Block reward | distributed per block by `rewards.go` |
| Base fee | computed EIP-1559 style by `gas_fees.go` |

## 6.3 Single-Point Notes

- **`p2p` must not import `economics` / `consensus`** (layer discipline).
- Staking-state changes must be invoked by `consensus` during block execution on `StakingManager`
  (via interfaces), not directly modified by `rpc`.
- The `blockHeight` parameter of `Stake` determines reward start/vesting; passing it incorrectly
  causes later rewards to be wrong.
