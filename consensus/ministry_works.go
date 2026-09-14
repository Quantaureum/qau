// Quantaureum Node source, version 1.0.0.
package consensus

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/quantaureum/qau/types"
)

type ShardState uint8

const (
	ShardStateNone      ShardState = 0
	ShardStateActive    ShardState = 1
	ShardStateInactive  ShardState = 2
	ShardStateMigrating ShardState = 3
)

func (s ShardState) String() string {
	switch s {
	case ShardStateNone:
		return "None"
	case ShardStateActive:
		return "Active"
	case ShardStateInactive:
		return "Inactive"
	case ShardStateMigrating:
		return "Migrating"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

type BridgeState uint8

const (
	BridgeStateNone      BridgeState = 0
	BridgeStateActive    BridgeState = 1
	BridgeStateSuspended BridgeState = 2
	BridgeStateDegraded  BridgeState = 3
)

func (b BridgeState) String() string {
	switch b {
	case BridgeStateNone:
		return "None"
	case BridgeStateActive:
		return "Active"
	case BridgeStateSuspended:
		return "Suspended"
	case BridgeStateDegraded:
		return "Degraded"
	default:
		return fmt.Sprintf("Unknown(%d)", b)
	}
}

type ShardInfo struct {
	ID             uint64
	State          ShardState
	ValidatorCount int
	TotalStake     string
	CreatedAt      time.Time
	LastActive     time.Time
	BlockHeight    uint64
}

type BridgeInfo struct {
	ID             uint64
	Name           string
	RemoteChainID  uint64
	State          BridgeState
	RelayerCount   int
	TotalLocked    string
	CreatedAt      time.Time
	LastActive     time.Time
	PendingTxCount int
}

type CrossChainTx struct {
	ID           uint64
	BridgeID     uint64
	SourceTxHash types.Hash
	DestTxHash   types.Hash
	Amount       string
	Status       string
	CreatedAt    time.Time
	CompletedAt  time.Time
}

type MinistryWorks struct {
	mu sync.RWMutex

	qpos        *QPOS
	coordinator *ThreeChambersCoordinator
	registry    *MinistryRegistry

	shards       map[uint64]*ShardInfo
	bridges      map[uint64]*BridgeInfo
	crossChainTx map[uint64]*CrossChainTx

	nextShardID  uint64
	nextBridgeID uint64
	nextTxID     uint64

	maxShards       int
	maxBridges      int
	maxCrossChainTx int

	operations uint64
	errors     uint64
	lastActive time.Time
}

func NewMinistryWorks(qpos *QPOS, coordinator *ThreeChambersCoordinator, registry *MinistryRegistry) *MinistryWorks {
	return &MinistryWorks{
		qpos:            qpos,
		coordinator:     coordinator,
		registry:        registry,
		shards:          make(map[uint64]*ShardInfo),
		bridges:         make(map[uint64]*BridgeInfo),
		crossChainTx:    make(map[uint64]*CrossChainTx),
		nextShardID:     1,
		nextBridgeID:    1,
		nextTxID:        1,
		maxShards:       64,
		maxBridges:      32,
		maxCrossChainTx: 10000,
	}
}

func (mw *MinistryWorks) RegisterShard(caller types.Address, validatorCount int, totalStake string) (*ShardInfo, error) {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can register shards.
	if caller == (types.Address{}) {
		return nil, fmt.Errorf("unauthorized: zero address cannot register shards")
	}
	if !isSystemCaller(caller) {
		return nil, fmt.Errorf("unauthorized: only system callers can register shards")
	}

	mw.mu.Lock()
	defer mw.mu.Unlock()
	mw.operations++
	mw.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	if len(mw.shards) >= mw.maxShards {
		mw.errors++
		return nil, fmt.Errorf("maximum shard count reached (%d)", mw.maxShards)
	}

	if validatorCount <= 0 {
		mw.errors++
		return nil, fmt.Errorf("validator count must be positive")
	}

	id := mw.nextShardID
	mw.nextShardID++

	now := time.Now() // NOT consensus-critical: local in-memory tracking
	shard := &ShardInfo{
		ID:             id,
		State:          ShardStateActive,
		ValidatorCount: validatorCount,
		TotalStake:     totalStake,
		CreatedAt:      now,
		LastActive:     now,
	}

	mw.shards[id] = shard
	return mw.copyShard(shard), nil
}

func (mw *MinistryWorks) DeactivateShard(caller types.Address, shardID uint64) error {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can deactivate shards.
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot deactivate shards")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can deactivate shards")
	}

	mw.mu.Lock()
	defer mw.mu.Unlock()
	mw.operations++
	mw.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	shard, exists := mw.shards[shardID]
	if !exists {
		mw.errors++
		return fmt.Errorf("shard %d not found", shardID)
	}

	if shard.State == ShardStateInactive {
		mw.errors++
		return fmt.Errorf("shard %d is already inactive", shardID)
	}

	shard.State = ShardStateInactive
	shard.LastActive = time.Now() // NOT consensus-critical: local in-memory tracking
	return nil
}

func (mw *MinistryWorks) ActivateShard(caller types.Address, shardID uint64) error {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can activate shards.
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot activate shards")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can activate shards")
	}

	mw.mu.Lock()
	defer mw.mu.Unlock()
	mw.operations++
	mw.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	shard, exists := mw.shards[shardID]
	if !exists {
		mw.errors++
		return fmt.Errorf("shard %d not found", shardID)
	}

	if shard.State == ShardStateActive {
		mw.errors++
		return fmt.Errorf("shard %d is already active", shardID)
	}

	shard.State = ShardStateActive
	shard.LastActive = time.Now() // NOT consensus-critical: local in-memory tracking
	return nil
}

// audit-remediation: reviewed 2026-09-11 — height bookkeeping; unrelated to stake.
func (mw *MinistryWorks) UpdateShardHeight(caller types.Address, shardID uint64, height uint64) error {
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot update shard height")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can update shard height")
	}

	mw.mu.Lock()
	defer mw.mu.Unlock()

	shard, exists := mw.shards[shardID]
	if !exists {
		return fmt.Errorf("shard %d not found", shardID)
	}

	shard.BlockHeight = height
	shard.LastActive = time.Now() // NOT consensus-critical: local in-memory tracking
	return nil
}

func (mw *MinistryWorks) GetShard(shardID uint64) (*ShardInfo, error) {
	mw.mu.RLock()
	defer mw.mu.RUnlock()

	shard, exists := mw.shards[shardID]
	if !exists {
		return nil, fmt.Errorf("shard %d not found", shardID)
	}

	return mw.copyShard(shard), nil
}

func (mw *MinistryWorks) GetActiveShards() []*ShardInfo {
	mw.mu.RLock()
	defer mw.mu.RUnlock()

	result := make([]*ShardInfo, 0)
	for _, s := range mw.shards {
		if s.State == ShardStateActive {
			result = append(result, mw.copyShard(s))
		}
	}
	return result
}

func (mw *MinistryWorks) RegisterBridge(caller types.Address, name string, remoteChainID uint64, relayerCount int, totalLocked string) (*BridgeInfo, error) {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can register bridges.
	if caller == (types.Address{}) {
		return nil, fmt.Errorf("unauthorized: zero address cannot register bridges")
	}
	if !isSystemCaller(caller) {
		return nil, fmt.Errorf("unauthorized: only system callers can register bridges")
	}

	mw.mu.Lock()
	defer mw.mu.Unlock()
	mw.operations++
	mw.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	if name == "" {
		mw.errors++
		return nil, fmt.Errorf("bridge name cannot be empty")
	}

	if len(mw.bridges) >= mw.maxBridges {
		mw.errors++
		return nil, fmt.Errorf("maximum bridge count reached (%d)", mw.maxBridges)
	}

	id := mw.nextBridgeID
	mw.nextBridgeID++

	now := time.Now() // NOT consensus-critical: local in-memory tracking
	bridge := &BridgeInfo{
		ID:            id,
		Name:          name,
		RemoteChainID: remoteChainID,
		State:         BridgeStateActive,
		RelayerCount:  relayerCount,
		TotalLocked:   totalLocked,
		CreatedAt:     now,
		LastActive:    now,
	}

	mw.bridges[id] = bridge
	return mw.copyBridge(bridge), nil
}

func (mw *MinistryWorks) SuspendBridge(caller types.Address, bridgeID uint64, reason string) error {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can suspend bridges.
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot suspend bridges")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can suspend bridges")
	}

	mw.mu.Lock()
	defer mw.mu.Unlock()
	mw.operations++
	mw.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	bridge, exists := mw.bridges[bridgeID]
	if !exists {
		mw.errors++
		return fmt.Errorf("bridge %d not found", bridgeID)
	}

	if bridge.State == BridgeStateSuspended {
		mw.errors++
		return fmt.Errorf("bridge %d is already suspended", bridgeID)
	}

	bridge.State = BridgeStateSuspended
	bridge.LastActive = time.Now() // NOT consensus-critical: local in-memory tracking
	return nil
}

func (mw *MinistryWorks) ReactivateBridge(caller types.Address, bridgeID uint64) error {
	// SECURITY (audit GOV-03): Authorization check — only system callers
	// can reactivate bridges.
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot reactivate bridges")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can reactivate bridges")
	}

	mw.mu.Lock()
	defer mw.mu.Unlock()
	mw.operations++
	mw.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	bridge, exists := mw.bridges[bridgeID]
	if !exists {
		mw.errors++
		return fmt.Errorf("bridge %d not found", bridgeID)
	}

	if bridge.State == BridgeStateActive {
		mw.errors++
		return fmt.Errorf("bridge %d is already active", bridgeID)
	}

	bridge.State = BridgeStateActive
	bridge.LastActive = time.Now()
	return nil
}

func (mw *MinistryWorks) RecordCrossChainTx(caller types.Address, bridgeID uint64, sourceTxHash types.Hash, amount string) (*CrossChainTx, error) {
	if caller == (types.Address{}) {
		return nil, fmt.Errorf("unauthorized: zero address cannot record cross-chain tx")
	}
	if !isSystemCaller(caller) {
		return nil, fmt.Errorf("unauthorized: only system callers can record cross-chain tx")
	}

	mw.mu.Lock()
	defer mw.mu.Unlock()
	mw.operations++
	mw.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	bridge, exists := mw.bridges[bridgeID]
	if !exists {
		mw.errors++
		return nil, fmt.Errorf("bridge %d not found", bridgeID)
	}

	if bridge.State != BridgeStateActive {
		mw.errors++
		return nil, fmt.Errorf("bridge %d is not active (state: %s)", bridgeID, bridge.State)
	}

	if len(mw.crossChainTx) >= mw.maxCrossChainTx {
		// GOV-R7-04: Tiered eviction so a backlog of pending/failed txs
		// cannot permanently block new cross-chain tx recording.
		// Preference order: completed → failed → pending (with warning).
		const sentinel = ^uint64(0)
		var oldestCompleted, oldestFailed, oldestPending uint64 = sentinel, sentinel, sentinel
		for id, tx := range mw.crossChainTx {
			switch tx.Status {
			case "completed":
				if id < oldestCompleted {
					oldestCompleted = id
				}
			case "failed":
				if id < oldestFailed {
					oldestFailed = id
				}
			default: // "pending" or any other state
				if id < oldestPending {
					oldestPending = id
				}
			}
		}
		switch {
		case oldestCompleted != sentinel:
			delete(mw.crossChainTx, oldestCompleted)
		case oldestFailed != sentinel:
			delete(mw.crossChainTx, oldestFailed)
		case oldestPending != sentinel:
			// Evicting a pending tx means its completion will be lost;
			// warn so operators can investigate the stalled bridge.
			log.Printf("GOV-R7-04: ministry_works evicting pending cross-chain tx %d from bridge %d to make room (pending backlog)", oldestPending, bridgeID)
			delete(mw.crossChainTx, oldestPending)
		}
	}

	id := mw.nextTxID
	mw.nextTxID++

	now := time.Now() // NOT consensus-critical: local in-memory tracking
	tx := &CrossChainTx{
		ID:           id,
		BridgeID:     bridgeID,
		SourceTxHash: sourceTxHash,
		Amount:       amount,
		Status:       "pending",
		CreatedAt:    now,
	}

	bridge.PendingTxCount++
	mw.crossChainTx[id] = tx

	return &CrossChainTx{
		ID:           tx.ID,
		BridgeID:     tx.BridgeID,
		SourceTxHash: tx.SourceTxHash,
		Amount:       tx.Amount,
		Status:       tx.Status,
		CreatedAt:    tx.CreatedAt,
	}, nil
}

func (mw *MinistryWorks) CompleteCrossChainTx(caller types.Address, txID uint64, destTxHash types.Hash) error {
	if caller == (types.Address{}) {
		return fmt.Errorf("unauthorized: zero address cannot complete cross-chain tx")
	}
	if !isSystemCaller(caller) {
		return fmt.Errorf("unauthorized: only system callers can complete cross-chain tx")
	}

	mw.mu.Lock()
	defer mw.mu.Unlock()
	mw.operations++
	mw.lastActive = time.Now() // NOT consensus-critical: local in-memory tracking only

	tx, exists := mw.crossChainTx[txID]
	if !exists {
		mw.errors++
		return fmt.Errorf("cross-chain tx %d not found", txID)
	}

	// SECURITY (audit GOV-R7-10): Idempotent handling — if the tx is already
	// completed, return success without decrementing PendingTxCount again.
	// This guards against RPC retries / network duplicates that could
	// otherwise underflow the uint64 counter (turning it into MaxUint64
	// and polluting GetBridgeHealth).
	if tx.Status == "completed" {
		return nil
	}

	if tx.Status != "pending" {
		mw.errors++
		return fmt.Errorf("cross-chain tx %d is not pending (status: %s)", txID, tx.Status)
	}

	tx.Status = "completed"
	tx.DestTxHash = destTxHash
	tx.CompletedAt = time.Now() // NOT consensus-critical: local in-memory tracking

	if bridge, ok := mw.bridges[tx.BridgeID]; ok {
		// SECURITY (audit GOV-R7-10): Defensive lower-bound check — even with
		// the idempotent guard above, never let PendingTxCount underflow.
		if bridge.PendingTxCount > 0 {
			bridge.PendingTxCount--
		}
		bridge.LastActive = time.Now() // NOT consensus-critical: local in-memory tracking
	}

	return nil
}

func (mw *MinistryWorks) GetBridge(bridgeID uint64) (*BridgeInfo, error) {
	mw.mu.RLock()
	defer mw.mu.RUnlock()

	bridge, exists := mw.bridges[bridgeID]
	if !exists {
		return nil, fmt.Errorf("bridge %d not found", bridgeID)
	}

	return mw.copyBridge(bridge), nil
}

func (mw *MinistryWorks) GetActiveBridges() []*BridgeInfo {
	mw.mu.RLock()
	defer mw.mu.RUnlock()

	result := make([]*BridgeInfo, 0)
	for _, b := range mw.bridges {
		if b.State == BridgeStateActive {
			result = append(result, mw.copyBridge(b))
		}
	}
	return result
}

func (mw *MinistryWorks) GetShardHealth(shardID uint64) (bool, error) {
	mw.mu.RLock()
	defer mw.mu.RUnlock()

	shard, exists := mw.shards[shardID]
	if !exists {
		return false, fmt.Errorf("shard %d not found", shardID)
	}

	if shard.State != ShardStateActive {
		return false, nil
	}

	timeSinceActive := time.Since(shard.LastActive)
	return timeSinceActive < 5*time.Minute, nil
}

func (mw *MinistryWorks) GetBridgeHealth(bridgeID uint64) (bool, error) {
	mw.mu.RLock()
	defer mw.mu.RUnlock()

	bridge, exists := mw.bridges[bridgeID]
	if !exists {
		return false, fmt.Errorf("bridge %d not found", bridgeID)
	}

	if bridge.State != BridgeStateActive {
		return false, nil
	}

	timeSinceActive := time.Since(bridge.LastActive)
	return timeSinceActive < 5*time.Minute, nil
}

func (mw *MinistryWorks) copyShard(s *ShardInfo) *ShardInfo {
	return &ShardInfo{
		ID:             s.ID,
		State:          s.State,
		ValidatorCount: s.ValidatorCount,
		TotalStake:     s.TotalStake,
		CreatedAt:      s.CreatedAt,
		LastActive:     s.LastActive,
		BlockHeight:    s.BlockHeight,
	}
}

func (mw *MinistryWorks) copyBridge(b *BridgeInfo) *BridgeInfo {
	return &BridgeInfo{
		ID:             b.ID,
		Name:           b.Name,
		RemoteChainID:  b.RemoteChainID,
		State:          b.State,
		RelayerCount:   b.RelayerCount,
		TotalLocked:    b.TotalLocked,
		CreatedAt:      b.CreatedAt,
		LastActive:     b.LastActive,
		PendingTxCount: b.PendingTxCount,
	}
}

func (mw *MinistryWorks) GetStatus() map[string]any {
	mw.mu.RLock()
	defer mw.mu.RUnlock()

	activeShards := 0
	for _, s := range mw.shards {
		if s.State == ShardStateActive {
			activeShards++
		}
	}

	activeBridges := 0
	pendingTxs := 0
	for _, b := range mw.bridges {
		if b.State == BridgeStateActive {
			activeBridges++
		}
		pendingTxs += b.PendingTxCount
	}

	return map[string]any{
		"ministry":      MinistryIDWorks.String(),
		"displayName":   MinistryIDWorks.DisplayName(),
		"active":        true,
		"operations":    mw.operations,
		"errors":        mw.errors,
		"lastActive":    mw.lastActive,
		"totalShards":   len(mw.shards),
		"activeShards":  activeShards,
		"totalBridges":  len(mw.bridges),
		"activeBridges": activeBridges,
		"pendingTxs":    pendingTxs,
		"crossChainTxs": len(mw.crossChainTx),
	}
}
