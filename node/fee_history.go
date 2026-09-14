// Quantaureum Node source, version 1.0.0.
package node

import (
	"math/big"
	"sort"
	"sync"

	"github.com/quantaureum/qau/encoding"
)

const maxFeeHistoryBlocks = 1024

type FeeHistoryEntry struct {
	BaseFee  *big.Int
	GasUsed  uint64
	GasLimit uint64
	Rewards  []*big.Int
	BlockNum uint64
}

type FeeHistoryTracker struct {
	mu      sync.RWMutex
	entries []*FeeHistoryEntry
	maxSize int
}

func NewFeeHistoryTracker() *FeeHistoryTracker {
	return &FeeHistoryTracker{
		entries: make([]*FeeHistoryEntry, 0, maxFeeHistoryBlocks),
		maxSize: maxFeeHistoryBlocks,
	}
}

func (fht *FeeHistoryTracker) RecordBlock(header *encoding.BlockHeader, txs []*encoding.Transaction) {
	fht.mu.Lock()
	defer fht.mu.Unlock()

	entry := &FeeHistoryEntry{
		BaseFee:  new(big.Int),
		GasUsed:  header.GasUsed,
		GasLimit: header.GasLimit,
		BlockNum: header.Height,
	}
	if header.BaseFee != nil {
		entry.BaseFee.Set(header.BaseFee)
	}

	if len(txs) > 0 {
		entry.Rewards = computeRewardPercentiles(txs, header.BaseFee)
	}

	fht.entries = append(fht.entries, entry)
	if len(fht.entries) > fht.maxSize {
		fht.entries = fht.entries[len(fht.entries)-fht.maxSize:]
	}
}

func (fht *FeeHistoryTracker) GetHistory(blockCount uint64, newestBlock uint64, rewardPercentiles []float64) (*FeeHistoryResult, error) {
	fht.mu.RLock()
	defer fht.mu.RUnlock()

	if blockCount > 1024 {
		blockCount = 1024
	}
	if blockCount < 1 {
		blockCount = 1
	}

	if newestBlock == 0 || newestBlock > fht.latestBlock() {
		newestBlock = fht.latestBlock()
	}

	startBlock := newestBlock
	if startBlock >= blockCount {
		startBlock = newestBlock - blockCount + 1
	} else {
		startBlock = 1
	}

	result := &FeeHistoryResult{
		OldestBlock:   startBlock,
		BaseFeePerGas: make([]string, 0, blockCount),
		GasUsedRatio:  make([]float64, 0, blockCount),
	}

	if len(rewardPercentiles) > 0 {
		result.Reward = make([][]string, 0, blockCount)
	}

	for _, entry := range fht.entries {
		if entry.BlockNum >= startBlock && entry.BlockNum <= newestBlock {
			result.BaseFeePerGas = append(result.BaseFeePerGas, toHexBig(entry.BaseFee))
			if entry.GasLimit > 0 {
				result.GasUsedRatio = append(result.GasUsedRatio, float64(entry.GasUsed)/float64(entry.GasLimit))
			} else {
				result.GasUsedRatio = append(result.GasUsedRatio, 0)
			}

			if len(rewardPercentiles) > 0 {
				rewards := make([]string, len(rewardPercentiles))
				for i, p := range rewardPercentiles {
					rewards[i] = toHexBig(percentileReward(entry.Rewards, p))
				}
				result.Reward = append(result.Reward, rewards)
			}
		}
	}

	return result, nil
}

func (fht *FeeHistoryTracker) latestBlock() uint64 {
	if len(fht.entries) == 0 {
		return 0
	}
	return fht.entries[len(fht.entries)-1].BlockNum
}

type FeeHistoryResult struct {
	OldestBlock   uint64     `json:"oldestBlock"`
	BaseFeePerGas []string   `json:"baseFeePerGas"`
	GasUsedRatio  []float64  `json:"gasUsedRatio"`
	Reward        [][]string `json:"reward,omitempty"`
}

func computeRewardPercentiles(txs []*encoding.Transaction, baseFee *big.Int) []*big.Int {
	rewards := make([]*big.Int, 0, len(txs))
	for _, tx := range txs {
		if tx.GasPrice != nil && baseFee != nil {
			reward := new(big.Int).Sub(tx.GasPrice, baseFee)
			if reward.Sign() < 0 {
				reward = big.NewInt(0)
			}
			rewards = append(rewards, reward)
		}
	}
	return rewards
}

func percentileReward(rewards []*big.Int, percentile float64) *big.Int {
	if len(rewards) == 0 {
		return big.NewInt(0)
	}

	sorted := make([]*big.Int, len(rewards))
	copy(sorted, rewards)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Cmp(sorted[j]) < 0
	})

	idx := int(float64(len(sorted)-1) * percentile / 100.0)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func toHexBig(n *big.Int) string {
	if n == nil {
		return "0x0"
	}
	return "0x" + n.Text(16)
}
