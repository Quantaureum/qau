// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"
)

type FeeHistoryArgs struct {
	BlockCount        string    `json:"blockCount"`
	NewestBlock       string    `json:"newestBlock"`
	RewardPercentiles []float64 `json:"rewardPercentiles"`
}

type FeeHistoryResult struct {
	OldestBlock   string     `json:"oldestBlock"`
	BaseFeePerGas []string   `json:"baseFeePerGas"`
	GasUsedRatio  []float64  `json:"gasUsedRatio"`
	Reward        [][]string `json:"reward,omitempty"`
}

type FeeHistoryReader interface {
	GetFeeHistory(blockCount uint64, newestBlock uint64, rewardPercentiles []float64) (*FeeHistoryResult, error)
}

type FeeAPI struct {
	blockReader BlockReader
	feeReader   FeeHistoryReader
}

func NewFeeAPI(blockReader BlockReader, feeReader FeeHistoryReader) *FeeAPI {
	return &FeeAPI{
		blockReader: blockReader,
		feeReader:   feeReader,
	}
}

func (api *FeeAPI) FeeHistory(ctx context.Context, params json.RawMessage) (any, *Error) {
	// Parse params — support both positional array and named object
	var blockCountStr string
	var newestBlockStr string
	var rewardPercentiles []float64

	// Try positional array first (standard Ethereum format: [blockCount, newestBlock, rewardPercentiles])
	var positional []json.RawMessage
	if err := json.Unmarshal(params, &positional); err == nil && len(positional) >= 2 {
		if len(positional) > 0 {
			json.Unmarshal(positional[0], &blockCountStr)
		}
		if len(positional) > 1 {
			json.Unmarshal(positional[1], &newestBlockStr)
		}
		if len(positional) > 2 {
			json.Unmarshal(positional[2], &rewardPercentiles)
		}
	} else {
		// Try named object format
		var args FeeHistoryArgs
		if err := json.Unmarshal(params, &args); err != nil {
			return nil, NewError(ErrCodeInvalidParams, "invalid fee history params")
		}
		blockCountStr = args.BlockCount
		newestBlockStr = args.NewestBlock
		rewardPercentiles = args.RewardPercentiles
	}

	blockCount := parseHexOrDecimalUint64(blockCountStr, 10)
	if blockCount > 1024 {
		blockCount = 1024
	}

	newestBlock := uint64(0)
	if newestBlockStr == "" || newestBlockStr == "latest" {
		newestBlock = api.blockReader.GetLatestHeight()
	} else {
		newestBlock = parseHexOrDecimalUint64(newestBlockStr, 0)
	}

	if rewardPercentiles == nil {
		rewardPercentiles = []float64{}
	}

	// R36-P2-RPC-01 FIX: Limit rewardPercentiles count and validate values to
	// prevent unauthenticated memory-amplification DoS. MaxParamsLength(64KB)
	// allows ~16k percentile elements; downstream (adapters.go:634) allocates
	// make([]string, len(rewardPercentiles)) per block (up to 1024) → 16M
	// string slots (~256MB) per request, a ~4000x amplification. Aligns with
	// go-ethereum: cap at 100 elements and require each value in [0, 100].
	if len(rewardPercentiles) > 100 {
		return nil, NewError(ErrCodeInvalidParams, "rewardPercentiles length exceeds maximum of 100")
	}
	for _, p := range rewardPercentiles {
		if p < 0 || p > 100 {
			return nil, NewError(ErrCodeInvalidParams, "rewardPercentiles values must be between 0 and 100")
		}
	}

	result, err := api.feeReader.GetFeeHistory(blockCount, newestBlock, rewardPercentiles)
	if err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	return &FeeHistoryResult{
		OldestBlock:   result.OldestBlock,
		BaseFeePerGas: result.BaseFeePerGas,
		GasUsedRatio:  result.GasUsedRatio,
		Reward:        result.Reward,
	}, nil
}

// MaxPriorityFeePerGas returns the priority fee per gas (tip to validator)
func (api *FeeAPI) MaxPriorityFeePerGas(ctx context.Context, params json.RawMessage) (any, *Error) {
	// FIX: Use dynamic base fee calculation instead of hardcoded 1 Gwei.
	// Priority fee = min(1 Gwei, baseFee * 10%) to avoid overpaying during high gas periods.
	var baseFee *big.Int
	if api.blockReader != nil {
		latestHeight := api.blockReader.GetLatestHeight()
		if latestHeight > 0 {
			block, err := api.blockReader.GetBlockByHeight(latestHeight)
			if err == nil && block != nil {
				// Try to extract BaseFee from block (type assertion depends on block type)
				if bf, ok := block.(interface{ GetBaseFee() *big.Int }); ok {
					baseFee = bf.GetBaseFee()
				}
			}
		}
	}
	// FIX: Use named constant instead of hardcoded magic number.
	defaultPriorityFee := big.NewInt(DefaultGasPriceWei) // 1 Gwei
	if baseFee != nil && baseFee.Sign() > 0 {
		// Use 10% of base fee as priority fee, capped at 1 Gwei
		dynamicFee := new(big.Int).Div(baseFee, big.NewInt(10))
		if dynamicFee.Cmp(defaultPriorityFee) < 0 {
			defaultPriorityFee = dynamicFee
		}
	}
	return "0x" + defaultPriorityFee.Text(16), nil
}

func (api *FeeAPI) RegisterHandlers(server *Server) {
	server.RegisterHandler("eth_feeHistory", api.FeeHistory)
	server.RegisterHandler("eth_maxPriorityFeePerGas", api.MaxPriorityFeePerGas)
}

func parseHexOrDecimalUint64(s string, defaultVal uint64) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return defaultVal
	}
	if len(s) >= 2 && s[:2] == "0x" {
		val, err := strconv.ParseUint(s[2:], 16, 64)
		if err != nil {
			return defaultVal
		}
		return val
	}
	val, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return defaultVal
	}
	return val
}
