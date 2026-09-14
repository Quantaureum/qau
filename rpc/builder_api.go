// Quantaureum Node source, version 1.0.0.
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/quantaureum/qau/miner"
)

type BuilderAPI struct {
	auction     *miner.MEVAuction
	registry    *miner.BuilderRegistry
	getSlotFunc func() uint64
}

func NewBuilderAPI(auction *miner.MEVAuction, registry *miner.BuilderRegistry, getSlotFunc func() uint64) *BuilderAPI {
	return &BuilderAPI{
		auction:     auction,
		registry:    registry,
		getSlotFunc: getSlotFunc,
	}
}

type submitBidParams struct {
	Slot           uint64   `json:"slot"`
	ParentHash     string   `json:"parentHash"`
	BlockHash      string   `json:"blockHash"`
	Value          string   `json:"value"`
	BuilderAddress string   `json:"builderAddress"`
	BuilderSig     string   `json:"builderSig"`
	GasUsed        uint64   `json:"gasUsed"`
	TxHashes       []string `json:"txHashes"`
}

type submitBidResult struct {
	Accepted bool   `json:"accepted"`
	BidHash  string `json:"bidHash,omitempty"`
	Message  string `json:"message,omitempty"`
}

type slotInfoResult struct {
	CurrentSlot   uint64 `json:"currentSlot"`
	AuctionOpen   bool   `json:"auctionOpen"`
	BidCount      int    `json:"bidCount"`
	MinBidValue   string `json:"minBidValue"`
	BidTimeoutSec int    `json:"bidTimeoutSec"`
}

type winningBidResult struct {
	Slot           uint64 `json:"slot"`
	HasWinner      bool   `json:"hasWinner"`
	Value          string `json:"value,omitempty"`
	BuilderAddress string `json:"builderAddress,omitempty"`
	BlockHash      string `json:"blockHash,omitempty"`
	GasUsed        uint64 `json:"gasUsed,omitempty"`
	TxCount        int    `json:"txCount,omitempty"`
}

// R24-018: This method uses a non-standard name. The convention across
// other API structs (API, DebugAPI, ProofAPI, etc.) is RegisterHandlers.
// The original name is retained for backward compatibility; a
// RegisterHandlers alias is defined below.
func (api *BuilderAPI) RegisterBuilderHandlers(server *Server) {
	server.RegisterHandler("qau_builder_submitBid", api.SubmitBid)
	server.RegisterHandler("qau_builder_getSlotInfo", api.GetSlotInfo)
	server.RegisterHandler("qau_builder_getWinningBid", api.GetWinningBid)
	// Security fix: qau_builder_submitBid is a write operation (submitting a MEV bid);
	// it must be registered as an admin method to enforce auth and prevent unauthorized calls
	server.RegisterAdminMethod("qau_builder_submitBid")
}

// RegisterHandlers is an alias for RegisterBuilderHandlers, following the
// standard naming convention used by other API structs (R24-018).
func (api *BuilderAPI) RegisterHandlers(server *Server) {
	api.RegisterBuilderHandlers(server)
}

func (api *BuilderAPI) SubmitBid(ctx context.Context, params json.RawMessage) (any, error) {
	var p submitBidParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	parentHash, err := parseHash(p.ParentHash)
	if err != nil {
		return nil, fmt.Errorf("invalid parentHash: %w", err)
	}

	blockHash, err := parseHash(p.BlockHash)
	if err != nil {
		return nil, fmt.Errorf("invalid blockHash: %w", err)
	}

	builderAddr, err := parseAddress(p.BuilderAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid builderAddress: %w", err)
	}

	builderSig, err := hex.DecodeString(stripHexPrefix(p.BuilderSig))
	if err != nil {
		return nil, fmt.Errorf("invalid builderSig: %w", err)
	}

	value, ok := new(big.Int).SetString(stripHexPrefix(p.Value), 16)
	if !ok {
		// R36-P3-19 FIX (2026-07-30): Reject invalid value instead of
		// silently degrading to 0. The previous behavior accepted any
		// garbage string as Value=0, which would create a bid with zero
		// value — the builder would commit to building a block for free,
		// and the bid would silently lose to any non-zero bid. Worse, a
		// misconfigured relay could submit malformed bids that always
		// evaluate to 0, effectively disabling builder participation.
		// Returning an error surfaces the misconfiguration immediately.
		return nil, fmt.Errorf("invalid value (must be hex-encoded non-negative integer): %q", p.Value)
	}

	bid := &miner.BuilderBid{
		Slot:           p.Slot,
		ParentHash:     parentHash,
		BlockHash:      blockHash,
		Value:          value,
		BuilderAddress: builderAddr,
		BuilderSig:     builderSig,
		Timestamp:      time.Now().UnixNano(),
		GasUsed:        p.GasUsed,
	}

	if api.registry != nil {
		if err := api.registry.VerifyBid(bid); err != nil {
			return &submitBidResult{
				Accepted: false,
				Message:  fmt.Sprintf("bid verification failed: %v", err),
			}, nil
		}
	}

	if err := api.auction.SubmitBid(bid); err != nil {
		return &submitBidResult{
			Accepted: false,
			Message:  err.Error(),
		}, nil
	}

	bidHash := bid.Hash()
	return &submitBidResult{
		Accepted: true,
		BidHash:  hex.EncodeToString(bidHash[:]),
		Message:  "bid accepted",
	}, nil
}

func (api *BuilderAPI) GetSlotInfo(ctx context.Context, params json.RawMessage) (any, error) {
	currentSlot := uint64(0)
	if api.getSlotFunc != nil {
		currentSlot = api.getSlotFunc()
	}

	auctionOpen := api.auction.IsOpen(currentSlot)

	bidTimeout := api.auction.BidTimeout()

	return &slotInfoResult{
		CurrentSlot:   currentSlot,
		AuctionOpen:   auctionOpen,
		BidCount:      0,
		MinBidValue:   "0",
		BidTimeoutSec: int(bidTimeout.Seconds()),
	}, nil
}

func (api *BuilderAPI) GetWinningBid(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		Slot uint64 `json:"slot"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	winningBid := api.auction.GetWinningBid(p.Slot)

	if winningBid == nil {
		return &winningBidResult{
			Slot:      p.Slot,
			HasWinner: false,
		}, nil
	}

	txCount := len(winningBid.Transactions)

	return &winningBidResult{
		Slot:           p.Slot,
		HasWinner:      true,
		Value:          winningBid.Value.String(),
		BuilderAddress: hex.EncodeToString(winningBid.BuilderAddress[:]),
		BlockHash:      hex.EncodeToString(winningBid.BlockHash[:]),
		GasUsed:        winningBid.GasUsed,
		TxCount:        txCount,
	}, nil
}
