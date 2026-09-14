// Quantaureum Node source, version 1.0.0.
// Economics RPC API — Inflation, Supply, Fee Distribution, Rewards, DeFi Incentives, Liquid Staking
package rpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/quantaureum/qau/crypto"
	"github.com/quantaureum/qau/economics"
	"github.com/quantaureum/qau/types"
)

// maxSupplyQAU is the maximum QAU supply: 100 million tokens with 18 decimals.
var maxSupplyQAU = new(big.Int).Mul(big.NewInt(100000000), big.NewInt(1e18))

// EconomicsAPI provides economics RPC methods.
type EconomicsAPI struct {
	inflationModel       *economics.InflationModel
	gasFeeCollector      *economics.GasFeeCollector
	feeDistributor       *economics.FeeDistributor
	rewardCalculator     *economics.RewardCalculator
	rewardDistributor    *economics.RewardDistributor
	defiIncentiveManager *economics.DeFiIncentiveManager
	liquidStakingManager *economics.LiquidStakingManager
	stakingManager       *economics.StakingManager
	blockReader          BlockReader
	chainID              uint64

	nonceMu    sync.Mutex
	usedNonces map[types.Address]map[string]time.Time
}

const maxEconomicsNoncesPerAddress = 10000
const maxEconomicsTrackedAddresses = 100000

// NewEconomicsAPI creates a new Economics API.
func NewEconomicsAPI(
	inflationModel *economics.InflationModel,
	gasFeeCollector *economics.GasFeeCollector,
	feeDistributor *economics.FeeDistributor,
	rewardCalculator *economics.RewardCalculator,
	rewardDistributor *economics.RewardDistributor,
	defiIncentiveManager *economics.DeFiIncentiveManager,
	liquidStakingManager *economics.LiquidStakingManager,
	stakingManager *economics.StakingManager,
	br BlockReader,
) *EconomicsAPI {
	return &EconomicsAPI{
		inflationModel:       inflationModel,
		gasFeeCollector:      gasFeeCollector,
		feeDistributor:       feeDistributor,
		rewardCalculator:     rewardCalculator,
		rewardDistributor:    rewardDistributor,
		defiIncentiveManager: defiIncentiveManager,
		liquidStakingManager: liquidStakingManager,
		stakingManager:       stakingManager,
		blockReader:          br,
		usedNonces:           make(map[types.Address]map[string]time.Time),
	}
}

func (api *EconomicsAPI) SetChainID(id uint64) {
	api.chainID = id
}

//	This method uses a non-standard name. The convention across
//
// other API structs (API, DebugAPI, ProofAPI, etc.) is RegisterHandlers.
// The original name is retained for backward compatibility; a
// RegisterHandlers alias is defined below.
// RegisterEconomicsHandlers registers all economics API handlers.
func (api *EconomicsAPI) RegisterEconomicsHandlers(server *Server) {
	// Inflation & supply
	server.RegisterHandler("qau_getInflationInfo", api.GetInflationInfo)
	server.RegisterHandler("qau_getSupply", api.GetSupply)

	// Fee distribution & rewards
	server.RegisterHandler("qau_getFeeDistribution", api.GetFeeDistribution)
	server.RegisterHandler("qau_getRewardStats", api.GetRewardStats)

	// DeFi incentives
	server.RegisterHandler("qau_getDeFiIncentives", api.GetDeFiIncentives)
	server.RegisterHandler("qau_claimDeFiIncentives", api.ClaimDeFiIncentives)
	server.RegisterAdminMethod("qau_claimDeFiIncentives")

	// Liquid staking
	server.RegisterHandler("qau_liquidStake", api.LiquidStake)
	server.RegisterAdminMethod("qau_liquidStake")
	server.RegisterHandler("qau_liquidUnstake", api.LiquidUnstake)
	server.RegisterAdminMethod("qau_liquidUnstake")
	server.RegisterHandler("qau_getExchangeRate", api.GetExchangeRate)
	server.RegisterHandler("qau_getLiquidStakingPosition", api.GetLiquidStakingPosition)
}

// RegisterHandlers is an alias for RegisterEconomicsHandlers, following the
// standard naming convention used by other API structs ().
func (api *EconomicsAPI) RegisterHandlers(server *Server) {
	api.RegisterEconomicsHandlers(server)
}

// currentHeight returns the current block height.
func (api *EconomicsAPI) currentHeight() uint64 {
	if api.blockReader != nil {
		return api.blockReader.GetLatestHeight()
	}
	return 0
}

// stakedSupply returns the total staked amount from the staking manager.
func (api *EconomicsAPI) stakedSupply() *big.Int {
	if api.stakingManager != nil {
		return api.stakingManager.GetTotalStaked()
	}
	return big.NewInt(0)
}

// verifyEconomicsSignature verifies a Dilithium3 signature for an economics operation.
// CRITICAL C-1 FIX: all state-mutating economics RPC calls require Dilithium3 signature
// verification proving ownership of the address being operated on, with nonce-based
// replay protection. The signature covers: method || userAddress || nonce || params.
func (api *EconomicsAPI) verifyEconomicsSignature(method string, userAddr types.Address, nonce, params string, signature, pubKeyHex string) error {
	if signature == "" || pubKeyHex == "" {
		return fmt.Errorf("signature and publicKey are required for state-mutating operations")
	}
	if nonce == "" {
		return fmt.Errorf("nonce is required for replay protection")
	}

	api.nonceMu.Lock()
	if len(api.usedNonces) > maxEconomicsTrackedAddresses {
		api.nonceMu.Unlock()
		return fmt.Errorf("too many tracked addresses (memory limit)")
	}
	if api.usedNonces[userAddr] == nil {
		api.usedNonces[userAddr] = make(map[string]time.Time)
	}
	const economicsNonceTTL = 10 * time.Minute
	now := time.Now()
	for k, ts := range api.usedNonces[userAddr] {
		// FIX: Skip pending (zero-time) nonces in TTL cleanup.
		// Pending nonces await signature verification and must NOT be evicted
		// by a concurrent request's cleanup, which would reopen a TOCTOU
		// window allowing the same nonce to be reused.
		if isNonceConfirmed(ts) && now.Sub(ts) > economicsNonceTTL {
			delete(api.usedNonces[userAddr], k)
		}
	}
	if _, used := api.usedNonces[userAddr][nonce]; used {
		api.nonceMu.Unlock()
		return fmt.Errorf("nonce already used (replay detected)")
	}
	api.usedNonces[userAddr][nonce] = time.Time{}
	api.nonceMu.Unlock()

	sigBytes, err := hex.DecodeString(strings.TrimPrefix(signature, "0x"))
	if err != nil {
		api.rollbackPendingEconomicsNonce(userAddr, nonce)
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(strings.TrimPrefix(pubKeyHex, "0x"))
	if err != nil {
		api.rollbackPendingEconomicsNonce(userAddr, nonce)
		return fmt.Errorf("invalid publicKey hex: %w", err)
	}

	pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		api.rollbackPendingEconomicsNonce(userAddr, nonce)
		return fmt.Errorf("invalid Dilithium3 public key: %w", err)
	}

	derivedAddr := pubKey.Address()
	if derivedAddr != userAddr {
		api.rollbackPendingEconomicsNonce(userAddr, nonce)
		return fmt.Errorf("public key does not match claimed address")
	}

	message := []byte(method + "|" + userAddr.ToHexAddress() + "|" + nonce + "|" + params)

	if !crypto.Verify(pubKey, message, sigBytes) {
		api.rollbackPendingEconomicsNonce(userAddr, nonce)
		return fmt.Errorf("signature verification failed")
	}

	api.nonceMu.Lock()
	// FIX: Re-verify the nonce is still in pending state before
	// confirming. This closes the TOCTOU window between the initial pending
	// reservation (first lock) and this confirmation (second lock).
	if ts, exists := api.usedNonces[userAddr][nonce]; !exists || isNonceConfirmed(ts) {
		api.nonceMu.Unlock()
		return fmt.Errorf("nonce reservation invalid or lost (possible replay)")
	}
	if len(api.usedNonces[userAddr]) >= maxEconomicsNoncesPerAddress {
		type nonceEntry struct {
			nonce string
			ts    time.Time
		}
		entries := make([]nonceEntry, 0, len(api.usedNonces[userAddr]))
		for k, ts := range api.usedNonces[userAddr] {
			// R22-NEW-004 FIX: Skip pending (zero-time) nonces in eviction.
			// Pending nonces sort first (year 1) and would be deleted first,
			// reopening a TOCTOU window allowing nonce replay.
			if isNonceConfirmed(ts) {
				entries = append(entries, nonceEntry{k, ts})
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].ts.Before(entries[j].ts)
		})
		for i := 0; i < len(entries)/2; i++ {
			delete(api.usedNonces[userAddr], entries[i].nonce)
		}
	}
	api.usedNonces[userAddr][nonce] = time.Now()
	api.nonceMu.Unlock()

	return nil
}

// rollbackPendingEconomicsNonce removes a pending nonce reservation when verification fails.
func (api *EconomicsAPI) rollbackPendingEconomicsNonce(userAddr types.Address, nonce string) {
	api.nonceMu.Lock()
	defer api.nonceMu.Unlock()
	if nonces, ok := api.usedNonces[userAddr]; ok {
		if ts, exists := nonces[nonce]; exists && ts.IsZero() {
			delete(nonces, nonce)
		}
	}
}

// GetInflationInfo returns inflation rate, block reward, total supply, and circulating supply.
func (api *EconomicsAPI) GetInflationInfo(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.inflationModel == nil {
		return nil, &Error{Code: -32601, Message: "inflation model not available"}
	}

	height := api.currentHeight()
	totalSupply := api.inflationModel.GetTotalSupply()
	staked := api.stakedSupply()
	circulating := new(big.Int).Sub(totalSupply, staked)
	if circulating.Sign() < 0 {
		circulating = big.NewInt(0)
	}

	result := map[string]any{
		"inflationRate":     api.inflationModel.GetCurrentRate().String(),
		"inflationPhase":    inflationPhaseString(api.inflationModel.GetCurrentPhase()),
		"blockReward":       big.NewInt(0).String(),
		"totalSupply":       totalSupply.String(),
		"circulatingSupply": circulating.String(),
		"stakedSupply":      staked.String(),
		"stakeRatio":        api.inflationModel.GetStakeRatio().String(),
		"adjustmentCount":   api.inflationModel.GetAdjustmentCount(),
		"currentHeight":     height,
	}

	if api.rewardCalculator != nil {
		result["blockReward"] = api.rewardCalculator.CalculateBlockReward(height).String()
	}

	return result, nil
}

// GetSupply returns total, circulating, and max supply.
func (api *EconomicsAPI) GetSupply(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.inflationModel == nil {
		return nil, &Error{Code: -32601, Message: "inflation model not available"}
	}

	totalSupply := api.inflationModel.GetTotalSupply()
	staked := api.stakedSupply()
	circulating := new(big.Int).Sub(totalSupply, staked)
	if circulating.Sign() < 0 {
		circulating = big.NewInt(0)
	}

	return map[string]any{
		"totalSupply":       totalSupply.String(),
		"circulatingSupply": circulating.String(),
		"maxSupply":         maxSupplyQAU.String(),
		"stakedSupply":      staked.String(),
	}, nil
}

// GetFeeDistribution returns the fee distribution configuration and statistics.
func (api *EconomicsAPI) GetFeeDistribution(ctx context.Context, params json.RawMessage) (any, *Error) {
	result := map[string]any{}

	if api.feeDistributor != nil {
		cfg := api.feeDistributor.GetConfig()
		pool := api.feeDistributor.GetPool()
		result["config"] = map[string]any{
			"validatorShare":       cfg.ValidatorShare,
			"burnShare":            cfg.BurnShare,
			"treasuryShare":        cfg.TreasuryShare,
			"developerShare":       cfg.DeveloperShare,
			"insuranceShare":       cfg.InsuranceShare,
			"distributionInterval": cfg.DistributionInterval,
		}
		result["pool"] = map[string]any{
			"validatorPool":    pool.ValidatorPool.String(),
			"burnPool":         pool.BurnPool.String(),
			"treasuryPool":     pool.TreasuryPool.String(),
			"developerPool":    pool.DeveloperPool.String(),
			"insurancePool":    pool.InsurancePool.String(),
			"totalCollected":   pool.TotalCollected.String(),
			"totalDistributed": pool.TotalDistributed.String(),
			"totalBurned":      pool.TotalBurned.String(),
		}
		result["burnRate"] = api.feeDistributor.GetBurnRate().String()
	}

	if api.gasFeeCollector != nil {
		result["gasFeeCollector"] = map[string]any{
			"baseFee":         api.gasFeeCollector.GetBaseFee().String(),
			"accumulatedFees": api.gasFeeCollector.GetAccumulatedFees().String(),
			"totalBurned":     api.gasFeeCollector.GetTotalBurned().String(),
		}
		gfcCfg := api.gasFeeCollector.GetConfig()
		result["gasFeeConfig"] = map[string]any{
			"baseFee":           gfcCfg.BaseFee.String(),
			"burnRate":          gfcCfg.BurnRate,
			"proposerRate":      gfcCfg.ProposerRate,
			"validatorPoolRate": gfcCfg.ValidatorPoolRate,
		}
	}

	if len(result) == 0 {
		return nil, &Error{Code: -32601, Message: "fee distribution not available"}
	}

	return result, nil
}

// GetRewardStats returns reward calculation statistics.
func (api *EconomicsAPI) GetRewardStats(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.rewardCalculator == nil {
		return nil, &Error{Code: -32601, Message: "reward calculator not available"}
	}

	height := api.currentHeight()
	cfg := api.rewardCalculator.GetConfig()

	result := map[string]any{
		"config": map[string]any{
			"initialBlockReward": cfg.InitialBlockReward.String(),
			"halvingInterval":    cfg.HalvingInterval,
			"minBlockReward":     cfg.MinBlockReward.String(),
			"inflationRate":      cfg.InflationRate,
			"blocksPerYear":      cfg.BlocksPerYear,
		},
		"currentBlockReward": api.rewardCalculator.CalculateBlockReward(height).String(),
		"halvingEpoch":       api.rewardCalculator.GetHalvingEpoch(height),
		"nextHalvingBlock":   api.rewardCalculator.GetNextHalvingBlock(height),
		"currentHeight":      height,
	}

	if api.rewardDistributor != nil {
		result["proposerShare"] = api.rewardDistributor.ProposerShare
	}

	return result, nil
}

// GetDeFiIncentives returns DeFi incentive programs and optionally a user's rewards.
// Params: {user?}  (user address is optional)
func (api *EconomicsAPI) GetDeFiIncentives(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.defiIncentiveManager == nil {
		return nil, &Error{Code: -32601, Message: "DeFi incentive manager not available"}
	}

	result := map[string]any{
		"activePrograms":   incentiveProgramsToMaps(api.defiIncentiveManager.ListActivePrograms()),
		"totalDistributed": api.defiIncentiveManager.GetTotalDistributed().String(),
		"remainingBudget":  api.defiIncentiveManager.GetRemainingBudget().String(),
	}

	// Optional: parse user address to return their claims
	if len(params) > 0 && string(params) != "null" && string(params) != "[]" {
		params, rerr := unwrapParams(params)
		if rerr == nil {
			var req struct {
				User string `json:"user"`
			}
			if err := json.Unmarshal(params, &req); err == nil && req.User != "" {
				user, addrErr := types.ParseHexAddress(req.User)
				if addrErr == nil {
					claims := api.defiIncentiveManager.GetClaimsByUser(user)
					result["userClaims"] = incentiveClaimsToMaps(claims)
				}
			}
		}
	}

	return result, nil
}

// ClaimDeFiIncentives claims DeFi incentives for a user.
// CRITICAL C-1 FIX: requires Dilithium3 signature verification.
// Params: {programId, claimant, nonce, signature, publicKey}
func (api *EconomicsAPI) ClaimDeFiIncentives(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.defiIncentiveManager == nil {
		return nil, &Error{Code: -32601, Message: "DeFi incentive manager not available"}
	}

	params, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		ProgramID string `json:"programId"`
		Claimant  string `json:"claimant"`
		Nonce     string `json:"nonce"`
		Signature string `json:"signature"`
		PublicKey string `json:"publicKey"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	claimant, err := types.ParseHexAddress(req.Claimant)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid claimant address: " + err.Error()}
	}

	authParams := req.ProgramID + req.Claimant
	if err := api.verifyEconomicsSignature("qau_claimDeFiIncentives", claimant, req.Nonce, authParams, req.Signature, req.PublicKey); err != nil {
		return nil, &Error{Code: -32603, Message: "signature verification required: " + err.Error()}
	}

	claim, err := api.defiIncentiveManager.ClaimReward(req.ProgramID, claimant, api.currentHeight())
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}

	return map[string]any{
		"success":     true,
		"programId":   claim.ProgramID,
		"claimant":    claim.Claimant.ToHexAddress(),
		"amount":      claim.Amount.String(),
		"blockHeight": claim.BlockHeight,
		"timestamp":   claim.Timestamp,
	}, nil
}

// LiquidStake stakes QAU to receive qAU liquid staking tokens.
// CRITICAL C-1 FIX: requires Dilithium3 signature verification.
// Params: {poolId, delegator, amount, nonce, signature, publicKey}
func (api *EconomicsAPI) LiquidStake(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.liquidStakingManager == nil {
		return nil, &Error{Code: -32601, Message: "liquid staking manager not available"}
	}

	params, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		PoolID    string `json:"poolId"`
		Delegator string `json:"delegator"`
		Amount    string `json:"amount"`
		Nonce     string `json:"nonce"`
		Signature string `json:"signature"`
		PublicKey string `json:"publicKey"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	delegator, err := types.ParseHexAddress(req.Delegator)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid delegator address: " + err.Error()}
	}

	amount, ok := new(big.Int).SetString(req.Amount, 10)
	if !ok {
		return nil, &Error{Code: -32602, Message: "invalid amount"}
	}

	authParams := req.PoolID + req.Delegator + req.Amount
	if err := api.verifyEconomicsSignature("qau_liquidStake", delegator, req.Nonce, authParams, req.Signature, req.PublicKey); err != nil {
		return nil, &Error{Code: -32603, Message: "signature verification required: " + err.Error()}
	}

	token, err := api.liquidStakingManager.StakeLiquid(req.PoolID, delegator, amount)
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}

	rate, _ := api.liquidStakingManager.GetExchangeRate(req.PoolID)
	rateStr := "0"
	if rate != nil {
		rateStr = rate.String()
	}

	return map[string]any{
		"success":      true,
		"poolId":       token.PoolID,
		"delegator":    token.Owner.ToHexAddress(),
		"stakedAmount": amount.String(),
		"liquidTokens": token.Amount.String(),
		"exchangeRate": rateStr,
	}, nil
}

// LiquidUnstake burns qAU liquid staking tokens to receive QAU back.
// CRITICAL C-1 FIX: requires Dilithium3 signature verification.
// Params: {poolId, delegator, liquidAmount, nonce, signature, publicKey}
func (api *EconomicsAPI) LiquidUnstake(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.liquidStakingManager == nil {
		return nil, &Error{Code: -32601, Message: "liquid staking manager not available"}
	}

	params, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		PoolID       string `json:"poolId"`
		Delegator    string `json:"delegator"`
		LiquidAmount string `json:"liquidAmount"`
		Nonce        string `json:"nonce"`
		Signature    string `json:"signature"`
		PublicKey    string `json:"publicKey"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	delegator, err := types.ParseHexAddress(req.Delegator)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid delegator address: " + err.Error()}
	}

	liquidAmount, ok := new(big.Int).SetString(req.LiquidAmount, 10)
	if !ok {
		return nil, &Error{Code: -32602, Message: "invalid liquid amount"}
	}

	authParams := req.PoolID + req.Delegator + req.LiquidAmount
	if err := api.verifyEconomicsSignature("qau_liquidUnstake", delegator, req.Nonce, authParams, req.Signature, req.PublicKey); err != nil {
		return nil, &Error{Code: -32603, Message: "signature verification required: " + err.Error()}
	}

	underlying, err := api.liquidStakingManager.UnstakeLiquid(req.PoolID, delegator, liquidAmount)
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}

	return map[string]any{
		"success":          true,
		"poolId":           req.PoolID,
		"delegator":        delegator.ToHexAddress(),
		"liquidAmount":     liquidAmount.String(),
		"underlyingAmount": underlying.String(),
	}, nil
}

// GetExchangeRate returns the QAU/qAU exchange rate for a pool.
// Params: [poolId]
func (api *EconomicsAPI) GetExchangeRate(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.liquidStakingManager == nil {
		return nil, &Error{Code: -32601, Message: "liquid staking manager not available"}
	}

	var arr []string
	if err := json.Unmarshal(params, &arr); err != nil || len(arr) == 0 {
		return nil, &Error{Code: -32602, Message: "invalid params: expected [poolId]"}
	}

	rate, err := api.liquidStakingManager.GetExchangeRate(arr[0])
	if err != nil {
		return nil, &Error{Code: -32000, Message: err.Error()}
	}

	return map[string]any{
		"poolId":       arr[0],
		"exchangeRate": rate.String(),
	}, nil
}

// GetLiquidStakingPosition returns a user's liquid staking position in a pool.
// Params: {poolId, delegator}
func (api *EconomicsAPI) GetLiquidStakingPosition(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.liquidStakingManager == nil {
		return nil, &Error{Code: -32601, Message: "liquid staking manager not available"}
	}

	params, rerr := unwrapParams(params)
	if rerr != nil {
		return nil, rerr
	}

	var req struct {
		PoolID    string `json:"poolId"`
		Delegator string `json:"delegator"`
	}
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, &Error{Code: -32602, Message: "invalid params: " + err.Error()}
	}

	delegator, err := types.ParseHexAddress(req.Delegator)
	if err != nil {
		return nil, &Error{Code: -32602, Message: "invalid delegator address: " + err.Error()}
	}

	stakedAmount := api.liquidStakingManager.GetDelegatorStake(req.PoolID, delegator)

	result := map[string]any{
		"poolId":       req.PoolID,
		"delegator":    delegator.ToHexAddress(),
		"stakedAmount": stakedAmount.String(),
		"poolActive":   false,
	}

	pool, err := api.liquidStakingManager.GetPool(req.PoolID)
	if err == nil && pool != nil {
		result["poolTotalStaked"] = pool.TotalStaked.String()
		result["poolTotalLiquidSupply"] = pool.TotalLiquidSupply.String()
		result["poolActive"] = pool.Active
		result["poolOperator"] = pool.Operator.ToHexAddress()
		result["commissionRate"] = pool.CommissionRate
	}

	rate, rateErr := api.liquidStakingManager.GetExchangeRate(req.PoolID)
	if rateErr == nil && rate != nil {
		result["exchangeRate"] = rate.String()
	}

	return result, nil
}

// inflationPhaseString returns the string representation of an inflation phase.
func inflationPhaseString(phase economics.InflationPhase) string {
	switch phase {
	case economics.InflationPhaseHigh:
		return "high"
	case economics.InflationPhaseModerate:
		return "moderate"
	case economics.InflationPhaseLow:
		return "low"
	case economics.InflationPhaseStable:
		return "stable"
	default:
		return "unknown"
	}
}

// incentiveTypeString returns the string representation of an incentive type.
func incentiveTypeString(t economics.IncentiveType) string {
	switch t {
	case economics.IncentiveTypeLiquidityProvision:
		return "liquidityProvision"
	case economics.IncentiveTypeTradingVolume:
		return "tradingVolume"
	case economics.IncentiveTypeProtocolUsage:
		return "protocolUsage"
	case economics.IncentiveTypeGovernanceParticipation:
		return "governanceParticipation"
	case economics.IncentiveTypeDeveloperGrant:
		return "developerGrant"
	default:
		return "unknown"
	}
}

// incentiveProgramsToMaps converts a slice of IncentiveProgram to a slice of maps.
func incentiveProgramsToMaps(programs []*economics.IncentiveProgram) []map[string]any {
	result := make([]map[string]any, 0, len(programs))
	for _, p := range programs {
		if p == nil {
			continue
		}
		result = append(result, map[string]any{
			"id":              p.ID,
			"name":            p.Name,
			"type":            incentiveTypeString(p.Type),
			"totalBudget":     p.TotalBudget.String(),
			"remainingBudget": p.RemainingBudget.String(),
			"rewardPerAction": p.RewardPerAction.String(),
			"startBlock":      p.StartBlock,
			"endBlock":        p.EndBlock,
			"maxParticipants": p.MaxParticipants,
			"active":          p.Active,
			"createdAt":       p.CreatedAt,
		})
	}
	return result
}

// incentiveClaimsToMaps converts a slice of IncentiveClaim to a slice of maps.
func incentiveClaimsToMaps(claims []*economics.IncentiveClaim) []map[string]any {
	result := make([]map[string]any, 0, len(claims))
	for _, c := range claims {
		if c == nil {
			continue
		}
		result = append(result, map[string]any{
			"programId":   c.ProgramID,
			"claimant":    c.Claimant.ToHexAddress(),
			"amount":      c.Amount.String(),
			"blockHeight": c.BlockHeight,
			"timestamp":   c.Timestamp,
			"actionType":  c.ActionType,
		})
	}
	return result
}
