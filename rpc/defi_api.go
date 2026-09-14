// Quantaureum Node source, version 1.0.0.
// DeFi RPC API - Liquidity Pools, Lending, and Yield Farming
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

// DeFiAPI provides DeFi RPC methods
type DeFiAPI struct {
	defiManager *economics.DeFiManager
	blockReader BlockReader
	chainID     uint64

	// audit-fix R4-M1: nonce tracking for replay protection on signed DeFi operations.
	// audit-fix M-3: track insertion time so eviction removes oldest entries.
	nonceMu    sync.Mutex
	usedNonces map[types.Address]map[string]time.Time // address -> nonce -> insertion time

	// FIX: optional admin allowlist for state-mutating DeFi operations.
	// When non-empty, only addresses in this set may perform admin-gated
	// operations. When empty, no restriction is enforced (backward-compatible).
	adminAddrs map[types.Address]bool

	// /FIX: enforceAdminAuth enables fail-closed admin checks.
	// When true (production mode), requireAdmin returns an error if the admin
	// allowlist is nil/empty, blocking all state-mutating DeFi operations until
	// admin addresses are configured. When false (default, test/dev mode), the
	// allowlist is optional (backward-compatible).
	enforceAdminAuth bool
}

// maxNoncesPerAddress is the maximum number of tracked nonces per address.
// audit-fix R4-M1: bounded to prevent unbounded memory growth.
const maxNoncesPerAddress = 10000

// maxDeFiTrackedAddresses is the maximum number of addresses tracked for DeFi nonces.
const maxDeFiTrackedAddresses = 100000

// NewDeFiAPI creates a new DeFi API
func NewDeFiAPI(dm *economics.DeFiManager, br BlockReader) *DeFiAPI {
	// FIX: Default enforceAdminAuth to true (fail-closed).
	// Tests that don't need admin enforcement should call SetEnforceAdminAuth(false).
	return &DeFiAPI{
		defiManager:      dm,
		blockReader:      br,
		usedNonces:       make(map[types.Address]map[string]time.Time),
		enforceAdminAuth: true, //  fail-closed by default
	}
}

func (api *DeFiAPI) SetChainID(id uint64) {
	api.chainID = id
}

// SetAdminAddresses configures the admin allowlist for state-mutating DeFi operations.
// FIX: when non-empty, only these addresses may perform admin-gated operations.
func (api *DeFiAPI) SetAdminAddresses(addrs []types.Address) {
	api.adminAddrs = make(map[types.Address]bool, len(addrs))
	for _, a := range addrs {
		api.adminAddrs[a] = true
	}
}

// SetEnforceAdminAuth enables fail-closed admin authentication.
// /FIX: when enabled (production mode), requireAuthorizedUser
// rejects all state-mutating DeFi operations if no admin allowlist has been
// configured, preventing unauthorized access when the admin list is empty.
// When disabled (default), the allowlist is optional (backward-compatible).
func (api *DeFiAPI) SetEnforceAdminAuth(enabled bool) {
	api.enforceAdminAuth = enabled
}

// requireAuthorizedUser returns an error when an allowlist is configured and
// the given address is not in it.
//
// AUDIT (2026) API-07 FIX: Renamed from requireAdmin to clarify semantics.
// This is a USER ALLOWLIST check (authorized-user gating), NOT an admin
// privilege check. The adminAddrs field is a per-user allowlist that controls
// who can call state-mutating DeFi operations — it is not the same as the
// server-level admin authorization in ValidateAdminRequest. The old name
// caused confusion about what security boundary was being enforced.
//
// /FIX: when enforceAdminAuth is true (production mode) and the
// allowlist is nil/empty, this fails-closed, returning an error instead of
// allowing unauthenticated access. When enforceAdminAuth is false (default,
// test/dev mode), an empty allowlist means no restriction (backward-compatible).
func (api *DeFiAPI) requireAuthorizedUser(addr types.Address) error {
	if api.enforceAdminAuth && len(api.adminAddrs) == 0 {
		return fmt.Errorf("authorized-user allowlist not configured: state-mutating DeFi operations are blocked until authorized addresses are set")
	}
	if len(api.adminAddrs) == 0 {
		return nil
	}
	if !api.adminAddrs[addr] {
		return fmt.Errorf("address %s is not in the authorized-user allowlist for DeFi operations", addr.ToHexAddress())
	}
	return nil
}

//	This method uses a non-standard name. The convention across
//
// other API structs (API, DebugAPI, ProofAPI, etc.) is RegisterHandlers.
// The original name is retained for backward compatibility; a
// RegisterHandlers alias is defined below.
// RegisterDeFiHandlers registers all DeFi API handlers
func (api *DeFiAPI) RegisterDeFiHandlers(server *Server) {
	// Liquidity Pool methods (read-only)
	server.RegisterHandler("qau_getLiquidityPools", api.GetLiquidityPools)
	server.RegisterHandler("qau_getLiquidityPool", api.GetLiquidityPool)
	server.RegisterHandler("qau_getSwapQuote", api.GetSwapQuote)
	server.RegisterHandler("qau_getUserLPBalance", api.GetUserLPBalance)

	// Liquidity Pool methods (state-mutating, require signature)
	// audit-fix R3-H3: these endpoints now require Dilithium3 signature verification
	server.RegisterHandler("qau_addLiquidity", api.AddLiquidity)
	server.RegisterHandler("qau_removeLiquidity", api.RemoveLiquidity)
	server.RegisterHandler("qau_swap", api.Swap)

	// Lending methods (read-only)
	server.RegisterHandler("qau_getLendingPools", api.GetLendingPools)
	server.RegisterHandler("qau_getLendingPool", api.GetLendingPool)
	server.RegisterHandler("qau_getUserLendingPosition", api.GetUserLendingPosition)

	// Lending methods (state-mutating, require signature)
	server.RegisterHandler("qau_supply", api.Supply)
	server.RegisterHandler("qau_withdraw", api.Withdraw)
	server.RegisterHandler("qau_borrow", api.Borrow)
	server.RegisterHandler("qau_repay", api.Repay)
	server.RegisterHandler("qau_liquidate", api.Liquidate)

	// Yield Farming methods (read-only)
	server.RegisterHandler("qau_getYieldFarms", api.GetYieldFarms)
	server.RegisterHandler("qau_getYieldFarm", api.GetYieldFarm)
	server.RegisterHandler("qau_getFarmPendingReward", api.GetFarmPendingReward)
	server.RegisterHandler("qau_getUserFarmStake", api.GetUserFarmStake)

	// Yield Farming methods (state-mutating, require signature)
	server.RegisterHandler("qau_stakeFarm", api.StakeFarm)
	server.RegisterHandler("qau_unstakeFarm", api.UnstakeFarm)
	server.RegisterHandler("qau_harvestFarm", api.HarvestFarm)
}

// RegisterHandlers is an alias for RegisterDeFiHandlers, following the
// standard naming convention used by other API structs ().
func (api *DeFiAPI) RegisterHandlers(server *Server) {
	api.RegisterDeFiHandlers(server)
}

// verifyDeFiSignature verifies a Dilithium3 signature for a DeFi operation.
// audit-fix R3-H3: all state-mutating DeFi RPC calls must include a signature
// proving ownership of the address being operated on.
// audit-fix R4-M1: includes nonce in signed message to prevent replay attacks.
// The signature should be over: method || userAddress || nonce || params...
// Format: signature is hex-encoded Dilithium3 signature, pubKey is hex-encoded public key.
func (api *DeFiAPI) verifyDeFiSignature(method string, userAddr types.Address, nonce, params string, signature, pubKeyHex string) error {
	// FIX: enforce admin allowlist when configured for state-mutating operations.
	if err := api.requireAuthorizedUser(userAddr); err != nil {
		return err
	}
	if signature == "" || pubKeyHex == "" {
		return fmt.Errorf("signature and publicKey are required for state-mutating DeFi operations")
	}
	if nonce == "" {
		return fmt.Errorf("nonce is required for replay protection")
	}

	// LOW-2 FIX: Reserve the nonce under lock with a "pending" marker (zero time).
	// This closes the window between check and record where concurrent requests
	// with the same nonce could both pass the uniqueness check.
	// If signature verification fails, we roll back by deleting the pending entry.
	api.nonceMu.Lock()
	// FIX: check global limit regardless of whether address exists
	if len(api.usedNonces) > maxDeFiTrackedAddresses {
		api.nonceMu.Unlock()
		return fmt.Errorf("too many tracked addresses (memory limit)")
	}
	if api.usedNonces[userAddr] == nil {
		api.usedNonces[userAddr] = make(map[string]time.Time)
	}
	// M-NEW-1 FIX: Evict nonces older than 10 minutes for time-based expiration.
	const defiNonceTTL = 10 * time.Minute
	now := time.Now()
	for k, ts := range api.usedNonces[userAddr] {
		if !ts.IsZero() && now.Sub(ts) > defiNonceTTL {
			delete(api.usedNonces[userAddr], k)
		}
	}
	if _, used := api.usedNonces[userAddr][nonce]; used {
		api.nonceMu.Unlock()
		return fmt.Errorf("nonce already used (replay detected)")
	}
	// LOW-2 FIX: Mark nonce as pending (zero time = pending, non-zero = confirmed).
	// Concurrent requests with the same nonce will see it as "used" and be rejected.
	api.usedNonces[userAddr][nonce] = time.Time{} // zero Time = pending marker
	api.nonceMu.Unlock()

	// Parse signature
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(signature, "0x"))
	if err != nil {
		api.rollbackPendingNonce(userAddr, nonce)
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	// Parse public key
	pubKeyBytes, err := hex.DecodeString(strings.TrimPrefix(pubKeyHex, "0x"))
	if err != nil {
		api.rollbackPendingNonce(userAddr, nonce)
		return fmt.Errorf("invalid publicKey hex: %w", err)
	}

	pubKey, err := crypto.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		api.rollbackPendingNonce(userAddr, nonce)
		return fmt.Errorf("invalid Dilithium3 public key: %w", err)
	}

	// Verify the public key corresponds to the claimed address
	derivedAddr := pubKey.Address()
	if derivedAddr != userAddr {
		api.rollbackPendingNonce(userAddr, nonce)
		return fmt.Errorf("public key does not match claimed address")
	}

	// audit-fix R4-M1: Construct message with nonce: method || address || nonce || params
	// M-NEW-6 FIX: Use delimiter to prevent field collision attacks
	// CRITICAL-1/HIGH-2 FIX: Include ChainID and QAU- domain prefix to prevent cross-chain replay
	message := []byte(fmt.Sprintf("QAU-%s|%d|%s|%s|%s", method, api.chainID, userAddr.ToHexAddress(), nonce, params))

	// Verify Dilithium3 signature
	if !crypto.Verify(pubKey, message, sigBytes) {
		api.rollbackPendingNonce(userAddr, nonce)
		return fmt.Errorf("signature verification failed")
	}

	// LOW-2 FIX: Confirm the nonce by updating its timestamp from pending (zero) to now.
	api.nonceMu.Lock()
	// audit-fix M-3: evict oldest nonces (by insertion time) if limit reached,
	// so that recently-used nonces are always retained for replay detection.
	if len(api.usedNonces[userAddr]) >= maxNoncesPerAddress {
		type nonceEntry struct {
			nonce string
			ts    time.Time
		}
		entries := make([]nonceEntry, 0, len(api.usedNonces[userAddr]))
		for k, ts := range api.usedNonces[userAddr] {
			if !ts.IsZero() {
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

// rollbackPendingNonce removes a pending nonce reservation when signature verification fails.
// LOW-2 FIX: This prevents nonces from being permanently consumed by failed requests,
// while still blocking concurrent requests during the verification window.
func (api *DeFiAPI) rollbackPendingNonce(userAddr types.Address, nonce string) {
	api.nonceMu.Lock()
	defer api.nonceMu.Unlock()
	if nonces, ok := api.usedNonces[userAddr]; ok {
		// Only delete if still in pending state (zero time) — don't delete confirmed nonces
		if ts, exists := nonces[nonce]; exists && ts.IsZero() {
			delete(nonces, nonce)
		}
	}
}

// extractDeFiAuth extracts nonce, signature and publicKey from args for authenticated operations.
// audit-fix R4-M1: now also extracts nonce for replay protection.
// Returns the remaining args (without auth fields), nonce, signature, publicKey, and any error.
// Auth fields are at the end: [...params, nonce, signature, publicKey]
func extractDeFiAuth(args []any, minArgs int) ([]any, string, string, string, *Error) {
	if len(args) < minArgs+3 {
		return nil, "", "", "", NewErrorWithData(ErrCodeInvalidParams, "missing authentication",
			"state-mutating DeFi operations require nonce, signature, and publicKey parameters")
	}

	nonce, ok := args[len(args)-3].(string)
	if !ok {
		return nil, "", "", "", NewErrorWithData(ErrCodeInvalidParams, "invalid nonce", "nonce must be a string")
	}

	sig, ok := args[len(args)-2].(string)
	if !ok {
		return nil, "", "", "", NewErrorWithData(ErrCodeInvalidParams, "invalid signature", "signature must be a hex string")
	}

	pubKey, ok := args[len(args)-1].(string)
	if !ok {
		return nil, "", "", "", NewErrorWithData(ErrCodeInvalidParams, "invalid publicKey", "publicKey must be a hex string")
	}

	return args[:len(args)-3], nonce, sig, pubKey, nil
}

// ============================================================================
// Liquidity Pool Methods
// ============================================================================

// GetLiquidityPools returns all liquidity pools
func (api *DeFiAPI) GetLiquidityPools(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.defiManager == nil {
		return nil, NewError(ErrCodeInternal, "DeFi manager not available")
	}

	pools := api.defiManager.LiquidityManager.GetAllPools()

	result := make([]map[string]any, 0, len(pools))
	for _, pool := range pools {
		price := float64(0)
		if pool.ReserveA.Sign() > 0 {
			priceRat, err := api.defiManager.LiquidityManager.GetPrice(pool.PoolID)
			if err == nil && priceRat != nil {
				price, _ = priceRat.Float64()
			}
		}

		// Calculate APY based on fee revenue (simplified)
		apy := float64(pool.FeeRate) * 365 / 100 // Rough estimate

		result = append(result, map[string]any{
			"pool_id":         pool.PoolID,
			"token_a":         pool.TokenA,
			"token_b":         pool.TokenB,
			"reserve_a":       pool.ReserveA.String(),
			"reserve_b":       pool.ReserveB.String(),
			"total_liquidity": pool.TotalLiquidity.String(),
			"fee_rate":        float64(pool.FeeRate) / 10000,
			"price":           price,
			"apy":             apy,
			"created_at":      pool.CreatedAt.Unix(),
		})
	}

	return map[string]any{
		"pools":     result,
		"timestamp": time.Now().Unix(),
	}, nil
}

// GetLiquidityPool returns a specific liquidity pool
func (api *DeFiAPI) GetLiquidityPool(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	poolID := args[0]
	pool, err := api.defiManager.LiquidityManager.GetPool(poolID)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, err.Error())
	}

	price := float64(0)
	if pool.ReserveA.Sign() > 0 {
		priceRat, err := api.defiManager.LiquidityManager.GetPrice(pool.PoolID)
		if err == nil && priceRat != nil {
			price, _ = priceRat.Float64()
		}
	}

	return map[string]any{
		"pool_id":         pool.PoolID,
		"token_a":         pool.TokenA,
		"token_b":         pool.TokenB,
		"reserve_a":       pool.ReserveA.String(),
		"reserve_b":       pool.ReserveB.String(),
		"total_liquidity": pool.TotalLiquidity.String(),
		"fee_rate":        float64(pool.FeeRate) / 10000,
		"price":           price,
		"created_at":      pool.CreatedAt.Unix(),
	}, nil
}

// AddLiquidity adds liquidity to a pool
// audit-fix R3-H3: requires signature and publicKey to prove address ownership.
// R45-M-M3 FIX: Added slippage protection for sandwich attack prevention.
// Parameters: [poolID, userAddress, amountA, amountB, minLPTokens?, nonce, signature, publicKey]
func (api *DeFiAPI) AddLiquidity(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, ErrInvalidParams
	}

	// R45-M-M3 FIX: Parse optional minLPTokens slippage parameter (at index 4).
	// An attacker can manipulate pool reserves between transaction signing and execution,
	// causing the user to receive fewer LP tokens than expected (sandwich attack).
	var minLPTokens *big.Int
	if len(args) >= 8 { // poolID + user + amountA + amountB + minLPTokens + nonce + sig + pubKey
		if minLPStr, ok := args[4].(string); ok {
			if parsed, ok := new(big.Int).SetString(minLPStr, 10); ok && parsed.Sign() > 0 {
				minLPTokens = parsed
			}
		}
	}

	// Extract auth params (signature + publicKey at end)
	args, nonce, sig, pubKey, authErr := extractDeFiAuth(args, 4)
	if authErr != nil {
		return nil, authErr
	}

	poolID, ok := args[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid pool_id", "pool_id must be a string")
	}

	userAddr, ok := args[1].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", "address must be a string")
	}
	user, err := parseAddress(userAddr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", err.Error())
	}

	amountAStr, ok := args[2].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount_a", "amount must be a string")
	}
	amountA, ok := new(big.Int).SetString(amountAStr, 10)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount_a", "cannot parse amount")
	}

	amountBStr, ok := args[3].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount_b", "amount must be a string")
	}
	amountB, ok := new(big.Int).SetString(amountBStr, 10)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount_b", "cannot parse amount")
	}

	// R45-M-M3 FIX: Include minLPTokens in signature for replay protection.
	authParams := poolID + amountAStr + amountBStr
	if minLPTokens != nil {
		authParams += minLPTokens.String()
	}
	if err := api.verifyDeFiSignature("qau_addLiquidity", user, nonce, authParams, sig, pubKey); err != nil {
		return nil, NewError(ErrCodeUnauthorized, err.Error())
	}

	// H-1 FIX: Pre-validate slippage BEFORE mutating state.
	// Estimate LP tokens from current pool reserves and reject if the estimate
	// is below the user's minimum. This prevents the state-change-without-rollback
	// issue where AddLiquidity succeeds but the slippage check fails, leaving
	// the pool in a modified state with no way to undo.
	if minLPTokens != nil {
		pool, poolErr := api.defiManager.LiquidityManager.GetPool(poolID)
		if poolErr == nil && pool != nil && pool.TotalLiquidity.Sign() > 0 {
			// Estimate LP tokens: sqrt(amountA * amountB) * totalLiquidity / sqrt(reserveA * reserveB)
			// Simplified: proportional to the smaller ratio
			ratioA := new(big.Int).Mul(amountA, pool.TotalLiquidity)
			ratioA.Div(ratioA, pool.ReserveA)
			ratioB := new(big.Int).Mul(amountB, pool.TotalLiquidity)
			ratioB.Div(ratioB, pool.ReserveB)
			estimatedLP := ratioA
			if ratioB.Cmp(ratioA) < 0 {
				estimatedLP = ratioB
			}
			if estimatedLP.Cmp(minLPTokens) < 0 {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "slippage_exceeded_add_liquidity",
					fmt.Sprintf("estimated LP tokens %s below minimum %s — slippage would exceed tolerance",
						estimatedLP.String(), minLPTokens.String()))
			}
		}
	}

	// R14-LOW (2026-07-21): Pass minLPTokens to the economics layer so
	// slippage protection is enforced at the lowest layer (inside the lock,
	// atomically with the state mutation). The post-execution check below
	// remains as defense-in-depth for callers that bypass the pre-check.
	lpTokens, err := api.defiManager.LiquidityManager.AddLiquidity(poolID, user, amountA, amountB, minLPTokens)
	if err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	// R45-M-M3 FIX: Post-execution slippage check (defense-in-depth).
	// If actual output is below minimum despite pre-check, the pool was manipulated
	// between pre-check and execution. Return error with the actual amounts so the
	// caller knows the operation went through but slippage was exceeded.
	// NOTE: The operation cannot be rolled back at this layer; the caller must
	// handle the slippage-exceeded case at the application level.
	if minLPTokens != nil && lpTokens.Cmp(minLPTokens) < 0 {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "slippage_exceeded_add_liquidity",
			fmt.Sprintf("LP tokens %s below minimum %s — possible sandwich attack or price manipulation",
				lpTokens.String(), minLPTokens.String()))
	}

	// audit-fix R10-M1: include timestamp so identical operations produce unique hashes.
	nowUnix := time.Now().Unix()
	txHash := keccak256(append(user[:], append(lpTokens.Bytes(), big.NewInt(nowUnix).Bytes()...)...))

	return map[string]any{
		"success":   true,
		"txHash":    formatHexBytes(txHash),
		"pool_id":   poolID,
		"lp_tokens": lpTokens.String(),
		"amount_a":  amountA.String(),
		"amount_b":  amountB.String(),
		"timestamp": nowUnix,
	}, nil
}

// RemoveLiquidity removes liquidity from a pool
// audit-fix R3-H3: requires signature and publicKey to prove address ownership.
// R45-M-M3 FIX: Added slippage protection for sandwich attack prevention.
// Parameters: [poolID, userAddress, lpAmount, minAmountA?, minAmountB?, nonce, signature, publicKey]
func (api *DeFiAPI) RemoveLiquidity(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, ErrInvalidParams
	}

	// R45-M-M3 FIX: Parse optional minAmountA and minAmountB slippage parameters (indices 4, 5).
	// An attacker can manipulate pool reserves between signing and execution,
	// causing the user to receive fewer tokens when removing liquidity.
	var minAmountA, minAmountB *big.Int
	if len(args) >= 9 { // poolID + user + lpAmount + minA + minB + nonce + sig + pubKey
		if minAStr, ok := args[4].(string); ok {
			if parsed, ok := new(big.Int).SetString(minAStr, 10); ok && parsed.Sign() > 0 {
				minAmountA = parsed
			}
		}
		if minBStr, ok := args[5].(string); ok {
			if parsed, ok := new(big.Int).SetString(minBStr, 10); ok && parsed.Sign() > 0 {
				minAmountB = parsed
			}
		}
	}

	args, nonce, sig, pubKey, authErr := extractDeFiAuth(args, 3)
	if authErr != nil {
		return nil, authErr
	}

	poolID, ok := args[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid pool_id", "pool_id must be a string")
	}

	userAddr, ok := args[1].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", "address must be a string")
	}
	user, err := parseAddress(userAddr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", err.Error())
	}

	lpAmountStr, ok := args[2].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid lp_amount", "amount must be a string")
	}
	lpAmount, ok := new(big.Int).SetString(lpAmountStr, 10)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid lp_amount", "cannot parse amount")
	}

	// R45-M-M3 FIX: Include slippage params in signature for replay protection.
	signedMsg := poolID + lpAmountStr
	if minAmountA != nil {
		signedMsg += minAmountA.String()
	}
	if minAmountB != nil {
		signedMsg += minAmountB.String()
	}
	if err := api.verifyDeFiSignature("qau_removeLiquidity", user, nonce, signedMsg, sig, pubKey); err != nil {
		return nil, NewError(ErrCodeUnauthorized, err.Error())
	}

	// H-1 FIX: Pre-validate slippage BEFORE mutating state for RemoveLiquidity.
	// Estimate the token amounts the user will receive and reject if below minimums.
	if (minAmountA != nil || minAmountB != nil) && lpAmount.Sign() > 0 {
		pool, poolErr := api.defiManager.LiquidityManager.GetPool(poolID)
		if poolErr == nil && pool != nil && pool.TotalLiquidity.Sign() > 0 {
			// Estimate proportional share: share = lpAmount / totalLiquidity
			// estimatedA = share * reserveA, estimatedB = share * reserveB
			estA := new(big.Int).Mul(lpAmount, pool.ReserveA)
			estA.Div(estA, pool.TotalLiquidity)
			estB := new(big.Int).Mul(lpAmount, pool.ReserveB)
			estB.Div(estB, pool.TotalLiquidity)
			if minAmountA != nil && estA.Cmp(minAmountA) < 0 {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "slippage_exceeded_remove_liquidity",
					fmt.Sprintf("estimated token A %s below minimum %s — slippage would exceed tolerance",
						estA.String(), minAmountA.String()))
			}
			if minAmountB != nil && estB.Cmp(minAmountB) < 0 {
				return nil, NewErrorWithData(ErrCodeInvalidParams, "slippage_exceeded_remove_liquidity",
					fmt.Sprintf("estimated token B %s below minimum %s — slippage would exceed tolerance",
						estB.String(), minAmountB.String()))
			}
		}
	}

	amountA, amountB, err := api.defiManager.LiquidityManager.RemoveLiquidity(poolID, user, lpAmount)
	if err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	// R45-M-M3 FIX: Post-execution slippage check (defense-in-depth).
	if minAmountA != nil && amountA.Cmp(minAmountA) < 0 {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "slippage_exceeded_remove_liquidity",
			fmt.Sprintf("token A amount %s below minimum %s — possible sandwich attack or price manipulation",
				amountA.String(), minAmountA.String()))
	}
	if minAmountB != nil && amountB.Cmp(minAmountB) < 0 {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "slippage_exceeded_remove_liquidity",
			fmt.Sprintf("token B amount %s below minimum %s — possible sandwich attack or price manipulation",
				amountB.String(), minAmountB.String()))
	}

	// audit-fix R10-M1: include timestamp so identical operations produce unique hashes.
	nowUnix := time.Now().Unix()
	txHash := keccak256(append(user[:], append(lpAmount.Bytes(), big.NewInt(nowUnix).Bytes()...)...))

	return map[string]any{
		"success":   true,
		"txHash":    formatHexBytes(txHash),
		"pool_id":   poolID,
		"amount_a":  amountA.String(),
		"amount_b":  amountB.String(),
		"lp_burned": lpAmount.String(),
		"timestamp": nowUnix,
	}, nil
}

// Swap performs a token swap
// audit-fix R3-H3: requires signature and publicKey to prove address ownership.
// audit-fix  accepts optional minAmountOut parameter for slippage protection.
// Parameters: [poolID, tokenIn, amountIn, userAddress, minAmountOut?, signature, publicKey]
func (api *DeFiAPI) Swap(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, ErrInvalidParams
	}

	// SECURITY FIX: Require minAmountOut for slippage protection.
	// Previously it was optional and silently defaulted to nil, enabling flash loan attacks.
	const (
		// Slippage protection bounds (in basis points, 100 = 1%)
		MinSlippageBasisPoints = 50   // 0.5% minimum acceptable slippage
		MaxSlippageBasisPoints = 5000 // 50% maximum acceptable slippage
	)

	var minAmountOut *big.Int
	if len(args) >= 6 {
		// minAmountOut may be at index 4 (before auth params)
		if minAmountStr, ok := args[4].(string); ok {
			if parsed, ok := new(big.Int).SetString(minAmountStr, 10); ok && parsed.Sign() > 0 {
				minAmountOut = parsed
			}
		}
	}

	// SECURITY FIX: Reject swap if minAmountOut is not provided.
	// Slippage protection is mandatory to prevent flash loan attacks.
	if minAmountOut == nil || minAmountOut.Sign() <= 0 {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "min_amount_out_required",
			"slippage protection is mandatory: provide min_amount_out parameter")
	}

	args, nonce, sig, pubKey, authErr := extractDeFiAuth(args, 4)
	if authErr != nil {
		return nil, authErr
	}

	poolID, ok := args[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid pool_id", "pool_id must be a string")
	}

	tokenIn, ok := args[1].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid token_in", "token must be a string")
	}

	amountInStr, ok := args[2].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount_in", "amount must be a string")
	}
	amountIn, ok := new(big.Int).SetString(amountInStr, 10)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount_in", "cannot parse amount")
	}

	userAddr, ok := args[3].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", "address must be a string")
	}
	user, err := parseAddress(userAddr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", err.Error())
	}

	// M-NEW-4 FIX: Validate minAmountOut is within reasonable range of the expected
	// output. Get a quote first and reject if minAmountOut is less than 50% of the
	// expected output (which effectively bypasses slippage protection).
	pool, poolErr := api.defiManager.LiquidityManager.GetPool(poolID)
	if poolErr == nil && pool != nil {
		// Calculate expected output
		var reserveIn, reserveOut *big.Int
		if tokenIn == pool.TokenA {
			reserveIn, reserveOut = pool.ReserveA, pool.ReserveB
		} else {
			reserveIn, reserveOut = pool.ReserveB, pool.ReserveA
		}
		if reserveIn != nil && reserveOut != nil && reserveIn.Sign() > 0 {
			feeMultiplier := big.NewInt(int64(10000 - pool.FeeRate)) //nolint:gosec,G115
			amountInWithFee := new(big.Int).Mul(amountIn, feeMultiplier)
			numerator := new(big.Int).Mul(reserveOut, amountInWithFee)
			denominator := new(big.Int).Mul(reserveIn, big.NewInt(10000))
			denominator.Add(denominator, amountInWithFee)
			if denominator.Sign() > 0 {
				expectedOut := new(big.Int).Div(numerator, denominator)
				if expectedOut.Sign() > 0 {
					// M-NEW-4 FIX: Require minAmountOut >= 50% of expected output
					minReasonable := new(big.Int).Div(expectedOut, big.NewInt(2))
					if minAmountOut.Cmp(minReasonable) < 0 {
						return nil, NewErrorWithData(ErrCodeInvalidParams, "slippage_too_high",
							fmt.Sprintf("min_amount_out %s is less than 50%% of expected output %s — slippage protection is effectively disabled",
								minAmountOut.String(), expectedOut.String()))
					}
				}
			}
		}
	}

	// Include minAmountOut in signed message for replay protection
	signedMsg := poolID + tokenIn + amountInStr + minAmountOut.String()
	if err := api.verifyDeFiSignature("qau_swap", user, nonce, signedMsg, sig, pubKey); err != nil {
		return nil, NewError(ErrCodeUnauthorized, err.Error())
	}

	// audit-fix  pass user-provided minAmountOut for slippage protection
	// ECON- pass the verified user address so Swap can debit/credit
	// the user's per-token balance. Previously the user address was verified
	// only for signature check but never passed to Swap, which meant Swap
	// updated pool reserves without any corresponding fund movement.
	amountOut, err := api.defiManager.LiquidityManager.Swap(poolID, user, tokenIn, amountIn, minAmountOut)
	if err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	// audit-fix R10-M1: include user and timestamp so identical operations produce unique hashes.
	// audit-fix R10-L1: include user address (previously missing, causing cross-user collisions).
	nowUnix := time.Now().Unix()
	txHash := keccak256(append(user[:], append([]byte(poolID), append(amountIn.Bytes(), big.NewInt(nowUnix).Bytes()...)...)...))

	return map[string]any{
		"success":    true,
		"txHash":     formatHexBytes(txHash),
		"pool_id":    poolID,
		"token_in":   tokenIn,
		"amount_in":  amountIn.String(),
		"amount_out": amountOut.String(),
		"timestamp":  nowUnix,
	}, nil
}

// GetSwapQuote returns a quote for a swap without executing
func (api *DeFiAPI) GetSwapQuote(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 3 {
		return nil, ErrInvalidParams
	}

	poolID, ok := args[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid pool_id", "pool_id must be a string")
	}

	tokenIn, ok := args[1].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid token_in", "token must be a string")
	}

	amountInStr, ok := args[2].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount_in", "amount must be a string")
	}
	amountIn, ok := new(big.Int).SetString(amountInStr, 10)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount_in", "cannot parse amount")
	}

	pool, err := api.defiManager.LiquidityManager.GetPool(poolID)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, err.Error())
	}

	// Calculate output without modifying state
	var reserveIn, reserveOut *big.Int
	var tokenOut string
	if tokenIn == pool.TokenA {
		reserveIn = pool.ReserveA
		reserveOut = pool.ReserveB
		tokenOut = pool.TokenB
	} else {
		reserveIn = pool.ReserveB
		reserveOut = pool.ReserveA
		tokenOut = pool.TokenA
	}

	feeMultiplier := big.NewInt(int64(10000 - pool.FeeRate)) //nolint:gosec,G115
	amountInWithFee := new(big.Int).Mul(amountIn, feeMultiplier)
	numerator := new(big.Int).Mul(reserveOut, amountInWithFee)
	denominator := new(big.Int).Mul(reserveIn, big.NewInt(10000))
	denominator.Add(denominator, amountInWithFee)
	amountOut := new(big.Int).Div(numerator, denominator)

	// Calculate price impact
	priceImpact := float64(0)
	if reserveIn.Sign() > 0 {
		impact := new(big.Float).SetInt(amountIn)
		reserve := new(big.Float).SetInt(reserveIn)
		impact.Quo(impact, reserve)
		priceImpact, _ = impact.Float64()
		priceImpact *= 100
	}

	return map[string]any{
		"pool_id":      poolID,
		"token_in":     tokenIn,
		"token_out":    tokenOut,
		"amount_in":    amountIn.String(),
		"amount_out":   amountOut.String(),
		"price_impact": priceImpact,
		"fee":          float64(pool.FeeRate) / 10000,
	}, nil
}

// GetUserLPBalance returns user's LP token balance
func (api *DeFiAPI) GetUserLPBalance(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, ErrInvalidParams
	}

	poolID := args[0]
	user, err := parseAddress(args[1])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	balance, err := api.defiManager.LiquidityManager.GetUserLPBalance(poolID, user)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, err.Error())
	}

	return map[string]any{
		"pool_id": poolID,
		"address": args[1],
		"balance": balance.String(),
	}, nil
}

// ============================================================================
// Lending Methods
// ============================================================================

// GetLendingPools returns all lending pools
func (api *DeFiAPI) GetLendingPools(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.defiManager == nil {
		return nil, NewError(ErrCodeInternal, "DeFi manager not available")
	}

	pools := api.defiManager.LendingManager.GetAllPools()

	result := make([]map[string]any, 0, len(pools))
	for _, pool := range pools {
		utilization, _ := api.defiManager.LendingManager.GetUtilizationRate(pool.PoolID)

		available := new(big.Int).Sub(pool.TotalSupply, pool.TotalBorrowed)

		result = append(result, map[string]any{
			"pool_id":               pool.PoolID,
			"asset":                 pool.Asset,
			"total_supply":          pool.TotalSupply.String(),
			"total_borrowed":        pool.TotalBorrowed.String(),
			"available_to_borrow":   available.String(),
			"supply_rate":           float64(pool.SupplyRate) / 100,
			"borrow_rate":           float64(pool.BorrowRate) / 100,
			"utilization_rate":      float64(utilization) / 100,
			"collateral_factor":     float64(pool.CollateralFactor) / 100,
			"liquidation_threshold": float64(pool.LiquidationThreshold) / 100,
			"created_at":            pool.CreatedAt.Unix(),
		})
	}

	return map[string]any{
		"pools":     result,
		"timestamp": time.Now().Unix(),
	}, nil
}

// GetLendingPool returns a specific lending pool
func (api *DeFiAPI) GetLendingPool(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	poolID := args[0]
	pool, err := api.defiManager.LendingManager.GetPool(poolID)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, err.Error())
	}

	utilization, _ := api.defiManager.LendingManager.GetUtilizationRate(pool.PoolID)
	available := new(big.Int).Sub(pool.TotalSupply, pool.TotalBorrowed)

	return map[string]any{
		"pool_id":               pool.PoolID,
		"asset":                 pool.Asset,
		"total_supply":          pool.TotalSupply.String(),
		"total_borrowed":        pool.TotalBorrowed.String(),
		"available_to_borrow":   available.String(),
		"supply_rate":           float64(pool.SupplyRate) / 100,
		"borrow_rate":           float64(pool.BorrowRate) / 100,
		"utilization_rate":      float64(utilization) / 100,
		"collateral_factor":     float64(pool.CollateralFactor) / 100,
		"liquidation_threshold": float64(pool.LiquidationThreshold) / 100,
	}, nil
}

// Supply adds assets to a lending pool
// audit-fix R3-H3: requires signature and publicKey to prove address ownership.
func (api *DeFiAPI) Supply(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, ErrInvalidParams
	}

	args, nonce, sig, pubKey, authErr := extractDeFiAuth(args, 3)
	if authErr != nil {
		return nil, authErr
	}

	poolID, ok := args[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid pool_id", "pool_id must be a string")
	}

	userAddr, ok := args[1].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", "address must be a string")
	}
	user, err := parseAddress(userAddr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", err.Error())
	}

	amountStr, ok := args[2].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "amount must be a string")
	}
	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "cannot parse amount")
	}

	if err := api.verifyDeFiSignature("qau_supply", user, nonce, poolID+amountStr, sig, pubKey); err != nil {
		return nil, NewError(ErrCodeUnauthorized, err.Error())
	}

	if err := api.defiManager.LendingManager.Supply(poolID, user, amount); err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	// audit-fix R10-M1: include timestamp so identical operations produce unique hashes.
	nowUnix := time.Now().Unix()
	txHash := keccak256(append(user[:], append(amount.Bytes(), big.NewInt(nowUnix).Bytes()...)...))

	return map[string]any{
		"success":   true,
		"txHash":    formatHexBytes(txHash),
		"pool_id":   poolID,
		"amount":    amount.String(),
		"timestamp": nowUnix,
	}, nil
}

// Withdraw removes assets from a lending pool
// audit-fix R3-H3: requires signature and publicKey to prove address ownership.
func (api *DeFiAPI) Withdraw(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, ErrInvalidParams
	}

	args, nonce, sig, pubKey, authErr := extractDeFiAuth(args, 3)
	if authErr != nil {
		return nil, authErr
	}

	poolID, ok := args[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid pool_id", "pool_id must be a string")
	}

	userAddr, ok := args[1].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", "address must be a string")
	}
	user, err := parseAddress(userAddr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", err.Error())
	}

	amountStr, ok := args[2].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "amount must be a string")
	}
	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "cannot parse amount")
	}

	if err := api.verifyDeFiSignature("qau_withdraw", user, nonce, poolID+amountStr, sig, pubKey); err != nil {
		return nil, NewError(ErrCodeUnauthorized, err.Error())
	}

	// audit-fix: pass current block height to enforce price freshness check.
	// Without this, currentBlock=0 bypasses the staleness check in Withdraw.
	currentBlock := uint64(0)
	if api.blockReader != nil {
		currentBlock = api.blockReader.GetLatestHeight()
	}
	if err := api.defiManager.LendingManager.Withdraw(poolID, user, amount, currentBlock); err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	// audit-fix R10-M1: include timestamp so identical operations produce unique hashes.
	nowUnix := time.Now().Unix()
	txHash := keccak256(append(user[:], append(amount.Bytes(), big.NewInt(nowUnix).Bytes()...)...))

	return map[string]any{
		"success":   true,
		"txHash":    formatHexBytes(txHash),
		"pool_id":   poolID,
		"amount":    amount.String(),
		"timestamp": nowUnix,
	}, nil
}

// Borrow borrows assets from a lending pool
// audit-fix R3-H3: requires signature and publicKey to prove address ownership.
func (api *DeFiAPI) Borrow(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, ErrInvalidParams
	}

	args, nonce, sig, pubKey, authErr := extractDeFiAuth(args, 3)
	if authErr != nil {
		return nil, authErr
	}

	poolID, ok := args[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid pool_id", "pool_id must be a string")
	}

	userAddr, ok := args[1].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", "address must be a string")
	}
	user, err := parseAddress(userAddr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", err.Error())
	}

	amountStr, ok := args[2].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "amount must be a string")
	}
	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "cannot parse amount")
	}

	if err := api.verifyDeFiSignature("qau_borrow", user, nonce, poolID+amountStr, sig, pubKey); err != nil {
		return nil, NewError(ErrCodeUnauthorized, err.Error())
	}

	currentBlock := uint64(0)
	if api.blockReader != nil {
		currentBlock = api.blockReader.GetLatestHeight()
	}
	if err := api.defiManager.LendingManager.Borrow(poolID, user, amount, currentBlock); err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	// audit-fix R10-M1: include timestamp so identical operations produce unique hashes.
	nowUnix := time.Now().Unix()
	txHash := keccak256(append(user[:], append(amount.Bytes(), big.NewInt(nowUnix).Bytes()...)...))

	return map[string]any{
		"success":   true,
		"txHash":    formatHexBytes(txHash),
		"pool_id":   poolID,
		"amount":    amount.String(),
		"timestamp": nowUnix,
	}, nil
}

// Repay repays borrowed assets
// audit-fix R3-H3: requires signature and publicKey to prove address ownership.
func (api *DeFiAPI) Repay(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, ErrInvalidParams
	}

	args, nonce, sig, pubKey, authErr := extractDeFiAuth(args, 3)
	if authErr != nil {
		return nil, authErr
	}

	poolID, ok := args[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid pool_id", "pool_id must be a string")
	}

	userAddr, ok := args[1].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", "address must be a string")
	}
	user, err := parseAddress(userAddr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", err.Error())
	}

	amountStr, ok := args[2].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "amount must be a string")
	}
	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "cannot parse amount")
	}

	if err := api.verifyDeFiSignature("qau_repay", user, nonce, poolID+amountStr, sig, pubKey); err != nil {
		return nil, NewError(ErrCodeUnauthorized, err.Error())
	}

	currentBlock := uint64(0)
	if api.blockReader != nil {
		currentBlock = api.blockReader.GetLatestHeight()
	}
	if err := api.defiManager.LendingManager.Repay(poolID, user, amount, currentBlock); err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	// audit-fix R10-M1: include timestamp so identical operations produce unique hashes.
	nowUnix := time.Now().Unix()
	txHash := keccak256(append(user[:], append(amount.Bytes(), big.NewInt(nowUnix).Bytes()...)...))

	return map[string]any{
		"success":   true,
		"txHash":    formatHexBytes(txHash),
		"pool_id":   poolID,
		"amount":    amount.String(),
		"timestamp": nowUnix,
	}, nil
}

// Liquidate liquidates an undercollateralized borrow position.
// The liquidator repays part of the borrower's debt and receives collateral
// (with a liquidation penalty) in return.
// audit-fix R3-H3: requires signature and publicKey to prove liquidator address ownership.
// Parameters: [poolID, liquidatorAddress, borrowerAddress, repayAmount, collateralToken, nonce, signature, publicKey]
func (api *DeFiAPI) Liquidate(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, ErrInvalidParams
	}

	args, nonce, sig, pubKey, authErr := extractDeFiAuth(args, 5)
	if authErr != nil {
		return nil, authErr
	}

	poolID, ok := args[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid pool_id", "pool_id must be a string")
	}

	liquidatorAddr, ok := args[1].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid liquidator address", "address must be a string")
	}
	liquidator, err := parseAddress(liquidatorAddr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid liquidator address", err.Error())
	}

	borrowerAddr, ok := args[2].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid borrower address", "address must be a string")
	}
	borrower, err := parseAddress(borrowerAddr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid borrower address", err.Error())
	}

	repayAmountStr, ok := args[3].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid repay_amount", "amount must be a string")
	}
	repayAmount, ok := new(big.Int).SetString(repayAmountStr, 10)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid repay_amount", "cannot parse amount")
	}

	collateralToken, ok := args[4].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid collateral_token", "collateral_token must be a string")
	}

	// Verify liquidator signature: the liquidator must prove ownership of their address.
	// L9-041 FIX: Use delimiters between fields to prevent field collision attacks
	// where different parameter combinations produce the same concatenated string.
	authParams := poolID + "|" + borrowerAddr + "|" + repayAmountStr + "|" + collateralToken
	if err := api.verifyDeFiSignature("qau_liquidate", liquidator, nonce, authParams, sig, pubKey); err != nil {
		return nil, NewError(ErrCodeUnauthorized, err.Error())
	}

	// Get current block height for price freshness check (matches Withdraw pattern).
	currentBlock := uint64(0)
	if api.blockReader != nil {
		currentBlock = api.blockReader.GetLatestHeight()
	}

	if err := api.defiManager.LendingManager.Liquidate(poolID, liquidator, borrower, repayAmount, currentBlock); err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	// audit-fix R10-M1: include timestamp so identical operations produce unique hashes.
	nowUnix := time.Now().Unix()
	txHash := keccak256(append(liquidator[:], append(borrower[:], append(repayAmount.Bytes(), big.NewInt(nowUnix).Bytes()...)...)...))

	return map[string]any{
		"success":          true,
		"txHash":           formatHexBytes(txHash),
		"pool_id":          poolID,
		"liquidator":       liquidatorAddr,
		"borrower":         borrowerAddr,
		"repay_amount":     repayAmount.String(),
		"collateral_token": collateralToken,
		"timestamp":        nowUnix,
	}, nil
}

// GetUserLendingPosition
func (api *DeFiAPI) GetUserLendingPosition(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, ErrInvalidParams
	}

	poolID := args[0]
	user, err := parseAddress(args[1])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	supplied, borrowed, interest, err := api.defiManager.LendingManager.GetUserPosition(poolID, user)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, err.Error())
	}

	// Calculate health factor
	pool, _ := api.defiManager.LendingManager.GetPool(poolID)
	healthFactor := float64(0)
	if borrowed.Sign() > 0 && pool != nil {
		collateralValue := new(big.Int).Mul(supplied, big.NewInt(int64(pool.LiquidationThreshold))) // #nosec G115 -- LiquidationThreshold is percentage
		collateralValue.Div(collateralValue, big.NewInt(100))
		hf := new(big.Float).SetInt(collateralValue)
		hf.Quo(hf, new(big.Float).SetInt(borrowed))
		healthFactor, _ = hf.Float64()
	}

	return map[string]any{
		"pool_id":       poolID,
		"address":       args[1],
		"supplied":      supplied.String(),
		"borrowed":      borrowed.String(),
		"interest":      interest.String(),
		"health_factor": healthFactor,
	}, nil
}

// ============================================================================
// Yield Farming Methods
// ============================================================================

// GetYieldFarms returns all yield farms
func (api *DeFiAPI) GetYieldFarms(ctx context.Context, params json.RawMessage) (any, *Error) {
	if api.defiManager == nil {
		return nil, NewError(ErrCodeInternal, "DeFi manager not available")
	}

	// Update current block
	if api.blockReader != nil {
		api.defiManager.FarmingManager.SetCurrentBlock(api.blockReader.GetLatestHeight())
	}

	farms := api.defiManager.FarmingManager.GetAllFarms()

	result := make([]map[string]any, 0, len(farms))
	for _, farm := range farms {
		// Calculate APY (simplified: assume 1 QAU = $0.03, LP token = $1)
		apy, _ := api.defiManager.FarmingManager.CalculateAPY(farm.FarmID, 1.0, 0.03)
		if apy == 0 {
			// Default APY based on multiplier
			apy = float64(farm.Multiplier) * 0.5
		}

		result = append(result, map[string]any{
			"farm_id":          farm.FarmID,
			"name":             farm.Name,
			"lp_token":         farm.LPToken,
			"reward_token":     farm.RewardToken,
			"total_staked":     farm.TotalStaked.String(),
			"reward_per_block": farm.RewardPerBlock.String(),
			"multiplier":       float64(farm.Multiplier) / 100,
			"apy":              apy,
			"start_block":      farm.StartBlock,
			"end_block":        farm.EndBlock,
			"status":           farm.Status,
			"created_at":       farm.CreatedAt.Unix(),
		})
	}

	return map[string]any{
		"farms":     result,
		"timestamp": time.Now().Unix(),
	}, nil
}

// GetYieldFarm returns a specific yield farm
func (api *DeFiAPI) GetYieldFarm(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 1 {
		return nil, ErrInvalidParams
	}

	farmID := args[0]
	farm, err := api.defiManager.FarmingManager.GetFarm(farmID)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, err.Error())
	}

	apy, _ := api.defiManager.FarmingManager.CalculateAPY(farm.FarmID, 1.0, 0.03)
	if apy == 0 {
		apy = float64(farm.Multiplier) * 0.5
	}

	return map[string]any{
		"farm_id":          farm.FarmID,
		"name":             farm.Name,
		"lp_token":         farm.LPToken,
		"reward_token":     farm.RewardToken,
		"total_staked":     farm.TotalStaked.String(),
		"reward_per_block": farm.RewardPerBlock.String(),
		"multiplier":       float64(farm.Multiplier) / 100,
		"apy":              apy,
		"start_block":      farm.StartBlock,
		"end_block":        farm.EndBlock,
		"status":           farm.Status,
	}, nil
}

// StakeFarm stakes LP tokens in a farm
// audit-fix R3-H3: requires signature and publicKey to prove address ownership.
func (api *DeFiAPI) StakeFarm(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, ErrInvalidParams
	}

	args, nonce, sig, pubKey, authErr := extractDeFiAuth(args, 3)
	if authErr != nil {
		return nil, authErr
	}

	farmID, ok := args[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid farm_id", "farm_id must be a string")
	}

	userAddr, ok := args[1].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", "address must be a string")
	}
	user, err := parseAddress(userAddr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", err.Error())
	}

	amountStr, ok := args[2].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "amount must be a string")
	}
	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "cannot parse amount")
	}

	if err := api.verifyDeFiSignature("qau_stakeFarm", user, nonce, farmID+amountStr, sig, pubKey); err != nil {
		return nil, NewError(ErrCodeUnauthorized, err.Error())
	}

	// Update current block
	if api.blockReader != nil {
		api.defiManager.FarmingManager.SetCurrentBlock(api.blockReader.GetLatestHeight())
	}

	if err := api.defiManager.FarmingManager.Stake(farmID, user, amount); err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	// audit-fix R10-M1: include timestamp so identical operations produce unique hashes.
	nowUnix := time.Now().Unix()
	txHash := keccak256(append(user[:], append(amount.Bytes(), big.NewInt(nowUnix).Bytes()...)...))

	return map[string]any{
		"success":   true,
		"txHash":    formatHexBytes(txHash),
		"farm_id":   farmID,
		"amount":    amount.String(),
		"timestamp": nowUnix,
	}, nil
}

// UnstakeFarm removes LP tokens from a farm
// audit-fix R3-H3: requires signature and publicKey to prove address ownership.
func (api *DeFiAPI) UnstakeFarm(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, ErrInvalidParams
	}

	args, nonce, sig, pubKey, authErr := extractDeFiAuth(args, 3)
	if authErr != nil {
		return nil, authErr
	}

	farmID, ok := args[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid farm_id", "farm_id must be a string")
	}

	userAddr, ok := args[1].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", "address must be a string")
	}
	user, err := parseAddress(userAddr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", err.Error())
	}

	amountStr, ok := args[2].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "amount must be a string")
	}
	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid amount", "cannot parse amount")
	}

	if err := api.verifyDeFiSignature("qau_unstakeFarm", user, nonce, farmID+amountStr, sig, pubKey); err != nil {
		return nil, NewError(ErrCodeUnauthorized, err.Error())
	}

	// Update current block
	if api.blockReader != nil {
		api.defiManager.FarmingManager.SetCurrentBlock(api.blockReader.GetLatestHeight())
	}

	rewards, err := api.defiManager.FarmingManager.Unstake(farmID, user, amount)
	if err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	// audit-fix R10-M1: include timestamp so identical operations produce unique hashes.
	nowUnix := time.Now().Unix()
	txHash := keccak256(append(user[:], append(amount.Bytes(), big.NewInt(nowUnix).Bytes()...)...))

	return map[string]any{
		"success":         true,
		"txHash":          formatHexBytes(txHash),
		"farm_id":         farmID,
		"amount":          amount.String(),
		"rewards_claimed": rewards.String(),
		"timestamp":       nowUnix,
	}, nil
}

// HarvestFarm claims pending rewards
// audit-fix R3-H3: requires signature and publicKey to prove address ownership.
func (api *DeFiAPI) HarvestFarm(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []any
	if err := json.Unmarshal(params, &args); err != nil {
		return nil, ErrInvalidParams
	}

	args, nonce, sig, pubKey, authErr := extractDeFiAuth(args, 2)
	if authErr != nil {
		return nil, authErr
	}

	farmID, ok := args[0].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid farm_id", "farm_id must be a string")
	}

	userAddr, ok := args[1].(string)
	if !ok {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", "address must be a string")
	}
	user, err := parseAddress(userAddr)
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid user address", err.Error())
	}

	if err := api.verifyDeFiSignature("qau_harvestFarm", user, nonce, farmID, sig, pubKey); err != nil {
		return nil, NewError(ErrCodeUnauthorized, err.Error())
	}

	// Update current block
	if api.blockReader != nil {
		api.defiManager.FarmingManager.SetCurrentBlock(api.blockReader.GetLatestHeight())
	}

	rewards, err := api.defiManager.FarmingManager.Harvest(farmID, user)
	if err != nil {
		return nil, NewError(ErrCodeInternal, err.Error())
	}

	// audit-fix R10-M1: include timestamp so identical operations produce unique hashes.
	nowUnix := time.Now().Unix()
	txHash := keccak256(append(user[:], append(rewards.Bytes(), big.NewInt(nowUnix).Bytes()...)...))

	return map[string]any{
		"success":   true,
		"txHash":    formatHexBytes(txHash),
		"farm_id":   farmID,
		"rewards":   rewards.String(),
		"timestamp": nowUnix,
	}, nil
}

// GetFarmPendingReward returns pending rewards for a user
func (api *DeFiAPI) GetFarmPendingReward(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, ErrInvalidParams
	}

	farmID := args[0]
	user, err := parseAddress(args[1])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	// Update current block
	if api.blockReader != nil {
		api.defiManager.FarmingManager.SetCurrentBlock(api.blockReader.GetLatestHeight())
	}

	pending, err := api.defiManager.FarmingManager.GetPendingReward(farmID, user)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, err.Error())
	}

	return map[string]any{
		"farm_id":         farmID,
		"address":         args[1],
		"pending_rewards": pending.String(),
	}, nil
}

// GetUserFarmStake returns user's stake in a farm
func (api *DeFiAPI) GetUserFarmStake(ctx context.Context, params json.RawMessage) (any, *Error) {
	var args []string
	if err := json.Unmarshal(params, &args); err != nil || len(args) < 2 {
		return nil, ErrInvalidParams
	}

	farmID := args[0]
	user, err := parseAddress(args[1])
	if err != nil {
		return nil, NewErrorWithData(ErrCodeInvalidParams, "invalid address", err.Error())
	}

	stake, err := api.defiManager.FarmingManager.GetUserStake(farmID, user)
	if err != nil {
		return nil, NewError(ErrCodeNotFound, err.Error())
	}

	pending, _ := api.defiManager.FarmingManager.GetPendingReward(farmID, user)

	return map[string]any{
		"farm_id":         farmID,
		"address":         args[1],
		"staked_amount":   stake.String(),
		"pending_rewards": pending.String(),
	}, nil
}
