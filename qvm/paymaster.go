// Quantaureum Node source, version 1.0.0.
package qvm

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/quantaureum/qau/encoding"
	"github.com/quantaureum/qau/types"
)

type PaymasterContext struct {
	Paymaster          types.Address
	Sender             types.Address // audit-fix C-5: Added sender for consistent balance deduction
	MaxGasCost         *big.Int
	GasPrice           *big.Int
	PaymasterData      []byte
	PaymasterPostOpGas uint64
}

type PaymasterResult struct {
	Context         *PaymasterContext
	Valid           bool
	ValidationError error
	ActualGasCost   *big.Int
}

type Paymaster interface {
	ValidatePaymasterUserOp(uo *encoding.UserOperation, userOpHash types.Hash, maxCost *big.Int, stateDB StateDB) (*PaymasterResult, error)
	PostOp(mode PostOpMode, context *PaymasterContext, actualGasCost *big.Int, stateDB StateDB) error
}

type PostOpMode uint8

const (
	PostOpModeSuccess PostOpMode = iota
	PostOpModeRevert
	PostOpModePostOpReverted
)

type VerifyingPaymaster struct {
	mu           sync.RWMutex
	owner        types.Address
	entryPoint   *EntryPoint
	sponsorRules map[types.Address]*SponsorRule
}

type SponsorRule struct {
	MaxGasPerOp     uint64
	MaxFeePerGas    *big.Int
	MaxTotalCost    *big.Int
	AllowedSenders  map[types.Address]bool
	AllowAllSenders bool
	Active          bool
}

func NewVerifyingPaymaster(owner types.Address, entryPoint *EntryPoint) *VerifyingPaymaster {
	return &VerifyingPaymaster{
		owner:        owner,
		entryPoint:   entryPoint,
		sponsorRules: make(map[types.Address]*SponsorRule),
	}
}

func (vp *VerifyingPaymaster) SetSponsorRule(paymaster types.Address, rule *SponsorRule) {
	vp.mu.Lock()
	defer vp.mu.Unlock()
	vp.sponsorRules[paymaster] = rule
}

func (vp *VerifyingPaymaster) GetSponsorRule(paymaster types.Address) *SponsorRule {
	vp.mu.RLock()
	defer vp.mu.RUnlock()
	rule, ok := vp.sponsorRules[paymaster]
	if !ok || rule == nil {
		return &SponsorRule{Active: false}
	}
	return rule
}

func (vp *VerifyingPaymaster) ValidatePaymasterUserOp(uo *encoding.UserOperation, userOpHash types.Hash, maxCost *big.Int, stateDB StateDB) (*PaymasterResult, error) {
	if uo.Paymaster == nil {
		return &PaymasterResult{Valid: true}, nil
	}

	paymasterAddr := *uo.Paymaster
	rule := vp.GetSponsorRule(paymasterAddr)
	if rule == nil {
		return &PaymasterResult{
			Valid:           false,
			ValidationError: fmt.Errorf("paymaster rule not found"),
		}, nil
	}

	if !rule.Active {
		return &PaymasterResult{
			Valid:           false,
			ValidationError: fmt.Errorf("paymaster not active"),
		}, nil
	}

	if !rule.AllowAllSenders {
		if !rule.AllowedSenders[uo.Sender] {
			return &PaymasterResult{
				Valid:           false,
				ValidationError: fmt.Errorf("sender not allowed by paymaster"),
			}, nil
		}
	}

	// R36-P2-QVMP-02 FIX: Check for uint64 overflow before comparison.
	// Without this, an attacker can set CallGasLimit near 2^63 so the
	// wrapped sum is small, bypassing the MaxGasPerOp check.
	gasSum := uo.CallGasLimit + uo.VerificationGasLimit
	if gasSum < uo.CallGasLimit || gasSum < uo.VerificationGasLimit {
		return &PaymasterResult{
			Valid:           false,
			ValidationError: fmt.Errorf("gas limit overflow"),
		}, nil
	}
	if gasSum > rule.MaxGasPerOp {
		return &PaymasterResult{
			Valid:           false,
			ValidationError: fmt.Errorf("gas limit exceeds paymaster max"),
		}, nil
	}

	if uo.MaxFeePerGas.Cmp(rule.MaxFeePerGas) > 0 {
		return &PaymasterResult{
			Valid:           false,
			ValidationError: fmt.Errorf("fee per gas exceeds paymaster max"),
		}, nil
	}

	if maxCost.Cmp(rule.MaxTotalCost) > 0 {
		return &PaymasterResult{
			Valid:           false,
			ValidationError: fmt.Errorf("total cost exceeds paymaster max"),
		}, nil
	}

	paymasterDeposit := vp.entryPoint.GetDepositInfo(paymasterAddr)
	if paymasterDeposit == nil {
		return &PaymasterResult{
			Valid:           false,
			ValidationError: fmt.Errorf("paymaster deposit info not available"),
		}, nil
	}
	if paymasterDeposit.Deposit.Cmp(maxCost) < 0 {
		return &PaymasterResult{
			Valid:           false,
			ValidationError: fmt.Errorf("paymaster insufficient deposit"),
		}, nil
	}

	return &PaymasterResult{
		Valid: true,
		Context: &PaymasterContext{
			Paymaster:     paymasterAddr,
			Sender:        uo.Sender, // audit-fix C-5: Store sender for consistent deduction
			MaxGasCost:    maxCost,
			PaymasterData: uo.PaymasterData,
		},
	}, nil
}

func (vp *VerifyingPaymaster) PostOp(mode PostOpMode, context *PaymasterContext, actualGasCost *big.Int, stateDB StateDB) error {
	if context == nil {
		return nil
	}

	if mode == PostOpModePostOpReverted {
		return fmt.Errorf("paymaster postOp reverted")
	}

	return nil
}

type TokenPaymaster struct {
	mu              sync.RWMutex
	owner           types.Address
	entryPoint      *EntryPoint
	tokenOracle     map[types.Address]*big.Int
	supportedTokens map[types.Address]bool
}

func NewTokenPaymaster(owner types.Address, entryPoint *EntryPoint) *TokenPaymaster {
	return &TokenPaymaster{
		owner:           owner,
		entryPoint:      entryPoint,
		tokenOracle:     make(map[types.Address]*big.Int),
		supportedTokens: make(map[types.Address]bool),
	}
}

func (tp *TokenPaymaster) AddSupportedToken(token types.Address, exchangeRate *big.Int) error {
	if exchangeRate == nil || exchangeRate.Sign() <= 0 {
		return fmt.Errorf("exchange rate must be positive")
	}
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.supportedTokens[token] = true
	tp.tokenOracle[token] = exchangeRate
	return nil
}

func (tp *TokenPaymaster) ValidatePaymasterUserOp(uo *encoding.UserOperation, userOpHash types.Hash, maxCost *big.Int, stateDB StateDB) (*PaymasterResult, error) {
	if uo.Paymaster == nil {
		return &PaymasterResult{Valid: true}, nil
	}

	paymasterAddr := *uo.Paymaster

	tp.mu.RLock()
	supported := tp.supportedTokens[paymasterAddr]
	exchangeRate := tp.tokenOracle[paymasterAddr]
	tp.mu.RUnlock()

	if !supported {
		return &PaymasterResult{
			Valid:           false,
			ValidationError: fmt.Errorf("token not supported by paymaster"),
		}, nil
	}

	if exchangeRate == nil || exchangeRate.Sign() <= 0 {
		return &PaymasterResult{
			Valid:           false,
			ValidationError: fmt.Errorf("invalid exchange rate for token"),
		}, nil
	}

	tokenCost := new(big.Int).Div(maxCost, exchangeRate)

	senderAddr := Address(uo.Sender)
	// V21-007 FIX: GetBalance returns native QAU balance, NOT ERC-20 token balance.
	// This is a known limitation. Proper token balance checking requires calling
	// the token contract balanceOf(sender) via QVM. QAU balance serves as proxy.
	// R35-P3 FIX (2026-07-29): Converted open TODO into a tracked limitation.
	// Implementing proper ERC-20 balanceOf requires AA to be production-ready
	// (a cross-module effort: QVM call into token contract, paymaster gas
	// accounting for the balanceOf call, and StateDB re-entrancy safety).
	// Until AA reaches production maturity, QAU balance remains the proxy.
	// Tracked as: AA-paymaster-erc20-balanceof (deferred until AA prod-ready).
	qauBalance := stateDB.GetBalance(senderAddr)

	if qauBalance.Cmp(tokenCost) < 0 {
		return &PaymasterResult{
			Valid:           false,
			ValidationError: fmt.Errorf("insufficient token balance"),
		}, nil
	}

	return &PaymasterResult{
		Valid: true,
		Context: &PaymasterContext{
			Paymaster:     paymasterAddr,
			Sender:        uo.Sender, // audit-fix C-5: Store sender for consistent deduction in PostOp
			MaxGasCost:    maxCost,
			PaymasterData: uo.PaymasterData,
		},
	}, nil
}

func (tp *TokenPaymaster) PostOp(mode PostOpMode, context *PaymasterContext, actualGasCost *big.Int, stateDB StateDB) error {
	// R36-P3-7 NOTE (2026-07-30): KNOWN LIMITATIONS (AA not in production).
	// This implementation has three deferred issues that MUST be resolved
	// before Account Abstraction is wired into production consensus:
	//
	// 1. BURN-WITHOUT-CREDIT: tokenCost is subtracted from the sender's
	//    QAU balance but NOT credited to any paymaster or token contract
	//    — the value is effectively burned. The intended design is to
	//    credit the paymaster (which pre-pays gas in QAU on-chain) so it
	//    can be reimbursed off-chain in the ERC-20 token. The credit path
	//    requires ERC-20 transfer logic that depends on QVM contract calls
	//    not yet wired into the paymaster.
	//
	// 2. DIVISION ROUNDING TO ZERO: tokenCost = actualGasCost / exchangeRate.
	//    When actualGasCost < exchangeRate, integer division yields 0 and
	//    the sender pays nothing for that op. ValidatePaymasterUserOp
	//    pre-charges maxCost (which is >= exchangeRate when the op is
	//    accepted), so in practice the rounding loss is bounded by the
	//    difference between maxCost and actualGasCost. A proper fix would
	//    accumulate fractional token debt across ops or round up.
	//
	// 3. NO SIGNATURE BINDING: the `userOpHash` parameter (passed via the
	//    EntryPoint to ValidatePaymasterUserOp but unused in PostOp) is
	//    not bound to the paymaster context or the token deduction. A
	//    malicious bundler could swap the userOpHash between validation
	//    and execution, although EntryPoint's commit-reveal pattern
	//    mitigates this in practice. The fix requires signing the
	//    PaymasterContext with userOpHash at validation time and verifying
	//    it in PostOp.
	//
	// These are documented here (not fixed) because AA is not yet live;
	// the entire paymaster path is reachable only from tests. Fixing them
	// prematurely would add complexity to a path that has no production
	// callers and would be reworked when AA is wired into consensus.
	if context == nil {
		return nil
	}

	if mode == PostOpModePostOpReverted {
		return fmt.Errorf("token paymaster postOp reverted")
	}

	tp.mu.RLock()
	exchangeRate := tp.tokenOracle[context.Paymaster]
	tp.mu.RUnlock()

	if exchangeRate == nil || exchangeRate.Sign() <= 0 {
		return fmt.Errorf("invalid exchange rate for token in postOp")
	}
	tokenCost := new(big.Int).Div(actualGasCost, exchangeRate)

	// audit-fix C-5: Deduct from sender (consistent with ValidatePaymasterUserOp)
	// Previously deducted from paymaster, causing validation/execution mismatch.
	senderAddr := Address(context.Sender)
	// V21-007 FIX: GetBalance/SetBalance operates on native QAU, not ERC-20 tokens.
	qauBalance := stateDB.GetBalance(senderAddr)
	if qauBalance.Cmp(tokenCost) < 0 {
		return fmt.Errorf("insufficient QAU balance for postOp (token deduction not implemented)")
	}
	stateDB.SetBalance(senderAddr, new(big.Int).Sub(qauBalance, tokenCost))

	return nil
}
