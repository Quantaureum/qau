package consensus

import "math/big"

// Effective-balance model (Ethereum EIP-7251 / consensus-specs alignment).
//
// Rationale: consensus weight must be a coarse, stable, deterministically
// reproducible quantity, decoupled from a validator's exact staked amount.
// Mirroring Ethereum, we split two distinct notions:
//
//   - Stake (principal): the exact amount a validator has locked. Used for
//     bookkeeping, reward accrual base, and slashing math.
//   - Effective balance: the value that counts toward consensus weight
//     (proposer election probability, attestation/finality weight). It is the
//     stake rounded DOWN to a whole EffectiveBalanceIncrement and then capped
//     at MaxEffectiveBalance.
//
// Two validators with stake 2048 and 6000 therefore carry identical consensus
// weight (2048). Excess principal above the cap is NOT confiscated — it simply
// does not contribute additional weight, exactly as in Ethereum where balance
// beyond MAX_EFFECTIVE_BALANCE stops counting.
//
// Determinism: all arithmetic uses math/big integer operations. No floats, no
// platform-dependent behavior. Given the same stake, every node computes the
// same effective balance byte-for-byte.
//
// Hysteresis note: Ethereum applies a hysteresis band when deriving effective
// balance from a continuously-drifting account balance (rewards accrue every
// epoch). In QAU the validator Stake field only changes on explicit staking
// transactions (StakingAPY is 0; consensus rewards accrue to the account
// balance, not the stake principal). There is no per-epoch drift to damp, so a
// direct floor+cap is deterministic and sufficient. If auto-compounding of
// rewards into stake is introduced later, hysteresis should be added here to
// avoid per-epoch weight-table churn.

var (
	// EffectiveBalanceIncrement is the rounding granularity for effective
	// balance: 1 QAU. Mirrors Ethereum's EFFECTIVE_BALANCE_INCREMENT (1 ETH).
	EffectiveBalanceIncrement = new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18))

	// MaxEffectiveBalance is the maximum consensus weight a single validator
	// can carry: 2048 QAU. Mirrors Ethereum EIP-7251 MAX_EFFECTIVE_BALANCE.
	MaxEffectiveBalance = new(big.Int).Mul(big.NewInt(2048), big.NewInt(1e18))
)

// EffectiveBalance returns the consensus weight for a validator holding the
// given stake: floor(stake, EffectiveBalanceIncrement) capped at
// MaxEffectiveBalance. A nil or non-positive stake yields 0. The returned value
// is always a fresh *big.Int; the input is never mutated.
func EffectiveBalance(stake *big.Int) *big.Int {
	if stake == nil || stake.Sign() <= 0 {
		return big.NewInt(0)
	}
	// Round down to a whole increment: eb = (stake / inc) * inc.
	eb := new(big.Int).Quo(stake, EffectiveBalanceIncrement)
	eb.Mul(eb, EffectiveBalanceIncrement)
	// Cap at the maximum effective balance.
	if eb.Cmp(MaxEffectiveBalance) > 0 {
		return new(big.Int).Set(MaxEffectiveBalance)
	}
	return eb
}

// effectiveBalanceEnabled reports whether the effective-balance weighting
// regime applies to the given epoch. It intentionally shares the weighted-
// proposer cutover so the entire consensus weight model (proposer election,
// finality weight, fork-choice weight) switches atomically at one coordinated,
// operator-configured epoch. Before the cutover every weight path is
// byte-identical to the legacy raw-stake behavior.
func (q *QPOS) effectiveBalanceEnabled(epoch uint64) bool {
	return q.weightedProposerEnabled(epoch)
}

// consensusWeight returns the weight a validator contributes to consensus for
// the given epoch. Once the effective-balance regime is active it is the
// validator's effective balance (floored + capped at MaxEffectiveBalance);
// before the cutover it is the raw stake, preserving legacy behavior exactly.
// The returned value is always a fresh *big.Int; the input is never mutated.
func (q *QPOS) consensusWeight(stake *big.Int, epoch uint64) *big.Int {
	if q.effectiveBalanceEnabled(epoch) {
		return EffectiveBalance(stake)
	}
	if stake == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Set(stake)
}

// currentFinalityEpoch derives the current epoch from the latest known block
// timestamp (consensus data, deterministic across honest peers), falling back
// to the wall-clock epoch only at cold start before any block is processed.
// This mirrors the epoch derivation inside tryUpdateFinality and is used by
// weight helpers that lack an explicit epoch argument (e.g. calculateTotalStake)
// so their effective-balance gating agrees with the finality loop.
func (q *QPOS) currentFinalityEpoch() uint64 {
	gt := GetGenesisTime()
	blockDerived := q.GetLastKnownBlockTime()
	if gt > 0 && blockDerived > gt {
		slot := uint64((blockDerived - gt) / int64(SlotDuration.Seconds())) // #nosec G115 -- positive delta / 12s fits in uint64
		return slot / SlotsPerEpoch
	}
	return q.GetCurrentEpoch()
}
