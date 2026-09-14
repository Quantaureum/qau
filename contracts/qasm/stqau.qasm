// Quantaureum Node source, version 1.0.0.
// QVM stQAU staking receipt contract (QASM) — R123
// Liquid staking receipt: the first QSwap pool asset
//
// Design (docs/plans/R123-STQAU-LIQUID-STAKING.md §3):
//   exchange-rate mode: the stQAU count is fixed while each unit becomes more valuable
//     rate = (SELFBALANCE − totalQueued) × 1e18 / totalSupply
//   honest accounting (D4): backing is read via SELFBALANCE, the contract's own native balance,
//     so the operator cannot lie about the rate — slash losses automatically degrade it
//   nominator model (D3): the operator runs extractForStaking to batch-extract funds for consensus-layer staking;
//     epoch rewards are reinjected via injectRewards, raising the rate
//   withdrawal queue (D6): the owed amount is rate-locked at request time, paid out after 21 days (151,200 blocks)
//
// Functions and selectors (actual keccak256):
//   deposit()                   0xd0e30db0  (anyone, CV>0, not paused)
//   withdraw(uint256)           0x2e1a7d4d  (anyone, shares>0, not paused)
//   claimWithdrawal()           0x6e66d84a  (NUMBER >= unlock)
//   injectRewards()             0x99c722bc  (anyone, CV>0)
//   extractForStaking(uint256)  0x8cc57d95  (owner only, amt<=backing)
//   recordSlash(uint256)        0x0f75baca  (owner only, audit snapshot)
//   exchangeRate()              0x3ba0b9a9  (view)
//   totalBacking()              0xeb2cd258  (view)
//   withdrawalOf(address)       0x14bf9d2b  (view: owed/unlock/shares)
//   pauseDeposits()             0x02191980  (owner only)
//   unpauseDeposits()           0x63d8882a  (owner only)
//   transferOwnership(address)  0xf2fde38b  (owner only)
//   owner()                     0x8da5cb5b
//   name() 0x06fdde03 → "Staked QAU" / symbol() 0x95d89b41 → "stQAU"
//   decimals() 0x313ce567 → 18
//   ERC20: totalSupply 0x18160ddd / balanceOf 0x70a08231 /
//          allowance 0xdd62ed3e / approve 0x095ea7b3 /
//          transfer 0xa9059cbb / transferFrom 0x23b872dd
//
// Storage (plain slots, full width):
//   slot 0:  owner (operator = deployer)
//   slot 1:  paused (0=normal)
//   slot 2:  totalSupply (total stQAU)
//   slot 3:  balanceOf mapping root   key = keccak256(pad(addr) ++ pad(3))
//   slot 4:  allowance mapping root   two-level: allowance[owner][spender]
//   slot 5:  totalQueued (total native pending in the queue)
//   slot 6:  queuedShares mapping root  key = keccak256(pad(addr) ++ pad(6))
//   slot 7:  queuedOwed mapping root    key = keccak256(pad(addr) ++ pad(7))
//   slot 8:  queuedUnlock mapping root  key = keccak256(pad(addr) ++ pad(8))
//   slot 9:  totalExtracted (operator cumulative extraction, for audit)
//   slot 10: lastSlashSnapshot (recordSlash audit)
//
// QVM arithmetic semantics (R122 doc §1.3, all verified):
//   SUB/LT/GT/DIV/MUL/MOD: a=top op b=second
//   MSTORE: offset=top, value=second; SSTORE: key=top, value=second
//   JUMPI: jumps when the top is non-zero; CALL bottom->top: gas,addr,value,inOff,inSize,retOff,retSize
//   CALL needs gas 500000 (23000 is not enough for QVM intrinsic cost; verified in R122)
//
// helper call convention (as in qswap_router): PUSH2 @retaddr; JUMP @helper; the helper ends with JUMP back

.INIT
    // slot0 = owner = CALLER
    CALLER
    PUSH1 0x00
    SSTORE
    // slot1 = 0 (not paused)
    PUSH1 0x00
    PUSH1 0x01
    SSTORE
    // runtime code copied to 0x00 and RETURNed
    PUSH2 @code_end-@code_start
    PUSH2 @code_start
    PUSH1 0x00
    CODECOPY
    PUSH2 @code_end-@code_start
    PUSH1 0x00
    RETURN

.CODE
code_start:
    PUSH1 0x04
    CALLDATASIZE
    LT
    ISZERO
    JUMPI @dispatch
    // empty calldata: silently accept funds (equivalent to injectRewards; the rate rise benefits holders)
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

dispatch:
    JUMPDEST
    PUSH1 0x00
    CALLDATALOAD
    PUSH1 0xe0
    SHR
    PUSH4 0xffffffff
    AND

    DUP1
    PUSH4 0xd0e30db0
    EQ
    JUMPI @fn_deposit

    DUP1
    PUSH4 0x2e1a7d4d
    EQ
    JUMPI @fn_withdraw

    DUP1
    PUSH4 0x6e66d84a
    EQ
    JUMPI @fn_claim_withdrawal

    DUP1
    PUSH4 0x99c722bc
    EQ
    JUMPI @fn_inject_rewards

    DUP1
    PUSH4 0x8cc57d95
    EQ
    JUMPI @fn_extract_for_staking

    DUP1
    PUSH4 0x0f75baca
    EQ
    JUMPI @fn_record_slash

    DUP1
    PUSH4 0x3ba0b9a9
    EQ
    JUMPI @fn_exchange_rate

    DUP1
    PUSH4 0xeb2cd258
    EQ
    JUMPI @fn_total_backing

    DUP1
    PUSH4 0x14bf9d2b
    EQ
    JUMPI @fn_withdrawal_of

    DUP1
    PUSH4 0x02191980
    EQ
    JUMPI @fn_pause_deposits

    DUP1
    PUSH4 0x63d8882a
    EQ
    JUMPI @fn_unpause_deposits

    DUP1
    PUSH4 0xf2fde38b
    EQ
    JUMPI @fn_transfer_ownership

    DUP1
    PUSH4 0x8da5cb5b
    EQ
    JUMPI @fn_owner

    DUP1
    PUSH4 0x06fdde03
    EQ
    JUMPI @fn_name

    DUP1
    PUSH4 0x95d89b41
    EQ
    JUMPI @fn_symbol

    DUP1
    PUSH4 0x313ce567
    EQ
    JUMPI @fn_decimals

    DUP1
    PUSH4 0x18160ddd
    EQ
    JUMPI @fn_total_supply

    DUP1
    PUSH4 0x70a08231
    EQ
    JUMPI @fn_balance_of

    DUP1
    PUSH4 0xdd62ed3e
    EQ
    JUMPI @fn_allowance

    DUP1
    PUSH4 0x095ea7b3
    EQ
    JUMPI @fn_approve

    DUP1
    PUSH4 0xa9059cbb
    EQ
    JUMPI @fn_transfer

    DUP1
    PUSH4 0x23b872dd
    EQ
    JUMPI @fn_transfer_from

    // unknown selector -> revert
    PUSH1 0x00
    PUSH1 0x00
    REVERT

// ============================================================
// helper stqau_caller_balkey: callerKey (balance slot3) -> mem[0xe0]
// ============================================================
stqau_caller_balkey:
    JUMPDEST
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x03
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    JUMP

// ============================================================
// helper stqau_effective_backing: effective backing -> stack top (including the current CV)
//   = SELFBALANCE − totalQueued
//   note: Executor.Call transfers before executing, so SELFBALANCE already includes the current CV
//   (the deposit formula needs the pre-backing excluding the current CV; see the inline correction in fn_deposit)
// ============================================================
stqau_effective_backing:
    JUMPDEST
    // stack entering the helper: [retaddr]; push only on top throughout, and restore to [backing, retaddr] before leaving
    SELFBALANCE               // [retaddr, selfBal]
    PUSH1 0x05
    SLOAD                     // [retaddr, selfBal, queued] top=queued
    SWAP1                     // [retaddr, queued, selfBal] top=selfBal
    SUB                      // [retaddr, selfBal-queued] top=backing (a=top=selfBal, b=second=queued) OK
    SWAP1                     // [backing, retaddr] top=retaddr
    JUMP                      // jump back, backing stays on top (same tail pattern as router helper_call1)

// ============================================================
// deposit() payable -> mint shares
//   shares = CV × supply / backing   (supply=0 → 1:1)
//   gates: not paused; CV>0
// ============================================================
fn_deposit:
    JUMPDEST
    // paused? slot1 != 0 → revert
    PUSH1 0x01
    SLOAD
    ISZERO
    ISZERO
    JUMPI @stqau_revert
    // CV>0?
    CALLVALUE
    ISZERO
    JUMPI @stqau_revert

    // supply = slot2 → mem[0x80]
    PUSH1 0x02
    SLOAD
    PUSH1 0x80
    MSTORE
    // supply == 0 -> first deposit at 1:1
    PUSH1 0x80
    MLOAD
    ISZERO
    JUMPI @dep_proportional

    // backing_pre = SELFBALANCE − CV − queued → mem[0xa0]
    //   (Call transfers before executing, so SELFBALANCE already includes the current CV and it must be subtracted back)
    PUSH2 @dep_cont
    JUMP @stqau_effective_backing
    // ^ when this helper returns, stack top = backing (incl. CV), so CV must be subtracted —
    //   but the JUMP-return brings control back to dep_cont, so the subtraction is at the start of dep_cont:
dep_cont:
    JUMPDEST
    // stack: [backingWithCV] -> mem[0x00]; backing_pre = backing - CV
    PUSH1 0x00
    MSTORE
    CALLVALUE               // [cv]
    PUSH1 0x00
    MLOAD                   // [cv, backing] top=backing
    SUB                     // backing - cv OK (a=top=backing, b=second=cv)
    PUSH1 0xa0
    MSTORE
    // prod = CV × supply → mem[0xc0]
    CALLVALUE                 // [cv]
    PUSH1 0x80
    MLOAD                     // [cv, supply] top=supply
    MUL                      // cv * supply OK (multiplication commutes)
    PUSH1 0xc0
    MSTORE
    // shares = prod / backing_pre: push backing (second) first, then prod (top)
    PUSH1 0xa0
    MLOAD                     // [backing]
    PUSH1 0xc0
    MLOAD                     // [backing, prod] top=prod
    DIV                       // prod / backing ✓
    JUMP @dep_mint

dep_proportional:
    JUMPDEST
    CALLVALUE                 // shares = CV (1:1)

dep_mint:
    JUMPDEST
    // R123-SEC-2: reject zero shares (anti ERC4626 rate-inflation attack)
    //   after an attacker's first 1 wei deposit plus a huge injectRewards, a user's deposit shares
    //   can floor to 0 via integer division -> the user pays QAU for 0 shares. Revert outright.
    DUP1
    ISZERO
    JUMPI @stqau_revert
    // shares (stack top) -> mem[0xc0]
    PUSH1 0xc0
    MSTORE
    // callerBalKey; callerBal += shares
    PUSH2 @dep_bal_done
    JUMP @stqau_caller_balkey
dep_bal_done:
    JUMPDEST
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH1 0xc0
    MLOAD
    ADD
    PUSH1 0xe0
    MLOAD
    SSTORE
    // totalSupply += shares
    PUSH1 0x02
    SLOAD
    PUSH1 0xc0
    MLOAD
    ADD
    PUSH1 0x02
    SSTORE
    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// withdraw(uint256 shares) -> queue the redemption (rate locked, 21 days)
//   calldata: [sel][shares]
//   owed = shares × backing / supply
//   writes the queuedShares/owed/unlock mappings; totalQueued += owed
//   gates: not paused; shares>0; supply>0; shares<=callerBal
// ============================================================
fn_withdraw:
    JUMPDEST
    // mem[0x80] = shares
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    // paused → revert
    PUSH1 0x01
    SLOAD
    ISZERO
    ISZERO
    JUMPI @stqau_revert
    // shares==0 → revert
    PUSH1 0x80
    MLOAD
    ISZERO
    JUMPI @stqau_revert
    // an existing queue entry (queuedShares[caller] > 0) -> revert
    //   a second request would overwrite the queue (shares burned twice while owed records only the last)
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x06
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    SLOAD
    ISZERO
    ISZERO
    JUMPI @stqau_revert
    // supply==0 → revert
    PUSH1 0x02
    SLOAD
    ISZERO
    JUMPI @stqau_revert
    // callerBalKey → mem[0xe0]; shares > callerBal → revert
    PUSH2 @wd_balkey_done
    JUMP @stqau_caller_balkey
wd_balkey_done:
    JUMPDEST
    PUSH1 0xe0
    MLOAD
    SLOAD                   // [callerBal]
    PUSH1 0x80
    MLOAD                   // [callerBal, shares] top=shares
    GT                      // shares > callerBal ?
    JUMPI @stqau_revert
    // callerBal -= shares
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH1 0x80
    MLOAD
    SWAP1                   // top=callerBal
    SUB                     // callerBal − shares ✓
    PUSH1 0xe0
    MLOAD
    SSTORE
    // (totalSupply -= shares is deferred until after the owed computation — a full withdrawal zeroing supply first
    //  would give owed = prod/0 = 0, losing the queued debt)
    // backing (not yet queued) -> mem[0xa0]
    PUSH2 @wd_owed_backing
    JUMP @stqau_effective_backing
wd_owed_backing:
    JUMPDEST
    PUSH1 0xa0
    MSTORE
    // owed = shares × backing / supply
    // prod = shares × backing → mem[0xc0]
    PUSH1 0x80
    MLOAD                     // [shares]
    PUSH1 0xa0
    MLOAD                     // [shares, backing] top=backing
    MUL                      // OK, commutative
    PUSH1 0xc0
    MSTORE
    // owed = prod / supply
    PUSH1 0x02
    SLOAD                     // [supply]
    PUSH1 0xc0
    MLOAD                     // [supply, prod] top=prod
    DIV                       // prod / supply ✓
    DUP1
    ISZERO
    JUMPI @stqau_revert       // R123-SEC-3: a dust redemption with owed=0 burns shares and can never be claimed -> reject
    PUSH1 0xc0
    MSTORE                    // mem[0xc0] = owed
    // (totalSupply is deducted only now — owed is already computed)
    PUSH1 0x02
    SLOAD
    PUSH1 0x80
    MLOAD
    SWAP1
    SUB
    PUSH1 0x02
    SSTORE
    // mem[0x100] = NUMBER + 151200 (computed in advance)
    NUMBER
    PUSH32 0x0000000000000000000000000000000000000000000000000000000000024ea0 // 151200 = 0x24EA0
    ADD
    PUSH2 0x100
    MSTORE
    // queuedShares[caller] = shares (slot6)
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x06
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    PUSH1 0x80
    MLOAD
    PUSH1 0xe0
    MLOAD
    SSTORE
    // queuedOwed[caller] = owed (slot7)
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x07
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    PUSH1 0xc0
    MLOAD
    PUSH1 0xe0
    MLOAD
    SSTORE
    // queuedUnlock[caller] = mem[0x100] (slot8)
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x08
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    PUSH2 0x100
    MLOAD
    PUSH1 0xe0
    MLOAD
    SSTORE
    // totalQueued += owed
    PUSH1 0x05
    SLOAD
    PUSH1 0xc0
    MLOAD
    ADD
    PUSH1 0x05
    SSTORE
    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// claimWithdrawal() -> pay out native at maturity
//   gates: queuedOwed[caller]>0; NUMBER >= unlock
//   actions: CALL the payout; clear the three slots; totalQueued -= owed
// ============================================================
fn_claim_withdrawal:
    JUMPDEST
    // queuedOwedKey(caller, slot7) → mem[0xe0]
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x07
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    // owed → mem[0x80]; owed==0 → revert
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH1 0x80
    MSTORE
    PUSH1 0x80
    MLOAD
    ISZERO
    JUMPI @stqau_revert
    // unlockKey(caller, slot8) → mem[0xe0]; unlock → mem[0xa0]
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x08
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH1 0xa0
    MSTORE
    // not yet due -> revert: unlock > NUMBER
    NUMBER
    PUSH1 0xa0
    MLOAD
    GT
    JUMPI @stqau_revert
    // R123-SEC-1 (CEI): settle all state first (anti-reentrancy), external CALL last
    //   on reentry queuedOwed is already 0 -> the owed==0 gate reverts on the first round;
    //   a failed CALL -> this function REVERTs -> all cleanup below rolls back, owed fully restored
    // totalQueued -= owed
    PUSH1 0x05
    SLOAD
    PUSH1 0x80
    MLOAD
    SWAP1
    SUB
    PUSH1 0x05
    SSTORE
    // clear queuedOwed (push value=0 first, key after on top)
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x07
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    PUSH1 0x00
    PUSH1 0xe0
    MLOAD
    SSTORE
    // clear queuedShares
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x06
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    PUSH1 0x00
    PUSH1 0xe0
    MLOAD
    SSTORE
    // clear queuedUnlock
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x08
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    PUSH1 0x00
    PUSH1 0xe0
    MLOAD
    SSTORE
    // native CALL: gas 500000, addr=CALLER, value=owed (mem[0x80] still holds it)
    PUSH4 0x0007a120
    CALLER
    PUSH1 0x80
    MLOAD
    PUSH1 0x00
    PUSH1 0x00
    PUSH1 0x00
    PUSH1 0x00
    CALL
    ISZERO
    JUMPI @stqau_revert
    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// injectRewards() payable -> simply accept CALLVALUE (the rate rises automatically)
//   gate: CV>0
// ============================================================
fn_inject_rewards:
    JUMPDEST
    CALLVALUE
    ISZERO
    JUMPI @stqau_revert
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// extractForStaking(uint256 amt) -> owner-only native extraction
//   gates: CALLER==owner; amt>0; amt <= backing
//   actions: CALL owner amt; totalExtracted += amt
// ============================================================
fn_extract_for_staking:
    JUMPDEST
    // mem[0x80] = amt
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    // owner check
    CALLER
    PUSH1 0x00
    SLOAD
    EQ
    JUMPI @ex_owner_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
ex_owner_ok:
    JUMPDEST
    // amt==0 → revert
    PUSH1 0x80
    MLOAD
    ISZERO
    JUMPI @stqau_revert
    // backing → mem[0xa0]
    PUSH2 @ex_backing_done
    JUMP @stqau_effective_backing
ex_backing_done:
    JUMPDEST
    PUSH1 0xa0
    MSTORE
    // amt > backing -> revert: push [backing, amt] with amt on top -> GT
    PUSH1 0xa0
    MLOAD
    PUSH1 0x80
    MLOAD
    GT
    JUMPI @stqau_revert
    // CALL gas 500000, addr=owner, value=amt
    PUSH4 0x0007a120
    PUSH1 0x00
    SLOAD
    PUSH1 0x80
    MLOAD
    PUSH1 0x00
    PUSH1 0x00
    PUSH1 0x00
    PUSH1 0x00
    CALL
    ISZERO
    JUMPI @stqau_revert
    // totalExtracted += amt
    PUSH1 0x09
    SLOAD
    PUSH1 0x80
    MLOAD
    ADD
    PUSH1 0x09
    SSTORE
    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// recordSlash(uint256 snapshot) -> owner-only audit snapshot (does not affect arithmetic, D4)
// ============================================================
fn_record_slash:
    JUMPDEST
    CALLER
    PUSH1 0x00
    SLOAD
    EQ
    JUMPI @rs_owner_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
rs_owner_ok:
    JUMPDEST
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x0a
    SSTORE
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// exchangeRate() view → backing × 1e18 / supply (supply=0 → 1e18)
// ============================================================
fn_exchange_rate:
    JUMPDEST
    PUSH1 0x02
    SLOAD
    ISZERO
    ISZERO
    JUMPI @er_compute          // supply>0 (non-zero) -> compute path
    // supply==0 → 1e18 = 0x0de0b6b3a7640000
    PUSH32 0x00000000000000000000000000000000000de0b6b3a7640000
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN
er_compute:
    JUMPDEST
    // backing → mem[0x80]
    PUSH2 @er_backing_done
    JUMP @stqau_effective_backing
er_backing_done:
    JUMPDEST
    PUSH1 0x80
    MSTORE
    // prod = backing × 1e18 → mem[0xc0]
    PUSH1 0x80
    MLOAD                     // [backing]
    PUSH32 0x00000000000000000000000000000000000de0b6b3a7640000
    MUL                      // OK, commutative
    PUSH1 0xc0
    MSTORE
    // rate = prod / supply
    PUSH1 0x02
    SLOAD
    PUSH1 0xc0
    MLOAD
    DIV
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// totalBacking() view → SELFBALANCE − totalQueued
// ============================================================
fn_total_backing:
    JUMPDEST
    PUSH2 @tb_done
    JUMP @stqau_effective_backing
tb_done:
    JUMPDEST
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// withdrawalOf(address) view -> (owed, unlock, shares) 96 bytes
// ============================================================
fn_withdrawal_of:
    JUMPDEST
    // mem[0x80] = addr
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    // owed -> mem[0x00] (slot7 mapping)
    PUSH1 0x80
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x07
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    SLOAD
    PUSH1 0x00
    MSTORE
    // unlock -> mem[0x20] (slot8 mapping)
    //   note: the keccak input area mem[0x20..0x60] gets clobbered; 0x00 is fetched and stored first
    PUSH1 0x80
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x08
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    SLOAD
    PUSH1 0x20
    MSTORE
    // shares -> mem[0x40] (slot6 mapping)
    //   the hash area reuses mem[0x20..0x60]: but 0x20 already holds the unlock return value (it would be clobbered;
    //   RETURN reads mem[0x00..0x60] only at the end — the unlock value must be moved to safety first!)
    //   rearrangement: move the unlock value from mem[0x20] -> mem[0x120] as a staging area?
    //   simplification: keep the RETURN layout owed(0x00) unlock(0x20) shares(0x40) untouched,
    //   and compute the shares keccak in a dedicated hash area mem[0x40..0x80]: addr@0x40, slot6@0x60,
    //   size=0x40 offset=0x40; after hashing, write the shares value back to mem[0x40] —
    //   but the hash inputs at mem[0x40/0x60] are then overwritten by MSTORE 0x40 — hash first, write after
    PUSH1 0x80
    MLOAD
    PUSH1 0x40
    MSTORE
    PUSH1 0x06
    PUSH1 0x60
    MSTORE
    PUSH1 0x40
    PUSH1 0x40
    KECCAK256
    SLOAD
    PUSH2 0x40
    MSTORE
    // returns mem[0x00..0x60]
    PUSH1 0x60
    PUSH1 0x00
    RETURN

// ============================================================
// pauseDeposits() / unpauseDeposits() — owner only
// ============================================================
fn_pause_deposits:
    JUMPDEST
    CALLER
    PUSH1 0x00
    SLOAD
    EQ
    JUMPI @pd_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
pd_ok:
    JUMPDEST
    PUSH1 0x01
    PUSH1 0x01
    SSTORE
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

fn_unpause_deposits:
    JUMPDEST
    CALLER
    PUSH1 0x00
    SLOAD
    EQ
    JUMPI @upd_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
upd_ok:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x01
    SSTORE
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// transferOwnership(address) — owner only
// ============================================================
fn_transfer_ownership:
    JUMPDEST
    CALLER
    PUSH1 0x00
    SLOAD
    EQ
    JUMPI @to_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
to_ok:
    JUMPDEST
    // reject the zero address (plan §4.3: non-zero address)
    PUSH1 0x04
    CALLDATALOAD
    DUP1
    ISZERO
    JUMPI @to_reject
    PUSH1 0x00
    SSTORE
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN
to_reject:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT
unused_to_ok_tail:
    JUMPDEST
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// owner() view
// ============================================================
fn_owner:
    JUMPDEST
    PUSH1 0x00
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// name() → "Staked QAU" (len 10)
// ============================================================
fn_name:
    JUMPDEST
    PUSH32 0x0000000000000000000000000000000000000000000000000000000000000020
    PUSH1 0x00
    MSTORE
    PUSH32 0x000000000000000000000000000000000000000000000000000000000000000a
    PUSH1 0x20
    MSTORE
    PUSH32 0x5374616b65642051415500000000000000000000000000000000000000000000
    PUSH2 0x40
    MSTORE
    PUSH2 0x60
    PUSH1 0x00
    RETURN

// ============================================================
// symbol() → "stQAU" (len 5)
// ============================================================
fn_symbol:
    JUMPDEST
    PUSH32 0x0000000000000000000000000000000000000000000000000000000000000020
    PUSH1 0x00
    MSTORE
    PUSH32 0x0000000000000000000000000000000000000000000000000000000000000005
    PUSH1 0x20
    MSTORE
    PUSH32 0x7374514155000000000000000000000000000000000000000000000000000000
    PUSH2 0x40
    MSTORE
    PUSH2 0x60
    PUSH1 0x00
    RETURN

// ============================================================
// decimals() → 18
// ============================================================
fn_decimals:
    JUMPDEST
    PUSH1 0x12
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// ERC20: totalSupply()
// ============================================================
fn_total_supply:
    JUMPDEST
    PUSH1 0x02
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// ERC20: balanceOf(address)
// ============================================================
fn_balance_of:
    JUMPDEST
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    PUSH1 0x80
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x03
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// ERC20: allowance(owner, spender) — two-level keccak slot4
// ============================================================
fn_allowance:
    JUMPDEST
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    PUSH1 0x24
    CALLDATALOAD
    PUSH1 0xa0
    MSTORE
    // ownerRoot = keccak(pad(owner) ++ pad(4)) → mem[0xe0]
    PUSH1 0x80
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x04
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    // leaf = keccak(pad(spender) ++ ownerRoot), SLOAD
    PUSH1 0xa0
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0xe0
    MLOAD
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// ERC20: approve(spender, wad)
// ============================================================
fn_approve:
    JUMPDEST
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    PUSH1 0x24
    CALLDATALOAD
    PUSH1 0xa0
    MSTORE
    // ownerRoot = keccak(pad(CALLER) ++ pad(4)) → mem[0xe0]
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x04
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    // leaf = keccak(pad(spender) ++ ownerRoot) → mem[0x100]
    PUSH1 0x80
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0xe0
    MLOAD
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH2 0x100
    MSTORE
    // storage[leaf] = wad
    PUSH1 0xa0
    MLOAD
    PUSH2 0x100
    MLOAD
    SSTORE
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// ERC20: transfer(to, wad)
// ============================================================
fn_transfer:
    JUMPDEST
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    PUSH1 0x24
    CALLDATALOAD
    PUSH1 0xa0
    MSTORE
    // callerKey → mem[0xe0]
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x03
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    // wad > callerBal → revert
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH1 0xa0
    MLOAD
    GT
    JUMPI @stqau_revert
    // callerBal -= wad
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH1 0xa0
    MLOAD
    SWAP1
    SUB
    PUSH1 0xe0
    MLOAD
    SSTORE
    // toKey → mem[0xe0]; toBal += wad
    PUSH1 0x80
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x03
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH1 0xa0
    MLOAD
    ADD
    PUSH1 0xe0
    MLOAD
    SSTORE
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// ERC20: transferFrom(from, to, wad)
// ============================================================
fn_transfer_from:
    JUMPDEST
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    PUSH1 0x24
    CALLDATALOAD
    PUSH1 0xa0
    MSTORE
    PUSH1 0x44
    CALLDATALOAD
    PUSH2 0xc0
    MSTORE
    // fromRoot = keccak(pad(from) ++ pad(4)) → mem[0xe0]
    PUSH1 0x80
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x04
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    // leaf = keccak(pad(CALLER) ++ fromRoot) → mem[0x100]
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0xe0
    MLOAD
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH2 0x100
    MSTORE
    // wad > allowance → revert
    PUSH2 0x100
    MLOAD
    SLOAD
    PUSH2 0xc0
    MLOAD
    GT
    JUMPI @stqau_revert
    // infinite approval (max) skips the deduction
    PUSH2 0x100
    MLOAD
    SLOAD
    PUSH32 0x521784d1a99bfaa8cacf8a16399195bd049878c2ffffffffffffffffffffffff
    EQ
    JUMPI @tf_skip_burn
    // allowance -= wad
    PUSH2 0x100
    MLOAD
    SLOAD
    PUSH2 0xc0
    MLOAD
    SWAP1
    SUB
    PUSH2 0x100
    MLOAD
    SSTORE
tf_skip_burn:
    JUMPDEST
    // fromBalKey → mem[0xe0]; wad > fromBal → revert
    PUSH1 0x80
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x03
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH2 0xc0
    MLOAD
    GT
    JUMPI @stqau_revert
    // fromBal -= wad
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH2 0xc0
    MLOAD
    SWAP1
    SUB
    PUSH1 0xe0
    MLOAD
    SSTORE
    // toBalKey → mem[0xe0]; toBal += wad
    PUSH1 0xa0
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x03
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH2 0xc0
    MLOAD
    ADD
    PUSH1 0xe0
    MLOAD
    SSTORE
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// shared revert exit
stqau_revert:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT

code_end:
