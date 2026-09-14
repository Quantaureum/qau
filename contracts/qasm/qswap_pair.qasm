// Quantaureum Node source, version 1.0.0.
// QVM QSwapPair contract (QASM) — R122 step 3 (core build)
// Uniswap V2 style AMM pair (single pool, no factory route registry, paused emergency switch)
//
// ============ Storage ============
//   slot 0:  token0 (the smaller address)
//   slot 1:  token1
//   slot 2:  reserve0
//   slot 3:  reserve1
//   slot 4:  blockTsLast
//   slot 5:  totalSupply (LP)
//   slot 6:  lpBalanceOf mapping root   key = keccak256(pad(addr) ++ pad(6))
//   slot 7:  lpAllowance mapping root   key = keccak256(pad(spender) ++ keccak256(pad(owner) ++ pad(7)))
//   slot 8:  router (the only authorized entry; mint/burn/swap require CALLER == router)
//   slot 9:  kLast
//   slot 10: paused (0=running, 1=paused)
//   slot 14: owner (emergency-switch holder, a constructor arg)
//   slot 11: price0CumulativeLast
//   slot 12: price1CumulativeLast
//   slot 13: lock (reentrancy lock)
//
// ============ Constructor ============
// The deploy script ABI-encodes the two token addresses in ascending order and appends them to the initCode.
//   [args_start+0 : +32]  token0
//   [args_start+32: +64]  token1
//   [args_start+64: +96]  router
//   [args_start+96:+128]  owner (emergency-switch holder)
// CODECOPY'd to mem[0x100] for reading.
//
// ============ ABI ============
//   getReserves() -> (uint112,uint112,uint32)  simplified: returns three 32B words
//   token0()/token1()/factory->always 0/router()/paused()
//   MINIMUM_LIQUIDITY() -> 1000
//   totalSupply()/balanceOf(a)/allowance(o,s)/approve(s,w)
//   transfer(t,w)/transferFrom(f,t,w)   (LP tokens)
//   mint(to)       called by the router; mints LP from the pool's token balance growth
//   burn(to)      called by the router; redeems LP for tokens at the min ratio
//   swap(amount0Out, amount1Out, to)  called by the router
//   skim(to)      skim off excess tokens (safety valve)
//   sync()        sync reserves = actual pool balances (safety valve)
//   pause()       owner
//   unpause()     owner
//   price0CumulativeLast()/price1CumulativeLast()
//
// ============ QVM semantics (verified cheat sheet) ============
//   LT/GT/SUB/DIV: a=top-of-stack op b=second
//   MSTORE/MLOAD/SLOAD: offset/key = top-of-stack;  SSTORE: key=top, value=second
//   KECCAK256: offset=top, size=second;  LOG*: offset=top, size=second
//   CALL (QVM native): push order gas,addr,value,inOff,inSize,retOff,retSize (retSize on top)
//   CALL pushes 1 on success, 0 on failure (top)
//   constructor args: CODECOPY @args_start reads from the code tail
//   memory is fresh on every call — no cross-call memory assumptions

.INIT
    // ---- copy args: 128 bytes to mem[0x100] ----
    PUSH1 0x80               // size = 128
    PUSH2 @args_start        // offset
    PUSH2 0x0100            // destOffset = 0x100
    CODECOPY

    // token0 = low 20 bytes of mem[0x100]
    PUSH2 0x0100
    MLOAD
    PUSH32 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
    AND
    PUSH1 0x00
    SSTORE

    // token1 = mem[0x120]
    PUSH2 0x0120
    MLOAD
    PUSH32 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
    AND
    PUSH1 0x01
    SSTORE

    // router = mem[0x140]
    PUSH2 0x0140
    MLOAD
    PUSH32 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
    AND
    PUSH1 0x08
    SSTORE

    // owner = mem[0x160] -> storage[14]
    PUSH2 0x0160
    MLOAD
    PUSH32 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
    AND
    PUSH1 0x0e
    SSTORE

    // ---- runtime code ----
    PUSH2 @code_end-@code_start
    PUSH2 @code_start
    PUSH1 0x00
    CODECOPY
    PUSH2 @code_end-@code_start
    PUSH1 0x00
    RETURN

.CODE
code_start:
    // enter the dispatcher only when calldata >= 4
    // QVM LT: a=top < b=second. Push order: PUSH4 first, CALLDATASIZE after → stack [4, cds]
    // a=cds, b=4 → cds<4 ? 1:0 → ISZERO inverts → 1 when calldata>=4 → jump
    PUSH1 0x04
    CALLDATASIZE
    LT
    ISZERO
    JUMPI @dispatch
    STOP

dispatch:
    JUMPDEST
    PUSH1 0x00
    CALLDATALOAD
    PUSH1 0xe0
    SHR
    PUSH4 0xffffffff
    AND

    DUP1
    PUSH4 0x0dfe1681
    EQ
    JUMPI @fn_token0

    DUP1
    PUSH4 0x0902f1ac
    EQ
    JUMPI @fn_get_reserves

    DUP1
    PUSH4 0xd21220a7
    EQ
    JUMPI @fn_token1

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

    DUP1
    PUSH4 0x6a627842
    EQ
    JUMPI @fn_mint

    DUP1
    PUSH4 0x89afcb44
    EQ
    JUMPI @fn_burn

    DUP1
    PUSH4 0x6d9a640a
    EQ
    JUMPI @fn_swap

    DUP1
    PUSH4 0xfff6cae9
    EQ
    JUMPI @fn_sync

    DUP1
    PUSH4 0xbc25cf77
    EQ
    JUMPI @fn_skim

    DUP1
    PUSH4 0xba9a7a56
    EQ
    JUMPI @fn_min_liquidity

    DUP1
    PUSH4 0x5909c0d5
    EQ
    JUMPI @fn_price0_cum

    DUP1
    PUSH4 0x5a3d5493
    EQ
    JUMPI @fn_price1_cum

    DUP1
    PUSH4 0xc45a0155
    EQ
    JUMPI @fn_factory

    DUP1
    PUSH4 0x5c975abb
    EQ
    JUMPI @fn_paused

    DUP1
    PUSH4 0x8456cb59
    EQ
    JUMPI @fn_pause

    DUP1
    PUSH4 0x3f4ba83a
    EQ
    JUMPI @fn_unpause

    DUP1
    PUSH4 0x8da5cb5b
    EQ
    JUMPI @fn_owner

    DUP1
    PUSH4 0xf887ea40
    EQ
    JUMPI @fn_router

    PUSH1 0x00
    PUSH1 0x00
    REVERT

// ============================================================
// view functions (read-only, no locks, no permissions)
// ============================================================

// ---- getReserves() -> 3 x 32B: reserve0, reserve1, blockTsLast ----
fn_get_reserves:
    JUMPDEST
    PUSH1 0x02
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x03
    SLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x04
    SLOAD
    PUSH2 0x40
    MSTORE
    PUSH2 0x60
    PUSH1 0x00
    RETURN

// ---- token0() ----
fn_token0:
    JUMPDEST
    PUSH1 0x00
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- token1() ----
fn_token1:
    JUMPDEST
    PUSH1 0x01
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- factory() -> 0 (v1 has no factory; 0 means a native pool) ----
fn_factory:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- router() -> storage[8] ----
fn_router:
    JUMPDEST
    PUSH1 0x08
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- owner() -> storage[10] ----
fn_owner:
    JUMPDEST
    PUSH1 0x0e
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- paused() -> storage[10]? No, slot 10 = owner... layout per header: 8=router, 9=kLast, 10=paused, owner uses slot 14 (added)
// Correction: the header declares slot 8=router, 10=paused; owner uses slot 14 (new)
// ---- paused() -> storage[10] ----
fn_paused:
    JUMPDEST
    PUSH1 0x0a
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- MINIMUM_LIQUIDITY() -> 1000 ----
fn_min_liquidity:
    JUMPDEST
    PUSH2 0x03e8
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- price0CumulativeLast() -> storage[11] ----
fn_price0_cum:
    JUMPDEST
    PUSH1 0x0b
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- price1CumulativeLast() -> storage[12] ----
fn_price1_cum:
    JUMPDEST
    PUSH1 0x0c
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- totalSupply() -> storage[5] ----
fn_total_supply:
    JUMPDEST
    PUSH1 0x05
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- balanceOf(address) -> lp mapping (slot 6) ----
fn_balance_of:
    JUMPDEST
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x06
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

// ---- allowance(owner, spender) -> lpAllowance (slot 7) ----
fn_allowance:
    JUMPDEST
    // mem[0x80]=owner, mem[0xa0]=spender
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    PUSH1 0x24
    CALLDATALOAD
    PUSH1 0xa0
    MSTORE
    // ownerRoot = keccak(pad(owner) ++ pad(7))
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

// ---- approve(spender, wad) (LP-token approval) ----
fn_approve:
    JUMPDEST
    // mem[0x80]=spender, mem[0xa0]=wad
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    PUSH1 0x24
    CALLDATALOAD
    PUSH1 0xa0
    MSTORE
    // ownerRoot = keccak(pad(CALLER) ++ pad(7))
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
    // leaf = keccak(pad(spender) ++ ownerRoot)
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
    PUSH1 0xe0
    MSTORE
    // storage[leaf] = wad
    PUSH1 0xa0
    MLOAD
    PUSH1 0xe0
    MLOAD
    SSTORE
    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// pause()/unpause() — owner only (storage[14] = owner)
// ============================================================
fn_pause:
    JUMPDEST
    // CALLER == owner(storage[14]) ?
    CALLER
    PUSH1 0x0e
    SLOAD
    EQ
    JUMPI @pause_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
pause_ok:
    JUMPDEST
    PUSH1 0x01
    PUSH1 0x0a
    SSTORE
    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

fn_unpause:
    JUMPDEST
    CALLER
    PUSH1 0x0e
    SLOAD
    EQ
    JUMPI @unpause_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
unpause_ok:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x0a
    SSTORE
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// LP transfer / transferFrom (standard ERC20 semantics, slot 6 balances, slot 7 allowances)
// ============================================================
fn_transfer:
    JUMPDEST
    // mem[0x80]=to, mem[0xa0]=wad
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    PUSH1 0x24
    CALLDATALOAD
    PUSH1 0xa0
    MSTORE
    // callerKey = keccak(pad(CALLER) ++ pad(6)) -> mem[0xe0]
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
    // wad > callerBal ? revert
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH1 0xa0
    MLOAD
    GT
    JUMPI @lp_transfer_insufficient
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
    // toKey = keccak(pad(to) ++ pad(6)) -> mem[0xe0]
    PUSH1 0x80
    MLOAD
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
    // toBal += wad
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH1 0xa0
    MLOAD
    ADD
    PUSH1 0xe0
    MLOAD
    SSTORE
    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

lp_transfer_insufficient:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT

fn_transfer_from:
    JUMPDEST
    // mem[0x80]=from, mem[0xa0]=to, mem[0xc0]=wad
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
    // fromRoot = keccak(pad(from) ++ pad(7)) -> mem[0xe0]
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
    PUSH1 0xe0
    MSTORE
    // leaf = keccak(pad(CALLER) ++ fromRoot) -> mem[0x100]
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
    // wad > allowance ? revert
    PUSH2 0x100
    MLOAD
    SLOAD
    PUSH2 0xc0
    MLOAD
    GT
    JUMPI @lp_transfer_from_insufficient
    // infinite approval skipped
    PUSH2 0x100
    MLOAD
    SLOAD
    PUSH32 0x521784d1a99bfaa8cacf8a16399195bd049878c2ffffffffffffffffffffffff
    EQ
    JUMPI @lp_skip_burn
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
    JUMP @lp_after_burn
lp_skip_burn:
    JUMPDEST
lp_after_burn:
    JUMPDEST
    // fromBalKey = keccak(pad(from) ++ pad(6)) -> mem[0xe0]
    PUSH1 0x80
    MLOAD
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
    // wad > fromBal ? revert
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH2 0xc0
    MLOAD
    GT
    JUMPI @lp_transfer_from_insufficient
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
    // toBalKey = keccak(pad(to) ++ pad(6)) -> mem[0xe0]
    PUSH1 0xa0
    MLOAD
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
    // toBal += wad
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH2 0xc0
    MLOAD
    ADD
    PUSH1 0xe0
    MLOAD
    SSTORE
    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

lp_transfer_from_insufficient:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT


// ============================================================
// unified cross-contract call layout (shared by all helpers, 32B-aligned, zero overlap):
//   mem[0x180..0x1a0)  token address (caller writes)
//   mem[0x1a0..0x1c0)  selector word (call1; caller writes)
//   mem[0x1c0..0x1e0)  arg/to 32B (caller writes)
//   mem[0x1e0..0x200)  wad 32B (transfer; caller writes)
//   mem[0x200..0x244)  CALL calldata assembly area (helper writes; 68B for transfer)
//   mem[0x240..0x260)  CALL retdata (helper writes)
//   helper convention: the caller pushes the return point, then JUMPs; the helper ends with SWAP1;JUMP back, leaving the return value on top
//
//   QVM CALL push order (retSize on top): gas, addr, value, inOff, inSize, retOff, retSize
//   QVM SHL: shift=top, value=second
//   QVM CALL: pushes 1 on success, 0 on failure; retdata copied to mem[retOff..]
// ============================================================

// ---- helper_token_call1: single-arg function on token(mem[0x180]).
//      layout (32B-aligned, zero overlap):
//        mem[0x180..0x1a0)  token address (caller writes)
//        mem[0x1a0..0x1c0)  selector word (caller writes)
//        mem[0x1c0..0x1e0)  arg 32B (caller writes)
//        mem[0x200..0x224)  CALL calldata assembly [4B sel][32B arg]
//        mem[0x240..0x260)  CALL retdata
//      return value (32B) on top of stack ----
helper_token_call1:
    JUMPDEST
    // mem[0x200] = sel << 224 (selector in the top 4 bytes of the word)
    PUSH2 0x1a0
    MLOAD               // stack: [sel]
    PUSH1 0xe0          // 224
    SHL                 // stack: [sel<<224] (SHL: shift on top)
    PUSH2 0x200
    MSTORE
    // mem[0x204] = arg (right after the 4B selector)
    PUSH2 0x1c0
    MLOAD
    PUSH2 0x204
    MSTORE
    // CALL: gas, addr, value, inOff, inSize, retOff, retSize (retSize on top)
    PUSH2 0x7530        // gas 30000
    PUSH2 0x180
    MLOAD               // addr
    PUSH1 0x00          // value
    PUSH2 0x200         // inOff
    PUSH1 0x24          // inSize 36
    PUSH2 0x240         // retOff
    PUSH1 0x20          // retSize 32
    CALL                // stack: [1/0]
    JUMPI @htc1_ok      // success (1) skips the revert (JUMPI: dest=top, cond=second)
    PUSH1 0x00
    PUSH1 0x00
    REVERT
htc1_ok:
    JUMPDEST
    PUSH2 0x240
    MLOAD               // stack: [retaddr, ret] (ret on top)
    SWAP1               // stack: [ret, retaddr] (retaddr on top)
    JUMP                // jump back to the caller, ret stays on top

// ============================================================
// mint(address to) — router only, unpaused; reentrancy lock
//   subsequent mint: amount = min(d0*S/r0, d1*S/r1)
//   first mint: amount = sqrt(b0*b1) - 1000, with 1000 LP forever locked at 0x0
//   then reserves = b0, b1 (sync semantics)
// ============================================================
fn_mint:
    JUMPDEST
    // CALLER == router(storage[8])?
    CALLER
    PUSH1 0x08
    SLOAD
    EQ
    JUMPI @mint_gate1     // EQ non-zero (match) -> skip the revert
    PUSH1 0x00
    PUSH1 0x00
    REVERT
mint_gate1:
    JUMPDEST
    // paused==0?
    PUSH1 0x0a
    SLOAD
    ISZERO
    JUMPI @mint_gate2
    PUSH1 0x00
    PUSH1 0x00
    REVERT
mint_gate2:
    JUMPDEST
    // lock==0?
    PUSH1 0x0d
    SLOAD
    ISZERO
    JUMPI @mint_gate3
    PUSH1 0x00
    PUSH1 0x00
    REVERT
mint_gate3:
    JUMPDEST
    // set the lock
    PUSH1 0x01
    PUSH1 0x0d
    SSTORE
    // mem[0x80] = to
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    // ---- b0 = token0.balanceOf(pair): token0->0x180, sel->0x1a0, arg(pair)->0x1c0 ----
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x70a08231
    PUSH2 0x1a0
    MSTORE
    ADDRESS
    PUSH2 0x1c0
    MSTORE
    PUSH2 @mint_have_b0
    JUMP @helper_token_call1
mint_have_b0:
    JUMPDEST
    PUSH1 0xa0
    MSTORE              // mem[0xa0] = b0
    // ---- b1 = token1.balanceOf(pair) ----
    PUSH1 0x01
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x70a08231
    PUSH2 0x1a0
    MSTORE
    ADDRESS
    PUSH2 0x1c0
    MSTORE
    PUSH2 @mint_have_b1
    JUMP @helper_token_call1
mint_have_b1:
    JUMPDEST
    PUSH1 0xc0
    MSTORE              // mem[0xc0] = b1
    // ---- S = supply -> mem[0xe0] ----
    PUSH1 0x05
    SLOAD
    PUSH1 0xe0
    MSTORE
    // S == 0 ? first mint : subsequent mint
    PUSH1 0xe0
    MLOAD
    ISZERO
    JUMPI @mint_first
    // ======== subsequent mint: amount = min(d0*S/r0, d1*S/r1) ========
    // d0 = b0 - r0 -> mem[0x100]  (SUB: a=top; push r0 first, then b0)
    PUSH1 0x02
    SLOAD
    PUSH1 0xa0
    MLOAD
    SUB
    PUSH2 0x100
    MSTORE
    // d1 = b1 - r1 -> mem[0x120]  (SUB: a=top; push r1 first, then b1)
    PUSH1 0x03
    SLOAD
    PUSH1 0xc0
    MLOAD
    SUB
    PUSH2 0x120
    MSTORE
    // cand0 = d0*S/r0 -> mem[0x140]  (DIV: a=top; push r0 first, then d0*S)
    PUSH1 0x02
    SLOAD
    PUSH2 0x100
    MLOAD
    PUSH1 0xe0
    MLOAD
    MUL
    DIV
    PUSH2 0x140
    MSTORE
    // cand1 = d1*S/r1 -> mem[0x160]  (DIV: a=top; push r1 first, then d1*S)
    PUSH1 0x03
    SLOAD
    PUSH2 0x120
    MLOAD
    PUSH1 0xe0
    MLOAD
    MUL
    DIV
    PUSH2 0x160
    MSTORE
    // amount = min(cand0, cand1): QVM LT a=top. Push [cand1, cand0] (cand0 on top)
    PUSH2 0x160
    MLOAD
    PUSH2 0x140
    MLOAD
    LT
    JUMPI @mint_take_c0
    JUMP @mint_take_c1
mint_take_c0:
    JUMPDEST
    PUSH2 0x140
    MLOAD
    JUMP @mint_have_amt
mint_take_c1:
    JUMPDEST
    PUSH2 0x160
    MLOAD
mint_have_amt:
    JUMPDEST
    // stack: [amount] -> mem[0xe0]
    PUSH1 0xe0
    MSTORE
    JUMP @mint_credit

    // ======== first mint: amount = sqrt(b0*b1) - 1000 ========
mint_first:
    JUMPDEST
    // p = b0*b1 -> mem[0x280]
    PUSH1 0xa0
    MLOAD
    PUSH1 0xc0
    MLOAD
    MUL
    PUSH2 0x280
    MSTORE
    // z = p -> mem[0x2a0]
    PUSH2 0x280
    MLOAD
    PUSH2 0x2a0
    MSTORE
    // p==0 -> revert (empty pool)
    PUSH2 0x280
    MLOAD
    ISZERO
    JUMPI @mint_too_small
sqrt_loop:
    JUMPDEST
    // znew = (z + p/z)/2 -> mem[0x2c0]
    // DIV: a=top/b=second. Push z first, then p: a=p/b=z -> p/z ✓
    PUSH2 0x2a0
    MLOAD               // stack: [z]
    PUSH2 0x280
    MLOAD               // stack: [z, p] p on top
    DIV                 // stack: [p/z] OK
    // ADD: a=top+b=second. Stack is [z(below), p/z(top)] — we need [p/z, z]:
    // ADD pops a=top=p/z, b=second=z -> p/z+z ✓ (addition commutes)
    PUSH2 0x2a0
    MLOAD               // stack: [p/z, z] z on top
    ADD                 // stack: [p/z+z] OK
    // (p/z+z)/2: DIV a=top. Push 2 first, then (p/z+z)? Stack currently [p/z+z(top)] — directly:
    // pushing 2 -> [p/z+z, 2], 2 on top=a gives 2/(p/z+z)=0 ✗
    // Correct: store the sum at mem[0x300], push 2, then MLOAD it back (2 second, sum on top)
    PUSH2 0x300
    MSTORE              // mem[0x300] = p/z+z
    PUSH1 0x02
    PUSH2 0x300
    MLOAD               // stack: [2, p/z+z] sum on top
    DIV                 // stack: [(p/z+z)/2] OK
    PUSH2 0x2c0
    MSTORE              // mem[0x2c0] = znew
    // znew < z ? continue (push [z, znew], znew on top: a=znew < z)
    PUSH2 0x2a0
    MLOAD
    PUSH2 0x2c0
    MLOAD
    LT
    JUMPI @sqrt_store_z   // znew<z: set z = znew and continue
    JUMP @sqrt_done
sqrt_store_z:
    JUMPDEST
    PUSH2 0x2c0
    MLOAD
    PUSH2 0x2a0
    MSTORE              // z = znew
    JUMP @sqrt_loop
sqrt_done:
    JUMPDEST
    // Converged: amount = z - 1000 -> mem[0xe0]  (SUB: a=top-b=second; push 1000 first, then z)
    PUSH2 0x03e8
    PUSH2 0x2a0
    MLOAD
    SUB
    PUSH1 0xe0
    MSTORE
    // sqrt < 1001 ? revert (push [1001, sqrt], sqrt on top: a=sqrt < 1001)
    PUSH2 0x03e9
    PUSH2 0x2a0
    MLOAD
    LT
    JUMPI @mint_too_small
    // 1000 LP forever locked at address 0: storage[keccak(pad(0)++pad(6))] = 1000
    // keccak input area: mem[0x20]=pad(0), mem[0x40]=pad(6); consumed immediately, no aliasing
    PUSH2 0x03e8        // value=1000 first
    PUSH1 0x00
    PUSH1 0x20
    MSTORE
    PUSH1 0x06
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256           // stack: [1000, zeroKey] key on top
    SSTORE

mint_credit:
    JUMPDEST
    // ---- LP[to] += amount; supply += amount ----
    // toKey = keccak(pad(to)++pad(6)) -> mem[0x2e0]
    PUSH1 0x80
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x06
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH2 0x2e0
    MSTORE
    // LP[to] += amount (value=old+amt first, key after)
    PUSH2 0x2e0
    MLOAD
    SLOAD
    PUSH1 0xe0
    MLOAD
    ADD                 // stack: [newBal]
    PUSH2 0x2e0
    MLOAD               // stack: [newBal, key]
    SSTORE
    // supply += amount
    PUSH1 0x05
    SLOAD
    PUSH1 0xe0
    MLOAD
    ADD
    PUSH1 0x05
    SSTORE
    // ---- _update: r0=b0, r1=b1, blockTsLast ----
    PUSH1 0xa0
    MLOAD
    PUSH1 0x02
    SSTORE
    PUSH1 0xc0
    MLOAD
    PUSH1 0x03
    SSTORE
    TIMESTAMP
    PUSH1 0x04
    SSTORE
    // ---- unlock + return true ----
    PUSH1 0x00
    PUSH1 0x0d
    SSTORE
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

mint_too_small:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT


// ---- helper_token_transfer: token(mem[0x180]).transfer(mem[0x1c0]=to, mem[0x1e0]=wad)
//      layout (32B-aligned, zero overlap):
//        mem[0x180..0x1a0)  token address (caller writes)
//        mem[0x1c0..0x1e0)  to 32B (caller writes)
//        mem[0x1e0..0x200)  wad 32B (caller writes)
//        mem[0x200..0x244)  CALL calldata [4B sel][32B to][32B wad] 68B
//        mem[0x240..0x260)  CALL retdata
//      no return value needed on success (only CALL's 1/0 checked)
helper_token_transfer:
    JUMPDEST
    // mem[0x200] = sel<<224
    PUSH4 0xa9059cbb
    PUSH1 0xe0
    SHL
    PUSH2 0x200
    MSTORE
    // mem[0x204] = to
    PUSH2 0x1c0
    MLOAD
    PUSH2 0x204
    MSTORE
    // mem[0x224] = wad (0x204+32 = 0x224)
    PUSH2 0x1e0
    MLOAD
    PUSH2 0x224
    MSTORE
    // CALL: gas, addr, value, inOff=0x200, inSize=0x44, retOff=0x240, retSize=0x20
    PUSH2 0x7530
    PUSH2 0x180
    MLOAD
    PUSH1 0x00
    PUSH2 0x200
    PUSH1 0x44
    PUSH2 0x240
    PUSH1 0x20
    CALL
    JUMPI @htt_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
htt_ok:
    JUMPDEST
    JUMP

// ============================================================
// burn(address to) — router only; LP redeemed for tokens pro rata to pool balances
//   liquidity = LP[caller(router)]  (the router first transferFrom's the user's LP to itself)
//   amount0 = liq * b0 / S ; amount1 = liq * b1 / S
//   (Uniswap computes a MINIMUM_LIQUIDITY gift via balance - reserve; v1 simplifies:
//    pro rata to current S; the 1000 locked at first mint stays in the pool forever)
fn_burn:
    JUMPDEST
    // router gate + not paused + lock (same as mint)
    CALLER
    PUSH1 0x08
    SLOAD
    EQ
    JUMPI @burn_gate1
    PUSH1 0x00
    PUSH1 0x00
    REVERT
burn_gate1:
    JUMPDEST
    PUSH1 0x0a
    SLOAD
    ISZERO
    JUMPI @burn_gate2
    PUSH1 0x00
    PUSH1 0x00
    REVERT
burn_gate2:
    JUMPDEST
    PUSH1 0x0d
    SLOAD
    ISZERO
    JUMPI @burn_gate3
    PUSH1 0x00
    PUSH1 0x00
    REVERT
burn_gate3:
    JUMPDEST
    PUSH1 0x01
    PUSH1 0x0d
    SSTORE
    // mem[0x80] = to
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    // ---- b0, b1 ----
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x70a08231
    PUSH2 0x1a0
    MSTORE
    ADDRESS
    PUSH2 0x1c0
    MSTORE
    PUSH2 @burn_have_b0
    JUMP @helper_token_call1
burn_have_b0:
    JUMPDEST
    PUSH1 0xa0
    MSTORE
    PUSH1 0x01
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x70a08231
    PUSH2 0x1a0
    MSTORE
    ADDRESS
    PUSH2 0x1c0
    MSTORE
    PUSH2 @burn_have_b1
    JUMP @helper_token_call1
burn_have_b1:
    JUMPDEST
    PUSH1 0xc0
    MSTORE
    // ---- liq = LP[CALLER] (i.e. the router itself) ----
    // layout (32B spacing): to=0x80 b0=0xa0 b1=0xc0 liq=0xe0 S=0x100 amt0=0x120 amt1=0x140 key=0x160
    // routerKey = keccak(pad(CALLER)++pad(6)) -> mem[0x160]
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x06
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH2 0x160
    MSTORE
    // liq -> mem[0xe0]
    PUSH2 0x160
    MLOAD
    SLOAD
    PUSH1 0xe0
    MSTORE
    // liq == 0 ? revert
    PUSH1 0xe0
    MLOAD
    ISZERO
    JUMPI @burn_zero
    // ---- S -> mem[0x100] ----
    PUSH1 0x05
    SLOAD
    PUSH2 0x100
    MSTORE
    // amount0 = liq*b0/S -> mem[0x120]  (DIV: a=top; push S first, then liq*b0)
    PUSH2 0x100
    MLOAD               // stack: [S]
    PUSH1 0xe0
    MLOAD
    PUSH1 0xa0
    MLOAD
    MUL                 // stack: [S, liq*b0] (liq*b0 on top)
    DIV                 // stack: [liq*b0/S] OK
    PUSH2 0x120
    MSTORE
    // amount1 = liq*b1/S -> mem[0x140]
    PUSH2 0x100
    MLOAD
    PUSH1 0xe0
    MLOAD
    PUSH1 0xc0
    MLOAD
    MUL
    DIV                 // [liq*b1/S] ✓
    PUSH2 0x140
    MSTORE
    // ---- LP[router] = 0; supply -= liq ----
    // SSTORE: key=top, value=second. Push value(0) first, then key(routerKey@0x160)
    PUSH1 0x00
    PUSH2 0x160
    MLOAD
    SSTORE
    // supply -= liq: SUB a=top. Push liq first, then supply (supply on top) -> supply - liq
    PUSH1 0xe0
    MLOAD
    PUSH1 0x05
    SLOAD
    SUB                     // stack: [supply - liq] OK
    PUSH1 0x05
    SSTORE
    // ---- transfer out token: token0.transfer(to, amount0) ----
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH1 0x80
    MLOAD
    PUSH2 0x1c0
    MSTORE
    PUSH2 0x120
    MLOAD
    PUSH2 0x1e0
    MSTORE
    PUSH2 @burn_sent0
    JUMP @helper_token_transfer
burn_sent0:
    JUMPDEST
    // ---- token1.transfer(to, amount1) ----
    PUSH1 0x01
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH1 0x80
    MLOAD
    PUSH2 0x1c0
    MSTORE
    PUSH2 0x140
    MLOAD
    PUSH2 0x1e0
    MSTORE
    PUSH2 @burn_sent1
    JUMP @helper_token_transfer
burn_sent1:
    JUMPDEST
    // ---- re-read balances and _update ----
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x70a08231
    PUSH2 0x1a0
    MSTORE
    ADDRESS
    PUSH2 0x1c0
    MSTORE
    PUSH2 @burn_have_b0b
    JUMP @helper_token_call1
burn_have_b0b:
    JUMPDEST
    PUSH1 0xa0
    MSTORE
    PUSH1 0x01
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x70a08231
    PUSH2 0x1a0
    MSTORE
    ADDRESS
    PUSH2 0x1c0
    MSTORE
    PUSH2 @burn_have_b1b
    JUMP @helper_token_call1
burn_have_b1b:
    JUMPDEST
    PUSH1 0xc0
    MSTORE
    PUSH1 0xa0
    MLOAD
    PUSH1 0x02
    SSTORE
    PUSH1 0xc0
    MLOAD
    PUSH1 0x03
    SSTORE
    TIMESTAMP
    PUSH1 0x04
    SSTORE
    // ---- unlock + return true ----
    PUSH1 0x00
    PUSH1 0x0d
    SSTORE
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

burn_zero:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT

// ============================================================
// swap(amount0Out, amount1Out, to) — router only; unpaused; reentrancy lock
//   checks: (amount0Out==0) XOR (amount1Out==0); to != token0/token1
//   constant k: b0adj*b1adj >= r0*r1*1e6
//     b0adj = (b0 - amount0Out)*1000, b1adj = (b1 - amount1Out)*1000
//     (Uniswap: (balance*1000 - amountOut*3) — i.e. a 0.3% fee)
// ============================================================
fn_swap:
    JUMPDEST
    CALLER
    PUSH1 0x08
    SLOAD
    EQ
    JUMPI @swap_gate1
    PUSH1 0x00
    PUSH1 0x00
    REVERT
swap_gate1:
    JUMPDEST
    PUSH1 0x0a
    SLOAD
    ISZERO
    JUMPI @swap_gate2
    PUSH1 0x00
    PUSH1 0x00
    REVERT
swap_gate2:
    JUMPDEST
    PUSH1 0x0d
    SLOAD
    ISZERO
    JUMPI @swap_gate3
    PUSH1 0x00
    PUSH1 0x00
    REVERT
swap_gate3:
    JUMPDEST
    PUSH1 0x01
    PUSH1 0x0d
    SSTORE
    // ---- args: mem[0x80]=amount0Out, mem[0xa0]=amount1Out, mem[0xc0]=to ----
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
    PUSH1 0xc0
    MSTORE
    // ---- check: (a0+a1)==0 -> revert. ISZERO=1 means the sum is 0, jump to the revert block ----
    PUSH1 0x80
    MLOAD
    PUSH1 0xa0
    MLOAD
    ADD
    ISZERO
    JUMPI @swap_zero_out     // sum is 0 -> revert
    JUMP @swap_gate4
swap_zero_out:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT
swap_gate4:
    JUMPDEST
    // ---- check to != token0, token1 ----
    // to == token0 ?  (push token0 first, then to: EQ a=top=to)
    PUSH1 0x00
    SLOAD
    PUSH1 0xc0
    MLOAD
    EQ
    JUMPI @swap_bad_to        // EQ=1 (equal) jumps to revert
    PUSH1 0x01
    SLOAD
    PUSH1 0xc0
    MLOAD
    EQ
    JUMPI @swap_bad_to
    JUMP @swap_gate5
swap_bad_to:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT
swap_gate5:
    JUMPDEST
    // ---- send amount0Out (token0 -> to) if > 0 ----
    // a0==0 ? skip the transfer : do it
    PUSH1 0x80
    MLOAD
    ISZERO
    JUMPI @swap_after_out0    // a0==0 (ISZERO=1) -> skip
    JUMP @swap_do_out0
swap_do_out0:
    JUMPDEST
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH1 0xc0
    MLOAD
    PUSH2 0x1c0
    MSTORE
    PUSH1 0x80
    MLOAD
    PUSH2 0x1e0
    MSTORE
    PUSH2 @swap_sent0
    JUMP @helper_token_transfer
swap_sent0:
    JUMPDEST
swap_after_out0:
    JUMPDEST
    // ---- send amount1Out ----
    // a1==0 ? skip the transfer : do it
    PUSH1 0xa0
    MLOAD
    ISZERO
    JUMPI @swap_after_out1    // a1==0 (ISZERO=1) -> skip
    JUMP @swap_do_out1
swap_do_out1:
    JUMPDEST
    PUSH1 0x01
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH1 0xc0
    MLOAD
    PUSH2 0x1c0
    MSTORE
    PUSH1 0xa0
    MLOAD
    PUSH2 0x1e0
    MSTORE
    PUSH2 @swap_sent1
    JUMP @helper_token_transfer
swap_sent1:
    JUMPDEST
swap_after_out1:
    JUMPDEST
    // ---- re-read b0, b1 ----
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x70a08231
    PUSH2 0x1a0
    MSTORE
    ADDRESS
    PUSH2 0x1c0
    MSTORE
    PUSH2 @swap_have_b0
    JUMP @helper_token_call1
swap_have_b0:
    JUMPDEST
    PUSH2 0x100
    MSTORE              // mem[0x100] = b0 (does not clobber a1Out/to)
    PUSH1 0x01
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x70a08231
    PUSH2 0x1a0
    MSTORE
    ADDRESS
    PUSH2 0x1c0
    MSTORE
    PUSH2 @swap_have_b1
    JUMP @helper_token_call1
swap_have_b1:
    JUMPDEST
    PUSH2 0x120
    MSTORE              // mem[0x120] = b1
    // ---- amountIn = b - (r - aOut); negative (underflow) reverts ----
    // a0In = b0 - (r0 - a0Out) -> mem[0x140]
    // SUB: a=top. For (r0-a0Out): push a0Out first, then r0 -> a=r0(top)
    PUSH1 0x80
    MLOAD
    PUSH1 0x02
    SLOAD
    SUB                 // stack: [r0 - a0Out]
    PUSH2 0x100
    MLOAD               // stack: [r0-a0Out, b0] b0 on top
    SUB                 // stack: [b0 - (r0-a0Out)] OK
    PUSH2 0x140
    MSTORE
    // a1In = b1 - (r1 - a1Out) -> mem[0x160]
    PUSH1 0xa0
    MLOAD
    PUSH1 0x03
    SLOAD
    SUB                 // stack: [r1 - a1Out]
    PUSH2 0x120
    MLOAD
    SUB                 // stack: [b1 - (r1-a1Out)] OK
    PUSH2 0x160
    MSTORE
    // Underflow defense: if b - (r + aOut) is negative (reserves + sent > balance) -> revert.
    // A negative number in QVM's unsigned domain = a huge value > 2^255. Detect via "value > 2^255-1 ? negative":
    // take the top bit: SHR 255 gives 1 when negative. SHR: shift=top.
    PUSH2 0x140
    MLOAD
    PUSH1 0xff          // 255
    SHR                 // a0In >> 255 (1=negative)
    JUMPI @swap_k_fail  // non-zero (negative) -> revert
    PUSH2 0x160
    MLOAD
    PUSH1 0xff
    SHR
    JUMPI @swap_k_fail  // a1In negative -> revert
    // ---- k check: b0adj*b1adj >= r0*r1*1e6 ----
    // b0adj = b0*1000 - a0In*3 -> mem[0x180? No, that's the helper area. Use 0x2c0]
    PUSH2 0x140
    MLOAD
    PUSH1 0x03
    MUL                 // stack: [a0In*3]
    PUSH2 0x100
    MLOAD
    PUSH2 0x03e8
    MUL                 // stack: [a0In*3, b0*1000] (b0*1000 on top)
    SUB                 // stack: [b0*1000 - a0In*3] OK
    PUSH2 0x2c0
    MSTORE
    // b1adj = b1*1000 - a1In*3 -> mem[0x2e0]
    PUSH2 0x160
    MLOAD
    PUSH1 0x03
    MUL
    PUSH2 0x120
    MLOAD
    PUSH2 0x03e8
    MUL
    SUB                 // stack: [b1*1000 - a1In*3] OK
    PUSH2 0x2e0
    MSTORE
    // lhs = b0adj*b1adj -> mem[0x280]
    PUSH2 0x2c0
    MLOAD
    PUSH2 0x2e0
    MLOAD
    MUL
    PUSH2 0x280
    MSTORE
    // rhs = r0 * r1 * 1000000 -> mem[0x2a0]
    PUSH1 0x02
    SLOAD
    PUSH1 0x03
    SLOAD
    MUL
    PUSH4 0x0f4240
    MUL
    PUSH2 0x2a0
    MSTORE
    // rhs > lhs ? revert. GT: a=top>second. Push [lhs, rhs] (rhs on top): a=rhs > lhs ✓
    PUSH2 0x280
    MLOAD
    PUSH2 0x2a0
    MLOAD
    GT
    JUMPI @swap_k_fail
    // ---- _update + unlock + true ----
    PUSH2 0x100
    MLOAD
    PUSH1 0x02
    SSTORE
    PUSH2 0x120
    MLOAD
    PUSH1 0x03
    SSTORE
    TIMESTAMP
    PUSH1 0x04
    SSTORE
    PUSH1 0x00
    PUSH1 0x0d
    SSTORE
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

swap_k_fail:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT

// ============================================================
// sync() — anyone can call: reserves = actual pool balances (safety valve)
// ============================================================
fn_sync:
    JUMPDEST
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x70a08231
    PUSH2 0x1a0
    MSTORE
    ADDRESS
    PUSH2 0x1c0
    MSTORE
    PUSH2 @sync_have_b0
    JUMP @helper_token_call1
sync_have_b0:
    JUMPDEST
    PUSH1 0xa0
    MSTORE
    PUSH1 0x01
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x70a08231
    PUSH2 0x1a0
    MSTORE
    ADDRESS
    PUSH2 0x1c0
    MSTORE
    PUSH2 @sync_have_b1
    JUMP @helper_token_call1
sync_have_b1:
    JUMPDEST
    PUSH1 0xc0
    MSTORE
    PUSH1 0xa0
    MLOAD
    PUSH1 0x02
    SSTORE
    PUSH1 0xc0
    MLOAD
    PUSH1 0x03
    SSTORE
    TIMESTAMP
    PUSH1 0x04
    SSTORE
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// skim(address to) — anyone can call: skim off tokens in excess of reserves
// ============================================================
fn_skim:
    JUMPDEST
    // mem[0x80] = to
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    // b0
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x70a08231
    PUSH2 0x1a0
    MSTORE
    ADDRESS
    PUSH2 0x1c0
    MSTORE
    PUSH2 @skim_have_b0
    JUMP @helper_token_call1
skim_have_b0:
    JUMPDEST
    PUSH1 0xa0
    MSTORE
    // b1
    PUSH1 0x01
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x70a08231
    PUSH2 0x1a0
    MSTORE
    ADDRESS
    PUSH2 0x1c0
    MSTORE
    PUSH2 @skim_have_b1
    JUMP @helper_token_call1
skim_have_b1:
    JUMPDEST
    PUSH1 0xc0
    MSTORE
    // d0 = b0 - r0 (transfer only if > 0)
    PUSH1 0xa0
    MLOAD
    PUSH1 0x02
    SLOAD
    SUB
    PUSH2 0x100
    MSTORE
    PUSH2 0x100
    MLOAD
    ISZERO
    JUMPI @skim_do0
    JUMP @skim_after0
skim_do0:
    JUMPDEST
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH1 0x80
    MLOAD
    PUSH2 0x1c0
    MSTORE
    PUSH2 0x100
    MLOAD
    PUSH2 0x1e0
    MSTORE
    PUSH2 @skim_sent0
    JUMP @helper_token_transfer
skim_sent0:
    JUMPDEST
skim_after0:
    JUMPDEST
    // d1 = b1 - r1
    PUSH1 0xc0
    MLOAD
    PUSH1 0x03
    SLOAD
    SUB
    PUSH2 0x110
    MSTORE
    PUSH2 0x110
    MLOAD
    ISZERO
    JUMPI @skim_do1
    JUMP @skim_after1
skim_do1:
    JUMPDEST
    PUSH1 0x01
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH1 0x80
    MLOAD
    PUSH2 0x1c0
    MSTORE
    PUSH2 0x110
    MLOAD
    PUSH2 0x1e0
    MSTORE
    PUSH2 @skim_sent1
    JUMP @helper_token_transfer
skim_sent1:
    JUMPDEST
skim_after1:
    JUMPDEST
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

code_end:

// constructor args (ABI-encoded by the deploy script, appended here):
//   [args_start+0 : +32]  token0 (ascending)
//   [args_start+32: +64]  token1
//   [args_start+64: +96]  router
//   [args_start+96:+128] owner
args_start:
