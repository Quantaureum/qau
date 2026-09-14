// Quantaureum Node source, version 1.0.0.
// QVM QSwapRouter contract (QASM) — R122 step 4
// v1 minimal single-pool router: the user entry point, wrapping the pair's mint/burn/swap
//
// ============ Storage ============
//   slot 0:  pair   (pair address)
//   slot 1:  wqau   (wQAU wrapper contract)
//   slot 2:  owner  (emergency-switch holder = feeToSetter)
//   slot 3:  paused (0=running, 1=paused)
//
// ============ Constructor ============
// The deploy script ABI-encodes and appends to the initCode tail:
//   [args_start+0 : +32]  pair
//   [args_start+32: +64]  wqau
//   [args_start+64: +96]  owner
// CODECOPY'd to mem[0x100] for reading.
//
// ============ ABI ============
//   addLiquidity(uint256 tokenAmt) payable 0x51c6590a
//     native QAU value = CALLVALUE; the user's token must approve(Router) first
//     flow: wqau.deposit{value}(pair) -> token.transferFrom(user,pair)
//           -> pair.mint(user) -> LP goes straight to the user
//     (simplified: pair.mint mints LP pro rata to pair balances; LP to = CALLER)
//   removeLiquidity(uint256 lp) 0x9c8f9f23
//     the user first does pair.approve(Router, lp)
//     flow: pairLP.transferFrom(user,router,lp) -> pair.burn(user)
//   swapExactQauForToken(uint256 minOut) payable 0x57924ccd
//     flow: wqau.deposit{value}(router) -> wqau.transfer(pair)
//           -> compute out -> pair.swap(direction, out, user) -> assert received >= minOut
//   swapTokenForQau(uint256 tokenIn, uint256 minQauOut) 0x6de9ca14
//     the user first does token.approve(Router, tokenIn)
//     flow: token.transferFrom(user,pair,tokenIn) -> compute out
//           -> pair.swap(out, 0, router) -> wqau.withdraw(out) sends native to user
//           -> assert the user's QAU balance delta >= minQauOut
//   pair() 0xa8aa1b31 / wqau() 0x0c976bc6 / paused() 0x5c975abb
//   pause() 0x8456cb59 / unpause() 0x3f4ba83a   (owner only)
//   getAmountOut(uint256,uint256,uint256) 0x054d50d4  pure view
//     out = amountIn*997*reserveOut / (reserveIn*1000 + amountIn*997)
//
// ============ Direction detection ============
//   pair.token0() == wqau ? "QAU is token0" : "QAU is token1"
//   swapExactQauForToken: qauIn → tokenOut:
//     pair.swap(qauIsToken0 ? (0, out, to) : (out, 0, to))
//   computed after storage loads; cached in mem, recomputed every call (stateless)
//
// ============ Memory layout (32B-aligned, no overlap!) ============
//   0x80:  arg1 / to
//   0xa0:  arg2 / minOut
//   0xc0:  scratch (general temp)
//   0xe0:  reserves r0 (getReserves return)
//   0x100: reserves r1
//   0x120: token0 (direction detection)
//   0x140: amountOut / liq / qauNeeded
//   0x160: scratch2 / r_qau / toPull
//   0x2a0: r_token (addLiquidity ratio computation)
//   0x2c0: toPull (addLiquidity actual token pull)
//   0x2e0: refund (addLiquidity native refund)
//   ---- helper comm area (same convention as the pair) ----
//   0x180: call target address
//   0x1a0: call1 selector
//   0x1c0: call1 arg / transfer to
//   0x1e0: transfer wad
//   0x200: calldata staging (4B sel + 32B arg1 [+32B arg2])
//   0x240: retdata (32B)
//   0x260+: second retdata area
//
// ============ QVM semantics cheat sheet (verified) ============
//   LT/GT/SUB/DIV: a=top op b=second
//   MSTORE/MLOAD/SLOAD: offset/key=top; SSTORE: key=top, value=second
//   KECCAK256: offset=top, size=second
//   CALL: push order gas,addr,value,inOff,inSize,retOff,retSize (retSize on top)
//         pushes 1 on success, 0 on failure; retdata copied to mem[retOff..]
//   CALLDATALOAD(offset) fetches a word; RETURN: offset=top, size=second
//   push order = reverse pop order: first pushed pops last (bottom), last pushed pops first (top)
//   JUMPI: dest=top, cond=second; per-frame fresh memory; REVERT rolls back storage

.INIT
    // ---- copy args: 96 bytes to mem[0x100] ----
    PUSH1 0x60               // size = 96
    PUSH2 @args_start        // offset
    PUSH2 0x0100              // destOffset = 0x100
    CODECOPY

    // pair = low 20 bytes of mem[0x100] -> storage[0]
    PUSH2 0x0100
    MLOAD
    PUSH32 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
    AND
    PUSH1 0x00
    SSTORE

    // wqau = mem[0x120] -> storage[1]
    PUSH2 0x0120
    MLOAD
    PUSH32 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
    AND
    PUSH1 0x01
    SSTORE

    // owner = mem[0x140] -> storage[2]
    PUSH2 0x0140
    MLOAD
    PUSH32 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
    AND
    PUSH1 0x02
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
    PUSH4 0x51c6590a
    EQ
    JUMPI @fn_add_liquidity

    DUP1
    PUSH4 0x9c8f9f23
    EQ
    JUMPI @fn_remove_liquidity

    DUP1
    PUSH4 0x57924ccd
    EQ
    JUMPI @fn_swap_qau_for_token

    DUP1
    PUSH4 0x6de9ca14
    EQ
    JUMPI @fn_swap_token_for_qau

    DUP1
    PUSH4 0xa8aa1b31
    EQ
    JUMPI @fn_pair

    DUP1
    PUSH4 0x0c976bc6
    EQ
    JUMPI @fn_wqau

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
    PUSH4 0x054d50d4
    EQ
    JUMPI @fn_get_amount_out

    PUSH1 0x00
    PUSH1 0x00
    REVERT

// ============================================================
// view functions
// ============================================================

// ---- pair() ----
fn_pair:
    JUMPDEST
    PUSH1 0x00
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- wqau() ----
fn_wqau:
    JUMPDEST
    PUSH1 0x01
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- paused() ----
fn_paused:
    JUMPDEST
    PUSH1 0x03
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- pause() owner only ----
fn_pause:
    JUMPDEST
    CALLER
    PUSH1 0x02
    SLOAD
    EQ
    JUMPI @pause_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
pause_ok:
    JUMPDEST
    PUSH1 0x01
    PUSH1 0x03
    SSTORE
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- unpause() owner only ----
fn_unpause:
    JUMPDEST
    CALLER
    PUSH1 0x02
    SLOAD
    EQ
    JUMPI @unpause_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
unpause_ok:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x03
    SSTORE
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- getAmountOut(amountIn, reserveIn, reserveOut) pure view ----
//   calldata: [4 sel][32 amountIn][32 reserveIn][32 reserveOut]
//   out = amountIn*997*reserveOut / (reserveIn*1000 + amountIn*997)
fn_get_amount_out:
    JUMPDEST
    // mem[0x80]=amountIn, mem[0xa0]=reserveIn, mem[0xc0]=reserveOut
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
    // amountIn > 0 ?
    PUSH1 0x80
    MLOAD
    ISZERO
    ISZERO
    JUMPI @gao_amt_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
gao_amt_ok:
    JUMPDEST
    // reserveIn > 0 ?
    PUSH1 0xa0
    MLOAD
    ISZERO
    ISZERO
    JUMPI @gao_rin_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
gao_rin_ok:
    JUMPDEST
    // reserveOut > 0 ?
    PUSH1 0xc0
    MLOAD
    ISZERO
    ISZERO
    JUMPI @gao_rout_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
gao_rout_ok:
    JUMPDEST
    // numerator = amountIn*997*reserveOut -> mem[0xe0]
    PUSH1 0x80
    MLOAD
    PUSH2 0x03e5              // 997
    MUL
    PUSH1 0xc0
    MLOAD
    MUL
    PUSH1 0xe0
    MSTORE
    // denominator = reserveIn*1000 + amountIn*997 -> mem[0x100]
    PUSH1 0xa0
    MLOAD
    PUSH2 0x03e8              // 1000
    MUL
    PUSH1 0x80
    MLOAD
    PUSH2 0x03e5
    MUL
    ADD
    PUSH2 0x100
    MSTORE
    // out = numerator / denominator  (DIV: a=top. Push denominator first, then numerator)
    PUSH2 0x100
    MLOAD
    PUSH1 0xe0
    MLOAD
    DIV                      // stack: [num/den]
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// shared helpers: call1 (single-arg call, result left on stack top) / transfer
// comm area: target@0x180, sel@0x1a0, arg/to@0x1c0, wad@0x1e0,
//         calldata@0x200, retbuf@0x240
// ============================================================

// helper_call1: CALL target.sel(arg) -> result word left on stack top, return address below
// layout as in the pair: push the return address first, then JUMP in
helper_call1:
    JUMPDEST
    // mem[0x200] = sel << 224
    PUSH2 0x1a0
    MLOAD
    PUSH1 0xe0
    SHL
    PUSH2 0x200
    MSTORE
    // mem[0x204] = arg
    PUSH2 0x1c0
    MLOAD
    PUSH2 0x204
    MSTORE
    // CALL gas,addr,value,inOff,inSize,retOff,retSize
    PUSH4 0x07a120
    PUSH2 0x180
    MLOAD
    PUSH1 0x00
    PUSH2 0x200
    PUSH1 0x24
    PUSH2 0x240
    PUSH1 0x20
    CALL
    JUMPI @hc1_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
hc1_ok:
    JUMPDEST
    PUSH2 0x240
    MLOAD               // stack: [retaddr, ret]
    SWAP1               // [ret, retaddr]
    JUMP                // jump back to the caller, ret stays on top

// helper_call1_big: like helper_call1 but with gas 500000 (compound calls like mint/burn/swap)
helper_call1_big:
    JUMPDEST
    PUSH2 0x1a0
    MLOAD
    PUSH1 0xe0
    SHL
    PUSH2 0x200
    MSTORE
    PUSH2 0x1c0
    MLOAD
    PUSH2 0x204
    MSTORE
    PUSH4 0x07a120          // gas 500000
    PUSH2 0x180
    MLOAD
    PUSH1 0x00
    PUSH2 0x200
    PUSH1 0x24
    PUSH2 0x240
    PUSH1 0x20
    CALL
    JUMPI @hc1b_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
hc1b_ok:
    JUMPDEST
    PUSH2 0x240
    MLOAD
    SWAP1
    JUMP

// helper_transfer: token.transfer(to, wad)
//   token@0x180, to@0x1c0, wad@0x1e0
helper_transfer:
    JUMPDEST
    // mem[0x200] = transfer sel << 224
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
    // mem[0x224] = wad
    PUSH2 0x1e0
    MLOAD
    PUSH2 0x224
    MSTORE
    // CALL
    PUSH4 0x07a120
    PUSH2 0x180
    MLOAD
    PUSH1 0x00
    PUSH2 0x200
    PUSH1 0x44
    PUSH2 0x240
    PUSH1 0x20
    CALL
    JUMPI @ht_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
ht_ok:
    JUMPDEST
    JUMP

// helper_transfer_from: token.transferFrom(from, to, wad)
//   token@0x180, from@0x1c0, to@0x1e0? — no, that collides with the wad area.
//   v1 layout: token@0x180, from@0x1c0, to@0x260, wad@0x1e0
//   calldata: sel + from-word(0x204) + to-word(0x224) + wad-word(0x244)
//   CALL inOff=0x200 inSize=0x64 (100)
helper_transfer_from:
    JUMPDEST
    PUSH4 0x23b872dd
    PUSH1 0xe0
    SHL
    PUSH2 0x200
    MSTORE
    // from -> 0x204
    PUSH2 0x1c0
    MLOAD
    PUSH2 0x204
    MSTORE
    // to -> 0x224 (read 0x260 first! writing wad at 0x244 would clobber 0x260..0x264)
    PUSH2 0x260
    MLOAD
    PUSH2 0x224
    MSTORE
    // wad -> 0x244 (third argument)
    PUSH2 0x1e0
    MLOAD
    PUSH2 0x244
    MSTORE
    // CALL: inOff=0x200, inSize=0x64
    PUSH4 0x07a120
    PUSH2 0x180
    MLOAD
    PUSH1 0x00
    PUSH2 0x200
    PUSH1 0x64
    PUSH2 0x280
    PUSH1 0x20
    CALL
    JUMPI @htf_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
htf_ok:
    JUMPDEST
    JUMP

// helper_call0_value: value-carrying call to wqau.deposit(value) — no args, passes CALLVALUE
//   target@0x180, sel@0x1a0, value@0x1e0
helper_deposit:
    JUMPDEST
    // calldata carries only the selector: mem[0x200] = sel<<224
    PUSH2 0x1a0
    MLOAD
    PUSH1 0xe0
    SHL
    PUSH2 0x200
    MSTORE
    // CALL value comes from mem[0x1e0]
    PUSH4 0x07a120          // gas 500000
    PUSH2 0x180
    MLOAD
    PUSH2 0x1e0
    MLOAD               // value
    PUSH2 0x200
    PUSH1 0x04          // inSize 4 (selector only)
    PUSH2 0x240
    PUSH1 0x20
    CALL
    JUMPI @hd_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
hd_ok:
    JUMPDEST
    JUMP

// helper_call2: two-arg call (reserves/swap)
//   token@0x180, sel@0x1a0, arg1@0x1c0, arg2@0x1e0
//   calldata: sel(0x200) + arg1(0x204) + arg2(0x224); inSize 0x44
//   result word (if retSize 32) @0x240; swap expects no return body
helper_call2:
    JUMPDEST
    PUSH2 0x1a0
    MLOAD
    PUSH1 0xe0
    SHL
    PUSH2 0x200
    MSTORE
    PUSH2 0x1c0
    MLOAD
    PUSH2 0x204
    MSTORE
    PUSH2 0x1e0
    MLOAD
    PUSH2 0x224
    MSTORE
    PUSH4 0x07a120
    PUSH2 0x180
    MLOAD
    PUSH1 0x00
    PUSH2 0x200
    PUSH1 0x44
    PUSH2 0x240
    PUSH1 0x20
    CALL
    JUMPI @hc2_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
hc2_ok:
    JUMPDEST
    PUSH2 0x240
    MLOAD
    SWAP1
    JUMP

// helper_call3: three-arg call (pair.swap: amount0Out, amount1Out, to)
//   token@0x180, sel@0x1a0, a1@0x1c0, a2@0x1e0, a3@0x260
//   calldata: sel(0x200)+a1(0x204)+a2(0x224)+a3(0x244); inSize 0x64
helper_call3:
    JUMPDEST
    PUSH2 0x1a0
    MLOAD
    PUSH1 0xe0
    SHL
    PUSH2 0x200
    MSTORE
    PUSH2 0x1c0
    MLOAD
    PUSH2 0x204
    MSTORE
    PUSH2 0x1e0
    MLOAD
    PUSH2 0x224
    MSTORE
    PUSH2 0x260
    MLOAD
    PUSH2 0x244
    MSTORE
    PUSH4 0x07a120
    PUSH2 0x180
    MLOAD
    PUSH1 0x00
    PUSH2 0x200
    PUSH1 0x64
    PUSH2 0x280
    PUSH1 0x20
    CALL
    JUMPI @hc3_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
hc3_ok:
    JUMPDEST
    PUSH2 0x280
    MLOAD
    SWAP1
    JUMP

// helper_send_native: send native QAU to an address (CALL value, empty input)
//   to@0x1c0, value@0x1e0
helper_send_native:
    JUMPDEST
    PUSH4 0x0007a120            // gas 500000 (23000 is not enough for QVM CALL intrinsic cost)
    PUSH2 0x1c0
    MLOAD                     // addr
    PUSH2 0x1e0
    MLOAD                     // value
    PUSH1 0x00
    PUSH1 0x00
    PUSH1 0x00
    PUSH1 0x00
    CALL
    JUMPI @hsn_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
hsn_ok:
    JUMPDEST
    JUMP

// ============================================================
// addLiquidity(uint256 tokenAmt) payable
//   CALLVALUE = native QAU amount; tokenAmt = ERC20 token amount
//   the user must first approve the Router for the token
//   flow:
//     1. gates: not paused; tokenAmt>0 and CALLVALUE>0
//     2. token.transferFrom(user, pair, tokenAmt)
//        token address = the non-wqau one in the pair (direction detection)
//     3. wqau.deposit{CALLVALUE}()  (wQAU minted to the Router)
//     4. wqau.transfer(pair, CALLVALUE)
//     5. pair.mint(user)  — LP goes straight to the user
// ============================================================
fn_add_liquidity:
    JUMPDEST
    // paused==0?
    PUSH1 0x03
    SLOAD
    ISZERO
    JUMPI @add_gate1
    PUSH1 0x00
    PUSH1 0x00
    REVERT
add_gate1:
    JUMPDEST
    // mem[0x80] = tokenAmt
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    // tokenAmt > 0 ?
    PUSH1 0x80
    MLOAD
    ISZERO
    ISZERO
    JUMPI @add_gate2
    PUSH1 0x00
    PUSH1 0x00
    REVERT
add_gate2:
    JUMPDEST
    // CALLVALUE > 0 ?
    CALLVALUE
    ISZERO
    ISZERO
    JUMPI @add_gate3
    PUSH1 0x00
    PUSH1 0x00
    REVERT
add_gate3:
    JUMPDEST
    // ============================================================
    // v2 refund semantics:
    //   1. read pool reserves r0/r1 -> detect which side is QAU via token0 ordering
    //   2. first mint (r0==0 || r1==0): full tokenAmt + CALLVALUE enter the pool, no refund
    //   3. subsequent add: two-sided truncation
    //        qauNeed = tokenAmt * rQau / rToken
    //        qauNeed <= CALLVALUE -> full token, only qauNeed of QAU enters, refund CALLVALUE-qauNeed
    //        qauNeed >  CALLVALUE -> full QAU, token truncated to CV*rToken/rQau, no refund
    //   4. pull only the needed token, deposit only the needed QAU (excess native stays in the router, refunded at the end)
    //   5. mint(user) -> LP goes straight to the user
    // ============================================================
    // ---- 3.1 read reserves: pair.getReserves() -> r0@0xe0, r1@0x100 ----
    // (getReserves returns 96B; manual CALL retOff=0xe0 retSize=0x60, same as swap)
    PUSH1 0x00
    SLOAD                   // pair
    PUSH2 0x180
    MSTORE
    PUSH4 0x0902f1ac       // getReserves()
    PUSH2 0x1a0
    MSTORE
    PUSH1 0x00
    PUSH2 0x1c0
    MSTORE
    PUSH2 0x1a0
    MLOAD
    PUSH1 0xe0
    SHL
    PUSH2 0x200
    MSTORE
    PUSH4 0x07a120         // gas 500000
    PUSH2 0x180
    MLOAD
    PUSH1 0x00             // value
    PUSH2 0x200            // argsOff
    PUSH1 0x04             // argsSize
    PUSH1 0xe0             // retOff
    PUSH1 0x60             // retSize 96
    CALL
    JUMPI @add_have_res
    PUSH1 0x00
    PUSH1 0x00
    REVERT
add_have_res:
    JUMPDEST
    // mem[0xe0]=r0, mem[0x100]=r1
    // ---- 3.2 direction: token0 = pair.token0() -> mem[0x120] (needed for both first and subsequent adds) ----
    PUSH1 0x00
    SLOAD                   // pair
    PUSH2 0x180
    MSTORE
    PUSH4 0x0dfe1681       // token0()
    PUSH2 0x1a0
    MSTORE
    PUSH1 0x00
    PUSH2 0x1c0
    MSTORE
    PUSH2 @add_have_t0
    JUMP @helper_call1
add_have_t0:
    JUMPDEST
    // stack top = token0 -> mem[0x120]
    PUSH2 0x120
    MSTORE
    // ---- 3.3 first-mint check: r0==0 || r1==0 -> add_first ----
    PUSH1 0xe0
    MLOAD
    ISZERO
    JUMPI @add_first
    PUSH2 0x100
    MLOAD
    ISZERO
    JUMPI @add_first
    // r_qau@0x160, r_token@0x2a0: token0==wqau ? (r0,r1) : (r1,r0)
    PUSH1 0x01
    SLOAD                   // wqau
    PUSH2 0x120
    MLOAD                   // token0
    EQ
    JUMPI @add_qau_t0
    // token0 != wqau → r_qau=r1, r_token=r0
    PUSH2 0x100
    MLOAD
    PUSH2 0x160
    MSTORE
    PUSH1 0xe0
    MLOAD
    PUSH2 0x2a0
    MSTORE
    JUMP @add_have_dir
add_qau_t0:
    JUMPDEST
    // token0 == wqau → r_qau=r0, r_token=r1
    PUSH1 0xe0
    MLOAD
    PUSH2 0x160
    MSTORE
    PUSH2 0x100
    MLOAD
    PUSH2 0x2a0
    MSTORE
add_have_dir:
    JUMPDEST
    // ---- 3.4 qauNeed = tokenAmt * r_qau / r_token → mem[0x140] ----
    // QVM arithmetic: a=top op b=second -> push the divisor first (deepest), then the numerator
    PUSH2 0x2a0
    MLOAD                   // r_token (divisor)
    PUSH1 0x80
    MLOAD                   // tokenAmt
    PUSH2 0x160
    MLOAD                   // r_qau
    MUL                     // top = tokenAmt*r_qau
    DIV                     // top = tokenAmt*r_qau/r_token
    PUSH2 0x140
    MSTORE                 // mem[0x140] = qauNeed
    // ---- 3.5 check qauNeed < CALLVALUE? ----
    // LT: a=top op b=second -> push qauNeed first (second), then CALLVALUE (top)
    //   LT = CALLVALUE < qauNeed  — inverted; we want qauNeed < CALLVALUE:
    //   push CALLVALUE first (second), then qauNeed (top) -> LT = qauNeed < CALLVALUE
    CALLVALUE               // pushed first -> second
    PUSH2 0x140
    MLOAD                   // qauNeed (pushed later -> top)
    LT                      // top = (qauNeed < CALLVALUE)
    JUMPI @add_qau_excess
    // ---- QAU-side limited: toPull = CALLVALUE*r_token/r_qau, qauUse = CALLVALUE, refund=0 ----
    PUSH2 0x160
    MLOAD                   // r_qau (divisor)
    CALLVALUE
    PUSH2 0x2a0
    MLOAD                   // r_token
    MUL                     // top = CALLVALUE*r_token
    DIV                     // top = CALLVALUE*r_token/r_qau
    PUSH2 0x2c0
    MSTORE                 // toPull
    CALLVALUE
    PUSH2 0x140
    MSTORE                 // qauUse = CALLVALUE
    PUSH1 0x00
    PUSH2 0x2e0
    MSTORE                 // refund = 0
    JUMP @add_pull_ready
add_qau_excess:
    JUMPDEST
    // ---- token-side limited: toPull = tokenAmt, qauUse = qauNeed, refund = CV-qauNeed ----
    PUSH1 0x80
    MLOAD
    PUSH2 0x2c0
    MSTORE                 // toPull = tokenAmt
    PUSH2 0x140
    MLOAD                   // qauNeed
    PUSH2 0x140
    MSTORE                 // qauUse = qauNeed
    PUSH2 0x140
    MLOAD                   // qauUse (pushed first -> second)
    CALLVALUE               // (pushed later -> top)
    SUB                     // top = CALLVALUE - qauUse
    PUSH2 0x2e0
    MSTORE                 // refund
    JUMP @add_pull_ready
add_first:
    JUMPDEST
    // ---- first mint: toPull = tokenAmt, qauUse = CALLVALUE, refund = 0 ----
    PUSH1 0x80
    MLOAD
    PUSH2 0x2c0
    MSTORE
    CALLVALUE
    PUSH2 0x140
    MSTORE
    PUSH1 0x00
    PUSH2 0x2e0
    MSTORE
add_pull_ready:
    JUMPDEST
    // ---- 3.6 zero guard: toPull>0 and qauUse>0 ----
    PUSH2 0x2c0
    MLOAD
    ISZERO
    ISZERO
    JUMPI @add_ok1
    PUSH1 0x00
    PUSH1 0x00
    REVERT
add_ok1:
    JUMPDEST
    PUSH2 0x140
    MLOAD
    ISZERO
    ISZERO
    JUMPI @add_ok2
    PUSH1 0x00
    PUSH1 0x00
    REVERT
add_ok2:
    JUMPDEST
    // ---- 3.7 token address = (token0==wqau) ? token1 : token0 -> mem[0x180] ----
    PUSH1 0x01
    SLOAD                   // wqau
    PUSH2 0x120
    MLOAD                   // token0
    EQ
    JUMPI @add_token_t1
    // token = token0 (mem[0x120] already holds it)
    PUSH2 0x120
    MLOAD
    PUSH2 0x180
    MSTORE
    JUMP @add_token_set
add_token_t1:
    JUMPDEST
    // token = pair.token1()
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0xd21220a7       // token1()
    PUSH2 0x1a0
    MSTORE
    PUSH1 0x00
    PUSH2 0x1c0
    MSTORE
    PUSH2 @add_have_t1
    JUMP @helper_call1
add_have_t1:
    JUMPDEST
    // stack top = token1 -> mem[0x180]
    PUSH2 0x180
    MSTORE
add_token_set:
    JUMPDEST
    // ---- 4. token.transferFrom(user, pair, toPull) ----
    // helper_transfer_from: token@0x180 from@0x1c0 to@0x260 wad@0x1e0
    PUSH1 0x00
    SLOAD                   // pair
    PUSH2 0x260
    MSTORE                 // to = pair
    CALLER
    PUSH2 0x1c0
    MSTORE                 // from = user
    PUSH2 0x2c0
    MLOAD
    PUSH2 0x1e0
    MSTORE                 // wad = toPull
    PUSH2 @add_pulled
    JUMP @helper_transfer_from
add_pulled:
    JUMPDEST
    // ---- 5. wqau.deposit{qauUse}() (mint only what is needed; excess native stays in the router, refunded at the end) ----
    PUSH1 0x01
    SLOAD                   // wqau
    PUSH2 0x180
    MSTORE
    PUSH4 0xd0e30db0       // deposit()
    PUSH2 0x1a0
    MSTORE
    PUSH2 0x140
    MLOAD                   // qauUse
    PUSH2 0x1e0
    MSTORE                 // value
    PUSH2 @add_deposited
    JUMP @helper_deposit
add_deposited:
    JUMPDEST
    // ---- 6. wqau.transfer(pair, qauUse) ----
    PUSH1 0x01
    SLOAD                   // wqau
    PUSH2 0x180
    MSTORE
    PUSH2 0x140
    MLOAD                   // qauUse
    PUSH2 0x1e0
    MSTORE                 // wad
    PUSH1 0x00
    SLOAD                   // pair
    PUSH2 0x1c0
    MSTORE                 // to
    PUSH2 @add_sent_qau
    JUMP @helper_transfer
add_sent_qau:
    JUMPDEST
    // ---- 7. refund > 0 ? -> refund native to CALLER ----
    PUSH2 0x2e0
    MLOAD
    ISZERO
    JUMPI @add_no_refund
    CALLER
    PUSH2 0x1c0
    MSTORE                 // refund to = CALLER
    PUSH2 0x2e0
    MLOAD
    PUSH2 0x1e0
    MSTORE                 // refund value
    PUSH2 @add_refunded
    JUMP @helper_send_native
add_refunded:
    JUMPDEST
add_no_refund:
    JUMPDEST
    // ---- 8. pair.mint(user) ----
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x6a627842       // mint(address)
    PUSH2 0x1a0
    MSTORE
    CALLER
    PUSH2 0x1c0
    MSTORE
    PUSH2 @add_minted
    JUMP @helper_call1_big
add_minted:
    JUMPDEST
    POP                     // drop mint's return value (true)
    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
fn_remove_liquidity:
    JUMPDEST
    PUSH1 0x03
    SLOAD
    ISZERO
    JUMPI @rem_gate1
    PUSH1 0x00
    PUSH1 0x00
    REVERT
rem_gate1:
    JUMPDEST
    // mem[0x80] = lp
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    // lp > 0 ?
    PUSH1 0x80
    MLOAD
    ISZERO
    ISZERO
    JUMPI @rem_gate2
    PUSH1 0x00
    PUSH1 0x00
    REVERT
rem_gate2:
    JUMPDEST
    // ---- pair LP transferFrom(user, router, lp) ----
    // target = pair; from=user@0x1c0; to=router(=ADDRESS)@0x260; wad=lp@0x1e0
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    CALLER
    PUSH2 0x1c0
    MSTORE
    ADDRESS
    PUSH2 0x260
    MSTORE
    PUSH1 0x80
    MLOAD
    PUSH2 0x1e0
    MSTORE
    PUSH2 @rem_pulled
    JUMP @helper_transfer_from
rem_pulled:
    JUMPDEST
    // ---- pair.burn(user) ----
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x89afcb44       // burn(address)
    PUSH2 0x1a0
    MSTORE
    CALLER
    PUSH2 0x1c0
    MSTORE
    PUSH2 @rem_burned
    JUMP @helper_call1
rem_burned:
    JUMPDEST
    POP
    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// swapExactQauForToken(uint256 minOut) payable
//   CALLVALUE = native QAU to swap in; minOut = minimum token amount out
//   flow:
//     1. gates: not paused; CALLVALUE>0
//     2. wqau.deposit{CALLVALUE}() (wQAU to the Router)
//     3. compute out = getAmountOut(CALLVALUE, rQau, rToken)
//        reserves = pair.getReserves() (3 words)
//     4. wqau.transfer(pair, CALLVALUE)
//     5. pair.swap(qauIsToken0 ? (0,out,user) : (out,0,user))
//     6. assert the user's token balance delta? v1: assert out >= minOut (formula value)
//        (arrival checks need before/after balances — instead: pair.swap's internal k check
//         already guarantees exact output; minOut checks the formula out)
// ============================================================
fn_swap_qau_for_token:
    JUMPDEST
    PUSH1 0x03
    SLOAD
    ISZERO
    JUMPI @sqf_gate1
    PUSH1 0x00
    PUSH1 0x00
    REVERT
sqf_gate1:
    JUMPDEST
    // mem[0xa0] = minOut
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0xa0
    MSTORE
    // CALLVALUE > 0 ?
    CALLVALUE
    ISZERO
    ISZERO
    JUMPI @sqf_gate2
    PUSH1 0x00
    PUSH1 0x00
    REVERT
sqf_gate2:
    JUMPDEST
    // ---- read reserves: pair.getReserves() -> r0@0xe0, r1@0x100 ----
    // getReserves returns 96B; use CALL retOff=0xe0 retSize=0x60
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x0902f1ac       // getReserves()
    PUSH2 0x1a0
    MSTORE
    PUSH1 0x00
    PUSH2 0x1c0
    MSTORE
    // manual CALL (needs retSize 0x60 — helper_call1 only takes 32B)
    // first write sel<<224 to 0x200 (staging)
    PUSH2 0x1a0
    MLOAD
    PUSH1 0xe0
    SHL
    PUSH2 0x200
    MSTORE
    PUSH4 0x07a120
    PUSH2 0x180
    MLOAD
    PUSH1 0x00
    PUSH2 0x200
    PUSH1 0x04
    PUSH1 0xe0              // retOff = 0xe0 (writes straight into the args area!)
    PUSH1 0x60              // retSize 96
    CALL
    JUMPI @sqf_have_res
    PUSH1 0x00
    PUSH1 0x00
    REVERT
sqf_have_res:
    JUMPDEST
    // mem[0xe0]=r0, mem[0x100]=r1
    // ---- direction detection ----
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x0dfe1681
    PUSH2 0x1a0
    MSTORE
    PUSH1 0x00
    PUSH2 0x1c0
    MSTORE
    PUSH2 @sqf_have_t0
    JUMP @helper_call1
sqf_have_t0:
    JUMPDEST
    PUSH2 0x120
    MSTORE                 // token0
    // qauIsToken0 = (token0 == wqau)
    PUSH1 0x01
    SLOAD
    PUSH2 0x120
    MLOAD
    EQ
    JUMPI @sqf_qau_is_t0
    JUMP @sqf_qau_is_t1
sqf_qau_is_t0:
    JUMPDEST
    // in-reserve = r0 (0xe0), out-reserve = r1 (0x100)
    // out = CALLVALUE*997*r1 / (r0*1000 + CALLVALUE*997)
    // compute the numerator first -> 0x140; denominator -> 0x160
    CALLVALUE
    PUSH2 0x03e5
    MUL
    PUSH2 0x0100
    MLOAD
    MUL
    PUSH2 0x140
    MSTORE
    PUSH1 0xe0
    MLOAD
    PUSH2 0x03e8
    MUL
    CALLVALUE
    PUSH2 0x03e5
    MUL
    ADD
    PUSH2 0x160
    MSTORE
    JUMP @sqf_calc_out
sqf_qau_is_t1:
    JUMPDEST
    // in-reserve = r1 (0x100), out-reserve = r0 (0xe0)
    CALLVALUE
    PUSH2 0x03e5
    MUL
    PUSH1 0xe0
    MLOAD
    MUL
    PUSH2 0x140
    MSTORE
    PUSH2 0x0100
    MLOAD
    PUSH2 0x03e8
    MUL
    CALLVALUE
    PUSH2 0x03e5
    MUL
    ADD
    PUSH2 0x160
    MSTORE
    JUMP @sqf_calc_out
sqf_calc_out:
    JUMPDEST
    // out = num(0x140) / den(0x160) -> 0x140 (DIV a=top: push den first, then num)
    PUSH2 0x160
    MLOAD
    PUSH2 0x140
    MLOAD
    DIV
    PUSH2 0x140
    MSTORE
    // out >= minOut? LT: a=top. Push minOut first, then out -> a=out < b=minOut
    PUSH1 0xa0
    MLOAD
    PUSH2 0x140
    MLOAD
    LT
    ISZERO              // !(out<minOut) = out>=minOut → 1
    JUMPI @sqf_min_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
sqf_min_ok:
    JUMPDEST
    // ---- wqau.deposit{CALLVALUE}() ----
    PUSH1 0x01
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0xd0e30db0
    PUSH2 0x1a0
    MSTORE
    CALLVALUE
    PUSH2 0x1e0
    MSTORE
    PUSH2 @sqf_deposited
    JUMP @helper_deposit
sqf_deposited:
    JUMPDEST
    // ---- wqau.transfer(pair, CALLVALUE) ----
    PUSH1 0x00
    SLOAD
    PUSH2 0x1c0
    MSTORE
    CALLVALUE
    PUSH2 0x1e0
    MSTORE
    PUSH2 @sqf_sent
    JUMP @helper_transfer
sqf_sent:
    JUMPDEST
    // ---- pair.swap(a0Out, a1Out, user) ----
    // detect direction again (0x120 vs token0)
    PUSH1 0x01
    SLOAD
    PUSH2 0x120
    MLOAD
    EQ
    JUMPI @sqf_swap_t0
    // QAU is token1 -> swap(out, 0, user): a1=out@0x1c0, a2=0@0x1e0, a3=user@0x260
    PUSH2 0x140
    MLOAD
    PUSH2 0x1c0
    MSTORE
    PUSH1 0x00
    PUSH2 0x1e0
    MSTORE
    CALLER
    PUSH2 0x260
    MSTORE
    JUMP @sqf_do_swap
sqf_swap_t0:
    JUMPDEST
    // QAU is token0 -> swap(0, out, user)
    PUSH1 0x00
    PUSH2 0x1c0
    MSTORE
    PUSH2 0x140
    MLOAD
    PUSH2 0x1e0
    MSTORE
    CALLER
    PUSH2 0x260
    MSTORE
sqf_do_swap:
    JUMPDEST
    // target=pair, sel=swap
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x6d9a640a
    PUSH2 0x1a0
    MSTORE
    PUSH2 @sqf_swapped
    JUMP @helper_call3
sqf_swapped:
    JUMPDEST
    POP
    // return out (so the frontend sees the actual amount out)
    PUSH2 0x140
    MLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// swapTokenForQau(uint256 tokenIn, uint256 minQauOut)
//   the user first does token.approve(Router, tokenIn)
//   flow:
//     1. token.transferFrom(user, pair, tokenIn)
//     2. read reserves; detect direction
//     3. out = getAmountOut(tokenIn, rToken, rQau)
//     4. assert out >= minQauOut
//     5. pair.swap(outQau per direction, to=Router)
//     6. wqau.withdraw(out) — native QAU to the user
// ============================================================
fn_swap_token_for_qau:
    JUMPDEST
    PUSH1 0x03
    SLOAD
    ISZERO
    JUMPI @stf_gate1
    PUSH1 0x00
    PUSH1 0x00
    REVERT
stf_gate1:
    JUMPDEST
    // mem[0x80]=tokenIn, mem[0xa0]=minQauOut
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    PUSH1 0x24
    CALLDATALOAD
    PUSH1 0xa0
    MSTORE
    PUSH1 0x80
    MLOAD
    ISZERO
    ISZERO
    JUMPI @stf_gate2
    PUSH1 0x00
    PUSH1 0x00
    REVERT
stf_gate2:
    JUMPDEST
    // ---- direction detection (same as add) ----
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x0dfe1681
    PUSH2 0x1a0
    MSTORE
    PUSH1 0x00
    PUSH2 0x1c0
    MSTORE
    PUSH2 @stf_have_t0
    JUMP @helper_call1
stf_have_t0:
    JUMPDEST
    PUSH2 0x120
    MSTORE
    PUSH1 0x01
    SLOAD
    PUSH2 0x120
    MLOAD
    EQ
    JUMPI @stf_token_is_t1
    // token = token0
    PUSH2 0x120
    MLOAD
    PUSH2 0x180
    MSTORE
    JUMP @stf_token_set
stf_token_is_t1:
    JUMPDEST
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0xd21220a7
    PUSH2 0x1a0
    MSTORE
    PUSH1 0x00
    PUSH2 0x1c0
    MSTORE
    PUSH2 @stf_have_t1
    JUMP @helper_call1
stf_have_t1:
    JUMPDEST
    PUSH2 0x180
    MSTORE
stf_token_set:
    JUMPDEST
    // ---- token.transferFrom(user, pair, tokenIn) ----
    PUSH1 0x00
    SLOAD
    PUSH2 0x260
    MSTORE
    CALLER
    PUSH2 0x1c0
    MSTORE
    PUSH1 0x80
    MLOAD
    PUSH2 0x1e0
    MSTORE
    PUSH2 @stf_pulled
    JUMP @helper_transfer_from
stf_pulled:
    JUMPDEST
    // ---- read reserves ----
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x0902f1ac
    PUSH2 0x1a0
    MSTORE
    PUSH1 0x00
    PUSH2 0x1c0
    MSTORE
    // manual CALL (reserves are 3 words; retOff 0x2c0 avoids token0@0x120)
    // first write sel<<224 to 0x200 (staging)
    PUSH2 0x1a0
    MLOAD
    PUSH1 0xe0
    SHL
    PUSH2 0x200
    MSTORE
    PUSH4 0x07a120
    PUSH2 0x180
    MLOAD
    PUSH1 0x00
    PUSH2 0x200
    PUSH1 0x04
    PUSH2 0x02c0             // retOff = 0x2c0 (r0@0x2c0, r1@0x2e0, ts@0x300)
    PUSH1 0x60
    CALL
    JUMPI @stf_have_res
    PUSH1 0x00
    PUSH1 0x00
    REVERT
stf_have_res:
    JUMPDEST
    // direction: token0==wqau?
    PUSH1 0x01
    SLOAD
    PUSH2 0x120
    MLOAD
    EQ
    JUMPI @stf_token_is_t0_res
    // token is token0 -> in=r0(0x2c0), out=r1(0x2e0)
    PUSH1 0x80
    MLOAD
    PUSH2 0x03e5
    MUL
    PUSH2 0x02e0
    MLOAD
    MUL
    PUSH2 0x140
    MSTORE
    PUSH2 0x02c0
    MLOAD
    PUSH2 0x03e8
    MUL
    PUSH1 0x80
    MLOAD
    PUSH2 0x03e5
    MUL
    ADD
    PUSH2 0x160
    MSTORE
    JUMP @stf_calc
stf_token_is_t0_res:
    JUMPDEST
    // token is token1 -> in=r1(0x2e0), out=r0(0x2c0)
    PUSH1 0x80
    MLOAD
    PUSH2 0x03e5
    MUL
    PUSH2 0x02c0
    MLOAD
    MUL
    PUSH2 0x140
    MSTORE
    PUSH2 0x02e0
    MLOAD
    PUSH2 0x03e8
    MUL
    PUSH1 0x80
    MLOAD
    PUSH2 0x03e5
    MUL
    ADD
    PUSH2 0x160
    MSTORE
    JUMP @stf_calc
stf_calc:
    JUMPDEST
    // out = num/den
    PUSH2 0x160
    MLOAD
    PUSH2 0x140
    MLOAD
    DIV
    PUSH2 0x140
    MSTORE
    // out >= minQauOut?
    PUSH1 0xa0
    MLOAD
    PUSH2 0x140
    MLOAD
    LT
    ISZERO
    JUMPI @stf_min_ok
    PUSH1 0x00
    PUSH1 0x00
    REVERT
stf_min_ok:
    JUMPDEST
    // ---- pair.swap: QAU output to the Router ----
    PUSH1 0x01
    SLOAD
    PUSH2 0x120
    MLOAD
    EQ
    JUMPI @stf_swap_t0
    // QAU is token1 -> the output goes in amount1Out = out
    PUSH1 0x00
    PUSH2 0x1c0
    MSTORE
    PUSH2 0x140
    MLOAD
    PUSH2 0x1e0
    MSTORE
    ADDRESS
    PUSH2 0x260
    MSTORE
    JUMP @stf_do_swap
stf_swap_t0:
    JUMPDEST
    // QAU is token0 -> the output goes in amount0Out = out
    PUSH2 0x140
    MLOAD
    PUSH2 0x1c0
    MSTORE
    PUSH1 0x00
    PUSH2 0x1e0
    MSTORE
    ADDRESS
    PUSH2 0x260
    MSTORE
stf_do_swap:
    JUMPDEST
    PUSH1 0x00
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x6d9a640a
    PUSH2 0x1a0
    MSTORE
    PUSH2 @stf_swapped
    JUMP @helper_call3
stf_swapped:
    JUMPDEST
    POP
    // ---- wqau.withdraw(out): wQAU -> native, to the Router ----
    PUSH1 0x01
    SLOAD
    PUSH2 0x180
    MSTORE
    PUSH4 0x2e1a7d4d       // withdraw(uint256)
    PUSH2 0x1a0
    MSTORE
    PUSH2 0x140
    MLOAD
    PUSH2 0x1c0
    MSTORE
    PUSH2 @stf_withdrew
    JUMP @helper_call1
stf_withdrew:
    JUMPDEST
    POP
    // ---- native QAU -> user ----
    CALLER
    PUSH2 0x1c0
    MSTORE
    PUSH2 0x140
    MLOAD
    PUSH2 0x1e0
    MSTORE
    PUSH2 @stf_sent_native
    JUMP @helper_send_native
stf_sent_native:
    JUMPDEST
    // return out
    PUSH2 0x140
    MLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

code_end:

// constructor args (ABI-encoded by the deploy script, appended here):
//   [args_start+0 : +32]  pair
//   [args_start+32: +64]  wqau
//   [args_start+64: +96]  owner
args_start:
