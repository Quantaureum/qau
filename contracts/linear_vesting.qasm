// Quantaureum Node source, version 1.0.0.
// QVM LinearVesting contract (QASM)
// Quantaureum native quantum blockchain — not EVM-compatible
//
// QVM opcode stack semantics (different from EVM!):
//   SUB: pops a(top), b(second), returns a - b
//   LT:  pops a(top), b(second), returns a < b ? 1 : 0
//   GT:  pops a(top), b(second), returns a > b ? 1 : 0
//   MUL: pops a(top), b(second), returns a * b
//   DIV: pops a(top), b(second), returns a / b
//   MSTORE: pops offset(top), value(second), writes memory[offset] = value
//   SSTORE: pops key(top), value(second), writes storage[key] = value
//
// Storage:
//   slot 0: owner
//   slot 1: beneficiary
//   slot 2: start (absolute timestamp)
//   slot 3: cliffEnd (absolute timestamp)
//   slot 4: vestingEnd (absolute timestamp)
//   slot 5: totalAmount
//   slot 6: released
//
// Constructor args:
//   [0:32]   beneficiary (left-padded to 32 bytes)
//   [32:64]  start (uint256)
//   [64:96]  cliff (relative seconds)
//   [96:128] duration (relative seconds)
//   [128:160] totalAmount (uint256)
//
// Function selectors:
//   0x8da5cb5b = owner()
//   0x38af3eed = beneficiary()
//   0x78e97925 = start()
//   0x3161e6c0 = cliff()
//   0x1a39d8ef = duration()
//   0x5b940081 = totalAmount()
//   0x96132521 = released()
//   0x86d1a69f = releasable()
//   0x15e4167e = release()

.INIT
    // store owner = CALLER
    CALLER
    PUSH1 0x00
    SSTORE

    // use CODECOPY to copy the constructor args from the code tail to memory 0x80
    PUSH1 0xa0           // size = 160
    PUSH2 @args_start    // offset
    PUSH1 0x80           // destOffset = 0x80
    CODECOPY

    // store beneficiary = low 20 bytes of mem[0x80:0xa0]
    PUSH1 0x80
    MLOAD
    PUSH32 0x000000000000000000000000ffffffffffffffffffffffffffffffffffffffff
    AND
    PUSH1 0x01
    SSTORE

    // store start = mem[0xa0:0xc0]
    PUSH1 0xa0
    MLOAD
    DUP1
    PUSH1 0x02
    SSTORE

    // store cliffEnd = start + mem[0xc0:0xe0] (absolute timestamp)
    PUSH1 0xc0
    MLOAD
    ADD
    PUSH1 0x03
    SSTORE

    // store vestingEnd = start + mem[0xe0:0x100] (absolute timestamp)
    PUSH1 0x02
    SLOAD
    PUSH1 0xe0
    MLOAD
    ADD
    PUSH1 0x04
    SSTORE

    // store totalAmount = mem[0x100:0x120]
    PUSH2 0x0100
    MLOAD
    PUSH1 0x05
    SSTORE

    // return runtime code
    PUSH2 @code_end-@code_start
    PUSH2 @code_start
    PUSH1 0x00
    CODECOPY
    PUSH2 @code_end-@code_start
    PUSH1 0x00
    RETURN

.CODE
code_start:
    // function dispatcher
    CALLDATASIZE
    PUSH1 0x04
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
    PUSH4 0x8da5cb5b
    EQ
    JUMPI @fn_owner

    DUP1
    PUSH4 0x38af3eed
    EQ
    JUMPI @fn_beneficiary

    DUP1
    PUSH4 0x78e97925
    EQ
    JUMPI @fn_start

    DUP1
    PUSH4 0x3161e6c0
    EQ
    JUMPI @fn_cliff

    DUP1
    PUSH4 0x1a39d8ef
    EQ
    JUMPI @fn_duration

    DUP1
    PUSH4 0x5b940081
    EQ
    JUMPI @fn_totalAmount

    DUP1
    PUSH4 0x96132521
    EQ
    JUMPI @fn_released

    DUP1
    PUSH4 0x86d1a69f
    EQ
    JUMPI @fn_releasable

    DUP1
    PUSH4 0x15e4167e
    EQ
    JUMPI @fn_release

    POP
    STOP

    // ===== getter functions =====
    // pattern: POP(selector) -> SLOAD(slot) -> PUSH1 offset -> MSTORE -> PUSH1 size -> PUSH1 offset -> RETURN

fn_owner:
    JUMPDEST
    POP
    PUSH1 0x00
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

fn_beneficiary:
    JUMPDEST
    POP
    PUSH1 0x01
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

fn_start:
    JUMPDEST
    POP
    PUSH1 0x02
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

fn_cliff:
    JUMPDEST
    POP
    PUSH1 0x03
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

fn_duration:
    JUMPDEST
    POP
    PUSH1 0x04
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

fn_totalAmount:
    JUMPDEST
    POP
    PUSH1 0x05
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

fn_released:
    JUMPDEST
    POP
    PUSH1 0x06
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

    // ===== releasable() =====
    // returns the currently releasable amount
fn_releasable:
    JUMPDEST
    POP              // drop the selector
    TIMESTAMP        // [time]

    // if time < cliffEnd: return 0
    // LT(a=top, b=second): a < b
    // keep time on the stack; duplicate via DUP1
    DUP1             // [time, time]
    PUSH1 0x03
    SLOAD            // [time, time, cliffEnd]
    SWAP1            // [time, cliffEnd, time] <- time on top
    LT               // LT(a=time, b=cliffEnd) = time < cliffEnd
                     // stack: [time, lt_result] <- lt_result on top
    // JUMPI pops dest(top) and cond(second)
    // so we need: [..., cond=lt_result, dest]
    // current stack: [time, lt_result] -> PUSH2 dest -> [time, lt_result, dest]
    // JUMPI pops dest and lt_result; time stays on the stack OK
    JUMPI @rel_zero

    // if time > vestingEnd: fully vested
    // time is still on the stack
    DUP1             // [time, time]
    PUSH1 0x04
    SLOAD            // [time, time, vestingEnd]
    SWAP1            // [time, vestingEnd, time] <- time on top
    GT               // GT(a=time, b=vestingEnd) = time > vestingEnd
                     // stack: [time, gt_result]
    ISZERO           // [time, iszero_result]
    // same as above: JUMPI pops dest and iszero_result; time stays on the stack
    JUMPI @rel_partial

    // fully vested: releasable = totalAmount - released
    POP              // [time] -> []
    PUSH1 0x06
    SLOAD            // [released]
    PUSH1 0x05
    SLOAD            // [released, totalAmount] <- totalAmount on top
    SUB              // SUB(a=totalAmount, b=released) = totalAmount - released ✓
    JUMP @rel_return

rel_zero:
    JUMPDEST
    POP              // [time] -> []
    PUSH1 0x00       // [0]
    JUMP @rel_return

rel_partial:
    JUMPDEST
    // stack: [time]
    // vestedAmount = totalAmount * (time - start) / (vestingEnd - start)

    // Step 1: (time - start)
    // SUB(a=top, b=second): a - b; time must be on top
    PUSH1 0x02
    SLOAD            // [time, start]
    SWAP1            // [start, time] <- time on top
    SUB              // SUB(a=time, b=start) = time - start ✓
                     // stack: [time-start]

    // Step 2: totalAmount * (time - start)
    // MUL(a=top, b=second): a * b
    PUSH1 0x05
    SLOAD            // [time-start, totalAmount] <- totalAmount on top
    MUL              // MUL(a=totalAmount, b=time-start) = totalAmount*(time-start) ✓
                     // stack: [product]

    // Step 3: (vestingEnd - start)
    // SUB(a=top, b=second): a - b; vestingEnd must be on top
    PUSH1 0x02
    SLOAD            // [product, start]
    PUSH1 0x04
    SLOAD            // [product, start, vestingEnd] <- vestingEnd on top
    SUB              // SUB(a=vestingEnd, b=start) = vestingEnd - start ✓
                     // stack: [product, vestingEnd-start]

    // Step 4: product / (vestingEnd - start)
    // DIV(a=top, b=second): a / b; product must be on top
    SWAP1            // [vestingEnd-start, product] <- product on top
    DIV              // DIV(a=product, b=vestingEnd-start) = vestedAmount ✓
                     // stack: [vestedAmount]

    // Step 5: releasable = vestedAmount - released
    // SUB(a=top, b=second): a - b; vestedAmount must be on top
    PUSH1 0x06
    SLOAD            // [vestedAmount, released]
    SWAP1            // [released, vestedAmount] <- vestedAmount on top
    SUB              // SUB(a=vestedAmount, b=released) = vestedAmount - released ✓

rel_return:
    JUMPDEST
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

    // ===== release() =====
fn_release:
    JUMPDEST
    POP              // drop the selector
    TIMESTAMP        // [time]

    // if time < cliffEnd: vestedAmount = 0
    DUP1             // [time, time]
    PUSH1 0x03
    SLOAD            // [time, time, cliffEnd]
    SWAP1            // [time, cliffEnd, time]
    LT               // LT(a=time, b=cliffEnd) = time < cliffEnd
                     // stack: [time, lt_result]
    JUMPI @rel2_zero // pops dest and lt_result; time stays on the stack

    // if time > vestingEnd: vestedAmount = totalAmount
    DUP1             // [time, time]
    PUSH1 0x04
    SLOAD            // [time, time, vestingEnd]
    SWAP1            // [time, vestingEnd, time]
    GT               // GT(a=time, b=vestingEnd) = time > vestingEnd
                     // stack: [time, gt_result]
    ISZERO           // [time, iszero_result]
    JUMPI @rel2_partial  // pops dest and iszero_result; time stays on the stack

    // fully vested
    POP              // [time] -> []
    PUSH1 0x05
    SLOAD            // [totalAmount]
    JUMP @rel2_done

rel2_zero:
    JUMPDEST
    POP              // [time] -> []
    PUSH1 0x00       // [0]
    JUMP @rel2_done

rel2_partial:
    JUMPDEST
    // stack: [time]
    // vestedAmount = totalAmount * (time - start) / (vestingEnd - start)

    // (time - start)
    PUSH1 0x02
    SLOAD            // [time, start]
    SWAP1            // [start, time]
    SUB              // time - start ✓

    // * totalAmount
    PUSH1 0x05
    SLOAD            // [time-start, totalAmount]
    MUL              // totalAmount * (time-start) ✓

    // / (vestingEnd - start)
    PUSH1 0x02
    SLOAD            // [product, start]
    PUSH1 0x04
    SLOAD            // [product, start, vestingEnd]
    SUB              // vestingEnd - start ✓
    SWAP1            // [vestingEnd-start, product]
    DIV              // product / (vestingEnd-start) ✓

rel2_done:
    JUMPDEST
    // stack: [vestedAmount]
    // releasable = vestedAmount - released
    PUSH1 0x06
    SLOAD            // [vestedAmount, released]
    SWAP1            // [released, vestedAmount]
    SUB              // vestedAmount - released ✓

    // check releasable > 0
    DUP1
    ISZERO
    JUMPI @release_noop

    // ===== core transfer logic =====
    // 1. store releasable at memory 0x00
    DUP1             // [releasable, releasable]
    PUSH1 0x00       // [releasable, releasable, 0x00]
    MSTORE           // MSTORE(offset=0x00, value=releasable) ✓
                     // stack: [releasable]

    // 2. update released: newReleased = oldReleased + releasable
    // ADD(a=top, b=second): a + b
    PUSH1 0x06
    SLOAD            // [releasable, oldReleased]
    SWAP1            // [oldReleased, releasable] <- releasable on top
    ADD              // ADD(a=releasable, b=oldReleased) = releasable + oldReleased ✓
    PUSH1 0x06
    SSTORE           // SSTORE(key=6, value=newReleased) ✓
                     // stack: []

    // 3. CALL the transfer: gas, addr, value, inOff, inSize, outOff, outSize
    GAS
    PUSH1 0x01
    SLOAD              // addr = beneficiary
    PUSH1 0x00
    MLOAD              // value = releasable (read from memory)
    PUSH1 0x00         // inOffset
    PUSH1 0x00         // inSize
    PUSH1 0x00         // outOffset
    PUSH1 0x00         // outSize
    CALL

    // security fix [CRITICAL]: check the CALL return value; on failure return 0
    // previously the return value was simply POPped, without checking transfer success
    DUP1                // duplicate the CALL return value
    ISZERO              // check for 0 (failure)
    JUMPI @release_failed

    // success: drop the return value, return 1
    POP
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

release_failed:
    JUMPDEST
    POP                 // drop the return value
    REVERT              // SECURITY FIX: REVERT rolls back all state changes (including the released update)
                        // previously RETURN returned 0 without rolling back, leaving the inconsistent "ledger updated but funds not transferred" state

release_noop:
    JUMPDEST
    POP
    PUSH1 0x00
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

code_end:
args_start:
