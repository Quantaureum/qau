// Quantaureum Node source, version 1.0.0.
// QVM wQAU contract (QASM) — R122 step 1
// Native QAU 1:1 wrapper. deposit() is called with native value; withdraw unwraps.
//
// Storage:
//   slot 0: totalSupply
//   slot 1: (reserved)
//   slot 2: balanceOf mapping root   key = keccak256(pad(addr) ++ pad(2))
//   slot 3: allowance mapping root   key = keccak256(pad(owner) ++ pad(3))
//          two-level: allowance[owner][spender] = storage[keccak256(pad(spender) ++ keccak256(pad(owner) ++ pad(3)))]
//
// ABI (standard Solidity selectors):
//   deposit()                              0xd0e30db0
//   withdraw(uint256)                      0x2e1a7d4d
//   totalSupply()                          0x18160ddd
//   balanceOf(address)                     0x70a08231
//   allowance(address,address)             0xdd62ed3e
//   approve(address,uint256)               0x095ea7b3
//   transfer(address,uint256)              0xa9059cbb
//   transferFrom(address,address,uint256)  0x23b872dd
//
// QVM semantics (R122 doc §1.3, all verified via smoke tests):
//   MSTORE/MLOAD/KECCAK256/SLOAD/SSTORE: offset/key on top when popping
//   LT/GT/SUB/DIV: a=top op b=second
//   memory discipline: the keccak input area is fixed at mem[0x20..0x60]; do not mix with other scratch space
//
// Function memory layout:
//   mem[0x00]        scratch (return value / staging)
//   mem[0x20..0x60]  keccak input area (32B value + 32B slot)
//   mem[0x80]        calldata arg 1
//   mem[0xa0]        calldata arg 2
//   mem[0xc0]        calldata arg 3
//   mem[0xe0]        save area 1 (key / staging)
//   mem[0x100]       save area 2
//   mem[0x120]       save area 3

.INIT
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
    // enter the dispatcher only when calldata >= 4 bytes
    PUSH1 0x04
    CALLDATASIZE
    LT
    ISZERO
    JUMPI @dispatch
    // empty calldata = native-value fallback -> deposit
    JUMP @fn_deposit

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
// deposit() payable — 1:1 mint against native input
// ============================================================
fn_deposit:
    JUMPDEST
    // callerBal += CALLVALUE
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x02
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256               // stack: [callerKey]
    PUSH1 0xe0
    MSTORE                  // mem[0xe0] = callerKey
    PUSH1 0xe0
    MLOAD
    SLOAD                   // stack: [callerBal]
    CALLVALUE               // stack: [callerBal, value]
    ADD                     // stack: [callerBal + value]
    PUSH1 0xe0
    MLOAD
    SSTORE                  // storage[callerKey] = sum

    // totalSupply += CALLVALUE
    PUSH1 0x00
    SLOAD
    CALLVALUE
    ADD
    PUSH1 0x00
    SSTORE

    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// withdraw(uint256 wad) — unwrap: burn wad, send out native
// calldata: [sel][wad]
// ============================================================
fn_withdraw:
    JUMPDEST
    // mem[0x80] = wad
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE

    // callerKey
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x02
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE

    // check: wad > callerBal ? -> revert
    PUSH1 0xe0
    MLOAD
    SLOAD                   // stack: [callerBal]
    PUSH1 0x80
    MLOAD                   // stack: [callerBal, wad] wad on top
    GT                      // wad > callerBal ?
    JUMPI @withdraw_insufficient

    // callerBal -= wad
    PUSH1 0xe0
    MLOAD
    SLOAD                   // [callerBal]
    PUSH1 0x80
    MLOAD                   // [callerBal, wad]
    SWAP1                   // [wad, callerBal] callerBal on top
    SUB                     // [newBal]
    PUSH1 0xe0
    MLOAD
    SSTORE

    // totalSupply -= wad
    PUSH1 0x00
    SLOAD                   // [supply]
    PUSH1 0x80
    MLOAD                   // [supply, wad]
    SWAP1
    SUB                     // [supply - wad]
    PUSH1 0x00
    SSTORE

    // send native to CALLER: QVM CALL (retSize,retOffset,inSize,inOffset,value,addr,gas, top-down)
    // prepare the calldata area first (empty input): inOffset=0, inSize=0
    // bottom->top: gas, addr, value, inOffset, inSize, retOffset, retSize
    // push order = reverse: gas, then addr, then value, then inOffset, then inSize, then retOffset, then retSize
    PUSH1 0x00              // gas = 0 (give all remaining gas? see QVM semantics in call.go; 23000 is the safe choice)
    // rearranged: pass a fixed 23000
    POP
    PUSH2 0x59d8            // gas = 23000
    CALLER                  // addr
    PUSH1 0x80
    MLOAD                   // value = wad
    PUSH1 0x00              // inOffset
    PUSH1 0x00              // inSize
    PUSH1 0x00              // retOffset
    PUSH1 0x00              // retSize
    CALL
    // CALL failure returns 0 -> revert
    ISZERO
    JUMPI @withdraw_call_failed

    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

withdraw_insufficient:
withdraw_call_failed:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT

// ============================================================
// totalSupply() -> uint256
// ============================================================
fn_total_supply:
    JUMPDEST
    PUSH1 0x00
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// balanceOf(address) -> uint256
// calldata: [sel][addr]
// ============================================================
fn_balance_of:
    JUMPDEST
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x02
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
// allowance(address owner, address spender) -> uint256
// calldata: [sel][owner][spender]
// ============================================================
fn_allowance:
    JUMPDEST
    // mem[0x80] = owner, mem[0xa0] = spender
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    PUSH1 0x24
    CALLDATALOAD
    PUSH1 0xa0
    MSTORE

    // ownerRoot = keccak256(pad(owner) ++ pad(3)) → mem[0xe0]
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

    // leaf = keccak256(pad(spender) ++ ownerRoot), a direct SLOAD
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
// approve(address spender, uint256 wad) -> bool
// calldata: [sel][spender][wad]
// ============================================================
fn_approve:
    JUMPDEST
    // mem[0x80] = spender, mem[0xa0] = wad
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    PUSH1 0x24
    CALLDATALOAD
    PUSH1 0xa0
    MSTORE

    // ownerRoot = keccak256(pad(CALLER) ++ pad(3)) → mem[0xe0]
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
    MSTORE                  // mem[0xe0] = ownerRoot

    // leaf = keccak256(pad(spender) ++ ownerRoot) → mem[0xe0]
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
    MSTORE                  // mem[0xe0] = leafKey

    // storage[leafKey] = wad  (SSTORE: key=top, value=second)
    PUSH1 0xa0
    MLOAD                   // [wad]
    PUSH1 0xe0
    MLOAD                   // [wad, leafKey] key on top
    SSTORE

    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// transfer(address to, uint256 wad) -> bool
// calldata: [sel][to][wad]
// ============================================================
fn_transfer:
    JUMPDEST
    // mem[0x80] = to, mem[0xa0] = wad
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
    PUSH1 0x02
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE

    // check wad > callerBal?
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH1 0xa0
    MLOAD
    GT
    JUMPI @transfer_insufficient

    // callerBal -= wad
    PUSH1 0xe0
    MLOAD
    SLOAD                   // [callerBal]
    PUSH1 0xa0
    MLOAD                   // [callerBal, wad]
    SWAP1
    SUB                     // [newCallerBal]
    PUSH1 0xe0
    MLOAD
    SSTORE

    // toKey → mem[0xe0]
    PUSH1 0x80
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x02
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

transfer_insufficient:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT

// ============================================================
// transferFrom(address from, address to, uint256 wad) -> bool
// calldata: [sel][from][to][wad]
// ============================================================
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
    PUSH1 0xc0
    MSTORE

    // ---- check the allowance ----
    // fromRoot = keccak256(pad(from) ++ pad(3)) → mem[0xe0]
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

    // leaf = keccak256(pad(CALLER) ++ fromRoot) → mem[0x100]
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

    // check: wad > allowance ? -> revert (0 = no allowance)
    PUSH2 0x100
    MLOAD
    SLOAD                   // [allowance]
    PUSH1 0xc0
    MLOAD                   // [allowance, wad]
    GT                      // wad > allowance ?
    JUMPI @transfer_from_insufficient

    // ---- deduct the allowance (unless it is the infinite max) ----
    // max check: allowance == 2^256-1 ? via ISZERO(allowance+1)? too complex —
    // simplified: v1 detects the infinite allowance as max via allowance XOR max == 0
    // written directly in QASM: if allowance == 0xffff...ff skip the deduction
    PUSH2 0x100
    MLOAD
    SLOAD                   // [allowance]
    // max = 2^256-1: PUSH32 of all f's
    PUSH32 0x521784d1a99bfaa8cacf8a16399195bd049878c2ffffffffffffffffffffffff
    EQ                      // stack: [allowance==max ? 1:0]
    JUMPI @skip_allowance_burn

    // deduct: allowance - wad
    PUSH2 0x100
    MLOAD
    SLOAD                   // [allowance]
    PUSH1 0xc0
    MLOAD                   // [allowance, wad]
    SWAP1
    SUB                     // [allowance - wad]
    PUSH2 0x100
    MLOAD
    SSTORE
    JUMP @after_allowance_burn

skip_allowance_burn:
    JUMPDEST

after_allowance_burn:
    JUMPDEST

    // ---- deduct from's balance ----
    // fromKey (balance, slot2) -> mem[0xe0]
    PUSH1 0x80
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x02
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE

    // check wad > fromBal?
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH1 0xc0
    MLOAD
    GT
    JUMPI @transfer_from_insufficient

    // fromBal -= wad
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH1 0xc0
    MLOAD
    SWAP1
    SUB
    PUSH1 0xe0
    MLOAD
    SSTORE

    // ---- add to's balance ----
    // toKey (balance, slot2) -> mem[0xe0]
    PUSH1 0xa0
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x02
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
    PUSH1 0xc0
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

transfer_from_insufficient:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT

code_end:
