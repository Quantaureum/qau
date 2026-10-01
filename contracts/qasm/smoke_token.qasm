// Quantaureum Node source, version 1.0.0.
// QVM SmokeToken contract (QASM)
// R122 step-0 smoke experiment: verifies (1) keccak256 mapping storage keys (2) balance transfers
// (3) transfer invoked via an external contract CALL with correct mapping updates (4) REVERT rollback
//
// Simplified ERC20:
//   selector 0x18160ddd = totalSupply()
//   selector 0x70a08231 = balanceOf(address)   [EVM: 0x70a08231]
//   selector 0xa9059cbb = transfer(address,uint256)
//   selector 0x2e64ce9d = ping() -> returns 42  (smoke self-check)
//
// Storage:
//   slot 0: totalSupply
//   slot 1: owner (deployer, may mint)
//   slot 2: balanceOf mapping root  (key = keccak256(addr ++ slot2))
//   slot 3: paused (0=normal)
//
// Constructor args: none (mint is called by the owner later)
//
// Safety notes (QVM operand order is the reverse of EVM; all verified per the R122 doc §1.3):
//   SUB/LT/GT/DIV: a=top, b=second, result a op b
//   MSTORE: top=offset, second=value
//   SSTORE: top=key, second=value

.INIT
    // slot1 = owner = CALLER
    CALLER
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
    // enter the dispatcher only when calldata >= 4 bytes
    // QVM LT: a=top < b=second. Push order: PUSH4 first, then CALLDATASIZE -> stack [4, cds]
    // a=cds, b=4 -> cds<4 ? 1:0 -> ISZERO inverts -> 1 when calldata>=4 -> jump
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
    PUSH4 0x2e64ce9d
    EQ
    JUMPI @fn_ping

    DUP1
    PUSH4 0x18160ddd
    EQ
    JUMPI @fn_total_supply

    DUP1
    PUSH4 0x70a08231
    EQ
    JUMPI @fn_balance_of

    DUP1
    PUSH4 0xa9059cbb
    EQ
    JUMPI @fn_transfer

// ---- ping() -> returns 42 (0x2a) ----
fn_ping:
    JUMPDEST
    PUSH1 0x2a
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- totalSupply() -> uint256 ----
fn_total_supply:
    JUMPDEST
    PUSH1 0x00
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

fn_balance_of:
    JUMPDEST
    // compute key = keccak256(pad(addr) ++ slot2)
    // mem[0x20..0x40] = keccak input area: [32B addr][32B slot]
    PUSH1 0x04
    CALLDATALOAD            // stack: [addr word]
    PUSH1 0x20
    MSTORE                  // mem[0x20] = addr
    PUSH1 0x02
    PUSH1 0x40
    MSTORE                  // mem[0x40] = slot 2
    // keccak256(mem[0x20..0x60]) — QVM KECCAK256 pops: offset=top, size=second
    // so the push order is: size first, then offset
    PUSH1 0x40              // size
    PUSH1 0x20              // offset (pushed last, on top)
    KECCAK256               // stack: [key32]
    PUSH1 0x00
    MSTORE                  // mem[0] = key
    // SLOAD(key) — push the key onto the stack first, then SLOAD
    PUSH1 0x00
    MLOAD
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- transfer(address,uint256) -> bool ----
// calldata: [selector][addr][amount]
fn_transfer:
    JUMPDEST
    // ---- read calldata into safe memory in one go ----
    // mem[0x80] = to
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    // mem[0xa0] = amount
    PUSH1 0x24
    CALLDATALOAD
    PUSH1 0xa0
    MSTORE

    // ---- callerKey = keccak256(pad(caller) ++ pad(2)) ----
    // keccak input area mem[0x20..0x60]
    CALLER
    PUSH1 0x20
    MSTORE                  // mem[0x20] = caller
    PUSH1 0x02
    PUSH1 0x40
    MSTORE                  // mem[0x40] = slot2
    PUSH1 0x40              // size
    PUSH1 0x20              // offset
    KECCAK256               // stack: [callerKey]
    PUSH1 0xc0
    MSTORE                  // mem[0xc0] = callerKey

    // ---- callerBal = storage[callerKey] ----
    PUSH1 0xc0
    MLOAD
    SLOAD                   // stack: [callerBal]

    // ---- insufficiency check: amount > callerBal ? -> revert ----
    // QVM GT: a=top > b=second. Currently [callerBal] -> push amount on top
    PUSH1 0xa0
    MLOAD                   // stack: [callerBal, amount] amount on top
    GT                      // amount > callerBal ?
    JUMPI @transfer_insufficient

    // ---- callerBal -= amount; storage[callerKey] = callerBal-amount ----
    // QVM SUB: a=top - b=second. We want callerBal-amount -> top=callerBal
    // the stack is currently empty (callerBal was consumed by GT)! reload callerBal
    PUSH1 0xc0
    MLOAD
    SLOAD                   // stack: [callerBal]
    PUSH1 0xa0
    MLOAD                   // stack: [callerBal, amount] (amount on top)
    SWAP1                   // [amount, callerBal] callerBal on top
    SUB                     // stack: [newCallerBal = callerBal - amount]
    PUSH1 0xc0
    MLOAD                   // stack: [newCallerBal, callerKey] key on top
    SSTORE                  // storage[callerKey] = newCallerBal

    // ---- toKey = keccak256(pad(to) ++ pad(2)) ----
    PUSH1 0x80
    MLOAD
    PUSH1 0x20
    MSTORE                  // mem[0x20] = to
    PUSH1 0x02
    PUSH1 0x40
    MSTORE                  // mem[0x40] = slot2
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    PUSH1 0xe0
    MSTORE                  // mem[0xe0] = toKey

    // ---- toBal += amount ----
    PUSH1 0xe0
    MLOAD
    SLOAD                   // stack: [toBal]
    PUSH1 0xa0
    MLOAD                   // stack: [toBal, amount]
    ADD                     // stack: [toBal + amount]
    PUSH1 0xe0
    MLOAD                   // stack: [sum, toKey] key on top
    SSTORE                  // storage[toKey] = sum

    // return true (1)
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

transfer_insufficient:
    JUMPDEST
    // revert "INSUF"
    PUSH1 0x00
    PUSH1 0x00
    REVERT

code_end:
