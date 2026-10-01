// Quantaureum Node source, version 1.0.0.
// QVM MockToken contract (QASM) — R122 step 2
// Test-only ERC20: the constructor pre-mints the totalSupply to the deployer, who may mint(to, amount).
// Used by QSwapPair tests and local-chain e2e; never deployed to mainnet.
//
// Storage:
//   slot 0: totalSupply
//   slot 1: owner (deployer)
//   slot 2: balanceOf mapping root   key = keccak256(pad(addr) ++ pad(2))
//   slot 3: allowance mapping root   key = keccak256(pad(spender) ++ keccak256(pad(owner) ++ pad(3)))
//
// Constructor (.INIT): pre-mints 1,000,000 QAU (18 decimals -> 1e24) to the deployer
//   CALLER -> storage[keccak(pad(caller)++pad(2))] += 1e24
//   totalSupply = 1e24
//   owner = CALLER
//
// ABI selectors (Solidity standard):
//   name()               -> "MockToken" (32B string: offset 0x20 + len 9 + right-padded)
//   symbol()             -> "MTK"
//   decimals()           -> 18
//   totalSupply()        0x18160ddd
//   balanceOf(address)   0x70a08231
//   allowance(o,s)       0xdd62ed3e
//   approve(s,w)         0x095ea7b3
//   transfer(t,w)        0xa9059cbb
//   transferFrom(f,t,w)  0x23b872dd
//   mint(to,amount)      0x40c10f19  (owner only)
//
// QVM semantics cheat sheet (R122 §1.3, all verified via smoke/wqau tests):
//   MSTORE/MLOAD/SLOAD/SSTORE/KECCAK256/LOG*: offset/key on top
//   LT/GT/SUB/DIV: a=top op b=second
//   SSTORE: key=top, value=second -> push value first, key after
//   CALL (QVM native order, retSize on top): push gas,addr,value,inOff,inSize,retOff,retSize

.INIT
    // storage[balKey(caller)] += 1e24 (pre-mint)
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x02
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256               // stack: [callerBalKey]
    SLOAD                   // stack: [callerBal] (0)
    PUSH32 0x00000000000000000000000000000000000D3C21BCECCEDA1000000 // 1e24
    ADD                     // stack: [1e24]
    // recompute callerBalKey and store it back
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x02
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    SSTORE                  // storage[callerBalKey] = 1e24

    // totalSupply = 1e24
    PUSH32 0x00000000000000000000000000000000000D3C21BCECCEDA1000000
    PUSH1 0x00
    SSTORE

    // owner = CALLER  (storage[1] = CALLER)
    CALLER
    PUSH1 0x01
    SSTORE

    // copy the runtime code and RETURN
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

    DUP1
    PUSH4 0x40c10f19
    EQ
    JUMPI @fn_mint

    PUSH1 0x00
    PUSH1 0x00
    REVERT

// ---- name() -> "MockToken" ----
fn_name:
    JUMPDEST
    PUSH32 0x0000000000000000000000000000000000000000000000000000000000000020 // offset
    PUSH1 0x00
    MSTORE
    PUSH32 0x0000000000000000000000000000000000000000000000000000000000000009 // len 9
    PUSH1 0x20
    MSTORE
    PUSH32 0x4D6F636B546F6B656E0000000000000000000000000000000000000000000000 // "MockToken"
    PUSH2 0x40
    MSTORE
    PUSH2 0x60
    PUSH1 0x00
    RETURN

// ---- symbol() -> "MTK" ----
fn_symbol:
    JUMPDEST
    PUSH32 0x0000000000000000000000000000000000000000000000000000000000000020
    PUSH1 0x00
    MSTORE
    PUSH32 0x0000000000000000000000000000000000000000000000000000000000000003
    PUSH1 0x20
    MSTORE
    PUSH32 0x4D544B0000000000000000000000000000000000000000000000000000000000 // "MTK"
    PUSH2 0x40
    MSTORE
    PUSH2 0x60
    PUSH1 0x00
    RETURN

// ---- decimals() -> 18 ----
fn_decimals:
    JUMPDEST
    PUSH1 0x12
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- totalSupply() ----
fn_total_supply:
    JUMPDEST
    PUSH1 0x00
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- balanceOf(address) ----
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

// ---- allowance(owner, spender) ----
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
    // ownerRoot = keccak(pad(owner) ++ pad(3)) → mem[0xe0]
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
    // leaf = keccak(pad(spender) ++ ownerRoot), returned by SLOAD
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

// ---- approve(spender, wad) ----
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
    // ownerRoot = keccak(pad(CALLER) ++ pad(3)) → mem[0xe0]
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
    // leaf = keccak(pad(spender) ++ ownerRoot) → mem[0xe0]
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

// ---- transfer(to, wad) ----
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
    // wad > callerBal ? revert
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
    SLOAD
    PUSH1 0xa0
    MLOAD
    SWAP1
    SUB
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

// ---- transferFrom(from, to, wad) ----
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
    // fromRoot = keccak(pad(from) ++ pad(3)) → mem[0xe0]
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
    // wad > allowance ? revert
    PUSH2 0x100
    MLOAD
    SLOAD
    PUSH2 0xc0
    MLOAD
    GT
    JUMPI @transfer_from_insufficient
    // infinite-allowance skip: allowance == max?
    PUSH2 0x100
    MLOAD
    SLOAD
    PUSH32 0x521784d1a99bfaa8cacf8a16399195bd049878c2ffffffffffffffffffffffff
    EQ
    JUMPI @skip_allowance_burn
    // deduct allowance -= wad
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
    JUMP @after_allowance_burn
skip_allowance_burn:
    JUMPDEST
after_allowance_burn:
    JUMPDEST
    // fromBalKey → mem[0xe0]
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
    // wad > fromBal ? revert
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH2 0xc0
    MLOAD
    GT
    JUMPI @transfer_from_insufficient
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
    // toBalKey → mem[0xe0]
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

transfer_from_insufficient:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT

// ---- mint(to, amount) owner only ----
fn_mint:
    JUMPDEST
    // mem[0x80]=to, mem[0xa0]=amount
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    PUSH1 0x24
    CALLDATALOAD
    PUSH1 0xa0
    MSTORE
    // CALLER == owner(storage[1]) ?
    CALLER
    PUSH1 0x01
    SLOAD
    EQ
    JUMPI @mint_authorized
    PUSH1 0x00
    PUSH1 0x00
    REVERT
mint_authorized:
    JUMPDEST
    // toBalKey → mem[0xe0]
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
    // toBal += amount
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH1 0xa0
    MLOAD
    ADD
    PUSH1 0xe0
    MLOAD
    SSTORE
    // totalSupply += amount
    PUSH1 0x00
    SLOAD
    PUSH1 0xa0
    MLOAD
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

code_end:
