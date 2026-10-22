// Quantaureum Node source, version 1.0.0.
// AirdropClaim contract (QASM) — QVM-native pull-style mainnet airdrop.
//
// Model (Arbitrum TokenDistributor-style, mapping-based — merkle requires the
// same KECCAK idiom but per-address import is cheaper to audit on QVM):
//   owner imports (address -> amount) via setClaimable(); each account pulls
//   its amount once via claim(); after the deadline, the owner sweeps the
//   unclaimed remainder back via sweep().
//
// QVM stack-semantics cheat sheet (verified against qasm/mock_token.qasm and
// qasm/../linear_vesting.qasm):
//   MSTORE: offset on top, value second
//   SSTORE: key on top, value second   (push value first, then key)
//   SLOAD : key on top
//   KECCAK256: offset on top, size second
//   LT/GT/SUB/DIV: a=top, b=second  ->  a < b / a > b / a - b / a / b
//   CALL  : push gas, addr, value, inOff, inSize, retOff, retSize (retSize top)
//   mapping key = KECCAK256(pad32(addr) ++ pad32(slotIndex))
//
// Storage:
//   slot 0: owner (deployer)
//   slot 1: claimDeadline (absolute unix timestamp)
//   slot 100 (mapped): claimable[address] = amount in wei
//
// Constructor args (code tail, 32 bytes):
//   [0:32] claimDeadline (unix seconds)
//
// Fund layout: plain value transfers to the contract address are accepted
// (calldata < 4 bytes falls through to STOP before the dispatcher).
//
// Selectors (legacy keccak256, Solidity-compatible):
//   owner()                     0x8da5cb5b
//   claimDeadline()             0x3ba86c44
//   claimableOf(address)        0x8903ab9d
//   setClaimable(address,uint)  0x5b27e893  (owner only)
//   claim()                     0x4e71d92d
//   sweep()                     0x35faa416  (owner only, after deadline)

.INIT
    // slot 0 = deployer
    CALLER
    PUSH1 0x00
    SSTORE

    // copy constructor args (32-byte deadline) from the code tail
    PUSH1 0x20            // size
    PUSH2 @args_start     // offset
    PUSH1 0x80            // destOffset
    CODECOPY
    PUSH1 0x80
    MLOAD
    PUSH1 0x01
    SSTORE                // slot 1 = deadline

    // install runtime code
    PUSH2 @code_end-@code_start
    PUSH2 @code_start
    PUSH1 0x00
    CODECOPY
    PUSH2 @code_end-@code_start
    PUSH1 0x00
    RETURN

.CODE
code_start:
    // funding hook: value transfers carry no calldata -> accept silently
    PUSH1 0x04
    CALLDATASIZE
    LT                    // datasize < 4 ?
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
    PUSH4 0x3ba86c44
    EQ
    JUMPI @fn_deadline

    DUP1
    PUSH4 0x8903ab9d
    EQ
    JUMPI @fn_claimable_of

    DUP1
    PUSH4 0x5b27e893
    EQ
    JUMPI @fn_set_claimable

    DUP1
    PUSH4 0x4e71d92d
    EQ
    JUMPI @fn_claim

    DUP1
    PUSH4 0x35faa416
    EQ
    JUMPI @fn_sweep

    PUSH1 0x00
    PUSH1 0x00
    REVERT

// ---- owner() ----
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

// ---- claimDeadline() ----
fn_deadline:
    JUMPDEST
    POP
    PUSH1 0x01
    SLOAD
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- claimableOf(address) ----
fn_claimable_of:
    JUMPDEST
    POP
    // key = keccak(pad32(calldata[4:36]) ++ pad32(100))
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x64
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256
    SLOAD                 // [amt]
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- setClaimable(address,uint256) — owner only ----
fn_set_claimable:
    JUMPDEST
    // mem[0x80] = addr, mem[0xa0] = amount
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0x80
    MSTORE
    PUSH1 0x24
    CALLDATALOAD
    PUSH1 0xa0
    MSTORE
    // caller == owner ?
    CALLER
    PUSH1 0x00
    SLOAD
    EQ
    JUMPI @sc_authorized
    PUSH1 0x00
    PUSH1 0x00
    REVERT
sc_authorized:
    JUMPDEST
    PUSH1 0x80
    MLOAD
    PUSH1 0x20
    MSTORE
    PUSH1 0x64
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256             // [key]
    PUSH1 0xa0
    MLOAD                 // [key, amount]
    SWAP1                 // [amount, key]  (key top)
    SSTORE                // claimable[addr] = amount
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ---- claim() ----
fn_claim:
    JUMPDEST
    POP                   // drop selector
    // reject when past the deadline
    TIMESTAMP
    PUSH1 0x01
    SLOAD
    SWAP1                 // GT pops a=top: need top=now, second=deadline
    GT                    // now > deadline
    JUMPI @claim_ended

    // key = keccak(pad32(caller) ++ pad32(100))
    CALLER
    PUSH1 0x20
    MSTORE
    PUSH1 0x64
    PUSH1 0x40
    MSTORE
    PUSH1 0x40
    PUSH1 0x20
    KECCAK256             // [key]
    DUP1
    SLOAD                 // [key, amt]
    DUP1
    PUSH1 0x00
    MSTORE                // mem[0x00] = amt  (call value below)
    ISZERO                // amt == 0 ?
    JUMPI @claim_none     // pops cond+dest; stack [key]

    // effects first (CEI): claimable[caller] = 0
    PUSH1 0x00            // [key, 0]
    SWAP1                 // [0, key]  (key top)
    SSTORE                // stack []

    // interaction: CALL(gas, caller, value=mem[0x00], 0, 0, 0, 0)
    GAS
    CALLER
    PUSH1 0x00
    MLOAD
    PUSH1 0x00
    PUSH1 0x00
    PUSH1 0x00
    PUSH1 0x00
    CALL                  // [result]
    DUP1
    ISZERO
    JUMPI @claim_failed   // REVERT rolls back the zeroing too
    POP                   // drop result
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

claim_ended:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT
claim_none:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT
claim_failed:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT

// ---- sweep() — owner, only after deadline; sends the unclaimed balance home ----
fn_sweep:
    JUMPDEST
    POP
    // require now > deadline
    TIMESTAMP
    PUSH1 0x01
    SLOAD
    SWAP1                 // GT pops a=top: need top=now, second=deadline
    GT                    // now > deadline ?
    ISZERO
    JUMPI @sweep_reject   // not yet past deadline -> reject
    // caller == owner ?
    CALLER
    PUSH1 0x00
    SLOAD
    EQ
    JUMPI @sweep_authorized
    PUSH1 0x00
    PUSH1 0x00
    REVERT
sweep_authorized:
    JUMPDEST
    ADDRESS
    BALANCE               // [selfBal]
    DUP1
    PUSH1 0x00
    MSTORE                // mem[0x00] = selfBal (call value below)
    GAS                   // [selfBal, gas]
    PUSH1 0x00
    SLOAD                 // owner -> [selfBal, gas, owner]
    PUSH1 0x00
    MLOAD                 // value -> [selfBal, gas, owner, selfBal']
    PUSH1 0x00
    PUSH1 0x00
    PUSH1 0x00
    PUSH1 0x00
    CALL                  // [selfBal, result]
    DUP1
    ISZERO
    JUMPI @sweep_failed
    POP                   // result
    POP                   // selfBal
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN
sweep_reject:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT
sweep_failed:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT

code_end:
args_start:
