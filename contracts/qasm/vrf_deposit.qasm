// Quantaureum Node source, version 1.0.0.
// QVM vrf_deposit contract (QASM) — on-chain billing for the random-number API
//
// Purpose:
//   deposit() payments are SERVICE FEES for the off-chain random-number API:
//   a depositor pays to top up the quota of the API key identified by keyHash
//   (the SHA-256 hex of their API key, passed as a 32-byte calldata word).
//   Deposits are non-refundable. withdraw() is the operator sweeping the
//   accumulated fees to the owner. There is no user-facing withdrawal.
//
// Functions and selectors (actual keccak256, golang.org/x/crypto/sha3
// NewLegacyKeccak256 over the ASCII signature):
//   deposit(bytes32 keyHash)  0xb214faa5  (anyone, CV>0, calldata==36 bytes)
//   withdraw()                0x3ccfd60b  (owner only, sweeps SELFBALANCE)
//   unknown selector                      -> REVERT
//
// Event (LOG1):
//   Deposit(address,uint256,bytes32)
//   topic0 = keccak256("Deposit(address,uint256,bytes32)")
//          = 0x1a771fe656018364a9369da21954bb3081cb08b0196c27e43ca59c7cae872737
//   data = 96 bytes: pad32(caller) ++ pad32(amount) ++ pad32(keyHash)
//
// Storage (plain slots, full width):
//   slot 0: owner (= deployer, set in .INIT)
//   slot 1: totalDeposited (u256 cumulative accrual counter; never reset)
//   slot 2: deposits[address] => u256 mapping root
//           key = keccak256(pad32(addr) ++ pad32(2))  (stqau_caller_balkey style)
//
// ABI note: deposit() is deliberately deposit(bytes32) — the caller passes the
// SHA-256 hash of the API key being topped up. A bare 4-byte deposit() call
// (no keyHash) is rejected: calldata length != 4+32 -> REVERT.
//
// QVM arithmetic semantics (R122 doc §1.3, all verified):
//   SUB/LT/GT/DIV/MUL/MOD: a=top op b=second
//   MSTORE: offset=top, value=second; KECCAK256: offset=top, size=second
//   SSTORE: key=top, value=second
//   LOG1 pops offset (top), size, topic — push order: topic, size, offset
//   JUMPI: jumps when the top is non-zero
//   CALL bottom->top: gas,addr,value,inOff,inSize,retOff,retSize
//   CALL needs gas 500000 (23000 is not enough for QVM intrinsic cost; verified in R122)

.INIT
    // slot0 = owner = CALLER (deployer)
    CALLER
    PUSH1 0x00
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
    // calldata shorter than a selector -> revert (no silent fund acceptance:
    // this contract's funds are accounted billing fees)
    PUSH1 0x00
    PUSH1 0x00
    REVERT

dispatch:
    JUMPDEST
    PUSH1 0x00
    CALLDATALOAD
    PUSH1 0xe0
    SHR
    PUSH4 0xffffffff
    AND

    DUP1
    PUSH4 0xb214faa5
    EQ
    JUMPI @fn_deposit

    DUP1
    PUSH4 0x3ccfd60b
    EQ
    JUMPI @fn_withdraw

    // unknown selector -> revert
    PUSH1 0x00
    PUSH1 0x00
    REVERT

// ============================================================
// deposit(bytes32 keyHash) payable
//   gates: calldata == 36 bytes (selector + keyHash); CV > 0
//   effects: deposits[CALLER] += CV; totalDeposited += CV
//   log: Deposit(CALLER, CV, keyHash)
//   memory layout during the call:
//     0x80 = caller (log data word 1)
//     0xa0 = CV     (log data word 2)
//     0xc0 = keyHash(log data word 3, read from calldata[4..36])
//     0xe0 = deposits mapping key (keccak area 0x20..0x60 is scratch)
// ============================================================
fn_deposit:
    JUMPDEST
    // calldata length must be exactly 4+32
    PUSH1 0x24
    CALLDATASIZE
    EQ
    ISZERO
    JUMPI @vrf_revert
    // CV == 0 -> revert
    CALLVALUE
    ISZERO
    JUMPI @vrf_revert
    // keyHash -> mem[0xc0]
    PUSH1 0x04
    CALLDATALOAD
    PUSH1 0xc0
    MSTORE
    // caller -> mem[0x80]
    CALLER
    PUSH1 0x80
    MSTORE
    // CV -> mem[0xa0]
    CALLVALUE
    PUSH1 0xa0
    MSTORE
    // deposits key = keccak(pad32(caller) ++ pad32(2)) -> mem[0xe0]
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
    // deposits[caller] += CV
    PUSH1 0xe0
    MLOAD
    SLOAD
    PUSH1 0xa0
    MLOAD
    ADD
    PUSH1 0xe0
    MLOAD
    SSTORE
    // totalDeposited (slot1) += CV
    PUSH1 0x01
    SLOAD
    PUSH1 0xa0
    MLOAD
    ADD
    PUSH1 0x01
    SSTORE
    // emit Deposit(caller, CV, keyHash): LOG1, data = mem[0x80..0xe0] (96 bytes)
    PUSH32 0x1a771fe656018364a9369da21954bb3081cb08b0196c27e43ca59c7cae872737
    PUSH1 0x60
    PUSH1 0x80
    LOG1
    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// ============================================================
// withdraw() — owner-only sweep of the entire contract balance
//   gate: CALLER == slot0
//   CEI: no storage effects to settle (deposits[] and totalDeposited are
//   cumulative billing records and stay intact), so the external CALL is the
//   only action; a failed CALL -> REVERT
// ============================================================
fn_withdraw:
    JUMPDEST
    // CALLER != owner -> revert
    CALLER
    PUSH1 0x00
    SLOAD
    EQ
    ISZERO
    JUMPI @vrf_revert
    // native CALL: gas 500000, addr=owner, value=SELFBALANCE
    PUSH4 0x0007a120
    PUSH1 0x00
    SLOAD
    SELFBALANCE
    PUSH1 0x00
    PUSH1 0x00
    PUSH1 0x00
    PUSH1 0x00
    CALL
    ISZERO
    JUMPI @vrf_revert
    // return true
    PUSH1 0x01
    PUSH1 0x00
    MSTORE
    PUSH1 0x20
    PUSH1 0x00
    RETURN

// shared revert exit
vrf_revert:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT

code_end:
