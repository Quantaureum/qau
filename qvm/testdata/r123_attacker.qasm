// Quantaureum Node source, version 1.0.0.
// R123 security audit — reentrancy attacker contract (for the SEC-1 test)
//
// Usage (from an EOA):
//   EOA -> ATTACKER.Call("0x01 ..." non-empty calldata) -> passthrough to stqau (calldata as-is,
//                                                  CALLVALUE = the contract's entire current balance? No, 0)
//   receive (empty calldata; stqau sends this contract QAU) -> immediately CALL stqau.claimWithdrawal()
//                                              (reentering stqau, testing the CEI defense)
//
// slot 0 = the stqau contract address (written by .INIT at deploy time)
//
// Note: QVM SSTORE semantics key=top, value=second; CALL stack order bottom->top = gas,addr,value,inOff,inSize,outOff,outSize

.INIT
    // slot0 = stqau (a PUSH20 constant template injected by the test harness before assembly)
PUSH32 0x000000000000000000000000__STQAU_ADDR_40__
    PUSH1 0x00
    SSTORE
    // copy runtime
    PUSH2 @code_end-@code_start
    PUSH2 @code_start
    PUSH1 0x00
    CODECOPY
    PUSH2 @code_end-@code_start
    PUSH1 0x00
    RETURN

.CODE
code_start:
    // empty calldata (<4B) -> receive path: reenter claim
    PUSH1 0x04
    CALLDATASIZE
    LT
    ISZERO
    JUMPI @passthrough
    // receive: call stqau's claimWithdrawal() — build calldata = sel 0x6e66d84a
    PUSH4 0x6e66d84a
    PUSH1 0xe0
    SHL
    PUSH1 0x00
    MSTORE          // mem[0..4] = selector
    // CALL(gas=500000, addr=slot0, value=0, in=0..4, out=0)
    PUSH4 0x0007a120
    PUSH1 0x00
    SLOAD           // addr = stqau
    PUSH1 0x00      // value = 0
    PUSH1 0x00      // inOff = 0
    PUSH1 0x04      // inSize = 4
    PUSH1 0x00      // outOff = 0
    PUSH1 0x00      // outSize = 0
    CALL
    // whether the reentry succeeds does not matter — a rejection just STOPs (note: the top-level CALL status is unchecked)
    STOP

passthrough:
    JUMPDEST
    // passthrough: CALL stqau with the calldata as-is (inOff=0, inSize=CALLDATASIZE), value=0
    // CALLDATACOPY stack order: top=dest, second=srcOffset, bottom=size (same as EVM)
    CALLDATASIZE    // size (bottom)
    PUSH1 0x00      // srcOffset = 0
    PUSH1 0x00      // dest = 0 (top)
    CALLDATACOPY
    // CALL
    PUSH4 0x0007a120
    PUSH1 0x00
    SLOAD           // addr = stqau
    PUSH1 0x00      // value = 0
    PUSH1 0x00      // inOff = 0
    CALLDATASIZE    // inSize
    PUSH1 0x00      // outOff = 0
    PUSH1 0x00      // outSize = 0
    CALL
    // passthrough semantics: a sub-call revert -> self revert as well (so the EOA sees the rejection)
    ISZERO
    PUSH2 @pt_fail
    JUMPI
    STOP
pt_fail:
    JUMPDEST
    PUSH1 0x00
    PUSH1 0x00
    REVERT

code_end:
