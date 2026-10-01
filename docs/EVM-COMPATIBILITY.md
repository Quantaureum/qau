# EVM compatibility layer (evmcompat) status

> Status: **known defect, fail-closed mode** — Solidity contract deployments are explicitly rejected;
> there is no more "fall back to native execution" nonsense. QASM (`contracts/qasm/`) is the only contract path verified on mainnet.
> Last updated: R122 (2026-09-05).

## 1. Fact summary

| Item | Status ||
|---|---|
| evmcompat translator (`evmcompat/evmcompat.go`) | **has an unfixable defect**, disabled by default ||
| EVM->QVM bytecode deployment | **fail-closed**: detected as EVM and translation fails -> deployment rejected with an explicit reason ||
| EVM runtime translation failure | **fail-closed**: deployment reverts (fixed in R122; previously deployed garbage silently) ||
| QASM native contracts | ✅ verified on mainnet (R120 LinearVesting 15M QAU lock, R122 QSwap suite) ||
| Solidity reference implementations | `contracts/solidity-reference/` (**reference only, not deployable on-chain**) ||

## 2. Defect details (why a 1:1 translation necessarily computes wrong)

**Core problem: EVM and QVM arithmetic operand orders are opposite.**

- EVM `SUB`: result = **second-from-top − top** (`a - b`, with b the top of the stack)
- QVM `SUB`: result = **top − second-from-top** (`qvm/operations.go`: `a=Pop(); b=Pop(); Push(a-b)`, a is the top)

`LT / GT / DIV / EXP` are all likewise reversed. evmcompat is a 1:1 opcode translation
**without any operand-swap sequences inserted**, hence:

1. any Solidity contract containing arithmetic computes **wrong results** after translation;
2. for AMM/DEX contracts this means **direct user fund loss** (wrong swap ratios).

This defect cannot be patched by "translating opcode by opcode" — the translator must be **rewritten**, inserting stack operations around every arithmetic opcode
to swap operand order (cost: +3~5 gas per arithmetic op, plus a full new test suite).
This is the R124 community task, see §5.

### Secondary defects (equally fatal)

- **metadata cannot be translated**: the ipfs CBOR tail of Solidity initcode contains arbitrary bytes
  (`0x22`,`0xda`,`0xc9`,`0x2d`...), absent from the opcode map -> the whole translation errors out.
- **no Solidity contract has ever run on-chain**: local testing of WQAU.sol deployment returned status=0x0.

## 3. fail-closed behavior (merged in R122)

Handling matrix when the deployment path meets EVM bytecode:

| Scenario | Behavior ||
|---|---|
| initcode detected as EVM, translation fails | `evm translation failed (deployment rejected, fail-closed)` — tx revert ||
| initcode translates, runtime translation fails | `evm runtime translation failed (deployment rejected, fail-closed)` — **deployment reverts** (before R122: silent garbage deployment!) ||
| parallel executor, same scenario | same fail-closed (`qvm/parallel/executor.go`; before R122 it logged then ran natively) ||
| everything translates | execution proceeds, but **results remain untrustworthy** (the §2 operand defect persists) -> see §4 ||

Code involved:
- `qvm/executor.go` `Create()` / `Create2()` — both init and runtime
- `qvm/parallel/executor.go` `executeContractCreate()`
- `qvm/jit_adapter.go` runtime translation failure is already fail-closed (existing behavior preserved)

## 4. Advice for users/developers

1. **To deploy contracts -> use QASM** (`contracts/qasm/` + `cmd/qasm assemble`).
   QASM contracts use standard Solidity ABI selectors; wallets/RPC call them the same way.
2. Solidity logic can live as a **reference implementation** under `contracts/solidity-reference/`,
   then be hand-translated to QASM (the R122 QSwap workflow).
3. **Do not** attempt to deploy any arithmetic-bearing contract via evmcompat — even if translation "succeeds",
   the arithmetic results are wrong.

## 5. Fix roadmap (community task R124)

Rewrite evmcompat from "1:1 transliteration" to "semantics-preserving translation":

1. Each arithmetic opcode (`ADD/SUB/MUL/DIV/LT/GT/EXP/MOD`...) is translated as
   `SWAP1; <op>` or `<op>` plus a stack-adjustment sequence so the result matches EVM semantics;
2. Handle `JUMPI` conditions, `SSTORE` key order, and other implicit stack-order differences the same way;
3. Skip the Solidity initcode CBOR metadata section (locate the `0x64 0x69 0x70 0x66 0x73`
   = "ipfs" marker and truncate);
4. Build differential tests: the same contract compiled from Solidity vs hand-written QASM, comparing all return values on random inputs;
5. Until everything passes, **stay fail-closed**; afterwards, enable per network parameter.

**Before R124, no "successfully translated" EVM contract may be considered usable.**
