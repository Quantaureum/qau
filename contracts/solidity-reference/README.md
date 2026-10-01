# solidity-reference — reference implementations (NOT deployable)

> ⚠️ **The Solidity contracts in this directory cannot be deployed to the Quantaureum chain.**
>
> Reason: the chain's evmcompat EVM->QVM translation layer has an **arithmetic operand-order defect**
> (EVM/QVM stack orders for `SUB/LT/GT/DIV/EXP` are opposite; a 1:1 translation necessarily computes wrong),
> so the deployment path was made **fail-closed** (R122). See `docs/EVM-COMPATIBILITY.md`.

## Purpose of this directory

1. **Logic reference**: the R122 QSwap QASM implementations (`contracts/qasm/`) were hand-translated from the
   Solidity versions here; reading them side by side clarifies each function's intent and edge conditions.
2. **ABI source**: function selectors, event layouts, and interface shapes follow this directory —
   the QASM contracts use 4-byte selectors fully consistent with the Solidity ABI.
3. **Differential-testing baseline for R124** (community task): once the evmcompat translator is rewritten,
   differential verification will use these contracts' expected behavior as the baseline.

## On-chain path (the only supported one)

```
Solidity (here, reference only)
    ↓  hand translation
QASM source  contracts/qasm/*.qasm
    ↓  go run ./cmd/qasm assemble X.qasm X.hex
hex bytecode
    ↓  go run ./cmd/deploy_qswap ...   (Dilithium3 signing)
mainnet/testnet
```

The only contract families verified on mainnet (R120 LinearVesting locking 15M QAU, R122 QSwap)
are all handwritten QASM.

## Historical notes

- 2026-09-04: evmcompat defect investigation concluded (R122 plan §1.1); the Solidity route was abandoned.
- 2026-09-05: the directory was renamed from `contracts/solidity/` to `contracts/solidity-reference/`,
  and the fail-closed evmcompat deployment path was merged.
