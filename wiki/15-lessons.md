# 15 - Engineering Lessons

> This chapter records source-level invariants that have prevented repeated
> implementation errors. It intentionally contains no operational incident
> timeline or environment-specific data.

## 15.1 R40A - RPC URL Selection

`qauctl account-remote` accepts an RPC address both positionally and through
the `--rpc` flag. The positional value is used when the flag has not been set;
an explicit flag always wins. This makes scripted use predictable without
changing the existing command syntax.

## 15.2 R40B - Bytecode Single Source Of Truth

`contracts/linear_vesting.qasm` is the authoritative LinearVesting source.
Tests and deployment tooling must assemble or derive bytecode from that file
rather than embedding a second copy or trusting generated `.hex` artifacts.
Before using derived bytecode, verify its byte length and the corresponding
contract ABI.

## 15.3 R40R - Transaction Receipt Persistence Window

Block storage, transaction indexing, and receipt persistence are separate
steps. A client may therefore query during the short window after a block is
stored but before its receipts are indexed. The RPC adapter retries the
priority path for a bounded interval before using its fallback.

Clients should treat an unexpected failed receipt as provisional until the
chain has had time to settle, then confirm with an independent call such as
`eth_getCode` or `eth_getBalance` when deployment state matters.

## 15.4 R40T - High-Value Transfer Protection

The chain requires commit-reveal authorization for high-value transfers. A
bare transfer above the configured threshold is rejected by the transaction
pool. Tools that submit protected transfers must use the same commit
authorization secret as the node, and operators should keep unlock windows
short.

## 15.5 R40G - Genesis Reconciliation

Genesis allocation is public chain data. Before using a genesis file, verify:

- the validator set matches the intended configuration;
- the total allocation equals the intended genesis supply;
- vesting and staking allocations are accounted for separately;
- the genesis hash is recomputed and recorded with the release.

Use deterministic tooling for the reconciliation and keep environment-specific
evidence outside the public repository.

## 15.6 R41 - Key File Format Handling

Validator key files may contain a raw Dilithium3 secret, a JSON keystore, or a
prefixed form. Parsing must detect the actual representation after prefix
handling and then decode the address using the supported address formats. The
regression suite covers raw hex, JSON, prefixed, and mixed prefix/JSON forms.

## 15.7 R50 - Public Repository Hygiene

- Keep operational evidence, private material, and local diagnostics under
  `.local-only/`; it is ignored by Git.
- Never commit credentials, host topology, internal paths, or deployment logs.
- Prefer environment variables for machine-specific inputs and fail closed when
  they are missing.
- Stage files explicitly. Do not use `git add .` or `git add -A`.

## 15.8 Implementation Invariants

- Validator key material must match the active genesis configuration.
- The QVM reentrancy check must distinguish calls to active contracts from
  transfers to externally owned accounts.
- Contract deployment arguments must be validated against the constructor ABI,
  including numeric units and byte-array prefixes.
- Binary replacement should be performed through the deployment supervisor so
  the node is stopped and restarted deterministically.
- Logging that is important for operation should use an unbuffered stream.

## 15.9 Change Discipline

- Keep fixes minimal and directly tied to a failing invariant.
- Add at least one focused regression test for every non-trivial bug.
- Include the affected behavior, root cause, fix boundary, compatibility
  impact, and verification commands in the change record.
- Do not push a change while required verification is failing.
