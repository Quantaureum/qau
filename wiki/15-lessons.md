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
- A `StateDB` instance admits exactly one top-level execution frame
  (`BeginExecution` / `TryBeginExecution` / `WithExecutionFrame`). The dirty
  journal and the position-based snapshot stack are shared per instance, so any
  entry point that commits, reverts a snapshot, rolls state back to a height, or
  writes accounts back into committed state must hold the frame for its whole
  duration, or it corrupts a block transition that is running concurrently
  (R4-07 C1, R6-03).
- `StateDB.Copy()` must deep-copy every mutable field an instance guards with its
  own `s.mu`. A field inherited by reference is one map behind two mutexes: the
  producer's copy and the live StateDB commit concurrently, and the collision is a
  fatal `concurrent map writes`, not a recoverable panic (R6-06: `stateSnapshots`
  was shared this way). When adding a field to `StateDB`, decide explicitly
  whether `Copy()` clones it or shares it on purpose, and say so at the site.
- Anything presented as a proof must verify against the state root the node is
  serving, before it is handed out. A backend that cannot prove, a proof that
  does not verify, and a header that disagrees with the live root are errors; a
  placeholder or empty proof is never an acceptable substitute for "no data"
  (R6-02).
- Match the claim to the data structure. Committed storage slots live in the
  key-value store, not in the Verkle state trie, so no state-root-bound storage
  proof exists: light clients are refused rather than handed a contradicting
  exclusion proof, and `eth_getProof` storage entries are labelled `unverified`
  instead of presented as proven (R6-05).
- A registered surface that is not live refuses explicitly at its own boundary
  (`-32603` plus a caller-facing reason) instead of performing a different,
  destructive operation under the requested name, and its wiring seam is removed
  rather than left half-connected (R5-05, R6-01).

## 15.9 Change Discipline

- Keep fixes minimal and directly tied to a failing invariant.
- Add at least one focused regression test for every non-trivial bug.
- Include the affected behavior, root cause, fix boundary, compatibility
  impact, and verification commands in the change record.
- Do not push a change while required verification is failing.
