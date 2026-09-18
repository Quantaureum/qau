# Pull request

Do not include keys, mnemonics, internal hostnames, real wallet-to-host
mappings, or production topology in this PR.

## What and why

<!-- Behavior, bug, or docs change; link the issue. Note breaking changes. -->

## Implementation notes

<!-- Key decisions. Call out consensus, crypto, storage-format,
     wire-protocol, or public-API changes explicitly. -->

## Verification

<!-- Paste REAL results per CONTRIBUTING.md. Delete rows you did not run;
     do not mark anything pass without running it. -->

| Check | Result | Notes |
|---|---|---|
| `git diff --check` | ran / not run | |
| `go vet ./...` | ran / not run | |
| `go build ./...` | ran / not run | |
| `go test ./... -count=1` | ran / not run | |
| affected-package race tests (concurrency changes) | ran / not run | |

## Compatibility and security

- [ ] No consensus, crypto, storage-format, wire-protocol, or public-API change; OR I explained the impact and migration path above.
- [ ] No secrets, real infrastructure details, or fabricated performance/security claims were added.
- [ ] New comments and docs are in English.
- [ ] I confirm this contribution is submitted under <LICENSE>, and I have the right to submit it.

## Disclosure

<!-- State any non-trivial AI-generated or third-party-derived content and how you verified it. -->
