# Contributing to Quantaureum

Contributions to code, tests, documentation, and developer tooling are welcome.
Start with a small, independently reviewable change. A merged contribution does
not automatically qualify for a payment or grant repository permissions.

## Before starting

- Read the [roadmap](ROADMAP.md) and [governance](GOVERNANCE.md).
- Follow the [code of conduct](CODE_OF_CONDUCT.md).
- Report suspected vulnerabilities privately using [SECURITY.md](SECURITY.md),
  not a public issue or pull request.
- For changes to consensus, cryptography, transaction encoding, storage formats,
  or economic rules, discuss a design before implementing it.
- Confirm scope and acceptance criteria with a maintainer before starting a
  substantial task. An issue assignment is coordination, not a payment promise.

## Set up a development checkout

Install Git and the Go version declared in `go.mod`. Fork the repository on
GitHub, clone your fork, and create a branch for your change. Run these commands
from the repository root:

```sh
go version
go mod download
go build ./...
go test ./... -count=1
```

Some packages may require platform-specific dependencies. If setup fails, report
which command failed, the commit, Go version, and operating system. Do not
silently skip failures or describe an untested platform as supported.

To build the daemon for a local experiment:

```sh
go build -trimpath -o .local-only/bin/qaud ./cmd/qaud
./.local-only/bin/qaud --help
./.local-only/bin/qaud --dev --network dev --datadir ./.local-only/dev-data
```

On Windows, use `qaud.exe` for the output and executable name. Development mode
uses intentionally public deterministic seeds: **DEVNET ONLY**. Never fund these
accounts with real assets or expose a development node to the public network.
Stop the foreground daemon with `Ctrl+C`. See the [usage guide](docs/USAGE.md)
and [configuration guide](docs/CONFIGURATION.md) before changing endpoints.

Keep generated binaries, runtime state, logs, credentials, and one-off scripts
under the ignored `.local-only/` directory or outside the checkout. Do not
commit them. Never include real keys, wallet-to-host mappings, or deployment
topology in examples, tests, screenshots, or logs.

## Choose a task

Useful starting points include documentation corrections, CLI help improvements,
unit tests for existing behavior, and SDK example validation. Look for issues
with explicit scope, non-goals, and acceptance criteria; ask for clarification
when these are missing. Do not turn a single task into multiple cosmetic PRs.

A good issue describes:

1. The problem and user-visible impact.
2. Relevant packages or documentation.
3. Expected behavior and non-goals.
4. Evidence required for acceptance.
5. Commands or manual steps that validate the result.

## Prepare a pull request

- Keep changes focused and explain why they are needed.
- Format changed Go files with `gofmt` and add tests for changed behavior.
- Use English for new code comments, commit messages, and technical documentation.
- Document compatibility changes and migrations explicitly.
- Cite the conditions and evidence behind performance and security claims.
- Disclose relevant generated or AI-assisted work. You remain responsible for
  correctness, licensing, understanding the change, and checking generated code.
- Identify third-party material and its license. Only submit work you have the
  right to contribute under this repository's [license](LICENSE).

Run the applicable checks and record exact results in the PR:

```sh
git diff --check
go vet ./...
go build ./...
go test ./... -count=1
```

For concurrency changes, also run race-enabled tests for affected packages on a
supported platform. If a check cannot run or fails, report that honestly with a
sanitized error summary. Do not claim that CI passes merely because a workflow
file exists. SDK changes need checks appropriate to the affected SDK as well.

Open a PR using the template and respond to review. Maintainers may request
changes or decline a contribution that conflicts with project scope. Do not
send private keys, production access, or payments to obtain a review.

## Recognition and rewards

The project is designing a tiered contributor reward process. There is no
active general reward schedule established by this document. Do not assume
that opening an issue, submitting a PR, or obtaining a merge creates a payment
entitlement. Any funded task must state its budget, reward asset, acceptance
criteria, approver, and payment terms in writing before work starts. Security
reports follow the separate disclosure process; no bug bounty is promised here.
