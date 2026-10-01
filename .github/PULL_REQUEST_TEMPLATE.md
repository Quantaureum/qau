# Pull Request

Thanks for contributing to Quantaureum. Fill out the sections below so reviewers have full context.

## Summary
<!-- One short paragraph. What does this PR change and why? -->

## Closes / Fixes
<!-- Link issue(s) with `Closes #123` syntax. If none, say "n/a". -->

## Type of change
- [ ] Bug fix (non-breaking behavior correction)
- [ ] New feature (adds capability)
- [ ] Breaking change (affects consensus, wire format, contract ABI, or public API)
- [ ] Refactor (no behavior change)
- [ ] Documentation only
- [ ] CI / build change

## Affected components
<!-- e.g. consensus, p2p, qvm, RPC, wallet, contracts/.., .github/... -->

## Risks & mitigations
<!-- Any mainnet impact? Contract behavior change? Backwards-compatibility break?
     For each risk, list mitigation (test, runbook, feature flag...). -->

## Testing
- [ ] `just ci` green locally
- [ ] `go test -short ./...` green
- [ ] `go test -race ./...` green on affected packages
- [ ] New tests added for all new paths (list files below)
- [ ] Manual smoke test on `localtest/` (6 validator) — describe result
- [ ] Fuzz run on touched surface (`go test -fuzz=` ...) — list runs

## Mainnet readiness checklist
<!-- Only for changes that can hit production binaries. Delete section if n/a. -->
- [ ] No new hardcoded IPs / endpoints in tracked sources
- [ ] No private keys, mnemonics, or keystore committed (`git log -p | grep -iE 'mnemonic|private_key|secret'`)
- [ ] Sensitive configuration lives in `.local-only/`
- [ ] Plan doc updated under `docs/plans/` if this introduces/extends a numbered milestone (e.g., R124 / R125...)
- [ ] Runbook updated under `docs/` for field operators

## Documentation
- [ ] Public API surface documented in `docs/DEVELOPER_GUIDE.md` or affected module's doc
- [ ] Breaking changes called out explicitly in PR description top

## License
By submitting this PR you agree your contribution will be distributed under the terms of the Apache-2.0 license (see `LICENSE`).
