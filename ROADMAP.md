# Engineering Roadmap

This is a prioritized work plan, not a claim that the milestones are complete or
a commitment to release dates. Track implementation and acceptance in issues and
pull requests. Existing source code alone does not establish production readiness.

## 1. Reproducible contributor setup

- Align CI with the Go version declared in `go.mod`.
- Validate clean-checkout build and test instructions on documented platforms.
- Validate an isolated local development node without production credentials.
- Prepare small issues with scope, non-goals, and acceptance criteria.

Acceptance: an unfamiliar contributor can build, run the documented checks, and
open a focused PR without private setup instructions. Record commands, platform,
commit, and outcomes, including known failures.

## 2. Reliability and capacity evidence

- Measure sync from an empty data directory in a controlled test network.
- Measure CPU, memory, disk growth, and bandwidth for defined workloads.
- Validate restart and recovery after controlled connectivity interruptions.
- Exercise version and storage compatibility in isolated test environments.

Acceptance: publish reproducible conditions and sanitized results. Distinguish
transaction execution from signature verification and finality. README hardware
figures remain provisional planning estimates until measurements support them.

## 3. Cryptographic and protocol assurance

- Inventory algorithms, parameters, dependencies, and serialization formats.
- Distinguish legacy Dilithium/Kyber variants from final ML-DSA/ML-KEM standards.
- Document QTD assumptions, protocol boundaries, and test vectors.
- Document algorithm and key-format migration paths.
- Seek independent review of cryptography and consensus.

Acceptance: specifications and reproducible conformance evidence are available;
review status and unresolved limitations are stated explicitly. Do not claim FIPS
certification or completed audits without verifiable evidence.

## 4. Release scope and compatibility

- Document maturity separately for the VM, data availability, sharding, rollup,
  bridge, light-client, and SDK components.
- Define a release checklist, supported-version policy, and compatibility notes.
- Add release-specific changelogs when actual releases are prepared.

Acceptance: users can identify experimental components and migration risks without
inferring support from a directory name or marketing description.

## 5. Sustainable contribution process

- Pilot the contribution guide with independent developers.
- Establish actual reviewers and private reporting contacts.
- Configure repository protection and verify untrusted-PR permissions.
- Activate funded tasks only after budgets and written terms are approved.

Acceptance: issues have clear owners and acceptance criteria; reviews and rewards
have separate authorization; personal data and payment records stay outside Git.

## Non-goals for this phase

Do not expand the feature list at the expense of correctness, publish unsupported
performance claims, promise rewards without funding, or require contributors to
access production systems. Running a node, contributing code, and becoming a
validator are separate participation paths.
