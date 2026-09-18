# Project Governance

## Maintenance model

Quantaureum uses maintainer-led review. Repository administrators control access,
merge permissions, and releases. This document does not establish a foundation,
an elected council, or token-holder governance over this repository.

Contributors propose changes through issues and pull requests. Reviewers evaluate
correctness, tests, compatibility, and maintainability. Administrators designate
maintainers explicitly; contribution counts and token ownership do not grant
permissions automatically.

## Decisions and review

Small fixes can be discussed in their PR. Changes to protocol rules, cryptography,
wire formats, storage compatibility, or public APIs need a written design before
implementation. Record the problem, alternatives, security assumptions, migration
impact, and acceptance evidence. A merge is not authorization for a network
upgrade or a production deployment.

Maintainers should explain acceptance and rejection decisions. Contributors may
request reconsideration with new technical evidence in the same discussion.
Security-sensitive discussion must remain in the private reporting channel.

## Repository controls

Administrators should configure protected branches, require passing applicable
checks and a non-author review before merging, and restrict release credentials.
These are required setup actions, not claims that GitHub settings are already
enabled. Workflows for untrusted pull requests must not receive production
secrets or write-enabled release credentials.

If no independent reviewer is available for a critical change, record the review
gap and defer merge rather than describe a self-review as independent assurance.

## Becoming a maintainer

Sustained, high-quality contributions and constructive reviews can support an
invitation to a scoped maintainer role. Administrators should document the scope,
permissions, and responsibilities, use least privilege, and periodically review
access. Inactive or unsafe access can be revoked. Becoming a maintainer does not
imply compensation or authority to spend project funds.

## Conflicts of interest and rewards

Authors must not approve their own reward claims. Reviewers should disclose
conflicts and recuse themselves when necessary. Financial authorization is
separate from technical acceptance. Funded tasks require written terms and an
identified budget owner before work begins; no reward schedule is activated by
this document. Store payment details and contributor personal information outside
the public repository.
